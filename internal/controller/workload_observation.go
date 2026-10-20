/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
)

type workloadObservation struct {
	ConfigMap      *corev1.ConfigMap
	Service        *corev1.Service
	StatefulSet    *appsv1.StatefulSet
	Pods           []corev1.Pod
	ConfigMapErr   error
	ServiceErr     error
	StatefulSetErr error
	PodsErr        error
}

func workloadOwnedBy(actual metav1.Object, parent *infrastructurev1alpha1.KeaCluster) bool {
	if isNilMetaObject(actual) || parent == nil || parent.UID == "" {
		return false
	}
	var controller *metav1.OwnerReference
	refs := actual.GetOwnerReferences()
	for i := range refs {
		ref := &refs[i]
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		if controller != nil {
			return false
		}
		controller = ref
	}
	return controller != nil && controller.APIVersion == infrastructurev1alpha1.GroupVersion.String() &&
		controller.Kind == "KeaCluster" && controller.Name == parent.Name && controller.UID == parent.UID
}

func workloadSoleOwnedBy(actual metav1.Object, parent *infrastructurev1alpha1.KeaCluster) bool {
	return !isNilMetaObject(actual) && len(actual.GetOwnerReferences()) == 1 && workloadOwnedBy(actual, parent)
}

func isNilMetaObject(actual metav1.Object) bool {
	if actual == nil {
		return true
	}
	value := reflect.ValueOf(actual)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func candidateWorkloadPods(parent *infrastructurev1alpha1.KeaCluster, names workloadNames, actual *appsv1.StatefulSet, pods []corev1.Pod) []corev1.Pod {
	if parent == nil {
		return nil
	}
	candidates := make(map[string]corev1.Pod)
	for _, pod := range pods {
		if pod.Namespace != parent.Namespace {
			continue
		}
		candidate := pod.Labels[clusterUIDLabel] == string(parent.UID) || reservedPodOrdinal(names.StatefulSet, pod.Name)
		for _, ref := range pod.OwnerReferences {
			if ref.Controller == nil || !*ref.Controller {
				continue
			}
			if actual != nil && actual.UID != "" && ref.UID == actual.UID {
				candidate = true
			}
			if ref.Kind == "StatefulSet" && ref.Name == names.StatefulSet {
				candidate = true
			}
		}
		if candidate {
			candidates[pod.Name] = pod
		}
	}
	out := make([]corev1.Pod, 0, len(candidates))
	for _, pod := range candidates {
		out = append(out, pod)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func reservedPodOrdinal(statefulSetName, podName string) bool {
	prefix := statefulSetName + "-"
	if !strings.HasPrefix(podName, prefix) {
		return false
	}
	ordinal := strings.TrimPrefix(podName, prefix)
	if ordinal == "" {
		return false
	}
	for _, char := range ordinal {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func workloadPodsSafe(actual *appsv1.StatefulSet, pods []corev1.Pod, requireSoleOwner bool) bool {
	if len(pods) == 0 {
		return true
	}
	if actual == nil || actual.UID == "" {
		return false
	}
	for i := range pods {
		pod := &pods[i]
		controllers := 0
		valid := false
		for j := range pod.OwnerReferences {
			ref := &pod.OwnerReferences[j]
			if ref.Controller == nil || !*ref.Controller {
				continue
			}
			controllers++
			valid = ref.APIVersion == "apps/v1" && ref.Kind == "StatefulSet" && ref.Name == actual.Name && ref.UID == actual.UID
		}
		if controllers != 1 || !valid || (requireSoleOwner && len(pod.OwnerReferences) != 1) {
			return false
		}
	}
	return true
}

func (r *KeaClusterReconciler) observeWorkload(ctx context.Context, parent *infrastructurev1alpha1.KeaCluster, names workloadNames) workloadObservation {
	var observation workloadObservation
	if parent == nil {
		err := fmt.Errorf("cannot observe workload without a KeaCluster")
		observation.ConfigMapErr, observation.ServiceErr, observation.StatefulSetErr, observation.PodsErr = err, err, err, err
		return observation
	}
	if r.APIReader == nil {
		err := fmt.Errorf("direct API reader is not configured")
		observation.ConfigMapErr, observation.ServiceErr, observation.StatefulSetErr, observation.PodsErr = err, err, err, err
		return observation
	}
	observe := func(object client.Object) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: parent.Namespace, Name: object.GetName()}, object)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil, err
	}
	configMap := &corev1.ConfigMap{}
	configMap.Name = names.ConfigMap
	found, err := observe(configMap)
	observation.ConfigMapErr = err
	if found {
		observation.ConfigMap = configMap
	}
	service := &corev1.Service{}
	service.Name = names.Service
	found, err = observe(service)
	observation.ServiceErr = err
	if found {
		observation.Service = service
	}
	statefulSet := &appsv1.StatefulSet{}
	statefulSet.Name = names.StatefulSet
	found, err = observe(statefulSet)
	observation.StatefulSetErr = err
	if found {
		observation.StatefulSet = statefulSet
	}
	if err := ctx.Err(); err != nil {
		observation.PodsErr = err
		return observation
	}
	podList := &corev1.PodList{}
	if err := r.APIReader.List(ctx, podList, client.InNamespace(parent.Namespace)); err != nil {
		observation.PodsErr = err
		return observation
	}
	observation.Pods = podList.Items
	return observation
}

func workloadConditions(parent *infrastructurev1alpha1.KeaCluster, names workloadNames, config workloadConfig, observation workloadObservation, artifactCondition metav1.Condition) []metav1.Condition {
	enabled, severity := effectiveWorkload(parent)
	oldReconciled := findWorkloadCondition(parent, "WorkloadReconciled")
	oldReady := findWorkloadCondition(parent, "WorkloadReady")
	reconciledStatus, reconciledReason, reconciledMessage := metav1.ConditionFalse, "ResourcesOutOfSync", "M2 workload resources are missing or differ from the desired configuration."
	readyStatus, readyReason, readyMessage := metav1.ConditionFalse, "RolloutPending", "The current workload revision has not yet produced two healthy process Pods."
	if _, err := generateKeaConfig(severity); err != nil {
		reconciledReason, reconciledMessage = "WorkloadBlocked", "The configured logging severity is unsupported; correct spec.workload.loggingSeverity."
		readyReason, readyMessage = "WorkloadBlocked", reconciledMessage
		return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, readyStatus, readyReason, readyMessage)
	}
	if enabled && workloadConfigNameCollides(parent, names) {
		reconciledReason, reconciledMessage = "NamingCollision", "The derived operational ConfigMap name collides with the identity ConfigMap; resolve the name collision manually."
		readyReason, readyMessage = "WorkloadBlocked", reconciledMessage
		return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, readyStatus, readyReason, readyMessage)
	}
	if !enabled {
		if workloadConfigNameCollides(parent, names) && observation.ConfigMap != nil {
			reconciledStatus, reconciledReason, reconciledMessage = metav1.ConditionFalse, "NamingCollision", "The operational ConfigMap name collides with the identity ConfigMap; preserve the identity object and resolve the collision manually."
			readyStatus, readyReason, readyMessage = metav1.ConditionFalse, "WorkloadBlocked", reconciledMessage
			return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, readyStatus, readyReason, readyMessage)
		}
		if observation.PodsErr != nil {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionUnknown, "ObservationFailed", "Namespace Pods could not be directly listed; workload cleanup remains unverified.", metav1.ConditionUnknown, "ObservationFailed", "Namespace Pods could not be directly listed; workload cleanup remains unverified.")
		}
		var configMapObject metav1.Object
		if observation.ConfigMap != nil {
			configMapObject = observation.ConfigMap
		}
		var serviceObject metav1.Object
		if observation.Service != nil {
			serviceObject = observation.Service
		}
		var statefulSetObject metav1.Object
		if observation.StatefulSet != nil {
			statefulSetObject = observation.StatefulSet
		}
		for _, child := range []struct {
			name   string
			object metav1.Object
			err    error
		}{{names.ConfigMap, configMapObject, observation.ConfigMapErr}, {names.Service, serviceObject, observation.ServiceErr}, {names.StatefulSet, statefulSetObject, observation.StatefulSetErr}} {
			if child.object != nil && !workloadSoleOwnedBy(child.object, parent) {
				reconciledStatus, reconciledReason, reconciledMessage = metav1.ConditionFalse, "CleanupOwnershipConflict", fmt.Sprintf("%s/%s is not solely owned by this KeaCluster; resolve its owner references manually before cleanup.", parent.Namespace, child.name)
				readyStatus, readyReason, readyMessage = metav1.ConditionFalse, "WorkloadBlocked", reconciledMessage
				return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, readyStatus, readyReason, readyMessage)
			}
			if child.err != nil {
				return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionUnknown, "ObservationFailed", "A workload resource could not be directly observed; retry after API access recovers.", metav1.ConditionUnknown, "ObservationFailed", "Workload cleanup cannot be confirmed because a direct resource observation failed.")
			}
			if child.object != nil {
				reconciledStatus, reconciledReason, reconciledMessage = metav1.ConditionFalse, "CleanupPending", fmt.Sprintf("%s/%s remains or is terminating; wait for verified workload cleanup to finish.", parent.Namespace, child.name)
				readyStatus, readyReason, readyMessage = metav1.ConditionFalse, "DisablePending", reconciledMessage
				return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, readyStatus, readyReason, readyMessage)
			}
		}
		if len(candidateWorkloadPods(parent, names, observation.StatefulSet, observation.Pods)) != 0 {
			reconciledStatus, reconciledReason, reconciledMessage = metav1.ConditionFalse, "OrphanedWorkloadPods", "Candidate workload Pods remain without a managed StatefulSet; resolve the orphaned Pods manually."
			readyStatus, readyReason, readyMessage = metav1.ConditionFalse, "WorkloadBlocked", reconciledMessage
			return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, readyStatus, readyReason, readyMessage)
		}
		return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionTrue, "WorkloadDisabled", "No M2 resources or candidate Pods remain.", metav1.ConditionTrue, "WorkloadDisabled", "The workload is disabled and no candidate Pods remain.")
	}
	if artifactCondition.Status != metav1.ConditionTrue {
		if artifactCondition.Status == metav1.ConditionUnknown {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionUnknown, "ObservationFailed", "The identity artifact is not currently verified; workload resources cannot be accepted.", metav1.ConditionUnknown, "ObservationFailed", "The identity artifact is not currently verified; process readiness cannot be accepted.")
		}
		return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionFalse, "WorkloadBlocked", "The identity artifact must be reconciled before the enabled workload can be accepted.", metav1.ConditionFalse, "WorkloadBlocked", "The identity artifact must be reconciled before process readiness can be accepted.")
	}
	if reason, message := observedWorkloadBlocker(parent, names, observation); reason != "" {
		return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionFalse, reason, message, metav1.ConditionFalse, "WorkloadBlocked", message)
	}
	if observation.ConfigMapErr != nil || observation.ServiceErr != nil || observation.StatefulSetErr != nil {
		return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionUnknown, "ObservationFailed", "A named workload resource could not be directly observed; retry after API access recovers.", metav1.ConditionUnknown, "ObservationFailed", "Workload readiness cannot be determined while a named resource observation is unresolved.")
	}
	candidates := candidateWorkloadPods(parent, names, observation.StatefulSet, observation.Pods)
	if observation.ConfigMap == nil || observation.Service == nil || observation.StatefulSet == nil {
		if observation.PodsErr != nil {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionUnknown, "ObservationFailed", "Namespace Pods could not be directly listed; creation safety is unverified.", metav1.ConditionUnknown, "ObservationFailed", "Namespace Pods could not be directly listed; creation safety is unverified.")
		}
		if observation.StatefulSet == nil && len(candidates) != 0 {
			message := "Candidate workload Pods exist without the expected StatefulSet; resolve the orphaned or colliding Pods manually."
			return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionFalse, "OrphanedWorkloadPods", message, metav1.ConditionFalse, "WorkloadBlocked", message)
		}
		return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionFalse, "ResourcesOutOfSync", "One or more enabled workload resources are missing and must be created after collision checks.", metav1.ConditionFalse, "RolloutPending", "The enabled workload resources or their Pods are still being created.")
	}
	wantConfig := desiredKeaConfig(parent, names, config)
	wantService := desiredHeadlessService(parent, names)
	wantSet := desiredKeaStatefulSet(parent, names, config)
	if !managedConfigurationEqual(observation.ConfigMap, wantConfig) || !managedServiceEqual(observation.Service, wantService) || !managedStatefulSetEqual(observation.StatefulSet, wantSet) {
		return finishWorkloadConditions(parent, oldReconciled, oldReady, metav1.ConditionFalse, "ResourcesOutOfSync", "One or more enabled workload resources differ from the approved desired shape.", metav1.ConditionFalse, "WorkloadBlocked", "Workload process readiness is withheld until managed resource drift is repaired.")
	}
	reconciledStatus, reconciledReason, reconciledMessage = metav1.ConditionTrue, "ResourcesInSync", "The operational ConfigMap, headless Service, and StatefulSet match the current desired workload."
	if observation.PodsErr != nil {
		return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionUnknown, "ObservationFailed", "Namespace Pods could not be directly listed; process readiness is unverified.")
	}
	if !workloadPodsSafe(observation.StatefulSet, candidates, false) {
		return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionFalse, "WorkloadBlocked", "A candidate workload Pod has invalid or foreign controller ownership; resolve it manually.")
	}
	if observation.StatefulSet.DeletionTimestamp != nil && !observation.StatefulSet.DeletionTimestamp.IsZero() {
		return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionFalse, "WorkloadBlocked", "The StatefulSet is terminating; wait for deletion and a fresh observation.")
	}
	if !statefulSetRolloutReady(observation.StatefulSet) {
		return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionFalse, "RolloutPending", "The StatefulSet has not observed and made all replicas available at one current revision.")
	}
	for _, pod := range candidates {
		if pod.Name != names.StatefulSet+"-0" && pod.Name != names.StatefulSet+"-1" {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionFalse, "PodDrift", "Unexpected candidate workload Pods exist; resolve the extra or higher-ordinal Pods manually.")
		}
	}
	if len(candidates) != 2 {
		return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionFalse, "RolloutPending", "The current StatefulSet revision does not yet have exactly two expected Pods.")
	}
	for ordinal := 0; ordinal < 2; ordinal++ {
		pod := candidateByName(candidates, fmt.Sprintf("%s-%d", names.StatefulSet, ordinal))
		if pod == nil || !pod.DeletionTimestamp.IsZero() {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionFalse, "RolloutPending", "An expected StatefulSet Pod is missing or terminating.")
		}
		if pod.Labels["controller-revision-hash"] != observation.StatefulSet.Status.UpdateRevision || !podMatchesConfiguration(pod, parent, config) {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionFalse, "PodDrift", "An expected Pod has a stale revision, configuration hash, image, or configuration environment value.")
		}
		if pod.Status.Phase != corev1.PodRunning {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionFalse, "ProcessUnhealthy", "An expected Pod is not in Running phase.")
		}
		ready, foundReady := podReadyCondition(pod)
		if !foundReady {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionUnknown, "ObservationFailed", "An expected Pod has no Ready condition observation.")
		}
		if !ready {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionFalse, "ProcessUnhealthy", "A process probe reports an expected Pod as not Ready.")
		}
		result, reason, message := containerProcessesHealthy(pod)
		if result != metav1.ConditionTrue {
			return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, result, reason, message)
		}
	}
	return finishWorkloadConditions(parent, oldReconciled, oldReady, reconciledStatus, reconciledReason, reconciledMessage, metav1.ConditionTrue, "ProcessesHealthy", "Both current-revision Pods report the expected running Kea processes.")
}

func observedWorkloadBlocker(parent *infrastructurev1alpha1.KeaCluster, names workloadNames, observation workloadObservation) (string, string) {
	if observation.ConfigMap != nil {
		if !workloadOwnedBy(observation.ConfigMap, parent) {
			return "OwnershipConflict", fmt.Sprintf("ConfigMap %s/%s lacks the current KeaCluster controller owner; resolve the conflict manually.", parent.Namespace, names.ConfigMap)
		}
		if observation.ConfigMap.Immutable != nil && *observation.ConfigMap.Immutable {
			return "ImmutableConfiguration", fmt.Sprintf("ConfigMap %s/%s is immutable; remove or correct it manually before enabling the workload.", parent.Namespace, names.ConfigMap)
		}
		if !observation.ConfigMap.DeletionTimestamp.IsZero() {
			return "CleanupPending", fmt.Sprintf("ConfigMap %s/%s is terminating; wait for deletion before continuing.", parent.Namespace, names.ConfigMap)
		}
	}
	if observation.Service != nil {
		if !workloadOwnedBy(observation.Service, parent) {
			return "OwnershipConflict", fmt.Sprintf("Service %s/%s lacks the current KeaCluster controller owner; resolve the conflict manually.", parent.Namespace, names.Service)
		}
		if !serviceCompatible(observation.Service, desiredHeadlessService(parent, names)) {
			return "IncompatibleResource", fmt.Sprintf("Service %s/%s has an incompatible allocated ClusterIP; remove it manually before enabling the workload.", parent.Namespace, names.Service)
		}
		if !observation.Service.DeletionTimestamp.IsZero() {
			return "CleanupPending", fmt.Sprintf("Service %s/%s is terminating; wait for deletion before continuing.", parent.Namespace, names.Service)
		}
	}
	if observation.StatefulSet != nil {
		if !workloadOwnedBy(observation.StatefulSet, parent) {
			return "OwnershipConflict", fmt.Sprintf("StatefulSet %s/%s lacks the current KeaCluster controller owner; resolve the conflict manually.", parent.Namespace, names.StatefulSet)
		}
		if !statefulSetCompatible(observation.StatefulSet, desiredKeaStatefulSet(parent, names, workloadConfig{})) {
			return "IncompatibleResource", fmt.Sprintf("StatefulSet %s/%s has incompatible immutable fields; remove or correct it manually.", parent.Namespace, names.StatefulSet)
		}
		if !observation.StatefulSet.DeletionTimestamp.IsZero() {
			return "CleanupPending", fmt.Sprintf("StatefulSet %s/%s is terminating; wait for deletion before continuing.", parent.Namespace, names.StatefulSet)
		}
	}
	return "", ""
}

func statefulSetRolloutReady(set *appsv1.StatefulSet) bool {
	return set != nil && set.DeletionTimestamp.IsZero() && set.Status.ObservedGeneration >= set.Generation && set.Spec.Replicas != nil && *set.Spec.Replicas == 2 &&
		set.Status.Replicas == 2 && set.Status.CurrentReplicas == 2 && set.Status.UpdatedReplicas == 2 && set.Status.ReadyReplicas == 2 && set.Status.AvailableReplicas == 2 &&
		set.Status.CurrentRevision != "" && set.Status.CurrentRevision == set.Status.UpdateRevision
}

func podMatchesConfiguration(pod *corev1.Pod, parent *infrastructurev1alpha1.KeaCluster, config workloadConfig) bool {
	if pod.Labels[clusterUIDLabel] != string(parent.UID) || pod.Labels[componentLabel] != "workload" || pod.Annotations[configHashAnnotation] != config.Hash || len(pod.Spec.Containers) != 2 {
		return false
	}
	want := map[string]struct {
		image string
		env   map[string]string
	}{
		"dhcp4": {image: keaDHCP4Image, env: map[string]string{"KEA_CONFIG_SHA256": config.DHCP4SHA256, "KEA_PIDFILE_DIR": "/run/kea/state", "KEA_LOCKFILE_DIR": "/run/kea/state", "KEA_DHCP_DATA_DIR": "/var/lib/kea/state"}},
		"dhcp6": {image: keaDHCP6Image, env: map[string]string{"KEA_CONFIG_SHA256": config.DHCP6SHA256, "KEA_PIDFILE_DIR": "/run/kea/state", "KEA_LOCKFILE_DIR": "/run/kea/state", "KEA_DHCP_DATA_DIR": "/var/lib/kea/state"}},
	}
	for _, container := range pod.Spec.Containers {
		expected, ok := want[container.Name]
		if !ok || container.Image != expected.image {
			return false
		}
		actualEnv := make(map[string]string, len(container.Env))
		if len(container.Env) != len(expected.env) {
			return false
		}
		for _, env := range container.Env {
			if env.ValueFrom != nil {
				return false
			}
			actualEnv[env.Name] = env.Value
		}
		if len(actualEnv) != len(expected.env) {
			return false
		}
		for name, value := range expected.env {
			if actualEnv[name] != value {
				return false
			}
		}
	}
	return true
}

func podReadyCondition(pod *corev1.Pod) (bool, bool) {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue, true
		}
	}
	return false, false
}

func containerProcessesHealthy(pod *corev1.Pod) (metav1.ConditionStatus, string, string) {
	want := map[string]bool{"dhcp4": false, "dhcp6": false}
	for _, status := range pod.Status.ContainerStatuses {
		if _, ok := want[status.Name]; !ok {
			continue
		}
		if status.ImageID == "" {
			return metav1.ConditionUnknown, "ObservationFailed", "A runtime container imageID is missing; process identity cannot be accepted."
		}
		if status.State.Running == nil || !status.Ready {
			return metav1.ConditionFalse, "ProcessUnhealthy", "A named Kea container is not Running and Ready."
		}
		want[status.Name] = true
	}
	for name, found := range want {
		if !found {
			return metav1.ConditionUnknown, "ObservationFailed", fmt.Sprintf("Runtime status for container %s is missing.", name)
		}
	}
	return metav1.ConditionTrue, "ProcessesHealthy", "Both named Kea containers report Running and Ready with runtime image identities."
}

func candidateByName(pods []corev1.Pod, name string) *corev1.Pod {
	for i := range pods {
		if pods[i].Name == name {
			return &pods[i]
		}
	}
	return nil
}

func findWorkloadCondition(parent *infrastructurev1alpha1.KeaCluster, conditionType string) *metav1.Condition {
	if parent == nil {
		return nil
	}
	for i := range parent.Status.Conditions {
		if parent.Status.Conditions[i].Type == conditionType {
			condition := parent.Status.Conditions[i]
			return &condition
		}
	}
	return nil
}

func finishWorkloadConditions(parent *infrastructurev1alpha1.KeaCluster, oldReconciled, oldReady *metav1.Condition, reconciledStatus metav1.ConditionStatus, reconciledReason, reconciledMessage string, readyStatus metav1.ConditionStatus, readyReason, readyMessage string) []metav1.Condition {
	return []metav1.Condition{
		makeWorkloadCondition(parent, oldReconciled, "WorkloadReconciled", reconciledStatus, reconciledReason, reconciledMessage),
		makeWorkloadCondition(parent, oldReady, "WorkloadReady", readyStatus, readyReason, readyMessage),
	}
}

func makeWorkloadCondition(parent *infrastructurev1alpha1.KeaCluster, old *metav1.Condition, conditionType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	condition := metav1.Condition{Type: conditionType, Status: status, Reason: reason, Message: message, ObservedGeneration: parent.Generation, LastTransitionTime: metav1.Now()}
	if old != nil && old.Status == status {
		condition.LastTransitionTime = old.LastTransitionTime
	}
	return condition
}
