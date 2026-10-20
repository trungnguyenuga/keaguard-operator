/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/
package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = func() bool {
	if selectedProfile.milestone != "m2" {
		return true
	}
	Describe("M2: Configuration rollout", func() {
		m2It("converges DEBUG source before template and rolls ordinal 1 before ordinal 0", m2CheckOrderedConfigRollout)
		m2It("keeps no-op and source drift from changing the running snapshots or Pod UIDs", m2CheckConfigNoOpAndSourceDrift)
	})
	Describe("M2: Configuration failure", func() {
		m2It("refuses a corrupted projected DHCPv4 file before daemon exec and recovers", m2CheckCorruptProjectionRecovery)
		m2It("fails a replacement mount when the DHCPv4 ConfigMap key is missing", func() { m2CheckMissingConfigKeyRecovery("kea-dhcp4.conf") })
		m2It("fails a replacement mount when the DHCPv6 ConfigMap key is missing", func() { m2CheckMissingConfigKeyRecovery("kea-dhcp6.conf") })
		m2It("fails a replacement mount when the operational ConfigMap is absent", m2CheckMissingConfigMapRecovery)
		m2It("refuses a separate test Pod with an incorrect expected configuration hash", m2CheckWrongExpectedHashPod)
	})
	Describe("M2: Stalled rollout", func() {
		m2It("keeps desired configuration pending under Baseline and recovers after policy repair", m2CheckStalledPolicyRollout)
		m2It("reports Pod image drift and recovers after checked manual replacement", m2CheckPodDriftManualRecovery)
	})
	return true
}()

type m2StalledPolicyObservation struct {
	Previous                      *infrastructurev1alpha1.KeaCluster
	Current                       *infrastructurev1alpha1.KeaCluster
	PreviousHash                  string
	DesiredHash                   string
	Config                        *corev1.ConfigMap
	StatefulSet                   *appsv1.StatefulSet
	PreviousStatefulSetUID        types.UID
	PreviousStatefulSetGeneration int64
	PreviousPodUIDs               map[string]types.UID
	Pods                          []corev1.Pod
}

func m2CheckStalledPolicyObservation(o m2StalledPolicyObservation) error {
	if o.Previous == nil || o.Current == nil || o.Config == nil || o.StatefulSet == nil || o.Previous.UID == "" || o.Previous.Generation < 1 ||
		o.Current.UID != o.Previous.UID || o.Current.Generation <= o.Previous.Generation || o.Current.Status.ObservedGeneration != o.Current.Generation ||
		o.Current.Spec == nil || o.Current.Spec.Workload == nil || o.Current.Spec.Workload.Enabled == false || o.Current.Spec.Workload.LoggingSeverity == nil || *o.Current.Spec.Workload.LoggingSeverity != "DEBUG" {
		return fmt.Errorf("stalled rollout lacks current desired parent identity/generation/configuration")
	}
	for _, expected := range []struct {
		kind, reason string
		status       metav1.ConditionStatus
	}{{"ArtifactReconciled", "ArtifactInSync", metav1.ConditionTrue}, {"WorkloadReconciled", "ResourcesInSync", metav1.ConditionTrue}, {"WorkloadReady", "RolloutPending", metav1.ConditionFalse}} {
		condition := meta.FindStatusCondition(o.Current.Status.Conditions, expected.kind)
		if condition == nil || condition.Status != expected.status || condition.Reason != expected.reason || condition.ObservedGeneration != o.Current.Generation {
			return fmt.Errorf("stalled rollout condition %s is not current %s/%s", expected.kind, expected.status, expected.reason)
		}
	}
	dhcp4Severity, dhcp4Err := m2ConfigSeverityValue([]byte(o.Config.Data["kea-dhcp4.conf"]))
	dhcp6Severity, dhcp6Err := m2ConfigSeverityValue([]byte(o.Config.Data["kea-dhcp6.conf"]))
	if o.Config.Namespace != o.Current.Namespace || o.Config.Name == "" || o.Config.UID == "" || o.Config.ResourceVersion == "" ||
		dhcp4Err != nil || dhcp6Err != nil || dhcp4Severity != "DEBUG" || dhcp6Severity != "DEBUG" ||
		o.DesiredHash == "" || o.DesiredHash == o.PreviousHash || m2ConfigMapHash(o.Config.Data) != o.DesiredHash {
		return fmt.Errorf("stalled rollout source did not retain the exact new DEBUG configuration hash")
	}
	configOwner := metav1.GetControllerOf(o.Config)
	if configOwner == nil || configOwner.APIVersion != infrastructurev1alpha1.GroupVersion.String() || configOwner.Kind != "KeaCluster" || configOwner.Name != o.Current.Name || configOwner.UID != o.Current.UID {
		return fmt.Errorf("stalled rollout ConfigMap owner identity differs from the scenario parent")
	}
	if o.StatefulSet.UID != o.PreviousStatefulSetUID || o.StatefulSet.Generation <= o.PreviousStatefulSetGeneration || o.StatefulSet.Status.ObservedGeneration != o.StatefulSet.Generation ||
		o.StatefulSet.Spec.Replicas == nil || *o.StatefulSet.Spec.Replicas != 2 || o.StatefulSet.Spec.PodManagementPolicy != appsv1.OrderedReadyPodManagement ||
		o.StatefulSet.Spec.Template.Annotations["keaguard.example/config-hash"] != o.DesiredHash || o.StatefulSet.Status.UpdateRevision == "" || o.StatefulSet.Status.CurrentRevision == "" || o.StatefulSet.Status.UpdateRevision == o.StatefulSet.Status.CurrentRevision {
		return fmt.Errorf("stalled rollout StatefulSet identity/revision/template does not retain the new desired revision")
	}
	if len(o.PreviousPodUIDs) != 2 || len(o.Pods) != 1 || o.PreviousPodUIDs[o.StatefulSet.Name+"-0"] == "" || o.PreviousPodUIDs[o.StatefulSet.Name+"-1"] == "" {
		return fmt.Errorf("stalled ordered rollout must retain only ordinal 0 and block ordinal 1 replacement")
	}
	seen := map[string]bool{}
	for _, pod := range o.Pods {
		if pod.Namespace != o.Current.Namespace || pod.Name != o.StatefulSet.Name+"-0" || pod.UID == "" || pod.UID != o.PreviousPodUIDs[pod.Name] || seen[pod.Name] || pod.DeletionTimestamp != nil {
			return fmt.Errorf("stalled rollout Pod identity changed or became ambiguous")
		}
		owner := metav1.GetControllerOf(&pod)
		if owner == nil || owner.APIVersion != appsv1.SchemeGroupVersion.String() || owner.Kind != "StatefulSet" || owner.Name != o.StatefulSet.Name || owner.UID != o.StatefulSet.UID {
			return fmt.Errorf("stalled rollout Pod owner identity changed")
		}
		seen[pod.Name] = true
	}
	if len(seen) != 1 {
		return fmt.Errorf("stalled rollout did not retain the exact original ordinal-0 Pod")
	}
	return nil
}

func m2ConfigSeverityValue(data []byte) (string, error) {
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return "", fmt.Errorf("decode projected Kea configuration: %w", err)
	}
	for _, family := range []string{"Dhcp4", "Dhcp6"} {
		root, ok := document[family].(map[string]any)
		if !ok {
			continue
		}
		loggers, ok := root["loggers"].([]any)
		if !ok || len(loggers) != 1 {
			return "", fmt.Errorf("%s configuration lacks one logger", family)
		}
		logger, ok := loggers[0].(map[string]any)
		if !ok {
			return "", fmt.Errorf("%s logger is not an object", family)
		}
		severity, ok := logger["severity"].(string)
		if !ok || severity == "" {
			return "", fmt.Errorf("%s logger has no severity", family)
		}
		if severity == "DEBUG" && logger["debuglevel"] != float64(99) {
			return "", fmt.Errorf("%s DEBUG logger lacks approved debuglevel", family)
		}
		if severity != "DEBUG" {
			if _, exists := logger["debuglevel"]; exists {
				return "", fmt.Errorf("%s non-DEBUG logger unexpectedly has debuglevel", family)
			}
		}
		return severity, nil
	}
	return "", fmt.Errorf("configuration lacks a recognized Kea family root")
}

type m2PodDriftObservation struct {
	Parent              *infrastructurev1alpha1.KeaCluster
	Current             *infrastructurev1alpha1.KeaCluster
	OriginalStatefulSet *appsv1.StatefulSet
	CurrentStatefulSet  *appsv1.StatefulSet
	OriginalPod         corev1.Pod
	CurrentPod          corev1.Pod
}

func m2CheckPodDriftObservation(o m2PodDriftObservation) error {
	if o.Parent == nil || o.Current == nil || o.OriginalStatefulSet == nil || o.CurrentStatefulSet == nil || o.Parent.UID == "" ||
		o.Current.UID != o.Parent.UID || o.Current.Generation != o.Parent.Generation || o.Current.Status.ObservedGeneration != o.Current.Generation {
		return fmt.Errorf("PodDrift observation lacks the exact current parent identity/generation")
	}
	for _, expected := range []struct {
		kind, reason string
		status       metav1.ConditionStatus
	}{{"ArtifactReconciled", "ArtifactInSync", metav1.ConditionTrue}, {"WorkloadReconciled", "ResourcesInSync", metav1.ConditionTrue}, {"WorkloadReady", "PodDrift", metav1.ConditionFalse}} {
		condition := meta.FindStatusCondition(o.Current.Status.Conditions, expected.kind)
		if condition == nil || condition.Status != expected.status || condition.Reason != expected.reason || condition.ObservedGeneration != o.Current.Generation {
			return fmt.Errorf("PodDrift condition %s is not current %s/%s", expected.kind, expected.status, expected.reason)
		}
	}
	if o.OriginalStatefulSet.UID == "" || o.CurrentStatefulSet.UID != o.OriginalStatefulSet.UID || o.CurrentStatefulSet.Generation != o.OriginalStatefulSet.Generation ||
		!reflect.DeepEqual(o.CurrentStatefulSet.Spec.Template, o.OriginalStatefulSet.Spec.Template) {
		return fmt.Errorf("PodDrift changed the desired StatefulSet template or identity")
	}
	if len(o.OriginalStatefulSet.Spec.Template.Spec.Containers) != 2 || !m2TemplateHasApprovedKeaImages(o.OriginalStatefulSet.Spec.Template.Spec.Containers) {
		return fmt.Errorf("PodDrift baseline template lacks the two approved immutable Kea images")
	}
	if o.OriginalPod.UID == "" || o.CurrentPod.UID != o.OriginalPod.UID || o.CurrentPod.Namespace != o.OriginalPod.Namespace || o.CurrentPod.Name != o.OriginalPod.Name ||
		o.CurrentPod.DeletionTimestamp != nil || o.CurrentPod.Labels["keaguard.example/cluster-uid"] != string(o.Parent.UID) {
		return fmt.Errorf("PodDrift target Pod incarnation/cluster identity changed")
	}
	oldOwner, currentOwner := metav1.GetControllerOf(&o.OriginalPod), metav1.GetControllerOf(&o.CurrentPod)
	if oldOwner == nil || currentOwner == nil || oldOwner.APIVersion != appsv1.SchemeGroupVersion.String() || oldOwner.Kind != "StatefulSet" ||
		oldOwner.Name != o.OriginalStatefulSet.Name || oldOwner.UID != o.OriginalStatefulSet.UID || !reflect.DeepEqual(oldOwner, currentOwner) {
		return fmt.Errorf("PodDrift target Pod owner chain changed")
	}
	if len(o.CurrentPod.Spec.Containers) != len(o.OriginalPod.Spec.Containers) {
		return fmt.Errorf("PodDrift changed the Pod container set")
	}
	mutatedSpec := o.CurrentPod.Spec.DeepCopy()
	faultedDHCP4 := false
	for i := range o.OriginalPod.Spec.Containers {
		original := o.OriginalPod.Spec.Containers[i]
		if mutatedSpec.Containers[i].Name != original.Name {
			return fmt.Errorf("PodDrift changed container ordering or identity")
		}
		if original.Name == "dhcp4" {
			if !m2IsDifferentDigestInSameRepository(mutatedSpec.Containers[i].Image, m2KeaDHCP4Image) {
				return fmt.Errorf("PodDrift DHCPv4 fault image is not a different full digest in the approved repository")
			}
			mutatedSpec.Containers[i].Image = original.Image
			faultedDHCP4 = true
		} else if mutatedSpec.Containers[i].Image != original.Image {
			return fmt.Errorf("PodDrift changed the sibling container image")
		}
	}
	if !faultedDHCP4 || !reflect.DeepEqual(*mutatedSpec, o.OriginalPod.Spec) {
		return fmt.Errorf("PodDrift changed more than the one test-only DHCPv4 image")
	}
	return nil
}

func m2TemplateHasApprovedKeaImages(containers []corev1.Container) bool {
	images := map[string]string{}
	for _, container := range containers {
		if _, exists := images[container.Name]; exists {
			return false
		}
		images[container.Name] = container.Image
	}
	return len(images) == 2 && images["dhcp4"] == m2KeaDHCP4Image && images["dhcp6"] == m2KeaDHCP6Image
}

func m2NonexistentImageReference(approved string) (string, error) {
	if approved != m2KeaDHCP4Image || !strings.Contains(approved, "@sha256:") {
		return "", fmt.Errorf("PodDrift test requires the exact approved DHCPv4 immutable image")
	}
	repository := strings.SplitN(approved, "@sha256:", 2)[0]
	return repository + "@sha256:" + strings.Repeat("0", 64), nil
}

func m2PodIdentitySummary(pods []corev1.Pod) []string {
	items := make([]string, 0, len(pods))
	for _, pod := range pods {
		items = append(items, fmt.Sprintf("%s=%s@%s", pod.Name, pod.UID, pod.ResourceVersion))
	}
	sort.Strings(items)
	return items
}

func m2IsDifferentDigestInSameRepository(candidate, approved string) bool {
	parts := strings.SplitN(approved, "@sha256:", 2)
	candidateParts := strings.SplitN(candidate, "@sha256:", 2)
	return len(parts) == 2 && len(candidateParts) == 2 && candidateParts[0] == parts[0] &&
		m2FullHexID(candidateParts[1]) && candidateParts[1] != parts[1]
}

func m2CheckStalledPolicyRollout() {
	parent, originalPods, initial, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
	m2WaitRuntimeConditions(parent, initial.Hash)
	Expect(m2VerifyNamespaceReceipt(labctx)).To(Succeed())
	Expect(m2VerifyManagerDeployment(labctx, m2ActiveScenario.ExpectedImage, m2ActiveScenario.ExpectedImageID)).To(Succeed())
	originalParent := &infrastructurev1alpha1.KeaCluster{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(parent), originalParent)).To(Succeed())
	configName, _, setName := m2NamesFor(parent)
	originalConfig := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, originalConfig)).To(Succeed())
	originalSetSnapshot := &appsv1.StatefulSet{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, originalSetSnapshot)).To(Succeed())
	originalUIDs := m2PodUIDs(originalPods)
	managerPod := t14GetManagerPod(labctx)
	fmt.Fprintf(GinkgoWriter, "M2_STALLED_POLICY_BEFORE parent=%s/%s uid=%s rv=%s generation=%d config=%s uid=%s rv=%s hash=%s statefulSet=%s uid=%s rv=%s generation=%d revision=%s pods=%v managerUID=%s managerPodUID=%s managerPodRV=%s image=%s imageID=%s namespaceUID=%s policy=%v\n",
		parent.Namespace, parent.Name, parent.UID, originalParent.ResourceVersion, originalParent.Generation,
		originalConfig.Name, originalConfig.UID, originalConfig.ResourceVersion, initial.Hash,
		originalSetSnapshot.Name, originalSetSnapshot.UID, originalSetSnapshot.ResourceVersion, originalSetSnapshot.Generation, originalSetSnapshot.Status.UpdateRevision,
		m2PodIdentitySummary(originalPods), m2ActiveScenario.Manager.UID, managerPod.UID, managerPod.ResourceVersion, m2ActiveScenario.ExpectedImage, m2ActiveScenario.ExpectedImageID,
		m2ActiveScenario.NamespaceUIDs[runtimeNamespace], m2ActiveScenario.PolicyLabels[runtimeNamespace])

	baseline := map[string]string{"pod-security.kubernetes.io/enforce": "baseline", "pod-security.kubernetes.io/enforce-version": "v1.37"}
	Expect(m2ActiveScenario.setNamespacePolicy(labctx, runtimeNamespace, baseline)).To(Succeed())
	current := &infrastructurev1alpha1.KeaCluster{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(parent), current)).To(Succeed())
	debug := "DEBUG"
	current.Spec.Workload.LoggingSeverity = &debug
	Expect(m2UpdateObject(labctx, current, "absent")).To(Succeed())

	var failedCreate *corev1.Event
	Eventually(func() error {
		events, err := adminset.CoreV1().Events(runtimeNamespace).List(labctx, metav1.ListOptions{})
		if err != nil {
			return err
		}
		for i := range events.Items {
			event := &events.Items[i]
			if event.InvolvedObject.UID == originalSetSnapshot.UID && event.Reason == "FailedCreate" && strings.Contains(event.Message, "NET_RAW") {
				failedCreate = event.DeepCopy()
				return nil
			}
		}
		return fmt.Errorf("no StatefulSet FailedCreate event naming NET_RAW has been observed")
	}, 120*time.Second, time.Second).Should(Succeed())

	var desiredHash string
	Eventually(func() error {
		config := &corev1.ConfigMap{}
		set := &appsv1.StatefulSet{}
		if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, config); err != nil {
			return err
		}
		if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, set); err != nil {
			return err
		}
		hash := m2ConfigMapHash(config.Data)
		if hash == "" || hash == initial.Hash || m2ConfigSeverity([]byte(config.Data["kea-dhcp4.conf"])) != "DEBUG" || set.Spec.Template.Annotations["keaguard.example/config-hash"] != hash {
			return fmt.Errorf("DEBUG source or desired StatefulSet template hash has not converged")
		}
		desiredHash = hash
		return nil
	}, 60*time.Second, 500*time.Millisecond).Should(Succeed())

	readObservation := func() (m2StalledPolicyObservation, error) {
		observedParent := &infrastructurev1alpha1.KeaCluster{}
		observedConfig := &corev1.ConfigMap{}
		observedSet := &appsv1.StatefulSet{}
		if err := admin.Get(labctx, client.ObjectKeyFromObject(parent), observedParent); err != nil {
			return m2StalledPolicyObservation{}, err
		}
		if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, observedConfig); err != nil {
			return m2StalledPolicyObservation{}, err
		}
		if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, observedSet); err != nil {
			return m2StalledPolicyObservation{}, err
		}
		podList := &corev1.PodList{}
		if err := admin.List(labctx, podList, client.InNamespace(runtimeNamespace), client.MatchingLabels{"keaguard.example/cluster-uid": string(parent.UID)}); err != nil {
			return m2StalledPolicyObservation{}, err
		}
		return m2StalledPolicyObservation{
			Previous: originalParent, Current: observedParent, PreviousHash: initial.Hash, DesiredHash: desiredHash,
			Config: observedConfig, StatefulSet: observedSet, PreviousStatefulSetUID: originalSetSnapshot.UID,
			PreviousStatefulSetGeneration: originalSetSnapshot.Generation, PreviousPodUIDs: originalUIDs, Pods: podList.Items,
		}, nil
	}
	Eventually(func() error {
		observation, err := readObservation()
		if err != nil {
			return err
		}
		return m2CheckStalledPolicyObservation(observation)
	}, 60*time.Second, time.Second).Should(Succeed())
	for interval := 1; interval <= 2; interval++ {
		select {
		case <-labctx.Done():
			Fail(fmt.Sprintf("stalled-rollout observation cancelled after FailedCreate: %v", labctx.Err()))
		case <-time.After(5 * time.Second):
		}
		observation, err := readObservation()
		Expect(err).NotTo(HaveOccurred())
		Expect(m2CheckStalledPolicyObservation(observation)).To(Succeed(), "desired DEBUG bytes/hash and old Pod UIDs must remain unchanged at five-second interval %d after FailedCreate", interval)
		for _, oldPod := range observation.Pods {
			for _, file := range []struct{ container, path, hash string }{{"dhcp4", "/run/kea/state/kea-dhcp4.conf", initial.file4}, {"dhcp6", "/run/kea/state/kea-dhcp6.conf", initial.file6}} {
				out, execErr := m2ExecOutput(oldPod.Name, file.container, "sha256sum", file.path)
				Expect(execErr).NotTo(HaveOccurred())
				Expect(strings.Fields(string(out))).To(HaveLen(2))
				Expect(strings.Fields(string(out))[0]).To(Equal(file.hash), "existing admitted Pods retain their original snapshots while the desired source stays DEBUG")
			}
		}
	}

	Expect(m2RestoreNamespacePolicy(labctx, m2ActiveScenario.NamespaceSnapshots[runtimeNamespace], baseline)).To(Succeed())
	Expect(m2VerifyNamespaceReceipt(labctx)).To(Succeed())
	// Policy repair is administrator-controlled. The CR stays on its new
	// desired DEBUG inputs and native StatefulSet progress completes them.
	m2WaitRuntimeConditions(parent, desiredHash)
	var finalPods []corev1.Pod
	Eventually(func() error {
		set := &appsv1.StatefulSet{}
		if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, set); err != nil {
			return err
		}
		if set.UID != originalSetSnapshot.UID || set.Status.ObservedGeneration != set.Generation || set.Status.UpdateRevision == "" || set.Status.UpdateRevision != set.Status.CurrentRevision {
			return fmt.Errorf("native StatefulSet rollout has not converged on one current revision")
		}
		podList := &corev1.PodList{}
		if err := admin.List(labctx, podList, client.InNamespace(runtimeNamespace), client.MatchingLabels{"keaguard.example/cluster-uid": string(parent.UID)}); err != nil {
			return err
		}
		if len(podList.Items) != 2 {
			return fmt.Errorf("native rollout has %d Pods, want 2", len(podList.Items))
		}
		for _, pod := range podList.Items {
			if pod.UID == originalUIDs[pod.Name] || !podReady(&pod) || pod.Labels["controller-revision-hash"] != set.Status.UpdateRevision {
				return fmt.Errorf("native replacement Pod %s has not become ready on the new revision", pod.Name)
			}
		}
		finalPods = podList.Items
		return nil
	}, 120*time.Second, time.Second).Should(Succeed())
	currentConfig := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, currentConfig)).To(Succeed())
	Expect(m2ConfigMapHash(currentConfig.Data)).To(Equal(desiredHash))
	for _, pod := range finalPods {
		for _, file := range []struct{ container, path, name string }{{"dhcp4", "/run/kea/state/kea-dhcp4.conf", "kea-dhcp4.conf"}, {"dhcp6", "/run/kea/state/kea-dhcp6.conf", "kea-dhcp6.conf"}} {
			out, err := m2ExecOutput(pod.Name, file.container, "sha256sum", file.path)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Fields(string(out))).To(HaveLen(2))
			Expect(strings.Fields(string(out))[0]).To(Equal(m2SHA256([]byte(currentConfig.Data[file.name]))))
		}
	}
	m2VerifyRuntimeConditions(parent, desiredHash)
	fmt.Fprintf(GinkgoWriter, "M2_STALLED_POLICY_RECOVERED parentUID=%s failedCreateEvent=%s/%s eventUID=%s namespacePolicyRestored=true oldPods=%v newPods=%v desiredHash=%s manualPolicyRepair=true\n",
		parent.UID, failedCreate.InvolvedObject.Kind, failedCreate.InvolvedObject.Name, failedCreate.UID, originalUIDs, m2PodUIDs(finalPods), desiredHash)
}

func m2CheckPodDriftManualRecovery() {
	parent, initialPods, initial, originalSet := m2CreateRuntimeFixture("INFO", 120*time.Second)
	m2WaitRuntimeConditions(parent, initial.Hash)
	Expect(m2VerifyNamespaceReceipt(labctx)).To(Succeed())
	Expect(m2VerifyManagerDeployment(labctx, m2ActiveScenario.ExpectedImage, m2ActiveScenario.ExpectedImageID)).To(Succeed())
	originalParent := &infrastructurev1alpha1.KeaCluster{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(parent), originalParent)).To(Succeed())
	originalSetSnapshot := &appsv1.StatefulSet{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(&originalSet), originalSetSnapshot)).To(Succeed())
	originalPodsByName := map[string]corev1.Pod{}
	for _, pod := range initialPods {
		originalPodsByName[pod.Name] = *pod.DeepCopy()
	}
	target := initialPods[0]
	managerPod := t14GetManagerPod(labctx)
	configName, _, _ := m2NamesFor(parent)
	originalConfig := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, originalConfig)).To(Succeed())
	fmt.Fprintf(GinkgoWriter, "M2_POD_DRIFT_BEFORE parent=%s/%s uid=%s rv=%s generation=%d config=%s uid=%s rv=%s hash=%s statefulSet=%s uid=%s rv=%s generation=%d revision=%s pods=%v managerUID=%s managerPodUID=%s managerPodRV=%s image=%s imageID=%s configHash=%s namespaceUID=%s policy=%v\n",
		parent.Namespace, parent.Name, parent.UID, originalParent.ResourceVersion, originalParent.Generation,
		originalConfig.Name, originalConfig.UID, originalConfig.ResourceVersion, initial.Hash,
		originalSetSnapshot.Name, originalSetSnapshot.UID, originalSetSnapshot.ResourceVersion, originalSetSnapshot.Generation, originalSetSnapshot.Status.UpdateRevision,
		m2PodIdentitySummary(initialPods), m2ActiveScenario.Manager.UID, managerPod.UID, managerPod.ResourceVersion, m2ActiveScenario.ExpectedImage, m2ActiveScenario.ExpectedImageID, initial.Hash,
		m2ActiveScenario.NamespaceUIDs[runtimeNamespace], m2ActiveScenario.PolicyLabels[runtimeNamespace])
	badImage, err := m2NonexistentImageReference(m2KeaDHCP4Image)
	Expect(err).NotTo(HaveOccurred())
	currentPod := &corev1.Pod{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(&target), currentPod)).To(Succeed())
	Expect(currentPod.UID).To(Equal(target.UID))
	Expect(currentPod.ResourceVersion).NotTo(BeEmpty())
	owner := metav1.GetControllerOf(currentPod)
	Expect(owner).NotTo(BeNil())
	if owner != nil {
		Expect(owner.APIVersion).To(Equal(appsv1.SchemeGroupVersion.String()))
		Expect(owner.Kind).To(Equal("StatefulSet"))
		Expect(owner.Name).To(Equal(originalSetSnapshot.Name))
		Expect(owner.UID).To(Equal(originalSetSnapshot.UID))
	}
	base := currentPod.DeepCopy()
	foundDHCP4 := false
	for i := range currentPod.Spec.Containers {
		if currentPod.Spec.Containers[i].Name == "dhcp4" {
			Expect(currentPod.Spec.Containers[i].Image).To(Equal(m2KeaDHCP4Image))
			currentPod.Spec.Containers[i].Image = badImage
			foundDHCP4 = true
		}
	}
	Expect(foundDHCP4).To(BeTrue())
	uidBeforeFault, rvBeforeFault := currentPod.UID, currentPod.ResourceVersion
	Expect(admin.Patch(labctx, currentPod, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))).To(Succeed())

	var driftSample m2PodDriftObservation
	Eventually(func() error {
		observedParent := &infrastructurev1alpha1.KeaCluster{}
		observedSet := &appsv1.StatefulSet{}
		observedPod := &corev1.Pod{}
		if err := admin.Get(labctx, client.ObjectKeyFromObject(parent), observedParent); err != nil {
			return err
		}
		if err := admin.Get(labctx, client.ObjectKeyFromObject(originalSetSnapshot), observedSet); err != nil {
			return err
		}
		if err := admin.Get(labctx, client.ObjectKeyFromObject(&target), observedPod); err != nil {
			return err
		}
		driftSample = m2PodDriftObservation{Parent: originalParent, Current: observedParent, OriginalStatefulSet: originalSetSnapshot, CurrentStatefulSet: observedSet, OriginalPod: target, CurrentPod: *observedPod}
		return m2CheckPodDriftObservation(driftSample)
	}, 60*time.Second, time.Second).Should(Succeed(), "the controller must report PodDrift from the live Pod spec without relying on stale Ready status")
	Expect(driftSample.CurrentPod.UID).To(Equal(uidBeforeFault))
	Expect(driftSample.CurrentPod.ResourceVersion).NotTo(Equal(rvBeforeFault), "the live Pod must be observed after our exact image mutation")
	staleReadyAtDetection := podReady(&driftSample.CurrentPod)

	var pullFailure string
	Eventually(func() error {
		observed := &corev1.Pod{}
		if err := admin.Get(labctx, client.ObjectKeyFromObject(&target), observed); err != nil {
			return err
		}
		if observed.UID != uidBeforeFault || observed.DeletionTimestamp != nil {
			return fmt.Errorf("faulted Pod incarnation changed before administrator recovery")
		}
		if len(observed.Spec.Containers) < 1 || observed.Spec.Containers[0].Image != badImage {
			return fmt.Errorf("controller edited the test-only faulted Pod spec")
		}
		for _, status := range observed.Status.ContainerStatuses {
			if status.Name == "dhcp4" && status.State.Waiting != nil && (status.State.Waiting.Reason == "ErrImagePull" || status.State.Waiting.Reason == "ImagePullBackOff") {
				pullFailure = status.State.Waiting.Reason + ":" + status.State.Waiting.Message
				return nil
			}
		}
		return fmt.Errorf("kubelet has not independently reported a failed pull for the nonexistent digest")
	}, 45*time.Second, time.Second).Should(Succeed())

	currentSet := &appsv1.StatefulSet{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(originalSetSnapshot), currentSet)).To(Succeed())
	Expect(currentSet.UID).To(Equal(originalSetSnapshot.UID))
	Expect(reflect.DeepEqual(currentSet.Spec.Template, originalSetSnapshot.Spec.Template)).To(BeTrue(), "operator must not substitute the template image")
	faultedPod := &corev1.Pod{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(&target), faultedPod)).To(Succeed())
	Expect(faultedPod.UID).To(Equal(uidBeforeFault))
	Expect(faultedPod.ResourceVersion).NotTo(BeEmpty())
	Expect(faultedPod.Spec.Containers[0].Image).To(Equal(badImage))
	owner = metav1.GetControllerOf(faultedPod)
	Expect(owner).NotTo(BeNil())
	if owner != nil {
		Expect(owner.UID).To(Equal(originalSetSnapshot.UID))
		Expect(owner.Name).To(Equal(originalSetSnapshot.Name))
	}
	deleteUID, deleteRV := faultedPod.UID, faultedPod.ResourceVersion
	deleteCtx, deleteCancel := context.WithTimeout(labctx, 10*time.Second)
	deleteErr := admin.Delete(deleteCtx, faultedPod, client.Preconditions{UID: &deleteUID, ResourceVersion: &deleteRV})
	deleteCancel()
	Expect(deleteErr).NotTo(HaveOccurred(), "administrator conditionally deletes only the verified failed Pod UID/resourceVersion")

	var replacement corev1.Pod
	Eventually(func() error {
		candidate := &corev1.Pod{}
		if err := admin.Get(labctx, client.ObjectKeyFromObject(&target), candidate); err != nil {
			return err
		}
		if candidate.UID == deleteUID {
			return fmt.Errorf("native StatefulSet has not replaced the exact administrator-deleted Pod")
		}
		if err := m2CheckNativePodSuccessor(faultedPod, candidate, currentSet, parent); err != nil {
			return err
		}
		replacement = *candidate.DeepCopy()
		return nil
	}, 120*time.Second, time.Second).Should(Succeed())
	otherName := initialPods[1].Name
	other := &corev1.Pod{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: otherName}, other)).To(Succeed())
	Expect(other.UID).To(Equal(originalPodsByName[otherName].UID), "manual recovery may replace only the exact drifted Pod")
	m2WaitRuntimeConditions(parent, initial.Hash)
	finalPods := m2SortedPods(parent)
	Expect(finalPods).To(HaveLen(2))
	for _, pod := range finalPods {
		Expect(podReady(&pod)).To(BeTrue())
		for _, file := range []struct{ container, path, name string }{{"dhcp4", "/run/kea/state/kea-dhcp4.conf", "kea-dhcp4.conf"}, {"dhcp6", "/run/kea/state/kea-dhcp6.conf", "kea-dhcp6.conf"}} {
			out, execErr := m2ExecOutput(pod.Name, file.container, "sha256sum", file.path)
			Expect(execErr).NotTo(HaveOccurred())
			Expect(strings.Fields(string(out))).To(HaveLen(2))
			Expect(strings.Fields(string(out))[0]).To(Equal(m2SHA256(initial.files[file.name])))
		}
	}
	m2VerifyRuntimeConditions(parent, initial.Hash)
	fmt.Fprintf(GinkgoWriter, "M2_POD_DRIFT_RECOVERED parentUID=%s badPodUID=%s badPodRV=%s badDigest=%s pullFailure=%s staleReadyAtDetection=%t replacementUID=%s otherPodUID=%s templateUnchanged=true manualPodDelete=true configHash=%s\n",
		parent.UID, deleteUID, deleteRV, badImage, m2RedactEvidence(pullFailure), staleReadyAtDetection, replacement.UID, other.UID, initial.Hash)
}

func m2CheckOrderedConfigRollout() {
	parent, oldPods, initial, initialSet := m2CreateRuntimeFixture("INFO", 120*time.Second)
	Expect(initialSet.Spec.MinReadySeconds).To(Equal(int32(5)))
	Expect(initialSet.Spec.PodManagementPolicy).To(Equal(appsv1.OrderedReadyPodManagement))
	oldUIDs := map[string]types.UID{}
	for _, pod := range oldPods {
		oldUIDs[pod.Name] = pod.UID
	}
	current := &infrastructurev1alpha1.KeaCluster{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(parent), current)).To(Succeed())
	debug := "DEBUG"
	current.Spec.Workload.LoggingSeverity = &debug
	Expect(m2UpdateObject(labctx, current, "absent")).To(Succeed())
	configName, _, setName := m2NamesFor(parent)
	deadline := time.Now().Add(100 * time.Second)
	sawSourceBeforeTemplate := false
	var ordinal1ReadyAt, ordinal0ChangedAt time.Time
	var finalPods []corev1.Pod
	for time.Now().Before(deadline) {
		cm := &corev1.ConfigMap{}
		set := &appsv1.StatefulSet{}
		if admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, cm) != nil || admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, set) != nil {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		desiredHash := m2ConfigMapHash(cm.Data)
		if desiredHash != "" && desiredHash != initial.Hash && m2ConfigSeverity([]byte(cm.Data["kea-dhcp4.conf"])) == "DEBUG" &&
			set.Spec.Template.Annotations["keaguard.example/config-hash"] == initial.Hash {
			sawSourceBeforeTemplate = true
		}
		pods := m2SortedPods(parent)
		byOrdinal := map[string]corev1.Pod{}
		for _, pod := range pods {
			byOrdinal[pod.Name] = pod
		}
		ordinal0 := byOrdinal[setName+"-0"]
		ordinal1 := byOrdinal[setName+"-1"]
		if ordinal1.UID != "" && ordinal1.UID != oldUIDs[ordinal1.Name] && podReady(&ordinal1) && ordinal1ReadyAt.IsZero() {
			ordinal1ReadyAt, _ = m2PodReadyTransitionTime(ordinal1)
		}
		if ordinal0.UID != "" && ordinal0.UID != oldUIDs[ordinal0.Name] {
			if ordinal0ChangedAt.IsZero() {
				ordinal0ChangedAt = ordinal0.CreationTimestamp.Time
			}
			finalPods = pods
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	Expect(sawSourceBeforeTemplate).To(BeTrue(), "the generated source ConfigMap must converge before its template hash advances")
	Expect(ordinal1ReadyAt).NotTo(BeZero(), "ordinal 1 must become ready on the new revision before ordinal 0 changes")
	Expect(ordinal0ChangedAt).NotTo(BeZero(), "ordinal 0 did not roll after ordinal 1")
	Expect(m2MinReadyElapsed(ordinal1ReadyAt, ordinal0ChangedAt, initialSet.Spec.MinReadySeconds)).To(BeTrue(), "Kubernetes Ready transition and replacement creation timestamps must prove minReadySeconds elapsed before the ordered next replacement")
	Expect(finalPods).To(HaveLen(2))
	for i := range finalPods {
		readyPod, err := m2WaitExactPodReady(finalPods[i], 90*time.Second)
		Expect(err).NotTo(HaveOccurred(), "replacement Pod %s UID %s must be Ready before reading its mounted configuration", finalPods[i].Name, finalPods[i].UID)
		Expect(readyPod.UID).To(Equal(finalPods[i].UID), "configuration checks must retain the observed replacement incarnation")
		finalPods[i] = readyPod
	}
	debugCM := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, debugCM)).To(Succeed())
	wantHash := m2ConfigMapHash(debugCM.Data)
	Expect(wantHash).NotTo(BeEmpty())
	Expect(m2ConfigSeverity([]byte(debugCM.Data["kea-dhcp4.conf"]))).To(Equal("DEBUG"))
	set := &appsv1.StatefulSet{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, set)).To(Succeed())
	Expect(set.Generation).To(BeNumerically(">", initialSet.Generation))
	Expect(set.Status.ObservedGeneration).To(Equal(set.Generation))
	Expect(set.Status.UpdateRevision).NotTo(Equal(initialSet.Status.UpdateRevision))
	for _, pod := range finalPods {
		Expect(pod.UID).NotTo(Equal(oldUIDs[pod.Name]))
		Expect(pod.Labels["controller-revision-hash"]).To(Equal(set.Status.UpdateRevision))
		for _, container := range []string{"dhcp4", "dhcp6"} {
			path := "/run/kea/state/kea-" + container + ".conf"
			actual, err := m2ExecOutput(pod.Name, container, "sha256sum", path)
			Expect(err).NotTo(HaveOccurred(), "kubectl exec sha256sum for %s/%s %s returned %q", pod.Name, container, path, m2RedactEvidence(string(actual)))
			want := debugCM.Data["kea-"+container+".conf"]
			Expect(strings.Fields(string(actual))).To(HaveLen(2))
			Expect(strings.Fields(string(actual))[0]).To(Equal(m2SHA256([]byte(want))))
		}
	}
	m2WaitRuntimeConditions(parent, wantHash)
	m2VerifyRuntimeConditions(parent, wantHash)
	_, _, stableSet := m2NamesFor(parent)
	Expect(stableSet).To(Equal(setName))
	_, tooling := m2VerifyRuntimeContainers(parent, finalPods, m2RuntimeConfig{files: map[string][]byte{"kea-dhcp4.conf": []byte(debugCM.Data["kea-dhcp4.conf"]), "kea-dhcp6.conf": []byte(debugCM.Data["kea-dhcp6.conf"])}, severity: "DEBUG", file4: m2SHA256([]byte(debugCM.Data["kea-dhcp4.conf"])), file6: m2SHA256([]byte(debugCM.Data["kea-dhcp6.conf"])), Hash: wantHash}, *set, true)
	Expect(tooling).NotTo(BeEmpty())
	fmt.Fprintf(GinkgoWriter, "M2_CONFIG_ROLLOUT parentUID=%s oldRevision=%s newRevision=%s oldPods=%v newPods=%v configHash=%s sourceBeforeTemplate=%t ordinal1Ready=%s ordinal0Changed=%s minReadySeconds=%d\n", parent.UID, initialSet.Status.UpdateRevision, set.Status.UpdateRevision, oldUIDs, m2PodUIDs(finalPods), wantHash, sawSourceBeforeTemplate, ordinal1ReadyAt.UTC().Format(time.RFC3339Nano), ordinal0ChangedAt.UTC().Format(time.RFC3339Nano), set.Spec.MinReadySeconds)
}

func m2CheckConfigNoOpAndSourceDrift() {
	parent, pods, config, set := m2CreateRuntimeFixture("INFO", 120*time.Second)
	configName, _, setName := m2NamesFor(parent)
	originalUIDs := m2PodUIDs(pods)
	originalGeneration, originalRevision := set.Generation, set.Status.UpdateRevision
	for i := 0; i < 3; i++ {
		current := &infrastructurev1alpha1.KeaCluster{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(parent), current)).To(Succeed())
		Expect(m2UpdateObject(labctx, current, "absent")).To(Succeed())
		time.Sleep(2 * time.Second)
		actualSet := &appsv1.StatefulSet{}
		actualCM := &corev1.ConfigMap{}
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, actualSet)).To(Succeed())
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, actualCM)).To(Succeed())
		Expect(actualSet.Generation).To(Equal(originalGeneration))
		Expect(actualSet.Status.UpdateRevision).To(Equal(originalRevision))
		Expect(m2PodUIDs(m2SortedPods(parent))).To(Equal(originalUIDs))
		Expect(m2ConfigMapHash(actualCM.Data)).To(Equal(config.Hash))
	}
	currentCM := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, currentCM)).To(Succeed())
	corrupted := currentCM.DeepCopy()
	corrupted.Data["kea-dhcp4.conf"] += "\n# authorized external drift probe\n"
	parentIdentity, err := m2IdentityFor(parent)
	Expect(err).NotTo(HaveOccurred())
	Expect(m2ActiveScenario.UpdateGeneratedConfigMap(labctx, corrupted, parentIdentity)).To(Succeed())
	observedDrift := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, observedDrift)).To(Succeed())
	Expect(observedDrift.UID).To(Equal(currentCM.UID))
	Expect(observedDrift.Data["kea-dhcp4.conf"]).To(Equal(corrupted.Data["kea-dhcp4.conf"]))
	for _, pod := range pods {
		out, err := m2ExecOutput(pod.Name, "dhcp4", "sha256sum", "/run/kea/state/kea-dhcp4.conf")
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Fields(string(out))[0]).To(Equal(config.file4), "loaded snapshot must remain the original bytes while the source ConfigMap is drifted")
	}
	Eventually(func(g Gomega) {
		repaired := &corev1.ConfigMap{}
		g.Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, repaired)).To(Succeed())
		g.Expect(repaired.UID).To(Equal(currentCM.UID))
		g.Expect(repaired.Data).To(Equal(map[string]string{"kea-dhcp4.conf": string(config.files["kea-dhcp4.conf"]), "kea-dhcp6.conf": string(config.files["kea-dhcp6.conf"])}))
	}, 60*time.Second, 500*time.Millisecond).Should(Succeed())
	actualSet := &appsv1.StatefulSet{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, actualSet)).To(Succeed())
	Expect(actualSet.Generation).To(Equal(originalGeneration))
	Expect(actualSet.Status.UpdateRevision).To(Equal(originalRevision))
	Expect(m2PodUIDs(m2SortedPods(parent))).To(Equal(originalUIDs))
	for _, pod := range pods {
		for _, family := range []struct{ container, path, hash string }{{"dhcp4", "/run/kea/state/kea-dhcp4.conf", config.file4}, {"dhcp6", "/run/kea/state/kea-dhcp6.conf", config.file6}} {
			out, err := m2ExecOutput(pod.Name, family.container, "sha256sum", family.path)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Fields(string(out))[0]).To(Equal(family.hash))
		}
	}
	m2VerifyRuntimeConditions(parent, config.Hash)
	fmt.Fprintf(GinkgoWriter, "M2_CONFIG_NOOP_DRIFT parentUID=%s podUIDs=%v generation=%d revision=%s sourceRestored=true snapshotsUnchanged=true\n", parent.UID, originalUIDs, originalGeneration, originalRevision)
}

func m2RunAfterVerifiedProjection(wait func() bool, fault func()) bool {
	if wait == nil || fault == nil || !wait() {
		return false
	}
	fault()
	return true
}

// m2ObserveThenRestore reserves a bounded observation interval for the fault,
// then restores the source fixture before returning either success or error.
// In particular, a failed assertion after KILL must not leave a bad projected
// ConfigMap in place while aggregate cleanup tries to prove process recovery.
func m2ObserveThenRestore(ctx context.Context, timeout time.Duration, observe, restore func(context.Context) error) error {
	if ctx == nil || timeout <= 0 || observe == nil || restore == nil {
		return fmt.Errorf("fault observation/restoration requires a live context and bounded callbacks")
	}
	observeCtx, cancel := context.WithTimeout(ctx, timeout)
	observeErr := observe(observeCtx)
	cancel()
	restoreErr := restore(ctx)
	return errors.Join(observeErr, restoreErr)
}

func m2WaitCorruptProcessFailure(ctx context.Context, pod corev1.Pod) error {
	return m2WaitCorruptProcessFailureWith(ctx, pod, func(ctx context.Context, podName string) ([]byte, error) {
		return m2Command(ctx, "kubectl", "logs", "-n", runtimeNamespace, podName, "-c", "dhcp4", "--previous")
	}, time.Second)
}

func m2WaitCorruptProcessFailureWith(ctx context.Context, pod corev1.Pod, readPrevious func(context.Context, string) ([]byte, error), retryInterval time.Duration) error {
	if ctx == nil || ctx.Err() != nil || pod.UID == "" || pod.Name == "" || pod.Namespace != runtimeNamespace || readPrevious == nil || retryInterval < 0 {
		return fmt.Errorf("corrupt restart observation lacks a current Pod identity")
	}
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, last)
		}
		current := &corev1.Pod{}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := admin.Get(requestCtx, client.ObjectKeyFromObject(&pod), current)
		cancel()
		if err == nil {
			if current.UID != pod.UID {
				return fmt.Errorf("corrupt restart observation saw a replacement Pod UID")
			}
			for i := range current.Status.ContainerStatuses {
				status := &current.Status.ContainerStatuses[i]
				if status.Name != "dhcp4" || status.RestartCount == 0 || status.LastTerminationState.Terminated == nil {
					continue
				}
				logs, logErr := readPrevious(ctx, pod.Name)
				if logErr == nil && strings.Contains(string(logs), "FAILED") && !strings.Contains(string(logs), "kea-dhcp4 -c") {
					return nil
				}
				if logErr != nil {
					last = logErr
				} else {
					last = fmt.Errorf("previous DHCPv4 container logs do not prove fail-closed startup")
				}
			}
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), last)
		case <-time.After(retryInterval):
		}
	}
}

const m2ProjectedConfigObservationTimeout = 90 * time.Second

func m2CheckCorruptProjectionRecovery() {
	parent, pods, config, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
	configName, _, _ := m2NamesFor(parent)
	cm := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, cm)).To(Succeed())
	originalData := map[string]string{"kea-dhcp4.conf": cm.Data["kea-dhcp4.conf"], "kea-dhcp6.conf": cm.Data["kea-dhcp6.conf"]}
	manager := &appsv1.Deployment{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: managerName}, manager)).To(Succeed())
	Expect(m2SetManagerReplicas(labctx, 0)).To(Succeed())
	corrupted := cm.DeepCopy()
	corrupted.Data["kea-dhcp4.conf"] = "not the approved Kea configuration\n"
	parentIdentity, err := m2IdentityFor(parent)
	Expect(err).NotTo(HaveOccurred())
	Expect(m2ActiveScenario.UpdateGeneratedConfigMap(labctx, corrupted, parentIdentity)).To(Succeed())
	badHash := m2SHA256([]byte(corrupted.Data["kea-dhcp4.conf"]))
	continued := m2RunAfterVerifiedProjection(func() bool {
		return Eventually(func(g Gomega) {
			out, err := m2ExecOutput(pods[0].Name, "dhcp4", "sha256sum", "/etc/kea/kea-dhcp4.conf")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.Fields(string(out))).To(HaveLen(2))
			g.Expect(strings.Fields(string(out))[0]).To(Equal(badHash))
		}, m2ProjectedConfigObservationTimeout, time.Second).Should(Succeed())
	}, func() {
		var oldIdentity m2ProcessIdentity
		recoveryErr := m2ObserveThenRestore(labctx, 45*time.Second, func(observeCtx context.Context) error {
			sibling, err := m2Command(observeCtx, "kubectl", "exec", pods[0].Name, "-n", runtimeNamespace, "-c", "dhcp6", "--", "sha256sum", "/run/kea/state/kea-dhcp6.conf")
			if err != nil {
				return err
			}
			if len(strings.Fields(string(sibling))) != 2 || strings.Fields(string(sibling))[0] != config.file6 {
				return fmt.Errorf("DHCPv6 snapshot changed during DHCPv4 projection fault")
			}
			oldIdentity, err = m2ObserveProcess(observeCtx, client.ObjectKeyFromObject(&pods[0]), "dhcp4")
			if err != nil {
				return err
			}
			if err := m2ActiveScenario.KillProcess(observeCtx, oldIdentity); err != nil {
				return err
			}
			return m2WaitCorruptProcessFailure(observeCtx, pods[0])
		}, func(restoreCtx context.Context) error {
			currentCM := &corev1.ConfigMap{}
			if err := admin.Get(restoreCtx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, currentCM); err != nil {
				return err
			}
			if currentCM.UID != cm.UID {
				return fmt.Errorf("generated ConfigMap UID changed before source restoration")
			}
			currentCM.Data = originalData
			return m2ActiveScenario.UpdateGeneratedConfigMap(restoreCtx, currentCM, parentIdentity)
		})
		Expect(recoveryErr).NotTo(HaveOccurred(), "corrupt restart evidence and source restoration must both complete")
		var replacement m2ProcessIdentity
		Eventually(func(g Gomega) {
			var observeErr error
			replacement, observeErr = m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pods[0]), "dhcp4")
			g.Expect(observeErr).NotTo(HaveOccurred())
			g.Expect(replacement.TaskID).NotTo(Equal(oldIdentity.TaskID))
		}, 90*time.Second, time.Second).Should(Succeed())
		Expect(m2ProveTaskReplacement(labctx, m2StoppedProcess{Identity: oldIdentity, Phase: "acknowledged"}, replacement)).To(Succeed())
		Expect(m2RestoreManager(labctx, m2ActiveScenario.Manager)).To(Succeed())
		Expect(m2WaitManagerHealthy(labctx, m2ActiveScenario.ExpectedImage, m2ActiveScenario.ExpectedImageID, m2VerifyManagerDeployment)).To(Succeed())
		m2WaitRuntimeConditions(parent, config.Hash)
		Expect(m2ActiveScenario.Killed).To(HaveLen(1))
		fmt.Fprintf(GinkgoWriter, "M2_CORRUPTED_PROJECTION parentUID=%s podUID=%s oldTask=%s recoveredTask=%s badHash=%s siblingSnapshotHash=%s managerRestored=true\n", parent.UID, pods[0].UID, oldIdentity.TaskID, replacement.TaskID, badHash, config.file6)
	})
	if !continued {
		return
	}
}

func m2CheckMissingConfigKeyRecovery(key string) {
	parent, pods, config, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
	configName, _, _ := m2NamesFor(parent)
	cm := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, cm)).To(Succeed())
	originalUID := cm.UID
	originalData := map[string]string{"kea-dhcp4.conf": cm.Data["kea-dhcp4.conf"], "kea-dhcp6.conf": cm.Data["kea-dhcp6.conf"]}
	Expect(m2SetManagerReplicas(labctx, 0)).To(Succeed())
	missing := cm.DeepCopy()
	delete(missing.Data, key)
	parentIdentity, err := m2IdentityFor(parent)
	Expect(err).NotTo(HaveOccurred())
	Expect(m2ActiveScenario.UpdateGeneratedConfigMap(labctx, missing, parentIdentity)).To(Succeed())
	oldPod := pods[1]
	Expect(m2DeleteObject(labctx, &oldPod)).To(Succeed())
	failed := m2WaitFailedMount(parent, oldPod)
	Expect(failed.UID).NotTo(Equal(oldPod.UID))
	Expect(m2ValidateKeaContainersNotStarted(failed.Status.ContainerStatuses)).To(Succeed(), "Kea containers must not start from a projection with a missing required key")
	repaired := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, repaired)).To(Succeed())
	repaired.Data = originalData
	Expect(m2ActiveScenario.UpdateGeneratedConfigMap(labctx, repaired, parentIdentity)).To(Succeed())
	Expect(m2SetManagerReplicas(labctx, 1)).To(Succeed())
	Expect(m2WaitManagerHealthy(labctx, m2ActiveScenario.ExpectedImage, m2ActiveScenario.ExpectedImageID, m2VerifyManagerDeployment)).To(Succeed())
	m2WaitRuntimeConditions(parent, config.Hash)
	Expect(m2WaitPodReady(parent, failed.Name, failed.UID, 90*time.Second)).To(Succeed())
	Expect(m2VerifyRecoveredKeaProcesses(parent, failed.Name, failed.UID)).To(Succeed())
	Expect(m2RecordReadyNativePodSuccessor(labctx, oldPod)).To(Succeed())
	cmAfter := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, cmAfter)).To(Succeed())
	Expect(cmAfter.UID).To(Equal(originalUID))
	fmt.Fprintf(GinkgoWriter, "M2_MISSING_CONFIG_KEY parentUID=%s oldPodUID=%s failedMountPodUID=%s configMapUID=%s restoredHash=%s managerRestored=true\n", parent.UID, oldPod.UID, failed.UID, cmAfter.UID, config.Hash)
}

func m2CheckMissingConfigMapRecovery() {
	parent, pods, config, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
	configName, _, _ := m2NamesFor(parent)
	cm := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, cm)).To(Succeed())
	oldConfigIdentity, err := m2IdentityFor(cm)
	Expect(err).NotTo(HaveOccurred())
	oldPod := pods[1]
	Expect(m2SetManagerReplicas(labctx, 0)).To(Succeed())
	Expect(m2DeleteObject(labctx, cm)).To(Succeed())
	Expect(m2DeleteObject(labctx, &oldPod)).To(Succeed())
	failed := m2WaitFailedMount(parent, oldPod)
	Expect(failed.UID).NotTo(Equal(oldPod.UID))
	Expect(m2ValidateKeaContainersNotStarted(failed.Status.ContainerStatuses)).To(Succeed(), "Kea containers must not start while the required ConfigMap is absent")
	Expect(m2SetManagerReplicas(labctx, 1)).To(Succeed())
	Expect(m2WaitManagerHealthy(labctx, m2ActiveScenario.ExpectedImage, m2ActiveScenario.ExpectedImageID, m2VerifyManagerDeployment)).To(Succeed())
	var generated corev1.ConfigMap
	Eventually(func(g Gomega) {
		g.Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, &generated)).To(Succeed())
		g.Expect(generated.UID).NotTo(Equal(cm.UID))
		g.Expect(generated.Data).To(Equal(cm.Data))
	}, 90*time.Second, time.Second).Should(Succeed())
	parentIdentity, err := m2IdentityFor(parent)
	Expect(err).NotTo(HaveOccurred())
	Expect(m2ActiveScenario.ObserveGeneratedSuccessor(labctx, oldConfigIdentity, parentIdentity)).To(Succeed())
	m2WaitRuntimeConditions(parent, config.Hash)
	Expect(m2WaitPodReady(parent, failed.Name, failed.UID, 90*time.Second)).To(Succeed())
	Expect(m2VerifyRecoveredKeaProcesses(parent, failed.Name, failed.UID)).To(Succeed())
	Expect(m2RecordReadyNativePodSuccessor(labctx, oldPod)).To(Succeed())
	fmt.Fprintf(GinkgoWriter, "M2_MISSING_CONFIGMAP parentUID=%s oldConfigMapUID=%s regeneratedConfigMapUID=%s failedMountPodUID=%s restoredHash=%s managerRestored=true\n", parent.UID, cm.UID, generated.UID, failed.UID, config.Hash)
}

func m2CheckWrongExpectedHashPod() {
	parent, _, config, set := m2CreateRuntimeFixture("INFO", 120*time.Second)
	wrong := "0000000000000000000000000000000000000000000000000000000000000000"
	Expect(wrong).NotTo(Equal(config.Hash))
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, GenerateName: "m2-wrong-hash-"}, Spec: *set.Spec.Template.Spec.DeepCopy()}
	for i := range pod.Spec.Containers {
		for j := range pod.Spec.Containers[i].Env {
			if pod.Spec.Containers[i].Env[j].Name == "KEA_CONFIG_SHA256" {
				pod.Spec.Containers[i].Env[j].Value = wrong
			}
		}
	}
	pod.Labels = nil
	pod.Annotations = nil
	pod.OwnerReferences = nil
	Expect(m2CreateObject(labctx, pod, nil)).To(Succeed())
	Eventually(func(g Gomega) {
		current := &corev1.Pod{}
		g.Expect(admin.Get(labctx, client.ObjectKeyFromObject(pod), current)).To(Succeed())
		g.Expect(current.UID).NotTo(BeEmpty())
		g.Expect(current.Status.ContainerStatuses).To(HaveLen(2))
		for _, status := range current.Status.ContainerStatuses {
			g.Expect(status.RestartCount).To(BeNumerically(">", 0))
			g.Expect(status.LastTerminationState.Terminated).NotTo(BeNil())
		}
	}, 90*time.Second, time.Second).Should(Succeed())
	Expect(m2WaitCorruptProcessFailure(labctx, *pod)).To(Succeed(), "previous DHCPv4 logs must prove fail-closed startup despite transient CRI log retrieval errors")
	Expect(pod.Labels).To(BeEmpty())
	Expect(metav1.GetControllerOf(pod)).To(BeNil())
	fmt.Fprintf(GinkgoWriter, "M2_WRONG_HASH_POD pod=%s expectedHash=%s actualHash4=%s actualHash6=%s launcherRefusedBeforeExec=true\n", pod.Name, wrong, config.file4, config.file6)
	_ = parent
}

func m2SetManagerReplicas(ctx context.Context, replicas int32) error {
	if m2ActiveScenario == nil || m2ActiveScenario.Manager == nil {
		return fmt.Errorf("manager replica mutation lacks a recorded Deployment identity")
	}
	if err := m2PatchManagerSpec(ctx, m2ActiveScenario.Manager, func(spec *appsv1.DeploymentSpec) { spec.Replicas = &replicas }); err != nil {
		return err
	}
	if replicas == 0 {
		return m2WaitManagerStopped(ctx, m2ActiveScenario.Manager.UID)
	}
	return nil
}

func m2ManagerScaleDownComplete(deployment *appsv1.Deployment, expectedUID types.UID, pods []corev1.Pod) error {
	if deployment == nil || expectedUID == "" || deployment.UID != expectedUID || deployment.Namespace != m2LabProfile.runtimeNamespace || deployment.Name != managerName {
		return fmt.Errorf("manager scale-down Deployment identity is missing or changed")
	}
	if deployment.Spec.Selector == nil || len(deployment.Spec.Selector.MatchLabels) == 0 {
		return fmt.Errorf("manager Deployment selector is empty or unverifiable")
	}
	selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil || selector.Empty() {
		return fmt.Errorf("manager Deployment selector is invalid: %v", err)
	}
	if deployment.Generation < 1 || deployment.Status.ObservedGeneration < deployment.Generation || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 ||
		deployment.Status.Replicas != 0 || deployment.Status.ReadyReplicas != 0 || deployment.Status.AvailableReplicas != 0 || deployment.Status.UpdatedReplicas != 0 {
		return fmt.Errorf("manager Deployment has not observed a settled zero-replica generation")
	}
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace == deployment.Namespace && selector.Matches(labels.Set(pod.Labels)) {
			return fmt.Errorf("manager Pod %s UID %s still matches the scaled-down Deployment", pod.Name, pod.UID)
		}
	}
	return nil
}

func m2WaitManagerStopped(ctx context.Context, expectedUID types.UID) error {
	if ctx == nil || expectedUID == "" {
		return fmt.Errorf("manager stop observation requires context and Deployment UID")
	}
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if err := stopCtx.Err(); err != nil {
			return errors.Join(fmt.Errorf("manager did not fully stop within the bounded observation: %w", err), last)
		}
		deployment := &appsv1.Deployment{}
		requestCtx, requestCancel := context.WithTimeout(stopCtx, 5*time.Second)
		getErr := admin.Get(requestCtx, client.ObjectKey{Namespace: runtimeNamespace, Name: managerName}, deployment)
		requestCancel()
		if getErr != nil {
			last = getErr
		} else {
			selector, selectorErr := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
			if selectorErr != nil || selector.Empty() {
				return fmt.Errorf("manager Deployment selector cannot be verified: %v", selectorErr)
			}
			pods := &corev1.PodList{}
			requestCtx, requestCancel = context.WithTimeout(stopCtx, 5*time.Second)
			listErr := admin.List(requestCtx, pods, client.InNamespace(runtimeNamespace), client.MatchingLabelsSelector{Selector: selector})
			requestCancel()
			if listErr != nil {
				last = listErr
			} else {
				last = m2ManagerScaleDownComplete(deployment, expectedUID, pods.Items)
				if last == nil {
					return nil
				}
			}
		}
		select {
		case <-stopCtx.Done():
		case <-ticker.C:
		}
	}
}

func m2WaitFailedMount(parent *infrastructurev1alpha1.KeaCluster, old corev1.Pod) corev1.Pod {
	var failed corev1.Pod
	_, _, setName := m2NamesFor(parent)
	Eventually(func(g Gomega) {
		pods := &corev1.PodList{}
		g.Expect(admin.List(labctx, pods, client.InNamespace(runtimeNamespace), client.MatchingLabels{"statefulset.kubernetes.io/pod-name": old.Name})).To(Succeed())
		g.Expect(pods.Items).To(HaveLen(1))
		failed = pods.Items[0]
		g.Expect(failed.Name).To(Equal(setName + "-1"))
		g.Expect(failed.UID).NotTo(Equal(old.UID))
		g.Expect(failed.Status.Phase).To(BeElementOf(corev1.PodPending, corev1.PodFailed))
		events := &corev1.EventList{}
		g.Expect(admin.List(labctx, events, client.InNamespace(runtimeNamespace))).To(Succeed())
		found := false
		for _, event := range events.Items {
			if event.InvolvedObject.UID == failed.UID && event.Reason == "FailedMount" {
				found = true
			}
		}
		g.Expect(found).To(BeTrue(), "native kubelet FailedMount event must name the replacement Pod UID")
	}, 60*time.Second, time.Second).Should(Succeed())
	return failed
}

func m2ValidateKeaContainersNotStarted(statuses []corev1.ContainerStatus) error {
	if len(statuses) != 2 {
		return fmt.Errorf("expected status for both Kea containers, observed %d", len(statuses))
	}
	wantImages := map[string]string{"dhcp4": m2KeaDHCP4Image, "dhcp6": m2KeaDHCP6Image}
	seen := make(map[string]bool, len(statuses))
	for _, status := range statuses {
		image, ok := wantImages[status.Name]
		if !ok || seen[status.Name] {
			return fmt.Errorf("unexpected or duplicate Kea container status %q", status.Name)
		}
		seen[status.Name] = true
		if status.Image != image {
			return fmt.Errorf("container %s reports unexpected image %q", status.Name, status.Image)
		}
		if status.State.Waiting == nil || status.State.Waiting.Reason != "ContainerCreating" || status.State.Running != nil || status.State.Terminated != nil {
			return fmt.Errorf("container %s is not in the expected kubelet waiting state", status.Name)
		}
		if status.ContainerID != "" || status.Started != nil && *status.Started || status.Ready || status.RestartCount != 0 || status.LastTerminationState.Terminated != nil {
			return fmt.Errorf("container %s has evidence of having started", status.Name)
		}
	}
	if !seen["dhcp4"] || !seen["dhcp6"] {
		return fmt.Errorf("both immutable Kea container identities were not observed")
	}
	return nil
}

func m2WaitPodReady(parent *infrastructurev1alpha1.KeaCluster, name string, oldUID types.UID, timeout time.Duration) error {
	if parent == nil || parent.Namespace != runtimeNamespace || oldUID == "" || timeout <= 0 {
		return fmt.Errorf("ready Pod wait lacks the exact failed-mount incarnation")
	}
	_, _, setName := m2NamesFor(parent)
	if name != setName+"-1" {
		return fmt.Errorf("ready Pod name %q is outside the observed StatefulSet fixture", name)
	}
	deadline := time.Now().Add(timeout)
	lastObservation := "Pod was not observed"
	for time.Now().Before(deadline) {
		current := &corev1.Pod{}
		if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: name}, current); err != nil {
			lastObservation = "Pod GET failed: " + err.Error()
		} else if current.UID != oldUID {
			return fmt.Errorf("same-name Pod incarnation changed from %s to %s: %s", oldUID, current.UID, m2PodReadinessSummary(*current, oldUID))
		} else if m2ReadyPodMatchesIncarnation(*current, oldUID) {
			return nil
		} else {
			lastObservation = m2PodReadinessSummary(*current, oldUID)
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("observed Pod %s incarnation %s did not become ready before timeout: %s", name, oldUID, lastObservation)
}

func m2PodReadinessSummary(pod corev1.Pod, expectedUID types.UID) string {
	parts := []string{fmt.Sprintf("name=%s uid=%s expectedUID=%s phase=%s podReady=%t", pod.Name, pod.UID, expectedUID, pod.Status.Phase, podReady(&pod))}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady || condition.Type == corev1.ContainersReady {
			parts = append(parts, fmt.Sprintf("%s=%s(%s)", condition.Type, condition.Status, condition.Reason))
		}
	}
	statuses := append([]corev1.ContainerStatus(nil), pod.Status.ContainerStatuses...)
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	for _, status := range statuses {
		state := "unknown"
		if status.State.Waiting != nil {
			state = "waiting:" + status.State.Waiting.Reason
		} else if status.State.Running != nil {
			state = "running"
		} else if status.State.Terminated != nil {
			state = fmt.Sprintf("terminated:%s/%d", status.State.Terminated.Reason, status.State.Terminated.ExitCode)
		}
		containerID := status.ContainerID
		if len(containerID) > 24 {
			containerID = containerID[:24]
		}
		started := "unset"
		if status.Started != nil {
			started = fmt.Sprint(*status.Started)
		}
		imageID := status.ImageID
		if len(imageID) > 100 {
			imageID = imageID[:100]
		}
		parts = append(parts, fmt.Sprintf("container=%s state=%s ready=%t started=%s restarts=%d image=%s imageID=%s containerIDPrefix=%s", status.Name, state, status.Ready, started, status.RestartCount, status.Image, imageID, containerID))
	}
	summary := m2RedactEvidence(strings.Join(parts, "; "))
	if len(summary) > 2048 {
		summary = summary[:2048]
	}
	return summary
}

func m2ReadyPodMatchesIncarnation(pod corev1.Pod, expectedUID types.UID) bool {
	if expectedUID == "" || pod.UID != expectedUID || pod.Namespace != m2LabProfile.runtimeNamespace || pod.Name == "" || pod.Status.Phase != corev1.PodRunning || !podReady(&pod) {
		return false
	}
	wantImages := map[string]string{"dhcp4": m2KeaDHCP4Image, "dhcp6": m2KeaDHCP6Image}
	if len(pod.Spec.Containers) != 2 || len(pod.Status.ContainerStatuses) != 2 {
		return false
	}
	for _, container := range pod.Spec.Containers {
		if wantImages[container.Name] != container.Image {
			return false
		}
		delete(wantImages, container.Name)
	}
	if len(wantImages) != 0 {
		return false
	}
	wantImages = map[string]string{"dhcp4": m2KeaDHCP4Image, "dhcp6": m2KeaDHCP6Image}
	for _, status := range pod.Status.ContainerStatuses {
		expectedImage, ok := wantImages[status.Name]
		if !ok || status.ContainerID == "" || !status.Ready || status.RestartCount != 0 || status.ImageID != expectedImage {
			return false
		}
		expectedConfigID, known := m2KeaExpectedConfigID(expectedImage)
		if !known || status.Image != expectedConfigID {
			return false
		}
		if !strings.HasPrefix(status.ContainerID, "containerd://") || !m2FullHexID(strings.TrimPrefix(status.ContainerID, "containerd://")) {
			return false
		}
		delete(wantImages, status.Name)
	}
	return len(wantImages) == 0
}

func m2PodReadyTransitionTime(pod corev1.Pod) (time.Time, bool) {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue && !condition.LastTransitionTime.IsZero() {
			return condition.LastTransitionTime.Time, true
		}
	}
	return time.Time{}, false
}

func m2MinReadyElapsed(readyAt, replacementCreatedAt time.Time, minReadySeconds int32) bool {
	if readyAt.IsZero() || replacementCreatedAt.IsZero() || minReadySeconds <= 0 {
		return false
	}
	return !replacementCreatedAt.Before(readyAt.Add(time.Duration(minReadySeconds) * time.Second))
}

func m2VerifyRecoveredKeaProcesses(parent *infrastructurev1alpha1.KeaCluster, podName string, expectedUID types.UID) error {
	if parent == nil || parent.UID == "" || podName == "" || expectedUID == "" {
		return fmt.Errorf("recovered Kea process verification lacks exact fixture identity")
	}
	for _, container := range []struct{ name, image string }{{"dhcp4", m2KeaDHCP4Image}, {"dhcp6", m2KeaDHCP6Image}} {
		identity, err := m2ObserveProcess(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: podName}, container.name)
		if err != nil {
			return fmt.Errorf("observe recovered %s process: %w", container.name, err)
		}
		if identity.PodUID != expectedUID || identity.KeaClusterUID != parent.UID || identity.ContainerName != container.name {
			return fmt.Errorf("recovered %s process belongs to a changed Pod or KeaCluster incarnation", container.name)
		}
		if err := m2VerifyKeaCRIIdentity(identity, container.image); err != nil {
			return fmt.Errorf("recovered %s CRI image identity: %w", container.name, err)
		}
	}
	return nil
}

// m2WaitExactPodReady waits for readiness without switching authority to a
// later same-name Pod incarnation. Rollout checks read mounted files only
// after both recorded replacement Pods are ready and still have their exact
// observed UIDs.
func m2WaitExactPodReady(expected corev1.Pod, timeout time.Duration) (corev1.Pod, error) {
	if expected.Namespace != m2LabProfile.runtimeNamespace || expected.Name == "" || expected.UID == "" || timeout <= 0 || labctx == nil {
		return corev1.Pod{}, fmt.Errorf("exact rollout Pod readiness lacks a valid identity, context or timeout")
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		requestTimeout := 5 * time.Second
		if remaining := time.Until(deadline); remaining < requestTimeout {
			requestTimeout = remaining
		}
		ctx, cancel := context.WithTimeout(labctx, requestTimeout)
		current := &corev1.Pod{}
		err := admin.Get(ctx, client.ObjectKeyFromObject(&expected), current)
		cancel()
		if err == nil {
			if current.UID != expected.UID {
				return corev1.Pod{}, fmt.Errorf("rollout Pod %s incarnation changed from %s to %s while awaiting readiness", expected.Name, expected.UID, current.UID)
			}
			if current.DeletionTimestamp != nil {
				return corev1.Pod{}, fmt.Errorf("rollout Pod %s UID %s is terminating", expected.Name, expected.UID)
			}
			readyContainers := map[string]bool{}
			for _, status := range current.Status.ContainerStatuses {
				if status.Ready {
					readyContainers[status.Name] = true
				}
			}
			if current.Status.Phase == corev1.PodRunning && podReady(current) && readyContainers["dhcp4"] && readyContainers["dhcp6"] {
				return *current.DeepCopy(), nil
			}
			lastErr = fmt.Errorf("rollout Pod %s UID %s is not Ready yet", expected.Name, expected.UID)
		} else {
			lastErr = err
		}
		select {
		case <-labctx.Done():
			return corev1.Pod{}, labctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return corev1.Pod{}, fmt.Errorf("rollout Pod %s UID %s did not become Ready before %s: %w", expected.Name, expected.UID, timeout, lastErr)
}

func m2SortedPods(parent *infrastructurev1alpha1.KeaCluster) []corev1.Pod {
	pods := m2GetPods(parent)
	sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })
	return pods
}

func m2PodUIDs(pods []corev1.Pod) map[string]types.UID {
	result := make(map[string]types.UID, len(pods))
	for _, pod := range pods {
		result[pod.Name] = pod.UID
	}
	return result
}

func m2ConfigMapHash(data map[string]string) string {
	four, fourOK := data["kea-dhcp4.conf"]
	six, sixOK := data["kea-dhcp6.conf"]
	if !fourOK || !sixOK {
		return ""
	}
	combined := append([]byte("kea-dhcp4.conf\x00"), []byte(four)...)
	combined = append(combined, 0)
	combined = append(combined, []byte("kea-dhcp6.conf\x00")...)
	combined = append(combined, []byte(six)...)
	return m2SHA256(combined)
}
