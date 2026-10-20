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
	"bytes"
	"maps"
	"reflect"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
)

const (
	clusterUIDLabel      = "keaguard.example/cluster-uid"
	componentLabel       = "keaguard.example/component"
	configHashAnnotation = "keaguard.example/config-hash"
)

func childMetadata(parent *infrastructurev1alpha1.KeaCluster, name, component string) metav1.ObjectMeta {
	controller, blockDeletion := true, false
	return metav1.ObjectMeta{
		Name: name, Namespace: parent.Namespace,
		Labels: map[string]string{clusterUIDLabel: string(parent.UID), componentLabel: component},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: parent.Name, UID: parent.UID,
			Controller: &controller, BlockOwnerDeletion: &blockDeletion,
		}},
	}
}

func desiredKeaConfig(parent *infrastructurev1alpha1.KeaCluster, names workloadNames, config workloadConfig) *corev1.ConfigMap {
	meta := childMetadata(parent, names.ConfigMap, "configuration")
	return &corev1.ConfigMap{
		ObjectMeta: meta,
		Data:       map[string]string{"kea-dhcp4.conf": config.DHCP4, "kea-dhcp6.conf": config.DHCP6},
	}
}

func workloadConfigNameCollides(parent *infrastructurev1alpha1.KeaCluster, names workloadNames) bool {
	return parent.Name == names.ConfigMap
}

func desiredHeadlessService(parent *infrastructurev1alpha1.KeaCluster, names workloadNames) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: childMetadata(parent, names.Service, "headless"),
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP, ClusterIP: corev1.ClusterIPNone,
			Selector:                 map[string]string{clusterUIDLabel: string(parent.UID)},
			PublishNotReadyAddresses: false,
		},
	}
}

func desiredKeaStatefulSet(parent *infrastructurev1alpha1.KeaCluster, names workloadNames, config workloadConfig) *appsv1.StatefulSet {
	labels := map[string]string{clusterUIDLabel: string(parent.UID), componentLabel: "workload"}
	replicas, history, start, partition := int32(2), int32(2), int32(0), int32(0)
	minReady, grace := int32(5), int64(30)
	falseValue, trueValue := false, true
	fsGroup, runAsUser, runAsGroup := int64(101), int64(100), int64(101)
	mode := int32(0444)
	optional := false
	size := resource.MustParse("16Mi")
	containers := []corev1.Container{
		keaContainer(4, keaDHCP4Image, config.DHCP4SHA256, "runtime4", "data4", []corev1.Capability{"NET_BIND_SERVICE", "NET_RAW"}),
		keaContainer(6, keaDHCP6Image, config.DHCP6SHA256, "runtime6", "data6", []corev1.Capability{"NET_BIND_SERVICE"}),
	}
	return &appsv1.StatefulSet{
		ObjectMeta: childMetadata(parent, names.StatefulSet, "workload"),
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas, ServiceName: names.Service,
			Selector:             &metav1.LabelSelector{MatchLabels: map[string]string{clusterUIDLabel: string(parent.UID)}},
			PodManagementPolicy:  appsv1.OrderedReadyPodManagement,
			UpdateStrategy:       appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType, RollingUpdate: &appsv1.RollingUpdateStatefulSetStrategy{Partition: &partition}},
			RevisionHistoryLimit: &history, MinReadySeconds: minReady, Ordinals: &appsv1.StatefulSetOrdinals{Start: start},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: maps.Clone(labels), Annotations: map[string]string{configHashAnnotation: config.Hash}},
				Spec: corev1.PodSpec{
					NodeSelector:  map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"},
					RestartPolicy: corev1.RestartPolicyAlways, TerminationGracePeriodSeconds: &grace, DNSPolicy: corev1.DNSClusterFirst,
					ServiceAccountName: "default", AutomountServiceAccountToken: &falseValue, EnableServiceLinks: &falseValue,
					SecurityContext: &corev1.PodSecurityContext{RunAsUser: &runAsUser, RunAsGroup: &runAsGroup, FSGroup: &fsGroup, RunAsNonRoot: &trueValue, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Affinity: &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{Weight: 100, PodAffinityTerm: corev1.PodAffinityTerm{
						LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{clusterUIDLabel: string(parent.UID)}}, Namespaces: []string{parent.Namespace}, TopologyKey: "kubernetes.io/hostname",
					}}}}},
					Volumes: []corev1.Volume{
						{Name: "runtime4", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumDefault, SizeLimit: quantityCopy(size)}}},
						{Name: "data4", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumDefault, SizeLimit: quantityCopy(size)}}},
						{Name: "runtime6", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumDefault, SizeLimit: quantityCopy(size)}}},
						{Name: "data6", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumDefault, SizeLimit: quantityCopy(size)}}},
						{Name: "configuration", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: names.ConfigMap}, Items: []corev1.KeyToPath{{Key: "kea-dhcp4.conf", Path: "kea-dhcp4.conf"}, {Key: "kea-dhcp6.conf", Path: "kea-dhcp6.conf"}}, DefaultMode: &mode, Optional: &optional,
						}}},
					},
					Containers: containers,
				},
			},
			VolumeClaimTemplates: nil,
		},
	}
}

func keaContainer(family int, image, configHash, runtimeVolume, dataVolume string, add []corev1.Capability) corev1.Container {
	familyText := string(rune('0' + family))
	falseValue, trueValue := false, true
	return corev1.Container{
		Name: "dhcp" + familyText, Image: image, ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{"/bin/sh", "-ec"}, Args: []string{keaLaunchScript(family)},
		Env: []corev1.EnvVar{
			{Name: "KEA_CONFIG_SHA256", Value: configHash}, {Name: "KEA_PIDFILE_DIR", Value: "/run/kea/state"},
			{Name: "KEA_LOCKFILE_DIR", Value: "/run/kea/state"}, {Name: "KEA_DHCP_DATA_DIR", Value: "/var/lib/kea/state"},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("16Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("128Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("64Mi")},
		},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: &falseValue, ReadOnlyRootFilesystem: &trueValue, RunAsNonRoot: &trueValue,
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: append([]corev1.Capability(nil), add...)},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: runtimeVolume, MountPath: "/run/kea"}, {Name: dataVolume, MountPath: "/var/lib/kea"},
			{Name: "configuration", MountPath: "/etc/kea", ReadOnly: true},
		},
		StartupProbe:   &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-ec", keaProcessProbe(family)}}}, PeriodSeconds: 2, TimeoutSeconds: 1, FailureThreshold: 30, SuccessThreshold: 1},
		ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-ec", keaProcessProbe(family)}}}, PeriodSeconds: 5, TimeoutSeconds: 1, FailureThreshold: 1, SuccessThreshold: 1},
		LivenessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-ec", keaProcessProbe(family)}}}, PeriodSeconds: 10, TimeoutSeconds: 1, FailureThreshold: 3, SuccessThreshold: 1},
	}
}

func managedConfigurationEqual(actual, desired *corev1.ConfigMap) bool {
	return maps.Equal(actual.Data, desired.Data) && maps.EqualFunc(actual.BinaryData, desired.BinaryData, bytes.Equal) &&
		actual.Labels[clusterUIDLabel] == desired.Labels[clusterUIDLabel] && actual.Labels[componentLabel] == desired.Labels[componentLabel]
}

func setManagedConfiguration(target, desired *corev1.ConfigMap) {
	target.Data = maps.Clone(desired.Data)
	target.BinaryData = make(map[string][]byte, len(desired.BinaryData))
	for key, value := range desired.BinaryData {
		target.BinaryData[key] = bytes.Clone(value)
	}
	setReservedMapValue(&target.Labels, clusterUIDLabel, desired.Labels[clusterUIDLabel])
	setReservedMapValue(&target.Labels, componentLabel, desired.Labels[componentLabel])
}

func managedServiceEqual(actual, desired *corev1.Service) bool {
	a, d := actual.Spec, desired.Spec
	return actual.Labels[clusterUIDLabel] == desired.Labels[clusterUIDLabel] && actual.Labels[componentLabel] == desired.Labels[componentLabel] &&
		a.Type == d.Type && a.ClusterIP == d.ClusterIP && maps.Equal(a.Selector, d.Selector) && len(a.Ports) == len(d.Ports) &&
		a.PublishNotReadyAddresses == d.PublishNotReadyAddresses && a.ExternalName == d.ExternalName && slices.Equal(a.ExternalIPs, d.ExternalIPs) &&
		a.LoadBalancerIP == d.LoadBalancerIP && slices.Equal(a.LoadBalancerSourceRanges, d.LoadBalancerSourceRanges) &&
		reflect.DeepEqual(a.AllocateLoadBalancerNodePorts, d.AllocateLoadBalancerNodePorts) && a.ExternalTrafficPolicy == d.ExternalTrafficPolicy &&
		a.HealthCheckNodePort == d.HealthCheckNodePort && reflect.DeepEqual(a.TrafficDistribution, d.TrafficDistribution)
}

func setManagedService(target, desired *corev1.Service) {
	t := &target.Spec
	d := desired.Spec
	t.Type, t.ClusterIP, t.Selector = d.Type, d.ClusterIP, maps.Clone(d.Selector)
	t.Ports = append([]corev1.ServicePort(nil), d.Ports...)
	t.PublishNotReadyAddresses = d.PublishNotReadyAddresses
	t.ExternalName, t.ExternalIPs = d.ExternalName, append([]string(nil), d.ExternalIPs...)
	t.LoadBalancerIP, t.LoadBalancerSourceRanges = d.LoadBalancerIP, append([]string(nil), d.LoadBalancerSourceRanges...)
	t.AllocateLoadBalancerNodePorts = copyBool(d.AllocateLoadBalancerNodePorts)
	t.ExternalTrafficPolicy, t.HealthCheckNodePort = d.ExternalTrafficPolicy, d.HealthCheckNodePort
	t.TrafficDistribution = copyString(d.TrafficDistribution)
	setReservedMapValue(&target.Labels, clusterUIDLabel, desired.Labels[clusterUIDLabel])
	setReservedMapValue(&target.Labels, componentLabel, desired.Labels[componentLabel])
}

func serviceCompatible(actual, desired *corev1.Service) bool {
	if actual.Spec.ClusterIP != "" && actual.Spec.ClusterIP != desired.Spec.ClusterIP {
		return false
	}
	for _, ip := range actual.Spec.ClusterIPs {
		if ip != "" && ip != desired.Spec.ClusterIP {
			return false
		}
	}
	return true
}

func managedStatefulSetEqual(actual, desired *appsv1.StatefulSet) bool {
	if actual.Labels[clusterUIDLabel] != desired.Labels[clusterUIDLabel] || actual.Labels[componentLabel] != desired.Labels[componentLabel] {
		return false
	}
	a, d := actual.DeepCopy().Spec, desired.DeepCopy().Spec
	retainTemplateReserved(&a.Template)
	retainTemplateReserved(&d.Template)
	normalizeStatefulSetDefaults(&a)
	normalizeStatefulSetDefaults(&d)
	normalizeEmptyCollections(reflect.ValueOf(&a).Elem())
	normalizeEmptyCollections(reflect.ValueOf(&d).Elem())
	return reflect.DeepEqual(a, d)
}

func setManagedStatefulSet(target, desired *appsv1.StatefulSet) {
	setReservedMapValue(&target.Labels, clusterUIDLabel, desired.Labels[clusterUIDLabel])
	setReservedMapValue(&target.Labels, componentLabel, desired.Labels[componentLabel])
	oldTemplate := target.Spec.Template.DeepCopy()
	target.Spec = *desired.Spec.DeepCopy()
	target.Spec.Template.ObjectMeta = *oldTemplate.ObjectMeta.DeepCopy()
	setReservedMapValue(&target.Spec.Template.Labels, clusterUIDLabel, desired.Spec.Template.Labels[clusterUIDLabel])
	setReservedMapValue(&target.Spec.Template.Labels, componentLabel, desired.Spec.Template.Labels[componentLabel])
	setReservedMapValue(&target.Spec.Template.Annotations, configHashAnnotation, desired.Spec.Template.Annotations[configHashAnnotation])
}

func statefulSetCompatible(actual, desired *appsv1.StatefulSet) bool {
	a, d := actual.DeepCopy().Spec, desired.DeepCopy().Spec
	normalizeEmptyCollections(reflect.ValueOf(&a).Elem())
	normalizeEmptyCollections(reflect.ValueOf(&d).Elem())
	return reflect.DeepEqual(a.Selector, d.Selector) && a.ServiceName == d.ServiceName && reflect.DeepEqual(a.VolumeClaimTemplates, d.VolumeClaimTemplates)
}

func normalizeStatefulSetDefaults(spec *appsv1.StatefulSetSpec) {
	if spec.Replicas == nil {
		spec.Replicas = pointerTo(int32(1))
	}
	if spec.PodManagementPolicy == "" {
		spec.PodManagementPolicy = appsv1.OrderedReadyPodManagement
	}
	if spec.UpdateStrategy.Type == "" {
		spec.UpdateStrategy.Type = appsv1.RollingUpdateStatefulSetStrategyType
	}
	if spec.UpdateStrategy.Type == appsv1.RollingUpdateStatefulSetStrategyType && spec.UpdateStrategy.RollingUpdate == nil {
		spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{}
	}
	if spec.UpdateStrategy.RollingUpdate != nil && spec.UpdateStrategy.RollingUpdate.Partition == nil {
		spec.UpdateStrategy.RollingUpdate.Partition = pointerTo(int32(0))
	}
	if spec.UpdateStrategy.RollingUpdate != nil && spec.UpdateStrategy.RollingUpdate.MaxUnavailable == nil {
		spec.UpdateStrategy.RollingUpdate.MaxUnavailable = pointerTo(intstr.FromInt32(1))
	}
	if spec.RevisionHistoryLimit == nil {
		spec.RevisionHistoryLimit = pointerTo(int32(10))
	}
	if spec.PersistentVolumeClaimRetentionPolicy == nil {
		spec.PersistentVolumeClaimRetentionPolicy = &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
			WhenDeleted: appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
			WhenScaled:  appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
		}
	}
	if spec.Ordinals == nil {
		spec.Ordinals = &appsv1.StatefulSetOrdinals{Start: 0}
	}
	pod := &spec.Template.Spec
	if pod.RestartPolicy == "" {
		pod.RestartPolicy = corev1.RestartPolicyAlways
	}
	if pod.DNSPolicy == "" {
		pod.DNSPolicy = corev1.DNSClusterFirst
	}
	if pod.TerminationGracePeriodSeconds == nil {
		pod.TerminationGracePeriodSeconds = pointerTo(int64(30))
	}
	if pod.SchedulerName == "" {
		pod.SchedulerName = "default-scheduler"
	}
	if pod.ServiceAccountName == "" {
		pod.ServiceAccountName = "default"
	}
	if pod.DeprecatedServiceAccount == "" {
		pod.DeprecatedServiceAccount = pod.ServiceAccountName
	}
	if pod.EnableServiceLinks == nil {
		pod.EnableServiceLinks = pointerTo(true)
	}
	for i := range pod.Containers {
		container := &pod.Containers[i]
		if container.ImagePullPolicy == "" {
			container.ImagePullPolicy = corev1.PullIfNotPresent
		}
		if container.TerminationMessagePath == "" {
			container.TerminationMessagePath = corev1.TerminationMessagePathDefault
		}
		if container.TerminationMessagePolicy == "" {
			container.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		}
	}
}

func retainTemplateReserved(template *corev1.PodTemplateSpec) {
	labels := make(map[string]string, 2)
	for _, key := range []string{clusterUIDLabel, componentLabel} {
		if value, ok := template.Labels[key]; ok {
			labels[key] = value
		}
	}
	annotations := make(map[string]string, 1)
	if value, ok := template.Annotations[configHashAnnotation]; ok {
		annotations[configHashAnnotation] = value
	}
	template.ObjectMeta = metav1.ObjectMeta{Labels: labels, Annotations: annotations}
}

func normalizeEmptyCollections(value reflect.Value) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !value.IsNil() {
			normalizeEmptyCollections(value.Elem())
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			if field.CanSet() {
				normalizeEmptyCollections(field)
			}
		}
	case reflect.Slice, reflect.Map:
		if value.IsNil() {
			return
		}
		if value.Len() == 0 {
			value.Set(reflect.Zero(value.Type()))
			return
		}
		if value.Kind() == reflect.Slice {
			for i := 0; i < value.Len(); i++ {
				normalizeEmptyCollections(value.Index(i))
			}
		}
	}
}

func setReservedMapValue(target *map[string]string, key, value string) {
	if *target == nil {
		*target = make(map[string]string)
	}
	if value == "" {
		delete(*target, key)
	} else {
		(*target)[key] = value
	}
}

func copyBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
func copyString(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
func quantityCopy(value resource.Quantity) *resource.Quantity {
	copied := value.DeepCopy()
	return &copied
}

func pointerTo[T any](value T) *T { return &value }
