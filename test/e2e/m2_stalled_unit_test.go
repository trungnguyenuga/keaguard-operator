package e2e

import (
	"strings"
	"testing"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func m2StalledPolicyFixture() (*infrastructurev1alpha1.KeaCluster, *infrastructurev1alpha1.KeaCluster, *corev1.ConfigMap, *appsv1.StatefulSet, []corev1.Pod) {
	severityInfo, severityDebug := "INFO", "DEBUG"
	previous := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: "stalled-fixture", UID: "parent-uid", Generation: 4}, Spec: &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true, LoggingSeverity: &severityInfo}}}
	current := previous.DeepCopy()
	current.Generation = 5
	current.Spec.Workload.LoggingSeverity = &severityDebug
	current.Status.ObservedGeneration = current.Generation
	setM2Condition(current, "ArtifactReconciled", metav1.ConditionTrue, "ArtifactInSync", current.Generation)
	setM2Condition(current, "WorkloadReconciled", metav1.ConditionTrue, "ResourcesInSync", current.Generation)
	setM2Condition(current, "WorkloadReady", metav1.ConditionFalse, "RolloutPending", current.Generation)
	data := map[string]string{
		"kea-dhcp4.conf": `{"Dhcp4":{"loggers":[{"severity":"DEBUG","debuglevel":99}]}}`,
		"kea-dhcp6.conf": `{"Dhcp6":{"loggers":[{"severity":"DEBUG","debuglevel":99}]}}`,
	}
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: "stalled-config", UID: "config-uid", ResourceVersion: "11", OwnerReferences: []metav1.OwnerReference{{APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: previous.Name, UID: previous.UID, Controller: m2BoolPtr(true)}}}, Data: data}
	desiredHash := m2ConfigMapHash(data)
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: "stalled-set", UID: "set-uid", Generation: 2}, Spec: appsv1.StatefulSetSpec{Replicas: m2Int32Ptr(2), PodManagementPolicy: appsv1.OrderedReadyPodManagement, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"keaguard.example/config-hash": desiredHash}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "dhcp4", Image: m2KeaDHCP4Image}, {Name: "dhcp6", Image: m2KeaDHCP6Image}}}}}, Status: appsv1.StatefulSetStatus{ObservedGeneration: 2, CurrentRevision: "old-rev", UpdateRevision: "new-rev"}}
	pods := make([]corev1.Pod, 2)
	for i, name := range []string{"stalled-set-0", "stalled-set-1"} {
		podUID := types.UID("pod-uid-" + string(rune('0'+i)))
		pods[i] = corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: name, UID: podUID, Labels: map[string]string{"controller-revision-hash": "old-rev", "keaguard.example/cluster-uid": string(previous.UID)}, OwnerReferences: []metav1.OwnerReference{{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "StatefulSet", Name: set.Name, UID: set.UID, Controller: m2BoolPtr(true)}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	}
	return previous, current, config, set, pods
}

func m2PodDriftFixture() m2PodDriftObservation {
	severity := "INFO"
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: "drift-fixture", UID: "parent-uid", Generation: 6}, Spec: &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true, LoggingSeverity: &severity}}}
	current := parent.DeepCopy()
	current.Status.ObservedGeneration = current.Generation
	setM2Condition(current, "ArtifactReconciled", metav1.ConditionTrue, "ArtifactInSync", current.Generation)
	setM2Condition(current, "WorkloadReconciled", metav1.ConditionTrue, "ResourcesInSync", current.Generation)
	setM2Condition(current, "WorkloadReady", metav1.ConditionFalse, "PodDrift", current.Generation)
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: "drift-set", UID: "set-uid", Generation: 3}, Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "dhcp4", Image: m2KeaDHCP4Image}, {Name: "dhcp6", Image: m2KeaDHCP6Image}}}}}}
	old := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: "drift-set-0", UID: "old-pod-uid", ResourceVersion: "40", Labels: map[string]string{"keaguard.example/cluster-uid": string(parent.UID)}, OwnerReferences: []metav1.OwnerReference{{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "StatefulSet", Name: set.Name, UID: set.UID, Controller: m2BoolPtr(true)}}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "dhcp4", Image: m2KeaDHCP4Image}, {Name: "dhcp6", Image: m2KeaDHCP6Image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	currentPod := *old.DeepCopy()
	currentPod.Spec.Containers[0].Image = strings.Split(m2KeaDHCP4Image, "@")[0] + "@sha256:" + strings.Repeat("0", 64)
	return m2PodDriftObservation{Parent: parent, Current: current, OriginalStatefulSet: set.DeepCopy(), CurrentStatefulSet: set.DeepCopy(), OriginalPod: old, CurrentPod: currentPod}
}

func m2BoolPtr(value bool) *bool { return &value }

func m2Int32Ptr(value int32) *int32 { return &value }

func setM2Condition(parent *infrastructurev1alpha1.KeaCluster, kind string, status metav1.ConditionStatus, reason string, generation int64) {
	condition := metav1.Condition{Type: kind, Status: status, Reason: reason, ObservedGeneration: generation, LastTransitionTime: metav1.Now()}
	for i := range parent.Status.Conditions {
		if parent.Status.Conditions[i].Type == kind {
			parent.Status.Conditions[i] = condition
			return
		}
	}
	parent.Status.Conditions = append(parent.Status.Conditions, condition)
}

func cloneM2StalledPolicyObservation(in m2StalledPolicyObservation) m2StalledPolicyObservation {
	out := in
	out.Previous = in.Previous.DeepCopy()
	out.Current = in.Current.DeepCopy()
	out.Config = in.Config.DeepCopy()
	out.StatefulSet = in.StatefulSet.DeepCopy()
	out.PreviousPodUIDs = map[string]types.UID{}
	for key, value := range in.PreviousPodUIDs {
		out.PreviousPodUIDs[key] = value
	}
	out.Pods = make([]corev1.Pod, len(in.Pods))
	for i := range in.Pods {
		out.Pods[i] = *in.Pods[i].DeepCopy()
	}
	return out
}

func cloneM2PodDriftObservation(in m2PodDriftObservation) m2PodDriftObservation {
	out := in
	out.Parent = in.Parent.DeepCopy()
	out.Current = in.Current.DeepCopy()
	out.OriginalStatefulSet = in.OriginalStatefulSet.DeepCopy()
	out.CurrentStatefulSet = in.CurrentStatefulSet.DeepCopy()
	out.OriginalPod = *in.OriginalPod.DeepCopy()
	out.CurrentPod = *in.CurrentPod.DeepCopy()
	return out
}

func TestUnitM2BadImageReferenceIsPinnedToOfficialRepository(t *testing.T) {
	got, err := m2NonexistentImageReference(m2KeaDHCP4Image)
	if err != nil {
		t.Fatal(err)
	}
	if !m2IsDifferentDigestInSameRepository(got, m2KeaDHCP4Image) {
		t.Fatalf("test-only image is not a different digest in the approved repository: %q", got)
	}
	for _, bad := range []string{"", "busybox:latest", "docker.cloudsmith.io/isc/docker/kea-dhcp6@sha256:" + strings.Repeat("0", 64), "docker.cloudsmith.io/isc/docker/kea-dhcp4:latest"} {
		if _, err := m2NonexistentImageReference(bad); err == nil {
			t.Fatalf("unsupported or nonapproved base image accepted: %q", bad)
		}
	}
}
