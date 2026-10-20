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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
)

func TestUnitM2Ownership(t *testing.T) {
	parent, _, _ := m2ResourceFixture(t)
	valid := metav1.OwnerReference{APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: parent.Name, UID: parent.UID, Controller: ptr(true)}
	foreign := valid
	foreign.UID = "old-uid"
	tests := []struct {
		name  string
		refs  []metav1.OwnerReference
		owned bool
		sole  bool
	}{
		{"valid sole controller", []metav1.OwnerReference{valid}, true, true},
		{"valid controller and extra non-controller", []metav1.OwnerReference{valid, {APIVersion: "v1", Kind: "ConfigMap", Name: "other", UID: "other"}}, true, false},
		{"unowned", nil, false, false},
		{"missing controller flag", []metav1.OwnerReference{{APIVersion: valid.APIVersion, Kind: valid.Kind, Name: valid.Name, UID: valid.UID}}, false, false},
		{"wrong API version", []metav1.OwnerReference{{APIVersion: "wrong/v1", Kind: valid.Kind, Name: valid.Name, UID: valid.UID, Controller: ptr(true)}}, false, false},
		{"wrong kind", []metav1.OwnerReference{{APIVersion: valid.APIVersion, Kind: "Other", Name: valid.Name, UID: valid.UID, Controller: ptr(true)}}, false, false},
		{"wrong name", []metav1.OwnerReference{{APIVersion: valid.APIVersion, Kind: valid.Kind, Name: "other", UID: valid.UID, Controller: ptr(true)}}, false, false},
		{"stale UID", []metav1.OwnerReference{foreign}, false, false},
		{"duplicate controllers", []metav1.OwnerReference{valid, valid}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{OwnerReferences: tt.refs}}
			if got := workloadOwnedBy(cm, parent); got != tt.owned {
				t.Fatalf("owned = %t, want %t", got, tt.owned)
			}
			if got := workloadSoleOwnedBy(cm, parent); got != tt.sole {
				t.Fatalf("sole-owned = %t, want %t", got, tt.sole)
			}
		})
	}
}

func TestUnitM2PodCandidates(t *testing.T) {
	parent, names, _ := m2ResourceFixture(t)
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: names.StatefulSet, Namespace: parent.Namespace, UID: types.UID("sts-uid")}}
	controllerRef := func(apiVersion, kind, name string, uid types.UID) metav1.OwnerReference {
		return metav1.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, UID: uid, Controller: ptr(true)}
	}
	pod := func(name string) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: parent.Namespace}}
	}
	actualUID := pod("actual-uid-link")
	actualUID.OwnerReferences = []metav1.OwnerReference{controllerRef("malformed", "Other", "wrong", set.UID)}
	staleName := pod(names.StatefulSet + "-2")
	staleName.OwnerReferences = []metav1.OwnerReference{controllerRef("apps/v1", "StatefulSet", names.StatefulSet, "stale")}
	parentLabel := pod("label-only")
	parentLabel.Labels = map[string]string{clusterUIDLabel: string(parent.UID)}
	highOrdinal := pod(names.StatefulSet + "-12")
	valid := pod(names.StatefulSet + "-0")
	valid.OwnerReferences = []metav1.OwnerReference{controllerRef("apps/v1", "StatefulSet", names.StatefulSet, set.UID)}
	notCandidate := pod("random-pod")
	input := []corev1.Pod{notCandidate, highOrdinal, parentLabel, valid, staleName, actualUID, valid}
	got := candidateWorkloadPods(parent, names, set, input)
	want := []string{"actual-uid-link", names.StatefulSet + "-0", names.StatefulSet + "-12", names.StatefulSet + "-2", "label-only"}
	gotNames := make([]string, len(got))
	for i := range got {
		gotNames[i] = got[i].Name
	}
	if !reflect.DeepEqual(gotNames, want) {
		t.Fatalf("candidate names = %v, want %v", gotNames, want)
	}
	if workloadPodsSafe(set, got, false) {
		t.Fatal("invalid/stale candidate ownership was considered safe")
	}
	if workloadPodsSafe(set, got[:0], false) != true {
		t.Fatal("empty candidate set is unsafe")
	}
	owned := []corev1.Pod{valid}
	if !workloadPodsSafe(set, owned, false) || !workloadPodsSafe(set, owned, true) {
		t.Fatal("valid sole-owned pod rejected")
	}
	withExtraOwner := valid.DeepCopy()
	withExtraOwner.OwnerReferences = append(withExtraOwner.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "x", UID: "x"})
	if !workloadPodsSafe(set, []corev1.Pod{*withExtraOwner}, false) || workloadPodsSafe(set, []corev1.Pod{*withExtraOwner}, true) {
		t.Fatal("additional-owner policy mismatch")
	}
}

func TestUnitM2Conditions(t *testing.T) {
	parent, names, config, observation, artifact := healthyWorkloadFixture(t)
	conditions := workloadConditions(parent, names, config, observation, artifact)
	if len(conditions) != 2 || conditions[0].Type != "WorkloadReconciled" || conditions[1].Type != "WorkloadReady" {
		t.Fatalf("conditions = %#v", conditions)
	}
	if conditions[0].Status != metav1.ConditionTrue || conditions[0].Reason != "ResourcesInSync" || conditions[1].Status != metav1.ConditionTrue || conditions[1].Reason != "ProcessesHealthy" {
		t.Fatalf("healthy conditions = %#v", conditions)
	}

	cases := []struct {
		name             string
		edit             func(*workloadObservation, *infrastructurev1alpha1.KeaCluster, *metav1.Condition)
		reconciledStatus metav1.ConditionStatus
		reconciledReason string
		readyStatus      metav1.ConditionStatus
		readyReason      string
	}{
		{"missing config", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.ConfigMap = nil
		}, metav1.ConditionFalse, "ResourcesOutOfSync", metav1.ConditionFalse, "RolloutPending"},
		{"config observation error", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.ConfigMapErr = errors.New("denied")
		}, metav1.ConditionUnknown, "ObservationFailed", metav1.ConditionUnknown, "ObservationFailed"},
		{"pod list error preserves resource sync", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.PodsErr = errors.New("denied")
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionUnknown, "ObservationFailed"},
		{"foreign config", func(o *workloadObservation, p *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.ConfigMap.OwnerReferences = nil
			_ = p
		}, metav1.ConditionFalse, "OwnershipConflict", metav1.ConditionFalse, "WorkloadBlocked"},
		{"config drift", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.ConfigMap.Data["kea-dhcp4.conf"] += " "
		}, metav1.ConditionFalse, "ResourcesOutOfSync", metav1.ConditionFalse, "WorkloadBlocked"},
		{"incompatible service identity", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Service.Spec.ClusterIP = "10.0.0.9"
		}, metav1.ConditionFalse, "IncompatibleResource", metav1.ConditionFalse, "WorkloadBlocked"},
		{"incompatible StatefulSet identity", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.StatefulSet.Spec.ServiceName = "foreign"
		}, metav1.ConditionFalse, "IncompatibleResource", metav1.ConditionFalse, "WorkloadBlocked"},
		{"rollout pending", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.StatefulSet.Status.ReadyReplicas = 1
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionFalse, "RolloutPending"},
		{"missing expected pod", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Pods = o.Pods[:1]
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionFalse, "RolloutPending"},
		{"higher ordinal candidate", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			pod := *o.Pods[0].DeepCopy()
			pod.Name = o.StatefulSet.Name + "-8"
			o.Pods = append(o.Pods[:1], pod)
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionFalse, "PodDrift"},
		{"foreign Pod owner", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Pods[0].OwnerReferences[0].UID = "stale"
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionFalse, "WorkloadBlocked"},
		{"stale pod revision", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Pods[0].Labels["controller-revision-hash"] = "old"
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionFalse, "PodDrift"},
		{"config environment drift", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Pods[0].Spec.Containers[0].Env[0].Value = "wrong"
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionFalse, "PodDrift"},
		{"missing pod ready condition", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Pods[0].Status.Conditions = nil
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionUnknown, "ObservationFailed"},
		{"container stopped", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Pods[0].Status.ContainerStatuses[0].State.Running = nil
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionFalse, "ProcessUnhealthy"},
		{"pod image drift", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Pods[0].Spec.Containers[0].Image = "foreign"
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionFalse, "PodDrift"},
		{"process unhealthy", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Pods[0].Status.ContainerStatuses[0].Ready = false
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionFalse, "ProcessUnhealthy"},
		{"image identity missing", func(o *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, _ *metav1.Condition) {
			o.Pods[0].Status.ContainerStatuses[0].ImageID = ""
		}, metav1.ConditionTrue, "ResourcesInSync", metav1.ConditionUnknown, "ObservationFailed"},
		{"artifact conflict", func(_ *workloadObservation, _ *infrastructurev1alpha1.KeaCluster, a *metav1.Condition) {
			a.Status = metav1.ConditionFalse
			a.Reason = "OwnershipConflict"
		}, metav1.ConditionFalse, "WorkloadBlocked", metav1.ConditionFalse, "WorkloadBlocked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := parent.DeepCopy()
			obs := cloneWorkloadObservation(observation)
			a := artifact
			tc.edit(&obs, p, &a)
			got := workloadConditions(p, names, config, obs, a)
			if got[0].Status != tc.reconciledStatus || got[0].Reason != tc.reconciledReason || got[1].Status != tc.readyStatus || got[1].Reason != tc.readyReason {
				t.Fatalf("conditions = %#v", got)
			}
			for _, c := range got {
				if c.ObservedGeneration != p.Generation {
					t.Fatalf("wrong observed generation: %#v", c)
				}
			}
		})
	}
	t.Run("disabled with no resources", func(t *testing.T) {
		p := parent.DeepCopy()
		p.Spec.Workload.Enabled = false
		got := workloadConditions(p, names, config, workloadObservation{}, artifact)
		if got[0].Status != metav1.ConditionTrue || got[0].Reason != "WorkloadDisabled" || got[1].Status != metav1.ConditionTrue || got[1].Reason != "WorkloadDisabled" {
			t.Fatalf("disabled conditions = %#v", got)
		}
	})
	t.Run("disabled cleanup remains pending", func(t *testing.T) {
		p := parent.DeepCopy()
		p.Spec.Workload.Enabled = false
		got := workloadConditions(p, names, config, observation, artifact)
		if got[0].Status != metav1.ConditionFalse || got[0].Reason != "CleanupPending" || got[1].Status != metav1.ConditionFalse || got[1].Reason != "DisablePending" {
			t.Fatalf("pending cleanup conditions = %#v", got)
		}
	})
	t.Run("disabled collision preserves identity artifact", func(t *testing.T) {
		p := parent.DeepCopy()
		p.Spec.Workload.Enabled = false
		collidingNames := names
		collidingNames.ConfigMap = p.Name
		obs := workloadObservation{ConfigMap: desiredKeaConfig(p, collidingNames, config)}
		got := workloadConditions(p, collidingNames, config, obs, artifact)
		if got[0].Status != metav1.ConditionFalse || got[0].Reason != "NamingCollision" || got[1].Status != metav1.ConditionFalse || got[1].Reason != "WorkloadBlocked" {
			t.Fatalf("collision conditions = %#v", got)
		}
	})
	t.Run("transition timestamp is stable when status is stable", func(t *testing.T) {
		p := parent.DeepCopy()
		p.Status.Conditions = append(p.Status.Conditions, conditions[0], conditions[1])
		got := workloadConditions(p, names, config, observation, artifact)
		if !got[0].LastTransitionTime.Equal(&conditions[0].LastTransitionTime) || !got[1].LastTransitionTime.Equal(&conditions[1].LastTransitionTime) {
			t.Fatal("stable status changed transition time")
		}
	})
}

func TestUnitM2DirectObservation(t *testing.T) {
	parent, names, _, observation, _ := healthyWorkloadFixture(t)
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	objects := []client.Object{observation.ConfigMap, observation.Service, observation.StatefulSet}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	r := &KeaClusterReconciler{APIReader: reader}
	got := r.observeWorkload(context.Background(), parent, names)
	if got.ConfigMapErr != nil || got.ServiceErr != nil || got.StatefulSetErr != nil || got.PodsErr != nil || got.ConfigMap == nil || got.Service == nil || got.StatefulSet == nil || len(got.Pods) != 0 {
		t.Fatalf("direct observation of children/empty list = %#v", got)
	}
	emptyReader := fake.NewClientBuilder().WithScheme(scheme).Build()
	empty := (&KeaClusterReconciler{APIReader: emptyReader}).observeWorkload(context.Background(), parent, names)
	if empty.ConfigMap != nil || empty.Service != nil || empty.StatefulSet != nil || empty.ConfigMapErr != nil || empty.ServiceErr != nil || empty.StatefulSetErr != nil || empty.PodsErr != nil || len(empty.Pods) != 0 {
		t.Fatalf("successful empty direct observation = %#v", empty)
	}
	failing := &listErrorReader{Reader: emptyReader, err: errors.New("pod list denied")}
	failed := (&KeaClusterReconciler{APIReader: failing}).observeWorkload(context.Background(), parent, names)
	if failed.PodsErr == nil || !strings.Contains(failed.PodsErr.Error(), "pod list denied") {
		t.Fatalf("failed Pod list error = %v", failed.PodsErr)
	}
	getFailure := &getErrorReader{Reader: emptyReader, name: names.Service, err: errors.New("service read denied")}
	partial := (&KeaClusterReconciler{APIReader: getFailure}).observeWorkload(context.Background(), parent, names)
	if partial.ServiceErr == nil || !strings.Contains(partial.ServiceErr.Error(), "service read denied") || partial.ConfigMapErr != nil || partial.StatefulSetErr != nil || partial.PodsErr != nil {
		t.Fatalf("independent direct Get errors were not retained: %#v", partial)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	canceledObservation := (&KeaClusterReconciler{APIReader: emptyReader}).observeWorkload(canceled, parent, names)
	if canceledObservation.ConfigMapErr == nil || canceledObservation.ServiceErr == nil || canceledObservation.StatefulSetErr == nil || canceledObservation.PodsErr == nil {
		t.Fatalf("canceled observation claimed missing/safe state: %#v", canceledObservation)
	}
}

type listErrorReader struct {
	client.Reader
	err error
}

type getErrorReader struct {
	client.Reader
	name string
	err  error
}

func (r *getErrorReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	if key.Name == r.name {
		return r.err
	}
	return r.Reader.Get(ctx, key, object, opts...)
}

func (r *listErrorReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*corev1.PodList); ok {
		return r.err
	}
	return r.Reader.List(ctx, list, opts...)
}

func healthyWorkloadFixture(t *testing.T) (*infrastructurev1alpha1.KeaCluster, workloadNames, workloadConfig, workloadObservation, metav1.Condition) {
	t.Helper()
	parent, names, config := m2ResourceFixture(t)
	set := desiredKeaStatefulSet(parent, names, config)
	set.UID = types.UID("sts-current")
	set.Generation = 3
	set.Status = appsv1.StatefulSetStatus{ObservedGeneration: 3, Replicas: 2, CurrentReplicas: 2, UpdatedReplicas: 2, ReadyReplicas: 2, AvailableReplicas: 2, CurrentRevision: "revision-a", UpdateRevision: "revision-a"}
	pods := make([]corev1.Pod, 2)
	for ordinal := range pods {
		name := fmt.Sprintf("%s-%d", names.StatefulSet, ordinal)
		pods[ordinal] = corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: parent.Namespace,
			Labels:          map[string]string{clusterUIDLabel: string(parent.UID), componentLabel: "workload", "controller-revision-hash": "revision-a"},
			Annotations:     map[string]string{configHashAnnotation: config.Hash},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: set.Name, UID: set.UID, Controller: ptr(true)}},
		}, Spec: *set.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "dhcp4", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}, ImageID: "containerd://sha256:4"},
				{Name: "dhcp6", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}, ImageID: "containerd://sha256:6"},
			},
		}}
	}
	artifact := metav1.Condition{Type: "ArtifactReconciled", Status: metav1.ConditionTrue, Reason: "ArtifactInSync", ObservedGeneration: parent.Generation, LastTransitionTime: metav1.NewTime(time.Unix(100, 0))}
	configMap := desiredKeaConfig(parent, names, config)
	configMap.UID = types.UID("config-uid")
	service := desiredHeadlessService(parent, names)
	service.UID = types.UID("service-uid")
	return parent, names, config, workloadObservation{ConfigMap: configMap, Service: service, StatefulSet: set, Pods: pods}, artifact
}

func cloneWorkloadObservation(in workloadObservation) workloadObservation {
	out := in
	if in.ConfigMap != nil {
		out.ConfigMap = in.ConfigMap.DeepCopy()
	}
	if in.Service != nil {
		out.Service = in.Service.DeepCopy()
	}
	if in.StatefulSet != nil {
		out.StatefulSet = in.StatefulSet.DeepCopy()
	}
	out.Pods = make([]corev1.Pod, len(in.Pods))
	for i := range in.Pods {
		in.Pods[i].DeepCopyInto(&out.Pods[i])
	}
	return out
}
