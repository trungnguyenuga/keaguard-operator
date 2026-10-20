/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/
package e2e

import (
	"context"
	"fmt"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("M2: Cleanup", func() {
	m2It("disables a live workload in observed process, StatefulSet, Service, configuration order", func() {
		parent, _, _, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
		previous := &infrastructurev1alpha1.KeaCluster{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(parent), previous)).To(Succeed())
		parent = previous.DeepCopy()
		configName, serviceName, setName := m2NamesFor(parent)
		set := &appsv1.StatefulSet{}
		service := &corev1.Service{}
		config := &corev1.ConfigMap{}
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, set)).To(Succeed())
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: serviceName}, service)).To(Succeed())
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, config)).To(Succeed())
		identities := []m2FixtureIdentity{}
		for _, object := range []client.Object{set, service, config} {
			identity, err := m2IdentityFor(object)
			Expect(err).NotTo(HaveOccurred())
			identities = append(identities, identity)
		}
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			for index := len(identities) - 1; index >= 0; index-- {
				if err := m2ReleaseCleanupHold(cleanupCtx, identities[index]); err != nil {
					fmt.Fprintf(GinkgoWriter, "T19 emergency exact-UID cleanup-hold release failed for %s/%s UID %s: %v\n", identities[index].Key.Namespace, identities[index].Key.Name, identities[index].UID, err)
				}
			}
		}()
		for _, object := range []client.Object{set, service, config} {
			Expect(m2AddCleanupHold(object)).To(Succeed())
		}

		parent.Spec.Workload.Enabled = false
		Expect(m2UpdateObject(labctx, parent, "absent")).To(Succeed())
		m2ObserveDisabledCleanup := func() (m2DisabledCleanupObservation, int, error) {
			current := &infrastructurev1alpha1.KeaCluster{}
			if err := admin.Get(labctx, client.ObjectKeyFromObject(parent), current); err != nil {
				return m2DisabledCleanupObservation{}, 0, err
			}
			observation := m2DisabledCleanupObservation{Previous: previous, Current: current}
			actualSet := &appsv1.StatefulSet{}
			if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, actualSet); err == nil {
				observation.StatefulSet = actualSet
			} else if !apierrors.IsNotFound(err) {
				return observation, 0, err
			}
			actualService := &corev1.Service{}
			if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: serviceName}, actualService); err == nil {
				observation.Service = actualService
			} else if !apierrors.IsNotFound(err) {
				return observation, 0, err
			}
			actualConfig := &corev1.ConfigMap{}
			if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, actualConfig); err == nil {
				observation.ConfigMap = actualConfig
			} else if !apierrors.IsNotFound(err) {
				return observation, 0, err
			}
			pods := &corev1.PodList{}
			if err := admin.List(labctx, pods, client.InNamespace(runtimeNamespace), client.MatchingLabels{"keaguard.example/cluster-uid": string(parent.UID)}); err != nil {
				return observation, 0, err
			}
			observation.Pods = pods.Items
			stage, err := m2CheckDisabledCleanupObservation(observation)
			return observation, stage, err
		}
		Eventually(func() (int, error) { _, stage, err := m2ObserveDisabledCleanup(); return stage, err }, 30*time.Second, 150*time.Millisecond).Should(Equal(0))
		// A case-owned finalizer holds the StatefulSet after Pod termination,
		// exposing a fresh API observation of the shutdown boundary.
		Eventually(func() (int, error) { _, stage, err := m2ObserveDisabledCleanup(); return stage, err }, 90*time.Second, 200*time.Millisecond).Should(Equal(1))
		Expect(m2ReleaseCleanupHold(labctx, identities[0])).To(Succeed())
		Eventually(func() (int, error) { _, stage, err := m2ObserveDisabledCleanup(); return stage, err }, 60*time.Second, 200*time.Millisecond).Should(Equal(2))
		Expect(m2ReleaseCleanupHold(labctx, identities[1])).To(Succeed())
		Eventually(func() (int, error) { _, stage, err := m2ObserveDisabledCleanup(); return stage, err }, 60*time.Second, 200*time.Millisecond).Should(Equal(3))
		Expect(m2ReleaseCleanupHold(labctx, identities[2])).To(Succeed())
		Eventually(func() (int, error) { _, stage, err := m2ObserveDisabledCleanup(); return stage, err }, 60*time.Second, 200*time.Millisecond).Should(Equal(4))
	})
})

var _ = Describe("M2: Garbage collection", func() {
	m2It("proves asynchronous parent and dependent GC with the manager stopped", func() {
		parent, originalPods, _, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
		assertArtifact(parent)
		child := t14CurrentArtifact(parent)
		set := &appsv1.StatefulSet{}
		configName, serviceName, setName := m2NamesFor(parent)
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, set)).To(Succeed())
		Expect(set.UID).NotTo(BeEmpty())
		Expect(originalPods).To(HaveLen(2))
		service := &corev1.Service{}
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: serviceName}, service)).To(Succeed())
		workloadConfig := &corev1.ConfigMap{}
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, workloadConfig)).To(Succeed())
		Expect(m2SetManagerReplicas(labctx, 0)).To(Succeed())
		Expect(m2WaitManagerStopped(labctx, m2ActiveScenario.Manager.UID)).To(Succeed())
		fmt.Fprintf(GinkgoWriter, "M2 GC proof parentUID=%s artifactUID=%s statefulSetUID=%s serviceUID=%s podUIDs=%v managerStopped=true\n", parent.UID, child.UID, set.UID, service.UID, m2PodIdentitySummary(originalPods))
		t14DeleteParent(parent)
		parentFixture := m2ActiveScenario.ledger.fixtures[fixtureKey(m2FixtureIdentity{Key: client.ObjectKeyFromObject(parent), GVK: infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"), UID: parent.UID})]
		Expect(m2WaitCaseWorkloadAbsent(labctx, parentFixture)).To(Succeed())
		t14WaitUIDGone(client.ObjectKeyFromObject(child), child.UID)
		for _, target := range []struct {
			name   string
			object client.Object
			uid    types.UID
		}{
			{serviceName, &corev1.Service{}, service.UID},
			{configName, &corev1.ConfigMap{}, workloadConfig.UID},
		} {
			key := client.ObjectKey{Namespace: runtimeNamespace, Name: target.name}
			Eventually(func() bool {
				if err := admin.Get(labctx, key, target.object); apierrors.IsNotFound(err) {
					return true
				} else if err != nil {
					return false
				}
				return target.object.GetUID() != target.uid
			}, 120*time.Second, time.Second).Should(BeTrue(), "GC did not remove recorded child key %s/%s UID %s", runtimeNamespace, target.name, target.uid)
		}
	})
})

func m2AddCleanupHold(object client.Object) error {
	for _, existing := range object.GetFinalizers() {
		if existing == t14HoldFinalizer {
			return fmt.Errorf("test hold finalizer already exists on target; refusing to claim ownership")
		}
	}
	object.SetFinalizers(append(object.GetFinalizers(), t14HoldFinalizer))
	return m2UpdateObject(labctx, object, "absent")
}

func m2ReleaseCleanupHold(ctx context.Context, identity m2FixtureIdentity) error {
	if ctx == nil || ctx.Err() != nil || identity.UID == "" || identity.Key.Namespace != m2LabProfile.runtimeNamespace {
		return fmt.Errorf("cleanup hold release requires a live context and exact runtime fixture identity")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := requestCtx.Err(); err != nil {
			return err
		}
		object, err := m2NewFixtureObject(identity.GVK)
		if err != nil {
			return err
		}
		getCtx, getCancel := context.WithTimeout(requestCtx, 5*time.Second)
		err = admin.Get(getCtx, identity.Key, object)
		getCancel()
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if object.GetUID() != identity.UID {
			return fmt.Errorf("cleanup hold target incarnation changed")
		}
		finalizers := object.GetFinalizers()
		if !slices.Contains(finalizers, t14HoldFinalizer) {
			return nil
		}
		updated := make([]string, 0, len(finalizers)-1)
		for _, finalizer := range finalizers {
			if finalizer != t14HoldFinalizer {
				updated = append(updated, finalizer)
			}
		}
		object.SetFinalizers(updated)
		updateCtx, updateCancel := context.WithTimeout(requestCtx, 5*time.Second)
		err = admin.Update(updateCtx, object)
		updateCancel()
		return err
	})
}

type m2DisabledCleanupObservation struct {
	Previous    *infrastructurev1alpha1.KeaCluster
	Current     *infrastructurev1alpha1.KeaCluster
	StatefulSet *appsv1.StatefulSet
	Pods        []corev1.Pod
	Service     *corev1.Service
	ConfigMap   *corev1.ConfigMap
}

func m2DisabledCleanupFixture() (*infrastructurev1alpha1.KeaCluster, *infrastructurev1alpha1.KeaCluster, *appsv1.StatefulSet, []corev1.Pod, *corev1.Service, *corev1.ConfigMap) {
	previous := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: "cleanup-unit", UID: types.UID("parent-uid"), Generation: 1}}
	previous.Spec = &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true}}
	current := previous.DeepCopy()
	current.Generation = 2
	current.Spec.Workload.Enabled = false
	current.Status.ObservedGeneration = current.Generation
	setM2Condition(current, "ArtifactReconciled", metav1.ConditionTrue, "ArtifactInSync", current.Generation)
	configName, serviceName, setName := m2NamesFor(current)
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: setName, UID: types.UID("set-uid"), OwnerReferences: []metav1.OwnerReference{m2CleanupOwner(infrastructurev1alpha1.GroupVersion.String(), "KeaCluster", current.Name, current.UID)}}, Spec: appsv1.StatefulSetSpec{Replicas: func() *int32 { value := int32(0); return &value }()}}
	pods := []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: setName + "-0", UID: types.UID("pod-uid"), Labels: map[string]string{"keaguard.example/cluster-uid": string(current.UID)}, OwnerReferences: []metav1.OwnerReference{m2CleanupOwner("apps/v1", "StatefulSet", set.Name, set.UID)}}}}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: serviceName, UID: types.UID("service-uid"), OwnerReferences: []metav1.OwnerReference{m2CleanupOwner(infrastructurev1alpha1.GroupVersion.String(), "KeaCluster", current.Name, current.UID)}}}
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, Name: configName, UID: types.UID("config-uid"), OwnerReferences: []metav1.OwnerReference{m2CleanupOwner(infrastructurev1alpha1.GroupVersion.String(), "KeaCluster", current.Name, current.UID)}}}
	return previous, current, set, pods, service, config
}

func m2CleanupOwner(apiVersion, kind, name string, uid types.UID) metav1.OwnerReference {
	controller := true
	return metav1.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, UID: uid, Controller: &controller}
}

func cloneM2DisabledCleanupObservation(in m2DisabledCleanupObservation) m2DisabledCleanupObservation {
	out := m2DisabledCleanupObservation{Previous: in.Previous.DeepCopy(), Current: in.Current.DeepCopy(), Pods: make([]corev1.Pod, len(in.Pods))}
	for i := range in.Pods {
		in.Pods[i].DeepCopyInto(&out.Pods[i])
	}
	if in.StatefulSet != nil {
		out.StatefulSet = in.StatefulSet.DeepCopy()
	}
	if in.Service != nil {
		out.Service = in.Service.DeepCopy()
	}
	if in.ConfigMap != nil {
		out.ConfigMap = in.ConfigMap.DeepCopy()
	}
	return out
}

// m2CheckDisabledCleanupObservation accepts only a current disabled parent and
// the exact ordered cleanup frontier. The returned stage is an observation,
// not a claim that a later stage has completed.
func m2CheckDisabledCleanupObservation(o m2DisabledCleanupObservation) (int, error) {
	if o.Previous == nil || o.Current == nil || o.Previous.UID == "" || o.Current.UID != o.Previous.UID ||
		o.Current.Generation <= o.Previous.Generation || o.Current.Status.ObservedGeneration != o.Current.Generation ||
		o.Current.Spec == nil || o.Current.Spec.Workload == nil || o.Current.Spec.Workload.Enabled {
		return 0, fmt.Errorf("disabled cleanup parent identity, generation, or desired state is not current")
	}
	artifact := meta.FindStatusCondition(o.Current.Status.Conditions, "ArtifactReconciled")
	if artifact == nil || artifact.Status != metav1.ConditionTrue || artifact.Reason != "ArtifactInSync" || artifact.ObservedGeneration != o.Current.Generation {
		return 0, fmt.Errorf("ArtifactReconciled is not current")
	}
	configName, serviceName, setName := m2NamesFor(o.Current)
	if o.StatefulSet != nil {
		if err := m2CheckCleanupOwner(o.StatefulSet, o.Current, setName); err != nil {
			return 0, err
		}
	}
	if o.Service != nil {
		if err := m2CheckCleanupOwner(o.Service, o.Current, serviceName); err != nil {
			return 0, err
		}
	}
	if o.ConfigMap != nil {
		if err := m2CheckCleanupOwner(o.ConfigMap, o.Current, configName); err != nil {
			return 0, err
		}
	}
	for _, pod := range o.Pods {
		if pod.UID == "" || pod.Namespace != o.Current.Namespace || pod.Labels["keaguard.example/cluster-uid"] != string(o.Current.UID) {
			return 0, fmt.Errorf("candidate Pod is foreign or lacks exact cluster identity")
		}
		if o.StatefulSet != nil {
			owner := metav1.GetControllerOf(&pod)
			if owner == nil || owner.UID != o.StatefulSet.UID || owner.Kind != "StatefulSet" || owner.Name != o.StatefulSet.Name || owner.APIVersion != "apps/v1" {
				return 0, fmt.Errorf("candidate Pod is not controlled by the observed StatefulSet")
			}
		}
	}
	if o.StatefulSet != nil {
		if o.Service == nil || o.ConfigMap == nil {
			return 0, fmt.Errorf("Service or configuration disappeared before StatefulSet")
		}
		if o.StatefulSet.Spec.Replicas == nil || *o.StatefulSet.Spec.Replicas != 0 {
			return 0, fmt.Errorf("StatefulSet has not been scaled to zero")
		}
		if len(o.Pods) != 0 {
			return 0, nil
		}
		return 1, nil
	}
	if len(o.Pods) != 0 {
		return 0, fmt.Errorf("candidate Pods remain after StatefulSet absence")
	}
	if o.Service != nil && o.ConfigMap == nil {
		return 0, fmt.Errorf("configuration disappeared before Service")
	}
	if o.Service != nil {
		return 2, nil
	}
	if o.ConfigMap != nil {
		return 3, nil
	}
	workload := meta.FindStatusCondition(o.Current.Status.Conditions, "WorkloadReconciled")
	ready := meta.FindStatusCondition(o.Current.Status.Conditions, "WorkloadReady")
	if workload == nil || workload.Status != metav1.ConditionTrue || workload.Reason != "WorkloadDisabled" || workload.ObservedGeneration != o.Current.Generation ||
		ready == nil || ready.Status != metav1.ConditionTrue || ready.Reason != "WorkloadDisabled" || ready.ObservedGeneration != o.Current.Generation {
		return 0, fmt.Errorf("fully removed workload lacks current disabled conditions")
	}
	return 4, nil
}

func m2CheckCleanupOwner(obj metav1.Object, parent *infrastructurev1alpha1.KeaCluster, expectedName string) error {
	if obj == nil {
		return nil
	}
	if parent == nil || obj.GetName() != expectedName || obj.GetNamespace() != parent.Namespace || obj.GetUID() == "" {
		return fmt.Errorf("cleanup child key or UID is unexpected")
	}
	controller := metav1.GetControllerOf(obj)
	if controller == nil || controller.UID != parent.UID || controller.APIVersion != infrastructurev1alpha1.GroupVersion.String() || controller.Kind != "KeaCluster" || controller.Name != parent.Name {
		return fmt.Errorf("cleanup child owner UID is not the expected parent")
	}
	return nil
}
