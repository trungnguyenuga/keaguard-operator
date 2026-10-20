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
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("M2: Reconciliation", func() {
	var requestCtx context.Context
	var stop context.CancelFunc
	var namespace *corev1.Namespace
	var recorder *statusRecordingClient
	var reconciler *KeaClusterReconciler

	BeforeEach(func() {
		requestCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		DeferCleanup(stop)
		namespace = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "m2-reconcile-"}}
		Expect(k8sClient.Create(requestCtx, namespace)).To(Succeed())
		recorder = &statusRecordingClient{Client: k8sClient}
		reconciler = newTestReconciler(recorder, k8sClient, namespace.Name)
		DeferCleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &appsv1.StatefulSet{}, client.InNamespace(namespace.Name))).To(Succeed())
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.Service{}, client.InNamespace(namespace.Name))).To(Succeed())
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.ConfigMap{}, client.InNamespace(namespace.Name))).To(Succeed())
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &infrastructurev1alpha1.KeaCluster{}, client.InNamespace(namespace.Name))).To(Succeed())
			Expect(k8sClient.Delete(cleanupCtx, namespace)).To(Succeed())
		})
	})

	newParent := func(name string, spec *infrastructurev1alpha1.KeaClusterSpec) *infrastructurev1alpha1.KeaCluster {
		parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace.Name}, Spec: spec}
		Expect(k8sClient.Create(requestCtx, parent)).To(Succeed())
		return parent
	}
	reconcile := func(parent *infrastructurev1alpha1.KeaCluster) ctrl.Result {
		result, err := reconciler.Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
		Expect(err).NotTo(HaveOccurred())
		return result
	}
	workloadSpec := func(enabled bool, severity string) *infrastructurev1alpha1.KeaClusterSpec {
		return &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: enabled, LoggingSeverity: &severity}}
	}
	identity := func(parent *infrastructurev1alpha1.KeaCluster) *corev1.ConfigMap {
		object := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), object)).To(Succeed())
		return object
	}
	storedParent := func(parent *infrastructurev1alpha1.KeaCluster) *infrastructurev1alpha1.KeaCluster {
		object := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), object)).To(Succeed())
		return object
	}
	assertCondition := func(parent *infrastructurev1alpha1.KeaCluster, conditionType string, status metav1.ConditionStatus, reason string) {
		condition := meta.FindStatusCondition(storedParent(parent).Status.Conditions, conditionType)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(status))
		Expect(condition.Reason).To(Equal(reason))
		Expect(condition.ObservedGeneration).To(Equal(parent.Generation))
	}
	settleEnabled := func(parent *infrastructurev1alpha1.KeaCluster) {
		var result ctrl.Result
		for pass := 0; pass < 8; pass++ {
			result = reconcile(parent)
			if result.RequeueAfter == 5*time.Second || result.RequeueAfter == 5*time.Minute {
				return
			}
			Expect(result.RequeueAfter).To(Equal(time.Second), "each accepted mutation is followed by a fresh observation")
		}
		operations := recorder.operationSnapshot()
		if len(operations) > 12 {
			operations = operations[len(operations)-12:]
		}
		names := namesFor(parent)
		_, severity := effectiveWorkload(parent)
		config, _ := generateKeaConfig(severity)
		actual := &appsv1.StatefulSet{}
		difference := ""
		if err := k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.StatefulSet}, actual); err == nil {
			actualSpec, desiredSpec := actual.DeepCopy().Spec, desiredKeaStatefulSet(parent, names, config).Spec
			normalizeStatefulSetDefaults(&actualSpec)
			normalizeStatefulSetDefaults(&desiredSpec)
			normalizeEmptyCollections(reflect.ValueOf(&actualSpec).Elem())
			normalizeEmptyCollections(reflect.ValueOf(&desiredSpec).Elem())
			difference = cmp.Diff(desiredSpec, actualSpec)
		}
		Fail(fmt.Sprintf("enabled workload did not settle, last result=%+v recent operations=%+v statefulset diff (-want +got)=%s", result, operations, difference))
	}

	It("keeps omitted and disabled specifications identity-only, including severity changes", func() {
		omitted := newParent("omitted", nil)
		disabled := newParent("disabled", workloadSpec(false, "INFO"))
		Expect(reconcile(omitted).RequeueAfter).To(Equal(time.Second))
		Expect(reconcile(disabled).RequeueAfter).To(Equal(time.Second))
		Expect(identity(omitted).Data["keacluster-uid"]).To(Equal(string(omitted.UID)))
		Expect(identity(disabled).Data["keacluster-uid"]).To(Equal(string(disabled.UID)))
		for _, parent := range []*infrastructurev1alpha1.KeaCluster{omitted, disabled} {
			Expect(apierrors.IsNotFound(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: namesFor(parent).ConfigMap}, &corev1.ConfigMap{}))).To(BeTrue())
			Expect(apierrors.IsNotFound(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: namesFor(parent).Service}, &corev1.Service{}))).To(BeTrue())
			Expect(apierrors.IsNotFound(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: namesFor(parent).StatefulSet}, &appsv1.StatefulSet{}))).To(BeTrue())
			Expect(reconcile(parent).RequeueAfter).To(Equal(5 * time.Minute))
			assertCondition(parent, "ArtifactReconciled", metav1.ConditionTrue, "ArtifactInSync")
			assertCondition(parent, "WorkloadReconciled", metav1.ConditionTrue, "WorkloadDisabled")
			assertCondition(parent, "WorkloadReady", metav1.ConditionTrue, "WorkloadDisabled")
		}
		writes, statusPatches := recorder.otherWrites(), recorder.statusPatches()
		disabled = storedParent(disabled)
		disabled.Spec.Workload.LoggingSeverity = pointerTo("DEBUG")
		Expect(k8sClient.Update(requestCtx, disabled)).To(Succeed())
		Expect(reconcile(disabled).RequeueAfter).To(Equal(5 * time.Minute))
		Expect(recorder.otherWrites()).To(Equal(writes))
		Expect(recorder.statusPatches()).To(Equal(statusPatches + 1))
		Expect(identity(disabled).Data["keacluster-uid"]).To(Equal(string(disabled.UID)))
		Expect(recorder.operationSnapshot()).NotTo(ContainElement(apiOperation{Verb: "delete", Kind: "ConfigMap", Namespace: namespace.Name, Name: disabled.Name}))
	})

	It("converges to exact owned API-defaulted resources and remains a no-op", func() {
		parent := newParent("enabled", workloadSpec(true, "INFO"))
		settleEnabled(parent)
		names := namesFor(parent)
		config, err := generateKeaConfig("INFO")
		Expect(err).NotTo(HaveOccurred())
		configMap := &corev1.ConfigMap{}
		service := &corev1.Service{}
		statefulSet := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.ConfigMap}, configMap)).To(Succeed())
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.Service}, service)).To(Succeed())
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.StatefulSet}, statefulSet)).To(Succeed())
		Expect(configMap.Data).To(Equal(map[string]string{"kea-dhcp4.conf": config.DHCP4, "kea-dhcp6.conf": config.DHCP6}))
		Expect(workloadSoleOwnedBy(configMap, parent)).To(BeTrue())
		Expect(workloadSoleOwnedBy(service, parent)).To(BeTrue())
		Expect(workloadSoleOwnedBy(statefulSet, parent)).To(BeTrue())
		Expect(service.Spec.ClusterIP).To(Equal(corev1.ClusterIPNone))
		Expect(service.Spec.ClusterIPs).To(ContainElement(corev1.ClusterIPNone))
		Expect(service.Spec.Ports).To(BeEmpty(), "the API server admits the intended portless headless Service")
		Expect(managedServiceEqual(service, desiredHeadlessService(parent, names))).To(BeTrue(), "API-added Service defaults normalize as a match")
		Expect(managedStatefulSetEqual(statefulSet, desiredKeaStatefulSet(parent, names, config))).To(BeTrue(), "API-defaulted StatefulSet matches desired Pod shape")
		Expect(len(statefulSet.Spec.Template.Spec.Containers)).To(Equal(2))
		Expect(statefulSet.Spec.Template.Spec.HostNetwork).To(BeFalse())
		Expect(statefulSet.Spec.Template.Spec.AutomountServiceAccountToken).NotTo(BeNil())
		Expect(*statefulSet.Spec.Template.Spec.AutomountServiceAccountToken).To(BeFalse())
		assertCondition(parent, "ArtifactReconciled", metav1.ConditionTrue, "ArtifactInSync")
		assertCondition(parent, "WorkloadReconciled", metav1.ConditionTrue, "ResourcesInSync")
		assertCondition(parent, "WorkloadReady", metav1.ConditionFalse, "RolloutPending")

		writes, statusPatches := recorder.otherWrites(), recorder.statusPatches()
		for range 3 {
			Expect(reconcile(parent).RequeueAfter).To(Equal(5*time.Second), "no API Pods exist to prove runtime readiness in envtest")
		}
		Expect(recorder.otherWrites()).To(Equal(writes))
		Expect(recorder.statusPatches()).To(Equal(statusPatches))
	})

	It("repairs representative managed drift while retaining unrelated metadata", func() {
		parent := newParent("drift", workloadSpec(true, "INFO"))
		settleEnabled(parent)
		names := namesFor(parent)
		configMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.ConfigMap}, configMap)).To(Succeed())
		configMap.Data["kea-dhcp4.conf"] = "invalid"
		configMap.Annotations = map[string]string{"external.example/note": "retain"}
		Expect(k8sClient.Update(requestCtx, configMap)).To(Succeed())
		Expect(reconcile(parent).RequeueAfter).To(Equal(time.Second))
		Expect(recorder.operationSnapshot()[len(recorder.operationSnapshot())-1].Verb).To(Equal("patch"))
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(configMap), configMap)).To(Succeed())
		config, err := generateKeaConfig("INFO")
		Expect(err).NotTo(HaveOccurred())
		Expect(configMap.Data["kea-dhcp4.conf"]).To(Equal(config.DHCP4))
		Expect(configMap.Annotations["external.example/note"]).To(Equal("retain"))

		service := &corev1.Service{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.Service}, service)).To(Succeed())
		service.Spec.Ports = []corev1.ServicePort{{Name: "drift", Port: 99, Protocol: corev1.ProtocolTCP}}
		service.Labels["external.example/label"] = "retain"
		Expect(k8sClient.Update(requestCtx, service)).To(Succeed())
		Expect(reconcile(parent).RequeueAfter).To(Equal(time.Second))
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(service), service)).To(Succeed())
		Expect(service.Spec.Ports).To(BeEmpty())
		Expect(service.Labels["external.example/label"]).To(Equal("retain"))

		statefulSet := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.StatefulSet}, statefulSet)).To(Succeed())
		statefulSet.Spec.Template.Spec.Containers[0].Image = "invalid.example/kea:drift"
		statefulSet.Annotations = map[string]string{"external.example/note": "retain"}
		Expect(k8sClient.Update(requestCtx, statefulSet)).To(Succeed())
		Expect(reconcile(parent).RequeueAfter).To(Equal(time.Second))
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(statefulSet), statefulSet)).To(Succeed())
		Expect(statefulSet.Spec.Template.Spec.Containers[0].Image).To(Equal(keaDHCP4Image))
		Expect(statefulSet.Annotations["external.example/note"]).To(Equal("retain"))
		settleEnabled(parent)
	})

	It("blocks immutable incompatibility and foreign ownership without mutation", func() {
		parent := newParent("blocked", workloadSpec(true, "INFO"))
		settleEnabled(parent)
		names := namesFor(parent)
		configMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.ConfigMap}, configMap)).To(Succeed())
		immutable := true
		configMap.Immutable = &immutable
		configMap.Data["kea-dhcp4.conf"] = "incompatible"
		Expect(k8sClient.Update(requestCtx, configMap)).To(Succeed())
		writes, statusPatches := recorder.otherWrites(), recorder.statusPatches()
		Expect(reconcile(parent).RequeueAfter).To(Equal(30 * time.Second))
		Expect(recorder.otherWrites()).To(Equal(writes))
		Expect(recorder.statusPatches()).To(Equal(statusPatches + 1))
		assertCondition(parent, "WorkloadReconciled", metav1.ConditionFalse, "ImmutableConfiguration")

		foreign := newParent("foreign", workloadSpec(true, "INFO"))
		foreignNames := namesFor(foreign)
		collision := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: foreignNames.ConfigMap, Namespace: namespace.Name}, Data: map[string]string{"foreign": "preserve"}}
		Expect(k8sClient.Create(requestCtx, collision)).To(Succeed())
		Expect(reconcile(foreign).RequeueAfter).To(Equal(time.Second), "identity creation is independently safe")
		writes = recorder.otherWrites()
		Expect(reconcile(foreign).RequeueAfter).To(Equal(30 * time.Second))
		Expect(recorder.otherWrites()).To(Equal(writes))
		assertCondition(foreign, "WorkloadReconciled", metav1.ConditionFalse, "OwnershipConflict")
		stored := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(collision), stored)).To(Succeed())
		Expect(stored.Data).To(Equal(map[string]string{"foreign": "preserve"}))
	})

	It("supports long dotted names and never transfers children across a replacement UID", func() {
		longName := strings.Repeat("long.", 48) + "example"
		parent := newParent(longName, workloadSpec(true, "INFO"))
		settleEnabled(parent)
		names := namesFor(parent)
		Expect(validDNSLabel(names.ConfigMap)).To(BeTrue())
		Expect(validDNSLabel(names.Service)).To(BeTrue())
		Expect(validDNSLabel(names.StatefulSet)).To(BeTrue())

		replacedName := "replacement"
		old := newParent(replacedName, workloadSpec(true, "INFO"))
		Expect(reconcile(old).RequeueAfter).To(Equal(time.Second))
		oldIdentity := identity(old)
		oldUID := old.UID
		Expect(k8sClient.Delete(requestCtx, old)).To(Succeed())
		fresh := newParent(replacedName, workloadSpec(true, "INFO"))
		Expect(fresh.UID).NotTo(Equal(oldUID))
		writes := recorder.otherWrites()
		Expect(reconcile(fresh).RequeueAfter).To(Equal(30 * time.Second))
		Expect(recorder.otherWrites()).To(Equal(writes), "replacement identity ownership must not be transferred")
		currentIdentity := identity(fresh)
		Expect(currentIdentity.UID).To(Equal(oldIdentity.UID))
		Expect(currentIdentity.Data["keacluster-uid"]).To(Equal(string(oldUID)))
		Expect(currentIdentity.OwnerReferences[0].UID).To(Equal(oldUID))
		assertCondition(fresh, "ArtifactReconciled", metav1.ConditionFalse, "OwnershipConflict")
	})

	It("blocks a deterministic identity/configuration-name collision before child writes", func() {
		parent := newParent("collision", workloadSpec(true, "INFO"))
		Expect(reconcile(parent).RequeueAfter).To(Equal(time.Second))
		config, err := generateKeaConfig("INFO")
		Expect(err).NotTo(HaveOccurred())
		names := namesFor(parent)
		names.ConfigMap = parent.Name // deterministic test fixture; production hash/naming remains untouched.
		observation := reconciler.observeWorkload(requestCtx, parent, names)
		writes := recorder.otherWrites()
		action := reconciler.reconcileEnabledWorkload(requestCtx, parent, names, config, &observation)
		Expect(action.Mutated).To(BeFalse())
		Expect(action.Err).NotTo(HaveOccurred())
		Expect(recorder.otherWrites()).To(Equal(writes))
		Expect(apierrors.IsNotFound(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.Service}, &corev1.Service{}))).To(BeTrue())
		Expect(identity(parent).Data["keacluster-uid"]).To(Equal(string(parent.UID)))
	})
})
