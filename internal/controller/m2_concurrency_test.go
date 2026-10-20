package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("M2: Concurrency", func() {
	var requestCtx context.Context
	var stop context.CancelFunc
	var namespace *corev1.Namespace
	var parent *infrastructurev1alpha1.KeaCluster
	var names workloadNames
	var config workloadConfig
	var recorder *statusRecordingClient
	var reconciler *KeaClusterReconciler

	BeforeEach(func() {
		requestCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		DeferCleanup(stop)
		namespace = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "m2-race-"}}
		Expect(k8sClient.Create(requestCtx, namespace)).To(Succeed())
		severity := "INFO"
		parent = &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "race", Namespace: namespace.Name}, Spec: &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true, LoggingSeverity: &severity}}}
		Expect(k8sClient.Create(requestCtx, parent)).To(Succeed())
		names = namesFor(parent)
		var err error
		config, err = generateKeaConfig(severity)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Create(requestCtx, desiredArtifact(parent))).To(Succeed())
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

	updateSeverity := func(severity string) {
		fresh := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), fresh)).To(Succeed())
		fresh.Spec.Workload.LoggingSeverity = &severity
		Expect(k8sClient.Update(requestCtx, fresh)).To(Succeed())
	}
	getConfig := func() *corev1.ConfigMap {
		object := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.ConfigMap}, object)).To(Succeed())
		return object
	}

	It("refuses stale workload creation when parent generation changes before the fresh guard", func() {
		gate := newAPIGate()
		reconciler.APIReader = &barrierReader{Reader: k8sClient, beforeParent: gate.wait}
		result, err := runAPIRace(gate, func(operationCtx context.Context) (ctrl.Result, error) {
			return reconciler.Reconcile(operationCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
		}, func() { updateSeverity("DEBUG") })
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(time.Second))
		Expect(recorder.otherWrites()).To(BeZero())
		Expect(recorder.statusPatches()).To(BeZero())
		Expect(apierrors.IsNotFound(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.ConfigMap}, &corev1.ConfigMap{}))).To(BeTrue())
	})

	It("keeps original ownership for a write admitted immediately before a parent change", func() {
		gate := newAPIGate()
		writer := &barrierClient{statusRecordingClient: recorder, beforeCreate: gate.wait}
		reconciler.Client = writer
		result, err := runAPIRace(gate, func(operationCtx context.Context) (ctrl.Result, error) {
			return reconciler.Reconcile(operationCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
		}, func() { updateSeverity("DEBUG") })
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(time.Second))
		Expect(recorder.otherWrites()).To(Equal(1))
		created := getConfig()
		Expect(workloadSoleOwnedBy(created, parent)).To(BeTrue())
		Expect(created.Data["kea-dhcp4.conf"]).To(Equal(config.DHCP4), "the accepted request retains its original intent")
		fresh := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), fresh)).To(Succeed())
		Expect(fresh.Generation).To(BeNumerically(">", parent.Generation))
		next := &statusRecordingClient{Client: k8sClient}
		_, err = newTestReconciler(next, k8sClient, namespace.Name).Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fresh)})
		Expect(err).NotTo(HaveOccurred())
		Expect(next.otherWrites()).To(Equal(1))
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(created), created)).To(Succeed())
		want, err := generateKeaConfig("DEBUG")
		Expect(err).NotTo(HaveOccurred())
		Expect(created.Data["kea-dhcp4.conf"]).To(Equal(want.DHCP4))
	})

	It("does not retry a stale-resourceVersion patch or overwrite concurrent metadata", func() {
		created := desiredKeaConfig(parent, names, config)
		created.Data = map[string]string{"drift": "before"}
		Expect(k8sClient.Create(requestCtx, created)).To(Succeed())
		gate := newAPIGate()
		writer := &barrierClient{statusRecordingClient: recorder, beforePatch: gate.wait}
		reconciler.Client = writer
		result, err := runAPIRace(gate, func(operationCtx context.Context) (ctrl.Result, error) {
			return reconciler.Reconcile(operationCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
		}, func() {
			concurrent := &corev1.ConfigMap{}
			Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(created), concurrent)).To(Succeed())
			if concurrent.Labels == nil {
				concurrent.Labels = make(map[string]string)
			}
			if concurrent.Annotations == nil {
				concurrent.Annotations = make(map[string]string)
			}
			concurrent.Labels["external.example/race"] = "preserve"
			concurrent.Annotations["external.example/race"] = "preserve"
			Expect(k8sClient.Update(requestCtx, concurrent)).To(Succeed())
		})
		Expect(apierrors.IsConflict(err)).To(BeTrue(), fmt.Sprint(err))
		Expect(result).To(Equal(ctrl.Result{}))
		Expect(recorder.otherWrites()).To(Equal(1), "the stale patch is counted once and not retried")
		current := getConfig()
		Expect(current.Data).To(Equal(map[string]string{"drift": "before"}))
		Expect(current.Labels["external.example/race"]).To(Equal("preserve"))
		Expect(current.Annotations["external.example/race"]).To(Equal("preserve"))
		next := &statusRecordingClient{Client: k8sClient}
		_, err = newTestReconciler(next, k8sClient, namespace.Name).Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
		Expect(err).NotTo(HaveOccurred())
		Expect(next.otherWrites()).To(Equal(1))
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(created), created)).To(Succeed())
		Expect(created.Data["kea-dhcp4.conf"]).To(Equal(config.DHCP4))
		Expect(created.Labels["external.example/race"]).To(Equal("preserve"))
	})

	It("protects conditional delete against concurrent owner changes and re-enable", func() {
		fresh := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), fresh)).To(Succeed())
		fresh.Spec.Workload.Enabled = false
		Expect(k8sClient.Update(requestCtx, fresh)).To(Succeed())
		object := desiredKeaConfig(fresh, namesFor(fresh), config)
		Expect(k8sClient.Create(requestCtx, object)).To(Succeed())
		gate := newAPIGate()
		writer := &barrierClient{statusRecordingClient: recorder, beforeDelete: gate.wait}
		r := newTestReconciler(writer, k8sClient, namespace.Name)
		result, err := runAPIRace(gate, func(operationCtx context.Context) (ctrl.Result, error) {
			return r.Reconcile(operationCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fresh)})
		}, func() {
			concurrent := &corev1.ConfigMap{}
			Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(object), concurrent)).To(Succeed())
			concurrent.OwnerReferences = append(concurrent.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "external", UID: types.UID("external-owner"), Controller: pointerTo(false)})
			Expect(k8sClient.Update(requestCtx, concurrent)).To(Succeed())
		})
		Expect(apierrors.IsConflict(err)).To(BeTrue(), fmt.Sprint(err))
		Expect(result).To(Equal(ctrl.Result{}))
		Expect(recorder.otherWrites()).To(Equal(1))
		current := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(object), current)).To(Succeed())
		Expect(current.UID).To(Equal(object.UID))
		Expect(current.OwnerReferences).To(HaveLen(2))
		next := &statusRecordingClient{Client: k8sClient}
		_, err = newTestReconciler(next, k8sClient, namespace.Name).Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fresh)})
		Expect(err).NotTo(HaveOccurred())
		Expect(next.otherWrites()).To(BeZero(), "extra owner blocks destructive cleanup")
	})

	It("does not delete a same-name child replacement after the delete guard", func() {
		fresh := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), fresh)).To(Succeed())
		fresh.Spec.Workload.Enabled = false
		Expect(k8sClient.Update(requestCtx, fresh)).To(Succeed())
		original := desiredKeaConfig(fresh, namesFor(fresh), config)
		Expect(k8sClient.Create(requestCtx, original)).To(Succeed())
		oldUID := original.UID
		gate := newAPIGate()
		writer := &barrierClient{statusRecordingClient: recorder, beforeDelete: gate.wait}
		r := newTestReconciler(writer, k8sClient, namespace.Name)
		_, err := runAPIRace(gate, func(operationCtx context.Context) (ctrl.Result, error) {
			return r.Reconcile(operationCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fresh)})
		}, func() {
			Expect(k8sClient.Delete(requestCtx, original)).To(Succeed())
			replacement := desiredKeaConfig(fresh, namesFor(fresh), config)
			replacement.Data["external.example.replacement"] = "preserve"
			Expect(k8sClient.Create(requestCtx, replacement)).To(Succeed())
			Expect(replacement.UID).NotTo(Equal(oldUID))
		})
		Expect(apierrors.IsConflict(err) || apierrors.IsNotFound(err)).To(BeTrue(), fmt.Sprint(err))
		Expect(recorder.otherWrites()).To(Equal(1), "no same-pass delete retry")
		current := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(original), current)).To(Succeed())
		Expect(current.UID).NotTo(Equal(oldUID))
		Expect(current.Data["external.example.replacement"]).To(Equal("preserve"))
	})

	It("rechecks before cleanup and reconciles fresh intent after an admitted delete", func() {
		fresh := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), fresh)).To(Succeed())
		fresh.Spec.Workload.Enabled = false
		Expect(k8sClient.Update(requestCtx, fresh)).To(Succeed())
		object := desiredKeaConfig(fresh, namesFor(fresh), config)
		Expect(k8sClient.Create(requestCtx, object)).To(Succeed())
		guard := newAPIGate()
		reader := &barrierReader{Reader: k8sClient, beforeParent: guard.wait}
		r := newTestReconciler(recorder, reader, namespace.Name)
		result, err := runAPIRace(guard, func(operationCtx context.Context) (ctrl.Result, error) {
			return r.Reconcile(operationCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fresh)})
		}, func() {
			current := &infrastructurev1alpha1.KeaCluster{}
			Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(fresh), current)).To(Succeed())
			current.Spec.Workload.Enabled = true
			Expect(k8sClient.Update(requestCtx, current)).To(Succeed())
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(time.Second))
		Expect(recorder.otherWrites()).To(BeZero())
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(object), &corev1.ConfigMap{})).To(Succeed())

		current := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(fresh), current)).To(Succeed())
		current.Spec.Workload.Enabled = false
		Expect(k8sClient.Update(requestCtx, current)).To(Succeed())
		deleteGate := newAPIGate()
		writer := &barrierClient{statusRecordingClient: recorder, beforeDelete: deleteGate.wait}
		r = newTestReconciler(writer, k8sClient, namespace.Name)
		result, err = runAPIRace(deleteGate, func(operationCtx context.Context) (ctrl.Result, error) {
			return r.Reconcile(operationCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(current)})
		}, func() {
			latest := &infrastructurev1alpha1.KeaCluster{}
			Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(current), latest)).To(Succeed())
			latest.Spec.Workload.Enabled = true
			Expect(k8sClient.Update(requestCtx, latest)).To(Succeed())
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(time.Second))
		Expect(recorder.otherWrites()).To(Equal(1), "only the already-admitted delete crosses the observation/submission race")
		Expect(apierrors.IsNotFound(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(object), &corev1.ConfigMap{}))).To(BeTrue())
		next := &statusRecordingClient{Client: k8sClient}
		_, err = newTestReconciler(next, k8sClient, namespace.Name).Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(current)})
		Expect(err).NotTo(HaveOccurred())
		Expect(next.otherWrites()).To(Equal(1), "fresh enabled intent recreates the configuration")
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(object), &corev1.ConfigMap{})).To(Succeed())
	})

	It("rejects a stale batched workload status after a generation change at submission", func() {
		fresh := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), fresh)).To(Succeed())
		fresh.Spec.Workload.Enabled = false
		Expect(k8sClient.Update(requestCtx, fresh)).To(Succeed())
		gate := newAPIGate()
		statusClient := &statusRecordingClient{Client: k8sClient, beforePatch: func(operationCtx context.Context, _ client.Object, _ client.Patch) error {
			return gate.wait(operationCtx)
		}}
		r := newTestReconciler(statusClient, k8sClient, namespace.Name)
		_, err := runAPIRace(gate, func(operationCtx context.Context) (ctrl.Result, error) {
			return r.Reconcile(operationCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fresh)})
		}, func() {
			latest := &infrastructurev1alpha1.KeaCluster{}
			Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(fresh), latest)).To(Succeed())
			severity := "DEBUG"
			latest.Spec.Workload.LoggingSeverity = &severity
			Expect(k8sClient.Update(requestCtx, latest)).To(Succeed())
		})
		Expect(apierrors.IsConflict(err)).To(BeTrue(), fmt.Sprint(err))
		Expect(statusClient.statusPatches()).To(Equal(1))
		Expect(statusClient.otherWrites()).To(BeZero())
		latest := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(fresh), latest)).To(Succeed())
		Expect(latest.Status.Conditions).To(BeEmpty(), "old-generation workload conditions were not transferred")
		next := &statusRecordingClient{Client: k8sClient}
		_, err = newTestReconciler(next, k8sClient, namespace.Name).Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(latest)})
		Expect(err).NotTo(HaveOccurred())
		Expect(next.statusPatches()).To(Equal(1))
		Expect(next.otherWrites()).To(BeZero())
	})
})
