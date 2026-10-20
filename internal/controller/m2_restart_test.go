package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func m2RestartCondition(key client.ObjectKey, conditionType string) string {
	parent := &infrastructurev1alpha1.KeaCluster{}
	if k8sClient.Get(ctx, key, parent) != nil {
		return ""
	}
	condition := meta.FindStatusCondition(parent.Status.Conditions, conditionType)
	if condition == nil {
		return ""
	}
	return string(condition.Status) + ":" + condition.Reason
}

func m2RestartManager(key client.ObjectKey, blocked time.Duration) (*managerRecordingClient, func() error) {
	_, reconciler, stop, err := startTestManager(ctx, key.Namespace, key.Name, time.Hour, blocked, false)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { Expect(stop()).To(Succeed()) })
	return reconciler.Client.(*managerRecordingClient), stop
}

var _ = Describe("M2: Restart", func() {
	It("reobserves correct resources after manager restart without writes", func() {
		parent, key := m2WatchParent()
		first, stop := m2RestartManager(key, time.Hour)
		m2WatchResourcesReady(key)
		watchSettled(first)
		before := first.otherWrites() + first.statusPatches()
		setBefore := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: namesFor(parent).StatefulSet}, setBefore)).To(Succeed())
		Expect(stop()).To(Succeed())

		fresh, _ := m2RestartManager(key, time.Hour)
		Eventually(func() int64 { return fresh.requests.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">", 0))
		Expect(fresh.requestSnapshot()).To(ContainElement(key))
		Consistently(func() int { return fresh.otherWrites() + fresh.statusPatches() }, 750*time.Millisecond, 20*time.Millisecond).Should(BeZero())
		setAfter := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(setBefore), setAfter)).To(Succeed())
		Expect(setAfter.UID).To(Equal(setBefore.UID))
		Expect(first.otherWrites() + first.statusPatches()).To(Equal(before))
	})

	It("reconstructs drift and partial enablement from fresh API observations", func() {
		parent, key := m2WatchParent()
		first, stop := m2RestartManager(key, time.Hour)
		m2WatchResourcesReady(key)
		Expect(stop()).To(Succeed())
		names := namesFor(parent)
		configMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.ConfigMap}, configMap)).To(Succeed())
		configMap.Data["kea-dhcp4.conf"] = "restart drift"
		Expect(k8sClient.Update(ctx, configMap)).To(Succeed())
		service := &corev1.Service{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.Service}, service)).To(Succeed())
		Expect(k8sClient.Delete(ctx, service)).To(Succeed())

		fresh, _ := m2RestartManager(key, time.Hour)
		m2WatchResourcesReady(key)
		observedConfig := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.ConfigMap}, observedConfig)).To(Succeed())
		Expect(observedConfig.Data["kea-dhcp4.conf"]).NotTo(Equal("restart drift"))
		recreatedService := &corev1.Service{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.Service}, recreatedService)).To(Succeed())
		Expect(recreatedService.UID).NotTo(Equal(service.UID))
		Expect(fresh.otherWrites()).To(Equal(2))
		Expect(first.otherWrites()).To(Equal(4))
	})

	It("continues safe partial disable cleanup after restart", func() {
		parent, key := m2WatchParent()
		_, stop := m2RestartManager(key, time.Hour)
		m2WatchResourcesReady(key)
		Expect(stop()).To(Succeed())
		latest := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(ctx, key, latest)).To(Succeed())
		latest.Spec.Workload.Enabled = false
		Expect(k8sClient.Update(ctx, latest)).To(Succeed())

		fresh, _ := m2RestartManager(key, time.Hour)
		Eventually(func() string { return m2RestartCondition(key, "WorkloadReconciled") }, 20*time.Second, 20*time.Millisecond).Should(Equal("True:WorkloadDisabled"))
		for _, object := range []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: namesFor(parent).ConfigMap, Namespace: key.Namespace}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: namesFor(parent).Service, Namespace: key.Namespace}},
			&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: namesFor(parent).StatefulSet, Namespace: key.Namespace}},
		} {
			Expect(apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(object), object))).To(BeTrue())
		}
		identity := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, key, identity)).To(Succeed())
		Expect(fresh.otherWrites()).To(BeNumerically(">=", 4))
	})

	It("retains an owner blocker across restart without adoption", func() {
		parent, key := m2WatchParent()
		_, stop := m2RestartManager(key, time.Hour)
		m2WatchResourcesReady(key)
		Expect(stop()).To(Succeed())
		names := namesFor(parent)
		configMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.ConfigMap}, configMap)).To(Succeed())
		configMap.OwnerReferences = nil
		Expect(k8sClient.Update(ctx, configMap)).To(Succeed())

		fresh, _ := m2RestartManager(key, time.Hour)
		Eventually(func() string { return m2RestartCondition(key, "WorkloadReconciled") }, 10*time.Second, 20*time.Millisecond).Should(Equal("False:OwnershipConflict"))
		Consistently(func() int { return fresh.otherWrites() }, 500*time.Millisecond, 20*time.Millisecond).Should(BeZero())
		Expect(fresh.statusPatches()).To(Equal(1))
		retained := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(configMap), retained)).To(Succeed())
		Expect(retained.UID).To(Equal(configMap.UID))
		Expect(retained.OwnerReferences).To(BeEmpty())
	})

	It("reobserves a committed lost create response after a fresh manager starts", func() {
		_, key := m2WatchParentWithWorkload(false)
		firstCtx := context.WithValue(ctx, managerFaultKey{}, "create-committed")
		_, reconciler, stop, err := startTestManager(firstCtx, key.Namespace, key.Name, time.Hour, time.Hour, false)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(stop()).To(Succeed()) })
		first := reconciler.Client.(*managerRecordingClient)
		Eventually(func() int64 { return first.attempts.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">", 0))
		Eventually(func() bool {
			for _, operation := range first.operationSnapshot() {
				if operation.Verb == "create-lost-response" && operation.Namespace == key.Namespace && operation.Name == key.Name {
					return true
				}
			}
			return false
		}, 10*time.Second, 20*time.Millisecond).Should(BeTrue(), "wait for the committed create and lost response before stopping the first manager")
		identity := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, key, identity)).To(Succeed())
		// The recorded Create proves the child write committed, but the first
		// reconcile still has to persist its observation. Do not stop the manager
		// between those two independently observable stages.
		Eventually(func() string { return watchReasonAndStatus(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("True:ArtifactInSync"))
		Expect(stop()).To(Succeed())
		Expect(first.otherWrites()).To(Equal(1))

		fresh, _ := m2RestartManager(key, time.Hour)
		Eventually(func() string { return watchReasonAndStatus(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("True:ArtifactInSync"))
		Consistently(func() int { return fresh.otherWrites() + fresh.statusPatches() }, 750*time.Millisecond, 20*time.Millisecond).Should(BeZero())
		observed := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, key, observed)).To(Succeed())
		Expect(observed.UID).To(Equal(identity.UID))
	})
})

func watchReasonAndStatus(key client.ObjectKey) string {
	parent := &infrastructurev1alpha1.KeaCluster{}
	if k8sClient.Get(ctx, key, parent) != nil {
		return ""
	}
	condition := meta.FindStatusCondition(parent.Status.Conditions, "ArtifactReconciled")
	if condition == nil {
		return ""
	}
	return string(condition.Status) + ":" + condition.Reason
}
