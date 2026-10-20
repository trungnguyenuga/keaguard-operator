package controller

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Restart regressions catch lost initial-list delivery, status churn, reliance on
// old queue/patch memory, and ownership/lifecycle checks bypassed after startup.
// Every manager has a new cache/reconciler/recorder; fixtures use the API client.
func restartManager(parent context.Context, namespace, identityName string, blocked time.Duration) (*managerRecordingClient, func() error) {
	_, r, stop, err := startTestManager(parent, namespace, identityName, time.Hour, blocked, false)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { Expect(stop()).To(Succeed()) })
	return r.Client.(*managerRecordingClient), stop
}
func restartParent(key client.ObjectKey) *infrastructurev1alpha1.KeaCluster {
	p := &infrastructurev1alpha1.KeaCluster{}
	Expect(k8sClient.Get(ctx, key, p)).To(Succeed())
	return p
}
func restartIdentity(key client.ObjectKey, before *infrastructurev1alpha1.KeaCluster) {
	p := restartParent(key)
	Expect(p.UID).To(Equal(before.UID))
	Expect(p.Generation).To(Equal(before.Generation))
}
func restartInSync(key client.ObjectKey, p *infrastructurev1alpha1.KeaCluster, c *managerRecordingClient) {
	Eventually(func() bool {
		return c.requests.Load() > 0 && c.observations.Load() > 0 && watchReason(key) == "ArtifactInSync"
	}, 10*time.Second, 20*time.Millisecond).Should(BeTrue())
	cm := watchChild(key)
	Expect(cm.Data).To(Equal(map[string]string{"keacluster-name": p.Name, "keacluster-namespace": p.Namespace, "keacluster-uid": string(p.UID)}))
	Expect(cm.BinaryData).To(BeEmpty())
	Expect(cm.Labels["keaguard.example/artifact"]).To(Equal("reconciliation"))
	Expect(cm.Annotations["keaguard.example/purpose"]).To(Equal("Internal reconciliation artifact; not operational Kea DHCP configuration."))
	owner := metav1.GetControllerOf(cm)
	Expect(owner).NotTo(BeNil())
	Expect(owner.APIVersion).To(Equal("infrastructure.keaguard.example/v1alpha1"))
	Expect(owner.Kind).To(Equal("KeaCluster"))
	Expect(owner.Name).To(Equal(p.Name))
	Expect(owner.UID).To(Equal(p.UID))
	Expect(owner.BlockOwnerDeletion).NotTo(BeNil())
	Expect(*owner.BlockOwnerDeletion).To(BeFalse())
	condition := meta.FindStatusCondition(restartParent(key).Status.Conditions, "ArtifactReconciled")
	Expect(condition).NotTo(BeNil())
	Expect(condition.Status).To(Equal(metav1.ConditionTrue))
	Expect(condition.ObservedGeneration).To(Equal(p.Generation))
	restartIdentity(key, p)
}
func restartHealthy() (*infrastructurev1alpha1.KeaCluster, client.ObjectKey, *managerRecordingClient, func() error) {
	p, key := concurrencyParent()
	c, stop := restartManager(ctx, p.Namespace, p.Name, time.Hour)
	restartInSync(key, p, c)
	watchSettled(c)
	return p, key, c, stop
}
func restartNoWrites(c *managerRecordingClient) {
	Consistently(func() int { return c.otherWrites() + c.statusPatches() }, 600*time.Millisecond, 20*time.Millisecond).Should(BeZero())
}

var _ = Describe("ENV: Restart correct", func() {
	It("initially observes existing correct state with zero writes and stable status", func() {
		p, key, old, stop := restartHealthy()
		beforeParent, beforeChild := restartParent(key), watchChild(key)
		Expect(stop()).To(Succeed())
		n := old.requests.Load()
		fresh, _ := restartManager(ctx, p.Namespace, p.Name, time.Hour)
		Expect(fresh).NotTo(BeIdenticalTo(old))
		restartInSync(key, p, fresh)
		restartNoWrites(fresh)
		Expect(restartParent(key)).To(Equal(beforeParent))
		Expect(watchChild(key)).To(Equal(beforeChild))
		Expect(old.requests.Load()).To(Equal(n))
	})
})
var _ = Describe("ENV: Restart drift", func() {
	It("repairs downtime payload, reserved metadata and binary drift without CR edits", func() {
		p, key, old, stop := restartHealthy()
		Expect(stop()).To(Succeed())
		beforeParent := restartParent(key)
		cm := watchChild(key)
		cm.Data = map[string]string{"keacluster-name": "wrong", "extra": "remove"}
		cm.BinaryData = map[string][]byte{"unexpected": {1, 2, 3}}
		cm.Labels = map[string]string{"external.example/label": "keep", "keaguard.example/artifact": "wrong"}
		cm.Annotations = map[string]string{"external.example/note": "keep", "keaguard.example/purpose": "wrong"}
		Expect(k8sClient.Update(ctx, cm)).To(Succeed())
		writes := old.otherWrites()
		Consistently(func() *corev1.ConfigMap { return watchChild(key) }, 600*time.Millisecond, 20*time.Millisecond).Should(Equal(cm))
		Expect(old.otherWrites()).To(Equal(writes))
		fresh, _ := restartManager(ctx, p.Namespace, p.Name, time.Hour)
		// Persisted True alone is insufficient: require actual repaired payload.
		Eventually(func() map[string]string { return watchChild(key).Data }, 10*time.Second, 20*time.Millisecond).Should(Equal(map[string]string{"keacluster-name": p.Name, "keacluster-namespace": p.Namespace, "keacluster-uid": string(p.UID)}))
		restartInSync(key, p, fresh)
		Expect(fresh.otherWrites()).To(Equal(1))
		Expect(fresh.statusPatches()).To(BeZero())
		got := watchChild(key)
		Expect(got.UID).To(Equal(cm.UID))
		Expect(got.OwnerReferences).To(Equal(cm.OwnerReferences))
		Expect(got.Labels["external.example/label"]).To(Equal("keep"))
		Expect(got.Annotations["external.example/note"]).To(Equal("keep"))
		Expect(restartParent(key)).To(Equal(beforeParent))
	})
})
var _ = Describe("ENV: Restart missing", func() {
	It("recreates a downtime-deleted artifact with current identity", func() {
		p, key, old, stop := restartHealthy()
		Expect(stop()).To(Succeed())
		beforeParent := restartParent(key)
		cm := watchChild(key)
		Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
		writes := old.otherWrites()
		Consistently(func() bool { return apierrors.IsNotFound(k8sClient.Get(ctx, key, &corev1.ConfigMap{})) }, 600*time.Millisecond, 20*time.Millisecond).Should(BeTrue())
		Expect(old.otherWrites()).To(Equal(writes))
		fresh, _ := restartManager(ctx, p.Namespace, p.Name, time.Hour)
		Eventually(func() error { return k8sClient.Get(ctx, key, &corev1.ConfigMap{}) }, 10*time.Second, 20*time.Millisecond).Should(Succeed())
		restartInSync(key, p, fresh)
		Expect(watchChild(key).UID).NotTo(Equal(cm.UID))
		Expect(fresh.otherWrites()).To(Equal(1))
		Expect(fresh.statusPatches()).To(BeZero())
		Expect(restartParent(key)).To(Equal(beforeParent))
	})
})

var _ = Describe("ENV: Restart interrupted", func() {
	for _, kind := range []string{"owner conflict", "immutable", "terminating"} {
		It("retains "+kind+" restrictions across restart and recovers after manual removal", func() {
			p, key, _, stop := restartHealthy()
			Expect(stop()).To(Succeed())
			cm := watchChild(key)
			reason := "OwnershipConflict"
			switch kind {
			case "owner conflict":
				cm.OwnerReferences = nil
				cm.Data = map[string]string{"foreign": "retain"}
			case "immutable":
				immutable := true
				cm.Immutable = &immutable
				reason = "ImmutableArtifact"
			case "terminating":
				cm.Finalizers = []string{"tests.keaguard.example/hold"}
				reason = "ArtifactDeleting"
			}
			Expect(k8sClient.Update(ctx, cm)).To(Succeed())
			if kind == "terminating" {
				Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
				cm = watchChild(key)
			}
			first, stopBlocked := restartManager(ctx, p.Namespace, p.Name, 100*time.Millisecond)
			Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal(reason))
			Expect(first.otherWrites()).To(BeZero())
			Expect(stopBlocked()).To(Succeed())
			blockedParent := restartParent(key)
			fresh, _ := restartManager(ctx, p.Namespace, p.Name, 100*time.Millisecond)
			Eventually(func() int64 { return fresh.observations.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">=", 3))
			restartNoWrites(fresh)
			Expect(watchChild(key)).To(Equal(cm))
			Expect(restartParent(key)).To(Equal(blockedParent))
			restartIdentity(key, p)
			if kind == "terminating" {
				cm.Finalizers = nil
				Expect(k8sClient.Update(ctx, cm)).To(Succeed())
			} else {
				Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
			}
			Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("ArtifactInSync"))
			restartInSync(key, p, fresh)
			Expect(fresh.otherWrites()).To(Equal(1))
		})
	}
	for _, terminating := range []bool{false, true} {
		It("does not mutate for a downtime missing/terminating parent terminating="+map[bool]string{false: "false", true: "true"}[terminating], func() {
			p, key, _, stop := restartHealthy()
			Expect(stop()).To(Succeed())
			if terminating {
				held := restartParent(key)
				held.Finalizers = []string{"tests.keaguard.example/hold"}
				Expect(k8sClient.Update(ctx, held)).To(Succeed())
			}
			Expect(k8sClient.Delete(ctx, p)).To(Succeed())
			if terminating {
				Expect(restartParent(key).DeletionTimestamp).NotTo(BeNil())
				Expect(restartParent(key).UID).To(Equal(p.UID))
			} else {
				Expect(apierrors.IsNotFound(k8sClient.Get(ctx, key, &infrastructurev1alpha1.KeaCluster{}))).To(BeTrue())
			}
			var lifecycle *infrastructurev1alpha1.KeaCluster
			if terminating {
				lifecycle = restartParent(key)
			}
			cm := watchChild(key) // envtest has no GC; leaving it proves no repair/status.
			cm.Data = map[string]string{"drift": "remain"}
			Expect(k8sClient.Update(ctx, cm)).To(Succeed())
			fresh, stopFresh := restartManager(ctx, p.Namespace, p.Name, time.Hour)
			if terminating {
				Eventually(func() int64 { return fresh.requests.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">", 0))
			}
			restartNoWrites(fresh)
			Expect(fresh.observations.Load()).To(BeZero())
			Expect(watchChild(key)).To(Equal(cm))
			Expect(stopFresh()).To(Succeed())
			if terminating {
				Expect(restartParent(key)).To(Equal(lifecycle))
				restartIdentity(key, lifecycle)
			} else {
				Expect(apierrors.IsNotFound(k8sClient.Get(ctx, key, &infrastructurev1alpha1.KeaCluster{}))).To(BeTrue())
			}
			if terminating {
				held := restartParent(key)
				held.Finalizers = nil
				Expect(k8sClient.Update(ctx, held)).To(Succeed())
			}
		})
	}
	It("refuses a surviving old-UID artifact for a same-name replacement", func() {
		old, key, _, stop := restartHealthy()
		Expect(stop()).To(Succeed())
		cm := watchChild(key)
		Expect(k8sClient.Delete(ctx, old)).To(Succeed())
		replacement := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}
		Expect(k8sClient.Create(ctx, replacement)).To(Succeed())
		Expect(replacement.UID).NotTo(Equal(old.UID))
		fresh, _ := restartManager(ctx, old.Namespace, old.Name, 100*time.Millisecond)
		Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("OwnershipConflict"))
		Eventually(func() int64 { return fresh.observations.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">=", 3))
		Expect(fresh.otherWrites()).To(BeZero())
		Expect(watchChild(key)).To(Equal(cm))
		Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
		Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("ArtifactInSync"))
		restartInSync(key, replacement, fresh)
		Expect(watchChild(key).UID).NotTo(Equal(cm.UID))
		Expect(fresh.otherWrites()).To(Equal(1))
	})
	It("observes committed artifact after failed status using a fresh manager without duplicate creation", func() {
		p, key := concurrencyParent()
		first, stop := restartManager(context.WithValue(ctx, managerFaultKey{}, "status"), p.Namespace, p.Name, time.Hour)
		Eventually(func() int64 { return first.attempts.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">", 0))
		Expect(stop()).To(Succeed())
		cm := watchChild(key)
		Expect(first.otherWrites()).To(Equal(1))
		Expect(restartParent(key).Status.Conditions).To(BeEmpty())
		fresh, _ := restartManager(ctx, p.Namespace, p.Name, time.Hour)
		restartInSync(key, p, fresh)
		Expect(fresh.otherWrites()).To(BeZero())
		Expect(fresh.statusPatches()).To(Equal(1))
		Expect(watchChild(key)).To(Equal(cm))
	})
	It("reconstructs a committed uncertain operation interrupted by cancellation", func() {
		p, key, _, stop := restartHealthy()
		Expect(stop()).To(Succeed())
		cm := watchChild(key)
		Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
		// Forward a real Create, then model a lost reply and cancellation. This is
		// deterministic interruption evidence, not an actual network outage.
		attemptCtx, cancelAttempt := context.WithCancel(ctx)
		defer cancelAttempt()
		recorder := &statusRecordingClient{Client: k8sClient}
		interrupted := &recoveryClient{statusRecordingClient: recorder, forward: true, writeErr: errors.New("modelled lost reply"), after: func(context.Context, *corev1.ConfigMap) { cancelAttempt() }}
		_, err := newTestReconciler(interrupted, k8sClient, p.Namespace).Reconcile(attemptCtx, ctrl.Request{NamespacedName: key})
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(recorder.otherWrites()).To(Equal(1))
		committed := watchChild(key)
		fresh, _ := restartManager(ctx, p.Namespace, p.Name, time.Hour)
		restartInSync(key, p, fresh)
		restartNoWrites(fresh)
		Expect(watchChild(key)).To(Equal(committed))
	})
	It("automatically recovers a temporary observation failure cleared after restart", func() {
		p, key, _, stop := restartHealthy()
		Expect(stop()).To(Succeed())
		first, stopFailed := restartManager(context.WithValue(ctx, managerFaultKey{}, "child"), p.Namespace, p.Name, time.Hour)
		Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("ObservationFailed"))
		Expect(first.otherWrites()).To(BeZero())
		Expect(stopFailed()).To(Succeed())
		cm := watchChild(key)
		fresh, _ := restartManager(context.WithValue(ctx, managerFaultKey{}, "child"), p.Namespace, p.Name, time.Hour)
		Eventually(func() int64 { return fresh.attempts.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">=", 2))
		Expect(fresh.otherWrites()).To(BeZero())
		Expect(fresh.statusPatches()).To(BeZero())
		fresh.stage.Store(nil)
		restartInSync(key, p, fresh)
		Expect(fresh.otherWrites()).To(BeZero())
		Expect(fresh.statusPatches()).To(Equal(1))
		Expect(watchChild(key)).To(Equal(cm))
	})
})
