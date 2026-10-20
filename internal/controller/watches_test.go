package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func watchReason(key client.ObjectKey) string {
	p := &infrastructurev1alpha1.KeaCluster{}
	if err := k8sClient.Get(ctx, key, p); err != nil {
		return fmt.Sprint(err)
	}
	c := meta.FindStatusCondition(p.Status.Conditions, "ArtifactReconciled")
	if c == nil {
		return ""
	}
	return c.Reason
}
func watchManager(namespace, identityName string, healthy, blocked time.Duration, suppress bool) (*KeaClusterReconciler, *managerRecordingClient) {
	_, r, stop, err := startTestManager(ctx, namespace, identityName, healthy, blocked, suppress)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { Expect(stop()).To(Succeed()) })
	return r, r.Client.(*managerRecordingClient)
}
func watchChild(key client.ObjectKey) *corev1.ConfigMap {
	c := &corev1.ConfigMap{}
	Expect(k8sClient.Get(ctx, key, c)).To(Succeed())
	return c
}
func watchSettled(c *managerRecordingClient) {
	Eventually(func() int64 { return c.observations.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">=", 2))
	lastN, lastO := c.requests.Load(), c.observations.Load()
	quietSince := time.Now()
	Eventually(func() bool {
		n, o := c.requests.Load(), c.observations.Load()
		if n != lastN || o != lastO {
			lastN, lastO = n, o
			quietSince = time.Now()
		}
		return time.Since(quietSince) >= time.Second
	}, 10*time.Second, 20*time.Millisecond).Should(BeTrue())
}

var _ = Describe("ENV: Watch mapping", func() {
	for _, replace := range []bool{false, true} {
		It(fmt.Sprintf("delivers settled former-owner request after replacement=%v and label removal", replace), func() {
			p, key := concurrencyParent()
			_, c := watchManager(p.Namespace, p.Name, time.Hour, time.Hour, false)
			Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("ArtifactInSync"))
			watchSettled(c)
			n, o := c.requests.Load(), c.observations.Load()
			cm := watchChild(key)
			cm.Labels = nil
			if replace {
				cm.OwnerReferences[0].Name = "foreign"
				cm.OwnerReferences[0].UID = "foreign-uid"
			} else {
				cm.OwnerReferences = nil
			}
			Expect(k8sClient.Update(ctx, cm)).To(Succeed())
			Eventually(func() bool { return c.requests.Load() > n && c.observations.Load() > o }, 10*time.Second, 20*time.Millisecond).Should(BeTrue())
			Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("OwnershipConflict"))
			Expect(c.otherWrites()).To(Equal(1)) // Only initial creation; no ownership repair.
		})
	}
})
var _ = Describe("ENV: Conflict polling", func() {
	It("leaves persistent conflict/status untouched and recovers after unowned removal", func() {
		p, key := concurrencyParent()
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: p.Name, Namespace: p.Namespace}, Data: map[string]string{"foreign": "retain"}}
		Expect(k8sClient.Create(ctx, cm)).To(Succeed())
		_, c := watchManager(p.Namespace, p.Name, 200*time.Millisecond, 100*time.Millisecond, false)
		Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("OwnershipConflict"))
		n := c.requests.Load()
		writes, status := c.otherWrites(), c.statusPatches()
		Eventually(func() int64 { return c.requests.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">=", n+3))
		Expect(c.otherWrites()).To(Equal(writes))
		Expect(writes).To(BeZero())
		Expect(c.statusPatches()).To(Equal(status))
		Expect(watchChild(key)).To(Equal(cm))
		Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
		Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("ArtifactInSync"))
		Expect(watchChild(key).OwnerReferences[0].UID).To(Equal(p.UID))
	})
})
var _ = Describe("ENV: Missed event", func() {
	It("detects owner loss with safety polling then recovers with blocked polling", func() {
		p, key := concurrencyParent()
		_, c := watchManager(p.Namespace, p.Name, 200*time.Millisecond, 100*time.Millisecond, true)
		Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("ArtifactInSync"))
		cm := watchChild(key)
		cm.OwnerReferences = nil
		cm.Labels = nil
		Expect(k8sClient.Update(ctx, cm)).To(Succeed())
		Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("OwnershipConflict"))
		n := c.requests.Load()
		status := c.statusPatches()
		Eventually(func() int64 { return c.requests.Load() }, 10*time.Second, 20*time.Millisecond).Should(BeNumerically(">=", n+3))
		Expect(c.otherWrites()).To(Equal(1))
		Expect(c.statusPatches()).To(Equal(status))
		Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
		Eventually(func() string { return watchReason(key) }, 10*time.Second, 20*time.Millisecond).Should(Equal("ArtifactInSync"))
	})
})
var _ = Describe("ENV: Failure scheduling", func() {
	for _, stage := range []string{"read", "child", "create", "patch", "status"} {
		It("automatically retries modelled "+stage+" failure without CR edits", func() {
			// Prepare API fixtures and fault selection before initial informer work.
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "watch-fault-"}}
			Expect(k8sClient.Create(ctx, ns)).To(Succeed())
			p := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "fault", Namespace: ns.Name}}
			Expect(k8sClient.Create(ctx, p)).To(Succeed())
			key := client.ObjectKeyFromObject(p)
			if stage == "patch" {
				cm := desiredArtifact(p)
				cm.Data = map[string]string{"drift": "x"}
				Expect(k8sClient.Create(ctx, cm)).To(Succeed())
			}
			_, r, stop, err := startTestManager(context.WithValue(ctx, managerFaultKey{}, stage), ns.Name, p.Name, time.Hour, time.Hour, false)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { Expect(stop()).To(Succeed()) })
			c := r.Client.(*managerRecordingClient)

			Eventually(func() int64 { return c.attempts.Load() }, 15*time.Second, 20*time.Millisecond).Should(BeNumerically(">=", 3))
			if stage == "child" || stage == "create" || stage == "patch" {
				reason := "MutationOutcomeUnknown"
				if stage == "child" {
					reason = "ObservationFailed"
				}
				Expect(watchReason(key)).To(Equal(reason))
				Expect(c.statusPatches()).To(Equal(1))
			}
			if stage == "read" || stage == "child" {
				Expect(c.otherWrites()).To(BeZero())
			}
			c.stage.Store(nil)
			Eventually(func() string { return watchReason(key) }, 15*time.Second, 20*time.Millisecond).Should(Equal("ArtifactInSync"))
			cm := watchChild(key)
			Expect(cm.Data).To(HaveLen(3))
			Expect(cm.OwnerReferences[0].UID).To(Equal(p.UID))
			Expect(p.Generation).To(Equal(int64(1)))
		})
	}
})
