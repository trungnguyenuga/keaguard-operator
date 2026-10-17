package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These cases catch blind adoption, lost RV preconditions, reused ownership
// decisions, and result transfer across parent UID/generation boundaries.
var _ = Describe("ENV: Creation race", func() {
	for _, ownership := range []string{"unowned", "foreign", "current"} {
		It("reobserves a competing "+ownership+" creation without adoption", func() {
			p, key := concurrencyParent()
			gate := newAPIGate()
			recorder := &statusRecordingClient{Client: k8sClient}
			c := &barrierClient{statusRecordingClient: recorder, beforeCreate: gate.wait}
			r := newTestReconciler(c, k8sClient, p.Namespace)
			var competitor *corev1.ConfigMap
			result, err := runAPIRace(gate, func(ctx context.Context) (ctrl.Result, error) {
				return r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
			}, func() {
				competitor = desiredArtifact(p)
				competitor.Data = map[string]string{"competitor": "retain until a fresh pass"}
				switch ownership {
				case "unowned":
					competitor.OwnerReferences = nil
				case "foreign":
					competitor.OwnerReferences[0].UID = "foreign-uid"
				}
				Expect(k8sClient.Create(ctx, competitor)).To(Succeed())
			})
			Expect(apierrors.IsAlreadyExists(err)).To(BeTrue(), fmt.Sprint(err))
			Expect(result).To(Equal(ctrl.Result{}))
			Expect(recorder.otherWrites()).To(Equal(1))
			got := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
			Expect(got).To(Equal(competitor))
			// A new recorder proves the next pass starts from new evidence.
			next := &statusRecordingClient{Client: k8sClient}
			result, err = newTestReconciler(next, k8sClient, p.Namespace).Reconcile(ctx, ctrl.Request{NamespacedName: key})
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
			if ownership == "current" {
				Expect(next.otherWrites()).To(Equal(1))
				Expect(got.Data["keacluster-uid"]).To(Equal(string(p.UID)))
				Expect(got.Data).To(HaveLen(3))
				Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
			} else {
				Expect(next.otherWrites()).To(BeZero())
				Expect(got).To(Equal(competitor))
				Expect(result.RequeueAfter).To(Equal(30 * time.Second))
				expectArtifactReason(key, "OwnershipConflict")
			}
		})
	}
})

var _ = Describe("ENV: Patch race", func() {
	for _, changeOwner := range []bool{false, true} {
		It(fmt.Sprintf("rejects a real stale RV and rechecks owner=%v", changeOwner), func() {
			p, key := concurrencyParent()
			cm := desiredArtifact(p)
			cm.Data = map[string]string{"drift": "old"}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())
			oldUID := cm.UID
			gate := newAPIGate()
			recorder := &statusRecordingClient{Client: k8sClient}
			c := &barrierClient{statusRecordingClient: recorder, beforePatch: gate.wait}
			r := newTestReconciler(c, k8sClient, p.Namespace)
			var concurrent *corev1.ConfigMap
			_, err := runAPIRace(gate, func(ctx context.Context) (ctrl.Result, error) {
				return r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
			}, func() {
				concurrent = &corev1.ConfigMap{}
				Expect(k8sClient.Get(ctx, key, concurrent)).To(Succeed())
				concurrent.Labels["external.example/label"] = "concurrent"
				concurrent.Annotations["external.example/note"] = "survive"
				if changeOwner {
					concurrent.OwnerReferences[0].UID = "foreign-uid"
				}
				Expect(k8sClient.Update(ctx, concurrent)).To(Succeed())
			})
			Expect(apierrors.IsConflict(err)).To(BeTrue(), fmt.Sprint(err))
			Expect(recorder.otherWrites()).To(Equal(1))
			got := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
			Expect(got).To(Equal(concurrent))
			next := &statusRecordingClient{Client: k8sClient}
			_, err = newTestReconciler(next, k8sClient, p.Namespace).Reconcile(ctx, ctrl.Request{NamespacedName: key})
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
			Expect(got.UID).To(Equal(oldUID))
			Expect(got.Labels["external.example/label"]).To(Equal("concurrent"))
			Expect(got.Annotations["external.example/note"]).To(Equal("survive"))
			Expect(got.OwnerReferences).To(Equal(concurrent.OwnerReferences))
			if changeOwner {
				Expect(next.otherWrites()).To(BeZero())
				Expect(got).To(Equal(concurrent))
				expectArtifactReason(key, "OwnershipConflict")
			} else {
				Expect(next.otherWrites()).To(Equal(1))
				Expect(got.Data).To(HaveLen(3))
				Expect(got.Data["keacluster-uid"]).To(Equal(string(p.UID)))
			}
		})
	}
})

var _ = Describe("ENV: Parent deletion barriers", func() {
	for _, patch := range []bool{false, true} {
		for _, lifecycle := range []string{"missing", "terminating", "replacement"} {
			It(fmt.Sprintf("stops before validation patch=%v parent=%s", patch, lifecycle), func() {
				p, key := concurrencyParent()
				var cm *corev1.ConfigMap
				if patch {
					cm = desiredArtifact(p)
					cm.Data = map[string]string{"drift": "retain"}
					Expect(k8sClient.Create(ctx, cm)).To(Succeed())
				}
				gate := newAPIGate()
				recorder := &statusRecordingClient{Client: k8sClient}
				reader := &barrierReader{Reader: k8sClient, beforeParent: gate.wait}
				r := newTestReconciler(recorder, reader, p.Namespace)
				result, err := runAPIRace(gate, func(ctx context.Context) (ctrl.Result, error) {
					return r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
				}, func() { changeParent(p, lifecycle) })
				Expect(err).NotTo(HaveOccurred())
				Expect(recorder.otherWrites()).To(BeZero())
				Expect(recorder.statusPatches()).To(BeZero())
				delay := time.Duration(0)
				if lifecycle == "replacement" {
					delay = time.Second
				}
				Expect(result.RequeueAfter).To(Equal(delay))
				got := &corev1.ConfigMap{}
				err = k8sClient.Get(ctx, key, got)
				if patch {
					Expect(err).NotTo(HaveOccurred())
					Expect(got).To(Equal(cm))
				} else {
					Expect(apierrors.IsNotFound(err)).To(BeTrue())
				}
			})
		}
		for _, lifecycle := range []string{"missing", "terminating", "replacement"} {
			It(fmt.Sprintf("retains original UID after validation patch=%v parent=%s", patch, lifecycle), func() {
				p, key := concurrencyParent()
				oldParent := p.DeepCopy()
				if patch {
					cm := desiredArtifact(p)
					cm.Data = map[string]string{"drift": "repair"}
					Expect(k8sClient.Create(ctx, cm)).To(Succeed())
				}
				gate := newAPIGate()
				recorder := &statusRecordingClient{Client: k8sClient}
				c := &barrierClient{statusRecordingClient: recorder}
				if patch {
					c.beforePatch = gate.wait
				} else {
					c.beforeCreate = gate.wait
				}
				r := newTestReconciler(c, k8sClient, p.Namespace)
				result, err := runAPIRace(gate, func(ctx context.Context) (ctrl.Result, error) {
					return r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
				}, func() { changeParent(p, lifecycle) })
				Expect(err).NotTo(HaveOccurred())
				Expect(recorder.otherWrites()).To(Equal(1))
				Expect(recorder.statusPatches()).To(BeZero())
				delay := time.Duration(0)
				if lifecycle == "replacement" {
					delay = time.Second
				}
				Expect(result.RequeueAfter).To(Equal(delay))
				got := &corev1.ConfigMap{}
				Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
				Expect(got.OwnerReferences[0].UID).To(Equal(oldParent.UID))
				Expect(got.Data["keacluster-uid"]).To(Equal(string(oldParent.UID)))
				if lifecycle == "replacement" {
					// Envtest has no GC: the old child survives and must block the new UID.
					next := &statusRecordingClient{Client: k8sClient}
					_, err = newTestReconciler(next, k8sClient, p.Namespace).Reconcile(ctx, ctrl.Request{NamespacedName: key})
					Expect(err).NotTo(HaveOccurred())
					Expect(next.otherWrites()).To(BeZero())
					after := &corev1.ConfigMap{}
					Expect(k8sClient.Get(ctx, key, after)).To(Succeed())
					Expect(after).To(Equal(got))
					expectArtifactReason(key, "OwnershipConflict")
				}
			})
		}
	}
	for _, createRace := range []bool{false, true} {
		for _, lifecycle := range []string{"missing", "terminating", "replacement"} {
			It(fmt.Sprintf("revalidates parent before retry create=%v parent=%s", createRace, lifecycle), func() {
				p, key := concurrencyParent()
				cm := desiredArtifact(p)
				cm.Data = map[string]string{"drift": "retain"}
				if !createRace {
					Expect(k8sClient.Create(ctx, cm)).To(Succeed())
				}
				firstGate := newAPIGate()
				first := &statusRecordingClient{Client: k8sClient}
				writer := &barrierClient{statusRecordingClient: first}
				if createRace {
					writer.beforeCreate = firstGate.wait
				} else {
					writer.beforePatch = firstGate.wait
				}
				r := newTestReconciler(writer, k8sClient, p.Namespace)
				_, err := runAPIRace(firstGate, func(ctx context.Context) (ctrl.Result, error) {
					return r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
				}, func() {
					if createRace {
						Expect(k8sClient.Create(ctx, cm)).To(Succeed())
					}
					Expect(k8sClient.Get(ctx, key, cm)).To(Succeed())
					cm.Annotations["external.example/edit"] = "before retry"
					Expect(k8sClient.Update(ctx, cm)).To(Succeed())
				})
				if createRace {
					Expect(apierrors.IsAlreadyExists(err)).To(BeTrue(), fmt.Sprint(err))
				} else {
					Expect(apierrors.IsConflict(err)).To(BeTrue(), fmt.Sprint(err))
				}
				Expect(first.otherWrites()).To(Equal(1))
				gate := newAPIGate()
				next := &statusRecordingClient{Client: k8sClient}
				retry := newTestReconciler(next, &barrierReader{Reader: k8sClient, beforeParent: gate.wait}, p.Namespace)
				result, err := runAPIRace(gate, func(ctx context.Context) (ctrl.Result, error) {
					return retry.Reconcile(ctx, ctrl.Request{NamespacedName: key})
				}, func() { changeParent(p, lifecycle) })
				Expect(err).NotTo(HaveOccurred())
				Expect(next.otherWrites()).To(BeZero())
				Expect(next.statusPatches()).To(BeZero())
				delay := time.Duration(0)
				if lifecycle == "replacement" {
					delay = time.Second
				}
				Expect(result.RequeueAfter).To(Equal(delay))
				got := &corev1.ConfigMap{}
				Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
				Expect(got).To(Equal(cm))
			})
		}
	}
})

var _ = Describe("ENV: Status replacement barrier", func() {
	for _, lifecycle := range []string{"missing", "terminating", "replacement"} {
		It("discards status when the fresh read observes "+lifecycle, func() {
			p, key := concurrencyParent()
			origin := p.DeepCopy()
			gate := newAPIGate()
			recorder := &statusRecordingClient{Client: k8sClient}
			r := newTestReconciler(recorder, &barrierReader{Reader: k8sClient, beforeParent: gate.wait}, p.Namespace)
			result, err := runAPIRace(gate, func(ctx context.Context) (ctrl.Result, error) {
				return r.finishReconcile(ctx, origin, concurrencyCondition(origin), ctrl.Result{}, nil)
			}, func() { changeParent(p, lifecycle) })
			Expect(err).NotTo(HaveOccurred())
			Expect(recorder.statusPatches()).To(BeZero())
			Expect(recorder.otherWrites()).To(BeZero())
			delay := time.Duration(0)
			if lifecycle == "replacement" {
				delay = time.Second
				fresh := &infrastructurev1alpha1.KeaCluster{}
				Expect(k8sClient.Get(ctx, key, fresh)).To(Succeed())
				Expect(fresh.Status.Conditions).To(BeEmpty())
			}
			Expect(result.RequeueAfter).To(Equal(delay))
		})
	}
	It("rejects a stale status patch after same-name replacement", func() {
		p, key := concurrencyParent()
		origin := p.DeepCopy()
		gate := newAPIGate()
		recorder := &statusRecordingClient{Client: k8sClient, beforePatch: func(ctx context.Context, _ client.Object, _ client.Patch) error { return gate.wait(ctx) }}
		r := newTestReconciler(recorder, k8sClient, p.Namespace)
		var replacement *infrastructurev1alpha1.KeaCluster
		_, err := runAPIRace(gate, func(ctx context.Context) (ctrl.Result, error) {
			return r.finishReconcile(ctx, origin, concurrencyCondition(origin), ctrl.Result{}, nil)
		}, func() {
			replacement = changeParent(p, "replacement")
			replacement.Status.Conditions = []metav1.Condition{externalRaceCondition("replacement")}
			Expect(k8sClient.Status().Update(ctx, replacement)).To(Succeed())
		})
		Expect(apierrors.IsConflict(err)).To(BeTrue(), fmt.Sprint(err))
		Expect(recorder.statusPatches()).To(Equal(1))
		Expect(recorder.otherWrites()).To(BeZero())
		got := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
		Expect(got).To(Equal(replacement))
		Expect(got.UID).NotTo(Equal(origin.UID))
	})
	It("preserves concurrent unrelated conditions by rejecting old RV then recomputing", func() {
		p, key := concurrencyParent()
		gate := newAPIGate()
		recorder := &statusRecordingClient{Client: k8sClient, beforePatch: func(ctx context.Context, _ client.Object, _ client.Patch) error { return gate.wait(ctx) }}
		r := newTestReconciler(recorder, k8sClient, p.Namespace)
		external := externalRaceCondition("concurrent")
		_, err := runAPIRace(gate, func(ctx context.Context) (ctrl.Result, error) {
			return r.finishReconcile(ctx, p, concurrencyCondition(p), ctrl.Result{}, nil)
		}, func() {
			fresh := &infrastructurev1alpha1.KeaCluster{}
			Expect(k8sClient.Get(ctx, key, fresh)).To(Succeed())
			fresh.Status.Conditions = []metav1.Condition{external}
			Expect(k8sClient.Status().Update(ctx, fresh)).To(Succeed())
		})
		Expect(apierrors.IsConflict(err)).To(BeTrue(), fmt.Sprint(err))
		Expect(recorder.statusPatches()).To(Equal(1))
		fresh := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(ctx, key, fresh)).To(Succeed())
		Expect(equality.Semantic.DeepEqual(fresh.Status.Conditions, []metav1.Condition{external})).To(BeTrue())
		next := &statusRecordingClient{Client: k8sClient}
		_, err = newTestReconciler(next, k8sClient, p.Namespace).finishReconcile(ctx, fresh, concurrencyCondition(fresh), ctrl.Result{}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(next.statusPatches()).To(Equal(1))
		Expect(next.otherWrites()).To(BeZero())
		Expect(k8sClient.Get(ctx, key, fresh)).To(Succeed())
		Expect(equality.Semantic.DeepEqual(meta.FindStatusCondition(fresh.Status.Conditions, "ExternalCheck"), &external)).To(BeTrue())
		Expect(meta.FindStatusCondition(fresh.Status.Conditions, "ArtifactReconciled")).NotTo(BeNil())
	})
	It("characterizes omitted-to-empty spec generation without public test fields", func() {
		p, key := concurrencyParent()
		origin := p.DeepCopy()
		p.Spec = &infrastructurev1alpha1.KeaClusterSpec{}
		Expect(k8sClient.Update(ctx, p)).To(Succeed())
		Expect(k8sClient.Get(ctx, key, p)).To(Succeed())
		GinkgoWriter.Printf("omitted-to-empty spec generation: %d -> %d\n", origin.Generation, p.Generation)
		Expect(p.Generation).To(BeNumerically(">=", origin.Generation))
		recorder := &statusRecordingClient{Client: k8sClient}
		result, err := newTestReconciler(recorder, k8sClient, p.Namespace).finishReconcile(ctx, origin, concurrencyCondition(origin), ctrl.Result{}, nil)
		Expect(err).NotTo(HaveOccurred())
		if p.Generation != origin.Generation {
			Expect(recorder.statusPatches()).To(BeZero())
			Expect(result.RequeueAfter).To(Equal(time.Second))
		} else {
			Expect(recorder.statusPatches()).To(Equal(1))
		}
	})
})

func TestUnitStaleGenerationStatus(t *testing.T) {
	origin := statusParent()
	newer := origin.DeepCopy()
	newer.Generation++
	external := externalRaceCondition("new generation")
	newer.Status.Conditions = []metav1.Condition{external}
	recorder, base := statusFixture(t, newer)
	result, err := newTestReconciler(recorder, base, origin.Namespace).finishReconcile(context.Background(), origin, concurrencyCondition(origin), ctrl.Result{}, nil)
	if err != nil || result.RequeueAfter != time.Second || recorder.statusPatches() != 0 || recorder.otherWrites() != 0 {
		t.Fatalf("stale generation rebased: result=%v err=%v status=%d writes=%d", result, err, recorder.statusPatches(), recorder.otherWrites())
	}
	got := &infrastructurev1alpha1.KeaCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(origin), got); err != nil {
		t.Fatal(err)
	}
	if !equality.Semantic.DeepEqual(got.Status, newer.Status) {
		t.Fatalf("new generation status modified: %+v", got.Status)
	}
}

func concurrencyParent() (*infrastructurev1alpha1.KeaCluster, client.ObjectKey) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "t08-race-"}}
	Expect(k8sClient.Create(ctx, ns)).To(Succeed())
	// Private envtest is stopped after the suite. No external cluster fixtures exist.
	p := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "race", Namespace: ns.Name}}
	Expect(k8sClient.Create(ctx, p)).To(Succeed())
	return p, client.ObjectKeyFromObject(p)
}
func changeParent(p *infrastructurev1alpha1.KeaCluster, lifecycle string) *infrastructurev1alpha1.KeaCluster {
	if lifecycle == "terminating" {
		// A preceding failed artifact write may now have persisted status.
		// Refresh only this fixture write, never the stale controller request.
		fresh := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(p), fresh)).To(Succeed())
		Expect(fresh.UID).To(Equal(p.UID))
		p = fresh
		p.Finalizers = []string{"test.keaguard.example/hold"}
		Expect(k8sClient.Update(ctx, p)).To(Succeed())
	}
	Expect(k8sClient.Delete(ctx, p)).To(Succeed())
	if lifecycle == "replacement" {
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(p), &infrastructurev1alpha1.KeaCluster{})).To(Satisfy(apierrors.IsNotFound))
		replacement := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: p.Name, Namespace: p.Namespace}}
		Expect(k8sClient.Create(ctx, replacement)).To(Succeed())
		Expect(replacement.UID).NotTo(Equal(p.UID))
		return replacement
	}
	return nil
}
func concurrencyCondition(p *infrastructurev1alpha1.KeaCluster) metav1.Condition {
	return metav1.Condition{Type: "ArtifactReconciled", Status: metav1.ConditionTrue, Reason: "ArtifactInSync", Message: "Internal artifact observation", ObservedGeneration: p.Generation, LastTransitionTime: statusTime}
}
func externalRaceCondition(message string) metav1.Condition {
	return metav1.Condition{Type: "ExternalCheck", Status: metav1.ConditionTrue, Reason: "External", Message: message, LastTransitionTime: statusTime}
}
func expectArtifactReason(key client.ObjectKey, reason string) {
	p := &infrastructurev1alpha1.KeaCluster{}
	Expect(k8sClient.Get(ctx, key, p)).To(Succeed())
	c := meta.FindStatusCondition(p.Status.Conditions, "ArtifactReconciled")
	Expect(c).NotTo(BeNil())
	Expect(c.Reason).To(Equal(reason))
}
