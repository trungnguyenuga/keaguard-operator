package controller

import (
	"context"
	"testing"
	"time"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Catches status feedback loops and filters that miss lifecycle changes.
func TestUnitKeaClusterPredicates(t *testing.T) {
	p, _ := coreUnitFixture(t)
	pred := keaClusterPredicate()
	if !pred.Create(event.CreateEvent{Object: p}) || !pred.Delete(event.DeleteEvent{Object: p}) {
		t.Fatal("initial/deleted parent rejected")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*infrastructurev1alpha1.KeaCluster)
		want   bool
	}{
		{"status", func(p *infrastructurev1alpha1.KeaCluster) { p.Status.ObservedGeneration = 4 }, false},
		{"label", func(p *infrastructurev1alpha1.KeaCluster) { p.Labels = map[string]string{"other": "yes"} }, false},
		{"generation", func(p *infrastructurev1alpha1.KeaCluster) { p.Generation++ }, true},
		{"uid", func(p *infrastructurev1alpha1.KeaCluster) { p.UID = "new" }, true},
		{"deletion", func(p *infrastructurev1alpha1.KeaCluster) { now := metav1.Now(); p.DeletionTimestamp = &now }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := p.DeepCopy()
			tc.mutate(n)
			if got := pred.Update(event.UpdateEvent{ObjectOld: p, ObjectNew: n}); got != tc.want {
				t.Fatalf("admission=%v want %v", got, tc.want)
			}
		})
	}
}

// Catches mutable-label/new-owner filtering and irrelevant metadata feedback.
func TestUnitConfigMapPredicates(t *testing.T) {
	p, _ := coreUnitFixture(t)
	cm := desiredArtifact(p)
	pred := configMapPredicate()
	if !pred.Create(event.CreateEvent{Object: cm}) || !pred.Delete(event.DeleteEvent{Object: cm}) {
		t.Fatal("child lifecycle rejected")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.ConfigMap)
		want   bool
	}{
		{"data", func(c *corev1.ConfigMap) { c.Data["extra"] = "x" }, true},
		{"binary", func(c *corev1.ConfigMap) { c.BinaryData = map[string][]byte{"x": {1}} }, true},
		{"reserved-label", func(c *corev1.ConfigMap) { c.Labels = nil }, true},
		{"reserved-annotation", func(c *corev1.ConfigMap) { c.Annotations = nil }, true},
		{"owner-removal-and-label", func(c *corev1.ConfigMap) { c.OwnerReferences = nil; c.Labels = nil }, true},
		{"owner-replacement", func(c *corev1.ConfigMap) { c.OwnerReferences[0].UID = "foreign" }, true},
		{"immutable", func(c *corev1.ConfigMap) { v := true; c.Immutable = &v }, true},
		{"deletion", func(c *corev1.ConfigMap) { now := metav1.Now(); c.DeletionTimestamp = &now }, true},
		{"unrelated-label", func(c *corev1.ConfigMap) { c.Labels["other"] = "x" }, false},
		{"unrelated-annotation", func(c *corev1.ConfigMap) { c.Annotations["other"] = "x" }, false},
		{"resource-version", func(c *corev1.ConfigMap) { c.ResourceVersion = "123" }, false},
		{"nil-empty-binary", func(c *corev1.ConfigMap) { c.BinaryData = map[string][]byte{} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := cm.DeepCopy()
			tc.mutate(n)
			if got := pred.Update(event.UpdateEvent{ObjectOld: cm, ObjectNew: n}); got != tc.want {
				t.Fatalf("admission=%v want %v", got, tc.want)
			}
		})
	}
}

// Characterizes the pinned upstream handler assumption independently of setup.
func TestUnitOwnerEventMapping(t *testing.T) {
	p, base := coreUnitFixture(t)
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{infrastructurev1alpha1.GroupVersion})
	mapper.Add(infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"), meta.RESTScopeNamespace)
	for _, replace := range []bool{false, true} {
		old := desiredArtifact(p)
		n := old.DeepCopy()
		n.Labels = nil
		n.OwnerReferences = nil
		if replace {
			n.OwnerReferences = append(n.OwnerReferences, old.OwnerReferences[0])
			n.OwnerReferences[0].Name = "replacement"
			n.OwnerReferences[0].UID = "foreign"
		}
		q := workqueue.NewTypedRateLimitingQueue(workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](time.Second, time.Minute))
		h := handler.EnqueueRequestForOwner(base.Scheme(), mapper, &infrastructurev1alpha1.KeaCluster{}, handler.OnlyControllerOwner())
		h.Update(context.Background(), event.UpdateEvent{ObjectOld: old, ObjectNew: n}, q)
		found := false
		for q.Len() > 0 {
			req, _ := q.Get()
			if req.NamespacedName == client.ObjectKeyFromObject(p) {
				found = true
			}
			q.Done(req)
		}
		q.ShutDown()
		if !found {
			t.Fatal("former owner missing from actual handler queue")
		}
	}
}

func TestUnitControllerOptions(t *testing.T) {
	o := controllerOptions()
	if o.MaxConcurrentReconciles != 1 || o.ReconciliationTimeout != 30*time.Second || o.NewQueue != nil || (o.SkipNameValidation != nil && *o.SkipNameValidation) {
		t.Fatalf("unsafe options: %+v", o)
	}
	if o.RateLimiter == nil {
		t.Fatal("missing per-key limiter")
	}
	req := reconcile.Request{NamespacedName: client.ObjectKey{Name: "one"}}
	for _, s := range []int{1, 2, 4, 8, 16, 32, 60, 60} {
		if d := o.RateLimiter.When(req); d != time.Duration(s)*time.Second {
			t.Fatalf("delay=%s want %ds", d, s)
		}
	}
	fresh := controllerOptions()
	if d := fresh.RateLimiter.When(req); d != time.Second {
		t.Fatal("limiter shared across controllers")
	}
	o.RateLimiter.Forget(req)
	if o.RateLimiter.When(req) != time.Second {
		t.Fatal("Forget did not reset backoff")
	}
}

func TestUnitRequeueContract(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		p, base := coreUnitFixture(t)
		r := newTestReconciler(base, base, p.Namespace)
		out, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)})
		if err != nil || out.RequeueAfter != 5*time.Minute {
			t.Fatalf("%v %v", out, err)
		}
	})
	// Existing focused lifecycle/blocker tests exercise actual results, not fixture constants.
	t.Run("blockers", TestUnitBlockedArtifact)
	t.Run("lifecycle-and-invalidated", TestUnitParentLifecycle)
	t.Run("outside", TestUnitNamespaceGuard)
}
