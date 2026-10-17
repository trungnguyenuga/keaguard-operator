package controller

import (
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func keaClusterPredicate() predicate.Predicate {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		if e.ObjectOld == nil || e.ObjectNew == nil {
			return false
		}
		return e.ObjectOld.GetUID() != e.ObjectNew.GetUID() || e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() || !e.ObjectOld.GetDeletionTimestamp().Equal(e.ObjectNew.GetDeletionTimestamp())
	}}
}

func configMapPredicate() predicate.Predicate {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		old, ok := e.ObjectOld.(*corev1.ConfigMap)
		if !ok {
			return false
		}
		next, ok := e.ObjectNew.(*corev1.ConfigMap)
		if !ok {
			return false
		}
		immutable := func(c *corev1.ConfigMap) bool { return c.Immutable != nil && *c.Immutable }
		// Managed comparison treats empty/nil payloads alike and ignores unrelated metadata.
		// Ownership changes stay eligible even when the new object has no owner/label.
		return !managedFieldsEqual(old, next) || !reflect.DeepEqual(old.OwnerReferences, next.OwnerReferences) || immutable(old) != immutable(next) || !old.DeletionTimestamp.Equal(next.DeletionTimestamp)
	}}
}

func controllerOptions() controller.Options {
	return controller.Options{MaxConcurrentReconciles: 1, ReconciliationTimeout: 30 * time.Second,
		RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](time.Second, 60*time.Second)}
}
