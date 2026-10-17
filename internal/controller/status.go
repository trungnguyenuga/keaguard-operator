package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// withArtifactCondition records artifact evidence without changing the observation's input.
// The caller supplies the attempted generation and observation time.
func withArtifactCondition(current infrastructurev1alpha1.KeaClusterStatus, condition metav1.Condition) (infrastructurev1alpha1.KeaClusterStatus, bool) {
	next := current.DeepCopy()
	meta.SetStatusCondition(&next.Conditions, condition)
	next.ObservedGeneration = condition.ObservedGeneration
	return *next, !equality.Semantic.DeepEqual(current, *next)
}

// finishReconcile persists only an eligible observation. It never mutates an artifact
// or retries a stale result, and reporting cannot consume a recoverable operation error.
func (r *KeaClusterReconciler) finishReconcile(ctx context.Context, origin *infrastructurev1alpha1.KeaCluster, condition metav1.Condition, result ctrl.Result, reconcileErr error) (ctrl.Result, error) {
	statusFailure := func(err error) (ctrl.Result, error) {
		wrapped := fmt.Errorf("persist artifact observation for KeaCluster %s/%s: %w", origin.Namespace, origin.Name, err)
		logf.FromContext(ctx).Error(wrapped, "Current artifact status could not be persisted; observation may be unresolved")
		return ctrl.Result{}, errors.Join(reconcileErr, wrapped)
	}
	finish := func(result ctrl.Result) (ctrl.Result, error) {
		if reconcileErr != nil {
			return ctrl.Result{}, reconcileErr
		}
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return statusFailure(err)
	}
	if _, changed := withArtifactCondition(origin.Status, condition); !changed {
		return finish(result)
	}

	fresh := &infrastructurev1alpha1.KeaCluster{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(origin), fresh); err != nil {
		if apierrors.IsNotFound(err) {
			return finish(ctrl.Result{})
		}
		return statusFailure(err)
	}
	if !fresh.DeletionTimestamp.IsZero() {
		return finish(ctrl.Result{})
	}
	if fresh.UID != origin.UID || fresh.Generation != origin.Generation {
		return finish(ctrl.Result{RequeueAfter: time.Second})
	}
	next, changed := withArtifactCondition(fresh.Status, condition)
	if !changed {
		return finish(result)
	}
	base := fresh.DeepCopy()
	fresh.Status = next
	if err := ctx.Err(); err != nil {
		return statusFailure(err)
	}
	if err := r.Status().Patch(ctx, fresh, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		return statusFailure(err)
	}
	return finish(result)
}
