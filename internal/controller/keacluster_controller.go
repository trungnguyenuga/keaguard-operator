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
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
)

// KeaClusterReconciler reconciles a KeaCluster object
type KeaClusterReconciler struct {
	client.Client
	APIReader           client.Reader
	Scheme              *runtime.Scheme
	Namespace           string
	healthyRequeueAfter time.Duration
	blockedRequeueAfter time.Duration
}

// +kubebuilder:rbac:groups=infrastructure.keaguard.example,namespace=keaguard-system,resources=keaclusters,verbs=get;list;watch
// +kubebuilder:rbac:groups=infrastructure.keaguard.example,namespace=keaguard-system,resources=keaclusters/status,verbs=patch
// +kubebuilder:rbac:groups="",namespace=keaguard-system,resources=configmaps,verbs=get;list;watch;create;patch

// Reconcile observes one parent incarnation and submits at most one artifact write.
func (r *KeaClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Namespace != r.Namespace {
		return ctrl.Result{}, nil
	}
	origin := &infrastructurev1alpha1.KeaCluster{}
	if err := r.Get(ctx, req.NamespacedName, origin); err != nil {
		if !apierrors.IsNotFound(err) {
			logf.FromContext(ctx).Error(err, "Parent observation failed; no artifact status can be established")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !origin.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	actual := &corev1.ConfigMap{}
	err := r.APIReader.Get(ctx, req.NamespacedName, actual)
	missing := apierrors.IsNotFound(err)
	if err != nil && !missing {
		return r.finishReconcile(ctx, origin, failedArtifactCondition(origin, "ObservationFailed"), ctrl.Result{}, err)
	}
	if missing || observedArtifactCondition(origin, actual).Reason == "ArtifactOutOfSync" {
		base := actual
		if missing {
			actual = desiredArtifact(origin)
		} else {
			actual = actual.DeepCopy()
			setManagedFields(actual, desiredArtifact(origin))
		}
		fresh := &infrastructurev1alpha1.KeaCluster{}
		if err := r.APIReader.Get(ctx, req.NamespacedName, fresh); err != nil {
			if apierrors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return r.finishReconcile(ctx, origin, failedArtifactCondition(origin, "ObservationFailed"), ctrl.Result{}, err)
		}
		if !fresh.DeletionTimestamp.IsZero() {
			return ctrl.Result{}, nil
		}
		if fresh.UID != origin.UID || fresh.Generation != origin.Generation {
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		if err := ctx.Err(); err != nil {
			return ctrl.Result{}, err
		}
		if missing {
			if err := r.Create(ctx, actual); err != nil {
				return r.finishArtifactFailure(ctx, origin, err)
			}
		} else {
			if err := r.Patch(ctx, actual, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
				return r.finishArtifactFailure(ctx, origin, err)
			}
		}
	}

	// Classify the returned object too: a successful write alone does not
	// establish ownership, mutability, or matching managed state.
	condition := observedArtifactCondition(origin, actual)
	delay := r.blockedRequeueAfter
	if condition.Status == metav1.ConditionTrue {
		delay = r.healthyRequeueAfter
	}
	return r.finishReconcile(ctx, origin, condition, ctrl.Result{RequeueAfter: delay}, nil)
}

// Reobserve failed writes without retrying a mutation. An acknowledgement error
// cannot establish failure; only explicit rejection plus observed drift can.
func (r *KeaClusterReconciler) finishArtifactFailure(ctx context.Context, origin *infrastructurev1alpha1.KeaCluster, writeErr error) (ctrl.Result, error) {
	condition := failedArtifactCondition(origin, "MutationOutcomeUnknown")
	if ctx.Err() == nil {
		observed := &corev1.ConfigMap{}
		err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(origin), observed)
		definite := apierrors.IsForbidden(writeErr) || apierrors.IsInvalid(writeErr) ||
			apierrors.IsConflict(writeErr) || apierrors.IsAlreadyExists(writeErr) || apierrors.IsNotFound(writeErr)
		switch {
		case err == nil:
			evidence := observedArtifactCondition(origin, observed)
			if evidence.Reason != "ArtifactOutOfSync" {
				condition = evidence
			} else if definite {
				condition = failedArtifactCondition(origin, "ArtifactWriteFailed")
			}
		case apierrors.IsNotFound(err):
			if definite {
				condition = failedArtifactCondition(origin, "ArtifactWriteFailed")
			}
		default:
			writeErr = errors.Join(writeErr, err)
		}
	}
	logf.FromContext(ctx).Error(writeErr, "Artifact mutation returned an error; reporting latest observation", "reason", condition.Reason)
	return r.finishReconcile(ctx, origin, condition, ctrl.Result{}, writeErr)
}

func failedArtifactCondition(parent *infrastructurev1alpha1.KeaCluster, reason string) metav1.Condition {
	status := metav1.ConditionUnknown
	message := " could not be observed; a later observation will retry."
	switch reason {
	case "MutationOutcomeUnknown":
		message = " mutation outcome is unresolved; reobserve before any later mutation."
	case "ArtifactWriteFailed":
		status = metav1.ConditionFalse
		message = " write was rejected and drift remains; manual correction of API access or validation restrictions may be required."
	}
	return metav1.Condition{Type: "ArtifactReconciled", Status: status, Reason: reason,
		ObservedGeneration: parent.Generation, LastTransitionTime: metav1.Now(),
		Message: fmt.Sprintf("ConfigMap %s/%s", parent.Namespace, parent.Name) + message}
}

// observedArtifactCondition describes observed evidence in safety order. It never
// normalizes ownership or permits metadata repair on a blocked artifact.
func observedArtifactCondition(parent *infrastructurev1alpha1.KeaCluster, actual *corev1.ConfigMap) metav1.Condition {
	condition := metav1.Condition{
		Type: "ArtifactReconciled", Status: metav1.ConditionFalse,
		ObservedGeneration: parent.Generation, LastTransitionTime: metav1.Now(),
	}
	identity := fmt.Sprintf("ConfigMap %s/%s", parent.Namespace, parent.Name)
	switch {
	case !artifactOwnedBy(actual, parent):
		condition.Reason = "OwnershipConflict"
		condition.Message = identity + " lacks the supported controller reference for the current KeaCluster UID; manual resolution of the conflicting resource is required."
	case actual.Immutable != nil && *actual.Immutable:
		condition.Reason = "ImmutableArtifact"
		condition.Message = identity + " is immutable; manual removal permits recreation of the mutable internal artifact while the KeaCluster remains active."
	case !actual.DeletionTimestamp.IsZero():
		condition.Reason = "ArtifactDeleting"
		condition.Message = identity + " is terminating; await disappearance and manual resolution of external deletion blockers before recreation."
	case !managedFieldsEqual(actual, desiredArtifact(parent)):
		condition.Reason = "ArtifactOutOfSync"
		condition.Message = identity + " differs from the internal reconciliation artifact; a later observation will retry managed-field repair."
	default:
		condition.Status = metav1.ConditionTrue
		condition.Reason = "ArtifactInSync"
		condition.Message = identity + " matches the internal reconciliation artifact."
	}
	return condition
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeaClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.healthyRequeueAfter <= 0 {
		r.healthyRequeueAfter = 5 * time.Minute
	}
	if r.blockedRequeueAfter <= 0 {
		r.blockedRequeueAfter = 30 * time.Second
	}
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controllerOptions()).
		For(&infrastructurev1alpha1.KeaCluster{}, builder.WithPredicates(keaClusterPredicate())).
		Owns(&corev1.ConfigMap{}, builder.WithPredicates(configMapPredicate())).
		Named("keacluster").
		Complete(r)
}
