package controller

import (
	"context"
	"errors"
	"time"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// reconcileEnabledWorkload repairs the operational configuration, headless
// Service, and StatefulSet in that fixed order, submitting at most one action.
func (r *KeaClusterReconciler) reconcileEnabledWorkload(ctx context.Context, parent *infrastructurev1alpha1.KeaCluster, names workloadNames, config workloadConfig, observation *workloadObservation) actionResult {
	if parent == nil || observation == nil {
		return actionResult{Err: errors.New("cannot reconcile workload without its parent observation")}
	}
	_, severity := effectiveWorkload(parent)
	if _, err := generateKeaConfig(severity); err != nil {
		return actionResult{}
	}
	if workloadConfigNameCollides(parent, names) {
		return actionResult{}
	}
	if err := workloadObservationError(*observation); err != nil {
		return actionResult{Err: err}
	}
	if reason, _ := observedWorkloadBlocker(parent, names, *observation); reason != "" {
		return actionResult{}
	}
	candidates := candidateWorkloadPods(parent, names, observation.StatefulSet, observation.Pods)
	if observation.StatefulSet == nil && len(candidates) != 0 {
		return actionResult{}
	}
	if !workloadPodsSafe(observation.StatefulSet, candidates, false) {
		return actionResult{}
	}

	desiredConfig := desiredKeaConfig(parent, names, config)
	if observation.ConfigMap == nil {
		if guard, proceed := r.workloadMutationGuard(ctx, parent, config); !proceed {
			return guard
		}
		if err := r.Create(ctx, desiredConfig); err != nil {
			return r.finishWorkloadMutation(ctx, parent, names, observation, err)
		}
		return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
	}
	if !managedConfigurationEqual(observation.ConfigMap, desiredConfig) {
		patched := observation.ConfigMap.DeepCopy()
		setManagedConfiguration(patched, desiredConfig)
		if guard, proceed := r.workloadMutationGuard(ctx, parent, config); !proceed {
			return guard
		}
		if err := r.Patch(ctx, patched, client.MergeFromWithOptions(observation.ConfigMap, client.MergeFromWithOptimisticLock{})); err != nil {
			return r.finishWorkloadMutation(ctx, parent, names, observation, err)
		}
		return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
	}

	desiredService := desiredHeadlessService(parent, names)
	if observation.Service == nil {
		if guard, proceed := r.workloadMutationGuard(ctx, parent, config); !proceed {
			return guard
		}
		if err := r.Create(ctx, desiredService); err != nil {
			return r.finishWorkloadMutation(ctx, parent, names, observation, err)
		}
		return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
	}
	if !managedServiceEqual(observation.Service, desiredService) {
		patched := observation.Service.DeepCopy()
		setManagedService(patched, desiredService)
		if guard, proceed := r.workloadMutationGuard(ctx, parent, config); !proceed {
			return guard
		}
		if err := r.Patch(ctx, patched, client.MergeFromWithOptions(observation.Service, client.MergeFromWithOptimisticLock{})); err != nil {
			return r.finishWorkloadMutation(ctx, parent, names, observation, err)
		}
		return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
	}

	desiredSet := desiredKeaStatefulSet(parent, names, config)
	if observation.StatefulSet == nil {
		if guard, proceed := r.workloadMutationGuard(ctx, parent, config); !proceed {
			return guard
		}
		if result := r.refreshWorkloadCandidates(ctx, parent, observation); result.Err != nil || result.Mutated || result.Result.RequeueAfter != 0 {
			return result
		}
		if len(candidateWorkloadPods(parent, names, nil, observation.Pods)) != 0 {
			return actionResult{}
		}
		if err := r.Create(ctx, desiredSet); err != nil {
			return r.finishWorkloadMutation(ctx, parent, names, observation, err)
		}
		return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
	}
	if !managedStatefulSetEqual(observation.StatefulSet, desiredSet) {
		if guard, proceed := r.workloadMutationGuard(ctx, parent, config); !proceed {
			return guard
		}
		if result := r.refreshWorkloadCandidates(ctx, parent, observation); result.Err != nil || result.Mutated || result.Result.RequeueAfter != 0 {
			return result
		}
		candidates = candidateWorkloadPods(parent, names, observation.StatefulSet, observation.Pods)
		if !workloadPodsSafe(observation.StatefulSet, candidates, true) {
			return actionResult{}
		}
		patched := observation.StatefulSet.DeepCopy()
		setManagedStatefulSet(patched, desiredSet)
		if err := r.Patch(ctx, patched, client.MergeFromWithOptions(observation.StatefulSet, client.MergeFromWithOptimisticLock{})); err != nil {
			return r.finishWorkloadMutation(ctx, parent, names, observation, err)
		}
		return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
	}
	return actionResult{}
}

// reconcileDisabledWorkload shuts down then removes owned workload resources
// in order. Every pass submits at most one guarded mutation and waits for fresh
// direct observations before advancing.
func (r *KeaClusterReconciler) reconcileDisabledWorkload(ctx context.Context, parent *infrastructurev1alpha1.KeaCluster, names workloadNames, observation *workloadObservation) actionResult {
	if parent == nil || observation == nil {
		return actionResult{Err: errors.New("cannot clean up workload without its parent observation")}
	}
	if enabled, _ := effectiveWorkload(parent); enabled {
		return actionResult{Result: reconcileResult(time.Second)}
	}
	if observation.PodsErr != nil {
		return actionResult{Err: observation.PodsErr}
	}
	candidates := candidateWorkloadPods(parent, names, observation.StatefulSet, observation.Pods)
	if observation.StatefulSetErr != nil {
		return actionResult{Err: observation.StatefulSetErr}
	}
	if observation.StatefulSet != nil {
		set := observation.StatefulSet
		if !workloadSoleOwnedBy(set, parent) || !set.DeletionTimestamp.IsZero() {
			return actionResult{}
		}
		if !workloadPodsSafe(set, candidates, true) {
			return actionResult{}
		}
		if set.Spec.Replicas == nil || *set.Spec.Replicas != 0 {
			if action, proceed := r.disabledMutationGuard(ctx, parent); !proceed {
				return action
			}
			if action := r.refreshWorkloadCandidates(ctx, parent, observation); action.Err != nil {
				return action
			}
			candidates = candidateWorkloadPods(parent, names, set, observation.Pods)
			if !workloadPodsSafe(set, candidates, true) {
				return actionResult{}
			}
			scaled := set.DeepCopy()
			scaled.Spec.Replicas = pointerTo(int32(0))
			if err := r.Patch(ctx, scaled, client.MergeFromWithOptions(set, client.MergeFromWithOptimisticLock{})); err != nil {
				return r.finishWorkloadMutation(ctx, parent, names, observation, err)
			}
			return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
		}
		if len(candidates) != 0 {
			return actionResult{}
		}
		if action, proceed := r.disabledMutationGuard(ctx, parent); !proceed {
			return action
		}
		if action := r.refreshWorkloadCandidates(ctx, parent, observation); action.Err != nil {
			return action
		}
		if len(candidateWorkloadPods(parent, names, set, observation.Pods)) != 0 {
			return actionResult{}
		}
		if err := r.Delete(ctx, set, workloadDeleteOptions(set)...); err != nil {
			return r.finishWorkloadMutation(ctx, parent, names, observation, err)
		}
		return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
	}
	if len(candidates) != 0 {
		return actionResult{}
	}

	if observation.ServiceErr != nil {
		return actionResult{Err: observation.ServiceErr}
	}
	if observation.Service != nil {
		service := observation.Service
		if !workloadSoleOwnedBy(service, parent) || !service.DeletionTimestamp.IsZero() {
			return actionResult{}
		}
		if action, proceed := r.disabledMutationGuard(ctx, parent); !proceed {
			return action
		}
		if action := r.refreshWorkloadCandidates(ctx, parent, observation); action.Err != nil {
			return action
		}
		if len(candidateWorkloadPods(parent, names, nil, observation.Pods)) != 0 {
			return actionResult{}
		}
		if err := r.Delete(ctx, service, workloadDeleteOptions(service)...); err != nil {
			return r.finishWorkloadMutation(ctx, parent, names, observation, err)
		}
		return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
	}

	if observation.ConfigMapErr != nil {
		return actionResult{Err: observation.ConfigMapErr}
	}
	if observation.ConfigMap != nil {
		configuration := observation.ConfigMap
		if workloadConfigNameCollides(parent, names) || !workloadSoleOwnedBy(configuration, parent) || !configuration.DeletionTimestamp.IsZero() {
			return actionResult{}
		}
		if action, proceed := r.disabledMutationGuard(ctx, parent); !proceed {
			return action
		}
		if action := r.refreshWorkloadCandidates(ctx, parent, observation); action.Err != nil {
			return action
		}
		if len(candidateWorkloadPods(parent, names, nil, observation.Pods)) != 0 {
			return actionResult{}
		}
		if err := r.Delete(ctx, configuration, workloadDeleteOptions(configuration)...); err != nil {
			return r.finishWorkloadMutation(ctx, parent, names, observation, err)
		}
		return r.finishWorkloadMutation(ctx, parent, names, observation, nil)
	}
	return actionResult{}
}

func (r *KeaClusterReconciler) disabledMutationGuard(ctx context.Context, origin *infrastructurev1alpha1.KeaCluster) (actionResult, bool) {
	if err := ctx.Err(); err != nil {
		return actionResult{Err: err}, false
	}
	fresh := &infrastructurev1alpha1.KeaCluster{}
	err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(origin), fresh)
	if apierrors.IsNotFound(err) || (err == nil && !fresh.DeletionTimestamp.IsZero()) {
		return actionResult{}, false
	}
	if err != nil {
		return actionResult{Err: err}, false
	}
	if fresh.UID != origin.UID || fresh.Generation != origin.Generation {
		return actionResult{Result: reconcileResult(time.Second)}, false
	}
	if enabled, _ := effectiveWorkload(fresh); enabled {
		return actionResult{Result: reconcileResult(time.Second)}, false
	}
	if err := ctx.Err(); err != nil {
		return actionResult{Err: err}, false
	}
	return actionResult{}, true
}

func workloadDeleteOptions(object client.Object) []client.DeleteOption {
	uid, resourceVersion := object.GetUID(), object.GetResourceVersion()
	return []client.DeleteOption{
		client.Preconditions{UID: &uid, ResourceVersion: &resourceVersion},
		client.PropagationPolicy(metav1.DeletePropagationBackground),
	}
}

func workloadObservationError(observation workloadObservation) error {
	return errors.Join(observation.ConfigMapErr, observation.ServiceErr, observation.StatefulSetErr, observation.PodsErr)
}

func (r *KeaClusterReconciler) workloadMutationGuard(ctx context.Context, origin *infrastructurev1alpha1.KeaCluster, config workloadConfig) (actionResult, bool) {
	if err := ctx.Err(); err != nil {
		return actionResult{Err: err}, false
	}
	fresh := &infrastructurev1alpha1.KeaCluster{}
	err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(origin), fresh)
	if apierrors.IsNotFound(err) || (err == nil && !fresh.DeletionTimestamp.IsZero()) {
		return actionResult{}, false
	}
	if err != nil {
		return actionResult{Err: err}, false
	}
	if fresh.UID != origin.UID || fresh.Generation != origin.Generation {
		return actionResult{Result: reconcileResult(time.Second)}, false
	}
	enabled, severity := effectiveWorkload(fresh)
	freshConfig, configErr := generateKeaConfig(severity)
	if !enabled || configErr != nil || freshConfig.Hash != config.Hash {
		return actionResult{Result: reconcileResult(time.Second)}, false
	}
	if err := ctx.Err(); err != nil {
		return actionResult{Err: err}, false
	}
	return actionResult{}, true
}

func (r *KeaClusterReconciler) finishWorkloadMutation(ctx context.Context, parent *infrastructurev1alpha1.KeaCluster, names workloadNames, observation *workloadObservation, writeErr error) actionResult {
	latest := r.observeWorkload(ctx, parent, names)
	*observation = latest
	return actionResult{Mutated: true, Result: reconcileResult(time.Second), Err: errors.Join(writeErr, workloadObservationError(latest))}
}

func (r *KeaClusterReconciler) refreshWorkloadCandidates(ctx context.Context, parent *infrastructurev1alpha1.KeaCluster, observation *workloadObservation) actionResult {
	if err := ctx.Err(); err != nil {
		observation.PodsErr = err
		return actionResult{Err: err}
	}
	list := &corev1.PodList{}
	if err := r.APIReader.List(ctx, list, client.InNamespace(parent.Namespace)); err != nil {
		observation.PodsErr = err
		return actionResult{Err: err}
	}
	observation.PodsErr = nil
	observation.Pods = list.Items
	return actionResult{}
}

func workloadRequeue(conditions []metav1.Condition, progressInterval, blockedInterval, healthyInterval time.Duration) time.Duration {
	if progressInterval <= 0 {
		progressInterval = 5 * time.Second
	}
	if blockedInterval <= 0 {
		blockedInterval = 30 * time.Second
	}
	if healthyInterval <= 0 {
		healthyInterval = 5 * time.Minute
	}
	delay := healthyInterval
	for _, condition := range conditions {
		if condition.Status == metav1.ConditionUnknown {
			if delay > blockedInterval {
				delay = blockedInterval
			}
		}
		if condition.Type == "ArtifactReconciled" && condition.Status != metav1.ConditionTrue {
			if delay > blockedInterval {
				delay = blockedInterval
			}
		}
		if condition.Type == "WorkloadReconciled" && condition.Status != metav1.ConditionTrue {
			switch condition.Reason {
			case "ResourcesOutOfSync", "RolloutPending", "PodDrift", "ProcessUnhealthy":
				if delay > progressInterval {
					delay = progressInterval
				}
			default:
				if delay > blockedInterval {
					delay = blockedInterval
				}
			}
		}
		if condition.Type == "WorkloadReady" && condition.Status != metav1.ConditionTrue {
			if condition.Reason == "RolloutPending" || condition.Reason == "ProcessUnhealthy" || condition.Reason == "PodDrift" {
				if delay > progressInterval {
					delay = progressInterval
				}
			} else if delay > blockedInterval {
				delay = blockedInterval
			}
		}
	}
	return delay
}

func reconcileResult(delay time.Duration) ctrl.Result { return ctrl.Result{RequeueAfter: delay} }
