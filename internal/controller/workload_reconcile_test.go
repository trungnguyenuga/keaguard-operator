package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func m2ReconcileFixture(t *testing.T, objects ...client.Object) (*infrastructurev1alpha1.KeaCluster, workloadNames, workloadConfig, *statusRecordingClient, *KeaClusterReconciler) {
	t.Helper()
	parent, names, config := m2ResourceFixture(t)
	parent.UID = types.UID("parent-uid")
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, infrastructurev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	all := []client.Object{parent}
	all = append(all, objects...)
	base := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&infrastructurev1alpha1.KeaCluster{}).WithObjects(all...).Build()
	recorder := &statusRecordingClient{Client: base}
	return parent, names, config, recorder, newTestReconciler(recorder, base, parent.Namespace)
}

func submittedMutations(operations []apiOperation) []apiOperation {
	var mutations []apiOperation
	for _, operation := range operations {
		switch operation.Verb {
		case "create", "patch", "delete", "delete-all-of":
			mutations = append(mutations, operation)
		}
	}
	return mutations
}

func TestUnitM2EnableSequence(t *testing.T) {
	parent, names, _, recorder, reconciler := m2ReconcileFixture(t)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)}
	want := []apiOperation{
		{Verb: "create", Kind: "ConfigMap", Namespace: parent.Namespace, Name: parent.Name},
		{Verb: "create", Kind: "ConfigMap", Namespace: parent.Namespace, Name: names.ConfigMap},
		{Verb: "create", Kind: "Service", Namespace: parent.Namespace, Name: names.Service},
		{Verb: "create", Kind: "StatefulSet", Namespace: parent.Namespace, Name: names.StatefulSet},
	}
	for pass, expected := range want {
		beforeOperations, beforeWrites, beforeStatus := len(recorder.operationSnapshot()), recorder.otherWrites(), recorder.statusPatches()
		result, err := reconciler.Reconcile(context.Background(), request)
		if err != nil || result.RequeueAfter != time.Second {
			t.Fatalf("pass %d result=%+v err=%v", pass+1, result, err)
		}
		operations := recorder.operationSnapshot()[beforeOperations:]
		mutations := submittedMutations(operations)
		if len(mutations) != 1 || mutations[0] != expected || recorder.otherWrites()-beforeWrites != 1 || recorder.statusPatches()-beforeStatus > 1 {
			t.Fatalf("pass %d mutations=%+v writes=%d status=%d operations=%+v", pass+1, mutations, recorder.otherWrites()-beforeWrites, recorder.statusPatches()-beforeStatus, operations)
		}
	}
	beforeWrites, beforeStatus := recorder.otherWrites(), recorder.statusPatches()
	result, err := reconciler.Reconcile(context.Background(), request)
	if err != nil || result.RequeueAfter != 5*time.Second || recorder.otherWrites() != beforeWrites || recorder.statusPatches() != beforeStatus {
		t.Fatalf("stable progress result=%+v err=%v writes=%d status=%d", result, err, recorder.otherWrites()-beforeWrites, recorder.statusPatches()-beforeStatus)
	}
}

func TestUnitM2RolloutRequiresFreshSoleOwnedPods(t *testing.T) {
	newRolloutFixture := func(t *testing.T, podOwnerRefs []metav1.OwnerReference) (*infrastructurev1alpha1.KeaCluster, workloadNames, workloadConfig, *statusRecordingClient, *KeaClusterReconciler, *corev1.Pod) {
		t.Helper()
		parent, names, oldConfig, recorder, reconciler := m2ReconcileFixture(t)
		parent.Spec.Workload.LoggingSeverity = pointerTo("DEBUG")
		if err := recorder.Client.Update(context.Background(), parent); err != nil {
			t.Fatal(err)
		}
		if err := recorder.Client.Get(context.Background(), client.ObjectKeyFromObject(parent), parent); err != nil {
			t.Fatal(err)
		}
		newConfig, err := generateKeaConfig("DEBUG")
		if err != nil {
			t.Fatal(err)
		}
		oldSet := desiredKeaStatefulSet(parent, names, oldConfig)
		oldSet.UID = types.UID("statefulset-uid")
		oldSet.Generation = 3
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: names.StatefulSet + "-0", Namespace: parent.Namespace, UID: types.UID("pod-uid"),
			OwnerReferences: podOwnerRefs,
		}}
		newConfigMap := desiredKeaConfig(parent, names, newConfig)
		service := desiredHeadlessService(parent, names)
		oldSet.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: parent.Name, UID: parent.UID, Controller: ptr(true),
		}}
		pod.OwnerReferences = podOwnerRefs
		for _, object := range []client.Object{newConfigMap, service, oldSet, pod} {
			if err := recorder.Client.Create(context.Background(), object); err != nil {
				t.Fatal(err)
			}
		}
		return parent, names, newConfig, recorder, reconciler, pod
	}
	controllerRef := func(uid types.UID) metav1.OwnerReference {
		return metav1.OwnerReference{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "kg-placeholder", UID: uid, Controller: ptr(true)}
	}

	t.Run("ordinary rollout retains valid sole owner", func(t *testing.T) {
		parent, names, config, recorder, reconciler, _ := newRolloutFixture(t, nil)
		set := &appsv1.StatefulSet{}
		if err := recorder.Client.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet}, set); err != nil {
			t.Fatal(err)
		}
		pod := &corev1.Pod{}
		if err := recorder.Client.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet + "-0"}, pod); err != nil {
			t.Fatal(err)
		}
		pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: set.Name, UID: set.UID, Controller: ptr(true)}}
		if err := recorder.Client.Update(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
		observation := reconciler.observeWorkload(context.Background(), parent, names)
		result := reconciler.reconcileEnabledWorkload(context.Background(), parent, names, config, &observation)
		if !result.Mutated || result.Err != nil {
			t.Fatalf("valid rollout action = %+v", result)
		}
		got := &appsv1.StatefulSet{}
		if err := recorder.Client.Get(context.Background(), client.ObjectKeyFromObject(set), got); err != nil {
			t.Fatal(err)
		}
		if got.Spec.Template.Annotations[configHashAnnotation] != config.Hash {
			t.Fatalf("valid sole-owned Pod did not permit ordinary template rollout: hash=%q want=%q", got.Spec.Template.Annotations[configHashAnnotation], config.Hash)
		}
	})

	t.Run("fresh additional owner blocks rollout and removal permits recovery", func(t *testing.T) {
		parent, names, config, recorder, reconciler, _ := newRolloutFixture(t, nil)
		set := &appsv1.StatefulSet{}
		if err := recorder.Client.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet}, set); err != nil {
			t.Fatal(err)
		}
		podKey := client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet + "-0"}
		pod := &corev1.Pod{}
		if err := recorder.Client.Get(context.Background(), podKey, pod); err != nil {
			t.Fatal(err)
		}
		pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: set.Name, UID: set.UID, Controller: ptr(true)}}
		if err := recorder.Client.Update(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
		staleObservation := reconciler.observeWorkload(context.Background(), parent, names)
		pod = &corev1.Pod{}
		if err := recorder.Client.Get(context.Background(), podKey, pod); err != nil {
			t.Fatal(err)
		}
		pod.OwnerReferences = append(pod.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "foreign", UID: "foreign"})
		if err := recorder.Client.Update(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
		before := recorder.otherWrites()
		blocked := reconciler.reconcileEnabledWorkload(context.Background(), parent, names, config, &staleObservation)
		if blocked.Mutated || blocked.Err != nil || recorder.otherWrites() != before {
			t.Fatalf("fresh additional owner was not safely blocked: action=%+v writes=%d", blocked, recorder.otherWrites()-before)
		}
		conditions := workloadConditions(parent, names, config, staleObservation, metav1.Condition{Type: "ArtifactReconciled", Status: metav1.ConditionTrue, Reason: "ArtifactInSync"})
		if conditions[0].Status != metav1.ConditionFalse || conditions[0].Reason != "ResourcesOutOfSync" || conditions[1].Status != metav1.ConditionFalse || conditions[1].Reason != "WorkloadBlocked" || workloadRequeue(conditions, 5*time.Second, 30*time.Second, 5*time.Minute) != 5*time.Second {
			t.Fatalf("blocked rollout conditions/retry = %#v / %s", conditions, workloadRequeue(conditions, 5*time.Second, 30*time.Second, 5*time.Minute))
		}
		pod = &corev1.Pod{}
		if err := recorder.Client.Get(context.Background(), podKey, pod); err != nil {
			t.Fatal(err)
		}
		pod.OwnerReferences = pod.OwnerReferences[:1]
		if err := recorder.Client.Update(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
		freshObservation := reconciler.observeWorkload(context.Background(), parent, names)
		recovered := reconciler.reconcileEnabledWorkload(context.Background(), parent, names, config, &freshObservation)
		if !recovered.Mutated || recovered.Err != nil {
			t.Fatalf("rollout did not recover after blocker removal: %+v", recovered)
		}
	})

	for _, tc := range []struct {
		name string
		ref  metav1.OwnerReference
	}{
		{name: "foreign controller", ref: func() metav1.OwnerReference {
			ref := controllerRef("statefulset-uid")
			ref.Name = "foreign"
			return ref
		}()},
		{name: "stale StatefulSet UID", ref: controllerRef("stale-statefulset-uid")},
	} {
		t.Run(tc.name+" blocks rollout", func(t *testing.T) {
			parent, names, config, recorder, reconciler, pod := newRolloutFixture(t, []metav1.OwnerReference{tc.ref})
			pod.OwnerReferences[0].Name = names.StatefulSet
			stored := &corev1.Pod{}
			if err := recorder.Client.Get(context.Background(), client.ObjectKeyFromObject(pod), stored); err != nil {
				t.Fatal(err)
			}
			stored.OwnerReferences = []metav1.OwnerReference{tc.ref}
			stored.OwnerReferences[0].Name = tc.ref.Name
			if err := recorder.Client.Update(context.Background(), stored); err != nil {
				t.Fatal(err)
			}
			observation := reconciler.observeWorkload(context.Background(), parent, names)
			before := recorder.otherWrites()
			result := reconciler.reconcileEnabledWorkload(context.Background(), parent, names, config, &observation)
			if result.Mutated || result.Err != nil || recorder.otherWrites() != before {
				t.Fatalf("unsafe controller identity allowed rollout: action=%+v writes=%d", result, recorder.otherWrites()-before)
			}
		})
	}
}

func TestUnitM2PreflightBlockers(t *testing.T) {
	for _, scenario := range []string{"identity", "foreign service", "terminating service", "candidate pod", "immutable configuration", "collision"} {
		t.Run(scenario, func(t *testing.T) {
			parent, names, config, recorder, reconciler := m2ReconcileFixture(t)
			base := recorder.Client
			identity := desiredArtifact(parent)
			if scenario == "identity" {
				identity.OwnerReferences = nil
			}
			if err := base.Create(context.Background(), identity); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "foreign service":
				foreign := desiredHeadlessService(parent, names)
				foreign.OwnerReferences = nil
				if err := base.Create(context.Background(), foreign); err != nil {
					t.Fatal(err)
				}
			case "terminating service":
				terminating := desiredHeadlessService(parent, names)
				terminating.Finalizers = []string{"external.example/hold"}
				if err := base.Create(context.Background(), terminating); err != nil {
					t.Fatal(err)
				}
				if err := base.Delete(context.Background(), terminating); err != nil {
					t.Fatal(err)
				}
			case "candidate pod":
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: names.StatefulSet + "-0", Namespace: parent.Namespace, Labels: map[string]string{clusterUIDLabel: string(parent.UID)}}}
				if err := base.Create(context.Background(), pod); err != nil {
					t.Fatal(err)
				}
			case "immutable configuration":
				configuration := desiredKeaConfig(parent, names, config)
				immutable := true
				configuration.Immutable = &immutable
				if err := base.Create(context.Background(), configuration); err != nil {
					t.Fatal(err)
				}
			}
			beforeWrites, beforeStatus := recorder.otherWrites(), recorder.statusPatches()
			var err error
			if scenario == "collision" {
				collidingNames := names
				collidingNames.ConfigMap = parent.Name
				observation := reconciler.observeWorkload(context.Background(), parent, collidingNames)
				action := reconciler.reconcileEnabledWorkload(context.Background(), parent, collidingNames, config, &observation)
				err = action.Err
			} else {
				_, err = reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
			}
			if scenario == "identity" {
				if err != nil || recorder.otherWrites() != beforeWrites || recorder.statusPatches()-beforeStatus != 1 {
					t.Fatalf("identity blocker result err=%v writes=%d status=%d", err, recorder.otherWrites()-beforeWrites, recorder.statusPatches()-beforeStatus)
				}
			} else if err != nil || recorder.otherWrites() != beforeWrites || recorder.statusPatches()-beforeStatus > 1 {
				t.Fatalf("preflight %q allowed mutation: err=%v writes=%d status=%d", scenario, err, recorder.otherWrites()-beforeWrites, recorder.statusPatches()-beforeStatus)
			}
		})
	}
}

func TestUnitM2MutationBudget(t *testing.T) {
	parent, names, config, recorder, reconciler := m2ReconcileFixture(t)
	base := recorder.Client
	if err := base.Create(context.Background(), desiredArtifact(parent)); err != nil {
		t.Fatal(err)
	}
	// A later child conflict is found before an earlier missing child can be created.
	foreign := desiredKeaStatefulSet(parent, names, config)
	foreign.OwnerReferences = nil
	if err := base.Create(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	writes, status := recorder.otherWrites(), recorder.statusPatches()
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
	if err != nil || recorder.otherWrites() != writes || recorder.statusPatches()-status > 1 {
		t.Fatalf("later-child blocker violated mutation budget: err=%v writes=%d status=%d", err, recorder.otherWrites()-writes, recorder.statusPatches()-status)
	}
	if err := base.Delete(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}

	// A rejected create is counted as submitted, returned as an error, and is not retried.
	failed := errors.New("create rejected")
	clientWithFault := &rejectCreateClient{statusRecordingClient: recorder, err: failed}
	reconciler.Client = clientWithFault
	observation := reconciler.observeWorkload(context.Background(), parent, names)
	action := reconciler.reconcileEnabledWorkload(context.Background(), parent, names, config, &observation)
	if !errors.Is(action.Err, failed) || !action.Mutated || clientWithFault.creates != 1 {
		t.Fatalf("rejected create action=%+v submissions=%d", action, clientWithFault.creates)
	}
	if recorder.otherWrites() != writes+1 {
		t.Fatalf("rejected create was not counted: before=%d after=%d", writes, recorder.otherWrites())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	observation = reconciler.observeWorkload(context.Background(), parent, names)
	beforeCanceled := clientWithFault.creates
	action = reconciler.reconcileEnabledWorkload(canceled, parent, names, config, &observation)
	if !errors.Is(action.Err, context.Canceled) || action.Mutated || clientWithFault.creates != beforeCanceled {
		t.Fatalf("canceled action=%+v submissions=%d", action, clientWithFault.creates-beforeCanceled)
	}
}

type rejectCreateClient struct {
	*statusRecordingClient
	err     error
	creates int
}

func (c *rejectCreateClient) Create(_ context.Context, obj client.Object, _ ...client.CreateOption) error {
	c.creates++
	c.recordResourceWrite()
	c.recordOperation("create", obj, c.err)
	return c.err
}

type deleteReceipt struct {
	Kind, Name, UID, ResourceVersion string
	Propagation                      *metav1.DeletionPropagation
	Preconditions                    *metav1.Preconditions
}

type deleteRecordingClient struct {
	*statusRecordingClient
	deletes []deleteReceipt
}

func (c *deleteRecordingClient) Delete(ctx context.Context, obj client.Object, options ...client.DeleteOption) error {
	var opts client.DeleteOptions
	for _, option := range options {
		option.ApplyToDelete(&opts)
	}
	c.deletes = append(c.deletes, deleteReceipt{
		Kind: operationKind(obj), Name: obj.GetName(), UID: string(obj.GetUID()), ResourceVersion: obj.GetResourceVersion(),
		Propagation: opts.PropagationPolicy, Preconditions: opts.Preconditions,
	})
	return c.statusRecordingClient.Delete(ctx, obj, options...)
}

type workloadReadFaultReader struct {
	client.Reader
	identityName string
	identityErr  error
	childName    string
	childErr     error
	listErr      error
}

func (r *workloadReadFaultReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if _, ok := object.(*corev1.ConfigMap); ok && key.Name == r.identityName && r.identityErr != nil {
		return r.identityErr
	}
	if key.Name == r.childName && r.childErr != nil {
		switch object.(type) {
		case *corev1.ConfigMap, *corev1.Service, *appsv1.StatefulSet:
			return r.childErr
		}
	}
	return r.Reader.Get(ctx, key, object, options...)
}

func (r *workloadReadFaultReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if _, ok := list.(*corev1.PodList); ok && r.listErr != nil {
		return r.listErr
	}
	return r.Reader.List(ctx, list, options...)
}

func m2DisableFixture(t *testing.T, statefulSet bool, podCount int, identityConflict bool) (*infrastructurev1alpha1.KeaCluster, workloadNames, workloadConfig, *statusRecordingClient, *deleteRecordingClient, *KeaClusterReconciler) {
	t.Helper()
	parent, names, config, recorder, reconciler := m2ReconcileFixture(t)
	base := recorder.Client
	parent.Spec.Workload.Enabled = false
	if err := base.Update(context.Background(), parent); err != nil {
		t.Fatal(err)
	}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(parent), parent); err != nil {
		t.Fatal(err)
	}
	identity := desiredArtifact(parent)
	identity.UID = types.UID("identity-uid")
	if identityConflict {
		identity.OwnerReferences = nil
	}
	if err := base.Create(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	configuration := desiredKeaConfig(parent, names, config)
	configuration.UID = types.UID("configuration-uid")
	if err := base.Create(context.Background(), configuration); err != nil {
		t.Fatal(err)
	}
	service := desiredHeadlessService(parent, names)
	service.UID = types.UID("service-uid")
	if err := base.Create(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	if statefulSet {
		set := desiredKeaStatefulSet(parent, names, config)
		set.UID = types.UID("statefulset-uid")
		if err := base.Create(context.Background(), set); err != nil {
			t.Fatal(err)
		}
		for ordinal := 0; ordinal < podCount; ordinal++ {
			controller := true
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%d", names.StatefulSet, ordinal), Namespace: parent.Namespace, Labels: map[string]string{clusterUIDLabel: string(parent.UID)}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: set.Name, UID: set.UID, Controller: &controller}}}}
			if err := base.Create(context.Background(), pod); err != nil {
				t.Fatal(err)
			}
		}
	}
	deleteClient := &deleteRecordingClient{statusRecordingClient: recorder}
	reconciler.Client = deleteClient
	return parent, names, config, recorder, deleteClient, reconciler
}

func TestUnitM2DisableSequence(t *testing.T) {
	parent, names, _, recorder, writer, reconciler := m2DisableFixture(t, true, 2, false)
	base := recorder.Client
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)}
	want := []apiOperation{{Verb: "patch", Kind: "StatefulSet", Namespace: parent.Namespace, Name: names.StatefulSet}}
	for pass := 0; pass < len(want); pass++ {
		beforeOps, beforeWrites, beforeStatus := len(recorder.operationSnapshot()), recorder.otherWrites(), recorder.statusPatches()
		result, err := reconciler.Reconcile(context.Background(), request)
		if err != nil || result.RequeueAfter != time.Second {
			t.Fatalf("scale pass result=%+v err=%v", result, err)
		}
		operations := recorder.operationSnapshot()[beforeOps:]
		mutations := submittedMutations(operations)
		if len(mutations) != 1 || mutations[0] != want[pass] || recorder.otherWrites()-beforeWrites != 1 || recorder.statusPatches()-beforeStatus > 1 {
			t.Fatalf("scale pass mutations=%+v operations=%+v", mutations, operations)
		}
	}
	set := &appsv1.StatefulSet{}
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet}, set); err != nil || set.Spec.Replicas == nil || *set.Spec.Replicas != 0 {
		t.Fatalf("scale-to-zero statefulset=%+v err=%v", set, err)
	}
	beforeWrites, beforeStatus := recorder.otherWrites(), recorder.statusPatches()
	result, err := reconciler.Reconcile(context.Background(), request)
	if err != nil || result.RequeueAfter != 30*time.Second || recorder.otherWrites() != beforeWrites || recorder.statusPatches()-beforeStatus > 1 {
		t.Fatalf("cleanup advanced before Pod absence: result=%+v err=%v writes=%d", result, err, recorder.otherWrites()-beforeWrites)
	}
	for ordinal := 0; ordinal < 2; ordinal++ {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%d", names.StatefulSet, ordinal), Namespace: parent.Namespace}}
		if err := base.Delete(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
	}
	want = []apiOperation{
		{Verb: "delete", Kind: "StatefulSet", Namespace: parent.Namespace, Name: names.StatefulSet},
		{Verb: "delete", Kind: "Service", Namespace: parent.Namespace, Name: names.Service},
		{Verb: "delete", Kind: "ConfigMap", Namespace: parent.Namespace, Name: names.ConfigMap},
	}
	for pass, expected := range want {
		beforeOps := len(recorder.operationSnapshot())
		beforeWrites, beforeStatus = recorder.otherWrites(), recorder.statusPatches()
		result, err = reconciler.Reconcile(context.Background(), request)
		if err != nil || result.RequeueAfter != time.Second {
			t.Fatalf("cleanup pass %d result=%+v err=%v", pass+1, result, err)
		}
		mutations := submittedMutations(recorder.operationSnapshot()[beforeOps:])
		if len(mutations) != 1 || mutations[0] != expected || recorder.otherWrites()-beforeWrites != 1 || recorder.statusPatches()-beforeStatus > 1 {
			t.Fatalf("cleanup pass %d mutations=%+v", pass+1, mutations)
		}
	}
	beforeWrites, beforeStatus = recorder.otherWrites(), recorder.statusPatches()
	result, err = reconciler.Reconcile(context.Background(), request)
	if err != nil || result.RequeueAfter != 5*time.Minute || recorder.otherWrites() != beforeWrites || recorder.statusPatches()-beforeStatus > 1 {
		t.Fatalf("settled disable result=%+v err=%v", result, err)
	}
	for _, deletion := range writer.deletes {
		if deletion.UID == "" || deletion.ResourceVersion == "" || deletion.Preconditions == nil || deletion.Preconditions.UID == nil || string(*deletion.Preconditions.UID) != deletion.UID || deletion.Preconditions.ResourceVersion == nil || *deletion.Preconditions.ResourceVersion != deletion.ResourceVersion || deletion.Propagation == nil || *deletion.Propagation != metav1.DeletePropagationBackground {
			t.Fatalf("delete lacks UID/RV/Background safeguards: %+v", deletion)
		}
	}
	for _, operation := range recorder.operationSnapshot() {
		if operation.Verb == "delete" && operation.Kind == "ConfigMap" && operation.Name == parent.Name {
			t.Fatal("cleanup submitted an identity ConfigMap delete")
		}
	}
	identity := &corev1.ConfigMap{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(parent), identity); err != nil || identity.UID != "identity-uid" || identity.Data["keacluster-uid"] != string(parent.UID) {
		t.Fatalf("identity changed during cleanup: %+v err=%v", identity, err)
	}
}

func TestUnitM2CleanupBlockers(t *testing.T) {
	for _, scenario := range []string{"foreign StatefulSet owner", "foreign Pod owner", "orphan Pod", "label drift candidate", "higher ordinal candidate", "terminating StatefulSet", "terminating Service", "foreign Service owner", "extra Service owner", "foreign Configuration owner", "extra Configuration owner", "immutable Configuration", "failed Pod List"} {
		t.Run(scenario, func(t *testing.T) {
			statefulSet := scenario != "orphan Pod" && scenario != "foreign Service owner" && scenario != "extra Service owner" && scenario != "foreign Configuration owner" && scenario != "extra Configuration owner" && scenario != "immutable Configuration"
			podCount := 0
			if statefulSet && scenario != "terminating StatefulSet" {
				podCount = 1
			}
			parent, names, _, recorder, writer, reconciler := m2DisableFixture(t, statefulSet, podCount, false)
			base := recorder.Client
			switch scenario {
			case "foreign StatefulSet owner":
				set := &appsv1.StatefulSet{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet}, set); err != nil {
					t.Fatal(err)
				}
				set.OwnerReferences = append(set.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "extra", UID: types.UID("extra"), Controller: pointerTo(false)})
				if err := base.Update(context.Background(), set); err != nil {
					t.Fatal(err)
				}
			case "foreign Pod owner":
				pod := &corev1.Pod{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet + "-0"}, pod); err != nil {
					t.Fatal(err)
				}
				pod.OwnerReferences[0].UID = types.UID("stale")
				if err := base.Update(context.Background(), pod); err != nil {
					t.Fatal(err)
				}
			case "terminating StatefulSet":
				set := &appsv1.StatefulSet{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet}, set); err != nil {
					t.Fatal(err)
				}
				set.Finalizers = []string{"external.example/hold"}
				if err := base.Update(context.Background(), set); err != nil {
					t.Fatal(err)
				}
				if err := base.Delete(context.Background(), set); err != nil {
					t.Fatal(err)
				}
			case "orphan Pod":
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: names.StatefulSet + "-4", Namespace: parent.Namespace, Labels: map[string]string{clusterUIDLabel: string(parent.UID)}}}
				if err := base.Create(context.Background(), pod); err != nil {
					t.Fatal(err)
				}
			case "label drift candidate":
				pod := &corev1.Pod{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet + "-0"}, pod); err != nil {
					t.Fatal(err)
				}
				pod.Labels[clusterUIDLabel] = "foreign-label"
				if err := base.Update(context.Background(), pod); err != nil {
					t.Fatal(err)
				}
			case "higher ordinal candidate":
				set := &appsv1.StatefulSet{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet}, set); err != nil {
					t.Fatal(err)
				}
				controller := true
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: names.StatefulSet + "-5", Namespace: parent.Namespace, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: set.Name, UID: set.UID, Controller: &controller}}}}
				if err := base.Create(context.Background(), pod); err != nil {
					t.Fatal(err)
				}
			case "terminating Service":
				set := &appsv1.StatefulSet{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet}, set); err != nil {
					t.Fatal(err)
				}
				set.UID = types.UID("statefulset-uid")
				set.Spec.Replicas = pointerTo(int32(0))
				if err := base.Update(context.Background(), set); err != nil {
					t.Fatal(err)
				}
				for ordinal := 0; ordinal < podCount; ordinal++ {
					pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%d", names.StatefulSet, ordinal), Namespace: parent.Namespace}}
					if err := base.Delete(context.Background(), pod); err != nil {
						t.Fatal(err)
					}
				}
				service := &corev1.Service{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.Service}, service); err != nil {
					t.Fatal(err)
				}
				service.Finalizers = []string{"external.example/hold"}
				if err := base.Update(context.Background(), service); err != nil {
					t.Fatal(err)
				}
				if err := base.Delete(context.Background(), service); err != nil {
					t.Fatal(err)
				}
			case "foreign Service owner", "extra Service owner":
				service := &corev1.Service{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.Service}, service); err != nil {
					t.Fatal(err)
				}
				if scenario == "foreign Service owner" {
					service.OwnerReferences = nil
				} else {
					service.OwnerReferences = append(service.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "extra", UID: types.UID("extra"), Controller: pointerTo(false)})
				}
				if err := base.Update(context.Background(), service); err != nil {
					t.Fatal(err)
				}
			case "foreign Configuration owner", "extra Configuration owner", "immutable Configuration":
				service := &corev1.Service{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.Service}, service); err != nil {
					t.Fatal(err)
				}
				if err := base.Delete(context.Background(), service); err != nil {
					t.Fatal(err)
				}
				configuration := &corev1.ConfigMap{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.ConfigMap}, configuration); err != nil {
					t.Fatal(err)
				}
				if scenario == "foreign Configuration owner" {
					configuration.OwnerReferences = nil
				} else if scenario == "extra Configuration owner" {
					configuration.OwnerReferences = append(configuration.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "extra", UID: types.UID("extra"), Controller: pointerTo(false)})
				} else {
					immutable := true
					configuration.Immutable = &immutable
				}
				if err := base.Update(context.Background(), configuration); err != nil {
					t.Fatal(err)
				}
			case "failed Pod List":
				reconciler.APIReader = &workloadReadFaultReader{Reader: base, listErr: errors.New("pod list unavailable")}
			}
			beforeWrites := recorder.otherWrites()
			_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
			if scenario == "immutable Configuration" {
				if err != nil || recorder.otherWrites()-beforeWrites != 1 || len(writer.deletes) != 1 || writer.deletes[0].Kind != "ConfigMap" || writer.deletes[0].Name != names.ConfigMap {
					t.Fatalf("owned immutable config was not cleaned up: writes=%d deletes=%+v err=%v", recorder.otherWrites()-beforeWrites, writer.deletes, err)
				}
			} else if scenario == "terminating Service" {
				if err != nil || recorder.otherWrites()-beforeWrites != 1 || len(writer.deletes) != 1 || writer.deletes[0].Kind != "StatefulSet" {
					t.Fatalf("safe shutdown did not precede later Service blocker: writes=%d deletes=%+v err=%v", recorder.otherWrites()-beforeWrites, writer.deletes, err)
				}
				beforeWrites = recorder.otherWrites()
				if _, err = reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)}); err != nil || recorder.otherWrites() != beforeWrites {
					t.Fatalf("terminating Service did not block subsequent cleanup: writes=%d err=%v", recorder.otherWrites()-beforeWrites, err)
				}
				service := &corev1.Service{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.Service}, service); err != nil || service.DeletionTimestamp.IsZero() {
					t.Fatalf("finalizer-held Service was changed or removed: %+v err=%v", service, err)
				}
			} else if scenario == "failed Pod List" {
				if !errors.Is(err, reconciler.APIReader.(*workloadReadFaultReader).listErr) || recorder.otherWrites() != beforeWrites {
					t.Fatalf("failed list cleanup writes=%d err=%v", recorder.otherWrites()-beforeWrites, err)
				}
			} else if scenario == "label drift candidate" || scenario == "higher ordinal candidate" {
				mutations := submittedMutations(recorder.operationSnapshot())
				if err != nil || recorder.otherWrites()-beforeWrites != 1 || len(mutations) != 1 || mutations[0].Verb != "patch" || mutations[0].Kind != "StatefulSet" || len(writer.deletes) != 0 {
					t.Fatalf("candidate-Pod safe shutdown writes=%d mutations=%+v deletes=%+v err=%v", recorder.otherWrites()-beforeWrites, mutations, writer.deletes, err)
				}
				set := &appsv1.StatefulSet{}
				if err := base.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet}, set); err != nil || set.Spec.Replicas == nil || *set.Spec.Replicas != 0 {
					t.Fatalf("candidate Pod was not preceded by scale-to-zero: replicas=%v err=%v", set.Spec.Replicas, err)
				}
			} else if err != nil || recorder.otherWrites() != beforeWrites {
				t.Fatalf("blocker %q mutated state: writes=%d err=%v", scenario, recorder.otherWrites()-beforeWrites, err)
			}
		})
	}
}

func TestUnitM2PodListFailureDoesNotSuppressIdentityRepair(t *testing.T) {
	parent, _, _, recorder, _, reconciler := m2DisableFixture(t, true, 0, false)
	base := recorder.Client
	identity := &corev1.ConfigMap{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(parent), identity); err != nil {
		t.Fatal(err)
	}
	if err := base.Delete(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	listFailure := errors.New("namespace Pod list unavailable")
	reconciler.APIReader = &workloadReadFaultReader{Reader: base, listErr: listFailure}
	beforeWrites := recorder.otherWrites()
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
	if !errors.Is(err, listFailure) {
		t.Fatalf("cleanup observation error was not retained: %v", err)
	}
	mutations := submittedMutations(recorder.operationSnapshot())
	if recorder.otherWrites()-beforeWrites != 1 || len(mutations) != 1 || mutations[0].Verb != "create" || mutations[0].Kind != "ConfigMap" || mutations[0].Name != parent.Name {
		t.Fatalf("safe identity repair was not the sole mutation: writes=%d mutations=%+v", recorder.otherWrites()-beforeWrites, mutations)
	}
	repaired := &corev1.ConfigMap{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(parent), repaired); err != nil || !artifactOwnedBy(repaired, parent) || repaired.Data["keacluster-uid"] != string(parent.UID) {
		t.Fatalf("identity artifact was not repaired for the observed parent: artifact=%+v err=%v", repaired, err)
	}
	current := &infrastructurev1alpha1.KeaCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(parent), current); err != nil {
		t.Fatal(err)
	}
	reconciled := findWorkloadCondition(current, "WorkloadReconciled")
	ready := findWorkloadCondition(current, "WorkloadReady")
	if reconciled == nil || reconciled.Status != metav1.ConditionUnknown || reconciled.Reason != "ObservationFailed" || ready == nil || ready.Status != metav1.ConditionUnknown || ready.Reason != "ObservationFailed" {
		t.Fatalf("unverified cleanup was not reported Unknown: reconciled=%+v ready=%+v", reconciled, ready)
	}
}

func TestUnitM2DisablePriority(t *testing.T) {
	for _, scenario := range []string{"identity conflict", "identity read error"} {
		t.Run(scenario, func(t *testing.T) {
			parent, names, _, recorder, writer, reconciler := m2DisableFixture(t, true, 0, scenario == "identity conflict")
			base := recorder.Client
			if scenario == "identity read error" {
				reconciler.APIReader = &workloadReadFaultReader{Reader: base, identityName: parent.Name, identityErr: errors.New("identity observation unavailable")}
			}
			beforeWrites := recorder.otherWrites()
			_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
			if scenario == "identity read error" && !errors.Is(err, reconciler.APIReader.(*workloadReadFaultReader).identityErr) {
				t.Fatalf("identity error was not retained: %v", err)
			}
			if recorder.otherWrites()-beforeWrites != 1 {
				t.Fatalf("cleanup was not prioritized as one action: writes=%d", recorder.otherWrites()-beforeWrites)
			}
			mutations := submittedMutations(recorder.operationSnapshot())
			if len(mutations) != 1 || mutations[0].Verb != "patch" || mutations[0].Kind != "StatefulSet" || mutations[0].Name != names.StatefulSet {
				t.Fatalf("identity action preceded cleanup: %+v", mutations)
			}
			for _, deletion := range writer.deletes {
				if deletion.Kind == "ConfigMap" && deletion.Name == parent.Name {
					t.Fatal("identity ConfigMap entered cleanup")
				}
			}
		})
	}
}

func TestUnitM2DisableScaleRetainsIndependentChildReadErrors(t *testing.T) {
	for _, kind := range []string{"ConfigMap", "Service"} {
		t.Run(kind, func(t *testing.T) {
			parent, names, _, recorder, _, reconciler := m2DisableFixture(t, true, 0, false)
			readFailure := errors.New(kind + " observation unavailable")
			name := names.ConfigMap
			if kind == "Service" {
				name = names.Service
			}
			reconciler.APIReader = &workloadReadFaultReader{Reader: recorder.Client, childName: name, childErr: readFailure}
			before := recorder.otherWrites()
			_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
			if !errors.Is(err, readFailure) {
				t.Fatalf("independent %s error not retained: %v", kind, err)
			}
			if recorder.otherWrites()-before != 1 {
				t.Fatalf("verified safe scale-down submissions=%d", recorder.otherWrites()-before)
			}
			mutations := submittedMutations(recorder.operationSnapshot())
			if len(mutations) != 1 || mutations[0].Verb != "patch" || mutations[0].Kind != "StatefulSet" || mutations[0].Name != names.StatefulSet {
				t.Fatalf("unrelated read failure changed mutation priority: %+v", mutations)
			}
			set := &appsv1.StatefulSet{}
			if err := recorder.Client.Get(context.Background(), client.ObjectKey{Namespace: parent.Namespace, Name: names.StatefulSet}, set); err != nil || set.Spec.Replicas == nil || *set.Spec.Replicas != 0 {
				t.Fatalf("safe scale-down did not commit: replicas=%v err=%v", set.Spec.Replicas, err)
			}
		})
	}
}
