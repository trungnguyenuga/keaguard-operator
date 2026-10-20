package controller

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var statusTime = metav1.NewTime(time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC))

func artifactCondition(status metav1.ConditionStatus, reason string) metav1.Condition {
	return metav1.Condition{Type: "ArtifactReconciled", Status: status, Reason: reason, Message: "ConfigMap lab/example: internal artifact observation", ObservedGeneration: 7, LastTransitionTime: statusTime}
}
func statusParent() *infrastructurev1alpha1.KeaCluster {
	return &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "lab", UID: "parent-uid", Generation: 7, ResourceVersion: "1"}}
}
func statusFixture(t *testing.T, objects ...client.Object) (*statusRecordingClient, client.Client) {
	t.Helper()
	s := runtime.NewScheme()
	if err := infrastructurev1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	base := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&infrastructurev1alpha1.KeaCluster{}).WithObjects(objects...).Build()
	return &statusRecordingClient{Client: base}, base
}

func TestUnitM2StatusBatch(t *testing.T) {
	origin := statusParent()
	prior := metav1.Condition{Type: "ExternalCheck", Status: metav1.ConditionTrue, Reason: "External", Message: "preserve", LastTransitionTime: statusTime}
	origin.Status.Conditions = []metav1.Condition{prior}
	first := artifactCondition(metav1.ConditionTrue, "ArtifactInSync")
	second := metav1.Condition{Type: "WorkloadReconciled", Status: metav1.ConditionFalse, Reason: "Disabled", Message: "workload disabled", ObservedGeneration: origin.Generation, LastTransitionTime: statusTime}
	got, changed := withConditions(origin.Status, first, second)
	if !changed || len(got.Conditions) != 3 || !reflect.DeepEqual(got.Conditions[0], prior) {
		t.Fatalf("batch did not preserve unrelated condition: %+v changed=%v", got, changed)
	}
	second.Message = "updated explanation"
	second.Reason = "Waiting"
	got, changed = withConditions(got, first, second)
	workload := meta.FindStatusCondition(got.Conditions, "WorkloadReconciled")
	if !changed || workload == nil || workload.Reason != "Waiting" || !workload.LastTransitionTime.Equal(&statusTime) {
		t.Fatalf("same-status batch changed transition time incorrectly: %+v", workload)
	}
	parent := statusParent()
	parent.Status = infrastructurev1alpha1.KeaClusterStatus{Conditions: []metav1.Condition{prior}}
	recorder, base := statusFixture(t, parent)
	r := newTestReconciler(recorder, base, parent.Namespace)
	result, err := r.finishConditions(context.Background(), parent, []metav1.Condition{first, second}, ctrl.Result{RequeueAfter: time.Second}, nil)
	if err != nil || result.RequeueAfter != time.Second || recorder.statusPatches() != 1 {
		t.Fatalf("batched status result=%v err=%v patches=%d", result, err, recorder.statusPatches())
	}
	result, err = r.finishConditions(context.Background(), parent, []metav1.Condition{first, second}, ctrl.Result{RequeueAfter: 2 * time.Second}, nil)
	if err != nil || result.RequeueAfter != 2*time.Second || recorder.statusPatches() != 1 {
		t.Fatalf("unchanged status was not suppressed: result=%v err=%v patches=%d", result, err, recorder.statusPatches())
	}
	patchFailure := errors.New("status batch unavailable")
	recorder.patchErr = patchFailure
	operationFailure := errors.New("resource action failed")
	third := metav1.Condition{Type: "WorkloadReady", Status: metav1.ConditionUnknown, Reason: "ObservationFailed", Message: "not observed", ObservedGeneration: parent.Generation, LastTransitionTime: statusTime}
	_, err = r.finishConditions(context.Background(), parent, []metav1.Condition{first, second, third}, ctrl.Result{}, operationFailure)
	if !errors.Is(err, patchFailure) || !errors.Is(err, operationFailure) {
		t.Fatalf("joined action/status failures lost an error: %v", err)
	}
}

// Catches lost/incorrect evidence categories and observed generation on unsuccessful outcomes.
func TestUnitArtifactConditions(t *testing.T) {
	for _, tc := range []struct {
		status metav1.ConditionStatus
		reason string
	}{
		{metav1.ConditionTrue, "ArtifactInSync"}, {metav1.ConditionFalse, "OwnershipConflict"}, {metav1.ConditionFalse, "ImmutableArtifact"}, {metav1.ConditionFalse, "ArtifactDeleting"}, {metav1.ConditionFalse, "ArtifactWriteFailed"}, {metav1.ConditionFalse, "ArtifactOutOfSync"}, {metav1.ConditionUnknown, "ObservationFailed"}, {metav1.ConditionUnknown, "MutationOutcomeUnknown"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			c := artifactCondition(tc.status, tc.reason)
			got, changed := withArtifactCondition(infrastructurev1alpha1.KeaClusterStatus{}, c)
			if !changed || got.ObservedGeneration != 7 || len(got.Conditions) != 1 || !reflect.DeepEqual(got.Conditions[0], c) {
				t.Fatalf("incorrect observation: %+v changed=%v", got, changed)
			}
			raw, _ := json.Marshal(got)
			if strings.Contains(string(raw), "Ready") || strings.Contains(string(raw), "DHCP") {
				t.Fatal("unexpected readiness claim")
			}
		})
	}
}

// Catches status churn, transition-time resets and mutation of the observed input.
func TestUnitStableStatus(t *testing.T) {
	old := artifactCondition(metav1.ConditionFalse, "OwnershipConflict")
	other := metav1.Condition{Type: "ExternalCheck", Status: metav1.ConditionTrue, Reason: "External", Message: "preserve", LastTransitionTime: statusTime}
	current := infrastructurev1alpha1.KeaClusterStatus{ObservedGeneration: 7, Conditions: []metav1.Condition{other, old}}
	saved := current.DeepCopy()
	next := old
	next.LastTransitionTime = metav1.NewTime(statusTime.Add(time.Hour))
	got, changed := withArtifactCondition(current, next)
	if changed || !reflect.DeepEqual(got, current) {
		t.Fatalf("unchanged observation churned: %+v", got)
	}
	next.Reason = "ImmutableArtifact"
	next.Message = "ConfigMap lab/example: remove immutable artifact manually to permit recreation"
	got, changed = withArtifactCondition(current, next)
	c := meta.FindStatusCondition(got.Conditions, "ArtifactReconciled")
	if !changed || c == nil || c.Reason != next.Reason || !c.LastTransitionTime.Equal(&old.LastTransitionTime) {
		t.Fatalf("same-status reason transition: %+v", got)
	}
	next.Status = metav1.ConditionTrue
	next.Reason = "ArtifactInSync"
	got, changed = withArtifactCondition(current, next)
	c = meta.FindStatusCondition(got.Conditions, "ArtifactReconciled")
	if !changed || c == nil || !c.LastTransitionTime.Equal(&next.LastTransitionTime) {
		t.Fatalf("status transition time: %+v", got)
	}
	if !reflect.DeepEqual(got.Conditions[0], other) || !reflect.DeepEqual(current, *saved) {
		t.Fatal("unrelated condition/input changed")
	}
	got.Conditions[0].Message = "mutated copy"
	if !reflect.DeepEqual(current, *saved) {
		t.Fatal("output aliases input")
	}
	// Equivalent serialized time representations must not cause churn.
	round := current.DeepCopy()
	round.Conditions[1].LastTransitionTime = metav1.NewTime(old.LastTransitionTime.In(time.FixedZone("other", 3600)))
	raw, _ := json.Marshal(round)
	if err := json.Unmarshal(raw, round); err != nil {
		t.Fatal(err)
	}
	if _, changed = withArtifactCondition(*round, old); changed {
		t.Fatal("serialization caused churn")
	}
}

func TestUnitStatusNoop(t *testing.T) {
	p := statusParent()
	c := artifactCondition(metav1.ConditionTrue, "ArtifactInSync")
	p.Status = infrastructurev1alpha1.KeaClusterStatus{ObservedGeneration: 7, Conditions: []metav1.Condition{c}}
	recorder, base := statusFixture(t, p)
	r := newTestReconciler(recorder, statusReader{Reader: base, err: errors.New("unnecessary fresh read")}, "lab")
	result, err := r.finishReconcile(context.Background(), p, c, ctrl.Result{RequeueAfter: 5 * time.Minute}, nil)
	if err != nil || result.RequeueAfter != 5*time.Minute || recorder.statusPatches() != 0 || recorder.otherWrites() != 0 {
		t.Fatalf("no-op: result=%v err=%v patches=%d", result, err, recorder.statusPatches())
	}
}

// Catches swallowed errors, stale-result transfer and missing conditional patches.
func TestUnitStatusReturnPriority(t *testing.T) {
	operationErr := errors.New("artifact operation")
	readErr := errors.New("status read")
	patchErr := errors.New("status patch")
	for _, tc := range []struct {
		name       string
		state      string
		prior      error
		read       error
		patch      error
		canceled   bool
		delay      time.Duration
		wantErrors []error
		patches    int
	}{
		{name: "persist", delay: 30 * time.Second, patches: 1},
		{name: "prior error persists", prior: operationErr, wantErrors: []error{operationErr}, patches: 1},
		{name: "absent", state: "absent"}, {name: "terminating", state: "terminating"},
		{name: "replacement", state: "uid", delay: time.Second}, {name: "new generation", state: "generation", delay: time.Second},
		{name: "prior and absent", state: "absent", prior: operationErr, wantErrors: []error{operationErr}},
		{name: "prior and replacement", state: "uid", prior: operationErr, wantErrors: []error{operationErr}},
		{name: "prior and terminating", state: "terminating", prior: operationErr, wantErrors: []error{operationErr}},
		{name: "prior and generation", state: "generation", prior: operationErr, wantErrors: []error{operationErr}},
		{name: "read failure", read: readErr, wantErrors: []error{readErr}},
		{name: "combined read", read: readErr, prior: operationErr, wantErrors: []error{readErr, operationErr}},
		{name: "patch failure", patch: patchErr, wantErrors: []error{patchErr}, patches: 1},
		{name: "combined patch", patch: patchErr, prior: operationErr, wantErrors: []error{patchErr, operationErr}, patches: 1},
		{name: "canceled", canceled: true, wantErrors: []error{context.Canceled}},
		{name: "canceled and prior", canceled: true, prior: operationErr, wantErrors: []error{context.Canceled, operationErr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := statusParent()
			fresh := origin.DeepCopy()
			switch tc.state {
			case "uid":
				fresh.UID = "replacement"
			case "generation":
				fresh.Generation++
			case "terminating":
				fresh.DeletionTimestamp = &statusTime
				fresh.Finalizers = []string{"test.example/hold"}
			}
			objects := []client.Object{fresh}
			if tc.state == "absent" {
				objects = nil
			}
			recorder, base := statusFixture(t, objects...)
			recorder.patchErr = tc.patch
			r := newTestReconciler(recorder, statusReader{Reader: base, err: tc.read}, "lab")
			requestCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			got, err := r.finishReconcile(requestCtx, origin, artifactCondition(metav1.ConditionUnknown, "ObservationFailed"), ctrl.Result{RequeueAfter: 30 * time.Second}, tc.prior)
			if len(tc.wantErrors) == 0 && err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.wantErrors {
				if !errors.Is(err, want) {
					t.Fatalf("lost %v in %v", want, err)
				}
			}
			if got.RequeueAfter != tc.delay || recorder.statusPatches() != tc.patches || recorder.otherWrites() != 0 {
				t.Fatalf("result=%v patches=%d want delay=%v patches=%d", got, recorder.statusPatches(), tc.delay, tc.patches)
			}
			if tc.patches == 1 && tc.patch == nil {
				persisted := &infrastructurev1alpha1.KeaCluster{}
				if err := base.Get(context.Background(), client.ObjectKeyFromObject(origin), persisted); err != nil {
					t.Fatal(err)
				}
				if persisted.Status.ObservedGeneration != 7 {
					t.Fatal("status not persisted")
				}
			}
		})
	}
}

func TestUnitStatusFreshSnapshot(t *testing.T) {
	origin := statusParent()
	fresh := origin.DeepCopy()
	external := metav1.Condition{Type: "ExternalCheck", Status: metav1.ConditionTrue, Reason: "External", Message: "fresh", LastTransitionTime: statusTime}
	fresh.Status.Conditions = []metav1.Condition{external}
	fresh.ResourceVersion = "2"
	recorder, base := statusFixture(t, fresh)
	recorder.beforePatch = func(ctx context.Context, obj client.Object, patch client.Patch) error {
		raw, err := patch.Data(obj)
		if err != nil {
			return err
		}
		var data struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		if err = json.Unmarshal(raw, &data); err != nil {
			return err
		}
		if data.Metadata.ResourceVersion != "2" {
			t.Fatalf("missing fresh RV precondition: %s", raw)
		}
		return nil
	}
	r := newTestReconciler(recorder, base, "lab")
	if _, err := r.finishReconcile(context.Background(), origin, artifactCondition(metav1.ConditionFalse, "OwnershipConflict"), ctrl.Result{}, nil); err != nil {
		t.Fatal(err)
	}
	got := &infrastructurev1alpha1.KeaCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(origin), got); err != nil {
		t.Fatal(err)
	}
	if recorder.statusPatches() != 1 || len(got.Status.Conditions) != 2 || !equality.Semantic.DeepEqual(got.Status.Conditions[0], external) {
		t.Fatalf("fresh unrelated status lost: %+v", got.Status)
	}
}

func TestUnitStatusCancellationAfterRead(t *testing.T) {
	p := statusParent()
	recorder, base := statusFixture(t, p)
	requestCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newTestReconciler(recorder, statusReader{Reader: base, beforeGet: func(context.Context) { cancel() }}, "lab")
	_, err := r.finishReconcile(requestCtx, p, artifactCondition(metav1.ConditionUnknown, "MutationOutcomeUnknown"), ctrl.Result{}, nil)
	if !errors.Is(err, context.Canceled) || recorder.statusPatches() != 0 || recorder.otherWrites() != 0 {
		t.Fatalf("cancellation lost or mutation submitted: %v patches=%d", err, recorder.statusPatches())
	}
}

func TestUnitStatusUnchangedPriorError(t *testing.T) {
	p := statusParent()
	c := artifactCondition(metav1.ConditionTrue, "ArtifactInSync")
	p.Status = infrastructurev1alpha1.KeaClusterStatus{ObservedGeneration: 7, Conditions: []metav1.Condition{c}}
	recorder, base := statusFixture(t, p)
	r := newTestReconciler(recorder, base, "lab")
	prior := errors.New("lost acknowledgement")
	got, err := r.finishReconcile(context.Background(), p, c, ctrl.Result{RequeueAfter: 5 * time.Minute}, prior)
	if !errors.Is(err, prior) || got != (ctrl.Result{}) || recorder.statusPatches() != 0 || recorder.otherWrites() != 0 {
		t.Fatalf("unchanged observation consumed error: %v %v", got, err)
	}
}
