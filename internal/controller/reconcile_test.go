package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func coreUnitFixture(t *testing.T) (*infrastructurev1alpha1.KeaCluster, client.Client) {
	t.Helper()
	s := runtime.NewScheme()
	if err := appsv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := infrastructurev1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	p := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "scope", UID: "parent-uid", Generation: 1}}
	return p, fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&infrastructurev1alpha1.KeaCluster{}).WithObjects(p).Build()
}

func TestUnitM2IdentityExtraction(t *testing.T) {
	p, base := coreUnitFixture(t)
	writer := &statusRecordingClient{Client: base}
	reader := &coreRecordingReader{Reader: base}
	r := newTestReconciler(writer, reader, p.Namespace)
	missing := &corev1.ConfigMap{}
	err := r.APIReader.Get(context.Background(), client.ObjectKeyFromObject(p), missing)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("fixture identity should be absent: %v", err)
	}
	condition, action := r.reconcileArtifact(context.Background(), p, nil, err, true)
	if action.Err != nil || !action.Mutated || action.Result.RequeueAfter != time.Second || condition.Type != "ArtifactReconciled" {
		t.Fatalf("identity action: condition=%+v action=%+v", condition, action)
	}
	if writer.statusPatches() != 0 {
		t.Fatalf("identity helper wrote status itself: %d patches", writer.statusPatches())
	}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(p), &corev1.ConfigMap{}); err != nil {
		t.Fatalf("identity mutation was not submitted: %v", err)
	}
}

// Catches an empty reconciler, duplicate creates, status churn, and redundant
// pre-mutation validation reads on the matching path.
func TestUnitCreateAndNoop(t *testing.T) {
	p, base := coreUnitFixture(t)
	c := &coreRecordingClient{statusRecordingClient: &statusRecordingClient{Client: base}}
	reader := &coreRecordingReader{Reader: base}
	r := newTestReconciler(c, reader, p.Namespace)
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)}
	result, err := r.Reconcile(context.Background(), req)
	if err != nil || result.RequeueAfter != time.Second {
		t.Fatalf("create result=%v err=%v", result, err)
	}
	if c.creates != 1 || c.otherWrites() != 1 || c.statusPatches() != 1 {
		t.Fatalf("create=%d resource writes=%d status patches=%d", c.creates, c.otherWrites(), c.statusPatches())
	}
	if reader.parents != 2 || reader.children != 4 || reader.lists != 1 {
		t.Fatalf("create reads: parent=%d child=%d lists=%d", reader.parents, reader.children, reader.lists)
	}
	cm := &corev1.ConfigMap{}
	if err := base.Get(context.Background(), req.NamespacedName, cm); err != nil {
		t.Fatal(err)
	}
	assertCoreArtifact(t, p, cm)
	stored := &infrastructurev1alpha1.KeaCluster{}
	if err := base.Get(context.Background(), req.NamespacedName, stored); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(stored.Status.Conditions, "ArtifactReconciled")
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "ArtifactInSync" || condition.ObservedGeneration != 1 || stored.Status.ObservedGeneration != 1 {
		t.Fatalf("status=%+v", stored.Status)
	}
	status := stored.Status.DeepCopy()
	for range 3 {
		beforeParent := reader.parents
		beforeWrites, beforeStatus := c.otherWrites(), c.statusPatches()
		result, err = r.Reconcile(context.Background(), req)
		if err != nil || result.RequeueAfter != 5*time.Minute {
			t.Fatalf("noop result=%v err=%v", result, err)
		}
		if reader.parents != beforeParent || c.otherWrites() != beforeWrites || c.statusPatches() != beforeStatus {
			t.Fatal("matching state submitted writes or unnecessary direct parent read")
		}
	}
	if err := base.Get(context.Background(), req.NamespacedName, stored); err != nil {
		t.Fatal(err)
	}
	if !equality.Semantic.DeepEqual(*status, stored.Status) {
		t.Fatal("no-op changed status/transition time")
	}
}

func assertCoreArtifact(t *testing.T, p *infrastructurev1alpha1.KeaCluster, cm *corev1.ConfigMap) {
	t.Helper()
	want := map[string]string{"keacluster-name": p.Name, "keacluster-namespace": p.Namespace, "keacluster-uid": string(p.UID)}
	if cm.Name != p.Name || cm.Namespace != p.Namespace || !equality.Semantic.DeepEqual(cm.Data, want) || len(cm.BinaryData) != 0 || (cm.Immutable != nil && *cm.Immutable) {
		t.Fatalf("artifact=%+v", cm)
	}
	if cm.Labels["keaguard.example/artifact"] != "reconciliation" || cm.Annotations["keaguard.example/purpose"] != "Internal reconciliation artifact; not operational Kea DHCP configuration." {
		t.Fatal("wrong reserved metadata")
	}
	if len(cm.OwnerReferences) != 1 {
		t.Fatal("wrong owner count")
	}
	o := cm.OwnerReferences[0]
	if o.APIVersion != "infrastructure.keaguard.example/v1alpha1" || o.Kind != "KeaCluster" || o.Name != p.Name || o.UID != p.UID || o.Controller == nil || !*o.Controller || o.BlockOwnerDeletion == nil || *o.BlockOwnerDeletion {
		t.Fatalf("owner=%+v", o)
	}
}

// A forced outside request must stop before any client/reader/status operation.
func TestUnitNamespaceGuard(t *testing.T) {
	p, base := coreUnitFixture(t)
	c := &coreRecordingClient{statusRecordingClient: &statusRecordingClient{Client: base}}
	reader := &coreRecordingReader{Reader: base}
	r := newTestReconciler(c, reader, p.Namespace)
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "outside", Name: p.Name}})
	if err != nil || result != (ctrl.Result{}) || c.calls != 0 || reader.parents+reader.children != 0 || c.otherWrites() != 0 || c.statusPatches() != 0 {
		t.Fatalf("outside result=%v err=%v client=%d reader=%+v", result, err, c.calls, reader)
	}
}

// Catches creates made after either cached or fresh parent invalidation.
func TestUnitParentLifecycle(t *testing.T) {
	for _, scenario := range []string{"cached missing", "cached terminating", "fresh missing", "fresh terminating", "fresh uid", "fresh generation"} {
		t.Run(scenario, func(t *testing.T) {
			p, base := coreUnitFixture(t)
			c := &coreRecordingClient{statusRecordingClient: &statusRecordingClient{Client: base}}
			reader := &coreRecordingReader{Reader: base}
			if scenario == "cached missing" {
				if err := base.Delete(context.Background(), p); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "cached terminating" {
				p.Finalizers = []string{"test.example/hold"}
				if err := base.Update(context.Background(), p); err != nil {
					t.Fatal(err)
				}
				if err := base.Delete(context.Background(), p); err != nil {
					t.Fatal(err)
				}
			}
			reader.parentGet = func(obj *infrastructurev1alpha1.KeaCluster) error {
				*obj = *p.DeepCopy()
				switch scenario {
				case "fresh missing":
					return apierrors.NewNotFound(schema.GroupResource{Group: "infrastructure.keaguard.example", Resource: "keaclusters"}, p.Name)
				case "fresh terminating":
					now := metav1.Now()
					obj.DeletionTimestamp = &now
				case "fresh uid":
					obj.UID = "replacement"
				case "fresh generation":
					obj.Generation++
				}
				return nil
			}
			r := newTestReconciler(c, reader, p.Namespace)
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)})
			want := time.Duration(0)
			if scenario == "fresh uid" || scenario == "fresh generation" {
				want = time.Second
			}
			if err != nil || result.RequeueAfter != want {
				t.Fatalf("result=%v err=%v want=%v", result, err, want)
			}
			if c.otherWrites() != 0 || c.statusPatches() != 0 {
				t.Fatal("invalid parent allowed mutation/status")
			}
			if (scenario == "cached missing" || scenario == "cached terminating") && reader.parents+reader.children != 0 {
				t.Fatal("read child/fresh parent after inactive cached parent")
			}
		})
	}
}

// A repair must replace the complete payload while preserving fields outside
// the operator's authority. Each case catches a skipped comparison/repair branch.
func TestUnitDriftRepair(t *testing.T) {
	t.Run("returned object", testRepairResponse)
	t.Run("fresh parent", testRepairParentValidation)
	changes := map[string]func(*corev1.ConfigMap){
		"missing data":        func(cm *corev1.ConfigMap) { cm.Data = nil },
		"empty data":          func(cm *corev1.ConfigMap) { cm.Data = map[string]string{} },
		"extra data":          func(cm *corev1.ConfigMap) { cm.Data["extra"] = "remove" },
		"binary entries":      func(cm *corev1.ConfigMap) { cm.BinaryData = map[string][]byte{"extra": {1}, "another": {2}} },
		"missing labels":      func(cm *corev1.ConfigMap) { cm.Labels = nil },
		"changed label":       func(cm *corev1.ConfigMap) { cm.Labels[artifactLabel] = "wrong" },
		"missing annotations": func(cm *corev1.ConfigMap) { cm.Annotations = nil },
		"changed annotation":  func(cm *corev1.ConfigMap) { cm.Annotations[artifactPurpose] = "wrong" },
	}
	for _, key := range []string{"keacluster-name", "keacluster-namespace", "keacluster-uid"} {
		changes["missing "+key] = func(cm *corev1.ConfigMap) { delete(cm.Data, key) }
		changes["changed "+key] = func(cm *corev1.ConfigMap) { cm.Data[key] = "wrong" }
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p, base := coreUnitFixture(t)
			cm := desiredArtifact(p)
			cm.UID = "child-uid"
			cm.Labels["other.example/label"] = "keep"
			cm.Annotations["other.example/annotation"] = "keep"
			cm.OwnerReferences[0].BlockOwnerDeletion = boolPointer(true)
			cm.OwnerReferences = append(cm.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "additional", UID: "other-owner"})
			change(cm)
			before := cm.DeepCopy()
			if err := base.Create(context.Background(), cm); err != nil {
				t.Fatal(err)
			}
			c := &repairRecordingClient{statusRecordingClient: &statusRecordingClient{Client: base}}
			reader := &coreRecordingReader{Reader: base}
			r := newTestReconciler(c, reader, p.Namespace)
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)}
			result, err := r.Reconcile(context.Background(), req)
			if err != nil || result.RequeueAfter != time.Second {
				t.Fatalf("repair result=%v err=%v", result, err)
			}
			if c.otherWrites() != 1 || c.artifactPatches != 1 || c.statusPatches() != 1 {
				t.Fatalf("writes=%d patch=%d status=%d", c.otherWrites(), c.artifactPatches, c.statusPatches())
			}
			if reader.parents != 2 {
				t.Fatalf("missing fresh mutation/status parent checks: %d", reader.parents)
			}
			if c.patchRV != cm.ResourceVersion || c.patchRV == "" {
				t.Fatalf("patch precondition=%q want=%q", c.patchRV, cm.ResourceVersion)
			}
			stored := &corev1.ConfigMap{}
			if err := base.Get(context.Background(), req.NamespacedName, stored); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"keacluster-name": p.Name, "keacluster-namespace": p.Namespace, "keacluster-uid": string(p.UID)}
			if !equality.Semantic.DeepEqual(stored.Data, want) || len(stored.BinaryData) != 0 {
				t.Fatalf("payload=%v binary=%v", stored.Data, stored.BinaryData)
			}
			if stored.Labels[artifactLabel] != "reconciliation" || stored.Annotations[artifactPurpose] != "Internal reconciliation artifact; not operational Kea DHCP configuration." {
				t.Fatal("reserved metadata not repaired")
			}
			if stored.Labels["other.example/label"] != before.Labels["other.example/label"] || stored.Annotations["other.example/annotation"] != before.Annotations["other.example/annotation"] || stored.UID != before.UID || !equality.Semantic.DeepEqual(stored.OwnerReferences, before.OwnerReferences) {
				t.Fatal("repair changed unrelated metadata/UID/owners")
			}
			assertArtifactCondition(t, base, p, "ArtifactInSync", metav1.ConditionTrue)
			for range 3 {
				result, err = r.Reconcile(context.Background(), req)
				if err != nil || result.RequeueAfter != 5*time.Minute || c.otherWrites() != 1 || c.statusPatches() != 1 {
					t.Fatalf("no-op churn: result=%v err=%v", result, err)
				}
			}
		})
	}
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("matching binary empty=%v", empty), func(t *testing.T) {
			p, base := coreUnitFixture(t)
			cm := desiredArtifact(p)
			if empty {
				cm.BinaryData = map[string][]byte{}
				cm.Immutable = boolPointer(false)
			}
			if err := base.Create(context.Background(), cm); err != nil {
				t.Fatal(err)
			}
			c := &statusRecordingClient{Client: base}
			r := newTestReconciler(c, base, p.Namespace)
			for range 3 {
				if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)}); err != nil {
					t.Fatal(err)
				}
			}
			if c.otherWrites() != 0 || c.statusPatches() != 1 {
				t.Fatal("nil/empty equivalence caused writes")
			}
		})
	}
}

// Malformed references here are unit-only fixtures; no API admission is claimed.
func TestUnitBlockedArtifact(t *testing.T) {
	cases := []struct {
		name, reason string
		change       func(*corev1.ConfigMap)
	}{
		{"unowned", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences = nil }},
		{"foreign", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].Name = "foreign" }},
		{"stale uid", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].UID = "old-uid" }},
		{"wrong group", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].APIVersion = "other.example/v1alpha1" }},
		{"unsupported version", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].APIVersion = "infrastructure.keaguard.example/v2" }},
		{"wrong kind", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].Kind = "Other" }},
		{"malformed version unit only", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].APIVersion = "bad/version/extra" }},
		{"duplicate controllers unit only", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences = append(cm.OwnerReferences, cm.OwnerReferences[0]) }},
		{"noncontroller", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].Controller = boolPointer(false) }},
		{"immutable matching", "ImmutableArtifact", func(cm *corev1.ConfigMap) { cm.Immutable = boolPointer(true) }},
		{"immutable drift", "ImmutableArtifact", func(cm *corev1.ConfigMap) { cm.Immutable = boolPointer(true); cm.Data = nil; cm.Labels = nil }},
		{"terminating", "ArtifactDeleting", func(cm *corev1.ConfigMap) {
			now := metav1.Now()
			cm.DeletionTimestamp = &now
			cm.Finalizers = []string{"test.example/hold"}
			cm.Data = nil
		}},
		{"foreign immutable", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences = nil; cm.Immutable = boolPointer(true) }},
		{"foreign terminating", "OwnershipConflict", func(cm *corev1.ConfigMap) {
			cm.OwnerReferences = nil
			now := metav1.Now()
			cm.DeletionTimestamp = &now
			cm.Finalizers = []string{"test.example/hold"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, initial := coreUnitFixture(t)
			cm := desiredArtifact(p)
			tc.change(cm)
			base := fake.NewClientBuilder().WithScheme(initial.Scheme()).WithStatusSubresource(&infrastructurev1alpha1.KeaCluster{}).WithObjects(p, cm).Build()
			before := &corev1.ConfigMap{}
			key := client.ObjectKeyFromObject(p)
			if err := base.Get(context.Background(), key, before); err != nil {
				t.Fatal(err)
			}
			c := &statusRecordingClient{Client: base}
			r := newTestReconciler(c, base, p.Namespace)
			var first infrastructurev1alpha1.KeaClusterStatus
			for i := range 4 {
				result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
				if err != nil || result.RequeueAfter != 30*time.Second {
					t.Fatalf("blocker result=%v err=%v", result, err)
				}
				assertArtifactCondition(t, base, p, tc.reason, metav1.ConditionFalse)
				stored := &infrastructurev1alpha1.KeaCluster{}
				if err := base.Get(context.Background(), key, stored); err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					first = *stored.Status.DeepCopy()
				} else if !equality.Semantic.DeepEqual(first, stored.Status) {
					t.Fatal("stable blocker status changed")
				}
			}
			if c.otherWrites() != 0 || c.statusPatches() != 1 {
				t.Fatalf("blocked writes=%d status=%d", c.otherWrites(), c.statusPatches())
			}
			after := &corev1.ConfigMap{}
			if err := base.Get(context.Background(), key, after); err != nil {
				t.Fatal(err)
			}
			if !equality.Semantic.DeepEqual(before, after) {
				t.Fatal("blocked artifact changed")
			}
		})
	}
}

func boolPointer(v bool) *bool { return &v }

func assertArtifactCondition(t *testing.T, base client.Client, p *infrastructurev1alpha1.KeaCluster, reason string, status metav1.ConditionStatus) {
	t.Helper()
	stored := &infrastructurev1alpha1.KeaCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(p), stored); err != nil {
		t.Fatal(err)
	}
	c := meta.FindStatusCondition(stored.Status.Conditions, "ArtifactReconciled")
	if c == nil || c.Reason != reason || c.Status != status || c.ObservedGeneration != p.Generation || stored.Status.ObservedGeneration != p.Generation || !strings.Contains(c.Message, p.Namespace+"/"+p.Name) {
		t.Fatalf("condition=%+v status=%+v", c, stored.Status)
	}
	if status == metav1.ConditionFalse && reason != "ArtifactOutOfSync" && !strings.Contains(c.Message, "manual") {
		t.Fatalf("missing remediation: %s", c.Message)
	}
}

// Forwards the real patch to the fake/API client and captures its optimistic
// precondition. Optional response modelling occurs only after a committed write.
type repairRecordingClient struct {
	*statusRecordingClient
	artifactPatches int
	patchRV         string
	response        func(*corev1.ConfigMap)
}

func (c *repairRecordingClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	c.artifactPatches++
	data, err := patch.Data(obj)
	if err != nil {
		return err
	}
	var body struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return err
	}
	c.patchRV = body.Metadata.ResourceVersion
	if err := c.statusRecordingClient.Patch(ctx, obj, patch, opts...); err != nil {
		return err
	}
	if c.response != nil {
		c.response(obj.(*corev1.ConfigMap))
	}
	return nil
}

func testRepairResponse(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(*corev1.ConfigMap)
	}{
		{"payload", "ArtifactOutOfSync", func(cm *corev1.ConfigMap) { cm.Data = nil }},
		{"ownership", "OwnershipConflict", func(cm *corev1.ConfigMap) { cm.OwnerReferences = nil }},
		{"immutable", "ImmutableArtifact", func(cm *corev1.ConfigMap) { cm.Immutable = boolPointer(true) }},
		{"deleting", "ArtifactDeleting", func(cm *corev1.ConfigMap) { now := metav1.Now(); cm.DeletionTimestamp = &now }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, base := coreUnitFixture(t)
			cm := desiredArtifact(p)
			cm.Data = nil
			if err := base.Create(context.Background(), cm); err != nil {
				t.Fatal(err)
			}
			c := &repairRecordingClient{statusRecordingClient: &statusRecordingClient{Client: base}, response: tc.change}
			r := newTestReconciler(c, base, p.Namespace)
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)})
			if err != nil || result.RequeueAfter != time.Second {
				t.Fatalf("response result=%v err=%v", result, err)
			}
			if c.otherWrites() != 1 || c.artifactPatches != 1 {
				t.Fatal("response caused additional artifact mutation")
			}
			assertArtifactCondition(t, base, p, tc.reason, metav1.ConditionFalse)
		})
	}
}

// A newly observed parent identity/lifecycle must invalidate a drift patch too.
func testRepairParentValidation(t *testing.T) {
	for _, scenario := range []string{"missing", "terminating", "uid", "generation"} {
		t.Run(scenario, func(t *testing.T) {
			p, base := coreUnitFixture(t)
			cm := desiredArtifact(p)
			cm.Data = nil
			if err := base.Create(context.Background(), cm); err != nil {
				t.Fatal(err)
			}
			c := &statusRecordingClient{Client: base}
			reader := &coreRecordingReader{Reader: base, parentGet: func(fresh *infrastructurev1alpha1.KeaCluster) error {
				*fresh = *p.DeepCopy()
				switch scenario {
				case "missing":
					return apierrors.NewNotFound(schema.GroupResource{Resource: "keaclusters"}, p.Name)
				case "terminating":
					now := metav1.Now()
					fresh.DeletionTimestamp = &now
				case "uid":
					fresh.UID = "replacement"
				case "generation":
					fresh.Generation++
				}
				return nil
			}}
			r := newTestReconciler(c, reader, p.Namespace)
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)})
			want := time.Duration(0)
			if scenario == "uid" || scenario == "generation" {
				want = time.Second
			}
			if err != nil || result.RequeueAfter != want || c.otherWrites() != 0 || c.statusPatches() != 0 {
				t.Fatalf("invalidated patch: result=%v err=%v writes=%d status=%d", result, err, c.otherWrites(), c.statusPatches())
			}
		})
	}
}
