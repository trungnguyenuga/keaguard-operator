package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// Faults are test-only and forward successful writes before modelling lost replies.
// Recorder counts submissions separately from administrative fixture operations.
type recoveryClient struct {
	*statusRecordingClient
	read                      func(context.Context, client.Object) error
	writeErr                  error
	forward                   bool
	after                     func(context.Context, *corev1.ConfigMap)
	afterObject               func(context.Context, client.Object)
	creates, patches, deletes int
}

func (c *recoveryClient) Get(ctx context.Context, k client.ObjectKey, o client.Object, opts ...client.GetOption) error {
	if c.read != nil {
		if err := c.read(ctx, o); err != nil {
			return err
		}
	}
	return c.Client.Get(ctx, k, o, opts...)
}
func (c *recoveryClient) Create(ctx context.Context, o client.Object, opts ...client.CreateOption) error {
	c.creates++
	c.recordResourceWrite()
	if c.writeErr != nil && !c.forward {
		c.recordOperation("create", o, c.writeErr)
		return c.writeErr
	}
	if err := c.Client.Create(ctx, o, opts...); err != nil {
		c.recordOperation("create", o, err)
		return err
	}
	c.afterMutation(ctx, o)
	c.recordOperation("create", o, c.writeErr)
	return c.writeErr
}
func (c *recoveryClient) Patch(ctx context.Context, o client.Object, p client.Patch, opts ...client.PatchOption) error {
	c.patches++
	c.recordResourceWrite()
	if c.writeErr != nil && !c.forward {
		c.recordOperation("patch", o, c.writeErr)
		return c.writeErr
	}
	if err := c.Client.Patch(ctx, o, p, opts...); err != nil {
		c.recordOperation("patch", o, err)
		return err
	}
	c.afterMutation(ctx, o)
	c.recordOperation("patch", o, c.writeErr)
	return c.writeErr
}

func (c *recoveryClient) Delete(ctx context.Context, o client.Object, opts ...client.DeleteOption) error {
	c.deletes++
	c.recordResourceWrite()
	if c.writeErr != nil && !c.forward {
		c.recordOperation("delete", o, c.writeErr)
		return c.writeErr
	}
	if err := c.Client.Delete(ctx, o, opts...); err != nil {
		c.recordOperation("delete", o, err)
		return err
	}
	c.afterMutation(ctx, o)
	c.recordOperation("delete", o, c.writeErr)
	return c.writeErr
}

func (c *recoveryClient) afterMutation(ctx context.Context, object client.Object) {
	if c.afterObject != nil {
		c.afterObject(ctx, object)
	}
	if c.after != nil {
		if configMap, ok := object.(*corev1.ConfigMap); ok {
			c.after(ctx, configMap)
		}
	}
}

type recoveryReader struct {
	client.Reader
	readAt   func(context.Context, client.ObjectKey, client.Object) error
	readList func(context.Context, client.ObjectList) error
}

func (r *recoveryReader) Get(ctx context.Context, k client.ObjectKey, o client.Object, opts ...client.GetOption) error {
	if r.readAt != nil {
		if err := r.readAt(ctx, k, o); err != nil {
			return err
		}
	}
	return r.Reader.Get(ctx, k, o, opts...)
}

func (r *recoveryReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if r.readList != nil {
		if err := r.readList(ctx, list); err != nil {
			return err
		}
	}
	return r.Reader.List(ctx, list, opts...)
}

// Catches missing failure observations, swallowed retry errors, false definitive
// failure on transport errors, and second writes inside one reconciliation.
func TestUnitFailureOutcomes(t *testing.T) {
	for _, stage := range []string{"cached-parent", "child", "fresh-parent", "create", "patch", "status-read", "status-patch", "combined", "conflict", "already-exists", "not-found", "invalid", "rejected-unobserved", "timeout", "unknown", "committed"} {
		t.Run(stage, func(t *testing.T) {
			p, base := coreUnitFixture(t)
			key := client.ObjectKeyFromObject(p)
			if stage == "patch" || stage == "conflict" || stage == "not-found" || stage == "status-read" || stage == "status-patch" {
				cm := desiredArtifact(p)
				if stage == "patch" || stage == "conflict" || stage == "not-found" {
					cm.Data = map[string]string{"drift": "yes"}
				}
				if err := base.Create(context.Background(), cm); err != nil {
					t.Fatal(err)
				}
			}
			operation := errors.New("temporary observation outage")
			reporting := errors.New("status unavailable")
			forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, p.Name, errors.New("denied"))
			c := &recoveryClient{statusRecordingClient: &statusRecordingClient{Client: base}}
			reader := &recoveryReader{Reader: base}
			parents, children := 0, 0
			reader.readAt = func(_ context.Context, readKey client.ObjectKey, o client.Object) error {
				if _, ok := o.(*corev1.ConfigMap); ok && readKey == key {
					children++
					if stage == "child" || ((stage == "unknown" || stage == "rejected-unobserved") && children > 1) {
						return operation
					}
				} else if _, ok := o.(*infrastructurev1alpha1.KeaCluster); ok && readKey == key {
					parents++
					if (stage == "fresh-parent" && parents == 1) || stage == "status-read" {
						return operation
					}
				}
				return nil
			}
			reason := "ObservationFailed"
			state := metav1.ConditionUnknown
			switch stage {
			case "cached-parent":
				c.read = func(context.Context, client.Object) error { return operation }
				reason = ""
			case "create", "patch", "combined":
				c.writeErr = forbidden
				operation = forbidden
				reason = "ArtifactWriteFailed"
				state = metav1.ConditionFalse
			case "conflict", "already-exists", "not-found":
				resource := schema.GroupResource{Resource: "configmaps"}
				switch stage {
				case "conflict":
					c.writeErr = apierrors.NewConflict(resource, p.Name, errors.New("concurrent change"))
				case "already-exists":
					c.writeErr = apierrors.NewAlreadyExists(resource, p.Name)
				case "not-found":
					c.writeErr = apierrors.NewNotFound(resource, p.Name)
				}
				operation = c.writeErr
				reason = "ArtifactWriteFailed"
				state = metav1.ConditionFalse
			case "invalid":
				c.writeErr = apierrors.NewInvalid(schema.GroupKind{Kind: "ConfigMap"}, p.Name, field.ErrorList{field.Invalid(field.NewPath("data"), "value", "injected rejection")})
				operation = c.writeErr
				reason = "ArtifactWriteFailed"
				state = metav1.ConditionFalse
			case "rejected-unobserved":
				c.writeErr = forbidden
				operation = forbidden
				reason = "MutationOutcomeUnknown"
			case "timeout", "unknown":
				c.writeErr = operation
				reason = "MutationOutcomeUnknown"
			case "committed":
				c.writeErr = operation
				c.forward = true
				reason = "ArtifactInSync"
				state = metav1.ConditionTrue
			case "status-read":
				reason = ""
			case "status-patch":
				c.patchErr = operation
				reason = ""
			}
			if stage == "combined" {
				c.patchErr = reporting
				reason = ""
			}
			result, err := newTestReconciler(c, reader, p.Namespace).Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
			if !errors.Is(err, operation) || result != (ctrl.Result{}) {
				t.Fatalf("result=%+v err=%v; lost original error", result, err)
			}
			if stage == "combined" && !errors.Is(err, reporting) {
				t.Fatalf("lost reporting error: %v", err)
			}
			if c.otherWrites() > 1 {
				t.Fatalf("mutations=%d", c.otherWrites())
			}
			if reason != "" {
				assertArtifactCondition(t, base, p, reason, state)
			}
			if stage == "cached-parent" && c.statusPatches() != 0 {
				t.Fatal("reported unknown parent")
			}
			next := &statusRecordingClient{Client: base}
			if _, err := newTestReconciler(next, base, p.Namespace).Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			assertArtifactCondition(t, base, p, "ArtifactInSync", metav1.ConditionTrue)
			if stage == "committed" && next.otherWrites() != 0 {
				t.Fatal("rewrote committed artifact")
			}
		})
	}
}

// Catches successful returned objects being treated as proof of desired state.
func TestUnitMutationResponse(t *testing.T) {
	for _, patch := range []bool{false, true} {
		for _, kind := range []string{"payload", "owner", "immutable", "deleting"} {
			t.Run(fmt.Sprint(patch, kind), func(t *testing.T) {
				p, base := coreUnitFixture(t)
				if patch {
					cm := desiredArtifact(p)
					cm.Data = nil
					if err := base.Create(context.Background(), cm); err != nil {
						t.Fatal(err)
					}
				}
				reason := map[string]string{"payload": "ArtifactOutOfSync", "owner": "OwnershipConflict", "immutable": "ImmutableArtifact", "deleting": "ArtifactDeleting"}[kind]
				c := &recoveryClient{statusRecordingClient: &statusRecordingClient{Client: base}, after: func(_ context.Context, cm *corev1.ConfigMap) {
					switch kind {
					case "payload":
						cm.Data = nil
					case "owner":
						cm.OwnerReferences = nil
					case "immutable":
						cm.Immutable = boolPointer(true)
					case "deleting":
						now := metav1.Now()
						cm.DeletionTimestamp = &now
					}
				}}
				result, err := newTestReconciler(c, base, p.Namespace).Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)})
				if err != nil || result.RequeueAfter != time.Second || c.otherWrites() != 1 {
					t.Fatalf("result=%+v err=%v writes=%d", result, err, c.otherWrites())
				}
				assertArtifactCondition(t, base, p, reason, metav1.ConditionFalse)
			})
		}
	}
}

// Catches deadline bypass, detached status writes, and assuming cancellation
// rolled back an already committed operation.
func TestUnitCancellation(t *testing.T) {
	for _, phase := range []string{"before-mutation", "after-create", "after-patch"} {
		t.Run(phase, func(t *testing.T) {
			p, base := coreUnitFixture(t)
			key := client.ObjectKeyFromObject(p)
			if phase == "after-patch" {
				cm := desiredArtifact(p)
				cm.Data = nil
				if err := base.Create(context.Background(), cm); err != nil {
					t.Fatal(err)
				}
			}
			var logs bytes.Buffer
			operationCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			operationCtx = logf.IntoContext(operationCtx, zap.New(zap.WriteTo(&logs), zap.UseDevMode(true)))
			check := func(got context.Context) {
				if got != operationCtx {
					t.Fatal("API received replacement context")
				}
				if _, ok := got.Deadline(); !ok {
					t.Fatal("lost deadline")
				}
			}
			c := &recoveryClient{statusRecordingClient: &statusRecordingClient{Client: base}, writeErr: context.Canceled, forward: true}
			c.read = func(ctx context.Context, _ client.Object) error { check(ctx); return nil }
			c.beforePatch = func(ctx context.Context, _ client.Object, _ client.Patch) error { check(ctx); return nil }
			c.after = func(ctx context.Context, _ *corev1.ConfigMap) {
				check(ctx)
				gate := newAPIGate()
				cancel()
				if !errors.Is(gate.wait(ctx), context.Canceled) {
					t.Fatal("held operation ignored cancellation")
				}
			}
			reader := &recoveryReader{Reader: base, readAt: func(ctx context.Context, readKey client.ObjectKey, o client.Object) error {
				check(ctx)
				if phase == "before-mutation" && readKey == key {
					if _, ok := o.(*infrastructurev1alpha1.KeaCluster); ok {
						cancel()
					}
				}
				return nil
			}}
			result, err := newTestReconciler(c, reader, p.Namespace).Reconcile(operationCtx, ctrl.Request{NamespacedName: key})
			if !errors.Is(err, context.Canceled) || result != (ctrl.Result{}) || c.statusPatches() != 0 {
				t.Fatalf("result=%+v err=%v status=%d", result, err, c.statusPatches())
			}
			expected := 1
			if phase == "before-mutation" {
				expected = 0
			} else if !strings.Contains(logs.String(), "could not be persisted") {
				t.Fatalf("missing reporting log: %s", logs.String())
			}
			if c.otherWrites() != expected {
				t.Fatalf("writes=%d expected=%d", c.otherWrites(), expected)
			}
			next := &statusRecordingClient{Client: base}
			if _, err := newTestReconciler(next, base, p.Namespace).Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			if phase != "before-mutation" && next.otherWrites() != 0 {
				t.Fatal("rewrote committed canceled operation")
			}
		})
	}
}

var _ = Describe("ENV: Partial success", func() {
	for _, patch := range []bool{false, true} {
		It(fmt.Sprintf("recovers committed write patch=%v after status failure", patch), func() {
			p, key := concurrencyParent()
			if patch {
				cm := desiredArtifact(p)
				cm.Data = nil
				Expect(k8sClient.Create(ctx, cm)).To(Succeed())
			}
			failure := errors.New("injected status outage")
			c := &recoveryClient{statusRecordingClient: &statusRecordingClient{Client: k8sClient, patchErr: failure}}
			result, err := newTestReconciler(c, k8sClient, p.Namespace).Reconcile(ctx, ctrl.Request{NamespacedName: key})
			Expect(errors.Is(err, failure)).To(BeTrue())
			Expect(result).To(Equal(ctrl.Result{}))
			Expect(c.otherWrites()).To(Equal(1))
			committed := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, key, committed)).To(Succeed())
			Expect(committed.Data).To(HaveLen(3))
			next := &statusRecordingClient{Client: k8sClient}
			_, err = newTestReconciler(next, k8sClient, p.Namespace).Reconcile(ctx, ctrl.Request{NamespacedName: key})
			Expect(err).NotTo(HaveOccurred())
			Expect(next.otherWrites()).To(BeZero())
			expectArtifactReason(key, "ArtifactInSync")
			got := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
			Expect(got).To(Equal(committed))
		})
	}
})
var _ = Describe("ENV: Lost response", func() {
	for _, patch := range []bool{false, true} {
		for _, unknown := range []bool{false, true} {
			It(fmt.Sprintf("reobserves real committed patch=%v unknown=%v", patch, unknown), func() {
				p, key := concurrencyParent()
				if patch {
					cm := desiredArtifact(p)
					cm.Data = nil
					Expect(k8sClient.Create(ctx, cm)).To(Succeed())
				}
				lost := errors.New("modelled lost acknowledgement")
				observation := errors.New("modelled follow-up failure")
				children := 0
				c := &recoveryClient{statusRecordingClient: &statusRecordingClient{Client: k8sClient}, writeErr: lost, forward: true}
				reader := &recoveryReader{Reader: k8sClient, readAt: func(_ context.Context, readKey client.ObjectKey, o client.Object) error {
					if _, ok := o.(*corev1.ConfigMap); ok && readKey == key {
						children++
						if unknown && children > 1 {
							return observation
						}
					}
					return nil
				}}
				result, err := newTestReconciler(c, reader, p.Namespace).Reconcile(ctx, ctrl.Request{NamespacedName: key})
				Expect(errors.Is(err, lost)).To(BeTrue())
				Expect(result).To(Equal(ctrl.Result{}))
				Expect(c.otherWrites()).To(Equal(1))
				reason := "ArtifactInSync"
				if unknown {
					reason = "MutationOutcomeUnknown"
					Expect(errors.Is(err, observation)).To(BeTrue())
				}
				expectArtifactReason(key, reason)
				committed := &corev1.ConfigMap{}
				Expect(k8sClient.Get(ctx, key, committed)).To(Succeed())
				Expect(committed.Data["keacluster-uid"]).To(Equal(string(p.UID)))
				next := &statusRecordingClient{Client: k8sClient}
				_, err = newTestReconciler(next, k8sClient, p.Namespace).Reconcile(ctx, ctrl.Request{NamespacedName: key})
				Expect(err).NotTo(HaveOccurred())
				Expect(next.otherWrites()).To(BeZero())
				expectArtifactReason(key, "ArtifactInSync")
				got := &corev1.ConfigMap{}
				Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
				Expect(got).To(Equal(committed))
			})
		}
	}
})

var _ = Describe("ENV: Lost response cancellation", func() {
	for _, patch := range []bool{false, true} {
		It(fmt.Sprintf("recovers a committed held write patch=%v after cancellation", patch), func() {
			p, key := concurrencyParent()
			if patch {
				cm := desiredArtifact(p)
				cm.Data = nil
				Expect(k8sClient.Create(ctx, cm)).To(Succeed())
			}
			gate := newAPIGate()
			var cancelOperation context.CancelFunc
			var logs bytes.Buffer
			c := &recoveryClient{statusRecordingClient: &statusRecordingClient{Client: k8sClient}, writeErr: context.Canceled, forward: true,
				after: func(operationCtx context.Context, _ *corev1.ConfigMap) { _ = gate.wait(operationCtx) }}
			result, err := runAPIRace(gate, func(bounded context.Context) (ctrl.Result, error) {
				operationCtx, cancel := context.WithCancel(bounded)
				cancelOperation = cancel
				defer cancel()
				operationCtx = logf.IntoContext(operationCtx, zap.New(zap.WriteTo(&logs), zap.UseDevMode(true)))
				return newTestReconciler(c, k8sClient, p.Namespace).Reconcile(operationCtx, ctrl.Request{NamespacedName: key})
			}, func() { cancelOperation() })
			Expect(errors.Is(err, context.Canceled)).To(BeTrue())
			Expect(result).To(Equal(ctrl.Result{}))
			Expect(c.otherWrites()).To(Equal(1))
			Expect(c.statusPatches()).To(BeZero())
			Expect(logs.String()).To(ContainSubstring("could not be persisted"))
			committed := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, key, committed)).To(Succeed())
			Expect(committed.Data).To(HaveLen(3))
			next := &statusRecordingClient{Client: k8sClient}
			_, err = newTestReconciler(next, k8sClient, p.Namespace).Reconcile(ctx, ctrl.Request{NamespacedName: key})
			Expect(err).NotTo(HaveOccurred())
			Expect(next.otherWrites()).To(BeZero())
			expectArtifactReason(key, "ArtifactInSync")
		})
	}
})
