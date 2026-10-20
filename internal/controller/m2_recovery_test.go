package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestUnitM2RecoveryWrapper(t *testing.T) {
	parent, names, config, recorder, _ := m2ReconcileFixture(t)
	objects := []client.Object{
		desiredKeaConfig(parent, names, config),
		desiredHeadlessService(parent, names),
		desiredKeaStatefulSet(parent, names, config),
	}
	for i, object := range objects {
		object.SetUID(types.UID(fmt.Sprintf("m2-recovery-%d", i)))
	}
	deleteObserver := &deleteRecordingClient{statusRecordingClient: recorder}
	recoveringRecorder := &statusRecordingClient{Client: deleteObserver}
	lost := errors.New("modelled acknowledgement lost")
	var afterKinds, legacyAfterKinds []string
	recovery := &recoveryClient{
		statusRecordingClient: recoveringRecorder, writeErr: lost, forward: true,
		afterObject: func(_ context.Context, object client.Object) { afterKinds = append(afterKinds, operationKind(object)) },
		after: func(_ context.Context, object *corev1.ConfigMap) {
			legacyAfterKinds = append(legacyAfterKinds, operationKind(object))
		},
	}
	for _, object := range objects {
		if err := recovery.Create(context.Background(), object); !errors.Is(err, lost) {
			t.Fatalf("forwarded %s create error=%v", operationKind(object), err)
		}
	}
	if recovery.creates != 3 || recovery.otherWrites() != 3 || len(afterKinds) != 3 || len(legacyAfterKinds) != 1 || legacyAfterKinds[0] != "ConfigMap" {
		t.Fatalf("create counts=%d writes=%d generic callbacks=%v legacy callbacks=%v", recovery.creates, recovery.otherWrites(), afterKinds, legacyAfterKinds)
	}

	for _, object := range objects {
		before := object.DeepCopyObject().(client.Object)
		switch value := object.(type) {
		case *corev1.ConfigMap:
			value.Data["kea-dhcp4.conf"] += " "
		case *corev1.Service:
			value.Spec.Ports = []corev1.ServicePort{{Name: "drift", Port: 99, Protocol: corev1.ProtocolTCP}}
		case *appsv1.StatefulSet:
			value.Spec.Replicas = pointerTo(int32(3))
		}
		patch := client.MergeFrom(before)
		if err := recovery.Patch(context.Background(), object, patch); !errors.Is(err, lost) {
			t.Fatalf("forwarded %s patch error=%v", operationKind(object), err)
		}
	}
	if recovery.patches != 3 || recovery.otherWrites() != 6 || len(afterKinds) != 6 || len(legacyAfterKinds) != 2 {
		t.Fatalf("patch counts=%d writes=%d callbacks=%v legacy=%v", recovery.patches, recovery.otherWrites(), afterKinds, legacyAfterKinds)
	}

	for _, object := range objects {
		if err := recovery.Delete(context.Background(), object, workloadDeleteOptions(object)...); !errors.Is(err, lost) {
			t.Fatalf("forwarded %s delete error=%v", operationKind(object), err)
		}
	}
	if recovery.deletes != 3 || recovery.otherWrites() != 9 || len(deleteObserver.deletes) != 3 || len(afterKinds) != 9 || len(legacyAfterKinds) != 3 {
		t.Fatalf("delete counts=%d writes=%d receipts=%+v callbacks=%v legacy=%v", recovery.deletes, recovery.otherWrites(), deleteObserver.deletes, afterKinds, legacyAfterKinds)
	}
	for _, receipt := range deleteObserver.deletes {
		if receipt.UID == "" || receipt.ResourceVersion == "" || receipt.Preconditions == nil || receipt.Preconditions.UID == nil || receipt.Preconditions.ResourceVersion == nil || receipt.Propagation == nil || *receipt.Propagation != metav1.DeletePropagationBackground {
			t.Fatalf("delete did not forward its conditional options: %+v", receipt)
		}
	}
}

func TestUnitM2RecoveryDefinitiveFailuresAreCountedWithoutForwarding(t *testing.T) {
	parent, names, config, recorder, _ := m2ReconcileFixture(t)
	base := recorder.Client
	objects := []client.Object{
		desiredKeaConfig(parent, names, config),
		desiredHeadlessService(parent, names),
		desiredKeaStatefulSet(parent, names, config),
	}
	if err := base.Create(context.Background(), objects[1]); err != nil {
		t.Fatal(err)
	}
	if err := base.Create(context.Background(), objects[2]); err != nil {
		t.Fatal(err)
	}
	rejected := apierrors.NewForbidden(schema.GroupResource{Resource: "workload"}, parent.Name, errors.New("denied"))
	c := &recoveryClient{statusRecordingClient: recorder, writeErr: rejected}
	if err := c.Create(context.Background(), objects[0]); !errors.Is(err, rejected) || c.creates != 1 || c.otherWrites() != 1 {
		t.Fatalf("rejected create err=%v creates=%d writes=%d", err, c.creates, c.otherWrites())
	}
	if err := c.Patch(context.Background(), objects[1], client.MergeFrom(objects[1].DeepCopyObject().(client.Object))); !errors.Is(err, rejected) || c.patches != 1 || c.otherWrites() != 2 {
		t.Fatalf("rejected patch err=%v patches=%d writes=%d", err, c.patches, c.otherWrites())
	}
	if err := c.Delete(context.Background(), objects[2], workloadDeleteOptions(objects[2])...); !errors.Is(err, rejected) || c.deletes != 1 || c.otherWrites() != 3 {
		t.Fatalf("rejected delete err=%v deletes=%d writes=%d", err, c.deletes, c.otherWrites())
	}
	for _, object := range objects {
		if err := base.Get(context.Background(), client.ObjectKeyFromObject(object), object); err != nil && !apierrors.IsNotFound(err) {
			t.Fatalf("read %s after rejected operation: %v", operationKind(object), err)
		} else if object == objects[0] && err == nil {
			t.Fatal("rejected create was forwarded")
		} else if object != objects[0] && err != nil {
			t.Fatalf("existing %s disappeared after rejected operation", operationKind(object))
		}
	}
}

func TestUnitM2RecoveryDefinitiveFailureMatrix(t *testing.T) {
	for _, kind := range []string{"ConfigMap", "Service", "StatefulSet"} {
		for _, verb := range []string{"create", "patch", "delete"} {
			for _, failure := range []string{"Forbidden", "Invalid", "Conflict", "NotFound"} {
				t.Run(kind+"/"+verb+"/"+failure, func(t *testing.T) {
					parent, names, config, recorder, _ := m2ReconcileFixture(t)
					var object client.Object
					resource := schema.GroupResource{Resource: "configmaps"}
					switch kind {
					case "ConfigMap":
						object = desiredKeaConfig(parent, names, config)
					case "Service":
						object = desiredHeadlessService(parent, names)
						resource.Resource = "services"
					case "StatefulSet":
						object = desiredKeaStatefulSet(parent, names, config)
						resource.Group, resource.Resource = "apps", "statefulsets"
					}
					object.SetUID(types.UID("m2-recovery-matrix"))
					var original client.Object
					if verb != "create" {
						original = object.DeepCopyObject().(client.Object)
						if err := recorder.Client.Create(context.Background(), original); err != nil {
							t.Fatal(err)
						}
					}
					var injected error
					switch failure {
					case "Forbidden":
						injected = apierrors.NewForbidden(resource, object.GetName(), errors.New("denied"))
					case "Invalid":
						injected = apierrors.NewInvalid(schema.GroupKind{Group: resource.Group, Kind: kind}, object.GetName(), field.ErrorList{field.Invalid(field.NewPath("spec"), "bad", "denied")})
					case "Conflict":
						injected = apierrors.NewConflict(resource, object.GetName(), errors.New("changed"))
					case "NotFound":
						injected = apierrors.NewNotFound(resource, object.GetName())
					}
					c := &recoveryClient{statusRecordingClient: recorder, writeErr: injected}
					var err error
					switch verb {
					case "create":
						err = c.Create(context.Background(), object)
					case "patch":
						base := original.DeepCopyObject().(client.Object)
						switch value := object.(type) {
						case *corev1.ConfigMap:
							value.Data["kea-dhcp4.conf"] = "drift"
						case *corev1.Service:
							value.Spec.Ports = []corev1.ServicePort{{Port: 90}}
						case *appsv1.StatefulSet:
							value.Spec.Replicas = pointerTo(int32(3))
						}
						err = c.Patch(context.Background(), object, client.MergeFrom(base))
					case "delete":
						err = c.Delete(context.Background(), object, workloadDeleteOptions(object)...)
					}
					if !errors.Is(err, injected) || c.otherWrites() != 1 {
						t.Fatalf("injected %s %s error=%v writes=%d", verb, kind, err, c.otherWrites())
					}
					got := object.DeepCopyObject().(client.Object)
					readErr := recorder.Client.Get(context.Background(), client.ObjectKeyFromObject(object), got)
					if verb == "create" {
						if !apierrors.IsNotFound(readErr) {
							t.Fatalf("rejected create was forwarded: object=%+v err=%v", got, readErr)
						}
					} else if readErr != nil || !reflect.DeepEqual(got, original) {
						t.Fatalf("rejected %s changed %s: got=%+v want=%+v err=%v", verb, kind, got, original, readErr)
					}
				})
			}
		}
	}
}

func TestUnitM2WorkloadLostResponseWithFailedReobservation(t *testing.T) {
	parent, names, config, recorder, _ := m2ReconcileFixture(t)
	base := recorder.Client
	if err := base.Create(context.Background(), desiredArtifact(parent)); err != nil {
		t.Fatal(err)
	}
	if err := base.Create(context.Background(), desiredHeadlessService(parent, names)); err != nil {
		t.Fatal(err)
	}
	if err := base.Create(context.Background(), desiredKeaStatefulSet(parent, names, config)); err != nil {
		t.Fatal(err)
	}
	object := desiredKeaConfig(parent, names, config)
	object.Data["kea-dhcp4.conf"] = "drift"
	if err := base.Create(context.Background(), object); err != nil {
		t.Fatal(err)
	}
	lost, readFailure := errors.New("lost workload patch response"), errors.New("post-patch ConfigMap read failed")
	reads := 0
	reader := &recoveryReader{Reader: base, readAt: func(_ context.Context, key client.ObjectKey, object client.Object) error {
		if key.Name == names.ConfigMap {
			reads++
			if reads == 2 {
				return readFailure
			}
		}
		return nil
	}}
	recovery := &recoveryClient{statusRecordingClient: recorder, writeErr: lost, forward: true}
	r := newTestReconciler(recovery, reader, parent.Namespace)
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
	if !errors.Is(err, lost) || !errors.Is(err, readFailure) || recovery.patches != 1 || recorder.otherWrites() != 1 {
		t.Fatalf("committed patch/reobservation outcome err=%v patches=%d writes=%d", err, recovery.patches, recorder.otherWrites())
	}
	got := &corev1.ConfigMap{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(object), got); err != nil || got.Data["kea-dhcp4.conf"] != config.DHCP4 {
		t.Fatalf("commit after lost acknowledgement not reflected: data=%v err=%v", got.Data, err)
	}
	stored := &infrastructurev1alpha1.KeaCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(parent), stored); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(stored.Status.Conditions, "WorkloadReconciled")
	if condition == nil || condition.Status != metav1.ConditionUnknown || condition.Reason != "ObservationFailed" {
		t.Fatalf("unresolved post-patch state was reported as confirmed: %+v", condition)
	}
	next := &statusRecordingClient{Client: base}
	if _, err := newTestReconciler(next, base, parent.Namespace).Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)}); err != nil {
		t.Fatal(err)
	}
	mutations := submittedMutations(next.operationSnapshot())
	if len(mutations) != 0 {
		t.Fatalf("reobserved committed patch was blindly retried: mutations=%+v", mutations)
	}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(parent), stored); err != nil {
		t.Fatal(err)
	}
	condition = meta.FindStatusCondition(stored.Status.Conditions, "WorkloadReconciled")
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "ResourcesInSync" {
		t.Fatalf("successful later observation did not resolve uncertainty: %+v", condition)
	}
}

var _ = Describe("M2: Recovery", func() {
	var requestCtx context.Context
	var stop context.CancelFunc
	var namespace *corev1.Namespace
	var parent *infrastructurev1alpha1.KeaCluster
	var names workloadNames
	var config workloadConfig
	var recorder *statusRecordingClient
	var recovery *recoveryClient
	var reconciler *KeaClusterReconciler
	var lost error

	BeforeEach(func() {
		requestCtx, stop = context.WithTimeout(ctx, 20*time.Second)
		DeferCleanup(stop)
		namespace = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "m2-recovery-"}}
		Expect(k8sClient.Create(requestCtx, namespace)).To(Succeed())
		severity := "INFO"
		parent = &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "recover", Namespace: namespace.Name}, Spec: &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true, LoggingSeverity: &severity}}}
		Expect(k8sClient.Create(requestCtx, parent)).To(Succeed())
		names = namesFor(parent)
		var err error
		config, err = generateKeaConfig(severity)
		Expect(err).NotTo(HaveOccurred())
		recorder = &statusRecordingClient{Client: k8sClient}
		recovery = &recoveryClient{statusRecordingClient: recorder}
		reconciler = newTestReconciler(recovery, k8sClient, namespace.Name)
		lost = errors.New("injected committed write with lost acknowledgement")
		Expect(k8sClient.Create(requestCtx, desiredArtifact(parent))).To(Succeed())
		DeferCleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &appsv1.StatefulSet{}, client.InNamespace(namespace.Name))).To(Succeed())
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.Service{}, client.InNamespace(namespace.Name))).To(Succeed())
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.ConfigMap{}, client.InNamespace(namespace.Name))).To(Succeed())
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &infrastructurev1alpha1.KeaCluster{}, client.InNamespace(namespace.Name))).To(Succeed())
			Expect(k8sClient.Delete(cleanupCtx, namespace)).To(Succeed())
		})
	})

	It("reobserves committed create, patch, and delete outcomes for all workload kinds", func() {
		recovery.writeErr, recovery.forward = lost, true
		for _, kind := range []string{"ConfigMap", "Service", "StatefulSet"} {
			before := len(recorder.operationSnapshot())
			_, err := reconciler.Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
			Expect(errors.Is(err, lost)).To(BeTrue(), "lost acknowledgement for create %s", kind)
			mutations := submittedMutations(recorder.operationSnapshot()[before:])
			Expect(mutations).To(HaveLen(1), "one submission maximum for create %s", kind)
			Expect(mutations[0].Verb).To(Equal("create"))
			Expect(mutations[0].Kind).To(Equal(kind))
		}
		Expect(recovery.creates).To(Equal(3))
		Expect(recovery.patches).To(BeZero())
		Expect(recovery.deletes).To(BeZero())

		for _, kind := range []string{"ConfigMap", "Service", "StatefulSet"} {
			before := len(recorder.operationSnapshot())
			switch kind {
			case "ConfigMap":
				object := &corev1.ConfigMap{}
				Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.ConfigMap}, object)).To(Succeed())
				object.Data["kea-dhcp4.conf"] = "drift"
				Expect(k8sClient.Update(requestCtx, object)).To(Succeed())
			case "Service":
				object := &corev1.Service{}
				Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.Service}, object)).To(Succeed())
				object.Spec.Ports = []corev1.ServicePort{{Name: "drift", Port: 99, Protocol: corev1.ProtocolTCP}}
				Expect(k8sClient.Update(requestCtx, object)).To(Succeed())
			case "StatefulSet":
				object := &appsv1.StatefulSet{}
				Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.StatefulSet}, object)).To(Succeed())
				object.Spec.Replicas = pointerTo(int32(3))
				Expect(k8sClient.Update(requestCtx, object)).To(Succeed())
			}
			_, err := reconciler.Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
			Expect(errors.Is(err, lost)).To(BeTrue(), "lost acknowledgement for patch %s", kind)
			mutations := submittedMutations(recorder.operationSnapshot()[before:])
			Expect(mutations).To(HaveLen(1), "one submission maximum for patch %s", kind)
			Expect(mutations[0].Verb).To(Equal("patch"))
			Expect(mutations[0].Kind).To(Equal(kind))
		}
		Expect(recovery.patches).To(Equal(3))

		parent = &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: "recover"}, parent)).To(Succeed())
		parent.Spec.Workload.Enabled = false
		Expect(k8sClient.Update(requestCtx, parent)).To(Succeed())
		statefulSet := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKey{Namespace: namespace.Name, Name: names.StatefulSet}, statefulSet)).To(Succeed())
		statefulSet.Spec.Replicas = pointerTo(int32(0))
		Expect(k8sClient.Update(requestCtx, statefulSet)).To(Succeed())
		for _, kind := range []string{"StatefulSet", "Service", "ConfigMap"} {
			before := len(recorder.operationSnapshot())
			_, err := reconciler.Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(parent)})
			Expect(errors.Is(err, lost)).To(BeTrue(), "lost acknowledgement for delete %s", kind)
			mutations := submittedMutations(recorder.operationSnapshot()[before:])
			Expect(mutations).To(HaveLen(1), "one submission maximum for delete %s", kind)
			Expect(mutations[0].Verb).To(Equal("delete"))
			Expect(mutations[0].Kind).To(Equal(kind))
			var object client.Object
			switch kind {
			case "StatefulSet":
				object = &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: names.StatefulSet, Namespace: namespace.Name}}
			case "Service":
				object = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: names.Service, Namespace: namespace.Name}}
			case "ConfigMap":
				object = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: names.ConfigMap, Namespace: namespace.Name}}
			}
			Expect(apierrors.IsNotFound(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(object), object))).To(BeTrue(), "direct reobservation after %s delete", kind)
		}
		Expect(recovery.creates).To(Equal(3))
		Expect(recovery.patches).To(Equal(3))
		Expect(recovery.deletes).To(Equal(3))
	})

	It("keeps Pod-list uncertainty Unknown and submits no cleanup action", func() {
		disabled := storedParentForM2(requestCtx, parent)
		disabled.Spec.Workload.Enabled = false
		Expect(k8sClient.Update(requestCtx, disabled)).To(Succeed())
		set := desiredKeaStatefulSet(disabled, namesFor(disabled), config)
		Expect(k8sClient.Create(requestCtx, set)).To(Succeed())
		listFailure := errors.New("namespace pod list unavailable")
		reader := &recoveryReader{Reader: k8sClient, readList: func(_ context.Context, list client.ObjectList) error {
			if _, ok := list.(*corev1.PodList); ok {
				return listFailure
			}
			return nil
		}}
		writes := recorder.otherWrites()
		result, err := newTestReconciler(recorder, reader, namespace.Name).Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(disabled)})
		Expect(errors.Is(err, listFailure)).To(BeTrue())
		Expect(result).To(Equal(ctrl.Result{}), "read failure uses retry backoff")
		Expect(recorder.otherWrites()).To(Equal(writes))
		condition := meta.FindStatusCondition(storedParentForM2(requestCtx, disabled).Status.Conditions, "WorkloadReconciled")
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionUnknown))
		Expect(condition.Reason).To(Equal("ObservationFailed"))
		ready := meta.FindStatusCondition(storedParentForM2(requestCtx, disabled).Status.Conditions, "WorkloadReady")
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionUnknown))
		Expect(ready.Reason).To(Equal("ObservationFailed"))
	})
})

func storedParentForM2(ctx context.Context, parent *infrastructurev1alpha1.KeaCluster) *infrastructurev1alpha1.KeaCluster {
	stored := &infrastructurev1alpha1.KeaCluster{}
	Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(parent), stored)).To(Succeed())
	return stored
}
