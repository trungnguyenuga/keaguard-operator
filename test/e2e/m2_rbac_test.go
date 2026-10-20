/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("M2: RBAC", func() {
	m2It("executes allowed manager-token operations in scope and proves their denial outside scope", func() {
		_, pods, _, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
		manager, dyn := m2ManagerTokenClients()
		for _, ns := range []string{runtimeNamespace, outsideNamespace} {
			inside := ns == runtimeNamespace
			objects := []client.Object{
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, GenerateName: "m2-rbac-cm-", Annotations: map[string]string{"m2-rbac-fixture": "created"}}, Data: map[string]string{"fixture": "initial"}},
				m2RBACServiceFixture(ns, "m2-rbac-service-"),
				m2RBACStatefulSet(ns),
			}
			for _, object := range objects {
				if inside {
					create := func(ctx context.Context, candidate client.Object) (client.Object, error) {
						return m2RBACCreate(manager, ctx, candidate)
					}
					Expect(m2ActiveScenario.createFixtureWith(labctx, object, nil, false, create)).To(Succeed())
				} else {
					Expect(m2CreateObject(labctx, object, nil)).To(Succeed())
				}
				m2RBACExercise(manager, object, inside)
			}
		}

		// The manager's Pod permissions are observation-only; the real two-Pod
		// workload supplies valid, independently identified targets.
		pod := pods[0]
		_, err := manager.CoreV1().Pods(runtimeNamespace).Get(labctx, pod.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = manager.CoreV1().Pods(runtimeNamespace).List(labctx, metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		seconds := int64(1)
		watch, err := manager.CoreV1().Pods(runtimeNamespace).Watch(labctx, metav1.ListOptions{TimeoutSeconds: &seconds})
		Expect(err).NotTo(HaveOccurred())
		watch.Stop()
		_, err = manager.CoreV1().Pods(outsideNamespace).List(labctx, metav1.ListOptions{})
		forbidden("outside Pod List", err)
		_, err = manager.CoreV1().Pods(outsideNamespace).Watch(labctx, metav1.ListOptions{TimeoutSeconds: &seconds})
		forbidden("outside Pod Watch", err)
		_, err = manager.CoreV1().Pods(outsideNamespace).Get(labctx, "not-present", metav1.GetOptions{})
		forbidden("outside Pod Get", err)

		parent := createCR(runtimeNamespace, "m2-rbac-parent-")
		outsideParent := createCR(outsideNamespace, "m2-rbac-parent-")
		resource := dyn.Resource(schema.GroupVersionResource{Group: infrastructurev1alpha1.GroupVersion.Group, Version: infrastructurev1alpha1.GroupVersion.Version, Resource: "keaclusters"})
		for _, item := range []struct {
			ns     string
			parent *infrastructurev1alpha1.KeaCluster
		}{{runtimeNamespace, parent}, {outsideNamespace, outsideParent}} {
			client := resource.Namespace(item.ns)
			_, err = client.Get(labctx, item.parent.Name, metav1.GetOptions{})
			if item.ns == runtimeNamespace {
				Expect(err).NotTo(HaveOccurred())
			} else {
				forbidden("outside KeaCluster Get", err)
			}
			_, err = client.List(labctx, metav1.ListOptions{})
			if item.ns == runtimeNamespace {
				Expect(err).NotTo(HaveOccurred())
			} else {
				forbidden("outside KeaCluster List", err)
			}
			watch, watchErr := client.Watch(labctx, metav1.ListOptions{TimeoutSeconds: &seconds})
			if item.ns == runtimeNamespace {
				Expect(watchErr).NotTo(HaveOccurred())
				watch.Stop()
			} else {
				forbidden("outside KeaCluster Watch", watchErr)
			}
			patch := []byte(`{"status":{"conditions":[{"type":"RBACFixture","status":"True","reason":"TokenRequestVerified","message":"fixture","lastTransitionTime":"2026-10-16T00:00:00Z"}]}}`)
			_, err = client.Patch(labctx, item.parent.Name, types.MergePatchType, patch, metav1.PatchOptions{}, "status")
			if item.ns == runtimeNamespace {
				Expect(err).NotTo(HaveOccurred())
			} else {
				forbidden("outside KeaCluster status Patch", err)
			}
		}
	})

	m2It("denies update, Pod mutation and exec, and unrelated namespaced or cluster APIs", func() {
		parent, pods, _, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
		manager, dyn := m2ManagerTokenClients()
		pod := pods[0]
		_, err := manager.CoreV1().Pods(runtimeNamespace).Update(labctx, &pod, metav1.UpdateOptions{})
		forbidden("Pod Update", err)
		_, err = manager.CoreV1().Pods(runtimeNamespace).Create(labctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, GenerateName: "denied-pod-"}}, metav1.CreateOptions{})
		forbidden("Pod Create", err)
		_, err = manager.CoreV1().Pods(runtimeNamespace).Patch(labctx, pod.Name, types.MergePatchType, []byte(`{"metadata":{"annotations":{"denied":"true"}}}`), metav1.PatchOptions{})
		forbidden("Pod Patch", err)
		uid, rv := pod.UID, pod.ResourceVersion
		err = manager.CoreV1().Pods(runtimeNamespace).Delete(labctx, pod.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
		forbidden("Pod Delete", err)
		execErr := manager.CoreV1().RESTClient().Post().Namespace(runtimeNamespace).Resource("pods").Name(pod.Name).SubResource("exec").Do(labctx).Error()
		forbidden("Pod exec", execErr)
		operations := []struct {
			name string
			run  func() error
		}{
			{"Namespace Get", func() error {
				_, e := manager.CoreV1().Namespaces().Get(labctx, runtimeNamespace, metav1.GetOptions{})
				return e
			}},
			{"Secrets List", func() error {
				_, e := manager.CoreV1().Secrets(runtimeNamespace).List(labctx, metav1.ListOptions{})
				return e
			}},
			{"PVC List", func() error {
				_, e := manager.CoreV1().PersistentVolumeClaims(runtimeNamespace).List(labctx, metav1.ListOptions{})
				return e
			}},
			{"PV List", func() error {
				_, e := manager.CoreV1().PersistentVolumes().List(labctx, metav1.ListOptions{})
				return e
			}},
			{"Events List", func() error {
				_, e := manager.CoreV1().Events(runtimeNamespace).List(labctx, metav1.ListOptions{})
				return e
			}},
			{"Lease List", func() error {
				_, e := manager.CoordinationV1().Leases(runtimeNamespace).List(labctx, metav1.ListOptions{})
				return e
			}},
			{"ServiceAccount TokenRequest", func() error {
				_, e := manager.CoreV1().ServiceAccounts(runtimeNamespace).CreateToken(labctx, managerName, &authenticationv1.TokenRequest{}, metav1.CreateOptions{})
				return e
			}},
			{"TokenReview Create", func() error {
				_, e := manager.AuthenticationV1().TokenReviews().Create(labctx, &authenticationv1.TokenReview{}, metav1.CreateOptions{})
				return e
			}},
			{"SubjectAccessReview Create", func() error {
				_, e := manager.AuthorizationV1().SubjectAccessReviews().Create(labctx, &authorizationv1.SubjectAccessReview{}, metav1.CreateOptions{})
				return e
			}},
			{"Role List", func() error {
				_, e := manager.RbacV1().Roles(runtimeNamespace).List(labctx, metav1.ListOptions{})
				return e
			}},
			{"RoleBinding List", func() error {
				_, e := manager.RbacV1().RoleBindings(runtimeNamespace).List(labctx, metav1.ListOptions{})
				return e
			}},
			{"CRD Get", func() error {
				_, e := dyn.Resource(schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}).Get(labctx, "keaclusters.infrastructure.keaguard.example", metav1.GetOptions{})
				return e
			}},
		}
		for _, operation := range operations {
			forbidden(operation.name, operation.run())
		}
		_, err = manager.DiscoveryV1().EndpointSlices(runtimeNamespace).List(labctx, metav1.ListOptions{})
		forbidden("EndpointSlice List", err)
		_, err = manager.AppsV1().Deployments(runtimeNamespace).List(labctx, metav1.ListOptions{})
		forbidden("Deployment List", err)
		resource := dyn.Resource(schema.GroupVersionResource{Group: infrastructurev1alpha1.GroupVersion.Group, Version: infrastructurev1alpha1.GroupVersion.Version, Resource: "keaclusters"}).Namespace(runtimeNamespace)
		_, err = resource.Create(labctx, &unstructured.Unstructured{Object: map[string]any{"apiVersion": infrastructurev1alpha1.GroupVersion.String(), "kind": "KeaCluster", "metadata": map[string]any{"generateName": "denied-"}}}, metav1.CreateOptions{})
		forbidden("KeaCluster Create", err)
		_, err = resource.Patch(labctx, parent.Name, types.MergePatchType, []byte(`{"spec":{}}`), metav1.PatchOptions{})
		forbidden("KeaCluster spec Patch", err)
		_, err = resource.Patch(labctx, parent.Name, types.MergePatchType, []byte(`{"metadata":{"finalizers":["denied"]}}`), metav1.PatchOptions{})
		forbidden("KeaCluster finalizer Patch", err)
		current, err := resource.Get(labctx, parent.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = resource.Update(labctx, current, metav1.UpdateOptions{})
		forbidden("KeaCluster Update", err)
		err = resource.Delete(labctx, parent.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &parent.UID}})
		forbidden("KeaCluster Delete", err)
	})
})

func TestUnitM2RBACServiceFixtureHasAnAPIValidPort(t *testing.T) {
	service := m2RBACServiceFixture("keaguard-m2-runtime", "m2-rbac-service-")
	if service.Namespace != "keaguard-m2-runtime" || service.GenerateName != "m2-rbac-service-" {
		t.Fatalf("unexpected RBAC Service fixture identity: %#v", service.ObjectMeta)
	}
	if len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Name != "fixture" || service.Spec.Ports[0].Port != 8080 {
		t.Fatalf("RBAC Service fixture must contain the reviewed valid TCP port 8080: %#v", service.Spec.Ports)
	}
}

func TestUnitM2RBACPatchBindsProbeToFixtureUID(t *testing.T) {
	const expectedUID types.UID = "fixture-incarnation-uid"
	patchType, patch, err := m2RBACPatch(expectedUID)
	if err != nil {
		t.Fatalf("build UID-bound patch: %v", err)
	}
	if patchType != types.JSONPatchType {
		t.Fatalf("RBAC patch must use a UID-tested JSON Patch, got %q", patchType)
	}
	var operations []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}
	if err := json.Unmarshal(patch, &operations); err != nil {
		t.Fatalf("decode UID-bound patch: %v", err)
	}
	if len(operations) != 2 || operations[0].Op != "test" || operations[0].Path != "/metadata/uid" || operations[0].Value != string(expectedUID) {
		t.Fatalf("first operation must atomically test the exact fixture UID, got %#v", operations)
	}
	if operations[1].Op != "add" || operations[1].Path != "/metadata/annotations/m2-rbac" || operations[1].Value != "patched" {
		t.Fatalf("second operation must exercise only the fixture annotation patch, got %#v", operations)
	}
}

func ptrInt32(value int32) *int32 { return &value }
func ptrBool(value bool) *bool    { return &value }
func ptrInt64(value int64) *int64 { return &value }

func m2RBACServiceFixture(namespace, generateName string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, GenerateName: generateName, Annotations: map[string]string{"m2-rbac-fixture": "created"}},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "fixture", Port: 8080}}},
	}
}

func m2RBACStatefulSet(ns string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, GenerateName: "m2-rbac-set-", Annotations: map[string]string{"m2-rbac-fixture": "created"}},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptrInt32(0), ServiceName: "m2-rbac-headless",
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"fixture": "m2-rbac"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"fixture": "m2-rbac"}},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptrBool(true), RunAsUser: ptrInt64(1000), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Containers:      []corev1.Container{{Name: "fixture", Image: "registry.k8s.io/pause:3.10", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptrBool(false), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}},
				},
			},
		},
	}
}

func m2ManagerTokenClients() (*kubernetes.Clientset, dynamic.Interface) {
	expiration := int64(600)
	request, err := adminset.CoreV1().ServiceAccounts(runtimeNamespace).CreateToken(labctx, managerName, &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &expiration}}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	Expect(request.Status.Token).NotTo(BeEmpty())
	cfg := runtimeConfig(adminConfig, request.Status.Token)
	manager, err := kubernetes.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())
	dyn, err := dynamic.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())
	return manager, dyn
}

func m2RBACCreate(manager *kubernetes.Clientset, ctx context.Context, object client.Object) (client.Object, error) {
	var created client.Object
	var err error
	switch typed := object.(type) {
	case *corev1.ConfigMap:
		created, err = manager.CoreV1().ConfigMaps(typed.Namespace).Create(ctx, typed, metav1.CreateOptions{})
	case *corev1.Service:
		created, err = manager.CoreV1().Services(typed.Namespace).Create(ctx, typed, metav1.CreateOptions{})
	case *appsv1.StatefulSet:
		created, err = manager.AppsV1().StatefulSets(typed.Namespace).Create(ctx, typed, metav1.CreateOptions{})
	default:
		return nil, fmt.Errorf("unsupported RBAC fixture kind %T", object)
	}
	if err != nil {
		return nil, err
	}
	switch target := object.(type) {
	case *corev1.ConfigMap:
		*target = *created.(*corev1.ConfigMap).DeepCopy()
	case *corev1.Service:
		*target = *created.(*corev1.Service).DeepCopy()
	case *appsv1.StatefulSet:
		*target = *created.(*appsv1.StatefulSet).DeepCopy()
	}
	return created, nil
}

func m2RBACExercise(manager *kubernetes.Clientset, object client.Object, inside bool) {
	ns, name := object.GetNamespace(), object.GetName()
	patchType, patch, patchBuildErr := m2RBACPatch(object.GetUID())
	Expect(patchBuildErr).NotTo(HaveOccurred())
	watchSeconds := int64(1)
	var getErr, listErr, watchErr, patchErr, deleteErr, createErr, updateErr error
	switch typed := object.(type) {
	case *corev1.ConfigMap:
		current, e := manager.CoreV1().ConfigMaps(ns).Get(labctx, name, metav1.GetOptions{})
		getErr = e
		if inside && e == nil {
			_, updateErr = manager.CoreV1().ConfigMaps(ns).Update(labctx, current, metav1.UpdateOptions{})
		}
		_, listErr = manager.CoreV1().ConfigMaps(ns).List(labctx, metav1.ListOptions{})
		w, e := manager.CoreV1().ConfigMaps(ns).Watch(labctx, metav1.ListOptions{TimeoutSeconds: &watchSeconds})
		watchErr = e
		if w != nil {
			w.Stop()
		}
		_, patchErr = manager.CoreV1().ConfigMaps(ns).Patch(labctx, name, patchType, patch, metav1.PatchOptions{})
		deleteErr = manager.CoreV1().ConfigMaps(ns).Delete(labctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &typed.UID}})
		if !inside {
			_, createErr = manager.CoreV1().ConfigMaps(ns).Create(labctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, GenerateName: "denied-"}}, metav1.CreateOptions{})
		}
	case *corev1.Service:
		current, e := manager.CoreV1().Services(ns).Get(labctx, name, metav1.GetOptions{})
		getErr = e
		if inside && e == nil {
			_, updateErr = manager.CoreV1().Services(ns).Update(labctx, current, metav1.UpdateOptions{})
		}
		_, listErr = manager.CoreV1().Services(ns).List(labctx, metav1.ListOptions{})
		w, e := manager.CoreV1().Services(ns).Watch(labctx, metav1.ListOptions{TimeoutSeconds: &watchSeconds})
		watchErr = e
		if w != nil {
			w.Stop()
		}
		_, patchErr = manager.CoreV1().Services(ns).Patch(labctx, name, patchType, patch, metav1.PatchOptions{})
		deleteErr = manager.CoreV1().Services(ns).Delete(labctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &typed.UID}})
		if !inside {
			_, createErr = manager.CoreV1().Services(ns).Create(labctx, m2RBACServiceFixture(ns, "denied-"), metav1.CreateOptions{})
		}
	case *appsv1.StatefulSet:
		current, e := manager.AppsV1().StatefulSets(ns).Get(labctx, name, metav1.GetOptions{})
		getErr = e
		if inside && e == nil {
			_, updateErr = manager.AppsV1().StatefulSets(ns).Update(labctx, current, metav1.UpdateOptions{})
		}
		_, listErr = manager.AppsV1().StatefulSets(ns).List(labctx, metav1.ListOptions{})
		w, e := manager.AppsV1().StatefulSets(ns).Watch(labctx, metav1.ListOptions{TimeoutSeconds: &watchSeconds})
		watchErr = e
		if w != nil {
			w.Stop()
		}
		_, patchErr = manager.AppsV1().StatefulSets(ns).Patch(labctx, name, patchType, patch, metav1.PatchOptions{})
		deleteErr = manager.AppsV1().StatefulSets(ns).Delete(labctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &typed.UID}})
		if !inside {
			denied := m2RBACStatefulSet(ns)
			denied.GenerateName = "denied-"
			_, createErr = manager.AppsV1().StatefulSets(ns).Create(labctx, denied, metav1.CreateOptions{})
		}
	}
	if inside {
		Expect(getErr).NotTo(HaveOccurred())
		forbidden("in-scope namespaced Update", updateErr)
		Expect(listErr).NotTo(HaveOccurred())
		Expect(watchErr).NotTo(HaveOccurred())
		Expect(patchErr).NotTo(HaveOccurred())
		Expect(deleteErr).NotTo(HaveOccurred())
	} else {
		for _, item := range []struct {
			name string
			err  error
		}{{"Get", getErr}, {"List", listErr}, {"Watch", watchErr}, {"Patch", patchErr}, {"Delete", deleteErr}, {"Create", createErr}} {
			forbidden("outside namespaced "+item.name, item.err)
		}
	}
	if inside {
		identity, err := m2IdentityFor(object)
		Expect(err).NotTo(HaveOccurred())
		Expect(m2ActiveScenario.VerifyAbsent(labctx, identity)).To(Succeed())
	}
}

// m2RBACPatch binds the Patch authorization probe to the fixture incarnation.
// This initial extraction intentionally preserves the old request semantics.
func m2RBACPatch(uid types.UID) (types.PatchType, []byte, error) {
	patch, err := json.Marshal([]struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value string `json:"value"`
	}{
		{Op: "test", Path: "/metadata/uid", Value: string(uid)},
		{Op: "add", Path: "/metadata/annotations/m2-rbac", Value: "patched"},
	})
	if err != nil {
		return "", nil, fmt.Errorf("marshal UID-bound RBAC patch: %w", err)
	}
	return types.JSONPatchType, patch, nil
}
