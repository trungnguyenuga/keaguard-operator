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
	"encoding/json"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
)

var _ = Describe("ENV: API", func() {
	var api dynamic.ResourceInterface
	var requestCtx context.Context
	var stop context.CancelFunc
	var namespace string
	var restClient rest.Interface

	BeforeEach(func() {
		requestCtx, stop = context.WithTimeout(ctx, 10*time.Second)
		DeferCleanup(stop)
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "t02-api-"}}
		Expect(k8sClient.Create(requestCtx, ns)).To(Succeed())
		namespace = ns.Name
		dc, err := dynamic.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())
		api = dc.Resource(schema.GroupVersionResource{Group: "infrastructure.keaguard.example", Version: "v1alpha1", Resource: "keaclusters"}).Namespace(namespace)
		// This client only talks to the private envtest server, never a kubeconfig.
		ac, err := apiextensionsclient.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())
		restClient = ac.RESTClient()
		DeferCleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			Expect(api.DeleteCollection(cleanupCtx, metav1.DeleteOptions{}, metav1.ListOptions{})).To(Succeed())
			Expect(k8sClient.Delete(cleanupCtx, ns)).To(Succeed())
		})
	})

	newCR := func(name string, spec bool) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "infrastructure.keaguard.example/v1alpha1", "kind": "KeaCluster",
			"metadata": map[string]any{"name": name, "namespace": namespace},
		}}
		if spec {
			obj.Object["spec"] = map[string]any{}
		}
		return obj
	}
	condition := func() map[string]any {
		return map[string]any{"type": "ArtifactReconciled", "status": "Unknown", "reason": "ObservationFailed", "message": "API-only fixture; no artifact observation", "observedGeneration": int64(1), "lastTransitionTime": "2026-10-16T00:00:00Z"}
	}

	It("admits omitted and empty specs without defaulting configuration", func() {
		for _, explicit := range []bool{false, true} {
			name := "omitted"
			if explicit {
				name = "empty"
			}
			created, err := api.Create(requestCtx, newCR(name, explicit), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			got, err := api.Get(requestCtx, name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(got.GetUID()).To(Equal(created.GetUID()))
			spec, exists, err := unstructured.NestedMap(got.Object, "spec")
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(Equal(explicit))
			Expect(spec).To(BeEmpty())
			_, exists = got.Object["status"]
			Expect(exists).To(BeFalse())
		}
	})

	It("publishes the optional workload API and list-map conditions", func() {
		ac, err := apiextensionsclient.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())
		crd, err := ac.ApiextensionsV1().CustomResourceDefinitions().Get(requestCtx, "keaclusters.infrastructure.keaguard.example", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(crd.Spec.Group).To(Equal("infrastructure.keaguard.example"))
		Expect(crd.Spec.Scope).To(Equal(apiextensionsv1.NamespaceScoped))
		Expect(crd.Spec.Names.Kind).To(Equal("KeaCluster"))
		Expect(crd.Spec.Names.Plural).To(Equal("keaclusters"))
		Expect(crd.Spec.Versions).To(HaveLen(1))
		version := crd.Spec.Versions[0]
		Expect(version.Name).To(Equal("v1alpha1"))
		Expect(version.Served).To(BeTrue())
		Expect(version.Storage).To(BeTrue())
		Expect(version.Subresources).NotTo(BeNil())
		Expect(version.Subresources.Status).NotTo(BeNil())
		root := version.Schema.OpenAPIV3Schema
		Expect(root.Required).NotTo(ContainElement("spec"))
		Expect(root.Properties).To(HaveKey("spec"))
		spec := root.Properties["spec"]
		Expect(spec.Type).To(Equal("object"))
		Expect(spec.Properties).To(HaveLen(1))
		Expect(spec.Properties).To(HaveKey("workload"))
		workload := spec.Properties["workload"]
		Expect(workload.Type).To(Equal("object"))
		Expect(workload.Required).To(BeEmpty())
		Expect(workload.Properties).To(HaveLen(2))
		Expect(workload.Properties["enabled"].Type).To(Equal("boolean"))
		Expect(workload.Properties["loggingSeverity"].Type).To(Equal("string"))
		Expect(workload.Properties["loggingSeverity"].Enum).To(HaveLen(6))
		Expect(workload.Properties["enabled"].Default).To(BeNil())
		Expect(workload.Properties["loggingSeverity"].Default).To(BeNil())
		status := root.Properties["status"]
		Expect(status.Properties).To(HaveLen(2))
		Expect(status.Properties).To(HaveKey("observedGeneration"))
		Expect(status.Properties["observedGeneration"].Type).To(Equal("integer"))
		Expect(status.Properties["observedGeneration"].Format).To(Equal("int64"))
		conditions := status.Properties["conditions"]
		Expect(conditions.Type).To(Equal("array"))
		Expect(conditions.XListType).NotTo(BeNil())
		Expect(*conditions.XListType).To(Equal("map"))
		Expect(conditions.XListMapKeys).To(Equal([]string{"type"}))
		var check func(apiextensionsv1.JSONSchemaProps)
		check = func(s apiextensionsv1.JSONSchemaProps) {
			Expect(s.Default).To(BeNil(), "no API defaults")
			Expect(s.XPreserveUnknownFields == nil || !*s.XPreserveUnknownFields).To(BeTrue(), "no arbitrary configuration escape hatch")
			Expect(s.AdditionalProperties == nil || !s.AdditionalProperties.Allows).To(BeTrue())
			for _, child := range s.Properties {
				check(child)
			}
			if s.Items != nil && s.Items.Schema != nil {
				check(*s.Items.Schema)
			}
		}
		check(*root)
	})

	It("prunes ordinary unknown spec fields", func() {
		obj := newCR("pruned", true)
		obj.Object["spec"] = map[string]any{"foo": "placeholder", "image": "unsupported", "dhcp": map[string]any{"subnet": "unsupported"}, "storage": "unsupported", "ha": true}
		_, err := api.Create(requestCtx, obj, metav1.CreateOptions{FieldValidation: "Ignore"})
		Expect(err).NotTo(HaveOccurred())
		got, err := api.Get(requestCtx, obj.GetName(), metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		spec, exists, err := unstructured.NestedMap(got.Object, "spec")
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeTrue())
		Expect(spec).To(BeEmpty())
	})

	It("rejects unsupported spec fields on a raw Strict request", func() {
		obj := newCR("strict", true)
		obj.Object["spec"] = map[string]any{"image": "unsupported"}
		raw, err := json.Marshal(obj.Object)
		Expect(err).NotTo(HaveOccurred())
		err = restClient.Post().AbsPath("/apis/infrastructure.keaguard.example/v1alpha1/namespaces/"+namespace+"/keaclusters").Param("fieldValidation", "Strict").Body(raw).Do(requestCtx).Error()
		Expect(apierrors.IsBadRequest(err)).To(BeTrue(), "strict request error: %v", err)
		Expect(err.Error()).To(ContainSubstring(`unknown field "spec.image"`))
		_, err = api.Get(requestCtx, "strict", metav1.GetOptions{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})

	It("isolates main-resource and status writes in both directions", func() {
		for _, explicit := range []bool{false, true} {
			name := "status-omitted"
			if explicit {
				name = "status-empty"
			}
			obj := newCR(name, explicit)
			obj.Object["status"] = map[string]any{"observedGeneration": int64(88), "conditions": []any{condition()}}
			created, err := api.Create(requestCtx, obj, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, exists := created.Object["status"]
			Expect(exists).To(BeFalse(), "create must ignore status")
			created.Object["status"] = obj.Object["status"]
			updated, err := api.Update(requestCtx, created, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, exists = updated.Object["status"]
			Expect(exists).To(BeFalse(), "main update must ignore status")
			updated.Object["status"] = map[string]any{"observedGeneration": updated.GetGeneration(), "conditions": []any{condition()}}
			// Flip omitted/empty spec through /status; the persisted spec must stay intact.
			if explicit {
				delete(updated.Object, "spec")
			} else {
				updated.Object["spec"] = map[string]any{}
			}
			_, err = api.UpdateStatus(requestCtx, updated, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			got, err := api.Get(requestCtx, name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, exists = got.Object["spec"]
			Expect(exists).To(Equal(explicit), "status update must preserve spec")
			generation, exists, err := unstructured.NestedInt64(got.Object, "status", "observedGeneration")
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue())
			Expect(generation).To(Equal(got.GetGeneration()))
			conditions, exists, err := unstructured.NestedSlice(got.Object, "status", "conditions")
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue())
			Expect(conditions).To(Equal([]any{condition()}))
			// Main updates must also preserve already persisted status.
			saved := got.Object["status"]
			got.Object["status"] = map[string]any{"observedGeneration": int64(99)}
			_, err = api.Update(requestCtx, got, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			persisted, err := api.Get(requestCtx, name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(persisted.Object["status"]).To(Equal(saved))
			// The typed fixture client consumes the same admitted API.
			typed := &infrastructurev1alpha1.KeaCluster{}
			Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(got), typed)).To(Succeed())
			Expect(typed.Spec != nil).To(Equal(explicit))
			Expect(typed.Status.ObservedGeneration).To(Equal(got.GetGeneration()))
			Expect(typed.Status.Conditions).To(HaveLen(1))
			Expect(typed.Status.Conditions[0].Type).To(Equal("ArtifactReconciled"))
		}
	})
})

var _ = Describe("ENV: Naming", func() {
	var requestCtx context.Context
	var namespaces []string
	BeforeEach(func() {
		var stop context.CancelFunc
		requestCtx, stop = context.WithTimeout(ctx, 10*time.Second)
		DeferCleanup(stop)
		namespaces = nil
		for range 2 {
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "t03-naming-"}}
			Expect(k8sClient.Create(requestCtx, ns)).To(Succeed())
			namespaces = append(namespaces, ns.Name)
			DeferCleanup(func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				// All writes/cleanup are administrative fixtures on the private API server.
				Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.ConfigMap{}, client.InNamespace(ns.Name))).To(Succeed())
				Expect(k8sClient.DeleteAllOf(cleanupCtx, &infrastructurev1alpha1.KeaCluster{}, client.InNamespace(ns.Name))).To(Succeed())
				Expect(k8sClient.Delete(cleanupCtx, ns)).To(Succeed())
			})
		}
	})

	createPair := func(namespace, name string, explicitSpec bool) (*infrastructurev1alpha1.KeaCluster, *corev1.ConfigMap) {
		parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
		if explicitSpec {
			parent.Spec = &infrastructurev1alpha1.KeaClusterSpec{}
		}
		Expect(k8sClient.Create(requestCtx, parent)).To(Succeed())
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), parent)).To(Succeed())
		Expect(parent.UID).NotTo(BeEmpty())
		cm := desiredArtifact(parent)
		Expect(k8sClient.Create(requestCtx, cm)).To(Succeed())
		persisted := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(cm), persisted)).To(Succeed())
		Expect(persisted.Name).To(Equal(name))
		Expect(persisted.Namespace).To(Equal(namespace))
		Expect(persisted.Data).To(Equal(map[string]string{"keacluster-name": name, "keacluster-namespace": namespace, "keacluster-uid": string(parent.UID)}))
		Expect(persisted.BinaryData).To(BeEmpty())
		yes, no := true, false
		Expect(persisted.OwnerReferences).To(Equal([]metav1.OwnerReference{{APIVersion: "infrastructure.keaguard.example/v1alpha1", Kind: "KeaCluster", Name: name, UID: parent.UID, Controller: &yes, BlockOwnerDeletion: &no}}))
		return parent, persisted
	}
	It("admits same-name artifacts with independent namespace and parent identities", func() {
		first, a := createPair(namespaces[0], "shared", false)
		second, b := createPair(namespaces[1], "shared", true)
		Expect(first.UID).NotTo(Equal(second.UID))
		Expect(a.UID).NotTo(Equal(b.UID))
		// Neither fixture creation mutates the other namespace's object.
		again := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(a), again)).To(Succeed())
		Expect(again).To(Equal(a))
	})
	It("admits a legal 253-character DNS-subdomain name for both resources", func() {
		name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
		Expect(name).To(HaveLen(253))
		createPair(namespaces[0], name, false)
	})
	It("rejects invalid names for both resources", func() {
		for _, name := range []string{"Uppercase", "bad_name", "-leading", "trailing-", "bad..name", strings.Repeat("a", 254)} {
			parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespaces[0]}}
			Expect(apierrors.IsInvalid(k8sClient.Create(requestCtx, parent))).To(BeTrue(), "CR name %q", name)
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespaces[0]}}
			Expect(apierrors.IsInvalid(k8sClient.Create(requestCtx, cm))).To(BeTrue(), "CM name %q", name)
		}
	})
})

var _ = Describe("ENV: Status boundaries", func() {
	It("persists fresh status, preserves unrelated conditions and skips repeated semantic writes", func() {
		requestCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "t04-status-"}}
		Expect(k8sClient.Create(requestCtx, ns)).To(Succeed())
		parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: ns.Name}}
		Expect(k8sClient.Create(requestCtx, parent)).To(Succeed())
		DeferCleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			Expect(k8sClient.Delete(cleanupCtx, parent)).To(Succeed())
			Expect(k8sClient.Delete(cleanupCtx, ns)).To(Succeed())
		})
		origin := parent.DeepCopy()
		external := metav1.Condition{Type: "ExternalCheck", Status: metav1.ConditionTrue, Reason: "External", Message: "preserve", LastTransitionTime: statusTime}
		parent.Status.Conditions = []metav1.Condition{external}
		Expect(k8sClient.Status().Update(requestCtx, parent)).To(Succeed())
		recorder := &statusRecordingClient{Client: k8sClient}
		r := newTestReconciler(recorder, k8sClient, ns.Name)
		condition := artifactCondition(metav1.ConditionFalse, "OwnershipConflict")
		condition.ObservedGeneration = origin.Generation
		condition.Message = "ConfigMap " + ns.Name + "/example: ownership conflict; resolve the conflicting resource manually"
		result, err := r.finishReconcile(requestCtx, origin, condition, ctrl.Result{RequeueAfter: 30 * time.Second}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(30 * time.Second))
		got := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), got)).To(Succeed())
		Expect(got.Status.ObservedGeneration).To(Equal(origin.Generation))
		Expect(got.Status.Conditions).To(HaveLen(2))
		Expect(equality.Semantic.DeepEqual(meta.FindStatusCondition(got.Status.Conditions, "ExternalCheck"), &external)).To(BeTrue())
		Expect(equality.Semantic.DeepEqual(meta.FindStatusCondition(got.Status.Conditions, "ArtifactReconciled"), &condition)).To(BeTrue())
		Expect(recorder.statusPatches()).To(Equal(1))
		saved := got.DeepCopy()
		// An older observation requires a fresh read, which may already match; still no patch.
		_, err = r.finishReconcile(requestCtx, origin, condition, ctrl.Result{}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(recorder.statusPatches()).To(Equal(1))
		condition.LastTransitionTime = metav1.NewTime(statusTime.Add(time.Hour))
		_, err = r.finishReconcile(requestCtx, got, condition, ctrl.Result{}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(recorder.statusPatches()).To(Equal(1))
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(parent), got)).To(Succeed())
		Expect(got.Status).To(Equal(saved.Status))
		Expect(got.ResourceVersion).To(Equal(saved.ResourceVersion))
		Expect(origin.Status.Conditions).To(BeEmpty())
		Expect(recorder.otherWrites()).To(BeZero())
	})
})

var _ = Describe("ENV: Core", func() {
	var requestCtx context.Context
	var stop context.CancelFunc
	var namespace string
	var c *coreRecordingClient
	var reader *coreRecordingReader
	var r *KeaClusterReconciler
	BeforeEach(func() {
		requestCtx, stop = context.WithTimeout(ctx, 10*time.Second)
		DeferCleanup(stop)
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "t06-core-"}}
		Expect(k8sClient.Create(requestCtx, ns)).To(Succeed())
		namespace = ns.Name
		c = &coreRecordingClient{statusRecordingClient: &statusRecordingClient{Client: k8sClient}}
		reader = &coreRecordingReader{Reader: k8sClient}
		r = newTestReconciler(c, reader, namespace)
		DeferCleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// Only test fixtures in this private API server; envtest has no GC.
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.ConfigMap{}, client.InNamespace(namespace))).To(Succeed())
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &infrastructurev1alpha1.KeaCluster{}, client.InNamespace(namespace))).To(Succeed())
			Expect(k8sClient.Delete(cleanupCtx, ns)).To(Succeed())
		})
	})
	makeParent := func(name string, explicit bool) *infrastructurev1alpha1.KeaCluster {
		p := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
		if explicit {
			p.Spec = &infrastructurev1alpha1.KeaClusterSpec{}
		}
		Expect(k8sClient.Create(requestCtx, p)).To(Succeed())
		return p
	}
	reconcile := func(p *infrastructurev1alpha1.KeaCluster) ctrl.Result {
		result, err := r.Reconcile(requestCtx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)})
		Expect(err).NotTo(HaveOccurred())
		return result
	}
	check := func(p *infrastructurev1alpha1.KeaCluster) *corev1.ConfigMap {
		cm := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(p), cm)).To(Succeed())
		Expect(cm.Data).To(Equal(map[string]string{"keacluster-name": p.Name, "keacluster-namespace": p.Namespace, "keacluster-uid": string(p.UID)}))
		Expect(cm.BinaryData).To(BeEmpty())
		Expect(cm.Immutable == nil || !*cm.Immutable).To(BeTrue())
		Expect(cm.Labels["keaguard.example/artifact"]).To(Equal("reconciliation"))
		Expect(cm.Annotations["keaguard.example/purpose"]).To(Equal("Internal reconciliation artifact; not operational Kea DHCP configuration."))
		yes, no := true, false
		Expect(cm.OwnerReferences).To(Equal([]metav1.OwnerReference{{APIVersion: "infrastructure.keaguard.example/v1alpha1", Kind: "KeaCluster", Name: p.Name, UID: p.UID, Controller: &yes, BlockOwnerDeletion: &no}}))
		stored := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(p), stored)).To(Succeed())
		condition := meta.FindStatusCondition(stored.Status.Conditions, "ArtifactReconciled")
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionTrue))
		Expect(condition.Reason).To(Equal("ArtifactInSync"))
		Expect(condition.ObservedGeneration).To(Equal(p.Generation))
		Expect(stored.Status.ObservedGeneration).To(Equal(p.Generation))
		return cm
	}
	It("creates exact admitted artifacts independently, preserves no-op status, and recreates a removed artifact", func() {
		first := makeParent("first", false)
		second := makeParent("second", true)
		Expect(reconcile(first).RequeueAfter).To(Equal(time.Second))
		Expect(reconcile(second).RequeueAfter).To(Equal(time.Second))
		old := check(first)
		secondCM := check(second)
		Expect(c.creates).To(Equal(2))
		Expect(c.otherWrites()).To(Equal(2))
		Expect(c.statusPatches()).To(Equal(2))
		before := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(first), before)).To(Succeed())
		parentReads := reader.parents
		for range 3 {
			reconcile(first)
			reconcile(second)
		}
		Expect(c.otherWrites()).To(Equal(2))
		Expect(c.statusPatches()).To(Equal(2))
		Expect(reader.parents).To(Equal(parentReads))
		after := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(first), after)).To(Succeed())
		Expect(after.Status).To(Equal(before.Status))
		Expect(k8sClient.Delete(requestCtx, old)).To(Succeed())
		Expect(reconcile(first).RequeueAfter).To(Equal(time.Second))
		replacement := check(first)
		Expect(replacement.UID).NotTo(Equal(old.UID))
		Expect(check(second).UID).To(Equal(secondCM.UID))
		Expect(c.creates).To(Equal(3))
		Expect(c.otherWrites()).To(Equal(3))
		Expect(c.statusPatches()).To(Equal(2))
	})
	It("stops outside requests before all resource operations and leaves administrative outside fixtures unchanged", func() {
		outside := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "t06-outside-"}}
		Expect(k8sClient.Create(requestCtx, outside)).To(Succeed())
		p := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "outside", Namespace: outside.Name}}
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: p.Name, Namespace: outside.Name}, Data: map[string]string{"fixture": "untouched"}}
		Expect(k8sClient.Create(requestCtx, p)).To(Succeed())
		Expect(k8sClient.Create(requestCtx, cm)).To(Succeed())
		DeferCleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			Expect(k8sClient.Delete(cleanupCtx, cm)).To(Succeed())
			Expect(k8sClient.Delete(cleanupCtx, p)).To(Succeed())
			Expect(k8sClient.Delete(cleanupCtx, outside)).To(Succeed())
		})
		Expect(reconcile(p)).To(Equal(ctrl.Result{}))
		Expect(c.calls).To(BeZero())
		Expect(c.otherWrites()).To(BeZero())
		Expect(c.statusPatches()).To(BeZero())
		Expect(reader.parents + reader.children).To(BeZero())
		gotP := &infrastructurev1alpha1.KeaCluster{}
		gotCM := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(p), gotP)).To(Succeed())
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(cm), gotCM)).To(Succeed())
		Expect(gotP).To(Equal(p))
		Expect(gotCM).To(Equal(cm))
	})
	It("submits no writes for missing or terminating parents", func() {
		absent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "absent", Namespace: namespace}}
		Expect(reconcile(absent)).To(Equal(ctrl.Result{}))
		p := makeParent("terminating", false)
		p.Finalizers = []string{"test.example/hold"}
		Expect(k8sClient.Update(requestCtx, p)).To(Succeed())
		Expect(k8sClient.Delete(requestCtx, p)).To(Succeed())
		Expect(reconcile(p)).To(Equal(ctrl.Result{}))
		Expect(c.otherWrites()).To(BeZero())
		Expect(c.statusPatches()).To(BeZero())
		Expect(reader.parents + reader.children).To(BeZero())
		cm := &corev1.ConfigMap{}
		Expect(apierrors.IsNotFound(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(p), cm))).To(BeTrue())
		Expect(k8sClient.Get(requestCtx, client.ObjectKeyFromObject(p), p)).To(Succeed())
		p.Finalizers = nil
		Expect(k8sClient.Update(requestCtx, p)).To(Succeed())
	})
})

var _ = Describe("ENV: Core setup", func() {
	It("initializes production intervals through actual SetupWithManager without starting a manager", func() {
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: testScheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0"})
		Expect(err).NotTo(HaveOccurred())
		r := &KeaClusterReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), Namespace: "t06-setup"}
		Expect(r.SetupWithManager(mgr)).To(Succeed())
		Expect(r.healthyRequeueAfter).To(Equal(5 * time.Minute))
		Expect(r.blockedRequeueAfter).To(Equal(30 * time.Second))
	})
})

var _ = Describe("ENV: Managed state", func() {
	var requestCtx context.Context
	var stop context.CancelFunc
	var ns *corev1.Namespace
	var p *infrastructurev1alpha1.KeaCluster
	var c *repairRecordingClient
	var r *KeaClusterReconciler
	var key client.ObjectKey
	BeforeEach(func() {
		requestCtx, stop = context.WithTimeout(ctx, 10*time.Second)
		DeferCleanup(stop)
		ns = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "t07-managed-"}}
		Expect(k8sClient.Create(requestCtx, ns)).To(Succeed())
		p = &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: ns.Name}}
		Expect(k8sClient.Create(requestCtx, p)).To(Succeed())
		key = client.ObjectKeyFromObject(p)
		c = &repairRecordingClient{statusRecordingClient: &statusRecordingClient{Client: k8sClient}}
		r = newTestReconciler(c, k8sClient, ns.Name)
		DeferCleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cm := &corev1.ConfigMap{}
			if err := k8sClient.Get(cleanupCtx, key, cm); err == nil {
				cm.Finalizers = nil
				Expect(k8sClient.Update(cleanupCtx, cm)).To(Succeed())
			} else {
				Expect(apierrors.IsNotFound(err)).To(BeTrue())
			}
			Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.ConfigMap{}, client.InNamespace(ns.Name))).To(Succeed())
			Expect(k8sClient.Delete(cleanupCtx, p)).To(Succeed())
			Expect(k8sClient.Delete(cleanupCtx, ns)).To(Succeed())
		})
	})
	reconcile := func(reason string, delay time.Duration) {
		result, err := r.Reconcile(requestCtx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(delay))
		stored := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, key, stored)).To(Succeed())
		condition := meta.FindStatusCondition(stored.Status.Conditions, "ArtifactReconciled")
		Expect(condition).NotTo(BeNil())
		Expect(condition.Reason).To(Equal(reason))
		want := metav1.ConditionFalse
		if reason == "ArtifactInSync" {
			want = metav1.ConditionTrue
		}
		Expect(condition.Status).To(Equal(want))
		Expect(condition.ObservedGeneration).To(Equal(p.Generation))
		Expect(stored.Status.ObservedGeneration).To(Equal(p.Generation))
	}
	checkPayload := func(cm *corev1.ConfigMap) {
		Expect(cm.Data).To(Equal(map[string]string{"keacluster-name": p.Name, "keacluster-namespace": p.Namespace, "keacluster-uid": string(p.UID)}))
		Expect(cm.BinaryData).To(BeEmpty())
		Expect(cm.Labels["keaguard.example/artifact"]).To(Equal("reconciliation"))
		Expect(cm.Annotations["keaguard.example/purpose"]).To(Equal("Internal reconciliation artifact; not operational Kea DHCP configuration."))
	}
	checkBlocked := func(before *corev1.ConfigMap, reason string) {
		writes, status := c.otherWrites(), c.statusPatches()
		reconcile(reason, 30*time.Second)
		stored := &infrastructurev1alpha1.KeaCluster{}
		Expect(k8sClient.Get(requestCtx, key, stored)).To(Succeed())
		initialStatus := stored.Status.DeepCopy()
		for range 3 {
			reconcile(reason, 30*time.Second)
		}
		Expect(c.otherWrites()).To(Equal(writes), "all CM mutation methods counted")
		Expect(c.statusPatches()).To(Equal(status + 1))
		Expect(k8sClient.Get(requestCtx, key, stored)).To(Succeed())
		Expect(stored.Status).To(Equal(*initialStatus))
		after := &corev1.ConfigMap{}
		Expect(k8sClient.Get(requestCtx, key, after)).To(Succeed())
		Expect(after).To(Equal(before), "blocked resource including ownership/finalizers/RV stays untouched")
	}
	It("repairs complete payload and reserved metadata while preserving unrelated metadata and owner flags", func() {
		cm := desiredArtifact(p)
		cm.Data = map[string]string{"keacluster-name": "wrong", "keacluster-uid": "wrong", "extra": "remove"}
		cm.BinaryData = map[string][]byte{"extra-binary": {1, 2}, "second": {3}}
		cm.Labels = map[string]string{"keaguard.example/artifact": "wrong", "other.example/label": "keep"}
		cm.Annotations = map[string]string{"other.example/annotation": "keep"}
		cm.OwnerReferences[0].BlockOwnerDeletion = boolPointer(true)
		cm.OwnerReferences = append(cm.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "other", UID: "extra-owner", Controller: boolPointer(false)})
		Expect(k8sClient.Create(requestCtx, cm)).To(Succeed())
		before := cm.DeepCopy()
		reconcile("ArtifactInSync", time.Second)
		Expect(c.artifactPatches).To(Equal(1))
		Expect(c.otherWrites()).To(Equal(1))
		Expect(c.patchRV).To(Equal(before.ResourceVersion))
		Expect(k8sClient.Get(requestCtx, key, cm)).To(Succeed())
		checkPayload(cm)
		Expect(cm.UID).To(Equal(before.UID))
		Expect(cm.OwnerReferences).To(Equal(before.OwnerReferences))
		Expect(cm.Labels["other.example/label"]).To(Equal("keep"))
		Expect(cm.Annotations["other.example/annotation"]).To(Equal("keep"))
		for range 3 {
			reconcile("ArtifactInSync", 5*time.Minute)
		}
		Expect(c.otherWrites()).To(Equal(1))
		Expect(c.statusPatches()).To(Equal(1))
		// A fixture-only empty-map update may serialize to nil; neither form
		// may cause a controller write.
		cm.BinaryData = map[string][]byte{}
		Expect(k8sClient.Update(requestCtx, cm)).To(Succeed())
		reconcile("ArtifactInSync", 5*time.Minute)
		Expect(c.otherWrites()).To(Equal(1))
		Expect(c.statusPatches()).To(Equal(1))
	})
	DescribeTable("leaves immutable artifacts untouched and recovers after manual removal",
		func(drift bool) {
			cm := desiredArtifact(p)
			cm.Immutable = boolPointer(true)
			if drift {
				cm.Data = map[string]string{"extra": "drift"}
				cm.Labels = nil
				cm.Annotations = nil
			}
			Expect(k8sClient.Create(requestCtx, cm)).To(Succeed())
			checkBlocked(cm.DeepCopy(), "ImmutableArtifact")
			oldUID := cm.UID
			Expect(k8sClient.Delete(requestCtx, cm)).To(Succeed())
			reconcile("ArtifactInSync", time.Second)
			Expect(c.otherWrites()).To(Equal(1))
			Expect(c.artifactPatches).To(BeZero())
			Expect(k8sClient.Get(requestCtx, key, cm)).To(Succeed())
			Expect(cm.UID).NotTo(Equal(oldUID))
			Expect(cm.Immutable == nil || !*cm.Immutable).To(BeTrue())
			checkPayload(cm)
			Expect(cm.OwnerReferences[0].UID).To(Equal(p.UID))
		}, Entry("matching", false), Entry("mismatched", true))
	It("awaits disappearance of a terminating child without removing its external finalizer", func() {
		cm := desiredArtifact(p)
		cm.Finalizers = []string{"test.example/hold"}
		cm.Data = nil
		cm.Labels = nil
		Expect(k8sClient.Create(requestCtx, cm)).To(Succeed())
		Expect(k8sClient.Delete(requestCtx, cm)).To(Succeed())
		Expect(k8sClient.Get(requestCtx, key, cm)).To(Succeed())
		Expect(cm.DeletionTimestamp.IsZero()).To(BeFalse())
		checkBlocked(cm.DeepCopy(), "ArtifactDeleting")
		oldUID := cm.UID
		cm.Finalizers = nil
		Expect(k8sClient.Update(requestCtx, cm)).To(Succeed())
		reconcile("ArtifactInSync", time.Second)
		Expect(c.otherWrites()).To(Equal(1))
		Expect(k8sClient.Get(requestCtx, key, cm)).To(Succeed())
		Expect(cm.UID).NotTo(Equal(oldUID))
		checkPayload(cm)
	})
	DescribeTable("refuses admitted ownership conflicts despite matching labels/payload",
		func(kind string) {
			cm := desiredArtifact(p)
			switch kind {
			case "unowned":
				cm.OwnerReferences = nil
			case "foreign":
				cm.OwnerReferences[0].Name = "foreign"
			case "stale":
				cm.OwnerReferences[0].UID = "old-parent"
			case "foreign immutable":
				cm.OwnerReferences = nil
				cm.Immutable = boolPointer(true)
			case "foreign terminating":
				cm.OwnerReferences = nil
				cm.Finalizers = []string{"test.example/hold"}
			}
			Expect(k8sClient.Create(requestCtx, cm)).To(Succeed())
			if kind == "foreign terminating" {
				Expect(k8sClient.Delete(requestCtx, cm)).To(Succeed())
				Expect(k8sClient.Get(requestCtx, key, cm)).To(Succeed())
			}
			checkBlocked(cm.DeepCopy(), "OwnershipConflict")
		}, Entry("unowned", "unowned"), Entry("foreign", "foreign"), Entry("stale UID", "stale"), Entry("foreign immutable precedence", "foreign immutable"), Entry("foreign terminating precedence", "foreign terminating"))
})
