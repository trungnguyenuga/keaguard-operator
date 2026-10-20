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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var _ = Describe("M2: API", func() {
	var api dynamic.ResourceInterface
	var requestCtx context.Context
	var namespace string
	var restClient rest.Interface

	BeforeEach(func() {
		var stop context.CancelFunc
		requestCtx, stop = context.WithTimeout(ctx, 10*time.Second)
		DeferCleanup(stop)
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "m2-api-"}}
		Expect(k8sClient.Create(requestCtx, ns)).To(Succeed())
		namespace = ns.Name
		dc, err := dynamic.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())
		api = dc.Resource(schema.GroupVersionResource{Group: "infrastructure.keaguard.example", Version: "v1alpha1", Resource: "keaclusters"}).Namespace(namespace)
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

	newObject := func(name string, spec any, includeSpec bool) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "infrastructure.keaguard.example/v1alpha1", "kind": "KeaCluster",
			"metadata": map[string]any{"name": name, "namespace": namespace},
		}}
		if includeSpec {
			obj.Object["spec"] = spec
		}
		return obj
	}

	It("preserves optional legacy and workload spec shapes without applying defaults", func() {
		cases := []struct {
			name             string
			spec             any
			includeSpec      bool
			wantSpec         bool
			wantWork         bool
			wantEnabledField bool
			wantEnabled      bool
		}{
			{name: "omitted-spec"},
			{name: "empty-spec", spec: map[string]any{}, includeSpec: true, wantSpec: true},
			{name: "absent-workload", spec: map[string]any{}, includeSpec: true, wantSpec: true},
			{name: "empty-workload", spec: map[string]any{"workload": map[string]any{}}, includeSpec: true, wantSpec: true, wantWork: true},
			{name: "enabled-omitted", spec: map[string]any{"workload": map[string]any{"loggingSeverity": "WARN"}}, includeSpec: true, wantSpec: true, wantWork: true},
			{name: "disabled", spec: map[string]any{"workload": map[string]any{"enabled": false}}, includeSpec: true, wantSpec: true, wantWork: true, wantEnabledField: true},
			{name: "enabled", spec: map[string]any{"workload": map[string]any{"enabled": true}}, includeSpec: true, wantSpec: true, wantWork: true, wantEnabledField: true, wantEnabled: true},
		}
		for _, tc := range cases {
			By(tc.name)
			created, err := api.Create(requestCtx, newObject(tc.name, tc.spec, tc.includeSpec), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			got, err := api.Get(requestCtx, tc.name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(got.GetUID()).To(Equal(created.GetUID()))
			_, specExists := got.Object["spec"]
			Expect(specExists).To(Equal(tc.wantSpec))
			workload, workloadExists, err := unstructured.NestedMap(got.Object, "spec", "workload")
			Expect(err).NotTo(HaveOccurred())
			Expect(workloadExists).To(Equal(tc.wantWork))
			if workloadExists {
				_, enabledExists := workload["enabled"]
				Expect(enabledExists).To(Equal(tc.wantEnabledField))
				if enabledExists {
					Expect(workload["enabled"]).To(Equal(tc.wantEnabled))
				}
			}
			_, severityExists, err := unstructured.NestedString(got.Object, "spec", "workload", "loggingSeverity")
			Expect(err).NotTo(HaveOccurred())
			Expect(severityExists).To(Equal(tc.name == "enabled-omitted"))
			_, statusExists := got.Object["status"]
			Expect(statusExists).To(BeFalse())
		}
	})

	It("prunes explicit nulls and admits all six severities while disabled", func() {
		for i, spec := range []any{
			nil,
			map[string]any{"workload": nil},
			map[string]any{"workload": map[string]any{"enabled": nil}},
			map[string]any{"workload": map[string]any{"loggingSeverity": nil}},
		} {
			name := fmt.Sprintf("null-%d", i)
			got, err := api.Create(requestCtx, newObject(name, spec, true), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			if i == 0 {
				_, exists := got.Object["spec"]
				Expect(exists).To(BeFalse(), "null spec should be pruned")
				continue
			}
			_, workloadExists, err := unstructured.NestedMap(got.Object, "spec", "workload")
			Expect(err).NotTo(HaveOccurred())
			Expect(workloadExists).To(Equal(i != 1))
		}

		for i, severity := range []string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE"} {
			name := fmt.Sprintf("severity-%d", i)
			created, err := api.Create(requestCtx, newObject(name, map[string]any{"workload": map[string]any{"enabled": false, "loggingSeverity": severity}}, true), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			got, err := api.Get(requestCtx, name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(got.GetUID()).To(Equal(created.GetUID()))
			Expect(got.Object["spec"]).To(Equal(map[string]any{"workload": map[string]any{"enabled": false, "loggingSeverity": severity}}))
		}
	})

	It("rejects invalid workload types and severity values", func() {
		cases := []struct {
			name string
			work map[string]any
		}{
			{name: "enabled-type", work: map[string]any{"enabled": "true"}},
			{name: "severity-type", work: map[string]any{"loggingSeverity": int64(3)}},
			{name: "severity-empty", work: map[string]any{"loggingSeverity": ""}},
			{name: "severity-lowercase", work: map[string]any{"loggingSeverity": "info"}},
			{name: "severity-unknown", work: map[string]any{"loggingSeverity": "TRACE"}},
		}
		for _, tc := range cases {
			_, err := api.Create(requestCtx, newObject(tc.name, map[string]any{"workload": tc.work}, true), metav1.CreateOptions{FieldValidation: "Ignore"})
			Expect(apierrors.IsInvalid(err) || apierrors.IsBadRequest(err)).To(BeTrue(), "%s should fail CRD schema validation, got %v", tc.name, err)
		}
	})

	It("publishes the exact optional schema and rejects unknown strict fields", func() {
		ac, err := apiextensionsclient.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())
		crd, err := ac.ApiextensionsV1().CustomResourceDefinitions().Get(requestCtx, "keaclusters.infrastructure.keaguard.example", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
		spec := root.Properties["spec"]
		Expect(spec.Properties).To(HaveKey("workload"))
		workload := spec.Properties["workload"]
		Expect(workload.Type).To(Equal("object"))
		Expect(workload.Properties).To(HaveLen(2))
		Expect(workload.Properties["enabled"].Type).To(Equal("boolean"))
		Expect(workload.Properties["loggingSeverity"].Type).To(Equal("string"))
		Expect(workload.Properties["loggingSeverity"].Enum).To(HaveLen(6))
		Expect(workload.Required).To(BeEmpty())
		Expect(workload.Properties["enabled"].Default).To(BeNil())
		Expect(workload.Properties["loggingSeverity"].Default).To(BeNil())
		Expect(workload.Properties["enabled"].Nullable).To(BeFalse())
		Expect(workload.Properties["loggingSeverity"].Nullable).To(BeFalse())
		var checkDefaults func(apiextensionsv1.JSONSchemaProps)
		checkDefaults = func(s apiextensionsv1.JSONSchemaProps) {
			Expect(s.Default).To(BeNil(), "M2 schema subtree must not materialize fields")
			for _, child := range s.Properties {
				checkDefaults(child)
			}
		}
		checkDefaults(spec)

		obj := newObject("strict-workload", map[string]any{"workload": map[string]any{"future": true}}, true)
		raw, err := json.Marshal(obj.Object)
		Expect(err).NotTo(HaveOccurred())
		err = restClient.Post().AbsPath("/apis/infrastructure.keaguard.example/v1alpha1/namespaces/"+namespace+"/keaclusters").Param("fieldValidation", "Strict").Body(raw).Do(requestCtx).Error()
		Expect(apierrors.IsBadRequest(err)).To(BeTrue(), "strict request error: %v", err)
		Expect(err.Error()).To(ContainSubstring(`unknown field "spec.workload.future"`))
	})
})
