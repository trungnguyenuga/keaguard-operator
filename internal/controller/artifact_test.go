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
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
)

func artifactParent() *infrastructurev1alpha1.KeaCluster {
	return &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "lab", UID: "parent-uid"}}
}
func artifactFixture() *corev1.ConfigMap {
	yes, no := true, false
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "lab",
		Labels:          map[string]string{"keaguard.example/artifact": "reconciliation"},
		Annotations:     map[string]string{"keaguard.example/purpose": "Internal reconciliation artifact; not operational Kea DHCP configuration."},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "infrastructure.keaguard.example/v1alpha1", Kind: "KeaCluster", Name: "alpha", UID: "parent-uid", Controller: &yes, BlockOwnerDeletion: &no}}},
		Data: map[string]string{"keacluster-name": "alpha", "keacluster-namespace": "lab", "keacluster-uid": "parent-uid"}}
}
func TestUnitArtifactIdentity(t *testing.T) {
	p := artifactParent()
	before := p.DeepCopy()
	got := desiredArtifact(p)
	want := artifactFixture()
	if got.Name != want.Name || got.Namespace != want.Namespace || !reflect.DeepEqual(got.Data, want.Data) || len(got.BinaryData) != 0 || !reflect.DeepEqual(got.Labels, want.Labels) || !reflect.DeepEqual(got.Annotations, want.Annotations) || !reflect.DeepEqual(got.OwnerReferences, want.OwnerReferences) || (got.Immutable != nil && *got.Immutable) {
		t.Fatalf("incorrect artifact: %#v", got)
	}
	if !reflect.DeepEqual(got, desiredArtifact(p)) {
		t.Fatal("nondeterministic output")
	}
	p.Spec = &infrastructurev1alpha1.KeaClusterSpec{}
	if !reflect.DeepEqual(got, desiredArtifact(p)) {
		t.Fatal("empty spec changed artifact")
	}
	p.Spec = nil
	if !reflect.DeepEqual(p, before) {
		t.Fatal("mutated parent")
	}
	got.Data["keacluster-name"] = "changed"
	got.Labels["keaguard.example/artifact"] = "changed"
	got.Annotations["keaguard.example/purpose"] = "changed"
	*got.OwnerReferences[0].Controller = false
	if !reflect.DeepEqual(desiredArtifact(p), desiredArtifact(before)) || desiredArtifact(p).Data["keacluster-name"] != "alpha" || !*desiredArtifact(p).OwnerReferences[0].Controller {
		t.Fatal("output aliases source or another output")
	}
}
func TestUnitManagedFields(t *testing.T) {
	cases := []struct {
		name string
		edit func(*corev1.ConfigMap)
	}{
		{"extra data", func(c *corev1.ConfigMap) { c.Data["extra"] = "x" }},
		{"missing data", func(c *corev1.ConfigMap) { delete(c.Data, "keacluster-uid") }},
		{"changed data", func(c *corev1.ConfigMap) { c.Data["keacluster-name"] = "wrong" }},
		{"binary", func(c *corev1.ConfigMap) { c.BinaryData = map[string][]byte{"unexpected": {1, 2}} }},
		{"missing label", func(c *corev1.ConfigMap) { c.Labels = nil }},
		{"changed label", func(c *corev1.ConfigMap) { c.Labels["keaguard.example/artifact"] = "wrong" }},
		{"missing annotation", func(c *corev1.ConfigMap) { c.Annotations = nil }},
		{"changed annotation", func(c *corev1.ConfigMap) { c.Annotations["keaguard.example/purpose"] = "wrong" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			desired := artifactFixture()
			desiredBefore := desired.DeepCopy()
			actual := artifactFixture()
			actual.UID = "child-uid"
			actual.ResourceVersion = "42"
			actual.Finalizers = []string{"external.example/hold"}
			yes := true
			actual.Immutable = &yes
			actual.DeletionTimestamp = &metav1.Time{Time: time.Unix(100, 0)}
			actual.OwnerReferences[0].BlockOwnerDeletion = &yes
			actual.OwnerReferences = append(actual.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "other", UID: "other"})
			actual.Labels["other"] = "label"
			actual.Annotations["other"] = "annotation"
			tc.edit(actual)
			before := actual.DeepCopy()
			if managedFieldsEqual(actual, desired) {
				t.Fatal("missed drift")
			}
			if !reflect.DeepEqual(actual, before) {
				t.Fatal("comparison mutated actual")
			}
			target := actual.DeepCopy()
			setManagedFields(target, desired)
			if !managedFieldsEqual(target, desired) {
				t.Fatal("repair did not converge")
			}
			expected := before.DeepCopy()
			expected.Data = desiredBefore.Data
			expected.BinaryData = desiredBefore.BinaryData
			if expected.Labels == nil {
				expected.Labels = map[string]string{}
			}
			expected.Labels["keaguard.example/artifact"] = "reconciliation"
			if expected.Annotations == nil {
				expected.Annotations = map[string]string{}
			}
			expected.Annotations["keaguard.example/purpose"] = "Internal reconciliation artifact; not operational Kea DHCP configuration."
			if !reflect.DeepEqual(target, expected) {
				t.Fatalf("changed unmanaged fields or wrong repair: %#v", target)
			}
			if !reflect.DeepEqual(actual, before) || !reflect.DeepEqual(desired, desiredBefore) {
				t.Fatal("mutated source")
			}
			target.Data["keacluster-name"] = "aliased"
			target.Labels["keaguard.example/artifact"] = "aliased"
			target.Annotations["keaguard.example/purpose"] = "aliased"
			if !reflect.DeepEqual(desired, desiredBefore) {
				t.Fatal("aliased desired")
			}
		})
	}
	t.Run("nil empty and unmanaged", func(t *testing.T) {
		a := artifactFixture()
		b := artifactFixture()
		a.Data = nil
		b.Data = map[string]string{}
		a.BinaryData = nil
		b.BinaryData = map[string][]byte{}
		a.Labels["other"] = "keep"
		a.UID = "different"
		a.OwnerReferences = nil
		yes := true
		a.Immutable = &yes
		if !managedFieldsEqual(a, b) {
			t.Fatal("nil/empty or unmanaged fields caused drift")
		}
		setManagedFields(a, b)
		b.Data["later"] = "x"
		b.BinaryData["later"] = []byte{1}
		if len(a.Data) != 0 || len(a.BinaryData) != 0 {
			t.Fatal("empty maps aliased")
		}
		b.Data = nil
		a.BinaryData = map[string][]byte{"bytes": {1, 2}}
		b.BinaryData = map[string][]byte{"bytes": {1, 2}}
		if !managedFieldsEqual(a, b) {
			t.Fatal("equal binary values differ")
		}
		b.BinaryData["bytes"][0] = 3
		if managedFieldsEqual(a, b) {
			t.Fatal("binary value drift missed")
		}
		setManagedFields(a, b)
		b.BinaryData["bytes"][0] = 4
		if a.BinaryData["bytes"][0] != 3 {
			t.Fatal("binary slices aliased")
		}
	})
}
func TestUnitOwnership(t *testing.T) {
	cases := []struct {
		name string
		edit func(*corev1.ConfigMap)
		want bool
	}{
		{"valid", func(c *corev1.ConfigMap) {}, true},
		{"absent despite labels", func(c *corev1.ConfigMap) { c.OwnerReferences = nil }, false},
		{"noncontroller", func(c *corev1.ConfigMap) { v := false; c.OwnerReferences[0].Controller = &v }, false},
		{"nil controller", func(c *corev1.ConfigMap) { c.OwnerReferences[0].Controller = nil }, false},
		{"group", func(c *corev1.ConfigMap) { c.OwnerReferences[0].APIVersion = "other.example/v1alpha1" }, false},
		{"version", func(c *corev1.ConfigMap) { c.OwnerReferences[0].APIVersion = "infrastructure.keaguard.example/v1beta1" }, false},
		{"malformed version", func(c *corev1.ConfigMap) { c.OwnerReferences[0].APIVersion = "/" }, false},
		{"kind", func(c *corev1.ConfigMap) { c.OwnerReferences[0].Kind = "Other" }, false},
		{"name", func(c *corev1.ConfigMap) { c.OwnerReferences[0].Name = "other" }, false},
		{"stale UID", func(c *corev1.ConfigMap) { c.OwnerReferences[0].UID = "old-uid" }, false},
		{"empty UID", func(c *corev1.ConfigMap) { c.OwnerReferences[0].UID = "" }, false},
		{"duplicate controllers", func(c *corev1.ConfigMap) { c.OwnerReferences = append(c.OwnerReferences, c.OwnerReferences[0]) }, false},
		{"second foreign controller", func(c *corev1.ConfigMap) {
			r := c.OwnerReferences[0]
			r.UID = "foreign"
			c.OwnerReferences = append([]metav1.OwnerReference{r}, c.OwnerReferences...)
		}, false},
		{"extra noncontroller", func(c *corev1.ConfigMap) {
			c.OwnerReferences = append(c.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "extra", UID: "extra"})
		}, true},
		{"existing blocking flag", func(c *corev1.ConfigMap) { v := true; c.OwnerReferences[0].BlockOwnerDeletion = &v }, true},
		{"nil blocking flag", func(c *corev1.ConfigMap) { c.OwnerReferences[0].BlockOwnerDeletion = nil }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := artifactFixture()
			tc.edit(c)
			before := c.DeepCopy()
			p := artifactParent()
			pb := p.DeepCopy()
			if got := artifactOwnedBy(c, p); got != tc.want {
				t.Errorf("owned=%v want %v", got, tc.want)
			}
			if !reflect.DeepEqual(c, before) || !reflect.DeepEqual(p, pb) {
				t.Fatal("ownership check mutated input")
			}
		})
	}
}
