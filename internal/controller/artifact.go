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
	"bytes"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
)

const (
	artifactLabel   = "keaguard.example/artifact"
	artifactPurpose = "keaguard.example/purpose"
)

func desiredArtifact(parent *infrastructurev1alpha1.KeaCluster) *corev1.ConfigMap {
	controller, blockDeletion := true, false
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: parent.Name, Namespace: parent.Namespace,
			Labels:          map[string]string{artifactLabel: "reconciliation"},
			Annotations:     map[string]string{artifactPurpose: "Internal reconciliation artifact; not operational Kea DHCP configuration."},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: parent.Name, UID: parent.UID, Controller: &controller, BlockOwnerDeletion: &blockDeletion}},
		},
		Data: map[string]string{"keacluster-name": parent.Name, "keacluster-namespace": parent.Namespace, "keacluster-uid": string(parent.UID)},
	}
}

func artifactOwnedBy(actual *corev1.ConfigMap, parent *infrastructurev1alpha1.KeaCluster) bool {
	var owner *metav1.OwnerReference
	for i := range actual.OwnerReferences {
		ref := &actual.OwnerReferences[i]
		if ref.Controller != nil && *ref.Controller {
			if owner != nil {
				return false
			}
			owner = ref
		}
	}
	return owner != nil && owner.APIVersion == infrastructurev1alpha1.GroupVersion.String() &&
		owner.Kind == "KeaCluster" && owner.Name == parent.Name && owner.UID == parent.UID
}

func managedFieldsEqual(actual, desired *corev1.ConfigMap) bool {
	return maps.Equal(actual.Data, desired.Data) && maps.EqualFunc(actual.BinaryData, desired.BinaryData, bytes.Equal) &&
		actual.Labels[artifactLabel] == desired.Labels[artifactLabel] && actual.Annotations[artifactPurpose] == desired.Annotations[artifactPurpose]
}

// setManagedFields changes only managed fields on the caller's deep copy.
func setManagedFields(target, desired *corev1.ConfigMap) {
	target.Data = maps.Clone(desired.Data)
	target.BinaryData = maps.Clone(desired.BinaryData)
	for key, value := range target.BinaryData {
		target.BinaryData[key] = slices.Clone(value)
	}
	if target.Labels == nil {
		target.Labels = make(map[string]string)
	}
	target.Labels[artifactLabel] = desired.Labels[artifactLabel]
	if target.Annotations == nil {
		target.Annotations = make(map[string]string)
	}
	target.Annotations[artifactPurpose] = desired.Annotations[artifactPurpose]
}
