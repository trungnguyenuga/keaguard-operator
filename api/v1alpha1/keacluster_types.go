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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// KeaClusterSpec contains optional desired workload settings. An omitted
// workload remains disabled for metadata-only M1 resources.
type KeaClusterSpec struct {
	// Workload optionally configures the fixed Kea process workload.
	// +optional
	Workload *KeaWorkloadSpec `json:"workload,omitempty"`
}

// KeaWorkloadSpec controls whether the fixed Kea process workload is enabled.
type KeaWorkloadSpec struct {
	// Enabled opts in to managing the Kea process workload.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// LoggingSeverity selects the Kea log threshold; omission is interpreted as INFO.
	// +kubebuilder:validation:Enum=DEBUG;INFO;WARN;ERROR;FATAL;NONE
	// +optional
	LoggingSeverity *string `json:"loggingSeverity,omitempty"`
}

// KeaClusterStatus records artifact observations, not Kea or DHCP availability.
type KeaClusterStatus struct {
	// ObservedGeneration is the generation used for the latest reconciliation
	// result, including unsuccessful observations.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions includes ArtifactReconciled evidence for the internal artifact.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// KeaCluster is the Schema for the keaclusters API
type KeaCluster struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of KeaCluster
	// +optional
	Spec *KeaClusterSpec `json:"spec,omitempty"`

	// status defines the observed state of KeaCluster
	// +optional
	Status KeaClusterStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// KeaClusterList contains a list of KeaCluster
type KeaClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []KeaCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &KeaCluster{}, &KeaClusterList{})
		return nil
	})
}
