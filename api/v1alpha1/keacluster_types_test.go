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
	"encoding/json"
	"reflect"
	"testing"
)

// Required spec, placeholder fields or defaults break metadata-only input.
func TestUnitMinimalAPI(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		wantSpec    bool
	}{
		{"omitted", `{"apiVersion":"infrastructure.keaguard.example/v1alpha1","kind":"KeaCluster","metadata":{"name":"minimal","namespace":"api-test"}}`, false},
		{"empty", `{"apiVersion":"infrastructure.keaguard.example/v1alpha1","kind":"KeaCluster","metadata":{"name":"minimal","namespace":"api-test"},"spec":{}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var obj KeaCluster
			if err := json.Unmarshal([]byte(tc.input), &obj); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			spec, exists := got["spec"]
			if exists != tc.wantSpec {
				t.Fatalf("spec presence = %v, want %v: %s", exists, tc.wantSpec, encoded)
			}
			if exists && !reflect.DeepEqual(spec, map[string]any{}) {
				t.Fatalf("spec has unexpected fields: %v", spec)
			}
			if _, exists := got["status"]; exists {
				t.Fatalf("empty status must be omitted: %s", encoded)
			}
		})
	}
	if got := reflect.TypeFor[KeaClusterSpec]().NumField(); got != 0 {
		t.Errorf("spec has %d fields, want none", got)
	}
}
