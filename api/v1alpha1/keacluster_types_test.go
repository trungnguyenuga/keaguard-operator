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
	specType := reflect.TypeFor[KeaClusterSpec]()
	if specType.NumField() != 1 {
		t.Fatalf("spec has %d fields, want only optional workload", specType.NumField())
	}
	workload, ok := specType.FieldByName("Workload")
	if !ok || workload.Type.Kind() != reflect.Pointer || workload.Type.Elem().Name() != "KeaWorkloadSpec" || workload.Tag.Get("json") != "workload,omitempty" {
		t.Fatalf("workload field = %#v, want *KeaWorkloadSpec `json:\"workload,omitempty\"`", workload)
	}
	workloadType := workload.Type.Elem()
	if workloadType.NumField() != 2 {
		t.Fatalf("KeaWorkloadSpec has %d fields, want enabled and loggingSeverity", workloadType.NumField())
	}
	enabled, ok := workloadType.FieldByName("Enabled")
	if !ok || enabled.Type.Kind() != reflect.Bool || enabled.Tag.Get("json") != "enabled,omitempty" {
		t.Fatalf("enabled field = %#v, want optional bool", enabled)
	}
	severity, ok := workloadType.FieldByName("LoggingSeverity")
	if !ok || severity.Type.Kind() != reflect.Pointer || severity.Type.Elem().Kind() != reflect.String || severity.Tag.Get("json") != "loggingSeverity,omitempty" {
		t.Fatalf("loggingSeverity field = %#v, want optional *string", severity)
	}
}

func TestUnitM2API(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want map[string]any
	}{
		{name: "absent-workload", json: `{"spec":{}}`, want: map[string]any{}},
		{name: "empty-workload", json: `{"spec":{"workload":{}}}`, want: map[string]any{"workload": map[string]any{}}},
		{name: "disabled", json: `{"spec":{"workload":{"enabled":false}}}`, want: map[string]any{"workload": map[string]any{}}},
		{name: "enabled", json: `{"spec":{"workload":{"enabled":true}}}`, want: map[string]any{"workload": map[string]any{"enabled": true}}},
		{name: "severity-omitted", json: `{"spec":{"workload":{"enabled":true}}}`, want: map[string]any{"workload": map[string]any{"enabled": true}}},
		{name: "severity-empty", json: `{"spec":{"workload":{"loggingSeverity":""}}}`, want: map[string]any{"workload": map[string]any{"loggingSeverity": ""}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var obj KeaCluster
			if err := json.Unmarshal([]byte(tc.json), &obj); err != nil {
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
			if spec, ok := got["spec"]; !ok || !reflect.DeepEqual(spec, tc.want) {
				t.Fatalf("round-trip spec = %#v, want %#v", spec, tc.want)
			}
		})
	}

	input := `{"apiVersion":"infrastructure.keaguard.example/v1alpha1","kind":"KeaCluster","metadata":{"name":"m2-api","namespace":"api-test"},"spec":{"workload":{"enabled":true,"loggingSeverity":"INFO"}}}`
	var obj KeaCluster
	if err := json.Unmarshal([]byte(input), &obj); err != nil {
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
	want := map[string]any{"workload": map[string]any{"enabled": true, "loggingSeverity": "INFO"}}
	spec, ok := got["spec"].(map[string]any)
	if !ok || !reflect.DeepEqual(spec, want) {
		t.Fatalf("round-trip spec = %#v, want %#v", spec, want)
	}

	workload := reflect.ValueOf(obj.Spec).Elem().FieldByName("Workload")
	if !workload.IsValid() || workload.IsNil() {
		t.Fatal("workload pointer was not retained")
	}
	severity := workload.Elem().FieldByName("LoggingSeverity")
	if !severity.IsValid() || severity.IsNil() {
		t.Fatal("loggingSeverity pointer was not retained")
	}
	copy := obj.DeepCopy()
	severity.Elem().SetString("ERROR")
	copyBytes, err := json.Marshal(copy)
	if err != nil {
		t.Fatal(err)
	}
	var copied map[string]any
	if err := json.Unmarshal(copyBytes, &copied); err != nil {
		t.Fatal(err)
	}
	copiedSpec := copied["spec"].(map[string]any)
	if !reflect.DeepEqual(copiedSpec, want) {
		t.Fatalf("deep copy changed with source severity: got %#v, want %#v", copiedSpec, want)
	}

	var empty KeaCluster
	if err := json.Unmarshal([]byte(`{"apiVersion":"infrastructure.keaguard.example/v1alpha1","kind":"KeaCluster","metadata":{"name":"empty","namespace":"api-test"},"spec":{"workload":{"loggingSeverity":""}}}`), &empty); err != nil {
		t.Fatal(err)
	}
	emptyWorkload := reflect.ValueOf(empty.Spec).Elem().FieldByName("Workload")
	if !emptyWorkload.IsValid() || emptyWorkload.IsNil() {
		t.Fatal("explicitly empty workload was not retained")
	}
	emptySeverity := emptyWorkload.Elem().FieldByName("LoggingSeverity")
	if !emptySeverity.IsValid() || emptySeverity.IsNil() || emptySeverity.Elem().String() != "" {
		t.Fatal("explicitly empty severity must remain distinguishable from omission")
	}
}
