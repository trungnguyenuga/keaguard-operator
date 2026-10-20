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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUnitM2Configuration(t *testing.T) {
	if keaDHCP4Image != "docker.cloudsmith.io/isc/docker/kea-dhcp4@sha256:aed0ed10d5d7510b0601a0de2b38ab64976de6b9278cdca9f4b9acbbf1f7e819" || keaDHCP6Image != "docker.cloudsmith.io/isc/docker/kea-dhcp6@sha256:0847044dca2af15f4de93607a98559f16450b6eb16a0ccad476ddc0ac1fd3b07" {
		t.Fatal("Kea images differ from the approved pinned digests")
	}
	severities := []string{"INFO", "DEBUG", "WARN", "ERROR", "FATAL", "NONE"}
	for _, severity := range severities {
		t.Run(severity, func(t *testing.T) {
			got, err := generateKeaConfig(severity)
			if err != nil {
				t.Fatal(err)
			}
			again, err := generateKeaConfig(severity)
			if err != nil {
				t.Fatal(err)
			}
			if got != again {
				t.Fatal("generation is not deterministic")
			}
			for family, data := range map[string][]byte{"4": []byte(got.DHCP4), "6": []byte(got.DHCP6)} {
				if len(data) == 0 || data[len(data)-1] != '\n' || strings.Contains(string(data), "\n\n") {
					t.Fatalf("family %s JSON must be compact and end in one newline: %q", family, data)
				}
				body := strings.TrimSuffix(string(data), "\n")
				var decoded map[string]any
				if err := json.Unmarshal(data, &decoded); err != nil {
					t.Fatal(err)
				}
				canonical, err := json.Marshal(decoded)
				if err != nil {
					t.Fatal(err)
				}
				if string(canonical) != body {
					t.Fatalf("family %s JSON is not compact sorted-key encoding: %s", family, body)
				}
				rootKey := "Dhcp" + family
				if len(decoded) != 1 || decoded[rootKey] == nil {
					t.Fatalf("family %s root keys: %#v", family, decoded)
				}
				root := decoded[rootKey].(map[string]any)
				if family == "4" {
					assertKeys(t, root, "interfaces-config", "subnet4", "lease-database", "valid-lifetime", "loggers")
				} else {
					assertKeys(t, root, "interfaces-config", "subnet6", "lease-database", "server-id", "valid-lifetime", "loggers")
				}
				iface := root["interfaces-config"].(map[string]any)
				if family == "4" {
					assertKeys(t, iface, "interfaces", "dhcp-socket-type")
					if iface["dhcp-socket-type"] != "udp" {
						t.Fatalf("socket type = %v", iface["dhcp-socket-type"])
					}
				} else {
					assertKeys(t, iface, "interfaces")
				}
				interfaces, ok := iface["interfaces"].([]any)
				if !ok || interfaces == nil || len(interfaces) != 0 {
					t.Fatalf("interfaces = %#v", iface["interfaces"])
				}
				subnetKey := "subnet" + family
				subnets, ok := root[subnetKey].([]any)
				if !ok || subnets == nil || len(subnets) != 0 {
					t.Fatalf("%s = %#v", subnetKey, root[subnetKey])
				}
				lease := root["lease-database"].(map[string]any)
				assertKeys(t, lease, "type", "persist", "name")
				wantLease := fmt.Sprintf("/var/lib/kea/state/kea-leases%s.csv", family)
				if lease["type"] != "memfile" || lease["persist"] != true || lease["name"] != wantLease {
					t.Fatalf("lease database = %#v", lease)
				}
				if root["valid-lifetime"] != float64(3600) {
					t.Fatalf("valid lifetime = %v", root["valid-lifetime"])
				}
				loggers := root["loggers"].([]any)
				if len(loggers) != 1 {
					t.Fatalf("loggers = %#v", loggers)
				}
				logger := loggers[0].(map[string]any)
				if severity == "DEBUG" {
					assertKeys(t, logger, "name", "severity", "output-options", "debuglevel")
					if logger["debuglevel"] != float64(99) {
						t.Fatalf("debuglevel = %v", logger["debuglevel"])
					}
				} else {
					assertKeys(t, logger, "name", "severity", "output-options")
				}
				if logger["name"] != "kea-dhcp"+family || logger["severity"] != severity {
					t.Fatalf("logger = %#v", logger)
				}
				outputs := logger["output-options"].([]any)
				if len(outputs) != 1 || outputs[0].(map[string]any)["output"] != "stdout" {
					t.Fatalf("outputs = %#v", outputs)
				}
				if family == "6" {
					serverID := root["server-id"].(map[string]any)
					assertKeys(t, serverID, "type", "persist")
					if serverID["type"] != "EN" || serverID["persist"] != true {
						t.Fatalf("server-id = %#v", serverID)
					}
				}
				for _, forbidden := range []string{"hooks-libraries", "control-socket", "pools", "reservations", "dhcp-ddns"} {
					if strings.Contains(body, forbidden) {
						t.Fatalf("unexpected %q in %s", forbidden, body)
					}
				}
			}
			want4 := sha256.Sum256([]byte(got.DHCP4))
			want6 := sha256.Sum256([]byte(got.DHCP6))
			wantCombinedInput := append([]byte("kea-dhcp4.conf\x00"), []byte(got.DHCP4)...)
			wantCombinedInput = append(wantCombinedInput, 0)
			wantCombinedInput = append(wantCombinedInput, []byte("kea-dhcp6.conf\x00")...)
			wantCombinedInput = append(wantCombinedInput, []byte(got.DHCP6)...)
			combined := sha256.Sum256(wantCombinedInput)
			if got.DHCP4SHA256 != hex.EncodeToString(want4[:]) || got.DHCP6SHA256 != hex.EncodeToString(want6[:]) || got.Hash != hex.EncodeToString(combined[:]) {
				t.Fatalf("hash mismatch: %s", got.Hash)
			}
		})
	}
	cluster := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "sample", Namespace: "lab"}}
	enabled, severity := effectiveWorkload(cluster)
	if enabled || severity != "INFO" {
		t.Fatalf("omitted workload = enabled %t, severity %q", enabled, severity)
	}
	got, err := generateKeaConfig(severity)
	if err != nil {
		t.Fatal(err)
	}
	want4 := []byte("{\"Dhcp4\":{\"interfaces-config\":{\"dhcp-socket-type\":\"udp\",\"interfaces\":[]},\"lease-database\":{\"name\":\"/var/lib/kea/state/kea-leases4.csv\",\"persist\":true,\"type\":\"memfile\"},\"loggers\":[{\"name\":\"kea-dhcp4\",\"output-options\":[{\"output\":\"stdout\"}],\"severity\":\"INFO\"}],\"subnet4\":[],\"valid-lifetime\":3600}}\n")
	want6 := []byte("{\"Dhcp6\":{\"interfaces-config\":{\"interfaces\":[]},\"lease-database\":{\"name\":\"/var/lib/kea/state/kea-leases6.csv\",\"persist\":true,\"type\":\"memfile\"},\"loggers\":[{\"name\":\"kea-dhcp6\",\"output-options\":[{\"output\":\"stdout\"}],\"severity\":\"INFO\"}],\"server-id\":{\"persist\":true,\"type\":\"EN\"},\"subnet6\":[],\"valid-lifetime\":3600}}\n")
	if got.DHCP4 != string(want4) || got.DHCP6 != string(want6) {
		t.Fatalf("omitted severity/default configuration differs from the approved compact JSON:\nDHCP4: %s\nDHCP6: %s", got.DHCP4, got.DHCP6)
	}
	fileHash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	combinedInput := append([]byte("kea-dhcp4.conf\x00"), want4...)
	combinedInput = append(combinedInput, 0)
	combinedInput = append(combinedInput, []byte("kea-dhcp6.conf\x00")...)
	combinedInput = append(combinedInput, want6...)
	if got.DHCP4SHA256 != fileHash(want4) || got.DHCP6SHA256 != fileHash(want6) || got.Hash != fileHash(combinedInput) {
		t.Fatalf("default file/combined hashes do not match independently fixed fixture bytes: %#v", got)
	}
	bad := "TRACE"
	if _, err := generateKeaConfig(bad); err == nil {
		t.Fatal("unsupported severity accepted")
	}
}

func TestUnitM2Names(t *testing.T) {
	tests := []struct{ namespace, name string }{{"default", "kea"}, {"lab.example", "a.b"}, {"ns", strings.Repeat("a", 253)}}
	for _, tt := range tests {
		h := sha256.Sum256([]byte(tt.namespace + "\x00" + tt.name))
		want := hex.EncodeToString(h[:])[:32]
		parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: tt.name, Namespace: tt.namespace}}
		got := namesFor(parent)
		if got.ConfigMap != "kg-"+want+"-config" || got.Service != "kg-"+want+"-headless" || got.StatefulSet != "kg-"+want {
			t.Fatalf("namesFor(%q,%q) = %#v, want hash %s", tt.namespace, tt.name, got, want)
		}
		for _, name := range []string{got.ConfigMap, got.Service, got.StatefulSet} {
			if len(name) > 63 || !validDNSLabel(name) {
				t.Fatalf("invalid bounded resource name %q", name)
			}
		}
	}
	a := namesFor(&infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "same", Namespace: "one"}})
	b := namesFor(&infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "same", Namespace: "two"}})
	if a == b {
		t.Fatal("namespace must contribute to name digest")
	}
	if namesFor(&infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "same", Namespace: "one"}}) != a {
		t.Fatal("UID replacement must not affect deterministic names")
	}
}

func TestUnitM2LaunchContract(t *testing.T) {
	for _, family := range []int{4, 6} {
		familyName := fmt.Sprint(family)
		launch := keaLaunchScript(family)
		wantLaunch := fmt.Sprintf("umask 077\nmkdir -p /run/kea/state /var/lib/kea/state\ncat /etc/kea/kea-dhcp%[1]s.conf > /run/kea/state/kea-dhcp%[1]s.conf.new\nprintf '%%s  %%s\\n' \"$KEA_CONFIG_SHA256\" /run/kea/state/kea-dhcp%[1]s.conf.new | sha256sum -c -\nmv -f /run/kea/state/kea-dhcp%[1]s.conf.new /run/kea/state/kea-dhcp%[1]s.conf\nrm -f /run/kea/state/kea-dhcp%[1]s.kea-dhcp%[1]s.pid\nexec /usr/sbin/kea-dhcp%[1]s -c /run/kea/state/kea-dhcp%[1]s.conf", familyName)
		if launch != wantLaunch {
			t.Fatalf("family %s launcher differs from frozen P05 sequence:\ngot:  %q\nwant: %q", familyName, launch, wantLaunch)
		}
		for _, fragment := range []string{"umask 077", "mkdir -p /run/kea/state /var/lib/kea/state", "cat /etc/kea/kea-dhcp" + familyName + ".conf > /run/kea/state/kea-dhcp" + familyName + ".conf.new", "sha256sum -c -", "mv -f /run/kea/state/kea-dhcp" + familyName + ".conf.new /run/kea/state/kea-dhcp" + familyName + ".conf", "rm -f /run/kea/state/kea-dhcp" + familyName + ".kea-dhcp" + familyName + ".pid", "exec /usr/sbin/kea-dhcp" + familyName + " -c /run/kea/state/kea-dhcp" + familyName + ".conf"} {
			if !strings.Contains(launch, fragment) {
				t.Fatalf("family %s launcher missing %q: %s", familyName, fragment, launch)
			}
		}
		if strings.Contains(launch, " -d") {
			t.Fatalf("family %s launcher enables foreground debug mode: %s", familyName, launch)
		}
		probe := keaProcessProbe(family)
		wantProbe := fmt.Sprintf("test \"$(cat /proc/1/comm)\" = kea-dhcp%[1]s\nread -r pid comm state rest < /proc/1/stat\ncase \"$state\" in R|S|D|I) exit 0;; *) exit 1;; esac", familyName)
		if probe != wantProbe {
			t.Fatalf("family %s probe differs from frozen P05 sequence:\ngot:  %q\nwant: %q", familyName, probe, wantProbe)
		}
		for _, fragment := range []string{`test "$(cat /proc/1/comm)" = kea-dhcp` + familyName, "read -r pid comm state rest < /proc/1/stat", "case \"$state\" in R|S|D|I) exit 0;; *) exit 1;; esac"} {
			if !strings.Contains(probe, fragment) {
				t.Fatalf("family %s probe missing %q: %s", familyName, fragment, probe)
			}
		}
		for _, forbidden := range []string{"/proc/1/exe", "kill -0", "ss ", "nc "} {
			if strings.Contains(probe, forbidden) {
				t.Fatalf("probe contains forbidden %q: %s", forbidden, probe)
			}
		}
	}
}

func assertKeys(t *testing.T, object map[string]any, expected ...string) {
	t.Helper()
	if len(object) != len(expected) {
		t.Fatalf("keys = %#v, want exactly %v", object, expected)
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			t.Fatalf("missing key %q in %#v", key, object)
		}
	}
}
