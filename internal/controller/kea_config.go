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

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	validation "k8s.io/apimachinery/pkg/util/validation"
)

const (
	keaDHCP4Image = "docker.cloudsmith.io/isc/docker/kea-dhcp4@sha256:aed0ed10d5d7510b0601a0de2b38ab64976de6b9278cdca9f4b9acbbf1f7e819"
	keaDHCP6Image = "docker.cloudsmith.io/isc/docker/kea-dhcp6@sha256:0847044dca2af15f4de93607a98559f16450b6eb16a0ccad476ddc0ac1fd3b07"
)

type workloadNames struct {
	ConfigMap   string
	Service     string
	StatefulSet string
}

type workloadConfig struct {
	DHCP4       string
	DHCP6       string
	DHCP4SHA256 string
	DHCP6SHA256 string
	Hash        string
}

func effectiveWorkload(parent *infrastructurev1alpha1.KeaCluster) (enabled bool, severity string) {
	if parent == nil || parent.Spec == nil || parent.Spec.Workload == nil {
		return false, "INFO"
	}
	severity = "INFO"
	if parent.Spec.Workload.LoggingSeverity != nil {
		severity = *parent.Spec.Workload.LoggingSeverity
	}
	return parent.Spec.Workload.Enabled, severity
}

func namesFor(parent *infrastructurev1alpha1.KeaCluster) workloadNames {
	sum := sha256.Sum256([]byte(parent.Namespace + "\x00" + parent.Name))
	h := hex.EncodeToString(sum[:])[:32]
	return workloadNames{ConfigMap: "kg-" + h + "-config", Service: "kg-" + h + "-headless", StatefulSet: "kg-" + h}
}

func validDNSLabel(value string) bool { return len(validation.IsDNS1123Label(value)) == 0 }

func generateKeaConfig(severity string) (workloadConfig, error) {
	switch severity {
	case "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE":
	default:
		return workloadConfig{}, fmt.Errorf("unsupported Kea logging severity %q", severity)
	}
	logger := func(family string) map[string]any {
		entry := map[string]any{"name": "kea-dhcp" + family, "severity": severity, "output-options": []any{map[string]any{"output": "stdout"}}}
		if severity == "DEBUG" {
			entry["debuglevel"] = 99
		}
		return entry
	}
	lease := func(family string) map[string]any {
		return map[string]any{"type": "memfile", "persist": true, "name": "/var/lib/kea/state/kea-leases" + family + ".csv"}
	}
	dhcp4 := map[string]any{"Dhcp4": map[string]any{
		"interfaces-config": map[string]any{"interfaces": []any{}, "dhcp-socket-type": "udp"},
		"subnet4":           []any{}, "lease-database": lease("4"), "valid-lifetime": 3600, "loggers": []any{logger("4")},
	}}
	dhcp6 := map[string]any{"Dhcp6": map[string]any{
		"interfaces-config": map[string]any{"interfaces": []any{}}, "subnet6": []any{},
		"lease-database": lease("6"), "server-id": map[string]any{"type": "EN", "persist": true},
		"valid-lifetime": 3600, "loggers": []any{logger("6")},
	}}
	encode := func(value any) ([]byte, error) {
		data, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			return nil, marshalErr
		}
		return append(data, '\n'), nil
	}
	file4, err := encode(dhcp4)
	if err != nil {
		return workloadConfig{}, err
	}
	file6, err := encode(dhcp6)
	if err != nil {
		return workloadConfig{}, err
	}
	fileHash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	combined := make([]byte, 0, len(file4)+len(file6)+32)
	combined = append(combined, "kea-dhcp4.conf\x00"...)
	combined = append(combined, file4...)
	combined = append(combined, 0)
	combined = append(combined, "kea-dhcp6.conf\x00"...)
	combined = append(combined, file6...)
	return workloadConfig{DHCP4: string(file4), DHCP6: string(file6), DHCP4SHA256: fileHash(file4), DHCP6SHA256: fileHash(file6), Hash: fileHash(combined)}, nil
}

func keaLaunchScript(family int) string {
	return fmt.Sprintf("umask 077\nmkdir -p /run/kea/state /var/lib/kea/state\ncat /etc/kea/kea-dhcp%[1]d.conf > /run/kea/state/kea-dhcp%[1]d.conf.new\nprintf '%%s  %%s\\n' \"$KEA_CONFIG_SHA256\" /run/kea/state/kea-dhcp%[1]d.conf.new | sha256sum -c -\nmv -f /run/kea/state/kea-dhcp%[1]d.conf.new /run/kea/state/kea-dhcp%[1]d.conf\nrm -f /run/kea/state/kea-dhcp%[1]d.kea-dhcp%[1]d.pid\nexec /usr/sbin/kea-dhcp%[1]d -c /run/kea/state/kea-dhcp%[1]d.conf", family)
}

func keaProcessProbe(family int) string {
	return fmt.Sprintf("test \"$(cat /proc/1/comm)\" = kea-dhcp%[1]d\nread -r pid comm state rest < /proc/1/stat\ncase \"$state\" in R|S|D|I) exit 0;; *) exit 1;; esac", family)
}
