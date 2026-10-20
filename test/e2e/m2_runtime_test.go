/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var m2RuntimeSeverityCases = []string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE"}

var _ = func() bool {
	if selectedProfile.milestone != "m2" {
		return true
	}
	Describe("M2: Runtime", func() {
		for _, severity := range m2RuntimeSeverityCases {
			severity := severity
			m2It("runs both real Kea parsers for severity "+severity, func() {
				m2RunRuntimeCase(severity, true)
			})
		}

		m2It("verifies both workloads, security, filesystem and closed networking", func() {
			m2RunRuntimeCase("INFO", false)
		})
	})

	Describe("M2: Logging NONE", func() {
		m2It("starts four healthy processes with loggingSeverity NONE", func() {
			parent, pods, config, set := m2CreateRuntimeFixture("NONE", 120*time.Second)
			m2WaitRuntimeConditions(parent, config.Hash)
			identities, tooling := m2VerifyRuntimeContainers(parent, pods, config, set, true)
			initialRestarts := m2RestartCounts(pods)
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				for _, pod := range pods {
					for _, name := range []string{"dhcp4", "dhcp6"} {
						family := "4"
						if name == "dhcp6" {
							family = "6"
						}
						probe := "test \"$(cat /proc/1/comm)\" = kea-dhcp" + family + "; read -r pid comm state rest < /proc/1/stat; case \"$state\" in R|S|D|I) exit 0;; *) exit 1;; esac"
						Expect(m2Exec(pod.Name, name, probe)).To(Succeed())
					}
				}
				current := m2GetPods(parent)
				Expect(m2SamePodIncarnations(pods, current)).To(Succeed())
				Expect(m2RestartCounts(current)).To(Equal(initialRestarts))
				m2VerifyRuntimeConditions(parent, config.Hash)
				pods = current
				time.Sleep(4 * time.Second)
			}
			Expect(identities).To(HaveLen(4))
			m2VerifyRuntimeConditions(parent, config.Hash)
			m2WriteRuntimeReceipt(parent, pods, config, identities, tooling)
		})
	})
	return true
}()

func m2RunRuntimeCase(severity string, runParsers bool) {
	parent, pods, config, set := m2CreateRuntimeFixture(severity, 120*time.Second)
	m2WaitRuntimeConditions(parent, config.Hash)
	identities, tooling := m2VerifyRuntimeContainers(parent, pods, config, set, severity == "INFO" && !runParsers)
	if runParsers {
		for _, container := range []string{"dhcp4", "dhcp6"} {
			binary, snapshot := "/usr/sbin/kea-dhcp4", "/run/kea/state/kea-dhcp4.conf"
			if container == "dhcp6" {
				binary, snapshot = "/usr/sbin/kea-dhcp6", "/run/kea/state/kea-dhcp6.conf"
			}
			out, err := m2ExecOutput(pods[0].Name, container, binary, "-t", snapshot)
			Expect(err).NotTo(HaveOccurred(), "%s -t rejected actual %s snapshot: %s", binary, severity, m2RedactEvidence(string(out)))
		}
		m2WriteRuntimeReceipt(parent, pods, config, identities, tooling)
		return
	}
	m2WriteRuntimeReceipt(parent, pods, config, identities, tooling)
}

func m2CreateRuntimeFixture(severity string, wait time.Duration) (*infrastructurev1alpha1.KeaCluster, []corev1.Pod, m2RuntimeConfig, appsv1.StatefulSet) {
	Expect(m2ActiveScenario).NotTo(BeNil())
	Expect(m2ScenarioHasAdmissionReserve(m2SuiteStart, time.Now())).To(BeTrue())
	Expect(m2VerifyNamespaceReceipt(labctx)).To(Succeed())
	parent := cr("", runtimeNamespace)
	parent.GenerateName = "runtime-" + strings.ToLower(severity) + "-"
	parent.Spec = &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true, LoggingSeverity: &severity}}
	Expect(m2CreateObject(labctx, parent, nil)).To(Succeed())
	configName, _, setName := m2NamesFor(parent)
	var configMap corev1.ConfigMap
	var set appsv1.StatefulSet
	var service corev1.Service
	var pods []corev1.Pod
	Eventually(func(g Gomega) {
		g.Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, &configMap)).To(Succeed())
		g.Expect(configMap.UID).NotTo(BeEmpty())
		g.Expect(metav1.IsControlledBy(&configMap, parent)).To(BeTrue())
		g.Expect(configMap.Labels["keaguard.example/cluster-uid"]).To(Equal(string(parent.UID)))
		g.Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, &set)).To(Succeed())
		g.Expect(set.UID).NotTo(BeEmpty())
		g.Expect(metav1.IsControlledBy(&set, parent)).To(BeTrue())
		_, serviceName, _ := m2NamesFor(parent)
		g.Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: serviceName}, &service)).To(Succeed())
		g.Expect(service.UID).NotTo(BeEmpty())
		g.Expect(metav1.IsControlledBy(&service, parent)).To(BeTrue())
		g.Expect(service.Spec.Ports).To(BeEmpty())
		g.Expect(service.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
		g.Expect(service.Spec.ClusterIP).To(Equal(corev1.ClusterIPNone))
		g.Expect(service.Spec.Selector).To(Equal(map[string]string{"keaguard.example/cluster-uid": string(parent.UID)}))
		g.Expect(service.Spec.ExternalIPs).To(BeEmpty())
		g.Expect(service.Spec.ExternalName).To(BeEmpty())
		list := &corev1.PodList{}
		g.Expect(admin.List(labctx, list, client.InNamespace(runtimeNamespace), client.MatchingLabels{"keaguard.example/cluster-uid": string(parent.UID)})).To(Succeed())
		g.Expect(list.Items).To(HaveLen(2))
		pods = append([]corev1.Pod(nil), list.Items...)
		sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })
		g.Expect(set.Status.ObservedGeneration).To(Equal(set.Generation))
		g.Expect(set.Status.ReadyReplicas).To(Equal(int32(2)))
		g.Expect(set.Status.CurrentReplicas).To(Equal(int32(2)))
		for _, pod := range pods {
			g.Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
			g.Expect(metav1.IsControlledBy(&pod, &set)).To(BeTrue())
			g.Expect(pod.Status.ContainerStatuses).To(HaveLen(2))
			for _, status := range pod.Status.ContainerStatuses {
				g.Expect(status.Ready).To(BeTrue())
				g.Expect(status.State.Running).NotTo(BeNil())
				g.Expect(status.ImageID).NotTo(BeEmpty())
			}
		}
	}, wait, time.Second).Should(Succeed())
	config := m2RuntimeConfig{files: map[string][]byte{
		"kea-dhcp4.conf": []byte(configMap.Data["kea-dhcp4.conf"]),
		"kea-dhcp6.conf": []byte(configMap.Data["kea-dhcp6.conf"]),
	}, severity: severity}
	Expect(config.files["kea-dhcp4.conf"]).NotTo(BeEmpty())
	Expect(config.files["kea-dhcp6.conf"]).NotTo(BeEmpty())
	config.file4 = m2SHA256(config.files["kea-dhcp4.conf"])
	config.file6 = m2SHA256(config.files["kea-dhcp6.conf"])
	combined := append([]byte("kea-dhcp4.conf\x00"), config.files["kea-dhcp4.conf"]...)
	combined = append(combined, 0)
	combined = append(combined, []byte("kea-dhcp6.conf\x00")...)
	combined = append(combined, config.files["kea-dhcp6.conf"]...)
	config.Hash = m2SHA256(combined)
	Expect(set.Spec.Template.Annotations["keaguard.example/config-hash"]).To(Equal(config.Hash))
	for _, item := range []struct{ name, family, hash string }{{"kea-dhcp4.conf", "Dhcp4", config.file4}, {"kea-dhcp6.conf", "Dhcp6", config.file6}} {
		Expect(m2ConfigSeverity(config.files[item.name])).To(Equal(severity))
		m2VerifyConfigContract(config.files[item.name], item.family, severity)
	}
	return parent, pods, config, set
}

type m2RuntimeConfig struct {
	files              map[string][]byte
	severity           string
	file4, file6, Hash string
}

func m2VerifyRuntimeContainers(parent *infrastructurev1alpha1.KeaCluster, pods []corev1.Pod, config m2RuntimeConfig, set appsv1.StatefulSet, full bool) ([]m2ProcessIdentity, map[string]m2RuntimeNodeTooling) {
	Expect(pods).To(HaveLen(2))
	Expect(set.Spec.Replicas).NotTo(BeNil())
	Expect(*set.Spec.Replicas).To(Equal(int32(2)))
	Expect(set.Spec.PodManagementPolicy).To(Equal(appsv1.OrderedReadyPodManagement))
	Expect(set.Spec.VolumeClaimTemplates).To(BeEmpty())
	Expect(set.Spec.Template.Spec.HostNetwork).To(BeFalse())
	Expect(set.Spec.Template.Spec.ServiceAccountName).To(Equal("default"))
	Expect(set.Spec.Template.Spec.AutomountServiceAccountToken).NotTo(BeNil())
	Expect(*set.Spec.Template.Spec.AutomountServiceAccountToken).To(BeFalse())
	Expect(set.Spec.Template.Spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution).To(HaveLen(1))
	anti := set.Spec.Template.Spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]
	Expect(anti.Weight).To(Equal(int32(100)))
	Expect(anti.PodAffinityTerm.TopologyKey).To(Equal("kubernetes.io/hostname"))
	Expect(set.Spec.Template.Spec.Containers).To(HaveLen(2))
	Expect(set.Spec.Template.Spec.Volumes).To(HaveLen(5))
	Expect(set.Spec.Template.Spec.SecurityContext.FSGroup).NotTo(BeNil())
	Expect(*set.Spec.Template.Spec.SecurityContext.FSGroup).To(Equal(int64(101)))
	for _, volume := range set.Spec.Template.Spec.Volumes {
		if volume.EmptyDir != nil {
			Expect(volume.EmptyDir.SizeLimit).NotTo(BeNil())
			if volume.EmptyDir.SizeLimit != nil {
				Expect(volume.EmptyDir.SizeLimit.String()).To(Equal("16Mi"))
			}
		}
	}
	volumeByName := make(map[string]corev1.Volume, len(set.Spec.Template.Spec.Volumes))
	for _, volume := range set.Spec.Template.Spec.Volumes {
		volumeByName[volume.Name] = volume
	}
	for _, name := range []string{"runtime4", "data4", "runtime6", "data6"} {
		volume, ok := volumeByName[name]
		Expect(ok).To(BeTrue())
		if ok {
			Expect(volume.EmptyDir).NotTo(BeNil())
			Expect(volume.ConfigMap).To(BeNil())
			Expect(volume.Secret).To(BeNil())
			Expect(volume.HostPath).To(BeNil())
			Expect(volume.PersistentVolumeClaim).To(BeNil())
		}
	}
	configVolume, ok := volumeByName["configuration"]
	Expect(ok).To(BeTrue())
	if ok {
		Expect(configVolume.ConfigMap).NotTo(BeNil())
		Expect(configVolume.Secret).To(BeNil())
		Expect(configVolume.HostPath).To(BeNil())
		if configVolume.ConfigMap != nil {
			Expect(configVolume.ConfigMap.Optional).NotTo(BeNil())
			if configVolume.ConfigMap.Optional != nil {
				Expect(*configVolume.ConfigMap.Optional).To(BeFalse())
			}
			Expect(configVolume.ConfigMap.DefaultMode).NotTo(BeNil())
			if configVolume.ConfigMap.DefaultMode != nil {
				Expect(*configVolume.ConfigMap.DefaultMode).To(Equal(int32(0444)))
			}
			Expect(configVolume.ConfigMap.Items).To(ConsistOf(corev1.KeyToPath{Key: "kea-dhcp4.conf", Path: "kea-dhcp4.conf"}, corev1.KeyToPath{Key: "kea-dhcp6.conf", Path: "kea-dhcp6.conf"}))
		}
	}
	identities := make([]m2ProcessIdentity, 0, 4)
	tooling := make(map[string]m2RuntimeNodeTooling)
	for _, pod := range pods {
		Expect(pod.Spec.NodeName).To(BeElementOf(m2LabProfile.nodes[1:]))
		Expect(pod.Spec.HostNetwork).To(BeFalse())
		Expect(pod.Spec.Volumes).NotTo(ContainElement(HaveField("HostPath", Not(BeNil()))))
		Expect(pod.Spec.Volumes).NotTo(ContainElement(HaveField("PersistentVolumeClaim", Not(BeNil()))))
		Expect(pod.Spec.Volumes).NotTo(ContainElement(HaveField("Secret", Not(BeNil()))))
		Expect(pod.Spec.Containers).To(HaveLen(2))
		Expect(pod.Spec.Containers[0].Ports).To(BeEmpty())
		Expect(pod.Spec.Containers[1].Ports).To(BeEmpty())
		for _, family := range []struct {
			name, image, bin, snapshot, cap string
			bound                           uint64
		}{
			{"dhcp4", m2KeaDHCP4Image, "/usr/sbin/kea-dhcp4", "/run/kea/state/kea-dhcp4.conf", "0x2400", 0x2400},
			{"dhcp6", m2KeaDHCP6Image, "/usr/sbin/kea-dhcp6", "/run/kea/state/kea-dhcp6.conf", "0x400", 0x400},
		} {
			identity, err := m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pod), family.name)
			Expect(err).NotTo(HaveOccurred())
			Expect(identity.KeaClusterUID).To(Equal(parent.UID))
			Expect(identity.ImageID).NotTo(BeEmpty())
			identities = append(identities, identity)
			Expect(m2VerifyKeaCRIIdentity(identity, family.image)).To(Succeed())
			if full {
				Expect(m2CheckCtrCNI(labctx, identity, m2Command)).To(Succeed())
				if _, recorded := tooling[identity.NodeName]; !recorded {
					tooling[identity.NodeName] = m2ReadRuntimeNodeTooling(identity)
				}
			}
			var observedStatus *corev1.ContainerStatus
			for i := range pod.Status.ContainerStatuses {
				if pod.Status.ContainerStatuses[i].Name == family.name {
					observedStatus = &pod.Status.ContainerStatuses[i]
				}
			}
			Expect(observedStatus).NotTo(BeNil())
			if observedStatus != nil {
				Expect(observedStatus.ContainerID).To(Equal(identity.ContainerID))
				Expect(observedStatus.ImageID).To(Equal(identity.ImageID))
			}
			var spec *corev1.Container
			for i := range pod.Spec.Containers {
				if pod.Spec.Containers[i].Name == family.name {
					spec = &pod.Spec.Containers[i]
					break
				}
			}
			Expect(spec).NotTo(BeNil())
			if spec != nil {
				Expect(spec.Image).To(Equal(family.image))
				Expect(spec.Ports).To(BeEmpty())
				Expect(spec.SecurityContext).NotTo(BeNil())
				if spec.SecurityContext != nil {
					Expect(spec.SecurityContext.AllowPrivilegeEscalation).NotTo(BeNil())
					Expect(*spec.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
					Expect(spec.SecurityContext.ReadOnlyRootFilesystem).NotTo(BeNil())
					Expect(*spec.SecurityContext.ReadOnlyRootFilesystem).To(BeTrue())
					Expect(spec.SecurityContext.Capabilities.Drop).To(ConsistOf(corev1.Capability("ALL")))
					wantCaps := []corev1.Capability{"NET_BIND_SERVICE"}
					if family.name == "dhcp4" {
						wantCaps = append(wantCaps, "NET_RAW")
					}
					Expect(spec.SecurityContext.Capabilities.Add).To(ConsistOf(wantCaps))
				}
				mounts := map[string]corev1.VolumeMount{}
				for _, mount := range spec.VolumeMounts {
					mounts[mount.Name] = mount
				}
				wantRuntime, wantData := "runtime4", "data4"
				if family.name == "dhcp6" {
					wantRuntime, wantData = "runtime6", "data6"
				}
				Expect(mounts[wantRuntime].MountPath).To(Equal("/run/kea"))
				Expect(mounts[wantData].MountPath).To(Equal("/var/lib/kea"))
				Expect(mounts["configuration"].MountPath).To(Equal("/etc/kea"))
				Expect(mounts["configuration"].ReadOnly).To(BeTrue())
				Expect(spec.Resources.Requests.Cpu().String()).To(Equal("100m"))
				Expect(spec.Resources.Requests.Memory().String()).To(Equal("64Mi"))
				Expect(spec.Resources.Limits.Memory().String()).To(Equal("128Mi"))
			}
			version, err := m2ExecOutput(pod.Name, family.name, family.bin, "-V")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(version)).To(ContainSubstring("3.2.1"))
			comm, err := m2ExecOutput(pod.Name, family.name, "cat", "/proc/1/comm")
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(string(comm))).To(Equal(filepath.Base(family.bin)))
			cmdline, err := m2ExecOutput(pod.Name, family.name, "cat", "/proc/1/cmdline")
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")).To(Equal([]string{family.bin, "-c", family.snapshot}))
			status, err := m2ExecOutput(pod.Name, family.name, "cat", "/proc/1/status")
			Expect(err).NotTo(HaveOccurred())
			parsed, err := m2ParseProcSecurityStatus(status)
			Expect(err).NotTo(HaveOccurred())
			Expect(parsed.CapEff).To(BeZero())
			Expect(parsed.CapPrm).To(BeZero())
			Expect(parsed.CapInh).To(BeZero())
			Expect(parsed.CapAmb).To(BeZero())
			Expect(parsed.CapBnd).To(Equal(family.bound))
			Expect(parsed.NoNewPrivs).To(Equal(uint64(1)))
			Expect(parsed.Seccomp).To(Equal(uint64(2)))
			fmt.Fprintf(GinkgoWriter, "M2_RUNTIME_PROCESS pod=%s podUID=%s node=%s nodeUID=%s nodeContainer=%s container=%s task=%s hostPID=%d startTicks=%d pidNS=%d NSpid=%v image=%s imageID=%s comm=%s argv=%q version=%q uid=%d gid=%d CapInh=%#x CapPrm=%#x CapEff=%#x CapBnd=%#x CapAmb=%#x NoNewPrivs=%d Seccomp=%d\n",
				pod.Name, identity.PodUID, identity.NodeName, identity.NodeUID, identity.NodeContainerID, identity.ContainerID, identity.TaskID,
				identity.HostPID, identity.StartTicks, identity.PIDNamespaceInode, identity.NSpid, family.image, identity.ImageID,
				strings.TrimSpace(string(comm)), identity.Argv, strings.TrimSpace(string(version)), identity.UID, identity.GID,
				parsed.CapInh, parsed.CapPrm, parsed.CapEff, parsed.CapBnd, parsed.CapAmb, parsed.NoNewPrivs, parsed.Seccomp)
			Expect(m2Exec(pod.Name, family.name, "test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token")).To(Succeed())
			m2VerifyRuntimeFiles(pod.Name, family.name, family.snapshot, config, family.name, parent)
			if full {
				m2VerifyNoListeners(pod.Name, family.name)
			}
		}
		podSecurity := pod.Spec.SecurityContext
		Expect(podSecurity).NotTo(BeNil())
		if podSecurity != nil {
			Expect(podSecurity.RunAsUser).NotTo(BeNil())
			if podSecurity.RunAsUser != nil {
				Expect(*podSecurity.RunAsUser).To(Equal(int64(100)))
			}
			Expect(podSecurity.RunAsGroup).NotTo(BeNil())
			if podSecurity.RunAsGroup != nil {
				Expect(*podSecurity.RunAsGroup).To(Equal(int64(101)))
			}
			Expect(podSecurity.RunAsNonRoot).NotTo(BeNil())
			if podSecurity.RunAsNonRoot != nil {
				Expect(*podSecurity.RunAsNonRoot).To(BeTrue())
			}
			Expect(podSecurity.SeccompProfile).NotTo(BeNil())
			if podSecurity.SeccompProfile != nil {
				Expect(podSecurity.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault))
			}
		}
		if full {
			m2VerifyPodNetworkShape(pod)
		}
	}
	if full {
		m2VerifyCrossPodMarkers(pods)
	}
	return identities, tooling
}

type m2RuntimeNodeTooling struct {
	DockerID      string `json:"dockerID"`
	CTRVersion    string `json:"ctrVersion"`
	CRICTLVersion string `json:"crictlVersion"`
	CNIAbsent     bool   `json:"cniAbsent"`
}

func m2ReadRuntimeNodeTooling(identity m2ProcessIdentity) m2RuntimeNodeTooling {
	ctr, err := m2Command(labctx, "docker", "exec", identity.NodeContainerID, "ctr", "version")
	Expect(err).NotTo(HaveOccurred())
	crictl, err := m2Command(labctx, "docker", "exec", identity.NodeContainerID, "crictl", "version")
	Expect(err).NotTo(HaveOccurred())
	Expect(string(ctr)).To(ContainSubstring("2.3.4"))
	Expect(string(crictl)).To(ContainSubstring("0.1.0"))
	record := m2RuntimeNodeTooling{DockerID: identity.NodeContainerID, CTRVersion: strings.TrimSpace(string(ctr)), CRICTLVersion: strings.TrimSpace(string(crictl)), CNIAbsent: true}
	fmt.Fprintf(GinkgoWriter, "M2_RUNTIME_NODE_TOOLING node=%s dockerID=%s ctr=%q crictl=%q CNIAbsent=%t\n", identity.NodeName, record.DockerID, record.CTRVersion, record.CRICTLVersion, record.CNIAbsent)
	return record
}

func m2VerifyKeaCRIIdentity(identity m2ProcessIdentity, image string) error {
	out, err := m2Command(labctx, "docker", "exec", identity.NodeContainerID, "crictl", "inspecti", "-o", "json", image)
	if err != nil {
		return err
	}
	var record struct {
		Status struct {
			ID          string   `json:"id"`
			RepoDigests []string `json:"repoDigests"`
			RepoTags    []string `json:"repoTags"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &record); err != nil {
		return err
	}
	if err := m2CheckKeaCRIIdentity(record.Status.ID, identity.ImageID, image, record.Status.RepoDigests); err != nil {
		return err
	}
	return nil
}

func m2KeaExpectedConfigID(image string) (string, bool) {
	// These exact config digests were derived from and cryptographically tied
	// to the approved repository manifests by the preserved T14 OCI audit.
	// CRI status.id is the config digest; Pod imageID is a manifest reference.
	switch image {
	case m2KeaDHCP4Image:
		return "sha256:edf856f99936b2e0318908ec7fa321eb1b0e7d980abcfaa2e09689849505f5e0", true
	case m2KeaDHCP6Image:
		return "sha256:86c615fdb2a111632178e0b99bd4430a58fca509f7b9048c6f01ba457366d123", true
	default:
		return "", false
	}
}

func m2CheckKeaCRIIdentity(configID, podImageID, expectedImage string, repoDigests []string) error {
	expectedConfigID, known := m2KeaExpectedConfigID(expectedImage)
	if !known {
		return fmt.Errorf("Kea image reference is not one of the approved immutable images")
	}
	if podImageID != expectedImage {
		return fmt.Errorf("Pod imageID is not the exact approved repository manifest reference: got %q want %q", podImageID, expectedImage)
	}
	if configID != expectedConfigID {
		return fmt.Errorf("CRI image config ID does not match the independently attested OCI manifest config: got %q want %q", configID, expectedConfigID)
	}
	exactRefs := 0
	for _, ref := range repoDigests {
		if ref == expectedImage {
			exactRefs++
		}
	}
	if exactRefs != 1 {
		return fmt.Errorf("CRI image has %d exact approved repository digest references; want one", exactRefs)
	}
	return nil
}

func m2VerifyRuntimeFiles(pod, container, snapshot string, config m2RuntimeConfig, family string, parent *infrastructurev1alpha1.KeaCluster) {
	runtimeMode, err := m2ExecOutput(pod, container, "stat", "-c", "%u|%g|%a", "/run/kea/state")
	Expect(err).NotTo(HaveOccurred())
	Expect(m2CheckRuntimeDirMode(string(runtimeMode))).To(Succeed())
	dataMode, err := m2ExecOutput(pod, container, "stat", "-c", "%u|%g|%a", "/var/lib/kea/state")
	Expect(err).NotTo(HaveOccurred())
	Expect(m2CheckRuntimeDirMode(string(dataMode))).To(Succeed())
	_, err = m2ExecOutput(pod, container, "sh", "-ec", "command -v touch >/dev/null && test -d /etc && if touch /etc/.m2-root-write-probe 2>/dev/null; then rm -f /etc/.m2-root-write-probe; exit 1; else exit 0; fi")
	Expect(err).NotTo(HaveOccurred())
	Expect(m2Exec(pod, container, "test -w /run/kea/state && test -w /var/lib/kea/state")).To(Succeed())
	mounted := strings.TrimPrefix(snapshot, "/run/kea/state/")
	actual, err := m2ExecOutput(pod, container, "cat", snapshot)
	Expect(err).NotTo(HaveOccurred())
	want := config.files[mounted]
	Expect(m2SHA256(actual)).To(Equal(m2SHA256(want)))
	projected, err := m2ExecOutput(pod, container, "cat", "/etc/kea/"+mounted)
	Expect(err).NotTo(HaveOccurred())
	Expect(m2SHA256(projected)).To(Equal(m2SHA256(want)))
	before, err := m2ObserveProcess(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: pod}, container)
	Expect(err).NotTo(HaveOccurred())
	var observedPod corev1.Pod
	Expect(m2GetSnapshot(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: pod}, &observedPod)).To(Succeed())
	configName, _, _ := m2NamesFor(parent)
	Expect(m2CheckProjectedConfigPodShape(observedPod, before, configName)).To(Succeed())
	projection, err := m2ExecOutput(pod, container, "sh", "-ec", m2ProjectedConfigInspectScript, "m2-projection", "/etc/kea", mounted)
	Expect(err).NotTo(HaveOccurred())
	after, err := m2ObserveProcess(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: pod}, container)
	Expect(err).NotTo(HaveOccurred())
	Expect(m2CheckSameProcessIncarnation(before, after)).To(Succeed())
	Expect(m2CheckProjectedConfigObservation(projection, "/etc/kea", mounted, m2SHA256(want))).To(Succeed())
	fmt.Fprintf(GinkgoWriter, "M2_PROJECTED_FILE_VERIFIED pod=%s uid=%s container=%s containerID=%s imageID=%s configMap=%s targetMode=0444 expectedSHA256=%s observation=%q\n",
		pod, before.PodUID, container, before.ContainerID, before.ImageID, configName, m2SHA256(want), string(projection))
	Expect(m2Exec(pod, container, "test ! -w /etc/kea/"+mounted)).To(Succeed())
	marker := "m2-" + family + "-" + strings.ToLower(pod)
	Expect(m2Exec(pod, container, "sh", "-ec", "printf '%s' "+marker+" > /var/lib/kea/state/"+marker)).To(Succeed())
	Expect(m2Exec(pod, container, "sh", "-ec", "printf '%s' "+marker+" > /run/kea/state/"+marker)).To(Succeed())
	fmt.Fprintf(GinkgoWriter, "M2_RUNTIME_FILES pod=%s container=%s runtimeDir=%q dataDir=%q rootWriteDenied=true configTargetMode=0444 projectedSHA256=%s snapshotSHA256=%s marker=%s\n",
		pod, container, strings.TrimSpace(string(runtimeMode)), strings.TrimSpace(string(dataMode)), m2SHA256(projected), m2SHA256(actual), marker)
}

const m2ProjectedConfigInspectScript = `set -eu
root=$1
key=$2
p=$root/$key
stat -c 'FILE_BEFORE|%F|%a|%u|%g|%d|%i' "$p"
printf 'FILE_LINK_BEFORE|'; readlink "$p"
stat -c 'DATA_BEFORE|%F|%a|%u|%g|%d|%i' "$root/..data"
printf 'DATA_LINK_BEFORE|'; readlink "$root/..data"
printf 'TARGET_PATH|'; readlink -f "$p"
stat -L -c 'TARGET_BEFORE|%F|%a|%u|%g|%d|%i' "$p"
sum=$(sha256sum "$p")
printf 'HASH|%s\n' "${sum%% *}"
stat -L -c 'TARGET_AFTER|%F|%a|%u|%g|%d|%i' "$p"
stat -c 'FILE_AFTER|%F|%a|%u|%g|%d|%i' "$p"
printf 'FILE_LINK_AFTER|'; readlink "$p"
stat -c 'DATA_AFTER|%F|%a|%u|%g|%d|%i' "$root/..data"
printf 'DATA_LINK_AFTER|'; readlink "$root/..data"`

type m2ProjectedFileMeta struct {
	fileType string
	mode     uint64
	uid      uint64
	gid      uint64
	device   uint64
	inode    uint64
}

func m2ParseProjectedFileMeta(line, label string) (m2ProjectedFileMeta, error) {
	fields := strings.Split(line, "|")
	if len(fields) != 7 || fields[0] != label || fields[1] == "" {
		return m2ProjectedFileMeta{}, fmt.Errorf("malformed %s metadata", label)
	}
	mode, err := strconv.ParseUint(fields[2], 8, 32)
	if err != nil {
		return m2ProjectedFileMeta{}, fmt.Errorf("invalid %s mode: %w", label, err)
	}
	values := [4]uint64{}
	for i := range values {
		values[i], err = strconv.ParseUint(fields[i+3], 10, 64)
		if err != nil {
			return m2ProjectedFileMeta{}, fmt.Errorf("invalid %s identity field: %w", label, err)
		}
	}
	if values[3] == 0 {
		return m2ProjectedFileMeta{}, fmt.Errorf("%s has no inode identity", label)
	}
	return m2ProjectedFileMeta{fileType: fields[1], mode: mode, uid: values[0], gid: values[1], device: values[2], inode: values[3]}, nil
}

func m2CheckProjectedConfigObservation(output []byte, root, key, expectedHash string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || (key != "kea-dhcp4.conf" && key != "kea-dhcp6.conf") || len(expectedHash) != 64 || strings.ToLower(expectedHash) != expectedHash {
		return fmt.Errorf("projected file expectation is not the approved absolute configuration path/hash")
	}
	if _, err := hex.DecodeString(expectedHash); err != nil {
		return fmt.Errorf("projected file expected hash is malformed: %w", err)
	}
	if len(output) == 0 || output[len(output)-1] != '\n' || strings.ContainsAny(string(output), "\x00\r") {
		return fmt.Errorf("projected file inspection output is incomplete or malformed")
	}
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) != 12 {
		return fmt.Errorf("projected file inspection has %d lines, want 12", len(lines))
	}
	fileBefore, err := m2ParseProjectedFileMeta(lines[0], "FILE_BEFORE")
	if err != nil {
		return err
	}
	dataBefore, err := m2ParseProjectedFileMeta(lines[2], "DATA_BEFORE")
	if err != nil {
		return err
	}
	targetBefore, err := m2ParseProjectedFileMeta(lines[5], "TARGET_BEFORE")
	if err != nil {
		return err
	}
	targetAfter, err := m2ParseProjectedFileMeta(lines[7], "TARGET_AFTER")
	if err != nil {
		return err
	}
	fileAfter, err := m2ParseProjectedFileMeta(lines[8], "FILE_AFTER")
	if err != nil {
		return err
	}
	dataAfter, err := m2ParseProjectedFileMeta(lines[10], "DATA_AFTER")
	if err != nil {
		return err
	}
	if fileBefore.fileType != "symbolic link" || fileBefore.mode != 0777 || dataBefore.fileType != "symbolic link" || dataBefore.mode != 0777 || targetBefore.fileType != "regular file" || targetBefore.mode != 0444 {
		return fmt.Errorf("projected file link/target type or target mode differs from approved 0444 atomic-writer shape")
	}
	if fileBefore != fileAfter || dataBefore != dataAfter || targetBefore != targetAfter {
		return fmt.Errorf("projected file link, data link or target identity changed during inspection")
	}
	if lines[1] != "FILE_LINK_BEFORE|..data/"+key || lines[9] != "FILE_LINK_AFTER|..data/"+key {
		return fmt.Errorf("projected file symlink does not target the required key through ..data")
	}
	const dataPrefix = "DATA_LINK_BEFORE|"
	if !strings.HasPrefix(lines[3], dataPrefix) {
		return fmt.Errorf("projected ..data symlink target is absent")
	}
	dataTarget := strings.TrimPrefix(lines[3], dataPrefix)
	if !strings.HasPrefix(dataTarget, "..") || len(dataTarget) <= 2 || dataTarget == "..data" || filepath.Base(dataTarget) != dataTarget || filepath.Clean(dataTarget) != dataTarget || strings.ContainsAny(dataTarget, "\\|\n") || lines[11] != "DATA_LINK_AFTER|"+dataTarget {
		return fmt.Errorf("projected ..data symlink is replaced or escapes its mount")
	}
	if lines[4] != "TARGET_PATH|"+filepath.Join(root, dataTarget, key) {
		return fmt.Errorf("resolved projected target escapes the expected mount/version/key")
	}
	if lines[6] != "HASH|"+expectedHash {
		return fmt.Errorf("projected target content hash differs from generated configuration")
	}
	return nil
}

func m2CheckProjectedConfigPodShape(pod corev1.Pod, identity m2ProcessIdentity, expectedConfigMap string) error {
	if identity.PodUID == "" || identity.ContainerID == "" || identity.ImageID == "" || expectedConfigMap == "" || pod.Namespace != identity.PodKey.Namespace || pod.Name != identity.PodKey.Name || pod.UID != identity.PodUID || pod.Spec.NodeName != identity.NodeName {
		return fmt.Errorf("projected file Pod UID/node or ConfigMap source identity changed")
	}
	wantImage := m2KeaDHCP4Image
	if identity.ContainerName == "dhcp6" {
		wantImage = m2KeaDHCP6Image
	} else if identity.ContainerName != "dhcp4" {
		return fmt.Errorf("projected file container name is unsupported")
	}
	volumes := 0
	for _, volume := range pod.Spec.Volumes {
		if volume.Name != "configuration" {
			continue
		}
		volumes++
		source := volume.ConfigMap
		if source == nil || source.Name != expectedConfigMap || source.DefaultMode == nil || *source.DefaultMode != 0444 || source.Optional == nil || *source.Optional || len(source.Items) != 2 {
			return fmt.Errorf("projected file ConfigMap source/defaultMode differs from approved shape")
		}
		keys := map[string]bool{}
		for _, item := range source.Items {
			if item.Key != item.Path || (item.Key != "kea-dhcp4.conf" && item.Key != "kea-dhcp6.conf") || item.Mode != nil || item.User != nil || keys[item.Key] {
				return fmt.Errorf("projected file ConfigMap key mapping differs from approved shape")
			}
			keys[item.Key] = true
		}
		if !keys["kea-dhcp4.conf"] || !keys["kea-dhcp6.conf"] {
			return fmt.Errorf("projected file ConfigMap keys are incomplete")
		}
	}
	if volumes != 1 {
		return fmt.Errorf("projected file ConfigMap volume is missing or duplicated")
	}
	containers, statuses := 0, 0
	for _, c := range pod.Spec.Containers {
		if c.Name != identity.ContainerName {
			continue
		}
		containers++
		if c.Image != wantImage {
			return fmt.Errorf("projected file container image differs from approved digest")
		}
		mounts := 0
		for _, mount := range c.VolumeMounts {
			if mount.Name == "configuration" || mount.MountPath == "/etc/kea" {
				mounts++
				if mount.Name != "configuration" || mount.MountPath != "/etc/kea" || !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" {
					return fmt.Errorf("projected file mount is not the approved read-only whole volume")
				}
			}
		}
		if mounts != 1 {
			return fmt.Errorf("projected file mount is missing or duplicated")
		}
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == identity.ContainerName {
			statuses++
			if status.ContainerID != identity.ContainerID || status.ImageID != identity.ImageID {
				return fmt.Errorf("projected file container incarnation/imageID changed")
			}
		}
	}
	if containers != 1 || statuses != 1 {
		return fmt.Errorf("projected file container specification/status is missing or duplicated")
	}
	return nil
}

func m2CheckSameProcessIncarnation(before, after m2ProcessIdentity) error {
	before.State, after.State = "", ""
	if !reflect.DeepEqual(before, after) {
		return fmt.Errorf("projected file Pod/container/task/process identity changed during inspection")
	}
	return nil
}

func m2VerifyCrossPodMarkers(pods []corev1.Pod) {
	for _, source := range pods {
		for _, sourceContainer := range []string{"dhcp4", "dhcp6"} {
			for _, target := range pods {
				for _, container := range []string{"dhcp4", "dhcp6"} {
					if source.UID == target.UID && sourceContainer == container {
						continue
					}
					marker := "m2-" + sourceContainer + "-" + strings.ToLower(source.Name)
					Expect(m2Exec(target.Name, container, "test ! -e /var/lib/kea/state/"+marker)).To(Succeed())
					Expect(m2Exec(target.Name, container, "test ! -e /run/kea/state/"+marker)).To(Succeed())
				}
			}
		}
	}
}

func m2VerifyNoListeners(pod, container string) {
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		out, err := m2ExecOutput(pod, container, "sh", "-ec", "awk 'NR>1 {print}' /proc/net/"+table)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(out))).To(BeEmpty(), "unexpected socket row in /proc/net/%s: %s", table, out)
	}
	for _, path := range []string{"/run/kea/state/kea-dhcp4.kea-dhcp4.pid", "/run/kea/state/kea-dhcp6.kea-dhcp6.pid"} {
		Expect(m2Exec(pod, container, "test ! -S "+path)).To(Succeed())
	}
	unix, err := m2ExecOutput(pod, container, "sh", "-ec", "awk 'NR>1 && /kea/ {print}' /proc/net/unix")
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(string(unix))).To(BeEmpty(), "unexpected Kea Unix socket")
}

func m2VerifyPodNetworkShape(before corev1.Pod) {
	var current corev1.Pod
	Expect(m2GetSnapshot(labctx, client.ObjectKeyFromObject(&before), &current)).To(Succeed())
	Expect(m2CheckPodNetworkShape(before, current)).To(Succeed())
}

func m2CheckPodNetworkShape(before, current corev1.Pod) error {
	if before.Namespace == "" || before.Name == "" || before.UID == "" || before.Spec.NodeName == "" ||
		current.Namespace != before.Namespace || current.Name != before.Name || current.UID != before.UID || current.Spec.NodeName != before.Spec.NodeName {
		return fmt.Errorf("Pod identity changed during network-shape inspection")
	}
	if current.Spec.HostNetwork || current.Spec.HostPID || current.Spec.HostIPC ||
		(current.Spec.ShareProcessNamespace != nil && *current.Spec.ShareProcessNamespace) ||
		current.Spec.ServiceAccountName != "default" || current.Spec.AutomountServiceAccountToken == nil || *current.Spec.AutomountServiceAccountToken {
		return fmt.Errorf("Pod uses forbidden host namespace or service-account token setting")
	}
	if len(current.Spec.InitContainers) != 0 || len(current.Spec.EphemeralContainers) != 0 || len(current.Spec.Containers) != 2 ||
		len(before.Status.ContainerStatuses) != 2 || len(current.Status.ContainerStatuses) != 2 {
		return fmt.Errorf("unexpected Pod container shape")
	}
	for _, name := range []string{"dhcp4", "dhcp6"} {
		var prior, now *corev1.ContainerStatus
		var container *corev1.Container
		for i := range before.Status.ContainerStatuses {
			if before.Status.ContainerStatuses[i].Name == name {
				prior = &before.Status.ContainerStatuses[i]
			}
		}
		for i := range current.Status.ContainerStatuses {
			if current.Status.ContainerStatuses[i].Name == name {
				now = &current.Status.ContainerStatuses[i]
			}
		}
		for i := range current.Spec.Containers {
			if current.Spec.Containers[i].Name == name {
				container = &current.Spec.Containers[i]
			}
		}
		if prior == nil || now == nil || container == nil || prior.ContainerID == "" || prior.ImageID == "" ||
			now.ContainerID != prior.ContainerID || now.ImageID != prior.ImageID || len(container.Ports) != 0 {
			return fmt.Errorf("%s container incarnation or port shape changed", name)
		}
	}
	for _, volume := range current.Spec.Volumes {
		if volume.HostPath != nil || volume.PersistentVolumeClaim != nil || volume.Secret != nil {
			return fmt.Errorf("forbidden Pod volume %s", volume.Name)
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.ServiceAccountToken != nil {
					return fmt.Errorf("service-account token projection in volume %s", volume.Name)
				}
			}
		}
	}
	return nil
}

func m2Exec(pod, container string, command string, args ...string) error {
	if len(args) == 0 {
		command, args = "sh", []string{"-ec", command}
	}
	_, err := m2ExecOutput(pod, container, command, args...)
	return err
}

func m2ExecOutput(pod, container string, command string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(labctx, 8*time.Second)
	defer cancel()
	kubectlArgs := []string{"exec", pod, "-n", runtimeNamespace, "-c", container, "--", command}
	kubectlArgs = append(kubectlArgs, args...)
	return kubectl(ctx, kubectlArgs...)
}

func m2SHA256(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func m2ConfigSeverity(data []byte) string {
	var value map[string]any
	Expect(json.Unmarshal(data, &value)).To(Succeed())
	for _, family := range []string{"Dhcp4", "Dhcp6"} {
		root, ok := value[family].(map[string]any)
		if !ok {
			continue
		}
		loggers, ok := root["loggers"].([]any)
		Expect(ok).To(BeTrue())
		Expect(loggers).To(HaveLen(1))
		logger, ok := loggers[0].(map[string]any)
		Expect(ok).To(BeTrue())
		Expect(logger["severity"]).NotTo(BeEmpty())
		if logger["severity"] == "DEBUG" {
			Expect(logger["debuglevel"]).To(Equal(float64(99)))
		} else {
			Expect(logger).NotTo(HaveKey("debuglevel"))
		}
		return logger["severity"].(string)
	}
	Fail("configuration has no recognized Kea family root")
	return ""
}

func m2VerifyConfigContract(data []byte, family, severity string) {
	var document map[string]any
	Expect(json.Unmarshal(data, &document)).To(Succeed())
	Expect(document).To(HaveLen(1))
	root, ok := document[family].(map[string]any)
	Expect(ok).To(BeTrue())
	if !ok {
		return
	}
	interfaces, ok := root["interfaces-config"].(map[string]any)
	Expect(ok).To(BeTrue())
	if ok {
		list, exists := interfaces["interfaces"].([]any)
		Expect(exists).To(BeTrue())
		if exists {
			Expect(list).To(BeEmpty())
		}
	}
	Expect(root).NotTo(HaveKey("control-socket"))
	Expect(root).NotTo(HaveKey("control-sockets"))
	subnetKey := "subnet4"
	if family == "Dhcp6" {
		subnetKey = "subnet6"
	}
	subnets, exists := root[subnetKey].([]any)
	Expect(exists).To(BeTrue())
	if exists {
		Expect(subnets).To(BeEmpty())
	}
	lease, ok := root["lease-database"].(map[string]any)
	Expect(ok).To(BeTrue())
	if ok {
		Expect(lease["type"]).To(Equal("memfile"))
		Expect(lease["persist"]).To(BeTrue())
		Expect(lease["name"]).To(ContainSubstring("/var/lib/kea/state/kea-leases"))
	}
	loggers, ok := root["loggers"].([]any)
	Expect(ok).To(BeTrue())
	if ok && len(loggers) == 1 {
		logger, valid := loggers[0].(map[string]any)
		Expect(valid).To(BeTrue())
		if valid {
			Expect(logger["severity"]).To(Equal(severity))
			if severity == "DEBUG" {
				Expect(logger["debuglevel"]).To(Equal(float64(99)))
			} else {
				Expect(logger).NotTo(HaveKey("debuglevel"))
			}
			outputs, validOutputs := logger["output-options"].([]any)
			Expect(validOutputs).To(BeTrue())
			if validOutputs {
				Expect(outputs).To(HaveLen(1))
				if len(outputs) == 1 {
					item, mapOK := outputs[0].(map[string]any)
					Expect(mapOK).To(BeTrue())
					if mapOK {
						Expect(item["output"]).To(Equal("stdout"))
					}
				}
			}
		}
	}
}

func m2RestartCounts(pods []corev1.Pod) map[string]int32 {
	result := map[string]int32{}
	for _, pod := range pods {
		for _, status := range pod.Status.ContainerStatuses {
			result[pod.Name+"/"+status.Name] = status.RestartCount
		}
	}
	return result
}

func m2CheckRuntimeDirMode(output string) error {
	fields := strings.Split(strings.TrimSpace(output), "|")
	if len(fields) != 3 || fields[0] != "100" || fields[1] != "101" {
		return fmt.Errorf("runtime state directory owner is not 100:101: %q", output)
	}
	mode, err := strconv.ParseUint(fields[2], 8, 32)
	if err != nil {
		return err
	}
	if mode != 0700 && mode != 02700 {
		return fmt.Errorf("runtime state directory access mode is not private 0700: %q", fields[2])
	}
	return nil
}

func m2GetPods(parent *infrastructurev1alpha1.KeaCluster) []corev1.Pod {
	list := &corev1.PodList{}
	Expect(admin.List(labctx, list, client.InNamespace(parent.Namespace), client.MatchingLabels{"keaguard.example/cluster-uid": string(parent.UID)})).To(Succeed())
	return list.Items
}

func m2SamePodIncarnations(before, after []corev1.Pod) error {
	if len(before) != 2 || len(after) != 2 {
		return fmt.Errorf("workload Pod set changed cardinality")
	}
	byName := map[string]types.UID{}
	for _, pod := range before {
		byName[pod.Name] = pod.UID
	}
	for _, pod := range after {
		if byName[pod.Name] == "" || byName[pod.Name] != pod.UID {
			return fmt.Errorf("workload Pod incarnation changed during NONE stability interval")
		}
	}
	return nil
}

func m2VerifyRuntimeConditions(parent *infrastructurev1alpha1.KeaCluster, hash string) {
	current := &infrastructurev1alpha1.KeaCluster{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(parent), current)).To(Succeed())
	Expect(current.UID).To(Equal(parent.UID))
	Expect(current.Status.ObservedGeneration).To(Equal(current.Generation))
	for kind, reason := range map[string]string{"ArtifactReconciled": "ArtifactInSync", "WorkloadReconciled": "ResourcesInSync", "WorkloadReady": "ProcessesHealthy"} {
		condition := meta.FindStatusCondition(current.Status.Conditions, kind)
		Expect(condition).NotTo(BeNil())
		if condition != nil {
			Expect(condition.Status).To(Equal(metav1.ConditionTrue))
			Expect(condition.Reason).To(Equal(reason))
			Expect(condition.ObservedGeneration).To(Equal(current.Generation))
		}
	}
	_, _, setName := m2NamesFor(parent)
	set := &appsv1.StatefulSet{}
	Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, set)).To(Succeed())
	Expect(set.Spec.Template.Annotations["keaguard.example/config-hash"]).To(Equal(hash))
}

func m2RuntimeConditionsCurrent(parent, current *infrastructurev1alpha1.KeaCluster) error {
	if current.UID != parent.UID || current.Status.ObservedGeneration != current.Generation {
		return fmt.Errorf("KeaCluster identity or observed generation is not current")
	}
	for kind, reason := range map[string]string{"ArtifactReconciled": "ArtifactInSync", "WorkloadReconciled": "ResourcesInSync", "WorkloadReady": "ProcessesHealthy"} {
		condition := meta.FindStatusCondition(current.Status.Conditions, kind)
		if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != reason || condition.ObservedGeneration != current.Generation {
			return fmt.Errorf("condition %s is not current %s", kind, reason)
		}
	}
	return nil
}

func m2WaitRuntimeConditions(parent *infrastructurev1alpha1.KeaCluster, hash string) {
	Eventually(func() error {
		current := &infrastructurev1alpha1.KeaCluster{}
		if err := admin.Get(labctx, client.ObjectKeyFromObject(parent), current); err != nil {
			return err
		}
		if err := m2RuntimeConditionsCurrent(parent, current); err != nil {
			return err
		}
		_, _, setName := m2NamesFor(parent)
		set := &appsv1.StatefulSet{}
		if err := admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, set); err != nil {
			return err
		}
		if set.Spec.Template.Annotations["keaguard.example/config-hash"] != hash {
			return errors.New("StatefulSet config hash is not current")
		}
		return nil
	}, 90*time.Second, time.Second).Should(Succeed())
}

func m2WriteRuntimeReceipt(parent *infrastructurev1alpha1.KeaCluster, pods []corev1.Pod, config m2RuntimeConfig, identities []m2ProcessIdentity, tooling ...map[string]m2RuntimeNodeTooling) {
	if m2ActiveScenario == nil || m2ActiveScenario.caseID == "" {
		Fail("runtime evidence lacks registered scenario identity")
		return
	}
	record := struct {
		CaseID          string                          `json:"caseID"`
		CR              m2FixtureIdentity               `json:"keaCluster"`
		OperatorImage   string                          `json:"operatorImage"`
		OperatorImageID string                          `json:"operatorImageID"`
		Severity        string                          `json:"severity"`
		FileHashes      map[string]string               `json:"fileHashes"`
		CombinedHash    string                          `json:"combinedHash"`
		NodeTooling     map[string]m2RuntimeNodeTooling `json:"nodeTooling,omitempty"`
		Pods            []struct {
			Name     string           `json:"name"`
			UID      types.UID        `json:"uid"`
			Node     string           `json:"node"`
			Restarts map[string]int32 `json:"restarts"`
		} `json:"pods"`
		Processes []m2ProcessIdentity `json:"processes"`
	}{CaseID: m2ActiveScenario.caseID, OperatorImage: m2ActiveScenario.ExpectedImage, OperatorImageID: m2ActiveScenario.ExpectedImageID, Severity: config.severity, FileHashes: map[string]string{"kea-dhcp4.conf": config.file4, "kea-dhcp6.conf": config.file6}, CombinedHash: config.Hash, Processes: identities}
	if len(tooling) > 0 {
		record.NodeTooling = tooling[0]
	}
	identity, err := m2IdentityFor(parent)
	Expect(err).NotTo(HaveOccurred())
	record.CR = identity
	for _, pod := range pods {
		record.Pods = append(record.Pods, struct {
			Name     string           `json:"name"`
			UID      types.UID        `json:"uid"`
			Node     string           `json:"node"`
			Restarts map[string]int32 `json:"restarts"`
		}{pod.Name, pod.UID, pod.Spec.NodeName, m2RestartCounts([]corev1.Pod{pod})})
	}
	data, err := json.Marshal(record)
	Expect(err).NotTo(HaveOccurred())
	path := filepath.Join(m2ActiveScenario.evidenceDir, "runtime-observation-"+m2ActiveScenario.caseID+".json")
	if _, err := os.Lstat(path); err == nil {
		Fail("runtime evidence path already exists")
		return
	} else if !os.IsNotExist(err) {
		Expect(err).NotTo(HaveOccurred())
		return
	}
	Expect(writePrivateReceipt(path, append(data, '\n'))).To(Succeed())
}

func TestUnitM2RuntimeDirectoryMode(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{{"100|101|700", true}, {"100|101|2700", true}, {"100|101|770", false}, {"101|101|700", false}, {"100|102|700", false}, {"100|101|2770", false}, {"100|101|4700", false}, {"100|101|700junk", false}, {"bad", false}} {
		err := m2CheckRuntimeDirMode(tc.out)
		if (err == nil) != tc.want {
			t.Errorf("m2CheckRuntimeDirMode(%q) err=%v want success=%t", tc.out, err, tc.want)
		}
	}
}

func TestUnitM2KeaCRIIdentity(t *testing.T) {
	for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
		wantConfigID, ok := m2KeaExpectedConfigID(image)
		if !ok {
			t.Fatalf("missing independently verified pinned config identity for %s", image)
		}
		if err := m2CheckKeaCRIIdentity(wantConfigID, image, image, []string{image}); err != nil {
			t.Errorf("valid repository manifest -> config identity rejected for %s: %v", image, err)
		}
		wrongReference := m2KeaDHCP4Image
		if image == m2KeaDHCP4Image {
			wrongReference = m2KeaDHCP6Image
		}
		for name, tc := range map[string]struct {
			configID, podImageID, image string
			repoDigests                 []string
		}{
			"wrong config digest":             {configID: "sha256:" + strings.Repeat("f", 64), podImageID: image, image: image, repoDigests: []string{image}},
			"wrong pod manifest reference":    {configID: wantConfigID, podImageID: wrongReference, image: image, repoDigests: []string{image}},
			"missing exact repository digest": {configID: wantConfigID, podImageID: image, image: image, repoDigests: nil},
			"unapproved image reference":      {configID: wantConfigID, podImageID: image, image: "example.invalid/kea@sha256:" + strings.Repeat("a", 64), repoDigests: []string{image}},
		} {
			t.Run(name, func(t *testing.T) {
				if err := m2CheckKeaCRIIdentity(tc.configID, tc.podImageID, tc.image, tc.repoDigests); err == nil {
					t.Fatalf("accepted inconsistent Kea OCI/CRI identities: %+v", tc)
				}
			})
		}
	}
}
