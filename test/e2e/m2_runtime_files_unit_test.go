/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/
package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const m2ProjectionKey = "kea-dhcp4.conf"
const m2ProjectionBytes = "approved generated configuration\n"

func m2ProjectionFixture(t *testing.T, mode os.FileMode) string {
	t.Helper()
	root := t.TempDir()
	version := filepath.Join(root, "..2026_10_19_00_00_00.000000000")
	if err := os.Mkdir(version, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(version, m2ProjectionKey)
	if err := os.WriteFile(target, []byte(m2ProjectionBytes), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(version), filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/"+m2ProjectionKey, filepath.Join(root, m2ProjectionKey)); err != nil {
		t.Fatal(err)
	}
	return root
}

func m2RunProjectionInspection(t *testing.T, root string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("sh", "-ec", m2ProjectedConfigInspectScript, "m2-projection", root, m2ProjectionKey)
	return cmd.CombinedOutput()
}

func TestUnitM2ProjectedConfigObservation(t *testing.T) {
	wantHash := m2SHA256([]byte(m2ProjectionBytes))
	t.Run("atomic writer symlink 0777 resolves to regular target 0444", func(t *testing.T) {
		root := m2ProjectionFixture(t, 0444)
		link, err := os.Lstat(filepath.Join(root, m2ProjectionKey))
		if err != nil || link.Mode()&os.ModeSymlink == 0 || link.Mode().Perm() != 0777 {
			t.Fatalf("fixture symlink mode = %v, err = %v", link.Mode(), err)
		}
		out, err := m2RunProjectionInspection(t, root)
		if err != nil {
			t.Fatalf("inspect valid projection: %v: %s", err, out)
		}
		if err := m2CheckProjectedConfigObservation(out, root, m2ProjectionKey, wantHash); err != nil {
			t.Fatalf("reject valid projection: %v\n%s", err, out)
		}
	})
	for _, mode := range []os.FileMode{0644, 0777} {
		t.Run("reject target mode "+mode.String(), func(t *testing.T) {
			root := m2ProjectionFixture(t, mode)
			out, err := m2RunProjectionInspection(t, root)
			if err != nil {
				t.Fatalf("inspect fixture: %v: %s", err, out)
			}
			if err := m2CheckProjectedConfigObservation(out, root, m2ProjectionKey, wantHash); err == nil {
				t.Fatal("accepted target mode other than 0444")
			}
		})
	}
	t.Run("reject broken symlink", func(t *testing.T) {
		root := m2ProjectionFixture(t, 0444)
		if err := os.Remove(filepath.Join(root, "..data")); err != nil {
			t.Fatal(err)
		}
		if out, err := m2RunProjectionInspection(t, root); err == nil {
			t.Fatalf("inspected broken projection: %s", out)
		}
	})
	t.Run("reject escaped target", func(t *testing.T) {
		root := m2ProjectionFixture(t, 0444)
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, m2ProjectionKey), []byte(m2ProjectionBytes), 0444); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "..data")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "..data")); err != nil {
			t.Fatal(err)
		}
		out, err := m2RunProjectionInspection(t, root)
		if err != nil {
			t.Fatalf("inspect escaped fixture: %v: %s", err, out)
		}
		if err := m2CheckProjectedConfigObservation(out, root, m2ProjectionKey, wantHash); err == nil {
			t.Fatal("accepted target outside projected mount")
		}
	})
	t.Run("reject target directory", func(t *testing.T) {
		root := m2ProjectionFixture(t, 0444)
		target := filepath.Join(root, "..2026_10_19_00_00_00.000000000", m2ProjectionKey)
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(target, 0444); err != nil {
			t.Fatal(err)
		}
		if out, err := m2RunProjectionInspection(t, root); err == nil {
			t.Fatalf("inspected target directory: %s", out)
		}
	})
	t.Run("reject wrong content", func(t *testing.T) {
		root := m2ProjectionFixture(t, 0444)
		out, err := m2RunProjectionInspection(t, root)
		if err != nil {
			t.Fatal(err)
		}
		if err := m2CheckProjectedConfigObservation(out, root, m2ProjectionKey, m2SHA256([]byte("different\n"))); err == nil {
			t.Fatal("accepted incorrect ConfigMap content")
		}
	})
	t.Run("reject data symlink replacement", func(t *testing.T) {
		root := m2ProjectionFixture(t, 0444)
		before, err := m2RunProjectionInspection(t, root)
		if err != nil {
			t.Fatal(err)
		}
		version := filepath.Join(root, "..2026_10_19_00_00_01.000000000")
		if err := os.Mkdir(version, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(version, m2ProjectionKey), []byte(m2ProjectionBytes), 0444); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "..data")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(version), filepath.Join(root, "..data")); err != nil {
			t.Fatal(err)
		}
		after, err := m2RunProjectionInspection(t, root)
		if err != nil {
			t.Fatal(err)
		}
		mixed := m2MixProjectedObservationHalves(t, before, after)
		if err := m2CheckProjectedConfigObservation(mixed, root, m2ProjectionKey, wantHash); err == nil {
			t.Fatal("accepted data symlink replacement during inspection")
		}
	})
	t.Run("reject target replacement with stable link", func(t *testing.T) {
		root := m2ProjectionFixture(t, 0444)
		before, err := m2RunProjectionInspection(t, root)
		if err != nil {
			t.Fatal(err)
		}
		version := filepath.Join(root, "..2026_10_19_00_00_00.000000000")
		replacement := filepath.Join(version, "replacement")
		if err := os.WriteFile(replacement, []byte(m2ProjectionBytes), 0444); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, filepath.Join(version, m2ProjectionKey)); err != nil {
			t.Fatal(err)
		}
		after, err := m2RunProjectionInspection(t, root)
		if err != nil {
			t.Fatal(err)
		}
		mixed := m2MixProjectedObservationHalves(t, before, after)
		if err := m2CheckProjectedConfigObservation(mixed, root, m2ProjectionKey, wantHash); err == nil {
			t.Fatal("accepted replaced target inode during inspection")
		}
	})
}

func m2MixProjectedObservationHalves(t *testing.T, before, after []byte) []byte {
	t.Helper()
	first := strings.Split(strings.TrimSpace(string(before)), "\n")
	second := strings.Split(strings.TrimSpace(string(after)), "\n")
	if len(first) != 12 || len(second) != 12 {
		t.Fatalf("unexpected inspection line count before=%d after=%d", len(first), len(second))
	}
	copy(first[7:], second[7:])
	return []byte(strings.Join(first, "\n") + "\n")
}

func TestUnitM2ProjectedConfigPodShape(t *testing.T) {
	mode, optional := int32(0444), false
	identity := m2ProcessIdentity{PodKey: client.ObjectKey{Namespace: "keaguard-m2-runtime", Name: "pod-0"}, PodUID: types.UID("pod-uid"), NodeName: "node-1", ContainerName: "dhcp4", ContainerID: "containerd://full-id", ImageID: m2KeaDHCP4Image}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: identity.PodKey.Namespace, Name: identity.PodKey.Name, UID: identity.PodUID}, Spec: corev1.PodSpec{NodeName: identity.NodeName,
		Volumes:    []corev1.Volume{{Name: "configuration", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "approved-config"}, DefaultMode: &mode, Optional: &optional, Items: []corev1.KeyToPath{{Key: "kea-dhcp4.conf", Path: "kea-dhcp4.conf"}, {Key: "kea-dhcp6.conf", Path: "kea-dhcp6.conf"}}}}}},
		Containers: []corev1.Container{{Name: "dhcp4", Image: m2KeaDHCP4Image, VolumeMounts: []corev1.VolumeMount{{Name: "configuration", MountPath: "/etc/kea", ReadOnly: true}}}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "dhcp4", ContainerID: identity.ContainerID, ImageID: identity.ImageID}}}}
	if err := m2CheckProjectedConfigPodShape(pod, identity, "approved-config"); err != nil {
		t.Fatalf("reject valid Pod shape: %v", err)
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"wrong Pod UID":      func(p *corev1.Pod) { p.UID = "replaced" },
		"wrong container ID": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID = "containerd://replaced" },
		"wrong image":        func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "wrong" },
		"writable mount":     func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts[0].ReadOnly = false },
		"wrong default mode": func(p *corev1.Pod) { wrong := int32(0644); p.Spec.Volumes[0].ConfigMap.DefaultMode = &wrong },
	} {
		t.Run(name, func(t *testing.T) {
			changed := pod.DeepCopy()
			mutate(changed)
			if err := m2CheckProjectedConfigPodShape(*changed, identity, "approved-config"); err == nil {
				t.Fatal("accepted changed Pod/container or projection shape")
			}
		})
	}
}

func TestUnitM2StableProcessIncarnation(t *testing.T) {
	base := m2ProcessIdentity{PodUID: types.UID("pod"), NodeUID: types.UID("node"), NodeContainerID: "node-container", ContainerID: "container", TaskID: "task", HostPID: 123, StartTicks: 456, PIDNamespaceInode: 789, ImageID: "image", State: "S"}
	after := base
	after.State = "R"
	if err := m2CheckSameProcessIncarnation(base, after); err != nil {
		t.Fatalf("ordinary process state transition changed identity: %v", err)
	}
	for name, mutate := range map[string]func(*m2ProcessIdentity){
		"Pod UID":         func(p *m2ProcessIdentity) { p.PodUID = "replaced" },
		"container ID":    func(p *m2ProcessIdentity) { p.ContainerID = "replaced" },
		"task ID":         func(p *m2ProcessIdentity) { p.TaskID = "replaced" },
		"PID start ticks": func(p *m2ProcessIdentity) { p.StartTicks++ },
		"image ID":        func(p *m2ProcessIdentity) { p.ImageID = "replaced" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if err := m2CheckSameProcessIncarnation(base, changed); err == nil {
				t.Fatal("accepted changed process incarnation")
			}
		})
	}
}

func TestUnitM2PodNetworkShape(t *testing.T) {
	no := false
	before := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "keaguard-m2-runtime", Name: "pod-0", UID: "pod-uid"},
		Spec: corev1.PodSpec{NodeName: "worker-1", ServiceAccountName: "default", AutomountServiceAccountToken: &no,
			Containers: []corev1.Container{{Name: "dhcp4"}, {Name: "dhcp6"}},
			Volumes:    []corev1.Volume{{Name: "configuration", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "dhcp4", ContainerID: "containerd://id4", ImageID: "image4"},
			{Name: "dhcp6", ContainerID: "containerd://id6", ImageID: "image6"},
		}},
	}
	if err := m2CheckPodNetworkShape(before, before); err != nil {
		t.Fatalf("rejected Pod with omitted/default false hostNetwork: %v", err)
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"host network":             func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"host PID":                 func(p *corev1.Pod) { p.Spec.HostPID = true },
		"host IPC":                 func(p *corev1.Pod) { p.Spec.HostIPC = true },
		"shared process namespace": func(p *corev1.Pod) { yes := true; p.Spec.ShareProcessNamespace = &yes },
		"container port":           func(p *corev1.Pod) { p.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 67}} },
		"host port": func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 67, HostPort: 67}}
		},
		"host path": func(p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/tmp"}}})
		},
		"PVC": func(p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "pvc", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "x"}}})
		},
		"projected token": func(p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}}}}})
		},
		"automount token":          func(p *corev1.Pod) { yes := true; p.Spec.AutomountServiceAccountToken = &yes },
		"implicit automount token": func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = nil },
		"wrong Pod UID":            func(p *corev1.Pod) { p.UID = "new-pod" },
		"wrong node":               func(p *corev1.Pod) { p.Spec.NodeName = "worker-2" },
		"replaced container":       func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID = "containerd://new" },
		"replaced image":           func(p *corev1.Pod) { p.Status.ContainerStatuses[1].ImageID = "new-image" },
	} {
		t.Run(name, func(t *testing.T) {
			after := before.DeepCopy()
			mutate(after)
			if err := m2CheckPodNetworkShape(before, *after); err == nil {
				t.Fatal("accepted changed or network-exposed Pod")
			}
		})
	}
}
