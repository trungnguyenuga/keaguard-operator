package e2e

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"
)

func TestUnitM2LabPolicyGuard(t *testing.T) {
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		labels := map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}
		for k, v := range m2ExpectedPolicy(name) {
			labels[k] = v
		}
		if err := checkFixtureNamespaceForProfile(m2LabProfile, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}); err != nil {
			t.Fatalf("valid %s policy: %v", name, err)
		}
		wrongPolicy := map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster, "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.37"}
		if name == m2LabProfile.outsideNamespace {
			wrongPolicy["pod-security.kubernetes.io/enforce"] = "privileged"
		}
		for _, bad := range []map[string]string{
			{m2LabProfile.fixtureLabel: m2LabProfile.cluster},
			wrongPolicy,
			{m2LabProfile.fixtureLabel: m2LabProfile.cluster, "pod-security.kubernetes.io/enforce": m2ExpectedPolicy(name)["pod-security.kubernetes.io/enforce"], "pod-security.kubernetes.io/enforce-version": "v1.37", "pod-security.kubernetes.io/audit": "restricted"},
			{m2LabProfile.fixtureLabel: "foreign", "pod-security.kubernetes.io/enforce": m2ExpectedPolicy(name)["pod-security.kubernetes.io/enforce"], "pod-security.kubernetes.io/enforce-version": "v1.37"},
		} {
			if err := checkFixtureNamespaceForProfile(m2LabProfile, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: bad}}); err == nil {
				t.Errorf("accepted unprepared/foreign policy for %s: %v", name, bad)
			}
		}
	}
}

func TestUnitM2RejectsStartedKeaContainersAfterFailedProjection(t *testing.T) {
	base := []corev1.ContainerStatus{
		{Name: "dhcp4", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}, Image: m2KeaDHCP4Image},
		{Name: "dhcp6", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}, Image: m2KeaDHCP6Image},
	}
	if err := m2ValidateKeaContainersNotStarted(base); err != nil {
		t.Fatalf("valid kubelet waiting state rejected: %v", err)
	}
	cases := map[string]func([]corev1.ContainerStatus){
		"missing expected status": func(s []corev1.ContainerStatus) { s[1].Name = "missing" },
		"running": func(s []corev1.ContainerStatus) {
			s[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
		},
		"container identity": func(s []corev1.ContainerStatus) { s[0].ContainerID = "containerd://id" },
		"started": func(s []corev1.ContainerStatus) {
			started := true
			s[0].Started = &started
		},
		"ready": func(s []corev1.ContainerStatus) { s[0].Ready = true },
		"terminated": func(s []corev1.ContainerStatus) {
			s[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}}
		},
		"restart":     func(s []corev1.ContainerStatus) { s[0].RestartCount = 1 },
		"wrong image": func(s []corev1.ContainerStatus) { s[0].Image = "kea:latest" },
		"wrong waiting reason": func(s []corev1.ContainerStatus) {
			s[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
		},
		"wrong name": func(s []corev1.ContainerStatus) { s[0].Name = "other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			statuses := append([]corev1.ContainerStatus(nil), base...)
			mutate(statuses)
			if err := m2ValidateKeaContainersNotStarted(statuses); err == nil {
				t.Fatal("unsafe or unverifiable container state accepted")
			}
		})
	}
	if err := m2ValidateKeaContainersNotStarted(nil); err == nil {
		t.Fatal("empty status snapshot was accepted as evidence")
	}
}

func TestUnitM2FailedMountRecoveryRequiresTheObservedPodIncarnation(t *testing.T) {
	ready := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "kea-1", UID: "failed-mount-uid"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "dhcp4", Image: m2KeaDHCP4Image}, {Name: "dhcp6", Image: m2KeaDHCP6Image}}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "dhcp4", Image: "sha256:edf856f99936b2e0318908ec7fa321eb1b0e7d980abcfaa2e09689849505f5e0", ImageID: m2KeaDHCP4Image, ContainerID: "containerd://" + strings.Repeat("a", 64), Ready: true},
				{Name: "dhcp6", Image: "sha256:86c615fdb2a111632178e0b99bd4430a58fca509f7b9048c6f01ba457366d123", ImageID: m2KeaDHCP6Image, ContainerID: "containerd://" + strings.Repeat("b", 64), Ready: true},
			},
		},
	}
	if !m2ReadyPodMatchesIncarnation(ready, "failed-mount-uid") {
		t.Fatal("same-UID ready Pod should prove recovery after projection repair")
	}
	cases := map[string]func(*corev1.Pod){
		"replacement UID": func(p *corev1.Pod) { p.UID = "replacement-uid" },
		"pending": func(p *corev1.Pod) {
			p.Status.Phase = corev1.PodPending
			p.Status.Conditions[0].Status = corev1.ConditionFalse
		},
		"not ready container":        func(p *corev1.Pod) { p.Status.ContainerStatuses[0].Ready = false },
		"missing container identity": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID = "" },
		"wrong config digest": func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].Image = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"wrong manifest reference": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "docker.io/library/kea:latest" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			pod := ready.DeepCopy()
			mutate(pod)
			if m2ReadyPodMatchesIncarnation(*pod, "failed-mount-uid") {
				t.Fatal("unready, stale or unexpected Pod identity accepted")
			}
		})
	}
}

func TestUnitM2ManagerScaleDownWaitsForObservedGenerationAndPodTermination(t *testing.T) {
	zero, one := int32(0), int32(1)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: managerName, UID: "manager-deployment-uid", Generation: 4},
		Spec:       appsv1.DeploymentSpec{Replicas: &zero, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"control-plane": "controller-manager"}}},
		Status:     appsv1.DeploymentStatus{ObservedGeneration: 4},
	}
	if err := m2ManagerScaleDownComplete(deployment, "manager-deployment-uid", nil); err != nil {
		t.Fatalf("settled zero-replica Deployment rejected: %v", err)
	}

	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "manager-pending-termination", Namespace: m2LabProfile.runtimeNamespace, Labels: map[string]string{"control-plane": "controller-manager"}, DeletionTimestamp: &metav1.Time{Time: time.Now()}}}
	if err := m2ManagerScaleDownComplete(deployment, "manager-deployment-uid", []corev1.Pod{pod}); err == nil {
		t.Fatal("manager scale-down accepted while a matching Pod incarnation was still terminating")
	}

	staleGeneration := deployment.DeepCopy()
	staleGeneration.Status.ObservedGeneration = 3
	if err := m2ManagerScaleDownComplete(staleGeneration, "manager-deployment-uid", nil); err == nil {
		t.Fatal("manager scale-down accepted before the Deployment observed its zero-replica generation")
	}

	replaced := deployment.DeepCopy()
	replaced.UID = "replacement-deployment-uid"
	if err := m2ManagerScaleDownComplete(replaced, "manager-deployment-uid", nil); err == nil {
		t.Fatal("manager scale-down accepted a replacement Deployment incarnation")
	}

	stillDesired := deployment.DeepCopy()
	stillDesired.Spec.Replicas = &one
	if err := m2ManagerScaleDownComplete(stillDesired, "manager-deployment-uid", nil); err == nil {
		t.Fatal("manager scale-down accepted a nonzero desired replica count")
	}
}

func TestUnitM2FailedMountReadinessDiagnosticIsBoundedAndUseful(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "kea-1", UID: "failed-mount-uid"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "dhcp4", Image: m2KeaDHCP4Image, ContainerID: "containerd://" + strings.Repeat("a", 64), Ready: false,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: strings.Repeat("detail", 1000)}},
		}}},
	}
	summary := m2PodReadinessSummary(pod, "failed-mount-uid")
	if len(summary) > 2048 {
		t.Fatalf("readiness diagnostic exceeds bound: %d bytes", len(summary))
	}
	for _, want := range []string{"failed-mount-uid", "kea-1", "CrashLoopBackOff", "ready=false"} {
		if !strings.Contains(summary, want) {
			t.Errorf("readiness diagnostic lacks %q: %s", want, summary)
		}
	}
}

func TestUnitM2MinReadySecondsUsesKubernetesObservedTimestamps(t *testing.T) {
	readyAt := time.Date(2026, 10, 19, 13, 0, 0, 0, time.UTC)
	if !m2MinReadyElapsed(readyAt, readyAt.Add(5*time.Second), 5) {
		t.Fatal("exact MinReadySeconds boundary should pass")
	}
	if !m2MinReadyElapsed(readyAt, readyAt.Add(5*time.Second+time.Nanosecond), 5) {
		t.Fatal("interval beyond MinReadySeconds should pass")
	}
	if m2MinReadyElapsed(readyAt, readyAt.Add(5*time.Second-time.Nanosecond), 5) {
		t.Fatal("interval shorter than MinReadySeconds was accepted")
	}
	if m2MinReadyElapsed(time.Time{}, readyAt.Add(5*time.Second), 5) || m2MinReadyElapsed(readyAt, time.Time{}, 5) || m2MinReadyElapsed(readyAt, readyAt.Add(5*time.Second), 0) {
		t.Fatal("missing timestamps or nonpositive reviewed minimum were accepted")
	}
}

func TestUnitM2ReadyTransitionRequiresKubernetesReadyTimestamp(t *testing.T) {
	readyAt := metav1.NewTime(time.Date(2026, 10, 19, 13, 0, 0, 0, time.UTC))
	pod := corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: readyAt}}}}
	observed, ok := m2PodReadyTransitionTime(pod)
	if !ok || !observed.Equal(readyAt.Time) {
		t.Fatalf("ready transition time = %v, %t; want %v", observed, ok, readyAt.Time)
	}
	pod.Status.Conditions[0].Status = corev1.ConditionFalse
	if _, ok := m2PodReadyTransitionTime(pod); ok {
		t.Fatal("false Ready condition was accepted")
	}
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if _, ok := m2PodReadyTransitionTime(pod); ok {
		t.Fatal("zero Ready transition timestamp was accepted")
	}
}

func TestUnitM2EvidenceRedaction(t *testing.T) {
	in := "token: abc.def authorization=BearerXYZ client-key-data:secret kubeconfig=" + m2LabProfile.kubeconfig
	out := m2RedactEvidence(in)
	for _, secret := range []string{"abc.def", "BearerXYZ", "client-key-data:secret", m2LabProfile.kubeconfig} {
		if strings.Contains(out, secret) {
			t.Errorf("evidence retained sensitive value %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "[REDACTED]") || !strings.Contains(out, "[KUBECONFIG-OMITTED]") {
		t.Fatalf("redaction markers missing: %s", out)
	}
}

func TestUnitM2DiagnosticCommandBounded(t *testing.T) {
	out, err := m2Command(context.Background(), "head", "-c", "300000", "/dev/zero")
	if err == nil || len(out) > 256*1024 {
		t.Fatalf("oversized diagnostic output was not bounded: length=%d err=%v", len(out), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := m2Command(ctx, "sleep", "10"); err == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("blocked diagnostic was not cancelled promptly: err=%v elapsed=%s", err, time.Since(started))
	}
}

func TestUnitM2BoundedInputCommand(t *testing.T) {
	out, err := m2CommandWithInput(context.Background(), []byte("reviewed-bundle"), "wc", "-c")
	if err != nil || strings.TrimSpace(string(out)) != "15" {
		t.Fatalf("bounded stdin command failed: output=%q err=%v", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m2CommandWithInput(ctx, []byte("never-send"), "wc", "-c"); err == nil {
		t.Fatal("cancelled input command was accepted")
	}
}

func TestUnitM2InputFingerprint(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}} {
		if out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git init: %v %s", err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("tracked.txt", "one")
	if out, err := exec.Command("git", "-C", root, "add", "tracked.txt").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v %s", err, out)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	first, fp1, err := m2InputManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	write("untracked/input.txt", "two")
	second, fp2, err := m2InputManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 || string(first) == string(second) || !strings.Contains(string(second), "untracked/input.txt\x00") {
		t.Fatal("untracked input did not alter complete fingerprint")
	}
	if err = os.Remove(filepath.Join(root, "untracked/input.txt")); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(root, "untracked")); err != nil {
		t.Fatal(err)
	}
	third, fp3, err := m2InputManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fp2 == fp3 || string(second) == string(third) {
		t.Fatal("input deletion did not alter complete path set")
	}
	if _, err = os.Stat(filepath.Join(root, "untracked")); !os.IsNotExist(err) {
		t.Fatal("test fixture unexpectedly retained untracked directory")
	}
}

func TestUnitM2InputFingerprintWorkingDirectories(t *testing.T) {
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, fromPackage, err := m2InputManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rootOut, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(strings.TrimSpace(string(rootOut))); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(packageDir)
	_, fromRoot, err := m2InputManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fromPackage != fromRoot {
		t.Fatalf("working directory changed fingerprint: package=%s root=%s", fromPackage, fromRoot)
	}
}

func TestUnitM2PrivateDirectoryModes(t *testing.T) {
	root := t.TempDir()
	task := filepath.Join(root, "task")
	docker := filepath.Join(task, "docker")
	if err := os.Mkdir(task, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(docker, 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkM2Directories(task, docker); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(task, 0755); err != nil {
		t.Fatal(err)
	}
	if err := checkM2Directories(task, docker); err == nil {
		t.Fatal("accepted non-private task directory")
	}
	if err := os.Chmod(task, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docker, "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkM2Directories(task, docker); err == nil {
		t.Fatal("accepted populated Docker config")
	}
}

func TestUnitM2ManagerImageIdentity(t *testing.T) {
	imageID := "sha256:" + strings.Repeat("a", 64)
	otherID := "sha256:" + strings.Repeat("b", 64)
	if err := m2VerifyManagerImage(context.Background(), "", "id"); err == nil {
		t.Fatal("accepted missing image")
	}
	if err := m2VerifyManagerImage(context.Background(), "image:test", ""); err == nil {
		t.Fatal("accepted missing content identity")
	}
	for _, tc := range []struct {
		out, id string
		want    bool
	}{{imageID + "|linux|amd64", imageID, true}, {otherID + "|linux|amd64", imageID, false}, {imageID + "|linux|arm64", imageID, false}, {imageID + "|linux|amd64|extra", imageID, false}} {
		err := m2CheckImageIdentity(tc.out, tc.id)
		if (err == nil) != tc.want {
			t.Errorf("identity %q expected success=%t, got %v", tc.out, tc.want, err)
		}
	}
	bin := t.TempDir()
	script := filepath.Join(bin, "docker")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"${M2_FAKE_IMAGE_ID}|${M2_FAKE_OS}|${M2_FAKE_ARCH}\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("IMG", "manager:m2-test")
	t.Setenv("M2_FAKE_IMAGE_ID", imageID)
	t.Setenv("M2_FAKE_OS", "linux")
	t.Setenv("M2_FAKE_ARCH", "amd64")
	if err := m2VerifyManagerImage(context.Background(), "manager:m2-test", imageID); err != nil {
		t.Fatalf("fake inspected exact image rejected: %v", err)
	}
	t.Setenv("M2_FAKE_ARCH", "arm64")
	if err := m2VerifyManagerImage(context.Background(), "manager:m2-test", imageID); err == nil {
		t.Fatal("wrong platform accepted")
	}
	containerID := strings.Repeat("a", 64)
	configID := "sha256:" + strings.Repeat("f", 64)
	validCRI := `{"status":{"id":"` + containerID + `","state":"CONTAINER_RUNNING","imageId":"` + configID + `"},"info":{"config":{"image":{"image":"` + configID + `"}},"snapshotKey":"` + containerID + `"}}`
	if err := m2CheckManagerContainerCRI([]byte(validCRI), containerID, configID); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(validCRI, containerID, strings.Repeat("b", 64), 1),
		strings.Replace(validCRI, `"imageId":"`+configID+`"`, `"imageId":"sha256:`+strings.Repeat("e", 64)+`"`, 1),
		strings.Replace(validCRI, `"image":{"image":"`+configID+`"}`, `"image":{"image":"sha256:`+strings.Repeat("e", 64)+`"}`, 1),
		strings.Replace(validCRI, `"snapshotKey":"`+containerID+`"`, `"snapshotKey":"`+strings.Repeat("e", 64)+`"`, 1),
		strings.Replace(validCRI, `"CONTAINER_RUNNING"`, `"CONTAINER_EXITED"`, 1),
	} {
		if err := m2CheckManagerContainerCRI([]byte(bad), containerID, configID); err == nil {
			t.Fatalf("stale CRI tuple accepted: %s", bad)
		}
	}
	if err := m2CheckManagerContainerCRI([]byte(validCRI), containerID, "sha256:short"); err == nil {
		t.Fatal("accepted a truncated expected CRI config digest")
	}
}

func TestUnitM2ManagerImageIdentityRejectsTruncatedDigest(t *testing.T) {
	if err := m2CheckImageIdentity("sha256:abc|linux|amd64", "sha256:abc"); err == nil {
		t.Fatal("truncated Docker image digest was accepted as a full content identity")
	}
}

func TestUnitM2ManagerCRIIndexAndConfigAreDistinct(t *testing.T) {
	containerID := strings.Repeat("c", 64)
	indexID := "sha256:" + strings.Repeat("a", 64)
	configID := "sha256:" + strings.Repeat("b", 64)
	cri := `{"status":{"id":"` + containerID + `","state":"CONTAINER_RUNNING","imageId":"` + configID + `"},"info":{"config":{"image":{"image":"` + configID + `"}},"snapshotKey":"` + containerID + `"}}`
	if err := m2CheckManagerContainerCRI([]byte(cri), containerID, configID); err != nil {
		t.Fatalf("rejected the verified CRI config digest: %v", err)
	}
	if err := m2CheckManagerContainerCRI([]byte(cri), containerID, indexID); err == nil {
		t.Fatal("accepted build index digest as a CRI config digest")
	}
}

func TestUnitM2ManagerCRIUsesActualImageIDField(t *testing.T) {
	containerID := strings.Repeat("c", 64)
	configID := "sha256:" + strings.Repeat("b", 64)
	oldIndex := "sha256:" + strings.Repeat("a", 64)
	ref := "docker.io/library/import-2026-10-18@" + oldIndex
	cri := fmt.Sprintf(`{"status":{"id":%q,"state":"CONTAINER_RUNNING","imageId":%q,"imageRef":%q,"image":{"image":"docker.io/library/keaguard-operator:m2-111111111111"},"labels":{"io.kubernetes.container.name":"manager","io.kubernetes.pod.name":"manager-pod","io.kubernetes.pod.namespace":"keaguard-m2-runtime","io.kubernetes.pod.uid":"pod-uid"}},"info":{"config":{"image":{"image":%q,"user_specified_image":"keaguard-operator:m2-222222222222"},"labels":{"io.kubernetes.container.name":"manager","io.kubernetes.pod.name":"manager-pod","io.kubernetes.pod.namespace":"keaguard-m2-runtime","io.kubernetes.pod.uid":"pod-uid"}},"runtimeSpec":{"annotations":{"io.kubernetes.cri.image-name":"keaguard-operator:m2-222222222222","io.kubernetes.cri.sandbox-name":"manager-pod","io.kubernetes.cri.sandbox-namespace":"keaguard-m2-runtime","io.kubernetes.cri.sandbox-uid":"pod-uid","io.kubernetes.cri.container-name":"manager"}},"snapshotKey":%q,"snapshotter":"overlayfs"}}`, containerID, configID, ref, configID, containerID)
	if err := m2CheckManagerContainerCRI([]byte(cri), containerID, configID); err != nil {
		t.Fatalf("actual CRI config identity with historical display reference rejected: %v", err)
	}
}

func TestUnitM2ManagerDeploymentUsesReviewedNodeAndCRIIdentity(t *testing.T) {
	oci := m2NewOCITestFixture()
	imageID := oci.indexID
	configID := oci.configID
	containerID := strings.Repeat("c", 64)
	nodeID := strings.Repeat("d", 64)
	worker := m2LabProfile.nodes[1]
	image := "keaguard-operator:m2-123456789abc"
	oldImage := "docker.io/library/keaguard-operator:m2-111111111111"
	wrapper := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":%q,"size":%d}]}`, imageID, len(oci.index)))
	wrapperID := m2TestDigest(wrapper)
	displayRef := "docker.io/library/import-2026-10-18@" + wrapperID
	one := int32(1)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: managerName, UID: "deployment-uid", Generation: 1}, Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"control-plane": "controller-manager"}}, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: managerName, Containers: []corev1.Container{{Name: "manager", Image: image}}}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 1}}
	controller := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: deployment.Namespace, Name: "manager-rs", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "Deployment", Name: managerName, UID: deployment.UID, Controller: &controller}}}, Spec: appsv1.ReplicaSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "manager", Image: image}}}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: deployment.Namespace, Name: "manager-pod", UID: "pod-uid", Labels: map[string]string{"control-plane": "controller-manager"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: worker, ServiceAccountName: managerName, Containers: []corev1.Container{{Name: "manager", Image: image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "manager", ContainerID: "containerd://" + containerID, Image: oldImage, ImageID: displayRef, Ready: true}}}}
	objects := []client.Object{deployment, rs, pod}
	for _, name := range m2LabProfile.nodes {
		labels := map[string]string{"kubernetes.io/hostname": name, "kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}
		if name == m2LabProfile.nodes[0] {
			labels["node-role.kubernetes.io/control-plane"] = ""
		}
		objects = append(objects, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid"), Labels: labels}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "linux", Architecture: "amd64"}}})
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	previousAdmin, previousConfig := admin, adminConfig
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	adminConfig = &rest.Config{Host: "https://127.0.0.1:6443", TLSClientConfig: rest.TLSClientConfig{CAData: []byte("fake-ca")}}
	defer func() { admin, adminConfig = previousAdmin, previousConfig }()
	bin := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = image ] && [ "$2" = inspect ]; then
  printf '%s|linux|amd64\n' "$M2_FAKE_NODE_IMAGE_ID"
  exit 0
fi
if [ "$1" = inspect ]; then
  role=worker
  if [ "$4" = "$M2_FAKE_CLUSTER-control-plane" ]; then role=control-plane; fi
  printf '%s|%s|%s|%s|%s\n' "$M2_FAKE_NODE_ID" "$M2_FAKE_NODE_IMAGE" "$M2_FAKE_NODE_IMAGE_ID" "$M2_FAKE_CLUSTER" "$role"
  exit 0
fi
if [ "$1" = exec ] && [ "$2" = "$M2_FAKE_NODE_ID" ] && [ "$3" = crictl ]; then
  if [ "$4" = inspect ] && [ "$7" = "$M2_FAKE_CONTAINER_ID" ]; then
    exec /bin/cat "$M2_FAKE_CRI_FILE"
    exit 0
  fi
  if [ "$4" = inspecti ]; then
    printf '{"status":{"id":"%s","repoTags":["%s"]}}\n' "$M2_FAKE_CRI_CONFIG_ID" "$M2_FAKE_OPERATOR_REF"
    exit 0
  fi
fi
if [ "$1" = exec ] && [ "$2" = "$M2_FAKE_NODE_ID" ] && [ "$3" = ctr ]; then
  if [ "$6" = images ] && [ "$7" = ls ]; then
    printf 'REF TYPE DIGEST SIZE PLATFORMS LABELS\n%s application/vnd.oci.image.index.v1+json %s 23MiB linux/amd64 -\n%s application/vnd.oci.image.index.v1+json %s 23MiB linux/amd64 -\n%s application/vnd.oci.image.index.v1+json %s 23MiB linux/amd64 -\n' "$M2_FAKE_OPERATOR_REF" "$M2_FAKE_INDEX_ID" "$M2_FAKE_OLD_IMAGE" "$M2_FAKE_OLD_INDEX_ID" "$M2_FAKE_DISPLAY_REF" "$M2_FAKE_WRAPPER_ID"
    if [ "${M2_FAKE_DUPLICATE_ROW:-}" = 1 ]; then
      printf '%s application/vnd.oci.image.index.v1+json %s 23MiB linux/amd64 -\n' "$M2_FAKE_DISPLAY_REF" "$M2_FAKE_WRAPPER_ID"
    fi
    exit 0
  fi
  if [ "$6" = content ] && [ "$7" = get ]; then
    case "$8" in sha256:*) file="$M2_FAKE_BLOB_DIR/${8#sha256:}";; *) exit 42;; esac
    exec /bin/cat "$file"
  fi
fi
if [ "$1" = exec ] && [ "$2" = "$M2_FAKE_NODE_ID" ] && [ "$3" = "/bin/sh" ] && [ "$4" = "-c" ]; then
  shift 6
  for path do
    local_path="$M2_FAKE_BLOB_DIR/${path##*/}"
    type=$(/usr/bin/stat -c '%F' "$local_path") || exit 1
    size=$(/usr/bin/stat -c '%s' "$local_path") || exit 1
    printf 'stat|%s|%s|%s\n' "$type" "$size" "$path"
  done
  for path do
    local_path="$M2_FAKE_BLOB_DIR/${path##*/}"
    hash=$(/usr/bin/sha256sum "$local_path") || exit 1
    printf 'hash|%s|%s\n' "${hash%% *}" "$path"
  done
  exit 0
fi
if [ "$1" = exec ] && [ "$2" = "$M2_FAKE_NODE_ID" ] && [ "$3" = stat ]; then
  /usr/bin/stat -c '%F|%s' "$M2_FAKE_BLOB_DIR/${6##*/}"
  exit 0
fi
if [ "$1" = exec ] && [ "$2" = "$M2_FAKE_NODE_ID" ] && [ "$3" = sha256sum ]; then
  hash=$(/usr/bin/sha256sum "$M2_FAKE_BLOB_DIR/${4##*/}") || exit 1
  printf '%s  %s\n' "${hash%% *}" "$4"
  exit 0
fi
exit 42
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("M2_FAKE_NODE_ID", nodeID)
	t.Setenv("M2_FAKE_NODE_IMAGE", m2LabProfile.nodeImage)
	t.Setenv("M2_FAKE_NODE_IMAGE_ID", "sha256:"+strings.Repeat("e", 64))
	t.Setenv("M2_FAKE_CLUSTER", m2LabProfile.cluster)
	t.Setenv("M2_FAKE_CONTAINER_ID", containerID)
	t.Setenv("M2_FAKE_CRI_CONFIG_ID", configID)
	t.Setenv("M2_FAKE_INDEX_ID", imageID)
	t.Setenv("M2_FAKE_OLD_INDEX_ID", imageID)
	t.Setenv("M2_FAKE_OPERATOR_REF", "docker.io/library/"+image)
	t.Setenv("M2_FAKE_OLD_IMAGE", oldImage)
	t.Setenv("M2_FAKE_DISPLAY_REF", displayRef)
	t.Setenv("M2_FAKE_WRAPPER_ID", wrapperID)
	cri := fmt.Sprintf(`{"status":{"id":%q,"state":"CONTAINER_RUNNING","imageId":%q,"imageRef":%q,"image":{"image":%q},"labels":{"io.kubernetes.container.name":"manager","io.kubernetes.pod.name":"manager-pod","io.kubernetes.pod.namespace":"keaguard-m2-runtime","io.kubernetes.pod.uid":"pod-uid"}},"info":{"config":{"image":{"image":%q,"user_specified_image":%q},"labels":{"io.kubernetes.container.name":"manager","io.kubernetes.pod.name":"manager-pod","io.kubernetes.pod.namespace":"keaguard-m2-runtime","io.kubernetes.pod.uid":"pod-uid"}},"runtimeSpec":{"annotations":{"io.kubernetes.cri.image-name":%q,"io.kubernetes.cri.sandbox-name":"manager-pod","io.kubernetes.cri.sandbox-namespace":"keaguard-m2-runtime","io.kubernetes.cri.sandbox-uid":"pod-uid","io.kubernetes.cri.container-name":"manager"}},"snapshotKey":%q,"snapshotter":"overlayfs"}}`, containerID, configID, displayRef, oldImage, configID, image, image, containerID)
	criFile := filepath.Join(t.TempDir(), "cri.json")
	if err := os.WriteFile(criFile, []byte(cri), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("M2_FAKE_CRI_FILE", criFile)
	blobDir := t.TempDir()
	for digest, blob := range oci.blobs {
		if err := os.WriteFile(filepath.Join(blobDir, strings.TrimPrefix(digest, "sha256:")), blob, 0600); err != nil {
			t.Fatal(err)
		}
		if string(blob) == "exact compressed layer bytes" {
			t.Setenv("M2_FAKE_LAYER_ID", digest)
			t.Setenv("M2_FAKE_LAYER_SIZE", fmt.Sprint(len(blob)))
		}
	}
	if err := os.WriteFile(filepath.Join(blobDir, strings.TrimPrefix(oci.indexID, "sha256:")), []byte(oci.index), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, strings.TrimPrefix(wrapperID, "sha256:")), wrapper, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("M2_FAKE_BLOB_DIR", blobDir)
	if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err != nil {
		t.Fatal(err)
	}
	t.Setenv("M2_FAKE_OPERATOR_REF", "docker.io/library/foreign:m2-123456789abc")
	if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
		t.Fatal("wrong containerd/CRI image reference was accepted")
	}
	t.Setenv("M2_FAKE_OPERATOR_REF", "docker.io/library/"+image)
	t.Setenv("M2_FAKE_CLUSTER", "foreign-cluster")
	if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
		t.Fatal("wrong Kind node cluster identity was accepted")
	}
	t.Setenv("M2_FAKE_CLUSTER", m2LabProfile.cluster)
	t.Setenv("M2_FAKE_CRI_CONFIG_ID", "sha256:"+strings.Repeat("b", 64))
	if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
		t.Fatal("stale CRI image was accepted")
	}
	t.Setenv("M2_FAKE_CRI_CONFIG_ID", configID)
	for name, bad := range map[string]string{
		"stale running config":  strings.Replace(cri, `"imageId":"`+configID+`"`, `"imageId":"sha256:`+strings.Repeat("b", 64)+`"`, 1),
		"wrong requested image": strings.Replace(cri, `"user_specified_image":"`+image+`"`, `"user_specified_image":"keaguard-operator:m2-333333333333"`, 1),
		"wrong Pod UID label":   strings.Replace(cri, `"io.kubernetes.pod.uid":"pod-uid"`, `"io.kubernetes.pod.uid":"foreign-pod"`, 1),
		"wrong Pod sandbox":     strings.Replace(cri, `"io.kubernetes.cri.sandbox-uid":"pod-uid"`, `"io.kubernetes.cri.sandbox-uid":"foreign-pod"`, 1),
		"wrong display ref":     strings.Replace(cri, `"imageRef":"`+displayRef+`"`, `"imageRef":"docker.io/library/import@sha256:`+strings.Repeat("a", 64)+`"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(criFile, []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
				t.Fatal("accepted stale or foreign running manager CRI identity")
			}
		})
	}
	if err := os.WriteFile(criFile, []byte(cri), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("M2_FAKE_DUPLICATE_ROW", "1")
	if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
		t.Fatal("ambiguous immutable display reference was accepted")
	}
	t.Setenv("M2_FAKE_DUPLICATE_ROW", "0")
	wrongIndex := "sha256:" + strings.Repeat("a", 64)
	t.Setenv("M2_FAKE_OLD_INDEX_ID", wrongIndex)
	if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
		t.Fatal("historical display tag with wrong OCI index was accepted")
	}
	t.Setenv("M2_FAKE_OLD_INDEX_ID", imageID)
	altLayer := []byte("different but valid compressed layer bytes")
	altLayerID := m2TestDigest(altLayer)
	altManifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}]}`, configID, len(oci.blobs[configID]), altLayerID, len(altLayer)))
	altManifestID := m2TestDigest(altManifest)
	altIndex := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d,"platform":{"os":"linux","architecture":"amd64"}}]}`, altManifestID, len(altManifest)))
	altIndexID := m2TestDigest(altIndex)
	for digest, blob := range map[string][]byte{altLayerID: altLayer, altManifestID: altManifest, altIndexID: altIndex} {
		if err := os.WriteFile(filepath.Join(blobDir, strings.TrimPrefix(digest, "sha256:")), blob, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("M2_FAKE_OLD_INDEX_ID", altIndexID)
	if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil || !strings.Contains(err.Error(), "different manifest/config content") {
		t.Fatalf("historical tag with identical config but different verified layer/manifest accepted or failed for the wrong reason: %v", err)
	}
	t.Setenv("M2_FAKE_OLD_INDEX_ID", imageID)
	armIndex := []byte(strings.Replace(string(altIndex), `"amd64"`, `"arm64"`, 1))
	armIndexID := m2TestDigest(armIndex)
	if err := os.WriteFile(filepath.Join(blobDir, strings.TrimPrefix(armIndexID, "sha256:")), armIndex, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("M2_FAKE_OLD_INDEX_ID", armIndexID)
	if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
		t.Fatal("historical tag with wrong platform manifest accepted")
	}
	t.Setenv("M2_FAKE_OLD_INDEX_ID", imageID)
	for digest, blob := range oci.blobs {
		if string(blob) != "exact compressed layer bytes" {
			continue
		}
		layerPath := filepath.Join(blobDir, strings.TrimPrefix(digest, "sha256:"))
		if err := os.WriteFile(layerPath, []byte("tampered content-store layer"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
			t.Fatal("tampered node content-store layer accepted")
		}
		if err := os.WriteFile(layerPath, blob, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, candidate := range []struct {
		name   string
		change func(*appsv1.ReplicaSet)
	}{
		{"wrong ReplicaSet owner", func(item *appsv1.ReplicaSet) { item.OwnerReferences[0].UID = "foreign-deployment" }},
		{"wrong ReplicaSet owner name", func(item *appsv1.ReplicaSet) { item.OwnerReferences[0].Name = "foreign-manager" }},
		{"wrong ReplicaSet owner API", func(item *appsv1.ReplicaSet) { item.OwnerReferences[0].APIVersion = "batch/v1" }},
		{"wrong ReplicaSet image", func(item *appsv1.ReplicaSet) {
			item.Spec.Template.Spec.Containers[0].Image = "keaguard-operator:m2-333333333333"
		}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			var changed appsv1.ReplicaSet
			if err := admin.Get(context.Background(), client.ObjectKeyFromObject(rs), &changed); err != nil {
				t.Fatal(err)
			}
			candidate.change(&changed)
			if err := admin.Update(context.Background(), &changed); err != nil {
				t.Fatal(err)
			}
			if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
				t.Fatal("foreign/stale ReplicaSet accepted")
			}
			if err := admin.Get(context.Background(), client.ObjectKeyFromObject(rs), &changed); err != nil {
				t.Fatal(err)
			}
			changed.OwnerReferences = rs.OwnerReferences
			changed.Spec.Template.Spec.Containers[0].Image = image
			if err := admin.Update(context.Background(), &changed); err != nil {
				t.Fatal(err)
			}
		})
	}
	initialAdmin := admin
	for name, change := range map[string]func(*corev1.Pod){
		"Pod UID replacement": func(item *corev1.Pod) { item.UID = "replaced-during-attestation" },
		"container replacement": func(item *corev1.Pod) {
			item.Status.ContainerStatuses[0].ContainerID = "containerd://" + strings.Repeat("f", 64)
		},
		"owner replacement": func(item *corev1.Pod) { item.OwnerReferences[0].UID = "replaced-rs" },
	} {
		t.Run(name+" during attestation", func(t *testing.T) {
			admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if err := c.Get(ctx, key, obj, opts...); err != nil {
						return err
					}
					if key.Namespace == pod.Namespace && key.Name == pod.Name {
						change(obj.(*corev1.Pod))
					}
					return nil
				},
			}).Build()
			if err := m2VerifyManagerDeployment(context.Background(), image, imageID); err == nil {
				t.Fatal("current Pod/container/owner replacement was accepted")
			}
		})
	}
	admin = initialAdmin
}

func TestUnitM2KindNodeImageAndPlatformGuards(t *testing.T) {
	name := m2LabProfile.nodes[1]
	imageID := "sha256:" + strings.Repeat("a", 64)
	nodeID := strings.Repeat("b", 64)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, UID: "node-uid", Labels: map[string]string{
		"kubernetes.io/hostname": name, "kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64",
	}}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "linux", Architecture: "amd64"}}}
	observed := nodeID + "|" + m2LabProfile.nodeImage + "|" + imageID + "|" + m2LabProfile.cluster + "|worker"
	if _, err := m2CheckKindNodeIdentity(name, node, observed, imageID); err != nil {
		t.Fatalf("reviewed node identity rejected: %v", err)
	}
	for label, mutate := range map[string]func(*corev1.Node){
		"wrong architecture label": func(n *corev1.Node) { n.Labels["kubernetes.io/arch"] = "arm64" },
		"wrong OS label":           func(n *corev1.Node) { n.Labels["kubernetes.io/os"] = "windows" },
		"wrong hostname label":     func(n *corev1.Node) { n.Labels["kubernetes.io/hostname"] = "foreign" },
		"wrong node status":        func(n *corev1.Node) { n.Status.NodeInfo.Architecture = "arm64" },
		"control-plane role":       func(n *corev1.Node) { n.Labels["node-role.kubernetes.io/control-plane"] = "" },
	} {
		t.Run(label, func(t *testing.T) {
			changed := node.DeepCopy()
			mutate(changed)
			if _, err := m2CheckKindNodeIdentity(name, changed, observed, imageID); err == nil {
				t.Fatal("wrong Kind node labels/platform were accepted")
			}
		})
	}
	for label, output := range map[string]string{
		"wrong full image ID": nodeID + "|" + m2LabProfile.nodeImage + "|sha256:" + strings.Repeat("c", 64) + "|" + m2LabProfile.cluster + "|worker",
		"wrong pinned image":  nodeID + "|kindest/node:foreign|" + imageID + "|" + m2LabProfile.cluster + "|worker",
		"wrong cluster":       nodeID + "|" + m2LabProfile.nodeImage + "|" + imageID + "|foreign|worker",
		"wrong node role":     nodeID + "|" + m2LabProfile.nodeImage + "|" + imageID + "|" + m2LabProfile.cluster + "|control-plane",
		"short Docker ID":     "abc|" + m2LabProfile.nodeImage + "|" + imageID + "|" + m2LabProfile.cluster + "|worker",
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := m2CheckKindNodeIdentity(name, node, output, imageID); err == nil {
				t.Fatal("wrong Docker node/image identity was accepted")
			}
		})
	}
}

func TestUnitM2RecoveryContract(t *testing.T) {
	l := newM2FixtureLedger()
	intent := m2CreateIntent{ID: "one", Key: client.ObjectKey{Namespace: "ns", Name: "fixture"}, GVK: corev1.SchemeGroupVersion.WithKind("ConfigMap"), Phase: "planned"}
	if err := l.RecordCreateIntent(intent); err != nil {
		t.Fatal(err)
	}
	identity := m2FixtureIdentity{Key: intent.Key, GVK: intent.GVK, UID: "uid-1"}
	if err := l.ConfirmCreated("one", identity); err != nil {
		t.Fatal(err)
	}
	if l.fixtures[fixtureKey(identity)].UID != "uid-1" {
		t.Fatal("confirmed UID not retained")
	}
	if err := l.ConfirmCreated("one", identity); err == nil {
		t.Fatal("duplicate confirmation accepted")
	}
}

func TestUnitM2ScenarioLedgerPersistsIntentAndIncarnations(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "ledger-test", evidenceDir: dir, ledger: newM2FixtureLedger()}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	created := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, GenerateName: "created-"}}
	intentID, err := s.RecordCreateIntent(created, nil)
	if err != nil {
		t.Fatal(err)
	}
	if intentID == "" {
		t.Fatal("missing durable intent ID")
	}
	durableName := created.Name
	ledger, err := os.ReadFile(filepath.Join(dir, "ledger.json"))
	if err != nil || durableName == "" || !strings.Contains(string(ledger), "\"phase\":\"planned\"") || !strings.Contains(string(ledger), durableName) || strings.Contains(string(ledger), `"generateName":"created-"`) {
		t.Fatalf("intent was not durably recorded before submission: %s, %v", ledger, err)
	}
	created.UID = "uid-created-1"
	if err := s.ConfirmCreated(intentID, created); err != nil {
		t.Fatal(err)
	}
	ledger, err = os.ReadFile(filepath.Join(dir, "ledger.json"))
	if err != nil || !strings.Contains(string(ledger), "uid-created-1") || !strings.Contains(string(ledger), "\"phase\":\"confirmed\"") {
		t.Fatalf("confirmed incarnation was not persisted: %s, %v", ledger, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "recovery-pending.json")); err != nil {
		t.Fatalf("pending marker disappeared before restoration: %v", err)
	}
	replacement := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: created.Namespace, Name: created.Name}}
	if _, err := s.RecordCreateIntent(replacement, nil); err == nil {
		t.Fatal("unplanned same-key replacement was accepted")
	}
	preexisting := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "existing", UID: "uid-original"}, Data: map[string]string{"key": "original"}}
	if err := s.RecordFixture(preexisting, preexisting, "restored"); err != nil {
		t.Fatal(err)
	}
	preexisting.Data["key"] = "later-mutation"
	ledger, err = os.ReadFile(filepath.Join(dir, "ledger.json"))
	if err != nil || !strings.Contains(string(ledger), "original") || strings.Contains(string(ledger), "later-mutation") {
		t.Fatalf("earliest original snapshot was not persisted independently: %s, %v", ledger, err)
	}
}

func TestUnitM2ScenarioCreateSubmissionAmbiguity(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "ambiguous-create", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	created := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, GenerateName: "ambiguous-"}}
	id, err := s.RecordCreateIntent(created, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCreateSubmitted(id); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ledger.json"))
	if err != nil || !strings.Contains(string(data), `"phase":"submitted"`) {
		t.Fatalf("submission was not persisted before request: %s, %v", data, err)
	}
	if err := s.MarkCreateUnresolved(id); err != nil {
		t.Fatal(err)
	}
	created.Name, created.GenerateName, created.UID = "ambiguous-1", "", "uid-after-lost-response"
	if err := s.ConfirmCreated(id, created); err == nil {
		t.Fatal("lost-response intent was confirmed without independent attribution")
	}
	if len(s.ledger.fixtures) != 0 {
		t.Fatal("ambiguous response granted fixture mutation rights")
	}
	if err := s.startEvidence(); err == nil {
		t.Fatal("pending recovery marker permitted another scenario")
	}
}

func TestUnitM2CreateFixturePersistsBeforeAPICall(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "fixture-create", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	clientScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(clientScheme); err != nil {
		t.Fatal(err)
	}
	previous := admin
	admin = fake.NewClientBuilder().WithScheme(clientScheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			data, err := os.ReadFile(filepath.Join(dir, "ledger.json"))
			if err != nil || !strings.Contains(string(data), `"phase":"submitted"`) {
				t.Fatalf("create reached API before durable submission: %s, %v", data, err)
			}
			if obj.GetName() == "failed" {
				return context.DeadlineExceeded
			}
			obj.SetUID("created-by-server")
			return c.Create(ctx, obj, opts...)
		},
	}).Build()
	defer func() { admin = previous }()
	created := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "fixture"}}
	if err := s.CreateFixture(context.Background(), created, nil); err != nil {
		t.Fatal(err)
	}
	if created.UID == "" || len(s.ledger.fixtures) != 1 {
		t.Fatalf("confirmed create was not recorded by UID: %q %+v", created.UID, s.ledger.fixtures)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ledger.json"))
	if err != nil || !strings.Contains(string(data), `"phase":"confirmed"`) || !strings.Contains(string(data), string(created.UID)) {
		t.Fatalf("confirmed incarnation was not persisted: %s, %v", data, err)
	}
	duplicate := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: created.Namespace, Name: created.Name}}
	if err := s.CreateFixture(context.Background(), duplicate, nil); err == nil {
		t.Fatal("duplicate create was accepted without explicit replacement intent")
	}
	if len(s.ledger.fixtures) != 1 {
		t.Fatal("failed create acquired an extra confirmed incarnation")
	}
	failed := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: created.Namespace, Name: "failed"}}
	if err := s.CreateFixture(context.Background(), failed, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ambiguous create response was not preserved: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(dir, "ledger.json"))
	if err != nil || !strings.Contains(string(data), `"phase":"unresolved"`) || len(s.ledger.fixtures) != 1 {
		t.Fatalf("failed submission was not retained without mutation rights: %s, %v", data, err)
	}
}

func TestUnitM2FixtureRecoveryChecksUIDAndResourceVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		liveUID types.UID
		wantErr bool
	}{
		{name: "recorded incarnation", liveUID: "recorded"},
		{name: "foreign replacement", liveUID: "foreign", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			s := &m2Scenario{Name: tc.name, evidenceDir: dir}
			if err := s.startEvidence(); err != nil {
				t.Fatal(err)
			}
			obj := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "fixture", UID: "recorded"}}
			id, err := s.RecordCreateIntent(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: obj.Namespace, Name: obj.Name}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.MarkCreateSubmitted(id); err != nil {
				t.Fatal(err)
			}
			if err := s.ConfirmCreated(id, obj); err != nil {
				t.Fatal(err)
			}
			clientScheme := runtime.NewScheme()
			if err := corev1.AddToScheme(clientScheme); err != nil {
				t.Fatal(err)
			}
			live := obj.DeepCopy()
			live.UID = tc.liveUID
			live.ResourceVersion = "123"
			previous := admin
			deletes := 0
			admin = fake.NewClientBuilder().WithScheme(clientScheme).WithObjects(live).WithInterceptorFuncs(interceptor.Funcs{
				Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					deletes++
					checked := (&client.DeleteOptions{}).ApplyOptions(opts)
					if checked.Preconditions == nil || checked.Preconditions.UID == nil || *checked.Preconditions.UID != "recorded" || checked.Preconditions.ResourceVersion == nil || *checked.Preconditions.ResourceVersion != "123" {
						t.Fatalf("delete lacked exact UID/resourceVersion preconditions: %+v", checked.Preconditions)
					}
					return c.Delete(ctx, obj, opts...)
				},
			}).Build()
			defer func() { admin = previous }()
			err = s.restoreFixtures(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("restoreFixtures error=%v wantErr=%t", err, tc.wantErr)
			}
			got := &corev1.ConfigMap{}
			getErr := admin.Get(context.Background(), client.ObjectKeyFromObject(obj), got)
			if tc.wantErr {
				if getErr != nil || got.UID != tc.liveUID || deletes != 0 {
					t.Fatalf("foreign replacement was altered: obj=%+v get=%v deletes=%d", got, getErr, deletes)
				}
			} else if !apierrors.IsNotFound(getErr) || deletes != 1 {
				t.Fatalf("recorded UID was not removed exactly once: get=%v deletes=%d", getErr, deletes)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "recovery-pending.json")); statErr != nil {
				t.Fatalf("fixture cleanup cleared recovery marker without aggregate proof: %v", statErr)
			}
		})
	}
}

func TestUnitM2FixtureRecoveryAcceptsIdentityArtifactOwnerGarbageCollection(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "owner garbage collection", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "fixture", UID: "parent-uid"}}
	child := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: parent.Namespace, Name: parent.Name, UID: "artifact-uid", ResourceVersion: "17",
		Labels:          map[string]string{"keaguard.example/artifact": "reconciliation"},
		Annotations:     map[string]string{"keaguard.example/purpose": "Internal reconciliation artifact; not operational Kea DHCP configuration."},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: parent.Name, UID: parent.UID, Controller: ptrBool(true), BlockOwnerDeletion: ptrBool(false)}},
	}, Data: map[string]string{"keacluster-name": parent.Name, "keacluster-namespace": parent.Namespace, "keacluster-uid": string(parent.UID)}}
	parentID, err := m2IdentityFor(parent)
	if err != nil {
		t.Fatal(err)
	}
	childID, err := m2IdentityFor(child)
	if err != nil {
		t.Fatal(err)
	}
	s.ledger.fixtures[fixtureKey(parentID)] = m2Fixture{m2FixtureIdentity: parentID, Created: true, EndState: "absent"}
	s.ledger.fixtures[fixtureKey(childID)] = m2Fixture{m2FixtureIdentity: childID, Original: child.DeepCopy(), EndState: "restored"}
	if err := s.persistLedger(); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, infrastructurev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	previousAdmin, previousWait := admin, m2WaitCaseWorkloadAbsentWork
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent.DeepCopy(), child.DeepCopy()).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			err := c.Delete(ctx, obj, opts...)
			if err == nil {
				if _, ok := obj.(*infrastructurev1alpha1.KeaCluster); ok {
					artifact := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: child.Namespace, Name: child.Name}}
					if getErr := c.Get(ctx, client.ObjectKeyFromObject(artifact), artifact); getErr == nil && artifact.UID == child.UID {
						return c.Delete(ctx, artifact, client.Preconditions{UID: &artifact.UID})
					}
				}
			}
			return err
		},
	}).Build()
	m2WaitCaseWorkloadAbsentWork = func(context.Context, m2Fixture) error { return nil }
	defer func() { admin, m2WaitCaseWorkloadAbsentWork = previousAdmin, previousWait }()
	if err := s.restoreFixtures(context.Background()); err != nil {
		t.Fatalf("exact controller-owned identity artifact should be reconciled as owner-GC absence: %v", err)
	}
	restored := s.ledger.fixtures[fixtureKey(childID)]
	if restored.EndState != "absent" || !restored.AbsentVerified {
		t.Fatalf("owner-GC outcome was not durably recorded as absent: %+v", restored)
	}
	got := &corev1.ConfigMap{}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(child), got); !apierrors.IsNotFound(err) {
		t.Fatalf("expected the exact owner-GC artifact to remain absent, got %v", err)
	}
}

func TestUnitM2FixtureRecoveryRetriesResourceVersionConflictWithFreshIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "pod status update race", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	obj := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "fixture", UID: "recorded"}}
	id, err := s.RecordCreateIntent(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: obj.Namespace, Name: obj.Name}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCreateSubmitted(id); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmCreated(id, obj); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	gets, deletes := 0, 0
	previous := admin
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj.DeepCopy()).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, target client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, target, opts...); err != nil {
				return err
			}
			gets++
			if target.GetUID() == "recorded" && gets == 1 {
				target.SetResourceVersion("stale-rv")
			}
			return nil
		},
		Delete: func(ctx context.Context, c client.WithWatch, target client.Object, opts ...client.DeleteOption) error {
			deletes++
			pre := (&client.DeleteOptions{}).ApplyOptions(opts).Preconditions
			if pre == nil || pre.UID == nil || *pre.UID != "recorded" || pre.ResourceVersion == nil {
				t.Fatalf("delete %d omitted exact UID/RV preconditions: %+v", deletes, pre)
			}
			wantRV := "999"
			if deletes == 1 {
				wantRV = "stale-rv"
			}
			if *pre.ResourceVersion != wantRV {
				t.Fatalf("delete %d used RV %q, want fresh RV %q", deletes, *pre.ResourceVersion, wantRV)
			}
			if deletes == 1 {
				return apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, target.GetName(), errors.New("simulated kubelet status update"))
			}
			return c.Delete(ctx, target, opts...)
		},
	}).Build()
	defer func() { admin = previous }()
	if err := s.restoreFixtures(context.Background()); err != nil {
		t.Fatalf("restore after fresh same-UID resourceVersion retry: %v", err)
	}
	if gets < 2 || deletes != 2 {
		t.Fatalf("expected a fresh read and exactly one conflict retry: gets=%d deletes=%d", gets, deletes)
	}
	got := &corev1.Pod{}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(obj), got); !apierrors.IsNotFound(err) {
		t.Fatalf("recorded Pod incarnation remains: %v", err)
	}
}

func TestUnitM2FixtureRecoveryReleasesOnlyCaseInstalledHold(t *testing.T) {
	for _, tc := range []struct {
		name         string
		foreign      bool
		foreignOwner bool
		wantFail     bool
	}{
		{name: "recorded hold"},
		{name: "foreign hold remains untouched", foreign: true, wantFail: true},
		{name: "foreign owner remains untouched", foreignOwner: true, wantFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			s := &m2Scenario{Name: tc.name, evidenceDir: dir}
			if err := s.startEvidence(); err != nil {
				t.Fatal(err)
			}
			obj := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "held", UID: "recorded", Finalizers: []string{t14HoldFinalizer}}}
			id, err := s.RecordCreateIntent(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: obj.Namespace, Name: obj.Name}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.MarkCreateSubmitted(id); err != nil {
				t.Fatal(err)
			}
			if err := s.ConfirmCreated(id, obj); err != nil {
				t.Fatal(err)
			}
			identity, err := m2IdentityFor(obj)
			if err != nil {
				t.Fatal(err)
			}
			fixture := s.ledger.fixtures[fixtureKey(identity)]
			fixture.AddedFinalizers = []string{t14HoldFinalizer}
			s.ledger.fixtures[fixtureKey(identity)] = fixture
			if err := s.persistLedger(); err != nil {
				t.Fatal(err)
			}
			live := obj.DeepCopy()
			if tc.foreign {
				live.Finalizers = append(live.Finalizers, "foreign.example/hold")
			}
			if tc.foreignOwner {
				live.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "foreign", UID: "foreign-uid"}}
			}
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			old := admin
			admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).Build()
			defer func() { admin = old }()
			err = s.restoreFixtures(context.Background())
			if (err != nil) != tc.wantFail {
				t.Fatalf("restoration error=%v wantFail=%t", err, tc.wantFail)
			}
			got := &corev1.ConfigMap{}
			getErr := admin.Get(context.Background(), client.ObjectKeyFromObject(obj), got)
			if tc.wantFail {
				if getErr != nil || !slices.Contains(got.Finalizers, t14HoldFinalizer) || tc.foreign && !slices.Contains(got.Finalizers, "foreign.example/hold") || tc.foreignOwner && len(got.OwnerReferences) != 1 {
					t.Fatalf("foreign hold mutated: object=%+v err=%v", got, getErr)
				}
			} else if !apierrors.IsNotFound(getErr) {
				t.Fatalf("case-held fixture not removed: %v", getErr)
			}
		})
	}
}

func TestUnitM2FixtureRecoveryAcceptsOnlyConfirmedSameNameSuccessor(t *testing.T) {
	for _, approved := range []bool{false, true} {
		t.Run(fmt.Sprintf("approved=%t", approved), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			s := &m2Scenario{Name: "replacement", evidenceDir: dir}
			if err := s.startEvidence(); err != nil {
				t.Fatal(err)
			}
			old := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "same", UID: "old"}}
			oldIntent, err := s.RecordCreateIntent(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: old.Namespace, Name: old.Name}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.MarkCreateSubmitted(oldIntent); err != nil {
				t.Fatal(err)
			}
			if err := s.ConfirmCreated(oldIntent, old); err != nil {
				t.Fatal(err)
			}
			oldIdentity, err := m2IdentityFor(old)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.ledger.MarkAbsentVerified(oldIdentity); err != nil {
				t.Fatal(err)
			}
			newObject := old.DeepCopy()
			newObject.UID = "new"
			if approved {
				newIntent, err := s.RecordCreateIntent(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: old.Namespace, Name: old.Name}}, &oldIdentity)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.MarkCreateSubmitted(newIntent); err != nil {
					t.Fatal(err)
				}
				if err := s.ConfirmCreated(newIntent, newObject); err != nil {
					t.Fatal(err)
				}
			}
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			oldAdmin := admin
			admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(newObject).Build()
			defer func() { admin = oldAdmin }()
			oldFixture := s.ledger.fixtures[fixtureKey(oldIdentity)]
			err = s.restoreFixture(context.Background(), oldFixture)
			if (err == nil) != approved {
				t.Fatalf("old-UID restoration result=%v approved=%t", err, approved)
			}
			got := &corev1.ConfigMap{}
			if err := admin.Get(context.Background(), client.ObjectKeyFromObject(newObject), got); err != nil || got.UID != newObject.UID {
				t.Fatalf("replacement was mutated: %+v %v", got, err)
			}
		})
	}
}

func TestUnitM2GeneratedSuccessorIsReadOnlyAndOwnerBound(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "generated-successor", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	old := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "generated", UID: "old-child"}}
	if err := s.RecordFixture(old, old, "absent"); err != nil {
		t.Fatal(err)
	}
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: old.Namespace, Name: old.Name, UID: "new-parent-uid"}}
	parentIntent, err := s.RecordCreateIntent(&infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: parent.Name}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCreateSubmitted(parentIntent); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmCreated(parentIntent, parent); err != nil {
		t.Fatal(err)
	}
	newChild := old.DeepCopy()
	newChild.UID = "new-child"
	// The same-name identity artifact deliberately keeps the M1 contract: its
	// exact parent UID is in the three-key Data payload, not the M2 workload
	// cluster-uid label. Adding that label would change preserved M1 semantics.
	newChild.Data = map[string]string{
		"keacluster-name":      parent.Name,
		"keacluster-namespace": parent.Namespace,
		"keacluster-uid":       string(parent.UID),
	}
	newChild.Labels = map[string]string{"keaguard.example/artifact": "reconciliation"}
	newChild.Annotations = map[string]string{"keaguard.example/purpose": "Internal reconciliation artifact; not operational Kea DHCP configuration."}
	controller := true
	newChild.OwnerReferences = []metav1.OwnerReference{{APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: parent.Name, UID: parent.UID, Controller: &controller}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	adminBefore := admin
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(newChild).Build()
	defer func() { admin = adminBefore }()
	oldIdentity, err := m2IdentityFor(old)
	if err != nil {
		t.Fatal(err)
	}
	parentIdentity, err := m2IdentityFor(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ObserveGeneratedSuccessor(context.Background(), oldIdentity, parentIdentity); err != nil {
		t.Fatal(err)
	}
	if _, trackedAsFixture := s.ledger.fixtures[fixtureKey(m2FixtureIdentity{Key: client.ObjectKeyFromObject(newChild), GVK: corev1.SchemeGroupVersion.WithKind("ConfigMap"), UID: newChild.UID})]; trackedAsFixture {
		t.Fatal("observed generated child gained deletion authority")
	}
	if err := s.restoreFixture(context.Background(), s.ledger.fixtures[fixtureKey(oldIdentity)]); err != nil {
		t.Fatal(err)
	}
	liveChild := &corev1.ConfigMap{}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(newChild), liveChild); err != nil {
		t.Fatal(err)
	}
	liveChild.Data["keacluster-uid"] = "foreign-parent"
	if err := admin.Update(context.Background(), liveChild); err != nil {
		t.Fatal(err)
	}
	if err := s.ObserveGeneratedSuccessor(context.Background(), oldIdentity, parentIdentity); err == nil {
		t.Fatal("successor with a mismatched identity payload was accepted")
	}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(newChild), liveChild); err != nil {
		t.Fatal(err)
	}
	liveChild.Data = map[string]string{
		"keacluster-name":      parent.Name,
		"keacluster-namespace": parent.Namespace,
		"keacluster-uid":       string(parent.UID),
	}
	if err := admin.Update(context.Background(), liveChild); err != nil {
		t.Fatal(err)
	}
	if err := s.restoreFixture(context.Background(), s.ledger.fixtures[fixtureKey(oldIdentity)]); err != nil {
		t.Fatalf("valid M1 identity successor was not preserved as read-only: %v", err)
	}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(newChild), liveChild); err != nil {
		t.Fatal(err)
	}
	liveChild.OwnerReferences[0].UID = "foreign-parent"
	if err := admin.Update(context.Background(), liveChild); err != nil {
		t.Fatal(err)
	}
	if err := s.restoreFixture(context.Background(), s.ledger.fixtures[fixtureKey(oldIdentity)]); err == nil {
		t.Fatal("changed generated owner accepted")
	}
}

func TestUnitM2OperationalConfigSuccessorIsReadOnlyAndOwnerBound(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "operational-config", UID: "parent-uid", ResourceVersion: "1"}}
	configName, _, _ := m2NamesFor(parent)
	old := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: configName, UID: "old-config-uid", ResourceVersion: "2", Labels: map[string]string{"keaguard.example/cluster-uid": string(parent.UID), "keaguard.example/component": "configuration"}}, Data: map[string]string{"kea-dhcp4.conf": "approved-v4", "kea-dhcp6.conf": "approved-v6"}}
	controller := true
	newChild := old.DeepCopy()
	newChild.UID, newChild.ResourceVersion = "new-config-uid", "3"
	newChild.OwnerReferences = []metav1.OwnerReference{{APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: parent.Name, UID: parent.UID, Controller: &controller}}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, infrastructurev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	for _, mutate := range []struct {
		name string
		fn   func(*corev1.ConfigMap)
	}{
		{name: "wrong owner UID", fn: func(cm *corev1.ConfigMap) { cm.OwnerReferences[0].UID = "foreign-parent" }},
		{name: "wrong cluster UID", fn: func(cm *corev1.ConfigMap) { cm.Labels["keaguard.example/cluster-uid"] = "foreign-parent" }},
		{name: "wrong component", fn: func(cm *corev1.ConfigMap) { cm.Labels["keaguard.example/component"] = "foreign" }},
		{name: "changed content", fn: func(cm *corev1.ConfigMap) { cm.Data["kea-dhcp4.conf"] = "unexpected" }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			s := &m2Scenario{Name: "operational-successor", evidenceDir: t.TempDir()}
			if err := os.Chmod(s.evidenceDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := s.startEvidence(); err != nil {
				t.Fatal(err)
			}
			if err := s.RecordFixture(old, old, "absent"); err != nil {
				t.Fatal(err)
			}
			intent, err := s.RecordCreateIntent(&infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: parent.Name}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.MarkCreateSubmitted(intent); err != nil {
				t.Fatal(err)
			}
			if err := s.ConfirmCreated(intent, parent); err != nil {
				t.Fatal(err)
			}
			if err := s.RecordFixture(parent, nil, "absent"); err != nil {
				t.Fatal(err)
			}
			candidate := newChild.DeepCopy()
			mutate.fn(candidate)
			oldAdmin := admin
			admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent, candidate).Build()
			defer func() { admin = oldAdmin }()
			oldIdentity, err := m2IdentityFor(old)
			if err != nil {
				t.Fatal(err)
			}
			parentIdentity, err := m2IdentityFor(parent)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.ObserveGeneratedSuccessor(context.Background(), oldIdentity, parentIdentity); err == nil {
				t.Fatal("unverified operational ConfigMap successor was accepted")
			}
		})
	}
	t.Run("valid successor remains read-only during restoration", func(t *testing.T) {
		s := &m2Scenario{Name: "operational-successor", evidenceDir: t.TempDir()}
		if err := os.Chmod(s.evidenceDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := s.startEvidence(); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordFixture(old, old, "absent"); err != nil {
			t.Fatal(err)
		}
		intent, err := s.RecordCreateIntent(&infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: parent.Name}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.MarkCreateSubmitted(intent); err != nil {
			t.Fatal(err)
		}
		if err := s.ConfirmCreated(intent, parent); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordFixture(parent, nil, "absent"); err != nil {
			t.Fatal(err)
		}
		oldAdmin := admin
		admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent, newChild).Build()
		defer func() { admin = oldAdmin }()
		oldIdentity, err := m2IdentityFor(old)
		if err != nil {
			t.Fatal(err)
		}
		parentIdentity, err := m2IdentityFor(parent)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ObserveGeneratedSuccessor(context.Background(), oldIdentity, parentIdentity); err != nil {
			t.Fatalf("valid operational successor rejected: %v", err)
		}
		if err := s.restoreFixture(context.Background(), s.ledger.fixtures[fixtureKey(oldIdentity)]); err != nil {
			t.Fatalf("restoration rejected verified successor: %v", err)
		}
		got := &corev1.ConfigMap{}
		if err := admin.Get(context.Background(), client.ObjectKeyFromObject(newChild), got); err != nil || got.UID != newChild.UID {
			t.Fatalf("restoration mutated the successor: uid=%s err=%v", got.UID, err)
		}
	})
}

func TestUnitM2CorruptProcessFailureRetriesUnavailableLogsWithoutWeakeningProof(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "log-retry", UID: "pod-uid"}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "dhcp4", RestartCount: 1, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}}}}}}
	oldAdmin := admin
	oldNamespace := runtimeNamespace
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	runtimeNamespace = m2LabProfile.runtimeNamespace
	defer func() { admin, runtimeNamespace = oldAdmin, oldNamespace }()

	t.Run("transient CRI log retrieval eventually proves fail-closed startup", func(t *testing.T) {
		calls := 0
		read := func(context.Context, string) ([]byte, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("temporarily unavailable previous container log")
			}
			return []byte("FAILED: configuration hash mismatch; refusing startup"), nil
		}
		if err := m2WaitCorruptProcessFailureWith(context.Background(), *pod, read, 0); err != nil {
			t.Fatalf("transient log retrieval failure did not recover: %v", err)
		}
		if calls != 2 {
			t.Fatalf("previous log reader calls=%d, want 2", calls)
		}
	})
	t.Run("unexpected execution output is never accepted", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		calls := 0
		err := m2WaitCorruptProcessFailureWith(ctx, *pod, func(context.Context, string) ([]byte, error) {
			calls++
			return []byte("kea-dhcp4 -c /etc/kea/kea-dhcp4.conf"), nil
		}, 0)
		if err == nil || calls == 0 {
			t.Fatalf("non-failure output was accepted: calls=%d err=%v", calls, err)
		}
	})
	t.Run("replaced Pod incarnation is refused", func(t *testing.T) {
		replacement := pod.DeepCopy()
		replacement.UID = "replacement-uid"
		previous := admin
		admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(replacement).Build()
		defer func() { admin = previous }()
		called := false
		err := m2WaitCorruptProcessFailureWith(context.Background(), *pod, func(context.Context, string) ([]byte, error) {
			called = true
			return []byte("FAILED"), nil
		}, 0)
		if err == nil || called {
			t.Fatalf("replacement Pod was accepted or read: called=%t err=%v", called, err)
		}
	})
}

func TestUnitM2CaseWorkloadAbsenceRequiresNoCandidatePod(t *testing.T) {
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "absence", UID: "case-parent"}}
	configName, serviceName, setName := m2NamesFor(parent)
	if configName != "kg-7012d7ab28f9fabbbe82edd52aa92bb1-config" || serviceName != "kg-7012d7ab28f9fabbbe82edd52aa92bb1-headless" || setName != "kg-7012d7ab28f9fabbbe82edd52aa92bb1" {
		t.Fatalf("wrong workload names: %s %s %s", configName, serviceName, setName)
	}
	fixture := m2Fixture{m2FixtureIdentity: m2FixtureIdentity{Key: client.ObjectKeyFromObject(parent), GVK: infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"), UID: parent.UID}, Created: true, EndState: "absent"}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	oldAdmin := admin
	admin = fake.NewClientBuilder().WithScheme(scheme).Build()
	defer func() { admin = oldAdmin }()
	if err := m2CaseWorkloadAbsent(context.Background(), fixture, configName, serviceName, setName); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: setName + "-0", UID: "candidate"}}
	if err := admin.Create(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if err := m2CaseWorkloadAbsent(context.Background(), fixture, configName, serviceName, setName); err == nil {
		t.Fatal("candidate Pod survived absence proof")
	}
}

func TestUnitM2RolloutExecWaitsForExactReadyPodIncarnation(t *testing.T) {
	ready := func() *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "rollout-0", UID: "expected-uid", ResourceVersion: "1"}, Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			Conditions:        []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "dhcp4", Ready: true}, {Name: "dhcp6", Ready: true}},
		}}
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		pod     *corev1.Pod
		wantErr bool
	}{
		{name: "exact ready incarnation", pod: ready()},
		{name: "same-name replacement is refused", pod: func() *corev1.Pod { p := ready(); p.UID = "replacement-uid"; return p }(), wantErr: true},
		{name: "not ready before bounded deadline", pod: func() *corev1.Pod { p := ready(); p.Status.Conditions[0].Status = corev1.ConditionFalse; return p }(), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous, previousContext := admin, labctx
			labctx = context.Background()
			admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.pod).Build()
			defer func() { admin, labctx = previous, previousContext }()
			expected := *ready()
			observed, err := m2WaitExactPodReady(expected, 25*time.Millisecond)
			if (err != nil) != tc.wantErr {
				t.Fatalf("m2WaitExactPodReady error=%v wantErr=%t", err, tc.wantErr)
			}
			if !tc.wantErr && observed.UID != expected.UID {
				t.Fatalf("ready observation UID=%q want exact UID %q", observed.UID, expected.UID)
			}
		})
	}
}

func TestUnitM2FixtureCleanupWaitsForParentWorkloadGCBeforePodIncarnations(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "parent workload cleanup ordering", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "cleanup-parent", UID: "parent-uid", ResourceVersion: "1"}}
	intent, err := s.RecordCreateIntent(parent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCreateSubmitted(intent); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmCreated(intent, parent); err != nil {
		t.Fatal(err)
	}
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: "cleanup-set", UID: "set-uid", ResourceVersion: "2", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(parent, infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"))}}}
	oldPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: "cleanup-set-0", UID: "old-pod-uid", ResourceVersion: "3", Labels: map[string]string{"keaguard.example/cluster-uid": string(parent.UID)}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(set, appsv1.SchemeGroupVersion.WithKind("StatefulSet"))}}}
	if err := s.RecordFixture(oldPod, oldPod, "absent"); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, infrastructurev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	previousAdmin, previousWait := admin, m2WaitCaseWorkloadAbsentWork
	podDeleteBeforeWait := false
	gcPhase := false
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent.DeepCopy(), oldPod.DeepCopy()).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, isPod := obj.(*corev1.Pod); isPod && !gcPhase {
				podDeleteBeforeWait = true
			}
			return c.Delete(ctx, obj, opts...)
		},
	}).Build()
	m2WaitCaseWorkloadAbsentWork = func(ctx context.Context, fixture m2Fixture) error {
		if fixture.GVK != infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster") || fixture.UID != parent.UID {
			return fmt.Errorf("unexpected parent workload wait identity: %+v", fixture.m2FixtureIdentity)
		}
		liveParent := &infrastructurev1alpha1.KeaCluster{}
		if err := admin.Get(ctx, client.ObjectKeyFromObject(parent), liveParent); !apierrors.IsNotFound(err) {
			return fmt.Errorf("parent workload wait started before exact parent deletion: %v", err)
		}
		if podDeleteBeforeWait {
			return fmt.Errorf("fixture Pod cleanup raced ahead of parent workload GC wait")
		}
		gcPhase = true
		defer func() { gcPhase = false }()
		livePod := &corev1.Pod{}
		if err := admin.Get(ctx, client.ObjectKeyFromObject(oldPod), livePod); err != nil || livePod.UID != oldPod.UID {
			return fmt.Errorf("expected owner-GC Pod identity before workload wait: %v", err)
		}
		return admin.Delete(ctx, livePod, client.Preconditions{UID: &livePod.UID})
	}
	defer func() { admin, m2WaitCaseWorkloadAbsentWork = previousAdmin, previousWait }()
	if err := s.restoreFixtures(context.Background()); err != nil {
		t.Fatalf("ordered parent/workload restoration failed: %v", err)
	}
	if podDeleteBeforeWait {
		t.Fatal("fixture Pod was deleted before the parent-owned workload disappeared")
	}
	if !s.ledger.fixtures[fixtureKey(m2FixtureIdentity{Key: client.ObjectKeyFromObject(oldPod), GVK: corev1.SchemeGroupVersion.WithKind("Pod"), UID: oldPod.UID})].AbsentVerified {
		t.Fatal("Pod absence was not proved after the parent-owned workload wait")
	}
}

func TestUnitM2FixtureRecoveryRestoresEarliestConfigMapSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "restore-existing", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	original := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "existing", UID: "original", ResourceVersion: "12", Labels: map[string]string{"reserved": "original"}}, Data: map[string]string{"key": "original"}}
	if err := s.RecordFixture(original, original, "restored"); err != nil {
		t.Fatal(err)
	}
	drifted := original.DeepCopy()
	drifted.Data["key"] = "drifted"
	drifted.Labels["reserved"] = "drifted"
	identity, err := m2IdentityFor(original)
	if err != nil {
		t.Fatal(err)
	}
	fixture := s.ledger.fixtures[fixtureKey(identity)]
	fixture.Submitted = []client.Object{drifted.DeepCopy()}
	s.ledger.fixtures[fixtureKey(identity)] = fixture
	if err := s.persistLedger(); err != nil {
		t.Fatal(err)
	}
	clientScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(clientScheme); err != nil {
		t.Fatal(err)
	}
	previous := admin
	patches := 0
	admin = fake.NewClientBuilder().WithScheme(clientScheme).WithObjects(drifted).WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			patches++
			return c.Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	defer func() { admin = previous }()
	if err := s.restoreFixtures(context.Background()); err != nil {
		t.Fatal(err)
	}
	actual := &corev1.ConfigMap{}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(original), actual); err != nil {
		t.Fatal(err)
	}
	if actual.Data["key"] != "original" || actual.Labels["reserved"] != "original" || patches != 1 {
		t.Fatalf("earliest snapshot not restored exactly once: %+v patches=%d", actual, patches)
	}
	if err := s.restoreFixtures(context.Background()); err != nil || patches != 1 {
		t.Fatalf("no-op restoration issued another patch: err=%v patches=%d", err, patches)
	}
	actual.Data["key"] = "foreign-unrecorded"
	if err := admin.Update(context.Background(), actual); err != nil {
		t.Fatal(err)
	}
	if err := s.restoreFixtures(context.Background()); err == nil || patches != 1 {
		t.Fatalf("unrecorded foreign drift was restored or patched: err=%v patches=%d", err, patches)
	}
}

func TestUnitM2UpdateRecordsPreMutationSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "checked-update", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	original := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "fixture", UID: "original", ResourceVersion: "3"}, Data: map[string]string{"key": "original"}}
	clientScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(clientScheme); err != nil {
		t.Fatal(err)
	}
	previousAdmin, previousProfile, previousScenario := admin, selectedProfile, m2ActiveScenario
	admin = fake.NewClientBuilder().WithScheme(clientScheme).WithObjects(original).Build()
	selectedProfile, m2ActiveScenario = m2LabProfile, s
	defer func() { admin, selectedProfile, m2ActiveScenario = previousAdmin, previousProfile, previousScenario }()
	mutated := original.DeepCopy()
	mutated.Data["key"] = "changed"
	if err := m2UpdateObject(context.Background(), mutated, "restored"); err != nil {
		t.Fatal(err)
	}
	fixture := s.ledger.fixtures[fixtureKey(m2FixtureIdentity{Key: client.ObjectKeyFromObject(original), GVK: corev1.SchemeGroupVersion.WithKind("ConfigMap"), UID: original.UID})]
	if fixture.Original == nil || fixture.Original.(*corev1.ConfigMap).Data["key"] != "original" || len(fixture.Submitted) != 1 || fixture.Submitted[0].(*corev1.ConfigMap).Data["key"] != "changed" {
		t.Fatalf("pre-mutation snapshot was not retained: %+v", fixture)
	}
	replacement := mutated.DeepCopy()
	replacement.UID = "foreign"
	if err := admin.Update(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := m2UpdateObject(context.Background(), mutated, "restored"); err == nil {
		t.Fatal("replacement UID was accepted for update")
	}
}

func TestUnitM2GeneratedConfigMapMutationDoesNotCreateFixtureRestorationAuthority(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "generated-child-drift", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "parent", UID: "parent-uid", ResourceVersion: "1"}}
	intent, err := s.RecordCreateIntent(parent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCreateSubmitted(intent); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmCreated(intent, parent); err != nil {
		t.Fatal(err)
	}
	owner := metav1.NewControllerRef(parent, infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"))
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: "parent-config", UID: "config-uid", ResourceVersion: "7", Labels: map[string]string{"keaguard.example/cluster-uid": string(parent.UID)}, OwnerReferences: []metav1.OwnerReference{*owner}}, Data: map[string]string{"kea-dhcp4.conf": "original"}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := infrastructurev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	previousAdmin, previousScenario, previousProfile := admin, m2ActiveScenario, selectedProfile
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent, config).Build()
	m2ActiveScenario = s
	selectedProfile = m2LabProfile
	defer func() { admin, m2ActiveScenario, selectedProfile = previousAdmin, previousScenario, previousProfile }()
	parentIdentity, err := m2IdentityFor(parent)
	if err != nil {
		t.Fatal(err)
	}
	mutated := config.DeepCopy()
	mutated.Data["kea-dhcp4.conf"] = "controlled drift"
	if err := s.UpdateGeneratedConfigMap(context.Background(), mutated, parentIdentity); err != nil {
		t.Fatalf("update exact owned generated child: %v", err)
	}
	live := &corev1.ConfigMap{}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(config), live); err != nil {
		t.Fatal(err)
	}
	if live.UID != config.UID || live.Data["kea-dhcp4.conf"] != "controlled drift" {
		t.Fatalf("generated-child data mutation did not preserve its incarnation: %+v", live)
	}
	configIdentity, err := m2IdentityFor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, recorded := s.ledger.fixtures[fixtureKey(configIdentity)]; recorded {
		t.Fatal("operator-owned ConfigMap was granted independent fixture restoration authority")
	}
	stale := live.DeepCopy()
	stale.ResourceVersion = "stale"
	stale.Data["kea-dhcp4.conf"] = "stale mutation"
	if err := s.UpdateGeneratedConfigMap(context.Background(), stale, parentIdentity); err == nil {
		t.Fatal("stale ConfigMap resourceVersion was accepted")
	}
	foreign := live.DeepCopy()
	foreign.OwnerReferences[0].UID = "foreign-parent"
	if err := admin.Update(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	foreign = &corev1.ConfigMap{}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(config), foreign); err != nil {
		t.Fatal(err)
	}
	foreign.Data["kea-dhcp4.conf"] = "foreign mutation"
	if err := s.UpdateGeneratedConfigMap(context.Background(), foreign, parentIdentity); err == nil {
		t.Fatal("ConfigMap with a replaced owner identity was accepted")
	}
}

func TestUnitM2ReadyNativePodSuccessorIsObservedBeforeFixtureCleanup(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "native-pod-successor", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "parent", UID: "parent-uid", ResourceVersion: "1"}}
	parentIntent, err := s.RecordCreateIntent(parent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCreateSubmitted(parentIntent); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmCreated(parentIntent, parent); err != nil {
		t.Fatal(err)
	}
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: "set", UID: "set-uid", ResourceVersion: "2", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(parent, infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"))}}}
	old := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: "set-0", UID: "old-pod", ResourceVersion: "3", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(set, appsv1.SchemeGroupVersion.WithKind("StatefulSet"))}}}
	newPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: old.Namespace, Name: old.Name, UID: "new-pod", ResourceVersion: "4", Labels: map[string]string{"keaguard.example/cluster-uid": string(parent.UID)}, OwnerReferences: append([]metav1.OwnerReference(nil), old.OwnerReferences...)}, Spec: corev1.PodSpec{NodeName: m2LabProfile.nodes[1], Containers: []corev1.Container{{Name: "dhcp4", Image: m2KeaDHCP4Image}, {Name: "dhcp6", Image: m2KeaDHCP6Image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "dhcp4", Ready: true, ContainerID: "containerd://" + strings.Repeat("a", 64), ImageID: m2KeaDHCP4Image}, {Name: "dhcp6", Ready: true, ContainerID: "containerd://" + strings.Repeat("b", 64), ImageID: m2KeaDHCP6Image}}}}
	if err := s.RecordFixture(old, old, "absent"); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, infrastructurev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	previousAdmin, previousScenario, previousProfile := admin, m2ActiveScenario, selectedProfile
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent, set, newPod).Build()
	m2ActiveScenario = s
	selectedProfile = m2LabProfile
	defer func() { admin, m2ActiveScenario, selectedProfile = previousAdmin, previousScenario, previousProfile }()
	oldIdentity, err := m2IdentityFor(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := m2RecordReadyNativePodSuccessor(context.Background(), *old); err != nil {
		t.Fatalf("record native replacement before cleanup: %v", err)
	}
	fixture := s.ledger.fixtures[fixtureKey(oldIdentity)]
	if !fixture.AbsentVerified || !s.ledger.isConfirmedSuccessor(oldIdentity, newPod) {
		t.Fatal("fresh same-name Pod UID was not bound to the old fixture and exact owner chain")
	}
	if err := s.restoreFixture(context.Background(), fixture); err != nil {
		t.Fatalf("cleanup refused the verified successor without mutation authority: %v", err)
	}
	stillLive := &corev1.Pod{}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(newPod), stillLive); err != nil || stillLive.UID != newPod.UID {
		t.Fatalf("cleanup mutated the native replacement Pod: %+v %v", stillLive, err)
	}
}

func TestUnitM2AggregateRestorationAttemptsIndependentActions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	baseline := func(name string) *corev1.Namespace {
		labels := map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}
		for key, value := range m2ExpectedPolicy(name) {
			labels[key] = value
		}
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid"), Labels: labels}}
	}
	runtimeNS := baseline(m2LabProfile.runtimeNamespace)
	outsideNS := baseline(m2LabProfile.outsideNamespace)
	badRuntime := runtimeNS.DeepCopy()
	badRuntime.Labels["pod-security.kubernetes.io/enforce"] = "restricted"
	one, zero := int32(1), int32(0)
	manager := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: managerName, Namespace: m2LabProfile.runtimeNamespace, UID: "manager-uid"}, Spec: appsv1.DeploymentSpec{Replicas: &one}}
	badManager := manager.DeepCopy()
	badManager.Spec.Replicas = &zero
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "keaguard-manager-role", Namespace: m2LabProfile.runtimeNamespace, UID: "role-uid"}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"configmaps"}}}}
	badRole := role.DeepCopy()
	badRole.Rules = nil
	binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "keaguard-manager-rolebinding", Namespace: m2LabProfile.runtimeNamespace, UID: "binding-uid"}, RoleRef: rbacv1.RoleRef{Kind: "Role", Name: role.Name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: managerName}}}
	badBinding := binding.DeepCopy()
	badBinding.Subjects = nil
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: managerName, Namespace: m2LabProfile.runtimeNamespace, UID: "sa-uid"}}
	clientScheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, rbacv1.AddToScheme} {
		if err := add(clientScheme); err != nil {
			t.Fatal(err)
		}
	}
	previous := admin
	admin = fake.NewClientBuilder().WithScheme(clientScheme).WithObjects(badRuntime, outsideNS, badManager, badRole, badBinding, serviceAccount).Build()
	defer func() { admin = previous }()
	s := &m2Scenario{Name: "independent", evidenceDir: dir, NamespaceSnapshots: map[string]*corev1.Namespace{runtimeNS.Name: runtimeNS, outsideNS.Name: outsideNS}, KnownFaultPolicies: map[string]map[string]string{}, Manager: manager, ServiceAccount: serviceAccount, Role: role, RoleBinding: binding}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	verified := 0
	err := s.restoreAndVerify(context.Background(), func(context.Context, string, string) error { verified++; return nil }, func(context.Context, m2StoppedProcess) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "namespace") || verified != 1 {
		t.Fatalf("unexpected aggregate result: err=%v runtime-verifies=%d", err, verified)
	}
	gotManager := &appsv1.Deployment{}
	gotRole := &rbacv1.Role{}
	gotBinding := &rbacv1.RoleBinding{}
	ctx := context.Background()
	if err := admin.Get(ctx, client.ObjectKeyFromObject(manager), gotManager); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(role), gotRole); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(binding), gotBinding); err != nil {
		t.Fatal(err)
	}
	if gotManager.Spec.Replicas == nil || *gotManager.Spec.Replicas != one || len(gotRole.Rules) != 1 || len(gotBinding.Subjects) != 1 {
		t.Fatal("a namespace-policy failure skipped independently safe manager/RBAC restoration")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "recovery-pending.json")); statErr != nil {
		t.Fatalf("aggregate failure cleared recovery marker: %v", statErr)
	}
}

func TestUnitM2ServiceAccountBaselineRejectsReplacement(t *testing.T) {
	original := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: managerName, Namespace: m2LabProfile.runtimeNamespace, UID: "approved-sa"}}
	live := original.DeepCopy()
	live.UID = "replacement-sa"
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	oldAdmin := admin
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).Build()
	defer func() { admin = oldAdmin }()
	if err := m2VerifyServiceAccount(context.Background(), original); err == nil {
		t.Fatal("replacement ServiceAccount was accepted")
	}
}

func TestUnitM2RBACBaselineRejectsRuleAndBindingDrift(t *testing.T) {
	data, err := os.ReadFile("../../config/rbac/role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	role := &rbacv1.Role{}
	if err := yaml.Unmarshal(data, role); err != nil {
		t.Fatal(err)
	}
	role.Name, role.Namespace, role.UID = "keaguard-manager-role", m2LabProfile.runtimeNamespace, "role-uid"
	binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "keaguard-manager-rolebinding", Namespace: m2LabProfile.runtimeNamespace, UID: "binding-uid"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: managerName, Namespace: m2LabProfile.runtimeNamespace}}}
	if err := m2VerifyRBACBaseline(role, binding); err != nil {
		t.Fatalf("reviewed baseline rejected: %v", err)
	}
	drifted := role.DeepCopy()
	drifted.Rules[0].Verbs = append(drifted.Rules[0].Verbs, "update")
	if err := m2VerifyRBACBaseline(drifted, binding); err == nil {
		t.Fatal("extra manager RBAC verb accepted")
	}
	foreign := binding.DeepCopy()
	foreign.Subjects[0].Name = "other-service-account"
	if err := m2VerifyRBACBaseline(role, foreign); err == nil {
		t.Fatal("foreign RoleBinding subject accepted")
	}
}

func TestUnitM2DiagnosticsRequireSealedRecoveryAndStayReadOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "diagnostics", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	var eventArgs []string
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if name != "kubectl" || len(args) < 7 || args[0] != "--kubeconfig" || args[1] != m2LabProfile.kubeconfig || args[2] != "--context" || args[3] != "kind-"+m2LabProfile.cluster {
			t.Fatalf("unscoped diagnostic command: %s %v", name, args)
		}
		for _, arg := range args {
			if arg == "apply" || arg == "delete" || arg == "patch" || arg == "exec" {
				t.Fatalf("diagnostics attempted mutation: %v", args)
			}
		}
		if slices.Contains(args, "events") {
			eventArgs = append([]string(nil), args...)
		}
		return []byte("token: secret-value\nobservation=ok\n"), nil
	}
	if err := s.captureDiagnostics(context.Background(), runner); err == nil || calls != 0 {
		t.Fatalf("diagnostics ran before recovery seal: err=%v calls=%d", err, calls)
	}
	if err := s.sealRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.captureDiagnostics(context.Background(), runner); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("expected manager logs, Pod inventory and bounded event summary, got %d", calls)
	}
	eventJSONPath := ""
	for _, arg := range eventArgs {
		if strings.HasPrefix(arg, "-o=jsonpath={range .items[-20:]}") {
			eventJSONPath = arg
		}
	}
	if !slices.Contains(eventArgs, "--sort-by=.metadata.creationTimestamp") || eventJSONPath == "" || strings.Contains(eventJSONPath, "{.message}") {
		t.Fatalf("event diagnostic is not sorted and limited to the newest 20 items: %v", eventArgs)
	}
	for _, field := range []string{".metadata.creationTimestamp", ".type", ".reason", ".involvedObject.kind", ".involvedObject.name", ".count"} {
		if !strings.Contains(eventJSONPath, "{"+field+"}") {
			t.Errorf("bounded event summary omitted %s: %s", field, eventJSONPath)
		}
	}
	for _, file := range []string{"diagnostic-manager-logs-" + s.caseID + ".txt", "diagnostic-namespace-" + s.caseID + ".txt", "diagnostic-events-" + s.caseID + ".txt"} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil || strings.Contains(string(data), "secret-value") || !strings.Contains(string(data), "observation=ok") {
			t.Fatalf("diagnostic evidence not private/redacted: %s %v", data, err)
		}
	}
}

func TestUnitM2RecoveryGuardRequiresVerifiedDiagnosticFailureReconciliation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	caseID := "123456789-42"
	diagnostic := []byte(`{"caseID":"123456789-42","status":"failed","error":"bounded command kubectl output exceeded 256 KiB"}` + "\n")
	recovery := []byte(`{"caseID":"123456789-42","name":"M2: Process recovery restarts the manager across a pending desired rollout","recovery":"restored","namespaceUIDs":{"keaguard-m2-runtime":"runtime-uid","keaguard-m2-outside":"outside-uid"},"image":"keaguard-operator:m2-bbbbbbbbbbbb","imageID":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}` + "\n")
	ledger := []byte(`{"scenario":"M2: Process recovery restarts the manager across a pending desired rollout","fixtures":[{"key":{"Namespace":"keaguard-m2-runtime","Name":"runtime-info-test"},"gvk":{"Group":"infrastructure.keaguard.example","Version":"v1alpha1","Kind":"KeaCluster"},"uid":"fixture-uid","created":true,"endState":"absent","absentVerified":true}],"intents":[{"phase":"confirmed"}],"stopped":[]}` + "\n")
	namespaceReceipt := []byte(`{"lab":{"cluster":"keaguard-m2-disposable","nodes":{"keaguard-m2-disposable-control-plane":{"kubernetesUID":"node-uid-1","dockerID":"1111111111111111111111111111111111111111111111111111111111111111","image":"kindest/node:v1.37.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","imageID":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"keaguard-m2-disposable-worker":{"kubernetesUID":"node-uid-2","dockerID":"2222222222222222222222222222222222222222222222222222222222222222","image":"kindest/node:v1.37.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","imageID":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"keaguard-m2-disposable-worker2":{"kubernetesUID":"node-uid-3","dockerID":"3333333333333333333333333333333333333333333333333333333333333333","image":"kindest/node:v1.37.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","imageID":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}},"namespaces":{"keaguard-m2-runtime":{"uid":"runtime-uid","labels":{"keaguard.example/e2e-owner":"keaguard-m2-disposable"},"policy":{"pod-security.kubernetes.io/enforce":"privileged","pod-security.kubernetes.io/enforce-version":"v1.37"}},"keaguard-m2-outside":{"uid":"outside-uid","labels":{"keaguard.example/e2e-owner":"keaguard-m2-disposable"},"policy":{"pod-security.kubernetes.io/enforce":"restricted","pod-security.kubernetes.io/enforce-version":"v1.37"}}}}` + "\n")
	namespaceReceipt = []byte(strings.ReplaceAll(string(namespaceReceipt), strings.Repeat("b", 64), strings.TrimPrefix(m2LabProfile.nodeImage, "kindest/node:v1.37.0@sha256:")))
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("diagnostics.json", diagnostic)
	write("diagnostics-"+caseID+".json", diagnostic)
	write("recovery-restored-"+caseID+".json", recovery)
	write("ledger.json", ledger)
	write("namespace-receipt.json", namespaceReceipt)
	var namespaceIdentity struct {
		Lab struct {
			Nodes map[string]m2ReconciledNode `json:"nodes"`
		} `json:"lab"`
	}
	if err := json.Unmarshal(namespaceReceipt, &namespaceIdentity); err != nil {
		t.Fatal(err)
	}
	if err := m2CheckNoPendingRecovery(dir); err == nil {
		t.Fatal("failed diagnostic state accepted without a separate reconciliation receipt")
	}
	receipt := m2DiagnosticFailureReconciliation{
		CaseID: caseID, Status: m2DiagnosticReconciliationStatus, ScenarioName: "M2: Process recovery restarts the manager across a pending desired rollout",
		DiagnosticsStatus: "failed", OriginalDiagnosticsSHA256: m2SHA256(diagnostic), OriginalRecordPreserved: true,
		RecoveryReceiptSHA256: m2SHA256(recovery), LedgerSHA256: m2SHA256(ledger), NamespaceReceiptSHA256: m2SHA256(namespaceReceipt), LiveAuditVerified: true,
		SourceFingerprint: strings.Repeat("b", 64), OperatorImage: "keaguard-operator:m2-bbbbbbbbbbbb", OperatorIndex: "sha256:" + strings.Repeat("a", 64),
		Manifest: "sha256:" + strings.Repeat("c", 64), Config: "sha256:" + strings.Repeat("d", 64), AllLayersVerified: true, AllM2NodeCRIReferences: true, AllKeaReferences: true,
		Fixture: m2ReconciledFixture{GVK: "infrastructure.keaguard.example/v1alpha1, Kind=KeaCluster", Namespace: "keaguard-m2-runtime", Name: "runtime-info-test", UID: "fixture-uid", LiveResult: "API_NOT_FOUND", ChildrenAbsent: true},
		Namespaces: map[string]m2ReconciledNamespace{
			"keaguard-m2-runtime": {UID: "runtime-uid", Owner: "keaguard-m2-disposable", Enforce: "privileged", Version: "v1.37"},
			"keaguard-m2-outside": {UID: "outside-uid", Owner: "keaguard-m2-disposable", Enforce: "restricted", Version: "v1.37"},
		},
		Manager:            m2ReconciledManager{DeploymentUID: "deployment-uid", Generation: 2, ObservedGeneration: 2, ReadyReplicas: 1, Image: "keaguard-operator:m2-bbbbbbbbbbbb", CRIImage: "docker.io/library/keaguard-operator:m2-aaaaaaaaaaaa", CRIImageIndex: "sha256:" + strings.Repeat("e", 64), CRIManifest: "sha256:" + strings.Repeat("c", 64), ImageIDManifest: "sha256:" + strings.Repeat("c", 64), CRIConfig: "sha256:" + strings.Repeat("d", 64), PodUID: "manager-pod-uid", ContainerID: "containerd://" + strings.Repeat("1", 64), ImageID: "docker.io/library/import-2026-10-18@sha256:" + strings.Repeat("d", 64), Node: "keaguard-m2-disposable-worker2", RoleUID: "role-uid", RoleBindingUID: "binding-uid", ServiceAccountUID: "sa-uid"},
		Nodes:              namespaceIdentity.Lab.Nodes,
		NoActiveOperations: true, M1ClusterPresent: true, ScenarioPass: false,
	}
	liveAudit := m2DiagnosticLiveAudit{CaseID: caseID, Cluster: m2LabProfile.cluster, Context: "kind-" + m2LabProfile.cluster, APIReady: true,
		Fixture: receipt.Fixture, Namespaces: receipt.Namespaces, Nodes: receipt.Nodes, Manager: receipt.Manager, NoActiveOperations: true,
		M1ControlPlaneDockerID: strings.Repeat("f", 64)}
	liveAuditBytes, err := json.Marshal(liveAudit)
	if err != nil {
		t.Fatal(err)
	}
	liveAuditBytes = append(liveAuditBytes, '\n')
	write("diagnostics-live-audit-"+caseID+".json", liveAuditBytes)
	receipt.LiveAuditSHA256 = m2SHA256(liveAuditBytes)
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	write("diagnostics-reconciled-"+caseID+".json", append(encoded, '\n'))
	if err := m2CheckNoPendingRecovery(dir); err != nil {
		t.Fatalf("valid restoration-only diagnostic reconciliation rejected: %v", err)
	}
	t.Run("stale manager incarnation is rejected", func(t *testing.T) {
		stale := receipt
		stale.Manager.PodUID = "replacement-pod-uid"
		data, err := json.Marshal(stale)
		if err != nil {
			t.Fatal(err)
		}
		write("diagnostics-reconciled-"+caseID+".json", append(data, '\n'))
		if err := m2CheckNoPendingRecovery(dir); err == nil {
			t.Fatal("reconciliation accepted a replaced manager Pod")
		}
		write("diagnostics-reconciled-"+caseID+".json", append(encoded, '\n'))
	})
	t.Run("tampered live audit is rejected", func(t *testing.T) {
		write("diagnostics-live-audit-"+caseID+".json", []byte(`{"caseID":"123456789-42"}`))
		if err := m2CheckNoPendingRecovery(dir); err == nil {
			t.Fatal("reconciliation accepted a changed live-audit record")
		}
		write("diagnostics-live-audit-"+caseID+".json", liveAuditBytes)
	})
	t.Run("preserved original diagnostic must match", func(t *testing.T) {
		write("diagnostics-"+caseID+".json", []byte(`{"caseID":"123456789-42","status":"ok"}`))
		if err := m2CheckNoPendingRecovery(dir); err == nil {
			t.Fatal("reconciliation accepted a changed original diagnostic record")
		}
	})
}

func TestM2PrivateDiagnosticFailureReconciliationReceipt(t *testing.T) {
	if os.Getenv("KEAGUARD_M2_VERIFY_PRIVATE_RECONCILIATION") != "1" {
		t.Skip("explicit read-only verification of private interrupted-scenario reconciliation")
	}
	if err := m2CheckNoPendingRecovery(m2NativeDir); err != nil {
		t.Fatalf("private diagnostic/restoration reconciliation did not verify: %v", err)
	}
}

func TestUnitM2ScenarioRecoverySealsBeforeDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name           string
		restoreFailure bool
		diagFailure    bool
		cancelRestore  bool
		wantMarker     bool
		wantReceipt    bool
		wantStatus     string
	}{
		{name: "success", wantReceipt: true, wantStatus: "ok"},
		{name: "incomplete restoration", restoreFailure: true, wantMarker: true, wantStatus: "skipped-recovery-incomplete"},
		{name: "cancelled restoration", cancelRestore: true, wantMarker: true, wantStatus: "skipped-recovery-incomplete"},
		{name: "diagnostic failure", diagFailure: true, wantReceipt: true, wantStatus: "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			s := &m2Scenario{Name: tc.name, evidenceDir: dir, ledger: newM2FixtureLedger(), NamespaceUIDs: map[string]types.UID{m2LabProfile.runtimeNamespace: "runtime-uid"}}
			if err := s.startEvidence(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stages := []string{}
			err := s.runRecovery(ctx, func(context.Context) error {
				stages = append(stages, "restore")
				if _, statErr := os.Stat(filepath.Join(dir, "recovery-pending.json")); statErr != nil {
					t.Fatalf("pending marker absent during restoration: %v", statErr)
				}
				if tc.cancelRestore {
					cancel()
					return ctx.Err()
				}
				if tc.restoreFailure {
					return errors.New("unproved baseline")
				}
				return nil
			}, func(context.Context) error {
				stages = append(stages, "diagnostics")
				if _, statErr := os.Stat(filepath.Join(dir, "recovery-pending.json")); !os.IsNotExist(statErr) {
					t.Fatalf("diagnostics ran before pending marker removal: %v", statErr)
				}
				if _, statErr := os.Stat(s.receiptPath); statErr != nil {
					t.Fatalf("diagnostics ran before verified receipt: %v", statErr)
				}
				if tc.diagFailure {
					return errors.New("bounded capture failed")
				}
				return nil
			})
			if (err == nil) != (tc.wantStatus == "ok") {
				t.Fatalf("recovery result=%v stages=%v", err, stages)
			}
			if (len(stages) == 2) != tc.wantReceipt || stages[0] != "restore" {
				t.Fatalf("wrong restoration/diagnostic order: %v", stages)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "recovery-pending.json")); (statErr == nil) != tc.wantMarker {
				t.Fatalf("resource marker presence mismatch: %v", statErr)
			}
			if _, statErr := os.Stat(s.receiptPath); (statErr == nil) != tc.wantReceipt {
				t.Fatalf("verified receipt presence mismatch: %v", statErr)
			}
			data, readErr := os.ReadFile(filepath.Join(dir, "diagnostics.json"))
			if readErr != nil || !strings.Contains(string(data), `"status":"`+tc.wantStatus+`"`) {
				t.Fatalf("wrong independent diagnostics result: %s, %v", data, readErr)
			}
			if tc.wantStatus != "ok" && m2CheckNoPendingRecovery(dir) == nil {
				t.Fatal("next invasive scenario accepted unresolved recovery/diagnostics")
			}
		})
	}
}

func TestUnitM2SlowManagerAttestationIsContextBoundAndTimed(t *testing.T) {
	oldReporter := m2RecoveryTimingReporter
	defer func() { m2RecoveryTimingReporter = oldReporter }()
	events := []m2RecoveryTimingEvent{}
	m2RecoveryTimingReporter = func(event m2RecoveryTimingEvent) { events = append(events, event) }

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	attempts := 0
	started := time.Now()
	err := m2WaitManagerHealthyForCase(ctx, "case-1", "operator:m2-123456789abc", "sha256:"+strings.Repeat("a", 64), func(ctx context.Context, _, _ string) error {
		attempts++
		<-ctx.Done()
		return ctx.Err()
	})
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) || attempts != 1 || elapsed > 300*time.Millisecond {
		t.Fatalf("slow attestation escaped its caller deadline or retried stale identity: attempts=%d elapsed=%s err=%v", attempts, elapsed, err)
	}
	if len(events) != 1 || events[0].CaseID != "case-1" || events[0].Stage != "manager-health-attestation" || events[0].Result != "failed" || events[0].DurationMS < 20 || events[0].StartedUTC == "" {
		t.Fatalf("missing accurate slow-attestation timing: %+v", events)
	}
}

func TestUnitM2ManagerAttestationMaySpanMultipleBoundedOperations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second+400*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := m2WaitManagerHealthyForCase(ctx, "case-aggregate-bound", "operator:m2-123456789abc", "sha256:"+strings.Repeat("a", 64), func(ctx context.Context, _, _ string) error {
		// The real manager attestation composes many individually bounded Docker,
		// CRI and API operations; their aggregate may exceed ten seconds while
		// remaining inside the critical-recovery caller's larger deadline.
		timer := time.NewTimer(10*time.Second + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	})
	if err != nil {
		t.Fatalf("complete attestation was incorrectly limited by a per-attempt aggregate timeout: %v", err)
	}
	if elapsed := time.Since(started); elapsed < 10*time.Second+100*time.Millisecond || elapsed >= 10*time.Second+350*time.Millisecond {
		t.Fatalf("attestation did not finish within the caller budget: elapsed=%s", elapsed)
	}
}

func TestUnitM2RecoveryGuard(t *testing.T) {
	dir := t.TempDir()
	if err := m2CheckNoPendingRecovery(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recovery-pending.json"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2CheckNoPendingRecovery(dir); err == nil {
		t.Fatal("unresolved recovery marker accepted")
	}
}

func TestUnitM2RecoveryGuardRequiresCaseMatchedRestorationReceiptWhenDiagnosticsWereSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	diagnostic := []byte(`{"caseID":"123-1","status":"skipped-recovery-incomplete"}`)
	if err := os.WriteFile(filepath.Join(dir, "diagnostics.json"), diagnostic, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "diagnostics-123-1.json"), diagnostic, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2CheckNoPendingRecovery(dir); err == nil {
		t.Fatal("skipped diagnostics without a reconciliation receipt were accepted")
	}
	archivedMarker := []byte(`{"caseID":"123-1","name":"failed","phase":"scenario"}`)
	markerHash := sha256.Sum256(archivedMarker)
	ledger := `{"scenario":"failed","fixtures":[{"key":{"Namespace":"runtime","Name":"fixture"},"gvk":{"Group":"infrastructure.keaguard.example","Version":"v1alpha1","Kind":"KeaCluster"},"uid":"parent-uid","created":true,"endState":"absent","absentVerified":true},{"key":{"Namespace":"runtime","Name":"fixture"},"gvk":{"Group":"","Version":"v1","Kind":"ConfigMap"},"uid":"artifact-uid","created":false,"endState":"restored","absentVerified":false,"original":{"metadata":{"name":"fixture","namespace":"runtime","uid":"artifact-uid","labels":{"keaguard.example/artifact":"reconciliation"},"annotations":{"keaguard.example/purpose":"Internal reconciliation artifact; not operational Kea DHCP configuration."},"ownerReferences":[{"apiVersion":"infrastructure.keaguard.example/v1alpha1","kind":"KeaCluster","name":"fixture","uid":"parent-uid","controller":true}]},"data":{"keacluster-name":"fixture","keacluster-namespace":"runtime","keacluster-uid":"parent-uid"}}}],"stopped":[]}`
	ledgerHash := m2SHA256([]byte(ledger))
	valid := `{"caseID":"123-1","status":"VERIFIED_RESTORATION_ONLY_NOT_SCENARIO_PASS","originalLedgerSHA256":"` + ledgerHash + `","originalScenario":{"name":"failed","scenarioResult":"FAILED_ABORTED","diagnosticsStatus":"skipped-recovery-incomplete","recoveryMarkerSHA256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"fixtures":[{"gvk":"infrastructure.keaguard.example/v1alpha1, Kind=KeaCluster","namespace":"runtime","name":"fixture","uid":"parent-uid","liveResult":"API_NOT_FOUND","restorationBasis":"case-created-absent","sameNameOwnedChildren":"NONE","ownerLabelledRuntimeChildren":"NONE"},{"gvk":"/v1, Kind=ConfigMap","namespace":"runtime","name":"fixture","uid":"artifact-uid","liveResult":"API_NOT_FOUND","restorationBasis":"owner-garbage-collected","parentUID":"parent-uid","sameNameOwnedChildren":"NONE","ownerLabelledRuntimeChildren":"NONE"}],"namespaces":[{"name":"runtime","uid":"runtime-uid"},{"name":"outside","uid":"outside-uid"}],"manager":{"deployment":{"uid":"deployment-uid","generation":1,"observedGeneration":1,"readyReplicas":1,"image":"operator:m2-0123456789ab"},"pod":{"uid":"pod-uid","ready":true,"configuredImage":"operator:m2-0123456789ab"},"roleUID":"role-uid","roleBindingUID":"binding-uid","serviceAccountUID":"sa-uid"},"identity":{"sourceFingerprint":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","operatorTag":"operator:m2-0123456789ab","buildIID":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","manifest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","config":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","namespaceUIDsMatchReceipt":true,"nodeUIDsAndDockerIDsMatchReceipt":true,"allM2CRIImageReferencesVerified":true,"m1ControlPlaneUnchanged":true},"restoration":{"fixtures":"VERIFIED_ABSENT","namespacePolicies":"VERIFIED_MATCH_ORIGINAL_RECEIPT","managerAndRBAC":"VERIFIED_HEALTHY_EXPECTED_IDENTITIES","stoppedProcesses":"NONE_RECORDED","activeTestOrRecoveryProcess":"NONE_OBSERVED"},"diagnostics":{"status":"skipped-recovery-incomplete","originalRecordPreserved":true}}`
	valid = strings.Replace(valid, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", hex.EncodeToString(markerHash[:]), 1)
	receipt := filepath.Join(dir, "recovery-reconciled-123-1.json")
	if err := os.WriteFile(filepath.Join(dir, "recovery-pending-archived-123-1.json"), archivedMarker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ledger.json"), []byte(ledger), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipt, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(dir, "recovery-pending.json")
	if err := os.WriteFile(markerPath, archivedMarker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, []byte(`{"caseID":"123-2"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2RetireReconciledRecoveryMarker(dir, "123-1"); err == nil {
		t.Fatal("marker retirement accepted a different active marker incarnation")
	}
	if err := os.WriteFile(markerPath, archivedMarker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2RetireReconciledRecoveryMarker(dir, "123-1"); err != nil {
		t.Fatalf("verified marker retirement failed: %v", err)
	}
	if err := m2CheckNoPendingRecovery(dir); err != nil {
		t.Fatalf("verified restoration-only receipt should permit continuation without rewriting diagnostics: %v", err)
	}
	t.Run("runtime scenario result does not misstate admission Gate B", func(t *testing.T) {
		runtimeReceipt := strings.Replace(valid, `"scenarioResult":"FAILED_ABORTED"`, `"gateBResult":"FAILED_ABORTED"`, 1)
		if runtimeReceipt == valid {
			t.Fatal("test fixture did not replace the admission-specific result field")
		}
		if err := os.WriteFile(receipt, []byte(runtimeReceipt), 0600); err != nil {
			t.Fatal(err)
		}
		if err := m2CheckNoPendingRecovery(dir); err != nil {
			t.Fatalf("runtime restoration receipt should record its own failed scenario without mislabeling Gate B: %v", err)
		}
		if err := os.WriteFile(receipt, []byte(valid), 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("archived marker bytes mismatch", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(dir, "recovery-pending-archived-123-1.json"), []byte("different marker"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := m2CheckNoPendingRecovery(dir); err == nil {
			t.Fatal("reconciliation receipt accepted a different archived marker")
		}
		if err := os.WriteFile(filepath.Join(dir, "recovery-pending-archived-123-1.json"), archivedMarker, 0600); err != nil {
			t.Fatal(err)
		}
	})
	for name, changed := range map[string]string{
		"wrong case":                  strings.Replace(valid, `"caseID":"123-1"`, `"caseID":"123-2"`, 1),
		"claims scenario pass":        strings.Replace(valid, "VERIFIED_RESTORATION_ONLY_NOT_SCENARIO_PASS", "PASS", 1),
		"claims diagnostics success":  strings.Replace(valid, `"status":"skipped-recovery-incomplete","originalRecordPreserved":true`, `"status":"ok","originalRecordPreserved":true`, 1),
		"fixture not absent":          strings.Replace(valid, "API_NOT_FOUND", "PRESENT", 1),
		"owner-GC parent mismatch":    strings.Replace(valid, `"parentUID":"parent-uid"`, `"parentUID":"foreign-uid"`, 1),
		"ledger hash mismatch":        strings.Replace(valid, ledgerHash, strings.Repeat("0", 64), 1),
		"namespace identity unproved": strings.Replace(valid, `"namespaceUIDsMatchReceipt":true`, `"namespaceUIDsMatchReceipt":false`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(receipt, []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
			if err := m2CheckNoPendingRecovery(dir); err == nil {
				t.Fatal("accepted an invalid restoration-only reconciliation receipt")
			}
		})
	}
}

func TestUnitM2RecoveryGuardRejectsUnfinishedReceiptWrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "diagnostics.json.new"), []byte(`{"status":"ok"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2CheckNoPendingRecovery(dir); err == nil {
		t.Fatal("unfinished diagnostic receipt write was accepted")
	}
}

func TestUnitM2ProjectionFaultRequiresVerifiedCorruptProjection(t *testing.T) {
	t.Run("unobserved projection blocks fault injection", func(t *testing.T) {
		faultCalls := 0
		continued := m2RunAfterVerifiedProjection(func() bool { return false }, func() { faultCalls++ })
		if continued || faultCalls != 0 {
			t.Fatalf("unverified projection must block fault injection: continued=%t faultCalls=%d", continued, faultCalls)
		}
	})
	t.Run("verified projection permits fault injection", func(t *testing.T) {
		faultCalls := 0
		continued := m2RunAfterVerifiedProjection(func() bool { return true }, func() { faultCalls++ })
		if !continued || faultCalls != 1 {
			t.Fatalf("verified projection should invoke fault injection once: continued=%t faultCalls=%d", continued, faultCalls)
		}
	})
}

func TestUnitM2ObservationAlwaysRestoresBeforeReturning(t *testing.T) {
	t.Run("restore follows a failed observation", func(t *testing.T) {
		var order []string
		ctx := context.Background()
		wantErr := errors.New("fault observation failed")
		err := m2ObserveThenRestore(ctx, time.Second,
			func(context.Context) error {
				order = append(order, "observe")
				return wantErr
			},
			func(restoreCtx context.Context) error {
				if restoreCtx.Err() != nil {
					t.Fatalf("restoration inherited the expired observation context: %v", restoreCtx.Err())
				}
				order = append(order, "restore")
				return nil
			})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected original observation error, got %v", err)
		}
		if !reflect.DeepEqual(order, []string{"observe", "restore"}) {
			t.Fatalf("restoration did not run after observation: %v", order)
		}
	})
	t.Run("restoration failure is reported after timeout", func(t *testing.T) {
		var order []string
		ctx := context.Background()
		wantRestoreErr := errors.New("source restore failed")
		err := m2ObserveThenRestore(ctx, 10*time.Millisecond,
			func(waitCtx context.Context) error {
				order = append(order, "observe")
				<-waitCtx.Done()
				return waitCtx.Err()
			},
			func(restoreCtx context.Context) error {
				if restoreCtx.Err() != nil {
					t.Fatalf("restoration inherited the expired observation context: %v", restoreCtx.Err())
				}
				order = append(order, "restore")
				return wantRestoreErr
			})
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, wantRestoreErr) {
			t.Fatalf("observation timeout and restoration error must both be retained: %v", err)
		}
		if !reflect.DeepEqual(order, []string{"observe", "restore"}) {
			t.Fatalf("restoration did not run after timeout: %v", order)
		}
	})
}

func TestUnitM2StalledPolicyObservationPreservesDesiredStateAndOldPods(t *testing.T) {
	previous, current, config, set, pods := m2StalledPolicyFixture()
	observation := m2StalledPolicyObservation{
		Previous: previous, Current: current, PreviousHash: "old-hash", DesiredHash: m2ConfigMapHash(config.Data),
		Config: config, StatefulSet: set, PreviousStatefulSetUID: set.UID,
		PreviousStatefulSetGeneration: 1, PreviousPodUIDs: map[string]types.UID{pods[0].Name: pods[0].UID, pods[1].Name: pods[1].UID}, Pods: pods[:1],
	}
	if err := m2CheckStalledPolicyObservation(observation); err != nil {
		t.Fatalf("valid baseline-stalled desired state rejected: %v", err)
	}

	for name, mutate := range map[string]func(*m2StalledPolicyObservation){
		"old configuration rolled back": func(o *m2StalledPolicyObservation) {
			o.Config.Data["kea-dhcp4.conf"] = `{"Dhcp4":{"loggers":[{"severity":"INFO"}]}}`
		},
		"template hash reverted": func(o *m2StalledPolicyObservation) {
			o.StatefulSet.Spec.Template.Annotations["keaguard.example/config-hash"] = o.PreviousHash
		},
		"ready condition false missing": func(o *m2StalledPolicyObservation) {
			setM2Condition(o.Current, "WorkloadReady", metav1.ConditionTrue, "ProcessesHealthy", o.Current.Generation)
		},
		"reconciliation regressed": func(o *m2StalledPolicyObservation) {
			setM2Condition(o.Current, "WorkloadReconciled", metav1.ConditionFalse, "ResourcesOutOfSync", o.Current.Generation)
		},
		"pod incarnation replaced": func(o *m2StalledPolicyObservation) { o.Pods[0].UID = "unexpected-replacement" },
		"highest ordinal was not blocked": func(o *m2StalledPolicyObservation) {
			o.Pods = append(o.Pods, *o.Pods[0].DeepCopy())
			o.Pods[1].Name = o.StatefulSet.Name + "-1"
			o.Pods[1].UID = o.PreviousPodUIDs[o.Pods[1].Name]
		},
		"lower ordinal missing": func(o *m2StalledPolicyObservation) { o.Pods = nil },
		"wrong ordinal remains": func(o *m2StalledPolicyObservation) {
			o.Pods[0].Name = o.StatefulSet.Name + "-1"
			o.Pods[0].UID = o.PreviousPodUIDs[o.Pods[0].Name]
		},
		"stale generation": func(o *m2StalledPolicyObservation) { o.Current.Status.ObservedGeneration-- },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneM2StalledPolicyObservation(observation)
			mutate(&changed)
			if err := m2CheckStalledPolicyObservation(changed); err == nil {
				t.Fatal("accepted stalled rollout without the reviewed identity/status invariants")
			}
		})
	}
}

func TestUnitM2PodDriftObservationDoesNotTrustStaleReadyStatus(t *testing.T) {
	observation := m2PodDriftFixture()
	if !podReady(&observation.CurrentPod) {
		t.Fatal("fixture must preserve a stale Ready status to exercise spec-first drift detection")
	}
	if err := m2CheckPodDriftObservation(observation); err != nil {
		t.Fatalf("PodDrift with stale Ready status rejected: %v", err)
	}
	for name, mutate := range map[string]func(*m2PodDriftObservation){
		"replaced Pod UID": func(o *m2PodDriftObservation) { o.CurrentPod.UID = "new-incarnation" },
		"template changed": func(o *m2PodDriftObservation) {
			o.CurrentStatefulSet.Spec.Template.Spec.Containers[0].Image = o.CurrentPod.Spec.Containers[0].Image
		},
		"ready condition not false": func(o *m2PodDriftObservation) {
			setM2Condition(o.Current, "WorkloadReady", metav1.ConditionTrue, "ProcessesHealthy", o.Current.Generation)
		},
		"wrong drift reason": func(o *m2PodDriftObservation) {
			setM2Condition(o.Current, "WorkloadReady", metav1.ConditionFalse, "RolloutPending", o.Current.Generation)
		},
		"unrelated Pod spec drift": func(o *m2PodDriftObservation) { o.CurrentPod.Spec.HostNetwork = true },
		"image outside approved repository": func(o *m2PodDriftObservation) {
			o.CurrentPod.Spec.Containers[0].Image = "foreign.example/kea@sha256:" + strings.Repeat("0", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneM2PodDriftObservation(observation)
			mutate(&changed)
			if err := m2CheckPodDriftObservation(changed); err == nil {
				t.Fatal("accepted stale, foreign, or uncorroborated PodDrift observation")
			}
		})
	}
}

func TestUnitM2DisabledCleanupObservationRequiresOrderedSafeStates(t *testing.T) {
	previous, current, set, pods, service, config := m2DisabledCleanupFixture()
	cases := []struct {
		name   string
		want   int
		mutate func(*m2DisabledCleanupObservation)
	}{
		{name: "replicas zero before Pods stop", want: 0},
		{name: "Pods absent while StatefulSet remains", want: 1, mutate: func(o *m2DisabledCleanupObservation) { o.Pods = nil }},
		{name: "StatefulSet absent before Service", want: 2, mutate: func(o *m2DisabledCleanupObservation) { o.Pods = nil; o.StatefulSet = nil }},
		{name: "Service absent before configuration", want: 3, mutate: func(o *m2DisabledCleanupObservation) { o.Pods = nil; o.StatefulSet = nil; o.Service = nil }},
		{name: "fully cleaned and disabled", want: 4, mutate: func(o *m2DisabledCleanupObservation) {
			o.Pods = nil
			o.StatefulSet = nil
			o.Service = nil
			o.ConfigMap = nil
			setM2Condition(o.Current, "WorkloadReconciled", metav1.ConditionTrue, "WorkloadDisabled", o.Current.Generation)
			setM2Condition(o.Current, "WorkloadReady", metav1.ConditionTrue, "WorkloadDisabled", o.Current.Generation)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observation := cloneM2DisabledCleanupObservation(m2DisabledCleanupObservation{Previous: previous, Current: current, StatefulSet: set, Pods: pods, Service: service, ConfigMap: config})
			if tc.mutate != nil {
				tc.mutate(&observation)
			}
			got, err := m2CheckDisabledCleanupObservation(observation)
			if err != nil || got != tc.want {
				t.Fatalf("disabled cleanup observation stage=%d err=%v, want stage=%d", got, err, tc.want)
			}
		})
	}

	for name, mutate := range map[string]func(*m2DisabledCleanupObservation){
		"Service before StatefulSet":               func(o *m2DisabledCleanupObservation) { o.Service = nil },
		"configuration before Service":             func(o *m2DisabledCleanupObservation) { o.ConfigMap = nil },
		"Pods remain after StatefulSet disappears": func(o *m2DisabledCleanupObservation) { o.StatefulSet = nil },
		"nonzero replicas":                         func(o *m2DisabledCleanupObservation) { *o.StatefulSet.Spec.Replicas = 1 },
		"stale parent generation":                  func(o *m2DisabledCleanupObservation) { o.Current.Status.ObservedGeneration-- },
		"foreign StatefulSet owner":                func(o *m2DisabledCleanupObservation) { o.StatefulSet.OwnerReferences[0].UID = "foreign-parent" },
		"wrong Pod owner incarnation":              func(o *m2DisabledCleanupObservation) { o.Pods[0].OwnerReferences[0].UID = "replaced-statefulset" },
		"wrong Pod cluster UID label": func(o *m2DisabledCleanupObservation) {
			o.Pods[0].Labels["keaguard.example/cluster-uid"] = "replaced-parent"
		},
		"replaced parent UID": func(o *m2DisabledCleanupObservation) { o.Current.UID = "new-parent" },
	} {
		t.Run(name, func(t *testing.T) {
			observation := cloneM2DisabledCleanupObservation(m2DisabledCleanupObservation{Previous: previous, Current: current, StatefulSet: set, Pods: pods, Service: service, ConfigMap: config})
			mutate(&observation)
			if _, err := m2CheckDisabledCleanupObservation(observation); err == nil {
				t.Fatal("accepted disabled cleanup state that violates identity or deletion ordering")
			}
		})
	}
}

func TestUnitM2LedgerCannotSealUnresolvedCreate(t *testing.T) {
	s := &m2Scenario{Name: "unresolved", evidenceDir: t.TempDir()}
	if err := os.Chmod(s.evidenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	intent, err := s.RecordCreateIntent(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "possible"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCreateSubmitted(intent); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCreateUnresolved(intent); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyTerminalCreateIntents(); err == nil {
		t.Fatal("ambiguous submitted Create was accepted as restored")
	}
}

func TestUnitM2CreateIntentUsesDurableNameAndRecoversLostAcknowledgement(t *testing.T) {
	s := &m2Scenario{Name: "lost-ack", evidenceDir: t.TempDir()}
	if err := os.Chmod(s.evidenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}

	obj := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, GenerateName: "m2-rbac-service-"}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	store := fake.NewClientBuilder().WithScheme(scheme).Build()
	createCalls := 0
	observe := func(ctx context.Context, key client.ObjectKey, gvk schema.GroupVersionKind) (client.Object, error) {
		observed, err := m2NewFixtureObject(gvk)
		if err != nil {
			return nil, err
		}
		if err := store.Get(ctx, key, observed); err != nil {
			return nil, err
		}
		return observed, nil
	}
	lostAck := errors.New("connection reset after server commit")
	err := s.createFixtureWithObserver(context.Background(), obj, nil, false,
		func(ctx context.Context, candidate client.Object) (client.Object, error) {
			createCalls++
			if candidate.GetName() == "" || candidate.GetGenerateName() != "" || candidate.GetAnnotations()[m2CreateIntentAnnotation] == "" {
				t.Fatalf("request identity was not concrete and annotated before Create: %#v", candidate)
			}
			persisted, readErr := os.ReadFile(filepath.Join(s.evidenceDir, "ledger.json"))
			if readErr != nil || !strings.Contains(string(persisted), `"phase":"submitted"`) || !strings.Contains(string(persisted), candidate.GetName()) || !strings.Contains(string(persisted), candidate.GetAnnotations()[m2CreateIntentAnnotation]) {
				t.Fatalf("durable exact create intent did not precede API submission: %s %v", persisted, readErr)
			}
			candidate.SetUID("service-uid-1")
			if err := store.Create(ctx, candidate); err != nil {
				return nil, err
			}
			return nil, lostAck
		}, observe)
	if !errors.Is(err, lostAck) {
		t.Fatalf("lost acknowledgement was hidden: %v", err)
	}
	if createCalls != 1 {
		t.Fatalf("ambiguous Create was blindly retried %d times", createCalls)
	}
	previousAdmin := admin
	admin = store
	defer func() { admin = previousAdmin }()
	if len(s.ledger.fixtures) != 1 || s.verifyTerminalCreateIntents() != nil {
		t.Fatalf("committed lost-ack object was not attributed for cleanup: fixtures=%d intents=%+v", len(s.ledger.fixtures), s.ledger.intents)
	}
	for _, fixture := range s.ledger.fixtures {
		if fixture.UID != "service-uid-1" || fixture.Key.Name != obj.Name || !fixture.Created {
			t.Fatalf("wrong recovered incarnation: %+v candidate=%+v", fixture, obj.ObjectMeta)
		}
	}
	if err := s.restoreFixtures(context.Background()); err != nil {
		t.Fatalf("UID-attributed lost-ack fixture could not be restored: %v", err)
	}
	for _, fixture := range s.ledger.fixtures {
		if !fixture.AbsentVerified {
			t.Fatalf("recovered lost-ack UID was not marked absent after restoration: %+v", fixture)
		}
	}
	data, err := os.ReadFile(filepath.Join(s.evidenceDir, "ledger.json"))
	if err != nil || !strings.Contains(string(data), "connection reset after server commit") {
		t.Fatalf("lost-ack result was not durably recorded: %s %v", data, err)
	}
}

func TestUnitM2CreateIntentRefusesPreexistingAndRacingNameCollisions(t *testing.T) {
	for _, mode := range []string{"preexisting", "raced"} {
		t.Run(mode, func(t *testing.T) {
			s := &m2Scenario{Name: "collision-" + mode, evidenceDir: t.TempDir()}
			if err := os.Chmod(s.evidenceDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := s.startEvidence(); err != nil {
				t.Fatal(err)
			}
			obj := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, GenerateName: "m2-rbac-service-"}}
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			store := fake.NewClientBuilder().WithScheme(scheme).Build()
			observeCalls := 0
			observe := func(ctx context.Context, key client.ObjectKey, gvk schema.GroupVersionKind) (client.Object, error) {
				observeCalls++
				if mode == "preexisting" && observeCalls == 1 {
					foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, UID: "foreign-preexisting", ResourceVersion: "1", Annotations: map[string]string{"foreign": "true"}}}
					return foreign, nil
				}
				observed, err := m2NewFixtureObject(gvk)
				if err != nil {
					return nil, err
				}
				if err := store.Get(ctx, key, observed); err != nil {
					return nil, err
				}
				return observed, nil
			}
			createCalls := 0
			err := s.createFixtureWithObserver(context.Background(), obj, nil, false,
				func(ctx context.Context, candidate client.Object) (client.Object, error) {
					createCalls++
					if mode == "raced" {
						foreign := candidate.DeepCopyObject().(client.Object)
						foreign.SetAnnotations(map[string]string{"foreign": "true"})
						foreign.SetUID("foreign-uid")
						if err := store.Create(ctx, foreign); err != nil {
							return nil, err
						}
						return nil, errors.New("connection lost after foreign name race")
					}
					return nil, errors.New("Create must not run when preflight finds a collision")
				}, observe)
			if err == nil {
				t.Fatal("colliding Create unexpectedly succeeded")
			}
			if mode == "preexisting" && createCalls != 0 {
				t.Fatalf("pre-existing name collision submitted Create %d times", createCalls)
			}
			if len(s.ledger.fixtures) != 0 {
				t.Fatalf("foreign same-name object was adopted: %+v", s.ledger.fixtures)
			}
			if mode == "preexisting" {
				if s.verifyTerminalCreateIntents() != nil {
					t.Fatalf("known preflight collision left a submitted intent unresolved: %v", s.verifyTerminalCreateIntents())
				}
			} else if s.verifyTerminalCreateIntents() == nil {
				t.Fatal("lost response racing a foreign object was incorrectly treated as terminal")
			} else {
				foreign := &corev1.Service{}
				if err := store.Get(context.Background(), client.ObjectKeyFromObject(obj), foreign); err != nil || foreign.UID != "foreign-uid" {
					t.Fatalf("foreign collision was removed or replaced: UID=%s err=%v", foreign.UID, err)
				}
			}
		})
	}
}

func TestUnitM2CreateIntentDoesNotAdoptUnrelatedSamePrefixResource(t *testing.T) {
	s := &m2Scenario{Name: "same-prefix", evidenceDir: t.TempDir()}
	if err := os.Chmod(s.evidenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "m2-rbac-service-foreign", UID: "foreign-uid"}}
	store := fake.NewClientBuilder().WithScheme(scheme).WithObjects(foreign).Build()
	obj := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, GenerateName: "m2-rbac-service-"}}
	observe := func(ctx context.Context, key client.ObjectKey, gvk schema.GroupVersionKind) (client.Object, error) {
		observed, err := m2NewFixtureObject(gvk)
		if err != nil {
			return nil, err
		}
		if err := store.Get(ctx, key, observed); err != nil {
			return nil, err
		}
		return observed, nil
	}
	err := s.createFixtureWithObserver(context.Background(), obj, nil, false,
		func(ctx context.Context, candidate client.Object) (client.Object, error) {
			candidate.SetUID("owned-uid")
			if err := store.Create(ctx, candidate); err != nil {
				return nil, err
			}
			return candidate, nil
		}, observe)
	if err != nil || len(s.ledger.fixtures) != 1 || s.verifyTerminalCreateIntents() != nil {
		t.Fatalf("exact-name fixture creation failed: err=%v fixtures=%d", err, len(s.ledger.fixtures))
	}
	stillForeign := &corev1.Service{}
	if err := store.Get(context.Background(), client.ObjectKeyFromObject(foreign), stillForeign); err != nil || stillForeign.UID != foreign.UID {
		t.Fatalf("unrelated same-prefix Service was adopted or altered: UID=%s err=%v", stillForeign.UID, err)
	}
}

func TestUnitM2UnknownCreateNotFoundAndInvalidResponseRemainUnresolved(t *testing.T) {
	for _, mode := range []string{"unknown-not-found", "missing-uid", "wrong-request-token"} {
		t.Run(mode, func(t *testing.T) {
			s := &m2Scenario{Name: "unknown-" + mode, evidenceDir: t.TempDir()}
			if err := os.Chmod(s.evidenceDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := s.startEvidence(); err != nil {
				t.Fatal(err)
			}
			obj := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, GenerateName: "m2-rbac-service-"}}
			observerCalls := 0
			observe := func(_ context.Context, key client.ObjectKey, _ schema.GroupVersionKind) (client.Object, error) {
				observerCalls++
				if mode == "unknown-not-found" {
					return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "services"}, "unknown")
				}
				if observerCalls == 1 {
					return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "services"}, key.Name)
				}
				observed := obj.DeepCopyObject().(client.Object)
				if mode == "missing-uid" {
					observed.SetResourceVersion("3")
				} else {
					annotations := maps.Clone(observed.GetAnnotations())
					annotations[m2CreateIntentAnnotation] = "different-intent"
					observed.SetAnnotations(annotations)
					observed.SetUID("foreign-uid")
					observed.SetResourceVersion("3")
				}
				return observed, nil
			}
			lostAck := errors.New("unexpected transport outcome")
			err := s.createFixtureWithObserver(context.Background(), obj, nil, false,
				func(context.Context, client.Object) (client.Object, error) { return nil, lostAck }, observe)
			if !errors.Is(err, lostAck) || observerCalls != 2 || len(s.ledger.fixtures) != 0 {
				t.Fatalf("invalid uncertain response was not preserved fail-closed: err=%v observer=%d fixtures=%d", err, observerCalls, len(s.ledger.fixtures))
			}
			if err := s.verifyTerminalCreateIntents(); err == nil {
				t.Fatal("unknown or mismatched create outcome was accepted as recovered")
			}
		})
	}
}

func TestUnitM2CreateResponseClassificationIsConservative(t *testing.T) {
	for _, tc := range []struct {
		name         string
		response     error
		wantTerminal bool
		wantStatus   int32
	}{
		{name: "forbidden", response: apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "fixture", errors.New("RBAC denied")), wantTerminal: true, wantStatus: 403},
		{name: "already exists race", response: apierrors.NewAlreadyExists(schema.GroupResource{Resource: "services"}, "fixture"), wantTerminal: true, wantStatus: 409},
		{name: "server error remains ambiguous", response: apierrors.NewInternalError(errors.New("server failed after request"))},
		{name: "request timeout remains ambiguous", response: apierrors.NewTimeoutError("request timed out", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &m2Scenario{Name: "response-" + strings.ReplaceAll(tc.name, " ", "-"), evidenceDir: t.TempDir()}
			if err := os.Chmod(s.evidenceDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := s.startEvidence(); err != nil {
				t.Fatal(err)
			}
			obj := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, GenerateName: "m2-rbac-service-"}}
			observe := func(context.Context, client.ObjectKey, schema.GroupVersionKind) (client.Object, error) {
				return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "services"}, "fixture")
			}
			err := s.createFixtureWithObserver(context.Background(), obj, nil, false,
				func(context.Context, client.Object) (client.Object, error) { return nil, tc.response }, observe)
			if !errors.Is(err, tc.response) {
				t.Fatalf("Create error was not preserved: %v", err)
			}
			terminalErr := s.verifyTerminalCreateIntents()
			if (terminalErr == nil) != tc.wantTerminal {
				t.Fatalf("terminal proof=%v wantTerminal=%t", terminalErr, tc.wantTerminal)
			}
			for _, intent := range s.ledger.intents {
				if tc.wantTerminal && (intent.Phase != "rejected" || intent.ResponseCode != tc.wantStatus || intent.OutcomeError == "") {
					t.Fatalf("definitive rejection evidence not persisted: %+v", intent)
				}
				if !tc.wantTerminal && intent.Phase != "unresolved" {
					t.Fatalf("ambiguous server outcome was misclassified: %+v", intent)
				}
			}
		})
	}
}

func TestUnitM2ExpectedAdmissionRejectionHasSeparateTerminalReceipt(t *testing.T) {
	s := &m2Scenario{Name: "rejection", evidenceDir: t.TempDir()}
	if err := os.Chmod(s.evidenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	obj := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "rejected"}}
	rejection := apierrors.NewInvalid(schema.GroupKind{Kind: "ConfigMap"}, obj.Name, field.ErrorList{
		field.Invalid(field.NewPath("metadata", "ownerReferences").Index(0).Child("apiVersion"), "bad", "invalid group/version"),
	})
	observeMissing := func(context.Context, client.ObjectKey, schema.GroupVersionKind) (client.Object, error) {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, obj.Name)
	}
	err := s.createFixtureWithObserver(context.Background(), obj, nil, true,
		func(context.Context, client.Object) (client.Object, error) { return nil, rejection }, observeMissing)
	if !errors.Is(err, rejection) || len(s.ledger.rejections) != 1 || len(s.ledger.fixtures) != 0 || s.verifyTerminalCreateIntents() != nil {
		t.Fatalf("definitive admission rejection was not distinct from ambiguity: err=%v ledger=%+v", err, s.ledger)
	}
	data, readErr := os.ReadFile(filepath.Join(s.evidenceDir, "ledger.json"))
	if readErr != nil || !strings.Contains(string(data), `"rejections"`) || !strings.Contains(string(data), `"phase":"submitted"`) {
		t.Fatalf("rejection was not persisted with submitted intent: %s %v", data, readErr)
	}
}

func TestUnitM2CommandCancelsOwnedDescendants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	output, err := m2Command(ctx, "/bin/sh", "-c", "sleep 30 & child=$!; printf '%s\\n' \"$child\"; wait")
	if err == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("blocked command was not bounded: err=%v elapsed=%s", err, time.Since(started))
	}
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(output)))
	if parseErr != nil || pid < 2 {
		t.Fatalf("did not capture owned descendant PID: %q, %v", output, parseErr)
	}
	stat, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if readErr == nil {
		fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+1:]))
		if len(fields) == 0 || fields[0] != "Z" {
			t.Fatalf("owned descendant still running after command cancellation: PID=%d state=%q", pid, stat)
		}
	} else if !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
}

func TestUnitM2CommandClosesInheritedOutputPipe(t *testing.T) {
	started := time.Now()
	output, err := m2Command(context.Background(), "/bin/sh", "-c", "sleep 30 & child=$!; printf '%s\\n' \"$child\"; exit 0")
	if err == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("inherited output pipe was not bounded: err=%v elapsed=%s", err, time.Since(started))
	}
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(output)))
	if parseErr != nil || pid < 2 {
		t.Fatalf("did not capture inherited-pipe descendant PID: %q, %v", output, parseErr)
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	stat, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if readErr == nil {
		fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+1:]))
		if len(fields) == 0 || fields[0] != "Z" {
			t.Fatalf("owned inherited-pipe descendant still running: PID=%d state=%q", pid, stat)
		}
	} else if !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
}

func TestUnitM2CommandRejectsDetachedDescendant(t *testing.T) {
	output, err := m2Command(context.Background(), "/bin/sh", "-c", "sleep 30 >/dev/null 2>&1 & child=$!; printf '%s\\n' \"$child\"; exit 0")
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(output)))
	if parseErr != nil || pid < 2 {
		t.Fatalf("did not capture detached descendant PID: %q, %v", output, parseErr)
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	if err == nil {
		t.Fatal("command with detached owned descendant was accepted")
	}
	stat, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if readErr == nil {
		fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+1:]))
		if len(fields) == 0 || fields[0] != "Z" {
			t.Fatalf("detached descendant still running: PID=%d state=%q", pid, stat)
		}
	} else if !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
}

func TestUnitM2CheckedRestoration(t *testing.T) {
	useFake := func(objects ...client.Object) (client.Client, func()) {
		t.Helper()
		s := runtime.NewScheme()
		if err := appsv1.AddToScheme(s); err != nil {
			t.Fatal(err)
		}
		if err := rbacv1.AddToScheme(s); err != nil {
			t.Fatal(err)
		}
		if err := corev1.AddToScheme(s); err != nil {
			t.Fatal(err)
		}
		previous := admin
		admin = fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()
		return admin, func() { admin = previous }
	}
	ctx := context.Background()
	t.Run("manager rejects changed UID and restores exact snapshot", func(t *testing.T) {
		one, zero := int32(1), int32(0)
		original := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: managerName, UID: "manager-old"}, Spec: appsv1.DeploymentSpec{Replicas: &one}}
		current := original.DeepCopy()
		current.Spec.Replicas = &zero
		c, done := useFake(current)
		defer done()
		if err := m2RestoreManager(ctx, original); err != nil {
			t.Fatal(err)
		}
		got := &appsv1.Deployment{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(original), got); err != nil {
			t.Fatal(err)
		}
		if got.Spec.Replicas == nil || *got.Spec.Replicas != one {
			t.Fatalf("manager spec not restored: %+v", got.Spec)
		}
		got.UID = "manager-replacement"
		if err := c.Update(ctx, got); err != nil {
			t.Fatal(err)
		}
		if err := m2RestoreManager(ctx, original); err == nil {
			t.Fatal("replacement manager UID accepted")
		}
	})
	t.Run("Role and RoleBinding reject replacement UID", func(t *testing.T) {
		role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "keaguard-manager-role", UID: "role-old"}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"configmaps"}}}}
		binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "keaguard-manager-rolebinding", UID: "binding-old"}, RoleRef: rbacv1.RoleRef{Kind: "Role", Name: role.Name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: managerName, Namespace: m2LabProfile.runtimeNamespace}}}
		actualRole := role.DeepCopy()
		actualRole.Rules = nil
		actualBinding := binding.DeepCopy()
		actualBinding.Subjects = nil
		c, done := useFake(actualRole, actualBinding)
		defer done()
		if err := m2RestoreRole(ctx, role); err != nil {
			t.Fatal(err)
		}
		if err := m2RestoreRoleBinding(ctx, binding); err != nil {
			t.Fatal(err)
		}
		gotRole := &rbacv1.Role{}
		gotBinding := &rbacv1.RoleBinding{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(role), gotRole); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(binding), gotBinding); err != nil {
			t.Fatal(err)
		}
		if len(gotRole.Rules) != 1 || len(gotBinding.Subjects) != 1 {
			t.Fatal("RBAC snapshots not restored")
		}
		gotRole.UID = "role-replacement"
		gotBinding.UID = "binding-replacement"
		if err := c.Update(ctx, gotRole); err != nil {
			t.Fatal(err)
		}
		if err := c.Update(ctx, gotBinding); err != nil {
			t.Fatal(err)
		}
		if err := m2RestoreRole(ctx, role); err == nil {
			t.Fatal("replacement Role UID accepted")
		}
		if err := m2RestoreRoleBinding(ctx, binding); err == nil {
			t.Fatal("replacement RoleBinding UID accepted")
		}
	})
	t.Run("namespace restores only known policy fault on same UID", func(t *testing.T) {
		baseline := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: m2LabProfile.runtimeNamespace, UID: "namespace-old", Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster, "pod-security.kubernetes.io/enforce": "privileged", "pod-security.kubernetes.io/enforce-version": "v1.37", "unrelated": "keep"}}}
		fault := map[string]string{"pod-security.kubernetes.io/enforce": "baseline", "pod-security.kubernetes.io/enforce-version": "v1.37"}
		current := baseline.DeepCopy()
		current.Labels["pod-security.kubernetes.io/enforce"] = "baseline"
		c, done := useFake(current)
		defer done()
		if err := m2RestoreNamespacePolicy(ctx, baseline, fault); err != nil {
			t.Fatal(err)
		}
		got := &corev1.Namespace{}
		if err := c.Get(ctx, client.ObjectKey{Name: baseline.Name}, got); err != nil {
			t.Fatal(err)
		}
		if got.Labels["pod-security.kubernetes.io/enforce"] != "privileged" || got.Labels["unrelated"] != "keep" {
			t.Fatalf("namespace policy/unrelated labels changed incorrectly: %v", got.Labels)
		}
		got.Labels["pod-security.kubernetes.io/audit"] = "foreign"
		if err := c.Update(ctx, got); err != nil {
			t.Fatal(err)
		}
		if err := m2RestoreNamespacePolicy(ctx, baseline, fault); err == nil {
			t.Fatal("unknown policy alteration accepted")
		}
	})
}

func TestUnitM2PolicyFaultRequiresRecordedNamespaceIncarnation(t *testing.T) {
	ctx := context.Background()
	name := m2LabProfile.runtimeNamespace
	labels := map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster,
		"pod-security.kubernetes.io/enforce": "privileged", "pod-security.kubernetes.io/enforce-version": "v1.37"}
	original := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, UID: "reviewed-uid", Labels: labels}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(original).Build()
	s := &m2Scenario{Name: "policy", evidenceDir: t.TempDir(), NamespaceSnapshots: map[string]*corev1.Namespace{name: original.DeepCopy()},
		KnownFaultPolicies: map[string]map[string]string{}}
	if err := os.Chmod(s.evidenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	baseline := map[string]string{"pod-security.kubernetes.io/enforce": "baseline", "pod-security.kubernetes.io/enforce-version": "v1.37"}
	if err := s.setNamespacePolicyWith(ctx, c, name, baseline); err != nil {
		t.Fatal(err)
	}
	got := &corev1.Namespace{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, got); err != nil || !equalStringMap(policyLabels(got.Labels), baseline) {
		t.Fatalf("reviewed policy mutation did not persist: %+v %v", got.Labels, err)
	}
	if err := m2RestoreNamespacePolicyWith(ctx, c, original, baseline); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, got); err != nil {
		t.Fatal(err)
	}
	got.UID = "foreign-replacement"
	if err := c.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := s.setNamespacePolicyWith(ctx, c, name, baseline); err == nil {
		t.Fatal("replacement namespace was modified")
	}
}

func TestUnitM2CheckedManagerMutationRejectsReplacement(t *testing.T) {
	one, zero := int32(1), int32(0)
	original := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: managerName, UID: "manager-original"}, Spec: appsv1.DeploymentSpec{Replicas: &one}}
	clientScheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(clientScheme); err != nil {
		t.Fatal(err)
	}
	previous := admin
	admin = fake.NewClientBuilder().WithScheme(clientScheme).WithObjects(original).Build()
	defer func() { admin = previous }()
	mutate := func(spec *appsv1.DeploymentSpec) { spec.Replicas = &zero }
	if err := m2PatchManagerSpec(context.Background(), original, mutate); err != nil {
		t.Fatal(err)
	}
	got := &appsv1.Deployment{}
	if err := admin.Get(context.Background(), client.ObjectKeyFromObject(original), got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != zero {
		t.Fatal("checked manager mutation was not applied")
	}
	got.UID = "manager-replacement"
	if err := admin.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	if err := m2PatchManagerSpec(context.Background(), original, mutate); err == nil {
		t.Fatal("checked manager mutation accepted a replacement UID")
	}
}
func TestUnitM2NamespaceSetup(t *testing.T) {
	notFound := func(name string) error {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, name)
	}
	if err := m2NamespacePreflight(map[string]error{m2LabProfile.runtimeNamespace: notFound("runtime"), m2LabProfile.outsideNamespace: notFound("outside")}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]error{{m2LabProfile.runtimeNamespace: notFound("runtime")}, {m2LabProfile.runtimeNamespace: nil, m2LabProfile.outsideNamespace: notFound("outside")}, {m2LabProfile.runtimeNamespace: notFound("runtime"), m2LabProfile.outsideNamespace: errors.New("API read failed")}} {
		if err := m2NamespacePreflight(bad); err == nil {
			t.Errorf("unsafe namespace preflight accepted: %v", bad)
		}
	}
}
func TestUnitM2NamespaceReuse(t *testing.T) {
	actual := map[string]corev1.Namespace{}
	identity := m2LabIdentity{Cluster: m2LabProfile.cluster, Server: "https://127.0.0.1:12345", CASHA256: strings.Repeat("a", 64), Nodes: map[string]m2NodeIdentity{}}
	for _, name := range m2LabProfile.nodes {
		identity.Nodes[name] = m2NodeIdentity{KubernetesUID: "node-" + name, DockerID: strings.Repeat("b", 64), Image: m2LabProfile.nodeImage}
	}
	receipt := m2NamespaceReceipt{Lab: identity, FixtureLabel: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Namespaces: map[string]m2NamespaceEntry{}}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		labels := map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}
		for k, v := range m2ExpectedPolicy(name) {
			labels[k] = v
		}
		uid := types.UID("uid-" + name)
		actual[name] = corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, UID: uid, Labels: labels}}
		receipt.Namespaces[name] = m2NamespaceEntry{UID: string(uid), Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Policy: m2ExpectedPolicy(name)}
	}
	if err := m2NamespaceReceiptMatches(receipt, actual, identity); err != nil {
		t.Fatal(err)
	}
	changed := actual[m2LabProfile.runtimeNamespace]
	changed.UID = "replacement"
	actual[changed.Name] = changed
	if err := m2NamespaceReceiptMatches(receipt, actual, identity); err == nil {
		t.Fatal("unexpected same-name namespace replacement accepted")
	}
	actual[changed.Name] = corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: changed.Name, UID: types.UID(receipt.Namespaces[changed.Name].UID), Labels: changed.Labels}}
	otherServer := identity
	otherServer.Server = "https://127.0.0.1:54321"
	if err := m2NamespaceReceiptMatches(receipt, actual, otherServer); err == nil {
		t.Fatal("receipt from another API server accepted")
	}
	otherCA := identity
	otherCA.CASHA256 = strings.Repeat("c", 64)
	if err := m2NamespaceReceiptMatches(receipt, actual, otherCA); err == nil {
		t.Fatal("receipt from another CA accepted")
	}
	otherNode := identity
	otherNode.Nodes = map[string]m2NodeIdentity{}
	for k, v := range identity.Nodes {
		otherNode.Nodes[k] = v
	}
	n := otherNode.Nodes[m2LabProfile.nodes[1]]
	n.DockerID = strings.Repeat("d", 64)
	otherNode.Nodes[m2LabProfile.nodes[1]] = n
	if err := m2NamespaceReceiptMatches(receipt, actual, otherNode); err == nil {
		t.Fatal("receipt from a replacement Kind node accepted")
	}
}

func TestUnitM2NamespaceProvisioningRetainsPartialCreateRace(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	identity := m2LabIdentity{Cluster: m2LabProfile.cluster, Server: "https://127.0.0.1:12345", CASHA256: strings.Repeat("a", 64), Nodes: map[string]m2NodeIdentity{}}
	for _, name := range m2LabProfile.nodes {
		identity.Nodes[name] = m2NodeIdentity{KubernetesUID: "node-" + name, DockerID: strings.Repeat("b", 64), Image: m2LabProfile.nodeImage}
	}
	clientScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(clientScheme); err != nil {
		t.Fatal(err)
	}
	creates, deletes := 0, 0
	c := fake.NewClientBuilder().WithScheme(clientScheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			creates++
			if creates == 2 {
				return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "namespaces"}, obj.GetName())
			}
			obj.SetUID("first-created-uid")
			return c.Create(ctx, obj, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			deletes++
			return c.Delete(ctx, obj, opts...)
		},
	}).Build()
	provisionErr := m2ProvisionNamespaces(context.Background(), c, dir, identity)
	if provisionErr == nil {
		t.Fatal("second namespace Create race was accepted")
	}
	if creates != 2 || deletes != 0 {
		t.Fatalf("partial setup performed unexpected writes: creates=%d deletes=%d err=%v", creates, deletes, provisionErr)
	}
	first := &corev1.Namespace{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: m2LabProfile.runtimeNamespace}, first); err != nil || first.UID != "first-created-uid" {
		t.Fatalf("known first namespace was not preserved: %+v err=%v", first, err)
	}
	partial, err := os.ReadFile(filepath.Join(dir, "namespaces.partial.json"))
	if err != nil || !strings.Contains(string(partial), "first-created-uid") || strings.Contains(string(partial), m2LabProfile.outsideNamespace+`":{"uid"`) {
		t.Fatalf("first UID partial receipt not preserved: %s err=%v", partial, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "recovery-pending.json")); err != nil {
		t.Fatalf("partial namespace setup cleared recovery marker: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "namespace-receipt.json")); !os.IsNotExist(err) {
		t.Fatalf("partial namespace setup wrote a complete receipt: %v", err)
	}
}

func TestUnitM2NamespaceProvisioningReadOnlyReuseAndCollision(t *testing.T) {
	identity := m2LabIdentity{Cluster: m2LabProfile.cluster, Server: "https://127.0.0.1:12345", CASHA256: strings.Repeat("a", 64), Nodes: map[string]m2NodeIdentity{}}
	for _, name := range m2LabProfile.nodes {
		identity.Nodes[name] = m2NodeIdentity{KubernetesUID: "node-" + name, DockerID: strings.Repeat("b", 64), Image: m2LabProfile.nodeImage}
	}
	clientScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(clientScheme); err != nil {
		t.Fatal(err)
	}
	for _, collision := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		t.Run("collision "+collision, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			foreign := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: collision, UID: "foreign"}}
			creates := 0
			c := fake.NewClientBuilder().WithScheme(clientScheme).WithObjects(foreign).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				creates++
				return c.Create(ctx, obj, opts...)
			}}).Build()
			if err := m2ProvisionNamespaces(context.Background(), c, dir, identity); err == nil || creates != 0 {
				t.Fatalf("foreign namespace collision caused writes: err=%v creates=%d", err, creates)
			}
			if _, err := os.Stat(filepath.Join(dir, "recovery-pending.json")); !os.IsNotExist(err) {
				t.Fatalf("collision created setup marker: %v", err)
			}
		})
	}
	t.Run("successful setup and read-only reuse", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		creates := 0
		c := fake.NewClientBuilder().WithScheme(clientScheme).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			creates++
			obj.SetUID(types.UID("created-" + obj.GetName()))
			return c.Create(ctx, obj, opts...)
		}}).Build()
		if err := m2ProvisionNamespaces(context.Background(), c, dir, identity); err != nil || creates != 2 {
			t.Fatalf("two-name create-only setup failed: err=%v creates=%d", err, creates)
		}
		if _, err := os.Stat(filepath.Join(dir, "recovery-pending.json")); !os.IsNotExist(err) {
			t.Fatalf("verified setup left pending marker: %v", err)
		}
		receiptPath := filepath.Join(dir, "namespace-receipt.json")
		if _, err := readM2PrivateRecord(receiptPath); err != nil {
			t.Fatalf("verified 0600 receipt missing: %v", err)
		}
		if err := m2ProvisionNamespaces(context.Background(), c, dir, identity); err != nil || creates != 2 {
			t.Fatalf("authorized reuse wrote or failed: err=%v creates=%d", err, creates)
		}
		other := identity
		other.Server = "https://127.0.0.1:54321"
		if err := m2ProvisionNamespaces(context.Background(), c, dir, other); err == nil || creates != 2 {
			t.Fatalf("tampered lab binding accepted/wrote: err=%v creates=%d", err, creates)
		}
	})
}

func TestUnitM2NamespaceLostCreateResponseStopsWithoutAdoption(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	identity := m2LabIdentity{Cluster: m2LabProfile.cluster, Server: "https://127.0.0.1:12345", CASHA256: strings.Repeat("a", 64), Nodes: map[string]m2NodeIdentity{}}
	for _, name := range m2LabProfile.nodes {
		identity.Nodes[name] = m2NodeIdentity{KubernetesUID: "node-" + name, DockerID: strings.Repeat("b", 64), Image: m2LabProfile.nodeImage}
	}
	clientScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(clientScheme); err != nil {
		t.Fatal(err)
	}
	creates, deletes := 0, 0
	c := fake.NewClientBuilder().WithScheme(clientScheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			creates++
			obj.SetUID("unacknowledged-uid")
			if err := c.Create(ctx, obj, opts...); err != nil {
				return err
			}
			return context.DeadlineExceeded
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			deletes++
			return c.Delete(ctx, obj, opts...)
		},
	}).Build()
	if err := m2ProvisionNamespaces(context.Background(), c, dir, identity); !errors.Is(err, context.DeadlineExceeded) || creates != 1 || deletes != 0 {
		t.Fatalf("lost Create response caused further writes/adoption: err=%v creates=%d deletes=%d", err, creates, deletes)
	}
	first := &corev1.Namespace{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: m2LabProfile.runtimeNamespace}, first); err != nil || first.UID != "unacknowledged-uid" {
		t.Fatalf("ambiguous namespace result was altered: %+v err=%v", first, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "recovery-pending.json")); err != nil {
		t.Fatalf("lost response cleared pending marker: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "namespace-receipt.json")); !os.IsNotExist(err) {
		t.Fatalf("lost response produced complete ownership receipt: %v", err)
	}
}
func TestUnitM2ProcessIdentity(t *testing.T) {
	identity := testM2ProcessIdentity()
	if !identity.valid() {
		t.Fatal("complete checked process identity rejected")
	}
	for i, mutate := range []func(*m2ProcessIdentity){func(p *m2ProcessIdentity) { p.PodUID = "" }, func(p *m2ProcessIdentity) { p.HostPID = 0 }, func(p *m2ProcessIdentity) { p.NodeImage = "other" }, func(p *m2ProcessIdentity) { p.NSpid = []int{42} }} {
		bad := identity
		mutate(&bad)
		if bad.valid() {
			t.Errorf("invalid identity variant %d accepted", i)
		}
	}
}

func TestUnitM2ProcessObservationParsers(t *testing.T) {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = "S", "123456"
	stat := "321 (kea) unusual) " + strings.Join(fields, " ")
	state, ticks, err := m2ParseProcStat([]byte(stat), 321)
	if err != nil || state != "S" || ticks != 123456 {
		t.Fatalf("failed to parse final comm delimiter/start ticks: state=%q ticks=%d err=%v", state, ticks, err)
	}
	if _, _, err := m2ParseProcStat([]byte(stat), 322); err == nil {
		t.Fatal("recycled host PID was accepted")
	}
	status := []byte("Name:\tkea-dhcp4\nUid:\t100\t100\t100\t100\nGid:\t101\t101\t101\t101\nNSpid:\t321\t1\n")
	uid, gid, nspid, err := m2ParseProcStatus(status)
	if err != nil || uid != 100 || gid != 101 || len(nspid) != 2 || nspid[1] != 1 {
		t.Fatalf("PID namespace/credentials not parsed: uid=%d gid=%d nspid=%v err=%v", uid, gid, nspid, err)
	}
	if _, _, _, err := m2ParseProcStatus([]byte("Uid:\t0 0 0 0\nGid:\t101 101 101 101\nNSpid:\t321 1\n")); err == nil {
		t.Fatal("root process credentials were accepted")
	}
	id := strings.Repeat("a", 64)
	pid, taskState, err := m2ParseTaskList([]byte("TASK PID STATUS\n"+id+" 321 RUNNING\n"), id)
	if err != nil || pid != 321 || taskState != "RUNNING" {
		t.Fatalf("exact task row rejected: pid=%d status=%q err=%v", pid, taskState, err)
	}
	for _, table := range []string{"TASK PID STATUS\n" + id[:12] + " 321 RUNNING\n", "TASK PID STATUS\n" + id + " 321 RUNNING\n" + id + " 322 RUNNING\n"} {
		if _, _, err := m2ParseTaskList([]byte(table), id); err == nil {
			t.Fatalf("truncated/duplicate task mapping accepted: %q", table)
		}
	}
	inspect := []byte(`{"status":{"id":"` + id + `","imageRef":"sha256:image"},"info":{"pid":321,"sandboxID":"` + strings.Repeat("b", 64) + `"}}`)
	if _, err := m2ParseCRIInspect(inspect, id); err != nil {
		t.Fatalf("exact CRI mapping rejected: %v", err)
	}
	if _, err := m2ParseCRIInspect(inspect, strings.Repeat("c", 64)); err == nil {
		t.Fatal("stale CRI container ID accepted")
	}
}

func TestUnitM2ProcSecurityStatus(t *testing.T) {
	status := []byte("Name:\tkea-dhcp4\nUid:\t100\t100\t100\t100\nGid:\t101\t101\t101\t101\n" +
		"CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n" +
		"CapBnd:\t0000000000002400\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n")
	got, err := m2ParseProcSecurityStatus(status)
	if err != nil {
		t.Fatalf("parse exact Linux process security fields: %v", err)
	}
	if got.CapInh != 0 || got.CapPrm != 0 || got.CapEff != 0 || got.CapBnd != 0x2400 || got.CapAmb != 0 || got.NoNewPrivs != 1 || got.Seccomp != 2 {
		t.Fatalf("unexpected process security evidence: %+v", got)
	}
	for name, broken := range map[string][]byte{
		"missing capability":   []byte("CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t2400\nNoNewPrivs:\t1\nSeccomp:\t2\n"),
		"duplicate capability": []byte("CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapEff:\t0\nCapBnd:\t2400\nCapAmb:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\n"),
		"malformed hex":        []byte("CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\txyz\nCapAmb:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\n"),
		"missing NoNewPrivs":   []byte("CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t2400\nCapAmb:\t0\nSeccomp:\t2\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := m2ParseProcSecurityStatus(broken); err == nil {
				t.Fatal("accepted incomplete or malformed process security status")
			}
		})
	}
}

func TestUnitM2ObserveProcessCheckedTuple(t *testing.T) {
	ctx := context.Background()
	containerID, nodeID, sandboxID := strings.Repeat("c", 64), strings.Repeat("a", 64), strings.Repeat("d", 64)
	imageRef := "sha256:" + strings.Repeat("e", 64)
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "kea", Namespace: m2LabProfile.runtimeNamespace, UID: "parent-uid"}, Spec: &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true}}}
	ownerTrue := true
	stateful := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "kea-set", Namespace: parent.Namespace, UID: "set-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: parent.Name, UID: parent.UID, Controller: &ownerTrue}}}, Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "dhcp4", Image: m2KeaDHCP4Image}}}}}}
	nodeName := m2LabProfile.nodes[1]
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kea-set-0", Namespace: parent.Namespace, UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "StatefulSet", Name: stateful.Name, UID: stateful.UID, Controller: &ownerTrue}}}, Spec: corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{{Name: "dhcp4", Image: m2KeaDHCP4Image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "dhcp4", ContainerID: "containerd://" + containerID, ImageID: imageRef}}}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName, UID: "node-uid"}}
	clientScheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, infrastructurev1alpha1.AddToScheme} {
		if err := add(clientScheme); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(clientScheme).WithObjects(parent, stateful, pod, node).Build()
	nodeImageID := "sha256:" + strings.Repeat("b", 64)
	lab := m2LabIdentity{Cluster: m2LabProfile.cluster, Server: "https://127.0.0.1:12345", CASHA256: strings.Repeat("f", 64), Nodes: map[string]m2NodeIdentity{nodeName: {KubernetesUID: string(node.UID), DockerID: nodeID, Image: m2LabProfile.nodeImage, ImageID: nodeImageID}}}
	statFields := make([]string, 20)
	for i := range statFields {
		statFields[i] = "0"
	}
	statFields[0], statFields[19] = "S", "123456"
	stat := "321 (kea-dhcp4) " + strings.Join(statFields, " ")
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "docker" {
			t.Fatalf("unexpected process observer executable %q", name)
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(joined, "inspect --format"):
			return []byte(nodeID + "|" + m2LabProfile.nodeImage + "|" + nodeImageID + "|" + m2LabProfile.cluster), nil
		case strings.Contains(joined, "crictl inspect -o json "+containerID):
			return []byte(`{"status":{"id":"` + containerID + `","imageRef":"` + imageRef + `"},"info":{"pid":321,"sandboxID":"` + sandboxID + `"}}`), nil
		case strings.Contains(joined, "ctr --namespace k8s.io tasks list"):
			return []byte("TASK PID STATUS\n" + containerID + " 321 RUNNING\n"), nil
		case strings.HasSuffix(joined, "cat /proc/321/stat"):
			return []byte(stat), nil
		case strings.HasSuffix(joined, "cat /proc/321/status"):
			return []byte("Uid:\t100 100 100 100\nGid:\t101 101 101 101\nNSpid:\t321 1\n"), nil
		case strings.Contains(joined, "cat /proc/321/cmdline"):
			return []byte("/usr/sbin/kea-dhcp4\x00-c\x00/run/kea/state/kea-dhcp4.conf\x00"), nil
		case strings.Contains(joined, "readlink /proc/321/ns/pid"):
			return []byte("pid:[45678]\n"), nil
		case strings.Contains(joined, "readlink /proc/321/exe"):
			return []byte("/usr/sbin/kea-dhcp4\n"), nil
		default:
			t.Fatalf("unexpected process observer command: %v", args)
			return nil, nil
		}
	}
	observed, err := m2ObserveProcessWith(ctx, client.ObjectKeyFromObject(pod), "dhcp4", c, lab, run)
	if err != nil || !observed.valid() || observed.PodUID != pod.UID || observed.TaskID != containerID || observed.StartTicks != 123456 || observed.PIDNamespaceInode != 45678 {
		t.Fatalf("exact observed process tuple invalid: %+v err=%v", observed, err)
	}
	changed := node.DeepCopy()
	changed.UID = "replacement-node"
	if err := c.Update(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := m2ObserveProcessWith(ctx, client.ObjectKeyFromObject(pod), "dhcp4", c, lab, run); err == nil {
		t.Fatal("stale Kubernetes node identity was accepted")
	}
}
func TestUnitM2ProcessSignals(t *testing.T) {
	expected := testM2ProcessIdentity()
	signals := 0
	observe := func(context.Context) (m2ProcessIdentity, error) { return expected, nil }
	checkCNI := func(context.Context, m2ProcessIdentity) error { return nil }
	submit := func(context.Context, m2ProcessIdentity, string) error { signals++; return nil }
	if err := m2SignalProcessWith(context.Background(), expected, "STOP", observe, checkCNI, submit); err != nil {
		t.Fatal(err)
	}
	stale := expected
	stale.HostPID++
	if err := m2SignalProcessWith(context.Background(), expected, "CONT", func(context.Context) (m2ProcessIdentity, error) { return stale, nil }, checkCNI, submit); err == nil {
		t.Fatal("stale process identity accepted")
	}
	stopped := expected
	stopped.State = "T"
	if err := m2SignalProcessWith(context.Background(), expected, "CONT", func(context.Context) (m2ProcessIdentity, error) { return stopped, nil }, checkCNI, submit); err != nil {
		t.Fatalf("checked CONT of same stopped task rejected: %v", err)
	}
	if err := m2SignalProcessWith(context.Background(), expected, "KILL", observe, func(context.Context, m2ProcessIdentity) error { return errors.New("CNI extension present") }, submit); err == nil {
		t.Fatal("task with CNI metadata was signalled")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m2SignalProcessWith(cancelled, expected, "KILL", observe, checkCNI, submit); err == nil {
		t.Fatal("cancelled signal was submitted")
	}
	if err := m2SignalProcessWith(context.Background(), expected, "TERM", observe, checkCNI, submit); err == nil {
		t.Fatal("unsupported signal accepted")
	}
	if signals != 2 {
		t.Fatalf("unsafe signal submitted; count=%d", signals)
	}
}

func TestUnitM2SignalRefusesStaleSecondObservationAndCNIMetadata(t *testing.T) {
	expected := testM2ProcessIdentity()
	mutations := []struct {
		name   string
		mutate func(*m2ProcessIdentity)
	}{
		{"Pod UID", func(p *m2ProcessIdentity) { p.PodUID = "replacement" }},
		{"node UID", func(p *m2ProcessIdentity) { p.NodeUID = "replacement" }},
		{"container ID", func(p *m2ProcessIdentity) {
			p.TaskID = strings.Repeat("f", 64)
			p.ContainerID = "containerd://" + p.TaskID
		}},
		{"PID start ticks", func(p *m2ProcessIdentity) { p.StartTicks++ }},
		{"PID namespace", func(p *m2ProcessIdentity) { p.PIDNamespaceInode++ }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			stale := expected
			tc.mutate(&stale)
			observations, submissions := 0, 0
			err := m2SignalProcessWith(context.Background(), expected, "STOP", func(context.Context) (m2ProcessIdentity, error) {
				observations++
				if observations == 1 {
					return expected, nil
				}
				return stale, nil
			}, func(context.Context, m2ProcessIdentity) error { return nil }, func(context.Context, m2ProcessIdentity, string) error { submissions++; return nil })
			if err == nil || submissions != 0 || observations != 2 {
				t.Fatalf("stale second observation reached signal: err=%v submissions=%d observations=%d", err, submissions, observations)
			}
		})
	}
	checks := 0
	for _, output := range []string{
		`{"id":"` + expected.TaskID + `","extensions":{}}`,
		`{"id":"` + expected.TaskID + `","extensions":{"io.containerd.cni.v1":{}}}`,
	} {
		err := m2CheckCtrCNI(context.Background(), expected, func(_ context.Context, name string, args ...string) ([]byte, error) {
			checks++
			if name != "docker" || len(args) != 8 || args[0] != "exec" || args[1] != expected.NodeContainerID || args[2] != "ctr" || args[3] != "--namespace" || args[4] != "k8s.io" || args[5] != "containers" || args[6] != "info" || args[7] != expected.TaskID {
				t.Fatalf("unexpected CNI side-effect inspection argv: %s %v", name, args)
			}
			return []byte(output), nil
		})
		if (err == nil) != (checks == 1) {
			t.Fatalf("CNI extension outcome mismatch: check=%d err=%v", checks, err)
		}
	}
	submitted := 0
	err := m2SignalProcessWith(context.Background(), expected, "STOP", func(context.Context) (m2ProcessIdentity, error) { return expected, nil }, func(context.Context, m2ProcessIdentity) error { return nil }, func(context.Context, m2ProcessIdentity, string) error { submitted++; return context.DeadlineExceeded })
	if !errors.Is(err, context.DeadlineExceeded) || submitted != 1 {
		t.Fatalf("lost acknowledgement was retried or hidden: err=%v submissions=%d", err, submitted)
	}
}

func TestUnitM2StopIntentPersistsAndLostAcknowledgementStaysUnresolved(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "stop-intent", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	identity := testM2ProcessIdentity()
	submissions := 0
	err := s.stopProcessWith(context.Background(), identity,
		func(_ context.Context, got m2ProcessIdentity, signal string) error {
			submissions++
			data, readErr := os.ReadFile(filepath.Join(dir, "ledger.json"))
			if readErr != nil || !strings.Contains(string(data), `"phase":"planned"`) || !strings.Contains(string(data), identity.TaskID) {
				t.Fatalf("STOP reached command before durable intent: %s %v", data, readErr)
			}
			if got.TaskID != identity.TaskID || signal != "STOP" {
				t.Fatal("STOP command targeted wrong task")
			}
			return context.DeadlineExceeded
		},
		func(context.Context) (m2ProcessIdentity, error) {
			t.Fatal("lost response was not retried or assumed acknowledged")
			return m2ProcessIdentity{}, nil
		})
	if !errors.Is(err, context.DeadlineExceeded) || submissions != 1 {
		t.Fatalf("lost STOP response was retried/hidden: err=%v submissions=%d", err, submissions)
	}
	data, readErr := os.ReadFile(filepath.Join(dir, "ledger.json"))
	if readErr != nil || !strings.Contains(string(data), `"phase":"unresolved"`) {
		t.Fatalf("unresolved task phase not persisted: %s %v", data, readErr)
	}
	if err := s.stopProcessWith(context.Background(), identity, func(context.Context, m2ProcessIdentity, string) error { submissions++; return nil }, nil); err == nil || submissions != 1 {
		t.Fatal("same task was blindly signalled a second time")
	}
}

func TestUnitM2KillIntentPersistsAndRequiresReplacementProof(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := &m2Scenario{Name: "kill-intent", evidenceDir: dir}
	if err := s.startEvidence(); err != nil {
		t.Fatal(err)
	}
	identity := testM2ProcessIdentity()
	submissions := 0
	err := s.killProcessWith(context.Background(), identity, func(_ context.Context, got m2ProcessIdentity, signal string) error {
		submissions++
		data, readErr := os.ReadFile(filepath.Join(dir, "ledger.json"))
		if readErr != nil || !strings.Contains(string(data), `"signal":"KILL"`) || !strings.Contains(string(data), `"phase":"planned"`) || !strings.Contains(string(data), identity.TaskID) {
			t.Fatalf("KILL reached command without durable full intent: %s %v", data, readErr)
		}
		if got.TaskID != identity.TaskID || signal != "KILL" {
			t.Fatal("KILL targeted a different task")
		}
		return context.DeadlineExceeded
	})
	if !errors.Is(err, context.DeadlineExceeded) || submissions != 1 {
		t.Fatalf("lost KILL response was hidden or retried: %v, %d", err, submissions)
	}
	data, readErr := os.ReadFile(filepath.Join(dir, "ledger.json"))
	if readErr != nil || !strings.Contains(string(data), `"phase":"unresolved"`) {
		t.Fatalf("unresolved KILL not persisted: %s %v", data, readErr)
	}
	if err := s.killProcessWith(context.Background(), identity, func(context.Context, m2ProcessIdentity, string) error { submissions++; return nil }); err == nil || submissions != 1 {
		t.Fatal("same task was blindly signalled again")
	}
	if len(s.Killed) != 1 {
		t.Fatalf("KILL ledger count = %d", len(s.Killed))
	}
	proofs := 0
	if err := m2VerifyKillActionWith(context.Background(), s.Killed[0], func(context.Context) (m2ProcessIdentity, error) { return identity, nil }, func(context.Context, m2StoppedProcess, m2ProcessIdentity) error { proofs++; return nil }); err == nil || proofs != 0 {
		t.Fatal("old live task was accepted as crash recovery")
	}
	replacement := identity
	replacement.TaskID = strings.Repeat("f", 64)
	replacement.ContainerID = "containerd://" + replacement.TaskID
	if err := m2VerifyKillActionWith(context.Background(), s.Killed[0], func(context.Context) (m2ProcessIdentity, error) { return replacement, nil }, func(_ context.Context, stopped m2StoppedProcess, got m2ProcessIdentity) error {
		proofs++
		if stopped.Identity.TaskID != identity.TaskID || got.TaskID != replacement.TaskID {
			t.Fatal("wrong replacement proof")
		}
		return nil
	}); err != nil || proofs != 1 {
		t.Fatalf("verified replacement refused: %v, %d", err, proofs)
	}
	for name, mutate := range map[string]func(*m2ProcessIdentity){
		"new Pod UID":         func(p *m2ProcessIdentity) { p.PodUID = "new-pod" },
		"new node container":  func(p *m2ProcessIdentity) { p.NodeContainerID = strings.Repeat("e", 64) },
		"wrong image":         func(p *m2ProcessIdentity) { p.ImageID = "wrong-image" },
		"stopped replacement": func(p *m2ProcessIdentity) { p.State = "T" },
	} {
		t.Run(name, func(t *testing.T) {
			stale := replacement
			mutate(&stale)
			if err := m2VerifyKillActionWith(context.Background(), s.Killed[0], func(context.Context) (m2ProcessIdentity, error) { return stale, nil }, func(context.Context, m2StoppedProcess, m2ProcessIdentity) error {
				t.Fatal("stale replacement reached proof")
				return nil
			}); err == nil {
				t.Fatal("accepted stale replacement")
			}
		})
	}
}

func TestUnitM2ResumeStoppedProcessCheckedRecovery(t *testing.T) {
	expected := testM2ProcessIdentity()
	stopped := expected
	stopped.State = "T"
	record := m2StoppedProcess{Identity: expected, Phase: "acknowledged"}
	t.Run("same stopped task receives one CONT and is reobserved live", func(t *testing.T) {
		observations, submissions := 0, 0
		err := m2ResumeStoppedWith(context.Background(), record, func(context.Context) (m2ProcessIdentity, error) {
			observations++
			if observations == 1 {
				return stopped, nil
			}
			return expected, nil
		}, func(_ context.Context, got m2ProcessIdentity, signal string) error {
			submissions++
			if got.TaskID != expected.TaskID || signal != "CONT" {
				t.Fatal("CONT targeted a replacement task")
			}
			return nil
		}, func(context.Context, m2StoppedProcess, m2ProcessIdentity) error {
			t.Fatal("replacement proof used for same task")
			return nil
		})
		if err != nil || submissions != 1 || observations != 2 {
			t.Fatalf("same-task recovery failed: err=%v submissions=%d observations=%d", err, submissions, observations)
		}
	})
	t.Run("lost CONT response is resolved only by independent live-state proof", func(t *testing.T) {
		observations, submissions := 0, 0
		err := m2ResumeStoppedWith(context.Background(), record, func(context.Context) (m2ProcessIdentity, error) {
			observations++
			if observations == 1 {
				return stopped, nil
			}
			return expected, nil
		}, func(context.Context, m2ProcessIdentity, string) error { submissions++; return context.DeadlineExceeded }, func(context.Context, m2StoppedProcess, m2ProcessIdentity) error {
			return errors.New("must not use replacement proof")
		})
		if err != nil || submissions != 1 || observations != 2 {
			t.Fatalf("lost acknowledgement was retried or not proved: err=%v submissions=%d observations=%d", err, submissions, observations)
		}
	})
	t.Run("replacement is never CONT-signalled", func(t *testing.T) {
		replacement := expected
		replacement.PodUID = "new-pod"
		replacement.TaskID = strings.Repeat("f", 64)
		replacement.ContainerID = "containerd://" + replacement.TaskID
		submissions, proofs := 0, 0
		err := m2ResumeStoppedWith(context.Background(), record, func(context.Context) (m2ProcessIdentity, error) { return replacement, nil }, func(context.Context, m2ProcessIdentity, string) error { submissions++; return nil }, func(_ context.Context, old m2StoppedProcess, current m2ProcessIdentity) error {
			proofs++
			if old.Identity.TaskID != expected.TaskID || current.TaskID != replacement.TaskID {
				t.Fatal("wrong task identities passed to replacement proof")
			}
			return errors.New("old task absence unproved")
		})
		if err == nil || submissions != 0 || proofs != 1 {
			t.Fatalf("replacement recovery did not fail closed: err=%v submissions=%d proofs=%d", err, submissions, proofs)
		}
	})
}

func TestUnitM2OldTaskAbsenceProof(t *testing.T) {
	oldID, otherID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := m2TaskAbsent([]byte("TASK PID STATUS\n"+otherID+" 123 RUNNING\n"), oldID); err != nil {
		t.Fatalf("verified old-task absence rejected: %v", err)
	}
	for _, table := range []string{
		"TASK PID STATUS\n" + oldID + " 321 RUNNING\n",
		"TASK PID STATUS\n" + oldID[:12] + " 321 RUNNING\n",
		"TASK PID STATUS\n" + otherID + " not-a-pid RUNNING\n",
		"TASK PID STATUS\n" + otherID + " 123 UNKNOWN\n",
	} {
		if err := m2TaskAbsent([]byte(table), oldID); err == nil {
			t.Fatalf("unsafe task-absence table accepted: %q", table)
		}
	}
}

func TestUnitM2ReplacementProofRequiresReadyPodAndOldTaskAbsence(t *testing.T) {
	old := testM2ProcessIdentity()
	replacement := old
	replacement.PodUID = "replacement-pod"
	replacement.TaskID = strings.Repeat("f", 64)
	replacement.ContainerID = "containerd://" + replacement.TaskID
	replacement.State = "S"
	ready := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: replacement.PodKey.Name, Namespace: replacement.PodKey.Namespace, UID: replacement.PodUID}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	clientScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(clientScheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(clientScheme).WithObjects(ready).Build()
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "docker" || len(args) != 7 || args[0] != "exec" || args[1] != old.NodeContainerID || args[2] != "ctr" || args[3] != "--namespace" || args[4] != "k8s.io" || args[5] != "tasks" || args[6] != "list" {
			t.Fatalf("old-node task absence used wrong argv: %s %v", name, args)
		}
		return []byte("TASK PID STATUS\n" + replacement.TaskID + " 456 RUNNING\n"), nil
	}
	stopped := m2StoppedProcess{Identity: old, Phase: "acknowledged"}
	if err := m2ProveTaskReplacementWith(context.Background(), stopped, replacement, c, run); err != nil {
		t.Fatalf("independently ready replacement/old absence rejected: %v", err)
	}
	ready.Status.Conditions[0].Status = corev1.ConditionFalse
	if err := c.Status().Update(context.Background(), ready); err != nil {
		t.Fatal(err)
	}
	if err := m2ProveTaskReplacementWith(context.Background(), stopped, replacement, c, run); err == nil {
		t.Fatal("unready replacement accepted")
	}
	ready.Status.Conditions[0].Status = corev1.ConditionTrue
	if err := c.Status().Update(context.Background(), ready); err != nil {
		t.Fatal(err)
	}
	if err := m2ProveTaskReplacementWith(context.Background(), stopped, replacement, c, func(context.Context, string, ...string) ([]byte, error) {
		return []byte("TASK PID STATUS\n" + old.TaskID + " 321 RUNNING\n"), nil
	}); err == nil {
		t.Fatal("old task still present was accepted as replacement recovery")
	}
}
func TestUnitM2GinkgoRecoveryTiming(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "recoveryfixture")
	build := exec.Command("go", "build", "-o", bin, "./test/e2e/testdata/recoveryfixture")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build pinned cluster-free Ginkgo fixture: %v\n%s", err, output)
	}
	for _, tc := range []struct {
		mode            string
		wantPass        bool
		wantMarker      bool
		wantReceipt     bool
		wantDiagnostics string
		ordered         []string
	}{
		{"legacy", false, false, true, "ok", []string{"body", "legacy-after", "critical", "sealed", "diagnostic"}},
		{"m2-selection", true, false, true, "ok", []string{"body", "critical", "sealed", "diagnostic", "sentinel"}},
		{"body-timeout", false, false, true, "ok", []string{"body", "critical", "sealed", "diagnostic"}},
		{"critical-timeout", false, true, false, "skipped-recovery-incomplete", []string{"body", "critical"}},
		{"critical-interrupt", false, true, false, "skipped-recovery-incomplete", []string{"body", "critical"}},
		{"diagnostic-block", false, false, true, "failed", []string{"body", "critical", "sealed", "diagnostic"}},
		{"diagnostic-interrupt", false, false, true, "interrupted", []string{"body", "critical", "sealed", "diagnostic"}},
		{"success", true, false, true, "ok", []string{"body", "critical", "sealed", "diagnostic", "sentinel"}},
		{"repeated-interrupt", false, true, false, "skipped-recovery-incomplete", []string{"body", "critical"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin)
			cmd.Env = append(os.Environ(), "M2_FIXTURE_MODE="+tc.mode, "M2_FIXTURE_DIR="+dir)
			cmd.Stderr = os.Stderr
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
			cmd.WaitDelay = time.Second
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			events := []string{}
			allLines := []string{}
			scan := bufio.NewScanner(stdout)
			for scan.Scan() {
				line := scan.Text()
				allLines = append(allLines, line)
				idx := strings.Index(line, "M2-EVENT ")
				if idx < 0 {
					continue
				}
				fields := strings.Fields(line[idx+len("M2-EVENT "):])
				if len(fields) == 0 {
					continue
				}
				event := fields[0]
				events = append(events, event)
				if event == "critical" && (tc.mode == "critical-interrupt" || tc.mode == "repeated-interrupt") {
					_ = syscall.Kill(cmd.Process.Pid, syscall.SIGINT)
				}
				if event == "suite-cancel" && tc.mode == "repeated-interrupt" {
					_ = syscall.Kill(cmd.Process.Pid, syscall.SIGINT)
				}
				if event == "diagnostic" && tc.mode == "diagnostic-interrupt" {
					_ = syscall.Kill(cmd.Process.Pid, syscall.SIGINT)
				}
			}
			if err := scan.Err(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			if ctx.Err() != nil {
				t.Fatalf("fixture exceeded 15s: %v, events=%v", ctx.Err(), events)
			}
			if (err == nil) != tc.wantPass {
				t.Fatalf("mode exit=%v wantPass=%t events=%v output=%v", err, tc.wantPass, events, allLines)
			}
			joined := strings.Join(events, "|")
			at := 0
			for _, event := range tc.ordered {
				found := strings.Index(joined[at:], event)
				if found < 0 {
					t.Fatalf("missing ordered event %q in %v output=%v", event, events, allLines)
				}
				at += found + len(event)
			}
			if strings.Contains(joined, "sentinel") != tc.wantPass {
				t.Fatalf("sentinel execution mismatch: %v", events)
			}
			for _, check := range []struct {
				name string
				want bool
			}{{"recovery-pending", tc.wantMarker}, {"recovery-restored", tc.wantReceipt}} {
				_, statErr := os.Stat(filepath.Join(dir, check.name))
				if (statErr == nil) != check.want {
					t.Fatalf("%s presence=%t want=%t: %v", check.name, statErr == nil, check.want, statErr)
				}
			}
			data, readErr := os.ReadFile(filepath.Join(dir, "diagnostics"))
			if readErr != nil || strings.TrimSpace(string(data)) != tc.wantDiagnostics {
				t.Fatalf("diagnostics=%q err=%v want=%s", data, readErr, tc.wantDiagnostics)
			}
			if strings.Count(joined, "critical") != 1 {
				t.Fatalf("not exactly one aggregate: %v", events)
			}
			if strings.Count(joined, "suite-cancel") != 1 {
				t.Fatalf("not exactly one cancellation-only suite cleanup: %v", events)
			}
			if tc.mode != "legacy" && strings.Contains(joined, "legacy-after") {
				t.Fatalf("inherited hook ran under M2: %v", events)
			}
			if tc.mode == "critical-timeout" {
				reuseCtx, reuseCancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer reuseCancel()
				reuse := exec.CommandContext(reuseCtx, bin)
				reuse.Env = append(os.Environ(), "M2_FIXTURE_MODE=reuse", "M2_FIXTURE_DIR="+dir)
				output, reuseErr := reuse.CombinedOutput()
				if reuseErr == nil || !strings.Contains(string(output), "M2-EVENT guard-refused") || strings.Contains(string(output), "M2-EVENT body") {
					t.Fatalf("next invocation reached mutation with unresolved marker: err=%v output=%s", reuseErr, output)
				}
			}
		})
	}
}
func TestUnitM2FixtureIncarnations(t *testing.T) {
	l := newM2FixtureLedger()
	key := client.ObjectKey{Namespace: "ns", Name: "same"}
	intent := m2CreateIntent{ID: "old", Key: key, GVK: corev1.SchemeGroupVersion.WithKind("ConfigMap"), Phase: "planned"}
	if err := l.RecordCreateIntent(intent); err != nil {
		t.Fatal(err)
	}
	old := m2FixtureIdentity{Key: key, GVK: intent.GVK, UID: "old-uid"}
	if err := l.ConfirmCreated("old", old); err != nil {
		t.Fatal(err)
	}
	if err := l.RecordCreateIntent(m2CreateIntent{ID: "unexpected", Key: key, GVK: intent.GVK, Phase: "planned"}); err == nil {
		t.Fatal("same-key replacement without an explicit predecessor accepted")
	}
	intent = m2CreateIntent{ID: "new", Key: key, GVK: corev1.SchemeGroupVersion.WithKind("ConfigMap"), Phase: "planned", Replaces: &old}
	if err := l.RecordCreateIntent(intent); err == nil {
		t.Fatal("replacement accepted before direct old-UID absence verification")
	}
	if err := l.MarkAbsentVerified(old); err != nil {
		t.Fatal(err)
	}
	if err := l.RecordCreateIntent(intent); err != nil {
		t.Fatal(err)
	}
	newID := m2FixtureIdentity{Key: key, GVK: intent.GVK, UID: "new-uid"}
	if err := l.ConfirmCreated("new", newID); err != nil {
		t.Fatal(err)
	}
	if len(l.fixtures) != 2 {
		t.Fatalf("incarnations collapsed: %d", len(l.fixtures))
	}
	generated := m2CreateIntent{ID: "generated", Key: client.ObjectKey{Namespace: "ns"}, GenerateName: "fixture-", GVK: corev1.SchemeGroupVersion.WithKind("ConfigMap"), Phase: "planned"}
	if err := l.RecordCreateIntent(generated); err != nil {
		t.Fatalf("generated-name intent rejected before Create: %v", err)
	}
	if err := l.ConfirmCreated("generated", m2FixtureIdentity{Key: client.ObjectKey{Namespace: "ns", Name: "unrelated"}, GVK: generated.GVK, UID: "unexpected"}); err == nil {
		t.Fatal("unattributed generated name accepted")
	}
	if err := l.ConfirmCreated("generated", m2FixtureIdentity{Key: client.ObjectKey{Namespace: "ns", Name: "fixture-abcde"}, GVK: generated.GVK, UID: "created"}); err != nil {
		t.Fatalf("returned generated UID/name rejected: %v", err)
	}
}

func testM2ProcessIdentity() m2ProcessIdentity {
	containerID := strings.Repeat("c", 64)
	return m2ProcessIdentity{PodKey: client.ObjectKey{Namespace: m2LabProfile.runtimeNamespace, Name: "pod"}, PodUID: "poduid", StatefulSetKey: client.ObjectKey{Namespace: m2LabProfile.runtimeNamespace, Name: "set"}, StatefulSetUID: "setuid", KeaClusterKey: client.ObjectKey{Namespace: m2LabProfile.runtimeNamespace, Name: "cr"}, KeaClusterUID: "cruid", NodeName: m2LabProfile.nodes[1], NodeUID: "nodeuid", NodeContainerID: strings.Repeat("a", 64), NodeImage: m2LabProfile.nodeImage, ContainerName: "dhcp4", ContainerID: "containerd://" + containerID, SandboxID: strings.Repeat("d", 64), TaskID: containerID, HostPID: 321, State: "S", StartTicks: 1234, PIDNamespaceInode: 56, NSpid: []int{321, 1}, Executable: "/usr/sbin/kea-dhcp4", Argv: []string{"/usr/sbin/kea-dhcp4", "-c", "/run/kea/state/kea-dhcp4.conf"}, UID: 100, GID: 101, ImageID: "sha256:" + strings.Repeat("e", 64)}
}
