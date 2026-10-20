package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestM2ReconcileInterruptedRecovery is an explicit, read-only-audit-backed
// recovery operation. It is inert unless both private directory and exact
// case identity are supplied, and it retires only a marker whose separate
// restoration-only receipt passes the production guard.
func TestM2ReconcileInterruptedRecovery(t *testing.T) {
	dir := os.Getenv("KEAGUARD_M2_RECOVERY_RECONCILIATION_DIR")
	caseID := os.Getenv("KEAGUARD_M2_RECOVERY_RECONCILIATION_CASE")
	if dir == "" && caseID == "" {
		return
	}
	if dir == "" || caseID == "" {
		t.Fatal("recovery reconciliation requires both private evidence directory and exact case identity")
	}
	before, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics-"+caseID+".json"))
	if err != nil {
		t.Fatalf("original failed diagnostic is unavailable: %v", err)
	}
	if err := m2RetireReconciledRecoveryMarker(dir, caseID); err != nil {
		t.Fatalf("verified recovery-marker retirement refused: %v", err)
	}
	after, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics-"+caseID+".json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("original failed diagnostic changed during restoration-only reconciliation: %v", err)
	}
	if err := m2CheckNoPendingRecovery(dir); err != nil {
		t.Fatalf("recovery guard still blocks after verified restoration-only reconciliation: %v", err)
	}
}

func m2ApprovedProbeScript(family string) string {
	if family != "dhcp4" && family != "dhcp6" {
		return ""
	}
	return fmt.Sprintf("test \"$(cat /proc/1/comm)\" = kea-%s\nread -r pid comm state rest < /proc/1/stat\ncase \"$state\" in R|S|D|I) exit 0;; *) exit 1;; esac", family)
}

func m2CheckProbeContract(container corev1.Container) error {
	script := m2ApprovedProbeScript(container.Name)
	if script == "" {
		return fmt.Errorf("unknown probe family %q", container.Name)
	}
	probe := func(period, failures int32) *corev1.Probe {
		return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-ec", script}}}, PeriodSeconds: period, TimeoutSeconds: 1, FailureThreshold: failures, SuccessThreshold: 1}
	}
	if !reflect.DeepEqual(container.StartupProbe, probe(2, 30)) || !reflect.DeepEqual(container.ReadinessProbe, probe(5, 1)) || !reflect.DeepEqual(container.LivenessProbe, probe(10, 3)) {
		return fmt.Errorf("%s process probes differ from approved command or thresholds", container.Name)
	}
	return nil
}

func m2CheckProbeRejection(output []byte, err error) error {
	var exit *exec.ExitError
	if err == nil || !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(output), "command terminated with exit code 1") {
		return fmt.Errorf("negative process probe did not produce a verified remote exit 1: %v, %q", err, output)
	}
	return nil
}

func TestUnitM2RecoveryWaitsForCurrentConditions(t *testing.T) {
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{UID: "parent", Generation: 7}}
	current := parent.DeepCopy()
	current.Status.ObservedGeneration = 7
	for kind, reason := range map[string]string{"ArtifactReconciled": "ArtifactInSync", "WorkloadReconciled": "ResourcesInSync", "WorkloadReady": "ProcessesHealthy"} {
		current.Status.Conditions = append(current.Status.Conditions, metav1.Condition{Type: kind, Status: metav1.ConditionTrue, Reason: reason, ObservedGeneration: 7, LastTransitionTime: metav1.Now()})
	}
	if err := m2RuntimeConditionsCurrent(parent, current); err != nil {
		t.Fatalf("current recovery rejected: %v", err)
	}
	for name, mutate := range map[string]func(*infrastructurev1alpha1.KeaCluster){
		"pod ready or process resumed before status propagation": func(cr *infrastructurev1alpha1.KeaCluster) {
			for i := range cr.Status.Conditions {
				if cr.Status.Conditions[i].Type == "WorkloadReady" {
					cr.Status.Conditions[i].Status = metav1.ConditionFalse
				}
			}
		},
		"stale generation":  func(cr *infrastructurev1alpha1.KeaCluster) { cr.Status.ObservedGeneration = 6 },
		"wrong incarnation": func(cr *infrastructurev1alpha1.KeaCluster) { cr.UID = "replacement" },
		"wrong reason": func(cr *infrastructurev1alpha1.KeaCluster) {
			for i := range cr.Status.Conditions {
				if cr.Status.Conditions[i].Type == "WorkloadReady" {
					cr.Status.Conditions[i].Reason = "Unknown"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := current.DeepCopy()
			mutate(changed)
			if err := m2RuntimeConditionsCurrent(parent, changed); err == nil {
				t.Fatal("accepted stale or unhealthy runtime status")
			}
		})
	}
}

func TestUnitM2ProbeContract(t *testing.T) {
	for _, family := range []string{"dhcp4", "dhcp6"} {
		t.Run(family, func(t *testing.T) {
			command := []string{"/bin/sh", "-ec", m2ApprovedProbeScript(family)}
			makeProbe := func(period, failure int32) *corev1.Probe {
				return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: command}}, PeriodSeconds: period, TimeoutSeconds: 1, FailureThreshold: failure, SuccessThreshold: 1}
			}
			container := corev1.Container{Name: family, StartupProbe: makeProbe(2, 30), ReadinessProbe: makeProbe(5, 1), LivenessProbe: makeProbe(10, 3)}
			if err := m2CheckProbeContract(container); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*corev1.Container){
				"wrong process":           func(c *corev1.Container) { c.StartupProbe.Exec.Command[2] = "test true" },
				"wrong startup threshold": func(c *corev1.Container) { c.StartupProbe.FailureThreshold = 31 },
				"wrong readiness period":  func(c *corev1.Container) { c.ReadinessProbe.PeriodSeconds = 10 },
				"wrong liveness timeout":  func(c *corev1.Container) { c.LivenessProbe.TimeoutSeconds = 2 },
				"missing probe":           func(c *corev1.Container) { c.ReadinessProbe = nil },
			} {
				t.Run(name, func(t *testing.T) {
					changed := container.DeepCopy()
					mutate(changed)
					if err := m2CheckProbeContract(*changed); err == nil {
						t.Fatal("accepted incorrect process probe contract")
					}
				})
			}
			if !reflect.DeepEqual(container.StartupProbe.Exec.Command, command) {
				t.Fatal("probe fixture mutated")
			}
		})
	}
	if err := m2CheckProbeContract(corev1.Container{Name: "foreign"}); err == nil {
		t.Fatal("unknown family accepted")
	}
}

func TestUnitM2ProbeRejectionRequiresActualExit(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 1").Run()
	if err == nil {
		t.Fatal("negative fixture did not exit nonzero")
	}
	if got := m2CheckProbeRejection([]byte("command terminated with exit code 1"), fmt.Errorf("bounded command kubectl failed: %w", err)); got != nil {
		t.Fatalf("actual negative exec rejected: %v", got)
	}
	for name, result := range map[string]struct {
		output []byte
		err    error
	}{
		"success":                      {nil, nil},
		"timeout":                      {nil, context.DeadlineExceeded},
		"missing remote exit evidence": {nil, err},
	} {
		t.Run(name, func(t *testing.T) {
			if m2CheckProbeRejection(result.output, result.err) == nil {
				t.Fatal("accepted non-probe failure as a negative probe")
			}
		})
	}
}

func TestUnitM2NativePodSuccessorGuard(t *testing.T) {
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: m2LabProfile.runtimeNamespace, Name: "case", UID: "parent-uid"}}
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: "set", UID: "set-uid", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(parent, infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"))}}}
	old := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: parent.Namespace, Name: "set-0", UID: "old-pod", ResourceVersion: "100", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(set, appsv1.SchemeGroupVersion.WithKind("StatefulSet"))}}}
	next := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: old.Namespace, Name: old.Name, UID: "new-pod", ResourceVersion: "101", Labels: map[string]string{"keaguard.example/cluster-uid": string(parent.UID)}, OwnerReferences: append([]metav1.OwnerReference(nil), old.OwnerReferences...)}, Spec: corev1.PodSpec{NodeName: m2LabProfile.nodes[1], Containers: []corev1.Container{{Name: "dhcp4", Image: m2KeaDHCP4Image}, {Name: "dhcp6", Image: m2KeaDHCP6Image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "dhcp4", Ready: true, ContainerID: "containerd://" + strings.Repeat("a", 64), ImageID: m2KeaDHCP4Image}, {Name: "dhcp6", Ready: true, ContainerID: "containerd://" + strings.Repeat("b", 64), ImageID: m2KeaDHCP6Image}}}}
	if err := m2CheckNativePodSuccessor(old, next, set, parent); err != nil {
		t.Fatalf("valid native Pod replacement refused: %v", err)
	}
	oldIdentity, err := m2IdentityFor(old)
	if err != nil {
		t.Fatal(err)
	}
	setIdentity, err := m2IdentityFor(set)
	if err != nil {
		t.Fatal(err)
	}
	ledger := newM2FixtureLedger()
	ledger.successors[fixtureKey(oldIdentity)] = m2GeneratedSuccessor{Old: oldIdentity, NewUID: next.UID, Parent: setIdentity, ClusterUID: parent.UID}
	if !ledger.isConfirmedSuccessor(oldIdentity, next) {
		t.Fatal("verified native successor not recognized by cleanup")
	}
	for name, mutate := range map[string]func(*corev1.Pod, *appsv1.StatefulSet){
		"same UID":            func(p *corev1.Pod, _ *appsv1.StatefulSet) { p.UID = old.UID },
		"wrong owner":         func(p *corev1.Pod, _ *appsv1.StatefulSet) { p.OwnerReferences[0].UID = "foreign-set" },
		"wrong cluster label": func(p *corev1.Pod, _ *appsv1.StatefulSet) { p.Labels["keaguard.example/cluster-uid"] = "foreign" },
		"wrong image":         func(p *corev1.Pod, _ *appsv1.StatefulSet) { p.Spec.Containers[0].Image = "foreign" },
		"not ready":           func(p *corev1.Pod, _ *appsv1.StatefulSet) { p.Status.Conditions[0].Status = corev1.ConditionFalse },
		"wrong parent":        func(_ *corev1.Pod, s *appsv1.StatefulSet) { s.OwnerReferences[0].UID = "foreign-parent" },
		"foreign node":        func(p *corev1.Pod, _ *appsv1.StatefulSet) { p.Spec.NodeName = "foreign-node" },
	} {
		t.Run(name, func(t *testing.T) {
			p, s := next.DeepCopy(), set.DeepCopy()
			mutate(p, s)
			if err := m2CheckNativePodSuccessor(old, p, s, parent); err == nil {
				t.Fatal("accepted unverified native Pod successor")
			}
			if name == "same UID" || name == "wrong owner" || name == "wrong cluster label" {
				if ledger.isConfirmedSuccessor(oldIdentity, p) {
					t.Fatal("cleanup accepted stale or foreign successor")
				}
			}
		})
	}
}

func m2CheckNativePodSuccessor(old, next *corev1.Pod, set *appsv1.StatefulSet, parent *infrastructurev1alpha1.KeaCluster) error {
	if old == nil || next == nil || set == nil || parent == nil || old.UID == "" || old.ResourceVersion == "" ||
		next.UID == "" || next.ResourceVersion == "" || next.UID == old.UID || next.Name != old.Name || next.Namespace != old.Namespace ||
		set.UID == "" || set.Namespace != old.Namespace || parent.UID == "" || parent.Namespace != old.Namespace ||
		next.DeletionTimestamp != nil || next.Status.Phase != corev1.PodRunning || !podReady(next) || !containsString(m2LabProfile.nodes[1:], next.Spec.NodeName) {
		return fmt.Errorf("native Pod replacement lacks original/new UID, readiness or approved node")
	}
	oldOwner, newOwner, setOwner := metav1.GetControllerOf(old), metav1.GetControllerOf(next), metav1.GetControllerOf(set)
	if len(old.OwnerReferences) != 1 || len(next.OwnerReferences) != 1 || len(set.OwnerReferences) != 1 ||
		oldOwner == nil || newOwner == nil || setOwner == nil ||
		oldOwner.APIVersion != appsv1.SchemeGroupVersion.String() || oldOwner.Kind != "StatefulSet" || oldOwner.Name != set.Name || oldOwner.UID != set.UID ||
		!reflect.DeepEqual(oldOwner, newOwner) || setOwner.APIVersion != infrastructurev1alpha1.GroupVersion.String() || setOwner.Kind != "KeaCluster" || setOwner.Name != parent.Name || setOwner.UID != parent.UID ||
		next.Labels["keaguard.example/cluster-uid"] != string(parent.UID) {
		return fmt.Errorf("native Pod replacement lacks the exact old StatefulSet/KeaCluster owner chain")
	}
	if len(next.Spec.InitContainers) != 0 || len(next.Spec.EphemeralContainers) != 0 || len(next.Spec.Containers) != 2 || len(next.Status.ContainerStatuses) != 2 {
		return fmt.Errorf("native Pod replacement has unexpected containers")
	}
	for name, image := range map[string]string{"dhcp4": m2KeaDHCP4Image, "dhcp6": m2KeaDHCP6Image} {
		seenSpec, seenStatus := 0, 0
		for _, container := range next.Spec.Containers {
			if container.Name == name && container.Image == image {
				seenSpec++
			}
		}
		for _, status := range next.Status.ContainerStatuses {
			if status.Name == name && status.Ready && status.ContainerID != "" && status.ImageID == image {
				seenStatus++
			}
		}
		if seenSpec != 1 || seenStatus != 1 {
			return fmt.Errorf("native Pod replacement %s image/status differs from approved content", name)
		}
	}
	return nil
}

var _ = func() bool {
	if selectedProfile.milestone != "m2" {
		return true
	}
	Describe("M2: Probes", func() {
		for _, family := range []string{"dhcp4", "dhcp6"} {
			family := family
			m2It("checks correct and wrong PID 1 for "+family, func() { m2CheckRealAndWrongPIDProbe(family) })
		}
	})
	Describe("M2: Process recovery", func() {
		for _, family := range []string{"dhcp4", "dhcp6"} {
			family := family
			m2It("resumes checked stopped "+family+" before liveness restart", func() { m2CheckStopContinue(family) })
			m2It("restarts stopped "+family+" through actual liveness failure", func() { m2CheckStoppedLivenessRestart(family) })
			m2It("restarts checked killed "+family+" without losing Pod data", func() { m2CheckKilledContainerRestart(family) })
		}
		m2It("replaces an exact Pod and loses only its ephemeral data", m2CheckPodReplacement)
		m2It("restarts the manager without changing healthy workload data", m2CheckManagerRestartWithoutWorkloadChange)
		m2It("restarts the manager across a pending desired rollout", m2CheckManagerRestartDuringPendingRollout)
	})
	return true
}()

func m2ProbeContainer(pod corev1.Pod, family string) corev1.Container {
	for _, container := range pod.Spec.Containers {
		if container.Name == family {
			return container
		}
	}
	Fail("approved family container is absent from verified Pod")
	return corev1.Container{}
}

func m2CheckRealAndWrongPIDProbe(family string) {
	parent, pods, config, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
	m2WaitRuntimeConditions(parent, config.Hash)
	for _, pod := range pods {
		container := m2ProbeContainer(pod, family)
		Expect(m2CheckProbeContract(container)).To(Succeed())
		identity, err := m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pod), family)
		Expect(err).NotTo(HaveOccurred())
		Expect(identity.PodUID).To(Equal(pod.UID))
		for _, probe := range []*corev1.Probe{container.StartupProbe, container.ReadinessProbe, container.LivenessProbe} {
			out, err := m2ExecOutput(pod.Name, family, probe.Exec.Command[0], probe.Exec.Command[1:]...)
			Expect(err).NotTo(HaveOccurred(), "correct %s probe rejected actual daemon: %s", family, out)
		}
	}
	wrong := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: runtimeNamespace, GenerateName: "m2-wrong-pid-" + family + "-", Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}}, Spec: *pods[0].Spec.DeepCopy()}
	wrong.Spec.Hostname, wrong.Spec.Subdomain = "", ""
	container := m2ProbeContainer(pods[0], family)
	container.Command = []string{"/bin/sh", "-ec"}
	container.Args = []string{"while :; do sleep 5; done"}
	wrong.Spec.Containers = []corev1.Container{container}
	Expect(m2CreateObject(labctx, wrong, nil)).To(Succeed())
	Expect(wrong.UID).NotTo(BeEmpty())
	Eventually(func(g Gomega) {
		current := &corev1.Pod{}
		g.Expect(m2GetSnapshot(labctx, client.ObjectKeyFromObject(wrong), current)).To(Succeed())
		g.Expect(current.UID).To(Equal(wrong.UID))
		g.Expect(current.Status.Phase).To(Equal(corev1.PodRunning))
		g.Expect(current.Status.ContainerStatuses).To(HaveLen(1))
	}, 60*time.Second, time.Second).Should(Succeed())
	probe := m2ProbeContainer(pods[0], family).ReadinessProbe.Exec.Command
	out, err := m2ExecOutput(wrong.Name, family, probe[0], probe[1:]...)
	Expect(m2CheckProbeRejection(out, err)).To(Succeed())
	current := &corev1.Pod{}
	Expect(m2GetSnapshot(labctx, client.ObjectKeyFromObject(wrong), current)).To(Succeed())
	Expect(current.UID).To(Equal(wrong.UID))
	Expect(current.Status.ContainerStatuses).To(HaveLen(1))
	Expect(current.Status.ContainerStatuses[0].Ready).To(BeFalse())
	fmt.Fprintf(GinkgoWriter, "M2_PROBE_WRONG_PID family=%s pod=%s uid=%s image=%s probeExit=%v ready=false\n", family, wrong.Name, wrong.UID, container.Image, err)
}

func m2CheckStopContinue(family string) {
	parent, pods, config, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
	m2WaitRuntimeConditions(parent, config.Hash)
	pod := pods[0]
	container := m2ProbeContainer(pod, family)
	Expect(m2CheckProbeContract(container)).To(Succeed())
	identity, err := m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pod), family)
	Expect(err).NotTo(HaveOccurred())
	Expect(identity.PodUID).To(Equal(pod.UID))
	for _, probe := range []*corev1.Probe{container.StartupProbe, container.ReadinessProbe, container.LivenessProbe} {
		out, err := m2ExecOutput(pod.Name, family, probe.Exec.Command[0], probe.Exec.Command[1:]...)
		Expect(err).NotTo(HaveOccurred(), "actual %s probe rejected before STOP: %s", family, out)
	}
	Expect(m2ActiveScenario.StopProcess(labctx, identity)).To(Succeed())
	stopped, err := m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pod), family)
	Expect(err).NotTo(HaveOccurred())
	Expect(m2CheckSameProcessIncarnation(identity, stopped)).To(Succeed())
	Expect(stopped.State).To(Equal("T"))
	probe := container.ReadinessProbe.Exec.Command
	out, err := m2ExecOutput(pod.Name, family, probe[0], probe[1:]...)
	Expect(m2CheckProbeRejection(out, err)).To(Succeed())
	Eventually(func(g Gomega) {
		current := &corev1.Pod{}
		g.Expect(m2GetSnapshot(labctx, client.ObjectKeyFromObject(&pod), current)).To(Succeed())
		g.Expect(current.UID).To(Equal(pod.UID))
		g.Expect(podReady(current)).To(BeFalse())
	}, 20*time.Second, time.Second).Should(Succeed())
	Expect(m2SignalProcess(labctx, identity, "CONT")).To(Succeed())
	resumed, err := m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pod), family)
	Expect(err).NotTo(HaveOccurred())
	Expect(m2CheckSameProcessIncarnation(identity, resumed)).To(Succeed())
	Expect(resumed.State).NotTo(Equal("T"))
	Eventually(func(g Gomega) {
		current := &corev1.Pod{}
		g.Expect(m2GetSnapshot(labctx, client.ObjectKeyFromObject(&pod), current)).To(Succeed())
		g.Expect(current.UID).To(Equal(pod.UID))
		g.Expect(podReady(current)).To(BeTrue())
	}, 40*time.Second, time.Second).Should(Succeed())
	Expect(m2SamePodIncarnations(pods, m2GetPods(parent))).To(Succeed())
	m2WaitRuntimeConditions(parent, config.Hash)
	m2VerifyRuntimeConditions(parent, config.Hash)
	fmt.Fprintf(GinkgoWriter, "M2_STOP_CONT family=%s pod=%s podUID=%s task=%s startTicks=%d stoppedState=%s resumedState=%s\n", family, pod.Name, pod.UID, identity.TaskID, identity.StartTicks, stopped.State, resumed.State)
}

func m2StatusFor(pod corev1.Pod, family string) corev1.ContainerStatus {
	var found *corev1.ContainerStatus
	for i := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[i].Name == family {
			Expect(found).To(BeNil(), "duplicate %s status in Pod %s", family, pod.Name)
			found = &pod.Status.ContainerStatuses[i]
		}
	}
	Expect(found).NotTo(BeNil(), "missing %s status in Pod %s", family, pod.Name)
	return *found
}

func m2DUIDHash(pod string) string {
	out, err := m2ExecOutput(pod, "dhcp6", "sha256sum", "/var/lib/kea/state/kea-dhcp6-serverid")
	Expect(err).NotTo(HaveOccurred())
	fields := strings.Fields(string(out))
	Expect(fields).To(HaveLen(2))
	Expect(fields[1]).To(Equal("/var/lib/kea/state/kea-dhcp6-serverid"))
	Expect(m2FullHexID(fields[0])).To(BeTrue())
	return fields[0]
}

func m2CrashMarker(family string) string {
	Expect(family).To(BeElementOf("dhcp4", "dhcp6"))
	return "/var/lib/kea/state/m2-crash-" + family
}

func m2WriteCrashMarker(pod, family string) {
	path := m2CrashMarker(family)
	Expect(m2Exec(pod, family, "sh", "-ec", "printf 'verified-m2-pod-data' > "+path)).To(Succeed())
	Expect(m2Exec(pod, family, "test", "-f", path)).To(Succeed())
}

func m2WaitSamePodReplacement(pod corev1.Pod, old m2ProcessIdentity) m2ProcessIdentity {
	var replacement m2ProcessIdentity
	Eventually(func(g Gomega) {
		current := &corev1.Pod{}
		g.Expect(m2GetSnapshot(labctx, client.ObjectKeyFromObject(&pod), current)).To(Succeed())
		g.Expect(current.UID).To(Equal(pod.UID))
		g.Expect(podReady(current)).To(BeTrue())
		now, err := m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pod), old.ContainerName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(now.TaskID).NotTo(Equal(old.TaskID))
		g.Expect(m2ProveTaskReplacement(labctx, m2StoppedProcess{Identity: old, Phase: "acknowledged"}, now)).To(Succeed())
		g.Expect(m2StatusFor(*current, old.ContainerName).RestartCount).To(BeNumerically(">", m2StatusFor(pod, old.ContainerName).RestartCount))
		replacement = now
	}, 100*time.Second, 2*time.Second).Should(Succeed())
	return replacement
}

func m2CheckStoppedLivenessRestart(family string) {
	parent, pods, config, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
	m2WaitRuntimeConditions(parent, config.Hash)
	pod := pods[0]
	container := m2ProbeContainer(pod, family)
	Expect(m2CheckProbeContract(container)).To(Succeed())
	identity, err := m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pod), family)
	Expect(err).NotTo(HaveOccurred())
	m2WriteCrashMarker(pod.Name, family)
	duid := m2DUIDHash(pod.Name)
	Expect(m2ActiveScenario.StopProcess(labctx, identity)).To(Succeed())
	stopped, err := m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pod), family)
	Expect(err).NotTo(HaveOccurred())
	Expect(stopped.State).To(Equal("T"))
	probe := container.LivenessProbe.Exec.Command
	out, err := m2ExecOutput(pod.Name, family, probe[0], probe[1:]...)
	Expect(m2CheckProbeRejection(out, err)).To(Succeed())
	replacement := m2WaitSamePodReplacement(pod, identity)
	Expect(m2Exec(pod.Name, family, "test", "-f", m2CrashMarker(family))).To(Succeed())
	Expect(m2DUIDHash(pod.Name)).To(Equal(duid))
	Expect(m2SamePodIncarnations(pods, m2GetPods(parent))).To(Succeed())
	m2WaitRuntimeConditions(parent, config.Hash)
	m2VerifyRuntimeConditions(parent, config.Hash)
	fmt.Fprintf(GinkgoWriter, "M2_STOP_LIVENESS family=%s podUID=%s oldTask=%s newTask=%s oldPID=%d newPID=%d markerRetained=true duidRetained=true\n", family, pod.UID, identity.TaskID, replacement.TaskID, identity.HostPID, replacement.HostPID)
}

func m2CheckKilledContainerRestart(family string) {
	parent, pods, config, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
	m2WaitRuntimeConditions(parent, config.Hash)
	pod := pods[0]
	identity, err := m2ObserveProcess(labctx, client.ObjectKeyFromObject(&pod), family)
	Expect(err).NotTo(HaveOccurred())
	m2WriteCrashMarker(pod.Name, family)
	duid := m2DUIDHash(pod.Name)
	Expect(m2ActiveScenario.KillProcess(labctx, identity)).To(Succeed())
	replacement := m2WaitSamePodReplacement(pod, identity)
	Expect(m2ActiveScenario.Killed).To(HaveLen(1))
	Expect(m2VerifyKillActionWith(labctx, m2ActiveScenario.Killed[0], func(ctx context.Context) (m2ProcessIdentity, error) {
		return m2ObserveProcess(ctx, client.ObjectKeyFromObject(&pod), family)
	}, m2ProveTaskReplacement)).To(Succeed())
	Expect(m2Exec(pod.Name, family, "test", "-f", m2CrashMarker(family))).To(Succeed())
	Expect(m2DUIDHash(pod.Name)).To(Equal(duid))
	Expect(m2SamePodIncarnations(pods, m2GetPods(parent))).To(Succeed())
	m2WaitRuntimeConditions(parent, config.Hash)
	m2VerifyRuntimeConditions(parent, config.Hash)
	fmt.Fprintf(GinkgoWriter, "M2_KILL_RESTART family=%s podUID=%s oldTask=%s newTask=%s oldPID=%d newPID=%d markerRetained=true duidRetained=true\n", family, pod.UID, identity.TaskID, replacement.TaskID, identity.HostPID, replacement.HostPID)
}

func m2CheckPodReplacement() {
	parent, pods, config, _ := m2CreateRuntimeFixture("INFO", 120*time.Second)
	m2WaitRuntimeConditions(parent, config.Hash)
	old := pods[0]
	other := pods[1]
	oldDUID, otherDUID := m2DUIDHash(old.Name), m2DUIDHash(other.Name)
	Expect(oldDUID).NotTo(Equal(otherDUID))
	m2WriteCrashMarker(old.Name, "dhcp4")
	m2WriteCrashMarker(old.Name, "dhcp6")
	Expect(old.ResourceVersion).NotTo(BeEmpty())
	Expect(m2DeleteObject(labctx, &old)).To(Succeed())
	var replacement corev1.Pod
	Eventually(func(g Gomega) {
		g.Expect(m2GetSnapshot(labctx, client.ObjectKeyFromObject(&old), &replacement)).To(Succeed())
		g.Expect(replacement.UID).NotTo(Equal(old.UID))
		g.Expect(podReady(&replacement)).To(BeTrue())
		g.Expect(replacement.Status.ContainerStatuses).To(HaveLen(2))
	}, 100*time.Second, 2*time.Second).Should(Succeed())
	oldIdentity, err := m2IdentityFor(&old)
	Expect(err).NotTo(HaveOccurred())
	Expect(m2ActiveScenario.ObserveNativePodSuccessor(labctx, oldIdentity)).To(Succeed())
	Expect(m2Exec(replacement.Name, "dhcp4", "test", "!", "-e", m2CrashMarker("dhcp4"))).To(Succeed())
	Expect(m2Exec(replacement.Name, "dhcp6", "test", "!", "-e", m2CrashMarker("dhcp6"))).To(Succeed())
	newDUID := m2DUIDHash(replacement.Name)
	Expect(newDUID).NotTo(Equal(oldDUID))
	Expect(newDUID).NotTo(Equal(otherDUID))
	Expect(m2DUIDHash(other.Name)).To(Equal(otherDUID))
	Expect(m2Exec(other.Name, "dhcp6", "test", "!", "-e", m2CrashMarker("dhcp6"))).To(Succeed())
	m2WaitRuntimeConditions(parent, config.Hash)
	m2VerifyRuntimeConditions(parent, config.Hash)
	fmt.Fprintf(GinkgoWriter, "M2_POD_REPLACEMENT pod=%s oldUID=%s newUID=%s oldDUIDHash=%s newDUIDHash=%s otherDUIDHash=%s ephemeralMarkerLost=true\n", old.Name, old.UID, replacement.UID, oldDUID, newDUID, otherDUID)
}

func m2CheckManagerRestartDuringPendingRollout() {
	parent, pods, config, oldSet := m2CreateRuntimeFixture("INFO", 120*time.Second)
	m2WaitRuntimeConditions(parent, config.Hash)
	manager := t14GetManager(labctx)
	Expect(manager.UID).To(Equal(m2ActiveScenario.Manager.UID))
	oldManagerPod := t14GetManagerPod(labctx)
	Expect(oldManagerPod.UID).NotTo(BeEmpty())
	Expect(t14ScaleManager(labctx, 0)).To(Succeed())
	t14WaitStopped(labctx)
	current := &infrastructurev1alpha1.KeaCluster{}
	Expect(m2GetSnapshot(labctx, client.ObjectKeyFromObject(parent), current)).To(Succeed())
	Expect(current.UID).To(Equal(parent.UID))
	debug := "DEBUG"
	current.Spec.Workload.LoggingSeverity = &debug
	Expect(m2UpdateObject(labctx, current, "absent")).To(Succeed())
	_, _, setName := m2NamesFor(parent)
	stillOld := &appsv1.StatefulSet{}
	Expect(m2GetSnapshot(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, stillOld)).To(Succeed())
	Expect(stillOld.UID).To(Equal(oldSet.UID))
	Expect(stillOld.Spec.Template.Annotations["keaguard.example/config-hash"]).To(Equal(config.Hash))
	Expect(m2SamePodIncarnations(pods, m2GetPods(parent))).To(Succeed())
	Expect(m2RestoreManager(labctx, m2ActiveScenario.Manager)).To(Succeed())
	t14WaitReady(labctx)
	newManagerPod := t14GetManagerPod(labctx)
	Expect(newManagerPod.UID).NotTo(Equal(oldManagerPod.UID))
	Expect(newManagerPod.Status.ContainerStatuses).To(HaveLen(1))
	var newHash string
	Eventually(func(g Gomega) {
		set := &appsv1.StatefulSet{}
		g.Expect(m2GetSnapshot(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, set)).To(Succeed())
		g.Expect(set.UID).To(Equal(oldSet.UID))
		newHash = set.Spec.Template.Annotations["keaguard.example/config-hash"]
		g.Expect(newHash).NotTo(BeEmpty())
		g.Expect(newHash).NotTo(Equal(config.Hash))
		g.Expect(set.Status.ObservedGeneration).To(Equal(set.Generation))
		g.Expect(set.Status.ReadyReplicas).To(Equal(int32(2)))
		g.Expect(set.Status.CurrentRevision).To(Equal(set.Status.UpdateRevision))
		g.Expect(set.Status.UpdateRevision).NotTo(BeEmpty())
		observedPods := m2GetPods(parent)
		g.Expect(observedPods).To(HaveLen(2))
		oldUIDs := map[string]string{}
		for _, pod := range pods {
			oldUIDs[pod.Name] = string(pod.UID)
		}
		for _, pod := range observedPods {
			g.Expect(podReady(&pod)).To(BeTrue())
			g.Expect(string(pod.UID)).NotTo(Equal(oldUIDs[pod.Name]))
		}
	}, 120*time.Second, 2*time.Second).Should(Succeed())
	configName, _, _ := m2NamesFor(parent)
	configMap := &corev1.ConfigMap{}
	Expect(m2GetSnapshot(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: configName}, configMap)).To(Succeed())
	Expect(configMap.UID).NotTo(BeEmpty())
	for _, name := range []string{"kea-dhcp4.conf", "kea-dhcp6.conf"} {
		Expect(m2ConfigSeverity([]byte(configMap.Data[name]))).To(Equal("DEBUG"))
	}
	m2WaitRuntimeConditions(parent, newHash)
	m2VerifyRuntimeConditions(parent, newHash)
	fmt.Fprintf(GinkgoWriter, "M2_MANAGER_PENDING_ROLLOUT managerUID=%s oldManagerPodUID=%s newManagerPodUID=%s oldHash=%s newHash=%s oldSetUID=%s newSetUID=%s\n", manager.UID, oldManagerPod.UID, newManagerPod.UID, config.Hash, newHash, oldSet.UID, stillOld.UID)
}

func m2CheckManagerRestartWithoutWorkloadChange() {
	parent, pods, config, set := m2CreateRuntimeFixture("INFO", 120*time.Second)
	m2WaitRuntimeConditions(parent, config.Hash)
	manager := t14GetManager(labctx)
	Expect(manager.UID).To(Equal(m2ActiveScenario.Manager.UID))
	oldManagerPod := t14GetManagerPod(labctx)
	duids := map[string]string{}
	for _, pod := range pods {
		duids[pod.Name] = m2DUIDHash(pod.Name)
		m2WriteCrashMarker(pod.Name, "dhcp4")
		m2WriteCrashMarker(pod.Name, "dhcp6")
	}
	Expect(t14ScaleManager(labctx, 0)).To(Succeed())
	t14WaitStopped(labctx)
	Expect(m2RestoreManager(labctx, m2ActiveScenario.Manager)).To(Succeed())
	t14WaitReady(labctx)
	newManagerPod := t14GetManagerPod(labctx)
	Expect(newManagerPod.UID).NotTo(Equal(oldManagerPod.UID))
	current := m2GetPods(parent)
	Expect(m2SamePodIncarnations(pods, current)).To(Succeed())
	for _, pod := range current {
		Expect(m2DUIDHash(pod.Name)).To(Equal(duids[pod.Name]))
		for _, family := range []string{"dhcp4", "dhcp6"} {
			Expect(m2Exec(pod.Name, family, "test", "-f", m2CrashMarker(family))).To(Succeed())
			Expect(m2StatusFor(pod, family).ContainerID).To(Equal(m2StatusFor(m2PodByName(pods, pod.Name), family).ContainerID))
		}
	}
	stillSet := &appsv1.StatefulSet{}
	Expect(m2GetSnapshot(labctx, client.ObjectKeyFromObject(&set), stillSet)).To(Succeed())
	Expect(stillSet.UID).To(Equal(set.UID))
	Expect(stillSet.Spec.Template.Annotations["keaguard.example/config-hash"]).To(Equal(config.Hash))
	m2WaitRuntimeConditions(parent, config.Hash)
	m2VerifyRuntimeConditions(parent, config.Hash)
	fmt.Fprintf(GinkgoWriter, "M2_MANAGER_RESTART managerUID=%s oldPodUID=%s newPodUID=%s workloadPodUIDsUnchanged=true containerIDsUnchanged=true duidsUnchanged=true dataMarkersRetained=true hash=%s\n", manager.UID, oldManagerPod.UID, newManagerPod.UID, config.Hash)
}

func m2PodByName(pods []corev1.Pod, name string) corev1.Pod {
	for _, pod := range pods {
		if pod.Name == name {
			return pod
		}
	}
	Fail("recorded workload Pod name disappeared")
	return corev1.Pod{}
}
