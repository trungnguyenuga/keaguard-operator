package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ginkgotypes "github.com/onsi/ginkgo/v2/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func validSelection() map[string]string {
	return map[string]string{
		"KEAGUARD_E2E": "1", "KEAGUARD_KIND_CLUSTER": m1LabProfile.cluster,
		"KEAGUARD_KIND_CONTEXT": "kind-" + m1LabProfile.cluster, "KEAGUARD_E2E_DISPOSABLE": m1LabProfile.cluster,
		"KUBECONFIG": m1LabProfile.kubeconfig, "IMG": "keaguard-operator:m1-test",
	}
}

func TestUnitM2KindSelection(t *testing.T) {
	env := validSelection()
	env["KEAGUARD_E2E_MILESTONE"] = "unknown"
	calls := 0
	if err := guardSelection(env, func() error { calls++; return nil }); err == nil || calls != 0 {
		t.Fatalf("unknown M2 milestone must fail before lab access: err=%v calls=%d", err, calls)
	}

	for _, scenario := range []struct {
		name, key, value string
	}{
		{name: "missing disposable opt-in", key: "KEAGUARD_E2E_DISPOSABLE"},
		{name: "wrong cluster", key: "KEAGUARD_KIND_CLUSTER", value: "keaguard-m1-disposable"},
		{name: "wrong context", key: "KEAGUARD_KIND_CONTEXT", value: "kind-keaguard-m1-disposable"},
		{name: "wrong kubeconfig", key: "KUBECONFIG", value: "/home/user/.kube/config"},
		{name: "wrong Docker config", key: "DOCKER_CONFIG", value: "/home/user/.docker"},
		{name: "missing image", key: "IMG"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			invalid := validM2Selection()
			invalid[scenario.key] = scenario.value
			called := 0
			err := guardSelection(invalid, func() error { called++; return nil })
			if err == nil || called != 0 {
				t.Fatalf("invalid selection reached lab callback: err=%v calls=%d", err, called)
			}
		})
	}
	for _, image := range []string{"", "keaguard-operator:latest", "keaguard-operator:m2-test", "bad image:tag", "keaguard-operator"} {
		invalid := validM2Selection()
		invalid["IMG"] = image
		if err := guardSelection(invalid, func() error { t.Errorf("invalid M2 image %q reached callback", image); return nil }); err == nil {
			t.Errorf("invalid M2 image %q accepted", image)
		}
	}
	if validNodeSet(m2LabProfile, []string{m2LabProfile.nodes[0], m2LabProfile.nodes[1]}) {
		t.Fatal("partial M2 topology accepted")
	}
	if validNodeSet(m2LabProfile, []string{m2LabProfile.nodes[0], m2LabProfile.nodes[1], "foreign-worker"}) {
		t.Fatal("foreign M2 node accepted")
	}
	if !validNodeSet(m2LabProfile, m2LabProfile.nodes) {
		t.Fatal("fixed M2 topology rejected")
	}

	good := validM2Selection()
	if err := guardSelection(good, func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatalf("fixed M2 selection rejected: err=%v calls=%d", err, calls)
	}

	t.Run("make test environment clears inherited lab selection", func(t *testing.T) {
		for _, key := range []string{"KEAGUARD_E2E_MILESTONE", "KEAGUARD_E2E", "KEAGUARD_KIND_CLUSTER", "KEAGUARD_KIND_CONTEXT", "KEAGUARD_E2E_DISPOSABLE", "KUBECONFIG", "DOCKER_CONFIG", "IMG", "KEAGUARD_M2_NAMESPACE_SETUP", "KEAGUARD_KIND_CREATE", "KEAGUARD_M2_CLUSTER_REPLACEMENT", "KEAGUARD_M2_REPLACEMENT_GATE_B", "KEAGUARD_M2_REPLACEMENT_STAGE"} {
			t.Setenv(key, "inherited")
		}
		for _, entry := range makeTestEnv("GOTOOLCHAIN=local") {
			if strings.HasPrefix(entry, "KEAGUARD_") || strings.HasPrefix(entry, "KUBECONFIG=") || strings.HasPrefix(entry, "DOCKER_CONFIG=") || strings.HasPrefix(entry, "IMG=") {
				t.Errorf("test subprocess retained selection variable %q", entry)
			}
		}
	})
}

// The fake binary exercises the same command router as TestKindCreate without
// contacting Docker or an existing cluster.
func TestUnitM2KindCommandDeadlines(t *testing.T) {
	bin := t.TempDir()
	kind := filepath.Join(bin, "kind")
	script := "#!/bin/sh\nif [ \"$1\" = create ]; then sleep 9; printf 'created\\n'; else sleep 10; printf 'inspected\\n'; fi\n"
	if err := os.WriteFile(kind, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	previous := selectedProfile
	selectedProfile = m2LabProfile
	t.Cleanup(func() { selectedProfile = previous })

	t.Run("creation outlives diagnostic deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := command(ctx, "kind", "create", "cluster", "--name", m2LabProfile.cluster)
		if err != nil || strings.TrimSpace(string(out)) != "created" {
			t.Fatalf("Kind creation was cut short: output=%q err=%v", out, err)
		}
	})
	t.Run("inspection retains diagnostic deadline", func(t *testing.T) {
		started := time.Now()
		_, err := command(context.Background(), "kind", "get", "clusters")
		elapsed := time.Since(started)
		if err == nil || elapsed < 7*time.Second || elapsed > 10*time.Second {
			t.Fatalf("diagnostic Kind command was not bounded near eight seconds: err=%v elapsed=%s", err, elapsed)
		}
	})
	t.Run("creation obeys parent cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		started := time.Now()
		_, err := command(ctx, "kind", "create", "cluster", "--name", m2LabProfile.cluster)
		if err == nil || time.Since(started) > 3*time.Second {
			t.Fatalf("cancelled creation did not terminate promptly: err=%v elapsed=%s", err, time.Since(started))
		}
	})
}

func TestUnitM2ManagerRolloutCommandDeadlines(t *testing.T) {
	bin := t.TempDir()
	kubectlPath := filepath.Join(bin, "kubectl")
	script := "#!/bin/sh\nsleep 9\nprintf 'rollout-complete\\n'\n"
	if err := os.WriteFile(kubectlPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	previous := selectedProfile
	selectedProfile = m2LabProfile
	t.Cleanup(func() { selectedProfile = previous })
	args := []string{"--kubeconfig", m2LabProfile.kubeconfig, "--context", "kind-" + m2LabProfile.cluster,
		"rollout", "status", "deployment/" + managerName, "-n", m2LabProfile.runtimeNamespace, "--timeout=120s"}
	retainedM1Wait := append([]string(nil), args...)
	retainedM1Wait[9] = "--timeout=110s"
	if !m2ManagerRolloutWait("kubectl", retainedM1Wait) {
		t.Fatal("retained M1 manager rollout lost its reviewed parent-bound wait")
	}
	for _, change := range []struct {
		index int
		value string
	}{
		{1, "/tmp/foreign.kubeconfig"}, {3, "kind-foreign"}, {8, "foreign-namespace"}, {9, "--timeout=999s"},
	} {
		wrong := append([]string(nil), args...)
		wrong[change.index] = change.value
		if m2ManagerRolloutWait("kubectl", wrong) {
			t.Fatalf("unreviewed rollout invocation gained lifecycle deadline: %v", wrong)
		}
	}

	t.Run("reviewed manager rollout outlives diagnostic deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := command(ctx, "kubectl", args...)
		if err != nil || strings.TrimSpace(string(out)) != "rollout-complete" {
			t.Fatalf("manager rollout wait was cut short: output=%q err=%v", out, err)
		}
	})
	t.Run("wrong rollout target retains diagnostic deadline", func(t *testing.T) {
		wrong := append([]string(nil), args...)
		wrong[6] = "deployment/not-the-manager"
		started := time.Now()
		_, err := command(context.Background(), "kubectl", wrong...)
		elapsed := time.Since(started)
		if err == nil || elapsed < 7*time.Second || elapsed > 10*time.Second {
			t.Fatalf("unreviewed rollout was not bounded near eight seconds: err=%v elapsed=%s", err, elapsed)
		}
	})
	t.Run("reviewed rollout obeys parent cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		started := time.Now()
		_, err := command(ctx, "kubectl", args...)
		if err == nil || time.Since(started) > 3*time.Second {
			t.Fatalf("cancelled manager rollout did not terminate promptly: err=%v elapsed=%s", err, time.Since(started))
		}
	})
}

func TestUnitM2SuiteSetupContextHasDeadline(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	ctx, cancel := m2SuiteOperationContext(parent)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 8*time.Minute || time.Until(deadline) < 7*time.Minute {
		t.Fatalf("M2 setup lost its reviewed eight-minute parent deadline: %v %v", deadline, ok)
	}
	if _, err := m2LifecycleCommand(ctx, "true"); err != nil {
		t.Fatalf("reviewed lifecycle command rejected bounded setup context: %v", err)
	}
	cancelParent()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("M2 setup context did not follow parent cancellation")
	}
}

func TestUnitKindSuiteTimeoutForwarding(t *testing.T) {
	for _, tc := range []struct {
		milestone string
		want      string
	}{
		{milestone: "m2", want: "-timeout=75m -ginkgo.timeout=70m"},
		{milestone: "m1", want: "-timeout=25m -ginkgo.timeout=24m"},
	} {
		t.Run(tc.milestone, func(t *testing.T) {
			cmd := exec.Command("make", "-n", "KEAGUARD_E2E_MILESTONE="+tc.milestone, "test-kind", "IMG=keaguard-operator:m2-test")
			cmd.Dir = filepath.Join("..", "..")
			cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("make dry-run failed: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("test-kind timeout forwarding = %q, want %q", out, tc.want)
			}
		})
	}
}

func TestUnitM2SuiteTimingAmendment(t *testing.T) {
	suiteConfig := ginkgotypes.SuiteConfig{Timeout: 44 * time.Minute}
	configureM2SuiteConfig(&suiteConfig)
	if suiteConfig.Timeout != 70*time.Minute {
		t.Fatalf("M2 Ginkgo suite timeout = %s, want exactly 70m", suiteConfig.Timeout)
	}

	suiteStart := time.Unix(100, 0)
	lastAdmissibleStart := suiteStart.Add(61 * time.Minute)
	if !m2ScenarioHasAdmissionReserve(suiteStart, lastAdmissibleStart) {
		t.Fatal("scenario at the exact nine-minute reserve boundary was refused")
	}
	if m2ScenarioHasAdmissionReserve(suiteStart, lastAdmissibleStart.Add(time.Nanosecond)) {
		t.Fatal("scenario with less than the full nine-minute reserve was admitted")
	}
	if m2ScenarioHasAdmissionReserve(time.Time{}, time.Now()) {
		t.Fatal("scenario without a suite start was admitted")
	}

	previousStart := m2SuiteStart
	m2SuiteStart = suiteStart
	t.Cleanup(func() { m2SuiteStart = previousStart })
	if got := m2BodyDeadline(suiteStart.Add(60 * time.Minute)); !got.Equal(suiteStart.Add(64 * time.Minute)) {
		t.Fatalf("ordinary M2 body deadline = %s, want suite start +64m", got)
	}
	if got := m2BodyDeadline(suiteStart.Add(63 * time.Minute)); !got.Equal(suiteStart.Add(66 * time.Minute)) {
		t.Fatalf("late M2 body deadline = %s, want suite start +66m", got)
	}

	if m2BodyNodeTimeout != 4*time.Minute {
		t.Fatalf("M2 body NodeTimeout changed: %s", m2BodyNodeTimeout)
	}
	if m2AggregateNodeTimeout != 170*time.Second {
		t.Fatalf("M2 aggregate recovery NodeTimeout changed: %s", m2AggregateNodeTimeout)
	}
	if m2CriticalRestoreWorkBudget != 120*time.Second || m2RecoveryProofBudget != 130*time.Second {
		t.Fatalf("M2 critical restoration budgets changed: work=%s proof=%s", m2CriticalRestoreWorkBudget, m2RecoveryProofBudget)
	}
	if m2DiagnosticWorkBudget != 20*time.Second || m2DiagnosticCommandDeadline != 8*time.Second {
		t.Fatalf("M2 diagnostic budgets changed: stage=%s command=%s", m2DiagnosticWorkBudget, m2DiagnosticCommandDeadline)
	}
}

func validM2Selection() map[string]string {
	return map[string]string{
		"KEAGUARD_E2E_MILESTONE": "m2", "KEAGUARD_E2E": "1",
		"KEAGUARD_KIND_CLUSTER": m2LabProfile.cluster, "KEAGUARD_KIND_CONTEXT": "kind-" + m2LabProfile.cluster,
		"KEAGUARD_E2E_DISPOSABLE": m2LabProfile.cluster, "KUBECONFIG": m2LabProfile.kubeconfig,
		"DOCKER_CONFIG": m2LabProfile.dockerConfig, "IMG": "keaguard-operator:m2-unit-fingerprint",
	}
}

func TestUnitKindSelection(t *testing.T) {
	for _, key := range []string{"KEAGUARD_E2E", "KEAGUARD_KIND_CLUSTER", "KEAGUARD_KIND_CONTEXT", "KEAGUARD_E2E_DISPOSABLE", "KUBECONFIG", "IMG"} {
		for _, value := range []string{"", "wrong"} {
			t.Run(key+"="+value, func(t *testing.T) {
				env := validSelection()
				env[key] = value
				calls := 0
				if err := guardSelection(env, func() error { calls++; return nil }); err == nil || calls != 0 {
					t.Errorf("invalid selection accepted or contacted lab: err=%v calls=%d", err, calls)
				}
			})
		}
	}
	for _, value := range []string{"/home/me/.kube/config", "/tmp/a:/tmp/b", "relative", "/tmp/config"} {
		env := validSelection()
		env["KUBECONFIG"] = value
		if err := guardSelection(env, func() error { t.Error("contacted lab"); return nil }); err == nil {
			t.Error("unsafe kubeconfig accepted")
		}
	}
	for _, value := range []string{"controller:latest", "controller", "repo/image:latest"} {
		env := validSelection()
		env["IMG"] = value
		if err := guardSelection(env, func() error { t.Error("contacted lab"); return nil }); err == nil {
			t.Error("floating image accepted")
		}
	}
	calls := 0
	if err := guardSelection(validSelection(), func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Errorf("valid selection: %v calls=%d", err, calls)
	}
	for _, labels := range []map[string]string{nil, {fixtureLabel: "someone-else"}} {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: runtimeNamespace, Labels: labels}}
		if err := checkFixtureNamespaceForProfile(m1LabProfile, ns); err == nil {
			t.Error("non-test namespace collision accepted")
		}
	}
	if err := checkFixtureNamespaceForProfile(m1LabProfile, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: m1LabProfile.runtimeNamespace, Labels: map[string]string{m1LabProfile.fixtureLabel: m1LabProfile.cluster}}}); err != nil {
		t.Fatal(err)
	}
	t.Run("normal targets cannot create cluster", func(t *testing.T) {
		for _, target := range []string{"test-unit", "test-envtest", "test", "test-manifests"} {
			cmd := exec.Command("make", "-n", target)
			cmd.Dir = "../.."
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("dry run: %v %s", err, out)
			}
			if strings.Contains(string(out), "kind-create") || strings.Contains(string(out), "create cluster") {
				t.Fatalf("%s can create a cluster", target)
			}
		}
	})
	t.Run("unsupported scaffold lifecycle targets are absent", func(t *testing.T) {
		for _, target := range []string{"run", "build-installer", "install", "uninstall", "deploy", "undeploy", "docker-push", "docker-buildx"} {
			cmd := exec.Command("make", "-n", target)
			cmd.Dir = "../.."
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "No rule to make target") {
				t.Errorf("unsupported target %q remains available: err=%v output=%s", target, err, out)
			}
		}
	})
	t.Run("ordinary suite skips before configuration", func(t *testing.T) {
		t.Setenv("KEAGUARD_E2E", "")
		t.Setenv("KUBECONFIG", "/unreadable")
		if suiteOptedIn() {
			t.Error("ordinary suite opted in")
		}
	})
	t.Run("Kind Make targets require caller-selected IMG before invoking Go", func(t *testing.T) {
		for _, target := range []string{"test-kind", "kind-create"} {
			for _, args := range [][]string{nil, {"IMG="}} {
				cmd := exec.Command("make", append([]string{"--no-print-directory", target}, args...)...)
				cmd.Dir = "../.."
				cmd.Env = makeTestEnv("GOTOOLCHAIN=local", "KEAGUARD_E2E=1")
				out, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(string(out), "explicit IMG= required for Kind") {
					t.Errorf("%s with IMG arguments %v did not fail at the Make IMG guard: err=%v output=%s", target, args, err, out)
				}
				if strings.Contains(string(out), "go test ./test/e2e") {
					t.Errorf("%s with IMG arguments %v invoked the e2e test process before rejection: %s", target, args, out)
				}
			}
		}
	})
	t.Run("Kind Make target forwards explicitly selected IMG", func(t *testing.T) {
		for _, selected := range []string{
			"keaguard-operator:m1-explicit",
			"registry.example:5000/team/keaguard-operator:v2",
			"keaguard-operator@sha256:" + strings.Repeat("a", 64),
		} {
			cmd := exec.Command("make", "--no-print-directory", "-n", "test-kind", "IMG="+selected)
			cmd.Dir = "../.."
			cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "KEAGUARD_E2E=1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("dry-run test-kind for %q: %v\n%s", selected, err, out)
			}
			if !strings.Contains(string(out), "IMG=\""+selected+"\" go test ./test/e2e") {
				t.Errorf("test-kind did not forward explicitly selected IMG %q: %s", selected, out)
			}
			commandLine := exec.Command("make", "--no-print-directory", "kind-image-required", "IMG="+selected)
			commandLine.Dir = "../.."
			commandLine.Env = makeTestEnv("GOTOOLCHAIN=local")
			if output, err := commandLine.CombinedOutput(); err != nil {
				t.Errorf("command-line IMG %q rejected: %v\n%s", selected, err, output)
			}
		}
		envSelected := "registry.example:5000/team/keaguard-operator:environment"
		envIMG := exec.Command("make", "--no-print-directory", "kind-image-required")
		envIMG.Dir = "../.."
		envIMG.Env = makeTestEnv("GOTOOLCHAIN=local", "IMG="+envSelected)
		if output, err := envIMG.CombinedOutput(); err != nil {
			t.Errorf("environment IMG %q rejected: %v\n%s", envSelected, err, output)
		}
		envForward := exec.Command("make", "--no-print-directory", "-n", "test-kind")
		envForward.Dir = "../.."
		envForward.Env = makeTestEnv("GOTOOLCHAIN=local", "KEAGUARD_E2E=1", "IMG="+envSelected)
		output, err := envForward.CombinedOutput()
		if err != nil {
			t.Fatalf("dry-run test-kind for environment IMG %q: %v\n%s", envSelected, err, output)
		}
		if !strings.Contains(string(output), "IMG=\""+envSelected+"\" go test ./test/e2e") {
			t.Errorf("test-kind did not forward environment IMG %q: %s", envSelected, output)
		}
	})
	t.Run("docker build IID is optional and restricted to the reviewed private output", func(t *testing.T) {
		cmd := exec.Command("make", "--no-print-directory", "-n", "docker-build", "IMG=keaguard-operator:m2-test")
		cmd.Dir = "../.."
		cmd.Env = makeTestEnv("GOTOOLCHAIN=local")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("default image build dry-run: %v\n%s", err, out)
		}
		if strings.Contains(string(out), "--iidfile") {
			t.Fatalf("unset IID file changed ordinary Docker build: %s", out)
		}
		cmd = exec.Command("make", "--no-print-directory", "-n", "docker-build", "IMG=keaguard-operator:m2-fingerprint", "BUILD_IID_FILE=/tmp/keaguard-m2-acceptance/manager-image.iid")
		cmd.Dir = "../.."
		cmd.Env = makeTestEnv("GOTOOLCHAIN=local")
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("approved IID build dry-run: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "build --platform=linux/amd64 --iidfile /tmp/keaguard-m2-acceptance/manager-image.iid") {
			t.Fatalf("approved IID not forwarded: %s", out)
		}
		cmd = exec.Command("make", "--no-print-directory", "-n", "docker-build", "BUILD_IID_FILE=/tmp/unrelated")
		cmd.Dir = "../.."
		cmd.Env = makeTestEnv("GOTOOLCHAIN=local")
		out, err = cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "BUILD_IID_FILE must use the reviewed private M2 path") {
			t.Fatalf("unrelated IID path not rejected at Make parse time: err=%v output=%s", err, out)
		}
	})
}

func makeTestEnv(extra ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "IMG=") && !strings.HasPrefix(entry, "GOTOOLCHAIN=") &&
			!strings.HasPrefix(entry, "KEAGUARD_E2E=") && !strings.HasPrefix(entry, "KEAGUARD_E2E_MILESTONE=") &&
			!strings.HasPrefix(entry, "KEAGUARD_KIND_CLUSTER=") && !strings.HasPrefix(entry, "KEAGUARD_KIND_CONTEXT=") &&
			!strings.HasPrefix(entry, "KEAGUARD_E2E_DISPOSABLE=") && !strings.HasPrefix(entry, "KEAGUARD_M2_NAMESPACE_SETUP=") && !strings.HasPrefix(entry, "KEAGUARD_M2_CLUSTER_REPLACEMENT=") && !strings.HasPrefix(entry, "KEAGUARD_M2_REPLACEMENT_GATE_B=") && !strings.HasPrefix(entry, "KEAGUARD_M2_REPLACEMENT_STAGE=") &&
			!strings.HasPrefix(entry, "KEAGUARD_KIND_CREATE=") && !strings.HasPrefix(entry, "KUBECONFIG=") && !strings.HasPrefix(entry, "DOCKER_CONFIG=") {
			env = append(env, entry)
		}
	}
	return append(env, extra...)
}

func TestUnitRenderRuntimeUsesSelectedImage(t *testing.T) {
	images := []string{
		"keaguard-operator:m1-unit-selected",
		"registry.example:5000/team/keaguard-operator:v2",
		"keaguard-operator@sha256:" + strings.Repeat("a", 64),
	}
	for _, selectedImage := range images {
		t.Run(selectedImage, func(t *testing.T) {
			t.Setenv("IMG", selectedImage)
			rendered, err := renderRuntime(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var deployment appsv1.Deployment
			decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
			found := false
			for {
				var obj unstructured.Unstructured
				err := decoder.Decode(&obj)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if obj.GetKind() == "Deployment" && obj.GetName() == managerName {
					data, err := json.Marshal(obj.Object)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(data, &deployment); err != nil {
						t.Fatal(err)
					}
					found = true
				}
			}
			if !found {
				t.Fatal("rendered runtime has no manager Deployment")
			}
			if len(deployment.Spec.Template.Spec.Containers) != 1 || deployment.Spec.Template.Spec.Containers[0].Name != "manager" {
				t.Fatalf("unexpected manager containers: %+v", deployment.Spec.Template.Spec.Containers)
			}
			if actual := deployment.Spec.Template.Spec.Containers[0].Image; !selectedImageMatches(actual, selectedImage) {
				t.Fatalf("rendered manager image = %q, want exact IMG %q", actual, selectedImage)
			}
		})
	}
}

func selectedImageMatches(actual, selected string) bool {
	return actual == selected
}

func TestUnitSelectedImageComparisonRejectsSubstrings(t *testing.T) {
	selected := "keaguard-operator:m1"
	for _, actual := range []string{"keaguard-operator:m1-test", "registry.example/keaguard-operator:m1", "prefix-keaguard-operator:m1"} {
		if selectedImageMatches(actual, selected) {
			t.Errorf("image %q must not be accepted as selected image %q", actual, selected)
		}
	}
}

// A namespace collision must fail before any fixture mutation, even if the first namespace is absent.
type fixtureRecorder struct {
	client.Client
	mutations int
}

func (r *fixtureRecorder) Create(ctx context.Context, o client.Object, opts ...client.CreateOption) error {
	r.mutations++
	return r.Client.Create(ctx, o, opts...)
}
func (r *fixtureRecorder) Delete(ctx context.Context, o client.Object, opts ...client.DeleteOption) error {
	r.mutations++
	return r.Client.Delete(ctx, o, opts...)
}
func TestUnitFixtureCollision(t *testing.T) {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	foreign := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: outsideNamespace}}
	r := &fixtureRecorder{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(foreign).Build()}
	if err := ensureFixtureNamespaces(context.Background(), r); err == nil || r.mutations != 0 {
		t.Fatalf("collision: err=%v mutations=%d", err, r.mutations)
	}
	var after corev1.Namespace
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(foreign), &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Labels) != 0 {
		t.Fatal("foreign namespace relabelled")
	}
}
func TestUnitRuntimeCredentials(t *testing.T) {
	admin := &rest.Config{Host: "https://127.0.0.1:1234", Username: "admin", Password: "secret", BearerToken: "admin", BearerTokenFile: "admin-token", TLSClientConfig: rest.TLSClientConfig{CAData: []byte("trusted-ca"), CertData: []byte("admin-cert"), KeyData: []byte("admin-key"), CertFile: "admin-cert", KeyFile: "admin-key"}, Impersonate: rest.ImpersonationConfig{UserName: "admin"}, ExecProvider: nil}
	actual := runtimeConfig(admin, "runtime-token")
	expected := &rest.Config{Host: "https://127.0.0.1:1234", BearerToken: "runtime-token", TLSClientConfig: rest.TLSClientConfig{CAData: []byte("trusted-ca")}, Timeout: actual.Timeout}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("runtime config retained unexpected admin settings")
	}
	actual.CAData[0] = 'X'
	if string(admin.CAData) != "trusted-ca" {
		t.Fatal("CA data aliased")
	}
}

func TestUnitPrivateKubeconfig(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "keaguard-private-config-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateKubeconfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateKubeconfig(path); err == nil {
		t.Fatal("readable kubeconfig accepted")
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateKubeconfig(link); err == nil {
		t.Fatal("symlink kubeconfig accepted")
	}
}
