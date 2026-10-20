package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const m2RealHookChildEnv = "KEAGUARD_M2_REAL_HOOK_CHILD"

func m2HookEvent(label string) {
	path := os.Getenv("KEAGUARD_M2_HOOK_EVENTS")
	if path == "" {
		panic("M2 hook fixture lacks event path")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintln(f, label); err != nil {
		f.Close()
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}
}

func init() {
	mode := os.Getenv(m2RealHookChildEnv)
	if mode == "" {
		return
	}
	Describe("M2 REAL HOOK FIXTURE", func() {
		m2It("runs through the actual profile BeforeEach and aggregate", func() {
			m2HookEvent("body")
			if mode == "body-fail" {
				Fail("intentional fixture body failure")
			}
			if mode == "body-timeout" {
				<-labctx.Done()
				m2HookEvent("body-cancelled")
			}
		})
	})
}

// This child is a separately executed test binary, so its package-level
// Ginkgo registrations are the real M1/M2 registrations, not a copied model.
func TestFixtureM2RealHookChild(t *testing.T) {
	mode := os.Getenv(m2RealHookChildEnv)
	if mode == "" {
		return
	}
	dir := os.Getenv("KEAGUARD_M2_HOOK_DIR")
	if dir == "" {
		t.Fatal("fixture lacks private directory")
	}
	admin = fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	labctx = context.Background()
	m2SuiteStart = time.Now()
	if mode == "body-timeout" {
		m2BodyNodeTimeout = 100 * time.Millisecond
	}
	if mode == "critical-timeout" || mode == "diagnostic-block" {
		m2AggregateNodeTimeout = 150 * time.Millisecond
	}
	m2SuiteSetupWork = func(SpecContext) { m2HookEvent("suite-setup") }
	m2ScenarioPrepare = func(_ context.Context, name string) (*m2Scenario, error) {
		m2HookEvent("preflight")
		if err := m2CheckNoPendingRecovery(dir); err != nil {
			m2HookEvent("guard-refused")
			return nil, err
		}
		return &m2Scenario{Name: name, evidenceDir: dir}, nil
	}
	m2ScenarioRestoreWork = func(s *m2Scenario, ctx context.Context) error {
		m2HookEvent("critical")
		if _, err := os.Stat(filepath.Join(dir, "recovery-pending.json")); err != nil {
			return fmt.Errorf("critical stage lost its pending marker: %w", err)
		}
		if mode == "restore-fail" {
			return errors.New("intentional incomplete restoration")
		}
		if mode == "critical-timeout" {
			<-ctx.Done()
			m2HookEvent("critical-cancelled")
			return ctx.Err()
		}
		return nil
	}
	m2ScenarioDiagnosticWork = func(s *m2Scenario, ctx context.Context) error {
		m2HookEvent("diagnostics")
		if _, err := os.Stat(filepath.Join(dir, "recovery-pending.json")); !os.IsNotExist(err) {
			return fmt.Errorf("diagnostics preceded resource recovery: %v", err)
		}
		if _, err := os.Stat(s.receiptPath); err != nil {
			return fmt.Errorf("diagnostics preceded verified receipt: %w", err)
		}
		if mode == "diagnostic-fail" {
			return errors.New("intentional bounded diagnostic failure")
		}
		if mode == "diagnostic-block" {
			<-ctx.Done()
			m2HookEvent("diagnostic-cancelled")
			return ctx.Err()
		}
		return nil
	}
	RegisterFailHandler(Fail)
	config, reporter := GinkgoConfiguration()
	config.FocusStrings = []string{"M2 REAL HOOK FIXTURE"}
	config.FailOnEmpty = true
	config.FailFast = true
	config.Timeout = 15 * time.Second
	RunSpecs(t, "M2 actual hook registration fixture", config, reporter)
}

func TestUnitM2RealHookIntegration(t *testing.T) {
	for _, mode := range []string{"success", "body-fail", "body-timeout", "restore-fail", "critical-timeout", "diagnostic-fail", "diagnostic-block", "reuse", "m1"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			events := filepath.Join(dir, "events.log")
			if mode == "reuse" {
				if err := os.WriteFile(filepath.Join(dir, "recovery-pending.json"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fakeBin := filepath.Join(dir, "bin")
			if err := os.Mkdir(fakeBin, 0700); err != nil {
				t.Fatal(err)
			}
			fakeKubectl := "#!/bin/sh\nprintf 'legacy-after\\n' >> \"$KEAGUARD_M2_HOOK_EVENTS\"\nprintf 'fixture logs\\n'\n"
			if err := os.WriteFile(filepath.Join(fakeBin, "kubectl"), []byte(fakeKubectl), 0700); err != nil {
				t.Fatal(err)
			}
			child := exec.Command(os.Args[0], "-test.run", "^TestFixtureM2RealHookChild$", "-test.v")
			child.Env = append(os.Environ(),
				m2RealHookChildEnv+"="+mode,
				"KEAGUARD_M2_HOOK_DIR="+dir,
				"KEAGUARD_M2_HOOK_EVENTS="+events,
				"PATH="+fakeBin+":"+os.Getenv("PATH"),
				"KEAGUARD_E2E=1",
				"KEAGUARD_KIND_CLUSTER="+m2LabProfile.cluster,
				"KEAGUARD_KIND_CONTEXT=kind-"+m2LabProfile.cluster,
				"KEAGUARD_E2E_DISPOSABLE="+m2LabProfile.cluster,
				"KUBECONFIG="+m2LabProfile.kubeconfig,
				"DOCKER_CONFIG="+m2LabProfile.dockerConfig,
				"IMG=keaguard-operator:m2-hook-fixture",
			)
			if mode == "m1" {
				child.Env = append(child.Env,
					"KEAGUARD_E2E_MILESTONE=",
					"KEAGUARD_KIND_CLUSTER="+m1LabProfile.cluster,
					"KEAGUARD_KIND_CONTEXT=kind-"+m1LabProfile.cluster,
					"KEAGUARD_E2E_DISPOSABLE="+m1LabProfile.cluster,
					"KUBECONFIG="+m1LabProfile.kubeconfig,
				)
			} else {
				child.Env = append(child.Env, "KEAGUARD_E2E_MILESTONE=m2")
			}
			output, err := child.CombinedOutput()
			wantFailure := mode != "success" && mode != "m1"
			if (err != nil) != wantFailure {
				t.Fatalf("child exit mismatch: mode=%s err=%v output=%s", mode, err, output)
			}
			data, readErr := os.ReadFile(events)
			if readErr != nil {
				t.Fatalf("child recorded no actual hook events: %v output=%s", readErr, output)
			}
			got := strings.Fields(string(data))
			if mode == "m1" {
				if strings.Join(got, ",") != "suite-setup,body,legacy-after" {
					t.Fatalf("M1 teardown was not retained: %v output=%s", got, output)
				}
				return
			}
			if strings.Contains(string(data), "legacy-after") {
				t.Fatalf("inherited M1 diagnostic ran under M2: %v", got)
			}
			want := "suite-setup,preflight,body,critical,diagnostics"
			switch mode {
			case "body-timeout":
				want = "suite-setup,preflight,body,body-cancelled,critical,diagnostics"
			case "restore-fail":
				want = "suite-setup,preflight,body,critical"
			case "critical-timeout":
				want = "suite-setup,preflight,body,critical,critical-cancelled"
			case "diagnostic-block":
				want = "suite-setup,preflight,body,critical,diagnostics,diagnostic-cancelled"
			case "reuse":
				want = "suite-setup,preflight,guard-refused"
			}
			if strings.Join(got, ",") != want {
				t.Fatalf("actual M2 hook order=%v want=%s output=%s", got, want, output)
			}
			_, markerErr := os.Stat(filepath.Join(dir, "recovery-pending.json"))
			wantMarker := mode == "restore-fail" || mode == "critical-timeout" || mode == "reuse"
			if (markerErr == nil) != wantMarker {
				t.Fatalf("recovery marker presence differs: mode=%s err=%v", mode, markerErr)
			}
			if mode == "restore-fail" || mode == "critical-timeout" || mode == "diagnostic-fail" || mode == "diagnostic-block" {
				next := exec.Command(os.Args[0], "-test.run", "^TestFixtureM2RealHookChild$", "-test.v")
				next.Env = append(append([]string(nil), child.Env...), m2RealHookChildEnv+"=reuse")
				nextOutput, nextErr := next.CombinedOutput()
				if nextErr == nil {
					t.Fatalf("next M2 invocation accepted unresolved %s outcome: %s", mode, nextOutput)
				}
				after, readErr := os.ReadFile(events)
				if readErr != nil || strings.Count(string(after), "body\n") != 1 || !strings.HasSuffix(string(after), "preflight\nguard-refused\n") {
					t.Fatalf("next M2 invocation reached mutation after %s: events=%q read=%v output=%s", mode, after, readErr, nextOutput)
				}
			}
		})
	}
}
