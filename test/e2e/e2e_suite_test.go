package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	ginkgotypes "github.com/onsi/ginkgo/v2/types"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var admin client.Client
var adminset *kubernetes.Clientset
var adminConfig *rest.Config
var labctx context.Context
var scheme = runtime.NewScheme()
var m2SuiteStart time.Time
var m2ActiveScenario *m2Scenario
var m2BodyNodeTimeout = 4 * time.Minute
var m2ReplacementGateBReports []SpecReport

const (
	m2SuiteTimeout             = 70 * time.Minute
	m2ScenarioAdmissionReserve = 9 * time.Minute
	m2SuiteBodyEndReserve      = 4 * time.Minute
)

func configureM2SuiteConfig(suiteConfig *ginkgotypes.SuiteConfig) {
	suiteConfig.Timeout = m2SuiteTimeout
}

func m2ScenarioHasAdmissionReserve(suiteStart, now time.Time) bool {
	if suiteStart.IsZero() {
		return false
	}
	latestStart := suiteStart.Add(m2SuiteTimeout - m2ScenarioAdmissionReserve)
	return !now.After(latestStart)
}

func m2BodyDeadline(now time.Time) time.Time {
	deadline := now.Add(m2BodyNodeTimeout)
	if m2SuiteStart.IsZero() {
		return deadline
	}
	if suiteBound := m2SuiteStart.Add(m2SuiteTimeout - m2SuiteBodyEndReserve); suiteBound.Before(deadline) {
		deadline = suiteBound
	}
	return deadline
}

func TestE2E(t *testing.T) {
	if selectedProfileErr != nil {
		t.Fatal(selectedProfileErr)
	}
	if !suiteOptedIn() {
		t.Skip("Kind acceptance requires explicit opt-in")
	}
	env := selectionEnv()
	profile, err := profileForMilestone(env["KEAGUARD_E2E_MILESTONE"])
	if err != nil {
		t.Fatal(err)
	}
	if !selectedProfileMatches(profile) {
		t.Fatal("runtime selection differs from the immutable process profile")
	}
	if err := guardSelection(env, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	RegisterFailHandler(Fail)
	suiteConfig, reporterConfig := GinkgoConfiguration()
	if selectedProfile.milestone == "m2" {
		if suiteConfig.ParallelTotal > 1 {
			t.Fatal("M2 acceptance refuses requested parallel execution")
		}
		suiteConfig.FailOnEmpty = true
		suiteConfig.FailFast = true
		configureM2SuiteConfig(&suiteConfig)
		suiteConfig.GracePeriod = 3 * time.Second
		m2SuiteStart = time.Now()
	}
	replacementCase := os.Getenv("KEAGUARD_M2_CLUSTER_REPLACEMENT")
	if replacementCase != "" {
		if err := m2ValidateReplacementGateBSelection(replacementCase, os.Getenv("KEAGUARD_M2_REPLACEMENT_GATE_B"), suiteConfig.FocusStrings, suiteConfig.SkipStrings); err != nil {
			t.Fatal(err)
		}
		if err := m2PrepareReplacementGateBEvidence(replacementCase); err != nil {
			t.Fatal(err)
		}
		m2ReplacementGateBReports = nil
		ReportAfterEach(func(report SpecReport) {
			if strings.Contains(report.FullText(), "M2: Admission") {
				m2ReplacementGateBReports = append(m2ReplacementGateBReports, report)
			}
		})
	}
	passed := RunSpecs(t, "KeaGuard disposable Kind acceptance", suiteConfig, reporterConfig)
	if replacementCase != "" {
		if !passed || len(m2ReplacementGateBReports) != 2 {
			t.Fatalf("replacement Gate B must execute exactly two selected specs: passed=%v observed=%d", passed, len(m2ReplacementGateBReports))
		}
		for _, report := range m2ReplacementGateBReports {
			if report.Failed() || report.State.Is(ginkgotypes.SpecStateSkipped|ginkgotypes.SpecStatePending) {
				t.Fatalf("replacement Gate B case did not pass: %s", report.FullText())
			}
		}
		if err := m2SealReplacementGateB(replacementCase, m2ScenarioEvidenceDir, m2NativeDir); err != nil {
			t.Fatal(err)
		}
	}
}

// Creation is a separate explicit target, never called by TestE2E or ordinary tests.
func TestKindCreate(t *testing.T) {
	if selectedProfileErr != nil {
		t.Fatal(selectedProfileErr)
	}
	if os.Getenv("KEAGUARD_KIND_CREATE") != "1" {
		t.Skip("explicit kind-create only")
	}
	if os.Getenv("KEAGUARD_M2_CLUSTER_REPLACEMENT") != "" {
		t.Fatal("cluster replacement has no verified staged live-lab lifecycle; refusing generic Kind creation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	env := selectionEnv()
	profile, err := profileForMilestone(env["KEAGUARD_E2E_MILESTONE"])
	if err != nil {
		t.Fatal(err)
	}
	if !selectedProfileMatches(profile) {
		t.Fatal("runtime selection differs from the immutable process profile")
	}
	err = guardSelection(env, func() error {
		if profile.milestone == "m2" {
			if err := m2CheckNoPendingRecovery(m2NativeDir); err != nil {
				return err
			}
			if err := checkM2Directories(filepath.Dir(profile.kubeconfig), profile.dockerConfig); err != nil {
				return err
			}
			if _, _, err := m2VerifyBuildEvidence(ctx, os.Getenv("IMG")); err != nil {
				return err
			}
		}
		out, err := command(ctx, "kind", "get", "clusters")
		if err != nil {
			return err
		}
		for _, name := range splitLines(string(out)) {
			if name == labCluster {
				return fmt.Errorf("selected cluster already exists; inspect it instead")
			}
		}
		// The runner may provide an empty placeholder. Preserve any populated file.
		if st, err := os.Lstat(labKubeconfig); err == nil {
			if !st.Mode().IsRegular() || st.Size() != 0 {
				return fmt.Errorf("refuse to overwrite populated/nonregular kubeconfig")
			}
			if profile.milestone == "m2" {
				if st.Mode().Perm() != 0600 {
					return fmt.Errorf("M2 kubeconfig placeholder must already be 0600")
				}
			} else if err = os.Chmod(labKubeconfig, 0600); err != nil {
				return err
			}
		} else if os.IsNotExist(err) {
			f, err := os.OpenFile(labKubeconfig, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			if err = f.Close(); err != nil {
				return err
			}
		} else {
			return err
		}

		if err := checkPrivateKubeconfig(labKubeconfig); err != nil {
			return err
		}
		out, err = command(ctx, "kind", kindCreateArgs(profile)...)
		t.Log(string(out))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

var m2SuiteSetupWork = realSuiteSetup

var _ = BeforeSuite(func(setupCtx SpecContext) { m2SuiteSetupWork(setupCtx) }, m2SuiteSetupDecorators()...)

func realSuiteSetup(setupCtx SpecContext) {
	if selectedProfile.milestone == "m2" {
		Expect(m2CheckNoPendingRecovery(m2NativeDir)).To(Succeed(), "unresolved M2 recovery/diagnostics must block suite setup before image load or apply")
	}
	var cancel context.CancelFunc
	suiteLifetime := 23 * time.Minute
	if selectedProfile.milestone == "m2" {
		suiteLifetime = m2SuiteTimeout - 10*time.Second
	}
	labctx, cancel = context.WithTimeout(context.Background(), suiteLifetime)
	operationCtx := context.Context(setupCtx)
	if selectedProfile.milestone == "m2" {
		var setupCancel context.CancelFunc
		operationCtx, setupCancel = m2SuiteOperationContext(operationCtx)
		defer setupCancel()
	} else {
		operationCtx = labctx
	}
	if selectedProfile.milestone == "m2" {
		DeferCleanup(func(SpecContext) { cancel() }, NodeTimeout(2*time.Second), GracePeriod(time.Second))
	} else {
		DeferCleanup(cancel)
	}
	var err error
	adminConfig, err = validateLab(operationCtx)
	Expect(err).NotTo(HaveOccurred())
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	Expect(infrastructurev1alpha1.AddToScheme(scheme)).To(Succeed())
	admin, err = client.New(adminConfig, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	adminset, err = kubernetes.NewForConfig(adminConfig)
	Expect(err).NotTo(HaveOccurred())
	managerImageID := ""
	if selectedProfile.milestone == "m2" {
		Expect(m2VerifyNamespaceReceipt(operationCtx)).To(Succeed())
		_, managerImageID, err = m2VerifyBuildEvidence(operationCtx, os.Getenv("IMG"))
		Expect(err).NotTo(HaveOccurred())
	} else {
		Expect(ensureFixtureNamespaces(operationCtx, admin)).To(Succeed())
	}
	format := "{{.Id}}|{{.Os}}/{{.Architecture}}"
	if selectedProfile.milestone == "m2" {
		format = "{{.Id}}|{{.Os}}|{{.Architecture}}"
	}
	out, err := command(operationCtx, "docker", "image", "inspect", os.Getenv("IMG"), "--format", format)
	Expect(err).NotTo(HaveOccurred())
	if selectedProfile.milestone == "m2" {
		Expect(m2CheckImageIdentity(string(out), managerImageID)).To(Succeed())
	}
	fmt.Fprintf(GinkgoWriter, "Selected image %s: %s", os.Getenv("IMG"), out)
	_, err = command(operationCtx, "kind", "load", "docker-image", os.Getenv("IMG"), "--name", labCluster)
	Expect(err).NotTo(HaveOccurred())
	if selectedProfile.milestone == "m2" {
		Expect(m2VerifyNodeImage(operationCtx, os.Getenv("IMG"), managerImageID)).To(Succeed())
	}
	crd, err := command(operationCtx, "kubectl", "kustomize", "../../config/crd")
	Expect(err).NotTo(HaveOccurred())
	Expect(applyBundle(operationCtx, crd)).To(Succeed())
	_, err = kubectl(operationCtx, "wait", "--for=condition=Established", "crd/keaclusters.infrastructure.keaguard.example", "--timeout=120s")
	Expect(err).NotTo(HaveOccurred())
	bundle, err := renderRuntime(operationCtx)
	Expect(err).NotTo(HaveOccurred())
	Expect(applyBundle(operationCtx, bundle)).To(Succeed())
	out, err = kubectl(operationCtx, "rollout", "status", "deployment/"+managerName, "-n", runtimeNamespace, "--timeout=120s")
	if selectedProfile.milestone == "m2" {
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(m2VerifyManagerDeployment(operationCtx, os.Getenv("IMG"), managerImageID)).To(Succeed())
	} else {
		Expect(err).NotTo(HaveOccurred(), "%s\n%s", out, managerLogs(operationCtx))
	}
}

func m2SuiteOperationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 8*time.Minute)
}

func m2SuiteSetupDecorators() []any {
	if selectedProfile.milestone == "m2" {
		return []any{NodeTimeout(8 * time.Minute), GracePeriod(10 * time.Second)}
	}
	return nil
}

func m2It(text string, body func()) bool {
	if selectedProfile.milestone != "m2" {
		return It(text, body)
	}
	return It(text, NodeTimeout(m2BodyNodeTimeout), SpecTimeout(8*time.Minute), GracePeriod(10*time.Second), func(ctx SpecContext) {
		if m2ActiveScenario == nil || m2SuiteStart.IsZero() {
			Fail("M2 body lacks its registered recovery scenario")
		}
		deadline := m2BodyDeadline(time.Now())
		bodyCtx, cancel := context.WithDeadline(ctx, deadline)
		previous := labctx
		labctx = bodyCtx
		defer func() { labctx = previous; cancel() }()
		body()
	})
}

// M2 suppresses the inherited diagnostic hook entirely; its one recovery
// aggregate invokes bounded diagnostics only after restoration is verified.
func init() {
	if selectedProfile.milestone == "m2" {
		BeforeEach(func(ctx SpecContext) {
			var err error
			m2ActiveScenario, err = m2BeginScenario(ctx, CurrentSpecReport().FullText())
			Expect(err).NotTo(HaveOccurred())
		}, NodeTimeout(30*time.Second), GracePeriod(10*time.Second))
	}
	if selectedProfile.milestone != "m2" {
		AfterEach(func() {
			fmt.Fprintln(GinkgoWriter, managerLogs(labctx))
			if CurrentSpecReport().Failed() {
				out, _ := kubectl(labctx, "get", "pods,events", "-n", runtimeNamespace, "-o", "wide")
				fmt.Fprintln(GinkgoWriter, string(out))
			}
		})
	}
}
