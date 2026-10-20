package e2e

import (
	"bytes"
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
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	ginkgo "github.com/onsi/ginkgo/v2"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const m2NativeDir = "/tmp/keaguard-m2-acceptance"
const m2NamespaceReceiptPath = m2NativeDir + "/namespace-receipt.json"

var m2ScenarioEvidenceDir = m2NativeDir

const m2CreateIntentAnnotation = "keaguard.example/m2-create-intent"
const m2KeaDHCP4Image = "docker.cloudsmith.io/isc/docker/kea-dhcp4@sha256:aed0ed10d5d7510b0601a0de2b38ab64976de6b9278cdca9f4b9acbbf1f7e819"
const m2KeaDHCP6Image = "docker.cloudsmith.io/isc/docker/kea-dhcp6@sha256:0847044dca2af15f4de93607a98559f16450b6eb16a0ccad476ddc0ac1fd3b07"

type m2NodeIdentity struct {
	KubernetesUID string `json:"kubernetesUID"`
	DockerID      string `json:"dockerID"`
	Image         string `json:"image"`
	ImageID       string `json:"imageID"`
}
type m2LabIdentity struct {
	Cluster  string                    `json:"cluster"`
	Server   string                    `json:"server"`
	CASHA256 string                    `json:"caSHA256"`
	Nodes    map[string]m2NodeIdentity `json:"nodes"`
}

type m2NamespaceReceipt struct {
	Lab          m2LabIdentity               `json:"lab"`
	FixtureLabel map[string]string           `json:"fixtureLabel"`
	Namespaces   map[string]m2NamespaceEntry `json:"namespaces"`
}
type m2NamespaceEntry struct {
	UID    string            `json:"uid"`
	Labels map[string]string `json:"labels"`
	Policy map[string]string `json:"policy"`
}

type m2ProcessIdentity struct {
	PodKey            client.ObjectKey
	PodUID            types.UID
	StatefulSetKey    client.ObjectKey
	StatefulSetUID    types.UID
	KeaClusterKey     client.ObjectKey
	KeaClusterUID     types.UID
	NodeName          string
	NodeUID           types.UID
	NodeContainerID   string
	NodeImage         string
	ContainerName     string
	ContainerID       string
	SandboxID         string
	TaskID            string
	HostPID           int
	State             string
	StartTicks        uint64
	PIDNamespaceInode uint64
	NSpid             []int
	Executable        string
	Argv              []string
	UID               int
	GID               int
	ImageID           string
}

type m2FixtureIdentity struct {
	Key client.ObjectKey        `json:"key"`
	GVK schema.GroupVersionKind `json:"gvk"`
	UID types.UID               `json:"uid"`
}
type m2CreateIntent struct {
	ID           string                  `json:"id"`
	Key          client.ObjectKey        `json:"key"`
	GVK          schema.GroupVersionKind `json:"gvk"`
	GenerateName string                  `json:"generateName,omitempty"`
	RequestToken string                  `json:"requestToken,omitempty"`
	OutcomeError string                  `json:"outcomeError,omitempty"`
	ResponseCode int32                   `json:"responseCode,omitempty"`
	Replaces     *m2FixtureIdentity      `json:"replaces,omitempty"`
	Phase        string                  `json:"phase"`
}
type m2RejectedCreate struct {
	Intent m2CreateIntent `json:"intent"`
	Reason string         `json:"reason"`
}
type m2GeneratedSuccessor struct {
	Old        m2FixtureIdentity `json:"old"`
	NewUID     types.UID         `json:"newUID"`
	Parent     m2FixtureIdentity `json:"parent"`
	ClusterUID types.UID         `json:"clusterUID,omitempty"`
}
type m2Fixture struct {
	m2FixtureIdentity
	Original        client.Object
	Submitted       []client.Object
	Created         bool
	InitialOwners   []metav1.OwnerReference
	AddedFinalizers []string
	AddedOwners     []metav1.OwnerReference
	EndState        string
	AbsentVerified  bool
}
type m2FixtureLedger struct {
	intents    map[string]m2CreateIntent
	rejections []m2RejectedCreate
	fixtures   map[string]m2Fixture
	successors map[string]m2GeneratedSuccessor
}

type m2StoppedProcess struct {
	Identity m2ProcessIdentity `json:"identity"`
	Phase    string            `json:"phase"`
}

type m2KilledProcess struct {
	Identity m2ProcessIdentity `json:"identity"`
	Signal   string            `json:"signal"`
	Phase    string            `json:"phase"`
}

// m2Scenario owns one invasive case. The native evidence path is private and
// deliberately separate from the repository's checkpoint records.
type m2Scenario struct {
	Name               string
	NamespaceUIDs      map[string]types.UID
	PolicyLabels       map[string]map[string]string
	NamespaceSnapshots map[string]*corev1.Namespace
	KnownFaultPolicies map[string]map[string]string
	Manager            *appsv1.Deployment
	ServiceAccount     *corev1.ServiceAccount
	Role               *rbacv1.Role
	RoleBinding        *rbacv1.RoleBinding
	ExpectedImage      string
	ExpectedImageID    string
	CreateIntents      []m2CreateIntent
	Fixtures           []m2Fixture
	Stopped            []m2StoppedProcess
	Killed             []m2KilledProcess
	evidenceDir        string
	ledger             *m2FixtureLedger
	intentSequence     uint64
	started            bool
	caseID             string
	markerData         []byte
	receiptPath        string
}

func m2FixtureGVK(obj client.Object) (schema.GroupVersionKind, error) {
	switch obj.(type) {
	case *corev1.ConfigMap:
		return corev1.SchemeGroupVersion.WithKind("ConfigMap"), nil
	case *corev1.Pod:
		return corev1.SchemeGroupVersion.WithKind("Pod"), nil
	case *corev1.Service:
		return corev1.SchemeGroupVersion.WithKind("Service"), nil
	case *corev1.ServiceAccount:
		return corev1.SchemeGroupVersion.WithKind("ServiceAccount"), nil
	case *appsv1.Deployment:
		return appsv1.SchemeGroupVersion.WithKind("Deployment"), nil
	case *appsv1.StatefulSet:
		return appsv1.SchemeGroupVersion.WithKind("StatefulSet"), nil
	case *rbacv1.Role:
		return rbacv1.SchemeGroupVersion.WithKind("Role"), nil
	case *rbacv1.RoleBinding:
		return rbacv1.SchemeGroupVersion.WithKind("RoleBinding"), nil
	case *infrastructurev1alpha1.KeaCluster:
		return infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"), nil
	default:
		return schema.GroupVersionKind{}, fmt.Errorf("unsupported M2 fixture kind %T", obj)
	}
}

func m2IdentityFor(obj client.Object) (m2FixtureIdentity, error) {
	if obj == nil || obj.GetNamespace() == "" || obj.GetName() == "" || obj.GetUID() == "" {
		return m2FixtureIdentity{}, fmt.Errorf("fixture lacks confirmed namespace, name or UID")
	}
	gvk, err := m2FixtureGVK(obj)
	if err != nil {
		return m2FixtureIdentity{}, err
	}
	return m2FixtureIdentity{Key: client.ObjectKeyFromObject(obj), GVK: gvk, UID: obj.GetUID()}, nil
}

// m2BeginScenario is invoked once from the M2 BeforeEach. All cluster work
// before cleanup registration is read-only; the pending marker is created only
// after Ginkgo owns the single aggregate recovery callback.
// These package-local seams are overridden only by the pinned-Ginkgo subprocess
// fixture; ordinary M2 acceptance always uses the real functions below.
var m2ScenarioPrepare = m2ReadScenarioBaseline
var m2ScenarioRestoreWork = func(s *m2Scenario, ctx context.Context) error { return s.RestoreAndVerify(ctx) }
var m2ScenarioDiagnosticWork = func(s *m2Scenario, ctx context.Context) error { return s.CaptureDiagnostics(ctx) }
var m2AggregateNodeTimeout = 170 * time.Second
var m2WaitCaseWorkloadAbsentWork = m2WaitCaseWorkloadAbsent

const (
	m2CriticalRestoreWorkBudget = 120 * time.Second
	m2RecoveryProofBudget       = 130 * time.Second
	m2DiagnosticWorkBudget      = 20 * time.Second
	m2DiagnosticCommandDeadline = 8 * time.Second
)

type m2RecoveryTimingEvent struct {
	CaseID     string `json:"caseID"`
	Stage      string `json:"stage"`
	StartedUTC string `json:"startedUTC"`
	DurationMS int64  `json:"durationMS"`
	Result     string `json:"result"`
}

var m2RecoveryTimingReporter = func(event m2RecoveryTimingEvent) {
	data, err := json.Marshal(event)
	if err == nil {
		fmt.Fprintf(os.Stderr, "M2_RECOVERY_TIMING %s\n", data)
	}
}

func m2TimedRecoveryStage(caseID, stage string, run func() error) error {
	started := time.Now()
	err := run()
	result := "ok"
	if err != nil {
		result = "failed"
	}
	m2RecoveryTimingReporter(m2RecoveryTimingEvent{CaseID: caseID, Stage: stage, StartedUTC: started.UTC().Format(time.RFC3339Nano), DurationMS: time.Since(started).Milliseconds(), Result: result})
	return err
}

func m2BeginScenario(ctx context.Context, name string) (*m2Scenario, error) {
	if err := m2VerifyLabSelection(); err != nil {
		return nil, err
	}
	if name == "" || admin == nil || !m2ScenarioHasAdmissionReserve(m2SuiteStart, time.Now()) {
		return nil, fmt.Errorf("M2 case lacks identity, client or nine-minute recovery reserve")
	}
	s, err := m2ScenarioPrepare(ctx, name)
	if err != nil {
		return nil, err
	}
	if s == nil || s.Name != name || s.evidenceDir == "" {
		return nil, fmt.Errorf("M2 scenario preflight returned no matching identity/evidence path")
	}
	ginkgo.DeferCleanup(func(cleanupCtx ginkgo.SpecContext) {
		defer func() { m2ActiveScenario = nil }()
		if !s.started {
			return
		}
		if err := s.runRecovery(cleanupCtx,
			func(ctx context.Context) error { return m2ScenarioRestoreWork(s, ctx) },
			func(ctx context.Context) error { return m2ScenarioDiagnosticWork(s, ctx) }); err != nil {
			ginkgo.AbortSuite(fmt.Sprintf("M2 recovery/diagnostics failed for %s: %v", s.Name, err))
		}
	}, ginkgo.NodeTimeout(m2AggregateNodeTimeout), ginkgo.GracePeriod(10*time.Second))
	if err := s.startEvidence(); err != nil {
		return nil, err
	}
	return s, nil
}

func m2ReadScenarioBaseline(ctx context.Context, name string) (*m2Scenario, error) {
	if _, err := validateLab(ctx); err != nil {
		return nil, err
	}
	if err := m2VerifyNamespaceReceipt(ctx); err != nil {
		return nil, err
	}
	image := os.Getenv("IMG")
	_, imageID, err := m2VerifyBuildEvidence(ctx, image)
	if err != nil {
		return nil, err
	}
	if err := m2VerifyManagerDeployment(ctx, image, imageID); err != nil {
		return nil, err
	}
	s := &m2Scenario{Name: name, evidenceDir: m2ScenarioEvidenceDir, ExpectedImage: image, ExpectedImageID: imageID,
		NamespaceUIDs: map[string]types.UID{}, PolicyLabels: map[string]map[string]string{},
		NamespaceSnapshots: map[string]*corev1.Namespace{}, KnownFaultPolicies: map[string]map[string]string{}}
	for _, namespace := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		original := &corev1.Namespace{}
		if err := m2GetSnapshot(ctx, client.ObjectKey{Name: namespace}, original); err != nil {
			return nil, err
		}
		if original.UID == "" || original.ResourceVersion == "" || checkFixtureNamespaceForProfile(m2LabProfile, original) != nil {
			return nil, fmt.Errorf("namespace %s snapshot is not the approved incarnation/policy", namespace)
		}
		s.NamespaceUIDs[namespace] = original.UID
		s.PolicyLabels[namespace] = policyLabels(original.Labels)
		s.NamespaceSnapshots[namespace] = original.DeepCopy()
	}
	s.Manager = &appsv1.Deployment{}
	if err := m2GetSnapshot(ctx, client.ObjectKey{Namespace: m2LabProfile.runtimeNamespace, Name: managerName}, s.Manager); err != nil {
		return nil, err
	}
	s.ServiceAccount = &corev1.ServiceAccount{}
	if err := m2GetSnapshot(ctx, client.ObjectKey{Namespace: m2LabProfile.runtimeNamespace, Name: managerName}, s.ServiceAccount); err != nil {
		return nil, err
	}
	s.Role = &rbacv1.Role{}
	if err := m2GetSnapshot(ctx, client.ObjectKey{Namespace: m2LabProfile.runtimeNamespace, Name: "keaguard-manager-role"}, s.Role); err != nil {
		return nil, err
	}
	s.RoleBinding = &rbacv1.RoleBinding{}
	if err := m2GetSnapshot(ctx, client.ObjectKey{Namespace: m2LabProfile.runtimeNamespace, Name: "keaguard-manager-rolebinding"}, s.RoleBinding); err != nil {
		return nil, err
	}
	if s.Manager.UID == "" || s.Manager.ResourceVersion == "" || s.ServiceAccount.UID == "" || s.ServiceAccount.ResourceVersion == "" || s.Role.ResourceVersion == "" || s.RoleBinding.ResourceVersion == "" {
		return nil, fmt.Errorf("M2 manager/RBAC snapshots lack UID or resourceVersion")
	}
	if err := m2VerifyRBACBaseline(s.Role, s.RoleBinding); err != nil {
		return nil, err
	}
	if err := m2VerifyNamespaceReceipt(ctx); err != nil {
		return nil, err
	}
	if err := m2CheckNoPendingRecovery(s.evidenceDir); err != nil {
		return nil, err
	}
	return s, nil
}

func m2GetSnapshot(ctx context.Context, key client.ObjectKey, obj client.Object) error {
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return admin.Get(requestCtx, key, obj)
}

func m2ListSnapshot(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return admin.List(requestCtx, list, opts...)
}

func (s *m2Scenario) startEvidence() error {
	if s == nil || s.Name == "" || s.evidenceDir == "" || s.started {
		return fmt.Errorf("invalid or repeated M2 scenario start")
	}
	info, err := os.Lstat(s.evidenceDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("M2 scenario evidence directory %s is not private: mode=%v", s.evidenceDir, info.Mode())
	}
	if err := m2CheckNoPendingRecovery(s.evidenceDir); err != nil {
		return err
	}
	if s.ledger == nil {
		s.ledger = newM2FixtureLedger()
	}
	s.caseID = fmt.Sprintf("%d-%d", time.Now().UTC().UnixNano(), os.Getpid())
	s.receiptPath = filepath.Join(s.evidenceDir, "recovery-restored-"+s.caseID+".json")
	marker := map[string]string{"phase": "scenario", "name": s.Name, "caseID": s.caseID, "startedUTC": time.Now().UTC().Format(time.RFC3339Nano)}
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	s.markerData = append(data, '\n')
	if err := writePrivateExclusiveOrReplace(filepath.Join(s.evidenceDir, "recovery-pending.json"), s.markerData); err != nil {
		return err
	}
	s.started = true
	if err := s.persistDiagnostics("not-started", nil); err != nil {
		return err
	}
	return s.persistLedger()
}

func (s *m2Scenario) persistDiagnostics(status string, outcome error) error {
	if s == nil || !s.started || s.caseID == "" {
		return fmt.Errorf("M2 diagnostics state has no scenario identity")
	}
	record := struct {
		CaseID string `json:"caseID"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}{CaseID: s.caseID, Status: status}
	if outcome != nil {
		record.Error = m2RedactEvidence(outcome.Error())
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := writePrivateReceipt(filepath.Join(s.evidenceDir, "diagnostics-"+s.caseID+".json"), data); err != nil {
		return err
	}
	return writePrivateReceipt(filepath.Join(s.evidenceDir, "diagnostics.json"), data)
}

func (s *m2Scenario) sealRecovery(ctx context.Context) error {
	if s == nil || !s.started || ctx.Err() != nil {
		return fmt.Errorf("M2 recovery cannot seal after cancellation or before start")
	}
	markerPath := filepath.Join(s.evidenceDir, "recovery-pending.json")
	marker, err := readM2PrivateRecord(markerPath)
	if err != nil {
		return fmt.Errorf("M2 recovery marker identity changed: %w", err)
	}
	if !bytes.Equal(marker, s.markerData) {
		return fmt.Errorf("M2 recovery marker identity changed")
	}
	receipt := struct {
		CaseID        string               `json:"caseID"`
		Name          string               `json:"name"`
		Recovery      string               `json:"recovery"`
		NamespaceUIDs map[string]types.UID `json:"namespaceUIDs"`
		Image         string               `json:"image"`
		ImageID       string               `json:"imageID"`
		VerifiedUTC   string               `json:"verifiedUTC"`
	}{s.caseID, s.Name, "restored", s.NamespaceUIDs, s.ExpectedImage, s.ExpectedImageID, time.Now().UTC().Format(time.RFC3339Nano)}
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	if err := writePrivateExclusiveOrReplace(s.receiptPath, append(data, '\n')); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Remove(markerPath); err != nil {
		return err
	}
	return syncPrivateDirectory(markerPath)
}

// runRecovery is the synchronous recovery/diagnostic transition used by the
// M2 Ginkgo aggregate. Unit tests replace only external API/command work.
func (s *m2Scenario) runRecovery(ctx context.Context, restore, diagnose func(context.Context) error) error {
	if s == nil || !s.started || restore == nil || diagnose == nil || ctx.Err() != nil {
		return fmt.Errorf("M2 recovery cannot start")
	}
	entry := time.Now()
	criticalCtx, criticalCancel := context.WithTimeout(ctx, m2CriticalRestoreWorkBudget)
	restoreErr := m2TimedRecoveryStage(s.caseID, "aggregate-resource-restoration", func() error { return restore(criticalCtx) })
	criticalCancel()
	if restoreErr == nil {
		restoreErr = ctx.Err()
	}
	if restoreErr == nil && time.Since(entry) > m2CriticalRestoreWorkBudget {
		restoreErr = fmt.Errorf("M2 restoration exceeded its 120-second work allocation")
	}
	if restoreErr != nil {
		return errors.Join(restoreErr, s.persistDiagnostics("skipped-recovery-incomplete", restoreErr))
	}
	proofCtx, proofCancel := context.WithDeadline(ctx, entry.Add(m2RecoveryProofBudget))
	sealErr := m2TimedRecoveryStage(s.caseID, "verified-recovery-receipt-seal", func() error { return s.sealRecovery(proofCtx) })
	proofCancel()
	if sealErr != nil {
		return errors.Join(sealErr, s.persistDiagnostics("skipped-recovery-incomplete", sealErr))
	}
	if err := s.persistDiagnostics("started", nil); err != nil {
		return err
	}
	diagnosticCtx, diagnosticCancel := context.WithTimeout(ctx, m2DiagnosticWorkBudget)
	diagnosticErr := m2TimedRecoveryStage(s.caseID, "bounded-diagnostics", func() error { return diagnose(diagnosticCtx) })
	diagnosticCancel()
	status := "ok"
	if diagnosticErr == nil {
		diagnosticErr = ctx.Err()
	}
	if diagnosticErr != nil {
		status = "failed"
		if errors.Is(diagnosticErr, context.Canceled) || errors.Is(diagnosticErr, context.DeadlineExceeded) {
			status = "interrupted"
		}
	}
	return errors.Join(diagnosticErr, s.persistDiagnostics(status, diagnosticErr))
}

func (s *m2Scenario) CaptureDiagnostics(ctx context.Context) error {
	return s.captureDiagnostics(ctx, m2Command)
}

func (s *m2Scenario) captureDiagnostics(ctx context.Context, run func(context.Context, string, ...string) ([]byte, error)) error {
	if s == nil || !s.started || run == nil || ctx.Err() != nil {
		return fmt.Errorf("M2 diagnostics lack a live recovered scenario")
	}
	if _, err := os.Lstat(filepath.Join(s.evidenceDir, "recovery-pending.json")); err == nil {
		return fmt.Errorf("M2 diagnostics refused while recovery marker exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := readM2PrivateRecord(s.receiptPath)
	if err != nil {
		return err
	}
	var receipt struct {
		CaseID   string `json:"caseID"`
		Recovery string `json:"recovery"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil || receipt.CaseID != s.caseID || receipt.Recovery != "restored" {
		return fmt.Errorf("M2 diagnostics require this case's verified restoration receipt")
	}
	bounded, cancel := context.WithTimeout(ctx, m2DiagnosticWorkBudget)
	defer cancel()
	prefix := []string{"--kubeconfig", m2LabProfile.kubeconfig, "--context", "kind-" + m2LabProfile.cluster}
	requests := []struct {
		file string
		args []string
	}{
		{file: "diagnostic-manager-logs-" + s.caseID + ".txt", args: []string{"logs", "-n", m2LabProfile.runtimeNamespace, "deployment/" + managerName, "--tail=100"}},
		{file: "diagnostic-namespace-" + s.caseID + ".txt", args: []string{"get", "pods", "-n", m2LabProfile.runtimeNamespace, "-o", "wide"}},
		{file: "diagnostic-events-" + s.caseID + ".txt", args: []string{"get", "events", "-n", m2LabProfile.runtimeNamespace, "--sort-by=.metadata.creationTimestamp", "-o=jsonpath={range .items[-20:]}{.metadata.creationTimestamp}{\" \"}{.type}{\" \"}{.reason}{\" \"}{.involvedObject.kind}{\"/\"}{.involvedObject.name}{\" x\"}{.count}{\"\\n\"}{end}"}},
	}
	var failures []error
	for _, request := range requests {
		if err := bounded.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		output, runErr := run(bounded, "kubectl", append(append([]string(nil), prefix...), request.args...)...)
		if err := writePrivateReceipt(filepath.Join(s.evidenceDir, request.file), []byte(m2RedactEvidence(string(output)))); err != nil {
			failures = append(failures, err)
		}
		if runErr != nil {
			failures = append(failures, runErr)
		}
	}
	return errors.Join(failures...)
}

func (s *m2Scenario) persistLedger() error {
	if s == nil || !s.started || s.ledger == nil {
		return fmt.Errorf("M2 scenario ledger is not started")
	}
	intents := make([]m2CreateIntent, 0, len(s.ledger.intents))
	for _, intent := range s.ledger.intents {
		intents = append(intents, intent)
	}
	sort.Slice(intents, func(i, j int) bool { return intents[i].ID < intents[j].ID })
	s.CreateIntents = append(s.CreateIntents[:0], intents...)
	type savedFixture struct {
		m2FixtureIdentity
		Created         bool                    `json:"created"`
		InitialOwners   []metav1.OwnerReference `json:"initialOwners,omitempty"`
		AddedFinalizers []string                `json:"addedFinalizers,omitempty"`
		AddedOwners     []metav1.OwnerReference `json:"addedOwners,omitempty"`
		EndState        string                  `json:"endState"`
		AbsentVerified  bool                    `json:"absentVerified"`
		Original        json.RawMessage         `json:"original,omitempty"`
		Submitted       []json.RawMessage       `json:"submitted,omitempty"`
	}
	keys := make([]string, 0, len(s.ledger.fixtures))
	for key := range s.ledger.fixtures {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fixtures := make([]savedFixture, 0, len(keys))
	s.Fixtures = s.Fixtures[:0]
	for _, key := range keys {
		fixture := s.ledger.fixtures[key]
		visible := fixture
		if fixture.Original != nil {
			visible.Original = fixture.Original.DeepCopyObject().(client.Object)
		}
		s.Fixtures = append(s.Fixtures, visible)
		saved := savedFixture{m2FixtureIdentity: fixture.m2FixtureIdentity, Created: fixture.Created, InitialOwners: append([]metav1.OwnerReference(nil), fixture.InitialOwners...), AddedFinalizers: append([]string(nil), fixture.AddedFinalizers...), AddedOwners: append([]metav1.OwnerReference(nil), fixture.AddedOwners...), EndState: fixture.EndState, AbsentVerified: fixture.AbsentVerified}
		if fixture.Original != nil {
			var err error
			saved.Original, err = json.Marshal(fixture.Original)
			if err != nil {
				return err
			}
		}
		for _, submission := range fixture.Submitted {
			encoded, err := json.Marshal(submission)
			if err != nil {
				return err
			}
			saved.Submitted = append(saved.Submitted, encoded)
		}
		fixtures = append(fixtures, saved)
	}
	data, err := json.Marshal(struct {
		Scenario     string                       `json:"scenario"`
		Intents      []m2CreateIntent             `json:"intents"`
		Rejections   []m2RejectedCreate           `json:"rejections,omitempty"`
		Successors   []m2GeneratedSuccessor       `json:"successors,omitempty"`
		Fixtures     []savedFixture               `json:"fixtures"`
		Stopped      []m2StoppedProcess           `json:"stopped"`
		Killed       []m2KilledProcess            `json:"killed,omitempty"`
		PolicyFaults map[string]map[string]string `json:"policyFaults,omitempty"`
	}{s.Name, intents, s.ledger.rejections, s.ledger.sortedSuccessors(), fixtures, s.Stopped, s.Killed, s.KnownFaultPolicies})
	if err != nil {
		return err
	}
	return writePrivateReceipt(filepath.Join(s.evidenceDir, "ledger.json"), append(data, '\n'))
}

func (s *m2Scenario) RecordCreateIntent(obj client.Object, replaces *m2FixtureIdentity) (string, error) {
	if s == nil || !s.started || obj == nil || obj.GetNamespace() == "" {
		return "", fmt.Errorf("M2 create intent requires a started scenario and namespace")
	}
	gvk, err := m2FixtureGVK(obj)
	if err != nil {
		return "", err
	}
	s.intentSequence++
	id := fmt.Sprintf("%s-%d", s.Name, s.intentSequence)
	identityMaterial := strings.Join([]string{s.caseID, id, gvk.String(), obj.GetNamespace(), obj.GetName(), obj.GetGenerateName()}, "\x00")
	tokenDigest := sha256.Sum256([]byte(identityMaterial))
	requestToken := hex.EncodeToString(tokenDigest[:])
	if obj.GetGenerateName() != "" {
		obj.SetName("m2-fixture-" + requestToken[:24])
		obj.SetGenerateName("")
	}
	annotations := maps.Clone(obj.GetAnnotations())
	if annotations == nil {
		annotations = map[string]string{}
	}
	if existing := annotations[m2CreateIntentAnnotation]; existing != "" && existing != requestToken {
		return "", fmt.Errorf("M2 fixture uses reserved create-intent annotation")
	}
	annotations[m2CreateIntentAnnotation] = requestToken
	obj.SetAnnotations(annotations)
	intent := m2CreateIntent{ID: id, Key: client.ObjectKeyFromObject(obj), GVK: gvk, RequestToken: requestToken, Replaces: replaces, Phase: "planned"}
	if err := s.ledger.RecordCreateIntent(intent); err != nil {
		return "", err
	}
	if err := s.persistLedger(); err != nil {
		return "", err
	}
	return id, nil
}

func (s *m2Scenario) ConfirmCreated(intentID string, obj client.Object) error {
	if s == nil || !s.started {
		return fmt.Errorf("M2 scenario is not started")
	}
	identity, err := m2IdentityFor(obj)
	if err != nil {
		return err
	}
	if err := s.ledger.ConfirmCreated(intentID, identity); err != nil {
		return err
	}
	fixture := s.ledger.fixtures[fixtureKey(identity)]
	fixture.InitialOwners = append([]metav1.OwnerReference(nil), obj.GetOwnerReferences()...)
	for _, finalizer := range obj.GetFinalizers() {
		if finalizer != t14HoldFinalizer {
			return fmt.Errorf("created fixture has unreviewed finalizer %q", finalizer)
		}
		fixture.AddedFinalizers = append(fixture.AddedFinalizers, finalizer)
	}
	s.ledger.fixtures[fixtureKey(identity)] = fixture
	return s.persistLedger()
}

func (s *m2Scenario) MarkCreateSubmitted(intentID string) error {
	if s == nil || !s.started {
		return fmt.Errorf("M2 scenario is not started")
	}
	if err := s.ledger.advanceCreateIntent(intentID, "planned", "submitted"); err != nil {
		return err
	}
	return s.persistLedger()
}

func (s *m2Scenario) MarkCreateUnresolved(intentID string) error {
	return s.markCreateUnresolved(intentID, nil)
}

func (s *m2Scenario) markCreateUnresolved(intentID string, outcome error) error {
	if s == nil || !s.started {
		return fmt.Errorf("M2 scenario is not started")
	}
	if err := s.ledger.advanceCreateIntent(intentID, "submitted", "unresolved"); err != nil {
		return err
	}
	intent := s.ledger.intents[intentID]
	if outcome != nil {
		intent.OutcomeError = m2RedactEvidence(outcome.Error())
	}
	s.ledger.intents[intentID] = intent
	return s.persistLedger()
}

func (s *m2Scenario) markCreateNotSubmitted(intentID string, outcome error) error {
	if s == nil || !s.started {
		return fmt.Errorf("M2 scenario is not started")
	}
	if err := s.ledger.advanceCreateIntent(intentID, "planned", "not-submitted"); err != nil {
		return err
	}
	intent := s.ledger.intents[intentID]
	if outcome != nil {
		intent.OutcomeError = m2RedactEvidence(outcome.Error())
	}
	s.ledger.intents[intentID] = intent
	return s.persistLedger()
}

func (s *m2Scenario) markCreateRejectedWithStatus(intentID string, outcome error, code int32) error {
	if s == nil || !s.started || outcome == nil || !m2DefinitiveCreateResponseCode(code) {
		return fmt.Errorf("M2 Create rejection lacks a definitive client-error API response")
	}
	if err := s.ledger.advanceCreateIntent(intentID, "submitted", "rejected"); err != nil {
		return err
	}
	intent := s.ledger.intents[intentID]
	intent.OutcomeError = m2RedactEvidence(outcome.Error())
	intent.ResponseCode = code
	s.ledger.intents[intentID] = intent
	return s.persistLedger()
}

func (s *m2Scenario) MarkCreateRejected(intentID string, rejection error) error {
	if s == nil || !s.started || !isExpectedOwnerReferenceAdmissionError(rejection) {
		return fmt.Errorf("M2 Create rejection is not a definitive reviewed admission error")
	}
	intent, ok := s.ledger.intents[intentID]
	if !ok || intent.Phase != "submitted" {
		return fmt.Errorf("M2 rejected Create lacks submitted intent")
	}
	s.ledger.rejections = append(s.ledger.rejections, m2RejectedCreate{Intent: intent, Reason: m2RedactEvidence(rejection.Error())})
	delete(s.ledger.intents, intentID)
	return s.persistLedger()
}

// CreateFixture persists the request identity before touching the API. A lost
// or failed response is unresolved: a name/label match cannot authorize a
// later delete without independent attribution of the returned UID.
func (s *m2Scenario) CreateFixture(ctx context.Context, obj client.Object, replaces *m2FixtureIdentity) error {
	return s.createFixtureWith(ctx, obj, replaces, false, func(requestCtx context.Context, candidate client.Object) (client.Object, error) {
		return candidate, admin.Create(requestCtx, candidate)
	})
}

func (s *m2Scenario) createFixtureWith(ctx context.Context, obj client.Object, replaces *m2FixtureIdentity, allowReviewedRejection bool, create func(context.Context, client.Object) (client.Object, error)) error {
	return s.createFixtureWithObserver(ctx, obj, replaces, allowReviewedRejection, create, m2ObserveCreateCandidate)
}

func m2ObserveCreateCandidate(ctx context.Context, key client.ObjectKey, gvk schema.GroupVersionKind) (client.Object, error) {
	observed, err := m2NewFixtureObject(gvk)
	if err != nil {
		return nil, err
	}
	if err := admin.Get(ctx, key, observed); err != nil {
		return nil, err
	}
	return observed, nil
}

func (s *m2Scenario) createFixtureWithObserver(ctx context.Context, obj client.Object, replaces *m2FixtureIdentity, allowReviewedRejection bool,
	create func(context.Context, client.Object) (client.Object, error), observe func(context.Context, client.ObjectKey, schema.GroupVersionKind) (client.Object, error)) error {
	if create == nil {
		return fmt.Errorf("M2 fixture Create has no submitting client")
	}
	if observe == nil {
		return fmt.Errorf("M2 fixture Create has no identity observer")
	}
	intentID, err := s.RecordCreateIntent(obj, replaces)
	if err != nil {
		return err
	}
	intent := s.ledger.intents[intentID]
	preflightCtx, preflightCancel := context.WithTimeout(ctx, 10*time.Second)
	_, preflightErr := observe(preflightCtx, intent.Key, intent.GVK)
	preflightCancel()
	if preflightErr == nil {
		collisionErr := fmt.Errorf("M2 fixture name %s/%s already exists before Create; foreign incarnation was not adopted", intent.Key.Namespace, intent.Key.Name)
		return errors.Join(collisionErr, s.markCreateNotSubmitted(intentID, collisionErr))
	}
	if !apierrors.IsNotFound(preflightErr) {
		return errors.Join(fmt.Errorf("M2 fixture Create was not submitted because name preflight was inconclusive"), s.markCreateNotSubmitted(intentID, preflightErr))
	}
	if err := s.MarkCreateSubmitted(intentID); err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	created, err := create(requestCtx, obj)
	if err != nil {
		if allowReviewedRejection && isExpectedOwnerReferenceAdmissionError(err) {
			return errors.Join(err, s.MarkCreateRejected(intentID, err))
		}
		if code := m2CreateHTTPClientError(err); code != 0 {
			return errors.Join(err, s.markCreateRejectedWithStatus(intentID, err, code))
		}
		observationCtx, observationCancel := context.WithTimeout(ctx, 10*time.Second)
		observed, observationErr := observe(observationCtx, intent.Key, intent.GVK)
		observationCancel()
		if observationErr == nil && m2ObservedCreateMatchesIntent(observed, intent) {
			if confirmErr := s.ConfirmCreated(intentID, observed); confirmErr == nil {
				current := s.ledger.intents[intentID]
				current.OutcomeError = m2RedactEvidence(err.Error())
				s.ledger.intents[intentID] = current
				if persistErr := s.persistLedger(); persistErr == nil {
					return fmt.Errorf("M2 Create returned an ambiguous error; exact request incarnation was observed and recorded for cleanup: %w", err)
				} else {
					return errors.Join(err, fmt.Errorf("persist observed lost-ack incarnation: %w", persistErr))
				}
			}
		}
		if observationErr == nil {
			observationErr = fmt.Errorf("observed object does not match the persisted request token, GVK, name, UID and resourceVersion")
		}
		return errors.Join(err, fmt.Errorf("M2 Create outcome remains ambiguous: %w", observationErr), s.markCreateUnresolved(intentID, errors.Join(err, observationErr)))
	}
	if created == nil {
		return errors.Join(fmt.Errorf("M2 Create returned a nil object without an error"), s.markCreateUnresolved(intentID, fmt.Errorf("nil Create response")))
	}
	if !m2ObservedCreateMatchesIntent(created, intent) {
		mismatchErr := fmt.Errorf("Create response does not prove the exact persisted request identity")
		return errors.Join(mismatchErr, s.markCreateUnresolved(intentID, mismatchErr))
	}
	if err := s.ConfirmCreated(intentID, created); err != nil {
		return errors.Join(fmt.Errorf("created fixture cannot be attributed to its intent; recovery marker retained: %w", err), s.markCreateUnresolved(intentID, err))
	}
	return nil
}

func m2CreateHTTPClientError(err error) int32 {
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return 0
	}
	response := status.Status()
	if !m2DefinitiveCreateReason(response.Reason) {
		return 0
	}
	return response.Code
}

func m2DefinitiveCreateReason(reason metav1.StatusReason) bool {
	switch reason {
	case metav1.StatusReasonAlreadyExists, metav1.StatusReasonForbidden, metav1.StatusReasonUnauthorized,
		metav1.StatusReasonInvalid, metav1.StatusReasonBadRequest, metav1.StatusReasonNotFound,
		metav1.StatusReasonMethodNotAllowed, metav1.StatusReasonUnsupportedMediaType,
		metav1.StatusReasonRequestEntityTooLarge, metav1.StatusReasonTooManyRequests:
		return true
	default:
		return false
	}
}

func m2DefinitiveCreateResponseCode(code int32) bool {
	switch code {
	case 400, 401, 403, 404, 405, 409, 413, 415, 422, 429:
		return true
	default:
		return false
	}
}

func m2ObservedCreateMatchesIntent(observed client.Object, intent m2CreateIntent) bool {
	if observed == nil || intent.RequestToken == "" || intent.Key.Name == "" || observed.GetNamespace() != intent.Key.Namespace ||
		observed.GetName() != intent.Key.Name || observed.GetUID() == "" || observed.GetResourceVersion() == "" ||
		observed.GetAnnotations()[m2CreateIntentAnnotation] != intent.RequestToken {
		return false
	}
	gvk, err := m2FixtureGVK(observed)
	return err == nil && gvk == intent.GVK
}

func m2CreateExpectedOwnerReference(ctx context.Context, obj client.Object) error {
	if selectedProfile.milestone != "m2" {
		return admin.Create(ctx, obj)
	}
	if m2ActiveScenario == nil {
		return fmt.Errorf("M2 expected-admission Create lacks a scenario")
	}
	return m2ActiveScenario.createFixtureWith(ctx, obj, nil, true, func(requestCtx context.Context, candidate client.Object) (client.Object, error) {
		return candidate, admin.Create(requestCtx, candidate)
	})
}

func m2CreateObject(ctx context.Context, obj client.Object, replaces *m2FixtureIdentity) error {
	if selectedProfile.milestone != "m2" {
		return admin.Create(ctx, obj)
	}
	if m2ActiveScenario == nil {
		return fmt.Errorf("M2 create lacks its registered scenario")
	}
	return m2ActiveScenario.CreateFixture(ctx, obj, replaces)
}

func m2DeleteObject(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if selectedProfile.milestone != "m2" {
		return admin.Delete(ctx, obj, opts...)
	}
	if m2ActiveScenario == nil {
		return fmt.Errorf("M2 delete lacks its registered scenario")
	}
	identity, err := m2IdentityFor(obj)
	if err != nil {
		return err
	}
	current, err := m2NewFixtureObject(identity.GVK)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = admin.Get(requestCtx, identity.Key, current)
	cancel()
	if err != nil {
		return err
	}
	if current.GetUID() != identity.UID || current.GetResourceVersion() == "" {
		return fmt.Errorf("M2 delete target UID/resourceVersion changed")
	}
	if fixture, recorded := m2ActiveScenario.ledger.fixtures[fixtureKey(identity)]; !recorded {
		if err := m2ActiveScenario.RecordFixture(current, current, "absent"); err != nil {
			return err
		}
	} else if fixture.EndState != "absent" {
		fixture.EndState = "absent"
		m2ActiveScenario.ledger.fixtures[fixtureKey(identity)] = fixture
		if err := m2ActiveScenario.persistLedger(); err != nil {
			return err
		}
	}
	uid, rv := current.GetUID(), current.GetResourceVersion()
	requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return admin.Delete(requestCtx, current, append(opts, client.Preconditions{UID: &uid, ResourceVersion: &rv})...)
}

func m2UpdateObject(ctx context.Context, obj client.Object, endState string) error {
	if selectedProfile.milestone != "m2" {
		return admin.Update(ctx, obj)
	}
	if m2ActiveScenario == nil || (endState != "restored" && endState != "absent") {
		return fmt.Errorf("M2 update lacks a scenario or valid end state")
	}
	identity, err := m2IdentityFor(obj)
	if err != nil {
		return err
	}
	current, err := m2NewFixtureObject(identity.GVK)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = admin.Get(requestCtx, identity.Key, current)
	cancel()
	if err != nil {
		return err
	}
	if current.GetUID() != identity.UID || current.GetResourceVersion() == "" || current.GetResourceVersion() != obj.GetResourceVersion() {
		return fmt.Errorf("M2 update target UID/resourceVersion changed")
	}
	if fixture, recorded := m2ActiveScenario.ledger.fixtures[fixtureKey(identity)]; recorded && fixture.Created {
		if err := m2ActiveScenario.RecordFixture(current, nil, "absent"); err != nil {
			return err
		}
	} else if err := m2ActiveScenario.RecordFixture(current, current, endState); err != nil {
		return err
	}
	if err := m2ActiveScenario.recordAddedMetadata(current, obj); err != nil {
		return err
	}
	fixture := m2ActiveScenario.ledger.fixtures[fixtureKey(identity)]
	fixture.Submitted = append(fixture.Submitted, obj.DeepCopyObject().(client.Object))
	m2ActiveScenario.ledger.fixtures[fixtureKey(identity)] = fixture
	if err := m2ActiveScenario.persistLedger(); err != nil {
		return err
	}
	requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return admin.Update(requestCtx, obj)
}

// UpdateGeneratedConfigMap applies only data changes to the exact ConfigMap
// generated for a scenario-owned KeaCluster. The parent fixture, not this
// controller-owned child, is the cleanup authority; independent snapshots of
// the child would become stale when parent deletion garbage-collects it.
func (s *m2Scenario) UpdateGeneratedConfigMap(ctx context.Context, desired *corev1.ConfigMap, parent m2FixtureIdentity) error {
	if ctx == nil || ctx.Err() != nil || selectedProfile.milestone != "m2" || s == nil || !s.started || s != m2ActiveScenario || desired == nil ||
		parent.GVK != infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster") || parent.UID == "" || parent.Key.Namespace != m2LabProfile.runtimeNamespace {
		return fmt.Errorf("generated ConfigMap update lacks a live M2 scenario and exact parent identity")
	}
	child, err := m2IdentityFor(desired)
	if err != nil || child.GVK != corev1.SchemeGroupVersion.WithKind("ConfigMap") || child.Key.Namespace != parent.Key.Namespace || child.UID == "" || desired.GetResourceVersion() == "" {
		return fmt.Errorf("generated ConfigMap update lacks exact child UID/resourceVersion")
	}
	if _, recorded := s.ledger.fixtures[fixtureKey(child)]; recorded {
		return fmt.Errorf("generated ConfigMap already has fixture restoration authority")
	}
	parentFixture, recorded := s.ledger.fixtures[fixtureKey(parent)]
	if !recorded || !parentFixture.Created {
		return fmt.Errorf("generated ConfigMap parent is not this scenario's confirmed fixture")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	liveParent := &infrastructurev1alpha1.KeaCluster{}
	err = admin.Get(requestCtx, parent.Key, liveParent)
	cancel()
	if err != nil || liveParent.UID != parent.UID {
		return fmt.Errorf("generated ConfigMap parent UID changed: %v", err)
	}
	requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
	live := &corev1.ConfigMap{}
	err = admin.Get(requestCtx, child.Key, live)
	cancel()
	if err != nil {
		return err
	}
	owner := metav1.GetControllerOf(live)
	if live.UID != child.UID || live.ResourceVersion != desired.ResourceVersion || owner == nil ||
		owner.APIVersion != infrastructurev1alpha1.GroupVersion.String() || owner.Kind != "KeaCluster" || owner.Name != parent.Key.Name || owner.UID != parent.UID ||
		live.Labels["keaguard.example/cluster-uid"] != string(parent.UID) {
		return fmt.Errorf("generated ConfigMap live UID/resourceVersion/owner identity changed")
	}
	metadataOnly := desired.DeepCopy()
	metadataOnly.Data = live.Data
	if !reflect.DeepEqual(metadataOnly, live) {
		return fmt.Errorf("generated ConfigMap update may change only Data")
	}
	requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return admin.Update(requestCtx, desired)
}

func m2RecordReadyNativePodSuccessor(ctx context.Context, old corev1.Pod) error {
	if m2ActiveScenario == nil || ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("native Pod successor observation lacks an active scenario and context")
	}
	identity, err := m2IdentityFor(&old)
	if err != nil {
		return err
	}
	return m2ActiveScenario.ObserveNativePodSuccessor(ctx, identity)
}

func (s *m2Scenario) recordAddedMetadata(before, after client.Object) error {
	identity, err := m2IdentityFor(before)
	if err != nil || after.GetUID() != identity.UID {
		return fmt.Errorf("case metadata mutation lacks confirmed source UID")
	}
	fixture, ok := s.ledger.fixtures[fixtureKey(identity)]
	if !ok {
		return fmt.Errorf("case metadata mutation lacks fixture ledger entry")
	}
	for _, finalizer := range before.GetFinalizers() {
		if !slices.Contains(after.GetFinalizers(), finalizer) {
			return fmt.Errorf("case update removes existing finalizer %q without checked release", finalizer)
		}
	}
	for _, owner := range before.GetOwnerReferences() {
		if !slices.ContainsFunc(after.GetOwnerReferences(), func(ref metav1.OwnerReference) bool { return reflect.DeepEqual(ref, owner) }) {
			return fmt.Errorf("case update removes an existing owner without checked release")
		}
	}
	for _, finalizer := range after.GetFinalizers() {
		if slices.Contains(before.GetFinalizers(), finalizer) {
			continue
		}
		if finalizer != t14HoldFinalizer {
			return fmt.Errorf("unreviewed case-added finalizer %q", finalizer)
		}
		if !slices.Contains(fixture.AddedFinalizers, finalizer) {
			fixture.AddedFinalizers = append(fixture.AddedFinalizers, finalizer)
		}
	}
	for _, owner := range after.GetOwnerReferences() {
		if slices.ContainsFunc(before.GetOwnerReferences(), func(ref metav1.OwnerReference) bool { return reflect.DeepEqual(ref, owner) }) {
			continue
		}
		found := false
		for _, candidate := range s.ledger.fixtures {
			if candidate.Created && candidate.UID == owner.UID && candidate.Key.Namespace == identity.Key.Namespace && candidate.Key.Name == owner.Name && candidate.GVK.Kind == owner.Kind && candidate.GVK.GroupVersion().String() == owner.APIVersion {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("case-added owner %s/%s UID %s is not a confirmed fixture", owner.Kind, owner.Name, owner.UID)
		}
		fixture.AddedOwners = append(fixture.AddedOwners, *owner.DeepCopy())
	}
	s.ledger.fixtures[fixtureKey(identity)] = fixture
	return s.persistLedger()
}

// VerifyAbsent directly observes the old name/UID before a recorded same-name
// replacement may be planned. It does not confer rights over a new UID.
func (s *m2Scenario) VerifyAbsent(ctx context.Context, identity m2FixtureIdentity) error {
	if s == nil || !s.started || identity.UID == "" {
		return fmt.Errorf("M2 absent proof lacks a recorded incarnation")
	}
	if _, ok := s.ledger.fixtures[fixtureKey(identity)]; !ok {
		return fmt.Errorf("M2 absent proof refers to an unrecorded incarnation")
	}
	obj, err := m2NewFixtureObject(identity.GVK)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = admin.Get(requestCtx, identity.Key, obj)
	cancel()
	if err == nil && obj.GetUID() == identity.UID {
		return fmt.Errorf("recorded old UID %s is still present", identity.UID)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if err := s.ledger.MarkAbsentVerified(identity); err != nil {
		return err
	}
	return s.persistLedger()
}

// ObserveGeneratedSuccessor records a controller-created child only as read-only
// replacement evidence. It never grants fixture deletion or update authority.
func (s *m2Scenario) ObserveGeneratedSuccessor(ctx context.Context, old, parent m2FixtureIdentity) error {
	if s == nil || !s.started || old.GVK != corev1.SchemeGroupVersion.WithKind("ConfigMap") ||
		parent.GVK != infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster") || old.UID == "" || parent.UID == "" ||
		old.Key.Namespace != parent.Key.Namespace {
		return fmt.Errorf("generated successor observation lacks exact old child/new parent identity")
	}
	oldFixture, oldRecorded := s.ledger.fixtures[fixtureKey(old)]
	parentFixture, parentRecorded := s.ledger.fixtures[fixtureKey(parent)]
	if !oldRecorded || oldFixture.EndState != "absent" || !parentRecorded || !parentFixture.Created {
		return fmt.Errorf("generated successor lacks old-child/new-parent ledger chain")
	}
	child := &corev1.ConfigMap{}
	if err := m2GetSnapshot(ctx, old.Key, child); err != nil {
		return err
	}
	validSuccessor := false
	if old.Key.Name == parent.Key.Name {
		validSuccessor = m2IsIdentityArtifactSuccessor(child, parent)
	} else {
		parentObject := &infrastructurev1alpha1.KeaCluster{}
		if err := m2GetSnapshot(ctx, parent.Key, parentObject); err != nil {
			return fmt.Errorf("read exact parent before operational successor observation: %w", err)
		}
		oldObject, ok := oldFixture.Original.(*corev1.ConfigMap)
		if !ok || parentObject.UID != parent.UID {
			return fmt.Errorf("operational ConfigMap successor parent or old fixture incarnation changed")
		}
		validSuccessor = m2IsOperationalConfigSuccessor(child, oldObject, parentObject)
	}
	if child.UID == "" || child.UID == old.UID || !validSuccessor {
		return fmt.Errorf("generated successor is not the new parent's exact owned ConfigMap")
	}
	if err := s.ledger.MarkAbsentVerified(old); err != nil {
		return err
	}
	if s.ledger.successors == nil {
		s.ledger.successors = map[string]m2GeneratedSuccessor{}
	}
	if prior, exists := s.ledger.successors[fixtureKey(old)]; exists && (prior.NewUID != child.UID || prior.Parent != parent) {
		return fmt.Errorf("generated successor changed after observation")
	}
	s.ledger.successors[fixtureKey(old)] = m2GeneratedSuccessor{Old: old, NewUID: child.UID, Parent: parent}
	return s.persistLedger()
}

// m2IsIdentityArtifactSuccessor preserves the M1 identity ConfigMap contract.
// Unlike M2 workload children, this object is bound through its owner UID and
// exact three-key payload; it intentionally has no cluster-uid label.
func m2IsIdentityArtifactSuccessor(child *corev1.ConfigMap, parent m2FixtureIdentity) bool {
	if child == nil || parent.GVK != infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster") ||
		child.Name != parent.Key.Name || child.Namespace != parent.Key.Namespace {
		return false
	}
	owner := metav1.GetControllerOf(child)
	return owner != nil && owner.APIVersion == infrastructurev1alpha1.GroupVersion.String() &&
		owner.Kind == "KeaCluster" && owner.Name == parent.Key.Name && owner.UID == parent.UID &&
		maps.Equal(child.Data, map[string]string{
			"keacluster-name":      parent.Key.Name,
			"keacluster-namespace": parent.Key.Namespace,
			"keacluster-uid":       string(parent.UID),
		}) && child.Labels["keaguard.example/artifact"] == "reconciliation" &&
		child.Annotations["keaguard.example/purpose"] == "Internal reconciliation artifact; not operational Kea DHCP configuration."
}

// m2IsOperationalConfigSuccessor distinguishes the workload ConfigMap from the
// same-name M1 identity artifact. It binds the replacement to the exact parent
// incarnation and the previously recorded operational configuration content.
func m2IsOperationalConfigSuccessor(child, old *corev1.ConfigMap, parent *infrastructurev1alpha1.KeaCluster) bool {
	if child == nil || old == nil || parent == nil || parent.UID == "" || child.UID == "" || child.UID == old.UID {
		return false
	}
	configName, _, _ := m2NamesFor(parent)
	owner := metav1.GetControllerOf(child)
	return configName != "" && child.Name == configName && child.Namespace == parent.Namespace &&
		len(child.OwnerReferences) == 1 && owner != nil && owner.APIVersion == infrastructurev1alpha1.GroupVersion.String() &&
		owner.Kind == "KeaCluster" && owner.Name == parent.Name && owner.UID == parent.UID &&
		child.Labels["keaguard.example/cluster-uid"] == string(parent.UID) &&
		child.Labels["keaguard.example/component"] == "configuration" &&
		maps.Equal(child.Data, old.Data)
}

// ObserveNativePodSuccessor records the StatefulSet controller's replacement
// after an exact UID/RV-preconditioned Pod deletion. It grants no mutation
// authority over the new Pod; cleanup still removes only the case parent.
func (s *m2Scenario) ObserveNativePodSuccessor(ctx context.Context, old m2FixtureIdentity) error {
	if s == nil || !s.started || ctx.Err() != nil || old.GVK != corev1.SchemeGroupVersion.WithKind("Pod") || old.UID == "" || old.Key.Namespace != m2LabProfile.runtimeNamespace {
		return fmt.Errorf("native Pod successor lacks a recorded approved old identity")
	}
	fixture, recorded := s.ledger.fixtures[fixtureKey(old)]
	original, typed := fixture.Original.(*corev1.Pod)
	if !recorded || !typed || fixture.EndState != "absent" || original.UID != old.UID {
		return fmt.Errorf("native Pod successor lacks the exact old Pod fixture")
	}
	next := &corev1.Pod{}
	if err := m2GetSnapshot(ctx, old.Key, next); err != nil {
		return err
	}
	owner := metav1.GetControllerOf(next)
	if owner == nil || owner.APIVersion != appsv1.SchemeGroupVersion.String() || owner.Kind != "StatefulSet" {
		return fmt.Errorf("native Pod successor has no StatefulSet controller")
	}
	set := &appsv1.StatefulSet{}
	if err := m2GetSnapshot(ctx, client.ObjectKey{Namespace: next.Namespace, Name: owner.Name}, set); err != nil {
		return err
	}
	parentOwner := metav1.GetControllerOf(set)
	if parentOwner == nil || parentOwner.APIVersion != infrastructurev1alpha1.GroupVersion.String() || parentOwner.Kind != "KeaCluster" {
		return fmt.Errorf("native Pod successor has no KeaCluster parent")
	}
	parent := &infrastructurev1alpha1.KeaCluster{}
	if err := m2GetSnapshot(ctx, client.ObjectKey{Namespace: next.Namespace, Name: parentOwner.Name}, parent); err != nil {
		return err
	}
	parentIdentity, err := m2IdentityFor(parent)
	if err != nil {
		return err
	}
	parentFixture, parentRecorded := s.ledger.fixtures[fixtureKey(parentIdentity)]
	if !parentRecorded || !parentFixture.Created {
		return fmt.Errorf("native Pod successor's KeaCluster is not this scenario's confirmed fixture")
	}
	if err := m2CheckNativePodSuccessor(original, next, set, parent); err != nil {
		return err
	}
	setIdentity, err := m2IdentityFor(set)
	if err != nil {
		return err
	}
	if prior, exists := s.ledger.successors[fixtureKey(old)]; exists && (prior.NewUID != next.UID || prior.Parent != setIdentity || prior.ClusterUID != parent.UID) {
		return fmt.Errorf("native Pod successor incarnation changed after observation")
	}
	if err := s.ledger.MarkAbsentVerified(old); err != nil {
		return err
	}
	s.ledger.successors[fixtureKey(old)] = m2GeneratedSuccessor{Old: old, NewUID: next.UID, Parent: setIdentity, ClusterUID: parent.UID}
	return s.persistLedger()
}

func (s *m2Scenario) PlanStop(identity m2ProcessIdentity) error {
	if s == nil || !s.started || !identity.valid() || identity.State == "T" {
		return fmt.Errorf("STOP plan lacks a live checked process")
	}
	for _, recorded := range s.Stopped {
		if recorded.Identity.TaskID == identity.TaskID || recorded.Identity.PodKey == identity.PodKey && recorded.Identity.ContainerName == identity.ContainerName {
			return fmt.Errorf("STOP target already has a recorded or unresolved plan")
		}
	}
	s.Stopped = append(s.Stopped, m2StoppedProcess{Identity: identity, Phase: "planned"})
	return s.persistLedger()
}

func (s *m2Scenario) markStopPhase(identity m2ProcessIdentity, phase string) error {
	if phase != "acknowledged" && phase != "unresolved" {
		return fmt.Errorf("invalid STOP phase %q", phase)
	}
	for i := range s.Stopped {
		if reflect.DeepEqual(s.Stopped[i].Identity, identity) {
			if s.Stopped[i].Phase != "planned" {
				return fmt.Errorf("STOP phase already settled or unresolved")
			}
			s.Stopped[i].Phase = phase
			return s.persistLedger()
		}
	}
	return fmt.Errorf("STOP phase refers to an unrecorded process")
}

func (s *m2Scenario) StopProcess(ctx context.Context, identity m2ProcessIdentity) error {
	return s.stopProcessWith(ctx, identity,
		func(ctx context.Context, expected m2ProcessIdentity, signal string) error {
			return m2SignalProcess(ctx, expected, signal)
		},
		func(ctx context.Context) (m2ProcessIdentity, error) {
			return m2ObserveProcess(ctx, identity.PodKey, identity.ContainerName)
		})
}

func (s *m2Scenario) stopProcessWith(ctx context.Context, identity m2ProcessIdentity, signal func(context.Context, m2ProcessIdentity, string) error, observe func(context.Context) (m2ProcessIdentity, error)) error {
	if signal == nil || ctx.Err() != nil {
		return fmt.Errorf("STOP submission lacks live context or command")
	}
	if err := s.PlanStop(identity); err != nil {
		return err
	}
	if err := signal(ctx, identity, "STOP"); err != nil {
		return errors.Join(err, s.markStopPhase(identity, "unresolved"))
	}
	if observe == nil {
		err := fmt.Errorf("STOP result lacks independent process observation")
		return errors.Join(err, s.markStopPhase(identity, "unresolved"))
	}
	current, err := observe(ctx)
	old, now := identity, current
	old.State, now.State = "", ""
	if err != nil || !current.valid() || !reflect.DeepEqual(old, now) || current.State != "T" {
		if err == nil {
			err = fmt.Errorf("STOP result did not prove the same task is stopped")
		}
		return errors.Join(err, s.markStopPhase(identity, "unresolved"))
	}
	return s.markStopPhase(identity, "acknowledged")
}

func (s *m2Scenario) killProcessWith(ctx context.Context, identity m2ProcessIdentity, signal func(context.Context, m2ProcessIdentity, string) error) error {
	if s == nil || !s.started || ctx.Err() != nil || !identity.valid() || identity.State == "T" || signal == nil {
		return fmt.Errorf("KILL submission lacks a live checked scenario/process")
	}
	for _, recorded := range s.Killed {
		if recorded.Identity.TaskID == identity.TaskID || recorded.Identity.PodKey == identity.PodKey && recorded.Identity.ContainerName == identity.ContainerName {
			return fmt.Errorf("KILL target already has a recorded or unresolved intent")
		}
	}
	s.Killed = append(s.Killed, m2KilledProcess{Identity: identity, Signal: "KILL", Phase: "planned"})
	if err := s.persistLedger(); err != nil {
		return err
	}
	err := signal(ctx, identity, "KILL")
	phase := "acknowledged"
	if err != nil {
		phase = "unresolved"
	}
	s.Killed[len(s.Killed)-1].Phase = phase
	return errors.Join(err, s.persistLedger())
}

func (s *m2Scenario) KillProcess(ctx context.Context, identity m2ProcessIdentity) error {
	return s.killProcessWith(ctx, identity, m2SignalProcess)
}

func (s *m2Scenario) RecordFixture(obj client.Object, original client.Object, endState string) error {
	if s == nil || !s.started || (endState != "absent" && endState != "restored") {
		return fmt.Errorf("invalid M2 fixture record")
	}
	identity, err := m2IdentityFor(obj)
	if err != nil {
		return err
	}
	key := fixtureKey(identity)
	fixture, exists := s.ledger.fixtures[key]
	if original == nil {
		if !exists || !fixture.Created || endState != "absent" {
			return fmt.Errorf("case-created fixture lacks a confirmed create intent")
		}
	} else {
		originalIdentity, err := m2IdentityFor(original)
		if err != nil || originalIdentity != identity || exists && fixture.Created {
			return fmt.Errorf("original fixture identity does not match the confirmed incarnation")
		}
		if !exists {
			fixture = m2Fixture{m2FixtureIdentity: identity, Original: original.DeepCopyObject().(client.Object), EndState: endState}
		}
	}
	s.ledger.fixtures[key] = fixture
	return s.persistLedger()
}

func newM2FixtureLedger() *m2FixtureLedger {
	return &m2FixtureLedger{intents: map[string]m2CreateIntent{}, fixtures: map[string]m2Fixture{}, successors: map[string]m2GeneratedSuccessor{}}
}

func (l *m2FixtureLedger) sortedSuccessors() []m2GeneratedSuccessor {
	keys := make([]string, 0, len(l.successors))
	for key := range l.successors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]m2GeneratedSuccessor, 0, len(keys))
	for _, key := range keys {
		items = append(items, l.successors[key])
	}
	return items
}
func fixtureKey(id m2FixtureIdentity) string {
	return id.GVK.String() + "\x00" + id.Key.Namespace + "/" + id.Key.Name + "\x00" + string(id.UID)
}
func (l *m2FixtureLedger) RecordCreateIntent(intent m2CreateIntent) error {
	if intent.ID == "" || intent.Key.Namespace == "" || intent.GVK.Empty() || intent.Phase != "planned" ||
		(intent.Key.Name == "" && intent.GenerateName == "") || (intent.Key.Name != "" && intent.GenerateName != "") {
		return fmt.Errorf("invalid create intent")
	}
	if _, ok := l.intents[intent.ID]; ok {
		return fmt.Errorf("duplicate create intent")
	}
	predecessorFound := false
	for _, fixture := range l.fixtures {
		if fixture.GVK != intent.GVK || fixture.Key != intent.Key {
			continue
		}
		if !fixture.AbsentVerified {
			return fmt.Errorf("old fixture incarnation is not verified absent")
		}
		if intent.Replaces != nil && fixture.m2FixtureIdentity == *intent.Replaces {
			predecessorFound = true
		}
		if intent.Replaces == nil {
			return fmt.Errorf("same-key replacement lacks predecessor intent")
		}
	}
	if intent.Replaces != nil && !predecessorFound {
		return fmt.Errorf("replacement predecessor is not a verified recorded incarnation")
	}
	l.intents[intent.ID] = intent
	return nil
}
func (l *m2FixtureLedger) advanceCreateIntent(intentID, from, to string) error {
	intent, ok := l.intents[intentID]
	if !ok || intent.Phase != from {
		return fmt.Errorf("create intent %s is not in %s phase", intentID, from)
	}
	intent.Phase = to
	l.intents[intentID] = intent
	return nil
}
func (l *m2FixtureLedger) ConfirmCreated(intentID string, identity m2FixtureIdentity) error {
	intent, ok := l.intents[intentID]
	if !ok || (intent.Phase != "planned" && intent.Phase != "submitted") {
		return fmt.Errorf("create intent is not confirmable")
	}
	if identity.UID == "" || identity.GVK != intent.GVK || identity.Key.Namespace != intent.Key.Namespace ||
		(intent.Key.Name != "" && identity.Key != intent.Key) ||
		(intent.GenerateName != "" && !strings.HasPrefix(identity.Key.Name, intent.GenerateName)) || identity.Key.Name == "" {
		return fmt.Errorf("created identity does not match intent")
	}
	for _, fixture := range l.fixtures {
		if fixture.GVK == identity.GVK && fixture.Key == identity.Key &&
			(intent.Replaces == nil || !fixture.AbsentVerified) {
			return fmt.Errorf("returned name collides with an unapproved fixture incarnation")
		}
	}
	key := fixtureKey(identity)
	if _, ok := l.fixtures[key]; ok {
		return fmt.Errorf("fixture incarnation already recorded")
	}
	intent.Phase = "confirmed"
	l.intents[intentID] = intent
	l.fixtures[key] = m2Fixture{m2FixtureIdentity: identity, Created: true, EndState: "absent"}
	return nil
}

// MarkAbsentVerified is bookkeeping for a direct API observation made by the
// caller; the ledger never infers absence from a desired end state or label.
func (l *m2FixtureLedger) MarkAbsentVerified(identity m2FixtureIdentity) error {
	key := fixtureKey(identity)
	fixture, ok := l.fixtures[key]
	if !ok || identity.UID == "" {
		return fmt.Errorf("unknown fixture incarnation cannot be marked absent")
	}
	fixture.AbsentVerified = true
	l.fixtures[key] = fixture
	return nil
}

func m2NewFixtureObject(gvk schema.GroupVersionKind) (client.Object, error) {
	switch gvk {
	case corev1.SchemeGroupVersion.WithKind("ConfigMap"):
		return &corev1.ConfigMap{}, nil
	case corev1.SchemeGroupVersion.WithKind("Pod"):
		return &corev1.Pod{}, nil
	case corev1.SchemeGroupVersion.WithKind("Service"):
		return &corev1.Service{}, nil
	case corev1.SchemeGroupVersion.WithKind("ServiceAccount"):
		return &corev1.ServiceAccount{}, nil
	case appsv1.SchemeGroupVersion.WithKind("Deployment"):
		return &appsv1.Deployment{}, nil
	case appsv1.SchemeGroupVersion.WithKind("StatefulSet"):
		return &appsv1.StatefulSet{}, nil
	case rbacv1.SchemeGroupVersion.WithKind("Role"):
		return &rbacv1.Role{}, nil
	case rbacv1.SchemeGroupVersion.WithKind("RoleBinding"):
		return &rbacv1.RoleBinding{}, nil
	case infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"):
		return &infrastructurev1alpha1.KeaCluster{}, nil
	default:
		return nil, fmt.Errorf("unsupported cleanup kind %s", gvk)
	}
}

func (s *m2Scenario) restoreFixtures(ctx context.Context) error {
	if s == nil || !s.started || s.ledger == nil {
		return fmt.Errorf("fixture recovery has no started scenario")
	}
	keys := make([]string, 0, len(s.ledger.fixtures))
	for key := range s.ledger.fixtures {
		keys = append(keys, key)
	}
	// Parent CRs must stop reconciling before their dependents are removed.
	sort.Slice(keys, func(i, j int) bool {
		left, right := s.ledger.fixtures[keys[i]], s.ledger.fixtures[keys[j]]
		leftParent := left.GVK == infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster")
		rightParent := right.GVK == infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster")
		if leftParent != rightParent {
			return leftParent
		}
		return keys[i] < keys[j]
	})
	var failures []error
	for _, key := range keys {
		fixture := s.ledger.fixtures[key]
		restoreErr := s.restoreFixture(ctx, fixture)
		if restoreErr != nil {
			failures = append(failures, fmt.Errorf("fixture %s/%s UID %s: %w", fixture.Key.Namespace, fixture.Key.Name, fixture.UID, restoreErr))
		}
		if fixture.Created && fixture.GVK == infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster") {
			// Parent deletion stops reconciliation, but StatefulSet-owned Pods can
			// remain or be recreated until Kubernetes finishes owner garbage
			// collection. Prove the complete workload absent before processing any
			// separately recorded Pod incarnation, preventing a cleanup race with a
			// native same-name replacement.
			if err := m2WaitCaseWorkloadAbsentWork(ctx, fixture); err != nil {
				failures = append(failures, fmt.Errorf("case workload %s/%s UID %s: %w", fixture.Key.Namespace, fixture.Key.Name, fixture.UID, err))
			}
		}
	}
	return errors.Join(failures...)
}

func (s *m2Scenario) verifyTerminalCreateIntents() error {
	if s == nil || s.ledger == nil {
		return fmt.Errorf("M2 create-intent ledger is missing")
	}
	var failures []error
	for _, intent := range s.ledger.intents {
		switch intent.Phase {
		case "confirmed":
			found := false
			for _, fixture := range s.ledger.fixtures {
				if fixture.GVK == intent.GVK && fixture.Key == intent.Key && fixture.Created && fixture.UID != "" {
					found = true
					break
				}
			}
			if !found {
				failures = append(failures, fmt.Errorf("confirmed create intent %s lacks its recorded UID incarnation", intent.ID))
			}
		case "not-submitted":
			if intent.OutcomeError == "" || m2LedgerHasFixtureAtKey(s.ledger, intent) {
				failures = append(failures, fmt.Errorf("not-submitted create intent %s lacks its preflight proof", intent.ID))
			}
		case "rejected":
			if intent.OutcomeError == "" || !m2DefinitiveCreateResponseCode(intent.ResponseCode) || m2LedgerHasFixtureAtKey(s.ledger, intent) {
				failures = append(failures, fmt.Errorf("rejected create intent %s lacks a definitive non-mutating API response", intent.ID))
			}
		default:
			failures = append(failures, fmt.Errorf("create intent %s for %s/%s remains %s", intent.ID, intent.Key.Namespace, intent.Key.Name, intent.Phase))
		}
	}
	return errors.Join(failures...)
}

func m2LedgerHasFixtureAtKey(ledger *m2FixtureLedger, intent m2CreateIntent) bool {
	for _, fixture := range ledger.fixtures {
		if fixture.GVK == intent.GVK && fixture.Key == intent.Key {
			return true
		}
	}
	return false
}

func m2NamesFor(parent *infrastructurev1alpha1.KeaCluster) (configName, serviceName, statefulSetName string) {
	if parent == nil || parent.Namespace == "" || parent.Name == "" {
		return "", "", ""
	}
	sum := sha256.Sum256([]byte(parent.Namespace + "\x00" + parent.Name))
	hash := hex.EncodeToString(sum[:])[:32]
	return "kg-" + hash + "-config", "kg-" + hash + "-headless", "kg-" + hash
}

func m2WaitCaseWorkloadAbsent(ctx context.Context, fixture m2Fixture) error {
	if !fixture.Created || fixture.GVK != infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster") || fixture.UID == "" {
		return fmt.Errorf("workload absence proof lacks a confirmed case parent")
	}
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: fixture.Key.Namespace, Name: fixture.Key.Name, UID: fixture.UID}}
	configName, serviceName, setName := m2NamesFor(parent)
	if configName == "" {
		return fmt.Errorf("workload absence names cannot be derived")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := m2CaseWorkloadAbsent(requestCtx, fixture, configName, serviceName, setName)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func m2CaseWorkloadAbsent(ctx context.Context, fixture m2Fixture, configName, serviceName, setName string) error {
	for _, target := range []client.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: fixture.Key.Namespace, Name: configName}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: fixture.Key.Namespace, Name: serviceName}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: fixture.Key.Namespace, Name: setName}},
	} {
		if err := admin.Get(ctx, client.ObjectKeyFromObject(target), target); err == nil {
			return fmt.Errorf("linked or colliding child %T %s still exists with UID %s", target, target.GetName(), target.GetUID())
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	}
	pods := &corev1.PodList{}
	if err := admin.List(ctx, pods, client.InNamespace(fixture.Key.Namespace)); err != nil {
		return err
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Labels["keaguard.example/cluster-uid"] == string(fixture.UID) || strings.HasPrefix(pod.Name, setName+"-") {
			return fmt.Errorf("linked/candidate/terminating case Pod %s UID %s remains", pod.Name, pod.UID)
		}
	}
	return nil
}

func (s *m2Scenario) restoreFixture(ctx context.Context, fixture m2Fixture) error {
	if fixture.UID == "" {
		return fmt.Errorf("unconfirmed fixture UID")
	}
	if fixture.EndState == "restored" {
		if parentUID, eligible := m2IdentityArtifactOwnerGCParent(fixture, s.ledger); eligible {
			current := &corev1.ConfigMap{}
			requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := admin.Get(requestCtx, fixture.Key, current)
			cancel()
			if !apierrors.IsNotFound(err) {
				if err != nil {
					return err
				}
				if current.UID != fixture.UID {
					return fmt.Errorf("owner-GC identity artifact was replaced by UID %s", current.UID)
				}
				return fmt.Errorf("identity artifact remains after its recorded owner UID %s was deleted", parentUID)
			}
			fixture.EndState = "absent"
			fixture.AbsentVerified = true
			s.ledger.fixtures[fixtureKey(fixture.m2FixtureIdentity)] = fixture
			return s.persistLedger()
		}
		return m2RestoreExistingFixture(ctx, fixture)
	}
	if fixture.EndState != "absent" {
		return fmt.Errorf("invalid fixture end state %q", fixture.EndState)
	}
	if !fixture.Created && fixture.Original == nil {
		return fmt.Errorf("absent fixture has no creation or original snapshot")
	}
	deleteConflicts := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := m2NewFixtureObject(fixture.GVK)
		if err != nil {
			return err
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = admin.Get(requestCtx, fixture.Key, current)
		cancel()
		if apierrors.IsNotFound(err) {
			if err := s.ledger.MarkAbsentVerified(fixture.m2FixtureIdentity); err != nil {
				return err
			}
			return s.persistLedger()
		}
		if err != nil {
			return err
		}
		if current.GetUID() != fixture.UID {
			if !fixture.AbsentVerified || !s.ledger.isConfirmedSuccessor(fixture.m2FixtureIdentity, current) {
				return fmt.Errorf("unexpected replacement UID %s; recorded old UID is not sufficient mutation authority", current.GetUID())
			}
			return nil
		}
		if current.GetResourceVersion() == "" {
			return fmt.Errorf("live fixture has no resourceVersion")
		}
		released, err := m2ReleaseCaseMetadata(ctx, current, fixture)
		if err != nil {
			return err
		}
		if released {
			continue
		}
		if fixture.GVK == infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster") {
			parent := current.(*infrastructurev1alpha1.KeaCluster)
			if parent.Spec != nil && parent.Spec.Workload != nil && parent.Spec.Workload.Enabled {
				base := parent.DeepCopy()
				parent.Spec.Workload.Enabled = false
				requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
				err = admin.Patch(requestCtx, parent, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
				cancel()
				if err != nil {
					return err
				}
				continue
			}
		}
		uid, rv := current.GetUID(), current.GetResourceVersion()
		requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
		err = admin.Delete(requestCtx, current, client.Preconditions{UID: &uid, ResourceVersion: &rv})
		cancel()
		if err != nil && !apierrors.IsNotFound(err) {
			if apierrors.IsConflict(err) {
				deleteConflicts++
				if deleteConflicts < 5 {
					// A Pod status update can invalidate the RV between GET and DELETE.
					// The next loop iteration performs a fresh GET, rechecks the exact
					// UID and owner/finalizer ledger, then retries with fresh UID+RV
					// preconditions. Never retry a replacement incarnation.
					continue
				}
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (l *m2FixtureLedger) isConfirmedSuccessor(old m2FixtureIdentity, current client.Object) bool {
	newUID := current.GetUID()
	if l == nil || old.UID == "" || newUID == "" || newUID == old.UID {
		return false
	}
	if successor, ok := l.successors[fixtureKey(old)]; ok && successor.NewUID == newUID {
		if old.GVK == corev1.SchemeGroupVersion.WithKind("ConfigMap") && successor.Parent.GVK == infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster") {
			child, ok := current.(*corev1.ConfigMap)
			if !ok {
				return false
			}
			if old.Key.Name == successor.Parent.Key.Name {
				return m2IsIdentityArtifactSuccessor(child, successor.Parent)
			}
			parentFixture, parentRecorded := l.fixtures[fixtureKey(successor.Parent)]
			oldFixture, oldRecorded := l.fixtures[fixtureKey(old)]
			oldConfig, oldTyped := oldFixture.Original.(*corev1.ConfigMap)
			parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Namespace: successor.Parent.Key.Namespace, Name: successor.Parent.Key.Name, UID: successor.Parent.UID}}
			return parentRecorded && parentFixture.Created && parentFixture.UID == successor.Parent.UID &&
				oldRecorded && oldTyped && m2IsOperationalConfigSuccessor(child, oldConfig, parent)
		}
		owner := metav1.GetControllerOf(current)
		if old.GVK == corev1.SchemeGroupVersion.WithKind("Pod") && successor.Parent.GVK == appsv1.SchemeGroupVersion.WithKind("StatefulSet") && successor.ClusterUID != "" {
			return owner != nil && owner.APIVersion == appsv1.SchemeGroupVersion.String() && owner.Kind == "StatefulSet" &&
				owner.Name == successor.Parent.Key.Name && owner.UID == successor.Parent.UID &&
				current.GetLabels()["keaguard.example/cluster-uid"] == string(successor.ClusterUID)
		}
		return owner != nil && owner.APIVersion == infrastructurev1alpha1.GroupVersion.String() && owner.Kind == "KeaCluster" &&
			owner.Name == successor.Parent.Key.Name && owner.UID == successor.Parent.UID &&
			current.GetLabels()["keaguard.example/cluster-uid"] == string(successor.Parent.UID)
	}
	for _, intent := range l.intents {
		if intent.Phase != "confirmed" || intent.Replaces == nil || *intent.Replaces != old || intent.Key != old.Key || intent.GVK != old.GVK {
			continue
		}
		if fixture, ok := l.fixtures[fixtureKey(m2FixtureIdentity{Key: old.Key, GVK: old.GVK, UID: newUID})]; ok && fixture.Created {
			return true
		}
	}
	return false
}

func m2ReleaseCaseMetadata(ctx context.Context, current client.Object, fixture m2Fixture) (bool, error) {
	if current.GetUID() != fixture.UID || current.GetResourceVersion() == "" {
		return false, fmt.Errorf("case metadata release target UID/resourceVersion changed")
	}
	for _, finalizer := range current.GetFinalizers() {
		if !slices.Contains(fixture.AddedFinalizers, finalizer) {
			return false, fmt.Errorf("foreign finalizer %q blocks checked fixture cleanup", finalizer)
		}
	}
	baselineOwners := fixture.InitialOwners
	if fixture.Original != nil {
		baselineOwners = fixture.Original.GetOwnerReferences()
	}
	for _, owner := range current.GetOwnerReferences() {
		if !slices.ContainsFunc(baselineOwners, func(ref metav1.OwnerReference) bool { return reflect.DeepEqual(ref, owner) }) &&
			!slices.ContainsFunc(fixture.AddedOwners, func(ref metav1.OwnerReference) bool { return reflect.DeepEqual(ref, owner) }) {
			return false, fmt.Errorf("foreign owner reference blocks checked fixture cleanup")
		}
	}
	for _, owner := range fixture.AddedOwners {
		if !slices.ContainsFunc(current.GetOwnerReferences(), func(ref metav1.OwnerReference) bool { return reflect.DeepEqual(ref, owner) }) {
			return false, fmt.Errorf("case-added owner reference changed before release")
		}
	}
	if len(current.GetFinalizers()) == 0 && len(fixture.AddedOwners) == 0 {
		return false, nil
	}
	base := current.DeepCopyObject().(client.Object)
	current.SetFinalizers(nil)
	if len(fixture.AddedOwners) != 0 {
		kept := make([]metav1.OwnerReference, 0, len(current.GetOwnerReferences()))
		for _, owner := range current.GetOwnerReferences() {
			if !slices.ContainsFunc(fixture.AddedOwners, func(ref metav1.OwnerReference) bool { return reflect.DeepEqual(ref, owner) }) {
				kept = append(kept, owner)
			}
		}
		current.SetOwnerReferences(kept)
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return true, admin.Patch(requestCtx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

// m2IdentityArtifactOwnerGCParent recognizes only the controller's preserved
// M1 identity ConfigMap shape whose exact case-created parent was deleted and
// independently observed absent. Labels alone never grant cleanup authority.
func m2IdentityArtifactOwnerGCParent(fixture m2Fixture, ledger *m2FixtureLedger) (types.UID, bool) {
	if ledger == nil || fixture.Created || fixture.EndState != "restored" || fixture.GVK != corev1.SchemeGroupVersion.WithKind("ConfigMap") || fixture.Original == nil {
		return "", false
	}
	original, ok := fixture.Original.(*corev1.ConfigMap)
	if !ok || original.UID != fixture.UID || original.Namespace != fixture.Key.Namespace || original.Name != fixture.Key.Name || original.Name == "" {
		return "", false
	}
	if original.Labels["keaguard.example/artifact"] != "reconciliation" || original.Annotations["keaguard.example/purpose"] != "Internal reconciliation artifact; not operational Kea DHCP configuration." ||
		len(original.Data) != 3 || original.BinaryData != nil && len(original.BinaryData) != 0 ||
		original.Data["keacluster-name"] != original.Name || original.Data["keacluster-namespace"] != original.Namespace {
		return "", false
	}
	uid := types.UID(original.Data["keacluster-uid"])
	if uid == "" {
		return "", false
	}
	ownerCount := 0
	for _, owner := range original.OwnerReferences {
		if owner.Controller == nil || !*owner.Controller {
			continue
		}
		ownerCount++
		if owner.APIVersion != infrastructurev1alpha1.GroupVersion.String() || owner.Kind != "KeaCluster" || owner.Name != original.Name || owner.UID != uid {
			return "", false
		}
	}
	if ownerCount != 1 {
		return "", false
	}
	parentIdentity := m2FixtureIdentity{Key: client.ObjectKey{Namespace: fixture.Key.Namespace, Name: original.Name}, GVK: infrastructurev1alpha1.GroupVersion.WithKind("KeaCluster"), UID: uid}
	parent, exists := ledger.fixtures[fixtureKey(parentIdentity)]
	if !exists || !parent.Created || parent.EndState != "absent" || !parent.AbsentVerified {
		return "", false
	}
	return uid, true
}

func m2RestoreExistingFixture(ctx context.Context, fixture m2Fixture) error {
	if fixture.Original == nil || fixture.Created || fixture.UID == "" {
		return fmt.Errorf("restored fixture lacks its original incarnation")
	}
	if fixture.GVK != corev1.SchemeGroupVersion.WithKind("ConfigMap") {
		return fmt.Errorf("restoration of %s is not explicitly supported", fixture.GVK)
	}
	original, ok := fixture.Original.(*corev1.ConfigMap)
	if !ok || original.UID != fixture.UID {
		return fmt.Errorf("ConfigMap snapshot type or UID mismatch")
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := &corev1.ConfigMap{}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := admin.Get(requestCtx, fixture.Key, current)
		cancel()
		if err != nil {
			return err
		}
		if current.UID != fixture.UID || current.DeletionTimestamp != nil {
			return fmt.Errorf("pre-existing ConfigMap incarnation changed or is deleting")
		}
		allowed := func(field string, got any, originalValue any, value func(*corev1.ConfigMap) any) error {
			if reflect.DeepEqual(got, originalValue) {
				return nil
			}
			for _, submission := range fixture.Submitted {
				candidate, ok := submission.(*corev1.ConfigMap)
				if ok && candidate.UID == fixture.UID && reflect.DeepEqual(got, value(candidate)) {
					return nil
				}
			}
			return fmt.Errorf("unrecorded ConfigMap %s drift blocks safe restoration", field)
		}
		for _, check := range []struct {
			name          string
			got, original any
			from          func(*corev1.ConfigMap) any
		}{
			{"data", current.Data, original.Data, func(cm *corev1.ConfigMap) any { return cm.Data }},
			{"binaryData", current.BinaryData, original.BinaryData, func(cm *corev1.ConfigMap) any { return cm.BinaryData }},
			{"labels", current.Labels, original.Labels, func(cm *corev1.ConfigMap) any { return cm.Labels }},
			{"annotations", current.Annotations, original.Annotations, func(cm *corev1.ConfigMap) any { return cm.Annotations }},
			{"finalizers", current.Finalizers, original.Finalizers, func(cm *corev1.ConfigMap) any { return cm.Finalizers }},
			{"owners", current.OwnerReferences, original.OwnerReferences, func(cm *corev1.ConfigMap) any { return cm.OwnerReferences }},
		} {
			if err := allowed(check.name, check.got, check.original, check.from); err != nil {
				return err
			}
		}
		if reflect.DeepEqual(current.Data, original.Data) && reflect.DeepEqual(current.BinaryData, original.BinaryData) &&
			reflect.DeepEqual(current.Labels, original.Labels) && reflect.DeepEqual(current.Annotations, original.Annotations) &&
			reflect.DeepEqual(current.Finalizers, original.Finalizers) && reflect.DeepEqual(current.OwnerReferences, original.OwnerReferences) {
			return nil
		}
		base := current.DeepCopy()
		current.Data = maps.Clone(original.Data)
		current.BinaryData = make(map[string][]byte, len(original.BinaryData))
		for key, value := range original.BinaryData {
			current.BinaryData[key] = bytes.Clone(value)
		}
		current.Labels = maps.Clone(original.Labels)
		current.Annotations = maps.Clone(original.Annotations)
		current.Finalizers = slices.Clone(original.Finalizers)
		current.OwnerReferences = slices.Clone(original.OwnerReferences)
		requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
		err = admin.Patch(requestCtx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
		cancel()
		return err
	})
}

// RestoreAndVerify is the only mutating M2 teardown stage. Every independently
// safe branch is attempted, and no diagnostic command is invoked here.
func (s *m2Scenario) RestoreAndVerify(ctx context.Context) error {
	if s == nil || !s.started || s.ExpectedImage == "" || s.ExpectedImageID == "" {
		return fmt.Errorf("M2 restoration has no verified scenario/image identity")
	}
	err := s.restoreAndVerify(ctx, m2VerifyManagerDeployment, m2ResumeStoppedProcess)
	receiptErr := m2TimedRecoveryStage(s.caseID, "namespace-lab-receipt", func() error { return m2VerifyNamespaceReceipt(ctx) })
	return errors.Join(err, receiptErr)
}

func (s *m2Scenario) restoreAndVerify(ctx context.Context, verifyManager func(context.Context, string, string) error, resume func(context.Context, m2StoppedProcess) error) error {
	if s == nil || !s.started || verifyManager == nil || resume == nil {
		return fmt.Errorf("M2 restoration has no started scenario or recovery operations")
	}
	var failures []error
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		original := s.NamespaceSnapshots[name]
		if err := m2TimedRecoveryStage(s.caseID, "namespace-policy:"+name, func() error { return m2RestoreNamespacePolicy(ctx, original, s.KnownFaultPolicies[name]) }); err != nil {
			failures = append(failures, fmt.Errorf("namespace %s policy: %w", name, err))
		}
	}
	if err := m2TimedRecoveryStage(s.caseID, "manager-role", func() error { return m2RestoreRole(ctx, s.Role) }); err != nil {
		failures = append(failures, fmt.Errorf("manager Role: %w", err))
	}
	if err := m2TimedRecoveryStage(s.caseID, "manager-rolebinding", func() error { return m2RestoreRoleBinding(ctx, s.RoleBinding) }); err != nil {
		failures = append(failures, fmt.Errorf("manager RoleBinding: %w", err))
	}
	if err := m2TimedRecoveryStage(s.caseID, "manager-serviceaccount", func() error { return m2VerifyServiceAccount(ctx, s.ServiceAccount) }); err != nil {
		failures = append(failures, fmt.Errorf("manager ServiceAccount: %w", err))
	}
	for _, stopped := range s.Stopped {
		if err := m2TimedRecoveryStage(s.caseID, "resume-task:"+stopped.Identity.TaskID, func() error { return resume(ctx, stopped) }); err != nil {
			failures = append(failures, fmt.Errorf("stopped task %s: %w", stopped.Identity.TaskID, err))
		}
	}
	for _, killed := range s.Killed {
		if err := m2TimedRecoveryStage(s.caseID, "prove-killed-task-replaced:"+killed.Identity.TaskID, func() error { return m2VerifyKilledProcess(ctx, killed) }); err != nil {
			failures = append(failures, fmt.Errorf("killed task %s: %w", killed.Identity.TaskID, err))
		}
	}
	if err := m2TimedRecoveryStage(s.caseID, "manager-deployment-restore", func() error { return m2RestoreManager(ctx, s.Manager) }); err != nil {
		failures = append(failures, fmt.Errorf("manager Deployment: %w", err))
	} else if err := m2WaitManagerHealthyForCase(ctx, s.caseID, s.ExpectedImage, s.ExpectedImageID, verifyManager); err != nil {
		failures = append(failures, fmt.Errorf("manager runtime: %w", err))
	}
	if err := m2TimedRecoveryStage(s.caseID, "fixture-restoration", func() error { return s.restoreFixtures(ctx) }); err != nil {
		failures = append(failures, err)
	}
	if err := m2TimedRecoveryStage(s.caseID, "create-intent-terminal-proof", s.verifyTerminalCreateIntents); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func m2VerifyServiceAccount(ctx context.Context, original *corev1.ServiceAccount) error {
	if original == nil || original.UID == "" || original.Namespace != m2LabProfile.runtimeNamespace || original.Name != managerName {
		return fmt.Errorf("manager ServiceAccount baseline is incomplete")
	}
	current := &corev1.ServiceAccount{}
	if err := m2GetSnapshot(ctx, client.ObjectKeyFromObject(original), current); err != nil {
		return err
	}
	if current.UID != original.UID || !reflect.DeepEqual(current.AutomountServiceAccountToken, original.AutomountServiceAccountToken) ||
		!reflect.DeepEqual(current.ImagePullSecrets, original.ImagePullSecrets) || !reflect.DeepEqual(current.Secrets, original.Secrets) {
		return fmt.Errorf("manager ServiceAccount identity/spec changed; no repair is authorized")
	}
	return nil
}

func m2WaitManagerHealthy(ctx context.Context, image, imageID string, verify func(context.Context, string, string) error) error {
	return m2WaitManagerHealthyForCase(ctx, "", image, imageID, verify)
}

func m2WaitManagerHealthyForCase(ctx context.Context, caseID, image, imageID string, verify func(context.Context, string, string) error) error {
	if verify == nil {
		return fmt.Errorf("manager verification callback is nil")
	}
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, last)
		}
		attemptStart := time.Now()
		// One full identity attestation composes many individually bounded API
		// and subprocess operations; its total duration is bounded by the
		// critical-recovery caller, not by an erroneous per-attempt 10s cap.
		last = verify(ctx, image, imageID)
		result := "ok"
		if last != nil {
			result = "failed"
		}
		m2RecoveryTimingReporter(m2RecoveryTimingEvent{CaseID: caseID, Stage: "manager-health-attestation", StartedUTC: attemptStart.UTC().Format(time.RFC3339Nano), DurationMS: time.Since(attemptStart).Milliseconds(), Result: result})
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), last)
		case <-time.After(time.Second):
		}
	}
}

func m2ResumeStoppedProcess(ctx context.Context, stopped m2StoppedProcess) error {
	return m2ResumeStoppedWith(ctx, stopped,
		func(ctx context.Context) (m2ProcessIdentity, error) {
			return m2ObserveProcess(ctx, stopped.Identity.PodKey, stopped.Identity.ContainerName)
		},
		func(ctx context.Context, identity m2ProcessIdentity, signal string) error {
			return m2SignalProcess(ctx, identity, signal)
		},
		m2ProveTaskReplacement)
}

func m2VerifyKillActionWith(ctx context.Context, killed m2KilledProcess, observe func(context.Context) (m2ProcessIdentity, error), prove func(context.Context, m2StoppedProcess, m2ProcessIdentity) error) error {
	if ctx.Err() != nil || !killed.Identity.valid() || killed.Signal != "KILL" || (killed.Phase != "acknowledged" && killed.Phase != "unresolved") || observe == nil || prove == nil {
		return fmt.Errorf("KILL terminal proof lacks a valid intent or context")
	}
	current, err := observe(ctx)
	if err != nil {
		return err
	}
	if !current.valid() || current.State == "T" || current.TaskID == killed.Identity.TaskID || current.PodKey != killed.Identity.PodKey ||
		current.PodUID != killed.Identity.PodUID || current.NodeUID != killed.Identity.NodeUID || current.NodeContainerID != killed.Identity.NodeContainerID ||
		current.ImageID != killed.Identity.ImageID || current.StatefulSetUID != killed.Identity.StatefulSetUID || current.KeaClusterUID != killed.Identity.KeaClusterUID {
		return fmt.Errorf("KILL did not produce a healthy same-Pod replacement task")
	}
	return prove(ctx, m2StoppedProcess{Identity: killed.Identity, Phase: killed.Phase}, current)
}

func m2VerifyKilledProcess(ctx context.Context, killed m2KilledProcess) error {
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var last error
	for bounded.Err() == nil {
		last = m2VerifyKillActionWith(bounded, killed, func(ctx context.Context) (m2ProcessIdentity, error) {
			return m2ObserveProcess(ctx, killed.Identity.PodKey, killed.Identity.ContainerName)
		}, m2ProveTaskReplacement)
		if last == nil {
			return nil
		}
		select {
		case <-bounded.Done():
		case <-time.After(time.Second):
		}
	}
	return errors.Join(bounded.Err(), last)
}

func m2ResumeStoppedWith(ctx context.Context, stopped m2StoppedProcess,
	observe func(context.Context) (m2ProcessIdentity, error),
	signal func(context.Context, m2ProcessIdentity, string) error,
	proveReplacement func(context.Context, m2StoppedProcess, m2ProcessIdentity) error) error {
	if ctx.Err() != nil || !stopped.Identity.valid() ||
		(stopped.Phase != "planned" && stopped.Phase != "acknowledged" && stopped.Phase != "unresolved") ||
		observe == nil || signal == nil || proveReplacement == nil {
		return fmt.Errorf("stopped-task recovery lacks exact identity, phase or live context")
	}
	current, err := observe(ctx)
	if err != nil {
		return err
	}
	if !current.valid() {
		return fmt.Errorf("stopped-task reobservation is incomplete")
	}
	old, now := stopped.Identity, current
	old.State, now.State = "", ""
	if !reflect.DeepEqual(old, now) {
		return proveReplacement(ctx, stopped, current)
	}
	if current.State != "T" {
		return nil
	}
	signalErr := signal(ctx, stopped.Identity, "CONT")
	// Even a successful command must be verified. A lost acknowledgement is not
	// retried; the same task's live state may independently prove restoration.
	current, err = observe(ctx)
	if err != nil {
		return errors.Join(signalErr, err)
	}
	old, now = stopped.Identity, current
	old.State, now.State = "", ""
	if current.valid() && !reflect.DeepEqual(old, now) {
		if err := proveReplacement(ctx, stopped, current); err != nil {
			return errors.Join(signalErr, err)
		}
		return nil
	}
	if !current.valid() || current.State == "T" {
		return errors.Join(signalErr, fmt.Errorf("old task was not proved resumed on the same process incarnation"))
	}
	return nil
}

func m2ProveTaskReplacement(ctx context.Context, stopped m2StoppedProcess, replacement m2ProcessIdentity) error {
	return m2ProveTaskReplacementWith(ctx, stopped, replacement, admin, m2Command)
}

func m2ProveTaskReplacementWith(ctx context.Context, stopped m2StoppedProcess, replacement m2ProcessIdentity, c client.Client, run func(context.Context, string, ...string) ([]byte, error)) error {
	old := stopped.Identity
	if ctx.Err() != nil || c == nil || run == nil || !old.valid() || !replacement.valid() || replacement.State == "T" || replacement.TaskID == old.TaskID ||
		replacement.StatefulSetKey != old.StatefulSetKey || replacement.StatefulSetUID != old.StatefulSetUID ||
		replacement.KeaClusterKey != old.KeaClusterKey || replacement.KeaClusterUID != old.KeaClusterUID {
		return fmt.Errorf("replacement process is not a live child of the same approved owner chain")
	}
	pod := &corev1.Pod{}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := c.Get(requestCtx, replacement.PodKey, pod)
	cancel()
	if err != nil || pod.UID != replacement.PodUID || pod.Status.Phase != corev1.PodRunning || !podReady(pod) {
		return fmt.Errorf("replacement Pod incarnation is not independently ready: %v", err)
	}
	out, err := run(ctx, "docker", "exec", old.NodeContainerID, "ctr", "--namespace", "k8s.io", "tasks", "list")
	if err != nil {
		return err
	}
	return m2TaskAbsent(out, old.TaskID)
}

func m2TaskAbsent(data []byte, exactID string) error {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || !slices.Equal(strings.Fields(lines[0]), []string{"TASK", "PID", "STATUS"}) || !m2FullHexID(exactID) {
		return fmt.Errorf("containerd task absence table is unsupported")
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != 3 || !m2FullHexID(fields[0]) {
			return fmt.Errorf("containerd task absence table has ambiguous row")
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil || pid <= 1 || (fields[2] != "RUNNING" && fields[2] != "STOPPED") {
			return fmt.Errorf("containerd task absence table has unsupported PID/state")
		}
		if fields[0] == exactID {
			return fmt.Errorf("old containerd task %s still exists", exactID)
		}
	}
	return nil
}

func m2RestoreManager(ctx context.Context, original *appsv1.Deployment) error {
	if original == nil || original.UID == "" || original.Namespace != m2LabProfile.runtimeNamespace || original.Name != managerName {
		return fmt.Errorf("invalid manager restoration snapshot")
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := &appsv1.Deployment{}
		if err := m2GetSnapshot(ctx, client.ObjectKeyFromObject(original), current); err != nil {
			return err
		}
		if current.UID != original.UID {
			return fmt.Errorf("manager Deployment UID changed from %s to %s", original.UID, current.UID)
		}
		if reflect.DeepEqual(current.Spec, original.Spec) {
			return nil
		}
		base := current.DeepCopy()
		current.Spec = *original.Spec.DeepCopy()
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return admin.Patch(requestCtx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	})
}

func m2PatchManagerSpec(ctx context.Context, original *appsv1.Deployment, mutate func(*appsv1.DeploymentSpec)) error {
	if original == nil || original.UID == "" || original.Namespace != m2LabProfile.runtimeNamespace || original.Name != managerName || mutate == nil {
		return fmt.Errorf("invalid checked manager mutation")
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := &appsv1.Deployment{}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := admin.Get(requestCtx, client.ObjectKeyFromObject(original), current)
		cancel()
		if err != nil {
			return err
		}
		if current.UID != original.UID {
			return fmt.Errorf("manager Deployment UID changed before mutation")
		}
		base := current.DeepCopy()
		mutate(&current.Spec)
		if reflect.DeepEqual(current.Spec, base.Spec) {
			return nil
		}
		requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
		err = admin.Patch(requestCtx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
		cancel()
		return err
	})
}

func m2RestoreRole(ctx context.Context, original *rbacv1.Role) error {
	if original == nil || original.UID == "" || original.Namespace != m2LabProfile.runtimeNamespace || original.Name != "keaguard-manager-role" {
		return fmt.Errorf("invalid Role restoration snapshot")
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := &rbacv1.Role{}
		if err := m2GetSnapshot(ctx, client.ObjectKeyFromObject(original), current); err != nil {
			return err
		}
		if current.UID != original.UID {
			return fmt.Errorf("manager Role UID changed from %s to %s", original.UID, current.UID)
		}
		if reflect.DeepEqual(current.Rules, original.Rules) {
			return nil
		}
		base := current.DeepCopy()
		current.Rules = make([]rbacv1.PolicyRule, len(original.Rules))
		for i := range original.Rules {
			current.Rules[i] = *original.Rules[i].DeepCopy()
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return admin.Patch(requestCtx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	})
}

func m2RestoreRoleBinding(ctx context.Context, original *rbacv1.RoleBinding) error {
	if original == nil || original.UID == "" || original.Namespace != m2LabProfile.runtimeNamespace || original.Name != "keaguard-manager-rolebinding" {
		return fmt.Errorf("invalid RoleBinding restoration snapshot")
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := &rbacv1.RoleBinding{}
		if err := m2GetSnapshot(ctx, client.ObjectKeyFromObject(original), current); err != nil {
			return err
		}
		if current.UID != original.UID {
			return fmt.Errorf("manager RoleBinding UID changed from %s to %s", original.UID, current.UID)
		}
		if current.RoleRef != original.RoleRef {
			return fmt.Errorf("manager RoleBinding RoleRef changed; immutable identity conflict")
		}
		if reflect.DeepEqual(current.Subjects, original.Subjects) {
			return nil
		}
		base := current.DeepCopy()
		current.Subjects = append([]rbacv1.Subject(nil), original.Subjects...)
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return admin.Patch(requestCtx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	})
}

func (s *m2Scenario) setNamespacePolicy(ctx context.Context, name string, policy map[string]string) error {
	if err := m2VerifyNamespaceReceipt(ctx); err != nil {
		return err
	}
	return s.setNamespacePolicyWith(ctx, admin, name, policy)
}

func (s *m2Scenario) setNamespacePolicyWith(ctx context.Context, c client.Client, name string, policy map[string]string) error {
	if s == nil || !s.started || c == nil || name != m2LabProfile.runtimeNamespace ||
		(policy["pod-security.kubernetes.io/enforce"] != "baseline" && policy["pod-security.kubernetes.io/enforce"] != "restricted") ||
		policy["pod-security.kubernetes.io/enforce-version"] != "v1.37" || len(policy) != 2 {
		return fmt.Errorf("M2 namespace policy fault is outside the reviewed runtime scope")
	}
	original := s.NamespaceSnapshots[name]
	if original == nil || original.UID == "" || !equalStringMap(policyLabels(original.Labels), m2ExpectedPolicy(name)) ||
		original.Labels[m2LabProfile.fixtureLabel] != m2LabProfile.cluster {
		return fmt.Errorf("M2 policy fault lacks the reviewed namespace snapshot")
	}
	current := &corev1.Namespace{}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := c.Get(requestCtx, client.ObjectKey{Name: name}, current)
	cancel()
	if err != nil {
		return err
	}
	if current.UID != original.UID || current.ResourceVersion == "" ||
		current.Labels[m2LabProfile.fixtureLabel] != m2LabProfile.cluster ||
		!equalStringMap(policyLabels(current.Labels), policyLabels(original.Labels)) {
		return fmt.Errorf("M2 policy fault refused stale or drifted namespace")
	}
	if s.KnownFaultPolicies == nil {
		s.KnownFaultPolicies = map[string]map[string]string{}
	}
	if existing, ok := s.KnownFaultPolicies[name]; ok && !equalStringMap(existing, policy) {
		return fmt.Errorf("M2 scenario already recorded a different policy fault")
	}
	s.KnownFaultPolicies[name] = maps.Clone(policy)
	if err := s.persistLedger(); err != nil {
		return err
	}
	base := current.DeepCopy()
	for key := range current.Labels {
		if strings.HasPrefix(key, "pod-security.kubernetes.io/") {
			delete(current.Labels, key)
		}
	}
	for key, value := range policy {
		current.Labels[key] = value
	}
	requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
	err = c.Patch(requestCtx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	cancel()
	if err != nil {
		return err
	}
	requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	verified := &corev1.Namespace{}
	if err := c.Get(requestCtx, client.ObjectKey{Name: name}, verified); err != nil {
		return err
	}
	if verified.UID != original.UID || verified.Labels[m2LabProfile.fixtureLabel] != m2LabProfile.cluster || !equalStringMap(policyLabels(verified.Labels), policy) {
		return fmt.Errorf("M2 policy fault did not produce the exact reviewed namespace state")
	}
	return nil
}

func m2RestoreNamespacePolicy(ctx context.Context, original *corev1.Namespace, knownFaultPolicy map[string]string) error {
	return m2RestoreNamespacePolicyWith(ctx, admin, original, knownFaultPolicy)
}

func m2RestoreNamespacePolicyWith(ctx context.Context, c client.Client, original *corev1.Namespace, knownFaultPolicy map[string]string) error {
	if original == nil || original.UID == "" || (original.Name != m2LabProfile.runtimeNamespace && original.Name != m2LabProfile.outsideNamespace) ||
		c == nil || original.Labels[m2LabProfile.fixtureLabel] != m2LabProfile.cluster || !equalStringMap(policyLabels(original.Labels), m2ExpectedPolicy(original.Name)) {
		return fmt.Errorf("invalid M2 namespace restoration snapshot")
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := &corev1.Namespace{}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := c.Get(requestCtx, client.ObjectKey{Name: original.Name}, current)
		cancel()
		if err != nil {
			return err
		}
		if current.UID != original.UID || current.Labels[m2LabProfile.fixtureLabel] != m2LabProfile.cluster {
			return fmt.Errorf("M2 namespace identity changed before policy restoration")
		}
		currentPolicy := policyLabels(current.Labels)
		baseline := policyLabels(original.Labels)
		if equalStringMap(currentPolicy, baseline) {
			return nil
		}
		if !equalStringMap(currentPolicy, knownFaultPolicy) {
			return fmt.Errorf("M2 namespace policy differs from the recorded fault")
		}
		base := current.DeepCopy()
		for key := range current.Labels {
			if strings.HasPrefix(key, "pod-security.kubernetes.io/") {
				delete(current.Labels, key)
			}
		}
		for key, value := range baseline {
			current.Labels[key] = value
		}
		requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return c.Patch(requestCtx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	})
}

func m2VerifyRBACBaseline(role *rbacv1.Role, binding *rbacv1.RoleBinding) error {
	if role == nil || binding == nil || role.UID == "" || binding.UID == "" ||
		role.Namespace != m2LabProfile.runtimeNamespace || role.Name != "keaguard-manager-role" ||
		binding.Namespace != m2LabProfile.runtimeNamespace || binding.Name != "keaguard-manager-rolebinding" {
		return fmt.Errorf("M2 manager RBAC object identity mismatch")
	}
	data, err := os.ReadFile("../../config/rbac/role.yaml")
	if err != nil {
		return err
	}
	expected := &rbacv1.Role{}
	if err := yaml.Unmarshal(data, expected); err != nil {
		return err
	}
	if !reflect.DeepEqual(role.Rules, expected.Rules) {
		return fmt.Errorf("manager Role rules differ from approved source manifest")
	}
	wantRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name}
	wantSubjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: managerName, Namespace: m2LabProfile.runtimeNamespace}}
	if binding.RoleRef != wantRef || !reflect.DeepEqual(binding.Subjects, wantSubjects) {
		return fmt.Errorf("manager RoleBinding differs from approved identity")
	}
	return nil
}

func (p m2ProcessIdentity) valid() bool {
	executable, config := "/usr/sbin/kea-dhcp4", "/run/kea/state/kea-dhcp4.conf"
	if p.ContainerName == "dhcp6" {
		executable, config = "/usr/sbin/kea-dhcp6", "/run/kea/state/kea-dhcp6.conf"
	} else if p.ContainerName != "dhcp4" {
		return false
	}
	return p.PodKey.Name != "" && p.PodKey.Namespace == m2LabProfile.runtimeNamespace && p.PodUID != "" &&
		p.StatefulSetKey.Name != "" && p.StatefulSetKey.Namespace == p.PodKey.Namespace && p.StatefulSetUID != "" &&
		p.KeaClusterKey.Name != "" && p.KeaClusterKey.Namespace == p.PodKey.Namespace && p.KeaClusterUID != "" &&
		containsString(m2LabProfile.nodes, p.NodeName) && p.NodeUID != "" && m2FullHexID(p.NodeContainerID) && p.NodeImage == m2LabProfile.nodeImage &&
		p.ContainerID == "containerd://"+p.TaskID && m2FullHexID(p.TaskID) && m2FullHexID(p.SandboxID) &&
		p.HostPID > 1 && strings.Contains("RSDIT", p.State) && len(p.State) == 1 && p.StartTicks > 0 && p.PIDNamespaceInode > 0 &&
		len(p.NSpid) >= 2 && p.NSpid[0] == p.HostPID && p.NSpid[len(p.NSpid)-1] == 1 &&
		p.Executable == executable && slices.Equal(p.Argv, []string{executable, "-c", config}) && p.UID == 100 && p.GID == 101 && p.ImageID != ""
}

func m2FullHexID(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func m2ObserveProcess(ctx context.Context, podKey client.ObjectKey, containerName string) (m2ProcessIdentity, error) {
	if err := m2VerifyNamespaceReceipt(ctx); err != nil {
		return m2ProcessIdentity{}, err
	}
	lab, err := m2InspectLabIdentity(ctx, adminConfig)
	if err != nil {
		return m2ProcessIdentity{}, err
	}
	return m2ObserveProcessWith(ctx, podKey, containerName, admin, lab, m2Command)
}

func m2ObserveProcessWith(ctx context.Context, podKey client.ObjectKey, containerName string, c client.Client, lab m2LabIdentity, run func(context.Context, string, ...string) ([]byte, error)) (m2ProcessIdentity, error) {
	if ctx.Err() != nil || c == nil || run == nil || podKey.Namespace != m2LabProfile.runtimeNamespace || podKey.Name == "" || (containerName != "dhcp4" && containerName != "dhcp6") {
		return m2ProcessIdentity{}, fmt.Errorf("process observation lacks an approved live target")
	}
	get := func(key client.ObjectKey, obj client.Object) error {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return c.Get(requestCtx, key, obj)
	}
	pod := &corev1.Pod{}
	if err := get(podKey, pod); err != nil {
		return m2ProcessIdentity{}, err
	}
	owner := metav1.GetControllerOf(pod)
	if pod.UID == "" || pod.Status.Phase != corev1.PodRunning || owner == nil || owner.APIVersion != appsv1.SchemeGroupVersion.String() || owner.Kind != "StatefulSet" || owner.UID == "" {
		return m2ProcessIdentity{}, fmt.Errorf("Pod lacks a live StatefulSet owner incarnation")
	}
	setKey := client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}
	set := &appsv1.StatefulSet{}
	if err := get(setKey, set); err != nil {
		return m2ProcessIdentity{}, err
	}
	parentOwner := metav1.GetControllerOf(set)
	if set.UID != owner.UID || parentOwner == nil || parentOwner.APIVersion != infrastructurev1alpha1.GroupVersion.String() || parentOwner.Kind != "KeaCluster" || parentOwner.UID == "" {
		return m2ProcessIdentity{}, fmt.Errorf("StatefulSet lacks the recorded KeaCluster owner chain")
	}
	parentKey := client.ObjectKey{Namespace: set.Namespace, Name: parentOwner.Name}
	parent := &infrastructurev1alpha1.KeaCluster{}
	if err := get(parentKey, parent); err != nil {
		return m2ProcessIdentity{}, err
	}
	if parent.UID != parentOwner.UID || parent.Spec == nil || parent.Spec.Workload == nil || !parent.Spec.Workload.Enabled {
		return m2ProcessIdentity{}, fmt.Errorf("KeaCluster workload owner UID or enabled state changed")
	}
	expectedImage, executable := m2KeaDHCP4Image, "/usr/sbin/kea-dhcp4"
	if containerName == "dhcp6" {
		expectedImage, executable = m2KeaDHCP6Image, "/usr/sbin/kea-dhcp6"
	}
	matchingSpec, matchingTemplate, matchingStatus := 0, 0, 0
	var status corev1.ContainerStatus
	for _, container := range pod.Spec.Containers {
		if container.Name == containerName {
			matchingSpec++
			if container.Image != expectedImage {
				return m2ProcessIdentity{}, fmt.Errorf("Pod Kea image differs from approved digest")
			}
		}
	}
	for _, container := range set.Spec.Template.Spec.Containers {
		if container.Name == containerName {
			matchingTemplate++
			if container.Image != expectedImage {
				return m2ProcessIdentity{}, fmt.Errorf("StatefulSet Kea image differs from approved digest")
			}
		}
	}
	for _, container := range pod.Status.ContainerStatuses {
		if container.Name == containerName {
			matchingStatus++
			status = container
		}
	}
	if matchingSpec != 1 || matchingTemplate != 1 || matchingStatus != 1 || !strings.HasPrefix(status.ContainerID, "containerd://") || status.ImageID == "" {
		return m2ProcessIdentity{}, fmt.Errorf("Kea Pod container/image incarnation is missing or ambiguous")
	}
	containerID := strings.TrimPrefix(status.ContainerID, "containerd://")
	if !m2FullHexID(containerID) {
		return m2ProcessIdentity{}, fmt.Errorf("Kea container ID is truncated or noncanonical")
	}
	nodeIdentity, ok := lab.Nodes[pod.Spec.NodeName]
	if !ok || lab.Cluster != m2LabProfile.cluster || !containsString(m2LabProfile.nodes, pod.Spec.NodeName) || !m2FullHexID(nodeIdentity.DockerID) || nodeIdentity.Image != m2LabProfile.nodeImage || !strings.HasPrefix(nodeIdentity.ImageID, "sha256:") || !m2FullHexID(strings.TrimPrefix(nodeIdentity.ImageID, "sha256:")) {
		return m2ProcessIdentity{}, fmt.Errorf("Pod node is not the approved full-ID Kind node")
	}
	node := &corev1.Node{}
	if err := get(client.ObjectKey{Name: pod.Spec.NodeName}, node); err != nil {
		return m2ProcessIdentity{}, err
	}
	if node.UID == "" || string(node.UID) != nodeIdentity.KubernetesUID {
		return m2ProcessIdentity{}, fmt.Errorf("Kubernetes Node UID changed before process observation")
	}
	out, err := run(ctx, "docker", "inspect", "--format", `{{.Id}}|{{.Config.Image}}|{{.Image}}|{{index .Config.Labels "io.x-k8s.kind.cluster"}}`, node.Name)
	if err != nil {
		return m2ProcessIdentity{}, err
	}
	if strings.TrimSpace(string(out)) != nodeIdentity.DockerID+"|"+nodeIdentity.Image+"|"+nodeIdentity.ImageID+"|"+lab.Cluster {
		return m2ProcessIdentity{}, fmt.Errorf("Docker node container ID/image/membership changed")
	}
	nodeExec := func(args ...string) ([]byte, error) {
		return run(ctx, "docker", append([]string{"exec", nodeIdentity.DockerID}, args...)...)
	}
	out, err = nodeExec("crictl", "inspect", "-o", "json", containerID)
	if err != nil {
		return m2ProcessIdentity{}, err
	}
	cri, err := m2ParseCRIInspect(out, containerID)
	if err != nil || cri.Status.ImageRef != status.ImageID || !m2FullHexID(cri.Info.SandboxID) {
		return m2ProcessIdentity{}, fmt.Errorf("CRI process/sandbox/image mapping changed: %v", err)
	}
	out, err = nodeExec("ctr", "--namespace", "k8s.io", "tasks", "list")
	if err != nil {
		return m2ProcessIdentity{}, err
	}
	pid, _, err := m2ParseTaskList(out, containerID)
	if err != nil || pid != cri.Info.PID {
		return m2ProcessIdentity{}, fmt.Errorf("containerd task PID differs from exact CRI mapping: %v", err)
	}
	proc := fmt.Sprintf("/proc/%d", pid)
	out, err = nodeExec("cat", proc+"/stat")
	if err != nil {
		return m2ProcessIdentity{}, err
	}
	state, ticks, err := m2ParseProcStat(out, pid)
	if err != nil {
		return m2ProcessIdentity{}, err
	}
	out, err = nodeExec("cat", proc+"/status")
	if err != nil {
		return m2ProcessIdentity{}, err
	}
	uid, gid, nspid, err := m2ParseProcStatus(out)
	if err != nil || nspid[0] != pid {
		return m2ProcessIdentity{}, fmt.Errorf("process credentials/NSpid host mapping mismatch: %v", err)
	}
	out, err = nodeExec("readlink", proc+"/ns/pid")
	if err != nil {
		return m2ProcessIdentity{}, err
	}
	nsLink := strings.TrimSpace(string(out))
	if !strings.HasPrefix(nsLink, "pid:[") || !strings.HasSuffix(nsLink, "]") {
		return m2ProcessIdentity{}, fmt.Errorf("process PID namespace inode is malformed")
	}
	inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(nsLink, "pid:["), "]"), 10, 64)
	if err != nil || inode == 0 {
		return m2ProcessIdentity{}, fmt.Errorf("process PID namespace inode is invalid")
	}
	out, err = nodeExec("readlink", proc+"/exe")
	if err != nil || strings.TrimSpace(string(out)) != executable {
		return m2ProcessIdentity{}, fmt.Errorf("process executable is not the approved Kea daemon: %v", err)
	}
	out, err = nodeExec("cat", proc+"/cmdline")
	if err != nil {
		return m2ProcessIdentity{}, err
	}
	argv := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	configPath := "/run/kea/state/kea-dhcp4.conf"
	if containerName == "dhcp6" {
		configPath = "/run/kea/state/kea-dhcp6.conf"
	}
	if !slices.Equal(argv, []string{executable, "-c", configPath}) {
		return m2ProcessIdentity{}, fmt.Errorf("process argv differs from approved Kea launch command")
	}
	identity := m2ProcessIdentity{PodKey: podKey, PodUID: pod.UID, StatefulSetKey: setKey, StatefulSetUID: set.UID,
		KeaClusterKey: parentKey, KeaClusterUID: parent.UID, NodeName: node.Name, NodeUID: node.UID,
		NodeContainerID: nodeIdentity.DockerID, NodeImage: nodeIdentity.Image, ContainerName: containerName,
		ContainerID: status.ContainerID, SandboxID: cri.Info.SandboxID, TaskID: containerID, HostPID: pid,
		State: state, StartTicks: ticks, PIDNamespaceInode: inode, NSpid: nspid, Executable: executable,
		Argv: argv, UID: uid, GID: gid, ImageID: status.ImageID}
	if !identity.valid() {
		return m2ProcessIdentity{}, fmt.Errorf("observed Kea process tuple is incomplete")
	}
	return identity, nil
}

func m2ParseProcStat(data []byte, expectedPID int) (string, uint64, error) {
	open, close := bytes.IndexByte(data, '('), bytes.LastIndexByte(data, ')')
	if open < 1 || close <= open || expectedPID <= 1 {
		return "", 0, fmt.Errorf("malformed process stat identity")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data[:open])))
	if err != nil || pid != expectedPID {
		return "", 0, fmt.Errorf("process stat PID changed")
	}
	fields := strings.Fields(string(data[close+1:]))
	if len(fields) < 20 || len(fields[0]) != 1 || !strings.Contains("RSDIT", fields[0]) {
		return "", 0, fmt.Errorf("process stat state/start-ticks format unsupported")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return "", 0, fmt.Errorf("process stat start ticks are missing")
	}
	return fields[0], ticks, nil
}

func m2ParseProcStatus(data []byte) (int, int, []int, error) {
	uid, gid := -1, -1
	var nspid []int
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "Uid:", "Gid:":
			if len(fields) != 5 {
				return 0, 0, nil, fmt.Errorf("process credentials are incomplete")
			}
			values := make([]int, 4)
			for i := range values {
				value, err := strconv.Atoi(fields[i+1])
				if err != nil || value < 0 {
					return 0, 0, nil, fmt.Errorf("process credentials are malformed")
				}
				values[i] = value
			}
			if !slices.Equal(values, []int{values[0], values[0], values[0], values[0]}) {
				return 0, 0, nil, fmt.Errorf("process credential slots differ")
			}
			if fields[0] == "Uid:" {
				uid = values[0]
			} else {
				gid = values[0]
			}
		case "NSpid:":
			if len(fields) < 3 {
				return 0, 0, nil, fmt.Errorf("process NSpid lacks host/container mapping")
			}
			for _, field := range fields[1:] {
				value, err := strconv.Atoi(field)
				if err != nil || value < 1 {
					return 0, 0, nil, fmt.Errorf("process NSpid is malformed")
				}
				nspid = append(nspid, value)
			}
		}
	}
	if uid != 100 || gid != 101 || len(nspid) < 2 || nspid[len(nspid)-1] != 1 {
		return 0, 0, nil, fmt.Errorf("process UID/GID or PID namespace init identity mismatch")
	}
	return uid, gid, nspid, nil
}

type m2ProcSecurityStatus struct {
	CapInh     uint64
	CapPrm     uint64
	CapEff     uint64
	CapBnd     uint64
	CapAmb     uint64
	NoNewPrivs uint64
	Seccomp    uint64
}

func m2ParseProcSecurityStatus(data []byte) (m2ProcSecurityStatus, error) {
	values := make(map[string]uint64, 7)
	wanted := map[string]bool{
		"CapInh:": true, "CapPrm:": true, "CapEff:": true, "CapBnd:": true,
		"CapAmb:": true, "NoNewPrivs:": true, "Seccomp:": true,
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !wanted[fields[0]] {
			continue
		}
		if len(fields) != 2 {
			return m2ProcSecurityStatus{}, fmt.Errorf("process security field %s is malformed", fields[0])
		}
		if _, duplicate := values[fields[0]]; duplicate {
			return m2ProcSecurityStatus{}, fmt.Errorf("process security field %s is duplicated", fields[0])
		}
		base := 10
		if strings.HasPrefix(fields[0], "Cap") {
			base = 16
		}
		value, err := strconv.ParseUint(fields[1], base, 64)
		if err != nil {
			return m2ProcSecurityStatus{}, fmt.Errorf("process security field %s is invalid: %w", fields[0], err)
		}
		values[fields[0]] = value
	}
	for key := range wanted {
		if _, ok := values[key]; !ok {
			return m2ProcSecurityStatus{}, fmt.Errorf("process security field %s is missing", key)
		}
	}
	if values["NoNewPrivs:"] > 1 || values["Seccomp:"] > 2 {
		return m2ProcSecurityStatus{}, fmt.Errorf("process NoNewPrivs/Seccomp value is unsupported")
	}
	return m2ProcSecurityStatus{
		CapInh: values["CapInh:"], CapPrm: values["CapPrm:"], CapEff: values["CapEff:"],
		CapBnd: values["CapBnd:"], CapAmb: values["CapAmb:"],
		NoNewPrivs: values["NoNewPrivs:"], Seccomp: values["Seccomp:"],
	}, nil
}

func m2ParseTaskList(data []byte, exactID string) (int, string, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 || !slices.Equal(strings.Fields(lines[0]), []string{"TASK", "PID", "STATUS"}) {
		return 0, "", fmt.Errorf("containerd task table header is unsupported")
	}
	found := 0
	var pid int
	var state string
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != 3 || len(fields[0]) != 64 {
			return 0, "", fmt.Errorf("containerd task row is truncated or ambiguous")
		}
		if fields[0] != exactID {
			continue
		}
		found++
		var err error
		pid, err = strconv.Atoi(fields[1])
		if err != nil || pid <= 1 || (fields[2] != "RUNNING" && fields[2] != "STOPPED") {
			return 0, "", fmt.Errorf("containerd task PID/state is unsupported")
		}
		state = fields[2]
	}
	if found != 1 {
		return 0, "", fmt.Errorf("expected exactly one full containerd task mapping, got %d", found)
	}
	return pid, state, nil
}

type m2CRIInspect struct {
	Status struct {
		ID       string `json:"id"`
		ImageRef string `json:"imageRef"`
	} `json:"status"`
	Info struct {
		PID       int    `json:"pid"`
		SandboxID string `json:"sandboxID"`
	} `json:"info"`
}

func m2ParseCRIInspect(data []byte, exactID string) (m2CRIInspect, error) {
	var record m2CRIInspect
	if err := json.Unmarshal(data, &record); err != nil {
		return record, err
	}
	if len(exactID) != 64 || record.Status.ID != exactID || record.Status.ImageRef == "" || record.Info.PID <= 1 || len(record.Info.SandboxID) != 64 {
		return record, fmt.Errorf("CRI inspect lacks exact container/task, sandbox, image or host PID identity")
	}
	return record, nil
}

func m2SignalProcess(ctx context.Context, expected m2ProcessIdentity, signal string) error {
	return m2SignalProcessWith(ctx, expected, signal,
		func(ctx context.Context) (m2ProcessIdentity, error) {
			return m2ObserveProcess(ctx, expected.PodKey, expected.ContainerName)
		},
		func(ctx context.Context, current m2ProcessIdentity) error {
			return m2CheckCtrCNI(ctx, current, m2Command)
		},
		func(ctx context.Context, current m2ProcessIdentity, signal string) error {
			_, err := m2Command(ctx, "docker", "exec", current.NodeContainerID, "ctr", "--namespace", "k8s.io", "tasks", "kill", "--signal", "SIG"+signal, current.TaskID)
			return err
		})
}

func m2SignalProcessWith(ctx context.Context, expected m2ProcessIdentity, signal string, observe func(context.Context) (m2ProcessIdentity, error), checkCNI func(context.Context, m2ProcessIdentity) error, submit func(context.Context, m2ProcessIdentity, string) error) error {
	if signal != "STOP" && signal != "CONT" && signal != "KILL" {
		return fmt.Errorf("unsupported process signal %q", signal)
	}
	if !expected.valid() || ctx.Err() != nil || observe == nil || checkCNI == nil || submit == nil {
		return fmt.Errorf("process identity or context is not safe")
	}
	for attempt := 0; attempt < 2; attempt++ {
		current, err := observe(ctx)
		if err != nil {
			return err
		}
		old, now := expected, current
		old.State, now.State = "", ""
		if !current.valid() || !reflect.DeepEqual(now, old) || signal == "CONT" && current.State != "T" || signal != "CONT" && current.State == "T" {
			return fmt.Errorf("process identity/state changed before signal")
		}
		if attempt == 0 {
			if err := checkCNI(ctx, current); err != nil {
				return err
			}
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return submit(ctx, current, signal)
	}
	return fmt.Errorf("process signal preflight did not complete")
}

func m2CheckCtrCNI(ctx context.Context, current m2ProcessIdentity, run func(context.Context, string, ...string) ([]byte, error)) error {
	if !current.valid() || run == nil || ctx.Err() != nil {
		return fmt.Errorf("containerd CNI side-effect preflight lacks exact task identity")
	}
	out, err := run(ctx, "docker", "exec", current.NodeContainerID, "ctr", "--namespace", "k8s.io", "containers", "info", current.TaskID)
	if err != nil {
		return err
	}
	var info struct {
		ID         string                     `json:"id"`
		Extensions map[string]json.RawMessage `json:"extensions"`
	}
	if err := json.Unmarshal(out, &info); err != nil || info.ID != current.TaskID {
		return fmt.Errorf("containerd container info cannot prove exact task: %v", err)
	}
	for key := range info.Extensions {
		if strings.Contains(strings.ToLower(key), "cni") {
			return fmt.Errorf("containerd task has CNI extension %q; signal side effects unapproved", key)
		}
	}
	return nil
}

func m2VerifyNamespaceReceipt(ctx context.Context) error {
	if err := checkM2PrivateInputs(m2NativeDir, m2LabProfile.dockerConfig, labKubeconfig); err != nil {
		return err
	}
	identity, err := m2InspectLabIdentity(ctx, adminConfig)
	if err != nil {
		return err
	}
	return m2VerifyNamespaceReceiptWith(ctx, admin, m2NamespaceReceiptPath, identity)
}

func m2VerifyNamespaceReceiptWith(ctx context.Context, c client.Client, path string, identity m2LabIdentity) error {
	if c == nil || ctx.Err() != nil {
		return fmt.Errorf("namespace receipt verification lacks a live administrator context/client")
	}
	data, err := readM2PrivateRecord(path)
	if err != nil {
		return fmt.Errorf("read M2 namespace receipt: %w", err)
	}
	var receipt m2NamespaceReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return fmt.Errorf("decode M2 namespace receipt: %w", err)
	}
	if receipt.Lab.Cluster != m2LabProfile.cluster || len(receipt.Namespaces) != 2 {
		return fmt.Errorf("M2 namespace receipt identity mismatch")
	}
	actual := map[string]corev1.Namespace{}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		var ns corev1.Namespace
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := c.Get(requestCtx, client.ObjectKey{Name: name}, &ns)
		cancel()
		if err != nil {
			return err
		}
		actual[name] = ns
	}
	return m2NamespaceReceiptMatches(receipt, actual, identity)
}

func m2InspectLabIdentity(ctx context.Context, cfg *rest.Config) (m2LabIdentity, error) {
	if cfg == nil || cfg.Host == "" || len(cfg.CAData) == 0 || admin == nil {
		return m2LabIdentity{}, fmt.Errorf("M2 lab identity lacks verified server, inline CA or administrator client")
	}
	imageOutput, err := m2Command(ctx, "docker", "image", "inspect", "--format", `{{.Id}}|{{.Os}}|{{.Architecture}}`, m2LabProfile.nodeImage)
	if err != nil {
		return m2LabIdentity{}, err
	}
	imageFields := strings.Split(strings.TrimSpace(string(imageOutput)), "|")
	if len(imageFields) != 3 || m2CheckImageIdentity(string(imageOutput), imageFields[0]) != nil {
		return m2LabIdentity{}, fmt.Errorf("pinned Kind node image lacks full Linux/amd64 local identity")
	}
	ca := sha256.Sum256(cfg.CAData)
	identity := m2LabIdentity{Cluster: m2LabProfile.cluster, Server: cfg.Host, CASHA256: hex.EncodeToString(ca[:]), Nodes: map[string]m2NodeIdentity{}}
	for _, name := range m2LabProfile.nodes {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		node := &corev1.Node{}
		err := admin.Get(requestCtx, client.ObjectKey{Name: name}, node)
		cancel()
		if err != nil {
			return m2LabIdentity{}, err
		}
		if node.UID == "" {
			return m2LabIdentity{}, fmt.Errorf("Kind node %s has no Kubernetes UID", name)
		}
		out, err := m2Command(ctx, "docker", "inspect", "--format", `{{.Id}}|{{.Config.Image}}|{{.Image}}|{{index .Config.Labels "io.x-k8s.kind.cluster"}}|{{index .Config.Labels "io.x-k8s.kind.role"}}`, name)
		if err != nil {
			return m2LabIdentity{}, err
		}
		entry, err := m2CheckKindNodeIdentity(name, node, string(out), imageFields[0])
		if err != nil {
			return m2LabIdentity{}, err
		}
		identity.Nodes[name] = entry
	}
	return identity, nil
}

func m2CheckKindNodeIdentity(name string, node *corev1.Node, dockerOutput, imageID string) (m2NodeIdentity, error) {
	role := false
	if node != nil {
		_, role = node.Labels["node-role.kubernetes.io/control-plane"]
	}
	if node == nil || node.Name != name || node.UID == "" || !containsString(m2LabProfile.nodes, name) ||
		node.Labels["kubernetes.io/hostname"] != name || node.Labels["kubernetes.io/os"] != "linux" ||
		node.Labels["kubernetes.io/arch"] != "amd64" || node.Status.NodeInfo.OperatingSystem != "linux" ||
		node.Status.NodeInfo.Architecture != "amd64" ||
		(name == m2LabProfile.nodes[0] && !role) || (name != m2LabProfile.nodes[0] && role) {
		return m2NodeIdentity{}, fmt.Errorf("Kind node %s Kubernetes labels/platform/UID mismatch", name)
	}
	fields := strings.Split(strings.TrimSpace(dockerOutput), "|")
	wantRole := "worker"
	if name == m2LabProfile.nodes[0] {
		wantRole = "control-plane"
	}
	if len(fields) != 5 || !m2FullHexID(fields[0]) || fields[1] != m2LabProfile.nodeImage ||
		!strings.HasPrefix(imageID, "sha256:") || !m2FullHexID(strings.TrimPrefix(imageID, "sha256:")) ||
		fields[2] != imageID || fields[3] != m2LabProfile.cluster || fields[4] != wantRole {
		return m2NodeIdentity{}, fmt.Errorf("Kind node %s full Docker/image/membership identity mismatch", name)
	}
	return m2NodeIdentity{KubernetesUID: string(node.UID), DockerID: fields[0], Image: fields[1], ImageID: fields[2]}, nil
}

func m2CheckNoPendingRecovery(dir string) error {
	if caseID := os.Getenv("KEAGUARD_M2_CLUSTER_REPLACEMENT"); caseID != "" {
		return m2CheckReplacementBootstrapState(dir, caseID)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".new") {
			return fmt.Errorf("unfinished M2 evidence write %s", entry.Name())
		}
	}
	for _, name := range []string{"recovery-pending.json", "teardown-failed.json", "diagnostics-failed.json"} {
		p := filepath.Join(dir, name)
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("unresolved M2 execution marker %s", name)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	statusPath := filepath.Join(dir, "diagnostics.json")
	if data, err := os.ReadFile(statusPath); err == nil {
		var state struct {
			CaseID string `json:"caseID"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("unreadable prior diagnostics state: %w", err)
		}
		if state.Status != "ok" {
			var reconcileErr error
			switch state.Status {
			case "skipped-recovery-incomplete":
				replacementReceipt := filepath.Join(dir, "cluster-replacement-reconciled-"+state.CaseID+".json")
				if _, err := os.Lstat(replacementReceipt); err == nil {
					reconcileErr = m2VerifyClusterReplacementRecovery(dir, state.CaseID, state.Status)
				} else if os.IsNotExist(err) {
					reconcileErr = m2VerifyRecoveryReconciliation(dir, state.CaseID, state.Status)
				} else {
					reconcileErr = err
				}
			case "failed":
				reconcileErr = m2VerifyDiagnosticFailureReconciliation(dir, state.CaseID)
			default:
				reconcileErr = fmt.Errorf("unsupported prior diagnostics state %q", state.Status)
			}
			if reconcileErr != nil {
				return fmt.Errorf("prior M2 diagnostics are not terminal-success and recovery reconciliation is unverified: %q: %w", state.Status, reconcileErr)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Bootstrap permits only read-only preflight of the single historically
// blocked T19 case while its exact original evidence remains unchanged.
func m2CheckReplacementBootstrapState(dir, caseID string) error {
	const historicCase = "1792432128521632810-890503"
	const markerHash = "7677ec685f8e6df21795f84d499c18bf98d87b51e47baea388c11972bb999232"
	const ledgerHash = "94af0604a1449e4657e63fe62bf013f53b3a4a41e4189bf686b1cd5081198a7c"
	if caseID != historicCase {
		return fmt.Errorf("replacement bootstrap is restricted to the exact historic M2 case")
	}
	if dir == m2NativeDir {
		return m2ValidateReplacementBootstrapEvidence(dir, caseID, markerHash, ledgerHash)
	}
	return m2ValidateReplacementGateBScenarioEvidence(m2NativeDir, dir, caseID, markerHash, ledgerHash)
}

func m2ValidateReplacementGateBScenarioEvidence(root, scenarioDir, caseID, markerHash, ledgerHash string) error {
	expected := filepath.Join(root, "replacement-gate-b-"+caseID)
	if scenarioDir != expected || filepath.Clean(filepath.Dir(scenarioDir)) != filepath.Clean(root) {
		return fmt.Errorf("replacement scenario evidence is outside the exact Gate B directory")
	}
	for _, dir := range []string{root, scenarioDir} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return fmt.Errorf("replacement Gate B evidence directory is not private and nonsymlink: %v", err)
		}
	}
	if err := m2ValidateReplacementBootstrapEvidence(root, caseID, markerHash, ledgerHash); err != nil {
		return err
	}
	created, err := readM2PrivateRecord(filepath.Join(root, "cluster-replacement-created-"+caseID+".json"))
	if err != nil {
		return err
	}
	namespaces, err := readM2PrivateRecord(filepath.Join(root, "cluster-replacement-namespaces-"+caseID+".json"))
	if err != nil {
		return err
	}
	started, err := readM2PrivateRecord(filepath.Join(scenarioDir, "gate-b-started.json"))
	if err != nil {
		return fmt.Errorf("replacement Gate B lacks its one-use start receipt: %w", err)
	}
	var state struct {
		CaseID           string `json:"caseID"`
		Status           string `json:"status"`
		CreatedSHA256    string `json:"createdSHA256"`
		NamespacesSHA256 string `json:"namespacesSHA256"`
	}
	if err := json.Unmarshal(started, &state); err != nil || state.CaseID != caseID || state.Status != "GATE_B_RUNNING_ON_VERIFIED_REPLACEMENT" || state.CreatedSHA256 != m2SHA256(created) || state.NamespacesSHA256 != m2SHA256(namespaces) {
		return fmt.Errorf("replacement Gate B start receipt is stale or mismatched: %v", err)
	}
	entries, err := os.ReadDir(scenarioDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".new") || entry.Name() == "recovery-pending.json" || entry.Name() == "teardown-failed.json" || entry.Name() == "diagnostics-failed.json" {
			return fmt.Errorf("replacement Gate B scenario has incomplete recovery state %s", entry.Name())
		}
	}
	if diagnostics, err := readM2PrivateRecord(filepath.Join(scenarioDir, "diagnostics.json")); err == nil {
		var result struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(diagnostics, &result); err != nil || result.Status != "ok" {
			return fmt.Errorf("previous replacement Gate B case diagnostics are not successful: %v", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func m2ValidateReplacementBootstrapEvidence(dir, caseID, markerHash, ledgerHash string) error {
	if _, err := os.Lstat(filepath.Join(dir, "cluster-replacement-namespace-intent-"+caseID+".json")); err == nil {
		if _, receiptErr := os.Lstat(filepath.Join(dir, "cluster-replacement-namespaces-"+caseID+".json")); receiptErr != nil {
			if !os.IsNotExist(receiptErr) {
				return receiptErr
			}
			if err := m2ValidateReplacementNamespaceStageBootstrap(dir, caseID); err != nil {
				return fmt.Errorf("replacement namespace creation intent is incomplete: %w", err)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, "cluster-replacement-namespace-pending-"+caseID+".json")); err == nil {
		return fmt.Errorf("replacement namespace setup is pending")
	} else if !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".new") || entry.Name() == "teardown-failed.json" || entry.Name() == "diagnostics-failed.json" {
			return fmt.Errorf("replacement bootstrap refuses incomplete evidence state %s", entry.Name())
		}
	}
	marker, err := readM2PrivateRecord(filepath.Join(dir, "recovery-pending.json"))
	if err != nil || m2SHA256(marker) != markerHash {
		return fmt.Errorf("replacement bootstrap original marker differs from preserved T19 evidence: %v", err)
	}
	ledger, err := readM2PrivateRecord(filepath.Join(dir, "ledger.json"))
	if err != nil || m2SHA256(ledger) != ledgerHash {
		return fmt.Errorf("replacement bootstrap original ledger differs from preserved T19 evidence: %v", err)
	}
	diagnostic, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics.json"))
	if err != nil {
		return err
	}
	original, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics-"+caseID+".json"))
	if err != nil || !bytes.Equal(diagnostic, original) {
		return fmt.Errorf("replacement bootstrap diagnostics changed: %v", err)
	}
	var state struct {
		CaseID string `json:"caseID"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(diagnostic, &state); err != nil || state.CaseID != caseID || state.Status != "skipped-recovery-incomplete" {
		return fmt.Errorf("replacement bootstrap diagnostics are not the exact historic failed state: %v", err)
	}
	return nil
}

func m2ValidateReplacementNamespaceStageBootstrap(dir, caseID string) error {
	stagePath := func(name string) string { return filepath.Join(dir, "cluster-replacement-"+name+"-"+caseID+".json") }
	intentBytes, err := readM2PrivateRecord(stagePath("namespace-intent"))
	if err != nil {
		return fmt.Errorf("namespace stage requires its durable intent: %w", err)
	}
	var namespaceIntent map[string]string
	if json.Unmarshal(intentBytes, &namespaceIntent) != nil || namespaceIntent["caseID"] != caseID || namespaceIntent["status"] != "NAMESPACE_CREATE_ONCE" {
		return fmt.Errorf("namespace stage intent is malformed or belongs to another case")
	}
	pathAbsent := func(path string) error {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("unexpected replacement namespace stage record %s", filepath.Base(path))
		} else if !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	for _, path := range []string{
		filepath.Join(dir, "cluster-replacement-namespace-pending-"+caseID+".json"),
		filepath.Join(dir, "namespaces.partial.json"),
		filepath.Join(dir, "namespace-receipt.json"),
		stagePath("namespaces"),
		stagePath("reconciled"),
	} {
		if err := pathAbsent(path); err != nil {
			return err
		}
	}
	notSubmittedPath, resumePath := stagePath("namespaces-not-submitted"), stagePath("namespace-resume-intent")
	switch os.Getenv("KEAGUARD_M2_REPLACEMENT_STAGE") {
	case "namespaces":
		if err := pathAbsent(notSubmittedPath); err != nil {
			return err
		}
		return pathAbsent(resumePath)
	case "reconcile-namespaces-not-submitted":
		if err := pathAbsent(notSubmittedPath); err != nil {
			return err
		}
		return pathAbsent(resumePath)
	case "resume-namespaces-not-submitted":
		notSubmittedBytes, err := readM2PrivateRecord(notSubmittedPath)
		if err != nil {
			return fmt.Errorf("namespace continuation requires its reconciliation receipt: %w", err)
		}
		var receipt m2ReplacementNamespaceReconciliation
		if json.Unmarshal(notSubmittedBytes, &receipt) != nil || receipt.CaseID != caseID || receipt.Status != "VERIFIED_NAMESPACE_STAGE_NOT_SUBMITTED" || receipt.NamespaceIntentSHA256 != m2SHA256(intentBytes) {
			return fmt.Errorf("namespace continuation reconciliation receipt is stale or malformed")
		}
		if err := m2ValidateReplacementIntent(resumePath, caseID, "CONTINUE_ABSENT_NAMESPACE_STAGE_ONCE", map[string]string{
			"namespaceIntentSHA256": m2SHA256(intentBytes),
			"notSubmittedSHA256":    m2SHA256(notSubmittedBytes),
			"createdSHA256":         receipt.CreatedSHA256,
			"preflightSHA256":       receipt.PreflightSHA256,
			"preflightLiveSHA256":   receipt.PreflightLiveSHA256,
			"keaPreflightSHA256":    receipt.KeaPreflightSHA256,
		}); err != nil {
			return fmt.Errorf("namespace continuation intent is stale or malformed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("replacement namespace intent is incomplete outside an explicit namespace lifecycle stage")
	}
}

const m2DiagnosticReconciliationStatus = "VERIFIED_RESTORATION_ONLY_NOT_SCENARIO_PASS"

type m2ReconciledFixture struct {
	GVK            string `json:"gvk"`
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	UID            string `json:"uid"`
	LiveResult     string `json:"liveResult"`
	ChildrenAbsent bool   `json:"childrenAbsent"`
}

type m2ReconciledNamespace struct {
	UID     string `json:"uid"`
	Owner   string `json:"owner"`
	Enforce string `json:"enforce"`
	Version string `json:"version"`
}

type m2ReconciledNode struct {
	KubernetesUID string `json:"kubernetesUID"`
	DockerID      string `json:"dockerID"`
	Image         string `json:"image"`
	ImageID       string `json:"imageID"`
}

type m2ReconciledManager struct {
	DeploymentUID      string `json:"deploymentUID"`
	Generation         int64  `json:"generation"`
	ObservedGeneration int64  `json:"observedGeneration"`
	ReadyReplicas      int32  `json:"readyReplicas"`
	Image              string `json:"image"`
	CRIImage           string `json:"criImage"`
	CRIImageIndex      string `json:"criImageIndex"`
	CRIManifest        string `json:"criManifest"`
	ImageIDManifest    string `json:"imageIDManifest"`
	CRIConfig          string `json:"criConfig"`
	PodUID             string `json:"podUID"`
	ContainerID        string `json:"containerID"`
	ImageID            string `json:"imageID"`
	Node               string `json:"node"`
	RoleUID            string `json:"roleUID"`
	RoleBindingUID     string `json:"roleBindingUID"`
	ServiceAccountUID  string `json:"serviceAccountUID"`
}

type m2DiagnosticFailureReconciliation struct {
	CaseID                    string                           `json:"caseID"`
	Status                    string                           `json:"status"`
	ScenarioName              string                           `json:"scenarioName"`
	DiagnosticsStatus         string                           `json:"diagnosticsStatus"`
	OriginalDiagnosticsSHA256 string                           `json:"originalDiagnosticsSHA256"`
	OriginalRecordPreserved   bool                             `json:"originalRecordPreserved"`
	RecoveryReceiptSHA256     string                           `json:"recoveryReceiptSHA256"`
	LedgerSHA256              string                           `json:"ledgerSHA256"`
	NamespaceReceiptSHA256    string                           `json:"namespaceReceiptSHA256"`
	LiveAuditSHA256           string                           `json:"liveAuditSHA256"`
	LiveAuditVerified         bool                             `json:"liveAuditVerified"`
	SourceFingerprint         string                           `json:"sourceFingerprint"`
	OperatorImage             string                           `json:"operatorImage"`
	OperatorIndex             string                           `json:"operatorIndex"`
	Manifest                  string                           `json:"manifest"`
	Config                    string                           `json:"config"`
	AllLayersVerified         bool                             `json:"allLayersVerified"`
	AllM2NodeCRIReferences    bool                             `json:"allM2NodeCRIReferences"`
	AllKeaReferences          bool                             `json:"allKeaReferences"`
	Fixture                   m2ReconciledFixture              `json:"fixture"`
	Namespaces                map[string]m2ReconciledNamespace `json:"namespaces"`
	Nodes                     map[string]m2ReconciledNode      `json:"nodes"`
	Manager                   m2ReconciledManager              `json:"manager"`
	NoActiveOperations        bool                             `json:"noActiveOperations"`
	M1ClusterPresent          bool                             `json:"m1ClusterPresent"`
	ScenarioPass              bool                             `json:"scenarioPass"`
}

type m2DiagnosticLiveAudit struct {
	CaseID                 string                           `json:"caseID"`
	Cluster                string                           `json:"cluster"`
	Context                string                           `json:"context"`
	APIReady               bool                             `json:"apiReady"`
	Fixture                m2ReconciledFixture              `json:"fixture"`
	Namespaces             map[string]m2ReconciledNamespace `json:"namespaces"`
	Nodes                  map[string]m2ReconciledNode      `json:"nodes"`
	Manager                m2ReconciledManager              `json:"manager"`
	NoActiveOperations     bool                             `json:"noActiveOperations"`
	M1ControlPlaneDockerID string                           `json:"m1ControlPlaneDockerID"`
}

func m2VerifyDiagnosticFailureReconciliation(dir, caseID string) error {
	if caseID == "" || strings.ContainsAny(caseID, `/\\`) {
		return fmt.Errorf("diagnostic reconciliation case identity is malformed")
	}
	for _, r := range caseID {
		if r != '-' && (r < '0' || r > '9') {
			return fmt.Errorf("diagnostic reconciliation case identity is malformed")
		}
	}
	read := func(name string) ([]byte, error) { return readM2PrivateRecord(filepath.Join(dir, name)) }
	original, err := read("diagnostics-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("original failed diagnostic record is unavailable: %w", err)
	}
	canonical, err := read("diagnostics.json")
	if err != nil || !bytes.Equal(original, canonical) {
		return fmt.Errorf("canonical diagnostics no longer matches the preserved failed case: %v", err)
	}
	var diagnostic struct {
		CaseID string `json:"caseID"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(original, &diagnostic); err != nil || diagnostic.CaseID != caseID || diagnostic.Status != "failed" || diagnostic.Error != "bounded command kubectl output exceeded 256 KiB" {
		return fmt.Errorf("original diagnostic is not the recorded bounded-event-output failure: %v", err)
	}
	recoveryBytes, err := read("recovery-restored-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("verified critical-restoration receipt is unavailable: %w", err)
	}
	ledgerBytes, err := read("ledger.json")
	if err != nil {
		return err
	}
	namespaceBytes, err := read("namespace-receipt.json")
	if err != nil {
		return err
	}
	liveAuditBytes, err := read("diagnostics-live-audit-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("independent live restoration audit is unavailable: %w", err)
	}
	reconciliationBytes, err := read("diagnostics-reconciled-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("separate diagnostic reconciliation receipt is unavailable: %w", err)
	}
	var recovery struct {
		CaseID        string            `json:"caseID"`
		Name          string            `json:"name"`
		Recovery      string            `json:"recovery"`
		NamespaceUIDs map[string]string `json:"namespaceUIDs"`
		Image         string            `json:"image"`
		ImageID       string            `json:"imageID"`
	}
	if err := json.Unmarshal(recoveryBytes, &recovery); err != nil || recovery.CaseID != caseID || recovery.Recovery != "restored" {
		return fmt.Errorf("critical-restoration receipt is malformed or not restored: %v", err)
	}
	var ledger struct {
		Scenario string `json:"scenario"`
		Fixtures []struct {
			GVK struct {
				Group   string `json:"Group"`
				Version string `json:"Version"`
				Kind    string `json:"Kind"`
			} `json:"gvk"`
			Key struct {
				Namespace string `json:"Namespace"`
				Name      string `json:"Name"`
			} `json:"key"`
			UID            string `json:"uid"`
			Created        bool   `json:"created"`
			EndState       string `json:"endState"`
			AbsentVerified bool   `json:"absentVerified"`
		} `json:"fixtures"`
		Intents []struct {
			Phase string `json:"phase"`
		} `json:"intents"`
		Stopped []json.RawMessage `json:"stopped"`
	}
	if err := json.Unmarshal(ledgerBytes, &ledger); err != nil || ledger.Scenario != recovery.Name || len(ledger.Fixtures) == 0 || len(ledger.Stopped) != 0 {
		return fmt.Errorf("scenario ledger is malformed or contains stopped/unrestored identities: %v", err)
	}
	for _, intent := range ledger.Intents {
		if intent.Phase != "confirmed" {
			return fmt.Errorf("scenario ledger has unresolved creation intent")
		}
	}
	var namespaceReceipt struct {
		Lab struct {
			Cluster string                      `json:"cluster"`
			Nodes   map[string]m2ReconciledNode `json:"nodes"`
		} `json:"lab"`
		Namespaces map[string]struct {
			UID    string            `json:"uid"`
			Labels map[string]string `json:"labels"`
			Policy map[string]string `json:"policy"`
		} `json:"namespaces"`
	}
	if err := json.Unmarshal(namespaceBytes, &namespaceReceipt); err != nil || namespaceReceipt.Lab.Cluster != m2LabProfile.cluster {
		return fmt.Errorf("original namespace receipt is malformed or names another cluster: %v", err)
	}
	var receipt m2DiagnosticFailureReconciliation
	if err := json.Unmarshal(reconciliationBytes, &receipt); err != nil {
		return fmt.Errorf("diagnostic reconciliation receipt is malformed: %w", err)
	}
	var liveAudit m2DiagnosticLiveAudit
	if err := json.Unmarshal(liveAuditBytes, &liveAudit); err != nil {
		return fmt.Errorf("independent live audit is malformed: %w", err)
	}
	if liveAudit.CaseID != caseID || liveAudit.Cluster != m2LabProfile.cluster || liveAudit.Context != "kind-"+m2LabProfile.cluster ||
		!liveAudit.APIReady || liveAudit.Fixture != receipt.Fixture || !reflect.DeepEqual(liveAudit.Namespaces, receipt.Namespaces) ||
		!reflect.DeepEqual(liveAudit.Nodes, receipt.Nodes) || liveAudit.Manager != receipt.Manager || !liveAudit.NoActiveOperations ||
		!m2FullHexID(liveAudit.M1ControlPlaneDockerID) {
		return fmt.Errorf("independent live audit does not bind the exact recovery and lab identities")
	}
	if receipt.CaseID != caseID || receipt.Status != m2DiagnosticReconciliationStatus || receipt.ScenarioName != recovery.Name ||
		receipt.DiagnosticsStatus != "failed" || !receipt.OriginalRecordPreserved || receipt.OriginalDiagnosticsSHA256 != m2SHA256(original) ||
		receipt.RecoveryReceiptSHA256 != m2SHA256(recoveryBytes) || receipt.LedgerSHA256 != m2SHA256(ledgerBytes) || receipt.NamespaceReceiptSHA256 != m2SHA256(namespaceBytes) ||
		receipt.LiveAuditSHA256 != m2SHA256(liveAuditBytes) || !receipt.LiveAuditVerified ||
		!m2FullHexID(receipt.SourceFingerprint) || receipt.OperatorImage != recovery.Image || receipt.OperatorIndex != recovery.ImageID ||
		!m2ValidSHA256Digest(receipt.OperatorIndex) || !m2ValidSHA256Digest(receipt.Manifest) || !m2ValidSHA256Digest(receipt.Config) ||
		!receipt.AllLayersVerified || !receipt.AllM2NodeCRIReferences || !receipt.AllKeaReferences || receipt.ScenarioPass || !receipt.NoActiveOperations || !receipt.M1ClusterPresent {
		return fmt.Errorf("diagnostic reconciliation receipt does not bind original evidence and verified identities: case=%t status=%t name=%t diag=%t original=%t recovery=%t ledger=%t namespace=%t fingerprint=%t image=%t index=%t manifest=%t config=%t layers=%t cri=%t kea=%t scenarioPass=%t active=%t m1=%t",
			receipt.CaseID == caseID, receipt.Status == m2DiagnosticReconciliationStatus, receipt.ScenarioName == recovery.Name,
			receipt.DiagnosticsStatus == "failed", receipt.OriginalRecordPreserved && receipt.OriginalDiagnosticsSHA256 == m2SHA256(original),
			receipt.RecoveryReceiptSHA256 == m2SHA256(recoveryBytes), receipt.LedgerSHA256 == m2SHA256(ledgerBytes),
			receipt.NamespaceReceiptSHA256 == m2SHA256(namespaceBytes), m2FullHexID(receipt.SourceFingerprint), receipt.OperatorImage == recovery.Image,
			receipt.OperatorIndex == recovery.ImageID && m2ValidSHA256Digest(receipt.OperatorIndex), m2ValidSHA256Digest(receipt.Manifest),
			m2ValidSHA256Digest(receipt.Config), receipt.AllLayersVerified, receipt.AllM2NodeCRIReferences, receipt.AllKeaReferences,
			receipt.ScenarioPass, receipt.NoActiveOperations, receipt.M1ClusterPresent)
	}
	imageTag, err := m2ImageTagForFingerprint(receipt.SourceFingerprint)
	if err != nil || imageTag != receipt.OperatorImage {
		return fmt.Errorf("diagnostic reconciliation image does not match its source fingerprint")
	}
	fixtureMatched := false
	for _, fixture := range ledger.Fixtures {
		if !fixture.Created || fixture.EndState != "absent" || !fixture.AbsentVerified || fixture.UID == "" || fixture.Key.Name == "" || fixture.Key.Namespace != m2LabProfile.runtimeNamespace {
			return fmt.Errorf("scenario ledger contains an unverified fixture restoration")
		}
		if fixture.UID == receipt.Fixture.UID && fixture.Key.Name == receipt.Fixture.Name && fixture.Key.Namespace == receipt.Fixture.Namespace &&
			fixture.GVK.Group+"/"+fixture.GVK.Version+", Kind="+fixture.GVK.Kind == receipt.Fixture.GVK {
			fixtureMatched = true
		}
	}
	if !fixtureMatched || receipt.Fixture.LiveResult != "API_NOT_FOUND" || !receipt.Fixture.ChildrenAbsent {
		return fmt.Errorf("diagnostic reconciliation does not account for the exact absent scenario fixture")
	}
	if len(receipt.Namespaces) != 2 || len(namespaceReceipt.Namespaces) != 2 || len(recovery.NamespaceUIDs) != 2 {
		return fmt.Errorf("diagnostic reconciliation must bind both reviewed namespaces")
	}
	for name, expected := range map[string]string{m2LabProfile.runtimeNamespace: "privileged", m2LabProfile.outsideNamespace: "restricted"} {
		ns, ok := receipt.Namespaces[name]
		original, originalOK := namespaceReceipt.Namespaces[name]
		if !ok || !originalOK || ns.UID == "" || ns.UID != original.UID || recovery.NamespaceUIDs[name] != ns.UID ||
			ns.Owner != m2LabProfile.cluster || original.Labels[m2LabProfile.fixtureLabel] != m2LabProfile.cluster ||
			ns.Enforce != expected || ns.Version != "v1.37" || original.Policy["pod-security.kubernetes.io/enforce"] != expected || original.Policy["pod-security.kubernetes.io/enforce-version"] != ns.Version {
			return fmt.Errorf("diagnostic reconciliation namespace %s differs from the reviewed receipt", name)
		}
	}
	if len(receipt.Nodes) != len(m2LabProfile.nodes) || len(namespaceReceipt.Lab.Nodes) != len(m2LabProfile.nodes) {
		return fmt.Errorf("diagnostic reconciliation must bind all approved M2 nodes")
	}
	for _, name := range m2LabProfile.nodes {
		node, ok := receipt.Nodes[name]
		original, originalOK := namespaceReceipt.Lab.Nodes[name]
		if !ok || !originalOK || node.KubernetesUID == "" || !m2FullHexID(node.DockerID) ||
			node.KubernetesUID != original.KubernetesUID || node.DockerID != original.DockerID || node.Image != m2LabProfile.nodeImage ||
			node.Image != original.Image || node.ImageID != original.ImageID {
			return fmt.Errorf("diagnostic reconciliation node %s differs from the namespace identity receipt: found=%+v original=%+v", name, node, original)
		}
	}
	manager := receipt.Manager
	_, immutableManagerID := m2ImmutableImageRefDigest(manager.ImageID)
	criImageSuffix := strings.TrimPrefix(manager.CRIImage, "docker.io/library/keaguard-operator:m2-")
	_, criTagErr := hex.DecodeString(criImageSuffix)
	if manager.DeploymentUID == "" || manager.Generation < 1 || manager.ObservedGeneration != manager.Generation || manager.ReadyReplicas != 1 ||
		manager.Image != recovery.Image || !strings.HasPrefix(manager.CRIImage, "docker.io/library/keaguard-operator:m2-") ||
		len(criImageSuffix) != 12 || criTagErr != nil || strings.ToLower(criImageSuffix) != criImageSuffix ||
		!m2ValidSHA256Digest(manager.CRIImageIndex) || manager.CRIManifest != receipt.Manifest || manager.ImageIDManifest != receipt.Manifest || manager.CRIConfig != receipt.Config ||
		manager.PodUID == "" || !strings.HasPrefix(manager.ContainerID, "containerd://") ||
		!m2FullHexID(strings.TrimPrefix(manager.ContainerID, "containerd://")) || !immutableManagerID || manager.Node == "" ||
		manager.RoleUID == "" || manager.RoleBindingUID == "" || manager.ServiceAccountUID == "" {
		return fmt.Errorf("diagnostic reconciliation manager/Role identity is incomplete or unhealthy")
	}
	if _, ok := receipt.Nodes[manager.Node]; !ok {
		return fmt.Errorf("diagnostic reconciliation manager Pod is assigned to an unverified node")
	}
	return nil
}

// m2VerifyRecoveryReconciliation permits continuation after an interrupted
// cleanup only when a separate private receipt proves restoration for that
// exact case. It intentionally preserves the original diagnostics status and
// never treats the interrupted scenario itself as a pass.
func m2VerifyRecoveryReconciliation(dir, caseID, diagnosticStatus string) error {
	if caseID == "" || strings.ContainsAny(caseID, `/\\`) || diagnosticStatus != "skipped-recovery-incomplete" {
		return fmt.Errorf("reconciliation is not eligible for this diagnostic state")
	}
	for _, r := range caseID {
		if r != '-' && (r < '0' || r > '9') {
			return fmt.Errorf("reconciliation case identity is malformed")
		}
	}
	path := filepath.Join(dir, "recovery-reconciled-"+caseID+".json")
	data, err := readM2PrivateRecord(path)
	if err != nil {
		return err
	}
	var receipt struct {
		CaseID               string `json:"caseID"`
		Status               string `json:"status"`
		OriginalLedgerSHA256 string `json:"originalLedgerSHA256"`
		OriginalScenario     struct {
			Name               string `json:"name"`
			ScenarioResult     string `json:"scenarioResult"`
			GateBResult        string `json:"gateBResult,omitempty"`
			DiagnosticsStatus  string `json:"diagnosticsStatus"`
			RecoveryMarkerHash string `json:"recoveryMarkerSHA256"`
		} `json:"originalScenario"`
		Fixtures []struct {
			GVK                          string `json:"gvk"`
			Namespace                    string `json:"namespace"`
			Name                         string `json:"name"`
			UID                          string `json:"uid"`
			LiveResult                   string `json:"liveResult"`
			RestorationBasis             string `json:"restorationBasis"`
			ParentUID                    string `json:"parentUID,omitempty"`
			SameNameOwnedChildren        string `json:"sameNameOwnedChildren"`
			OwnerLabelledRuntimeChildren string `json:"ownerLabelledRuntimeChildren"`
		} `json:"fixtures"`
		Namespaces []struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"namespaces"`
		Manager struct {
			Deployment struct {
				UID                string `json:"uid"`
				Generation         int64  `json:"generation"`
				ObservedGeneration int64  `json:"observedGeneration"`
				ReadyReplicas      int32  `json:"readyReplicas"`
				Image              string `json:"image"`
			} `json:"deployment"`
			Pod struct {
				UID             string `json:"uid"`
				Ready           bool   `json:"ready"`
				ConfiguredImage string `json:"configuredImage"`
			} `json:"pod"`
			RoleUID           string `json:"roleUID"`
			RoleBindingUID    string `json:"roleBindingUID"`
			ServiceAccountUID string `json:"serviceAccountUID"`
		} `json:"manager"`
		Identity struct {
			SourceFingerprint                string `json:"sourceFingerprint"`
			OperatorTag                      string `json:"operatorTag"`
			BuildIID                         string `json:"buildIID"`
			Manifest                         string `json:"manifest"`
			Config                           string `json:"config"`
			NamespaceUIDsMatchReceipt        bool   `json:"namespaceUIDsMatchReceipt"`
			NodeUIDsAndDockerIDsMatchReceipt bool   `json:"nodeUIDsAndDockerIDsMatchReceipt"`
			AllM2CRIImageReferencesVerified  bool   `json:"allM2CRIImageReferencesVerified"`
			M1ControlPlaneUnchanged          bool   `json:"m1ControlPlaneUnchanged"`
		} `json:"identity"`
		Restoration struct {
			Fixtures          string `json:"fixtures"`
			NamespacePolicies string `json:"namespacePolicies"`
			ManagerAndRBAC    string `json:"managerAndRBAC"`
			StoppedProcesses  string `json:"stoppedProcesses"`
			ActiveOperations  string `json:"activeTestOrRecoveryProcess"`
		} `json:"restoration"`
		Diagnostics struct {
			Status                  string `json:"status"`
			OriginalRecordPreserved bool   `json:"originalRecordPreserved"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		return fmt.Errorf("reconciliation receipt is malformed: %w", err)
	}
	ledgerBytes, err := readM2PrivateRecord(filepath.Join(dir, "ledger.json"))
	if err != nil {
		return fmt.Errorf("original interrupted fixture ledger is unavailable: %w", err)
	}
	originalDiagnostic, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics-"+caseID+".json"))
	if err != nil {
		return fmt.Errorf("original interrupted diagnostic is unavailable: %w", err)
	}
	canonicalDiagnostic, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics.json"))
	if err != nil || !bytes.Equal(originalDiagnostic, canonicalDiagnostic) {
		return fmt.Errorf("original interrupted diagnostic changed: %v", err)
	}
	var diagnostic struct {
		CaseID string `json:"caseID"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(originalDiagnostic, &diagnostic); err != nil || diagnostic.CaseID != caseID || diagnostic.Status != diagnosticStatus {
		return fmt.Errorf("original diagnostic does not prove the exact failed recovery state: %v", err)
	}
	var ledger struct {
		Scenario string `json:"scenario"`
		Fixtures []struct {
			GVK struct {
				Group   string `json:"Group"`
				Version string `json:"Version"`
				Kind    string `json:"Kind"`
			} `json:"gvk"`
			Key struct {
				Namespace string `json:"Namespace"`
				Name      string `json:"Name"`
			} `json:"key"`
			UID            string          `json:"uid"`
			Created        bool            `json:"created"`
			EndState       string          `json:"endState"`
			AbsentVerified bool            `json:"absentVerified"`
			Original       json.RawMessage `json:"original"`
		} `json:"fixtures"`
		Stopped []json.RawMessage `json:"stopped"`
	}
	if err := json.Unmarshal(ledgerBytes, &ledger); err != nil || ledger.Scenario == "" || len(ledger.Fixtures) == 0 || len(ledger.Stopped) != 0 {
		return fmt.Errorf("original fixture ledger is malformed or contains stopped processes: %v", err)
	}
	scenarioResult := receipt.OriginalScenario.ScenarioResult
	if scenarioResult == "" {
		scenarioResult = receipt.OriginalScenario.GateBResult
	}
	archivedMarker, err := readM2PrivateRecord(filepath.Join(dir, "recovery-pending-archived-"+caseID+".json"))
	if err != nil {
		return fmt.Errorf("original pending marker archive is unavailable: %w", err)
	}
	archivedMarkerHash := sha256.Sum256(archivedMarker)
	if receipt.CaseID != caseID || receipt.Status != "VERIFIED_RESTORATION_ONLY_NOT_SCENARIO_PASS" || receipt.OriginalLedgerSHA256 != m2SHA256(ledgerBytes) ||
		receipt.Identity.SourceFingerprint == "" || scenarioResult != "FAILED_ABORTED" ||
		(receipt.OriginalScenario.ScenarioResult != "" && receipt.OriginalScenario.GateBResult != "" && receipt.OriginalScenario.ScenarioResult != receipt.OriginalScenario.GateBResult) ||
		receipt.OriginalScenario.Name != ledger.Scenario || receipt.OriginalScenario.DiagnosticsStatus != diagnosticStatus || !m2FullHexID(receipt.OriginalScenario.RecoveryMarkerHash) ||
		receipt.OriginalScenario.RecoveryMarkerHash != hex.EncodeToString(archivedMarkerHash[:]) ||
		len(receipt.Fixtures) == 0 || len(receipt.Fixtures) != len(ledger.Fixtures) || len(receipt.Namespaces) != 2 ||
		receipt.Manager.Deployment.UID == "" || receipt.Manager.Deployment.Generation < 1 || receipt.Manager.Deployment.ObservedGeneration < receipt.Manager.Deployment.Generation ||
		receipt.Manager.Deployment.ReadyReplicas != 1 || receipt.Manager.Deployment.Image == "" || receipt.Manager.Pod.UID == "" || !receipt.Manager.Pod.Ready ||
		receipt.Manager.Pod.ConfiguredImage != receipt.Manager.Deployment.Image || receipt.Manager.RoleUID == "" || receipt.Manager.RoleBindingUID == "" || receipt.Manager.ServiceAccountUID == "" ||
		receipt.Identity.OperatorTag == "" || !m2ValidSHA256Digest(receipt.Identity.BuildIID) || !m2ValidSHA256Digest(receipt.Identity.Manifest) || !m2ValidSHA256Digest(receipt.Identity.Config) ||
		!receipt.Identity.NamespaceUIDsMatchReceipt || !receipt.Identity.NodeUIDsAndDockerIDsMatchReceipt || !receipt.Identity.AllM2CRIImageReferencesVerified || !receipt.Identity.M1ControlPlaneUnchanged ||
		receipt.Restoration.Fixtures != "VERIFIED_ABSENT" || receipt.Restoration.NamespacePolicies != "VERIFIED_MATCH_ORIGINAL_RECEIPT" ||
		receipt.Restoration.ManagerAndRBAC != "VERIFIED_HEALTHY_EXPECTED_IDENTITIES" || receipt.Restoration.StoppedProcesses != "NONE_RECORDED" || receipt.Restoration.ActiveOperations != "NONE_OBSERVED" ||
		receipt.Diagnostics.Status != diagnosticStatus || !receipt.Diagnostics.OriginalRecordPreserved {
		return fmt.Errorf("reconciliation receipt does not prove the exact interrupted case's restoration-only contract")
	}
	seenFixtures := map[string]bool{}
	for _, fixture := range receipt.Fixtures {
		if fixture.UID == "" || fixture.Namespace == "" || fixture.Name == "" || fixture.GVK == "" || fixture.LiveResult != "API_NOT_FOUND" || fixture.SameNameOwnedChildren != "NONE" || fixture.OwnerLabelledRuntimeChildren != "NONE" {
			return fmt.Errorf("reconciliation receipt contains an unverified fixture outcome")
		}
		matched := false
		for _, recorded := range ledger.Fixtures {
			recordedGVK := schema.GroupVersionKind{Group: recorded.GVK.Group, Version: recorded.GVK.Version, Kind: recorded.GVK.Kind}.String()
			if recorded.UID != fixture.UID || recorded.Key.Namespace != fixture.Namespace || recorded.Key.Name != fixture.Name || recordedGVK != fixture.GVK {
				continue
			}
			key := recordedGVK + "\x00" + recorded.Key.Namespace + "\x00" + recorded.Key.Name + "\x00" + recorded.UID
			if seenFixtures[key] {
				return fmt.Errorf("reconciliation receipt repeats a recorded fixture incarnation")
			}
			seenFixtures[key] = true
			if recorded.Created {
				if recorded.EndState != "absent" || !recorded.AbsentVerified || fixture.RestorationBasis != "case-created-absent" || fixture.ParentUID != "" {
					return fmt.Errorf("case-created fixture lacks its recorded UID absence proof")
				}
				matched = true
				break
			}
			if fixture.RestorationBasis != "owner-garbage-collected" || recorded.EndState != "restored" || recorded.Original == nil {
				continue
			}
			var original corev1.ConfigMap
			if err := json.Unmarshal(recorded.Original, &original); err != nil || string(original.UID) != recorded.UID || original.Namespace != recorded.Key.Namespace || original.Name != recorded.Key.Name ||
				original.Labels["keaguard.example/artifact"] != "reconciliation" || original.Annotations["keaguard.example/purpose"] != "Internal reconciliation artifact; not operational Kea DHCP configuration." ||
				len(original.Data) != 3 || original.Data["keacluster-name"] != original.Name || original.Data["keacluster-namespace"] != original.Namespace {
				return fmt.Errorf("owner-GC reconciliation does not identify the exact preserved M1 identity artifact: %v", err)
			}
			ownerUID := types.UID(original.Data["keacluster-uid"])
			ownerCount := 0
			for _, owner := range original.OwnerReferences {
				if owner.Controller != nil && *owner.Controller {
					ownerCount++
					if owner.APIVersion != infrastructurev1alpha1.GroupVersion.String() || owner.Kind != "KeaCluster" || owner.Name != original.Name || owner.UID != ownerUID {
						return fmt.Errorf("owner-GC artifact owner identity conflicts with its original snapshot")
					}
				}
			}
			parentFound := false
			for _, parent := range ledger.Fixtures {
				if parent.GVK.Group == infrastructurev1alpha1.GroupVersion.Group && parent.GVK.Version == infrastructurev1alpha1.GroupVersion.Version && parent.GVK.Kind == "KeaCluster" &&
					parent.Key.Namespace == recorded.Key.Namespace && parent.Key.Name == original.Name && parent.UID == string(ownerUID) && parent.Created && parent.EndState == "absent" && parent.AbsentVerified {
					parentFound = true
				}
			}
			if ownerCount != 1 || ownerUID == "" || !parentFound || fixture.ParentUID != string(ownerUID) {
				return fmt.Errorf("owner-GC artifact lacks the exact absent case-created parent proof")
			}
			matched = true
			break
		}
		if !matched {
			return fmt.Errorf("reconciliation fixture %s/%s UID %s does not match a proven ledger restoration path", fixture.Namespace, fixture.Name, fixture.UID)
		}
	}
	for _, namespace := range receipt.Namespaces {
		if namespace.Name == "" || namespace.UID == "" {
			return fmt.Errorf("reconciliation receipt contains an incomplete namespace identity")
		}
	}
	return nil
}

func m2RetireReconciledRecoveryMarker(dir, caseID string) error {
	if caseID == "" || strings.ContainsAny(caseID, `/\\`) {
		return fmt.Errorf("recovery-marker retirement requires an exact case identity")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("recovery-marker retirement requires a private nonsymlink evidence directory: %v", err)
	}
	markerPath := filepath.Join(dir, "recovery-pending.json")
	marker, err := readM2PrivateRecord(markerPath)
	if err != nil {
		return fmt.Errorf("active recovery marker is unavailable: %w", err)
	}
	archived, err := readM2PrivateRecord(filepath.Join(dir, "recovery-pending-archived-"+caseID+".json"))
	if err != nil || !bytes.Equal(marker, archived) {
		return fmt.Errorf("active marker differs from its preserved archive: %v", err)
	}
	var state struct {
		CaseID string `json:"caseID"`
	}
	if err := json.Unmarshal(marker, &state); err != nil || state.CaseID != caseID {
		return fmt.Errorf("active recovery marker does not identify the requested case: %v", err)
	}
	if err := m2VerifyRecoveryReconciliation(dir, caseID, "skipped-recovery-incomplete"); err != nil {
		return fmt.Errorf("restoration-only reconciliation is incomplete: %w", err)
	}
	current, err := readM2PrivateRecord(markerPath)
	if err != nil || !bytes.Equal(current, marker) {
		return fmt.Errorf("active marker changed during retirement verification: %v", err)
	}
	if err := os.Remove(markerPath); err != nil {
		return err
	}
	if _, err := os.Lstat(markerPath); !os.IsNotExist(err) {
		return fmt.Errorf("active recovery marker remains or cannot be verified absent: %v", err)
	}
	archivedAfter, err := readM2PrivateRecord(filepath.Join(dir, "recovery-pending-archived-"+caseID+".json"))
	if err != nil || !bytes.Equal(archivedAfter, marker) {
		return fmt.Errorf("archived recovery marker changed during retirement: %v", err)
	}
	return nil
}

func m2NamespaceReceiptMatches(receipt m2NamespaceReceipt, actual map[string]corev1.Namespace, identity m2LabIdentity) error {
	if receipt.Lab.Cluster != m2LabProfile.cluster || !reflect.DeepEqual(receipt.Lab, identity) || len(identity.Nodes) != len(m2LabProfile.nodes) ||
		!equalStringMap(receipt.FixtureLabel, map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}) ||
		len(receipt.Namespaces) != 2 || len(actual) != 2 {
		return fmt.Errorf("M2 namespace receipt lab/ownership/cardinality mismatch")
	}
	if identity.Server == "" || len(identity.CASHA256) != 64 {
		return fmt.Errorf("M2 namespace receipt lacks server/CA binding")
	}
	for _, name := range m2LabProfile.nodes {
		node, ok := identity.Nodes[name]
		if !ok || node.KubernetesUID == "" || len(node.DockerID) != 64 || node.Image != m2LabProfile.nodeImage {
			return fmt.Errorf("M2 namespace receipt lacks approved node %s identity", name)
		}
	}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		entry, ok := receipt.Namespaces[name]
		ns, exists := actual[name]
		if !ok || !exists || entry.UID == "" || entry.UID != string(ns.UID) {
			return fmt.Errorf("M2 namespace %s incarnation mismatch", name)
		}
		if err := checkFixtureNamespaceForProfile(m2LabProfile, &ns); err != nil {
			return err
		}
		if !equalStringMap(entry.Labels, map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}) ||
			!equalStringMap(entry.Policy, m2ExpectedPolicy(name)) || !equalStringMap(policyLabels(ns.Labels), entry.Policy) {
			return fmt.Errorf("M2 namespace %s policy mismatch", name)
		}
	}
	return nil
}

func m2NamespacePreflight(results map[string]error) error {
	if len(results) != 2 {
		return fmt.Errorf("both exact namespace names must be inspected")
	}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		err, ok := results[name]
		if !ok || !apierrors.IsNotFound(err) {
			return fmt.Errorf("namespace %s absence is not proven", name)
		}
	}
	return nil
}

func policyLabels(labels map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range labels {
		if strings.HasPrefix(k, "pod-security.kubernetes.io/") {
			out[k] = v
		}
	}
	return out
}
func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func m2CreateLabNamespaces(ctx context.Context) error {
	if err := m2VerifyLabSelection(); err != nil {
		return err
	}
	cfg, err := validateLab(ctx)
	if err != nil {
		return err
	}
	adminConfig = cfg
	identity, err := m2InspectLabIdentity(ctx, cfg)
	if err != nil {
		return err
	}
	return m2ProvisionNamespaces(ctx, admin, m2NativeDir, identity)
}

func m2ProvisionNamespaces(ctx context.Context, c client.Client, dir string, identity m2LabIdentity) error {
	if ctx.Err() != nil || c == nil {
		return fmt.Errorf("namespace setup lacks a live administrator context/client")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("namespace evidence directory is not a private 0700 directory")
	}
	if err := m2CheckNoPendingRecovery(dir); err != nil {
		return err
	}
	receiptPath := filepath.Join(dir, "namespace-receipt.json")
	if _, err := os.Lstat(receiptPath); err == nil {
		return m2VerifyNamespaceReceiptWith(ctx, c, receiptPath, identity)
	} else if !os.IsNotExist(err) {
		return err
	}
	partialPath := filepath.Join(dir, "namespaces.partial.json")
	if _, err := os.Lstat(partialPath); err == nil {
		return fmt.Errorf("unresolved partial namespace setup evidence exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	// Both names must be proven absent before the exclusive marker or any write.
	preflight := map[string]error{}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		var ns corev1.Namespace
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := c.Get(requestCtx, client.ObjectKey{Name: name}, &ns)
		cancel()
		preflight[name] = err
	}
	if err := m2NamespacePreflight(preflight); err != nil {
		return err
	}
	markerName := "recovery-pending.json"
	if caseID := os.Getenv("KEAGUARD_M2_CLUSTER_REPLACEMENT"); caseID != "" {
		if caseID != historicM2ReplacementCase {
			return fmt.Errorf("namespace setup replacement case mismatch")
		}
		markerName = "cluster-replacement-namespace-pending-" + caseID + ".json"
	}
	marker := filepath.Join(dir, markerName)
	markerData, _ := json.Marshal(map[string]string{"phase": "namespace-setup", "cluster": m2LabProfile.cluster, "runID": fmt.Sprintf("%d-%d", time.Now().UTC().UnixNano(), os.Getpid())})
	markerData = append(markerData, '\n')
	if err := writePrivateExclusiveOrReplace(marker, markerData); err != nil {
		return fmt.Errorf("create exclusive namespace setup marker: %w", err)
	}
	receipt := m2NamespaceReceipt{Lab: identity, FixtureLabel: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Namespaces: map[string]m2NamespaceEntry{}}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		labels := map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}
		for k, v := range m2ExpectedPolicy(name) {
			labels[k] = v
		}
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := c.Create(requestCtx, ns)
		cancel()
		if err != nil {
			return fmt.Errorf("create-only namespace %s failed; marker retained: %w", name, err)
		}
		if ns.UID == "" || ns.ResourceVersion == "" {
			return fmt.Errorf("namespace %s Create returned no confirmed UID/resourceVersion; marker retained", name)
		}
		receipt.Namespaces[name] = m2NamespaceEntry{UID: string(ns.UID), Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Policy: m2ExpectedPolicy(name)}
		b, _ := json.Marshal(receipt)
		if err := writePrivateReceipt(partialPath, append(b, '\n')); err != nil {
			return err
		}
	}
	actual := map[string]corev1.Namespace{}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		var ns corev1.Namespace
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := c.Get(requestCtx, client.ObjectKey{Name: name}, &ns)
		cancel()
		if err != nil {
			return err
		}
		actual[name] = ns
	}
	if err := m2NamespaceReceiptMatches(receipt, actual, identity); err != nil {
		return err
	}
	b, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	if err := writePrivateExclusiveOrReplace(receiptPath, append(b, '\n')); err != nil {
		return err
	}
	if err := m2VerifyNamespaceReceiptWith(ctx, c, receiptPath, identity); err != nil {
		return err
	}
	currentMarker, err := readM2PrivateRecord(marker)
	if err != nil || !bytes.Equal(currentMarker, markerData) {
		return fmt.Errorf("namespace setup marker identity changed before completion: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		return err
	}
	return nil
}

func writePrivateExclusiveOrReplace(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refuse to overwrite evidence %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return syncPrivateDirectory(path)
}
func writePrivateReceipt(path string, data []byte) error {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			return fmt.Errorf("unsafe partial receipt")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp := path + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncPrivateDirectory(path)
}

func syncPrivateDirectory(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func m2VerifyLabSelection() error {
	if selectedProfileErr != nil {
		return selectedProfileErr
	}
	if selectedProfile.milestone != "m2" || !selectedProfileMatches(m2LabProfile) {
		return fmt.Errorf("fixed M2 selection required")
	}
	return guardSelection(selectionEnv(), func() error { return nil })
}

func m2Command(ctx context.Context, name string, args ...string) ([]byte, error) {
	return m2CommandWithInput(ctx, nil, name, args...)
}

func m2CommandWithInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, m2DiagnosticCommandDeadline)
	defer cancel()
	return m2RunCommand(bounded, input, name, args...)
}

// Cluster creation is a lifecycle operation, not an eight-second diagnostic.
// Its caller must supply a bounded context (TestKindCreate uses five minutes).
func m2LifecycleCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, fmt.Errorf("M2 lifecycle command %s requires a parent deadline", name)
	}
	return m2RunCommand(ctx, nil, name, args...)
}

func m2RunCommand(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	output := &m2CappedOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	leaked := false
	if cmd.Process != nil {
		var cleanupErr error
		leaked, cleanupErr = m2TerminateOwnedGroup(cmd.Process.Pid)
		if cleanupErr != nil {
			return output.Bytes(), fmt.Errorf("bounded command %s owned process group did not terminate: %w", name, cleanupErr)
		}
	}
	out := output.Bytes()
	if err != nil {
		return out, fmt.Errorf("bounded command %s failed: %w", name, err)
	}
	if leaked {
		return out, fmt.Errorf("bounded command %s left an owned descendant requiring termination", name)
	}
	if output.truncated {
		return out, fmt.Errorf("bounded command %s output exceeded 256 KiB", name)
	}
	return out, nil
}

// The child starts in a new process group. Go reaps the direct child in Wait;
// a descendant can still hold a copied output pipe after the child exits.
// The group identifier remains reserved while any member survives, so only
// members of this command's known group are eligible for termination.
func m2TerminateOwnedGroup(pgid int) (bool, error) {
	if pgid <= 1 {
		return false, fmt.Errorf("invalid owned process group %d", pgid)
	}
	active, err := m2LiveGroupMembers(pgid)
	if err != nil || !active {
		return false, err
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return true, err
	}
	deadline := time.Now().Add(time.Second)
	for {
		active, err = m2LiveGroupMembers(pgid)
		if err != nil || !active {
			return true, err
		}
		if !time.Now().Before(deadline) {
			return true, fmt.Errorf("process group %d still has live members", pgid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func m2LiveGroupMembers(pgid int) (bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		end := bytes.LastIndexByte(data, ')')
		if end < 0 {
			return false, fmt.Errorf("malformed process stat for PID %s", entry.Name())
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) < 3 {
			return false, fmt.Errorf("short process stat for PID %s", entry.Name())
		}
		group, err := strconv.Atoi(fields[2])
		if err != nil {
			return false, err
		}
		if group == pgid && fields[0] != "Z" && fields[0] != "X" {
			return true, nil
		}
	}
	return false, nil
}

type m2CappedOutput struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
}

func (w *m2CappedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	left := 256*1024 - w.buf.Len()
	if left < n {
		w.truncated = true
		if left > 0 {
			_, _ = w.buf.Write(p[:left])
		}
		return n, nil
	}
	_, _ = w.buf.Write(p)
	return n, nil
}

func (w *m2CappedOutput) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

var m2SecretAssignment = regexp.MustCompile(`(?i)(token|password|authorization|client-key-data|client-certificate-data)(\s*[:=]\s*)[^\s,]+`)

func m2RedactEvidence(s string) string {
	s = m2SecretAssignment.ReplaceAllString(s, "$1$2[REDACTED]")
	s = strings.ReplaceAll(s, m2LabProfile.kubeconfig, "[KUBECONFIG-OMITTED]")
	s = strings.ReplaceAll(s, m1LabProfile.kubeconfig, "[KUBECONFIG-OMITTED]")
	return s
}

func m2VerifyManagerImage(ctx context.Context, expectedImage, expectedImageID string) error {
	if expectedImage == "" || expectedImage != os.Getenv("IMG") || expectedImageID == "" {
		return fmt.Errorf("manager image expectation is incomplete")
	}
	out, err := m2Command(ctx, "docker", "image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", expectedImage)
	if err != nil {
		return err
	}
	return m2CheckImageIdentity(string(out), expectedImageID)
}

func m2CheckImageIdentity(output, expectedID string) error {
	if !strings.HasPrefix(expectedID, "sha256:") || !m2FullHexID(strings.TrimPrefix(expectedID, "sha256:")) {
		return fmt.Errorf("manager image ID is not a full canonical SHA-256 digest")
	}
	fields := strings.Split(strings.TrimSpace(output), "|")
	if len(fields) != 3 || fields[0] != expectedID || fields[1] != "linux" || fields[2] != "amd64" {
		return fmt.Errorf("local manager image identity/platform mismatch: %q", strings.TrimSpace(output))
	}
	return nil
}

func TestM2NamespaceSetup(t *testing.T) {
	if os.Getenv("KEAGUARD_M2_NAMESPACE_SETUP") != "1" {
		t.Skip("explicit create-only M2 namespace setup only")
	}
	if err := m2VerifyLabSelection(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cfg, err := validateLab(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	admin, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := m2CreateLabNamespaces(ctx); err != nil {
		t.Fatal(err)
	}
}

func m2InputManifest(ctx context.Context) ([]byte, string, error) {
	rootOut, err := m2Command(ctx, "git", "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, "", err
	}
	root := strings.TrimSpace(string(rootOut))
	if root == "" {
		return nil, "", fmt.Errorf("empty git root")
	}
	names, err := m2Command(ctx, "git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, "", err
	}
	set := map[string]struct{}{}
	for _, b := range strings.Split(string(names), "\x00") {
		if b != "" {
			set[b] = struct{}{}
		}
	}
	paths := make([]string, 0, len(set))
	for p := range set {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var manifest []byte
	for _, name := range paths {
		if !utf8.ValidString(name) {
			return nil, "", fmt.Errorf("input path is not valid UTF-8")
		}
		if strings.ContainsAny(name, "\r\n") {
			return nil, "", fmt.Errorf("unsupported path encoding in %q", name)
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil, "", fmt.Errorf("input escapes repository: %q", name)
		}
		for p := path; p != root; p = filepath.Dir(p) {
			info, e := os.Lstat(p)
			if e != nil {
				if os.IsNotExist(e) {
					break
				}
				return nil, "", e
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, "", fmt.Errorf("symlink input %q", name)
			}
		}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if !info.Mode().IsRegular() {
			return nil, "", fmt.Errorf("nonregular input %q", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, "", err
		}
		sum := sha256.Sum256(data)
		manifest = append(manifest, []byte(name)...)
		manifest = append(manifest, 0)
		manifest = append(manifest, []byte(hex.EncodeToString(sum[:]))...)
		manifest = append(manifest, '\n')
	}
	sum := sha256.Sum256(manifest)
	return manifest, hex.EncodeToString(sum[:]), nil
}

func m2ImageTagForFingerprint(fingerprint string) (string, error) {
	if len(fingerprint) != 64 {
		return "", fmt.Errorf("source fingerprint must contain 64 lowercase hex characters")
	}
	if _, err := hex.DecodeString(fingerprint); err != nil || strings.ToLower(fingerprint) != fingerprint {
		return "", fmt.Errorf("source fingerprint is not canonical SHA-256")
	}
	return "keaguard-operator:m2-" + fingerprint[:12], nil
}
func m2VerifySelectedFingerprintImage(ctx context.Context, image string) (string, error) {
	_, fingerprint, err := m2InputManifest(ctx)
	if err != nil {
		return "", err
	}
	want, err := m2ImageTagForFingerprint(fingerprint)
	if err != nil {
		return "", err
	}
	if image != want {
		return fingerprint, fmt.Errorf("IMG %q is not the complete-input-derived image %q", image, want)
	}
	return fingerprint, nil
}

func readM2PrivateRecord(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("M2 evidence %s must be a non-symlink regular 0600 file", filepath.Base(path))
	}
	return os.ReadFile(path)
}

func m2VerifyBuildEvidence(ctx context.Context, image string) (string, string, error) {
	manifest, fingerprint, err := m2InputManifest(ctx)
	if err != nil {
		return "", "", err
	}
	storedManifest, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "inputs.manifest"))
	if err != nil {
		return "", "", err
	}
	storedFingerprint, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "inputs.sha256"))
	if err != nil {
		return "", "", err
	}
	if string(storedManifest) != string(manifest) || strings.TrimSpace(string(storedFingerprint)) != fingerprint {
		return "", "", fmt.Errorf("M2 build inputs differ from the complete current source fingerprint")
	}
	want, err := m2ImageTagForFingerprint(fingerprint)
	if err != nil {
		return "", "", err
	}
	if image != want {
		return "", "", fmt.Errorf("selected IMG does not match complete source fingerprint")
	}
	iidBytes, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "manager-image.iid"))
	if err != nil {
		return "", "", err
	}
	expectedID := strings.TrimSpace(string(iidBytes))
	if expectedID == "" || strings.ContainsAny(expectedID, "\r\n ") {
		return "", "", fmt.Errorf("invalid build-written image ID")
	}
	identity, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "manager-image.identity"))
	if err != nil {
		return "", "", err
	}
	if err := m2CheckImageIdentity(string(identity), expectedID); err != nil {
		return "", "", err
	}
	if err := m2VerifyManagerImage(ctx, image, expectedID); err != nil {
		return "", "", err
	}
	return fingerprint, expectedID, nil
}

func m2VerifyNodeImage(ctx context.Context, image, expectedID string) error {
	lab, err := m2InspectLabIdentity(ctx, adminConfig)
	if err != nil {
		return err
	}
	for _, node := range m2LabProfile.nodes {
		if _, err := m2VerifyOperatorNodeOCI(ctx, lab.Nodes[node].DockerID, image, expectedID); err != nil {
			return fmt.Errorf("node %s operator OCI identity: %w", node, err)
		}
	}
	return nil
}

func m2VerifyManagerDeployment(ctx context.Context, expectedImage, expectedID string) error {
	lab, err := m2InspectLabIdentity(ctx, adminConfig)
	if err != nil {
		return err
	}
	var deployment appsv1.Deployment
	if err := m2GetSnapshot(ctx, client.ObjectKey{Namespace: m2LabProfile.runtimeNamespace, Name: managerName}, &deployment); err != nil {
		return err
	}
	if deployment.UID == "" || deployment.Generation < 1 || deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.ReadyReplicas != 1 || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Spec.Template.Spec.ServiceAccountName != managerName || len(deployment.Spec.Template.Spec.Containers) != 1 || deployment.Spec.Template.Spec.Containers[0].Image != expectedImage {
		return fmt.Errorf("live manager Deployment does not match the verified one-replica image/identity contract")
	}
	var pods corev1.PodList
	if err := m2ListSnapshot(ctx, &pods, client.InNamespace(m2LabProfile.runtimeNamespace), client.MatchingLabels(deployment.Spec.Selector.MatchLabels)); err != nil {
		return err
	}
	if len(pods.Items) != 1 {
		return fmt.Errorf("expected exactly one manager Pod, observed %d", len(pods.Items))
	}
	pod := pods.Items[0]
	if pod.UID == "" || pod.Spec.NodeName == "" || !containsString(m2LabProfile.nodes, pod.Spec.NodeName) || pod.Spec.ServiceAccountName != managerName || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "manager" || pod.Spec.Containers[0].Image != expectedImage || pod.Status.Phase != corev1.PodRunning || !podReady(&pod) || pod.Labels == nil || !labels.Set(deployment.Spec.Selector.MatchLabels).AsSelectorPreValidated().Matches(labels.Set(pod.Labels)) {
		return fmt.Errorf("manager Pod is not the sole current ready selected incarnation")
	}
	owner := metav1.GetControllerOf(&pod)
	if owner == nil || owner.APIVersion != appsv1.SchemeGroupVersion.String() || owner.Kind != "ReplicaSet" || owner.Name == "" || owner.UID == "" {
		return fmt.Errorf("manager Pod lacks ReplicaSet owner identity")
	}
	var rs appsv1.ReplicaSet
	if err := m2GetSnapshot(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, &rs); err != nil {
		return err
	}
	rsOwner := metav1.GetControllerOf(&rs)
	if rs.UID != owner.UID || rsOwner == nil || rsOwner.APIVersion != appsv1.SchemeGroupVersion.String() || rsOwner.Kind != "Deployment" || rsOwner.Name != deployment.Name || rsOwner.UID != deployment.UID || len(rs.Spec.Template.Spec.Containers) != 1 || rs.Spec.Template.Spec.Containers[0].Image != expectedImage {
		return fmt.Errorf("manager ReplicaSet owner chain does not match Deployment UID")
	}
	var status *corev1.ContainerStatus
	for i := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[i].Name == "manager" {
			status = &pod.Status.ContainerStatuses[i]
			break
		}
	}
	if status == nil || status.ContainerID == "" || status.ImageID == "" || status.Image == "" || !status.Ready {
		return fmt.Errorf("manager Pod container identity is missing or stale")
	}
	containerID := strings.TrimPrefix(status.ContainerID, "containerd://")
	if !m2FullHexID(containerID) || containerID == status.ContainerID {
		return fmt.Errorf("manager container is not a containerd incarnation")
	}
	node, ok := lab.Nodes[pod.Spec.NodeName]
	if !ok || node.KubernetesUID == "" {
		return fmt.Errorf("manager Pod node is not bound to reviewed Kind identity")
	}
	identity, err := m2VerifyOperatorNodeOCI(ctx, node.DockerID, expectedImage, expectedID)
	if err != nil {
		return fmt.Errorf("running manager node OCI identity: %w", err)
	}
	out, err := m2Command(ctx, "docker", "exec", node.DockerID, "crictl", "inspect", "-o", "json", containerID)
	if err != nil {
		return err
	}
	if err := m2CheckManagerContainerCRI(out, containerID, identity.ConfigID); err != nil {
		return fmt.Errorf("running CRI container image identity differs from verified OCI config: %w", err)
	}
	if err := m2CheckManagerCRIBinding(out, &pod, status, expectedImage); err != nil {
		return fmt.Errorf("running CRI container/Pod binding: %w", err)
	}
	for _, ref := range []string{status.ImageID, status.Image} {
		if err := m2VerifyOperatorDisplayReference(ctx, node.DockerID, ref, identity); err != nil {
			return fmt.Errorf("running manager display reference %q: %w", ref, err)
		}
	}
	lastCRI, err := m2Command(ctx, "docker", "exec", node.DockerID, "crictl", "inspect", "-o", "json", containerID)
	if err != nil || m2CheckManagerContainerCRI(lastCRI, containerID, identity.ConfigID) != nil || m2CheckManagerCRIBinding(lastCRI, &pod, status, expectedImage) != nil {
		return fmt.Errorf("running CRI container incarnation changed during attestation: %v", err)
	}
	var current corev1.Pod
	if err := m2GetSnapshot(ctx, client.ObjectKeyFromObject(&pod), &current); err != nil {
		return err
	}
	found := false
	for _, currentStatus := range current.Status.ContainerStatuses {
		if currentStatus.Name == "manager" && currentStatus.Image == status.Image && currentStatus.Ready && m2CheckManagerIncarnation(string(pod.UID), status.ContainerID, status.ImageID, string(current.UID), currentStatus.ContainerID, currentStatus.ImageID) == nil {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("manager container incarnation changed during image verification")
	}
	currentOwner := metav1.GetControllerOf(&current)
	if len(current.Spec.Containers) != 1 || current.Spec.Containers[0].Image != expectedImage || current.Spec.NodeName != pod.Spec.NodeName || currentOwner == nil || currentOwner.APIVersion != appsv1.SchemeGroupVersion.String() || currentOwner.Kind != "ReplicaSet" || currentOwner.Name != rs.Name || currentOwner.UID != rs.UID || current.Status.Phase != corev1.PodRunning || !podReady(&current) {
		return fmt.Errorf("manager Pod spec/node/owner changed during attestation")
	}
	var currentDeployment appsv1.Deployment
	var currentRS appsv1.ReplicaSet
	if err := m2GetSnapshot(ctx, client.ObjectKeyFromObject(&deployment), &currentDeployment); err != nil {
		return err
	}
	if err := m2GetSnapshot(ctx, client.ObjectKeyFromObject(&rs), &currentRS); err != nil {
		return err
	}
	currentRSOwner := metav1.GetControllerOf(&currentRS)
	if currentDeployment.UID != deployment.UID || currentDeployment.Generation != deployment.Generation || currentDeployment.Status.ObservedGeneration < currentDeployment.Generation || currentDeployment.Status.ReadyReplicas != 1 || len(currentDeployment.Spec.Template.Spec.Containers) != 1 || currentDeployment.Spec.Template.Spec.Containers[0].Image != expectedImage || currentRS.UID != rs.UID || currentRSOwner == nil || currentRSOwner.APIVersion != appsv1.SchemeGroupVersion.String() || currentRSOwner.Kind != "Deployment" || currentRSOwner.Name != currentDeployment.Name || currentRSOwner.UID != currentDeployment.UID || len(currentRS.Spec.Template.Spec.Containers) != 1 || currentRS.Spec.Template.Spec.Containers[0].Image != expectedImage {
		return fmt.Errorf("manager ReplicaSet/Deployment incarnation changed during attestation")
	}
	var currentPods corev1.PodList
	if err := m2ListSnapshot(ctx, &currentPods, client.InNamespace(m2LabProfile.runtimeNamespace), client.MatchingLabels(deployment.Spec.Selector.MatchLabels)); err != nil {
		return err
	}
	if len(currentPods.Items) != 1 || currentPods.Items[0].UID != pod.UID {
		return fmt.Errorf("manager Pod selection changed during attestation")
	}
	return nil
}

func m2CheckManagerCRIBinding(data []byte, pod *corev1.Pod, status *corev1.ContainerStatus, expectedImage string) error {
	if pod == nil || status == nil || pod.UID == "" || pod.Name == "" || pod.Namespace == "" || expectedImage == "" || status.Image == "" || status.ImageID == "" {
		return fmt.Errorf("manager CRI/Pod binding lacks an exact incarnation")
	}
	var record struct {
		Status struct {
			ImageRef string `json:"imageRef"`
			Image    struct {
				Image string `json:"image"`
			} `json:"image"`
			Labels map[string]string `json:"labels"`
		} `json:"status"`
		Info struct {
			Config struct {
				Image struct {
					UserSpecifiedImage string `json:"user_specified_image"`
				} `json:"image"`
				Labels map[string]string `json:"labels"`
			} `json:"config"`
			RuntimeSpec struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"runtimeSpec"`
		} `json:"info"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}
	if record.Status.ImageRef != status.ImageID || record.Status.Image.Image != status.Image || record.Info.Config.Image.UserSpecifiedImage != expectedImage || record.Info.RuntimeSpec.Annotations["io.kubernetes.cri.image-name"] != expectedImage {
		return fmt.Errorf("manager CRI requested/display image differs from current Pod")
	}
	labels := map[string]string{"io.kubernetes.container.name": "manager", "io.kubernetes.pod.name": pod.Name, "io.kubernetes.pod.namespace": pod.Namespace, "io.kubernetes.pod.uid": string(pod.UID)}
	for key, value := range labels {
		if record.Status.Labels[key] != value || record.Info.Config.Labels[key] != value {
			return fmt.Errorf("manager CRI labels differ from current Pod identity")
		}
	}
	annotations := map[string]string{"io.kubernetes.cri.container-name": "manager", "io.kubernetes.cri.sandbox-name": pod.Name, "io.kubernetes.cri.sandbox-namespace": pod.Namespace, "io.kubernetes.cri.sandbox-uid": string(pod.UID)}
	for key, value := range annotations {
		if record.Info.RuntimeSpec.Annotations[key] != value {
			return fmt.Errorf("manager CRI sandbox differs from current Pod identity")
		}
	}
	return nil
}

func m2CheckManagerContainerCRI(data []byte, containerID, expectedID string) error {
	if !m2FullHexID(containerID) || !m2ValidSHA256Digest(expectedID) {
		return fmt.Errorf("manager CRI verification lacks full container/image identity")
	}
	var container struct {
		Status struct {
			ID      string `json:"id"`
			State   string `json:"state"`
			ImageID string `json:"imageId"`
		} `json:"status"`
		Info struct {
			Config struct {
				Image struct {
					Image string `json:"image"`
				} `json:"image"`
			} `json:"config"`
			SnapshotKey string `json:"snapshotKey"`
		} `json:"info"`
	}
	if err := json.Unmarshal(data, &container); err != nil {
		return err
	}
	if container.Status.ID != containerID || container.Status.State != "CONTAINER_RUNNING" || container.Status.ImageID != expectedID || container.Info.Config.Image.Image != expectedID || container.Info.SnapshotKey != containerID {
		return fmt.Errorf("manager CRI container/image identity mismatch")
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}
