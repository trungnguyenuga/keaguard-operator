package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

func m2ReplacementFixtureLab(prefix string) m2LabIdentity {
	imageID := strings.TrimPrefix(m2LabProfile.nodeImage, "kindest/node:v1.37.0@")
	ca, port, base := "b", 35423, '1'
	if prefix == "new" {
		ca, port, base = "c", 35424, '4'
	}
	identity := m2LabIdentity{Cluster: m2LabProfile.cluster, Server: fmt.Sprintf("https://127.0.0.1:%d", port), CASHA256: strings.Repeat(ca, 64), Nodes: map[string]m2NodeIdentity{}}
	for i, name := range m2LabProfile.nodes {
		identity.Nodes[name] = m2NodeIdentity{KubernetesUID: prefix + "-uid-" + string(rune('1'+i)), DockerID: strings.Repeat(string(base+rune(i)), 64), Image: m2LabProfile.nodeImage, ImageID: imageID}
	}
	return identity
}
func m2ReplacementFixtureNamespaces(prefix string) map[string]m2NamespaceEntry {
	return map[string]m2NamespaceEntry{m2LabProfile.runtimeNamespace: {UID: prefix + "-runtime", Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Policy: m2ExpectedPolicy(m2LabProfile.runtimeNamespace)}, m2LabProfile.outsideNamespace: {UID: prefix + "-outside", Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Policy: m2ExpectedPolicy(m2LabProfile.outsideNamespace)}}
}
func m2ReplacementFixtureVolumes(prefix string) map[string]string {
	out := map[string]string{}
	for i, name := range m2LabProfile.nodes {
		out[name] = strings.Repeat(string(rune('7'+i)), 64)
		if prefix == "new" {
			out[name] = strings.Repeat(string(rune('a'+i)), 64)
		}
	}
	return out
}

type fakeM2ReplacementOps struct {
	preflightCalls                         int
	keaPreflightCalls                      int
	teardownCalls                          int
	verifyTeardownCalls                    int
	createCalls                            int
	namespaceCalls                         int
	fail                                   string
	markerHash, ledgerHash, diagnosticHash string
	finalCalls                             int
	dir                                    string
	preflightMismatchOnRevalidate          bool
	namespaceReceiptPath                   string
}

func (f *fakeM2ReplacementOps) preflight(context.Context) (m2ReplacementPreflight, error) {
	f.preflightCalls++
	if f.fail == "preflight" {
		return m2ReplacementPreflight{}, errors.New("preflight mismatch")
	}
	refs := []m2ReplacementResourceRef{{Resource: "namespaces", Name: "default", UID: "default-uid"}}
	data, _ := json.Marshal(refs)
	inventoryPath := filepath.Join(f.dir, "cluster-replacement-resource-inventory-"+historicM2ReplacementCase+".json")
	if existing, err := readM2PrivateRecord(inventoryPath); err == nil {
		if string(existing) != string(append(data, '\n')) {
			return m2ReplacementPreflight{}, errors.New("inventory changed")
		}
	} else if os.IsNotExist(err) {
		if err := writePrivateExclusiveOrReplace(inventoryPath, append(data, '\n')); err != nil {
			return m2ReplacementPreflight{}, err
		}
	} else {
		return m2ReplacementPreflight{}, err
	}
	result := m2ReplacementPreflight{CaseID: historicM2ReplacementCase, Status: "VERIFIED_OLD_LAB_PREFLIGHT", OldCluster: m2LabProfile.cluster, OldLab: m2ReplacementFixtureLab("old"), OldNamespaces: m2ReplacementFixtureNamespaces("old"), OldVolumes: m2ReplacementFixtureVolumes("old"), ResourceInventorySHA256: m2ReplacementInventoryHash(refs), ResourceInventoryCount: len(refs), MarkerSHA256: f.markerHash, LedgerSHA256: f.ledgerHash, DiagnosticsSHA256: f.diagnosticHash, M1DockerID: strings.Repeat("d", 64), M1Image: m2LabProfile.nodeImage, Quiescent: true}
	namespaceReceipt := m2NamespaceReceipt{Lab: result.OldLab, FixtureLabel: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Namespaces: result.OldNamespaces}
	namespaceBytes, err := json.Marshal(namespaceReceipt)
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	namespacePath := filepath.Join(f.dir, "namespace-receipt.json")
	if existing, readErr := readM2PrivateRecord(namespacePath); readErr == nil {
		if !bytes.Equal(existing, append(namespaceBytes, '\n')) {
			return m2ReplacementPreflight{}, errors.New("old namespace receipt changed")
		}
	} else if os.IsNotExist(readErr) {
		if err := writePrivateExclusiveOrReplace(namespacePath, append(namespaceBytes, '\n')); err != nil {
			return m2ReplacementPreflight{}, err
		}
	} else {
		return m2ReplacementPreflight{}, readErr
	}
	result.NamespaceReceiptSHA256 = m2SHA256(append(namespaceBytes, '\n'))
	if f.preflightMismatchOnRevalidate && f.preflightCalls > 1 {
		result.M1DockerID = strings.Repeat("e", 64)
	}
	return result, nil
}

func (f *fakeM2ReplacementOps) approvedKeaImages(context.Context) (map[string]string, error) {
	f.keaPreflightCalls++
	if f.fail == "kea-preflight" {
		return nil, errors.New("local image identity mismatch")
	}
	return m2ReplacementKeaConfigIDs(), nil
}

func m2ReplacementKeaConfigIDs() map[string]string {
	ids := map[string]string{}
	for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
		ids[image], _ = m2KeaExpectedConfigID(image)
	}
	return ids
}

func m2ReplacementKeaConfigIDFixture() map[string]map[string]string {
	ids := map[string]map[string]string{}
	for _, node := range m2LabProfile.nodes {
		ids[node] = map[string]string{}
		for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
			ids[node][image], _ = m2KeaExpectedConfigID(image)
		}
	}
	return ids
}

func TestUnitM2ReplacementLocalKeaDockerIdentityDistinguishesManifestAndConfig(t *testing.T) {
	for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
		configID, ok := m2KeaExpectedConfigID(image)
		if !ok {
			t.Fatalf("missing approved config mapping for %s", image)
		}
		manifestID := "sha256:" + strings.SplitN(image, "@sha256:", 2)[1]
		t.Run(strings.TrimPrefix(strings.SplitN(image, "/", 4)[3], "kea-"), func(t *testing.T) {
			for _, imageID := range []string{manifestID, configID} {
				got, err := m2ValidateLocalDockerKeaIdentity(image, imageID, "linux", "amd64", []string{image})
				if err != nil || got != configID {
					t.Fatalf("approved manifest/config identity %s rejected: got=%q err=%v", imageID, got, err)
				}
			}
		})
	}
}

func TestUnitM2ReplacementLocalKeaDockerIdentityRejectsUnrelatedOrAmbiguousObjects(t *testing.T) {
	image := m2KeaDHCP4Image
	configID, _ := m2KeaExpectedConfigID(image)
	for name, tc := range map[string]struct {
		imageID     string
		os          string
		arch        string
		repoDigests []string
	}{
		"wrong manifest digest":       {imageID: "sha256:" + strings.Repeat("f", 64), os: "linux", arch: "amd64", repoDigests: []string{image}},
		"wrong config digest":         {imageID: "sha256:" + strings.Repeat("e", 64), os: "linux", arch: "amd64", repoDigests: []string{image}},
		"wrong platform":              {imageID: configID, os: "linux", arch: "arm64", repoDigests: []string{image}},
		"missing repository identity": {imageID: configID, os: "linux", arch: "amd64"},
		"extra repository identity":   {imageID: configID, os: "linux", arch: "amd64", repoDigests: []string{image, "docker.io/library/kea:latest"}},
		"unknown image reference":     {imageID: configID, os: "linux", arch: "amd64", repoDigests: []string{strings.Replace(image, "dhcp4", "dhcp5", 1)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := m2ValidateLocalDockerKeaIdentity(image, tc.imageID, tc.os, tc.arch, tc.repoDigests); err == nil {
				t.Fatal("unrelated or ambiguous local image identity was accepted")
			}
		})
	}
}

func m2PrepareReplacementWorkflow(t *testing.T, dir string) (*fakeM2ReplacementOps, m2ReplacementWorkflow) {
	t.Helper()
	marker := []byte(`{"caseID":"` + historicM2ReplacementCase + `","phase":"scenario"}` + "\n")
	ledger := []byte(`{"historicServiceCreateOutcome":"UNKNOWN","phase":"unresolved"}` + "\n")
	diagnostic := []byte(`{"caseID":"` + historicM2ReplacementCase + `","status":"skipped-recovery-incomplete"}` + "\n")
	for name, data := range map[string][]byte{"recovery-pending.json": marker, "ledger.json": ledger, "diagnostics.json": diagnostic, "diagnostics-" + historicM2ReplacementCase + ".json": diagnostic} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ops := &fakeM2ReplacementOps{markerHash: m2SHA256(marker), ledgerHash: m2SHA256(ledger), diagnosticHash: m2SHA256(diagnostic), dir: dir}
	return ops, m2ReplacementWorkflow{dir: dir, caseID: historicM2ReplacementCase, ops: ops, expectedMarker: ops.markerHash, expectedLedger: ops.ledgerHash, expectedDiagnostics: ops.diagnosticHash}
}
func (f *fakeM2ReplacementOps) teardown(context.Context, m2ReplacementPreflight) (m2ReplacementTeardown, error) {
	f.teardownCalls++
	if f.fail == "teardown-not-submitted" {
		return m2ReplacementTeardown{Status: "NOT_SUBMITTED"}, errors.New("pre-delete check refused before command submission")
	}
	if f.fail == "teardown-blank-status" {
		return m2ReplacementTeardown{}, errors.New("teardown outcome classification absent")
	}
	if f.fail == "teardown" {
		return m2ReplacementTeardown{Status: "DELETE_ACK_UNKNOWN"}, errors.New("lost delete acknowledgement")
	}
	if f.fail == "partial-teardown" {
		return m2ReplacementTeardown{Status: "PARTIAL_OR_UNVERIFIED", OldClusterAbsent: true, OldContainersAbsent: true, OldVolumesAbsent: false, M1DockerID: strings.Repeat("d", 64)}, nil
	}
	return m2ReplacementTeardown{Status: "VERIFIED_OLD_LAB_ABSENT", OldClusterAbsent: true, OldContainersAbsent: true, OldVolumesAbsent: true, M1DockerID: strings.Repeat("d", 64)}, nil
}
func (f *fakeM2ReplacementOps) verifyTeardown(context.Context, m2ReplacementPreflight) (m2ReplacementTeardown, error) {
	f.verifyTeardownCalls++
	if f.fail == "observation-failed" {
		return m2ReplacementTeardown{}, errors.New("old node identity is still present")
	}
	return m2ReplacementTeardown{Status: "VERIFIED_OLD_LAB_ABSENT", OldClusterAbsent: true, OldContainersAbsent: true, OldVolumesAbsent: true, M1DockerID: strings.Repeat("d", 64)}, nil
}

func TestUnitM2ReplacementWorkflowAllowsAppendOnlyResumeOnlyAfterProvenNotSubmitted(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	for _, step := range []func() error{
		func() error { return wf.preflight(context.Background()) },
		func() error { return wf.revalidatePreflight(context.Background()) },
		func() error { return wf.verifyKeaImages(context.Background()) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	ops.fail = "teardown-not-submitted"
	if err := wf.teardown(context.Background()); err == nil {
		t.Fatal("pre-delete refusal was reported as a successful teardown")
	}
	firstIntent, err := readM2PrivateRecord(wf.path("teardown-intent"))
	if err != nil {
		t.Fatal(err)
	}
	firstReceipt, err := readM2PrivateRecord(wf.path("teardown"))
	if err != nil {
		t.Fatal(err)
	}
	var failed map[string]any
	if err := json.Unmarshal(firstReceipt, &failed); err != nil || failed["status"] != "NOT_SUBMITTED" {
		t.Fatalf("pre-delete refusal was not distinctly recorded: %v", failed)
	}
	ops.fail = ""
	if err := wf.teardown(context.Background()); err != nil {
		t.Fatalf("verified NOT_SUBMITTED attempt did not permit append-only continuation: %v", err)
	}
	currentIntent, err := readM2PrivateRecord(wf.path("teardown-intent"))
	if err != nil || !bytes.Equal(firstIntent, currentIntent) {
		t.Fatalf("original teardown intent changed: %v", err)
	}
	currentReceipt, err := readM2PrivateRecord(wf.path("teardown"))
	if err != nil || !bytes.Equal(firstReceipt, currentReceipt) {
		t.Fatalf("original NOT_SUBMITTED receipt changed: %v", err)
	}
	for _, stage := range []string{"teardown-intent-attempt-2", "teardown-attempt-2"} {
		if _, err := os.Lstat(wf.path(stage)); err != nil {
			t.Fatalf("missing append-only retry evidence %s: %v", stage, err)
		}
	}
	if err := wf.create(context.Background()); err != nil {
		t.Fatalf("creation did not consume the independently verified latest teardown receipt: %v", err)
	}
	if ops.teardownCalls != 2 || ops.createCalls != 1 {
		t.Fatalf("unexpected operation ordering/calls: %+v", ops)
	}
}

func TestUnitM2ReplacementWorkflowRefusesRetryAfterAmbiguousOrInterruptedTeardown(t *testing.T) {
	for _, mode := range []string{"ambiguous", "blank-status", "interrupted-retry", "out-of-order-retry"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			ops, wf := m2PrepareReplacementWorkflow(t, dir)
			for _, step := range []func() error{
				func() error { return wf.preflight(context.Background()) },
				func() error { return wf.revalidatePreflight(context.Background()) },
				func() error { return wf.verifyKeaImages(context.Background()) },
			} {
				if err := step(); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "ambiguous" {
				ops.fail = "teardown"
			} else if mode == "blank-status" {
				ops.fail = "teardown-blank-status"
			} else {
				ops.fail = "teardown-not-submitted"
			}
			if err := wf.teardown(context.Background()); err == nil {
				t.Fatal("failed teardown attempt was accepted")
			}
			ops.fail = ""
			if mode == "interrupted-retry" {
				if err := wf.write("teardown-intent-attempt-2", map[string]string{"status": "TEARDOWN_ONCE"}); err != nil {
					t.Fatal(err)
				}
			} else if mode == "out-of-order-retry" {
				if err := wf.write("teardown-intent-attempt-3", map[string]string{"status": "TEARDOWN_ONCE"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := wf.teardown(context.Background()); err == nil {
				t.Fatal("ambiguous or interrupted teardown was replayed")
			}
			if ops.teardownCalls != 1 {
				t.Fatalf("unsafe retry reached live operation: calls=%d", ops.teardownCalls)
			}
		})
	}
}

func TestUnitM2ReplacementWorkflowReconcilesPartialTeardownWithoutRepeatingDelete(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	for _, step := range []func() error{
		func() error { return wf.preflight(context.Background()) },
		func() error { return wf.revalidatePreflight(context.Background()) },
		func() error { return wf.verifyKeaImages(context.Background()) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	ops.fail = "partial-teardown"
	if err := wf.teardown(context.Background()); err == nil {
		t.Fatal("partial teardown was accepted")
	}
	partialBefore, err := readM2PrivateRecord(wf.path("teardown"))
	if err != nil {
		t.Fatal(err)
	}
	if err := wf.teardown(context.Background()); err == nil {
		t.Fatal("partial destructive outcome was replayed")
	}
	if ops.teardownCalls != 1 {
		t.Fatalf("delete operation repeated after partial outcome: %d calls", ops.teardownCalls)
	}
	ops.fail = ""
	if err := wf.reconcileTeardown(context.Background()); err != nil {
		t.Fatalf("read-only exact-absence reconciliation failed: %v", err)
	}
	partialAfter, err := readM2PrivateRecord(wf.path("teardown"))
	if err != nil || !bytes.Equal(partialBefore, partialAfter) {
		t.Fatalf("original partial receipt was overwritten: %v", err)
	}
	if err := wf.create(context.Background()); err != nil {
		t.Fatalf("create did not consume the separate verified reconciliation receipt: %v", err)
	}
	if ops.teardownCalls != 1 || ops.verifyTeardownCalls != 1 || ops.createCalls != 1 {
		t.Fatalf("unexpected operation sequence: %+v", ops)
	}
}

func TestUnitM2ReplacementWorkflowRefusesUnverifiedOrTamperedTeardownReconciliation(t *testing.T) {
	for _, mode := range []string{"observation-failed", "tampered-partial"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			ops, wf := m2PrepareReplacementWorkflow(t, dir)
			for _, step := range []func() error{
				func() error { return wf.preflight(context.Background()) },
				func() error { return wf.revalidatePreflight(context.Background()) },
				func() error { return wf.verifyKeaImages(context.Background()) },
			} {
				if err := step(); err != nil {
					t.Fatal(err)
				}
			}
			ops.fail = "partial-teardown"
			if err := wf.teardown(context.Background()); err == nil {
				t.Fatal("partial teardown was accepted")
			}
			ops.fail = mode
			if mode == "tampered-partial" {
				if err := os.WriteFile(wf.path("teardown"), []byte(`{"status":"VERIFIED_OLD_LAB_ABSENT"}`+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := wf.reconcileTeardown(context.Background()); err == nil {
				t.Fatal("unverified or tampered partial teardown was accepted")
			}
			if ops.createCalls != 0 {
				t.Fatal("creation followed an unverified teardown reconciliation")
			}
			if _, err := os.Lstat(wf.path("teardown-reconciled")); !os.IsNotExist(err) {
				t.Fatalf("failed reconciliation wrote a successful receipt: %v", err)
			}
		})
	}
}

func TestUnitM2ReplacementNotFoundUsesCapturedCommandOutput(t *testing.T) {
	for _, tc := range []struct {
		name, output, identity string
		want                   bool
	}{
		{name: "docker object absence", output: "error: no such object: deadbeef", identity: "deadbeef", want: true},
		{name: "volume absence case insensitive", output: "Error response from daemon: get deadbeef: no such volume", identity: "deadbeef", want: true},
		{name: "wrong identity", output: "error: no such object: other", identity: "deadbeef", want: false},
		{name: "unrelated failure", output: "permission denied", identity: "deadbeef", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := m2CommandOutputConfirmsAbsent(tc.output, tc.identity); got != tc.want {
				t.Fatalf("absence classification=%t want %t", got, tc.want)
			}
		})
	}
}

func TestUnitM2ReplacementAbsenceRequiresCommandErrorAndMatchingCapturedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, output, identity string
		commandErr             error
		wantErr                bool
	}{
		{name: "exact docker absence", output: "error: no such object: deadbeef", identity: "deadbeef", commandErr: errors.New("exit status 1")},
		{name: "exact volume absence", output: "no such volume deadbeef", identity: "deadbeef", commandErr: errors.New("exit status 1")},
		{name: "still present", output: "deadbeef", identity: "deadbeef", commandErr: nil, wantErr: true},
		{name: "wrong object", output: "no such object: other", identity: "deadbeef", commandErr: errors.New("exit status 1"), wantErr: true},
		{name: "unrelated error", output: "permission denied deadbeef", identity: "deadbeef", commandErr: errors.New("exit status 1"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotErr := m2RequireCommandAbsence([]byte(tc.output), tc.commandErr, tc.identity)
			if (gotErr != nil) != tc.wantErr {
				t.Fatalf("absence result error=%v wantErr=%t", gotErr, tc.wantErr)
			}
		})
	}
}

func TestUnitM2ReplacementAdminClientIsInitializedBeforeLabIdentityObservation(t *testing.T) {
	priorAdmin, priorConfig := admin, adminConfig
	t.Cleanup(func() { admin, adminConfig = priorAdmin, priorConfig })
	admin, adminConfig = nil, nil
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cfg := &rest.Config{Host: "https://127.0.0.1:6443", TLSClientConfig: rest.TLSClientConfig{CAData: ca}}
	if err := m2InitializeReplacementAdmin(cfg); err != nil {
		t.Fatal(err)
	}
	if admin == nil || adminConfig != cfg {
		t.Fatal("replacement identity observation would run without its configured administrator client")
	}
}

func TestUnitM2ReplacementFinalIdentityObservationInitializesFreshAdmin(t *testing.T) {
	priorAdmin, priorConfig := admin, adminConfig
	t.Cleanup(func() { admin, adminConfig = priorAdmin, priorConfig })
	admin, adminConfig = nil, nil
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cfg := &rest.Config{Host: "https://127.0.0.1:6443", TLSClientConfig: rest.TLSClientConfig{CAData: ca}}
	observed, err := m2WithReplacementLabIdentity(context.Background(), cfg, func(_ context.Context, gotConfig *rest.Config) (m2LabIdentity, error) {
		if admin == nil || adminConfig != gotConfig || gotConfig != cfg {
			return m2LabIdentity{}, errors.New("identity observation ran before admin initialization")
		}
		return m2ReplacementFixtureLab("new"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observed, m2ReplacementFixtureLab("new")) {
		t.Fatal("replacement lab identity was not returned from the fresh observation")
	}
}

func TestUnitM2ReplacementLiveTeardownClassifiesOnlyPreSubmissionRefusal(t *testing.T) {
	got, err := (m2LiveReplacementOps{}).teardown(context.Background(), m2ReplacementPreflight{})
	if err == nil || got.Status != "NOT_SUBMITTED" {
		t.Fatalf("invalid preflight must be classified as definitively not submitted, got status=%q err=%v", got.Status, err)
	}
}

func TestUnitM2ReplacementNamespaceProvisioningInitializesFreshAdminClient(t *testing.T) {
	priorAdmin, priorConfig := admin, adminConfig
	t.Cleanup(func() { admin, adminConfig = priorAdmin, priorConfig })
	admin, adminConfig = nil, nil
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cfg := &rest.Config{Host: "https://127.0.0.1:6443", TLSClientConfig: rest.TLSClientConfig{CAData: ca}}
	runCalled := false
	if err := m2WithReplacementNamespaceAdmin(context.Background(), cfg, func(context.Context) error {
		runCalled = true
		if admin == nil || adminConfig != cfg {
			return errors.New("namespace callback ran without its initialized live administrator")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !runCalled {
		t.Fatal("namespace provisioning callback was not invoked")
	}
}

func TestUnitM2ReplacementNamespaceBootstrapRejectsClusterOrM1IncarnationChanges(t *testing.T) {
	created := m2ReplacementCreated{Status: "VERIFIED_NEW_LAB", NewLab: m2ReplacementFixtureLab("new"), M1DockerID: strings.Repeat("d", 64)}
	if err := m2VerifyReplacementNamespaceBootstrapIdentity(m2ReplacementFixtureLab("new"), created.M1DockerID, created); err != nil {
		t.Fatalf("exact replacement/M1 identity rejected: %v", err)
	}
	changedLab := m2ReplacementFixtureLab("new")
	changedLab.Nodes[m2LabProfile.nodes[0]] = m2NodeIdentity{DockerID: strings.Repeat("f", 64)}
	for name, tc := range map[string]struct {
		observed m2LabIdentity
		m1ID     string
		created  m2ReplacementCreated
	}{
		"changed node incarnation": {observed: changedLab, m1ID: created.M1DockerID, created: created},
		"changed M1":               {observed: created.NewLab, m1ID: strings.Repeat("e", 64), created: created},
		"unverified creation":      {observed: created.NewLab, m1ID: created.M1DockerID, created: m2ReplacementCreated{NewLab: created.NewLab, M1DockerID: created.M1DockerID}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := m2VerifyReplacementNamespaceBootstrapIdentity(tc.observed, tc.m1ID, tc.created); err == nil {
				t.Fatal("changed or unverified lab identity accepted")
			}
		})
	}
}

func (f *fakeM2ReplacementOps) create(context.Context, m2ReplacementPreflight, m2ReplacementTeardown) (m2ReplacementCreated, error) {
	f.createCalls++
	if f.fail == "create-not-submitted" {
		return m2ReplacementCreated{}, errors.New("M2 build inputs differ from the complete current source fingerprint")
	}
	if f.fail == "create" {
		return m2ReplacementCreated{Status: "CREATE_ACK_UNKNOWN"}, errors.New("create outcome unknown")
	}
	return m2ReplacementCreated{Status: "VERIFIED_NEW_LAB", NewLab: m2ReplacementFixtureLab("new"), NewVolumes: m2ReplacementFixtureVolumes("new"), KeaConfigIDs: m2ReplacementKeaConfigIDFixture(), M1DockerID: strings.Repeat("d", 64)}, nil
}

func TestUnitM2ReplacementCreateContinuationUsesOnlyOneExactNotSubmittedIntent(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	for _, step := range []func() error{
		func() error { return wf.preflight(context.Background()) },
		func() error { return wf.revalidatePreflight(context.Background()) },
		func() error { return wf.verifyKeaImages(context.Background()) },
		func() error { return wf.teardown(context.Background()) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	ops.fail = "create-not-submitted"
	if err := wf.create(context.Background()); err == nil {
		t.Fatal("initial pre-submission failure was accepted")
	}
	intentBefore, err := readM2PrivateRecord(wf.path("create-intent"))
	if err != nil {
		t.Fatal(err)
	}
	receiptBefore, err := readM2PrivateRecord(wf.path("created"))
	if err != nil {
		t.Fatal(err)
	}
	ops.fail = ""
	if err := wf.resumeUnsubmittedCreate(context.Background()); err != nil {
		t.Fatalf("verified not-submitted creation did not continue: %v", err)
	}
	intentAfter, err := readM2PrivateRecord(wf.path("create-intent"))
	if err != nil || !bytes.Equal(intentBefore, intentAfter) {
		t.Fatalf("single-use creation intent changed: %v", err)
	}
	archived, err := readM2PrivateRecord(wf.path("created-not-submitted-attempt-1"))
	if err != nil || !bytes.Equal(receiptBefore, archived) {
		t.Fatalf("original failure receipt was not preserved byte-for-byte: %v", err)
	}
	if err := wf.read("created", &m2ReplacementCreated{}); err != nil {
		t.Fatalf("verified continuation result did not replace the active stage receipt: %v", err)
	}
	if _, err := os.Lstat(wf.path("create-resume-intent")); err != nil {
		t.Fatal("single-use continuation intent was not sealed")
	}
	if err := wf.resumeUnsubmittedCreate(context.Background()); err == nil {
		t.Fatal("second continuation was accepted")
	}
	if err := wf.create(context.Background()); err == nil {
		t.Fatal("second cluster creation was accepted")
	}
	if ops.createCalls != 2 {
		t.Fatalf("unexpected create callback count %d", ops.createCalls)
	}
}

func TestUnitM2ReplacementCreateContinuationRejectsAmbiguousOrAlteredOutcome(t *testing.T) {
	for _, mode := range []string{"ambiguous", "wrong-error", "observation-present", "altered-link", "interrupted-resume"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			ops, wf := m2PrepareReplacementWorkflow(t, dir)
			for _, step := range []func() error{
				func() error { return wf.preflight(context.Background()) },
				func() error { return wf.revalidatePreflight(context.Background()) },
				func() error { return wf.verifyKeaImages(context.Background()) },
				func() error { return wf.teardown(context.Background()) },
			} {
				if err := step(); err != nil {
					t.Fatal(err)
				}
			}
			ops.fail = "create-not-submitted"
			if mode == "ambiguous" {
				ops.fail = "create"
			}
			if err := wf.create(context.Background()); err == nil {
				t.Fatal("failed initial create was accepted")
			}
			if mode != "ambiguous" {
				var receipt map[string]any
				if err := wf.read("created", &receipt); err != nil {
					t.Fatal(err)
				}
				if mode == "wrong-error" {
					receipt["error"] = "unclassified failure"
				} else if mode == "observation-present" {
					receipt["observation"] = map[string]any{"status": "observed"}
				} else if mode == "altered-link" {
					receipt["teardownSHA256"] = strings.Repeat("0", 64)
				}
				b, _ := json.Marshal(receipt)
				if err := os.WriteFile(wf.path("created"), append(b, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "interrupted-resume" {
				if err := wf.write("create-resume-intent", map[string]string{"status": "CONTINUE_NOT_SUBMITTED_ONCE"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := wf.resumeUnsubmittedCreate(context.Background()); err == nil {
				t.Fatal("ambiguous, changed, or interrupted continuation was accepted")
			}
			if ops.createCalls != 1 {
				t.Fatalf("unsafe continuation reached live create callback: %d", ops.createCalls)
			}
			if _, err := os.Lstat(wf.path("created-not-submitted-attempt-1")); !os.IsNotExist(err) {
				t.Fatal("rejected continuation archived or rewrote original receipt")
			}
		})
	}
}

func TestUnitM2ReplacementNamespaceContinuationRequiresIndependentNotSubmittedProof(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	for _, step := range []func() error{
		func() error { return wf.preflight(context.Background()) },
		func() error { return wf.revalidatePreflight(context.Background()) },
		func() error { return wf.verifyKeaImages(context.Background()) },
		func() error { return wf.teardown(context.Background()) },
		func() error { return wf.create(context.Background()) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	ops.fail = "namespace-not-submitted"
	if err := wf.namespaces(context.Background()); err == nil {
		t.Fatal("failed namespace-stage setup was accepted")
	}
	if _, err := os.Lstat(wf.path("namespace-intent")); err != nil {
		t.Fatal("original namespace intent was not preserved")
	}
	if err := os.WriteFile(filepath.Join(dir, "namespaces-stage-failed-attempt-1.log"), []byte("M2 lab identity lacks verified server, inline CA or administrator client\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ops.fail = ""
	if err := wf.reconcileUnsubmittedNamespaces(context.Background()); err != nil {
		t.Fatalf("read-only namespace absence reconciliation failed: %v", err)
	}
	if err := wf.resumeUnsubmittedNamespaces(context.Background()); err != nil {
		t.Fatalf("verified namespace continuation failed: %v", err)
	}
	if ops.namespaceCalls != 2 {
		t.Fatalf("namespace create callback count=%d want initial+single continuation", ops.namespaceCalls)
	}
	if err := wf.resumeUnsubmittedNamespaces(context.Background()); err == nil {
		t.Fatal("second namespace continuation was accepted")
	}
}

func TestUnitM2ReplacementNamespaceContinuationRejectsUnknownOrIncompleteState(t *testing.T) {
	for _, mode := range []string{"wrong-error", "missing-log", "foreign-namespace", "observation-failed", "interrupted", "namespace-present"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			ops, wf := m2PrepareReplacementWorkflow(t, dir)
			for _, step := range []func() error{
				func() error { return wf.preflight(context.Background()) },
				func() error { return wf.revalidatePreflight(context.Background()) },
				func() error { return wf.verifyKeaImages(context.Background()) },
				func() error { return wf.teardown(context.Background()) },
				func() error { return wf.create(context.Background()) },
			} {
				if err := step(); err != nil {
					t.Fatal(err)
				}
			}
			ops.fail = "namespace-not-submitted"
			if err := wf.namespaces(context.Background()); err == nil {
				t.Fatal("initial namespace stage unexpectedly succeeded")
			}
			if mode != "missing-log" {
				log := "M2 lab identity lacks verified server, inline CA or administrator client\n"
				if mode == "wrong-error" {
					log = "unrelated namespace failure\n"
				}
				if err := os.WriteFile(filepath.Join(dir, "namespaces-stage-failed-attempt-1.log"), []byte(log), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "foreign-namespace" || mode == "observation-failed" {
				ops.fail = "namespace-observation-failed"
			} else {
				ops.fail = ""
			}
			if mode == "interrupted" {
				if err := wf.write("namespace-resume-intent", map[string]string{"status": "CONTINUE_ABSENT_NAMESPACE_STAGE_ONCE"}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "namespace-present" {
				if err := wf.write("namespaces", m2ReplacementNamespaces{Status: "UNEXPECTED_PRESENT"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := wf.reconcileUnsubmittedNamespaces(context.Background()); err == nil {
				t.Fatal("unknown or incomplete namespace outcome was reconciled")
			}
			if err := wf.resumeUnsubmittedNamespaces(context.Background()); err == nil {
				t.Fatal("unknown or incomplete namespace outcome was replayed")
			}
			if ops.namespaceCalls != 1 {
				t.Fatalf("unsafe namespace callback reached: %d", ops.namespaceCalls)
			}
		})
	}
}
func (f *fakeM2ReplacementOps) namespaces(_ context.Context, created m2ReplacementCreated) (m2ReplacementNamespaces, error) {
	f.namespaceCalls++
	if f.fail == "namespace-not-submitted" {
		return m2ReplacementNamespaces{}, errors.New("M2 lab identity lacks verified server, inline CA or administrator client")
	}
	if f.fail == "namespaces" {
		return m2ReplacementNamespaces{}, errors.New("foreign namespace")
	}
	namespaces := m2ReplacementFixtureNamespaces("new")
	if f.fail == "namespace-invalid-policy" {
		entry := namespaces[m2LabProfile.outsideNamespace]
		entry.Policy["pod-security.kubernetes.io/enforce"] = "privileged"
		namespaces[m2LabProfile.outsideNamespace] = entry
	}
	if f.namespaceReceiptPath != "" {
		receipt := m2NamespaceReceipt{Lab: created.NewLab, FixtureLabel: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Namespaces: namespaces}
		data, err := json.Marshal(receipt)
		if err != nil {
			return m2ReplacementNamespaces{}, err
		}
		if err := writePrivateExclusiveOrReplace(f.namespaceReceiptPath, append(data, '\n')); err != nil {
			return m2ReplacementNamespaces{}, err
		}
	}
	return m2ReplacementNamespaces{Status: "VERIFIED_NEW_NAMESPACES", Namespaces: namespaces}, nil
}
func (f *fakeM2ReplacementOps) verifyNamespacesAbsent(context.Context, m2ReplacementCreated) (m2ReplacementNamespaceAbsence, error) {
	if f.fail == "namespace-observation-failed" {
		return m2ReplacementNamespaceAbsence{}, errors.New("namespace identity changed")
	}
	return m2ReplacementNamespaceAbsence{Status: "VERIFIED_NEW_NAMESPACES_ABSENT", Cluster: m2ReplacementFixtureLab("new"), RuntimeAbsent: true, OutsideAbsent: true, M1DockerID: strings.Repeat("d", 64)}, nil
}
func (f *fakeM2ReplacementOps) verifyFinal(context.Context, m2ReplacementPreflight, m2ReplacementCreated, m2ReplacementNamespaces) error {
	f.finalCalls++
	if f.fail == "final" {
		return errors.New("fresh identity changed")
	}
	return nil
}

func TestUnitM2ReplacementWorkflowEnforcesSingleUseStageOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	if err := wf.teardown(context.Background()); err == nil {
		t.Fatal("teardown ran before preflight")
	}
	if ops.teardownCalls != 0 {
		t.Fatal("out-of-order teardown callback was invoked")
	}
	if err := wf.preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wf.revalidatePreflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wf.preflight(context.Background()); err == nil {
		t.Fatal("preflight authorization replay was accepted")
	}
	if err := wf.teardown(context.Background()); err == nil {
		t.Fatal("teardown ran before local approved Kea image verification")
	}
	if ops.teardownCalls != 0 {
		t.Fatal("teardown callback ran before its Kea preflight prerequisite")
	}
	if _, err := os.Lstat(wf.path("teardown-intent")); !os.IsNotExist(err) {
		t.Fatal("failed prerequisite consumed the destructive teardown intent")
	}
	if err := wf.verifyKeaImages(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wf.teardown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wf.teardown(context.Background()); err == nil {
		t.Fatal("second teardown was accepted")
	}
	if err := wf.create(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wf.create(context.Background()); err == nil {
		t.Fatal("second creation attempt was accepted")
	}
	if err := wf.namespaces(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wf.finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ops.preflightCalls != 2 || ops.keaPreflightCalls != 1 || ops.teardownCalls != 1 || ops.createCalls != 1 || ops.namespaceCalls != 1 || ops.finalCalls != 1 {
		t.Fatalf("unexpected operation calls: %+v", ops)
	}
	for _, name := range []string{"cluster-replacement-preflight-" + historicM2ReplacementCase + ".json", "cluster-replacement-preflight-live-verified-" + historicM2ReplacementCase + ".json", "cluster-replacement-kea-preflight-" + historicM2ReplacementCase + ".json", "cluster-replacement-teardown-" + historicM2ReplacementCase + ".json", "cluster-replacement-create-intent-" + historicM2ReplacementCase + ".json", "cluster-replacement-created-" + historicM2ReplacementCase + ".json", "cluster-replacement-namespaces-" + historicM2ReplacementCase + ".json", "cluster-replacement-reconciled-" + historicM2ReplacementCase + ".json"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing durable stage receipt %s: %v", name, err)
		}
	}
}

func TestUnitM2ReplacementNamespaceStageAcceptsProvisionerReceiptWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	ops.namespaceReceiptPath = filepath.Join(dir, "namespace-receipt.json")
	for _, step := range []func() error{
		func() error { return wf.preflight(context.Background()) },
		func() error { return wf.revalidatePreflight(context.Background()) },
		func() error { return wf.verifyKeaImages(context.Background()) },
		func() error { return wf.teardown(context.Background()) },
		func() error { return wf.create(context.Background()) },
		func() error { return wf.namespaces(context.Background()) },
	} {
		if err := step(); err != nil {
			t.Fatalf("replacement stage failed: %v", err)
		}
	}
	var persisted m2NamespaceReceipt
	if err := readJSONM2(ops.namespaceReceiptPath, &persisted); err != nil {
		t.Fatal(err)
	}
	var stage m2ReplacementNamespaces
	if err := wf.read("namespaces", &stage); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(persisted.Lab, m2ReplacementFixtureLab("new")) || !reflect.DeepEqual(persisted.Namespaces, stage.Namespaces) {
		t.Fatal("provisioner receipt and replacement stage receipt diverged")
	}
}

func TestUnitM2ReplacementNamespaceReceiptRefusesDifferentExistingEvidence(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "namespace-receipt.json")
	original := []byte("{\"preserved\":true}\n")
	if err := writePrivateExclusiveOrReplace(path, original); err != nil {
		t.Fatal(err)
	}
	want := m2NamespaceReceipt{Lab: m2ReplacementFixtureLab("new"), FixtureLabel: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Namespaces: m2ReplacementFixtureNamespaces("new")}
	if err := m2PersistReplacementNamespaceReceipt(path, want); err == nil {
		t.Fatal("different existing namespace evidence was accepted")
	}
	got, err := readM2PrivateRecord(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("existing evidence was changed: %v", err)
	}
}

func TestUnitM2ReplacementWorkflowPersistsAmbiguousTeardownAndCreate(t *testing.T) {
	for _, stage := range []string{"teardown", "partial-teardown", "create"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			ops, wf := m2PrepareReplacementWorkflow(t, dir)
			ops.fail = stage
			if err := wf.preflight(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := wf.revalidatePreflight(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := wf.verifyKeaImages(context.Background()); err != nil {
				t.Fatal(err)
			}
			if stage == "teardown" || stage == "partial-teardown" {
				if err := wf.teardown(context.Background()); err == nil {
					t.Fatal("lost teardown ack accepted")
				}
				if stage == "teardown" {
					var receipt map[string]any
					if err := wf.read("teardown", &receipt); err != nil || receipt["status"] != "DELETE_ACK_UNKNOWN" {
						t.Fatalf("ambiguous deletion outcome was not preserved distinctly: receipt=%v err=%v", receipt, err)
					}
				}
				if err := wf.teardown(context.Background()); err == nil {
					t.Fatal("ambiguous teardown replay accepted")
				}
			} else {
				if err := wf.teardown(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := wf.create(context.Background()); err == nil {
					t.Fatal("ambiguous create accepted")
				}
				var receipt map[string]any
				if err := wf.read("created", &receipt); err != nil || receipt["status"] != "CREATE_ACK_UNKNOWN" {
					t.Fatalf("ambiguous create outcome was not preserved distinctly: receipt=%v err=%v", receipt, err)
				}
				if err := wf.create(context.Background()); err == nil {
					t.Fatal("ambiguous create replay accepted")
				}
			}
		})
	}
}

func TestUnitM2ReplacementWorkflowRevalidationMustMatchBeforeDestructiveIntent(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	ops.preflightMismatchOnRevalidate = true
	if err := wf.preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wf.revalidatePreflight(context.Background()); err == nil {
		t.Fatal("changed M1 identity in fresh preflight observation was accepted")
	}
	if _, err := os.Lstat(wf.path("preflight-live-verified")); !os.IsNotExist(err) {
		t.Fatal("mismatched fresh observation was sealed")
	}
	if err := wf.verifyKeaImages(context.Background()); err == nil {
		t.Fatal("Kea preflight continued without a verified live revalidation")
	}
	if err := wf.teardown(context.Background()); err == nil || ops.teardownCalls != 0 {
		t.Fatal("destructive callback ran after fresh identity mismatch")
	}
	if _, err := os.Lstat(wf.path("teardown-intent")); !os.IsNotExist(err) {
		t.Fatal("failed preflight revalidation consumed the teardown authorization")
	}
}

func TestUnitM2ReplacementWorkflowRefusesResumeAfterEveryIncompleteStage(t *testing.T) {
	for _, incomplete := range []string{"preflight", "preflight-live-verified", "kea-preflight", "teardown", "created", "namespaces"} {
		t.Run(incomplete, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			ops, wf := m2PrepareReplacementWorkflow(t, dir)
			if incomplete != "preflight" {
				if err := wf.preflight(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if incomplete == "preflight-live-verified" || incomplete == "kea-preflight" || incomplete == "teardown" || incomplete == "created" || incomplete == "namespaces" {
				if err := wf.revalidatePreflight(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if incomplete == "kea-preflight" || incomplete == "teardown" || incomplete == "created" || incomplete == "namespaces" {
				if err := wf.verifyKeaImages(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if incomplete == "teardown" || incomplete == "created" || incomplete == "namespaces" {
				if err := wf.teardown(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if incomplete == "created" || incomplete == "namespaces" {
				if err := wf.create(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if err := wf.finalize(context.Background()); err == nil {
				t.Fatalf("final replacement receipt was sealed with incomplete %s stage", incomplete)
			}
			if _, err := os.Lstat(wf.path("reconciled")); !os.IsNotExist(err) {
				t.Fatalf("incomplete %s stage created a final receipt", incomplete)
			}
			if _, err := os.Lstat(filepath.Join(dir, "recovery-pending.json")); err != nil {
				t.Fatalf("incomplete %s stage retired the historical marker", incomplete)
			}
			if ops.finalCalls != 0 {
				t.Fatalf("final live verification ran after incomplete %s stage", incomplete)
			}
		})
	}
}

func TestUnitM2ReplacementWorkflowRefusesBadPreflightAndNewNamespace(t *testing.T) {
	for _, stage := range []string{"preflight", "kea-preflight", "namespaces", "namespace-invalid-policy", "final"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			ops, wf := m2PrepareReplacementWorkflow(t, dir)
			ops.fail = stage
			if stage == "preflight" {
				if err := wf.preflight(context.Background()); err == nil {
					t.Fatal("mismatched live preflight accepted")
				}
				if _, err := os.Lstat(filepath.Join(dir, "cluster-replacement-preflight-"+historicM2ReplacementCase+".json")); !os.IsNotExist(err) {
					t.Fatal("invalid preflight was sealed")
				}
				return
			}
			if err := wf.preflight(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := wf.revalidatePreflight(context.Background()); err != nil {
				t.Fatal(err)
			}
			if stage == "kea-preflight" {
				ops.fail = stage
				if err := wf.verifyKeaImages(context.Background()); err == nil {
					t.Fatal("invalid local Kea image identity was accepted")
				}
				if err := wf.teardown(context.Background()); err == nil || ops.teardownCalls != 0 {
					t.Fatal("teardown proceeded without a verified Kea image preflight")
				}
				return
			}
			if err := wf.verifyKeaImages(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := wf.teardown(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := wf.create(context.Background()); err != nil {
				t.Fatal(err)
			}
			if stage == "namespaces" || stage == "namespace-invalid-policy" {
				if err := wf.namespaces(context.Background()); err == nil {
					t.Fatal("foreign or weak namespace evidence accepted")
				}
				if err := wf.finalize(context.Background()); err == nil {
					t.Fatal("final receipt sealed without verified namespaces")
				}
				return
			}
			if err := wf.namespaces(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := wf.finalize(context.Background()); err == nil {
				t.Fatal("final receipt sealed after fresh identity mismatch")
			}
		})
	}
}

func TestUnitM2ReplacementPendingRecoveryAllowsOnlyGateB(t *testing.T) {
	for name, tc := range map[string]struct {
		caseID, enabled string
		focus, skip     []string
	}{"ordinary E2E": {historicM2ReplacementCase, "", []string{""}, nil}, "wrong focus": {historicM2ReplacementCase, "1", []string{"M2: RBAC"}, nil}, "skips": {historicM2ReplacementCase, "1", []string{"M2: Admission"}, []string{"some case"}}, "wrong case": {"1792432128521632810-000000", "1", []string{"M2: Admission"}, nil}} {
		t.Run(name, func(t *testing.T) {
			if err := m2ValidateReplacementGateBSelection(tc.caseID, tc.enabled, tc.focus, tc.skip); err == nil {
				t.Fatal("pending-recovery ordinary E2E selection accepted")
			}
		})
	}
	if err := m2ValidateReplacementGateBSelection(historicM2ReplacementCase, "1", []string{"M2: Admission"}, nil); err != nil {
		t.Fatalf("reviewed replacement Gate B selection rejected: %v", err)
	}
}

func TestUnitM2ReplacementWorkflowPreflightBindsOriginalEvidence(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "ledger.json"), []byte("changed unresolved history\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := wf.preflight(context.Background()); err == nil {
		t.Fatal("changed historic ledger accepted")
	}
	if ops.preflightCalls != 0 {
		t.Fatal("live inventory ran after historic evidence mismatch")
	}
	if _, err := os.Lstat(wf.path("preflight")); !os.IsNotExist(err) {
		t.Fatal("preflight receipt sealed despite changed history")
	}
}

func TestUnitM2ReplacementWorkflowRefusesTamperedPreflightBeforeTeardown(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	if err := wf.preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wf.revalidatePreflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wf.verifyKeaImages(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := wf.path("preflight")
	var receipt m2ReplacementPreflight
	if err := wf.read("preflight", &receipt); err != nil {
		t.Fatal(err)
	}
	node := m2LabProfile.nodes[0]
	entry := receipt.OldLab.Nodes[node]
	entry.DockerID = strings.Repeat("e", 64)
	receipt.OldLab.Nodes[node] = entry
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := wf.teardown(context.Background()); err == nil {
		t.Fatal("tampered preflight receipt reached destructive callback")
	}
	if ops.teardownCalls != 0 {
		t.Fatal("teardown callback ran with tampered preflight")
	}
}

func TestUnitM2ReplacementWorkflowRejectsTamperedLifecycleLinksBeforeRetirement(t *testing.T) {
	for _, stage := range []string{"preflight-live-verified", "kea-preflight", "teardown", "created", "namespaces", "create-intent", "namespace-intent"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			ops, wf := m2PrepareReplacementWorkflow(t, dir)
			for _, run := range []func() error{func() error { return wf.preflight(context.Background()) }, func() error { return wf.revalidatePreflight(context.Background()) }, func() error { return wf.verifyKeaImages(context.Background()) }, func() error { return wf.teardown(context.Background()) }, func() error { return wf.create(context.Background()) }, func() error { return wf.namespaces(context.Background()) }} {
				if err := run(); err != nil {
					t.Fatal(err)
				}
			}
			name := stage
			if stage == "create-intent" {
				name = "create-intent"
			} else if stage == "namespace-intent" {
				name = "namespace-intent"
			}
			path := wf.path(name)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if err := json.Unmarshal(b, &record); err != nil {
				t.Fatal(err)
			}
			for key := range record {
				if strings.Contains(strings.ToLower(key), "sha256") {
					record[key] = strings.Repeat("0", 64)
					break
				}
			}
			b, _ = json.Marshal(record)
			if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if err := wf.finalize(context.Background()); err == nil {
				t.Fatal("tampered lifecycle link was accepted")
			}
			if ops.finalCalls != 0 {
				t.Fatal("fresh final observation ran after a tampered receipt")
			}
			if _, err := os.Lstat(filepath.Join(dir, "recovery-pending.json")); err != nil {
				t.Fatal("original marker was retired before final proof")
			}
		})
	}
}

func TestUnitM2ReplacementMountInventoryRequiresExactReviewedMounts(t *testing.T) {
	volume := strings.Repeat("a", 64)
	valid := []byte(`[{"Type":"volume","Name":"` + volume + `","Destination":"/var","Source":"/var/lib/docker/volumes/` + volume + `/_data","RW":true},{"Type":"bind","Destination":"/lib/modules","Source":"/lib/modules","RW":false}]`)
	if got, err := m2ValidateReplacementMounts(valid); err != nil || got != volume {
		t.Fatalf("reviewed mounts rejected: got=%q err=%v", got, err)
	}
	for name, input := range map[string][]byte{
		"extra mount":             []byte(strings.TrimSuffix(string(valid), "]") + `,{"Type":"bind","Destination":"/extra","Source":"/extra","RW":false}]`),
		"writable module bind":    []byte(strings.Replace(string(valid), `"RW":false`, `"RW":true`, 1)),
		"untrusted volume source": []byte(strings.Replace(string(valid), `/var/lib/docker/volumes/`+volume+`/_data`, `/tmp/foreign`, 1)),
		"missing bind":            []byte(`[{"Type":"volume","Name":"` + volume + `","Destination":"/var","Source":"/var/lib/docker/volumes/` + volume + `/_data","RW":true}]`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := m2ValidateReplacementMounts(input); err == nil {
				t.Fatal("unreviewed mount layout accepted")
			}
		})
	}
}

func TestUnitM2ReplacementContainerSetRequiresExactFullNodeIDs(t *testing.T) {
	nodes := m2ReplacementFixtureLab("old").Nodes
	valid := strings.Join([]string{nodes[m2LabProfile.nodes[0]].DockerID, nodes[m2LabProfile.nodes[1]].DockerID, nodes[m2LabProfile.nodes[2]].DockerID}, "\n") + "\n"
	if err := m2ValidateReplacementContainerSet(valid, nodes); err != nil {
		t.Fatalf("exact old node container set rejected: %v", err)
	}
	for label, output := range map[string]string{
		"unexpected container": valid + strings.Repeat("f", 64) + "\n",
		"missing node":         strings.Join(strings.Split(strings.TrimSpace(valid), "\n")[:2], "\n"),
		"short ID":             "abc\n" + strings.Join(strings.Split(strings.TrimSpace(valid), "\n")[1:], "\n"),
		"duplicate ID":         strings.Join([]string{nodes[m2LabProfile.nodes[0]].DockerID, nodes[m2LabProfile.nodes[0]].DockerID, nodes[m2LabProfile.nodes[2]].DockerID}, "\n"),
	} {
		t.Run(label, func(t *testing.T) {
			if err := m2ValidateReplacementContainerSet(output, nodes); err == nil {
				t.Fatal("unexpected M2-attributed Docker container set was accepted")
			}
		})
	}
}

func TestUnitM2ReplacementActiveContainerSetRequiresNewNodesAndExcludesOldIncarnation(t *testing.T) {
	oldNodes := m2ReplacementFixtureLab("old").Nodes
	newNodes := m2ReplacementFixtureLab("new").Nodes
	newIDs := strings.Join([]string{newNodes[m2LabProfile.nodes[0]].DockerID, newNodes[m2LabProfile.nodes[1]].DockerID, newNodes[m2LabProfile.nodes[2]].DockerID}, "\n") + "\n"
	if err := m2ValidateReplacementActiveContainerSet(newIDs, oldNodes, newNodes); err != nil {
		t.Fatalf("exact replacement node set rejected: %v", err)
	}
	oldIDs := strings.Join([]string{oldNodes[m2LabProfile.nodes[0]].DockerID, oldNodes[m2LabProfile.nodes[1]].DockerID, oldNodes[m2LabProfile.nodes[2]].DockerID}, "\n") + "\n"
	if err := m2ValidateReplacementActiveContainerSet(oldIDs, oldNodes, newNodes); err == nil {
		t.Fatal("old cluster incarnation accepted as the active replacement node set")
	}
	if err := m2ValidateReplacementActiveContainerSet(newIDs+strings.Repeat("f", 64)+"\n", oldNodes, newNodes); err == nil {
		t.Fatal("unexpected cluster-attributed container accepted")
	}
	if err := m2ValidateReplacementActiveContainerSet(strings.Join(strings.Split(strings.TrimSpace(newIDs), "\n")[:2], "\n"), oldNodes, newNodes); err == nil {
		t.Fatal("incomplete replacement node set accepted")
	}
}

func TestUnitM2ReplacementFinalInventoryRequestsFullDockerIDs(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "m2_replacement_live_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var finalizer *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "verifyFinal" {
			finalizer = fn
			break
		}
	}
	if finalizer == nil {
		t.Fatal("replacement finalizer not found")
	}
	found := false
	ast.Inspect(finalizer.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 4 {
			return true
		}
		selector, ok := call.Fun.(*ast.Ident)
		if !ok || selector.Name != "m2Command" || len(call.Args) < 3 {
			return true
		}
		values := map[string]bool{}
		for _, arg := range call.Args[1:] {
			if literal, ok := arg.(*ast.BasicLit); ok && literal.Kind == token.STRING {
				values[strings.Trim(literal.Value, "\"")] = true
			}
		}
		if values["docker"] && values["ps"] && values["-aq"] && values["--no-trunc"] {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("final replacement inventory must request full Docker IDs before validating exact node identities")
	}
}

func TestUnitM2ReplacementResourceInventoryRejectsForeignNamespacesAndPVs(t *testing.T) {
	base := []m2ReplacementResourceRef{{Resource: "namespaces", Name: "default", UID: "uid-default"}, {Resource: "pods", Namespace: m2LabProfile.runtimeNamespace, Name: "manager", UID: "uid-manager"}}
	if err := m2ValidateReplacementResourceInventory(base, nil); err != nil {
		t.Fatal(err)
	}
	foreign := append(append([]m2ReplacementResourceRef(nil), base...), m2ReplacementResourceRef{Resource: "pods", Namespace: "foreign", Name: "unexpected", UID: "uid-foreign"})
	if err := m2ValidateReplacementResourceInventory(foreign, nil); err == nil {
		t.Fatal("foreign namespace resource accepted")
	}
	foreignNamespace := append(append([]m2ReplacementResourceRef(nil), base...), m2ReplacementResourceRef{Resource: "namespaces", Name: "foreign", UID: "uid-foreign"})
	if err := m2ValidateReplacementResourceInventory(foreignNamespace, nil); err == nil {
		t.Fatal("foreign namespace object accepted")
	}
	foreignCRD := append(append([]m2ReplacementResourceRef(nil), base...), m2ReplacementResourceRef{Resource: "customresourcedefinitions.apiextensions.k8s.io", Name: "foreign.example.com", UID: "uid-foreign"})
	if err := m2ValidateReplacementResourceInventory(foreignCRD, nil); err == nil {
		t.Fatal("foreign CRD accepted")
	}
	if err := m2ValidateReplacementResourceInventory(base, []string{"pv-unexpected"}); err == nil {
		t.Fatal("persistent volume was not rejected")
	}
	if err := m2ValidateReplacementResourceInventory([]m2ReplacementResourceRef{{Resource: "nodes", Name: "node", UID: ""}}, nil); err == nil {
		t.Fatal("resource without UID was accepted")
	}
	if err := m2ValidateReplacementResourceInventory(append(append([]m2ReplacementResourceRef(nil), base...), m2ReplacementResourceRef{Resource: "componentstatuses", Name: "scheduler"}), nil); err != nil {
		t.Fatalf("UID-less virtual ComponentStatus rejected: %v", err)
	}
	if err := m2ValidateReplacementResourceInventory(append(append([]m2ReplacementResourceRef(nil), base...), m2ReplacementResourceRef{Resource: "componentstatuses", Namespace: "default", Name: "scheduler"}), nil); err == nil {
		t.Fatal("malformed virtual ComponentStatus accepted")
	}
}

func TestUnitM2ReplacementKeaImportReferenceIsExactAndUnambiguous(t *testing.T) {
	image := m2KeaDHCP4Image
	digest := strings.SplitN(image, "@", 2)[1]
	valid := "other@sha256:" + strings.Repeat("0", 64) + "\nimport-2026-10-19@" + digest + "\n"
	got, err := m2ReplacementKeaImportReference(valid, image)
	if err != nil || got != "import-2026-10-19@"+digest {
		t.Fatalf("exact imported descriptor was not selected: got=%q err=%v", got, err)
	}
	for name, listing := range map[string]string{
		"missing":              "other@sha256:" + strings.Repeat("0", 64) + "\n",
		"wrong digest":         "import-2026-10-19@sha256:" + strings.Repeat("f", 64) + "\n",
		"ambiguous imports":    "import-2026-10-18@" + digest + "\nimport-2026-10-19@" + digest + "\n",
		"target is not import": image + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := m2ReplacementKeaImportReference(listing, image); err == nil {
				t.Fatal("missing, conflicting, or non-import image reference was accepted")
			}
		})
	}
}

func TestUnitM2ReplacementKeaContainerdReferencesRequireIdenticalApprovedDescriptor(t *testing.T) {
	image := m2KeaDHCP6Image
	digest := strings.SplitN(image, "@", 2)[1]
	source := "import-2026-10-19@" + digest
	valid := source + " application/vnd.oci.image.manifest.v1+json " + digest + " 1050\n" +
		image + " application/vnd.oci.image.manifest.v1+json " + digest + " 1050\n"
	if err := m2CheckReplacementKeaContainerdReferences(valid, source, image); err != nil {
		t.Fatalf("identical source/target OCI descriptor rejected: %v", err)
	}
	for name, rows := range map[string]string{
		"wrong manifest":   strings.Replace(valid, digest, "sha256:"+strings.Repeat("f", 64), 1),
		"wrong media type": strings.Replace(valid, "application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.index.v1+json", 1),
		"missing target":   strings.Split(valid, "\n")[0] + "\n",
		"duplicate target": valid + strings.Split(valid, "\n")[1] + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := m2CheckReplacementKeaContainerdReferences(rows, source, image); err == nil {
				t.Fatal("non-identical or ambiguous containerd descriptor accepted")
			}
		})
	}
}

func TestUnitM2ReplacementKeaConfigReceiptRequiresAllNodesAndExactPins(t *testing.T) {
	valid := map[string]map[string]string{}
	for _, node := range m2LabProfile.nodes {
		valid[node] = map[string]string{}
		for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
			valid[node][image], _ = m2KeaExpectedConfigID(image)
		}
	}
	if err := m2ValidateReplacementKeaConfigIDs(valid); err != nil {
		t.Fatalf("complete exact config receipt rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]map[string]string){
		"missing node":  func(e map[string]map[string]string) { delete(e, m2LabProfile.nodes[0]) },
		"missing image": func(e map[string]map[string]string) { delete(e[m2LabProfile.nodes[0]], m2KeaDHCP4Image) },
		"wrong config": func(e map[string]map[string]string) {
			e[m2LabProfile.nodes[0]][m2KeaDHCP6Image] = "sha256:" + strings.Repeat("f", 64)
		},
		"unapproved image": func(e map[string]map[string]string) {
			e[m2LabProfile.nodes[0]]["example.invalid/kea@sha256:"+strings.Repeat("a", 64)] = "sha256:" + strings.Repeat("b", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := map[string]map[string]string{}
			for node, images := range valid {
				copy[node] = map[string]string{}
				for image, id := range images {
					copy[node][image] = id
				}
			}
			mutate(copy)
			if err := m2ValidateReplacementKeaConfigIDs(copy); err == nil {
				t.Fatal("incomplete or unapproved Kea identity receipt accepted")
			}
		})
	}
}

func TestUnitM2ReplacementGateBAllowsOnlyVerifiedIsolatedScenarioEvidence(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ops, wf := m2PrepareReplacementWorkflow(t, dir)
	for _, run := range []func() error{
		func() error { return wf.preflight(context.Background()) },
		func() error { return wf.revalidatePreflight(context.Background()) },
		func() error { return wf.verifyKeaImages(context.Background()) },
		func() error { return wf.teardown(context.Background()) },
		func() error { return wf.create(context.Background()) },
		func() error { return wf.namespaces(context.Background()) },
	} {
		if err := run(); err != nil {
			t.Fatal(err)
		}
	}
	if ops.finalCalls != 0 {
		t.Fatal("replacement proof finalized before Gate B")
	}
	scenarioDir := filepath.Join(dir, "replacement-gate-b-"+historicM2ReplacementCase)
	if err := os.Mkdir(scenarioDir, 0700); err != nil {
		t.Fatal(err)
	}
	created, err := os.ReadFile(wf.path("created"))
	if err != nil {
		t.Fatal(err)
	}
	namespaces, err := os.ReadFile(wf.path("namespaces"))
	if err != nil {
		t.Fatal(err)
	}
	started, _ := json.Marshal(map[string]string{
		"caseID": historicM2ReplacementCase, "status": "GATE_B_RUNNING_ON_VERIFIED_REPLACEMENT",
		"createdSHA256": m2SHA256(created), "namespacesSHA256": m2SHA256(namespaces),
	})
	if err := writePrivateExclusiveOrReplace(filepath.Join(scenarioDir, "gate-b-started.json"), append(started, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := m2ValidateReplacementGateBScenarioEvidence(dir, scenarioDir, historicM2ReplacementCase, ops.markerHash, ops.ledgerHash); err != nil {
		t.Fatalf("exact isolated replacement Gate B evidence was rejected: %v", err)
	}
	if err := m2ValidateReplacementGateBScenarioEvidence(dir, dir, historicM2ReplacementCase, ops.markerHash, ops.ledgerHash); err == nil {
		t.Fatal("ordinary evidence directory was accepted as the isolated Gate B scenario directory")
	}
	if err := os.WriteFile(filepath.Join(scenarioDir, "recovery-pending.json"), []byte("pending\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2ValidateReplacementGateBScenarioEvidence(dir, scenarioDir, historicM2ReplacementCase, ops.markerHash, ops.ledgerHash); err == nil {
		t.Fatal("scenario with unresolved recovery marker was allowed to continue")
	}
}
