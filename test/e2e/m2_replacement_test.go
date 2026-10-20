package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

const m2ClusterReplacementRecoveryStatus = "VERIFIED_CLUSTER_REPLACEMENT_RECOVERY_NOT_SCENARIO_PASS"
const historicM2ReplacementCase = "1792432128521632810-890503"

type m2ReplacementPreflight struct {
	CaseID                  string                      `json:"caseID"`
	Status                  string                      `json:"status"`
	OldCluster              string                      `json:"oldCluster"`
	OldLab                  m2LabIdentity               `json:"oldLab"`
	OldNamespaces           map[string]m2NamespaceEntry `json:"oldNamespaces"`
	NamespaceReceiptSHA256  string                      `json:"oldNamespaceReceiptSHA256"`
	PartialNamespaceSHA256  string                      `json:"oldPartialNamespaceSHA256,omitempty"`
	OldVolumes              map[string]string           `json:"oldVolumes"`
	ResourceInventorySHA256 string                      `json:"resourceInventorySHA256"`
	ResourceInventoryCount  int                         `json:"resourceInventoryCount"`
	PersistentVolumeNames   []string                    `json:"persistentVolumeNames"`
	MarkerSHA256            string                      `json:"markerSHA256"`
	LedgerSHA256            string                      `json:"ledgerSHA256"`
	DiagnosticsSHA256       string                      `json:"diagnosticsSHA256"`
	M1DockerID              string                      `json:"m1DockerID"`
	M1Image                 string                      `json:"m1Image"`
	KeaDockerConfigIDs      map[string]string           `json:"keaDockerConfigIDs,omitempty"`
	Quiescent               bool                        `json:"quiescent"`
}
type m2ReplacementTeardown struct {
	Status              string `json:"status"`
	PreflightSHA256     string `json:"preflightSHA256"`
	PreflightLiveSHA256 string `json:"preflightLiveSHA256"`
	KeaPreflightSHA256  string `json:"keaPreflightSHA256"`
	OldClusterAbsent    bool   `json:"oldClusterAbsent"`
	OldContainersAbsent bool   `json:"oldContainersAbsent"`
	OldVolumesAbsent    bool   `json:"oldVolumesAbsent"`
	M1DockerID          string `json:"m1DockerID"`
}
type m2ReplacementTeardownAttemptInfo struct {
	Attempt         int
	IntentPath      string
	ReceiptPath     string
	IntentBytes     []byte
	ReceiptBytes    []byte
	PreviousIntent  []byte
	PreviousReceipt []byte
	Teardown        m2ReplacementTeardown
	Done            bool
	Blocked         bool
	Status          string
}
type m2ReplacementTeardownReconciliation struct {
	CaseID                string                `json:"caseID"`
	Status                string                `json:"status"`
	PreflightSHA256       string                `json:"preflightSHA256"`
	PreflightLiveSHA256   string                `json:"preflightLiveSHA256"`
	KeaPreflightSHA256    string                `json:"keaPreflightSHA256"`
	PreviousIntentSHA256  string                `json:"previousIntentSHA256"`
	PreviousReceiptSHA256 string                `json:"previousReceiptSHA256"`
	IntentSHA256          string                `json:"intentSHA256"`
	Observation           m2ReplacementTeardown `json:"observation"`
}
type m2ReplacementCreated struct {
	Status              string                       `json:"status"`
	PreflightSHA256     string                       `json:"preflightSHA256"`
	PreflightLiveSHA256 string                       `json:"preflightLiveSHA256"`
	KeaPreflightSHA256  string                       `json:"keaPreflightSHA256"`
	TeardownSHA256      string                       `json:"teardownSHA256"`
	NewLab              m2LabIdentity                `json:"newLab"`
	NewVolumes          map[string]string            `json:"newVolumes"`
	KeaConfigIDs        map[string]map[string]string `json:"keaConfigIDs"`
	M1DockerID          string                       `json:"m1DockerID"`
}
type m2ReplacementNamespaceAbsence struct {
	Status        string        `json:"status"`
	Cluster       m2LabIdentity `json:"cluster"`
	RuntimeAbsent bool          `json:"runtimeAbsent"`
	OutsideAbsent bool          `json:"outsideAbsent"`
	M1DockerID    string        `json:"m1DockerID"`
}
type m2ReplacementNamespaceReconciliation struct {
	CaseID                string                        `json:"caseID"`
	Status                string                        `json:"status"`
	NamespaceIntentSHA256 string                        `json:"namespaceIntentSHA256"`
	CreatedSHA256         string                        `json:"createdSHA256"`
	PreflightSHA256       string                        `json:"preflightSHA256"`
	PreflightLiveSHA256   string                        `json:"preflightLiveSHA256"`
	KeaPreflightSHA256    string                        `json:"keaPreflightSHA256"`
	FailureLogSHA256      string                        `json:"failureLogSHA256"`
	Error                 string                        `json:"error"`
	Observation           m2ReplacementNamespaceAbsence `json:"observation"`
}
type m2ReplacementKeaPreflight struct {
	CaseID          string            `json:"caseID"`
	Status          string            `json:"status"`
	PreflightSHA256 string            `json:"preflightSHA256"`
	ConfigIDs       map[string]string `json:"configIDs"`
}
type m2ReplacementPreflightRevalidation struct {
	CaseID            string                 `json:"caseID"`
	Status            string                 `json:"status"`
	PreflightSHA256   string                 `json:"preflightSHA256"`
	ObservationSHA256 string                 `json:"observationSHA256"`
	Observation       m2ReplacementPreflight `json:"observation"`
}
type m2ReplacementNamespaces struct {
	Status        string                      `json:"status"`
	CreatedSHA256 string                      `json:"createdSHA256"`
	Namespaces    map[string]m2NamespaceEntry `json:"namespaces"`
}
type m2ReplacementOps interface {
	preflight(context.Context) (m2ReplacementPreflight, error)
	approvedKeaImages(context.Context) (map[string]string, error)
	teardown(context.Context, m2ReplacementPreflight) (m2ReplacementTeardown, error)
	verifyTeardown(context.Context, m2ReplacementPreflight) (m2ReplacementTeardown, error)
	create(context.Context, m2ReplacementPreflight, m2ReplacementTeardown) (m2ReplacementCreated, error)
	verifyNamespacesAbsent(context.Context, m2ReplacementCreated) (m2ReplacementNamespaceAbsence, error)
	namespaces(context.Context, m2ReplacementCreated) (m2ReplacementNamespaces, error)
	verifyFinal(context.Context, m2ReplacementPreflight, m2ReplacementCreated, m2ReplacementNamespaces) error
}
type m2ReplacementWorkflow struct {
	dir, caseID                                         string
	ops                                                 m2ReplacementOps
	expectedMarker, expectedLedger, expectedDiagnostics string
}

func (w m2ReplacementWorkflow) path(stage string) string {
	return filepath.Join(w.dir, "cluster-replacement-"+stage+"-"+w.caseID+".json")
}
func (w m2ReplacementWorkflow) write(stage string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writePrivateExclusiveOrReplace(w.path(stage), append(b, '\n'))
}
func (w m2ReplacementWorkflow) read(stage string, value any) error {
	b, err := readM2PrivateRecord(w.path(stage))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}
func (w m2ReplacementWorkflow) readPreflight(value *m2ReplacementPreflight) error {
	b, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	seal, err := readM2PrivateRecord(w.path("preflight-seal"))
	if err != nil {
		return fmt.Errorf("preflight seal unavailable: %w", err)
	}
	var s struct {
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal(seal, &s) != nil || s.SHA256 != m2SHA256(b) {
		return fmt.Errorf("preflight receipt differs from its immutable seal")
	}
	if err := json.Unmarshal(b, value); err != nil {
		return err
	}
	return nil
}

func m2ValidateReplacementIntent(path, caseID, status string, fields map[string]string) error {
	b, err := readM2PrivateRecord(path)
	if err != nil {
		return err
	}
	var intent map[string]string
	if err := json.Unmarshal(b, &intent); err != nil || intent["caseID"] != caseID || intent["status"] != status {
		return fmt.Errorf("replacement %s intent is malformed or belongs to another case: %v", status, err)
	}
	for key, want := range fields {
		if intent[key] != want {
			return fmt.Errorf("replacement %s intent has stale %s binding", status, key)
		}
	}
	return nil
}

func m2VerifyReplacementInventoryFile(dir string, p m2ReplacementPreflight) error {
	if !m2FullHexID(p.ResourceInventorySHA256) || p.ResourceInventoryCount <= 0 || len(p.PersistentVolumeNames) != 0 {
		return fmt.Errorf("complete preflight inventory with no persistent volumes is required")
	}
	b, err := readM2PrivateRecord(filepath.Join(dir, "cluster-replacement-resource-inventory-"+p.CaseID+".json"))
	if err != nil {
		return err
	}
	var refs []m2ReplacementResourceRef
	if err := json.Unmarshal(b, &refs); err != nil || len(refs) != p.ResourceInventoryCount || m2ReplacementInventoryHash(refs) != p.ResourceInventorySHA256 {
		return fmt.Errorf("durable old-cluster resource inventory differs from sealed preflight: %v", err)
	}
	return m2ValidateReplacementResourceInventory(refs, p.PersistentVolumeNames)
}
func (w m2ReplacementWorkflow) ready() error {
	if !m2ValidCaseID(w.caseID) || w.caseID != historicM2ReplacementCase || w.ops == nil {
		return fmt.Errorf("replacement workflow is not authorized for this case")
	}
	st, err := os.Lstat(w.dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 {
		return fmt.Errorf("replacement evidence directory must be private and nonsymlink: %v", err)
	}
	return nil
}
func (w m2ReplacementWorkflow) preflight(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	if _, err := os.Lstat(w.path("preflight")); err == nil {
		return fmt.Errorf("preflight authorization already consumed")
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, stage := range []string{"preflight-live-verified", "kea-preflight", "teardown-intent", "teardown", "create-intent", "created", "namespace-intent", "namespaces", "reconciled"} {
		if _, err := os.Lstat(w.path(stage)); err == nil {
			return fmt.Errorf("replacement stage %s exists before preflight; refuse replay", stage)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := m2VerifyReplacementHistory(w.dir, w.caseID, w.expectedMarker, w.expectedLedger, w.expectedDiagnostics); err != nil {
		return fmt.Errorf("historic recovery evidence changed before preflight: %w", err)
	}
	r, err := w.ops.preflight(ctx)
	if err != nil {
		return err
	}
	if r.CaseID != w.caseID || r.Status != "VERIFIED_OLD_LAB_PREFLIGHT" || r.OldCluster != m2LabProfile.cluster || !r.Quiescent || r.MarkerSHA256 != w.expectedMarker || r.LedgerSHA256 != w.expectedLedger || r.DiagnosticsSHA256 != w.expectedDiagnostics || r.M1DockerID == "" || r.M1Image != m2LabProfile.nodeImage {
		return fmt.Errorf("old-lab preflight evidence mismatch")
	}
	if err := m2ValidateReplacementNodes(r.OldLab.Nodes, r.OldVolumes); err != nil {
		return err
	}
	if err := m2VerifyReplacementInventoryFile(w.dir, r); err != nil {
		return err
	}
	if err := m2ValidateReplacementNamespaces(r.OldNamespaces); err != nil {
		return err
	}
	if err := w.write("preflight", r); err != nil {
		return err
	}
	sealed, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	seal, _ := json.Marshal(map[string]string{"sha256": m2SHA256(sealed)})
	return writePrivateExclusiveOrReplace(w.path("preflight-seal"), append(seal, '\n'))
}

// revalidatePreflight preserves the historical preflight receipt and proves
// that its complete live identity is still current immediately before any
// destructive stage. The independent observation is sealed as a new record.
func (w m2ReplacementWorkflow) revalidatePreflight(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	var sealed m2ReplacementPreflight
	if err := w.readPreflight(&sealed); err != nil {
		return fmt.Errorf("sealed original preflight required: %w", err)
	}
	if sealed.CaseID != w.caseID || sealed.Status != "VERIFIED_OLD_LAB_PREFLIGHT" || !sealed.Quiescent || sealed.MarkerSHA256 != w.expectedMarker || sealed.LedgerSHA256 != w.expectedLedger || sealed.DiagnosticsSHA256 != w.expectedDiagnostics {
		return fmt.Errorf("sealed preflight does not bind the exact failed historic case")
	}
	if err := m2VerifyReplacementHistory(w.dir, w.caseID, w.expectedMarker, w.expectedLedger, w.expectedDiagnostics); err != nil {
		return fmt.Errorf("historic evidence changed before fresh preflight observation: %w", err)
	}
	if err := m2VerifyReplacementInventoryFile(w.dir, sealed); err != nil {
		return err
	}
	if _, err := os.Lstat(w.path("preflight-live-verified")); err == nil {
		return fmt.Errorf("fresh old-cluster preflight observation is one-use")
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, stage := range []string{"kea-preflight", "teardown-intent", "teardown", "create-intent", "created", "namespace-intent", "namespaces", "reconciled"} {
		if _, err := os.Lstat(w.path(stage)); err == nil {
			return fmt.Errorf("fresh preflight observation is too late; stage %s has begun", stage)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	observed, err := w.ops.preflight(ctx)
	if err != nil {
		return err
	}
	// Kea local-image IDs are independently recorded by the following stage;
	// they are intentionally not part of the old-cluster preflight snapshot.
	sealed.KeaDockerConfigIDs = nil
	observed.KeaDockerConfigIDs = nil
	if !reflect.DeepEqual(observed, sealed) {
		return fmt.Errorf("fresh live preflight identity differs from the immutable old-cluster receipt")
	}
	preflightBytes, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	observationBytes, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	receipt := m2ReplacementPreflightRevalidation{CaseID: w.caseID, Status: "VERIFIED_OLD_LAB_PREFLIGHT_REVALIDATED", PreflightSHA256: m2SHA256(preflightBytes), ObservationSHA256: m2SHA256(observationBytes), Observation: observed}
	return w.write("preflight-live-verified", receipt)
}

func m2ValidateReplacementPreflightRevalidation(receipt m2ReplacementPreflightRevalidation, caseID string, preflightBytes []byte, sealed m2ReplacementPreflight) error {
	if receipt.CaseID != caseID || receipt.Status != "VERIFIED_OLD_LAB_PREFLIGHT_REVALIDATED" || receipt.PreflightSHA256 != m2SHA256(preflightBytes) || !m2FullHexID(receipt.ObservationSHA256) {
		return fmt.Errorf("fresh old-cluster preflight receipt is malformed or stale")
	}
	observedBytes, err := json.Marshal(receipt.Observation)
	if err != nil || m2SHA256(observedBytes) != receipt.ObservationSHA256 {
		return fmt.Errorf("fresh old-cluster observation hash mismatch: %v", err)
	}
	sealed.KeaDockerConfigIDs = nil
	receipt.Observation.KeaDockerConfigIDs = nil
	if !reflect.DeepEqual(receipt.Observation, sealed) {
		return fmt.Errorf("fresh old-cluster observation differs from sealed preflight")
	}
	return nil
}

func (w m2ReplacementWorkflow) verifyKeaImages(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	var preflight m2ReplacementPreflight
	if err := w.readPreflight(&preflight); err != nil {
		return fmt.Errorf("sealed old-cluster preflight required before Kea image inspection: %w", err)
	}
	var livePreflight m2ReplacementPreflightRevalidation
	if err := w.read("preflight-live-verified", &livePreflight); err != nil || livePreflight.CaseID != w.caseID || livePreflight.Status != "VERIFIED_OLD_LAB_PREFLIGHT_REVALIDATED" {
		return fmt.Errorf("fresh live old-cluster preflight required before Kea image inspection: %v", err)
	}
	preflightBytes, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil || m2ValidateReplacementPreflightRevalidation(livePreflight, w.caseID, preflightBytes, preflight) != nil {
		return fmt.Errorf("fresh live preflight receipt is stale or malformed: %v", err)
	}
	if err := m2VerifyReplacementHistory(w.dir, w.caseID, w.expectedMarker, w.expectedLedger, w.expectedDiagnostics); err != nil {
		return fmt.Errorf("historic evidence changed before Kea image inspection: %w", err)
	}
	if err := m2VerifyReplacementInventoryFile(w.dir, preflight); err != nil {
		return err
	}
	if _, err := os.Lstat(w.path("kea-preflight")); err == nil {
		return fmt.Errorf("Kea image preflight is one-use and already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, stage := range []string{"teardown-intent", "teardown", "create-intent", "created", "namespace-intent", "namespaces", "reconciled"} {
		if _, err := os.Lstat(w.path(stage)); err == nil {
			return fmt.Errorf("cannot verify Kea image preflight after replacement stage %s began", stage)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	ids, err := w.ops.approvedKeaImages(ctx)
	if err != nil {
		return err
	}
	if err := m2ValidateReplacementKeaDockerConfigIDs(ids); err != nil {
		return fmt.Errorf("local approved Kea image inspection failed: %w", err)
	}
	preflightBytes, err = readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	return w.write("kea-preflight", m2ReplacementKeaPreflight{CaseID: w.caseID, Status: "VERIFIED_APPROVED_KEA_LOCAL_IMAGES", PreflightSHA256: m2SHA256(preflightBytes), ConfigIDs: ids})
}

func m2VerifyReplacementHistory(dir, caseID, markerHash, ledgerHash, diagnosticsHash string) error {
	marker, err := readM2PrivateRecord(filepath.Join(dir, "recovery-pending.json"))
	if err != nil || m2SHA256(marker) != markerHash {
		return fmt.Errorf("original recovery marker mismatch: %v", err)
	}
	ledger, err := readM2PrivateRecord(filepath.Join(dir, "ledger.json"))
	if err != nil || m2SHA256(ledger) != ledgerHash {
		return fmt.Errorf("original ledger mismatch: %v", err)
	}
	diag, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics.json"))
	if err != nil || m2SHA256(diag) != diagnosticsHash {
		return fmt.Errorf("original diagnostic mismatch: %v", err)
	}
	copyDiag, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics-"+caseID+".json"))
	if err != nil || !bytes.Equal(diag, copyDiag) {
		return fmt.Errorf("per-case diagnostics do not match canonical bytes: %v", err)
	}
	var record struct {
		CaseID string `json:"caseID"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(diag, &record); err != nil || record.CaseID != caseID || record.Status != "skipped-recovery-incomplete" {
		return fmt.Errorf("historic scenario is not the expected failed/incomplete case: %v", err)
	}
	return nil
}
func (w m2ReplacementWorkflow) teardown(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	var p m2ReplacementPreflight
	if err := w.readPreflight(&p); err != nil {
		return fmt.Errorf("valid preflight required: %w", err)
	}
	if p.CaseID != w.caseID || p.MarkerSHA256 != w.expectedMarker || p.LedgerSHA256 != w.expectedLedger {
		return fmt.Errorf("stale preflight receipt")
	}
	var livePreflight m2ReplacementPreflightRevalidation
	if err := w.read("preflight-live-verified", &livePreflight); err != nil || livePreflight.CaseID != w.caseID || livePreflight.Status != "VERIFIED_OLD_LAB_PREFLIGHT_REVALIDATED" {
		return fmt.Errorf("fresh live preflight receipt required before teardown: %v", err)
	}
	preflightBytes, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil || m2ValidateReplacementPreflightRevalidation(livePreflight, w.caseID, preflightBytes, p) != nil {
		return fmt.Errorf("fresh live preflight receipt is not bound to the immutable preflight: %v", err)
	}
	if err := m2VerifyReplacementHistory(w.dir, w.caseID, w.expectedMarker, w.expectedLedger, w.expectedDiagnostics); err != nil {
		return fmt.Errorf("historic failure evidence changed after preflight: %w", err)
	}
	if err := m2VerifyReplacementInventoryFile(w.dir, p); err != nil {
		return fmt.Errorf("preflight resource inventory is incomplete: %w", err)
	}
	var keaPreflight m2ReplacementKeaPreflight
	if err := w.read("kea-preflight", &keaPreflight); err != nil || keaPreflight.CaseID != w.caseID || keaPreflight.Status != "VERIFIED_APPROVED_KEA_LOCAL_IMAGES" || m2ValidateReplacementKeaDockerConfigIDs(keaPreflight.ConfigIDs) != nil {
		return fmt.Errorf("verified local Kea image preflight is required before teardown: %v", err)
	}
	preflightBytes, err = readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	keaBytes, err := readM2PrivateRecord(w.path("kea-preflight"))
	if err != nil {
		return err
	}
	if keaPreflight.PreflightSHA256 != m2SHA256(preflightBytes) {
		return fmt.Errorf("Kea image preflight is not linked to the sealed old-cluster preflight")
	}
	keaHash := m2SHA256(keaBytes)
	livePreflightBytes, err := readM2PrivateRecord(w.path("preflight-live-verified"))
	if err != nil {
		return err
	}
	livePreflightHash := m2SHA256(livePreflightBytes)
	preflightHash := m2SHA256(preflightBytes)
	prior, err := m2FindReplacementTeardownAttempt(w, p, preflightHash, livePreflightHash, keaHash)
	if err != nil {
		return err
	}
	if prior.Done {
		return fmt.Errorf("replacement teardown already has a submitted or completed outcome; no replay")
	}
	if prior.Blocked {
		return fmt.Errorf("replacement teardown has a %s outcome; destructive replay is forbidden", prior.Status)
	}
	attempt := prior.Attempt
	p.KeaDockerConfigIDs = keaPreflight.ConfigIDs
	intentPath, receiptPath := m2ReplacementTeardownAttemptPaths(w, attempt)
	intentRecord := map[string]any{"caseID": w.caseID, "status": "TEARDOWN_ONCE", "preflightSHA256": preflightHash, "preflightLiveSHA256": livePreflightHash, "keaPreflightSHA256": keaHash}
	if attempt > 1 {
		intentRecord["attempt"] = attempt
		intentRecord["previousIntentSHA256"] = m2SHA256(prior.PreviousIntent)
		intentRecord["previousReceiptSHA256"] = m2SHA256(prior.PreviousReceipt)
	}
	intentData, _ := json.Marshal(intentRecord)
	if err := writePrivateExclusiveOrReplace(intentPath, append(intentData, '\n')); err != nil {
		return fmt.Errorf("teardown intent already exists or cannot be sealed: %w", err)
	}
	r, opErr := w.ops.teardown(ctx, p)
	if opErr != nil {
		status := r.Status
		if status == "" {
			status = "OUTCOME_UNKNOWN"
		}
		receipt := map[string]any{"caseID": w.caseID, "attempt": attempt, "status": status, "error": opErr.Error(), "observation": r, "preflightSHA256": preflightHash, "preflightLiveSHA256": livePreflightHash, "keaPreflightSHA256": keaHash, "intentSHA256": m2SHA256(append(intentData, '\n'))}
		if attempt > 1 {
			receipt["previousReceiptSHA256"] = m2SHA256(prior.PreviousReceipt)
		}
		data, _ := json.Marshal(receipt)
		_ = writePrivateExclusiveOrReplace(receiptPath, append(data, '\n'))
		if status == "NOT_SUBMITTED" {
			return fmt.Errorf("teardown was refused before command submission; original evidence retained for checked continuation: %w", opErr)
		}
		return fmt.Errorf("teardown outcome is not verified; no retry: %w", opErr)
	}
	r.PreflightSHA256 = preflightHash
	r.PreflightLiveSHA256 = livePreflightHash
	r.KeaPreflightSHA256 = keaHash
	if r.Status != "VERIFIED_OLD_LAB_ABSENT" || !r.OldClusterAbsent || !r.OldContainersAbsent || !r.OldVolumesAbsent || r.M1DockerID != p.M1DockerID {
		receipt := map[string]any{"caseID": w.caseID, "attempt": attempt, "status": "FAILED_OR_PARTIAL", "observation": r, "preflightSHA256": r.PreflightSHA256, "preflightLiveSHA256": r.PreflightLiveSHA256, "keaPreflightSHA256": r.KeaPreflightSHA256, "intentSHA256": m2SHA256(append(intentData, '\n'))}
		data, _ := json.Marshal(receipt)
		_ = writePrivateExclusiveOrReplace(receiptPath, append(data, '\n'))
		return fmt.Errorf("teardown receipt does not prove exact old-lab absence and M1 preservation")
	}
	if attempt == 1 {
		return writePrivateExclusiveOrReplace(receiptPath, append(mustJSON(r), '\n'))
	}
	receipt := map[string]any{"caseID": w.caseID, "attempt": attempt, "status": r.Status, "observation": r, "preflightSHA256": preflightHash, "preflightLiveSHA256": livePreflightHash, "keaPreflightSHA256": keaHash, "intentSHA256": m2SHA256(append(intentData, '\n')), "previousReceiptSHA256": m2SHA256(prior.PreviousReceipt)}
	data, _ := json.Marshal(receipt)
	return writePrivateExclusiveOrReplace(receiptPath, append(data, '\n'))
}

func m2ReplacementTeardownAttemptPaths(w m2ReplacementWorkflow, attempt int) (string, string) {
	if attempt == 1 {
		return w.path("teardown-intent"), w.path("teardown")
	}
	return w.path(fmt.Sprintf("teardown-intent-attempt-%d", attempt)), w.path(fmt.Sprintf("teardown-attempt-%d", attempt))
}

func m2FindReplacementTeardownAttempt(w m2ReplacementWorkflow, p m2ReplacementPreflight, preflightHash, liveHash, keaHash string) (m2ReplacementTeardownAttemptInfo, error) {
	var previousIntent, previousReceipt []byte
	for attempt := 1; ; attempt++ {
		intentPath, receiptPath := m2ReplacementTeardownAttemptPaths(w, attempt)
		_, intentErr := os.Lstat(intentPath)
		_, receiptErr := os.Lstat(receiptPath)
		intentMissing, receiptMissing := os.IsNotExist(intentErr), os.IsNotExist(receiptErr)
		if intentMissing && receiptMissing {
			entries, err := os.ReadDir(w.dir)
			if err != nil {
				return m2ReplacementTeardownAttemptInfo{}, err
			}
			for _, entry := range entries {
				for _, prefix := range []string{"cluster-replacement-teardown-intent-attempt-", "cluster-replacement-teardown-attempt-"} {
					name := entry.Name()
					if strings.HasPrefix(name, prefix) {
						n, parseErr := strconv.Atoi(strings.TrimPrefix(name, prefix))
						if parseErr != nil || n >= attempt {
							return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("unexpected or out-of-order teardown retry evidence %s", name)
						}
					}
				}
			}
			return m2ReplacementTeardownAttemptInfo{Attempt: attempt, IntentPath: intentPath, ReceiptPath: receiptPath, PreviousIntent: previousIntent, PreviousReceipt: previousReceipt}, nil
		}
		if intentErr != nil || receiptErr != nil || intentMissing || receiptMissing {
			return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("teardown attempt %d has incomplete intent/receipt evidence", attempt)
		}
		intentBytes, err := readM2PrivateRecord(intentPath)
		if err != nil {
			return m2ReplacementTeardownAttemptInfo{}, err
		}
		receiptBytes, err := readM2PrivateRecord(receiptPath)
		if err != nil {
			return m2ReplacementTeardownAttemptInfo{}, err
		}
		if attempt == 1 {
			if err := m2ValidateReplacementIntent(intentPath, w.caseID, "TEARDOWN_ONCE", map[string]string{"preflightSHA256": preflightHash, "preflightLiveSHA256": liveHash, "keaPreflightSHA256": keaHash}); err != nil {
				return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("initial teardown intent is invalid: %w", err)
			}
		} else {
			var intent struct {
				CaseID                string `json:"caseID"`
				Status                string `json:"status"`
				Attempt               int    `json:"attempt"`
				PreflightSHA256       string `json:"preflightSHA256"`
				PreflightLiveSHA256   string `json:"preflightLiveSHA256"`
				KeaPreflightSHA256    string `json:"keaPreflightSHA256"`
				PreviousIntentSHA256  string `json:"previousIntentSHA256"`
				PreviousReceiptSHA256 string `json:"previousReceiptSHA256"`
			}
			if json.Unmarshal(intentBytes, &intent) != nil || intent.CaseID != w.caseID || intent.Status != "TEARDOWN_ONCE" || intent.Attempt != attempt || intent.PreflightSHA256 != preflightHash || intent.PreflightLiveSHA256 != liveHash || intent.KeaPreflightSHA256 != keaHash || intent.PreviousIntentSHA256 != m2SHA256(previousIntent) || intent.PreviousReceiptSHA256 != m2SHA256(previousReceipt) {
				return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("teardown attempt %d intent does not extend the prior NOT_SUBMITTED attempt", attempt)
			}
		}
		var envelope struct {
			CaseID                string                 `json:"caseID"`
			Attempt               int                    `json:"attempt"`
			Status                string                 `json:"status"`
			Error                 string                 `json:"error"`
			Observation           *m2ReplacementTeardown `json:"observation"`
			PreflightSHA256       string                 `json:"preflightSHA256"`
			PreflightLiveSHA256   string                 `json:"preflightLiveSHA256"`
			KeaPreflightSHA256    string                 `json:"keaPreflightSHA256"`
			IntentSHA256          string                 `json:"intentSHA256"`
			PreviousReceiptSHA256 string                 `json:"previousReceiptSHA256"`
		}
		if json.Unmarshal(receiptBytes, &envelope) != nil || envelope.Status == "" {
			return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("teardown attempt %d receipt is malformed", attempt)
		}
		if envelope.PreflightSHA256 != preflightHash || envelope.PreflightLiveSHA256 != liveHash || envelope.KeaPreflightSHA256 != keaHash {
			return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("teardown attempt %d receipt does not bind the exact preflight", attempt)
		}
		var observed m2ReplacementTeardown
		if envelope.Observation != nil {
			observed = *envelope.Observation
		} else if err := json.Unmarshal(receiptBytes, &observed); err != nil {
			return m2ReplacementTeardownAttemptInfo{}, err
		}
		if attempt > 1 && (envelope.CaseID != w.caseID || envelope.Attempt != attempt || envelope.IntentSHA256 != m2SHA256(intentBytes) || envelope.PreviousReceiptSHA256 != m2SHA256(previousReceipt)) {
			return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("teardown attempt %d receipt linkage mismatch", attempt)
		}
		if envelope.Status == "NOT_SUBMITTED" {
			if envelope.Error == "" || (observed.Status != "" && observed.Status != "NOT_SUBMITTED") || observed.OldClusterAbsent || observed.OldContainersAbsent || observed.OldVolumesAbsent || observed.M1DockerID != "" {
				return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("teardown attempt %d NOT_SUBMITTED receipt is ambiguous", attempt)
			}
			previousIntent, previousReceipt = intentBytes, receiptBytes
			continue
		}
		if attempt > 1 && (envelope.CaseID != w.caseID || envelope.Attempt != attempt || envelope.IntentSHA256 != m2SHA256(intentBytes) || envelope.PreviousReceiptSHA256 != m2SHA256(previousReceipt)) {
			return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("teardown attempt %d receipt linkage mismatch", attempt)
		}
		if envelope.Status == "VERIFIED_OLD_LAB_ABSENT" && observed.OldClusterAbsent && observed.OldContainersAbsent && observed.OldVolumesAbsent && observed.M1DockerID == p.M1DockerID && observed.PreflightSHA256 == preflightHash && observed.PreflightLiveSHA256 == liveHash && observed.KeaPreflightSHA256 == keaHash {
			return m2ReplacementTeardownAttemptInfo{Attempt: attempt, IntentPath: intentPath, ReceiptPath: receiptPath, IntentBytes: intentBytes, ReceiptBytes: receiptBytes, PreviousIntent: previousIntent, PreviousReceipt: previousReceipt, Teardown: observed, Done: true}, nil
		}
		return m2ReplacementTeardownAttemptInfo{Attempt: attempt, IntentPath: intentPath, ReceiptPath: receiptPath, IntentBytes: intentBytes, ReceiptBytes: receiptBytes, PreviousIntent: previousIntent, PreviousReceipt: previousReceipt, Teardown: observed, Blocked: true, Status: envelope.Status}, nil
	}
}

func m2ReadLatestReplacementTeardown(w m2ReplacementWorkflow, p m2ReplacementPreflight) (m2ReplacementTeardownAttemptInfo, error) {
	preflight, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return m2ReplacementTeardownAttemptInfo{}, err
	}
	live, err := readM2PrivateRecord(w.path("preflight-live-verified"))
	if err != nil {
		return m2ReplacementTeardownAttemptInfo{}, err
	}
	kea, err := readM2PrivateRecord(w.path("kea-preflight"))
	if err != nil {
		return m2ReplacementTeardownAttemptInfo{}, err
	}
	info, err := m2FindReplacementTeardownAttempt(w, p, m2SHA256(preflight), m2SHA256(live), m2SHA256(kea))
	if err != nil {
		return m2ReplacementTeardownAttemptInfo{}, err
	}
	if info.Blocked {
		return m2ReadReplacementTeardownReconciliation(w, p, info, preflight, live, kea)
	}
	if !info.Done {
		return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("no completed verified teardown receipt exists")
	}
	return info, nil
}

func m2ReadReplacementTeardownReconciliation(w m2ReplacementWorkflow, p m2ReplacementPreflight, partial m2ReplacementTeardownAttemptInfo, preflight, live, kea []byte) (m2ReplacementTeardownAttemptInfo, error) {
	intentBytes, err := readM2PrivateRecord(w.path("teardown-reconcile-intent"))
	if err != nil {
		return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("partial teardown lacks a read-only reconciliation intent: %w", err)
	}
	var intent map[string]string
	if json.Unmarshal(intentBytes, &intent) != nil || intent["caseID"] != w.caseID || intent["status"] != "VERIFY_TEARDOWN_READ_ONLY" || intent["preflightSHA256"] != m2SHA256(preflight) || intent["preflightLiveSHA256"] != m2SHA256(live) || intent["keaPreflightSHA256"] != m2SHA256(kea) || intent["previousIntentSHA256"] != m2SHA256(partial.IntentBytes) || intent["previousReceiptSHA256"] != m2SHA256(partial.ReceiptBytes) {
		return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("read-only reconciliation intent is stale or unbound")
	}
	receiptBytes, err := readM2PrivateRecord(w.path("teardown-reconciled"))
	if err != nil {
		return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("partial teardown lacks a verified reconciliation receipt: %w", err)
	}
	var receipt m2ReplacementTeardownReconciliation
	if json.Unmarshal(receiptBytes, &receipt) != nil || receipt.CaseID != w.caseID || receipt.Status != "VERIFIED_OLD_LAB_ABSENT_AFTER_PARTIAL_RECEIPT" || receipt.PreflightSHA256 != m2SHA256(preflight) || receipt.PreflightLiveSHA256 != m2SHA256(live) || receipt.KeaPreflightSHA256 != m2SHA256(kea) || receipt.PreviousIntentSHA256 != m2SHA256(partial.IntentBytes) || receipt.PreviousReceiptSHA256 != m2SHA256(partial.ReceiptBytes) || receipt.IntentSHA256 != m2SHA256(intentBytes) {
		return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("read-only reconciliation receipt is malformed or stale")
	}
	observed := receipt.Observation
	if observed.Status != "VERIFIED_OLD_LAB_ABSENT" || !observed.OldClusterAbsent || !observed.OldContainersAbsent || !observed.OldVolumesAbsent || observed.M1DockerID != p.M1DockerID || observed.PreflightSHA256 != m2SHA256(preflight) || observed.PreflightLiveSHA256 != m2SHA256(live) || observed.KeaPreflightSHA256 != m2SHA256(kea) {
		return m2ReplacementTeardownAttemptInfo{}, fmt.Errorf("read-only reconciliation does not prove exact old-lab absence and M1 preservation")
	}
	return m2ReplacementTeardownAttemptInfo{Attempt: partial.Attempt, IntentPath: w.path("teardown-reconcile-intent"), ReceiptPath: w.path("teardown-reconciled"), IntentBytes: intentBytes, ReceiptBytes: receiptBytes, Teardown: observed, Done: true}, nil
}

func (w m2ReplacementWorkflow) reconcileTeardown(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	var p m2ReplacementPreflight
	if err := w.readPreflight(&p); err != nil {
		return err
	}
	preflight, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	live, err := readM2PrivateRecord(w.path("preflight-live-verified"))
	if err != nil {
		return err
	}
	kea, err := readM2PrivateRecord(w.path("kea-preflight"))
	if err != nil {
		return err
	}
	var liveReceipt m2ReplacementPreflightRevalidation
	var keaReceipt m2ReplacementKeaPreflight
	if json.Unmarshal(live, &liveReceipt) != nil || m2ValidateReplacementPreflightRevalidation(liveReceipt, w.caseID, preflight, p) != nil || json.Unmarshal(kea, &keaReceipt) != nil || keaReceipt.CaseID != w.caseID || keaReceipt.Status != "VERIFIED_APPROVED_KEA_LOCAL_IMAGES" || keaReceipt.PreflightSHA256 != m2SHA256(preflight) {
		return fmt.Errorf("reconciliation requires exact sealed preflight, fresh observation, and Kea image evidence")
	}
	if err := m2VerifyReplacementHistory(w.dir, w.caseID, w.expectedMarker, w.expectedLedger, w.expectedDiagnostics); err != nil {
		return fmt.Errorf("historic failure evidence changed before teardown reconciliation: %w", err)
	}
	if err := m2VerifyReplacementInventoryFile(w.dir, p); err != nil {
		return err
	}
	partial, err := m2FindReplacementTeardownAttempt(w, p, m2SHA256(preflight), m2SHA256(live), m2SHA256(kea))
	if err != nil {
		return err
	}
	if !partial.Blocked || (partial.Status != "PARTIAL_OR_UNVERIFIED" && partial.Status != "FAILED_OR_PARTIAL") {
		return fmt.Errorf("read-only reconciliation requires the exact preserved partial teardown outcome")
	}
	if _, err := os.Lstat(w.path("teardown-reconcile-intent")); err == nil {
		return fmt.Errorf("read-only teardown reconciliation is one-use")
	} else if !os.IsNotExist(err) {
		return err
	}
	intentData, _ := json.Marshal(map[string]string{"caseID": w.caseID, "status": "VERIFY_TEARDOWN_READ_ONLY", "preflightSHA256": m2SHA256(preflight), "preflightLiveSHA256": m2SHA256(live), "keaPreflightSHA256": m2SHA256(kea), "previousIntentSHA256": m2SHA256(partial.IntentBytes), "previousReceiptSHA256": m2SHA256(partial.ReceiptBytes)})
	if err := writePrivateExclusiveOrReplace(w.path("teardown-reconcile-intent"), append(intentData, '\n')); err != nil {
		return err
	}
	observed, err := w.ops.verifyTeardown(ctx, p)
	if err != nil {
		_ = w.write("teardown-reconcile-failed", map[string]any{"caseID": w.caseID, "status": "READ_ONLY_VERIFICATION_FAILED", "error": err.Error(), "previousReceiptSHA256": m2SHA256(partial.ReceiptBytes)})
		return fmt.Errorf("read-only teardown reconciliation failed; destructive retry remains forbidden: %w", err)
	}
	observed.PreflightSHA256, observed.PreflightLiveSHA256, observed.KeaPreflightSHA256 = m2SHA256(preflight), m2SHA256(live), m2SHA256(kea)
	if observed.Status != "VERIFIED_OLD_LAB_ABSENT" || !observed.OldClusterAbsent || !observed.OldContainersAbsent || !observed.OldVolumesAbsent || observed.M1DockerID != p.M1DockerID {
		_ = w.write("teardown-reconcile-failed", map[string]any{"caseID": w.caseID, "status": "READ_ONLY_VERIFICATION_INCOMPLETE", "observation": observed, "previousReceiptSHA256": m2SHA256(partial.ReceiptBytes)})
		return fmt.Errorf("read-only reconciliation did not prove exact old-lab absence and M1 preservation")
	}
	receipt := m2ReplacementTeardownReconciliation{CaseID: w.caseID, Status: "VERIFIED_OLD_LAB_ABSENT_AFTER_PARTIAL_RECEIPT", PreflightSHA256: m2SHA256(preflight), PreflightLiveSHA256: m2SHA256(live), KeaPreflightSHA256: m2SHA256(kea), PreviousIntentSHA256: m2SHA256(partial.IntentBytes), PreviousReceiptSHA256: m2SHA256(partial.ReceiptBytes), IntentSHA256: m2SHA256(append(intentData, '\n')), Observation: observed}
	if err := w.write("teardown-reconciled", receipt); err != nil {
		return err
	}
	if _, err := m2ReadLatestReplacementTeardown(w, p); err != nil {
		return fmt.Errorf("new read-only teardown reconciliation receipt failed independent validation: %w", err)
	}
	return nil
}

func (w m2ReplacementWorkflow) create(ctx context.Context) error {
	return w.createWithIntent(ctx, false)
}

// resumeUnsubmittedCreate preserves the original failed create receipt and
// allows one continuation only for the exact known pre-submission guard. It
// never repeats teardown and refuses any ambiguous or interrupted outcome.
func (w m2ReplacementWorkflow) resumeUnsubmittedCreate(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	if err := m2VerifyReplacementHistory(w.dir, w.caseID, w.expectedMarker, w.expectedLedger, w.expectedDiagnostics); err != nil {
		return fmt.Errorf("historic failure evidence changed before create continuation: %w", err)
	}
	intentBytes, err := readM2PrivateRecord(w.path("create-intent"))
	if err != nil {
		return fmt.Errorf("original single-use create intent required: %w", err)
	}
	receiptBytes, err := readM2PrivateRecord(w.path("created"))
	if err != nil {
		return fmt.Errorf("original create outcome required: %w", err)
	}
	var p m2ReplacementPreflight
	if err := w.readPreflight(&p); err != nil {
		return err
	}
	teardownInfo, err := m2ReadLatestReplacementTeardown(w, p)
	if err != nil {
		return err
	}
	preflightBytes, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	liveBytes, err := readM2PrivateRecord(w.path("preflight-live-verified"))
	if err != nil {
		return err
	}
	keaBytes, err := readM2PrivateRecord(w.path("kea-preflight"))
	if err != nil {
		return err
	}
	wantLinks := map[string]string{"preflightSHA256": m2SHA256(preflightBytes), "preflightLiveSHA256": m2SHA256(liveBytes), "keaPreflightSHA256": m2SHA256(keaBytes), "teardownSHA256": m2SHA256(teardownInfo.ReceiptBytes)}
	if err := m2ValidateReplacementIntent(w.path("create-intent"), w.caseID, "CREATE_ONCE", wantLinks); err != nil {
		return fmt.Errorf("original create intent is invalid: %w", err)
	}
	var failed struct {
		Status              string               `json:"status"`
		Error               string               `json:"error"`
		Observation         m2ReplacementCreated `json:"observation"`
		PreflightSHA256     string               `json:"preflightSHA256"`
		PreflightLiveSHA256 string               `json:"preflightLiveSHA256"`
		KeaPreflightSHA256  string               `json:"keaPreflightSHA256"`
		TeardownSHA256      string               `json:"teardownSHA256"`
	}
	if err := json.Unmarshal(receiptBytes, &failed); err != nil {
		return fmt.Errorf("original create receipt is malformed: %w", err)
	}
	if failed.Status != "NOT_SUBMITTED" || failed.Error != "M2 build inputs differ from the complete current source fingerprint" || !reflect.DeepEqual(failed.Observation, m2ReplacementCreated{}) || failed.PreflightSHA256 != wantLinks["preflightSHA256"] || failed.PreflightLiveSHA256 != wantLinks["preflightLiveSHA256"] || failed.KeaPreflightSHA256 != wantLinks["keaPreflightSHA256"] || failed.TeardownSHA256 != wantLinks["teardownSHA256"] {
		return fmt.Errorf("create continuation requires the exact preserved, proven pre-submission fingerprint-guard failure")
	}
	for _, stage := range []string{"create-resume-intent", "created-not-submitted-attempt-1", "namespaces", "namespace-intent", "reconciled"} {
		if _, err := os.Lstat(w.path(stage)); err == nil {
			return fmt.Errorf("create continuation refuses existing stage %s", stage)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	resumeIntent, _ := json.Marshal(map[string]string{"caseID": w.caseID, "status": "CONTINUE_NOT_SUBMITTED_CREATE_ONCE", "createIntentSHA256": m2SHA256(intentBytes), "failedReceiptSHA256": m2SHA256(receiptBytes), "preflightSHA256": wantLinks["preflightSHA256"], "preflightLiveSHA256": wantLinks["preflightLiveSHA256"], "keaPreflightSHA256": wantLinks["keaPreflightSHA256"], "teardownSHA256": wantLinks["teardownSHA256"]})
	if err := writePrivateExclusiveOrReplace(w.path("create-resume-intent"), append(resumeIntent, '\n')); err != nil {
		return fmt.Errorf("single-use continuation intent already consumed: %w", err)
	}
	if err := os.Rename(w.path("created"), w.path("created-not-submitted-attempt-1")); err != nil {
		return fmt.Errorf("preserve original not-submitted receipt before continuation: %w", err)
	}
	if err := syncPrivateDirectory(w.dir); err != nil {
		return fmt.Errorf("sync original create receipt archive: %w", err)
	}
	return w.createWithIntent(ctx, true)
}

func (w m2ReplacementWorkflow) createWithIntent(ctx context.Context, continuing bool) error {
	if err := w.ready(); err != nil {
		return err
	}
	var p m2ReplacementPreflight
	if err := w.readPreflight(&p); err != nil {
		return err
	}
	if err := m2VerifyReplacementHistory(w.dir, w.caseID, w.expectedMarker, w.expectedLedger, w.expectedDiagnostics); err != nil {
		return fmt.Errorf("historic failure evidence changed before recreation: %w", err)
	}
	teardownInfo, err := m2ReadLatestReplacementTeardown(w, p)
	if err != nil {
		return fmt.Errorf("verified teardown required before create: %w", err)
	}
	d := teardownInfo.Teardown
	preflightBytes, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	keaBytes, err := readM2PrivateRecord(w.path("kea-preflight"))
	if err != nil {
		return fmt.Errorf("verified local Kea image preflight required before creation: %w", err)
	}
	livePreflightBytes, err := readM2PrivateRecord(w.path("preflight-live-verified"))
	if err != nil {
		return fmt.Errorf("fresh old-cluster preflight revalidation required before creation: %w", err)
	}
	var keaPreflight m2ReplacementKeaPreflight
	if err := json.Unmarshal(keaBytes, &keaPreflight); err != nil || keaPreflight.CaseID != w.caseID || keaPreflight.Status != "VERIFIED_APPROVED_KEA_LOCAL_IMAGES" || m2ValidateReplacementKeaDockerConfigIDs(keaPreflight.ConfigIDs) != nil {
		return fmt.Errorf("Kea image preflight is malformed or unapproved: %v", err)
	}
	teardownBytes := teardownInfo.ReceiptBytes
	preflightHash, livePreflightHash, keaHash, teardownHash := m2SHA256(preflightBytes), m2SHA256(livePreflightBytes), m2SHA256(keaBytes), m2SHA256(teardownBytes)
	if keaPreflight.PreflightSHA256 != preflightHash || d.PreflightSHA256 != preflightHash || d.PreflightLiveSHA256 != livePreflightHash || d.KeaPreflightSHA256 != keaHash {
		return fmt.Errorf("teardown receipt or intent is not bound to the sealed preflight")
	}
	p.KeaDockerConfigIDs = keaPreflight.ConfigIDs
	intentData, _ := json.Marshal(map[string]string{"caseID": w.caseID, "status": "CREATE_ONCE", "preflightSHA256": preflightHash, "preflightLiveSHA256": livePreflightHash, "keaPreflightSHA256": keaHash, "teardownSHA256": teardownHash})
	if continuing {
		readErr := m2ValidateReplacementIntent(w.path("create-resume-intent"), w.caseID, "CONTINUE_NOT_SUBMITTED_CREATE_ONCE", map[string]string{"createIntentSHA256": m2SHA256(append(intentData, '\n'))})
		if readErr != nil {
			return fmt.Errorf("single-use create continuation intent is missing or mismatched: %v", readErr)
		}
	} else if err := writePrivateExclusiveOrReplace(w.path("create-intent"), append(intentData, '\n')); err != nil {
		return fmt.Errorf("creation intent already exists or cannot be sealed: %w", err)
	}
	r, err := w.ops.create(ctx, p, d)
	if err != nil {
		status := r.Status
		if status == "" {
			status = "NOT_SUBMITTED"
		}
		_ = w.write("created", map[string]any{"status": status, "error": err.Error(), "observation": r, "preflightSHA256": preflightHash, "preflightLiveSHA256": livePreflightHash, "keaPreflightSHA256": keaHash, "teardownSHA256": teardownHash})
		return fmt.Errorf("creation outcome is not verified; no retry: %w", err)
	}
	r.PreflightSHA256, r.PreflightLiveSHA256, r.KeaPreflightSHA256, r.TeardownSHA256 = preflightHash, livePreflightHash, keaHash, teardownHash
	if r.Status != "VERIFIED_NEW_LAB" || r.M1DockerID != p.M1DockerID || r.NewLab.Cluster != m2LabProfile.cluster {
		_ = w.write("created", map[string]any{"status": "FAILED_OR_PARTIAL", "observation": r})
		return fmt.Errorf("new lab receipt/M1 identity mismatch")
	}
	if err := m2ValidateReplacementKeaConfigIDs(r.KeaConfigIDs); err != nil {
		_ = w.write("created", map[string]any{"status": "FAILED_OR_PARTIAL", "observation": r, "error": err.Error()})
		return fmt.Errorf("new lab exact Kea image identities are incomplete: %w", err)
	}
	if err := m2ValidateReplacementNodes(r.NewLab.Nodes, r.NewVolumes); err != nil {
		_ = w.write("created", map[string]any{"status": "FAILED_OR_PARTIAL", "observation": r, "error": err.Error()})
		return err
	}
	for _, name := range m2LabProfile.nodes {
		if p.OldLab.Nodes[name].DockerID == r.NewLab.Nodes[name].DockerID || p.OldLab.Nodes[name].KubernetesUID == r.NewLab.Nodes[name].KubernetesUID || p.OldVolumes[name] == r.NewVolumes[name] {
			_ = w.write("created", map[string]any{"status": "FAILED_OR_PARTIAL", "observation": r})
			return fmt.Errorf("new cluster reused old node/storage incarnation")
		}
	}
	return w.write("created", r)
}
func (w m2ReplacementWorkflow) reconcileUnsubmittedNamespaces(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	if err := m2VerifyReplacementHistory(w.dir, w.caseID, w.expectedMarker, w.expectedLedger, w.expectedDiagnostics); err != nil {
		return fmt.Errorf("historic failure evidence changed before namespace reconciliation: %w", err)
	}
	var p m2ReplacementPreflight
	var c m2ReplacementCreated
	if err := w.readPreflight(&p); err != nil {
		return err
	}
	if err := w.read("created", &c); err != nil || c.Status != "VERIFIED_NEW_LAB" {
		return fmt.Errorf("verified new cluster required before namespace reconciliation: %v", err)
	}
	if _, err := m2ReadLatestReplacementTeardown(w, p); err != nil {
		return err
	}
	preflightBytes, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	liveBytes, err := readM2PrivateRecord(w.path("preflight-live-verified"))
	if err != nil {
		return err
	}
	keaBytes, err := readM2PrivateRecord(w.path("kea-preflight"))
	if err != nil {
		return err
	}
	createdBytes, err := readM2PrivateRecord(w.path("created"))
	if err != nil {
		return err
	}
	ph, lph, kh, ch := m2SHA256(preflightBytes), m2SHA256(liveBytes), m2SHA256(keaBytes), m2SHA256(createdBytes)
	if m2ValidateReplacementIntent(w.path("namespace-intent"), w.caseID, "NAMESPACE_CREATE_ONCE", map[string]string{"createdSHA256": ch, "preflightSHA256": ph, "preflightLiveSHA256": lph, "keaPreflightSHA256": kh}) != nil {
		return fmt.Errorf("original one-use namespace intent is missing or mismatched")
	}
	for _, stage := range []string{"namespaces-not-submitted", "namespace-resume-intent", "namespaces", "reconciled"} {
		if _, err := os.Lstat(w.path(stage)); err == nil {
			return fmt.Errorf("namespace reconciliation refuses existing stage %s", stage)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for _, path := range []string{filepath.Join(w.dir, "cluster-replacement-namespace-pending-"+w.caseID+".json"), filepath.Join(w.dir, "namespaces.partial.json"), filepath.Join(w.dir, "namespace-receipt.json")} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("namespace reconciliation found active or partial namespace state %s", filepath.Base(path))
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	oldReceipt := filepath.Join(w.dir, "namespace-receipt-archived-old-"+w.caseID+".json")
	oldBytes, err := readM2PrivateRecord(oldReceipt)
	if err != nil || m2SHA256(oldBytes) != p.NamespaceReceiptSHA256 {
		return fmt.Errorf("archived old namespace receipt is missing or changed: %v", err)
	}
	oldPartial := filepath.Join(w.dir, "namespaces-partial-archived-old-"+w.caseID+".json")
	if p.PartialNamespaceSHA256 != "" {
		partialBytes, err := readM2PrivateRecord(oldPartial)
		if err != nil || m2SHA256(partialBytes) != p.PartialNamespaceSHA256 {
			return fmt.Errorf("archived old partial namespace evidence is missing or changed: %v", err)
		}
	}
	logPath := filepath.Join(w.dir, "namespaces-stage-failed-attempt-1.log")
	failureLog, err := readM2PrivateRecord(logPath)
	if err != nil || !bytes.Contains(failureLog, []byte("M2 lab identity lacks verified server, inline CA or administrator client")) {
		return fmt.Errorf("exact preserved pre-submission namespace failure log is required: %v", err)
	}
	observation, err := w.ops.verifyNamespacesAbsent(ctx, c)
	if err != nil {
		return fmt.Errorf("fresh namespace absence observation failed: %w", err)
	}
	if observation.Status != "VERIFIED_NEW_NAMESPACES_ABSENT" || !reflect.DeepEqual(observation.Cluster, c.NewLab) || !observation.RuntimeAbsent || !observation.OutsideAbsent || observation.M1DockerID != p.M1DockerID || observation.M1DockerID != c.M1DockerID {
		return fmt.Errorf("namespace absence reconciliation did not verify exact new cluster and M1 identities")
	}
	namespaceIntentBytes, err := readM2PrivateRecord(w.path("namespace-intent"))
	if err != nil {
		return err
	}
	receipt := m2ReplacementNamespaceReconciliation{CaseID: w.caseID, Status: "VERIFIED_NAMESPACE_STAGE_NOT_SUBMITTED", NamespaceIntentSHA256: m2SHA256(namespaceIntentBytes), CreatedSHA256: ch, PreflightSHA256: ph, PreflightLiveSHA256: lph, KeaPreflightSHA256: kh, FailureLogSHA256: m2SHA256(failureLog), Error: "M2 lab identity lacks verified server, inline CA or administrator client", Observation: observation}
	return w.write("namespaces-not-submitted", receipt)
}

func (w m2ReplacementWorkflow) resumeUnsubmittedNamespaces(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	var receipt m2ReplacementNamespaceReconciliation
	if err := w.read("namespaces-not-submitted", &receipt); err != nil {
		return fmt.Errorf("verified namespace not-submitted reconciliation required: %w", err)
	}
	if receipt.CaseID != w.caseID || receipt.Status != "VERIFIED_NAMESPACE_STAGE_NOT_SUBMITTED" || receipt.Error != "M2 lab identity lacks verified server, inline CA or administrator client" || !receipt.Observation.RuntimeAbsent || !receipt.Observation.OutsideAbsent || receipt.Observation.M1DockerID == "" {
		return fmt.Errorf("namespace continuation receipt is malformed")
	}
	var p m2ReplacementPreflight
	var c m2ReplacementCreated
	if err := w.readPreflight(&p); err != nil {
		return err
	}
	if err := w.read("created", &c); err != nil || c.Status != "VERIFIED_NEW_LAB" {
		return fmt.Errorf("verified new cluster receipt missing at namespace continuation: %v", err)
	}
	if _, err := m2ReadLatestReplacementTeardown(w, p); err != nil {
		return err
	}
	preflightBytes, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	liveBytes, err := readM2PrivateRecord(w.path("preflight-live-verified"))
	if err != nil {
		return err
	}
	keaBytes, err := readM2PrivateRecord(w.path("kea-preflight"))
	if err != nil {
		return err
	}
	createdBytes, err := readM2PrivateRecord(w.path("created"))
	if err != nil {
		return err
	}
	ph, lph, kh, ch := m2SHA256(preflightBytes), m2SHA256(liveBytes), m2SHA256(keaBytes), m2SHA256(createdBytes)
	intentBytes, err := readM2PrivateRecord(w.path("namespace-intent"))
	if err != nil || m2SHA256(intentBytes) != receipt.NamespaceIntentSHA256 ||
		receipt.CreatedSHA256 != ch || receipt.PreflightSHA256 != ph || receipt.PreflightLiveSHA256 != lph || receipt.KeaPreflightSHA256 != kh ||
		m2ValidateReplacementIntent(w.path("namespace-intent"), w.caseID, "NAMESPACE_CREATE_ONCE", map[string]string{"createdSHA256": ch, "preflightSHA256": ph, "preflightLiveSHA256": lph, "keaPreflightSHA256": kh}) != nil ||
		!reflect.DeepEqual(receipt.Observation.Cluster, c.NewLab) || receipt.Observation.M1DockerID != p.M1DockerID || receipt.Observation.M1DockerID != c.M1DockerID {
		return fmt.Errorf("namespace continuation reconciliation is stale or mismatched: %v", err)
	}
	failureLog, err := readM2PrivateRecord(filepath.Join(w.dir, "namespaces-stage-failed-attempt-1.log"))
	if err != nil || m2SHA256(failureLog) != receipt.FailureLogSHA256 {
		return fmt.Errorf("namespace failure log changed after reconciliation: %v", err)
	}
	for _, stage := range []string{"namespace-resume-intent", "namespaces", "reconciled"} {
		if _, err := os.Lstat(w.path(stage)); err == nil {
			return fmt.Errorf("namespace continuation refuses existing stage %s", stage)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	intentBytes, err = readM2PrivateRecord(w.path("namespace-intent"))
	if err != nil || m2SHA256(intentBytes) != receipt.NamespaceIntentSHA256 {
		return fmt.Errorf("original namespace intent changed after reconciliation: %v", err)
	}
	notSubmittedBytes, err := readM2PrivateRecord(w.path("namespaces-not-submitted"))
	if err != nil {
		return err
	}
	resumeIntent, _ := json.Marshal(map[string]string{"caseID": w.caseID, "status": "CONTINUE_ABSENT_NAMESPACE_STAGE_ONCE", "namespaceIntentSHA256": receipt.NamespaceIntentSHA256, "notSubmittedSHA256": m2SHA256(notSubmittedBytes), "createdSHA256": receipt.CreatedSHA256, "preflightSHA256": receipt.PreflightSHA256, "preflightLiveSHA256": receipt.PreflightLiveSHA256, "keaPreflightSHA256": receipt.KeaPreflightSHA256})
	if err := writePrivateExclusiveOrReplace(w.path("namespace-resume-intent"), append(resumeIntent, '\n')); err != nil {
		return fmt.Errorf("one-use namespace continuation already consumed: %w", err)
	}
	return w.namespacesWithIntent(ctx, true)
}

func (w m2ReplacementWorkflow) namespaces(ctx context.Context) error {
	return w.namespacesWithIntent(ctx, false)
}

func (w m2ReplacementWorkflow) namespacesWithIntent(ctx context.Context, continuing bool) error {
	if err := w.ready(); err != nil {
		return err
	}
	var p m2ReplacementPreflight
	var c m2ReplacementCreated
	if err := w.readPreflight(&p); err != nil {
		return fmt.Errorf("namespace stage requires verified preflight: %w", err)
	}
	teardownInfo, err := m2ReadLatestReplacementTeardown(w, p)
	if err != nil {
		return fmt.Errorf("namespace stage requires verified teardown: %w", err)
	}
	d := teardownInfo.Teardown
	if err := w.read("created", &c); err != nil {
		return fmt.Errorf("namespace stage requires verified creation: %w", err)
	}
	preflightBytes, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	keaBytes, err := readM2PrivateRecord(w.path("kea-preflight"))
	if err != nil {
		return err
	}
	livePreflightBytes, err := readM2PrivateRecord(w.path("preflight-live-verified"))
	if err != nil {
		return err
	}
	teardownBytes := teardownInfo.ReceiptBytes
	createdBytes, err := readM2PrivateRecord(w.path("created"))
	if err != nil {
		return err
	}
	namespaceIntentBytes, err := readM2PrivateRecord(w.path("namespace-intent"))
	if continuing && err != nil {
		return fmt.Errorf("original namespace intent missing during continuation: %w", err)
	}
	preflightHash, livePreflightHash, keaHash, teardownHash, createdHash := m2SHA256(preflightBytes), m2SHA256(livePreflightBytes), m2SHA256(keaBytes), m2SHA256(teardownBytes), m2SHA256(createdBytes)
	var keaPreflight m2ReplacementKeaPreflight
	if json.Unmarshal(keaBytes, &keaPreflight) != nil || keaPreflight.CaseID != w.caseID || keaPreflight.Status != "VERIFIED_APPROVED_KEA_LOCAL_IMAGES" || keaPreflight.PreflightSHA256 != preflightHash || m2ValidateReplacementKeaDockerConfigIDs(keaPreflight.ConfigIDs) != nil ||
		d.Status != "VERIFIED_OLD_LAB_ABSENT" || d.PreflightSHA256 != preflightHash || d.PreflightLiveSHA256 != livePreflightHash || d.KeaPreflightSHA256 != keaHash || c.Status != "VERIFIED_NEW_LAB" || c.PreflightSHA256 != preflightHash || c.PreflightLiveSHA256 != livePreflightHash || c.KeaPreflightSHA256 != keaHash || c.TeardownSHA256 != teardownHash ||
		m2ValidateReplacementIntent(w.path("create-intent"), w.caseID, "CREATE_ONCE", map[string]string{"preflightSHA256": preflightHash, "preflightLiveSHA256": livePreflightHash, "keaPreflightSHA256": keaHash, "teardownSHA256": teardownHash}) != nil {
		return fmt.Errorf("namespace stage requires linked, verified teardown and creation receipts")
	}
	intent, _ := json.Marshal(map[string]string{"caseID": w.caseID, "status": "NAMESPACE_CREATE_ONCE", "createdSHA256": createdHash, "preflightSHA256": preflightHash, "preflightLiveSHA256": livePreflightHash, "keaPreflightSHA256": keaHash})
	if continuing {
		notSubmittedBytes, readErr := readM2PrivateRecord(w.path("namespaces-not-submitted"))
		if readErr != nil {
			return fmt.Errorf("namespace continuation lacks preserved not-submitted receipt: %w", readErr)
		}
		if err := m2ValidateReplacementIntent(w.path("namespace-resume-intent"), w.caseID, "CONTINUE_ABSENT_NAMESPACE_STAGE_ONCE", map[string]string{"namespaceIntentSHA256": m2SHA256(namespaceIntentBytes), "notSubmittedSHA256": m2SHA256(notSubmittedBytes), "createdSHA256": createdHash, "preflightSHA256": preflightHash, "preflightLiveSHA256": livePreflightHash, "keaPreflightSHA256": keaHash}); err != nil {
			return fmt.Errorf("namespace continuation intent is stale or malformed: %w", err)
		}
	} else if err := writePrivateExclusiveOrReplace(w.path("namespace-intent"), append(intent, '\n')); err != nil {
		return fmt.Errorf("namespace creation intent already consumed: %w", err)
	}
	oldReceipt := filepath.Join(w.dir, "namespace-receipt.json")
	oldArchive := filepath.Join(w.dir, "namespace-receipt-archived-old-"+w.caseID+".json")
	if _, err := os.Lstat(oldReceipt); err == nil {
		var p m2ReplacementPreflight
		if err := w.readPreflight(&p); err != nil {
			return err
		}
		oldBytes, err := readM2PrivateRecord(oldReceipt)
		if err != nil || m2SHA256(oldBytes) != p.NamespaceReceiptSHA256 {
			return fmt.Errorf("old namespace receipt differs from preflight: %v", err)
		}
		if _, existsErr := os.Lstat(oldArchive); existsErr == nil {
			return fmt.Errorf("old namespace receipt archive already exists")
		} else if !os.IsNotExist(existsErr) {
			return existsErr
		}
		if err := os.Rename(oldReceipt, oldArchive); err != nil {
			return fmt.Errorf("archive old namespace receipt: %w", err)
		}
		if err := syncPrivateDirectory(w.dir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	oldPartial := filepath.Join(w.dir, "namespaces.partial.json")
	partialArchive := filepath.Join(w.dir, "namespaces-partial-archived-old-"+w.caseID+".json")
	if _, err := os.Lstat(oldPartial); err == nil {
		var p m2ReplacementPreflight
		if err := w.readPreflight(&p); err != nil {
			return err
		}
		partialBytes, err := readM2PrivateRecord(oldPartial)
		if err != nil || p.PartialNamespaceSHA256 == "" || m2SHA256(partialBytes) != p.PartialNamespaceSHA256 {
			return fmt.Errorf("old partial namespace receipt differs from preflight: %v", err)
		}
		if _, e := os.Lstat(partialArchive); e == nil {
			return fmt.Errorf("old partial namespace receipt archive already exists")
		} else if !os.IsNotExist(e) {
			return e
		}
		if err := os.Rename(oldPartial, partialArchive); err != nil {
			return err
		}
		if err := syncPrivateDirectory(w.dir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	r, err := w.ops.namespaces(ctx, c)
	if err != nil {
		return err
	}
	if r.Status != "VERIFIED_NEW_NAMESPACES" {
		return fmt.Errorf("new namespace stage is not verified")
	}
	if err := m2ValidateReplacementNamespaces(r.Namespaces); err != nil {
		return err
	}
	r.CreatedSHA256 = createdHash
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		if name == "" {
			return fmt.Errorf("unexpected namespace")
		}
	}
	if err := w.write("namespaces", r); err != nil {
		return err
	}
	newReceipt := m2NamespaceReceipt{Lab: c.NewLab, FixtureLabel: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Namespaces: r.Namespaces}
	return m2PersistReplacementNamespaceReceipt(oldReceipt, newReceipt)
}

// m2PersistReplacementNamespaceReceipt handles both provisioning adapters: the
// live adapter seals namespace-receipt.json while provisioning, whereas test
// adapters may return the verified state without writing that shared receipt.
// An existing file is accepted only when it is the exact expected private
// receipt; it is never overwritten.
func m2PersistReplacementNamespaceReceipt(path string, receipt m2NamespaceReceipt) error {
	want, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	want = append(want, '\n')
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return writePrivateExclusiveOrReplace(path, want)
	} else if err != nil {
		return err
	}
	got, err := readM2PrivateRecord(path)
	if err != nil {
		return fmt.Errorf("read provisioner namespace receipt: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("provisioner namespace receipt does not match verified replacement state")
	}
	return nil
}
func (w m2ReplacementWorkflow) finalize(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	var p m2ReplacementPreflight
	var d m2ReplacementTeardown
	var c m2ReplacementCreated
	var n m2ReplacementNamespaces
	if err := w.readPreflight(&p); err != nil {
		return fmt.Errorf("final proof requires sealed preflight: %w", err)
	}
	teardownInfo, err := m2ReadLatestReplacementTeardown(w, p)
	if err != nil {
		return fmt.Errorf("final proof requires verified teardown: %w", err)
	}
	d = teardownInfo.Teardown
	stageBytes := map[string][]byte{}
	stageBytes["teardown"] = teardownInfo.ReceiptBytes
	for stage, dst := range map[string]any{"created": &c, "namespaces": &n} {
		stageBytes[stage], err = readM2PrivateRecord(w.path(stage))
		if err != nil {
			return fmt.Errorf("final proof requires %s receipt: %w", stage, err)
		}
		if err := json.Unmarshal(stageBytes[stage], dst); err != nil {
			return fmt.Errorf("final proof requires %s receipt: %w", stage, err)
		}
	}
	preflightBytes, err := readM2PrivateRecord(w.path("preflight"))
	if err != nil {
		return err
	}
	keaBytes, err := readM2PrivateRecord(w.path("kea-preflight"))
	if err != nil {
		return err
	}
	livePreflightBytes, err := readM2PrivateRecord(w.path("preflight-live-verified"))
	if err != nil {
		return err
	}
	ph, lph, kh, th, ch := m2SHA256(preflightBytes), m2SHA256(livePreflightBytes), m2SHA256(keaBytes), m2SHA256(stageBytes["teardown"]), m2SHA256(stageBytes["created"])
	var livePreflight m2ReplacementPreflightRevalidation
	if json.Unmarshal(livePreflightBytes, &livePreflight) != nil || m2ValidateReplacementPreflightRevalidation(livePreflight, w.caseID, preflightBytes, p) != nil {
		return fmt.Errorf("fresh old-cluster preflight evidence is malformed or stale")
	}
	if ctx.Err() != nil || d.Status != "VERIFIED_OLD_LAB_ABSENT" || d.PreflightSHA256 != ph || d.PreflightLiveSHA256 != lph || d.KeaPreflightSHA256 != kh || c.Status != "VERIFIED_NEW_LAB" || c.PreflightSHA256 != ph || c.PreflightLiveSHA256 != lph || c.KeaPreflightSHA256 != kh || c.TeardownSHA256 != th || n.Status != "VERIFIED_NEW_NAMESPACES" || n.CreatedSHA256 != ch || c.M1DockerID != p.M1DockerID || d.M1DockerID != p.M1DockerID ||
		m2ValidateReplacementIntent(w.path("create-intent"), w.caseID, "CREATE_ONCE", map[string]string{"preflightSHA256": ph, "preflightLiveSHA256": lph, "keaPreflightSHA256": kh, "teardownSHA256": th}) != nil ||
		m2ValidateReplacementIntent(w.path("namespace-intent"), w.caseID, "NAMESPACE_CREATE_ONCE", map[string]string{"createdSHA256": ch, "preflightSHA256": ph, "preflightLiveSHA256": lph, "keaPreflightSHA256": kh}) != nil {
		return fmt.Errorf("lifecycle proof is incomplete or M1 changed")
	}
	if err := m2VerifyReplacementInventoryFile(w.dir, p); err != nil {
		return fmt.Errorf("final proof lost the sealed old-cluster resource inventory: %w", err)
	}
	if err := w.ops.verifyFinal(ctx, p, c, n); err != nil {
		return fmt.Errorf("fresh independent final observation failed: %w", err)
	}
	if p.MarkerSHA256 != w.expectedMarker || p.LedgerSHA256 != w.expectedLedger {
		return fmt.Errorf("final proof historical hashes differ from preflight")
	}
	marker, err := readM2PrivateRecord(filepath.Join(w.dir, "recovery-pending.json"))
	if err != nil || m2SHA256(marker) != p.MarkerSHA256 {
		return fmt.Errorf("original marker differs from preflight: %v", err)
	}
	ledger, err := readM2PrivateRecord(filepath.Join(w.dir, "ledger.json"))
	if err != nil || m2SHA256(ledger) != p.LedgerSHA256 {
		return fmt.Errorf("original ledger differs from preflight: %v", err)
	}
	diagnostic, err := readM2PrivateRecord(filepath.Join(w.dir, "diagnostics.json"))
	if err != nil {
		return err
	}
	var diag struct {
		CaseID string `json:"caseID"`
		Status string `json:"status"`
	}
	if json.Unmarshal(diagnostic, &diag) != nil || diag.CaseID != w.caseID || diag.Status != "skipped-recovery-incomplete" || m2SHA256(diagnostic) != p.DiagnosticsSHA256 {
		return fmt.Errorf("historic diagnostics changed or are not skipped-recovery-incomplete")
	}
	namespaceBytes, err := readM2PrivateRecord(filepath.Join(w.dir, "namespace-receipt.json"))
	if err != nil {
		return err
	}
	newNamespaces := m2NamespaceReceipt{}
	if err := json.Unmarshal(namespaceBytes, &newNamespaces); err != nil {
		return err
	}
	receipt := m2ClusterReplacementReceipt{CaseID: w.caseID, Status: m2ClusterReplacementRecoveryStatus, ScenarioResult: "FAILED_ABORTED", ScenarioPass: false, HistoricServiceOutcome: "UNKNOWN", DiagnosticsStatus: diag.Status, MarkerSHA256: p.MarkerSHA256, LedgerSHA256: p.LedgerSHA256, OldResourceInventorySHA256: p.ResourceInventorySHA256, OldResourceInventoryCount: p.ResourceInventoryCount, NamespaceReceiptSHA256: m2SHA256(namespaceBytes), OldLab: p.OldLab, NewLab: c.NewLab, OldNamespaces: p.OldNamespaces, NewNamespaces: n.Namespaces, OldNodeVolumes: p.OldVolumes, NewNodeVolumes: c.NewVolumes, NewKeaConfigIDs: c.KeaConfigIDs, OldClusterAbsent: d.OldClusterAbsent, OldNodeContainersAbsent: d.OldContainersAbsent, OldNodeVolumesAbsent: d.OldVolumesAbsent, ReplacementIsolated: true, NoActiveOperations: true, M1Cluster: "keaguard-m1-disposable", M1DockerIDBefore: p.M1DockerID, M1DockerIDAfter: c.M1DockerID, M1Image: p.M1Image}
	if err := m2ValidateClusterReplacementReceipt(receipt, w.caseID, marker, ledger, namespaceBytes); err != nil {
		return fmt.Errorf("independent replacement receipt verification: %w", err)
	}
	if err := m2RetireClusterReplacementMarker(w.dir, receipt); err != nil {
		return err
	}
	return m2VerifyClusterReplacementRecovery(w.dir, w.caseID, diag.Status)
}

type m2ClusterReplacementReceipt struct {
	CaseID                     string                       `json:"caseID"`
	Status                     string                       `json:"status"`
	ScenarioResult             string                       `json:"scenarioResult"`
	ScenarioPass               bool                         `json:"scenarioPass"`
	HistoricServiceOutcome     string                       `json:"historicServiceCreateOutcome"`
	DiagnosticsStatus          string                       `json:"originalDiagnosticsStatus"`
	MarkerSHA256               string                       `json:"originalMarkerSHA256"`
	LedgerSHA256               string                       `json:"originalLedgerSHA256"`
	OldResourceInventorySHA256 string                       `json:"oldResourceInventorySHA256"`
	OldResourceInventoryCount  int                          `json:"oldResourceInventoryCount"`
	NamespaceReceiptSHA256     string                       `json:"newNamespaceReceiptSHA256"`
	OldLab                     m2LabIdentity                `json:"oldLab"`
	NewLab                     m2LabIdentity                `json:"newLab"`
	OldNamespaces              map[string]m2NamespaceEntry  `json:"oldNamespaces"`
	NewNamespaces              map[string]m2NamespaceEntry  `json:"newNamespaces"`
	OldNodeVolumes             map[string]string            `json:"oldNodeVolumes"`
	NewNodeVolumes             map[string]string            `json:"newNodeVolumes"`
	NewKeaConfigIDs            map[string]map[string]string `json:"newKeaConfigIDs"`
	OldClusterAbsent           bool                         `json:"oldClusterAbsent"`
	OldNodeContainersAbsent    bool                         `json:"oldNodeContainersAbsent"`
	OldNodeVolumesAbsent       bool                         `json:"oldNodeVolumesAbsent"`
	ReplacementIsolated        bool                         `json:"oldRequestCannotReachReplacement"`
	NoActiveOperations         bool                         `json:"noActiveOperations"`
	M1Cluster                  string                       `json:"m1Cluster"`
	M1DockerIDBefore           string                       `json:"m1DockerIDBefore"`
	M1DockerIDAfter            string                       `json:"m1DockerIDAfter"`
	M1Image                    string                       `json:"m1Image"`
}

type m2ClusterReplacementRetirement struct {
	CaseID                   string `json:"caseID"`
	Status                   string `json:"status"`
	MarkerSHA256             string `json:"markerSHA256"`
	LedgerSHA256             string `json:"ledgerSHA256"`
	ReplacementReceiptSHA256 string `json:"replacementReceiptSHA256"`
}

type m2ClusterReplacementRetirementIntent struct {
	CaseID                   string `json:"caseID"`
	Status                   string `json:"status"`
	MarkerSHA256             string `json:"markerSHA256"`
	LedgerSHA256             string `json:"ledgerSHA256"`
	ReplacementReceiptSHA256 string `json:"replacementReceiptSHA256"`
}

func m2VerifyClusterReplacementRecovery(dir, caseID, diagnosticStatus string) error {
	if !m2ValidCaseID(caseID) || diagnosticStatus != "skipped-recovery-incomplete" {
		return fmt.Errorf("cluster replacement is not eligible for this diagnostic state")
	}
	read := func(name string) ([]byte, error) { return readM2PrivateRecord(filepath.Join(dir, name)) }
	marker, err := read("recovery-pending-archived-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("original pending marker archive is unavailable: %w", err)
	}
	ledger, err := read("ledger-archived-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("original unresolved ledger archive is unavailable: %w", err)
	}
	diagnostic, err := read("diagnostics-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("original failed diagnostics are unavailable: %w", err)
	}
	canonical, err := read("diagnostics.json")
	if err != nil || !bytes.Equal(canonical, diagnostic) {
		return fmt.Errorf("original diagnostics status/bytes were changed: %v", err)
	}
	var diagnosticRecord struct {
		CaseID string `json:"caseID"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(diagnostic, &diagnosticRecord); err != nil || diagnosticRecord.CaseID != caseID || diagnosticRecord.Status != diagnosticStatus {
		return fmt.Errorf("original diagnostics do not identify the unresolved case: %v", err)
	}
	namespaceBytes, err := read("namespace-receipt.json")
	if err != nil {
		return fmt.Errorf("replacement namespace receipt is unavailable: %w", err)
	}
	replacementBytes, err := read("cluster-replacement-reconciled-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("verified replacement recovery receipt is unavailable: %w", err)
	}
	retirementBytes, err := read("cluster-replacement-retired-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("replacement marker-retirement receipt is unavailable: %w", err)
	}
	intentBytes, err := read("cluster-replacement-retirement-intent-" + caseID + ".json")
	if err != nil {
		return fmt.Errorf("replacement marker-retirement intent is unavailable: %w", err)
	}
	var receipt m2ClusterReplacementReceipt
	if err := json.Unmarshal(replacementBytes, &receipt); err != nil {
		return fmt.Errorf("replacement recovery receipt is malformed: %w", err)
	}
	if err := m2ValidateClusterReplacementReceipt(receipt, caseID, marker, ledger, namespaceBytes); err != nil {
		return err
	}
	var retirement m2ClusterReplacementRetirement
	if err := json.Unmarshal(retirementBytes, &retirement); err != nil {
		return fmt.Errorf("replacement marker-retirement record is malformed: %w", err)
	}
	var intent m2ClusterReplacementRetirementIntent
	if err := json.Unmarshal(intentBytes, &intent); err != nil {
		return fmt.Errorf("replacement marker-retirement intent is malformed: %w", err)
	}
	if intent.CaseID != caseID || intent.Status != "RETIREMENT_AUTHORIZED_BY_VERIFIED_REPLACEMENT_RECEIPT" ||
		intent.MarkerSHA256 != receipt.MarkerSHA256 || intent.LedgerSHA256 != receipt.LedgerSHA256 ||
		intent.ReplacementReceiptSHA256 != m2SHA256(replacementBytes) {
		return fmt.Errorf("replacement marker-retirement intent does not bind the exact verified replacement")
	}
	if retirement.CaseID != caseID || retirement.Status != "RETIRED_AFTER_VERIFIED_CLUSTER_REPLACEMENT" ||
		retirement.MarkerSHA256 != receipt.MarkerSHA256 || retirement.LedgerSHA256 != receipt.LedgerSHA256 ||
		retirement.ReplacementReceiptSHA256 != m2SHA256(replacementBytes) {
		return fmt.Errorf("replacement marker-retirement record does not bind the exact verified replacement")
	}
	return nil
}

func m2ValidateClusterReplacementReceipt(receipt m2ClusterReplacementReceipt, caseID string, marker, ledger, namespaceBytes []byte) error {
	if !m2ValidCaseID(caseID) || receipt.CaseID != caseID || receipt.Status != m2ClusterReplacementRecoveryStatus ||
		receipt.ScenarioResult != "FAILED_ABORTED" || receipt.ScenarioPass || receipt.HistoricServiceOutcome != "UNKNOWN" ||
		receipt.DiagnosticsStatus != "skipped-recovery-incomplete" || receipt.MarkerSHA256 != m2SHA256(marker) ||
		receipt.LedgerSHA256 != m2SHA256(ledger) || receipt.NamespaceReceiptSHA256 != m2SHA256(namespaceBytes) {
		return fmt.Errorf("cluster replacement receipt changes or fails to bind the original failed scenario/evidence")
	}
	if !receipt.OldClusterAbsent || !receipt.OldNodeContainersAbsent || !receipt.OldNodeVolumesAbsent || !m2FullHexID(receipt.OldResourceInventorySHA256) || receipt.OldResourceInventoryCount <= 0 ||
		!receipt.ReplacementIsolated || !receipt.NoActiveOperations {
		return fmt.Errorf("cluster replacement receipt lacks complete teardown, isolation, or quiescence proof")
	}
	if receipt.OldLab.Cluster != m2LabProfile.cluster || receipt.NewLab.Cluster != m2LabProfile.cluster ||
		receipt.OldLab.Server == "" || receipt.NewLab.Server == "" || !m2ValidHexSHA256(receipt.OldLab.CASHA256) ||
		!m2ValidHexSHA256(receipt.NewLab.CASHA256) || receipt.OldLab.CASHA256 == receipt.NewLab.CASHA256 ||
		!m2ValidHTTPSURL(receipt.OldLab.Server) || !m2ValidHTTPSURL(receipt.NewLab.Server) {
		return fmt.Errorf("old/new cluster server or CA identity is incomplete, reused, or invalid")
	}
	if err := m2ValidateReplacementNodes(receipt.OldLab.Nodes, receipt.OldNodeVolumes); err != nil {
		return fmt.Errorf("old cluster identity: %w", err)
	}
	if err := m2ValidateReplacementNodes(receipt.NewLab.Nodes, receipt.NewNodeVolumes); err != nil {
		return fmt.Errorf("replacement cluster identity: %w", err)
	}
	if err := m2ValidateReplacementKeaConfigIDs(receipt.NewKeaConfigIDs); err != nil {
		return fmt.Errorf("replacement Kea image identity: %w", err)
	}
	for _, name := range m2LabProfile.nodes {
		old, next := receipt.OldLab.Nodes[name], receipt.NewLab.Nodes[name]
		if old.KubernetesUID == next.KubernetesUID || old.DockerID == next.DockerID || receipt.OldNodeVolumes[name] == receipt.NewNodeVolumes[name] {
			return fmt.Errorf("replacement reused the old node/container/storage incarnation for %s", name)
		}
	}
	if err := m2ValidateReplacementNamespaces(receipt.OldNamespaces); err != nil {
		return fmt.Errorf("old namespace identity: %w", err)
	}
	if err := m2ValidateReplacementNamespaces(receipt.NewNamespaces); err != nil {
		return fmt.Errorf("replacement namespace identity: %w", err)
	}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		if receipt.OldNamespaces[name].UID == receipt.NewNamespaces[name].UID {
			return fmt.Errorf("replacement reused namespace UID for %s", name)
		}
	}
	if receipt.M1Cluster != "keaguard-m1-disposable" || !m2FullHexID(receipt.M1DockerIDBefore) ||
		receipt.M1DockerIDBefore != receipt.M1DockerIDAfter || receipt.M1Image != m2LabProfile.nodeImage {
		return fmt.Errorf("M1 cluster identity was not independently preserved")
	}
	var namespaceReceipt m2NamespaceReceipt
	if err := json.Unmarshal(namespaceBytes, &namespaceReceipt); err != nil {
		return fmt.Errorf("replacement namespace receipt is malformed: %w", err)
	}
	if !reflect.DeepEqual(namespaceReceipt.Lab, receipt.NewLab) ||
		!reflect.DeepEqual(namespaceReceipt.Namespaces, receipt.NewNamespaces) ||
		!reflect.DeepEqual(namespaceReceipt.FixtureLabel, map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}) {
		return fmt.Errorf("replacement receipt differs from the exact current namespace/server/node receipt")
	}
	return nil
}

// m2RetireClusterReplacementMarker is a one-shot, auditable transition. It
// seals the replacement proof and intent before moving the original marker
// and ledger, then writes a completion record. Any interrupted stage remains
// fail-closed because the next-invocation guard requires every exact record.
func m2RetireClusterReplacementMarker(dir string, receipt m2ClusterReplacementReceipt) error {
	if !m2ValidCaseID(receipt.CaseID) {
		return fmt.Errorf("replacement case identity is invalid")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("replacement evidence directory is not a private 0700 directory: %v", err)
	}
	markerPath := filepath.Join(dir, "recovery-pending.json")
	ledgerPath := filepath.Join(dir, "ledger.json")
	marker, err := readM2PrivateRecord(markerPath)
	if err != nil {
		return fmt.Errorf("active original recovery marker is unavailable: %w", err)
	}
	ledger, err := readM2PrivateRecord(ledgerPath)
	if err != nil {
		return fmt.Errorf("active original ledger is unavailable: %w", err)
	}
	diagnostic, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics.json"))
	if err != nil {
		return err
	}
	originalDiagnostic, err := readM2PrivateRecord(filepath.Join(dir, "diagnostics-"+receipt.CaseID+".json"))
	if err != nil || !bytes.Equal(diagnostic, originalDiagnostic) {
		return fmt.Errorf("original skipped diagnostics changed before marker retirement: %v", err)
	}
	namespaceBytes, err := readM2PrivateRecord(filepath.Join(dir, "namespace-receipt.json"))
	if err != nil {
		return err
	}
	var diagnosticState struct {
		CaseID string `json:"caseID"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(diagnostic, &diagnosticState); err != nil || diagnosticState.CaseID != receipt.CaseID || diagnosticState.Status != receipt.DiagnosticsStatus {
		return fmt.Errorf("original diagnostics are not the exact interrupted case: %v", err)
	}
	if err := m2ValidateClusterReplacementReceipt(receipt, receipt.CaseID, marker, ledger, namespaceBytes); err != nil {
		return err
	}
	markerArchive := filepath.Join(dir, "recovery-pending-archived-"+receipt.CaseID+".json")
	ledgerArchive := filepath.Join(dir, "ledger-archived-"+receipt.CaseID+".json")
	replacementPath := filepath.Join(dir, "cluster-replacement-reconciled-"+receipt.CaseID+".json")
	intentPath := filepath.Join(dir, "cluster-replacement-retirement-intent-"+receipt.CaseID+".json")
	retiredPath := filepath.Join(dir, "cluster-replacement-retired-"+receipt.CaseID+".json")
	for _, path := range []string{markerArchive, ledgerArchive, replacementPath, intentPath, retiredPath} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refuse to reuse existing replacement evidence %s", filepath.Base(path))
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	replacementBytes, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	replacementBytes = append(replacementBytes, '\n')
	if err := writePrivateExclusiveOrReplace(replacementPath, replacementBytes); err != nil {
		return fmt.Errorf("seal cluster replacement receipt: %w", err)
	}
	intent := m2ClusterReplacementRetirementIntent{CaseID: receipt.CaseID, Status: "RETIREMENT_AUTHORIZED_BY_VERIFIED_REPLACEMENT_RECEIPT",
		MarkerSHA256: receipt.MarkerSHA256, LedgerSHA256: receipt.LedgerSHA256, ReplacementReceiptSHA256: m2SHA256(replacementBytes)}
	intentBytes, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	if err := writePrivateExclusiveOrReplace(intentPath, append(intentBytes, '\n')); err != nil {
		return fmt.Errorf("seal replacement marker-retirement intent: %w", err)
	}
	if err := os.Rename(ledgerPath, ledgerArchive); err != nil {
		return fmt.Errorf("archive original unresolved ledger: %w", err)
	}
	if err := syncPrivateDirectory(ledgerArchive); err != nil {
		return err
	}
	if err := os.Rename(markerPath, markerArchive); err != nil {
		return fmt.Errorf("retire original marker after replacement proof: %w", err)
	}
	if err := syncPrivateDirectory(markerArchive); err != nil {
		return err
	}
	retirement := m2ClusterReplacementRetirement{CaseID: receipt.CaseID, Status: "RETIRED_AFTER_VERIFIED_CLUSTER_REPLACEMENT",
		MarkerSHA256: receipt.MarkerSHA256, LedgerSHA256: receipt.LedgerSHA256, ReplacementReceiptSHA256: m2SHA256(replacementBytes)}
	retirementBytes, err := json.Marshal(retirement)
	if err != nil {
		return err
	}
	if err := writePrivateExclusiveOrReplace(retiredPath, append(retirementBytes, '\n')); err != nil {
		return fmt.Errorf("seal replacement marker-retirement completion: %w", err)
	}
	return m2VerifyClusterReplacementRecovery(dir, receipt.CaseID, receipt.DiagnosticsStatus)
}

func m2ValidateReplacementNodes(nodes map[string]m2NodeIdentity, volumes map[string]string) error {
	if len(nodes) != len(m2LabProfile.nodes) || len(volumes) != len(m2LabProfile.nodes) {
		return fmt.Errorf("expected exactly the three reviewed nodes and their attached storage identities")
	}
	dockerIDs, kubernetesUIDs, volumeIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	expectedImageID := strings.TrimPrefix(m2LabProfile.nodeImage, "kindest/node:v1.37.0@")
	for _, name := range m2LabProfile.nodes {
		node, ok := nodes[name]
		volume, volumeOK := volumes[name]
		if !ok || !volumeOK || node.KubernetesUID == "" || !m2FullHexID(node.DockerID) ||
			node.Image != m2LabProfile.nodeImage || node.ImageID != expectedImageID || !m2FullHexID(strings.TrimPrefix(node.ImageID, "sha256:")) ||
			!m2FullHexID(volume) || dockerIDs[node.DockerID] || kubernetesUIDs[node.KubernetesUID] || volumeIDs[volume] {
			return fmt.Errorf("node %s lacks a unique full UID/container/image/storage identity", name)
		}
		dockerIDs[node.DockerID], kubernetesUIDs[node.KubernetesUID], volumeIDs[volume] = true, true, true
	}
	return nil
}

func m2ValidateReplacementContainerSet(output string, nodes map[string]m2NodeIdentity) error {
	ids := splitLines(output)
	if len(ids) != len(m2LabProfile.nodes) || len(nodes) != len(m2LabProfile.nodes) {
		return fmt.Errorf("expected exactly the three approved M2 node containers")
	}
	observed := map[string]bool{}
	for _, id := range ids {
		if !m2FullHexID(id) || observed[id] {
			return fmt.Errorf("M2 Docker container inventory contains an invalid or duplicate full ID")
		}
		observed[id] = true
	}
	for _, name := range m2LabProfile.nodes {
		entry, ok := nodes[name]
		if !ok || !observed[entry.DockerID] {
			return fmt.Errorf("M2 Docker container inventory contains a foreign or missing node identity")
		}
	}
	return nil
}

func m2ValidateReplacementActiveContainerSet(output string, oldNodes, newNodes map[string]m2NodeIdentity) error {
	if len(oldNodes) != len(m2LabProfile.nodes) || len(newNodes) != len(m2LabProfile.nodes) {
		return fmt.Errorf("old and replacement node identities must both contain exactly three nodes")
	}
	for _, name := range m2LabProfile.nodes {
		oldNode, oldOK := oldNodes[name]
		newNode, newOK := newNodes[name]
		if !oldOK || !newOK || !m2FullHexID(oldNode.DockerID) || !m2FullHexID(newNode.DockerID) || oldNode.DockerID == newNode.DockerID {
			return fmt.Errorf("old and replacement Docker identities are missing, invalid, or reused for %s", name)
		}
	}
	if err := m2ValidateReplacementContainerSet(output, newNodes); err != nil {
		return fmt.Errorf("active cluster-attributed containers are not the exact replacement node set: %w", err)
	}
	return nil
}

func m2ValidateReplacementNamespaces(namespaces map[string]m2NamespaceEntry) error {
	if len(namespaces) != 2 {
		return fmt.Errorf("expected exactly the two reviewed M2 namespaces")
	}
	seenUIDs := map[string]bool{}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		entry, ok := namespaces[name]
		if !ok || entry.UID == "" || seenUIDs[entry.UID] ||
			!reflect.DeepEqual(entry.Labels, map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}) ||
			!reflect.DeepEqual(entry.Policy, m2ExpectedPolicy(name)) {
			return fmt.Errorf("namespace %s has missing/duplicate UID, foreign ownership, or wrong policy", name)
		}
		seenUIDs[entry.UID] = true
	}
	return nil
}

func m2ReplacementKeaImportReference(listing, approved string) (string, error) {
	if _, known := m2KeaExpectedConfigID(approved); !known {
		return "", fmt.Errorf("image is not an approved immutable Kea reference")
	}
	parts := strings.SplitN(approved, "@", 2)
	if len(parts) != 2 || !m2ValidSHA256Digest(parts[1]) {
		return "", fmt.Errorf("approved Kea reference has no exact SHA-256 manifest digest")
	}
	var matches []string
	for _, line := range strings.Fields(listing) {
		if strings.HasPrefix(line, "import-") && strings.HasSuffix(line, "@"+parts[1]) {
			matches = append(matches, line)
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected one imported reference for exact Kea manifest %s, found %d", parts[1], len(matches))
	}
	return matches[0], nil
}

func m2CheckReplacementKeaContainerdReferences(listing, source, approved string) error {
	parts := strings.SplitN(approved, "@", 2)
	if len(parts) != 2 || source == approved || !strings.HasPrefix(source, "import-") {
		return fmt.Errorf("Kea source/approved references are invalid")
	}
	if _, known := m2KeaExpectedConfigID(approved); !known || !m2ValidSHA256Digest(parts[1]) || !strings.HasSuffix(source, "@"+parts[1]) {
		return fmt.Errorf("Kea source is not the exact approved manifest")
	}
	rows := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(listing), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && (fields[0] == source || fields[0] == approved) {
			if _, duplicate := rows[fields[0]]; duplicate {
				return fmt.Errorf("duplicate containerd image reference %s", fields[0])
			}
			rows[fields[0]] = fields
		}
	}
	if len(rows) != 2 {
		return fmt.Errorf("containerd must retain exactly one source and one approved alias")
	}
	var size string
	for _, ref := range []string{source, approved} {
		fields := rows[ref]
		if len(fields) < 4 || fields[1] != m2OCIManifestMediaType || fields[2] != parts[1] || fields[3] == "" {
			return fmt.Errorf("containerd reference %s does not resolve to the exact approved OCI manifest", ref)
		}
		if size == "" {
			size = fields[3]
		} else if fields[3] != size {
			return fmt.Errorf("source and alias descriptor sizes differ")
		}
	}
	return nil
}

func m2CheckReplacementKeaSourceReference(listing, source, approved string) error {
	parts := strings.SplitN(approved, "@", 2)
	if len(parts) != 2 || source == approved || !strings.HasPrefix(source, "import-") || !strings.HasSuffix(source, "@"+parts[1]) {
		return fmt.Errorf("Kea imported source is not the exact approved manifest")
	}
	if _, known := m2KeaExpectedConfigID(approved); !known || !m2ValidSHA256Digest(parts[1]) {
		return fmt.Errorf("Kea source target is not approved")
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(listing), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == source {
			count++
			if len(fields) < 4 || fields[1] != m2OCIManifestMediaType || fields[2] != parts[1] || fields[3] == "" {
				return fmt.Errorf("imported Kea image does not resolve to the exact approved manifest descriptor")
			}
		}
	}
	if count != 1 {
		return fmt.Errorf("expected one exact imported Kea reference, found %d", count)
	}
	return nil
}

func m2ValidateReplacementKeaConfigIDs(receipts map[string]map[string]string) error {
	if len(receipts) != len(m2LabProfile.nodes) {
		return fmt.Errorf("replacement Kea receipt must contain exactly three nodes")
	}
	approved := []string{m2KeaDHCP4Image, m2KeaDHCP6Image}
	for _, node := range m2LabProfile.nodes {
		images, ok := receipts[node]
		if !ok || len(images) != len(approved) {
			return fmt.Errorf("replacement node %s lacks the two approved Kea identities", node)
		}
		for _, image := range approved {
			want, _ := m2KeaExpectedConfigID(image)
			if images[image] != want {
				return fmt.Errorf("replacement node %s Kea config identity mismatch for %s", node, image)
			}
		}
	}
	for node := range receipts {
		if !containsString(m2LabProfile.nodes, node) {
			return fmt.Errorf("replacement Kea receipt contains an unapproved node %s", node)
		}
	}
	return nil
}

func m2ValidateReplacementKeaDockerConfigIDs(receipts map[string]string) error {
	if len(receipts) != 2 {
		return fmt.Errorf("preflight must bind both approved local Kea images")
	}
	for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
		want, _ := m2KeaExpectedConfigID(image)
		if receipts[image] != want {
			return fmt.Errorf("local Docker image identity is not the approved config for %s", image)
		}
	}
	for image := range receipts {
		if _, known := m2KeaExpectedConfigID(image); !known {
			return fmt.Errorf("preflight contains an unapproved local Kea image %s", image)
		}
	}
	return nil
}

func m2ValidCaseID(caseID string) bool {
	if caseID == "" || strings.ContainsAny(caseID, `/\\`) {
		return false
	}
	for _, r := range caseID {
		if r != '-' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func m2ValidHexSHA256(value string) bool {
	return len(value) == 64 && m2FullHexID(value) && strings.ToLower(value) == value
}

func m2ValidHTTPSURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
