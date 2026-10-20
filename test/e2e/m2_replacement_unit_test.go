package e2e

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type m2ReplacementReceiptFixture struct {
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

func m2ReplacementFixture(caseID string, marker, ledger []byte) (m2ReplacementReceiptFixture, m2NamespaceReceipt) {
	imageID := strings.TrimPrefix(m2LabProfile.nodeImage, "kindest/node:v1.37.0@")
	oldNodes := map[string]m2NodeIdentity{}
	newNodes := map[string]m2NodeIdentity{}
	oldVolumes := map[string]string{}
	newVolumes := map[string]string{}
	for i, name := range m2LabProfile.nodes {
		oldNodes[name] = m2NodeIdentity{KubernetesUID: "old-node-uid-" + string(rune('1'+i)), DockerID: strings.Repeat(string(rune('1'+i)), 64), Image: m2LabProfile.nodeImage, ImageID: imageID}
		newNodes[name] = m2NodeIdentity{KubernetesUID: "new-node-uid-" + string(rune('1'+i)), DockerID: strings.Repeat(string(rune('4'+i)), 64), Image: m2LabProfile.nodeImage, ImageID: imageID}
		oldVolumes[name] = strings.Repeat(string(rune('7'+i)), 64)
		newVolumes[name] = strings.Repeat(string(rune('a'+i)), 64)
	}
	oldLab := m2LabIdentity{Cluster: m2LabProfile.cluster, Server: "https://127.0.0.1:35421", CASHA256: strings.Repeat("b", 64), Nodes: oldNodes}
	newLab := m2LabIdentity{Cluster: m2LabProfile.cluster, Server: "https://127.0.0.1:35422", CASHA256: strings.Repeat("c", 64), Nodes: newNodes}
	oldNamespaces := map[string]m2NamespaceEntry{
		m2LabProfile.runtimeNamespace: {UID: "old-runtime-namespace", Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Policy: m2ExpectedPolicy(m2LabProfile.runtimeNamespace)},
		m2LabProfile.outsideNamespace: {UID: "old-outside-namespace", Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Policy: m2ExpectedPolicy(m2LabProfile.outsideNamespace)},
	}
	newNamespaces := map[string]m2NamespaceEntry{
		m2LabProfile.runtimeNamespace: {UID: "new-runtime-namespace", Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Policy: m2ExpectedPolicy(m2LabProfile.runtimeNamespace)},
		m2LabProfile.outsideNamespace: {UID: "new-outside-namespace", Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Policy: m2ExpectedPolicy(m2LabProfile.outsideNamespace)},
	}
	namespaceReceipt := m2NamespaceReceipt{Lab: newLab, FixtureLabel: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}, Namespaces: newNamespaces}
	namespaceBytes, _ := json.Marshal(namespaceReceipt)
	receipt := m2ReplacementReceiptFixture{
		CaseID: caseID, Status: "VERIFIED_CLUSTER_REPLACEMENT_RECOVERY_NOT_SCENARIO_PASS", ScenarioResult: "FAILED_ABORTED",
		ScenarioPass: false, HistoricServiceOutcome: "UNKNOWN", DiagnosticsStatus: "skipped-recovery-incomplete",
		MarkerSHA256: m2SHA256(marker), LedgerSHA256: m2SHA256(ledger), OldResourceInventorySHA256: strings.Repeat("e", 64), OldResourceInventoryCount: 1, NamespaceReceiptSHA256: m2SHA256(append(namespaceBytes, '\n')),
		OldLab: oldLab, NewLab: newLab, OldNamespaces: oldNamespaces, NewNamespaces: newNamespaces,
		OldNodeVolumes: oldVolumes, NewNodeVolumes: newVolumes, NewKeaConfigIDs: m2ReplacementKeaConfigIDFixture(), OldClusterAbsent: true,
		OldNodeContainersAbsent: true, OldNodeVolumesAbsent: true, ReplacementIsolated: true, NoActiveOperations: true,
		M1Cluster: "keaguard-m1-disposable", M1DockerIDBefore: strings.Repeat("d", 64), M1DockerIDAfter: strings.Repeat("d", 64),
		M1Image: m2LabProfile.nodeImage,
	}
	return receipt, namespaceReceipt
}

func TestUnitM2ClusterReplacementRecoveryReceiptKeepsHistoricScenarioFailed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	caseID := "1792432128521632810-890503"
	marker := []byte(`{"caseID":"1792432128521632810-890503","phase":"scenario","name":"T19 unresolved Service Create"}` + "\n")
	ledger := []byte(`{"scenario":"T19 RBAC","intents":[{"kind":"Service","generateName":"m2-rbac-service-","phase":"unresolved"}]}` + "\n")
	diagnostic := []byte(`{"caseID":"1792432128521632810-890503","status":"skipped-recovery-incomplete"}` + "\n")
	receipt, namespaceReceipt := m2ReplacementFixture(caseID, marker, ledger)
	namespaceBytes, err := json.Marshal(namespaceReceipt)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"recovery-pending.json":           marker,
		"ledger.json":                     ledger,
		"diagnostics.json":                diagnostic,
		"diagnostics-" + caseID + ".json": diagnostic,
		"namespace-receipt.json":          append(namespaceBytes, '\n'),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := m2CheckNoPendingRecovery(dir); err == nil {
		t.Fatal("active historical marker must block even with replacement records staged")
	}
	replacementBytes, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var sealed m2ClusterReplacementReceipt
	if err := json.Unmarshal(replacementBytes, &sealed); err != nil {
		t.Fatal(err)
	}
	if err := m2RetireClusterReplacementMarker(dir, sealed); err != nil {
		t.Fatalf("verified replacement retirement failed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "recovery-pending.json")); !os.IsNotExist(err) {
		t.Fatalf("original pending marker was not atomically retired: %v", err)
	}
	archivedMarker, err := os.ReadFile(filepath.Join(dir, "recovery-pending-archived-"+caseID+".json"))
	if err != nil || string(archivedMarker) != string(marker) {
		t.Fatalf("original marker archive changed bytes: %v", err)
	}
	archivedLedger, err := os.ReadFile(filepath.Join(dir, "ledger-archived-"+caseID+".json"))
	if err != nil || string(archivedLedger) != string(ledger) {
		t.Fatalf("original ledger archive changed bytes: %v", err)
	}
	if err := m2CheckNoPendingRecovery(dir); err != nil {
		t.Fatalf("verified replacement receipt should permit a new invocation without relabeling the old scenario: %v", err)
	}
	if err := m2RetireClusterReplacementMarker(dir, sealed); err == nil {
		t.Fatal("replacement receipt replay retired the marker twice")
	}
	retiredPath := filepath.Join(dir, "cluster-replacement-retired-"+caseID+".json")
	retiredBytes, err := os.ReadFile(retiredPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(retiredPath); err != nil {
		t.Fatal(err)
	}
	if err := m2CheckNoPendingRecovery(dir); err == nil {
		t.Fatal("missing marker-retirement completion was accepted")
	}
	if err := os.WriteFile(retiredPath, retiredBytes, 0600); err != nil {
		t.Fatal(err)
	}
	markerArchivePath := filepath.Join(dir, "recovery-pending-archived-"+caseID+".json")
	if err := os.WriteFile(markerArchivePath, []byte("changed marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2CheckNoPendingRecovery(dir); err == nil {
		t.Fatal("replacement receipt accepted changed historical marker bytes")
	}
	if err := os.WriteFile(markerArchivePath, marker, 0600); err != nil {
		t.Fatal(err)
	}
	namespacePath := filepath.Join(dir, "namespace-receipt.json")
	currentNamespaceBytes, err := os.ReadFile(namespacePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(namespacePath, []byte("stale cluster namespace receipt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2CheckNoPendingRecovery(dir); err == nil {
		t.Fatal("stale replacement namespace receipt was accepted")
	}
	if err := os.WriteFile(namespacePath, currentNamespaceBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recovery-pending.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2CheckNoPendingRecovery(dir); err == nil {
		t.Fatal("active original marker was ignored after replacement completion")
	}
	if err := os.Remove(filepath.Join(dir, "recovery-pending.json")); err != nil {
		t.Fatal(err)
	}
	var preserved m2ReplacementReceiptFixture
	if err := json.Unmarshal(replacementBytes, &preserved); err != nil {
		t.Fatal(err)
	}
	if preserved.ScenarioPass || preserved.ScenarioResult != "FAILED_ABORTED" || preserved.HistoricServiceOutcome != "UNKNOWN" {
		t.Fatalf("replacement receipt rewrote historical outcome: %+v", preserved)
	}
}

func TestUnitM2ClusterReplacementReceiptFailsClosed(t *testing.T) {
	caseID := "1792432128521632810-890503"
	marker := []byte("original marker\n")
	ledger := []byte(`{"intents":[{"phase":"unresolved"}]}` + "\n")
	base, baseNamespaces := m2ReplacementFixture(caseID, marker, ledger)
	for name, mutate := range map[string]func(*m2ReplacementReceiptFixture, *m2NamespaceReceipt){
		"claims the original scenario passed": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.ScenarioPass = true },
		"changes failed result":               func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.ScenarioResult = "PASS" },
		"invents historic Create outcome":     func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.HistoricServiceOutcome = "REJECTED" },
		"wrong case identity":                 func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.CaseID = "1792432128521632810-890504" },
		"stale marker hash":                   func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.MarkerSHA256 = strings.Repeat("0", 64) },
		"stale ledger hash":                   func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.LedgerSHA256 = strings.Repeat("0", 64) },
		"old cluster remains":                 func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.OldClusterAbsent = false },
		"old container remains":               func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.OldNodeContainersAbsent = false },
		"old node volume remains":             func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.OldNodeVolumesAbsent = false },
		"old request isolation unproved":      func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.ReplacementIsolated = false },
		"concurrent operation observed":       func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.NoActiveOperations = false },
		"missing old node": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			delete(r.OldLab.Nodes, m2LabProfile.nodes[1])
		},
		"missing replacement node": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			delete(r.NewLab.Nodes, m2LabProfile.nodes[2])
		},
		"wrong node image pin": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			n := r.NewLab.Nodes[m2LabProfile.nodes[0]]
			n.Image = "kindest/node:latest"
			r.NewLab.Nodes[m2LabProfile.nodes[0]] = n
		},
		"wrong node image digest": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			n := r.NewLab.Nodes[m2LabProfile.nodes[0]]
			n.ImageID = "sha256:" + strings.Repeat("0", 64)
			r.NewLab.Nodes[m2LabProfile.nodes[0]] = n
		},
		"reuses old Kubernetes node UID": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			n := r.NewLab.Nodes[m2LabProfile.nodes[0]]
			n.KubernetesUID = r.OldLab.Nodes[m2LabProfile.nodes[0]].KubernetesUID
			r.NewLab.Nodes[m2LabProfile.nodes[0]] = n
		},
		"reuses old Docker container ID": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			n := r.NewLab.Nodes[m2LabProfile.nodes[0]]
			n.DockerID = r.OldLab.Nodes[m2LabProfile.nodes[0]].DockerID
			r.NewLab.Nodes[m2LabProfile.nodes[0]] = n
		},
		"reuses old node volume": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			r.NewNodeVolumes[m2LabProfile.nodes[0]] = r.OldNodeVolumes[m2LabProfile.nodes[0]]
		},
		"reuses old cluster CA": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) { r.NewLab.CASHA256 = r.OldLab.CASHA256 },
		"unsupported server URL": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			r.NewLab.Server = "http://127.0.0.1:34425"
		},
		"reuses old namespace UID": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			n := m2LabProfile.runtimeNamespace
			x := r.NewNamespaces[n]
			x.UID = r.OldNamespaces[n].UID
			r.NewNamespaces[n] = x
		},
		"foreign namespace owner": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			x := r.NewNamespaces[m2LabProfile.runtimeNamespace]
			x.Labels[m2LabProfile.fixtureLabel] = "foreign"
			r.NewNamespaces[m2LabProfile.runtimeNamespace] = x
		},
		"weakened outside policy": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			x := r.NewNamespaces[m2LabProfile.outsideNamespace]
			x.Policy["pod-security.kubernetes.io/enforce"] = "baseline"
			r.NewNamespaces[m2LabProfile.outsideNamespace] = x
		},
		"M1 identity changed": func(r *m2ReplacementReceiptFixture, _ *m2NamespaceReceipt) {
			r.M1DockerIDAfter = strings.Repeat("e", 64)
		},
		"stale current namespace receipt": func(_ *m2ReplacementReceiptFixture, n *m2NamespaceReceipt) {
			x := n.Namespaces[m2LabProfile.runtimeNamespace]
			x.UID = "stale-namespace"
			n.Namespaces[m2LabProfile.runtimeNamespace] = x
		},
	} {
		t.Run(name, func(t *testing.T) {
			receipt := base
			receipt.OldLab.Nodes = cloneM2NodeIdentityMap(base.OldLab.Nodes)
			receipt.NewLab.Nodes = cloneM2NodeIdentityMap(base.NewLab.Nodes)
			receipt.OldNamespaces = cloneM2NamespaceEntryMap(base.OldNamespaces)
			receipt.NewNamespaces = cloneM2NamespaceEntryMap(base.NewNamespaces)
			receipt.OldNodeVolumes = maps.Clone(base.OldNodeVolumes)
			receipt.NewNodeVolumes = maps.Clone(base.NewNodeVolumes)
			namespaceReceipt := baseNamespaces
			namespaceReceipt.Namespaces = cloneM2NamespaceEntryMap(baseNamespaces.Namespaces)
			mutate(&receipt, &namespaceReceipt)
			namespaceBytes, err := json.Marshal(namespaceReceipt)
			if err != nil {
				t.Fatal(err)
			}
			receiptBytes, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			var validated m2ClusterReplacementReceipt
			if err := json.Unmarshal(receiptBytes, &validated); err != nil {
				t.Fatal(err)
			}
			if err := m2ValidateClusterReplacementReceipt(validated, caseID, marker, ledger, append(namespaceBytes, '\n')); err == nil {
				t.Fatal("accepted invalid, stale, or incomplete replacement identity evidence")
			}
		})
	}
}

func TestUnitM2ClusterReplacementModeAllowsOnlyRecordedRecoveryBootstrap(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	caseID := "1792432128521632810-890503"
	marker := []byte(`{"caseID":"1792432128521632810-890503","phase":"scenario"}` + "\n")
	ledger := []byte(`{"intents":[{"kind":"Service","phase":"unresolved"}]}` + "\n")
	diagnostic := []byte(`{"caseID":"1792432128521632810-890503","status":"skipped-recovery-incomplete"}` + "\n")
	for name, data := range map[string][]byte{
		"recovery-pending.json":           marker,
		"ledger.json":                     ledger,
		"diagnostics.json":                diagnostic,
		"diagnostics-" + caseID + ".json": diagnostic,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := m2ValidateReplacementBootstrapEvidence(dir, caseID, m2SHA256(marker), m2SHA256(ledger)); err != nil {
		t.Fatalf("explicit read-only replacement preflight mode should accept only the original matching pending state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recovery-pending.json"), []byte("different case\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2ValidateReplacementBootstrapEvidence(dir, caseID, m2SHA256(marker), m2SHA256(ledger)); err == nil {
		t.Fatal("replacement bootstrap accepted a changed original marker")
	}
	if err := os.WriteFile(filepath.Join(dir, "recovery-pending.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ledger.json.new"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m2ValidateReplacementBootstrapEvidence(dir, caseID, m2SHA256(marker), m2SHA256(ledger)); err == nil {
		t.Fatal("replacement bootstrap accepted an unfinished evidence write")
	}
}

func TestUnitM2ReplacementBootstrapAllowsReadOnlyNamespaceReconciliation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	caseID := "1792432128521632810-890503"
	marker := []byte(`{"caseID":"1792432128521632810-890503","phase":"scenario"}` + "\n")
	ledger := []byte(`{"intents":[{"kind":"Service","phase":"unresolved"}]}` + "\n")
	diagnostic := []byte(`{"caseID":"1792432128521632810-890503","status":"skipped-recovery-incomplete"}` + "\n")
	for name, data := range map[string][]byte{
		"recovery-pending.json":           marker,
		"ledger.json":                     ledger,
		"diagnostics.json":                diagnostic,
		"diagnostics-" + caseID + ".json": diagnostic,
		"cluster-replacement-namespace-intent-" + caseID + ".json": []byte(`{"caseID":"1792432128521632810-890503","status":"NAMESPACE_CREATE_ONCE"}` + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KEAGUARD_M2_REPLACEMENT_STAGE", "reconcile-namespaces-not-submitted")
	if err := m2ValidateReplacementBootstrapEvidence(dir, caseID, m2SHA256(marker), m2SHA256(ledger)); err != nil {
		t.Fatalf("read-only namespace reconciliation must reach its independent live absence check: %v", err)
	}
}

func TestUnitM2ReplacementBootstrapNamespaceStagesFailClosed(t *testing.T) {
	caseID := "1792432128521632810-890503"
	marker := []byte(`{"caseID":"1792432128521632810-890503","phase":"scenario"}` + "\n")
	ledger := []byte(`{"intents":[{"kind":"Service","phase":"unresolved"}]}` + "\n")
	diagnostic := []byte(`{"caseID":"1792432128521632810-890503","status":"skipped-recovery-incomplete"}` + "\n")
	newFixture := func(t *testing.T) (string, []byte) {
		t.Helper()
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		intent := []byte(`{"caseID":"1792432128521632810-890503","status":"NAMESPACE_CREATE_ONCE"}` + "\n")
		for name, data := range map[string][]byte{
			"recovery-pending.json":           marker,
			"ledger.json":                     ledger,
			"diagnostics.json":                diagnostic,
			"diagnostics-" + caseID + ".json": diagnostic,
			"cluster-replacement-namespace-intent-" + caseID + ".json": intent,
		} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return dir, intent
	}
	write := func(t *testing.T, dir, name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name+"-"+caseID+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, stage := range []string{"", "ordinary-e2e", "reconcile-namespaces-not-submitted", "resume-namespaces-not-submitted", "namespaces"} {
		t.Run("stage="+stage, func(t *testing.T) {
			dir, namespaceIntent := newFixture(t)
			t.Setenv("KEAGUARD_M2_REPLACEMENT_STAGE", stage)
			if stage == "reconcile-namespaces-not-submitted" {
				write(t, dir, "cluster-replacement-namespaces-not-submitted", []byte(`{"caseID":"1792432128521632810-890503"}`+"\n"))
			} else if stage == "resume-namespaces-not-submitted" {
				receipt := m2ReplacementNamespaceReconciliation{CaseID: caseID, Status: "VERIFIED_NAMESPACE_STAGE_NOT_SUBMITTED", NamespaceIntentSHA256: m2SHA256(namespaceIntent), CreatedSHA256: "created", PreflightSHA256: "preflight", PreflightLiveSHA256: "live", KeaPreflightSHA256: "kea"}
				notSubmitted, _ := json.Marshal(receipt)
				notSubmitted = append(notSubmitted, '\n')
				write(t, dir, "cluster-replacement-namespaces-not-submitted", notSubmitted)
				resume, _ := json.Marshal(map[string]string{
					"caseID": caseID, "status": "CONTINUE_ABSENT_NAMESPACE_STAGE_ONCE",
					"namespaceIntentSHA256": m2SHA256(namespaceIntent), "notSubmittedSHA256": m2SHA256(notSubmitted),
					"createdSHA256": receipt.CreatedSHA256, "preflightSHA256": receipt.PreflightSHA256, "preflightLiveSHA256": receipt.PreflightLiveSHA256, "keaPreflightSHA256": receipt.KeaPreflightSHA256,
				})
				write(t, dir, "cluster-replacement-namespace-resume-intent", append(resume, '\n'))
			}
			err := m2ValidateReplacementBootstrapEvidence(dir, caseID, m2SHA256(marker), m2SHA256(ledger))
			if stage == "namespaces" || stage == "resume-namespaces-not-submitted" {
				if err != nil {
					t.Fatalf("namespace stage should be admitted only with its exact lifecycle evidence: %v", err)
				}
			} else if err == nil {
				t.Fatal("incomplete or replayed namespace stage passed the bootstrap guard")
			}
		})
	}
	t.Run("resume without reconciliation", func(t *testing.T) {
		dir, _ := newFixture(t)
		t.Setenv("KEAGUARD_M2_REPLACEMENT_STAGE", "resume-namespaces-not-submitted")
		if err := m2ValidateReplacementBootstrapEvidence(dir, caseID, m2SHA256(marker), m2SHA256(ledger)); err == nil {
			t.Fatal("namespace continuation passed without its independently verified reconciliation receipt")
		}
	})
}

func cloneM2NodeIdentityMap(in map[string]m2NodeIdentity) map[string]m2NodeIdentity {
	out := make(map[string]m2NodeIdentity, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneM2NamespaceEntryMap(in map[string]m2NamespaceEntry) map[string]m2NamespaceEntry {
	out := make(map[string]m2NamespaceEntry, len(in))
	for key, value := range in {
		value.Labels = maps.Clone(value.Labels)
		value.Policy = maps.Clone(value.Policy)
		out[key] = value
	}
	return out
}
