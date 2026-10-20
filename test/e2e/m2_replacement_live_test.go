package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type m2LiveReplacementOps struct{}

func m2InitializeReplacementAdmin(cfg *rest.Config) error {
	if cfg == nil || cfg.Host == "" || len(cfg.CAData) == 0 {
		return fmt.Errorf("replacement administrator requires an API server and inline CA")
	}
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := infrastructurev1alpha1.AddToScheme(scheme); err != nil {
		return err
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	adminConfig, admin = cfg, c
	return nil
}

func m2WithReplacementNamespaceAdmin(ctx context.Context, cfg *rest.Config, run func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || run == nil {
		return fmt.Errorf("replacement namespace stage requires a live context and operation")
	}
	if err := m2InitializeReplacementAdmin(cfg); err != nil {
		return err
	}
	return run(ctx)
}

func m2WithReplacementLabIdentity(ctx context.Context, cfg *rest.Config, observe func(context.Context, *rest.Config) (m2LabIdentity, error)) (m2LabIdentity, error) {
	if ctx == nil || ctx.Err() != nil || observe == nil {
		return m2LabIdentity{}, fmt.Errorf("replacement identity observation requires a live context and observer")
	}
	if err := m2InitializeReplacementAdmin(cfg); err != nil {
		return m2LabIdentity{}, err
	}
	return observe(ctx, cfg)
}

func m2VerifyReplacementNamespaceBootstrapIdentity(observed m2LabIdentity, m1DockerID string, created m2ReplacementCreated) error {
	if created.Status != "VERIFIED_NEW_LAB" || !reflect.DeepEqual(observed, created.NewLab) || m1DockerID == "" || m1DockerID != created.M1DockerID {
		return fmt.Errorf("namespace bootstrap cluster or independent M1 identity changed")
	}
	return nil
}

func m2AssertNoConcurrentLabOperation() error {
	// Walk /proc directly, excluding only this test process and its ancestors.
	// Any other Kind/Kubernetes/CRI mutator is a hard stop.
	ancestors := map[int]bool{}
	pid := os.Getpid()
	for pid > 1 {
		ancestors[pid] = true
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			break
		}
		ppid := 0
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), "%d", &ppid)
				break
			}
		}
		if ppid <= 0 || ppid == pid {
			break
		}
		pid = ppid
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var candidate int
		if _, err := fmt.Sscanf(entry.Name(), "%d", &candidate); err != nil || candidate < 1 || ancestors[candidate] {
			continue
		}
		argv, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrPermission) {
				continue
			}
			return err
		}
		args := strings.ReplaceAll(string(argv), "\x00", " ")
		lower := strings.ToLower(args)
		if strings.Contains(lower, "kind ") || strings.Contains(lower, "kubectl") || strings.Contains(lower, "crictl") || strings.Contains(lower, "ctr ") || strings.Contains(lower, "docker ") || strings.Contains(lower, "go test") || strings.Contains(lower, "make test-kind") || strings.Contains(lower, "e2e.test") {
			return fmt.Errorf("concurrent lab mutation process %d observed", candidate)
		}
	}
	return nil
}

func (m2LiveReplacementOps) preflight(ctx context.Context) (m2ReplacementPreflight, error) {
	if os.Getenv("KEAGUARD_M2_CLUSTER_REPLACEMENT") != historicM2ReplacementCase {
		return m2ReplacementPreflight{}, fmt.Errorf("exact replacement case opt-in required")
	}
	if err := m2VerifyLabSelection(); err != nil {
		return m2ReplacementPreflight{}, err
	}
	if err := m2CheckNoPendingRecovery(m2NativeDir); err != nil {
		return m2ReplacementPreflight{}, err
	}
	if err := m2AssertNoConcurrentLabOperation(); err != nil {
		return m2ReplacementPreflight{}, err
	}
	clusters, err := m2Command(ctx, "kind", "get", "clusters")
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	clusterNames := splitLines(string(clusters))
	if len(clusterNames) != 2 || !containsString(clusterNames, m2LabProfile.cluster) || !containsString(clusterNames, m1LabProfile.cluster) {
		return m2ReplacementPreflight{}, fmt.Errorf("only the exact M2 and separate M1 clusters may exist")
	}
	cfg, err := validateLab(ctx)
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	adminConfig = cfg
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return m2ReplacementPreflight{}, err
	}
	if err := infrastructurev1alpha1.AddToScheme(scheme); err != nil {
		return m2ReplacementPreflight{}, err
	}
	admin, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	identity, err := m2InspectLabIdentity(ctx, cfg)
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	nodeContainers, err := m2Command(ctx, "docker", "ps", "-aq", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster="+m2LabProfile.cluster)
	if err != nil || m2ValidateReplacementContainerSet(string(nodeContainers), identity.Nodes) != nil {
		return m2ReplacementPreflight{}, fmt.Errorf("M2-attributed Docker container set differs from the exact three node identities: %v", err)
	}
	nsReceiptBytes, err := readM2PrivateRecord(m2NamespaceReceiptPath)
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	var nsReceipt m2NamespaceReceipt
	if err := json.Unmarshal(nsReceiptBytes, &nsReceipt); err != nil {
		return m2ReplacementPreflight{}, err
	}
	if err := m2VerifyNamespaceReceiptWith(ctx, admin, m2NamespaceReceiptPath, identity); err != nil {
		return m2ReplacementPreflight{}, err
	}
	volumes := map[string]string{}
	for _, node := range m2LabProfile.nodes {
		v, err := m2ReplacementNodeVolume(ctx, node, identity.Nodes[node].DockerID)
		if err != nil {
			return m2ReplacementPreflight{}, err
		}
		volumes[node] = v
	}
	resourceInventory, pvNames, err := m2ReplacementLiveResourceInventory(ctx, cfg)
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	if err := m2ValidateReplacementResourceInventory(resourceInventory, pvNames); err != nil {
		return m2ReplacementPreflight{}, err
	}
	inventoryBytes, err := json.Marshal(resourceInventory)
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	inventoryPath := filepath.Join(m2NativeDir, "cluster-replacement-resource-inventory-"+historicM2ReplacementCase+".json")
	if existing, err := readM2PrivateRecord(inventoryPath); err == nil {
		if !reflect.DeepEqual(existing, append(inventoryBytes, '\n')) {
			return m2ReplacementPreflight{}, fmt.Errorf("live resource inventory differs from preserved old-cluster evidence")
		}
	} else if os.IsNotExist(err) {
		if err := writePrivateExclusiveOrReplace(inventoryPath, append(inventoryBytes, '\n')); err != nil {
			return m2ReplacementPreflight{}, err
		}
	} else {
		return m2ReplacementPreflight{}, err
	}
	m1ID, err := m2ReplacementM1Identity(ctx)
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	marker, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "recovery-pending.json"))
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	ledger, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "ledger.json"))
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	diagnostic, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "diagnostics.json"))
	if err != nil {
		return m2ReplacementPreflight{}, err
	}
	partialHash := ""
	if partial, e := readM2PrivateRecord(filepath.Join(m2NativeDir, "namespaces.partial.json")); e == nil {
		partialHash = m2SHA256(partial)
	} else if !os.IsNotExist(e) {
		return m2ReplacementPreflight{}, e
	}
	return m2ReplacementPreflight{CaseID: historicM2ReplacementCase, Status: "VERIFIED_OLD_LAB_PREFLIGHT", OldCluster: m2LabProfile.cluster, OldLab: identity, OldNamespaces: nsReceipt.Namespaces, NamespaceReceiptSHA256: m2SHA256(nsReceiptBytes), PartialNamespaceSHA256: partialHash, OldVolumes: volumes, ResourceInventorySHA256: m2ReplacementInventoryHash(resourceInventory), ResourceInventoryCount: len(resourceInventory), PersistentVolumeNames: pvNames, MarkerSHA256: m2SHA256(marker), LedgerSHA256: m2SHA256(ledger), DiagnosticsSHA256: m2SHA256(diagnostic), M1DockerID: m1ID, M1Image: m2LabProfile.nodeImage, Quiescent: true}, nil
}

func (m2LiveReplacementOps) approvedKeaImages(ctx context.Context) (map[string]string, error) {
	return m2InspectApprovedKeaDockerImages(ctx)
}

func m2InspectApprovedKeaDockerImages(ctx context.Context) (map[string]string, error) {
	result := map[string]string{}
	for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
		out, err := m2Command(ctx, "docker", "image", "inspect", image, "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}|{{json .RepoDigests}}")
		if err != nil {
			return nil, err
		}
		fields := strings.Split(strings.TrimSpace(string(out)), "|")
		if len(fields) != 4 {
			return nil, fmt.Errorf("Docker inspection for %s has an unexpected shape", image)
		}
		var repoDigests []string
		if err := json.Unmarshal([]byte(fields[3]), &repoDigests); err != nil {
			return nil, err
		}
		configID, err := m2ValidateLocalDockerKeaIdentity(image, fields[0], fields[1], fields[2], repoDigests)
		if err != nil {
			return nil, fmt.Errorf("local Docker content for %s is not the single exact approved linux/amd64 image: %w", image, err)
		}
		result[image] = configID
	}
	return result, nil
}

// Docker's classic image store reports the config digest as image ID, while
// its containerd-backed store can report the exact pinned manifest/index
// digest for digest-addressed images. Both are accepted only for the two
// reviewed immutable references and their audited config mappings.
func m2ValidateLocalDockerKeaIdentity(image, imageID, osName, architecture string, repoDigests []string) (string, error) {
	configID, known := m2KeaExpectedConfigID(image)
	if !known {
		return "", fmt.Errorf("unapproved Kea image reference")
	}
	parts := strings.Split(image, "@sha256:")
	if len(parts) != 2 || parts[0] == "" || !m2FullHexID(parts[1]) {
		return "", fmt.Errorf("approved Kea reference is not a canonical immutable digest")
	}
	manifestID := "sha256:" + parts[1]
	if imageID != configID && imageID != manifestID {
		return "", fmt.Errorf("Docker image ID matches neither the approved manifest nor config digest")
	}
	if osName != "linux" || architecture != "amd64" {
		return "", fmt.Errorf("approved Kea image platform is not linux/amd64")
	}
	if len(repoDigests) != 1 || repoDigests[0] != image {
		return "", fmt.Errorf("Docker repository digest is missing, conflicting, or ambiguous")
	}
	return configID, nil
}

func m2VerifyReplacementKeaNodeImage(ctx context.Context, dockerID, image string) (string, error) {
	if !m2FullHexID(dockerID) {
		return "", fmt.Errorf("Kea image verification requires a full node container ID")
	}
	parts := strings.SplitN(image, "@", 2)
	wantConfig, known := m2KeaExpectedConfigID(image)
	if !known || len(parts) != 2 {
		return "", fmt.Errorf("image reference is not one of the approved Kea digests")
	}
	listing, err := m2Command(ctx, "docker", "exec", dockerID, "ctr", "--namespace", "k8s.io", "images", "ls")
	if err != nil {
		return "", err
	}
	refs, err := m2Command(ctx, "docker", "exec", dockerID, "ctr", "--namespace", "k8s.io", "images", "ls", "-q")
	if err != nil {
		return "", err
	}
	source, err := m2ReplacementKeaImportReference(string(refs), image)
	if err != nil {
		return "", err
	}
	if err := m2CheckReplacementKeaSourceReference(string(listing), source, image); err != nil {
		return "", err
	}
	manifestBytes, err := m2Command(ctx, "docker", "exec", dockerID, "ctr", "--namespace", "k8s.io", "content", "get", parts[1])
	if err != nil {
		return "", err
	}
	var manifest struct {
		SchemaVersion int               `json:"schemaVersion"`
		MediaType     string            `json:"mediaType"`
		Config        m2OCIDescriptor   `json:"config"`
		Layers        []m2OCIDescriptor `json:"layers"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", err
	}
	if err := m2CheckOCIBlob(m2OCIDescriptor{MediaType: m2OCIManifestMediaType, Digest: parts[1], Size: int64(len(manifestBytes))}, manifestBytes); err != nil {
		return "", err
	}
	if manifest.SchemaVersion != 2 || manifest.MediaType != m2OCIManifestMediaType || manifest.Config.MediaType != m2OCIConfigMediaType || manifest.Config.Digest != wantConfig || len(manifest.Layers) != 4 {
		return "", fmt.Errorf("approved Kea manifest/config descriptor does not match the archived OCI identity")
	}
	configBytes, err := m2Command(ctx, "docker", "exec", dockerID, "ctr", "--namespace", "k8s.io", "content", "get", manifest.Config.Digest)
	if err != nil {
		return "", err
	}
	if err := m2CheckOCIBlob(manifest.Config, configBytes); err != nil {
		return "", err
	}
	var config struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		RootFS       struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return "", err
	}
	if config.OS != "linux" || config.Architecture != "amd64" || config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(manifest.Layers) {
		return "", fmt.Errorf("approved Kea image config is not linux/amd64 with matching layers")
	}
	layers := make([]m2OCIDescriptor, 0, len(manifest.Layers))
	for i, layer := range manifest.Layers {
		if layer.MediaType != m2OCILayerMediaType {
			return "", fmt.Errorf("approved Kea layer %d has unsupported media type", i)
		}
		layers = append(layers, layer)
	}
	if err := m2VerifyNodeOCILayers(ctx, dockerID, layers); err != nil {
		return "", fmt.Errorf("approved Kea image layer content: %w", err)
	}
	return wantConfig, nil
}

func m2LoadAndVerifyReplacementKeaImages(ctx context.Context, identity m2LabIdentity, expectedDockerIDs map[string]string) (map[string]map[string]string, error) {
	if err := m2ValidateReplacementKeaDockerConfigIDs(expectedDockerIDs); err != nil {
		return nil, err
	}
	for _, node := range m2LabProfile.nodes {
		nodeID := identity.Nodes[node].DockerID
		if !m2FullHexID(nodeID) {
			return nil, fmt.Errorf("replacement node %s lacks a full container ID", node)
		}
		refs, err := m2Command(ctx, "docker", "exec", nodeID, "ctr", "--namespace", "k8s.io", "images", "ls", "-q")
		if err != nil {
			return nil, err
		}
		for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
			if containsString(splitLines(string(refs)), image) {
				return nil, fmt.Errorf("new replacement node %s already contains approved Kea reference %s", node, image)
			}
		}
	}
	if _, err := m2LifecycleCommand(ctx, "kind", "load", "docker-image", m2KeaDHCP4Image, m2KeaDHCP6Image, "--name", m2LabProfile.cluster); err != nil {
		return nil, fmt.Errorf("one-shot exact Kea image load failed/ambiguous: %w", err)
	}
	result := map[string]map[string]string{}
	for _, node := range m2LabProfile.nodes {
		result[node] = map[string]string{}
		for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
			nodeID := identity.Nodes[node].DockerID
			refs, err := m2Command(ctx, "docker", "exec", nodeID, "ctr", "--namespace", "k8s.io", "images", "ls", "-q")
			if err != nil {
				return nil, err
			}
			source, err := m2ReplacementKeaImportReference(string(refs), image)
			if err != nil {
				return nil, fmt.Errorf("node %s loaded Kea reference %s: %w", node, image, err)
			}
			listing, err := m2Command(ctx, "docker", "exec", nodeID, "ctr", "--namespace", "k8s.io", "images", "ls")
			if err != nil {
				return nil, err
			}
			if containsString(splitLines(string(refs)), image) {
				return nil, fmt.Errorf("new node %s acquired an unexpected approved alias during import", node)
			}
			if err := m2CheckReplacementKeaSourceReference(string(listing), source, image); err != nil {
				return nil, fmt.Errorf("node %s imported image descriptor: %w", node, err)
			}
			if _, err := m2VerifyReplacementKeaNodeImage(ctx, nodeID, image); err != nil {
				return nil, fmt.Errorf("node %s Kea OCI content verification: %w", node, err)
			}
			if _, err := m2Command(ctx, "docker", "exec", nodeID, "ctr", "--namespace", "k8s.io", "images", "tag", "--local", source, image); err != nil {
				return nil, fmt.Errorf("node %s exact Kea metadata alias failed/ambiguous: %w", node, err)
			}
			after, err := m2Command(ctx, "docker", "exec", nodeID, "ctr", "--namespace", "k8s.io", "images", "ls")
			if err != nil {
				return nil, err
			}
			if err := m2CheckReplacementKeaContainerdReferences(string(after), source, image); err != nil {
				return nil, fmt.Errorf("node %s Kea alias target identity: %w", node, err)
			}
			configID, err := m2VerifyReplacementKeaNodeImage(ctx, nodeID, image)
			if err != nil {
				return nil, fmt.Errorf("node %s exact Kea content after alias: %w", node, err)
			}
			cri, err := m2Command(ctx, "docker", "exec", nodeID, "crictl", "inspecti", "-o", "json", image)
			if err != nil {
				return nil, err
			}
			var record struct {
				Status struct {
					ID          string   `json:"id"`
					RepoDigests []string `json:"repoDigests"`
				} `json:"status"`
			}
			if err := json.Unmarshal(cri, &record); err != nil {
				return nil, err
			}
			if record.Status.ID != configID || m2CheckKeaCRIIdentity(record.Status.ID, image, image, record.Status.RepoDigests) != nil {
				return nil, fmt.Errorf("node %s CRI did not resolve exact approved Kea reference %s", node, image)
			}
			result[node][image] = configID
		}
	}
	if err := m2ValidateReplacementKeaConfigIDs(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (m2LiveReplacementOps) teardown(ctx context.Context, p m2ReplacementPreflight) (result m2ReplacementTeardown, returnErr error) {
	submitted := false
	defer func() {
		if returnErr != nil && !submitted && result.Status == "" {
			result.Status = "NOT_SUBMITTED"
		}
	}()
	if p.CaseID != historicM2ReplacementCase || p.OldCluster != m2LabProfile.cluster {
		return m2ReplacementTeardown{}, fmt.Errorf("teardown is not bound to the exact M2 preflight")
	}
	if err := m2AssertNoConcurrentLabOperation(); err != nil {
		return m2ReplacementTeardown{}, err
	}
	clusters, err := m2Command(ctx, "kind", "get", "clusters")
	if err != nil {
		return m2ReplacementTeardown{}, err
	}
	clusterNames := splitLines(string(clusters))
	if len(clusterNames) != 2 || !containsString(clusterNames, m2LabProfile.cluster) || !containsString(clusterNames, m1LabProfile.cluster) {
		return m2ReplacementTeardown{}, fmt.Errorf("fresh pre-delete cluster inventory differs from exact M1/M2 pair")
	}
	cfg, err := validateLab(ctx)
	if err != nil {
		return m2ReplacementTeardown{}, err
	}
	if err := m2InitializeReplacementAdmin(cfg); err != nil {
		return m2ReplacementTeardown{}, err
	}
	identity, err := m2InspectLabIdentity(ctx, cfg)
	if err != nil || !reflect.DeepEqual(identity, p.OldLab) {
		return m2ReplacementTeardown{}, fmt.Errorf("old M2 cluster incarnation changed since preflight: %v", err)
	}
	nodeContainers, err := m2Command(ctx, "docker", "ps", "-aq", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster="+m2LabProfile.cluster)
	if err != nil || m2ValidateReplacementContainerSet(string(nodeContainers), identity.Nodes) != nil {
		return m2ReplacementTeardown{}, fmt.Errorf("M2-attributed Docker container set changed since preflight: %v", err)
	}
	var oldReceipt m2NamespaceReceipt
	oldReceiptBytes, receiptErr := readM2PrivateRecord(m2NamespaceReceiptPath)
	if receiptErr == nil {
		receiptErr = json.Unmarshal(oldReceiptBytes, &oldReceipt)
	}
	if receiptErr != nil || !reflect.DeepEqual(oldReceipt.Namespaces, p.OldNamespaces) || m2SHA256(oldReceiptBytes) != p.NamespaceReceiptSHA256 {
		return m2ReplacementTeardown{}, fmt.Errorf("old namespace ownership/policy receipt changed since preflight: %v", receiptErr)
	}
	if err := m2VerifyNamespaceReceiptWith(ctx, admin, m2NamespaceReceiptPath, p.OldLab); err != nil {
		return m2ReplacementTeardown{}, fmt.Errorf("fresh namespace/policy observation failed: %w", err)
	}
	currentInventory, pvs, err := m2ReplacementLiveResourceInventory(ctx, adminConfig)
	if err != nil || m2ReplacementInventoryHash(currentInventory) != p.ResourceInventorySHA256 || len(currentInventory) != p.ResourceInventoryCount || !reflect.DeepEqual(pvs, p.PersistentVolumeNames) {
		return m2ReplacementTeardown{}, fmt.Errorf("live resource inventory differs from sealed preflight: %v", err)
	}
	inventoryBytes, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "cluster-replacement-resource-inventory-"+historicM2ReplacementCase+".json"))
	if err != nil || string(inventoryBytes) != string(append(mustJSON(currentInventory), '\n')) {
		return m2ReplacementTeardown{}, fmt.Errorf("durable resource inventory no longer matches live preflight: %v", err)
	}
	for _, node := range m2LabProfile.nodes {
		volume, err := m2ReplacementNodeVolume(ctx, node, p.OldLab.Nodes[node].DockerID)
		if err != nil || volume != p.OldVolumes[node] {
			return m2ReplacementTeardown{}, fmt.Errorf("node %s mount/storage identity changed since preflight: %v", node, err)
		}
	}
	m1ID, err := m2ReplacementM1Identity(ctx)
	if err != nil || m1ID != p.M1DockerID {
		return m2ReplacementTeardown{}, fmt.Errorf("M1 identity changed since preflight: %v", err)
	}
	keaIDs, err := m2InspectApprovedKeaDockerImages(ctx)
	if err != nil || !reflect.DeepEqual(keaIDs, p.KeaDockerConfigIDs) {
		return m2ReplacementTeardown{}, fmt.Errorf("approved local Kea image identity changed since its preflight: %v", err)
	}
	submitted = true
	out, err := command(ctx, "kind", "delete", "cluster", "--name", m2LabProfile.cluster, "--kubeconfig", m2LabProfile.kubeconfig)
	if err != nil {
		return m2ReplacementTeardown{Status: "DELETE_ACK_UNKNOWN"}, fmt.Errorf("Kind deletion failed/ambiguous (output %s): %w", m2RedactEvidence(string(out)), err)
	}
	result = m2ReplacementTeardown{Status: "PARTIAL_OR_UNVERIFIED", M1DockerID: ""}
	clusters, e := m2Command(ctx, "kind", "get", "clusters")
	if e != nil {
		return result, e
	}
	clusterNames = splitLines(string(clusters))
	result.OldClusterAbsent = len(clusterNames) == 1 && clusterNames[0] == m1LabProfile.cluster
	result.OldContainersAbsent = true
	for _, n := range m2LabProfile.nodes {
		oldID := p.OldLab.Nodes[n].DockerID
		o, x := m2Command(ctx, "docker", "inspect", "--format", "{{.Id}}", oldID)
		if x == nil {
			if strings.TrimSpace(string(o)) != oldID {
				return result, fmt.Errorf("old M2 container identity %s returned an unexpected inspect result", n)
			}
			result.OldContainersAbsent = false
		} else if !m2CommandOutputConfirmsAbsent(string(o), oldID) {
			return result, x
		}
	}
	remaining, e := m2Command(ctx, "docker", "ps", "-aq", "--filter", "label=io.x-k8s.kind.cluster="+m2LabProfile.cluster)
	if e != nil {
		return result, e
	}
	if len(splitLines(string(remaining))) != 0 {
		result.OldContainersAbsent = false
	}
	result.OldVolumesAbsent = true
	for _, v := range p.OldVolumes {
		out, x := m2Command(ctx, "docker", "volume", "inspect", v)
		if x == nil {
			result.OldVolumesAbsent = false
		} else if !m2CommandOutputConfirmsAbsent(string(out), v) {
			return result, x
		}
	}
	result.M1DockerID, e = m2ReplacementM1Identity(ctx)
	if e != nil {
		return result, e
	}
	if e := m2AssertNoConcurrentLabOperation(); e != nil {
		return result, e
	}
	if result.OldClusterAbsent && result.OldContainersAbsent && result.OldVolumesAbsent && result.M1DockerID == p.M1DockerID {
		result.Status = "VERIFIED_OLD_LAB_ABSENT"
	}
	return result, nil
}

func (m2LiveReplacementOps) verifyTeardown(ctx context.Context, p m2ReplacementPreflight) (m2ReplacementTeardown, error) {
	if p.CaseID != historicM2ReplacementCase || p.OldCluster != m2LabProfile.cluster {
		return m2ReplacementTeardown{}, fmt.Errorf("read-only teardown verification is not bound to the exact M2 preflight")
	}
	if err := m2AssertNoConcurrentLabOperation(); err != nil {
		return m2ReplacementTeardown{}, err
	}
	clusters, err := m2Command(ctx, "kind", "get", "clusters")
	if err != nil || !reflect.DeepEqual(splitLines(string(clusters)), []string{m1LabProfile.cluster}) {
		return m2ReplacementTeardown{}, fmt.Errorf("read-only verification requires only the original M1 Kind cluster to remain: %v", err)
	}
	result := m2ReplacementTeardown{Status: "VERIFIED_OLD_LAB_ABSENT", OldClusterAbsent: true, OldContainersAbsent: true, OldVolumesAbsent: true}
	for _, node := range m2LabProfile.nodes {
		id := p.OldLab.Nodes[node].DockerID
		out, inspectErr := m2Command(ctx, "docker", "inspect", "--format", "{{.Id}}", id)
		if inspectErr == nil {
			if strings.TrimSpace(string(out)) != id {
				return m2ReplacementTeardown{}, fmt.Errorf("old M2 node %s resolved to an unexpected Docker identity", node)
			}
			result.OldContainersAbsent = false
		} else if !m2CommandOutputConfirmsAbsent(string(out), id) {
			return m2ReplacementTeardown{}, fmt.Errorf("old M2 node %s absence is not proven: %w", node, inspectErr)
		}
	}
	containers, err := m2Command(ctx, "docker", "ps", "-aq", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster="+m2LabProfile.cluster)
	if err != nil || len(splitLines(string(containers))) != 0 {
		return m2ReplacementTeardown{}, fmt.Errorf("unexpected M2-attributed Docker containers remain: %v", err)
	}
	volumes, err := m2Command(ctx, "docker", "volume", "ls", "-q")
	if err != nil {
		return m2ReplacementTeardown{}, err
	}
	listedVolumes := splitLines(string(volumes))
	for _, name := range p.OldVolumes {
		if containsString(listedVolumes, name) {
			result.OldVolumesAbsent = false
			continue
		}
		out, inspectErr := m2Command(ctx, "docker", "volume", "inspect", name)
		if inspectErr == nil {
			result.OldVolumesAbsent = false
		} else if !m2CommandOutputConfirmsAbsent(string(out), name) {
			return m2ReplacementTeardown{}, fmt.Errorf("old M2 volume %s absence is not proven: %w", name, inspectErr)
		}
	}
	m1ID, err := m2ReplacementM1Identity(ctx)
	if err != nil || m1ID != p.M1DockerID {
		return m2ReplacementTeardown{}, fmt.Errorf("M1 identity changed or cannot be verified after teardown: %v", err)
	}
	result.M1DockerID = m1ID
	if err := m2AssertNoConcurrentLabOperation(); err != nil {
		return m2ReplacementTeardown{}, err
	}
	if !result.OldContainersAbsent || !result.OldVolumesAbsent {
		result.Status = "PARTIAL_OR_UNVERIFIED"
	}
	return result, nil
}

func m2CommandOutputConfirmsAbsent(output, identity string) bool {
	if identity == "" || !strings.Contains(output, identity) {
		return false
	}
	lower := strings.ToLower(output)
	return strings.Contains(lower, "no such object") || strings.Contains(lower, "no such volume")
}

func m2RequireCommandAbsence(output []byte, commandErr error, identity string) error {
	if commandErr == nil {
		return fmt.Errorf("resource %s is present", identity)
	}
	if !m2CommandOutputConfirmsAbsent(string(output), identity) {
		return fmt.Errorf("resource %s absence is not proven: %w", identity, commandErr)
	}
	return nil
}

func (m2LiveReplacementOps) create(ctx context.Context, p m2ReplacementPreflight, d m2ReplacementTeardown) (created m2ReplacementCreated, returnErr error) {
	submitted := false
	defer func() {
		if returnErr != nil && submitted && created.Status == "" {
			created.Status = "CREATED_BUT_UNVERIFIED"
		}
	}()
	if d.Status != "VERIFIED_OLD_LAB_ABSENT" || p.CaseID != historicM2ReplacementCase {
		return m2ReplacementCreated{}, fmt.Errorf("verified one-time teardown required")
	}
	if err := m2ValidateReplacementKeaDockerConfigIDs(p.KeaDockerConfigIDs); err != nil {
		return m2ReplacementCreated{}, fmt.Errorf("preflight lacks exact approved local Kea image identities: %w", err)
	}
	currentKeaIDs, err := m2InspectApprovedKeaDockerImages(ctx)
	if err != nil || !reflect.DeepEqual(currentKeaIDs, p.KeaDockerConfigIDs) {
		return m2ReplacementCreated{}, fmt.Errorf("local approved Kea image identities changed after preflight: %v", err)
	}
	if err := m2VerifyLabSelection(); err != nil {
		return m2ReplacementCreated{}, err
	}
	if err := checkM2PrivateInputs(filepath.Dir(m2LabProfile.kubeconfig), m2LabProfile.dockerConfig, m2LabProfile.kubeconfig); err != nil {
		return m2ReplacementCreated{}, err
	}
	if err := m2AssertNoConcurrentLabOperation(); err != nil {
		return m2ReplacementCreated{}, err
	}
	clusters, err := m2Command(ctx, "kind", "get", "clusters")
	if err != nil || !reflect.DeepEqual(splitLines(string(clusters)), []string{m1LabProfile.cluster}) {
		return m2ReplacementCreated{}, fmt.Errorf("one-shot creation requires only the exact unchanged M1 cluster to remain: %v", err)
	}
	remainingM2Containers, err := m2Command(ctx, "docker", "ps", "-aq", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster="+m2LabProfile.cluster)
	if err != nil || len(splitLines(string(remainingM2Containers))) != 0 {
		return m2ReplacementCreated{}, fmt.Errorf("one-shot creation refuses any remaining old M2-attributed container: %v", err)
	}
	for _, node := range m2LabProfile.nodes {
		oldID := p.OldLab.Nodes[node].DockerID
		out, inspectErr := m2Command(ctx, "docker", "inspect", "--format", "{{.Id}}", oldID)
		if err := m2RequireCommandAbsence(out, inspectErr, oldID); err != nil {
			return m2ReplacementCreated{}, fmt.Errorf("old M2 node container %s absence is not verified: %w", node, err)
		}
		out, inspectErr = m2Command(ctx, "docker", "volume", "inspect", p.OldVolumes[node])
		if err := m2RequireCommandAbsence(out, inspectErr, p.OldVolumes[node]); err != nil {
			return m2ReplacementCreated{}, fmt.Errorf("old M2 node storage %s absence is not verified: %w", node, err)
		}
	}
	m1ID, err := m2ReplacementM1Identity(ctx)
	if err != nil || m1ID != p.M1DockerID {
		return m2ReplacementCreated{}, fmt.Errorf("M1 identity changed immediately before creation: %v", err)
	}
	oldCfg := m2LabProfile.kubeconfig + ".old-" + historicM2ReplacementCase
	if _, err := os.Lstat(oldCfg); err == nil {
		return m2ReplacementCreated{}, fmt.Errorf("old kubeconfig archive path already exists")
	} else if !os.IsNotExist(err) {
		return m2ReplacementCreated{}, err
	}
	if _, _, err := m2VerifyBuildEvidence(ctx, os.Getenv("IMG")); err != nil {
		return m2ReplacementCreated{}, err
	}
	if err := os.Rename(m2LabProfile.kubeconfig, oldCfg); err != nil {
		return m2ReplacementCreated{}, fmt.Errorf("preserve old kubeconfig before recreation: %w", err)
	}
	f, err := os.OpenFile(m2LabProfile.kubeconfig, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return m2ReplacementCreated{}, err
	}
	if err = f.Close(); err != nil {
		return m2ReplacementCreated{}, err
	}
	if _, err := command(ctx, "kind", kindCreateArgs(m2LabProfile)...); err != nil {
		return m2ReplacementCreated{Status: "CREATE_ACK_UNKNOWN"}, fmt.Errorf("one-shot Kind create failed/ambiguous; no retry: %w", err)
	}
	submitted = true
	cfg, err := validateLab(ctx)
	if err != nil {
		return m2ReplacementCreated{}, err
	}
	adminConfig = cfg
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return m2ReplacementCreated{}, err
	}
	if err := infrastructurev1alpha1.AddToScheme(scheme); err != nil {
		return m2ReplacementCreated{}, err
	}
	admin, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return m2ReplacementCreated{}, err
	}
	identity, err := m2InspectLabIdentity(ctx, cfg)
	if err != nil {
		return m2ReplacementCreated{}, err
	}
	if err := m2AssertNoConcurrentLabOperation(); err != nil {
		return m2ReplacementCreated{}, err
	}
	keaConfigIDs, err := m2LoadAndVerifyReplacementKeaImages(ctx, identity, p.KeaDockerConfigIDs)
	if err != nil {
		return m2ReplacementCreated{}, fmt.Errorf("replacement Kea image import/identity failed; creation cannot be retried: %w", err)
	}
	volumes := map[string]string{}
	for _, node := range m2LabProfile.nodes {
		v, e := m2ReplacementNodeVolume(ctx, node, identity.Nodes[node].DockerID)
		if e != nil {
			return m2ReplacementCreated{}, e
		}
		volumes[node] = v
	}
	m1ID, err = m2ReplacementM1Identity(ctx)
	if err != nil {
		return m2ReplacementCreated{}, err
	}
	return m2ReplacementCreated{Status: "VERIFIED_NEW_LAB", NewLab: identity, NewVolumes: volumes, KeaConfigIDs: keaConfigIDs, M1DockerID: m1ID}, nil
}

func (m2LiveReplacementOps) namespaces(ctx context.Context, c m2ReplacementCreated) (m2ReplacementNamespaces, error) {
	if c.Status != "VERIFIED_NEW_LAB" {
		return m2ReplacementNamespaces{}, fmt.Errorf("new cluster receipt required")
	}
	cfg, err := validateLab(ctx)
	if err != nil {
		return m2ReplacementNamespaces{}, err
	}
	if err := m2WithReplacementNamespaceAdmin(ctx, cfg, func(ctx context.Context) error {
		observed, err := m2InspectLabIdentity(ctx, cfg)
		if err != nil {
			return err
		}
		m1ID, err := m2ReplacementM1Identity(ctx)
		if err != nil {
			return err
		}
		if err := m2VerifyReplacementNamespaceBootstrapIdentity(observed, m1ID, c); err != nil {
			return err
		}
		return m2CreateLabNamespaces(ctx)
	}); err != nil {
		return m2ReplacementNamespaces{}, err
	}
	var receipt m2NamespaceReceipt
	if err := readJSONM2(m2NamespaceReceiptPath, &receipt); err != nil {
		return m2ReplacementNamespaces{}, err
	}
	if !reflect.DeepEqual(receipt.Lab, c.NewLab) {
		return m2ReplacementNamespaces{}, fmt.Errorf("new namespace receipt is not bound to created cluster identity")
	}
	return m2ReplacementNamespaces{Status: "VERIFIED_NEW_NAMESPACES", Namespaces: receipt.Namespaces}, nil
}

func (m2LiveReplacementOps) verifyNamespacesAbsent(ctx context.Context, c m2ReplacementCreated) (m2ReplacementNamespaceAbsence, error) {
	if c.Status != "VERIFIED_NEW_LAB" || ctx.Err() != nil {
		return m2ReplacementNamespaceAbsence{}, fmt.Errorf("verified new cluster and live context required")
	}
	if err := m2AssertNoConcurrentLabOperation(); err != nil {
		return m2ReplacementNamespaceAbsence{}, err
	}
	cfg, err := validateLab(ctx)
	if err != nil {
		return m2ReplacementNamespaceAbsence{}, err
	}
	var observed m2LabIdentity
	if err := m2WithReplacementNamespaceAdmin(ctx, cfg, func(ctx context.Context) error {
		var inspectErr error
		observed, inspectErr = m2InspectLabIdentity(ctx, cfg)
		return inspectErr
	}); err != nil {
		return m2ReplacementNamespaceAbsence{}, err
	}
	m1ID, err := m2ReplacementM1Identity(ctx)
	if err != nil {
		return m2ReplacementNamespaceAbsence{}, err
	}
	if err := m2VerifyReplacementNamespaceBootstrapIdentity(observed, m1ID, c); err != nil {
		return m2ReplacementNamespaceAbsence{}, err
	}
	for _, name := range []string{m2LabProfile.runtimeNamespace, m2LabProfile.outsideNamespace} {
		var namespace corev1.Namespace
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		getErr := admin.Get(requestCtx, client.ObjectKey{Name: name}, &namespace)
		cancel()
		if !apierrors.IsNotFound(getErr) {
			return m2ReplacementNamespaceAbsence{}, fmt.Errorf("namespace %s absence is not proven: %v", name, getErr)
		}
	}
	return m2ReplacementNamespaceAbsence{Status: "VERIFIED_NEW_NAMESPACES_ABSENT", Cluster: observed, RuntimeAbsent: true, OutsideAbsent: true, M1DockerID: m1ID}, nil
}

func (m2LiveReplacementOps) verifyFinal(ctx context.Context, p m2ReplacementPreflight, c m2ReplacementCreated, n m2ReplacementNamespaces) error {
	if err := m2AssertNoConcurrentLabOperation(); err != nil {
		return err
	}
	gateBBytes, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "cluster-replacement-gate-b-"+historicM2ReplacementCase+".json"))
	if err != nil {
		return fmt.Errorf("new-lab Gate B receipt required before finalization: %w", err)
	}
	var gateB struct {
		Status   string `json:"status"`
		Selected int    `json:"selected"`
		Executed int    `json:"executed"`
		Passed   int    `json:"passed"`
	}
	if json.Unmarshal(gateBBytes, &gateB) != nil || gateB.Status != "VERIFIED_GATE_B_PASS" || gateB.Selected != 2 || gateB.Executed != 2 || gateB.Passed != 2 {
		return fmt.Errorf("new-lab Gate B receipt is incomplete")
	}
	cfg, err := validateLab(ctx)
	if err != nil {
		return err
	}
	identity, err := m2WithReplacementLabIdentity(ctx, cfg, m2InspectLabIdentity)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(identity, c.NewLab) {
		return fmt.Errorf("fresh node/server/CA identity differs from creation receipt")
	}
	clusters, err := m2Command(ctx, "kind", "get", "clusters")
	if err != nil {
		return err
	}
	clusterNames := splitLines(string(clusters))
	if !containsString(clusterNames, m2LabProfile.cluster) || !containsString(clusterNames, m1LabProfile.cluster) || len(clusterNames) != 2 {
		return fmt.Errorf("new M2 and unchanged M1 must be the only selected Kind clusters")
	}
	for _, node := range m2LabProfile.nodes {
		oldID := p.OldLab.Nodes[node].DockerID
		out, inspectErr := m2Command(ctx, "docker", "inspect", "--format", "{{.Id}}", oldID)
		if err := m2RequireCommandAbsence(out, inspectErr, oldID); err != nil {
			return fmt.Errorf("old M2 container %s is still present or absence is unverified: %w", node, err)
		}
		volume := p.OldVolumes[node]
		out, inspectErr = m2Command(ctx, "docker", "volume", "inspect", volume)
		if err := m2RequireCommandAbsence(out, inspectErr, volume); err != nil {
			return fmt.Errorf("old M2 node storage remains or absence is unverified: %w", err)
		}
	}
	remainingM2Containers, err := m2Command(ctx, "docker", "ps", "-aq", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster="+m2LabProfile.cluster)
	if err != nil {
		return err
	}
	if err := m2ValidateReplacementActiveContainerSet(string(remainingM2Containers), p.OldLab.Nodes, identity.Nodes); err != nil {
		return fmt.Errorf("active M2-attributed containers do not match the exact replacement incarnation: %w", err)
	}
	var receipt m2NamespaceReceipt
	if err := readJSONM2(m2NamespaceReceiptPath, &receipt); err != nil {
		return err
	}
	if !reflect.DeepEqual(receipt.Namespaces, n.Namespaces) {
		return fmt.Errorf("fresh namespace identities differ from receipt")
	}
	m1ID, err := m2ReplacementM1Identity(ctx)
	if err != nil {
		return err
	}
	if m1ID != p.M1DockerID || m1ID != c.M1DockerID {
		return fmt.Errorf("fresh M1 identity changed")
	}
	fingerprint, managerID, err := m2VerifyBuildEvidence(ctx, os.Getenv("IMG"))
	if err != nil || fingerprint == "" {
		return fmt.Errorf("current fingerprinted manager build evidence failed: %v", err)
	}
	if err := m2VerifyNodeImage(ctx, os.Getenv("IMG"), managerID); err != nil {
		return err
	}
	if err := m2VerifyManagerDeployment(ctx, os.Getenv("IMG"), managerID); err != nil {
		return err
	}
	keaConfigIDs := map[string]map[string]string{}
	for _, node := range m2LabProfile.nodes {
		keaConfigIDs[node] = map[string]string{}
		for _, image := range []string{m2KeaDHCP4Image, m2KeaDHCP6Image} {
			configID, e := m2VerifyReplacementKeaNodeImage(ctx, identity.Nodes[node].DockerID, image)
			if e != nil {
				return e
			}
			out, e := m2Command(ctx, "docker", "exec", identity.Nodes[node].DockerID, "crictl", "inspecti", "-o", "json", image)
			if e != nil {
				return e
			}
			var record struct {
				Status struct {
					ID          string   `json:"id"`
					RepoDigests []string `json:"repoDigests"`
				} `json:"status"`
			}
			if e := json.Unmarshal(out, &record); e != nil {
				return e
			}
			if e := m2CheckKeaCRIIdentity(record.Status.ID, image, image, record.Status.RepoDigests); e != nil {
				return fmt.Errorf("new M2 node %s Kea reference %s: %w", node, image, e)
			}
			if record.Status.ID != configID {
				return fmt.Errorf("new M2 node %s Kea CRI config changed during final observation", node)
			}
			keaConfigIDs[node][image] = configID
		}
	}
	if err := m2ValidateReplacementKeaConfigIDs(keaConfigIDs); err != nil || !reflect.DeepEqual(keaConfigIDs, c.KeaConfigIDs) {
		return fmt.Errorf("final Kea image identities differ from the creation receipt: %v", err)
	}
	return nil
}

func m2ReplacementNodeVolume(ctx context.Context, node, expectedDockerID string) (string, error) {
	if !m2FullHexID(expectedDockerID) {
		return "", fmt.Errorf("node %s lacks an exact Docker incarnation", node)
	}
	out, err := m2Command(ctx, "docker", "inspect", "--format", "{{.Id}}|{{json .Mounts}}", expectedDockerID)
	if err != nil {
		return "", err
	}
	fields := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	if len(fields) != 2 || fields[0] != expectedDockerID {
		return "", fmt.Errorf("node %s Docker container changed during mount inspection", node)
	}
	volume, err := m2ValidateReplacementMounts([]byte(fields[1]))
	if err != nil {
		return "", fmt.Errorf("node %s mounts: %w", node, err)
	}
	if _, err := m2Command(ctx, "docker", "volume", "inspect", volume); err != nil {
		return "", err
	}
	return volume, nil
}

type m2ReplacementMount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Destination string `json:"Destination"`
	Source      string `json:"Source"`
	RW          bool   `json:"RW"`
}

func m2ValidateReplacementMounts(data []byte) (string, error) {
	var mounts []m2ReplacementMount
	if err := json.Unmarshal(data, &mounts); err != nil {
		return "", err
	}
	if len(mounts) != 2 {
		return "", fmt.Errorf("expected exactly the reviewed /var volume and /lib/modules bind mounts")
	}
	var volume string
	seen := map[string]bool{}
	for _, m := range mounts {
		if seen[m.Destination] {
			return "", fmt.Errorf("duplicate mount destination %q", m.Destination)
		}
		seen[m.Destination] = true
		switch m.Destination {
		case "/var":
			if m.Type != "volume" || !m.RW || !m2FullHexID(m.Name) || m.Source != "/var/lib/docker/volumes/"+m.Name+"/_data" {
				return "", fmt.Errorf("/var volume identity or source invalid")
			}
			volume = m.Name
		case "/lib/modules":
			if m.Type != "bind" || m.RW || m.Source != "/lib/modules" {
				return "", fmt.Errorf("/lib/modules must be the reviewed read-only host bind")
			}
		default:
			return "", fmt.Errorf("unreviewed mount destination %q", m.Destination)
		}
	}
	if volume == "" {
		return "", fmt.Errorf("reviewed /var volume is missing")
	}
	return volume, nil
}

type m2ReplacementResourceRef struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

func m2ReplacementLiveResourceInventory(ctx context.Context, cfg *rest.Config) ([]m2ReplacementResourceRef, []string, error) {
	if cfg == nil || ctx.Err() != nil {
		return nil, nil, fmt.Errorf("live resource inventory requires a current cluster context")
	}
	disco, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	resources, err := disco.ServerPreferredResources()
	if err != nil {
		return nil, nil, fmt.Errorf("complete API resource discovery failed: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	var refs []m2ReplacementResourceRef
	for _, group := range resources {
		gv, err := schema.ParseGroupVersion(group.GroupVersion)
		if err != nil {
			return nil, nil, err
		}
		for _, resource := range group.APIResources {
			if strings.Contains(resource.Name, "/") || !containsString(resource.Verbs, "list") {
				continue
			}
			gvr := gv.WithResource(resource.Name)
			resourceID := resource.Name
			if gv.Group != "" {
				resourceID += "." + gv.Group
			}
			var list *unstructured.UnstructuredList
			if resource.Namespaced {
				list, err = dyn.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
			} else {
				list, err = dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
			}
			if err != nil {
				return nil, nil, fmt.Errorf("list %s: %w", gvr.String(), err)
			}
			for i := range list.Items {
				obj := &list.Items[i]
				refs = append(refs, m2ReplacementResourceRef{Resource: resourceID, Namespace: obj.GetNamespace(), Name: obj.GetName(), UID: string(obj.GetUID())})
			}
		}
	}
	slices.SortFunc(refs, func(a, b m2ReplacementResourceRef) int {
		return strings.Compare(a.Resource+"/"+a.Namespace+"/"+a.Name+"/"+a.UID, b.Resource+"/"+b.Namespace+"/"+b.Name+"/"+b.UID)
	})
	var pvs []string
	for _, ref := range refs {
		if ref.Resource == "persistentvolumes" {
			pvs = append(pvs, ref.Name)
		}
	}
	return refs, pvs, nil
}

func m2ReplacementInventoryHash(refs []m2ReplacementResourceRef) string {
	b, _ := json.Marshal(refs)
	return m2SHA256(b)
}

func mustJSON(value any) []byte {
	b, _ := json.Marshal(value)
	return b
}

func m2ValidateReplacementResourceInventory(refs []m2ReplacementResourceRef, pvs []string) error {
	if len(refs) == 0 || len(pvs) != 0 {
		return fmt.Errorf("resource inventory is empty or persistent volumes exist")
	}
	allowedNamespaces := map[string]bool{"default": true, "kube-system": true, "kube-public": true, "kube-node-lease": true, "local-path-storage": true, m2LabProfile.runtimeNamespace: true, m2LabProfile.outsideNamespace: true}
	for _, ref := range refs {
		if ref.Name == "" || ref.UID == "" && ref.Resource != "componentstatuses" {
			return fmt.Errorf("resource inventory contains an incomplete identity: resource=%s namespace=%s name=%s uid=%s", ref.Resource, ref.Namespace, ref.Name, ref.UID)
		}
		if ref.Resource == "componentstatuses" && (ref.Namespace != "" || ref.UID != "") {
			return fmt.Errorf("virtual ComponentStatus identity is malformed")
		}
		if ref.Resource == "namespaces" && !allowedNamespaces[ref.Name] {
			return fmt.Errorf("unexpected cluster namespace %q", ref.Name)
		}
		if ref.Resource == "nodes" && !containsString(m2LabProfile.nodes, ref.Name) {
			return fmt.Errorf("unexpected Kubernetes node %q", ref.Name)
		}
		if ref.Resource == "customresourcedefinitions.apiextensions.k8s.io" && ref.Name != "keaclusters.infrastructure.keaguard.example" {
			return fmt.Errorf("unexpected cluster-scoped CRD %q", ref.Name)
		}
		if ref.Namespace != "" && !allowedNamespaces[ref.Namespace] {
			return fmt.Errorf("unexpected namespace resource %s/%s/%s", ref.Resource, ref.Namespace, ref.Name)
		}
	}
	return nil
}
func m2ReplacementM1Identity(ctx context.Context) (string, error) {
	clusters, err := m2Command(ctx, "kind", "get", "clusters")
	if err != nil {
		return "", err
	}
	if !containsString(splitLines(string(clusters)), m1LabProfile.cluster) {
		return "", fmt.Errorf("separate M1 cluster absent")
	}
	node := m1LabProfile.cluster + "-control-plane"
	out, err := m2Command(ctx, "docker", "inspect", "--format", `{{.Id}}|{{.Config.Image}}|{{index .Config.Labels "io.x-k8s.kind.cluster"}}`, node)
	if err != nil {
		return "", err
	}
	fields := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(fields) != 3 || !m2FullHexID(fields[0]) || fields[1] != m1LabProfile.nodeImage || fields[2] != m1LabProfile.cluster {
		return "", fmt.Errorf("M1 identity mismatch")
	}
	return fields[0], nil
}
func readJSONM2(path string, v any) error {
	b, err := readM2PrivateRecord(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

const m2ExpectedHistoricMarkerSHA = "7677ec685f8e6df21795f84d499c18bf98d87b51e47baea388c11972bb999232"
const m2ExpectedHistoricLedgerSHA = "94af0604a1449e4657e63fe62bf013f53b3a4a41e4189bf686b1cd5081198a7c"

func m2ValidateReplacementGateBSelection(caseID, enabled string, focus, skip []string) error {
	if caseID != historicM2ReplacementCase || enabled != "1" || len(focus) != 1 || focus[0] != "M2: Admission" || len(skip) != 0 {
		return fmt.Errorf("pending-recovery E2E is restricted to exact M2 Admission Gate B selection")
	}
	return nil
}

func m2PrepareReplacementGateBEvidence(caseID string) error {
	if caseID != historicM2ReplacementCase {
		return fmt.Errorf("wrong replacement case")
	}
	if err := m2ValidateReplacementBootstrapEvidence(m2NativeDir, caseID, m2ExpectedHistoricMarkerSHA, m2ExpectedHistoricLedgerSHA); err != nil {
		return err
	}
	var created m2ReplacementCreated
	var namespaces m2ReplacementNamespaces
	for stage, dst := range map[string]any{"created": &created, "namespaces": &namespaces} {
		b, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "cluster-replacement-"+stage+"-"+caseID+".json"))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, dst); err != nil {
			return err
		}
	}
	if created.Status != "VERIFIED_NEW_LAB" || namespaces.Status != "VERIFIED_NEW_NAMESPACES" {
		return fmt.Errorf("replacement Gate B requires verified new cluster and namespace receipts")
	}
	dir := filepath.Join(m2NativeDir, "replacement-gate-b-"+caseID)
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("Gate B evidence is one-use: %w", err)
	}
	m2ScenarioEvidenceDir = dir
	createdBytes, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "cluster-replacement-created-"+caseID+".json"))
	if err != nil {
		return err
	}
	namespaceBytes, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "cluster-replacement-namespaces-"+caseID+".json"))
	if err != nil {
		return err
	}
	started, _ := json.Marshal(map[string]string{"caseID": caseID, "status": "GATE_B_RUNNING_ON_VERIFIED_REPLACEMENT", "createdSHA256": m2SHA256(createdBytes), "namespacesSHA256": m2SHA256(namespaceBytes)})
	return writePrivateExclusiveOrReplace(filepath.Join(dir, "gate-b-started.json"), append(started, '\n'))
}
func m2SealReplacementGateB(caseID, dir, root string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var restorations, diagnostics []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "recovery-restored-") && strings.HasSuffix(entry.Name(), ".json") {
			restorations = append(restorations, entry.Name())
		}
		if strings.HasPrefix(entry.Name(), "diagnostics-") && strings.HasSuffix(entry.Name(), ".json") {
			diagnostics = append(diagnostics, entry.Name())
		}
		if entry.Name() == "recovery-pending.json" {
			return fmt.Errorf("Gate B left an unresolved scenario marker")
		}
	}
	if len(restorations) != 2 || len(diagnostics) != 2 {
		return fmt.Errorf("Gate B expected exactly two restoration/diagnostic receipts, got %d/%d", len(restorations), len(diagnostics))
	}
	for _, name := range restorations {
		b, err := readM2PrivateRecord(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		var r struct {
			CaseID   string `json:"caseID"`
			Recovery string `json:"recovery"`
		}
		if json.Unmarshal(b, &r) != nil || r.CaseID == "" || r.Recovery != "restored" {
			return fmt.Errorf("invalid Gate B restoration receipt %s", name)
		}
	}
	for _, name := range diagnostics {
		b, err := readM2PrivateRecord(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		var d struct {
			CaseID string `json:"caseID"`
			Status string `json:"status"`
		}
		if json.Unmarshal(b, &d) != nil || d.CaseID == "" || d.Status != "ok" {
			return fmt.Errorf("invalid Gate B diagnostics %s", name)
		}
	}
	data, _ := json.Marshal(map[string]any{"caseID": caseID, "status": "VERIFIED_GATE_B_PASS", "selected": 2, "executed": len(m2ReplacementGateBReports), "passed": len(m2ReplacementGateBReports), "restorationReceipts": restorations, "diagnostics": diagnostics})
	return writePrivateExclusiveOrReplace(filepath.Join(root, "cluster-replacement-gate-b-"+caseID+".json"), append(data, '\n'))
}

func TestM2ClusterReplacementStage(t *testing.T) {
	caseID := os.Getenv("KEAGUARD_M2_CLUSTER_REPLACEMENT")
	if caseID == "" {
		t.Skip("explicit replacement recovery only")
	}
	if caseID != historicM2ReplacementCase {
		t.Fatal("wrong historic case")
	}
	stage := os.Getenv("KEAGUARD_M2_REPLACEMENT_STAGE")
	if stage == "" {
		t.Fatal("explicit replacement stage required")
	}
	marker, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "recovery-pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, err := readM2PrivateRecord(filepath.Join(m2NativeDir, "diagnostics.json"))
	if err != nil {
		t.Fatal(err)
	}
	w := m2ReplacementWorkflow{dir: m2NativeDir, caseID: caseID, ops: m2LiveReplacementOps{}, expectedMarker: m2SHA256(marker), expectedLedger: m2SHA256(ledger), expectedDiagnostics: m2SHA256(diagnostic)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var runErr error
	switch stage {
	case "preflight":
		if _, statErr := os.Lstat(w.path("preflight")); statErr == nil {
			runErr = w.revalidatePreflight(ctx)
		} else if os.IsNotExist(statErr) {
			runErr = w.preflight(ctx)
			if runErr == nil {
				runErr = w.revalidatePreflight(ctx)
			}
		} else {
			runErr = statErr
		}
	case "preflight-revalidate":
		runErr = w.revalidatePreflight(ctx)
	case "kea-preflight":
		runErr = w.verifyKeaImages(ctx)
	case "teardown":
		runErr = w.teardown(ctx)
	case "reconcile-teardown":
		runErr = w.reconcileTeardown(ctx)
	case "create":
		runErr = w.create(ctx)
	case "resume-create-not-submitted":
		runErr = w.resumeUnsubmittedCreate(ctx)
	case "namespaces":
		runErr = w.namespaces(ctx)
	case "reconcile-namespaces-not-submitted":
		runErr = w.reconcileUnsubmittedNamespaces(ctx)
	case "resume-namespaces-not-submitted":
		runErr = w.resumeUnsubmittedNamespaces(ctx)
	case "finalize":
		runErr = w.finalize(ctx)
	default:
		runErr = fmt.Errorf("unsupported replacement stage %q", stage)
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
}
