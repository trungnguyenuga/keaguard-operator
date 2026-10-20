package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	m2OCIIndexMediaType    = "application/vnd.oci.image.index.v1+json"
	m2OCIManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	m2OCIConfigMediaType   = "application/vnd.oci.image.config.v1+json"
	m2OCILayerMediaType    = "application/vnd.oci.image.layer.v1.tar+gzip"
)

type m2OCIDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform,omitempty"`
}

type m2OperatorOCIIdentity struct {
	IndexID    string
	ManifestID string
	ConfigID   string
}

func m2ValidSHA256Digest(digest string) bool {
	if len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	for _, c := range digest[len("sha256:"):] {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func m2CheckOCIBlob(desc m2OCIDescriptor, data []byte) error {
	if !m2ValidSHA256Digest(desc.Digest) || desc.Size < 0 || int64(len(data)) != desc.Size {
		return fmt.Errorf("OCI blob descriptor size or digest is invalid")
	}
	sum := sha256.Sum256(data)
	if desc.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		return fmt.Errorf("OCI blob content hash does not match descriptor")
	}
	return nil
}

func m2CheckOperatorOCI(indexBytes []byte, indexID string, read func(string) ([]byte, error), verifyLayer func(m2OCIDescriptor) error) (m2OperatorOCIIdentity, error) {
	if read == nil || verifyLayer == nil {
		return m2OperatorOCIIdentity{}, fmt.Errorf("OCI content verification functions are required")
	}
	var selected *m2OCIDescriptor
	current := indexBytes
	currentDesc := m2OCIDescriptor{MediaType: m2OCIIndexMediaType, Digest: indexID, Size: int64(len(indexBytes))}
	for depth := 0; depth < 3; depth++ {
		if err := m2CheckOCIBlob(currentDesc, current); err != nil {
			return m2OperatorOCIIdentity{}, fmt.Errorf("image index: %w", err)
		}
		var index struct {
			SchemaVersion int               `json:"schemaVersion"`
			MediaType     string            `json:"mediaType"`
			Manifests     []m2OCIDescriptor `json:"manifests"`
		}
		if err := json.Unmarshal(current, &index); err != nil || index.SchemaVersion != 2 || index.MediaType != m2OCIIndexMediaType {
			return m2OperatorOCIIdentity{}, fmt.Errorf("unsupported or malformed OCI image index: %v", err)
		}
		for i := range index.Manifests {
			desc := &index.Manifests[i]
			if desc.Platform != nil && desc.Platform.OS == "linux" && desc.Platform.Architecture == "amd64" {
				if selected != nil {
					return m2OperatorOCIIdentity{}, fmt.Errorf("ambiguous linux/amd64 manifest selection")
				}
				selected = desc
			}
		}
		if selected != nil {
			break
		}
		if len(index.Manifests) != 1 || index.Manifests[0].Platform != nil || index.Manifests[0].MediaType != m2OCIIndexMediaType {
			return m2OperatorOCIIdentity{}, fmt.Errorf("index lacks a unique supported linux/amd64 image path")
		}
		currentDesc = index.Manifests[0]
		var err error
		current, err = read(currentDesc.Digest)
		if err != nil {
			return m2OperatorOCIIdentity{}, fmt.Errorf("read nested image index: %w", err)
		}
	}
	if selected == nil || selected.MediaType != m2OCIManifestMediaType {
		return m2OperatorOCIIdentity{}, fmt.Errorf("index lacks a supported linux/amd64 image manifest")
	}
	manifestBytes, err := read(selected.Digest)
	if err != nil {
		return m2OperatorOCIIdentity{}, fmt.Errorf("read selected manifest: %w", err)
	}
	if err := m2CheckOCIBlob(*selected, manifestBytes); err != nil {
		return m2OperatorOCIIdentity{}, fmt.Errorf("selected manifest: %w", err)
	}
	var manifest struct {
		SchemaVersion int               `json:"schemaVersion"`
		MediaType     string            `json:"mediaType"`
		Config        m2OCIDescriptor   `json:"config"`
		Layers        []m2OCIDescriptor `json:"layers"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil || manifest.SchemaVersion != 2 || manifest.MediaType != m2OCIManifestMediaType || manifest.Config.MediaType != m2OCIConfigMediaType || len(manifest.Layers) == 0 {
		return m2OperatorOCIIdentity{}, fmt.Errorf("unsupported or malformed linux/amd64 manifest: %v", err)
	}
	configBytes, err := read(manifest.Config.Digest)
	if err != nil {
		return m2OperatorOCIIdentity{}, fmt.Errorf("read image config: %w", err)
	}
	if err := m2CheckOCIBlob(manifest.Config, configBytes); err != nil {
		return m2OperatorOCIIdentity{}, fmt.Errorf("image config: %w", err)
	}
	var config struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil || config.OS != "linux" || config.Architecture != "amd64" {
		return m2OperatorOCIIdentity{}, fmt.Errorf("selected image config is not linux/amd64: %v", err)
	}
	for i, layer := range manifest.Layers {
		if layer.MediaType != m2OCILayerMediaType || !m2ValidSHA256Digest(layer.Digest) || layer.Size < 0 {
			return m2OperatorOCIIdentity{}, fmt.Errorf("unsupported layer descriptor %d", i)
		}
		if err := verifyLayer(layer); err != nil {
			return m2OperatorOCIIdentity{}, fmt.Errorf("verify layer %d: %w", i, err)
		}
	}
	return m2OperatorOCIIdentity{IndexID: indexID, ManifestID: selected.Digest, ConfigID: manifest.Config.Digest}, nil
}

func m2OperatorCanonicalRef(image string) (string, error) {
	if !strings.HasPrefix(image, "keaguard-operator:m2-") || len(image) != len("keaguard-operator:m2-")+12 {
		return "", fmt.Errorf("operator image is not a fingerprinted M2 reference")
	}
	for _, c := range image[len("keaguard-operator:m2-"):] {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return "", fmt.Errorf("operator fingerprint tag contains non-hex characters")
		}
	}
	return "docker.io/library/" + image, nil
}

func m2CheckOperatorReference(list, image, indexID string) error {
	ref, err := m2OperatorCanonicalRef(image)
	if err != nil || !m2ValidSHA256Digest(indexID) {
		return fmt.Errorf("invalid expected operator reference or index digest: %v", err)
	}
	found := 0
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != ref {
			continue
		}
		if len(fields) < 3 || fields[1] != m2OCIIndexMediaType || fields[2] != indexID {
			return fmt.Errorf("operator containerd reference has wrong descriptor")
		}
		found++
	}
	if found != 1 {
		return fmt.Errorf("expected exactly one exact operator containerd reference, found %d", found)
	}
	return nil
}

func m2ImmutableImageRefDigest(ref string) (string, bool) {
	if !strings.HasPrefix(ref, "docker.io/library/") || strings.ContainsAny(ref, " \t\r\n") {
		return "", false
	}
	name, digest, ok := strings.Cut(ref, "@")
	if !ok || name == "docker.io/library/" || strings.Contains(name, "@") || !m2ValidSHA256Digest(digest) {
		return "", false
	}
	return digest, true
}

func m2DisplayReferenceIndex(list, ref string) (string, error) {
	immutableDigest, immutable := m2ImmutableImageRefDigest(ref)
	shortRef := ""
	if !immutable {
		image := strings.TrimPrefix(ref, "docker.io/library/")
		canonical, err := m2OperatorCanonicalRef(image)
		if err != nil || canonical != ref {
			return "", fmt.Errorf("unrecognized operator display reference %q", ref)
		}
	} else {
		// CRI normalizes an imported repository digest to docker.io/library,
		// while Kind's containerd import may retain the unqualified name.
		// Accept that exact spelling only when it remains unique and its
		// descriptor matches the immutable digest; the OCI chain is hashed below.
		shortRef = strings.TrimPrefix(ref, "docker.io/library/")
	}
	var indexID string
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != ref && fields[0] != shortRef {
			continue
		}
		if len(fields) < 3 || fields[1] != m2OCIIndexMediaType || !m2ValidSHA256Digest(fields[2]) || indexID != "" {
			return "", fmt.Errorf("ambiguous or unsupported operator display descriptor")
		}
		indexID = fields[2]
	}
	if indexID == "" || immutable && indexID != immutableDigest {
		return "", fmt.Errorf("operator display reference target is absent or differs from its immutable digest")
	}
	return indexID, nil
}

func m2VerifyOperatorDisplayReference(ctx context.Context, dockerID, ref string, approved m2OperatorOCIIdentity) error {
	if !m2FullHexID(dockerID) || !m2ValidSHA256Digest(approved.ManifestID) || !m2ValidSHA256Digest(approved.ConfigID) {
		return fmt.Errorf("operator display verification lacks node or approved OCI identities")
	}
	if ref == approved.ConfigID {
		return fmt.Errorf("config digest alone does not prove the running display manifest and layers")
	}
	list, err := m2Command(ctx, "docker", "exec", dockerID, "ctr", "--namespace", "k8s.io", "images", "ls")
	if err != nil {
		return err
	}
	indexID, err := m2DisplayReferenceIndex(string(list), ref)
	if err != nil {
		return err
	}
	indexBytes, err := m2ReadNodeOCIBlob(ctx, dockerID, indexID)
	if err != nil {
		return err
	}
	if err := m2CheckOperatorDisplayOCI(indexBytes, indexID,
		func(digest string) ([]byte, error) { return m2ReadNodeOCIBlob(ctx, dockerID, digest) }, approved); err != nil {
		return err
	}
	current, err := m2Command(ctx, "docker", "exec", dockerID, "ctr", "--namespace", "k8s.io", "images", "ls")
	if err != nil {
		return err
	}
	currentID, err := m2DisplayReferenceIndex(string(current), ref)
	if err != nil || currentID != indexID {
		return fmt.Errorf("operator display reference changed during attestation: %v", err)
	}
	return nil
}

// m2CheckOperatorDisplayOCI binds a live display reference to the manifest and
// config already fully attested by m2VerifyOperatorNodeOCI. The manifest digest
// cryptographically binds its layer descriptors, so rereading every layer for
// each CRI/Kubernetes display spelling adds no identity proof. Index, nested
// index, manifest and config bytes are freshly read and hashed on every call;
// callers still re-read the reference listing after this check.
func m2CheckOperatorDisplayOCI(indexBytes []byte, indexID string, read func(string) ([]byte, error), approved m2OperatorOCIIdentity) error {
	if !m2ValidSHA256Digest(approved.ManifestID) || !m2ValidSHA256Digest(approved.ConfigID) {
		return fmt.Errorf("operator display verification lacks approved manifest/config identities")
	}
	identity, err := m2CheckOperatorOCI(indexBytes, indexID, read, func(m2OCIDescriptor) error { return nil })
	if err != nil {
		return err
	}
	if identity.ManifestID != approved.ManifestID || identity.ConfigID != approved.ConfigID {
		return fmt.Errorf("operator display reference selects different manifest/config content")
	}
	return nil
}

func m2ReadNodeOCIBlob(ctx context.Context, dockerID, digest string) ([]byte, error) {
	if !m2FullHexID(dockerID) || !m2ValidSHA256Digest(digest) {
		return nil, fmt.Errorf("invalid node or OCI blob identity")
	}
	return m2Command(ctx, "docker", "exec", dockerID, "ctr", "--namespace", "k8s.io", "content", "get", digest)
}

func m2NodeLayerPath(digest string) string {
	return "/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func m2CheckNodeLayerBatch(output string, descriptors []m2OCIDescriptor) error {
	if len(descriptors) == 0 {
		return fmt.Errorf("node layer batch is empty")
	}
	for _, desc := range descriptors {
		if desc.MediaType != m2OCILayerMediaType || !m2ValidSHA256Digest(desc.Digest) || desc.Size < 0 {
			return fmt.Errorf("invalid OCI layer descriptor in node batch")
		}
	}
	if !strings.HasSuffix(output, "\n") {
		return fmt.Errorf("node layer batch output is incomplete")
	}
	rows := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(rows) != 2*len(descriptors) {
		return fmt.Errorf("node layer batch returned %d rows, want %d", len(rows), 2*len(descriptors))
	}
	for i, desc := range descriptors {
		path := m2NodeLayerPath(desc.Digest)
		fields := strings.SplitN(rows[i], "|", 4)
		if len(fields) != 4 || fields[0] != "stat" || fields[1] != "regular file" || fields[2] != fmt.Sprint(desc.Size) || fields[3] != path {
			return fmt.Errorf("node layer %d type, size or path differs from its OCI descriptor", i)
		}
		fields = strings.SplitN(rows[len(descriptors)+i], "|", 3)
		if len(fields) != 3 || fields[0] != "hash" || fields[1] != strings.TrimPrefix(desc.Digest, "sha256:") || fields[2] != path {
			return fmt.Errorf("node layer %d bytes differ from its OCI descriptor", i)
		}
	}
	return nil
}

func m2RunNodeLayerBatch(ctx context.Context, dockerID string, descriptors []m2OCIDescriptor,
	command func(context.Context, string, ...string) ([]byte, error)) error {
	if ctx == nil || ctx.Err() != nil || !m2FullHexID(dockerID) || command == nil || len(descriptors) == 0 {
		return fmt.Errorf("node layer batch lacks a live context, exact node identity or descriptors")
	}
	paths := make([]string, 0, len(descriptors))
	for _, desc := range descriptors {
		if desc.MediaType != m2OCILayerMediaType || !m2ValidSHA256Digest(desc.Digest) || desc.Size < 0 {
			return fmt.Errorf("invalid OCI layer descriptor in node batch")
		}
		paths = append(paths, m2NodeLayerPath(desc.Digest))
	}
	const script = `for path do stat -c 'stat|%F|%s|%n' -- "$path" || exit; done
for path do sum=$(sha256sum -- "$path") || exit; printf 'hash|%s|%s\n' "${sum%% *}" "$path"; done`
	args := []string{"exec", dockerID, "/bin/sh", "-c", script, "--"}
	args = append(args, paths...)
	output, err := command(ctx, "docker", args...)
	if err != nil {
		return err
	}
	return m2CheckNodeLayerBatch(string(output), descriptors)
}

func m2VerifyNodeOCILayers(ctx context.Context, dockerID string, descriptors []m2OCIDescriptor) error {
	return m2RunNodeLayerBatch(ctx, dockerID, descriptors, m2Command)
}

func m2VerifyOperatorNodeOCI(ctx context.Context, dockerID, image, indexID string) (m2OperatorOCIIdentity, error) {
	if !m2FullHexID(dockerID) || !m2ValidSHA256Digest(indexID) {
		return m2OperatorOCIIdentity{}, fmt.Errorf("operator node verification requires full identities")
	}
	list, err := m2Command(ctx, "docker", "exec", dockerID, "ctr", "--namespace", "k8s.io", "images", "ls")
	if err != nil {
		return m2OperatorOCIIdentity{}, err
	}
	if err := m2CheckOperatorReference(string(list), image, indexID); err != nil {
		return m2OperatorOCIIdentity{}, err
	}
	indexBytes, err := m2ReadNodeOCIBlob(ctx, dockerID, indexID)
	if err != nil {
		return m2OperatorOCIIdentity{}, err
	}
	var layers []m2OCIDescriptor
	identity, err := m2CheckOperatorOCI(indexBytes, indexID,
		func(digest string) ([]byte, error) { return m2ReadNodeOCIBlob(ctx, dockerID, digest) },
		func(desc m2OCIDescriptor) error { layers = append(layers, desc); return nil })
	if err != nil {
		return m2OperatorOCIIdentity{}, err
	}
	if err := m2VerifyNodeOCILayers(ctx, dockerID, layers); err != nil {
		return m2OperatorOCIIdentity{}, err
	}
	if err := m2VerifyOperatorNodeOCIReference(ctx, dockerID, image, indexID, identity.ConfigID); err != nil {
		return m2OperatorOCIIdentity{}, err
	}
	return identity, nil
}

func m2VerifyOperatorNodeOCIReference(ctx context.Context, dockerID, image, indexID, configID string) error {
	if !m2FullHexID(dockerID) || !m2ValidSHA256Digest(indexID) || !m2ValidSHA256Digest(configID) {
		return fmt.Errorf("operator reference verification lacks exact node/index/config identities")
	}
	list, err := m2Command(ctx, "docker", "exec", dockerID, "ctr", "--namespace", "k8s.io", "images", "ls")
	if err != nil {
		return err
	}
	if err := m2CheckOperatorReference(string(list), image, indexID); err != nil {
		return err
	}
	out, err := m2Command(ctx, "docker", "exec", dockerID, "crictl", "inspecti", "-o", "json", image)
	if err != nil {
		return err
	}
	var record struct {
		Status struct {
			ID       string   `json:"id"`
			RepoTags []string `json:"repoTags"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &record); err != nil {
		return err
	}
	ref, _ := m2OperatorCanonicalRef(image)
	if record.Status.ID != configID || !containsString(record.Status.RepoTags, ref) {
		return fmt.Errorf("CRI operator image config/reference differs from verified OCI chain")
	}
	return nil
}

func m2CheckManagerIncarnation(beforeUID, beforeContainerID, beforeImageID, afterUID, afterContainerID, afterImageID string) error {
	_, immutable := m2ImmutableImageRefDigest(beforeImageID)
	if beforeUID == "" || !strings.HasPrefix(beforeContainerID, "containerd://") || !m2FullHexID(strings.TrimPrefix(beforeContainerID, "containerd://")) || !m2ValidSHA256Digest(beforeImageID) && !immutable || beforeUID != afterUID || beforeContainerID != afterContainerID || beforeImageID != afterImageID {
		return fmt.Errorf("manager Pod/container incarnation changed during image verification")
	}
	return nil
}
