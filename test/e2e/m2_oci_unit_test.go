package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

type m2OCITestFixture struct {
	index, indexID, manifestID, configID string
	blobs                                map[string][]byte
}

func m2TestDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func m2NewOCITestFixture() m2OCITestFixture {
	layer := []byte("exact compressed layer bytes")
	layerID := m2TestDigest(layer)
	config := []byte(`{"os":"linux","architecture":"amd64"}`)
	configID := m2TestDigest(config)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}]}`, configID, len(config), layerID, len(layer)))
	manifestID := m2TestDigest(manifest)
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d,"platform":{"os":"linux","architecture":"amd64"}}]}`, manifestID, len(manifest)))
	indexID := m2TestDigest(index)
	return m2OCITestFixture{index: string(index), indexID: indexID, manifestID: manifestID, configID: configID,
		blobs: map[string][]byte{manifestID: manifest, configID: config, layerID: layer}}
}

func TestUnitM2OperatorOCIExactIndexManifestConfigAndLayers(t *testing.T) {
	f := m2NewOCITestFixture()
	read := func(digest string) ([]byte, error) {
		blob, ok := f.blobs[digest]
		if !ok {
			return nil, fmt.Errorf("missing blob %s", digest)
		}
		return blob, nil
	}
	verifyLayer := func(desc m2OCIDescriptor) error {
		blob, err := read(desc.Digest)
		if err != nil {
			return err
		}
		return m2CheckOCIBlob(desc, blob)
	}
	identity, err := m2CheckOperatorOCI([]byte(f.index), f.indexID, read, verifyLayer)
	if err != nil {
		t.Fatalf("valid OCI chain rejected: %v", err)
	}
	if identity.IndexID != f.indexID || identity.ManifestID != f.manifestID || identity.ConfigID != f.configID || identity.IndexID == identity.ConfigID {
		t.Fatalf("wrong OCI object identities: %+v", identity)
	}
	for name, mutate := range map[string]func(*m2OCITestFixture){
		"stale build IID":       func(f *m2OCITestFixture) { f.indexID = "sha256:" + strings.Repeat("a", 64) },
		"tampered index":        func(f *m2OCITestFixture) { f.index += " " },
		"wrong manifest digest": func(f *m2OCITestFixture) { f.blobs[f.manifestID] = []byte(`{}`) },
		"wrong config digest":   func(f *m2OCITestFixture) { f.blobs[f.configID] = []byte(`{}`) },
		"wrong platform": func(f *m2OCITestFixture) {
			f.index = strings.Replace(f.index, `"amd64"`, `"arm64"`, 1)
			f.indexID = m2TestDigest([]byte(f.index))
		},
		"unsupported descriptor": func(f *m2OCITestFixture) {
			f.index = strings.Replace(f.index, `application/vnd.oci.image.manifest.v1+json`, `application/octet-stream`, 1)
			f.indexID = m2TestDigest([]byte(f.index))
		},
		"unavailable content": func(f *m2OCITestFixture) { delete(f.blobs, f.manifestID) },
		"tampered layer": func(f *m2OCITestFixture) {
			for digest, blob := range f.blobs {
				if string(blob) == "exact compressed layer bytes" {
					f.blobs[digest] = []byte("wrong")
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := m2NewOCITestFixture()
			mutate(&bad)
			readBad := func(digest string) ([]byte, error) {
				blob, ok := bad.blobs[digest]
				if !ok {
					return nil, fmt.Errorf("missing blob")
				}
				return blob, nil
			}
			_, err := m2CheckOperatorOCI([]byte(bad.index), bad.indexID, readBad, func(desc m2OCIDescriptor) error {
				blob, err := readBad(desc.Digest)
				if err != nil {
					return err
				}
				return m2CheckOCIBlob(desc, blob)
			})
			if err == nil {
				t.Fatal("accepted invalid OCI chain")
			}
		})
	}
}

func TestUnitM2OperatorOCIExactReferenceAndPodIncarnation(t *testing.T) {
	f := m2NewOCITestFixture()
	ref := "docker.io/library/keaguard-operator:m2-123456789abc"
	row := "REF TYPE DIGEST SIZE PLATFORMS LABELS\n" + ref + " application/vnd.oci.image.index.v1+json " + f.indexID + " 23MiB linux/amd64 -\n"
	if err := m2CheckOperatorReference(row, "keaguard-operator:m2-123456789abc", f.indexID); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{strings.Replace(row, ref, "docker.io/library/foreign:m2-123456789abc", 1), strings.Replace(row, f.indexID, "sha256:"+strings.Repeat("b", 64), 1)} {
		if err := m2CheckOperatorReference(changed, "keaguard-operator:m2-123456789abc", f.indexID); err == nil {
			t.Fatal("accepted wrong reference target")
		}
	}
	if err := m2CheckManagerIncarnation("pod-uid", "containerd://"+strings.Repeat("c", 64), f.configID, "pod-uid", "containerd://"+strings.Repeat("c", 64), f.configID); err != nil {
		t.Fatal(err)
	}
	for _, observed := range [][3]string{{"new-pod", "containerd://" + strings.Repeat("c", 64), f.configID}, {"pod-uid", "containerd://" + strings.Repeat("d", 64), f.configID}, {"pod-uid", "containerd://" + strings.Repeat("c", 64), "sha256:" + strings.Repeat("e", 64)}} {
		if err := m2CheckManagerIncarnation("pod-uid", "containerd://"+strings.Repeat("c", 64), f.configID, observed[0], observed[1], observed[2]); err == nil {
			t.Fatal("accepted replaced Pod/container incarnation")
		}
	}
}

func TestUnitM2OperatorOCIResolvesVerifiedImportWrapper(t *testing.T) {
	f := m2NewOCITestFixture()
	wrapper := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":%q,"size":%d}]}`, f.indexID, len(f.index)))
	wrapperID := m2TestDigest(wrapper)
	f.blobs[f.indexID] = []byte(f.index)
	read := func(digest string) ([]byte, error) {
		blob, ok := f.blobs[digest]
		if !ok {
			return nil, fmt.Errorf("missing OCI blob %s", digest)
		}
		return blob, nil
	}
	identity, err := m2CheckOperatorOCI(wrapper, wrapperID, read, func(desc m2OCIDescriptor) error {
		blob, err := read(desc.Digest)
		if err != nil {
			return err
		}
		return m2CheckOCIBlob(desc, blob)
	})
	if err != nil || identity.ManifestID != f.manifestID || identity.ConfigID != f.configID {
		t.Fatalf("verified import wrapper did not resolve to the approved manifest/config: identity=%+v err=%v", identity, err)
	}
}

func TestUnitM2NodeLayerBatchPreservesEveryContentCheck(t *testing.T) {
	first := []byte("first exact layer")
	second := []byte("second exact layer")
	descriptors := []m2OCIDescriptor{
		{MediaType: m2OCILayerMediaType, Digest: m2TestDigest(first), Size: int64(len(first))},
		{MediaType: m2OCILayerMediaType, Digest: m2TestDigest(second), Size: int64(len(second))},
	}
	output := m2NodeLayerBatchFixture(descriptors)
	if err := m2CheckNodeLayerBatch(output, descriptors); err != nil {
		t.Fatalf("valid exact layer batch rejected: %v", err)
	}
	for name, mutate := range map[string]func(string) string{
		"wrong type": func(s string) string { return strings.Replace(s, "regular file", "directory", 1) },
		"wrong size": func(s string) string { return strings.Replace(s, "|17|", "|18|", 1) },
		"wrong hash": func(s string) string {
			return strings.Replace(s, descriptors[0].Digest[7:], strings.Repeat("a", 64), 1)
		},
		"wrong path": func(s string) string {
			return strings.Replace(s, strings.TrimPrefix(descriptors[0].Digest, "sha256:"), strings.Repeat("b", 64), 1)
		},
		"missing row": func(s string) string { return strings.TrimSuffix(s, "\n") },
		"extra row":   func(s string) string { return s + "unexpected\n" },
	} {
		t.Run(name, func(t *testing.T) {
			if err := m2CheckNodeLayerBatch(mutate(output), descriptors); err == nil {
				t.Fatal("accepted malformed or mismatched node layer evidence")
			}
		})
	}
}

func TestUnitM2NodeLayerBatchUsesOneBoundedCommandAndLiteralPaths(t *testing.T) {
	blob := []byte("exact layer")
	descriptor := m2OCIDescriptor{MediaType: m2OCILayerMediaType, Digest: m2TestDigest(blob), Size: int64(len(blob))}
	calls := 0
	err := m2RunNodeLayerBatch(context.Background(), strings.Repeat("b", 64), []m2OCIDescriptor{descriptor}, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if name != "docker" || len(args) < 6 || args[0] != "exec" || args[1] != strings.Repeat("b", 64) || args[2] != "/bin/sh" || args[3] != "-c" {
			return nil, fmt.Errorf("unexpected bounded batch command: %s %q", name, args)
		}
		if args[len(args)-1] != m2NodeLayerPath(descriptor.Digest) {
			return nil, fmt.Errorf("layer path was not passed as a literal argument")
		}
		return []byte(m2NodeLayerBatchFixture([]m2OCIDescriptor{descriptor})), nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("expected one bounded command and valid verification: calls=%d err=%v", calls, err)
	}
}

func m2NodeLayerBatchFixture(descriptors []m2OCIDescriptor) string {
	var rows []string
	for _, desc := range descriptors {
		rows = append(rows, "stat|regular file|"+fmt.Sprint(desc.Size)+"|"+m2NodeLayerPath(desc.Digest))
	}
	for _, desc := range descriptors {
		rows = append(rows, "hash|"+strings.TrimPrefix(desc.Digest, "sha256:")+"|"+m2NodeLayerPath(desc.Digest))
	}
	return strings.Join(rows, "\n") + "\n"
}

func TestUnitM2OperatorDisplayDoesNotTreatConfigDigestAsCompleteContent(t *testing.T) {
	f := m2NewOCITestFixture()
	err := m2VerifyOperatorDisplayReference(context.Background(), strings.Repeat("d", 64), f.configID,
		m2OperatorOCIIdentity{IndexID: f.indexID, ManifestID: f.manifestID, ConfigID: f.configID})
	if err == nil || !strings.Contains(err.Error(), "config digest alone") {
		t.Fatalf("config-only display identity bypassed the manifest/layer proof: %v", err)
	}
}

func TestUnitM2OperatorDisplayReferenceContainerdNormalization(t *testing.T) {
	f := m2NewOCITestFixture()
	short := "import-2026-10-18@" + f.indexID
	full := "docker.io/library/" + short
	row := "REF TYPE DIGEST SIZE PLATFORMS LABELS\n" + short + " " + m2OCIIndexMediaType + " " + f.indexID + " 1MiB linux/amd64 -\n"
	if got, err := m2DisplayReferenceIndex(row, full); err != nil || got != f.indexID {
		t.Fatalf("CRI canonical repository digest did not resolve exact containerd short name: got=%q err=%v", got, err)
	}
	for name, listing := range map[string]string{
		"wrong digest": strings.Replace(row, f.indexID, "sha256:"+strings.Repeat("a", 64), 1),
		"wrong name":   strings.Replace(row, short, "foreign@"+f.indexID, 1),
		"duplicate":    row + short + " " + m2OCIIndexMediaType + " " + f.indexID + " 1MiB linux/amd64 -\n",
		"conflict":     row + full + " " + m2OCIIndexMediaType + " " + f.indexID + " 1MiB linux/amd64 -\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := m2DisplayReferenceIndex(listing, full); err == nil {
				t.Fatalf("accepted ambiguous or mismatched display target %q", got)
			}
		})
	}
}

func TestUnitM2DisplayReferenceUsesFreshIndexManifestAndConfigProof(t *testing.T) {
	f := m2NewOCITestFixture()
	wrapper := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":%q,"size":%d}]}`, f.indexID, len(f.index)))
	wrapperID := m2TestDigest(wrapper)
	f.blobs[f.indexID] = []byte(f.index)
	approved := m2OperatorOCIIdentity{IndexID: f.indexID, ManifestID: f.manifestID, ConfigID: f.configID}

	reads := map[string]int{}
	read := func(digest string) ([]byte, error) {
		reads[digest]++
		blob, ok := f.blobs[digest]
		if !ok {
			return nil, fmt.Errorf("missing blob %s", digest)
		}
		return blob, nil
	}
	if err := m2CheckOperatorDisplayOCI(wrapper, wrapperID, read, approved); err != nil {
		t.Fatalf("exact nested display reference rejected: %v", err)
	}
	if reads[wrapperID] != 0 || reads[f.indexID] != 1 || reads[f.manifestID] != 1 || reads[f.configID] != 1 {
		t.Fatalf("display proof did not read current index/manifest/config exactly once: %v", reads)
	}
	for digest := range f.blobs {
		if digest != f.indexID && digest != f.manifestID && digest != f.configID {
			if reads[digest] != 0 {
				t.Fatalf("display proof redundantly read already-manifest-bound layer %s", digest)
			}
		}
	}

	for name, tc := range map[string]struct {
		wrapper []byte
		id      string
		read    func(string) ([]byte, error)
		trusted m2OperatorOCIIdentity
	}{
		"wrong wrapper digest": {wrapper: wrapper, id: "sha256:" + strings.Repeat("a", 64), read: read, trusted: approved},
		"wrong manifest":       {wrapper: wrapper, id: wrapperID, read: read, trusted: m2OperatorOCIIdentity{ManifestID: "sha256:" + strings.Repeat("b", 64), ConfigID: f.configID}},
		"wrong config":         {wrapper: wrapper, id: wrapperID, read: read, trusted: m2OperatorOCIIdentity{ManifestID: f.manifestID, ConfigID: "sha256:" + strings.Repeat("c", 64)}},
		"tampered nested index": {wrapper: wrapper, id: wrapperID, read: func(d string) ([]byte, error) {
			if d == f.indexID {
				return []byte(f.index + " "), nil
			}
			return read(d)
		}, trusted: approved},
		"unavailable config": {wrapper: wrapper, id: wrapperID, read: func(d string) ([]byte, error) {
			if d == f.configID {
				return nil, fmt.Errorf("unavailable")
			}
			return read(d)
		}, trusted: approved},
	} {
		t.Run(name, func(t *testing.T) {
			if err := m2CheckOperatorDisplayOCI(tc.wrapper, tc.id, tc.read, tc.trusted); err == nil {
				t.Fatal("accepted changed or unverifiable display content")
			}
		})
	}
}
