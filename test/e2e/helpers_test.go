package e2e

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const labCluster = "keaguard-m1-disposable"
const runtimeNamespace = "keaguard-m1-runtime"
const outsideNamespace = "keaguard-m1-outside"
const fixtureLabel = "keaguard.example/e2e-owner"
const managerName = "keaguard-controller-manager"
const nodeImage = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
const approvedKubeconfig = "/tmp/keaguard-m1-t13-lenovo/keaguard-kind.kubeconfig"

// Every Kind and kubectl operation uses the explicitly selected file.
var labKubeconfig = os.Getenv("KUBECONFIG")

func selectionEnv() map[string]string {
	m := map[string]string{}
	for _, k := range []string{"KEAGUARD_E2E", "KEAGUARD_KIND_CLUSTER", "KEAGUARD_KIND_CONTEXT", "KEAGUARD_E2E_DISPOSABLE", "KUBECONFIG", "IMG"} {
		m[k] = os.Getenv(k)
	}
	return m
}
func suiteOptedIn() bool { return os.Getenv("KEAGUARD_E2E") == "1" }
func guardSelection(env map[string]string, next func() error) error {
	if env["KEAGUARD_E2E"] != "1" || env["KEAGUARD_KIND_CLUSTER"] != labCluster || env["KEAGUARD_KIND_CONTEXT"] != "kind-"+labCluster || env["KEAGUARD_E2E_DISPOSABLE"] != labCluster {
		return fmt.Errorf("explicit disposable Kind selection required")
	}
	if env["KUBECONFIG"] != approvedKubeconfig {
		return fmt.Errorf("KUBECONFIG must select the single approved private file")
	}
	img := env["IMG"]
	last := img[strings.LastIndex(img, "/")+1:]
	if strings.TrimSpace(img) != img || strings.ContainsAny(img, "\n\r\t ") || (!strings.Contains(last, ":") && !strings.Contains(img, "@sha256:")) || strings.HasSuffix(img, ":latest") {
		return fmt.Errorf("explicit non-latest IMG required")
	}
	return next()
}
func checkFixtureNamespace(ns *corev1.Namespace) error {
	if (ns.Name != runtimeNamespace && ns.Name != outsideNamespace) || ns.Labels[fixtureLabel] != labCluster || ns.DeletionTimestamp != nil {
		return fmt.Errorf("namespace %s is not an active test-owned fixture", ns.Name)
	}
	return nil
}
func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %v failed: %w: %s", name, args, err, out)
	}
	return out, nil
}

// validateLab performs only local config/Kind/Docker inspection before client creation.
func validateLab(ctx context.Context) (*rest.Config, error) {
	var cfg *rest.Config
	err := guardSelection(selectionEnv(), func() error {
		if err := checkPrivateKubeconfig(labKubeconfig); err != nil {
			return err
		}

		raw, err := clientcmd.LoadFromFile(labKubeconfig)
		if err != nil {
			return err
		}
		name := "kind-" + labCluster
		c := raw.Contexts[name]
		if raw.CurrentContext != name || c == nil || c.Cluster != name || c.AuthInfo != name || len(raw.Clusters) != 1 || len(raw.Contexts) != 1 || len(raw.AuthInfos) != 1 {
			return fmt.Errorf("kubeconfig context/cluster selection mismatch")
		}
		cluster := raw.Clusters[name]
		if cluster == nil {
			return fmt.Errorf("missing cluster")
		}
		u, err := url.Parse(cluster.Server)
		if err != nil || u.Scheme != "https" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.Port() == "" {
			return fmt.Errorf("expected selected loopback Kind API server")
		}
		out, err := command(ctx, "kind", "get", "nodes", "--name", labCluster)
		if err != nil {
			return err
		}
		nodes := strings.Fields(string(out))
		if len(nodes) == 0 {
			return fmt.Errorf("selected cluster has no nodes")
		}
		for _, node := range nodes {
			out, err = command(ctx, "docker", "inspect", "--format", `{{index .Config.Labels "io.x-k8s.kind.cluster"}}|{{.Config.Image}}`, node)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(out)) != labCluster+"|"+nodeImage {
				return fmt.Errorf("Kind membership/node image mismatch")
			}
		}
		// Match the API endpoint against Kind's own selected-cluster configuration.
		out, err = command(ctx, "kind", "get", "kubeconfig", "--name", labCluster)
		if err != nil {
			return err
		}
		kindConfig, err := clientcmd.Load(out)
		if err != nil {
			return err
		}
		kc := kindConfig.Clusters[name]
		if kc == nil || kc.Server != cluster.Server || string(kc.CertificateAuthorityData) != string(cluster.CertificateAuthorityData) {
			return fmt.Errorf("selected server/CA does not match Kind cluster")
		}
		cfg, err = clientcmd.NewNonInteractiveClientConfig(*raw, name, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
		if err != nil {
			return err
		}
		cfg.Timeout = 10 * time.Second
		return nil
	})
	return cfg, err
}
func ensureFixtureNamespaces(ctx context.Context, c client.Client) error {
	// Inspect both before modifying either; collisions never trigger cleanup.
	missing := []string{}
	for _, name := range []string{runtimeNamespace, outsideNamespace} {
		var ns corev1.Namespace
		err := c.Get(ctx, client.ObjectKey{Name: name}, &ns)
		if apierrors.IsNotFound(err) {
			missing = append(missing, name)
		} else if err != nil {
			return err
		} else if err = checkFixtureNamespace(&ns); err != nil {
			return err
		}
	}
	for _, name := range missing {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{fixtureLabel: labCluster}}}); err != nil {
			return err
		}
	}
	return nil
}
func kubectl(ctx context.Context, args ...string) ([]byte, error) {
	return command(ctx, "kubectl", append([]string{"--kubeconfig", labKubeconfig, "--context", "kind-" + labCluster}, args...)...)
}
func kustomizeImageTransformer(img string) (string, error) {
	name := img
	digest := ""
	if at := strings.IndexByte(name, '@'); at >= 0 {
		digest = name[at+1:]
		name = name[:at]
	}
	tag := ""
	if colon := strings.LastIndexByte(name, ':'); colon > strings.LastIndexByte(name, '/') {
		tag = name[colon+1:]
		name = name[:colon]
	}
	if name == "" || (tag == "" && digest == "") {
		return "", fmt.Errorf("selected image %q must have a tag or digest", img)
	}
	if digest != "" && !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("selected image %q has an unsupported digest", img)
	}
	fields := []string{"- name: keaguard-operator", "  newName: " + strconv.Quote(name)}
	if tag != "" {
		fields = append(fields, "  newTag: "+strconv.Quote(tag))
	}
	if digest != "" {
		fields = append(fields, "  digest: "+strconv.Quote(digest))
	}
	return strings.Join(fields, "\n"), nil
}
func renderRuntime(ctx context.Context) ([]byte, error) {
	dir, err := os.MkdirTemp("", "keaguard-t13-overlay-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	// Copy the reviewed tree below the overlay; never disable Kustomize load restrictions.
	err = filepath.WalkDir("../../config", func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel("../../config", p)
		if e != nil {
			return e
		}
		dst := filepath.Join(dir, "config", rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0700)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("unexpected config entry %s", p)
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		return os.WriteFile(dst, b, 0600)
	})
	if err != nil {
		return nil, err
	}
	replacement, err := os.ReadFile("../../config/default/namespace_replacement.yaml")
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(dir, "namespace_replacement.yaml"), replacement, 0600); err != nil {
		return nil, err
	}
	image, err := kustomizeImageTransformer(os.Getenv("IMG"))
	if err != nil {
		return nil, err
	}
	body := fmt.Sprintf("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: %s\nresources:\n- config/default\nreplacements:\n- path: namespace_replacement.yaml\nimages:\n%s\n", runtimeNamespace, image)
	if err = os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(body), 0600); err != nil {
		return nil, err
	}
	return command(ctx, "kubectl", "kustomize", dir)
}
func applyBundle(ctx context.Context, b []byte) error {
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", labKubeconfig, "--context", "kind-"+labCluster, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(b))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply failed: %w %s", err, out)
	}
	return nil
}

// New config copies only server and trust settings; no admin authentication/transport survives.
func runtimeConfig(admin *rest.Config, token string) *rest.Config {
	return &rest.Config{Host: admin.Host, TLSClientConfig: rest.TLSClientConfig{CAData: append([]byte(nil), admin.CAData...), CAFile: admin.CAFile, ServerName: admin.ServerName}, BearerToken: token, Timeout: 10 * time.Second}
}
func managerLogs(ctx context.Context) string {
	b, err := kubectl(ctx, "logs", "-n", runtimeNamespace, "deployment/"+managerName, "--tail=100")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func checkPrivateKubeconfig(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("kubeconfig must be a private regular file (0600)")
	}
	return nil
}
