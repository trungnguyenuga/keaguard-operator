package e2e

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
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

type labProfile struct {
	milestone, cluster, runtimeNamespace, outsideNamespace string
	fixtureLabel, nodeImage, kubeconfig, dockerConfig      string
	nodes                                                  []string
}

var m1LabProfile = labProfile{
	cluster: "keaguard-m1-disposable", runtimeNamespace: "keaguard-m1-runtime", outsideNamespace: "keaguard-m1-outside",
	fixtureLabel: "keaguard.example/e2e-owner", nodeImage: "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
	kubeconfig: "/tmp/keaguard-m1-t13-lenovo/keaguard-kind.kubeconfig",
}
var m2LabProfile = labProfile{
	milestone: "m2", cluster: "keaguard-m2-disposable", runtimeNamespace: "keaguard-m2-runtime", outsideNamespace: "keaguard-m2-outside",
	fixtureLabel: "keaguard.example/e2e-owner", nodeImage: "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
	kubeconfig: "/tmp/keaguard-m2-acceptance/keaguard-kind.kubeconfig", dockerConfig: "/tmp/keaguard-m2-acceptance/docker-config",
	nodes: []string{"keaguard-m2-disposable-control-plane", "keaguard-m2-disposable-worker", "keaguard-m2-disposable-worker2"},
}

func profileForMilestone(milestone string) (labProfile, error) {
	switch milestone {
	case "":
		return m1LabProfile, nil
	case "m2":
		return m2LabProfile, nil
	default:
		return labProfile{}, fmt.Errorf("unsupported KEAGUARD_E2E_MILESTONE %q", milestone)
	}
}

// The profile is frozen before Ginkgo registers any nodes. M1 remains the
// default, while an unknown profile is retained as an error for suite guards.
var selectedProfile, selectedProfileErr = profileForMilestone(os.Getenv("KEAGUARD_E2E_MILESTONE"))

var labCluster = selectedProfile.cluster
var runtimeNamespace = selectedProfile.runtimeNamespace
var outsideNamespace = selectedProfile.outsideNamespace
var fixtureLabel = selectedProfile.fixtureLabel

const managerName = "keaguard-controller-manager"

var nodeImage = selectedProfile.nodeImage
var approvedKubeconfig = selectedProfile.kubeconfig

// Every Kind and kubectl operation uses the explicitly selected file.
var labKubeconfig = os.Getenv("KUBECONFIG")

func selectionEnv() map[string]string {
	m := map[string]string{}
	for _, k := range []string{"KEAGUARD_E2E_MILESTONE", "KEAGUARD_E2E", "KEAGUARD_KIND_CLUSTER", "KEAGUARD_KIND_CONTEXT", "KEAGUARD_E2E_DISPOSABLE", "KUBECONFIG", "DOCKER_CONFIG", "IMG", "KEAGUARD_M2_NAMESPACE_SETUP", "KEAGUARD_M2_CLUSTER_REPLACEMENT", "KEAGUARD_M2_REPLACEMENT_GATE_B", "KEAGUARD_M2_REPLACEMENT_STAGE"} {
		m[k] = os.Getenv(k)
	}
	return m
}
func suiteOptedIn() bool { return os.Getenv("KEAGUARD_E2E") == "1" }
func guardSelection(env map[string]string, next func() error) error {
	profile, err := profileForMilestone(env["KEAGUARD_E2E_MILESTONE"])
	if err != nil {
		return err
	}
	if env["KEAGUARD_E2E"] != "1" || env["KEAGUARD_KIND_CLUSTER"] != profile.cluster || env["KEAGUARD_KIND_CONTEXT"] != "kind-"+profile.cluster || env["KEAGUARD_E2E_DISPOSABLE"] != profile.cluster {
		return fmt.Errorf("explicit disposable Kind selection required")
	}
	if env["KUBECONFIG"] != profile.kubeconfig {
		return fmt.Errorf("KUBECONFIG must select the single approved private file")
	}
	if profile.milestone == "m2" && env["DOCKER_CONFIG"] != profile.dockerConfig {
		return fmt.Errorf("DOCKER_CONFIG must select the empty task-local M2 directory")
	}
	img := env["IMG"]
	last := img[strings.LastIndex(img, "/")+1:]
	if strings.TrimSpace(img) != img || strings.ContainsAny(img, "\n\r\t ") || (!strings.Contains(last, ":") && !strings.Contains(img, "@sha256:")) || strings.HasSuffix(img, ":latest") {
		return fmt.Errorf("explicit non-latest IMG required")
	}
	if profile.milestone == "m2" && img == "keaguard-operator:m2-test" {
		return fmt.Errorf("M2 acceptance requires an input-fingerprinted operator image, not the test tag")
	}
	return next()
}

func selectedProfileMatches(profile labProfile) bool {
	return selectedProfileErr == nil && profile.milestone == selectedProfile.milestone && profile.cluster == selectedProfile.cluster &&
		profile.runtimeNamespace == selectedProfile.runtimeNamespace && profile.outsideNamespace == selectedProfile.outsideNamespace &&
		profile.fixtureLabel == selectedProfile.fixtureLabel && profile.nodeImage == selectedProfile.nodeImage &&
		profile.kubeconfig == selectedProfile.kubeconfig && profile.dockerConfig == selectedProfile.dockerConfig &&
		reflect.DeepEqual(profile.nodes, selectedProfile.nodes)
}

func checkM2Directory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("M2 private directory %s must be a non-symlink 0700 directory", path)
	}
	return nil
}

func checkM2PrivateInputs(taskDir, dockerConfig, kubeconfig string) error {
	if taskDir != m2LabProfile.kubeconfig[:strings.LastIndex(m2LabProfile.kubeconfig, "/")] || dockerConfig != m2LabProfile.dockerConfig || kubeconfig != m2LabProfile.kubeconfig {
		return fmt.Errorf("M2 private inputs must use the fixed native task paths")
	}
	if taskDir != filepath.Dir(dockerConfig) || taskDir != filepath.Dir(kubeconfig) {
		return fmt.Errorf("M2 private inputs must share the fixed task directory")
	}
	if err := checkM2Directories(taskDir, dockerConfig); err != nil {
		return err
	}
	info, err := os.Lstat(kubeconfig)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("M2 kubeconfig must be a non-symlink regular 0600 file")
	}
	return nil
}

func checkM2Directories(taskDir, dockerConfig string) error {
	if taskDir != filepath.Dir(dockerConfig) {
		return fmt.Errorf("M2 Docker config must be inside the fixed task directory")
	}
	if err := checkM2Directory(taskDir); err != nil {
		return err
	}
	if err := checkM2Directory(dockerConfig); err != nil {
		return err
	}
	entries, err := os.ReadDir(dockerConfig)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("M2 Docker config directory must be empty")
	}
	return nil
}

func validNodeSet(profile labProfile, nodes []string) bool {
	if len(profile.nodes) == 0 {
		return len(nodes) != 0
	}
	if len(nodes) != len(profile.nodes) {
		return false
	}
	want := make(map[string]struct{}, len(profile.nodes))
	for _, node := range profile.nodes {
		want[node] = struct{}{}
	}
	for _, node := range nodes {
		if _, ok := want[node]; !ok {
			return false
		}
		delete(want, node)
	}
	return len(want) == 0
}
func checkFixtureNamespace(ns *corev1.Namespace) error {
	return checkFixtureNamespaceForProfile(selectedProfile, ns)
}

func checkFixtureNamespaceForProfile(profile labProfile, ns *corev1.Namespace) error {
	if ns == nil {
		return fmt.Errorf("namespace observation is nil")
	}
	if (ns.Name != profile.runtimeNamespace && ns.Name != profile.outsideNamespace) || ns.Labels[profile.fixtureLabel] != profile.cluster || ns.DeletionTimestamp != nil {
		return fmt.Errorf("namespace %s is not an active test-owned fixture", ns.Name)
	}
	if profile.milestone == "m2" {
		return checkM2LabPolicy(ns)
	}
	return nil
}

func m2ExpectedPolicy(namespace string) map[string]string {
	enforce := "privileged"
	if namespace == m2LabProfile.outsideNamespace {
		enforce = "restricted"
	}
	return map[string]string{"pod-security.kubernetes.io/enforce": enforce, "pod-security.kubernetes.io/enforce-version": "v1.37"}
}

func checkM2LabPolicy(ns *corev1.Namespace) error {
	if ns == nil || (ns.Name != m2LabProfile.runtimeNamespace && ns.Name != m2LabProfile.outsideNamespace) || ns.Labels[m2LabProfile.fixtureLabel] != m2LabProfile.cluster {
		return fmt.Errorf("namespace is not an owned M2 fixture")
	}
	want := m2ExpectedPolicy(ns.Name)
	seen := 0
	for key, value := range ns.Labels {
		if !strings.HasPrefix(key, "pod-security.kubernetes.io/") {
			continue
		}
		seen++
		if expected, ok := want[key]; !ok || expected != value {
			return fmt.Errorf("unexpected M2 Pod Security label %s=%q", key, value)
		}
	}
	if seen != len(want) {
		return fmt.Errorf("M2 namespace %s must have exactly the reviewed enforce labels", ns.Name)
	}
	return nil
}

func kindCreateArgs(profile labProfile) []string {
	args := []string{"create", "cluster", "--name", profile.cluster, "--image", profile.nodeImage, "--kubeconfig", profile.kubeconfig, "--wait", "120s", "--retain"}
	if profile.milestone == "m2" {
		args = append(args, "--config", "testdata/m2-kind.yaml")
	}
	return args
}
func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	if selectedProfile.milestone == "m2" {
		if name == "kind" && len(args) >= 2 && ((args[0] == "create" && args[1] == "cluster") || (args[0] == "delete" && args[1] == "cluster" && slices.Contains(args, m2LabProfile.cluster))) || m2ManagerRolloutWait(name, args) {
			return m2LifecycleCommand(ctx, name, args...)
		}
		return m2Command(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %v failed: %w: %s", name, args, err, out)
	}
	return out, nil
}

func m2ManagerRolloutWait(name string, args []string) bool {
	if name != "kubectl" || len(args) != 10 {
		return false
	}
	return args[0] == "--kubeconfig" && args[1] == m2LabProfile.kubeconfig &&
		args[2] == "--context" && args[3] == "kind-"+m2LabProfile.cluster &&
		args[4] == "rollout" && args[5] == "status" && args[6] == "deployment/"+managerName &&
		args[7] == "-n" && args[8] == m2LabProfile.runtimeNamespace &&
		(args[9] == "--timeout=120s" || args[9] == "--timeout=110s")
}

// validateLab performs only local config/Kind/Docker inspection before client creation.
func validateLab(ctx context.Context) (*rest.Config, error) {
	var cfg *rest.Config
	env := selectionEnv()
	requestedProfile, err := profileForMilestone(env["KEAGUARD_E2E_MILESTONE"])
	if err != nil {
		return nil, err
	}
	if !selectedProfileMatches(requestedProfile) {
		return nil, fmt.Errorf("runtime selection differs from the immutable process profile")
	}
	err = guardSelection(env, func() error {
		profile := selectedProfile
		if err := checkPrivateKubeconfig(labKubeconfig); err != nil {
			return err
		}
		if profile.milestone == "m2" {
			if err := checkM2PrivateInputs(filepath.Dir(profile.kubeconfig), profile.dockerConfig, labKubeconfig); err != nil {
				return err
			}
			if err := m2CheckNoPendingRecovery(filepath.Dir(profile.kubeconfig)); err != nil {
				return err
			}
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
		if !validNodeSet(profile, nodes) {
			return fmt.Errorf("selected cluster node set does not match the fixed %s profile", profile.milestone)
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
	if selectedProfile.milestone == "m2" {
		out, err := m2CommandWithInput(ctx, b, "kubectl", "--kubeconfig", labKubeconfig, "--context", "kind-"+labCluster, "apply", "-f", "-")
		if err != nil {
			return fmt.Errorf("bounded M2 apply failed: %w %s", err, m2RedactEvidence(string(out)))
		}
		return nil
	}
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
