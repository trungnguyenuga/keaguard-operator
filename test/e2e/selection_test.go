package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func validSelection() map[string]string {
	return map[string]string{
		"KEAGUARD_E2E": "1", "KEAGUARD_KIND_CLUSTER": labCluster,
		"KEAGUARD_KIND_CONTEXT": "kind-" + labCluster, "KEAGUARD_E2E_DISPOSABLE": labCluster,
		"KUBECONFIG": approvedKubeconfig, "IMG": "keaguard-operator:m1-test",
	}
}
func TestUnitKindSelection(t *testing.T) {
	for _, key := range []string{"KEAGUARD_E2E", "KEAGUARD_KIND_CLUSTER", "KEAGUARD_KIND_CONTEXT", "KEAGUARD_E2E_DISPOSABLE", "KUBECONFIG", "IMG"} {
		for _, value := range []string{"", "wrong"} {
			t.Run(key+"="+value, func(t *testing.T) {
				env := validSelection()
				env[key] = value
				calls := 0
				if err := guardSelection(env, func() error { calls++; return nil }); err == nil || calls != 0 {
					t.Errorf("invalid selection accepted or contacted lab: err=%v calls=%d", err, calls)
				}
			})
		}
	}
	for _, value := range []string{"/home/me/.kube/config", "/tmp/a:/tmp/b", "relative", "/tmp/config"} {
		env := validSelection()
		env["KUBECONFIG"] = value
		if err := guardSelection(env, func() error { t.Error("contacted lab"); return nil }); err == nil {
			t.Error("unsafe kubeconfig accepted")
		}
	}
	for _, value := range []string{"controller:latest", "controller", "repo/image:latest"} {
		env := validSelection()
		env["IMG"] = value
		if err := guardSelection(env, func() error { t.Error("contacted lab"); return nil }); err == nil {
			t.Error("floating image accepted")
		}
	}
	calls := 0
	if err := guardSelection(validSelection(), func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Errorf("valid selection: %v calls=%d", err, calls)
	}
	for _, labels := range []map[string]string{nil, {fixtureLabel: "someone-else"}} {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: runtimeNamespace, Labels: labels}}
		if err := checkFixtureNamespace(ns); err == nil {
			t.Error("non-test namespace collision accepted")
		}
	}
	if err := checkFixtureNamespace(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: runtimeNamespace, Labels: map[string]string{fixtureLabel: labCluster}}}); err != nil {
		t.Fatal(err)
	}
	t.Run("normal targets cannot create cluster", func(t *testing.T) {
		for _, target := range []string{"test-unit", "test-envtest", "test", "test-manifests"} {
			cmd := exec.Command("make", "-n", target)
			cmd.Dir = "../.."
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("dry run: %v %s", err, out)
			}
			if strings.Contains(string(out), "kind-create") || strings.Contains(string(out), "create cluster") {
				t.Fatalf("%s can create a cluster", target)
			}
		}
	})
	t.Run("unsupported scaffold lifecycle targets are absent", func(t *testing.T) {
		for _, target := range []string{"run", "build-installer", "install", "uninstall", "deploy", "undeploy", "docker-push", "docker-buildx"} {
			cmd := exec.Command("make", "-n", target)
			cmd.Dir = "../.."
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "No rule to make target") {
				t.Errorf("unsupported target %q remains available: err=%v output=%s", target, err, out)
			}
		}
	})
	t.Run("ordinary suite skips before configuration", func(t *testing.T) {
		t.Setenv("KEAGUARD_E2E", "")
		t.Setenv("KUBECONFIG", "/unreadable")
		if suiteOptedIn() {
			t.Error("ordinary suite opted in")
		}
	})
	t.Run("Kind Make targets require caller-selected IMG before invoking Go", func(t *testing.T) {
		for _, target := range []string{"test-kind", "kind-create"} {
			for _, args := range [][]string{nil, {"IMG="}} {
				cmd := exec.Command("make", append([]string{"--no-print-directory", target}, args...)...)
				cmd.Dir = "../.."
				cmd.Env = makeTestEnv("GOTOOLCHAIN=local", "KEAGUARD_E2E=1")
				out, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(string(out), "explicit IMG= required for Kind") {
					t.Errorf("%s with IMG arguments %v did not fail at the Make IMG guard: err=%v output=%s", target, args, err, out)
				}
				if strings.Contains(string(out), "go test ./test/e2e") {
					t.Errorf("%s with IMG arguments %v invoked the e2e test process before rejection: %s", target, args, out)
				}
			}
		}
	})
	t.Run("Kind Make target forwards explicitly selected IMG", func(t *testing.T) {
		for _, selected := range []string{
			"keaguard-operator:m1-explicit",
			"registry.example:5000/team/keaguard-operator:v2",
			"keaguard-operator@sha256:" + strings.Repeat("a", 64),
		} {
			cmd := exec.Command("make", "--no-print-directory", "-n", "test-kind", "IMG="+selected)
			cmd.Dir = "../.."
			cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "KEAGUARD_E2E=1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("dry-run test-kind for %q: %v\n%s", selected, err, out)
			}
			if !strings.Contains(string(out), "IMG=\""+selected+"\" go test ./test/e2e") {
				t.Errorf("test-kind did not forward explicitly selected IMG %q: %s", selected, out)
			}
			commandLine := exec.Command("make", "--no-print-directory", "kind-image-required", "IMG="+selected)
			commandLine.Dir = "../.."
			commandLine.Env = makeTestEnv("GOTOOLCHAIN=local")
			if output, err := commandLine.CombinedOutput(); err != nil {
				t.Errorf("command-line IMG %q rejected: %v\n%s", selected, err, output)
			}
		}
		envSelected := "registry.example:5000/team/keaguard-operator:environment"
		envIMG := exec.Command("make", "--no-print-directory", "kind-image-required")
		envIMG.Dir = "../.."
		envIMG.Env = makeTestEnv("GOTOOLCHAIN=local", "IMG="+envSelected)
		if output, err := envIMG.CombinedOutput(); err != nil {
			t.Errorf("environment IMG %q rejected: %v\n%s", envSelected, err, output)
		}
		envForward := exec.Command("make", "--no-print-directory", "-n", "test-kind")
		envForward.Dir = "../.."
		envForward.Env = makeTestEnv("GOTOOLCHAIN=local", "KEAGUARD_E2E=1", "IMG="+envSelected)
		output, err := envForward.CombinedOutput()
		if err != nil {
			t.Fatalf("dry-run test-kind for environment IMG %q: %v\n%s", envSelected, err, output)
		}
		if !strings.Contains(string(output), "IMG=\""+envSelected+"\" go test ./test/e2e") {
			t.Errorf("test-kind did not forward environment IMG %q: %s", envSelected, output)
		}
	})
}

func makeTestEnv(extra ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "IMG=") && !strings.HasPrefix(entry, "GOTOOLCHAIN=") && !strings.HasPrefix(entry, "KEAGUARD_E2E=") {
			env = append(env, entry)
		}
	}
	return append(env, extra...)
}

func TestUnitRenderRuntimeUsesSelectedImage(t *testing.T) {
	images := []string{
		"keaguard-operator:m1-unit-selected",
		"registry.example:5000/team/keaguard-operator:v2",
		"keaguard-operator@sha256:" + strings.Repeat("a", 64),
	}
	for _, selectedImage := range images {
		t.Run(selectedImage, func(t *testing.T) {
			t.Setenv("IMG", selectedImage)
			rendered, err := renderRuntime(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var deployment appsv1.Deployment
			decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
			found := false
			for {
				var obj unstructured.Unstructured
				err := decoder.Decode(&obj)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if obj.GetKind() == "Deployment" && obj.GetName() == managerName {
					data, err := json.Marshal(obj.Object)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(data, &deployment); err != nil {
						t.Fatal(err)
					}
					found = true
				}
			}
			if !found {
				t.Fatal("rendered runtime has no manager Deployment")
			}
			if len(deployment.Spec.Template.Spec.Containers) != 1 || deployment.Spec.Template.Spec.Containers[0].Name != "manager" {
				t.Fatalf("unexpected manager containers: %+v", deployment.Spec.Template.Spec.Containers)
			}
			if actual := deployment.Spec.Template.Spec.Containers[0].Image; !selectedImageMatches(actual, selectedImage) {
				t.Fatalf("rendered manager image = %q, want exact IMG %q", actual, selectedImage)
			}
		})
	}
}

func selectedImageMatches(actual, selected string) bool {
	return actual == selected
}

func TestUnitSelectedImageComparisonRejectsSubstrings(t *testing.T) {
	selected := "keaguard-operator:m1"
	for _, actual := range []string{"keaguard-operator:m1-test", "registry.example/keaguard-operator:m1", "prefix-keaguard-operator:m1"} {
		if selectedImageMatches(actual, selected) {
			t.Errorf("image %q must not be accepted as selected image %q", actual, selected)
		}
	}
}

// A namespace collision must fail before any fixture mutation, even if the first namespace is absent.
type fixtureRecorder struct {
	client.Client
	mutations int
}

func (r *fixtureRecorder) Create(ctx context.Context, o client.Object, opts ...client.CreateOption) error {
	r.mutations++
	return r.Client.Create(ctx, o, opts...)
}
func (r *fixtureRecorder) Delete(ctx context.Context, o client.Object, opts ...client.DeleteOption) error {
	r.mutations++
	return r.Client.Delete(ctx, o, opts...)
}
func TestUnitFixtureCollision(t *testing.T) {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	foreign := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: outsideNamespace}}
	r := &fixtureRecorder{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(foreign).Build()}
	if err := ensureFixtureNamespaces(context.Background(), r); err == nil || r.mutations != 0 {
		t.Fatalf("collision: err=%v mutations=%d", err, r.mutations)
	}
	var after corev1.Namespace
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(foreign), &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Labels) != 0 {
		t.Fatal("foreign namespace relabelled")
	}
}
func TestUnitRuntimeCredentials(t *testing.T) {
	admin := &rest.Config{Host: "https://127.0.0.1:1234", Username: "admin", Password: "secret", BearerToken: "admin", BearerTokenFile: "admin-token", TLSClientConfig: rest.TLSClientConfig{CAData: []byte("trusted-ca"), CertData: []byte("admin-cert"), KeyData: []byte("admin-key"), CertFile: "admin-cert", KeyFile: "admin-key"}, Impersonate: rest.ImpersonationConfig{UserName: "admin"}, ExecProvider: nil}
	actual := runtimeConfig(admin, "runtime-token")
	expected := &rest.Config{Host: "https://127.0.0.1:1234", BearerToken: "runtime-token", TLSClientConfig: rest.TLSClientConfig{CAData: []byte("trusted-ca")}, Timeout: actual.Timeout}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("runtime config retained unexpected admin settings")
	}
	actual.CAData[0] = 'X'
	if string(admin.CAData) != "trusted-ca" {
		t.Fatal("CA data aliased")
	}
}

func TestUnitPrivateKubeconfig(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "keaguard-private-config-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateKubeconfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateKubeconfig(path); err == nil {
		t.Fatal("readable kubeconfig accepted")
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateKubeconfig(link); err == nil {
		t.Fatal("symlink kubeconfig accepted")
	}
}
