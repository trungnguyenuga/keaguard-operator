package manifests

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// Render copies of the real tree: overlays must change all namespace consumers.
func render(t *testing.T, namespace, composition string) []unstructured.Unstructured {
	t.Helper()
	dir := t.TempDir()
	err := filepath.WalkDir("../../config", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("../../config", path)
		if err != nil {
			return err
		}
		dest := filepath.Join(dir, "config", rel)
		if entry.IsDir() {
			return os.MkdirAll(dest, 0700)
		}
		if !entry.Type().IsRegular() {
			t.Fatalf("nonregular config input: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "overlay")
	if err := os.Mkdir(overlay, 0700); err != nil {
		t.Fatal(err)
	}
	data := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- ../config/" + composition + "\n"
	if namespace != "" {
		data += "namespace: " + namespace + "\n"
		if composition == "default" {
			// Kustomize requires replacement files beneath the current root.
			replacement, err := os.ReadFile(filepath.Join(dir, "config/default/namespace_replacement.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(overlay, "namespace_replacement.yaml"), replacement, 0600); err != nil {
				t.Fatal(err)
			}
			data += "replacements:\n- path: namespace_replacement.yaml\n"
		}
	}
	if err := os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	kubectl := os.Getenv("KUBECTL")
	if kubectl == "" {
		kubectl = "kubectl"
	}
	cmd := exec.Command(kubectl, "kustomize", overlay)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("render: %v: %s", err, stderr.String())
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(out), 4096)
	var objects []unstructured.Unstructured
	for {
		var obj unstructured.Unstructured
		err := decoder.Decode(&obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(obj.Object) > 0 {
			objects = append(objects, obj)
		}
	}
	if len(objects) == 0 {
		t.Fatal("rendered zero objects")
	}
	return objects
}

func decode(t *testing.T, obj unstructured.Unstructured, target any) {
	t.Helper()
	data, err := json.Marshal(obj.Object)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func TestUnitManifestRendering(t *testing.T) {
	for _, ns := range []string{"keaguard-m1-a", "keaguard-m1-b"} {
		t.Run(ns, func(t *testing.T) { render(t, ns, "default"); render(t, "", "crd") })
	}
}

func TestUnitMakefileRenderUsesSelectedImage(t *testing.T) {
	images := []string{
		"keaguard-operator:m1-review-selected",
		"registry.example:5000/team/keaguard-operator:v2",
		"keaguard-operator@sha256:" + strings.Repeat("a", 64),
	}
	for _, selected := range images {
		t.Run(selected, func(t *testing.T) {
			cmd := exec.Command("make", "--no-print-directory", "render-manifests", "IMG="+selected)
			cmd.Dir = "../.."
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("make render-manifests: %v\n%s", err, output)
			}
			runtime, err := os.ReadFile(filepath.Join("..", "..", "dist", "runtime.yaml"))
			if err != nil {
				t.Fatalf("read rendered runtime: %v\nmake output:\n%s", err, output)
			}
			var deployment appsv1.Deployment
			found := false
			decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(runtime), 4096)
			for {
				var obj unstructured.Unstructured
				err := decoder.Decode(&obj)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if obj.GetKind() == "Deployment" && obj.GetName() == "keaguard-controller-manager" {
					decode(t, obj, &deployment)
					found = true
				}
			}
			if !found || len(deployment.Spec.Template.Spec.Containers) != 1 || deployment.Spec.Template.Spec.Containers[0].Name != "manager" {
				t.Fatalf("rendered runtime does not contain the manager Deployment and container:\n%s", runtime)
			}
			actual := deployment.Spec.Template.Spec.Containers[0].Image
			if !imageIdentityMatches(actual, selected) {
				t.Fatalf("rendered manager image = %q, want exact IMG %q", actual, selected)
			}
			crd, err := os.ReadFile(filepath.Join("..", "..", "dist", "crd.yaml"))
			if err != nil {
				t.Fatalf("read rendered CRD installer: %v", err)
			}
			if !bytes.Contains(crd, []byte("kind: CustomResourceDefinition")) || bytes.Contains(runtime, []byte("kind: CustomResourceDefinition")) {
				t.Fatal("Makefile must render the CRD installer separately from the runtime bundle")
			}
		})
	}
}

func imageIdentityMatches(actual, selected string) bool {
	return actual == selected
}

func TestUnitImageIdentityRejectsSubstringMatches(t *testing.T) {
	selected := "keaguard-operator:m1"
	for _, actual := range []string{"keaguard-operator:m1-test", "registry.example/keaguard-operator:m1", "prefix-keaguard-operator:m1"} {
		if imageIdentityMatches(actual, selected) {
			t.Errorf("image %q must not be accepted as selected image %q", actual, selected)
		}
	}
}

// Broadening grants, reintroducing installer/metrics resources, or hardcoding the
// namespace must fail against the objects the installer would actually apply.
func TestUnitRuntimeManifestContract(t *testing.T) {
	for _, ns := range []string{"keaguard-m1-a", "keaguard-m1-b"} {
		t.Run(ns, func(t *testing.T) {
			objects := render(t, ns, "default")
			counts := map[string]int{}
			var deployment appsv1.Deployment
			var role rbacv1.Role
			var binding rbacv1.RoleBinding
			var account corev1.ServiceAccount
			for _, obj := range objects {
				counts[obj.GetKind()]++
				if obj.GetKind() == "Namespace" {
					if obj.GetName() != ns {
						t.Errorf("namespace object = %q", obj.GetName())
					}
				} else if obj.GetNamespace() != ns {
					t.Errorf("%s/%s namespace = %q, want %s", obj.GetKind(), obj.GetName(), obj.GetNamespace(), ns)
				}
				switch obj.GetKind() {
				case "Deployment":
					decode(t, obj, &deployment)
				case "Role":
					decode(t, obj, &role)
				case "RoleBinding":
					decode(t, obj, &binding)
				case "ServiceAccount":
					decode(t, obj, &account)
				case "Namespace":
				default:
					t.Errorf("unapproved runtime resource %s/%s", obj.GetKind(), obj.GetName())
				}
			}
			wantCounts := map[string]int{"Namespace": 1, "Deployment": 1, "ServiceAccount": 1, "Role": 1, "RoleBinding": 1}
			if !reflect.DeepEqual(counts, wantCounts) {
				t.Errorf("runtime kinds/counts = %v, want %v", counts, wantCounts)
			}
			permissions := map[string][]string{}
			for _, rule := range role.Rules {
				if len(rule.ResourceNames) > 0 || len(rule.NonResourceURLs) > 0 || len(rule.APIGroups) != 1 || len(rule.Resources) == 0 || len(rule.Verbs) == 0 {
					t.Errorf("unexpected RBAC rule shape: %+v", rule)
					continue
				}
				group := rule.APIGroups[0]
				if strings.Contains(group, "*") {
					t.Errorf("wildcard API group is forbidden: %+v", rule)
				}
				verbs := append([]string(nil), rule.Verbs...)
				sort.Strings(verbs)
				if containsDuplicate(verbs) || containsWildcard(verbs) {
					t.Errorf("duplicate or wildcard verb in RBAC rule: %+v", rule)
				}
				for _, resource := range rule.Resources {
					key := group + "/" + resource
					if resource == "*" || strings.Contains(resource, "*") {
						t.Errorf("wildcard resource is forbidden: %s", key)
					}
					if _, exists := permissions[key]; exists {
						t.Errorf("duplicate RBAC grant key: %s", key)
					}
					permissions[key] = append([]string(nil), verbs...)
				}
			}
			wantPermissions := map[string][]string{
				"/configmaps":       {"create", "delete", "get", "list", "patch", "watch"},
				"/pods":             {"get", "list", "watch"},
				"/services":         {"create", "delete", "get", "list", "patch", "watch"},
				"apps/statefulsets": {"create", "delete", "get", "list", "patch", "watch"},
				"infrastructure.keaguard.example/keaclusters":        {"get", "list", "watch"},
				"infrastructure.keaguard.example/keaclusters/status": {"patch"},
			}
			if !reflect.DeepEqual(permissions, wantPermissions) {
				t.Errorf("runtime permissions = %v, want %v", permissions, wantPermissions)
			}
			if binding.RoleRef != (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name}) {
				t.Errorf("roleRef does not reference runtime Role: %+v", binding.RoleRef)
			}
			wantSubjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: account.Name, Namespace: ns}}
			if account.Name == "" || !reflect.DeepEqual(binding.Subjects, wantSubjects) {
				t.Errorf("binding subjects = %+v, want %+v", binding.Subjects, wantSubjects)
			}
			if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType || deployment.Spec.Strategy.RollingUpdate != nil {
				t.Error("deployment must use one replica and Recreate")
			}
			pod := deployment.Spec.Template.Spec
			if pod.ServiceAccountName != account.Name || pod.ServiceAccountName == "" {
				t.Error("deployment ServiceAccount does not match binding")
			}
			if len(pod.Containers) != 1 || len(pod.InitContainers) != 0 || len(pod.Volumes) != 0 {
				t.Errorf("unexpected workload containers/volumes: %+v", pod)
				return
			}
			c := pod.Containers[0]
			// No flags enable metrics or leader election. Main's option tests prove both
			// disabled; only the required namespace argument is passed to its parser.
			if !reflect.DeepEqual(c.Command, []string{"/manager"}) || !reflect.DeepEqual(c.Args, []string{"--watch-namespace=" + ns}) {
				t.Errorf("manager command/args = %v %v", c.Command, c.Args)
			}
			if len(c.Env) != 0 || len(c.EnvFrom) != 0 || len(c.VolumeMounts) != 0 {
				t.Error("unexpected environment or mounted credentials")
			}
			if len(c.Ports) != 1 || c.Ports[0].ContainerPort != 8081 {
				t.Errorf("only health port allowed: %v", c.Ports)
			}
			for name, probe := range map[string]*corev1.Probe{"liveness": c.LivenessProbe, "readiness": c.ReadinessProbe} {
				path := "/healthz"
				if name == "readiness" {
					path = "/readyz"
				}
				if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Path != path || probe.HTTPGet.Port.IntVal != 8081 {
					t.Errorf("%s manager health probe invalid: %+v", name, probe)
				}
			}
			if pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot || pod.SecurityContext.SeccompProfile == nil || pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
				t.Error("missing pod nonroot/seccomp hardening")
			}
			if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem || c.SecurityContext.Capabilities == nil || !reflect.DeepEqual(c.SecurityContext.Capabilities.Drop, []corev1.Capability{"ALL"}) {
				t.Error("missing container hardening")
			}
		})
	}
	objects := render(t, "", "crd")
	if len(objects) != 1 || objects[0].GetKind() != "CustomResourceDefinition" {
		t.Fatalf("installer must contain only the CRD: %v", objects)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	decode(t, objects[0], &crd)
	if crd.Name != "keaclusters.infrastructure.keaguard.example" || crd.Spec.Group != "infrastructure.keaguard.example" || crd.Spec.Names.Kind != "KeaCluster" || crd.Spec.Names.Plural != "keaclusters" || crd.Spec.Scope != apiextensionsv1.NamespaceScoped {
		t.Errorf("incorrect namespaced API: %+v", crd.Spec)
	}
	if len(crd.Spec.Versions) != 1 || crd.Spec.Versions[0].Name != "v1alpha1" || !crd.Spec.Versions[0].Served || !crd.Spec.Versions[0].Storage || crd.Spec.Versions[0].Subresources == nil || crd.Spec.Versions[0].Subresources.Status == nil {
		t.Error("incorrect version/status API contract")
	}
}

func containsDuplicate(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			return true
		}
	}
	return false
}

func containsWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" || strings.Contains(value, "*") {
			return true
		}
	}
	return false
}
