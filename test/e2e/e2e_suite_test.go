package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var admin client.Client
var adminset *kubernetes.Clientset
var adminConfig *rest.Config
var labctx context.Context
var scheme = runtime.NewScheme()

func TestE2E(t *testing.T) {
	if !suiteOptedIn() {
		t.Skip("Kind acceptance requires explicit opt-in")
	}
	if err := guardSelection(selectionEnv(), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "KeaGuard disposable Kind acceptance")
}

// Creation is a separate explicit target, never called by TestE2E or ordinary tests.
func TestKindCreate(t *testing.T) {
	if os.Getenv("KEAGUARD_KIND_CREATE") != "1" {
		t.Skip("explicit kind-create only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := guardSelection(selectionEnv(), func() error {
		out, err := command(ctx, "kind", "get", "clusters")
		if err != nil {
			return err
		}
		for _, name := range splitLines(string(out)) {
			if name == labCluster {
				return fmt.Errorf("selected cluster already exists; inspect it instead")
			}
		}
		// The runner may provide an empty placeholder. Preserve any populated file.
		if st, err := os.Lstat(labKubeconfig); err == nil {
			if !st.Mode().IsRegular() || st.Size() != 0 {
				return fmt.Errorf("refuse to overwrite populated/nonregular kubeconfig")
			}
			if err = os.Chmod(labKubeconfig, 0600); err != nil {
				return err
			}
		} else if os.IsNotExist(err) {
			f, err := os.OpenFile(labKubeconfig, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			if err = f.Close(); err != nil {
				return err
			}
		} else {
			return err
		}

		if err := checkPrivateKubeconfig(labKubeconfig); err != nil {
			return err
		}
		out, err = command(ctx, "kind", "create", "cluster", "--name", labCluster, "--image", nodeImage, "--kubeconfig", labKubeconfig, "--wait", "120s", "--retain")
		t.Log(string(out))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

var _ = BeforeSuite(func() {
	var cancel context.CancelFunc
	labctx, cancel = context.WithTimeout(context.Background(), 23*time.Minute)
	DeferCleanup(cancel)
	var err error
	adminConfig, err = validateLab(labctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	Expect(infrastructurev1alpha1.AddToScheme(scheme)).To(Succeed())
	admin, err = client.New(adminConfig, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	adminset, err = kubernetes.NewForConfig(adminConfig)
	Expect(err).NotTo(HaveOccurred())
	Expect(ensureFixtureNamespaces(labctx, admin)).To(Succeed())
	out, err := command(labctx, "docker", "image", "inspect", os.Getenv("IMG"), "--format", "{{.Id}}|{{.Os}}/{{.Architecture}}")
	Expect(err).NotTo(HaveOccurred())
	fmt.Fprintf(GinkgoWriter, "Selected image %s: %s", os.Getenv("IMG"), out)
	_, err = command(labctx, "kind", "load", "docker-image", os.Getenv("IMG"), "--name", labCluster)
	Expect(err).NotTo(HaveOccurred())
	crd, err := command(labctx, "kubectl", "kustomize", "../../config/crd")
	Expect(err).NotTo(HaveOccurred())
	Expect(applyBundle(labctx, crd)).To(Succeed())
	_, err = kubectl(labctx, "wait", "--for=condition=Established", "crd/keaclusters.infrastructure.keaguard.example", "--timeout=120s")
	Expect(err).NotTo(HaveOccurred())
	bundle, err := renderRuntime(labctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(applyBundle(labctx, bundle)).To(Succeed())
	out, err = kubectl(labctx, "rollout", "status", "deployment/"+managerName, "-n", runtimeNamespace, "--timeout=120s")
	Expect(err).NotTo(HaveOccurred(), "%s\n%s", out, managerLogs(labctx))
})
var _ = AfterEach(func() {
	fmt.Fprintln(GinkgoWriter, managerLogs(labctx))
	if CurrentSpecReport().Failed() {
		out, _ := kubectl(labctx, "get", "pods,events", "-n", runtimeNamespace, "-o", "wide")
		fmt.Fprintln(GinkgoWriter, string(out))
	}
})
