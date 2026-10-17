package e2e

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func splitLines(s string) []string { return strings.Fields(s) }
func cr(name, ns string) *infrastructurev1alpha1.KeaCluster {
	return &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{fixtureLabel: labCluster}}}
}
func cm(name, ns string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{fixtureLabel: labCluster}}, Data: map[string]string{"fixture": "unchanged"}}
}

// Generated names prevent reusing/deleting preexisting fixtures. No namespace/CRD/cluster cleanup.
func createCR(ns, prefix string) *infrastructurev1alpha1.KeaCluster {
	p := cr("", ns)
	p.GenerateName = prefix
	Expect(admin.Create(labctx, p)).To(Succeed())
	return p
}
func assertArtifact(p *infrastructurev1alpha1.KeaCluster) {
	Eventually(func(g Gomega) {
		var actual corev1.ConfigMap
		g.Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), &actual)).To(Succeed())
		g.Expect(actual.Data).To(Equal(map[string]string{"keacluster-name": p.Name, "keacluster-namespace": p.Namespace, "keacluster-uid": string(p.UID)}))
		g.Expect(actual.BinaryData).To(BeEmpty())
		g.Expect(actual.Labels["keaguard.example/artifact"]).To(Equal("reconciliation"))
		g.Expect(actual.Annotations["keaguard.example/purpose"]).To(Equal("Internal reconciliation artifact; not operational Kea DHCP configuration."))
		owner := metav1.GetControllerOf(&actual)
		g.Expect(owner).NotTo(BeNil())
		if owner != nil {
			g.Expect(owner.APIVersion).To(Equal("infrastructure.keaguard.example/v1alpha1"))
			g.Expect(owner.Kind).To(Equal("KeaCluster"))
			g.Expect(owner.Name).To(Equal(p.Name))
			g.Expect(owner.UID).To(Equal(p.UID))
			g.Expect(owner.BlockOwnerDeletion).NotTo(BeNil())
			g.Expect(*owner.BlockOwnerDeletion).To(BeFalse())
		}
		var current infrastructurev1alpha1.KeaCluster
		g.Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), &current)).To(Succeed())
		condition := meta.FindStatusCondition(current.Status.Conditions, "ArtifactReconciled")
		g.Expect(condition).NotTo(BeNil())
		if condition != nil {
			g.Expect(condition.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(condition.Reason).To(Equal("ArtifactInSync"))
			g.Expect(condition.ObservedGeneration).To(Equal(p.Generation))
		}
		g.Expect(current.Status.ObservedGeneration).To(Equal(p.Generation))
		g.Expect(meta.FindStatusCondition(current.Status.Conditions, "Ready")).To(BeNil())
	}, 120*time.Second, time.Second).Should(Succeed())
}
func forbidden(name string, err error) {
	ExpectWithOffset(1, apierrors.IsForbidden(err)).To(BeTrue(), "%s expected Forbidden, got %v", name, err)
	fmt.Fprintf(GinkgoWriter, "Forbidden confirmed: %s\n", name)
}

var _ = Describe("KIND: Runtime identity", func() {
	It("uses the selected image and exact ServiceAccount with real namespaced requests", func() {
		var deployment appsv1.Deployment
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: managerName}, &deployment)).To(Succeed())
		Expect(deployment.Spec.Template.Spec.ServiceAccountName).To(Equal(managerName))
		Expect(*deployment.Spec.Replicas).To(Equal(int32(1)))
		Expect(deployment.Spec.Strategy.Type).To(Equal(appsv1.RecreateDeploymentStrategyType))
		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(deployment.Spec.Template.Spec.Containers[0].Image).To(Equal(os.Getenv("IMG")))
		Expect(deployment.Spec.Template.Spec.Containers[0].Args).To(Equal([]string{"--watch-namespace=" + runtimeNamespace}))
		for _, v := range deployment.Spec.Template.Spec.Volumes {
			Expect(v.HostPath).To(BeNil())
			Expect(v.Secret).To(BeNil())
			Expect(v.ConfigMap).To(BeNil())
		}
		pods, err := adminset.CoreV1().Pods(runtimeNamespace).List(labctx, metav1.ListOptions{LabelSelector: "control-plane=controller-manager"})
		Expect(err).NotTo(HaveOccurred())
		Expect(pods.Items).To(HaveLen(1))
		pod := pods.Items[0]
		Expect(pod.Spec.ServiceAccountName).To(Equal(managerName))
		Expect(pod.Spec.Containers[0].Image).To(Equal(os.Getenv("IMG")))
		Expect(pod.Status.ContainerStatuses).To(HaveLen(1))
		Expect(pod.Status.ContainerStatuses[0].ImageID).NotTo(BeEmpty())
		fmt.Fprintf(GinkgoWriter, "Context=kind-%s node=%s serviceAccount=%s/%s selected=%s runtimeImageID=%s\n", labCluster, nodeImage, runtimeNamespace, managerName, os.Getenv("IMG"), pod.Status.ContainerStatuses[0].ImageID)
		role, err := adminset.RbacV1().Roles(runtimeNamespace).Get(labctx, "keaguard-manager-role", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		fmt.Fprintf(GinkgoWriter, "Runtime Role rules: %+v\n", role.Rules)
		binding, err := adminset.RbacV1().RoleBindings(runtimeNamespace).Get(labctx, "keaguard-manager-rolebinding", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(binding.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: role.Name}))
		Expect(binding.Subjects).To(Equal([]rbacv1.Subject{{Kind: "ServiceAccount", Name: managerName, Namespace: runtimeNamespace}}))
		expiration := int64(600)
		token, err := adminset.CoreV1().ServiceAccounts(runtimeNamespace).CreateToken(labctx, managerName, &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &expiration}}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(token.Status.Token).NotTo(BeEmpty())
		cfg := runtimeConfig(adminConfig, token.Status.Token)
		runtimeSet, err := kubernetes.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())
		runtimeClient, err := client.New(cfg, client.Options{Scheme: scheme})
		Expect(err).NotTo(HaveOccurred())
		dyn, err := dynamic.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())
		// Runtime cannot create parents; admin prepares both namespaces' fixtures.
		for _, ns := range []string{runtimeNamespace, outsideNamespace} {
			parent := createCR(ns, "identity-")
			child := cm("", ns)
			child.GenerateName = "identity-cm-"
			Expect(admin.Create(labctx, child)).To(Succeed())
			_, err = runtimeSet.CoreV1().ConfigMaps(ns).Get(labctx, child.Name, metav1.GetOptions{})
			if ns == outsideNamespace {
				forbidden("outside ConfigMap Get", err)
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			_, err = runtimeSet.CoreV1().ConfigMaps(ns).List(labctx, metav1.ListOptions{})
			if ns == outsideNamespace {
				forbidden("outside ConfigMap List", err)
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			seconds := int64(5)
			w, err := runtimeSet.CoreV1().ConfigMaps(ns).Watch(labctx, metav1.ListOptions{TimeoutSeconds: &seconds})
			if ns == outsideNamespace {
				forbidden("outside ConfigMap Watch", err)
			} else {
				Expect(err).NotTo(HaveOccurred())
				w.Stop()
			}
			candidate := cm("", ns)
			candidate.GenerateName = "runtime-created-"
			_, err = runtimeSet.CoreV1().ConfigMaps(ns).Create(labctx, candidate, metav1.CreateOptions{})
			if ns == outsideNamespace {
				forbidden("outside ConfigMap Create", err)
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			_, err = runtimeSet.CoreV1().ConfigMaps(ns).Patch(labctx, child.Name, types.MergePatchType, []byte(`{"data":{"patched":"yes"}}`), metav1.PatchOptions{})
			if ns == outsideNamespace {
				forbidden("outside ConfigMap Patch", err)
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			var fetched infrastructurev1alpha1.KeaCluster
			err = runtimeClient.Get(labctx, client.ObjectKeyFromObject(parent), &fetched)
			if ns == outsideNamespace {
				forbidden("outside KeaCluster Get", err)
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			resource := dyn.Resource(schema.GroupVersionResource{Group: "infrastructure.keaguard.example", Version: "v1alpha1", Resource: "keaclusters"}).Namespace(ns)
			_, err = resource.List(labctx, metav1.ListOptions{})
			if ns == outsideNamespace {
				forbidden("outside KeaCluster List", err)
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			w, err = resource.Watch(labctx, metav1.ListOptions{TimeoutSeconds: &seconds})
			if ns == outsideNamespace {
				forbidden("outside KeaCluster Watch", err)
			} else {
				Expect(err).NotTo(HaveOccurred())
				w.Stop()
			}
			_, err = resource.Patch(labctx, parent.Name, types.MergePatchType, []byte(`{"status":{"conditions":[{"type":"IdentityFixture","status":"True","reason":"TokenRequestVerified","message":"test fixture","lastTransitionTime":"2026-10-16T00:00:00Z"}]}}`), metav1.PatchOptions{}, "status")
			if ns == outsideNamespace {
				forbidden("outside status Patch", err)
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			_, err = runtimeSet.CoreV1().ConfigMaps(ns).Update(labctx, child, metav1.UpdateOptions{})
			forbidden(ns+" ConfigMap Update", err)
			forbidden(ns+" ConfigMap Delete", runtimeSet.CoreV1().ConfigMaps(ns).Delete(labctx, child.Name, metav1.DeleteOptions{}))
			for _, patch := range []string{`{"spec":{}}`, `{"metadata":{"finalizers":["keaguard.example/fixture"]}}`} {
				_, err = resource.Patch(labctx, parent.Name, types.MergePatchType, []byte(patch), metav1.PatchOptions{})
				forbidden(ns+" parent spec/finalizer Patch", err)
			}
			_, err = runtimeSet.CoreV1().Secrets(ns).List(labctx, metav1.ListOptions{})
			forbidden(ns+" Secrets List", err)
			_, err = runtimeSet.CoordinationV1().Leases(ns).List(labctx, metav1.ListOptions{})
			forbidden(ns+" Leases List", err)
		}
		_, err = runtimeSet.CoreV1().Namespaces().Get(labctx, runtimeNamespace, metav1.GetOptions{})
		forbidden("Namespace Get", err)
		_, err = dyn.Resource(schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}).Get(labctx, "keaclusters.infrastructure.keaguard.example", metav1.GetOptions{})
		forbidden("CRD Get", err)
	})
})
var _ = Describe("KIND: Core", func() {
	It("creates internal artifacts, refuses collisions, recovers after removal and leaves outside fixtures unchanged", func() {
		outside := createCR(outsideNamespace, "outside-core-")
		outsideCM := cm(outside.Name, outsideNamespace)
		Expect(admin.Create(labctx, outsideCM)).To(Succeed())
		beforeParent := outside.DeepCopy()
		beforeCM := outsideCM.DeepCopy()
		p := createCR(runtimeNamespace, "core-")
		assertArtifact(p)
		// Create the collision before its CR, so the manager never had an ownership edge.
		collision := cm("", runtimeNamespace)
		collision.GenerateName = "collision-"
		Expect(admin.Create(labctx, collision)).To(Succeed())
		blocked := cr(collision.Name, runtimeNamespace)
		Expect(admin.Create(labctx, blocked)).To(Succeed())
		Eventually(func(g Gomega) {
			var current infrastructurev1alpha1.KeaCluster
			g.Expect(admin.Get(labctx, client.ObjectKeyFromObject(blocked), &current)).To(Succeed())
			c := meta.FindStatusCondition(current.Status.Conditions, "ArtifactReconciled")
			g.Expect(c).NotTo(BeNil())
			if c != nil {
				g.Expect(c.Reason).To(Equal("OwnershipConflict"))
				g.Expect(c.Status).To(Equal(metav1.ConditionFalse))
			}
		}, 120*time.Second, time.Second).Should(Succeed())
		var unchanged corev1.ConfigMap
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(collision), &unchanged)).To(Succeed())
		Expect(unchanged).To(Equal(*collision))
		// Only this newly created test-owned collision is deleted, with UID precondition.
		Expect(admin.Delete(labctx, collision, client.Preconditions{UID: &collision.UID})).To(Succeed())
		assertArtifact(blocked)
		var afterParent infrastructurev1alpha1.KeaCluster
		var afterCM corev1.ConfigMap
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(outside), &afterParent)).To(Succeed())
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(outsideCM), &afterCM)).To(Succeed())
		Expect(afterParent).To(Equal(*beforeParent))
		Expect(afterCM).To(Equal(*beforeCM))
	})
})
var _ = Describe("KIND: Startup authorization", func() {
	It("logs scoped authorization failures with an unbound identity and recovers after restoring the approved identity", func() {
		// Perturb only the verified test deployment; always restore the exact approved pod spec.
		var original appsv1.Deployment
		key := client.ObjectKey{Namespace: runtimeNamespace, Name: managerName}
		Expect(admin.Get(labctx, key, &original)).To(Succeed())
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{GenerateName: "unbound-", Namespace: runtimeNamespace, Labels: map[string]string{fixtureLabel: labCluster}}}
		Expect(admin.Create(labctx, sa)).To(Succeed())
		restore := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			var current appsv1.Deployment
			Expect(admin.Get(ctx, key, &current)).To(Succeed())
			base := current.DeepCopy()
			current.Spec = *original.Spec.DeepCopy()
			Expect(admin.Patch(ctx, &current, client.MergeFrom(base))).To(Succeed())
			out, err := kubectl(ctx, "rollout", "status", "deployment/"+managerName, "-n", runtimeNamespace, "--timeout=110s")
			Expect(err).NotTo(HaveOccurred(), "%s", out)
		}
		DeferCleanup(restore)
		current := original.DeepCopy()
		current.Spec.Template.Spec.ServiceAccountName = sa.Name
		Expect(admin.Patch(labctx, current, client.MergeFrom(&original))).To(Succeed())
		Eventually(func(g Gomega) {
			logs := managerLogs(labctx)
			g.Expect(logs).To(ContainSubstring("forbidden"))
			g.Expect(logs).To(ContainSubstring(runtimeNamespace))
			g.Expect(logs).To(ContainSubstring(sa.Name))
		}, 120*time.Second, time.Second).Should(Succeed())
		fmt.Fprintln(GinkgoWriter, "Unbound identity scoped failure:", managerLogs(labctx))
		// Invalid syntax is exercised in the same disposable Deployment, before API setup.
		var negative appsv1.Deployment
		Expect(admin.Get(labctx, key, &negative)).To(Succeed())
		base := negative.DeepCopy()
		negative.Spec.Template.Spec.Containers[0].Args = []string{"--watch-namespace=*"}
		Expect(admin.Patch(labctx, &negative, client.MergeFrom(base))).To(Succeed())
		Eventually(func(g Gomega) {
			logs := managerLogs(labctx)
			g.Expect(logs).To(ContainSubstring("watch-namespace"))
			g.Expect(logs).To(ContainSubstring("must be one valid Kubernetes namespace name"))
		}, 120*time.Second, time.Second).Should(Succeed())
		fmt.Fprintln(GinkgoWriter, "Invalid flag startup:", managerLogs(labctx))
		restore()
		p := createCR(runtimeNamespace, "restored-")
		assertArtifact(p)
	})
})
