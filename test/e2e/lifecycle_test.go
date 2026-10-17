package e2e

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const t14HoldFinalizer = "keaguard.example/t14-hold"

func isExpectedOwnerReferenceAdmissionError(err error) bool {
	if !apierrors.IsInvalid(err) {
		return false
	}
	var apiStatus apierrors.APIStatus
	if !errors.As(err, &apiStatus) {
		return false
	}
	details := apiStatus.Status().Details
	if details == nil {
		return false
	}
	for _, cause := range details.Causes {
		if strings.HasPrefix(cause.Field, "metadata.ownerReferences") {
			return true
		}
	}
	return false
}

func t14GetManager(ctx context.Context) *appsv1.Deployment {
	var deployment appsv1.Deployment
	Expect(admin.Get(ctx, client.ObjectKey{Namespace: runtimeNamespace, Name: managerName}, &deployment)).To(Succeed())
	return &deployment
}

func t14GetManagerPod(ctx context.Context) *corev1.Pod {
	var pods corev1.PodList
	Expect(admin.List(ctx, &pods, client.InNamespace(runtimeNamespace), client.MatchingLabels{"control-plane": "controller-manager"})).To(Succeed())
	Expect(pods.Items).To(HaveLen(1))
	return &pods.Items[0]
}

func t14SetManagerSpec(ctx context.Context, spec appsv1.DeploymentSpec) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &appsv1.Deployment{}
		if err := admin.Get(ctx, client.ObjectKey{Namespace: runtimeNamespace, Name: managerName}, current); err != nil {
			return err
		}
		base := current.DeepCopy()
		current.Spec = *spec.DeepCopy()
		return admin.Patch(ctx, current, client.MergeFrom(base))
	})
}

func t14ScaleManager(ctx context.Context, replicas int32) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &appsv1.Deployment{}
		if err := admin.Get(ctx, client.ObjectKey{Namespace: runtimeNamespace, Name: managerName}, current); err != nil {
			return err
		}
		base := current.DeepCopy()
		current.Spec.Replicas = &replicas
		return admin.Patch(ctx, current, client.MergeFrom(base))
	})
}

func t14WaitStopped(ctx context.Context) {
	Eventually(func() int {
		var pods corev1.PodList
		if err := admin.List(ctx, &pods, client.InNamespace(runtimeNamespace), client.MatchingLabels{"control-plane": "controller-manager"}); err != nil {
			return -1
		}
		return len(pods.Items)
	}, 120*time.Second, time.Second).Should(BeZero())
}

func t14WaitReady(ctx context.Context) {
	out, err := kubectl(ctx, "rollout", "status", "deployment/"+managerName, "-n", runtimeNamespace, "--timeout=110s")
	Expect(err).NotTo(HaveOccurred(), "%s", out)
	Eventually(func() bool {
		pod := t14GetManagerPod(ctx)
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				return true
			}
		}
		return false
	}, 30*time.Second, time.Second).Should(BeTrue())
}

func t14RestoreManager(original *appsv1.Deployment) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	Expect(t14SetManagerSpec(ctx, original.Spec)).To(Succeed())
	t14WaitReady(ctx)
}

func t14CurrentArtifact(p *infrastructurev1alpha1.KeaCluster) *corev1.ConfigMap {
	actual := &corev1.ConfigMap{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), actual)).To(Succeed())
	return actual
}

func t14Condition(p *infrastructurev1alpha1.KeaCluster) *metav1.Condition {
	current := &infrastructurev1alpha1.KeaCluster{}
	Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), current)).To(Succeed())
	return meta.FindStatusCondition(current.Status.Conditions, "ArtifactReconciled")
}

func t14ConditionReason(p *infrastructurev1alpha1.KeaCluster) string {
	condition := t14Condition(p)
	if condition == nil {
		return ""
	}
	return condition.Reason
}

func t14WaitParentGone(key client.ObjectKey, oldUID types.UID) {
	Eventually(func() (bool, error) {
		current := &infrastructurev1alpha1.KeaCluster{}
		err := admin.Get(labctx, key, current)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return current.UID != oldUID, nil
	}, 120*time.Second, time.Second).Should(BeTrue())
}

// A same-name replacement counts as disappearance of the recorded old child UID.
func t14WaitUIDGone(key client.ObjectKey, oldUID types.UID) {
	Eventually(func() (bool, error) {
		current := &corev1.ConfigMap{}
		err := admin.Get(labctx, key, current)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return current.UID != oldUID, nil
	}, 180*time.Second, time.Second).Should(BeTrue())
}

func t14DeleteParent(p *infrastructurev1alpha1.KeaCluster, options ...client.DeleteOption) {
	Expect(admin.Delete(labctx, p, append(options, client.Preconditions{UID: &p.UID})...)).To(Succeed())
	t14WaitParentGone(client.ObjectKeyFromObject(p), p.UID)
}

func t14RestoreRoleRules(original *rbacv1.Role) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &rbacv1.Role{}
		if err := admin.Get(ctx, client.ObjectKey{Namespace: runtimeNamespace, Name: original.Name}, current); err != nil {
			return err
		}
		base := current.DeepCopy()
		current.Rules = append([]rbacv1.PolicyRule(nil), original.Rules...)
		return admin.Patch(ctx, current, client.MergeFrom(base))
	})).To(Succeed())
}

func t14RemoveStatusPatch(ctx context.Context) *rbacv1.Role {
	original := &rbacv1.Role{}
	Expect(admin.Get(ctx, client.ObjectKey{Namespace: runtimeNamespace, Name: "keaguard-manager-role"}, original)).To(Succeed())
	found := false
	rules := make([]rbacv1.PolicyRule, 0, len(original.Rules))
	for _, rule := range original.Rules {
		if slices.Contains(rule.APIGroups, infrastructurev1alpha1.GroupVersion.Group) && slices.Contains(rule.Resources, "keaclusters/status") && slices.Contains(rule.Verbs, "patch") {
			found = true
			copy := *rule.DeepCopy()
			copy.Verbs = slices.DeleteFunc(copy.Verbs, func(verb string) bool { return verb == "patch" })
			if len(copy.Verbs) > 0 {
				rules = append(rules, copy)
			}
			continue
		}
		rules = append(rules, *rule.DeepCopy())
	}
	Expect(found).To(BeTrue(), "approved status patch rule must exist")
	Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &rbacv1.Role{}
		if err := admin.Get(ctx, client.ObjectKeyFromObject(original), current); err != nil {
			return err
		}
		base := current.DeepCopy()
		current.Rules = rules
		return admin.Patch(ctx, current, client.MergeFrom(base))
	})).To(Succeed())
	return original
}

func t14AddHoldFinalizer(cm *corev1.ConfigMap) *corev1.ConfigMap {
	base := cm.DeepCopy()
	cm.Finalizers = append(cm.Finalizers, t14HoldFinalizer)
	Expect(admin.Update(labctx, cm)).To(Succeed())
	return base
}

func t14ReleaseHoldFinalizer(key client.ObjectKey, uid types.UID) {
	Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &corev1.ConfigMap{}
		if err := admin.Get(labctx, key, current); err != nil {
			return err
		}
		if current.UID != uid {
			return fmt.Errorf("refuse to release finalizer from replacement UID %s", current.UID)
		}
		base := current.DeepCopy()
		finalizers := current.Finalizers[:0]
		for _, finalizer := range current.Finalizers {
			if finalizer != t14HoldFinalizer {
				finalizers = append(finalizers, finalizer)
			}
		}
		current.Finalizers = finalizers
		return admin.Patch(labctx, current, client.MergeFrom(base))
	})).To(Succeed())
}

var _ = Describe("KIND: Restart", func() {
	It("preserves matching artifact and transition time after a full manager restart", func() {
		p := createCR(runtimeNamespace, "restart-correct-")
		assertArtifact(p)
		beforeParent := &infrastructurev1alpha1.KeaCluster{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), beforeParent)).To(Succeed())
		beforeArtifact := t14CurrentArtifact(p)
		beforeCondition := meta.FindStatusCondition(beforeParent.Status.Conditions, "ArtifactReconciled")
		Expect(beforeCondition).NotTo(BeNil())
		oldPodUID := t14GetManagerPod(labctx).UID
		original := t14GetManager(labctx)
		DeferCleanup(func() { t14RestoreManager(original) })
		Expect(t14ScaleManager(labctx, 0)).To(Succeed())
		t14WaitStopped(labctx)
		Consistently(func() types.UID { return t14CurrentArtifact(p).UID }, 2*time.Second, 200*time.Millisecond).Should(Equal(beforeArtifact.UID))
		Expect(t14SetManagerSpec(labctx, original.Spec)).To(Succeed())
		t14WaitReady(labctx)
		Expect(t14GetManagerPod(labctx).UID).NotTo(Equal(oldPodUID))
		assertArtifact(p)
		afterArtifact := t14CurrentArtifact(p)
		afterParent := &infrastructurev1alpha1.KeaCluster{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), afterParent)).To(Succeed())
		afterCondition := meta.FindStatusCondition(afterParent.Status.Conditions, "ArtifactReconciled")
		Expect(afterArtifact.UID).To(Equal(beforeArtifact.UID))
		Expect(afterArtifact.ResourceVersion).To(Equal(beforeArtifact.ResourceVersion))
		Expect(afterParent.UID).To(Equal(beforeParent.UID))
		Expect(afterParent.Generation).To(Equal(beforeParent.Generation))
		Expect(afterCondition.LastTransitionTime).To(Equal(beforeCondition.LastTransitionTime))
	})

	It("repairs payload and reserved metadata drift introduced during downtime", func() {
		p := createCR(runtimeNamespace, "restart-drift-")
		assertArtifact(p)
		beforeParent := &infrastructurev1alpha1.KeaCluster{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), beforeParent)).To(Succeed())
		original := t14GetManager(labctx)
		DeferCleanup(func() { t14RestoreManager(original) })
		Expect(t14ScaleManager(labctx, 0)).To(Succeed())
		t14WaitStopped(labctx)
		drifted := t14CurrentArtifact(p)
		drifted.Data["keacluster-uid"] = "wrong-uid"
		drifted.Data["rogue-data"] = "remove"
		drifted.Labels["keaguard.example/artifact"] = "wrong"
		drifted.Annotations["keaguard.example/purpose"] = "wrong"
		drifted.BinaryData = map[string][]byte{"rogue-binary": []byte("remove")}
		Expect(admin.Update(labctx, drifted)).To(Succeed())
		Expect(t14SetManagerSpec(labctx, original.Spec)).To(Succeed())
		t14WaitReady(labctx)
		assertArtifact(p)
		repaired := t14CurrentArtifact(p)
		parentAfter := &infrastructurev1alpha1.KeaCluster{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), parentAfter)).To(Succeed())
		Expect(repaired.UID).To(Equal(drifted.UID))
		Expect(parentAfter.UID).To(Equal(beforeParent.UID))
		Expect(parentAfter.Generation).To(Equal(beforeParent.Generation))
	})

	It("recreates an artifact deleted during downtime without editing its parent", func() {
		p := createCR(runtimeNamespace, "restart-delete-")
		assertArtifact(p)
		beforeParent := &infrastructurev1alpha1.KeaCluster{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), beforeParent)).To(Succeed())
		beforeArtifact := t14CurrentArtifact(p)
		oldPodUID := t14GetManagerPod(labctx).UID
		original := t14GetManager(labctx)
		DeferCleanup(func() { t14RestoreManager(original) })
		Expect(t14ScaleManager(labctx, 0)).To(Succeed())
		t14WaitStopped(labctx)
		Expect(admin.Delete(labctx, beforeArtifact, client.Preconditions{UID: &beforeArtifact.UID})).To(Succeed())
		t14WaitUIDGone(client.ObjectKeyFromObject(p), beforeArtifact.UID)
		Expect(t14SetManagerSpec(labctx, original.Spec)).To(Succeed())
		t14WaitReady(labctx)
		assertArtifact(p)
		recreated := t14CurrentArtifact(p)
		parentAfter := &infrastructurev1alpha1.KeaCluster{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), parentAfter)).To(Succeed())
		Expect(recreated.UID).NotTo(Equal(beforeArtifact.UID))
		Expect(parentAfter.UID).To(Equal(beforeParent.UID))
		Expect(parentAfter.Generation).To(Equal(beforeParent.Generation))
		Expect(t14GetManagerPod(labctx).UID).NotTo(Equal(oldPodUID))
	})

	It("keeps an unowned collision untouched across restart, then recovers after fixture removal", func() {
		original := t14GetManager(labctx)
		DeferCleanup(func() { t14RestoreManager(original) })
		Expect(t14ScaleManager(labctx, 0)).To(Succeed())
		t14WaitStopped(labctx)
		collision := cm("", runtimeNamespace)
		collision.GenerateName = "restart-conflict-"
		Expect(admin.Create(labctx, collision)).To(Succeed())
		parent := cr(collision.Name, runtimeNamespace)
		Expect(admin.Create(labctx, parent)).To(Succeed())
		Expect(t14SetManagerSpec(labctx, original.Spec)).To(Succeed())
		t14WaitReady(labctx)
		Eventually(func() string { return t14ConditionReason(parent) }, 120*time.Second, time.Second).Should(Equal("OwnershipConflict"))
		unchanged := &corev1.ConfigMap{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(collision), unchanged)).To(Succeed())
		Expect(unchanged).To(Equal(collision))
		Expect(admin.Delete(labctx, collision, client.Preconditions{UID: &collision.UID})).To(Succeed())
		assertArtifact(parent)
		Expect(t14CurrentArtifact(parent).UID).NotTo(Equal(collision.UID))
	})

	It("recovers committed artifact state after status permission failure and manager restart", func() {
		originalDeployment := t14GetManager(labctx)
		originalRole := t14RemoveStatusPatch(labctx)
		DeferCleanup(func() {
			t14RestoreRoleRules(originalRole)
			t14RestoreManager(originalDeployment)
		})
		p := createCR(runtimeNamespace, "restart-status-")
		Eventually(func() error {
			actual := &corev1.ConfigMap{}
			return admin.Get(labctx, client.ObjectKeyFromObject(p), actual)
		}, 120*time.Second, time.Second).Should(Succeed())
		committed := t14CurrentArtifact(p)
		Expect(metav1.GetControllerOf(committed)).NotTo(BeNil())
		Expect(metav1.GetControllerOf(committed).UID).To(Equal(p.UID))
		Eventually(func() string {
			return strings.ToLower(managerLogs(labctx))
		}, 120*time.Second, time.Second).Should(And(ContainSubstring("forbidden"), ContainSubstring("keaclusters/status")))
		parentDuringFailure := &infrastructurev1alpha1.KeaCluster{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(p), parentDuringFailure)).To(Succeed())
		Expect(meta.FindStatusCondition(parentDuringFailure.Status.Conditions, "ArtifactReconciled")).To(BeNil())
		Expect(t14ScaleManager(labctx, 0)).To(Succeed())
		t14WaitStopped(labctx)
		t14RestoreRoleRules(originalRole)
		Expect(t14SetManagerSpec(labctx, originalDeployment.Spec)).To(Succeed())
		t14WaitReady(labctx)
		assertArtifact(p)
		Expect(t14CurrentArtifact(p).UID).To(Equal(committed.UID))
	})
})

func TestUnitT14AdmissionErrorClassification(t *testing.T) {
	ownerReferencePath := field.NewPath("metadata", "ownerReferences").Index(0).Child("apiVersion")
	expected := apierrors.NewInvalid(schema.GroupKind{Kind: "ConfigMap"}, "fixture", field.ErrorList{
		field.Invalid(ownerReferencePath, "not-a-group-version", "must be a valid group/version"),
	})
	unrelatedValidation := apierrors.NewInvalid(schema.GroupKind{Kind: "ConfigMap"}, "fixture", field.ErrorList{
		field.Required(field.NewPath("metadata", "name"), "name is required"),
	})
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "owner reference validation", err: expected, want: true},
		{name: "unrelated validation", err: unrelatedValidation},
		{name: "bad request", err: apierrors.NewBadRequest("bad request")},
		{name: "forbidden", err: apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "fixture", fmt.Errorf("denied"))},
		{name: "timeout", err: apierrors.NewTimeoutError("timed out", 1)},
		{name: "server failure", err: apierrors.NewInternalError(fmt.Errorf("server failure"))},
		{name: "connectivity", err: context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isExpectedOwnerReferenceAdmissionError(tc.err); got != tc.want {
				t.Errorf("isExpectedOwnerReferenceAdmissionError(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

var _ = Describe("KIND: Garbage collection", func() {
	It("removes the recorded dependent UID through Kubernetes GC without runtime delete permission", func() {
		p := createCR(runtimeNamespace, "gc-normal-")
		assertArtifact(p)
		child := t14CurrentArtifact(p)
		role := &rbacv1.Role{}
		Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: "keaguard-manager-role"}, role)).To(Succeed())
		for _, rule := range role.Rules {
			Expect(rule.Verbs).NotTo(ContainElement("delete"), "runtime Role must not grant delete")
		}
		fmt.Fprintf(GinkgoWriter, "GC fixture parentUID=%s childUID=%s runtimeDeleteGrant=false\n", p.UID, child.UID)
		t14DeleteParent(p)
		t14WaitUIDGone(client.ObjectKeyFromObject(child), child.UID)
	})

	It("holds the old child UID, refuses same-name replacement adoption, then accepts a new owned UID", func() {
		oldParent := createCR(runtimeNamespace, "gc-replace-")
		assertArtifact(oldParent)
		oldChild := t14CurrentArtifact(oldParent)
		oldUID := oldChild.UID
		oldChild.Finalizers = append(oldChild.Finalizers, t14HoldFinalizer)
		Expect(admin.Update(labctx, oldChild)).To(Succeed())
		Expect(admin.Delete(labctx, oldParent, client.Preconditions{UID: &oldParent.UID})).To(Succeed())
		t14WaitParentGone(client.ObjectKeyFromObject(oldParent), oldParent.UID)
		Eventual := func() *corev1.ConfigMap {
			actual := &corev1.ConfigMap{}
			Expect(admin.Get(labctx, client.ObjectKeyFromObject(oldChild), actual)).To(Succeed())
			return actual
		}
		Eventually(func() bool {
			actual := Eventual()
			return actual.UID == oldUID && actual.DeletionTimestamp != nil
		}, 120*time.Second, time.Second).Should(BeTrue())
		held := Eventual()
		Expect(held.UID).To(Equal(oldUID))
		newParent := cr(oldParent.Name, oldParent.Namespace)
		Expect(admin.Create(labctx, newParent)).To(Succeed())
		Expect(newParent.UID).NotTo(Equal(oldParent.UID))
		Eventually(func() string { return t14ConditionReason(newParent) }, 120*time.Second, time.Second).Should(Equal("OwnershipConflict"))
		stillOld := Eventual()
		Expect(stillOld.UID).To(Equal(oldUID))
		Expect(stillOld.Data).To(Equal(held.Data), "controller must not mutate the old terminating child")
		Expect(metav1.GetControllerOf(stillOld).UID).To(Equal(oldParent.UID))
		fmt.Fprintf(GinkgoWriter, "Held old child UID=%s while replacement parent UID=%s reported OwnershipConflict\n", oldUID, newParent.UID)
		t14ReleaseHoldFinalizer(client.ObjectKeyFromObject(oldChild), oldUID)
		t14WaitUIDGone(client.ObjectKeyFromObject(oldChild), oldUID)
		assertArtifact(newParent)
		replacement := t14CurrentArtifact(newParent)
		Expect(replacement.UID).NotTo(Equal(oldUID))
		Expect(metav1.GetControllerOf(replacement).UID).To(Equal(newParent.UID))
	})
})

var _ = Describe("KIND: Ownership cleanup limits", func() {
	It("separates refusal of an unowned collision from explicit orphan deletion policy", func() {
		collision := cm("", runtimeNamespace)
		collision.GenerateName = "limits-unowned-"
		Expect(admin.Create(labctx, collision)).To(Succeed())
		parent := cr(collision.Name, runtimeNamespace)
		Expect(admin.Create(labctx, parent)).To(Succeed())
		Eventually(func() string { return t14ConditionReason(parent) }, 120*time.Second, time.Second).Should(Equal("OwnershipConflict"))
		unchanged := &corev1.ConfigMap{}
		Expect(admin.Get(labctx, client.ObjectKeyFromObject(collision), unchanged)).To(Succeed())
		Expect(unchanged).To(Equal(collision))
		Expect(admin.Delete(labctx, collision, client.Preconditions{UID: &collision.UID})).To(Succeed())
		assertArtifact(parent)

		child := t14CurrentArtifact(parent)
		orphan := metav1.DeletePropagationOrphan
		t14DeleteParent(parent, &client.DeleteOptions{PropagationPolicy: &orphan})
		Eventual := func() (*corev1.ConfigMap, error) {
			actual := &corev1.ConfigMap{}
			err := admin.Get(labctx, client.ObjectKeyFromObject(child), actual)
			return actual, err
		}
		Eventually(func() bool {
			actual, err := Eventual()
			if err != nil {
				return false
			}
			return actual.UID == child.UID && metav1.GetControllerOf(actual) == nil
		}, 120*time.Second, time.Second).Should(BeTrue())
		observed, err := Eventual()
		Expect(err).NotTo(HaveOccurred())
		fmt.Fprintf(GinkgoWriter, "Explicit orphan policy left child UID=%s with %d owner references\n", observed.UID, len(observed.OwnerReferences))
		Expect(admin.Delete(labctx, observed, client.Preconditions{UID: &observed.UID})).To(Succeed())
	})

	It("records actual handling of valid dangling and malformed owner references", func() {
		dangling := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			GenerateName: "limits-dangling-", Namespace: runtimeNamespace,
			Labels: map[string]string{fixtureLabel: labCluster}, Finalizers: []string{t14HoldFinalizer},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: infrastructurev1alpha1.GroupVersion.String(), Kind: "KeaCluster", Name: "missing-t14-parent", UID: types.UID("missing-t14-parent-uid"), Controller: func() *bool { v := true; return &v }()}},
		}}
		err := admin.Create(labctx, dangling)
		if err != nil {
			if !isExpectedOwnerReferenceAdmissionError(err) {
				Fail(fmt.Sprintf("creating dangling-owner fixture failed outside owner-reference admission validation: %v", err))
				return
			}
			fmt.Fprintf(GinkgoWriter, "API rejected valid-format dangling owner reference: %v\n", err)
		} else {
			observed := ""
			Eventually(func() bool {
				current := &corev1.ConfigMap{}
				getErr := admin.Get(labctx, client.ObjectKeyFromObject(dangling), current)
				if apierrors.IsNotFound(getErr) {
					observed = "collected before inspection"
					return true
				}
				if getErr != nil {
					return false
				}
				if current.DeletionTimestamp != nil {
					observed = "deletion held by test finalizer"
					return true
				}
				if len(current.OwnerReferences) == 0 {
					observed = "owner reference removed; dependent orphaned"
					return true
				}
				return false
			}, 120*time.Second, time.Second).Should(BeTrue())
			fmt.Fprintf(GinkgoWriter, "Valid dangling reference outcome: %s\n", observed)
			current := &corev1.ConfigMap{}
			if err := admin.Get(labctx, client.ObjectKeyFromObject(dangling), current); err == nil {
				if slices.Contains(current.Finalizers, t14HoldFinalizer) {
					t14ReleaseHoldFinalizer(client.ObjectKeyFromObject(current), current.UID)
				}
				current = &corev1.ConfigMap{}
				if err := admin.Get(labctx, client.ObjectKeyFromObject(dangling), current); err == nil {
					Expect(admin.Delete(labctx, current, client.Preconditions{UID: &current.UID})).To(Succeed())
				}
			}
		}

		malformed := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			GenerateName: "limits-malformed-", Namespace: runtimeNamespace,
			Labels:          map[string]string{fixtureLabel: labCluster},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "not-a-group-version", Kind: "KeaCluster", Name: "invalid-t14-parent", UID: types.UID("invalid-t14-parent-uid")}},
		}}
		err = admin.Create(labctx, malformed)
		if err != nil {
			if !isExpectedOwnerReferenceAdmissionError(err) {
				Fail(fmt.Sprintf("creating malformed-owner fixture failed outside owner-reference admission validation: %v", err))
				return
			}
			fmt.Fprintf(GinkgoWriter, "API rejected malformed owner reference: %v\n", err)
			return
		}
		fmt.Fprintf(GinkgoWriter, "API admitted malformed owner reference; fixture UID=%s\n", malformed.UID)
		Expect(admin.Delete(labctx, malformed, client.Preconditions{UID: &malformed.UID})).To(Succeed())
	})

	It("retains an artifact while another live owner remains, then collects it", func() {
		parent := createCR(runtimeNamespace, "limits-extra-owner-")
		assertArtifact(parent)
		child := t14CurrentArtifact(parent)
		secondary := cm("", runtimeNamespace)
		secondary.GenerateName = "limits-secondary-owner-"
		Expect(admin.Create(labctx, secondary)).To(Succeed())
		child.OwnerReferences = append(child.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: secondary.Name, UID: secondary.UID})
		Expect(admin.Update(labctx, child)).To(Succeed())
		parentUID, childUID, secondaryUID := parent.UID, child.UID, secondary.UID
		t14DeleteParent(parent)
		Consistently(func() bool {
			current := &corev1.ConfigMap{}
			err := admin.Get(labctx, client.ObjectKeyFromObject(child), current)
			return err == nil && current.UID == childUID && slices.ContainsFunc(current.OwnerReferences, func(ref metav1.OwnerReference) bool {
				return ref.UID == secondaryUID
			})
		}, 3*time.Second, 300*time.Millisecond).Should(BeTrue())
		fmt.Fprintf(GinkgoWriter, "Child UID=%s survived owner UID=%s while secondary owner UID=%s remained live\n", childUID, parentUID, secondaryUID)
		Expect(admin.Delete(labctx, secondary, client.Preconditions{UID: &secondaryUID})).To(Succeed())
		t14WaitUIDGone(client.ObjectKeyFromObject(child), childUID)
	})
})
