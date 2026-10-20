package e2e

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The dry-run object is copied from the operator's actual PodTemplate. Only
// test-owned metadata is supplied; it cannot match the StatefulSet selector.
func m2AdmissionDryRunPod(template *corev1.PodTemplateSpec, removeRaw bool) (*corev1.Pod, error) {
	if template == nil {
		return nil, fmt.Errorf("admission dry-run lacks the operator PodTemplate")
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{GenerateName: "m2-psa-dry-run-", Namespace: m2LabProfile.runtimeNamespace,
		Labels: map[string]string{m2LabProfile.fixtureLabel: m2LabProfile.cluster}}, Spec: *template.Spec.DeepCopy()}
	if !removeRaw {
		return pod, nil
	}
	removed := 0
	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		if container.Name != "dhcp4" || container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
			continue
		}
		add := container.SecurityContext.Capabilities.Add
		kept := make([]corev1.Capability, 0, len(add))
		for _, capability := range add {
			if capability == corev1.Capability("NET_RAW") {
				removed++
				continue
			}
			kept = append(kept, capability)
		}
		container.SecurityContext.Capabilities.Add = kept
	}
	if removed != 1 {
		return nil, fmt.Errorf("operator template did not contain exactly one DHCPv4 NET_RAW capability")
	}
	return pod, nil
}

func TestUnitM2AdmissionDryRunControl(t *testing.T) {
	template := &corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"keaguard.example/cluster-uid": "workload"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "dhcp4", SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_BIND_SERVICE", "NET_RAW"}}}}, {Name: "dhcp6", SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_BIND_SERVICE"}}}}}}}
	actual, err := m2AdmissionDryRunPod(template, false)
	if err != nil {
		t.Fatal(err)
	}
	control, err := m2AdmissionDryRunPod(template, true)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Labels["keaguard.example/cluster-uid"] != "" || len(actual.OwnerReferences) != 0 || actual.Namespace != m2LabProfile.runtimeNamespace ||
		reflect.DeepEqual(actual.Spec, control.Spec) || len(actual.Spec.Containers[0].SecurityContext.Capabilities.Add) != 2 ||
		len(control.Spec.Containers[0].SecurityContext.Capabilities.Add) != 1 ||
		!reflect.DeepEqual(actual.Spec.Containers[1], control.Spec.Containers[1]) ||
		!reflect.DeepEqual(template.Spec.Containers[0].SecurityContext.Capabilities.Add, []corev1.Capability{"NET_BIND_SERVICE", "NET_RAW"}) {
		t.Fatalf("dry-run control changed metadata or fields other than DHCPv4 NET_RAW: actual=%+v control=%+v", actual, control)
	}
	if _, err := m2AdmissionDryRunPod(&corev1.PodTemplateSpec{}, true); err == nil {
		t.Fatal("template without NET_RAW was accepted as the differential control")
	}
}

var _ = func() bool {
	if selectedProfile.milestone != "m2" {
		return true
	}
	return Describe("M2: Admission", func() {
		for _, policy := range []string{"baseline", "restricted"} {
			policy := policy
			m2It("rejects NET_RAW under "+policy+" and recovers under the reviewed policy", func() {
				Expect(m2ActiveScenario).NotTo(BeNil())
				Expect(m2VerifyNamespaceReceipt(labctx)).To(Succeed())
				var existing appsv1.StatefulSetList
				Expect(admin.List(labctx, &existing, client.InNamespace(runtimeNamespace))).To(Succeed())
				Expect(existing.Items).To(BeEmpty(), "admission fault requires no active Kea workload")

				source := cr("", runtimeNamespace)
				source.GenerateName = "admission-template-"
				source.Spec = &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true}}
				Expect(m2CreateObject(labctx, source, nil)).To(Succeed())
				_, _, setName := m2NamesFor(source)
				var generated appsv1.StatefulSet
				Eventually(func(g Gomega) {
					g.Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: setName}, &generated)).To(Succeed())
					g.Expect(generated.UID).NotTo(BeEmpty())
				}, 120*time.Second, time.Second).Should(Succeed())
				template := generated.Spec.Template.DeepCopy()
				current := &infrastructurev1alpha1.KeaCluster{}
				Expect(admin.Get(labctx, client.ObjectKeyFromObject(source), current)).To(Succeed())
				current.Spec.Workload.Enabled = false
				Expect(m2UpdateObject(labctx, current, "absent")).To(Succeed())
				identity, err := m2IdentityFor(source)
				Expect(err).NotTo(HaveOccurred())
				Expect(m2WaitCaseWorkloadAbsent(labctx, m2Fixture{m2FixtureIdentity: identity, Created: true})).To(Succeed())

				pod, err := m2AdmissionDryRunPod(template, false)
				Expect(err).NotTo(HaveOccurred())
				control, err := m2AdmissionDryRunPod(template, true)
				Expect(err).NotTo(HaveOccurred())
				_, err = adminset.CoreV1().Pods(runtimeNamespace).Create(labctx, pod, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
				Expect(err).NotTo(HaveOccurred(), "reviewed positive namespace must admit the actual template shape")

				fault := map[string]string{"pod-security.kubernetes.io/enforce": policy, "pod-security.kubernetes.io/enforce-version": "v1.37"}
				Expect(m2ActiveScenario.setNamespacePolicy(labctx, runtimeNamespace, fault)).To(Succeed())
				_, err = adminset.CoreV1().Pods(runtimeNamespace).Create(labctx, pod, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
				Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected typed PodSecurity Forbidden, got %v", err)
				Expect(err.Error()).To(ContainSubstring("NET_RAW"))
				_, err = adminset.CoreV1().Pods(runtimeNamespace).Create(labctx, control, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
				Expect(err).NotTo(HaveOccurred(), "NET_RAW-only dry-run control should pass policy")

				blocked := cr("", runtimeNamespace)
				blocked.GenerateName = "admission-blocked-"
				blocked.Spec = &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true}}
				Expect(m2CreateObject(labctx, blocked, nil)).To(Succeed())
				_, _, blockedSetName := m2NamesFor(blocked)
				var blockedSet appsv1.StatefulSet
				Eventually(func(g Gomega) {
					g.Expect(admin.Get(labctx, client.ObjectKey{Namespace: runtimeNamespace, Name: blockedSetName}, &blockedSet)).To(Succeed())
					g.Expect(blockedSet.UID).NotTo(BeEmpty())
				}, 120*time.Second, time.Second).Should(Succeed())
				Eventually(func(g Gomega) {
					events, listErr := adminset.CoreV1().Events(runtimeNamespace).List(labctx, metav1.ListOptions{})
					g.Expect(listErr).NotTo(HaveOccurred())
					found := false
					for _, event := range events.Items {
						if event.InvolvedObject.UID == blockedSet.UID && event.Reason == "FailedCreate" && strings.Contains(event.Message, "NET_RAW") {
							found = true
						}
					}
					g.Expect(found).To(BeTrue(), "native StatefulSet FailedCreate/NET_RAW event was not observed")
				}, 120*time.Second, 2*time.Second).Should(Succeed())
				Eventually(func(g Gomega) {
					observed := &infrastructurev1alpha1.KeaCluster{}
					g.Expect(admin.Get(labctx, client.ObjectKeyFromObject(blocked), observed)).To(Succeed())
					reconciled := meta.FindStatusCondition(observed.Status.Conditions, "WorkloadReconciled")
					ready := meta.FindStatusCondition(observed.Status.Conditions, "WorkloadReady")
					g.Expect(reconciled).NotTo(BeNil())
					g.Expect(ready).NotTo(BeNil())
					if reconciled != nil && ready != nil {
						g.Expect(reconciled.Status).To(Equal(metav1.ConditionTrue))
						g.Expect(reconciled.Reason).To(Equal("ResourcesInSync"))
						g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
						g.Expect(ready.Reason).To(Equal("RolloutPending"))
					}
					pods := &corev1.PodList{}
					g.Expect(admin.List(labctx, pods, client.InNamespace(runtimeNamespace), client.MatchingLabels{"keaguard.example/cluster-uid": string(blocked.UID)})).To(Succeed())
					g.Expect(pods.Items).To(BeEmpty())
				}, 90*time.Second, 2*time.Second).Should(Succeed())
				actual := &corev1.Namespace{}
				Expect(admin.Get(labctx, client.ObjectKey{Name: runtimeNamespace}, actual)).To(Succeed())
				Expect(actual.UID).To(Equal(types.UID(m2ActiveScenario.NamespaceUIDs[runtimeNamespace])))
				Expect(policyLabels(actual.Labels)).To(Equal(fault))

				Expect(m2RestoreNamespacePolicy(labctx, m2ActiveScenario.NamespaceSnapshots[runtimeNamespace], fault)).To(Succeed())
				Expect(m2VerifyNamespaceReceipt(labctx)).To(Succeed())
				Eventually(func(g Gomega) {
					observed := &infrastructurev1alpha1.KeaCluster{}
					g.Expect(admin.Get(labctx, client.ObjectKeyFromObject(blocked), observed)).To(Succeed())
					ready := meta.FindStatusCondition(observed.Status.Conditions, "WorkloadReady")
					g.Expect(ready).NotTo(BeNil())
					if ready != nil {
						g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
						g.Expect(ready.Reason).To(Equal("ProcessesHealthy"))
					}
				}, 120*time.Second, 2*time.Second).Should(Succeed())
				current = &infrastructurev1alpha1.KeaCluster{}
				Expect(admin.Get(labctx, client.ObjectKeyFromObject(blocked), current)).To(Succeed())
				current.Spec.Workload.Enabled = false
				Expect(m2UpdateObject(labctx, current, "absent")).To(Succeed())
				blockedIdentity, idErr := m2IdentityFor(blocked)
				Expect(idErr).NotTo(HaveOccurred())
				Expect(m2WaitCaseWorkloadAbsent(labctx, m2Fixture{m2FixtureIdentity: blockedIdentity, Created: true})).To(Succeed())
			})
		}
	})
}()
