package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestUnitM2Predicates(t *testing.T) {
	parent, names, config := m2ResourceFixture(t)
	parent.UID = types.UID("parent-uid")
	service := desiredHeadlessService(parent, names)
	statefulSet := desiredKeaStatefulSet(parent, names, config)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload-0", Namespace: parent.Namespace}}

	tests := []struct {
		name string
		pred func() bool
	}{
		{"service managed fields", func() bool {
			next := service.DeepCopy()
			next.Spec.Selector = map[string]string{"changed": "yes"}
			return servicePredicate().Update(eventUpdate(service, next))
		}},
		{"service ownership", func() bool {
			next := service.DeepCopy()
			next.OwnerReferences = nil
			return servicePredicate().Update(eventUpdate(service, next))
		}},
		{"statefulset managed fields", func() bool {
			next := statefulSet.DeepCopy()
			next.Spec.Replicas = pointerTo(int32(3))
			return statefulSetPredicate().Update(eventUpdate(statefulSet, next))
		}},
		{"statefulset status", func() bool {
			next := statefulSet.DeepCopy()
			next.Status.ReadyReplicas = 1
			return statefulSetPredicate().Update(eventUpdate(statefulSet, next))
		}},
		{"pod status", func() bool {
			next := pod.DeepCopy()
			next.Status.Phase = corev1.PodRunning
			return podPredicate().Update(eventUpdate(pod, next))
		}},
		{"pod owner change", func() bool {
			next := pod.DeepCopy()
			next.OwnerReferences = []metav1.OwnerReference{{Kind: "StatefulSet", Name: "other", UID: "other"}}
			return podPredicate().Update(eventUpdate(pod, next))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.pred() {
				t.Fatal("relevant update was suppressed")
			}
		})
	}
}

func eventUpdate(old, next client.Object) event.UpdateEvent {
	return event.UpdateEvent{ObjectOld: old, ObjectNew: next}
}

func TestUnitM2OwnerMapping(t *testing.T) {
	parent, names, config := m2ResourceFixture(t)
	parent.UID = types.UID("parent-uid")
	statefulSet := desiredKeaStatefulSet(parent, names, config)
	statefulSet.UID = types.UID("set-uid")
	controller := true
	basePod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "workload-0", Namespace: parent.Namespace,
		Labels:          map[string]string{clusterUIDLabel: string(parent.UID)},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: statefulSet.Name, UID: statefulSet.UID, Controller: &controller}},
	}}
	_, _, _, recorder, _ := m2ReconcileFixture(t, statefulSet)
	reconciler := newTestReconciler(recorder, recorder.Client, parent.Namespace)
	if got := reconciler.mapPodToKeaCluster(context.Background(), basePod); len(got) != 1 || got[0].NamespacedName != client.ObjectKeyFromObject(parent) {
		t.Fatalf("valid StatefulSet controller chain mapped to %v", got)
	}

	for _, mutate := range []struct {
		name string
		fn   func(*corev1.Pod)
	}{
		{"labels only", func(p *corev1.Pod) { p.OwnerReferences = nil }},
		{"wrong StatefulSet UID", func(p *corev1.Pod) { p.OwnerReferences[0].UID = "replacement" }},
		{"wrong StatefulSet API version", func(p *corev1.Pod) { p.OwnerReferences[0].APIVersion = "example/v1" }},
		{"wrong StatefulSet kind", func(p *corev1.Pod) { p.OwnerReferences[0].Kind = "Deployment" }},
		{"non-controller StatefulSet reference", func(p *corev1.Pod) { p.OwnerReferences[0].Controller = nil }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			pod := basePod.DeepCopy()
			mutate.fn(pod)
			if got := reconciler.mapPodToKeaCluster(context.Background(), pod); len(got) != 0 {
				t.Fatalf("invalid owner chain mapped to %v", got)
			}
		})
	}

	badSet := statefulSet.DeepCopy()
	badSet.OwnerReferences[0].UID = "old-parent"
	if err := recorder.Client.Update(context.Background(), badSet); err != nil {
		t.Fatal(err)
	}
	if got := reconciler.mapPodToKeaCluster(context.Background(), basePod); len(got) != 0 {
		t.Fatalf("stale parent owner mapped to %v", got)
	}
}

func TestUnitM2WorkloadRequeueIntervals(t *testing.T) {
	for _, test := range []struct {
		name      string
		condition metav1.Condition
		want      time.Duration
	}{
		{"healthy", metav1.Condition{Type: "WorkloadReconciled", Status: metav1.ConditionTrue}, 500 * time.Millisecond},
		{"progress", metav1.Condition{Type: "WorkloadReady", Status: metav1.ConditionFalse, Reason: "RolloutPending"}, 100 * time.Millisecond},
		{"blocked", metav1.Condition{Type: "WorkloadReconciled", Status: metav1.ConditionFalse, Reason: "OwnershipConflict"}, 250 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := workloadRequeue([]metav1.Condition{test.condition}, 100*time.Millisecond, 250*time.Millisecond, 500*time.Millisecond); got != test.want {
				t.Fatalf("requeue=%s want %s", got, test.want)
			}
		})
	}
}

func m2WatchParent() (*infrastructurev1alpha1.KeaCluster, client.ObjectKey) {
	return m2WatchParentWithWorkload(true)
}

func m2WatchParentWithWorkload(enabled bool) (*infrastructurev1alpha1.KeaCluster, client.ObjectKey) {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "m2-watch-"}}
	Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "watched", Namespace: namespace.Name}}
	if enabled {
		severity := "INFO"
		parent.Spec = &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true, LoggingSeverity: &severity}}
	}
	Expect(k8sClient.Create(ctx, parent)).To(Succeed())
	key := client.ObjectKeyFromObject(parent)
	DeferCleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.Pod{}, client.InNamespace(namespace.Name))).To(Succeed())
		Expect(k8sClient.DeleteAllOf(cleanupCtx, &appsv1.StatefulSet{}, client.InNamespace(namespace.Name))).To(Succeed())
		Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.Service{}, client.InNamespace(namespace.Name))).To(Succeed())
		Expect(k8sClient.DeleteAllOf(cleanupCtx, &corev1.ConfigMap{}, client.InNamespace(namespace.Name))).To(Succeed())
		Expect(k8sClient.DeleteAllOf(cleanupCtx, &infrastructurev1alpha1.KeaCluster{}, client.InNamespace(namespace.Name))).To(Succeed())
		Expect(k8sClient.Delete(cleanupCtx, namespace)).To(Succeed())
	})
	return parent, key
}

func m2WatchResourceKeys(key client.ObjectKey) workloadNames {
	parent := &infrastructurev1alpha1.KeaCluster{}
	Expect(k8sClient.Get(ctx, key, parent)).To(Succeed())
	return namesFor(parent)
}

func m2WatchResourcesReady(key client.ObjectKey) {
	Eventually(func() bool {
		parent := &infrastructurev1alpha1.KeaCluster{}
		if k8sClient.Get(ctx, key, parent) != nil {
			return false
		}
		condition := meta.FindStatusCondition(parent.Status.Conditions, "WorkloadReconciled")
		if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "ResourcesInSync" {
			return false
		}
		names := namesFor(parent)
		for _, object := range []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: names.ConfigMap, Namespace: key.Namespace}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: names.Service, Namespace: key.Namespace}},
			&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: names.StatefulSet, Namespace: key.Namespace}},
		} {
			if k8sClient.Get(ctx, client.ObjectKeyFromObject(object), object) != nil {
				return false
			}
		}
		return true
	}, 20*time.Second, 20*time.Millisecond).Should(BeTrue())
}

func m2WatchEventAfter(c *managerRecordingClient, previous []client.ObjectKey, key client.ObjectKey) {
	Eventually(func() bool {
		requests := c.requestSnapshot()
		if len(requests) <= len(previous) {
			return false
		}
		for _, got := range requests[len(previous):] {
			if got == key {
				return true
			}
		}
		return false
	}, 10*time.Second, 20*time.Millisecond).Should(BeTrue(), "actual manager handler should enqueue %s", key)
}

var _ = Describe("M2: Watches", func() {
	It("maps old and new Pod owners and watches managed resource drift before timers", func() {
		parent, key := m2WatchParent()
		names := m2WatchResourceKeys(key)
		_, reconciler, stop, err := startTestManager(ctx, key.Namespace, key.Name, time.Hour, time.Hour, false)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(stop()).To(Succeed()) })
		c := reconciler.Client.(*managerRecordingClient)
		m2WatchResourcesReady(key)
		watchSettled(c)

		configMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.ConfigMap}, configMap)).To(Succeed())
		before := c.requestSnapshot()
		configMap.Data["kea-dhcp4.conf"] = "drift"
		Expect(k8sClient.Update(ctx, configMap)).To(Succeed())
		m2WatchEventAfter(c, before, key)
		Eventually(func() string {
			observed := &corev1.ConfigMap{}
			if k8sClient.Get(ctx, client.ObjectKeyFromObject(configMap), observed) != nil {
				return ""
			}
			return observed.Data["kea-dhcp4.conf"]
		}, 10*time.Second, 20*time.Millisecond).ShouldNot(Equal("drift"))

		service := &corev1.Service{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.Service}, service)).To(Succeed())
		before = c.requestSnapshot()
		service.Spec.Selector = map[string]string{"drift": "yes"}
		Expect(k8sClient.Update(ctx, service)).To(Succeed())
		m2WatchEventAfter(c, before, key)
		Eventually(func() map[string]string {
			observed := &corev1.Service{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(service), observed)).To(Succeed())
			return observed.Spec.Selector
		}, 10*time.Second, 20*time.Millisecond).Should(Equal(map[string]string{clusterUIDLabel: string(parent.UID)}))

		set := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.StatefulSet}, set)).To(Succeed())
		before = c.requestSnapshot()
		set.Spec.Replicas = pointerTo(int32(3))
		Expect(k8sClient.Update(ctx, set)).To(Succeed())
		m2WatchEventAfter(c, before, key)
		Eventually(func() int32 {
			observed := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(set), observed)).To(Succeed())
			return *observed.Spec.Replicas
		}, 10*time.Second, 20*time.Millisecond).Should(Equal(int32(2)))

		set = &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.StatefulSet}, set)).To(Succeed())
		controller := true
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: names.StatefulSet + "-0", Namespace: key.Namespace, OwnerReferences: []metav1.OwnerReference{{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "StatefulSet", Name: set.Name, UID: set.UID, Controller: &controller}}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "probe", Image: keaDHCP4Image}}}}
		before = c.requestSnapshot()
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		m2WatchEventAfter(c, before, key)
		before = c.requestSnapshot()
		pod = &corev1.Pod{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.StatefulSet + "-0"}, pod)).To(Succeed())
		pod.OwnerReferences = nil
		Expect(k8sClient.Update(ctx, pod)).To(Succeed())
		m2WatchEventAfter(c, before, key) // The old object maps even though the new owner is gone.
	})

	for _, kind := range []string{"ConfigMap", "Service", "StatefulSet"} {
		It(fmt.Sprintf("delivers owner removal for former %s owner", kind), func() {
			parent, key := m2WatchParent()
			_, reconciler, stop, err := startTestManager(ctx, key.Namespace, key.Name, time.Hour, time.Hour, false)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { Expect(stop()).To(Succeed()) })
			c := reconciler.Client.(*managerRecordingClient)
			m2WatchResourcesReady(key)
			watchSettled(c)
			names := namesFor(parent)
			var object client.Object
			switch kind {
			case "ConfigMap":
				object = &corev1.ConfigMap{}
				object.SetName(names.ConfigMap)
			case "Service":
				object = &corev1.Service{}
				object.SetName(names.Service)
			case "StatefulSet":
				object = &appsv1.StatefulSet{}
				object.SetName(names.StatefulSet)
			}
			object.SetNamespace(key.Namespace)
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(object), object)).To(Succeed())
			before := c.requestSnapshot()
			object.SetOwnerReferences(nil)
			Expect(k8sClient.Update(ctx, object)).To(Succeed())
			m2WatchEventAfter(c, before, key)
			Eventually(func() string {
				stored := &infrastructurev1alpha1.KeaCluster{}
				Expect(k8sClient.Get(ctx, key, stored)).To(Succeed())
				condition := meta.FindStatusCondition(stored.Status.Conditions, "WorkloadReconciled")
				if condition == nil {
					return ""
				}
				return condition.Reason
			}, 10*time.Second, 20*time.Millisecond).Should(Equal("OwnershipConflict"))
			Expect(c.otherWrites()).To(Equal(4), "only the four initial resources were created")
		})
	}

	It("recovers progress, blocker and healthy timers when all child events are suppressed", func() {
		parent, key := m2WatchParent()
		_, reconciler, stop, err := startTestManager(ctx, key.Namespace, key.Name, 150*time.Millisecond, 80*time.Millisecond, true, 100*time.Millisecond)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(stop()).To(Succeed()) })
		c := reconciler.Client.(*managerRecordingClient)
		m2WatchResourcesReady(key) // One-second post-action progress timers build the complete graph.
		progressRequests := c.requests.Load()
		Eventually(func() int64 { return c.requests.Load() }, 2*time.Second, 20*time.Millisecond).Should(BeNumerically(">", progressRequests))
		healthyRequests := c.requests.Load()
		Eventually(func() int64 { return c.requests.Load() }, 2*time.Second, 20*time.Millisecond).Should(BeNumerically(">", healthyRequests))
		writes, status := c.otherWrites(), c.statusPatches()
		Consistently(func() int { return c.otherWrites() + c.statusPatches() }, 300*time.Millisecond, 20*time.Millisecond).Should(Equal(writes + status))
		Expect(c.otherWrites()).To(Equal(writes))
		Expect(c.statusPatches()).To(Equal(status))

		cm := &corev1.ConfigMap{}
		names := namesFor(parent)
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: names.ConfigMap}, cm)).To(Succeed())
		cm.OwnerReferences = nil
		Expect(k8sClient.Update(ctx, cm)).To(Succeed())
		Eventually(func() string {
			stored := &infrastructurev1alpha1.KeaCluster{}
			Expect(k8sClient.Get(ctx, key, stored)).To(Succeed())
			condition := meta.FindStatusCondition(stored.Status.Conditions, "WorkloadReconciled")
			if condition == nil {
				return ""
			}
			return condition.Reason
		}, 5*time.Second, 20*time.Millisecond).Should(Equal("OwnershipConflict"))
		blockedRequests := c.requests.Load()
		Eventually(func() int64 { return c.requests.Load() }, 5*time.Second, 20*time.Millisecond).Should(BeNumerically(">", blockedRequests))
		Expect(c.otherWrites()).To(Equal(writes))
	})

})
