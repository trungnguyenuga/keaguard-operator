/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
)

func m2ResourceFixture(t *testing.T) (*infrastructurev1alpha1.KeaCluster, workloadNames, workloadConfig) {
	t.Helper()
	severity := "INFO"
	parent := &infrastructurev1alpha1.KeaCluster{ObjectMeta: metav1.ObjectMeta{Name: "edge.example", Namespace: "lab", UID: types.UID("parent-uid"), Generation: 7}}
	parent.Spec = &infrastructurev1alpha1.KeaClusterSpec{Workload: &infrastructurev1alpha1.KeaWorkloadSpec{Enabled: true, LoggingSeverity: &severity}}
	names := namesFor(parent)
	config, err := generateKeaConfig(severity)
	if err != nil {
		t.Fatal(err)
	}
	return parent, names, config
}

func TestUnitM2DesiredResources(t *testing.T) {
	parent, names, config := m2ResourceFixture(t)
	if workloadConfigNameCollides(parent, names) {
		t.Fatal("ordinary derived configuration name collided")
	}
	fakeCollision := names
	fakeCollision.ConfigMap = parent.Name
	if !workloadConfigNameCollides(parent, fakeCollision) {
		t.Fatal("explicit identity/config-name collision fixture was not detected")
	}
	configMap := desiredKeaConfig(parent, names, config)
	assertChildOwner(t, configMap.OwnerReferences, parent)
	if configMap.Name != names.ConfigMap || configMap.Namespace != parent.Namespace || configMap.Labels[clusterUIDLabel] != string(parent.UID) || configMap.Labels[componentLabel] != "configuration" || len(configMap.Annotations) != 0 {
		t.Fatalf("configuration metadata = %#v", configMap.ObjectMeta)
	}
	if len(configMap.Data) != 2 || configMap.Data["kea-dhcp4.conf"] != config.DHCP4 || configMap.Data["kea-dhcp6.conf"] != config.DHCP6 || len(configMap.BinaryData) != 0 {
		t.Fatalf("configuration data = %#v / %#v", configMap.Data, configMap.BinaryData)
	}

	service := desiredHeadlessService(parent, names)
	assertChildOwner(t, service.OwnerReferences, parent)
	if service.Name != names.Service || service.Namespace != parent.Namespace || service.Spec.Type != corev1.ServiceTypeClusterIP || service.Spec.ClusterIP != corev1.ClusterIPNone || len(service.Spec.Ports) != 0 || service.Spec.PublishNotReadyAddresses || !reflect.DeepEqual(service.Spec.Selector, map[string]string{clusterUIDLabel: string(parent.UID)}) {
		t.Fatalf("headless service = %#v", service)
	}
	if service.Spec.ExternalName != "" || len(service.Spec.ExternalIPs) != 0 || service.Spec.LoadBalancerIP != "" || len(service.Spec.LoadBalancerSourceRanges) != 0 || service.Spec.AllocateLoadBalancerNodePorts != nil {
		t.Fatalf("service has external exposure fields: %#v", service.Spec)
	}

	statefulSet := desiredKeaStatefulSet(parent, names, config)
	assertChildOwner(t, statefulSet.OwnerReferences, parent)
	assertKeaStatefulSet(t, statefulSet, parent, names, config)
	if statefulSet.Name != names.StatefulSet || statefulSet.Namespace != parent.Namespace || statefulSet.Spec.Replicas == nil || *statefulSet.Spec.Replicas != 2 || statefulSet.Spec.ServiceName != names.Service || statefulSet.Spec.MinReadySeconds != 5 || statefulSet.Spec.RevisionHistoryLimit == nil || *statefulSet.Spec.RevisionHistoryLimit != 2 || statefulSet.Spec.Ordinals == nil || statefulSet.Spec.Ordinals.Start != 0 || statefulSet.Spec.VolumeClaimTemplates != nil {
		t.Fatalf("statefulset top-level contract = %#v", statefulSet.Spec)
	}
	if !reflect.DeepEqual(statefulSet.Spec.Selector.MatchLabels, map[string]string{clusterUIDLabel: string(parent.UID)}) || statefulSet.Spec.Template.Labels[clusterUIDLabel] != string(parent.UID) || statefulSet.Spec.Template.Labels[componentLabel] != "workload" || statefulSet.Spec.Template.Annotations[configHashAnnotation] != config.Hash {
		t.Fatalf("statefulset selector/template metadata = %#v / %#v", statefulSet.Spec.Selector, statefulSet.Spec.Template.ObjectMeta)
	}
}

func TestUnitM2ManagedFields(t *testing.T) {
	parent, names, config := m2ResourceFixture(t)
	t.Run("configuration managed fields", func(t *testing.T) {
		desired := desiredKeaConfig(parent, names, config)
		mutations := map[string]func(*corev1.ConfigMap){
			"data":            func(v *corev1.ConfigMap) { v.Data["kea-dhcp4.conf"] += " " },
			"extra data":      func(v *corev1.ConfigMap) { v.Data["unexpected"] = "x" },
			"binary data":     func(v *corev1.ConfigMap) { v.BinaryData = map[string][]byte{"x": {1}} },
			"reserved label":  func(v *corev1.ConfigMap) { v.Labels[clusterUIDLabel] = "wrong" },
			"component label": func(v *corev1.ConfigMap) { v.Labels[componentLabel] = "wrong" },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				actual := desired.DeepCopy()
				mutate(actual)
				if managedConfigurationEqual(actual, desired) {
					t.Fatal("managed drift was missed")
				}
				before := actual.DeepCopy()
				target := actual.DeepCopy()
				setManagedConfiguration(target, desired)
				if !managedConfigurationEqual(target, desired) {
					t.Fatal("managed repair did not converge")
				}
				if !reflect.DeepEqual(actual, before) {
					t.Fatal("setter mutated source")
				}
			})
		}
		t.Run("unrelated annotations are preserved", func(t *testing.T) {
			actual := desired.DeepCopy()
			actual.Annotations = map[string]string{"external.example/note": "keep"}
			actual.Labels["external.example/label"] = "keep"
			actual.ResourceVersion = "17"
			actual.Finalizers = []string{"external.example/finalizer"}
			actual.OwnerReferences = append(actual.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "extra", UID: types.UID("extra")})
			before := actual.DeepCopy()
			target := actual.DeepCopy()
			setManagedConfiguration(target, desired)
			if !reflect.DeepEqual(actual, before) || target.Annotations["external.example/note"] != "keep" || target.Labels["external.example/label"] != "keep" || target.ResourceVersion != "17" || !reflect.DeepEqual(target.Finalizers, before.Finalizers) || !reflect.DeepEqual(target.OwnerReferences, before.OwnerReferences) {
				t.Fatal("configuration setter changed unrelated object metadata")
			}
		})
	})
	t.Run("service managed fields and API defaults", func(t *testing.T) {
		desired := desiredHeadlessService(parent, names)
		mutations := map[string]func(*corev1.Service){
			"selector":                func(v *corev1.Service) { v.Spec.Selector[clusterUIDLabel] = "wrong" },
			"cluster uid label":       func(v *corev1.Service) { v.Labels[clusterUIDLabel] = "wrong" },
			"component label":         func(v *corev1.Service) { v.Labels[componentLabel] = "wrong" },
			"type":                    func(v *corev1.Service) { v.Spec.Type = corev1.ServiceTypeNodePort },
			"ports":                   func(v *corev1.Service) { v.Spec.Ports = []corev1.ServicePort{{Port: 67, Protocol: corev1.ProtocolUDP}} },
			"publish not ready":       func(v *corev1.Service) { v.Spec.PublishNotReadyAddresses = true },
			"external name":           func(v *corev1.Service) { v.Spec.ExternalName = "foreign.example" },
			"external IPs":            func(v *corev1.Service) { v.Spec.ExternalIPs = []string{"192.0.2.1"} },
			"load balancer IP":        func(v *corev1.Service) { v.Spec.LoadBalancerIP = "192.0.2.2" },
			"source ranges":           func(v *corev1.Service) { v.Spec.LoadBalancerSourceRanges = []string{"0.0.0.0/0"} },
			"allocate node ports":     func(v *corev1.Service) { v.Spec.AllocateLoadBalancerNodePorts = ptr(true) },
			"external traffic policy": func(v *corev1.Service) { v.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal },
			"health check port":       func(v *corev1.Service) { v.Spec.HealthCheckNodePort = 32000 },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				actual := desired.DeepCopy()
				mutate(actual)
				if managedServiceEqual(actual, desired) {
					t.Fatal("managed drift was missed")
				}
				before := actual.DeepCopy()
				target := actual.DeepCopy()
				setManagedService(target, desired)
				if !managedServiceEqual(target, desired) {
					t.Fatal("managed repair did not converge")
				}
				if !reflect.DeepEqual(actual, before) {
					t.Fatal("setter mutated source")
				}
			})
		}
		actual := desired.DeepCopy()
		actual.Spec.Ports = []corev1.ServicePort{}
		actual.Spec.ExternalIPs = []string{}
		actual.Spec.LoadBalancerSourceRanges = []string{}
		actual.Spec.ClusterIPs = []string{corev1.ClusterIPNone}
		actual.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol}
		actual.Spec.IPFamilyPolicy = ptr(corev1.IPFamilyPolicySingleStack)
		actual.Spec.InternalTrafficPolicy = ptr(corev1.ServiceInternalTrafficPolicyCluster)
		actual.Spec.SessionAffinity = corev1.ServiceAffinityNone
		if !managedServiceEqual(actual, desired) {
			t.Fatal("harmless API defaults were treated as drift")
		}
		t.Run("setter preserves allocation defaults and unrelated metadata", func(t *testing.T) {
			actual := desired.DeepCopy()
			actual.Spec.ClusterIPs = []string{corev1.ClusterIPNone}
			actual.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol}
			actual.Spec.IPFamilyPolicy = ptr(corev1.IPFamilyPolicySingleStack)
			actual.Spec.InternalTrafficPolicy = ptr(corev1.ServiceInternalTrafficPolicyCluster)
			actual.Spec.SessionAffinity = corev1.ServiceAffinityNone
			actual.ResourceVersion = "21"
			actual.Finalizers = []string{"external.example/hold"}
			actual.Labels["external.example/label"] = "keep"
			actual.Annotations = map[string]string{"external.example/note": "keep"}
			actual.Spec.Type = corev1.ServiceTypeNodePort
			before := actual.DeepCopy()
			target := actual.DeepCopy()
			setManagedService(target, desired)
			if !reflect.DeepEqual(actual, before) || target.ResourceVersion != "21" || !reflect.DeepEqual(target.Finalizers, before.Finalizers) || target.Labels["external.example/label"] != "keep" || target.Annotations["external.example/note"] != "keep" || !reflect.DeepEqual(target.Spec.ClusterIPs, before.Spec.ClusterIPs) || !reflect.DeepEqual(target.Spec.IPFamilies, before.Spec.IPFamilies) || !reflect.DeepEqual(target.Spec.IPFamilyPolicy, before.Spec.IPFamilyPolicy) || !reflect.DeepEqual(target.Spec.InternalTrafficPolicy, before.Spec.InternalTrafficPolicy) || target.Spec.SessionAffinity != before.Spec.SessionAffinity {
				t.Fatal("service setter changed API defaults or unrelated metadata")
			}
		})
	})
	t.Run("statefulset managed fields", func(t *testing.T) {
		desired := desiredKeaStatefulSet(parent, names, config)
		mutations := map[string]func(*appsv1.StatefulSet){
			"cluster uid label": func(v *appsv1.StatefulSet) { v.Labels[clusterUIDLabel] = "wrong" },
			"component label":   func(v *appsv1.StatefulSet) { v.Labels[componentLabel] = "wrong" },
			"pod uid label":     func(v *appsv1.StatefulSet) { v.Spec.Template.Labels[clusterUIDLabel] = "wrong" },
			"pod component label": func(v *appsv1.StatefulSet) {
				v.Spec.Template.Labels[componentLabel] = "wrong"
			},
			"config hash annotation": func(v *appsv1.StatefulSet) { v.Spec.Template.Annotations[configHashAnnotation] = "wrong" },
			"replicas":               func(v *appsv1.StatefulSet) { *v.Spec.Replicas = 3 },
			"pod management":         func(v *appsv1.StatefulSet) { v.Spec.PodManagementPolicy = appsv1.ParallelPodManagement },
			"update type":            func(v *appsv1.StatefulSet) { v.Spec.UpdateStrategy.Type = appsv1.OnDeleteStatefulSetStrategyType },
			"partition":              func(v *appsv1.StatefulSet) { *v.Spec.UpdateStrategy.RollingUpdate.Partition = 1 },
			"minimum ready":          func(v *appsv1.StatefulSet) { v.Spec.MinReadySeconds = 6 },
			"revision history":       func(v *appsv1.StatefulSet) { *v.Spec.RevisionHistoryLimit = 3 },
			"ordinal start":          func(v *appsv1.StatefulSet) { v.Spec.Ordinals.Start = 1 },
			"node selector":          func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.NodeSelector["kubernetes.io/arch"] = "arm64" },
			"restart policy":         func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyNever },
			"termination grace":      func(v *appsv1.StatefulSet) { *v.Spec.Template.Spec.TerminationGracePeriodSeconds = 31 },
			"DNS policy":             func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.DNSPolicy = corev1.DNSDefault },
			"service account":        func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.ServiceAccountName = "other" },
			"automount token":        func(v *appsv1.StatefulSet) { *v.Spec.Template.Spec.AutomountServiceAccountToken = true },
			"service links":          func(v *appsv1.StatefulSet) { *v.Spec.Template.Spec.EnableServiceLinks = true },
			"pod user":               func(v *appsv1.StatefulSet) { *v.Spec.Template.Spec.SecurityContext.RunAsUser = 101 },
			"pod seccomp": func(v *appsv1.StatefulSet) {
				v.Spec.Template.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
			},
			"container image":   func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.Containers[0].Image = "wrong" },
			"image pull policy": func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.Containers[0].ImagePullPolicy = corev1.PullAlways },
			"command":           func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.Containers[0].Command[0] = "/bin/bash" },
			"environment":       func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.Containers[0].Env[0].Value = "wrong" },
			"resources": func(v *appsv1.StatefulSet) {
				limits := v.Spec.Template.Spec.Containers[0].Resources.Limits
				memory := limits[corev1.ResourceMemory]
				memory.Set(1 << 20)
				limits[corev1.ResourceMemory] = memory
			},
			"capabilities": func(v *appsv1.StatefulSet) {
				v.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}
			},
			"volume mounts":   func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath = "/tmp" },
			"startup probe":   func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.Containers[0].StartupProbe.FailureThreshold++ },
			"readiness probe": func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.Containers[0].ReadinessProbe.PeriodSeconds++ },
			"liveness probe":  func(v *appsv1.StatefulSet) { v.Spec.Template.Spec.Containers[0].LivenessProbe.FailureThreshold++ },
			"injected sidecar": func(v *appsv1.StatefulSet) {
				v.Spec.Template.Spec.Containers = append(v.Spec.Template.Spec.Containers, corev1.Container{Name: "injected"})
			},
			"volume": func(v *appsv1.StatefulSet) {
				changed := resource.MustParse("1Mi")
				v.Spec.Template.Spec.Volumes[0].EmptyDir.SizeLimit = &changed
			},
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				actual := desired.DeepCopy()
				mutate(actual)
				if managedStatefulSetEqual(actual, desired) {
					t.Fatal("managed drift was missed")
				}
				before := actual.DeepCopy()
				target := actual.DeepCopy()
				setManagedStatefulSet(target, desired)
				if !managedStatefulSetEqual(target, desired) {
					t.Fatal("managed repair did not converge")
				}
				if !reflect.DeepEqual(actual, before) {
					t.Fatal("setter mutated source")
				}
			})
		}
		t.Run("nil and API defaults normalize", func(t *testing.T) {
			actual := desired.DeepCopy()
			actual.Spec.PodManagementPolicy = ""
			actual.Spec.UpdateStrategy.Type = ""
			actual.Spec.UpdateStrategy.RollingUpdate = nil
			actual.Spec.Ordinals = nil
			actual.Spec.Template.Spec.SchedulerName = ""
			actual.Spec.Template.Spec.ServiceAccountName = ""
			actual.Spec.Template.Spec.TerminationGracePeriodSeconds = nil
			actual.Spec.Template.Spec.Containers[0].ImagePullPolicy = ""
			actual.Spec.Template.Spec.Containers[0].TerminationMessagePath = ""
			actual.Spec.Template.Spec.Containers[0].TerminationMessagePolicy = ""
			actual.Spec.Template.Spec.Containers[0].Ports = []corev1.ContainerPort{}
			actual.Spec.Template.Spec.DeprecatedServiceAccount = "default"
			actual.Spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{MaxUnavailable: pointerTo(intstr.FromInt32(1))}
			actual.Spec.PersistentVolumeClaimRetentionPolicy = &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
				WhenDeleted: appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
				WhenScaled:  appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
			}
			if !managedStatefulSetEqual(actual, desired) {
				t.Fatal("nil/empty equivalents or known API defaults were treated as drift")
			}
		})
		t.Run("setter preserves status and unrelated metadata", func(t *testing.T) {
			actual := desired.DeepCopy()
			actual.ResourceVersion = "31"
			actual.Finalizers = []string{"external.example/hold"}
			actual.OwnerReferences = append(actual.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "extra", UID: types.UID("extra")})
			actual.Labels["external.example/object"] = "keep"
			actual.Annotations = map[string]string{"external.example/object": "keep"}
			actual.Spec.Template.Labels["external.example/template"] = "keep"
			actual.Spec.Template.Annotations["external.example/template"] = "keep"
			actual.Spec.Template.Name = "external-template-name"
			actual.Status.ReadyReplicas = 1
			actual.Spec.Replicas = ptr(int32(3))
			before := actual.DeepCopy()
			target := actual.DeepCopy()
			setManagedStatefulSet(target, desired)
			if !reflect.DeepEqual(actual, before) || !managedStatefulSetEqual(target, desired) || target.ResourceVersion != "31" || !reflect.DeepEqual(target.Finalizers, before.Finalizers) || !reflect.DeepEqual(target.OwnerReferences, before.OwnerReferences) || target.Labels["external.example/object"] != "keep" || target.Annotations["external.example/object"] != "keep" || target.Spec.Template.Labels["external.example/template"] != "keep" || target.Spec.Template.Annotations["external.example/template"] != "keep" || target.Spec.Template.Name != "external-template-name" || !reflect.DeepEqual(target.Status, before.Status) {
				t.Fatal("StatefulSet setter changed status or unrelated metadata")
			}
		})
	})
}

func TestUnitM2Compatibility(t *testing.T) {
	parent, names, config := m2ResourceFixture(t)
	wantService := desiredHeadlessService(parent, names)
	for name, mutate := range map[string]func(*corev1.Service){
		"allocated cluster IP": func(v *corev1.Service) { v.Spec.ClusterIP = "10.0.0.8" },
	} {
		t.Run("service/"+name, func(t *testing.T) {
			actual := wantService.DeepCopy()
			mutate(actual)
			if serviceCompatible(actual, wantService) {
				t.Fatal("incompatible service accepted")
			}
		})
	}
	if !serviceCompatible(wantService.DeepCopy(), wantService) {
		t.Fatal("desired service incompatible with itself")
	}
	wantSet := desiredKeaStatefulSet(parent, names, config)
	for name, mutate := range map[string]func(*appsv1.StatefulSet){
		"selector":     func(v *appsv1.StatefulSet) { v.Spec.Selector.MatchLabels[clusterUIDLabel] = "other" },
		"service name": func(v *appsv1.StatefulSet) { v.Spec.ServiceName = "other" },
		"claim template": func(v *appsv1.StatefulSet) {
			v.Spec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data"}}}
		},
	} {
		t.Run("statefulset/"+name, func(t *testing.T) {
			actual := wantSet.DeepCopy()
			mutate(actual)
			if statefulSetCompatible(actual, wantSet) {
				t.Fatal("incompatible StatefulSet accepted")
			}
		})
	}
	if !statefulSetCompatible(wantSet.DeepCopy(), wantSet) {
		t.Fatal("desired StatefulSet incompatible with itself")
	}
}

func assertChildOwner(t *testing.T, refs []metav1.OwnerReference, parent *infrastructurev1alpha1.KeaCluster) {
	t.Helper()
	if len(refs) != 1 || refs[0].APIVersion != infrastructurev1alpha1.GroupVersion.String() || refs[0].Kind != "KeaCluster" || refs[0].Name != parent.Name || refs[0].UID != parent.UID || refs[0].Controller == nil || !*refs[0].Controller || refs[0].BlockOwnerDeletion == nil || *refs[0].BlockOwnerDeletion {
		t.Fatalf("owner refs = %#v", refs)
	}
}

func assertKeaStatefulSet(t *testing.T, set *appsv1.StatefulSet, parent *infrastructurev1alpha1.KeaCluster, names workloadNames, config workloadConfig) {
	t.Helper()
	spec := set.Spec
	if spec.PodManagementPolicy != appsv1.OrderedReadyPodManagement || spec.UpdateStrategy.Type != appsv1.RollingUpdateStatefulSetStrategyType || spec.UpdateStrategy.RollingUpdate == nil || spec.UpdateStrategy.RollingUpdate.Partition == nil || *spec.UpdateStrategy.RollingUpdate.Partition != 0 {
		t.Fatalf("pod/update policy = %#v / %#v", spec.PodManagementPolicy, spec.UpdateStrategy)
	}
	template := spec.Template
	pod := template.Spec
	if pod.RestartPolicy != corev1.RestartPolicyAlways || pod.TerminationGracePeriodSeconds == nil || *pod.TerminationGracePeriodSeconds != 30 || pod.DNSPolicy != corev1.DNSClusterFirst || pod.ServiceAccountName != "default" || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.EnableServiceLinks == nil || *pod.EnableServiceLinks || pod.HostNetwork || pod.HostPID || pod.HostIPC || pod.ShareProcessNamespace != nil || len(pod.ImagePullSecrets) != 0 || len(pod.HostAliases) != 0 {
		t.Fatalf("pod runtime/network contract = %#v", pod)
	}
	if !reflect.DeepEqual(pod.NodeSelector, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}) || pod.SecurityContext == nil || pod.SecurityContext.RunAsUser == nil || *pod.SecurityContext.RunAsUser != 100 || pod.SecurityContext.RunAsGroup == nil || *pod.SecurityContext.RunAsGroup != 101 || pod.SecurityContext.FSGroup == nil || *pod.SecurityContext.FSGroup != 101 || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot || pod.SecurityContext.SeccompProfile == nil || pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("pod security contract = %#v", pod.SecurityContext)
	}
	if len(pod.Containers) != 2 || len(pod.InitContainers) != 0 || len(pod.EphemeralContainers) != 0 || len(pod.Volumes) != 5 {
		t.Fatalf("container/volume counts = %d/%d/%d/%d", len(pod.Containers), len(pod.InitContainers), len(pod.EphemeralContainers), len(pod.Volumes))
	}
	wantNames := []string{"dhcp4", "dhcp6"}
	wantImages := []string{keaDHCP4Image, keaDHCP6Image}
	wantConfigHash := []string{config.DHCP4SHA256, config.DHCP6SHA256}
	wantAdds := [][]corev1.Capability{{corev1.Capability("NET_BIND_SERVICE"), corev1.Capability("NET_RAW")}, {corev1.Capability("NET_BIND_SERVICE")}}
	wantRuntime := []string{"runtime4", "runtime6"}
	wantData := []string{"data4", "data6"}
	wantRuntimePath := "/run/kea"
	wantDataPath := "/var/lib/kea"
	for i, container := range pod.Containers {
		if container.Name != wantNames[i] || container.Image != wantImages[i] || container.ImagePullPolicy != corev1.PullIfNotPresent || !reflect.DeepEqual(container.Command, []string{"/bin/sh", "-ec"}) || len(container.Args) != 1 {
			t.Fatalf("container[%d] launch = %#v", i, container)
		}
		family := i + 4
		if i == 1 {
			family = 6
		}
		if container.Args[0] != keaLaunchScript(family) || len(container.Ports) != 0 || container.Lifecycle != nil {
			t.Fatalf("container[%d] command/ports/lifecycle mismatch", i)
		}
		if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem || container.SecurityContext.RunAsNonRoot == nil || !*container.SecurityContext.RunAsNonRoot || container.SecurityContext.Capabilities == nil || !reflect.DeepEqual(container.SecurityContext.Capabilities.Drop, []corev1.Capability{"ALL"}) || !reflect.DeepEqual(container.SecurityContext.Capabilities.Add, wantAdds[i]) {
			t.Fatalf("container[%d] security = %#v", i, container.SecurityContext)
		}
		env := map[string]string{}
		for _, item := range container.Env {
			env[item.Name] = item.Value
		}
		wantEnv := map[string]string{"KEA_CONFIG_SHA256": wantConfigHash[i], "KEA_PIDFILE_DIR": "/run/kea/state", "KEA_LOCKFILE_DIR": "/run/kea/state", "KEA_DHCP_DATA_DIR": "/var/lib/kea/state"}
		if !reflect.DeepEqual(env, wantEnv) || len(container.Env) != len(wantEnv) {
			t.Fatalf("container[%d] env = %#v", i, container.Env)
		}
		if len(container.VolumeMounts) != 3 || container.VolumeMounts[0].Name != wantRuntime[i] || container.VolumeMounts[0].MountPath != wantRuntimePath || container.VolumeMounts[1].Name != wantData[i] || container.VolumeMounts[1].MountPath != wantDataPath || container.VolumeMounts[2].Name != "configuration" || container.VolumeMounts[2].MountPath != "/etc/kea" || !container.VolumeMounts[2].ReadOnly || container.VolumeMounts[2].SubPath != "" {
			t.Fatalf("container[%d] mounts = %#v", i, container.VolumeMounts)
		}
		if container.StartupProbe == nil || container.ReadinessProbe == nil || container.LivenessProbe == nil || !reflect.DeepEqual(container.StartupProbe.Exec.Command, []string{"/bin/sh", "-ec", keaProcessProbe(family)}) || container.StartupProbe.PeriodSeconds != 2 || container.StartupProbe.TimeoutSeconds != 1 || container.StartupProbe.FailureThreshold != 30 || container.StartupProbe.InitialDelaySeconds != 0 || container.ReadinessProbe.PeriodSeconds != 5 || container.ReadinessProbe.TimeoutSeconds != 1 || container.ReadinessProbe.FailureThreshold != 1 || container.ReadinessProbe.SuccessThreshold != 1 || container.LivenessProbe.PeriodSeconds != 10 || container.LivenessProbe.TimeoutSeconds != 1 || container.LivenessProbe.FailureThreshold != 3 || container.LivenessProbe.InitialDelaySeconds != 0 {
			t.Fatalf("container[%d] probes = startup %#v readiness %#v liveness %#v", i, container.StartupProbe, container.ReadinessProbe, container.LivenessProbe)
		}
		if container.Resources.Requests.Cpu().String() != "100m" || container.Resources.Requests.Memory().String() != "64Mi" || container.Resources.Requests.StorageEphemeral().String() != "16Mi" || container.Resources.Limits.Cpu().String() != "500m" || container.Resources.Limits.Memory().String() != "128Mi" || container.Resources.Limits.StorageEphemeral().String() != "64Mi" {
			t.Fatalf("container[%d] resources = %#v", i, container.Resources)
		}
	}
	wantVolumeNames := []string{"runtime4", "data4", "runtime6", "data6", "configuration"}
	for i, volume := range pod.Volumes {
		if volume.Name != wantVolumeNames[i] {
			t.Fatalf("volume[%d] = %#v", i, volume)
		}
		if i < 4 && (volume.EmptyDir == nil || volume.EmptyDir.Medium != corev1.StorageMediumDefault || volume.EmptyDir.SizeLimit == nil || volume.EmptyDir.SizeLimit.String() != "16Mi") {
			t.Fatalf("emptyDir[%d] = %#v", i, volume)
		}
	}
	configVolume := pod.Volumes[4].ConfigMap
	if configVolume == nil || configVolume.Name != names.ConfigMap || configVolume.Optional == nil || *configVolume.Optional || configVolume.DefaultMode == nil || *configVolume.DefaultMode != 0444 || len(configVolume.Items) != 2 || configVolume.Items[0].Key != "kea-dhcp4.conf" || configVolume.Items[0].Path != "kea-dhcp4.conf" || configVolume.Items[1].Key != "kea-dhcp6.conf" || configVolume.Items[1].Path != "kea-dhcp6.conf" {
		t.Fatalf("config volume = %#v", pod.Volumes[4])
	}
	affinity := pod.Affinity
	if affinity == nil || affinity.PodAntiAffinity == nil || len(affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatalf("anti-affinity = %#v", affinity)
	}
	preferred := affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]
	term := preferred.PodAffinityTerm
	if preferred.Weight != 100 || term.TopologyKey != "kubernetes.io/hostname" || term.NamespaceSelector != nil || !reflect.DeepEqual(term.Namespaces, []string{parent.Namespace}) || !reflect.DeepEqual(term.LabelSelector.MatchLabels, map[string]string{clusterUIDLabel: string(parent.UID)}) {
		t.Fatalf("preferred anti-affinity = %#v", preferred)
	}
}

func ptr[T any](value T) *T { return &value }
