# KeaGuard

KeaGuard is a Kubernetes Operator written in Go for managing ISC Kea workloads through a namespaced `KeaCluster` resource. The project is currently in M2, focused on deploying and managing Kea processes in a controlled local environment.

With `spec.workload.enabled: true`, the operator manages a two-replica StatefulSet, a generated configuration ConfigMap, and a headless Service. Each replica runs separate DHCPv4 and DHCPv6 containers using pinned ISC Kea images, process health probes, and ephemeral runtime storage. The operator also maintains an internal identity ConfigMap for each `KeaCluster`.

M2 demonstrates process management only. The generated Kea configurations have no DHCP listeners, subnets, or address pools. The two replicas operate independently; lease synchronization, Kea HA, and DHCP failover are outside this milestone. `ArtifactReconciled` describes the identity artifact, while `WorkloadReady` reports workload readiness under the process-only contract. Neither condition establishes DHCP service availability.

The workload is disabled by default. The [enabled M2 sample](config/samples/infrastructure_v1alpha1_keacluster_m2.yaml) is intentionally excluded from the default sample bundle. Read [M2 development and local acceptance](docs/development/m2.md) for pinned tools and images, namespace-policy requirements, verification commands, and dedicated disposable Kind lab setup before enabling it.
