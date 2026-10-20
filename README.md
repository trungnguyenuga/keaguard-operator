# KeaGuard

KeaGuard M1 is a Kubernetes controller foundation for reconciling a namespaced `KeaCluster` resource into an internal ConfigMap artifact. Its `spec` is intentionally empty. The ConfigMap records the parent name, namespace, and UID; it is not Kea configuration.

`ArtifactReconciled` reports whether that internal artifact matches the controller's ownership and managed-field contract. It does not report Kea process health, DHCP service, lease synchronization, or failover readiness. M1 does not deploy or configure Kea and makes no DHCP, HA, availability, latency, or performance claims.

See [M1 development and local acceptance](docs/development/m1.md) for pinned tools, separate CRD/runtime installation, tests, safe opt-in Kind selection, and the limits of the current milestone.

The fixed Kea process workload is a separate opt-in profile with distinct image, namespace-policy, and runtime requirements. See [M2 development and local acceptance](docs/development/m2.md) before preparing its dedicated disposable Kind lab. The default M1 sample remains disabled by default; the enabled M2 sample is intentionally excluded from the default sample bundle.
