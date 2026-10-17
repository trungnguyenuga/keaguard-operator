#!/usr/bin/env python3
"""Fail on stale or nondeterministic generated files; never restore or stage them."""
import hashlib
import os
from pathlib import Path
import subprocess


def snapshot():
    paths = sorted({*Path("api").rglob("zz_generated*.go"),
                    *Path("config/crd/bases").glob("*.yaml"),
                    Path("config/rbac/role.yaml")})
    state = {str(path): path.read_bytes() for path in paths}
    for bundle in ("default", "crd"):
        state["render/" + bundle] = subprocess.check_output(
            [os.environ.get("KUBECTL", "kubectl"), "kustomize", "config/" + bundle])
    return state


baseline = snapshot()
for iteration in (1, 2):
    subprocess.run(["make", "generate", "manifests"], check=True)
    current = snapshot()
    changed = sorted(key for key in baseline.keys() | current.keys()
                     if baseline.get(key) != current.get(key))
    if changed:
        raise SystemExit(f"Regeneration {iteration} differs from reviewed baseline: {changed}")
    print(f"Regeneration {iteration}: generated files and runtime/installer renders unchanged", flush=True)
for name, content in sorted(baseline.items()):
    print(hashlib.sha256(content).hexdigest(), name)
