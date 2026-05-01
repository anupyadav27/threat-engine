"""
Pattern : nested-spec-is-true
Rule    : k8s.pod.container.readonly_rootfs_enabled
ForEach : k8s.pod.list
Severity: HIGH

Check: Every container must have a read-only root filesystem.
`spec.containers[].securityContext.readOnlyRootFilesystem` must be true.
Demonstrates the `all` + nested-spec array pattern.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "k8s.pod.container.readonly_rootfs_enabled",
    for_each  = "k8s.pod.list",
    severity  = "HIGH",
    pattern   = "nested-spec-is-true",
    conditions = {
        "var"  : "item.spec.containers[].securityContext.readOnlyRootFilesystem",
        "op"   : "not_contains",
        "value": False,
    },
)

FIXTURE_PASS = {
    "metadata": {"name": "hardened-pod"},
    "spec"    : {
        "containers": [
            {
                "name"           : "app",
                "securityContext": {"readOnlyRootFilesystem": True},
            },
            {
                "name"           : "sidecar",
                "securityContext": {"readOnlyRootFilesystem": True},
            },
        ]
    },
}

FIXTURE_FAIL = {
    "metadata": {"name": "writable-pod"},
    "spec"    : {
        "containers": [
            {
                "name"           : "app",
                "securityContext": {"readOnlyRootFilesystem": False},  # writable → FAIL
            }
        ]
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "All containers must have readOnlyRootFilesystem = true",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
