"""
Pattern : boolean-is-false
Rule    : k8s.pod.container.privileged_mode_disabled
ForEach : k8s.pod.list
Severity: CRITICAL

Check: No container in the pod may run in privileged mode.
`spec.containers[].securityContext.privileged` must be false (or absent,
which defaults to false in Kubernetes).
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "k8s.pod.container.privileged_mode_disabled",
    for_each  = "k8s.pod.list",
    severity  = "CRITICAL",
    pattern   = "boolean-is-false",
    conditions = {
        "var": "item.spec.containers[].securityContext.privileged",
        "op" : "not_contains",
        "value": True,
    },
)

FIXTURE_PASS = {
    "metadata": {"name": "secure-pod", "namespace": "production"},
    "spec"    : {
        "containers": [
            {
                "name"           : "app",
                "image"          : "nginx:1.25",
                "securityContext": {"privileged": False, "readOnlyRootFilesystem": True},
            },
            {
                "name"           : "sidecar",
                "image"          : "envoy:1.27",
                "securityContext": {"privileged": False},
            },
        ]
    },
    "status": {"phase": "Running"},
}

FIXTURE_FAIL = {
    "metadata": {"name": "privileged-pod", "namespace": "default"},
    "spec"    : {
        "containers": [
            {
                "name"           : "root-container",
                "image"          : "ubuntu:22.04",
                "securityContext": {"privileged": True},   # FAIL
            }
        ]
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "No container in the pod must have securityContext.privileged = true",
    extra_notes  = (
        "Array expansion `containers[].securityContext.privileged` collects the "
        "value from every container. `not_contains true` fails if any container "
        "is privileged."
    ),
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
