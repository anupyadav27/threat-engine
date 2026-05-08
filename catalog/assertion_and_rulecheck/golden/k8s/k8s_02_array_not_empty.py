"""
Pattern : array-not-empty
Rule    : k8s.pod.container.resource_limits_configured
ForEach : k8s.pod.list
Severity: HIGH

Check: Every container in the pod must have resource limits set.
`spec.containers[].resources.limits` should be a non-empty dict.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "k8s.pod.container.resource_limits_configured",
    for_each  = "k8s.pod.list",
    severity  = "HIGH",
    pattern   = "array-not-empty",
    conditions = {
        "var": "item.spec.containers[].resources.limits",
        "op" : "not_empty",
    },
)

FIXTURE_PASS = {
    "metadata": {"name": "bounded-pod", "namespace": "production"},
    "spec"    : {
        "containers": [
            {
                "name"     : "app",
                "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits"  : {"cpu": "500m", "memory": "512Mi"},
                },
            }
        ]
    },
}

FIXTURE_FAIL = {
    "metadata": {"name": "unbounded-pod", "namespace": "default"},
    "spec"    : {
        "containers": [
            {
                "name"     : "app",
                "resources": {
                    "requests": {"cpu": "100m"},
                    # No 'limits' key → extract_value returns [] → not_empty([]) → FAIL
                },
            }
        ]
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "All containers must have non-empty resource.limits",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
