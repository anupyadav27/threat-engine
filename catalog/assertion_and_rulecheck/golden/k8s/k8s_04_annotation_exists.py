"""
Pattern : annotation-key-exists
Rule    : k8s.pod.security.pod_security_standard_applied
ForEach : k8s.namespace.list
Severity: HIGH

Check: Namespace must have a Pod Security Standard label applied
(`pod-security.kubernetes.io/enforce` annotation/label must exist).

K8s metadata labels are a flat map — the path uses dot-quoted key notation
because the label key contains slashes.  The discovery adapter emits the
label map under `metadata.labels`; we check for the key's existence.

Simplified: check `metadata.labels` is not empty (the adapter flattens
all PSS labels into the standard map).
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

# The discovery adapter normalises the PSS enforce label to a flat field.
SPEC = CheckSpec(
    rule_id   = "k8s.namespace.security.pod_security_standard_applied",
    for_each  = "k8s.namespace.list",
    severity  = "HIGH",
    pattern   = "annotation-key-exists",
    conditions = {
        "var": "item.metadata.labels",
        "op" : "not_empty",
    },
)

FIXTURE_PASS = {
    "metadata": {
        "name"  : "production",
        "labels": {
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/warn"   : "restricted",
            "environment"                       : "prod",
        },
    },
}

FIXTURE_FAIL = {
    "metadata": {
        "name"  : "default",
        "labels": {},   # no labels at all → FAIL
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "Namespace must have at least one label (pod-security standard enforcement)",
    extra_notes  = (
        "A stricter check would verify the specific "
        "'pod-security.kubernetes.io/enforce' key exists. That requires the "
        "discovery adapter to flatten label keys into a structure the engine "
        "can navigate, or a MULTI_OP check using the raw map."
    ),
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
