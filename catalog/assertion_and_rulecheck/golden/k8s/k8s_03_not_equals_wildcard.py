"""
Pattern : not-equals-wildcard
Rule    : k8s.rbac.clusterrole.wildcard_verbs_restricted
ForEach : k8s.rbac.list_cluster_role
Severity: HIGH

Check: ClusterRole rules must not use wildcard (*) for verbs.
`rules[].verbs` is a list of strings; assert "*" is not in any of them.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "k8s.rbac.clusterrole.wildcard_verbs_restricted",
    for_each  = "k8s.rbac.list_cluster_role",
    severity  = "HIGH",
    pattern   = "not-equals-wildcard",
    conditions = {
        "var"  : "item.rules[].verbs",
        "op"   : "not_contains",
        "value": "*",
    },
)

FIXTURE_PASS = {
    "metadata": {"name": "pod-reader", "namespace": ""},
    "rules"   : [
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "watch", "list"]},
        {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "list"]},
    ],
}

FIXTURE_FAIL = {
    "metadata": {"name": "all-access", "namespace": ""},
    "rules"   : [
        {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},   # wildcard → FAIL
    ],
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "ClusterRole rules must not use wildcard (*) verbs",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
