"""
Pattern : scalar-equals-enum
Rule    : alicloud.slb.listener.https_listener_only
ForEach : alicloud.slb.describe_load_balancer_attribute
Severity: HIGH

Check: AliCloud SLB listener must use HTTPS (not plain HTTP).
`ListenerPortAndProtocol[].ListenerProtocol` should not contain "http".
Uses `not_contains` on the collected protocol values.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "alicloud.slb.listener.https_listener_only",
    for_each  = "alicloud.slb.describe_load_balancer_attribute",
    severity  = "HIGH",
    pattern   = "scalar-equals-enum",
    conditions = {
        "var"  : "item.ListenerPortsAndProtocol.ListenerPortAndProtocol[].ListenerProtocol",
        "op"   : "not_contains",
        "value": "http",
    },
)

FIXTURE_PASS = {
    "LoadBalancerId"  : "lb-bp1abc123456",
    "LoadBalancerName": "prod-slb",
    "LoadBalancerStatus": "active",
    "ListenerPortsAndProtocol": {
        "ListenerPortAndProtocol": [
            {"ListenerPort": 443, "ListenerProtocol": "https"},
            {"ListenerPort": 80,  "ListenerProtocol": "https"},  # redirect-only HTTPS
        ]
    },
}

FIXTURE_FAIL = {
    "LoadBalancerId": "lb-bp1bad000000",
    "LoadBalancerName": "legacy-slb",
    "ListenerPortsAndProtocol": {
        "ListenerPortAndProtocol": [
            {"ListenerPort": 80,  "ListenerProtocol": "http"},   # plain HTTP → FAIL
            {"ListenerPort": 443, "ListenerProtocol": "https"},
        ]
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "AliCloud SLB must not have plain HTTP listeners",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
