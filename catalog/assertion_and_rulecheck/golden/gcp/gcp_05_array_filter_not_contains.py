"""
Pattern : array-filter-not-contains
Rule    : gcp.compute.firewall.no_open_rdp_from_internet
ForEach : gcp.compute.firewalls.list
Severity: CRITICAL

Check: GCP Firewall rule must not allow RDP (tcp:3389) from 0.0.0.0/0.
`allowed[].IPProtocol` and `sourceRanges` live at different levels.
This check uses the `sourceRanges` array and asserts 0.0.0.0/0 is absent,
combined with an `allowed` port check.

Multi-condition `all`:
  1. sourceRanges must not contain "0.0.0.0/0"
  2. allowed[].ports must not contain "3389"
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "gcp.compute.firewall.no_open_rdp_from_internet",
    for_each  = "gcp.compute.firewalls.list",
    severity  = "CRITICAL",
    pattern   = "array-filter-not-contains",
    conditions = {
        "any": [
            # Either not from internet …
            {"var": "item.sourceRanges", "op": "not_contains", "value": "0.0.0.0/0"},
            # … or does not allow port 3389
            {"var": "item.allowed[].ports", "op": "not_contains", "value": "3389"},
        ]
    },
)

FIXTURE_PASS = {
    "name"        : "allow-rdp-corp",
    "direction"   : "INGRESS",
    "priority"    : 1000,
    "sourceRanges": ["10.0.0.0/8"],   # only from corp network
    "allowed"     : [{"IPProtocol": "tcp", "ports": ["3389"]}],
}

FIXTURE_FAIL = {
    "name"        : "allow-rdp-internet",
    "direction"   : "INGRESS",
    "priority"    : 1000,
    "sourceRanges": ["0.0.0.0/0"],    # from everywhere
    "allowed"     : [{"IPProtocol": "tcp", "ports": ["3389"]}],  # port 3389
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "Firewall must not allow RDP (3389) from 0.0.0.0/0",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
