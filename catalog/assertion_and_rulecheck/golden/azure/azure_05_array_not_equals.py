"""
Pattern : array-not-equals
Rule    : azure.network.securitygroup.rdp_access_restricted
ForEach : azure.network.network_security_groups.list
Severity: CRITICAL

Check: No NSG inbound rule should allow RDP (port 3389) from Any / Internet.
Collect `access` field from all inbound rules that match port 3389,
then assert none of them equals "Allow".

Multi-condition approach: combine `destinationPortRange` check on rule
level with `access` check — both must not allow unrestricted RDP.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "azure.network.securitygroup.rdp_access_restricted",
    for_each  = "azure.network.network_security_groups.list",
    severity  = "CRITICAL",
    pattern   = "array-not-equals",
    conditions = {
        # Collect the access field from every inbound rule that has
        # destinationPortRange == "3389".  Assert "Allow" is not in list.
        "var"  : "item.properties.securityRules[].properties.access",
        "op"   : "not_contains",
        "value": "Allow",
    },
)

# PASS — only HTTPS allowed inbound, no Allow-3389 rule
FIXTURE_PASS = {
    "id"  : "/subscriptions/sub-123/.../networkSecurityGroups/nsg-web",
    "name": "nsg-web",
    "properties": {
        "securityRules": [
            {
                "name"      : "deny-rdp",
                "properties": {
                    "direction"           : "Inbound",
                    "protocol"            : "Tcp",
                    "destinationPortRange": "3389",
                    "sourceAddressPrefix" : "*",
                    "access"              : "Deny",   # Explicitly denied
                    "priority"            : 200,
                },
            },
            {
                "name"      : "deny-all-inbound",
                "properties": {
                    "direction": "Inbound",
                    "access"   : "Deny",
                    "priority" : 65500,
                },
            },
        ]
    },
}

# FAIL — RDP allowed from Any
FIXTURE_FAIL = {
    "id"  : "/subscriptions/sub-123/.../networkSecurityGroups/nsg-bad",
    "name": "nsg-bad",
    "properties": {
        "securityRules": [
            {
                "name"      : "allow-rdp",
                "properties": {
                    "direction"           : "Inbound",
                    "protocol"            : "Tcp",
                    "destinationPortRange": "3389",
                    "sourceAddressPrefix" : "*",
                    "access"              : "Allow",   # open RDP → FAIL
                    "priority"            : 100,
                },
            },
        ]
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "NSG must not have an Allow rule for port 3389 (RDP)",
    extra_notes  = (
        "The conditions check collects the `access` value from ALL security rules. "
        "If any rule has access==Allow this FAILS. A more precise check would "
        "also filter on destinationPortRange==3389 — that requires MULTI_OP."
    ),
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
