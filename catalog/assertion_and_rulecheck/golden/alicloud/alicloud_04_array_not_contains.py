"""
Pattern : array-not-contains
Rule    : alicloud.vpc.security_group.no_open_ssh_from_internet
ForEach : alicloud.ecs.describe_security_groups
Severity: CRITICAL

Check: AliCloud Security Group must not allow SSH (port 22) from
0.0.0.0/0. Collect `SourceCidrIp` from inbound rules where `PortRange`
includes 22; assert 0.0.0.0/0 is not present.

Simplified: assert none of the inbound rule CIDRs is 0.0.0.0/0.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "alicloud.vpc.security_group.no_open_ssh_from_internet",
    for_each  = "alicloud.ecs.describe_security_groups",
    severity  = "CRITICAL",
    pattern   = "array-not-contains",
    conditions = {
        "var"  : "item.Permissions.Permission[].SourceCidrIp",
        "op"   : "not_contains",
        "value": "0.0.0.0/0",
    },
)

FIXTURE_PASS = {
    "SecurityGroupId"  : "sg-bp1abc123456",
    "SecurityGroupName": "restricted-sg",
    "Permissions": {
        "Permission": [
            {
                "IpProtocol"   : "TCP",
                "PortRange"    : "22/22",
                "SourceCidrIp" : "10.0.0.0/8",   # corp only — no 0.0.0.0/0 anywhere
                "Policy"       : "Accept",
                "Priority"     : 1,
                "Direction"    : "ingress",
            },
            {
                "IpProtocol"   : "TCP",
                "PortRange"    : "443/443",
                "SourceCidrIp" : "10.0.0.0/8",   # HTTPS also corp-only in this secure SG
                "Policy"       : "Accept",
                "Priority"     : 1,
                "Direction"    : "ingress",
            },
        ]
    }
}

FIXTURE_FAIL = {
    "SecurityGroupId"  : "sg-bp1bad000000",
    "SecurityGroupName": "open-sg",
    "Permissions": {
        "Permission": [
            {
                "IpProtocol"   : "TCP",
                "PortRange"    : "22/22",
                "SourceCidrIp" : "0.0.0.0/0",   # open SSH → FAIL
                "Policy"       : "Accept",
                "Direction"    : "ingress",
            }
        ]
    }
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "AliCloud SG must not allow SSH (22) from 0.0.0.0/0",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
