"""
Pattern : array-not-contains
Rule    : aws.ec2.securitygroup.unrestricted_ssh_access
ForEach : aws.ec2.describe_security_groups
Severity: CRITICAL

Check: No inbound rule in the security group should allow SSH (port 22)
from 0.0.0.0/0 or ::/0.

Uses array[] expansion to flatten all IpRanges across all inbound rules,
then asserts that "0.0.0.0/0" is NOT in the collected CidrIp values.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "aws.ec2.securitygroup.unrestricted_ssh_access",
    for_each  = "aws.ec2.describe_security_groups",
    severity  = "CRITICAL",
    pattern   = "array-not-contains",
    conditions = {
        "var"  : "item.IpPermissions[].IpRanges[].CidrIp",
        "op"   : "not_contains",
        "value": "0.0.0.0/0",
    },
)

# PASS — SSH only from corp (10.0.0.0/8); no rule has 0.0.0.0/0 in any CidrIp
FIXTURE_PASS = {
    "GroupId"      : "sg-0abcdef1234567890",
    "GroupName"    : "restricted-ssh",
    "IpPermissions": [
        {
            "FromPort"  : 22,
            "ToPort"    : 22,
            "IpProtocol": "tcp",
            "IpRanges"  : [{"CidrIp": "10.0.0.0/8", "Description": "Corporate VPN"}],
            "Ipv6Ranges": [],
        },
        {
            "FromPort"  : 443,
            "ToPort"    : 443,
            "IpProtocol": "tcp",
            "IpRanges"  : [{"CidrIp": "10.0.0.0/8"}],   # HTTPS also restricted to corp
            "Ipv6Ranges": [],
        },
    ],
}

# FAIL — SSH open to world
FIXTURE_FAIL = {
    "GroupId"      : "sg-0bad000000000000",
    "GroupName"    : "open-ssh",
    "IpPermissions": [
        {
            "FromPort"  : 22,
            "ToPort"    : 22,
            "IpProtocol": "tcp",
            "IpRanges"  : [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
        },
    ],
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "Security group must not allow SSH (22) from 0.0.0.0/0",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
