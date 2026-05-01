"""
Pattern : boolean-equals-false
Rule    : aws.ec2.instance.public_ip_auto_assign_disabled
ForEach : aws.ec2.describe_instances
Severity: HIGH

Check: EC2 instance must NOT have a public IP automatically assigned.
The API returns `PublicIpAddress` only when a public IP is present;
checking `not_exists` (equals None/absent) captures the PASS state.

Alternative form: `PublicIpAddress  op: not_exists` — covered here.
Also shows how to use `is_false` on a boolean-typed field
(`MetadataOptions.HttpPutResponseHopLimit`-style booleans are common).
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "aws.ec2.instance.public_ip_auto_assign_disabled",
    for_each  = "aws.ec2.describe_instances",
    severity  = "HIGH",
    pattern   = "boolean-equals-false",
    conditions = {
        "var": "item.PublicIpAddress",
        "op" : "not_exists",
    },
)

FIXTURE_PASS = {
    "InstanceId"      : "i-0abc123456789def0",
    "InstanceType"    : "t3.micro",
    "State"           : {"Name": "running"},
    "SubnetId"        : "subnet-0a1b2c3d",
    # No PublicIpAddress key → private instance
}

FIXTURE_FAIL = {
    "InstanceId"      : "i-0fff000111222333",
    "InstanceType"    : "t3.micro",
    "State"           : {"Name": "running"},
    "PublicIpAddress" : "54.201.100.12",  # has public IP → FAIL
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "EC2 instance must not have a public IP address",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
