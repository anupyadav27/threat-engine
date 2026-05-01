"""
Pattern : scalar-equals-true
Rule    : alicloud.ecs.instance.disk_encrypted
ForEach : alicloud.ecs.describe_disks
Severity: HIGH

Check: ECS system disk must be encrypted.
`Encrypted` is a boolean field on the disk resource.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "alicloud.ecs.instance.disk_encrypted",
    for_each  = "alicloud.ecs.describe_disks",
    severity  = "HIGH",
    pattern   = "scalar-equals-true",
    conditions = {
        "var": "item.Encrypted",
        "op" : "is_true",
    },
)

FIXTURE_PASS = {
    "DiskId"       : "d-bp1abc123456",
    "DiskName"     : "prod-system-disk",
    "Type"         : "system",
    "Status"       : "In_use",
    "Encrypted"    : True,
    "KMSKeyId"     : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "Size"         : 100,
}

FIXTURE_FAIL = {
    "DiskId"   : "d-bp1def789012",
    "DiskName" : "old-system-disk",
    "Type"     : "system",
    "Status"   : "In_use",
    "Encrypted": False,   # not encrypted → FAIL
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "AliCloud ECS disk must be encrypted (Encrypted = true)",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
