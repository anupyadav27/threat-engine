"""
Pattern : scalar-exists
Rule    : alicloud.oss.bucket.server_side_encryption_enabled
ForEach : alicloud.oss.list_buckets
Severity: HIGH

Check: Alibaba Cloud OSS bucket must have server-side encryption configured.
`ServerSideEncryptionRule.SSEAlgorithm` is only present when encryption
is enabled; `exists` captures the compliance state.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "alicloud.oss.bucket.server_side_encryption_enabled",
    for_each  = "alicloud.oss.list_buckets",
    severity  = "HIGH",
    pattern   = "scalar-exists",
    conditions = {
        "var": "item.ServerSideEncryptionRule.SSEAlgorithm",
        "op" : "exists",
    },
)

FIXTURE_PASS = {
    "Name"          : "secure-prod-bucket",
    "Location"      : "oss-cn-shanghai",
    "StorageClass"  : "Standard",
    "CreationDate"  : "2025-01-10T08:00:00.000Z",
    "ServerSideEncryptionRule": {
        "SSEAlgorithm"   : "KMS",
        "KMSMasterKeyID" : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    },
}

FIXTURE_FAIL = {
    "Name"        : "legacy-bucket",
    "Location"    : "oss-cn-hangzhou",
    "StorageClass": "Standard",
    # No ServerSideEncryptionRule → encryption not configured → FAIL
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "AliCloud OSS bucket must have SSE configured (SSEAlgorithm exists)",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
