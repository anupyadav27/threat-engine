"""
Pattern : scalar-exists
Rule    : aws.s3.bucket.server_side_encryption_enabled
ForEach : aws.s3.get_bucket_encryption
Severity: HIGH

Check: The bucket must have at least one SSE rule configured.
The SSEAlgorithm field is only present when encryption is on,
so `exists` on that path is sufficient.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "aws.s3.bucket.server_side_encryption_enabled",
    for_each  = "aws.s3.get_bucket_encryption",
    severity  = "HIGH",
    pattern   = "scalar-exists",
    conditions = {
        "var": "item.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm",
        "op" : "exists",
    },
)

FIXTURE_PASS = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/abc123",
                },
                "BucketKeyEnabled": True,
            }
        ]
    }
}

FIXTURE_FAIL = {
    "ServerSideEncryptionConfiguration": {
        "Rules": []
    }
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "S3 bucket SSE rule must exist (aws:kms or AES256)",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
