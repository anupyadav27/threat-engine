"""
Pattern : scalar-exists
Rule    : oci.objectstorage.bucket.encryption_at_rest_enabled
ForEach : oci.object_storage.list_buckets
Severity: HIGH

Check: OCI Object Storage bucket must use a customer-managed key (CMK).
`kmsKeyId` is only present when CMK is configured; `exists` on this field
captures the compliance state.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "oci.objectstorage.bucket.encryption_at_rest_enabled",
    for_each  = "oci.object_storage.list_buckets",
    severity  = "HIGH",
    pattern   = "scalar-exists",
    conditions = {
        "var": "item.kmsKeyId",
        "op" : "exists",
    },
)

FIXTURE_PASS = {
    "name"          : "prod-secure-bucket",
    "compartmentId" : "ocid1.compartment.oc1..aaaaaa",
    "namespace"     : "mytenancy",
    "kmsKeyId"      : "ocid1.key.oc1..aaaaaakeyid",  # CMK present → PASS
    "storageClass"  : "STANDARD",
    "timeCreated"   : "2025-01-15T10:00:00.000Z",
}

FIXTURE_FAIL = {
    "name"         : "dev-unencrypted-bucket",
    "compartmentId": "ocid1.compartment.oc1..aaaaaa",
    "namespace"    : "mytenancy",
    # No kmsKeyId field → Oracle-managed encryption only → FAIL
    "storageClass" : "STANDARD",
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "OCI Object Storage bucket must have a customer-managed KMS key (kmsKeyId exists)",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
