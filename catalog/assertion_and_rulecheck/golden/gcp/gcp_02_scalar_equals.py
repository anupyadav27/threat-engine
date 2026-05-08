"""
Pattern : scalar-equals
Rule    : gcp.storage.bucket.public_access_prevention_enforced
ForEach : gcp.storage.buckets.list
Severity: HIGH

Check: GCP Storage bucket must have public access prevention set to
"enforced". The `iamConfiguration.publicAccessPrevention` field is
returned directly in the bucket resource.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "gcp.storage.bucket.public_access_prevention_enforced",
    for_each  = "gcp.storage.buckets.list",
    severity  = "HIGH",
    pattern   = "scalar-equals",
    conditions = {
        "var"  : "item.iamConfiguration.publicAccessPrevention",
        "op"   : "equals",
        "value": "enforced",
    },
)

FIXTURE_PASS = {
    "id"              : "my-secure-bucket",
    "name"            : "my-secure-bucket",
    "location"        : "US-CENTRAL1",
    "storageClass"    : "STANDARD",
    "iamConfiguration": {
        "uniformBucketLevelAccess": {"enabled": True},
        "publicAccessPrevention"  : "enforced",
    },
}

FIXTURE_FAIL = {
    "id"              : "my-public-bucket",
    "name"            : "my-public-bucket",
    "iamConfiguration": {
        "publicAccessPrevention": "inherited",   # could be public → FAIL
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "GCS bucket iamConfiguration.publicAccessPrevention must be 'enforced'",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
