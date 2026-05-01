"""
Pattern : numeric-threshold
Rule    : aws.iam.user.access_key_age_90_days
ForEach : aws.iam.list_access_keys   (one item per access key)
Severity: HIGH

Check: IAM user access keys must be rotated within 90 days.
The `CreateDate` field is an ISO-8601 string; the check engine coerces
string fields to numbers via `greater_than` / `gte` operators when
compared against a numeric value.

For age checks we use the "days_since" virtual field pattern:
  var: item.key_age_days   (emitted by the discovery adapter)
  op : gte
  value: "90"

If the discovery doesn't pre-compute key_age_days, use `Status` field
as a proxy — but this golden check demonstrates the age-threshold pattern.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "aws.iam.user.access_key_age_90_days",
    for_each  = "aws.iam.list_access_keys",
    severity  = "HIGH",
    pattern   = "numeric-threshold",
    conditions = {
        "all": [
            # Key must be active (inactive keys don't pose a rotation risk)
            {"var": "item.Status", "op": "equals", "value": "Active"},
            # Age (in days) must be < 90 — note: discovery adapter emits key_age_days
            {"var": "item.key_age_days", "op": "lt", "value": "90"},
        ]
    },
)

FIXTURE_PASS = {
    "UserName"    : "svc-deploy",
    "AccessKeyId" : "AKIAIOSFODNN7EXAMPLE",
    "Status"      : "Active",
    "CreateDate"  : "2026-02-15T00:00:00Z",
    "key_age_days": 61,  # 61 days < 90 → PASS
}

FIXTURE_FAIL = {
    "UserName"    : "legacy-user",
    "AccessKeyId" : "AKIAI44QH8DHBEXAMPLE",
    "Status"      : "Active",
    "CreateDate"  : "2025-10-01T00:00:00Z",
    "key_age_days": 198,  # 198 days ≥ 90 → FAIL
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "Active IAM access keys must be rotated within 90 days",
    extra_notes  = (
        "The discovery adapter must emit `key_age_days` as an integer. "
        "If it doesn't, use `CreateDate` with a `days_since` virtual op "
        "or move to a MULTI_OP check that calls GetLoginProfile."
    ),
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
