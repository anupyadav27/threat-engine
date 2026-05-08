"""
Pattern : scalar-equals
Rule    : oci.iam.user.mfa_activated
ForEach : oci.identity.list_users
Severity: CRITICAL

Check: OCI IAM user must have MFA (TOTP) device activated.
`isMfaActivated` is a top-level boolean on the user object.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "oci.iam.user.mfa_activated",
    for_each  = "oci.identity.list_users",
    severity  = "CRITICAL",
    pattern   = "scalar-equals",
    conditions = {
        "var"  : "item.isMfaActivated",
        "op"   : "is_true",
    },
)

FIXTURE_PASS = {
    "id"              : "ocid1.user.oc1..aaaaaa1",
    "name"            : "admin.user@example.com",
    "lifecycleState"  : "ACTIVE",
    "isMfaActivated"  : True,
    "timeCreated"     : "2024-01-01T00:00:00.000Z",
}

FIXTURE_FAIL = {
    "id"            : "ocid1.user.oc1..aaaaaa2",
    "name"          : "no-mfa-user@example.com",
    "lifecycleState": "ACTIVE",
    "isMfaActivated": False,   # MFA not set up → FAIL
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "OCI IAM user must have MFA activated (isMfaActivated = true)",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
