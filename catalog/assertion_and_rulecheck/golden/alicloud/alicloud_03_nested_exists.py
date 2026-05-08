"""
Pattern : nested-exists
Rule    : alicloud.ram.account.mfa_required_for_login
ForEach : alicloud.ram.get_security_preference
Severity: CRITICAL

Check: AliCloud RAM account security preference must require MFA for login.
`LoginProfile.MFABindRequired` is a nested boolean field.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "alicloud.ram.account.mfa_required_for_login",
    for_each  = "alicloud.ram.get_security_preference",
    severity  = "CRITICAL",
    pattern   = "nested-exists",
    conditions = {
        "all": [
            {"var": "item.SecurityPreference.LoginProfilePreference.MFAOperationForLogin",
             "op" : "equals", "value": "mandatory"},
        ]
    },
)

FIXTURE_PASS = {
    "SecurityPreference": {
        "LoginProfilePreference": {
            "LoginNetworkMasks"     : "",
            "LoginSessionDuration"  : 6,
            "MFAOperationForLogin"  : "mandatory",   # MFA enforced → PASS
            "AllowUserToManageMFADevices": True,
        },
        "AccessKeyPreference": {
            "AllowUserToManageAccessKeys": False,
        },
    }
}

FIXTURE_FAIL = {
    "SecurityPreference": {
        "LoginProfilePreference": {
            "LoginSessionDuration": 6,
            "MFAOperationForLogin": "optional",   # MFA only optional → FAIL
        },
    }
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "AliCloud RAM MFAOperationForLogin must be 'mandatory'",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
