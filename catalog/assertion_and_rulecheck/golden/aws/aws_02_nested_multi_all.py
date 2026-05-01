"""
Pattern : nested-multi-all
Rule    : aws.iam.account.password_policy_compliant
ForEach : aws.iam.get_account_password_policy
Severity: HIGH

Check: IAM account password policy must meet minimum security requirements.
Uses multi-condition `all` block checking deeply nested fields.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "aws.iam.account.password_policy_compliant",
    for_each  = "aws.iam.get_account_password_policy",
    severity  = "HIGH",
    pattern   = "nested-multi-all",
    conditions = {
        "all": [
            {"var": "item.PasswordPolicy.MinimumPasswordLength", "op": "gte", "value": "8"},
            {"var": "item.PasswordPolicy.RequireSymbols",        "op": "is_true"},
            {"var": "item.PasswordPolicy.RequireNumbers",        "op": "is_true"},
            {"var": "item.PasswordPolicy.RequireUppercaseCharacters", "op": "is_true"},
            {"var": "item.PasswordPolicy.RequireLowercaseCharacters", "op": "is_true"},
            {"var": "item.PasswordPolicy.MaxPasswordAge",        "op": "lte", "value": "90"},
            {"var": "item.PasswordPolicy.PasswordReusePrevention", "op": "gte", "value": "5"},
        ]
    },
)

FIXTURE_PASS = {
    "PasswordPolicy": {
        "MinimumPasswordLength"         : 12,
        "RequireSymbols"                : True,
        "RequireNumbers"                : True,
        "RequireUppercaseCharacters"    : True,
        "RequireLowercaseCharacters"    : True,
        "AllowUsersToChangePassword"    : True,
        "ExpirePasswords"               : True,
        "MaxPasswordAge"                : 60,
        "PasswordReusePrevention"       : 10,
        "HardExpiry"                    : False,
    }
}

FIXTURE_FAIL = {
    "PasswordPolicy": {
        "MinimumPasswordLength"         : 6,   # too short
        "RequireSymbols"                : False,
        "RequireNumbers"                : True,
        "RequireUppercaseCharacters"    : False,
        "RequireLowercaseCharacters"    : True,
        "MaxPasswordAge"                : 365,  # too old
        "PasswordReusePrevention"       : 1,
    }
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "IAM password policy must enforce 8-char min, symbols, numbers, upper/lower, max-age 90, reuse-5",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
