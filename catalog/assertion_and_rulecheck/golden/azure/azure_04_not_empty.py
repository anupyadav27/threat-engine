"""
Pattern : not-empty
Rule    : azure.monitor.activitylog.alert_for_policy_write_configured
ForEach : azure.monitor.activity_log_alerts.list
Severity: MEDIUM

Check: At least one Activity Log Alert must exist at the subscription level.
Rather than checking a specific alert name (fragile), we assert that the
list of alerts returned by the API is not empty.

This is the "account-wide / missing-resource = FAIL" pattern:
  - `for_each` iterates over a list at the subscription scope
  - The check verifies the list itself is non-empty (i.e. `item.value` exists
    and has at least one entry — ARM list responses wrap results in `value`)
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "azure.monitor.activitylog.alert_for_policy_write_configured",
    for_each  = "azure.monitor.activity_log_alerts.list",
    severity  = "MEDIUM",
    pattern   = "not-empty",
    conditions = {
        "var": "item.value",
        "op" : "not_empty",
    },
)

FIXTURE_PASS = {
    "value": [
        {
            "id"        : "/subscriptions/sub-123/.../alerts/policy-write-alert",
            "name"      : "policy-write-alert",
            "properties": {
                "enabled"    : True,
                "description": "Alert on Microsoft.Authorization/policyAssignments/write",
                "condition"  : {"allOf": []},
            },
        }
    ]
}

FIXTURE_FAIL = {
    "value": []   # No activity log alerts configured → FAIL
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "At least one Activity Log Alert must be configured (subscription-scope)",
    extra_notes  = (
        "ARM list APIs wrap results in `value`. The discovery adapter emits a "
        "single synthetic item `{value: [...]}` representing the whole list."
    ),
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
