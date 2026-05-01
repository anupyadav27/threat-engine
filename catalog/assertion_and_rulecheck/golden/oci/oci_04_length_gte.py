"""
Pattern : length-gte  (array-count)
Rule    : oci.monitoring.alarm.critical_alarm_count_sufficient
ForEach : oci.monitoring.list_alarms
Severity: MEDIUM

Check: At least 1 critical alarm must be configured in the tenancy
(account-wide resource-count check).
The discovery emits a synthetic wrapper `{alarms: [...]}` for
account-wide list operations.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "oci.monitoring.alarm.critical_alarm_count_sufficient",
    for_each  = "oci.monitoring.list_alarms",
    severity  = "MEDIUM",
    pattern   = "length-gte",
    conditions = {
        "var"  : "item.alarms",
        "op"   : "length_gte",
        "value": "1",
    },
)

FIXTURE_PASS = {
    "alarms": [
        {
            "id"             : "ocid1.alarm.oc1..aaaaaacpu",
            "displayName"    : "High CPU Alarm",
            "lifecycleState" : "ACTIVE",
            "severity"       : "CRITICAL",
            "isEnabled"      : True,
        },
        {
            "id"             : "ocid1.alarm.oc1..aaaaaadisk",
            "displayName"    : "Disk Full Alarm",
            "lifecycleState" : "ACTIVE",
            "severity"       : "WARNING",
            "isEnabled"      : True,
        },
    ]
}

FIXTURE_FAIL = {
    "alarms": []   # no alarms configured → FAIL
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "At least one OCI Monitoring alarm must exist (tenancy-level)",
    extra_notes  = (
        "Account-wide list checks: discovery emits a single synthetic item "
        "wrapping the full result list. `length_gte 1` asserts non-empty."
    ),
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
