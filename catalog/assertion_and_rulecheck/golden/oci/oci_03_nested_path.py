"""
Pattern : nested-path
Rule    : oci.database.autonomous_database.auto_backup_enabled
ForEach : oci.database.list_autonomous_databases
Severity: HIGH

Check: OCI Autonomous Database must have automatic backups configured.
`backupConfig.manualBackupBucketName` exists only when auto-backup is on,
but the cleaner signal is `isAutoScalingForStorageEnabled` at top-level.
Use the direct `backupConfig.canRunAutomaticFailover` as a nested-path demo.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "oci.database.autonomous_database.auto_backup_enabled",
    for_each  = "oci.database.list_autonomous_databases",
    severity  = "HIGH",
    pattern   = "nested-path",
    conditions = {
        "all": [
            {"var": "item.isAutoBackupEnabled",                   "op": "is_true"},
            {"var": "item.backupConfig.autoBackupEnabled",        "op": "is_true"},
        ]
    },
)

FIXTURE_PASS = {
    "id"                  : "ocid1.autonomousdatabase.oc1..aaaaaaprod",
    "dbName"              : "PRODDB",
    "lifecycleState"      : "AVAILABLE",
    "isAutoBackupEnabled" : True,
    "backupConfig"        : {
        "autoBackupEnabled"       : True,
        "autoBackupWindow"        : "SLOT_ONE",
        "recoveryWindowInDays"    : 7,
    },
}

FIXTURE_FAIL = {
    "id"                  : "ocid1.autonomousdatabase.oc1..aaaaadev",
    "dbName"              : "DEVDB",
    "lifecycleState"      : "AVAILABLE",
    "isAutoBackupEnabled" : False,    # backup off → FAIL
    "backupConfig"        : {
        "autoBackupEnabled": False,
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "OCI Autonomous DB must have auto-backup enabled in both top-level and backupConfig",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
