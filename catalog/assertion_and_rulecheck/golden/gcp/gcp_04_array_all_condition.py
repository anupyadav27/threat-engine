"""
Pattern : array-all-condition
Rule    : gcp.compute.instance.shielded_vm_all_options_enabled
ForEach : gcp.compute.instances.list
Severity: HIGH

Check: All shieldedInstanceConfig options must be enabled:
  vtpmEnabled, integrityMonitoringEnabled, enableSecureBoot.
Three scalar checks with `all` — demonstrates multi-field boolean audit.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "gcp.compute.instance.shielded_vm_all_options_enabled",
    for_each  = "gcp.compute.instances.list",
    severity  = "HIGH",
    pattern   = "array-all-condition",
    conditions = {
        "all": [
            {"var": "item.shieldedInstanceConfig.enableVtpm",               "op": "is_true"},
            {"var": "item.shieldedInstanceConfig.enableIntegrityMonitoring", "op": "is_true"},
            {"var": "item.shieldedInstanceConfig.enableSecureBoot",         "op": "is_true"},
        ]
    },
)

FIXTURE_PASS = {
    "name"  : "shielded-vm-01",
    "status": "RUNNING",
    "shieldedInstanceConfig": {
        "enableVtpm"               : True,
        "enableIntegrityMonitoring": True,
        "enableSecureBoot"         : True,
    },
}

FIXTURE_FAIL = {
    "name"  : "unshielded-vm",
    "status": "RUNNING",
    "shieldedInstanceConfig": {
        "enableVtpm"               : True,
        "enableIntegrityMonitoring": True,
        "enableSecureBoot"         : False,   # secure boot off → FAIL
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "GCP Compute instance must have all Shielded VM options enabled",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
