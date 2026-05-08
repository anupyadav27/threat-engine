"""
Pattern : boolean-is-false
Rule    : gcp.compute.instance.serial_port_access_disabled
ForEach : gcp.compute.instances.list
Severity: HIGH

Check: GCP Compute Instance must not have serial port access enabled.
`metadata.items[]` is a list of key-value pairs. We check that
`enable-serial-port` is NOT set to "true".

Simplified form: use the flattened `metadata_enable_serial_port` field
emitted by the discovery adapter, or the raw metadata.items path.
Here we use the direct metadata path with `not_contains`.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "gcp.compute.instance.serial_port_access_disabled",
    for_each  = "gcp.compute.instances.list",
    severity  = "HIGH",
    pattern   = "boolean-is-false",
    conditions = {
        "var"  : "item.metadata.items[].value",
        "op"   : "not_contains",
        "value": "true",   # no metadata item should have value "true" for serial port
    },
)

FIXTURE_PASS = {
    "id"          : "1234567890",
    "name"        : "prod-vm-01",
    "zone"        : "projects/my-project/zones/us-central1-a",
    "machineType" : "n1-standard-2",
    "status"      : "RUNNING",
    "metadata"    : {
        "fingerprint": "abc123",
        "items"      : [
            {"key": "enable-serial-port", "value": "false"},
            {"key": "startup-script",     "value": "#!/bin/bash\necho hello"},
        ],
    },
}

FIXTURE_FAIL = {
    "id"    : "9876543210",
    "name"  : "dev-vm-bad",
    "status": "RUNNING",
    "metadata": {
        "items": [
            {"key": "enable-serial-port", "value": "true"},   # FAIL
        ]
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "GCP Compute instance must not have serial port access enabled",
    extra_notes  = (
        "GCP metadata is a key-value list. The discovery adapter should ideally "
        "flatten serial-port state to a top-level boolean. The raw path check "
        "here may match other 'true' values in metadata — more precise checks "
        "filter on key==enable-serial-port first (MULTI_OP territory)."
    ),
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
