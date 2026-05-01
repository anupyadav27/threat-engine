"""
Pattern : scalar-equals-true
Rule    : azure.storage.account.https_traffic_only_enabled
ForEach : azure.storage.accounts.list
Severity: HIGH

Check: Azure Storage Account must enforce HTTPS-only traffic.
The `supportsHttpsTrafficOnly` boolean field is returned directly by
the ARM List API — single scalar check.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "azure.storage.account.https_traffic_only_enabled",
    for_each  = "azure.storage.accounts.list",
    severity  = "HIGH",
    pattern   = "scalar-equals-true",
    conditions = {
        "var"  : "item.properties.supportsHttpsTrafficOnly",
        "op"   : "is_true",
    },
)

FIXTURE_PASS = {
    "id"        : "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/mystore",
    "name"      : "mystore",
    "type"      : "Microsoft.Storage/storageAccounts",
    "properties": {
        "provisioningState"       : "Succeeded",
        "primaryLocation"         : "eastus",
        "supportsHttpsTrafficOnly": True,
        "minimumTlsVersion"       : "TLS1_2",
    },
}

FIXTURE_FAIL = {
    "id"        : "/subscriptions/sub-123/resourceGroups/rg-dev/providers/Microsoft.Storage/storageAccounts/oldstore",
    "name"      : "oldstore",
    "properties": {
        "provisioningState"       : "Succeeded",
        "supportsHttpsTrafficOnly": False,   # HTTP allowed → FAIL
        "minimumTlsVersion"       : "TLS1_0",
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "Storage Account must set supportsHttpsTrafficOnly = true",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
