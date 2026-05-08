"""
Pattern : nested-boolean
Rule    : azure.keyvault.vault.soft_delete_enabled
ForEach : azure.keyvault.vaults.list
Severity: HIGH

Check: Azure Key Vault must have soft-delete enabled.
`properties.enableSoftDelete` is a nested boolean field.
Shows how to navigate two-level nested ARM `properties.*` paths.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "azure.keyvault.vault.soft_delete_enabled",
    for_each  = "azure.keyvault.vaults.list",
    severity  = "HIGH",
    pattern   = "nested-boolean",
    conditions = {
        "all": [
            {"var": "item.properties.enableSoftDelete",    "op": "is_true"},
            {"var": "item.properties.softDeleteRetentionInDays", "op": "gte", "value": "7"},
        ]
    },
)

FIXTURE_PASS = {
    "id"        : "/subscriptions/sub-123/resourceGroups/rg-security/providers/Microsoft.KeyVault/vaults/prod-kv",
    "name"      : "prod-kv",
    "properties": {
        "sku"                        : {"family": "A", "name": "standard"},
        "tenantId"                   : "tenant-abc",
        "enableSoftDelete"           : True,
        "softDeleteRetentionInDays"  : 90,
        "enablePurgeProtection"      : True,
    },
}

FIXTURE_FAIL = {
    "id"        : "/subscriptions/sub-123/resourceGroups/rg-dev/providers/Microsoft.KeyVault/vaults/dev-kv",
    "name"      : "dev-kv",
    "properties": {
        "enableSoftDelete"          : False,   # soft-delete off → FAIL
        "softDeleteRetentionInDays" : 0,
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "Key Vault must have soft-delete enabled with ≥7-day retention",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
