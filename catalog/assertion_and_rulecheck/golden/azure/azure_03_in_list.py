"""
Pattern : value-in-list
Rule    : azure.sql.server.tls_minimum_version_compliant
ForEach : azure.sql.servers.list
Severity: HIGH

Check: Azure SQL Server must use TLS 1.2 or higher.
The `minimalTlsVersion` field is a string enum. Using `in` asserts
the value is one of the acceptable versions.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "azure.sql.server.tls_minimum_version_compliant",
    for_each  = "azure.sql.servers.list",
    severity  = "HIGH",
    pattern   = "value-in-list",
    conditions = {
        "var"  : "item.properties.minimalTlsVersion",
        "op"   : "in",
        "value": ["1.2", "1.3"],
    },
)

FIXTURE_PASS = {
    "id"        : "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Sql/servers/prod-sql",
    "name"      : "prod-sql",
    "properties": {
        "state"             : "Ready",
        "minimalTlsVersion" : "1.2",
        "publicNetworkAccess": "Disabled",
    },
}

FIXTURE_FAIL = {
    "id"        : "/subscriptions/sub-123/resourceGroups/rg-legacy/providers/Microsoft.Sql/servers/old-sql",
    "name"      : "old-sql",
    "properties": {
        "state"             : "Ready",
        "minimalTlsVersion" : "1.0",   # too old → FAIL
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "SQL Server minimalTlsVersion must be 1.2 or 1.3",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
