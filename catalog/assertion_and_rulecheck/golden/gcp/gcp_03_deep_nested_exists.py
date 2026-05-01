"""
Pattern : deep-nested-exists
Rule    : gcp.sql.instance.ssl_enforcement_enabled
ForEach : gcp.sqladmin.instances.list
Severity: HIGH

Check: Cloud SQL instance must require SSL for all connections.
`settings.ipConfiguration.requireSsl` is a 3-level nested boolean.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "gcp.sql.instance.ssl_enforcement_enabled",
    for_each  = "gcp.sqladmin.instances.list",
    severity  = "HIGH",
    pattern   = "deep-nested-exists",
    conditions = {
        "var": "item.settings.ipConfiguration.requireSsl",
        "op" : "is_true",
    },
)

FIXTURE_PASS = {
    "name"           : "prod-mysql",
    "project"        : "my-project",
    "databaseVersion": "MYSQL_8_0",
    "state"          : "RUNNABLE",
    "settings"       : {
        "tier"           : "db-n1-standard-2",
        "ipConfiguration": {
            "requireSsl"              : True,
            "ipv4Enabled"             : False,
            "privateNetwork"          : "projects/my-project/global/networks/default",
            "authorizedNetworks"      : [],
        },
    },
}

FIXTURE_FAIL = {
    "name"    : "dev-mysql",
    "settings": {
        "ipConfiguration": {
            "requireSsl" : False,   # SSL not required → FAIL
            "ipv4Enabled": True,
        },
    },
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "Cloud SQL instance must have requireSsl = true",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
