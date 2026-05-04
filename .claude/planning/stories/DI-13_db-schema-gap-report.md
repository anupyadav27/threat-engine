# DI-13: DB Schema Alignment — Automated Gap Report Script

## Track
Track 3 — DB Schema Alignment

## Priority
P1 — foundational for DI-14 (migrations) and DI-15 (MITRE backfill)

## Story
As a backend engineer, I need an automated script that compares the SQL columns used in BFF queries against the actual columns in each engine's PostgreSQL database, so that we have a definitive list of schema gaps (missing columns, wrong column names, always-NULL columns).

## Background

The BFF calls engine endpoints which in turn query PostgreSQL. If the BFF asks the threat engine for `mitre_tactics` but that column is always NULL, the MITRE tab will always be empty regardless of how perfect the BFF logic is.

The script connects to each engine DB via `kubectl exec` (since RDS is not publicly accessible) and runs `information_schema.columns` queries.

## File to Create

`/Users/apple/Desktop/threat-engine/scripts/db_schema_gap_report.py`

## Implementation

```python
#!/usr/bin/env python3
"""
DB schema gap report — compare BFF-expected columns against actual DB schema.

Usage:
    python scripts/db_schema_gap_report.py --engine threat
    python scripts/db_schema_gap_report.py --all
    python scripts/db_schema_gap_report.py --all --null-check

Requires: kubectl access to threat-engine-engines namespace.
"""

import argparse
import subprocess
import json
import sys

ENGINES = {
    "threat": {
        "deployment": "engine-threat",
        "db_env": "THREAT_DB",
        "tables_to_check": ["threat_detections", "threat_findings"],
        "expected_columns": {
            "threat_detections": [
                "finding_id", "scan_run_id", "tenant_id", "account_id",
                "provider", "region", "resource_uid", "resource_type",
                "threat_category", "severity", "risk_score",
                "mitre_tactics", "mitre_techniques",   # <-- often NULL
                "status", "first_seen_at", "last_seen_at",
            ],
        },
    },
    "check": {
        "deployment": "engine-check",
        "db_env": "CHECK_DB",
        "tables_to_check": ["check_findings", "rule_discoveries"],
        "expected_columns": {
            "check_findings": [
                "finding_id", "scan_run_id", "tenant_id", "account_id",
                "rule_id", "status", "severity", "resource_uid",
                "resource_type", "region", "provider",
                "first_seen_at", "last_seen_at",
            ],
        },
    },
    "inventory": {
        "deployment": "engine-inventory",
        "db_env": "INVENTORY_DB",
        "tables_to_check": ["resource_inventory", "resource_relationships"],
        "expected_columns": {
            "resource_inventory": [
                "resource_uid", "resource_type", "tenant_id", "account_id",
                "provider", "region", "tags", "first_seen_at", "last_seen_at",
            ],
        },
    },
    "compliance": {
        "deployment": "engine-compliance",
        "db_env": "COMPLIANCE_DB",
        "tables_to_check": ["compliance_scores", "compliance_frameworks", "rule_control_mapping"],
        "expected_columns": {
            "compliance_frameworks": [
                "framework_id", "framework_name", "version", "csp", "is_active",
            ],
            "compliance_scores": [
                "scan_run_id", "tenant_id", "framework_id", "score",
                "pass_count", "fail_count", "total_controls",
            ],
        },
    },
    "risk": {
        "deployment": "engine-risk",
        "db_env": "RISK_DB",
        "tables_to_check": ["risk_scenarios", "risk_summary"],
        "expected_columns": {
            "risk_scenarios": [
                "scan_run_id", "tenant_id", "account_id",
                "scenario_id", "title", "risk_score", "severity", "blast_radius",
            ],
        },
    },
}


def exec_in_pod(deployment: str, python_code: str) -> dict:
    """Run Python inline in a pod and return parsed JSON output."""
    cmd = [
        "kubectl", "exec", "-n", "threat-engine-engines",
        f"deployment/{deployment}", "--",
        "python3", "-c", python_code,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return {"error": result.stderr[:500]}
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return {"error": f"Non-JSON output: {result.stdout[:200]}"}


def check_columns(engine_name: str, engine_config: dict, null_check: bool = False):
    """Check actual DB columns against expected list."""
    deployment = engine_config["deployment"]
    tables = engine_config["tables_to_check"]
    expected = engine_config.get("expected_columns", {})

    print(f"\n=== Engine: {engine_name} (deployment/{deployment}) ===")

    for table in tables:
        # Get actual columns from information_schema
        py_code = f"""
import os, json, psycopg2
db_host = os.getenv('{engine_config["db_env"]}_HOST', '')
db_name = os.getenv('{engine_config["db_env"]}_NAME', '')
db_user = os.getenv('{engine_config["db_env"]}_USER', 'postgres')
db_pass = os.getenv('{engine_config["db_env"]}_PASSWORD', '')
conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_pass)
cur = conn.cursor()
cur.execute("SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_name=%s ORDER BY ordinal_position", ('{table}',))
rows = cur.fetchall()
print(json.dumps({{"table": "{table}", "columns": [dict(name=r[0], type=r[1], nullable=r[2]) for r in rows]}}))
"""
        result = exec_in_pod(deployment, py_code)

        if "error" in result:
            print(f"  [{table}] ERROR: {result['error']}")
            continue

        actual_cols = {c["name"] for c in result.get("columns", [])}
        expected_cols = set(expected.get(table, []))

        missing = expected_cols - actual_cols
        extra = actual_cols - expected_cols

        print(f"\n  Table: {table}")
        print(f"  Actual columns ({len(actual_cols)}): {sorted(actual_cols)}")
        if missing:
            print(f"  MISSING (BFF expects but DB lacks): {sorted(missing)}")
        if extra:
            print(f"  EXTRA (DB has but BFF doesn't use): {sorted(extra)[:10]}")

        # Check for always-NULL columns
        if null_check and expected_cols:
            for col in expected_cols & actual_cols:
                null_py = f"""
import os, json, psycopg2
db_host = os.getenv('{engine_config["db_env"]}_HOST', '')
db_name = os.getenv('{engine_config["db_env"]}_NAME', '')
db_user = os.getenv('{engine_config["db_env"]}_USER', 'postgres')
db_pass = os.getenv('{engine_config["db_env"]}_PASSWORD', '')
conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_pass)
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM {table} WHERE {col} IS NOT NULL LIMIT 1")
count = cur.fetchone()[0]
print(json.dumps({{"col": "{col}", "non_null_count": count}}))
"""
                null_result = exec_in_pod(deployment, null_py)
                if null_result.get("non_null_count", -1) == 0:
                    print(f"  ALWAYS NULL: {col}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=list(ENGINES.keys()), help="Single engine to check")
    parser.add_argument("--all", action="store_true", help="Check all engines")
    parser.add_argument("--null-check", action="store_true", help="Also check for always-NULL columns")
    args = parser.parse_args()

    engines_to_check = ENGINES if args.all else {args.engine: ENGINES[args.engine]} if args.engine else {}
    if not engines_to_check:
        parser.print_help()
        sys.exit(1)

    for name, config in engines_to_check.items():
        check_columns(name, config, null_check=args.null_check)
```

## Running the Script

```bash
# Check threat engine for missing columns
python /Users/apple/Desktop/threat-engine/scripts/db_schema_gap_report.py --engine threat --null-check

# Check all engines
python /Users/apple/Desktop/threat-engine/scripts/db_schema_gap_report.py --all --null-check
```

## Acceptance Criteria

- [ ] Script file created at `scripts/db_schema_gap_report.py`
- [ ] Script runs for at least `threat`, `check`, `compliance`, `inventory`, `risk` engines
- [ ] Output identifies columns in `expected_columns` dict that are missing in the actual DB
- [ ] With `--null-check`: output identifies columns that are always NULL
- [ ] Script produces output consumed by DI-14 (migrations) and DI-15 (MITRE backfill)
- [ ] Script handles engine pod not available gracefully (prints error, continues to next engine)

## Expected Findings (based on known bugs)

- `threat_detections.mitre_tactics` — likely always NULL (bug DI-15)
- `threat_detections.mitre_techniques` — likely always NULL
- Various `check_findings` schema fields — verify match against actual DB

## Definition of Done
- Script runs against staging cluster
- Gap report committed or pasted into a follow-up doc
- Findings drive the DI-14 migration stories
