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
from typing import Dict, Any

ENGINES: Dict[str, Any] = {
    "threat": {
        "deployment": "engine-threat",
        "db_env": "THREAT_DB",
        "tables_to_check": ["threat_detections", "threat_findings"],
        "expected_columns": {
            "threat_detections": [
                "finding_id", "scan_run_id", "tenant_id", "account_id",
                "provider", "region", "resource_uid", "resource_type",
                "threat_category", "severity", "risk_score",
                "mitre_tactics", "mitre_techniques",
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
        "tables_to_check": ["inventory_findings", "inventory_relationships", "inventory_scans"],
        "expected_columns": {
            "inventory_findings": [
                "resource_uid", "resource_type", "tenant_id", "account_id",
                "provider", "region", "first_seen_at", "last_seen_at",
            ],
        },
    },
    "compliance": {
        "deployment": "engine-compliance",
        "db_env": "COMPLIANCE_DB",
        "tables_to_check": ["compliance_report", "compliance_frameworks", "rule_control_mapping"],
        "expected_columns": {
            "compliance_frameworks": [
                "framework_id", "framework_name", "version", "csp", "is_active",
            ],
            "compliance_report": [
                "scan_run_id", "tenant_id", "framework_id",
                "total_controls", "controls_passed", "controls_failed", "overall_score",
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


def check_columns(engine_name: str, engine_config: dict, null_check: bool = False) -> None:
    """Check actual DB columns against expected list."""
    deployment = engine_config["deployment"]
    tables = engine_config["tables_to_check"]
    expected = engine_config.get("expected_columns", {})

    print(f"\n=== Engine: {engine_name} (deployment/{deployment}) ===")

    for table in tables:
        py_code = f"""
import os, json, psycopg2
db_host = os.getenv('{engine_config["db_env"]}_HOST', '')
db_name = os.getenv('{engine_config["db_env"]}_NAME', '')
db_user = os.getenv('{engine_config["db_env"]}_USER', 'postgres')
db_pass = os.getenv('{engine_config["db_env"]}_PASSWORD', '')
if not db_host:
    print(json.dumps({{"error": "no DB_HOST env var"}}))
else:
    conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_pass, sslmode='require')
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
            print(f"  *** MISSING (BFF expects but DB lacks): {sorted(missing)}")
        if extra:
            print(f"  Extra (DB has but BFF doesn't track): {sorted(extra)[:10]}")
        if not missing:
            print(f"  OK — all expected columns present")

        if null_check and expected_cols:
            always_null = []
            for col in sorted(expected_cols & actual_cols):
                null_py = f"""
import os, json, psycopg2
db_host = os.getenv('{engine_config["db_env"]}_HOST', '')
db_name = os.getenv('{engine_config["db_env"]}_NAME', '')
db_user = os.getenv('{engine_config["db_env"]}_USER', 'postgres')
db_pass = os.getenv('{engine_config["db_env"]}_PASSWORD', '')
conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_pass, sslmode='require')
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM {table} WHERE {col} IS NOT NULL")
count = cur.fetchone()[0]
total_py = "SELECT COUNT(*) FROM {table}"
cur.execute(total_py)
total = cur.fetchone()[0]
print(json.dumps({{"col": "{col}", "non_null_count": count, "total": total}}))
"""
                null_result = exec_in_pod(deployment, null_py)
                if "error" not in null_result:
                    non_null = null_result.get("non_null_count", -1)
                    total = null_result.get("total", 0)
                    if total > 0 and non_null == 0:
                        always_null.append(col)
            if always_null:
                print(f"  *** ALWAYS NULL (column exists but no data): {always_null}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check DB schema gaps vs BFF expectations")
    parser.add_argument("--engine", choices=list(ENGINES.keys()), help="Single engine to check")
    parser.add_argument("--all", action="store_true", help="Check all engines")
    parser.add_argument("--null-check", action="store_true", help="Also check for always-NULL columns")
    args = parser.parse_args()

    if args.all:
        engines_to_check = ENGINES
    elif args.engine:
        engines_to_check = {args.engine: ENGINES[args.engine]}
    else:
        parser.print_help()
        sys.exit(1)

    for name, config in engines_to_check.items():
        check_columns(name, config, null_check=args.null_check)
