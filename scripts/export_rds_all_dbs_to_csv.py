#!/usr/bin/env python3
"""
Export all tables from selected RDS Postgres databases into CSV files.

Outputs:
  <out>/<db_name>/
    tables/<schema>.<table>.csv
    schema/<schema>.<table>.txt
    manifest.json
  <out>/engine_database_table_mapping.csv

Notes:
  - Password is read from env var RDS_PASSWORD (or PGPASSWORD).
  - Uses psql + \\copy so CSV is written locally.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Tuple, Dict, Optional


@dataclass(frozen=True)
class Conn:
    host: str
    port: int
    user: str
    sslmode: str


ENGINE_BY_DB: Dict[str, str] = {
    "threat_engine_check": "engine_check",
    "threat_engine_discoveries": "engine_discoveries",
    "threat_engine_inventory": "engine_inventory",
    "threat_engine_threat": "engine_threat",
    "threat_engine_compliance": "engine_compliance",
    "threat_engine_iam": "engine_iam",
    "threat_engine_datasec": "engine_datasec",
    "threat_engine_onboarding": "engine_onboarding",
    "threat_engine_shared": "engine_common_orchestration",
    "threat_engine_pythonsdk": "data_pythonsdk",
    "threat_engine_secops": "engine_secops",
}


def _run_psql(conn: Conn, dbname: str, sql: str) -> str:
    env = os.environ.copy()
    # Prefer RDS_PASSWORD, otherwise rely on PGPASSWORD/.pgpass.
    if env.get("RDS_PASSWORD") and not env.get("PGPASSWORD"):
        env["PGPASSWORD"] = env["RDS_PASSWORD"]

    conninfo = f"host={conn.host} port={conn.port} user={conn.user} dbname={dbname} sslmode={conn.sslmode}"
    cmd = ["psql", conninfo, "-v", "ON_ERROR_STOP=1", "-At", "-c", sql]
    return subprocess.check_output(cmd, env=env, text=True)


def _run_psql_file(conn: Conn, dbname: str, sql: str, out_path: Path) -> None:
    env = os.environ.copy()
    if env.get("RDS_PASSWORD") and not env.get("PGPASSWORD"):
        env["PGPASSWORD"] = env["RDS_PASSWORD"]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        conninfo = f"host={conn.host} port={conn.port} user={conn.user} dbname={dbname} sslmode={conn.sslmode}"
        cmd = ["psql", conninfo, "-v", "ON_ERROR_STOP=1", "-c", sql]
        subprocess.check_call(cmd, env=env, stdout=f, stderr=subprocess.STDOUT)


def _sanitize_filename(s: str) -> str:
    # Keep it human readable; replace path-unsafe chars.
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)

def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def list_databases(conn: Conn, db_like: str) -> List[str]:
    # Connect to the default postgres db to list other databases.
    sql = f"""
        SELECT datname
        FROM pg_database
        WHERE datistemplate = false
          AND datname NOT IN ('rdsadmin')
          AND datname LIKE {_sql_literal(db_like)}
        ORDER BY datname;
    """
    out = _run_psql(conn, "postgres", sql)
    return [line.strip() for line in out.splitlines() if line.strip()]


def list_tables(conn: Conn, dbname: str) -> List[Tuple[str, str]]:
    sql = """
        SELECT table_schema, table_name
        FROM information_schema.tables
        WHERE table_type = 'BASE TABLE'
          AND table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY table_schema, table_name;
    """
    out = _run_psql(conn, dbname, sql)
    tables: List[Tuple[str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        schema, table = line.split("|", 1)
        tables.append((schema, table))
    return tables


def table_stats(conn: Conn, dbname: str) -> List[Dict[str, object]]:
    # Fast-ish stats (approx rows + size) for mapping and sanity checks.
    sql = """
        SELECT
          n.nspname AS schema,
          c.relname AS table,
          pg_total_relation_size(c.oid) AS size_bytes,
          c.reltuples::bigint AS approx_rows
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'r'
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        ORDER BY size_bytes DESC;
    """
    out = _run_psql(conn, dbname, sql)
    rows: List[Dict[str, object]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        schema, table, size_bytes, approx_rows = line.split("|", 3)
        rows.append(
            {
                "schema": schema,
                "table": table,
                "size_bytes": int(size_bytes),
                "approx_rows": int(float(approx_rows)) if approx_rows else 0,
            }
        )
    return rows


def export_table_csv(conn: Conn, dbname: str, schema: str, table: str, csv_path: Path) -> None:
    env = os.environ.copy()
    if env.get("RDS_PASSWORD") and not env.get("PGPASSWORD"):
        env["PGPASSWORD"] = env["RDS_PASSWORD"]

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    qualified = f'"{schema}"."{table}"'
    copy_sql = f"\\copy (SELECT * FROM {qualified}) TO {_sql_literal(str(csv_path))} CSV HEADER"

    conninfo = f"host={conn.host} port={conn.port} user={conn.user} dbname={dbname} sslmode={conn.sslmode}"
    cmd = ["psql", conninfo, "-v", "ON_ERROR_STOP=1", "-c", copy_sql]
    subprocess.check_call(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def export_table_schema(conn: Conn, dbname: str, schema: str, table: str, schema_path: Path) -> None:
    qualified = f'"{schema}"."{table}"'
    # \d+ is a psql meta-command; must go through psql -c as-is
    _run_psql_file(conn, dbname, f"\\d+ {qualified}", schema_path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5432)
    ap.add_argument("--user", required=True)
    ap.add_argument("--sslmode", default="require")
    ap.add_argument("--out", required=True, help="Output directory (will be created)")
    ap.add_argument("--db-like", default="threat_engine_%", help="SQL LIKE pattern for DB names")
    args = ap.parse_args()

    conn = Conn(host=args.host, port=args.port, user=args.user, sslmode=args.sslmode)
    out_root = Path(args.out).expanduser().resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    if not (os.environ.get("RDS_PASSWORD") or os.environ.get("PGPASSWORD") or os.environ.get("PGPASSFILE") or Path.home().joinpath(".pgpass").exists()):
        raise SystemExit("Missing password. Set env var RDS_PASSWORD (recommended) or PGPASSWORD.")

    dbs = list_databases(conn, args.db_like)
    mapping_rows: List[Dict[str, object]] = []

    for db in dbs:
        db_out = out_root / db
        (db_out / "tables").mkdir(parents=True, exist_ok=True)
        (db_out / "schema").mkdir(parents=True, exist_ok=True)

        stats = table_stats(conn, db)
        stats_by_key = {(r["schema"], r["table"]): r for r in stats}

        tables = list_tables(conn, db)
        exported: List[Dict[str, object]] = []

        for schema, table in tables:
            safe_name = _sanitize_filename(f"{schema}.{table}")
            csv_path = db_out / "tables" / f"{safe_name}.csv"
            schema_path = db_out / "schema" / f"{safe_name}.txt"

            export_table_csv(conn, db, schema, table, csv_path)
            export_table_schema(conn, db, schema, table, schema_path)

            s = stats_by_key.get((schema, table), {})
            exported.append(
                {
                    "schema": schema,
                    "table": table,
                    "csv": str(csv_path.relative_to(out_root)),
                    "schema_txt": str(schema_path.relative_to(out_root)),
                    "size_bytes": s.get("size_bytes"),
                    "approx_rows": s.get("approx_rows"),
                }
            )

            mapping_rows.append(
                {
                    "engine": ENGINE_BY_DB.get(db, db.replace("threat_engine_", "engine_")),
                    "database": db,
                    "schema": schema,
                    "table": table,
                    "size_bytes": s.get("size_bytes"),
                    "approx_rows": s.get("approx_rows"),
                }
            )

        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "connection": {
                "host": conn.host,
                "port": conn.port,
                "user": conn.user,
                "sslmode": conn.sslmode,
            },
            "database": db,
            "engine": ENGINE_BY_DB.get(db),
            "tables_exported": len(exported),
            "tables": exported,
        }
        (db_out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    mapping_path = out_root / "engine_database_table_mapping.csv"
    with mapping_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "engine",
                "database",
                "schema",
                "table",
                "size_bytes",
                "approx_rows",
            ],
        )
        w.writeheader()
        for r in mapping_rows:
            w.writerow(r)

    (out_root / "manifest.json").write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "db_like": args.db_like,
                "databases": dbs,
                "mapping_csv": str(mapping_path.name),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

