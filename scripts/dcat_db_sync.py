#!/usr/bin/env python3
"""DCAT-01 DB sync — upsert catalog YAMLs into rule_discoveries.

Reads /tmp/catalog/discovery_generator_data/{provider}/{service}/step6_*.discovery.yaml
and upserts into threat_engine_check.rule_discoveries.discoveries_data.

Idempotent: if existing row's discoveries_data already matches the YAML
(byte-for-byte after canonicalization), no UPDATE issued.
"""
import json
import os
import sys
from pathlib import Path

import psycopg2
import yaml

DB_HOST = os.getenv("CHECK_DB_HOST", "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com")
DB_NAME = os.getenv("CHECK_DB_NAME", "threat_engine_check")
DB_USER = os.getenv("CHECK_DB_USER", "postgres")
DB_PASS = os.getenv("CHECK_DB_PASSWORD", "jtv2BkJF8qoFtAKP")
DB_PORT = int(os.getenv("CHECK_DB_PORT", "5432"))

ROOT = Path("/tmp/catalog/discovery_generator_data")


def load_yaml_canonical(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f) or {}


def main() -> int:
    if not ROOT.is_dir():
        print(f"ERROR: {ROOT} not found")
        return 1

    conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER,
                            password=DB_PASS, port=DB_PORT)
    conn.autocommit = False

    total = updated = inserted = unchanged = errors = 0

    with conn.cursor() as cur:
        for provider_dir in sorted(ROOT.iterdir()):
            if not provider_dir.is_dir():
                continue
            provider = provider_dir.name
            for svc_dir in sorted(provider_dir.iterdir()):
                if not svc_dir.is_dir():
                    continue
                service = svc_dir.name
                yaml_files = sorted(svc_dir.glob("step6_*.discovery.yaml"))
                if not yaml_files:
                    continue
                yaml_path = yaml_files[0]

                try:
                    data = load_yaml_canonical(yaml_path)
                except Exception as exc:
                    print(f"  ERR {provider}/{service}: yaml load failed: {exc}")
                    errors += 1
                    continue

                total += 1
                discoveries_data_json = json.dumps(data, default=str, sort_keys=True)

                # Check existing row
                cur.execute(
                    "SELECT discoveries_data::text FROM rule_discoveries "
                    "WHERE provider=%s AND service=%s AND is_active=true "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (provider, service),
                )
                row = cur.fetchone()

                if row:
                    existing = row[0]
                    try:
                        existing_norm = json.dumps(json.loads(existing), sort_keys=True)
                    except Exception:
                        existing_norm = existing
                    if existing_norm == discoveries_data_json:
                        unchanged += 1
                        continue
                    cur.execute(
                        "UPDATE rule_discoveries "
                        "SET discoveries_data = %s::jsonb, updated_at = now(), "
                        "    source = 'dcat01_autogen', generated_by = 'catalog_gap_autogen.py' "
                        "WHERE provider=%s AND service=%s AND is_active=true",
                        (discoveries_data_json, provider, service),
                    )
                    updated += 1
                else:
                    cur.execute(
                        "INSERT INTO rule_discoveries "
                        "(service, provider, version, discoveries_data, source, generated_by, is_active) "
                        "VALUES (%s, %s, '1.0', %s::jsonb, 'dcat01_autogen', 'catalog_gap_autogen.py', true) "
                        "ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET "
                        "  discoveries_data = EXCLUDED.discoveries_data, "
                        "  updated_at = now(), "
                        "  is_active = true, "
                        "  source = EXCLUDED.source, "
                        "  generated_by = EXCLUDED.generated_by",
                        (service, provider, discoveries_data_json),
                    )
                    inserted += 1

                if (total % 50) == 0:
                    conn.commit()
                    print(f"  ...{total} processed (commit checkpoint)")

        conn.commit()

    print()
    print(f"=== DB Sync Complete ===")
    print(f"  total processed: {total}")
    print(f"  inserted:        {inserted}")
    print(f"  updated:         {updated}")
    print(f"  unchanged:       {unchanged}")
    print(f"  errors:          {errors}")
    return 0 if errors == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
