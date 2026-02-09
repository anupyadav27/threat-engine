#!/usr/bin/env python3
"""
Upload AWS rule YAML files to discoveries DB table rule_definitions.
Reference: consolidated_services/database/migrations/009_rule_definitions.sql
Source: engine_input/engine_configscan_aws/input/rule_db/default/services/
"""
import os
import sys

# Project root
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import psycopg2
from pathlib import Path

# Default paths
DEFAULT_SERVICES_DIR = os.path.join(
    ROOT, "engine_input", "engine_configscan_aws", "input", "rule_db", "default", "services"
)
CSP = "aws"


def get_discoveries_config():
    """Read config from env (DISCOVERIES_DB_*) so script runs without asyncpg/consolidated_services."""
    return {
        "host": os.getenv("DISCOVERIES_DB_HOST", "localhost"),
        "port": int(os.getenv("DISCOVERIES_DB_PORT", "5432")),
        "database": os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        "user": os.getenv("DISCOVERIES_DB_USER", "postgres"),
        "password": os.getenv("DISCOVERIES_DB_PASSWORD", ""),
    }


def upload_rules(services_dir: str = None, csp: str = CSP, upsert: bool = True):
    services_dir = services_dir or DEFAULT_SERVICES_DIR
    services_path = Path(services_dir)
    if not services_path.is_dir():
        raise FileNotFoundError(f"Services dir not found: {services_dir}")

    config = get_discoveries_config()
    conn = psycopg2.connect(**config)
    cur = conn.cursor()

    sql = """
    INSERT INTO rule_definitions (csp, service, file_path, content_yaml, updated_at)
    VALUES (%s, %s, %s, %s, NOW())
    ON CONFLICT (csp, service, file_path)
    DO UPDATE SET content_yaml = EXCLUDED.content_yaml, updated_at = NOW();
    """ if upsert else """
    INSERT INTO rule_definitions (csp, service, file_path, content_yaml)
    VALUES (%s, %s, %s, %s);
    """

    count = 0
    for service_dir in sorted(services_path.iterdir()):
        if not service_dir.is_dir():
            continue
        service_name = service_dir.name
        for yaml_path in service_dir.rglob("*.yaml"):
            rel = yaml_path.relative_to(service_dir)
            file_path = str(rel).replace("\\", "/")
            try:
                content = yaml_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                print(f"  skip {service_name}/{file_path}: {e}")
                continue
            try:
                cur.execute(sql, (csp, service_name, file_path, content))
                count += 1
                if count % 100 == 0:
                    print(f"  uploaded {count} files...")
            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Insert failed {service_name}/{file_path}: {e}") from e

    conn.commit()
    cur.close()
    conn.close()
    return count


def main():
    import argparse
    p = argparse.ArgumentParser(description="Upload AWS rule YAMLs to rule_definitions (discoveries DB)")
    p.add_argument("--services-dir", default=DEFAULT_SERVICES_DIR, help="Path to services folder")
    p.add_argument("--csp", default=CSP, help="CSP identifier (default: aws)")
    p.add_argument("--no-upsert", action="store_true", help="Fail on duplicate instead of update")
    args = p.parse_args()
    n = upload_rules(services_dir=args.services_dir, csp=args.csp, upsert=not args.no_upsert)
    print(f"Done. Uploaded {n} rule definition(s).")


if __name__ == "__main__":
    main()
