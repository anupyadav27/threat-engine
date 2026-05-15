#!/usr/bin/env python3
"""
Sync YAML pattern catalog → threat_scenario_patterns table.

Run at deploy time (Sprint 5 pipeline) or manually to update the DB copy
of patterns from the catalog/threat_patterns/ YAML files.

Usage:
    python sync_patterns_to_db.py [--catalog-dir <path>] [--dry-run]

The YAML is the source of truth. This script is an idempotent upsert —
safe to run multiple times. It does NOT delete patterns that are no longer
in YAML (they must be manually deprecated via deprecated_at).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from threat_v1.database import get_threat_conn
from threat_v1.patterns.registry import PatternRegistry


def sync(catalog_dir: str, dry_run: bool = False) -> int:
    patterns = PatternRegistry.load_from_yaml_dir(catalog_dir)
    if not patterns:
        print(f"ERROR: no valid patterns found in {catalog_dir}", file=sys.stderr)
        return 1

    conn = get_threat_conn()
    cur = conn.cursor()

    upserted = 0
    for p in patterns:
        raw_yaml = yaml.dump(p.model_dump(), default_flow_style=False)
        if dry_run:
            print(f"DRY-RUN upsert {p.id} tier={p.tier} csp={p.csps}")
            upserted += 1
            continue

        cur.execute(
            """
            INSERT INTO threat_scenario_patterns (
                pattern_key, pattern_yaml, tier, severity_base, confidence,
                csps, mitre_techniques, mitre_tactics,
                deprecated_at, version, active
            ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s, true)
            ON CONFLICT (pattern_key) DO UPDATE SET
                pattern_yaml    = EXCLUDED.pattern_yaml,
                tier            = EXCLUDED.tier,
                severity_base   = EXCLUDED.severity_base,
                confidence      = EXCLUDED.confidence,
                csps            = EXCLUDED.csps,
                mitre_techniques= EXCLUDED.mitre_techniques,
                mitre_tactics   = EXCLUDED.mitre_tactics,
                deprecated_at   = EXCLUDED.deprecated_at,
                version         = EXCLUDED.version,
                active          = EXCLUDED.active,
                updated_at      = NOW()
            """,
            (
                p.id,
                raw_yaml,
                p.tier,
                p.severity_base,
                p.confidence,
                json.dumps(list(p.csps)),
                json.dumps(p.mitre_techniques),
                json.dumps(p.mitre_tactics),
                None,
                p.version,
            ),
        )
        upserted += 1

    if not dry_run:
        conn.commit()
    cur.close()
    conn.close()

    print(f"{'DRY-RUN ' if dry_run else ''}Synced {upserted}/{len(patterns)} patterns.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync YAML patterns to DB")
    parser.add_argument("--catalog-dir", default="catalog/threat_patterns")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    sys.exit(sync(args.catalog_dir, args.dry_run))
