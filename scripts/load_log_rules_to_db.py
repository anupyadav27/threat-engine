#!/usr/bin/env python3
"""
Load ALL log detection rules (hand-written + generated) into rule_metadata table.

Merges with existing 10,440 config rules. Uses ON CONFLICT to avoid duplicates.
"""

import json
import os
import yaml
import psycopg2
from psycopg2.extras import execute_values
from pathlib import Path

RULES_DIR = Path("/Users/apple/Desktop/threat-engine/engines/ciem/rules")


def get_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"),
        port=5432,
        database="threat_engine_check",
        user="postgres",
        password=os.getenv("DB_PASSWORD", "jtv2BkJF8qoFtAKP"),
    )


def load_hand_written():
    """Load curated hand-written rules from l1_*.yaml, l2_*, l3_*."""
    rules = []
    for f in RULES_DIR.glob("l1_*.yaml"):
        data = yaml.safe_load(f.read_text()) or []
        # Handle both list format and {rules: [...]} format
        if isinstance(data, dict):
            data = data.get("rules", [])
        if not isinstance(data, list):
            data = []
        for r in data:
            r["quality"] = "curated"
            r["rule_source"] = "log"
            rules.append(r)

    # L2 scenarios as rules too (different rule_source)
    for f in RULES_DIR.glob("l2_*.yaml"):
        data = yaml.safe_load(f.read_text()) or []
        for r in data:
            r["quality"] = "curated"
            r["rule_source"] = "correlation"
            r["rule_id"] = r.get("scenario_id", r.get("rule_id", ""))
            rules.append(r)

    return rules


def load_generated():
    """Load auto-generated rules from generated/{csp}/*.yaml (if any exist)."""
    rules = []
    gen_dir = RULES_DIR / "generated"
    if not gen_dir.exists():
        return rules
    for csp_dir in gen_dir.iterdir():
        if not csp_dir.is_dir():
            continue
        for f in csp_dir.glob("*.yaml"):
            data = yaml.safe_load(f.read_text()) or []
            for r in data:
                r["quality"] = "auto"
                r["rule_source"] = "log"
                rules.append(r)
    return rules


def upsert_rules(conn, rules):
    """Insert/update rules into rule_metadata."""
    cur = conn.cursor()
    values = []
    for r in rules:
        rule_id = r.get("rule_id", r.get("scenario_id", ""))
        if not rule_id:
            continue

        csp = r.get("csp", "aws")
        service = r.get("service", "")
        severity = r.get("severity", "medium")
        title = r.get("title", "")
        description = r.get("description", "")

        # Engine classification
        engines = r.get("engines", [])
        if not engines:
            engines = [r.get("engine", r.get("primary_engine", "threat_engine"))]
        primary_engine = r.get("primary_engine", engines[0] if engines else "threat_engine")

        # MITRE
        mitre_tactics = r.get("mitre_tactic", r.get("mitre_tactics", ""))
        if isinstance(mitre_tactics, str):
            mitre_tactics = [mitre_tactics] if mitre_tactics else []
        mitre_techniques = r.get("mitre_technique", r.get("mitre_techniques", ""))
        if isinstance(mitre_techniques, str):
            mitre_techniques = [mitre_techniques] if mitre_techniques else []

        # L2/L3
        l2 = r.get("l2_scenarios", [])
        l3 = r.get("l3_baseline", "")

        values.append((
            rule_id, service, csp, csp,  # provider = csp
            severity, title, description,
            r.get("rule_source", "log"),
            r.get("log_source_type", r.get("audit_log_type", "")),
            r.get("audit_log_event", r.get("cloudtrail_event", "")),
            r.get("action_category", ""),
            engines, primary_engine,
            r.get("is_security_relevant", True),
            l2, l3,
            r.get("quality", "auto"),
            json.dumps(mitre_tactics),
            json.dumps(mitre_techniques),
            r.get("domain", r.get("mitre_tactic", "")),
            r.get("subcategory", r.get("action_category", "")),
        ))

    if values:
        execute_values(cur, """
            INSERT INTO rule_metadata (
                rule_id, service, csp, provider,
                severity, title, description,
                rule_source, log_source_type, audit_log_event,
                action_category, engines, primary_engine,
                is_security_relevant, l2_scenarios, l3_baseline,
                quality, mitre_tactics, mitre_techniques,
                domain, subcategory
            ) VALUES %s
            ON CONFLICT (rule_id) WHERE customer_id IS NULL AND tenant_id IS NULL DO UPDATE SET
                rule_source = COALESCE(EXCLUDED.rule_source, rule_metadata.rule_source),
                log_source_type = COALESCE(EXCLUDED.log_source_type, rule_metadata.log_source_type),
                audit_log_event = COALESCE(EXCLUDED.audit_log_event, rule_metadata.audit_log_event),
                action_category = COALESCE(EXCLUDED.action_category, rule_metadata.action_category),
                engines = COALESCE(EXCLUDED.engines, rule_metadata.engines),
                primary_engine = COALESCE(EXCLUDED.primary_engine, rule_metadata.primary_engine),
                is_security_relevant = COALESCE(EXCLUDED.is_security_relevant, rule_metadata.is_security_relevant),
                l2_scenarios = COALESCE(EXCLUDED.l2_scenarios, rule_metadata.l2_scenarios),
                l3_baseline = COALESCE(EXCLUDED.l3_baseline, rule_metadata.l3_baseline),
                quality = COALESCE(EXCLUDED.quality, rule_metadata.quality),
                csp = COALESCE(EXCLUDED.csp, rule_metadata.csp),
                updated_at = NOW()
        """, values, page_size=500)
        conn.commit()

    return len(values)


def upsert_rule_checks(conn, rules):
    """Insert/update curated rules into rule_checks (evaluator reads this)."""
    cur = conn.cursor()
    inserted = 0

    for r in rules:
        rule_id = r.get("rule_id", r.get("scenario_id", ""))
        if not rule_id:
            continue

        conditions = r.get("conditions")
        if not conditions:
            continue

        csp = r.get("csp", "aws")
        service = ""
        # Extract service from conditions for indexing
        conds = conditions.get("all", [conditions] if "field" in conditions else [])
        for c in conds:
            if c.get("field") == "service" and c.get("op") == "equals":
                service = c.get("value", "")
                break

        check_config = json.dumps({"conditions": conditions})

        cur.execute("""
            INSERT INTO rule_checks (rule_id, service, check_type, check_config, provider, is_active)
            VALUES (%s, %s, 'log', %s::jsonb, %s, true)
            ON CONFLICT (rule_id) DO UPDATE SET
                is_active = true,
                check_config = EXCLUDED.check_config,
                service = EXCLUDED.service
        """, (rule_id, service, check_config, csp))
        inserted += 1

    conn.commit()
    return inserted


def main():
    conn = get_conn()

    print("Loading hand-written rules...")
    hand = load_hand_written()
    print(f"  {len(hand)} hand-written rules")

    print("Loading generated rules...")
    gen = load_generated()
    print(f"  {len(gen)} generated rules")

    # Deduplicate — hand-written wins over generated
    seen = {}
    for r in hand:
        rid = r.get("rule_id", r.get("scenario_id", ""))
        if rid:
            seen[rid] = r
    for r in gen:
        rid = r.get("rule_id", "")
        if rid and rid not in seen:
            seen[rid] = r

    all_rules = list(seen.values())
    print(f"\nTotal rules to load: {len(all_rules)} (deduped from {len(hand) + len(gen)})")

    print("Upserting into rule_metadata...")
    loaded = upsert_rules(conn, all_rules)
    print(f"  {loaded} rules upserted")

    # Also sync curated rules into rule_checks (evaluator reads this)
    curated_with_conditions = [r for r in all_rules if r.get("conditions") and r.get("quality") == "curated"]
    if curated_with_conditions:
        print(f"\nSyncing {len(curated_with_conditions)} curated rules to rule_checks...")
        checks_loaded = upsert_rule_checks(conn, curated_with_conditions)
        print(f"  {checks_loaded} rules synced to rule_checks")

    # Verify
    cur = conn.cursor()
    cur.execute("SELECT rule_source, quality, count(*) FROM rule_metadata GROUP BY rule_source, quality ORDER BY rule_source, quality")
    print("\nFinal rule_metadata breakdown:")
    for r in cur.fetchall():
        print(f"  {r[0]:15s} {r[1]:10s} {r[2]}")

    cur.execute("SELECT count(*) FROM rule_metadata")
    print(f"\nTotal rules in DB: {cur.fetchone()[0]}")

    cur.execute("SELECT count(*) FROM rule_checks WHERE check_type = 'log' AND is_active = true")
    print(f"Active log rules in rule_checks: {cur.fetchone()[0]}")

    conn.close()


if __name__ == "__main__":
    main()
