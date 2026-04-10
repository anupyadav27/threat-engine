#!/usr/bin/env python3
"""
Load enriched CIEM YAML rules into the Check database tables:
  - rule_metadata  (metadata_source = 'ciem')
  - rule_checks    (source = 'ciem', check_type = 'log_event')

This makes CIEM rules joinable with ciem_findings by rule_id, just like
Check rules are joinable with check_findings.

Usage:
    python load_ciem_rules_to_db.py                    # dry-run (print stats)
    python load_ciem_rules_to_db.py --apply            # upsert to database
    python load_ciem_rules_to_db.py --apply --tenant-id default-tenant
"""

import os
import sys
import json
import argparse
import glob as globmod

import yaml

# Add project paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


def _get_check_db_conn():
    """Connect to the Check database (where rule_metadata lives)."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
    )


def load_all_rules() -> list:
    """Load all L1 CIEM rules from YAML files.

    Returns list of enriched rule dicts.
    """
    rules_dir = os.path.abspath(RULES_DIR)
    all_rules = []

    for fpath in sorted(globmod.glob(os.path.join(rules_dir, "l1_*.yaml"))):
        with open(fpath, "r") as f:
            data = yaml.safe_load(f)

        if isinstance(data, list):
            rules = data
        elif isinstance(data, dict) and "rules" in data:
            rules = data["rules"]
        else:
            continue

        for rule in rules:
            if isinstance(rule, dict) and "rule_id" in rule:
                rule["_source_file"] = os.path.basename(fpath)
                all_rules.append(rule)

    return all_rules


def rule_to_metadata_row(rule: dict, tenant_id: str) -> dict:
    """Convert a CIEM rule dict → row for rule_metadata table."""
    rule_id = rule["rule_id"]
    severity = (rule.get("severity") or "medium").lower()

    # Service: prefer explicit service field, fall back to log_source_type
    service = rule.get("service") or rule.get("log_source_type") or "cloudtrail"

    # Provider
    provider = rule.get("provider", "aws")

    # MITRE — normalize to JSON arrays
    mitre_tactics = rule.get("mitre_tactics") or rule.get("mitre_tactic")
    if isinstance(mitre_tactics, str):
        mitre_tactics = [mitre_tactics]
    mitre_techniques = rule.get("mitre_techniques") or rule.get("mitre_technique")
    if isinstance(mitre_techniques, str):
        mitre_techniques = [mitre_techniques]

    # Compliance frameworks
    compliance = rule.get("compliance_frameworks") or []

    # Domain → subcategory mapping
    domain = rule.get("domain", "general")
    action_category = rule.get("action_category", "")

    return {
        "rule_id": rule_id,
        "service": service,
        "provider": provider,
        "severity": severity,
        "title": rule.get("title", rule_id),
        "description": rule.get("description", ""),
        "remediation": rule.get("remediation", ""),
        "rationale": rule.get("description", ""),
        "domain": domain,
        "subcategory": action_category,
        "compliance_frameworks": json.dumps(compliance),
        "mitre_tactics": json.dumps(mitre_tactics or []),
        "mitre_techniques": json.dumps(mitre_techniques or []),
        "risk_score": rule.get("risk_score", 50),
        "threat_category": domain,
        "metadata_source": "ciem",
        "source": "ciem",
        "generated_by": "ciem_rule_loader",
        "customer_id": "default",
        "tenant_id": tenant_id,
        "version": "1.0",
        "risk_indicators": json.dumps({
            "action_category": action_category,
            "engines": rule.get("engines", []),
            "primary_engine": rule.get("primary_engine", "ciem"),
            "log_source_type": rule.get("log_source_type") or rule.get("source_type", "cloudtrail"),
        }),
    }


def rule_to_check_row(rule: dict, tenant_id: str) -> dict:
    """Convert a CIEM rule dict → row for rule_checks table."""
    service = rule.get("service") or rule.get("log_source_type") or "cloudtrail"

    # Build check_config from conditions
    conditions = rule.get("conditions") or rule.get("condition") or {}
    check_config = {
        "conditions": conditions,
        "log_source_type": rule.get("log_source_type") or rule.get("source_type", "cloudtrail"),
        "engines": rule.get("engines", []),
        "primary_engine": rule.get("primary_engine", "ciem"),
        "l2_scenarios": rule.get("l2_scenarios", []),
    }

    return {
        "rule_id": rule["rule_id"],
        "service": service,
        "provider": rule.get("provider", "aws"),
        "check_type": "log_event",
        "customer_id": "default",
        "tenant_id": tenant_id,
        "check_config": json.dumps(check_config),
        "source": "ciem",
        "generated_by": "ciem_rule_loader",
        "version": "1.0",
        "is_active": True,
    }


UPSERT_METADATA_SQL = """
INSERT INTO rule_metadata (
    rule_id, service, provider, severity, title, description,
    remediation, rationale, domain, subcategory,
    compliance_frameworks, mitre_tactics, mitre_techniques,
    risk_score, threat_category,
    metadata_source, source, generated_by,
    customer_id, tenant_id, version, risk_indicators
) VALUES (
    %(rule_id)s, %(service)s, %(provider)s, %(severity)s, %(title)s, %(description)s,
    %(remediation)s, %(rationale)s, %(domain)s, %(subcategory)s,
    %(compliance_frameworks)s::jsonb, %(mitre_tactics)s::jsonb, %(mitre_techniques)s::jsonb,
    %(risk_score)s, %(threat_category)s,
    %(metadata_source)s, %(source)s, %(generated_by)s,
    %(customer_id)s, %(tenant_id)s, %(version)s, %(risk_indicators)s::jsonb
)
ON CONFLICT (rule_id, customer_id, tenant_id) DO UPDATE SET
    service = EXCLUDED.service,
    provider = EXCLUDED.provider,
    severity = EXCLUDED.severity,
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    remediation = EXCLUDED.remediation,
    rationale = EXCLUDED.rationale,
    domain = EXCLUDED.domain,
    subcategory = EXCLUDED.subcategory,
    compliance_frameworks = EXCLUDED.compliance_frameworks,
    mitre_tactics = EXCLUDED.mitre_tactics,
    mitre_techniques = EXCLUDED.mitre_techniques,
    risk_score = EXCLUDED.risk_score,
    threat_category = EXCLUDED.threat_category,
    risk_indicators = EXCLUDED.risk_indicators,
    updated_at = NOW()
"""

UPSERT_CHECK_SQL = """
INSERT INTO rule_checks (
    rule_id, service, provider, check_type,
    customer_id, tenant_id, check_config,
    source, generated_by, version, is_active
) VALUES (
    %(rule_id)s, %(service)s, %(provider)s, %(check_type)s,
    %(customer_id)s, %(tenant_id)s, %(check_config)s::jsonb,
    %(source)s, %(generated_by)s, %(version)s, %(is_active)s
)
ON CONFLICT (rule_id, customer_id, tenant_id) DO UPDATE SET
    service = EXCLUDED.service,
    provider = EXCLUDED.provider,
    check_type = EXCLUDED.check_type,
    check_config = EXCLUDED.check_config,
    source = EXCLUDED.source,
    is_active = EXCLUDED.is_active,
    updated_at = NOW()
"""


def main():
    parser = argparse.ArgumentParser(description="Load CIEM rules into rule_metadata + rule_checks")
    parser.add_argument("--apply", action="store_true", help="Actually write to database")
    parser.add_argument("--tenant-id", default="default-tenant", help="Tenant ID (default: default-tenant)")
    args = parser.parse_args()

    rules = load_all_rules()
    print(f"Loaded {len(rules)} CIEM L1 rules from YAML\n")

    # Stats by provider
    by_provider = {}
    by_domain = {}
    for r in rules:
        p = r.get("provider", "aws")
        d = r.get("domain", "general")
        by_provider[p] = by_provider.get(p, 0) + 1
        by_domain[d] = by_domain.get(d, 0) + 1

    print("By provider:")
    for p, c in sorted(by_provider.items(), key=lambda x: -x[1]):
        print(f"  {p:<10} {c:>4}")
    print()
    print("By domain:")
    for d, c in sorted(by_domain.items(), key=lambda x: -x[1]):
        print(f"  {d:<25} {c:>4}")
    print()

    if not args.apply:
        print("Dry-run complete. Use --apply to write to database.")

        # Print sample rows
        if rules:
            sample = rules[0]
            print(f"\nSample rule_metadata row for: {sample['rule_id']}")
            row = rule_to_metadata_row(sample, args.tenant_id)
            for k, v in row.items():
                print(f"  {k:<25} = {v}")
        return

    # ── Apply to database ─────────────────────────────────────────────
    import psycopg2

    conn = _get_check_db_conn()
    try:
        with conn.cursor() as cur:
            metadata_ok = 0
            metadata_err = 0
            checks_ok = 0
            checks_err = 0

            for rule in rules:
                # rule_metadata
                try:
                    row = rule_to_metadata_row(rule, args.tenant_id)
                    cur.execute(UPSERT_METADATA_SQL, row)
                    metadata_ok += 1
                except Exception as exc:
                    metadata_err += 1
                    conn.rollback()
                    print(f"  ERROR rule_metadata {rule['rule_id']}: {exc}")
                    continue

                # rule_checks
                try:
                    row = rule_to_check_row(rule, args.tenant_id)
                    cur.execute(UPSERT_CHECK_SQL, row)
                    checks_ok += 1
                except Exception as exc:
                    checks_err += 1
                    conn.rollback()
                    print(f"  ERROR rule_checks {rule['rule_id']}: {exc}")

            conn.commit()

        print(f"\nrule_metadata: {metadata_ok} upserted, {metadata_err} errors")
        print(f"rule_checks:   {checks_ok} upserted, {checks_err} errors")
        print(f"\nAll CIEM rules loaded with metadata_source='ciem', check_type='log_event'")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
