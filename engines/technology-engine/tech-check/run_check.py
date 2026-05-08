"""
tech-check — K8s Job entry point.

Evaluates active tech_rule_metadata rules against discovery findings
and writes PASS/FAIL results to tech_check_findings.

Usage::

    python run_check.py \\
        --scan-run-id 337a7425-... \\
        --account-id acct_abc123

Mirrors: engines/check/run_check.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(__file__))

from common.database.tech_db_manager import TechDBManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("tech_check")


def _finding_id(rule_id: str, resource_uid: str, scan_run_id: str) -> str:
    return hashlib.sha256(f"{rule_id}|{resource_uid}|{scan_run_id}".encode()).hexdigest()[:16]


def _evaluate_rule(rule: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate one rule against one discovery finding.

    Rule metadata may carry a `rule_metadata.check` dict with:
      expected_value  — the value raw_data must have
      expected_key    — the key to check inside raw_data
      operator        — eq | ne | in | gt | lt | gte | lte | contains | not_contains | exists (default: eq)

    Falls back to PASS when no check criteria are configured (schema-only discovery).
    """
    raw: Dict[str, Any] = finding.get("raw_data") or {}
    rule_meta: Dict[str, Any] = rule.get("rule_metadata") or {}
    check_cfg: Dict[str, Any] = rule_meta.get("check") or {}

    status   = "PASS"
    evidence: Dict[str, Any] = {"raw_data": raw}

    if check_cfg:
        key      = check_cfg.get("expected_key", "")
        expected = check_cfg.get("expected_value")
        operator = check_cfg.get("operator", "eq")
        actual   = raw.get(key)

        evidence["checked_key"]      = key
        evidence["expected_value"]   = expected
        evidence["actual_value"]     = actual
        evidence["operator"]         = operator

        if operator == "eq":
            status = "PASS" if str(actual) == str(expected) else "FAIL"
        elif operator == "ne":
            status = "PASS" if str(actual) != str(expected) else "FAIL"
        elif operator == "in":
            status = "PASS" if actual in (expected or []) else "FAIL"
        elif operator == "exists":
            status = "PASS" if actual is not None else "FAIL"
        elif operator == "contains":
            status = "PASS" if expected and expected in str(actual or "") else "FAIL"
        elif operator == "gt":
            try:
                status = "PASS" if float(actual) > float(expected) else "FAIL"
            except (TypeError, ValueError):
                status = "ERROR"
        elif operator == "lt":
            try:
                status = "PASS" if float(actual) < float(expected) else "FAIL"
            except (TypeError, ValueError):
                status = "ERROR"
        elif operator == "gte":
            try:
                status = "PASS" if float(actual) >= float(expected) else "FAIL"
            except (TypeError, ValueError):
                status = "ERROR"
        elif operator == "lte":
            try:
                status = "PASS" if float(actual) <= float(expected) else "FAIL"
            except (TypeError, ValueError):
                status = "ERROR"
        elif operator == "not_contains":
            status = "PASS" if expected and expected not in str(actual or "") else "FAIL"

    return {
        "finding_id":        _finding_id(rule["rule_id"], finding["resource_uid"], finding["scan_run_id"]),
        "scan_run_id":       finding["scan_run_id"],
        "tenant_id":         finding["tenant_id"],
        "account_id":        finding["account_id"],
        "credential_ref":    finding.get("credential_ref"),
        "credential_type":   finding.get("credential_type"),
        "provider":          finding["provider"],
        "tech_category":     finding["tech_category"],
        "region":            finding.get("region"),
        "resource_uid":      finding["resource_uid"],
        "resource_type":     finding.get("resource_type"),
        "rule_id":           rule["rule_id"],
        "rule_title":        rule.get("title"),
        "cis_benchmark":     rule.get("cis_benchmark"),
        "severity":          rule.get("severity", "medium"),
        "status":            status,
        "evidence":          evidence,
        "framework_mappings": {
            "nist":  rule.get("nist_controls", []),
            "soc2":  rule.get("soc2_criteria", []),
        },
        "remediation": rule.get("remediation"),
    }


def run(scan_run_id: str, account_id: str) -> None:
    db = TechDBManager()

    credential = db.get_credential(account_id=account_id)
    if not credential:
        raise ValueError(f"No credential for account_id={account_id}")

    tech_type = credential["tech_type"]
    rules     = db.get_active_rules(tech_type=tech_type)
    if not rules:
        logger.warning("No active rules for tech_type=%s", tech_type)
        db.mark_engine_completed(scan_run_id=scan_run_id, engine="tech-check", count=0)
        return

    raw_findings = db.get_findings_for_inventory(scan_run_id)
    if not raw_findings:
        logger.warning("No discovery findings for scan_run_id=%s", scan_run_id)
        db.mark_engine_completed(scan_run_id=scan_run_id, engine="tech-check", count=0)
        return

    check_findings: List[Dict[str, Any]] = []
    for rule in rules:
        disc_id = rule.get("discovery_id")
        # Match findings by discovery_id if rule specifies one; otherwise evaluate all
        targets = (
            [f for f in raw_findings if f.get("discovery_id") == disc_id]
            if disc_id else raw_findings
        )
        for finding in targets:
            check_findings.append(_evaluate_rule(rule, finding))

    inserted = db.upsert_check_findings(check_findings)
    fail_count = sum(1 for f in check_findings if f["status"] == "FAIL")
    db.mark_engine_completed(scan_run_id=scan_run_id, engine="tech-check", count=inserted)
    logger.info(
        "Check complete: %d findings (%d FAIL) for %s",
        inserted, fail_count, tech_type,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-run-id", required=True)
    parser.add_argument("--account-id",  required=True)
    args = parser.parse_args()
    try:
        run(args.scan_run_id, args.account_id)
    except Exception as exc:
        logger.error("tech-check failed: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
