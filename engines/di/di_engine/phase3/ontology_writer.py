"""
DI Engine Phase 3 — Attack Ontology Writer.

Reads resource_ontology_catalog from DB (seeded by catalog/ontology/upload_ontology_catalog.py),
classifies every asset in asset_inventory for this scan, and writes:
  - is_attack_entry_point + attack_entry_point_category
  - is_attack_target      + attack_target_category

into resource_security_posture via upsert.

Non-fatal: any exception is caught and logged — never aborts the DI pipeline.
Called from: engines/di/run_scan.py after write_catalog_relationships() (Phase 2).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

import psycopg2
import psycopg2.extras

from engine_common.db_connections import get_di_conn

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500


@dataclass
class OntologyRule:
    entry_point_category:   Optional[str]
    attack_target_category: Optional[str]
    is_conditional:         bool
    condition_field:        Optional[str]
    condition_value:        Optional[str]
    condition_operator:     str = "eq"


# ── DB loaders ───────────────────────────────────────────────────────────────────

def _load_rules(
    conn: "psycopg2.connection",
    csp: str,
) -> Dict[str, List[OntologyRule]]:
    """Load all active ontology rules for the given CSP, keyed by resource_type."""
    sql = """
        SELECT resource_type, entry_point_category, attack_target_category,
               is_conditional, condition_field, condition_value, condition_operator
        FROM resource_ontology_catalog
        WHERE csp = %s AND is_active = TRUE
        ORDER BY resource_type
    """
    rules: Dict[str, List[OntologyRule]] = {}
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (csp,))
        for row in cur.fetchall():
            rt = row["resource_type"]
            rules.setdefault(rt, []).append(OntologyRule(
                entry_point_category=row["entry_point_category"],
                attack_target_category=row["attack_target_category"],
                is_conditional=row["is_conditional"],
                condition_field=row["condition_field"],
                condition_value=row["condition_value"],
                condition_operator=row["condition_operator"] or "eq",
            ))
    return rules


def _fetch_assets(
    conn: "psycopg2.connection",
    tenant_id: str,
    scan_run_id: str,
    csp: str,
) -> Iterator[Tuple[str, str, str, Dict[str, Any]]]:
    """Yield (resource_uid, resource_type, resource_name, emitted_fields) for all assets."""
    sql = """
        SELECT resource_uid, resource_type, resource_name,
               account_id, region, emitted_fields
        FROM asset_inventory
        WHERE tenant_id = %s AND scan_run_id = %s AND provider = %s
          AND resource_uid > %s
        ORDER BY resource_uid
        LIMIT 1000
    """
    last_uid = ""
    while True:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (tenant_id, scan_run_id, csp, last_uid))
            rows = cur.fetchall()
        if not rows:
            break
        for row in rows:
            ef = row["emitted_fields"]
            if isinstance(ef, str):
                try:
                    ef = json.loads(ef)
                except (ValueError, TypeError):
                    ef = {}
            yield (
                row["resource_uid"],
                row["resource_type"],
                row.get("resource_name") or "",
                row.get("account_id") or "",
                row.get("region") or "",
                ef or {},
            )
        last_uid = rows[-1]["resource_uid"]
        if len(rows) < 1000:
            break


# ── Condition evaluator ──────────────────────────────────────────────────────────

def _get_nested(emitted: Dict[str, Any], field_path: str) -> Any:
    """Resolve a dotted field path like 'PublicAccessBlockConfiguration.BlockPublicAcls'."""
    parts = field_path.split(".")
    node: Any = emitted
    for part in parts:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
        if node is None:
            return None
    return node


def _condition_passes(rule: OntologyRule, emitted: Dict[str, Any]) -> bool:
    """Evaluate the rule's condition against emitted_fields."""
    if not rule.is_conditional:
        return True
    if not rule.condition_field:
        return True

    value = _get_nested(emitted, rule.condition_field)
    op = rule.condition_operator

    if op == "not_null":
        return value is not None
    if op == "eq":
        return str(value) == str(rule.condition_value)
    if op == "ne":
        return str(value) != str(rule.condition_value)
    if op == "contains":
        return rule.condition_value is not None and rule.condition_value in str(value or "")

    return False


# ── Posture upsert ───────────────────────────────────────────────────────────────

_UPSERT_SQL = """
INSERT INTO resource_security_posture (
    posture_id, tenant_id, scan_run_id, account_id, provider, region,
    resource_uid, resource_type, resource_name,
    is_attack_entry_point, attack_entry_point_category,
    is_attack_target, attack_target_category,
    is_internet_exposed, is_crown_jewel
)
VALUES (
    gen_random_uuid(), %(tenant_id)s, %(scan_run_id)s, %(account_id)s,
    %(provider)s, %(region)s,
    %(resource_uid)s, %(resource_type)s, %(resource_name)s,
    %(is_attack_entry_point)s, %(attack_entry_point_category)s,
    %(is_attack_target)s, %(attack_target_category)s,
    %(is_attack_entry_point)s, %(is_attack_target)s
)
ON CONFLICT (tenant_id, scan_run_id, resource_uid)
DO UPDATE SET
    is_attack_entry_point =
        CASE WHEN EXCLUDED.is_attack_entry_point
             THEN TRUE
             ELSE resource_security_posture.is_attack_entry_point END,
    attack_entry_point_category =
        COALESCE(resource_security_posture.attack_entry_point_category,
                 EXCLUDED.attack_entry_point_category),
    is_attack_target =
        CASE WHEN EXCLUDED.is_attack_target
             THEN TRUE
             ELSE resource_security_posture.is_attack_target END,
    attack_target_category =
        COALESCE(resource_security_posture.attack_target_category,
                 EXCLUDED.attack_target_category),
    is_internet_exposed =
        CASE WHEN EXCLUDED.is_attack_entry_point
             THEN TRUE
             ELSE resource_security_posture.is_internet_exposed END,
    is_crown_jewel =
        CASE WHEN EXCLUDED.is_attack_target
             THEN TRUE
             ELSE resource_security_posture.is_crown_jewel END
"""


def _flush(
    conn: "psycopg2.connection",
    batch: List[Dict[str, Any]],
) -> None:
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, _UPSERT_SQL, batch, page_size=200)
    conn.commit()


# ── Main entry point ─────────────────────────────────────────────────────────────

def write_ontology_classifications(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> Tuple[int, int]:
    """
    Classify all assets for this scan and write ontology categories to posture.

    Returns:
        (entry_point_count, target_count) — 0s on any error.
    """
    try:
        conn = get_di_conn()
        try:
            return _run(conn, scan_run_id, tenant_id, account_id, provider)
        finally:
            conn.close()
    except Exception as exc:
        logger.warning(
            "ontology_writer failed (non-fatal): %s", exc, exc_info=True
        )
        return (0, 0)


def _run(
    conn: "psycopg2.connection",
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    csp: str,
) -> Tuple[int, int]:
    rules_by_type = _load_rules(conn, csp)
    if not rules_by_type:
        logger.info("ontology_writer: no rules for csp=%s", csp)
        return (0, 0)

    logger.info(
        "ontology_writer: loaded %d resource types for csp=%s scan=%s",
        len(rules_by_type), csp, scan_run_id,
    )

    batch: List[Dict[str, Any]] = []
    entry_point_count = 0
    target_count = 0

    for uid, rtype, rname, acct_id, region, emitted in _fetch_assets(
        conn, tenant_id, scan_run_id, csp
    ):
        rules = rules_by_type.get(rtype)
        if not rules:
            continue

        is_entry = False
        is_target = False
        entry_cat: Optional[str] = None
        target_cat: Optional[str] = None

        for rule in rules:
            if not _condition_passes(rule, emitted):
                continue
            if rule.entry_point_category and not is_entry:
                is_entry = True
                entry_cat = rule.entry_point_category
            if rule.attack_target_category and not is_target:
                is_target = True
                target_cat = rule.attack_target_category

        if not is_entry and not is_target:
            continue

        if is_entry:
            entry_point_count += 1
        if is_target:
            target_count += 1

        batch.append({
            "tenant_id":                tenant_id,
            "scan_run_id":              scan_run_id,
            "account_id":               acct_id or account_id,
            "provider":                 csp,
            "region":                   region,
            "resource_uid":             uid,
            "resource_type":            rtype,
            "resource_name":            rname,
            "is_attack_entry_point":    is_entry,
            "attack_entry_point_category": entry_cat,
            "is_attack_target":         is_target,
            "attack_target_category":   target_cat,
        })

        if len(batch) >= _BATCH_SIZE:
            _flush(conn, batch)
            batch = []

    if batch:
        _flush(conn, batch)

    logger.info(
        "ontology_writer: %d entry_points, %d targets classified csp=%s scan=%s",
        entry_point_count, target_count, csp, scan_run_id,
    )
    return (entry_point_count, target_count)
