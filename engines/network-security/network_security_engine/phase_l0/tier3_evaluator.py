"""
IEDS Phase L0 — Tier 3 Multi-Hop Graph Traversal Evaluator.

Evaluates exposure chains that require traversing asset_relationships.
Each Tier 3 rule defines traversal_steps:

  step: int                   — ordered step number
  label: str                  — human-readable label for the chain hop
  check_field: str (optional) — emitted_fields key to check on the current resource
  operator: str               — same operators as Tier 2 (eq, not_null, contains, …)
  value: Any (optional)       — comparison value for the check
  traverse_field: str (opt)   — emitted_fields key whose value is a related resource UID
  target_type: str (optional) — resource_type of the related resource
  relation: str (optional)    — asset_relationships.relation_type to follow

For each base resource:
  1. Run check_field step (if defined) — if it fails, skip this resource
  2. If traverse_field is defined, look up related resources:
     a. Try asset_relationships WHERE source_uid = current_uid AND relation_type = relation
     b. Fallback: look up the field value directly in asset_inventory.resource_uid
  3. Recurse through all steps
  4. If ALL steps pass → resource is exposed (write to network_exposure_findings with chain_hops)

Writes same outputs as exposure_evaluator.py but includes chain_hops evidence JSON.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2.extras

from engine_common.db_connections import get_network_conn, get_di_conn
from engine_common.posture_writer import upsert_posture_signals
from engine_common.relationship_writer import upsert_asset_relationships

from .exposure_evaluator import _eval_condition, _get_field

logger = logging.getLogger(__name__)

_INTERNET_UID = "pseudo:internet:global"
_INTERNET_TYPE = "internet"
_BATCH_SIZE = 200


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _load_tier3_rules(net_conn: Any, provider: str) -> List[Dict[str, Any]]:
    """Load active Tier 3 rules for this CSP."""
    with net_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT rule_id, tier, csp, resource_type, origin_type,
                   title, description, severity, traversal_steps
            FROM   network_exposure_rules
            WHERE  is_active = true
              AND  tier = 3
              AND  (csp = %s OR csp = 'all')
            ORDER  BY rule_id
        """, (provider,))
        return [dict(r) for r in cur.fetchall()]


def _load_base_assets(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: Optional[str],
    resource_types: List[str],
) -> List[Dict[str, Any]]:
    """Load base resource assets from asset_inventory."""
    if not resource_types:
        return []
    with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        query = """
            SELECT resource_uid, resource_type, region, account_id,
                   provider, emitted_fields, resource_name
            FROM   asset_inventory
            WHERE  scan_run_id   = %s
              AND  tenant_id     = %s
              AND  resource_type = ANY(%s)
        """
        params: list = [scan_run_id, tenant_id, resource_types]
        if account_id:
            query += " AND account_id = %s"
            params.append(account_id)
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


def _fetch_related_by_relationship(
    di_conn: Any,
    tenant_id: str,
    source_uid: str,
    relation_type: str,
    target_type: Optional[str],
) -> List[str]:
    """Look up target UIDs via asset_relationships."""
    with di_conn.cursor() as cur:
        query = """
            SELECT target_uid
            FROM   asset_relationships
            WHERE  tenant_id    = %s
              AND  source_uid   = %s
              AND  relation_type = %s
        """
        params: list = [tenant_id, source_uid, relation_type]
        if target_type:
            query += " AND target_type = %s"
            params.append(target_type)
        cur.execute(query, params)
        return [row[0] for row in cur.fetchall()]


def _fetch_asset_by_uid(
    di_conn: Any,
    tenant_id: str,
    uid: str,
    resource_type: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Load a single asset_inventory row by resource_uid."""
    with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        query = """
            SELECT resource_uid, resource_type, emitted_fields
            FROM   asset_inventory
            WHERE  tenant_id    = %s
              AND  resource_uid = %s
        """
        params: list = [tenant_id, uid]
        if resource_type:
            query += " AND resource_type = %s"
            params.append(resource_type)
        query += " LIMIT 1"
        cur.execute(query, params)
        row = cur.fetchone()
        return dict(row) if row else None


def _fetch_assets_by_field_value(
    di_conn: Any,
    tenant_id: str,
    scan_run_id: str,
    resource_type: str,
    field_value: str,
) -> List[Dict[str, Any]]:
    """
    Fallback: find related assets by matching field_value against resource_uid.
    Handles cases where traverse_field contains a raw AWS ID (e.g. subnet-xxx)
    and the asset_inventory resource_uid IS that ID.
    """
    with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT resource_uid, resource_type, emitted_fields
            FROM   asset_inventory
            WHERE  tenant_id    = %s
              AND  scan_run_id  = %s
              AND  resource_type = %s
              AND  resource_uid LIKE %s
            LIMIT  50
        """, (tenant_id, scan_run_id, resource_type, f"%{field_value}%"))
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Traversal engine
# ---------------------------------------------------------------------------

def _traverse_steps(
    di_conn: Any,
    tenant_id: str,
    scan_run_id: str,
    asset: Dict[str, Any],
    steps: List[Dict[str, Any]],
    hop_index: int = 0,
) -> Optional[List[Dict[str, Any]]]:
    """
    Recursively walk traversal_steps.

    Returns a list of chain hop dicts if ALL steps pass, or None if any step fails.
    Each hop dict is suitable for the chain_hops JSONB column.
    """
    if hop_index >= len(steps):
        return []  # all steps passed

    step = steps[hop_index]
    emitted = asset.get("emitted_fields") or {}
    hops_so_far = []

    # --- Check step (field condition on current resource) ---
    check_field = step.get("check_field") or step.get("field")
    if check_field:
        cond = {
            "field": check_field,
            "operator": step.get("operator", "not_null"),
            "value": step.get("value"),
        }
        if not _eval_condition(emitted, cond):
            return None  # step failed

        hops_so_far.append({
            "step": step.get("step", hop_index + 1),
            "label": step.get("label", f"step_{hop_index + 1}"),
            "resource_uid": asset["resource_uid"],
            "resource_type": asset.get("resource_type", ""),
            "check": f"{check_field} {cond['operator']} {cond.get('value', 'NOT NULL')}",
            "result": "PASS",
        })

    # --- No traverse — just a check step; continue to next step ---
    traverse_field = step.get("traverse_field")
    if not traverse_field:
        tail = _traverse_steps(di_conn, tenant_id, scan_run_id, asset, steps, hop_index + 1)
        if tail is None:
            return None
        return hops_so_far + tail

    # --- Traverse step: get target UIDs ---
    target_type = step.get("target_type")
    relation = step.get("relation", "")

    # 1. Try asset_relationships
    field_values = _get_field(emitted, traverse_field)
    if field_values is None:
        return None  # can't traverse, required field missing

    # Normalise to list
    if isinstance(field_values, list):
        uid_candidates = [str(v) for v in field_values if v]
    else:
        uid_candidates = [str(field_values)] if field_values else []

    if not uid_candidates:
        return None

    # Try relationship table first
    related_uids: List[str] = []
    if relation:
        for uid_val in uid_candidates:
            rel_uids = _fetch_related_by_relationship(
                di_conn, tenant_id, uid_val, relation, target_type
            )
            related_uids.extend(rel_uids)
            if not rel_uids and target_type:
                # Fallback: direct resource_uid match
                fallback = _fetch_assets_by_field_value(
                    di_conn, tenant_id, scan_run_id, target_type, uid_val
                )
                related_uids.extend(a["resource_uid"] for a in fallback)
    else:
        # No explicit relation — look up by raw UID value
        for uid_val in uid_candidates:
            asset_direct = _fetch_asset_by_uid(di_conn, tenant_id, uid_val, target_type)
            if asset_direct:
                related_uids.append(asset_direct["resource_uid"])
            elif target_type:
                fallback = _fetch_assets_by_field_value(
                    di_conn, tenant_id, scan_run_id, target_type, uid_val
                )
                related_uids.extend(a["resource_uid"] for a in fallback)

    if not related_uids:
        return None  # no related resources found → chain broken

    # At least ONE related resource must satisfy the remaining steps
    for rel_uid in related_uids:
        rel_asset = _fetch_asset_by_uid(di_conn, tenant_id, rel_uid, target_type)
        if not rel_asset:
            continue

        tail = _traverse_steps(
            di_conn, tenant_id, scan_run_id, rel_asset, steps, hop_index + 1
        )
        if tail is not None:
            hop = {
                "step": step.get("step", hop_index + 1),
                "label": step.get("label", f"traverse_{hop_index + 1}"),
                "source_uid": asset["resource_uid"],
                "target_uid": rel_uid,
                "target_type": target_type,
                "traverse_field": traverse_field,
                "result": "PASS",
            }
            return hops_so_far + [hop] + tail

    return None  # no related resource satisfied the chain


# ---------------------------------------------------------------------------
# DB write helpers (reuse posture writer)
# ---------------------------------------------------------------------------

def _insert_tier3_findings(
    net_conn: Any, rows: List[Dict[str, Any]]
) -> int:
    """Write Tier 3 findings to network_exposure_findings with chain_hops."""
    if not rows:
        return 0
    now = datetime.now(timezone.utc)
    total = 0
    for i in range(0, len(rows), _BATCH_SIZE):
        batch = rows[i: i + _BATCH_SIZE]
        with net_conn.cursor() as cur:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO network_exposure_findings (
                    scan_run_id, tenant_id, account_id, credential_ref, credential_type,
                    provider, region, resource_uid, resource_type, resource_name,
                    exposure_tier, origin_type, rule_id, exposure_reason,
                    exposure_detail, chain_hops, severity, status,
                    first_seen_at, last_seen_at
                ) VALUES %s
                ON CONFLICT (scan_run_id, resource_uid, rule_id, origin_type) DO UPDATE SET
                    last_seen_at = EXCLUDED.last_seen_at,
                    chain_hops   = EXCLUDED.chain_hops
                """,
                [
                    (
                        r["scan_run_id"], r["tenant_id"],
                        r.get("account_id", ""), r.get("credential_ref", ""),
                        r.get("credential_type", ""), r["provider"],
                        r.get("region", ""), r["resource_uid"], r["resource_type"],
                        r.get("resource_name"),
                        3, r["origin_type"], r["rule_id"],
                        r.get("title", r["rule_id"]),
                        psycopg2.extras.Json({"tier": 3, "rule_id": r["rule_id"]}),
                        psycopg2.extras.Json(r.get("chain_hops", [])),
                        r.get("severity", "critical"),
                        "OPEN", now, now,
                    )
                    for r in batch
                ],
                page_size=100,
            )
            total += len(batch)
    net_conn.commit()
    return total


def _write_tier3_posture(
    di_conn: Any,
    exposed: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> int:
    written = 0
    for asset in exposed:
        try:
            upsert_posture_signals(
                di_conn,
                resource_uid=asset["resource_uid"],
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=asset.get("account_id", ""),
                provider=asset.get("provider", ""),
                resource_type=asset.get("resource_type", ""),
                is_internet_exposed=True,
            )
            written += 1
        except Exception as exc:
            logger.debug("Tier3 posture upsert skipped for %s: %s", asset.get("resource_uid"), exc)
    return written


def _write_tier3_edges(
    di_conn: Any,
    exposed: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> int:
    if not exposed:
        return 0
    seen: set = set()
    edges = []
    for asset in exposed:
        uid = asset.get("resource_uid", "")
        if uid and uid not in seen:
            seen.add(uid)
            edges.append({
                "source_uid": uid,
                "source_type": asset.get("resource_type", ""),
                "target_uid": _INTERNET_UID,
                "target_type": _INTERNET_TYPE,
                "relation_type": "INTERNET_ACCESSIBLE",
                "metadata": {
                    "origin": "ieds_tier3",
                    "chain_length": asset.get("chain_length", 0),
                    "rule_id": asset.get("rule_id", ""),
                },
            })
    if not edges:
        return 0
    try:
        from engine_common.relationship_writer import upsert_asset_relationships
        return upsert_asset_relationships(
            di_conn, edges, scan_run_id=scan_run_id, tenant_id=tenant_id
        )
    except Exception as exc:
        logger.warning("Tier3: asset_relationships write failed: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_tier3(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    credential_ref: str = "",
    credential_type: str = "",
) -> Dict[str, Any]:
    """
    Execute IEDS Tier 3 graph traversal evaluation.

    Returns dict: status, rules_evaluated, assets_scanned, findings.
    """
    logger.info("=== IEDS Tier 3 START provider=%s scan=%s ===", provider, scan_run_id)

    net_conn = get_network_conn()
    di_conn = get_di_conn()

    try:
        rules = _load_tier3_rules(net_conn, provider)
        if not rules:
            logger.info("IEDS Tier 3: no active rules for provider=%s", provider)
            return {"status": "skipped", "findings": 0}

        logger.info("IEDS Tier 3: %d rules for provider=%s", len(rules), provider)

        # Load base resources
        base_types = list({r["resource_type"] for r in rules})
        base_assets = _load_base_assets(
            di_conn, scan_run_id, tenant_id, account_id or None, base_types
        )
        logger.info("IEDS Tier 3: %d base assets for types %s", len(base_assets), base_types)

        if not base_assets:
            return {"status": "no_assets", "findings": 0}

        # Index assets by resource_type
        assets_by_rtype: Dict[str, List[Dict]] = {}
        for a in base_assets:
            assets_by_rtype.setdefault(a["resource_type"], []).append(a)

        findings: List[Dict[str, Any]] = []
        exposed: List[Dict[str, Any]] = []

        for rule in rules:
            rtype = rule["resource_type"]
            steps = sorted(rule.get("traversal_steps") or [], key=lambda s: s.get("step", 0))
            if not steps:
                continue

            for asset in assets_by_rtype.get(rtype, []):
                chain = _traverse_steps(
                    di_conn, tenant_id, scan_run_id, asset, steps
                )
                if chain is None:
                    continue

                finding_id = hashlib.sha256(
                    f"ieds3|{rule['rule_id']}|{asset['resource_uid']}|{scan_run_id}".encode()
                ).hexdigest()[:32]

                findings.append({
                    "finding_id": finding_id,
                    "scan_run_id": scan_run_id,
                    "tenant_id": tenant_id,
                    "account_id": asset.get("account_id") or account_id or "",
                    "credential_ref": credential_ref,
                    "credential_type": credential_type,
                    "provider": asset.get("provider") or provider,
                    "region": asset.get("region", ""),
                    "resource_uid": asset["resource_uid"],
                    "resource_type": rtype,
                    "resource_name": asset.get("resource_name"),
                    "rule_id": rule["rule_id"],
                    "origin_type": rule["origin_type"],
                    "title": rule.get("title", rule["rule_id"]),
                    "severity": rule.get("severity", "critical"),
                    "chain_hops": chain,
                })

                exposed.append({
                    "resource_uid": asset["resource_uid"],
                    "resource_type": rtype,
                    "account_id": asset.get("account_id") or account_id or "",
                    "provider": asset.get("provider") or provider,
                    "region": asset.get("region"),
                    "rule_id": rule["rule_id"],
                    "chain_length": len(chain),
                })

        logger.info("IEDS Tier 3: %d chain-based exposure findings", len(findings))

        if not findings:
            return {"status": "completed", "findings": 0}

        written_nef = _insert_tier3_findings(net_conn, findings)
        written_posture = _write_tier3_posture(di_conn, exposed, scan_run_id, tenant_id)
        edges = _write_tier3_edges(di_conn, exposed, scan_run_id, tenant_id)

        logger.info(
            "=== IEDS Tier 3 COMPLETE: %d findings, %d posture rows, %d edges ===",
            len(findings), written_posture, edges,
        )
        return {
            "status": "completed",
            "rules_evaluated": len(rules),
            "assets_scanned": len(base_assets),
            "findings": len(findings),
            "posture_updated": written_posture,
            "edges_written": edges,
        }

    except Exception as exc:
        logger.error("IEDS Tier 3 failed: %s", exc, exc_info=True)
        try:
            net_conn.rollback()
        except Exception:
            pass
        return {"status": "failed", "error": str(exc), "findings": 0}

    finally:
        try:
            net_conn.close()
        except Exception:
            pass
        try:
            di_conn.close()
        except Exception:
            pass
