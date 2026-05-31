"""
IEDS Phase L0 — Tier 1 + Tier 2 Internet/External Exposure Evaluator.

Reads from:
  - network_exposure_rules (threat_engine_network): active Tier 1+2 rules for this CSP
  - asset_inventory (threat_engine_di): emitted_fields for matching resources

Writes to:
  - network_exposure_findings (threat_engine_network): per-resource findings with evidence
  - resource_security_posture (threat_engine_di): sets is_internet_exposed=true
  - asset_relationships (threat_engine_di): INTERNET_ACCESSIBLE edges for attack-path BFS
  - security_findings (threat_engine_di): unified findings layer

Called in run_scan.py Phase L0, before Layer 1 check_findings.
CSP-agnostic: works for all 7 providers — rules in the DB determine what applies per CSP.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2.extras

from engine_common.db_connections import get_network_conn, get_di_conn
from engine_common.posture_writer import upsert_posture_signals
from engine_common.security_findings_writer import upsert_findings
from engine_common.relationship_writer import upsert_asset_relationships

logger = logging.getLogger(__name__)

_INTERNET_UID = "pseudo:internet:global"
_INTERNET_TYPE = "internet"
_BATCH_SIZE = 200


# ---------------------------------------------------------------------------
# Field lookup helpers
# ---------------------------------------------------------------------------

def _norm_key(field: str) -> str:
    """Normalize a field name: lowercase, strip separators, take first dotted segment."""
    return re.sub(r"[_\-\s]", "", field.split(".")[0]).lower()


def _get_field(data: Any, field_path: str) -> Any:
    """
    Resolve a dotted field_path against data with case-insensitive, separator-agnostic
    key matching at every level.

    Examples:
        _get_field({"PublicIpAddress": "1.2.3.4"}, "public_ip_address") → "1.2.3.4"
        _get_field({"spec": {"type": "LoadBalancer"}}, "spec.type") → "LoadBalancer"
    """
    if data is None:
        return None

    dot = field_path.find(".")
    if dot == -1:
        first, rest = field_path, None
    else:
        first, rest = field_path[:dot], field_path[dot + 1:]

    first_norm = _norm_key(first)

    if isinstance(data, dict):
        for k, v in data.items():
            if _norm_key(k) == first_norm:
                return _get_field(v, rest) if rest else v
        return None

    if isinstance(data, list) and rest:
        # Descend into each list item and return first non-None match
        for item in data:
            val = _get_field(item, field_path)
            if val is not None:
                return val

    return None


def _values_eq(field_val: Any, rule_val: Any) -> bool:
    """Compare with bool/string/int coercion."""
    if field_val is None:
        return False
    if isinstance(rule_val, bool):
        if isinstance(field_val, bool):
            return field_val == rule_val
        return str(field_val).lower() == str(rule_val).lower()
    if isinstance(rule_val, str):
        if isinstance(field_val, bool):
            return str(field_val).lower() == rule_val.lower()
        return str(field_val) == str(rule_val)
    try:
        return float(field_val) == float(rule_val)
    except (ValueError, TypeError):
        return str(field_val) == str(rule_val)


# ---------------------------------------------------------------------------
# Condition evaluator
# ---------------------------------------------------------------------------

def _eval_condition(emitted: dict, cond: dict) -> bool:
    """Evaluate one condition. Returns True when the condition is satisfied."""
    field = cond.get("field", "")
    operator = cond.get("operator", "eq")
    value = cond.get("value")

    fv = _get_field(emitted, field)

    if operator == "not_null":
        return fv is not None

    if operator == "eq":
        return _values_eq(fv, value)

    if operator == "ne":
        return not _values_eq(fv, value)

    if operator == "contains":
        return fv is not None and str(value) in str(fv)

    if operator == "not_empty":
        if fv is None:
            return False
        if isinstance(fv, (list, dict, str)):
            return len(fv) > 0
        return True

    if operator == "any_has_field":
        # fv is a list; any item (dict) contains the key `value`
        if not isinstance(fv, list):
            return False
        return any(isinstance(item, dict) and value in item for item in fv)

    if operator == "any_has_non_empty":
        # fv is a list; any item (dict) has a non-empty value for key `value`
        # Empty list/None/"" all count as empty — used for IBM floating_ips detection
        if not isinstance(fv, list):
            return False
        return any(
            isinstance(item, dict) and bool(item.get(value))
            for item in fv
        )

    if operator == "any_type_eq":
        # fv is a list; any item has key "type" == value
        if not isinstance(fv, list):
            return False
        return any(
            isinstance(item, dict) and str(item.get("type", "")) == str(value)
            for item in fv
        )

    if operator == "contains_cidr_any":
        if fv is None:
            return False
        cidrs = value if isinstance(value, list) else [value]
        field_str = str(fv)
        return any(str(cidr) in field_str for cidr in cidrs)

    logger.debug("Unknown condition operator: %s — treating as False", operator)
    return False


def _eval_conditions(emitted: dict, conditions: list) -> bool:
    """ALL conditions must pass (AND logic). Empty conditions = always True (Tier 1)."""
    if not conditions:
        return True
    return all(_eval_condition(emitted, c) for c in conditions)


# ---------------------------------------------------------------------------
# DB readers
# ---------------------------------------------------------------------------

def _load_rules(net_conn: Any, provider: str) -> List[Dict[str, Any]]:
    """Load active Tier 1+2 rules for this CSP from network_exposure_rules."""
    with net_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT rule_id, tier, csp, resource_type, origin_type,
                   title, description, severity, exposure_conditions
            FROM   network_exposure_rules
            WHERE  is_active = true
              AND  tier IN (1, 2)
              AND  (csp = %s OR csp = 'all')
            ORDER  BY tier, rule_id
        """, (provider,))
        return [dict(r) for r in cur.fetchall()]


def _norm_rtype(rtype: str) -> str:
    """Normalize resource_type for format-agnostic matching.

    Converts dots and hyphens to underscores, lowercases.
    ec2.instance → ec2_instance, kms.key → kms_key, etc.
    """
    return rtype.lower().replace(".", "_").replace("-", "_")


def _load_assets(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: Optional[str],
    resource_types: List[str],
) -> List[Dict[str, Any]]:
    """Load asset_inventory rows that match resource_types for this scan.

    Matching is format-agnostic: dots and hyphens are treated as underscores
    so that rule resource_types like 'ec2.instance' match DI-written types
    like 'ec2_instance' and vice versa.
    """
    if not resource_types:
        return []
    normalized = [_norm_rtype(rt) for rt in resource_types]
    with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        query = """
            SELECT resource_uid, resource_type, region, account_id, provider,
                   emitted_fields, resource_name
            FROM   asset_inventory
            WHERE  scan_run_id = %s
              AND  tenant_id   = %s
              AND  LOWER(REPLACE(REPLACE(resource_type, '.', '_'), '-', '_')) = ANY(%s)
        """
        params: list = [scan_run_id, tenant_id, normalized]
        if account_id:
            query += " AND account_id = %s"
            params.append(account_id)
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# DB writers
# ---------------------------------------------------------------------------

def _insert_exposure_findings(net_conn: Any, rows: List[Dict[str, Any]]) -> int:
    """Batch-insert rows into network_exposure_findings."""
    if not rows:
        return 0
    total = 0
    now = datetime.now(timezone.utc)
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
                    exposure_detail, severity, status, first_seen_at, last_seen_at
                ) VALUES %s
                ON CONFLICT (scan_run_id, resource_uid, rule_id, origin_type) DO UPDATE SET
                    last_seen_at    = EXCLUDED.last_seen_at,
                    exposure_detail = EXCLUDED.exposure_detail,
                    severity        = EXCLUDED.severity
                """,
                [
                    (
                        r["scan_run_id"],
                        r["tenant_id"],
                        r.get("account_id", ""),
                        r.get("credential_ref", ""),
                        r.get("credential_type", ""),
                        r["provider"],
                        r.get("region", ""),
                        r["resource_uid"],
                        r["resource_type"],
                        r.get("resource_name"),
                        r["exposure_tier"],
                        r["origin_type"],
                        r["rule_id"],
                        r.get("title", r["rule_id"]),
                        psycopg2.extras.Json(r.get("exposure_detail", {})),
                        r.get("severity", "high"),
                        "OPEN",
                        now,
                        now,
                    )
                    for r in batch
                ],
                page_size=100,
            )
            total += len(batch)
    net_conn.commit()
    return total


def _write_posture(
    di_conn: Any,
    exposed_assets: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> int:
    """Upsert is_internet_exposed=true into resource_security_posture."""
    written = 0
    for asset in exposed_assets:
        try:
            upsert_posture_signals(
                di_conn,
                resource_uid=asset["resource_uid"],
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=asset.get("account_id", ""),
                provider=asset.get("provider", ""),
                resource_type=asset.get("resource_type", ""),
                region=asset.get("region"),
                resource_name=asset.get("resource_name"),
                is_internet_exposed=True,
            )
            written += 1
        except Exception as exc:
            logger.debug("Posture upsert skipped for %s: %s", asset.get("resource_uid"), exc)
    return written


def _write_internet_edges(
    di_conn: Any,
    exposed_assets: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    account_id: str = "",
    provider: str = "aws",
) -> int:
    """Write INTERNET_ACCESSIBLE edges to asset_relationships for attack-path BFS."""
    if not exposed_assets:
        return 0

    # Deduplicate by resource_uid
    seen: set = set()
    edges = []
    for asset in exposed_assets:
        uid = asset.get("resource_uid", "")
        if uid and uid not in seen:
            seen.add(uid)
            edges.append({
                "source_uid": uid,
                "source_type": asset.get("resource_type", ""),
                "target_uid": _INTERNET_UID,
                "target_type": _INTERNET_TYPE,
                "relation_type": "INTERNET_ACCESSIBLE",
                "relation_metadata": {
                    "origin": "ieds_phase_l0",
                    "origin_type": asset.get("origin_type", "internet"),
                    "tier": asset.get("tier", 1),
                    "rule_id": asset.get("rule_id", ""),
                },
            })

    if not edges:
        return 0

    try:
        return upsert_asset_relationships(
            di_conn, edges,
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider,
        )
    except Exception as exc:
        logger.warning("IEDS: asset_relationships write failed (non-fatal): %s", exc)
        return 0


def _write_security_findings(
    di_conn: Any,
    findings: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> int:
    """Write exposure findings to the security_findings unified layer."""
    if not findings:
        return 0

    rows = []
    seen: set = set()
    for f in findings:
        key = (f["resource_uid"], f["rule_id"])
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "source_finding_id": f["finding_id"],
            "resource_uid": f["resource_uid"],
            "account_id": f.get("account_id", ""),
            "provider": f.get("provider", ""),
            "resource_type": f.get("resource_type", ""),
            "finding_type": "internet_exposure",
            "severity": f.get("severity", "high"),
            "rule_id": f["rule_id"],
            "title": f.get("title", f["rule_id"]),
            "description": f.get("description", ""),
            "mitre_technique_id": None,
            "mitre_tactic": "Initial Access",
            "detail": {
                "exposure_tier": f.get("exposure_tier"),
                "origin_type": f.get("origin_type"),
                "rule_id": f["rule_id"],
            },
            "status": "open",
        })

    if not rows:
        return 0

    try:
        return upsert_findings(
            conn=di_conn,
            findings=rows,
            source_engine="network",
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
        )
    except Exception as exc:
        logger.warning("IEDS: security_findings write skipped (non-fatal): %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_phase_l0(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    credential_ref: str = "",
    credential_type: str = "",
) -> Dict[str, Any]:
    """
    Execute IEDS Tier 1 + Tier 2 evaluation for all active rules matching this CSP.

    Returns:
        Dict with keys: status, rules_evaluated, assets_scanned, findings,
        posture_updated, edges_written.
    """
    logger.info("=== IEDS Phase L0 START provider=%s scan=%s ===", provider, scan_run_id)

    net_conn = get_network_conn()
    di_conn = get_di_conn()

    try:
        # 1. Load rules
        rules = _load_rules(net_conn, provider)
        if not rules:
            logger.info("IEDS Phase L0: no active rules for provider=%s — skipping", provider)
            return {"status": "skipped", "findings": 0}

        logger.info("IEDS Phase L0: %d rules loaded for provider=%s", len(rules), provider)

        # 2. Group rules by resource_type for efficient asset lookup
        rules_by_rtype: Dict[str, List[Dict]] = {}
        for r in rules:
            rules_by_rtype.setdefault(r["resource_type"], []).append(r)

        # 3. Load matching assets from asset_inventory (one query per resource_type batch)
        resource_types = list(rules_by_rtype.keys())
        assets = _load_assets(
            di_conn, scan_run_id, tenant_id, account_id or None, resource_types
        )
        logger.info(
            "IEDS Phase L0: %d assets across %d resource types",
            len(assets), len(resource_types),
        )

        if not assets:
            logger.info("IEDS Phase L0: no matching assets for scan %s", scan_run_id)
            return {"status": "no_assets", "findings": 0}

        # 4. Build normalized resource_type → assets index for O(1) lookup.
        # Keyed by normalized form so rule rtypes (ec2.instance) resolve to
        # DI-stored rtypes (ec2_instance) transparently.
        assets_by_norm: Dict[str, List[Dict]] = {}
        for asset in assets:
            norm = _norm_rtype(asset.get("resource_type") or "")
            assets_by_norm.setdefault(norm, []).append(asset)

        # 5. Evaluate rules against assets
        findings: List[Dict[str, Any]] = []
        exposed_for_posture: List[Dict[str, Any]] = []  # carries rule_id/tier for edges

        for rtype, rtype_rules in rules_by_rtype.items():
            rtype_assets = assets_by_norm.get(_norm_rtype(rtype), [])
            for asset in rtype_assets:
                emitted = asset.get("emitted_fields") or {}
                for rule in rtype_rules:
                    conditions = rule.get("exposure_conditions") or []
                    if not _eval_conditions(emitted, conditions):
                        continue

                    # Build a stable finding_id
                    finding_id = hashlib.sha256(
                        f"ieds|{rule['rule_id']}|{asset['resource_uid']}|{scan_run_id}".encode()
                    ).hexdigest()[:32]

                    finding = {
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
                        "exposure_tier": rule["tier"],
                        "origin_type": rule["origin_type"],
                        "title": rule.get("title", rule["rule_id"]),
                        "description": rule.get("description", ""),
                        "severity": rule.get("severity", "high"),
                        "exposure_detail": {
                            "rule_id": rule["rule_id"],
                            "tier": rule["tier"],
                            "conditions_count": len(conditions),
                        },
                    }
                    findings.append(finding)

                    exposed_for_posture.append({
                        "resource_uid": asset["resource_uid"],
                        "resource_type": rtype,
                        "account_id": asset.get("account_id") or account_id or "",
                        "provider": asset.get("provider") or provider,
                        "region": asset.get("region"),
                        "resource_name": asset.get("resource_name"),
                        "origin_type": rule["origin_type"],
                        "tier": rule["tier"],
                        "rule_id": rule["rule_id"],
                    })

        logger.info(
            "IEDS Phase L0: %d exposure findings from %d rules × %d assets",
            len(findings), len(rules), len(assets),
        )

        if not findings:
            return {"status": "completed", "rules_evaluated": len(rules),
                    "assets_scanned": len(assets), "findings": 0}

        # 6. Write to network_exposure_findings
        written_nef = _insert_exposure_findings(net_conn, findings)
        logger.info("IEDS Phase L0: wrote %d rows to network_exposure_findings", written_nef)

        # 7. Update resource_security_posture — is_internet_exposed=true for internet findings
        internet_assets = [
            a for a in exposed_for_posture if a.get("origin_type") == "internet"
        ]
        written_posture = _write_posture(di_conn, internet_assets, scan_run_id, tenant_id)
        logger.info("IEDS Phase L0: set is_internet_exposed=true on %d posture rows", written_posture)

        # 8. Write INTERNET_ACCESSIBLE edges to asset_relationships
        edges_written = _write_internet_edges(
            di_conn, internet_assets, scan_run_id, tenant_id,
            account_id=account_id, provider=provider,
        )
        logger.info("IEDS Phase L0: wrote %d INTERNET_ACCESSIBLE edges", edges_written)

        # 9. Write to security_findings unified layer
        written_sf = _write_security_findings(di_conn, findings, scan_run_id, tenant_id)
        logger.info("IEDS Phase L0: wrote %d rows to security_findings", written_sf)

        logger.info("=== IEDS Phase L0 COMPLETE: %d findings ===", len(findings))

        return {
            "status": "completed",
            "rules_evaluated": len(rules),
            "assets_scanned": len(assets),
            "findings": len(findings),
            "posture_updated": written_posture,
            "edges_written": edges_written,
        }

    except Exception as exc:
        logger.error("IEDS Phase L0 failed: %s", exc, exc_info=True)
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
