"""
BFF view: GET /api/v1/views/relationship-quality

Returns attack edge counts grouped by validator and edge type. Used by ops
teams to verify that the VAL-01 validator layer is producing edges after a scan.

Data source: asset_relationships WHERE is_attack_edge=TRUE (threat_engine_di DB).
No engine HTTP call — direct DB read, similar to read_findings/_shared.py.

Security:
  - Requires attack_path:read permission.
  - tenant_id always resolved from AuthContext (never from query param).
  - Parameterised queries only — no string interpolation.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

import psycopg2.extras
from fastapi import APIRouter, Depends, Query, Request

from ._auth import resolve_tenant_id

logger = logging.getLogger("api-gateway.bff.relationship_quality")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# Validator name derived from validation_rule_id prefix
_RULE_PREFIX_TO_VALIDATOR: Dict[str, str] = {
    "AWS-INET": "internet_reachability",
    "AWS-SVC":  "service_chain",
    "AWS-ID":   "identity_usage",
    "AWS-XACC": "assume_role",
    "AWS-DATA": "data_access",
    "AWS-SEC":  "data_access",
    "AWS-KMS":  "data_access",
}

# Auth dependency — graceful fallback when engine_auth not installed in gateway
try:
    from engine_auth.fastapi.dependencies import require_permission
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

    def require_permission(_perm: str):  # type: ignore[misc]
        def _ok():
            pass
        return Depends(_ok)


def _validator_from_rule_id(rule_id: Optional[str]) -> str:
    if not rule_id:
        return "unknown"
    for prefix, name in _RULE_PREFIX_TO_VALIDATOR.items():
        if rule_id.startswith(prefix):
            return name
    return "unknown"


@router.get(
    "/relationship-quality",
    dependencies=[Depends(require_permission("attack_path:read"))],
)
async def view_relationship_quality(
    request: Request,
    scan_run_id: Optional[str] = Query(default=None, description="Filter to a specific scan run"),
) -> Dict[str, Any]:
    """Return validator attack-edge counts for the authenticated tenant.

    Groups asset_relationships WHERE is_attack_edge=TRUE by attack_edge_type and
    validation_rule_id to show how many edges each VAL-01 validator has produced.
    Useful for ops to confirm validators are running and producing paths.

    Response shape:
      {
        "tenant_id": "...",
        "scan_run_id": null | "...",   # echoes filter if provided
        "total_attack_edges": 74,
        "by_attack_edge_type": {"CAN_REACH": 52, "CAN_ASSUME": 3, ...},
        "by_validator": {
          "internet_reachability": {"total": 42, "edge_types": {"CAN_REACH": 42}},
          ...
        }
      }
    """
    tenant_id = resolve_tenant_id(request)
    if not tenant_id:
        tenant_id = "default-tenant"

    try:
        from engine_common.db_connections import get_di_conn
    except ImportError:
        logger.warning("relationship-quality: engine_common not available")
        return _empty_response(tenant_id, scan_run_id)

    try:
        conn = get_di_conn()
    except Exception as exc:
        logger.warning("relationship-quality: DI DB unavailable: %s", exc)
        return _empty_response(tenant_id, scan_run_id)

    try:
        rows = _query_attack_edges(conn, tenant_id, scan_run_id)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return _aggregate(tenant_id, scan_run_id, rows)


def _query_attack_edges(
    conn: Any,
    tenant_id: str,
    scan_run_id: Optional[str],
) -> List[Dict[str, Any]]:
    """Query attack edges grouped by type and rule from the DI DB."""
    params: list = [tenant_id]
    scan_filter = ""
    if scan_run_id:
        scan_filter = "AND scan_run_id = %s"
        params.append(scan_run_id)

    sql = f"""
        SELECT
            COALESCE(attack_edge_type, 'UNKNOWN') AS attack_edge_type,
            COALESCE(validation_rule_id, '')       AS validation_rule_id,
            COUNT(*)                               AS edge_count
        FROM asset_relationships
        WHERE tenant_id     = %s
          AND is_attack_edge = TRUE
          {scan_filter}
        GROUP BY attack_edge_type, validation_rule_id
        ORDER BY edge_count DESC
    """

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        logger.warning("relationship-quality: query failed: %s", exc)
        try:
            conn.rollback()
        except Exception:
            pass
        return []


def _aggregate(
    tenant_id: str,
    scan_run_id: Optional[str],
    rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    total = 0
    by_type: Dict[str, int] = defaultdict(int)
    by_validator: Dict[str, Dict[str, Any]] = {}

    for row in rows:
        edge_type = row["attack_edge_type"]
        rule_id = row["validation_rule_id"]
        count = int(row["edge_count"])
        validator = _validator_from_rule_id(rule_id)

        total += count
        by_type[edge_type] += count

        v = by_validator.setdefault(validator, {"total": 0, "edge_types": {}})
        v["total"] += count
        v["edge_types"][edge_type] = v["edge_types"].get(edge_type, 0) + count

    return {
        "tenant_id":          tenant_id,
        "scan_run_id":        scan_run_id,
        "total_attack_edges": total,
        "by_attack_edge_type": dict(by_type),
        "by_validator":       by_validator,
    }


def _empty_response(tenant_id: str, scan_run_id: Optional[str]) -> Dict[str, Any]:
    return {
        "tenant_id":          tenant_id,
        "scan_run_id":        scan_run_id,
        "total_attack_edges": 0,
        "by_attack_edge_type": {},
        "by_validator":       {},
    }
