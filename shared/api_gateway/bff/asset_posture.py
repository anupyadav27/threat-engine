"""
BFF view handler: /api/v1/views/inventory/asset/{uid}/posture (AP-P4-04)

Reads resource_security_posture from the inventory DB (threat_engine_inventory)
and returns posture data grouped by security dimension:
  network, iam, encryption, data, database, attack_path

Field stripping by role level (RBAC — AP-P4-04 AC-4/AC-18..22):
  platform_admin / org_admin  (level ≤ 2): all fields
  tenant_admin / analyst      (level 4):   IAM tab: omit attached_role_arn, iam_detail
  viewer                      (level 4, role=viewer): IAM tab → {} ; attack_path → minimal fields only

Security:
  - tenant_id always from AuthContext (never from query param)
  - resource_uid validated 1–512 chars
  - No mock/fallback data — DB unreachable → 503 immediately
  - require_permission("attack_path:read") on this endpoint
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, Depends, HTTPException, Path, Request

from ._auth import resolve_tenant_id

logger = logging.getLogger("api-gateway.bff.asset_posture")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ── Auth ──────────────────────────────────────────────────────────────────────
try:
    from engine_auth.fastapi.dependencies import require_permission
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

    def require_permission(_perm: str):  # type: ignore[misc]
        def _ok():
            pass
        return _ok


# ── Inventory DB connection ───────────────────────────────────────────────────

def _get_inventory_conn() -> psycopg2.extensions.connection:
    """Open a direct psycopg2 connection to the inventory DB."""
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("INVENTORY_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or os.getenv("DISCOVERIES_DB_PASSWORD", "")
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=5,
    )


# ── Field stripping ───────────────────────────────────────────────────────────

_IAM_SENSITIVE_FIELDS = frozenset({"attached_role_arn", "iam_detail"})

# New depth columns added by migration 027 (PC-INFRA-01)
_DEPTH_IAM_FIELDS = ("has_priv_escalation_path", "priv_escalation_hop_count", "priv_escalation_cdr_confirmed")
_DEPTH_CONTAINER_FIELDS = ("ecr_scan_on_push_enabled", "eks_node_ami_outdated")

# Safe defaults when row is missing a depth column (e.g. pre-migration row)
_DEPTH_DEFAULTS: Dict[str, Any] = {
    "has_priv_escalation_path":      False,
    "priv_escalation_hop_count":     0,
    "priv_escalation_cdr_confirmed": False,
    "ecr_scan_on_push_enabled":      True,
    "eks_node_ami_outdated":         False,
}


def _build_response(row: Dict[str, Any], role: str, level: int) -> Dict[str, Any]:
    """Build grouped posture response with RBAC field stripping applied.

    Args:
        row:   raw psycopg2 RealDictRow from resource_security_posture
        role:  AuthContext.role string (e.g. "viewer", "analyst")
        level: AuthContext.level integer (1=platform_admin, 2=org_admin, 4=tenant_admin/analyst/viewer)
    """
    is_viewer = role == "viewer"
    is_restricted = level >= 4  # tenant_admin, analyst, viewer

    # ── Network dimension ─────────────────────────────────────────────
    network = {
        "is_internet_exposed":   row.get("is_internet_exposed"),
        "entry_point_type":      row.get("entry_point_type"),
        "waf_protected":         row.get("waf_protected"),
        "is_onprem_reachable":   row.get("is_onprem_reachable"),
        "effective_exposure":    row.get("effective_exposure"),
    }

    # ── IAM dimension ─────────────────────────────────────────────────
    def _depth_iam(include_cdr_confirmed: bool) -> Dict[str, Any]:
        return {
            "has_priv_escalation_path":  row.get("has_priv_escalation_path", _DEPTH_DEFAULTS["has_priv_escalation_path"]),
            "priv_escalation_hop_count": row.get("priv_escalation_hop_count", _DEPTH_DEFAULTS["priv_escalation_hop_count"]),
            **({"priv_escalation_cdr_confirmed": row.get("priv_escalation_cdr_confirmed", False)} if include_cdr_confirmed else {}),
        }

    if is_viewer:
        # Viewer: IAM tab empty except non-sensitive depth fields (AC-22 + PC-INFRA-03)
        iam = _depth_iam(include_cdr_confirmed=False)
    elif is_restricted:
        # tenant_admin / analyst: no ARN, no raw iam_detail (AC-20/AC-21)
        iam = {
            "is_admin_role":           row.get("is_admin_role"),
            "has_wildcard_policy":     row.get("has_wildcard_policy"),
            "mfa_required":            row.get("mfa_required"),
            "has_permission_boundary": row.get("has_permission_boundary"),
            "iam_reachable_count":     row.get("iam_reachable_count"),
            **_depth_iam(include_cdr_confirmed=True),
        }
    else:
        # platform_admin / org_admin: all fields (AC-18/AC-19)
        iam = {
            "attached_role_arn":       row.get("attached_role_arn"),
            "is_admin_role":           row.get("is_admin_role"),
            "has_wildcard_policy":     row.get("has_wildcard_policy"),
            "mfa_required":            row.get("mfa_required"),
            "has_permission_boundary": row.get("has_permission_boundary"),
            "iam_reachable_count":     row.get("iam_reachable_count"),
            "iam_detail":              row.get("iam_detail"),  # JSONB — already a dict
            **_depth_iam(include_cdr_confirmed=True),
        }

    # ── Encryption dimension ──────────────────────────────────────────
    encryption = {
        "volume_encrypted":   row.get("volume_encrypted"),
        "encryption_type":    row.get("encryption_type"),
        "cert_expiry_date":   str(row["cert_expiry_date"]) if row.get("cert_expiry_date") else None,
        "cert_days_to_expiry": row.get("cert_days_to_expiry"),
        "in_transit_tls":     row.get("in_transit_tls"),
    }

    # ── Data dimension ────────────────────────────────────────────────
    data = {
        "data_classification": row.get("data_classification"),
        "can_access_pii":      row.get("can_access_pii"),
        "can_write_data":      row.get("can_write_data"),
        "exfil_path_exists":   row.get("exfil_path_exists"),
    }

    # ── Container dimension ───────────────────────────────────────────
    container = {
        "has_privileged_container":          row.get("has_privileged_container"),
        "image_has_critical_cve":            row.get("image_has_critical_cve"),
        "k8s_rbac_overpermissive":           row.get("k8s_rbac_overpermissive"),
        "container_network_policy_missing":  row.get("container_network_policy_missing"),
        "container_security_score":          row.get("container_security_score"),
        "ecr_scan_on_push_enabled":          row.get("ecr_scan_on_push_enabled", _DEPTH_DEFAULTS["ecr_scan_on_push_enabled"]),
        "eks_node_ami_outdated":             row.get("eks_node_ami_outdated", _DEPTH_DEFAULTS["eks_node_ami_outdated"]),
    }

    # ── Database dimension ────────────────────────────────────────────
    database = {
        "connected_db_uids": row.get("connected_db_uids"),  # JSONB list
        "db_auth_type":      row.get("db_auth_type"),
        "db_same_vpc":       row.get("db_same_vpc"),
    }

    # ── API Security dimension ────────────────────────────────────────
    api_security = {
        "api_auth_type":               row.get("api_auth_type"),
        "api_has_waf":                 row.get("api_has_waf"),
        "api_has_rate_limit":          row.get("api_has_rate_limit"),
        "api_publicly_accessible":     row.get("api_publicly_accessible"),
        "api_deprecated_version_active": row.get("api_deprecated_version_active"),
        "api_security_score":          row.get("api_security_score"),
        "api_detail":                  row.get("api_detail"),  # JSONB — already dict
    }

    # ── Attack path dimension ─────────────────────────────────────────
    if is_viewer:
        # Viewer: minimal fields only (AC-22)
        attack_path = {
            "is_on_attack_path": row.get("is_on_attack_path"),
            "is_choke_point":    row.get("is_choke_point"),
        }
    else:
        attack_path = {
            "is_on_attack_path":   row.get("is_on_attack_path"),
            "attack_path_count":   row.get("attack_path_count"),
            "is_choke_point":      row.get("is_choke_point"),
            "has_active_cdr_actor": row.get("has_active_cdr_actor"),
            "blast_radius_count":  row.get("blast_radius_count"),
            "crown_jewel_type":    row.get("crown_jewel_type"),
            "is_crown_jewel":      row.get("is_crown_jewel"),
        }

    return {
        "resource_uid":   row.get("resource_uid"),
        "resource_type":  row.get("resource_type"),
        "scan_run_id":    str(row["scan_run_id"]) if row.get("scan_run_id") else None,
        "updated_at":     str(row["updated_at"]) if row.get("updated_at") else None,
        "network":        network,
        "iam":            iam,
        "container":      container,
        "encryption":     encryption,
        "data":           data,
        "database":       database,
        "api_security":   api_security,
        "attack_path":    attack_path,
    }


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get(
    "/inventory/asset/{uid}/posture",
    dependencies=[Depends(require_permission("attack_path:read"))],
)
async def get_asset_posture(
    uid: str = Path(..., min_length=1, max_length=512),
    request: Request = None,
) -> Dict[str, Any]:
    """Return security posture dimensions for a single resource.

    Multi-tenant: tenant_id always from AuthContext (AC-4 — never from query param).
    Field stripping: IAM fields stripped for analyst/tenant_admin; empty for viewer.
    """
    # ── Resolve tenant and role from AuthContext ──────────────────────
    from ._auth import _parse_auth_context
    ctx = _parse_auth_context(request) if request else {}
    tenant_id = resolve_tenant_id(request)
    if not tenant_id:
        raise HTTPException(status_code=422, detail="tenant_id required")

    role  = ctx.get("role", "viewer")
    level = int(ctx.get("level", 4))

    # ── Query resource_security_posture ───────────────────────────────
    conn: Optional[psycopg2.extensions.connection] = None
    try:
        conn = _get_inventory_conn()
    except Exception as exc:
        logger.error("asset_posture: cannot connect to inventory DB: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "inventory DB unavailable"},
        )

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM resource_security_posture
                WHERE resource_uid = %s
                  AND tenant_id    = %s
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (uid, tenant_id),
            )
            row = cur.fetchone()
    except Exception as exc:
        logger.error("asset_posture: query failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "posture query failed"},
        )
    finally:
        conn.close()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "No posture data found for this resource"},
        )

    return _build_response(dict(row), role=role, level=level)
