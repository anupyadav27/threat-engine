"""
Network Security — UI Data Router

Provides the unified /api/v1/network-security/ui-data endpoint
for frontend consumption.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from psycopg2.extras import RealDictCursor

from engine_common.db_connections import get_network_conn

logger = logging.getLogger(__name__)

router = APIRouter()

# Allowed values for the effective_exposure column (empty string = unset/unknown).
# Values outside this set are invalid — log at WARNING and treat as empty.
_ALLOWED_EXPOSURE = {"internet", "vpc_internal", "cross_vpc", "subnet_only", "isolated", ""}

# ── Auth imports (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile) ──
try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]


def strip_sensitive_fields(data: List[Dict[str, Any]], auth: Any) -> List[Dict[str, Any]]:
    """Remove credential fields based on caller's auth level.

    For network-security engine (standard strip only):
    - level > 1: strip credential_ref, credential_type
    NOTE: blast_radius_score is owned by the risk engine and must not be
    set or modified here. Network findings always have blast_radius_score=0.

    Args:
        data: List of finding dicts.
        auth: AuthContext instance (or None when auth is unavailable).

    Returns:
        New list with sensitive fields removed; original dicts are not mutated.
    """
    if not isinstance(data, list):
        return data
    stripped = []
    for row in data:
        r = dict(row) if not isinstance(row, dict) else row.copy()
        if auth is not None and auth.level > 1:
            r.pop("credential_ref", None)
            r.pop("credential_type", None)
        # Viewer-level (level >= 3): strip network topology intelligence
        if auth is not None and hasattr(auth, "level") and auth.level >= 3:
            fd = r.get("finding_data")
            if isinstance(fd, dict):
                fd = dict(fd)
                fd.pop("sg_posture", None)
                r["finding_data"] = fd
            r.pop("effective_exposure", None)
        stripped.append(r)
    return stripped


def _query_scan_trend(cur, tenant_id: str) -> list:
    """Return last 8 completed network scan summaries for trend charts (oldest-first)."""
    try:
        cur.execute(
            """
            SELECT
                to_char(generated_at, 'Mon DD')            AS date,
                COALESCE(total_findings, 0)                AS total,
                COALESCE(critical_findings, 0)             AS critical,
                COALESCE(high_findings, 0)                 AS high,
                COALESCE(medium_findings, 0)               AS medium,
                COALESCE(low_findings, 0)                  AS low,
                COALESCE(posture_score, 0)                 AS pass_rate,
                COALESCE(internet_exposed_resources, 0)    AS exposed_resources,
                COALESCE(waf_score, 0)                     AS waf_coverage
            FROM network_report
            WHERE tenant_id = %s AND status = 'completed'
            ORDER BY generated_at DESC
            LIMIT 8
            """,
            (tenant_id,),
        )
        return [dict(r) for r in reversed(cur.fetchall())]
    except Exception:
        logger.warning("network scan_trend query failed", exc_info=True)
        return []


def _resolve_scan_ids(tenant_id: str, scan_id: str) -> List[str]:
    """
    Return scan_run_ids to aggregate.

    When scan_id='latest': returns the most recent completed scan_run_id per
    (provider, account_id) pair — a tenant may have multiple accounts per CSP
    and each account's latest scan must be included independently.

    For (provider, account_id) pairs that have findings in network_findings but
    no network_report row (scan wrote findings but skipped the summary write),
    falls back to the most recent scan_run_id from network_findings.

    Otherwise: returns [scan_id] verbatim.
    """
    if scan_id != "latest":
        return [scan_id]

    conn = get_network_conn()
    try:
        with conn.cursor() as cur:
            # Primary: latest completed scan per (provider, account_id) — skip orphaned reports
            cur.execute("""
                SELECT DISTINCT ON (provider, account_id) scan_run_id, provider, account_id
                FROM network_report r
                WHERE r.tenant_id = %s AND r.status = 'completed'
                  AND EXISTS (
                      SELECT 1 FROM network_findings f
                      WHERE f.scan_run_id = r.scan_run_id AND f.tenant_id = r.tenant_id
                  )
                ORDER BY provider, account_id, generated_at DESC
            """, (tenant_id,))
            # key = (provider, account_id) → scan_run_id
            scan_map: dict = {(r[1], r[2]): r[0] for r in cur.fetchall()}

            # Fallback: (provider, account_id) pairs present in findings but absent from report
            covered_pairs = list(scan_map.keys()) or [("__none__", "__none__")]
            covered_providers = list({p for p, _ in covered_pairs})
            covered_accounts  = list({a for _, a in covered_pairs})
            cur.execute("""
                SELECT DISTINCT ON (provider, account_id) scan_run_id, provider, account_id
                FROM network_findings
                WHERE tenant_id = %s
                  AND NOT (provider = ANY(%s) AND account_id = ANY(%s))
                ORDER BY provider, account_id, first_seen_at DESC
            """, (tenant_id, covered_providers, covered_accounts))
            for row in cur.fetchall():
                scan_map[(row[1], row[2])] = row[0]

            return list(scan_map.values()) if scan_map else []
    finally:
        conn.close()


def _aggregate_reports(reports: list) -> dict:
    """Merge multiple per-provider network_report rows into one unified summary."""
    if not reports:
        return {}

    def _safe_sum(field: str) -> int:
        return sum(int(r.get(field) or 0) for r in reports)

    def _safe_avg(field: str) -> int:
        vals = [int(r.get(field) or 0) for r in reports if r.get(field) is not None]
        return round(sum(vals) / len(vals)) if vals else 0

    # Posture score: average across providers (each already 0-100)
    posture_score = _safe_avg("posture_score")

    layer_fields = [
        ("topology",    "topology_score"),
        ("reachability","reachability_score"),
        ("nacl",        "nacl_score"),
        ("firewall",    "firewall_score"),
        ("load_balancer","lb_score"),
        ("waf",         "waf_score"),
        ("monitoring",  "monitoring_score"),
    ]
    layer_scores = {k: _safe_avg(f) for k, f in layer_fields}

    inventory_fields = [
        "total_vpcs", "total_subnets", "total_security_groups", "total_nacls",
        "total_route_tables", "total_load_balancers", "total_waf_acls",
        "total_nat_gateways", "total_igws", "total_tgws", "total_eips",
    ]

    return {
        "total_findings":            _safe_sum("total_findings"),
        "critical_findings":         _safe_sum("critical_findings"),
        "high_findings":             _safe_sum("high_findings"),
        "medium_findings":           _safe_sum("medium_findings"),
        "low_findings":              _safe_sum("low_findings"),
        "posture_score":             posture_score,
        "by_severity":               {},  # re-derived from findings below
        "by_module":                 {},
        "by_layer":                  {},
        "by_status":                 {},
        "exposure_summary":          {},
        "layer_scores":              layer_scores,
        "inventory": {
            k.removeprefix("total_"): _safe_sum(k) for k in inventory_fields
        },
        "internet_exposed_resources": _safe_sum("internet_exposed_resources"),
        "cross_vpc_paths_count":      _safe_sum("cross_vpc_paths_count"),
        "orphaned_sg_count":          _safe_sum("orphaned_sg_count"),
    }


def _classify_findings(findings: list) -> dict:
    """Classify findings by network_layer into UI sub-tab arrays.

    Single-pass O(n). Uses network_layer as the primary signal; effective_exposure
    as a secondary signal for L5_lb rows where exposure is internet.

    Args:
        findings: List of finding dicts from network_findings table.

    Returns:
        Dict with keys: security_groups, internet_exposure, waf, topology.
    """
    sg: list = []
    exposure: list = []
    waf: list = []
    topology_findings: list = []
    for f in findings:
        layer = (f.get("network_layer") or "").lower()
        raw_eff = (f.get("effective_exposure") or "").lower()
        # Validate effective_exposure before use (AC-S3)
        if raw_eff not in _ALLOWED_EXPOSURE:
            logger.warning(
                "Unexpected effective_exposure value %r on finding %s — treating as empty",
                raw_eff,
                f.get("finding_id", "unknown"),
            )
            raw_eff = ""
        eff = raw_eff
        if layer in ("l4_sg", "security_group_rules"):
            sg.append(f)
        elif layer in ("l5_lb", "load_balancer_security") or eff == "internet":
            exposure.append(f)
        elif layer in ("l6_waf", "waf_protection"):
            waf.append(f)
        else:  # L1, L2, L3, L7, unknown
            topology_findings.append(f)
    return {
        "security_groups":   sg,
        "internet_exposure": exposure,
        "waf":               waf,
        "topology":          topology_findings,
    }


@router.get("/api/v1/network-security/ui-data")
async def get_ui_data(
    tenant_id: str = Query(...),
    scan_id: str = Query("latest"),
    limit: int = Query(10000, le=10000),
    auth: Any = Depends(require_permission("network:read") if _AUTH_AVAILABLE else (lambda: None)),
) -> Dict[str, Any]:
    """
    Unified UI data endpoint for network security.

    When scan_id='latest', aggregates the most recent completed scan per CSP
    so all providers are visible simultaneously.
    """
    scan_ids = _resolve_scan_ids(tenant_id, scan_id)
    if not scan_ids:
        return {
            "summary": {},
            "modules": [],
            "layers": [],
            "findings": [],
            "security_groups":   [],
            "internet_exposure": [],
            "waf":               [],
            "topology":          [],
            "topology_snapshots": [],
            "total_findings": 0,
            "scan_id": None,
        }

    conn = get_network_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Report summaries (one row per scan_run_id / provider)
            cur.execute(
                "SELECT * FROM network_report WHERE scan_run_id = ANY(%s) AND tenant_id = %s",
                (scan_ids, tenant_id),
            )
            reports = [dict(r) for r in cur.fetchall()]

            # Findings — include provider + account_id for BFF filtering
            cur.execute("""
                SELECT finding_id, rule_id, title, description, severity, status,
                       network_layer, network_modules, effective_exposure,
                       resource_uid, resource_type, provider, account_id, region,
                       remediation, finding_data
                FROM network_findings
                WHERE scan_run_id = ANY(%s) AND tenant_id = %s
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    status DESC
                LIMIT %s
            """, (scan_ids, tenant_id, limit))
            raw_findings = cur.fetchall()
            findings = []
            for f in raw_findings:
                row = dict(f)
                fd = row.get("finding_data") or {}
                if not isinstance(fd, dict):
                    fd = {}
                row["finding_data"] = fd
                row.setdefault("compliance_frameworks", fd.get("compliance_frameworks") or [])
                row.setdefault("mitre_tactics",         fd.get("mitre_tactics") or [])
                row.setdefault("mitre_techniques",      fd.get("mitre_techniques") or [])
                row.setdefault("risk_score",            fd.get("risk_score"))
                row.setdefault("posture_category",      fd.get("posture_category") or "")
                row.setdefault("checked_fields",        fd.get("checked_fields"))
                row.setdefault("actual_values",         fd.get("actual_values"))
                row.setdefault("source",                fd.get("source", "check"))
                findings.append(row)

            # Topology snapshots from all scans (VPC-level snapshot dicts)
            cur.execute("""
                SELECT vpc_id, vpc_cidr_blocks, is_default_vpc, flow_log_enabled,
                       igw_id, isolation_score, public_subnet_count,
                       private_subnet_count, has_internet_path,
                       subnets, nat_gateways, peering_connections, tgw_attachments
                FROM network_topology_snapshot
                WHERE scan_run_id = ANY(%s) AND tenant_id = %s
            """, (scan_ids, tenant_id))
            topology_snapshots = [dict(r) for r in cur.fetchall()]

            # Scan trend (last 8 scans across all providers, oldest-first)
            scan_trend = _query_scan_trend(cur, tenant_id)

        summary = _aggregate_reports(reports)

        # Derive by_severity from actual findings (more accurate than stored totals)
        if findings:
            by_sev: dict = {}
            for f in findings:
                sev = (f.get("severity") or "medium").lower()
                by_sev[sev] = by_sev.get(sev, 0) + 1
            summary["by_severity"] = by_sev

        # Strip sensitive fields BEFORE classifying so all sub-tab arrays
        # are viewer-safe (sg_posture.cidrs removed for level >= 3).
        stripped_findings = strip_sensitive_fields(findings, auth)
        classified = _classify_findings(stripped_findings)
        logger.info(
            "network ui-data classified",
            extra={
                "tenant_id": tenant_id,
                "scan_ids": scan_ids,
                "sg": len(classified["security_groups"]),
                "exposure": len(classified["internet_exposure"]),
                "waf": len(classified["waf"]),
                "topology": len(classified["topology"]),
            },
        )

        return {
            "summary": summary,
            "modules": [
                "network_isolation", "network_reachability", "network_acl",
                "security_group_rules", "load_balancer_security",
                "waf_protection", "internet_exposure", "network_monitoring",
            ],
            "layers": [
                {"id": "L1_topology",     "name": "Network Topology",    "score": summary.get("layer_scores", {}).get("topology", 0)},
                {"id": "L2_reachability", "name": "Network Reachability","score": summary.get("layer_scores", {}).get("reachability", 0)},
                {"id": "L3_nacl",         "name": "Network ACL",         "score": summary.get("layer_scores", {}).get("nacl", 0)},
                {"id": "L4_sg",           "name": "Security Groups",     "score": summary.get("layer_scores", {}).get("firewall", 0)},
                {"id": "L5_lb",           "name": "Load Balancers",      "score": summary.get("layer_scores", {}).get("load_balancer", 0)},
                {"id": "L6_waf",          "name": "WAF Protection",      "score": summary.get("layer_scores", {}).get("waf", 0)},
                {"id": "L7_flow",         "name": "Flow Monitoring",     "score": summary.get("layer_scores", {}).get("monitoring", 0)},
            ],
            "findings":          stripped_findings,
            "security_groups":   classified["security_groups"],
            "internet_exposure": classified["internet_exposure"],
            "waf":               classified["waf"],
            "topology":          classified["topology"],
            "topology_snapshots": topology_snapshots,
            "total_findings": len(findings),
            "scan_id": scan_ids[0] if len(scan_ids) == 1 else "latest-all",
            "scan_ids": scan_ids,
            "scan_trend": scan_trend,
        }

    finally:
        conn.close()
