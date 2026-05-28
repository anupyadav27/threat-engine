"""BFF view: /datasec page.

Uses the datasec engine's /ui-data endpoint as the primary source and ALWAYS
also queries the check engine (data_protection_and_privacy domain) as a
supplemental/fallback source.

Two parallel calls are made:
1. datasec engine  → /api/v1/data-security/ui-data
2. check engine    → /api/v1/check/findings?domain=data_protection_and_privacy

The datasec engine data is used when present (catalog, classifications,
dlp_violations, encryption_status, residency, activity, lineage, summary).
Check findings are always used to supplement/replace the findings tab and
are split by posture_category to fill the DLP and encryption tabs when
the datasec engine returns no data for those.
"""

import asyncio
from typing import Dict, List, Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, fetch_all_check_findings, safe_get, is_empty_or_health, read_findings
from ._transforms import (
    normalize_datastore, normalize_classification, normalize_dlp_violation,
    normalize_residency, normalize_access_activity, apply_global_filters,
)
from ._page_context import datasec_page_context, datasec_filter_schema
from ._common_schemas import DatasecViewResponse

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _split_by_module(check_findings: List[dict]) -> Dict[str, list]:
    """Split check findings (data_protection_and_privacy domain) by posture_category.

    Returns a dict with keys:
      findings         – all findings
      encryption       – posture_category == 'encryption'
      data_protection  – posture_category == 'data_protection'
      dlp              – empty (check engine has no DLP findings)
      residency        – empty (check engine has no residency findings)
      activity         – empty (check engine has no activity findings)
      catalog          – same as findings (used as resource catalog)
      summary          – empty dict (no pre-computed KPIs)
    """
    encryption_findings = [f for f in check_findings if (f.get("posture_category") or "").lower() == "encryption"]
    data_protection_findings = [f for f in check_findings if (f.get("posture_category") or "").lower() == "data_protection"]

    return {
        "findings": check_findings,
        "encryption": encryption_findings,
        "data_protection": data_protection_findings,
        "dlp": [],
        "residency": [],
        "activity": [],
        "catalog": check_findings,
        "summary": {},
    }


@router.get("/datasec", response_model=DatasecViewResponse, response_model_exclude_none=False)
async def view_datasec(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    tenant_ids: Optional[str] = Query(None),
    account_ids: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    csp: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the data security page needs.

    Always makes two parallel upstream calls:
    - datasec engine (for rich data security findings when available)
    - check engine   (data_protection_and_privacy domain, always reliable)
    """

    tenant_id = resolve_tenant_id(request)
    effective_csp = csp or (provider.lower() if provider else "aws")

    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    # ── Three parallel calls: datasec engine + paginated check (all + DLP) ──
    datasec_resp, check_findings, dlp_check_findings = await asyncio.gather(
        fetch_many([("datasec", "/api/v1/data-security/ui-data", {
            "tenant_id": tenant_id,
            "csp": effective_csp,
            "scan_id": scan_id,
        })], auth_headers=fwd_headers),
        fetch_all_check_findings({
            "tenant_id": tenant_id,
            "domain": "data_protection_and_privacy",
        }, auth_headers=fwd_headers),
        fetch_all_check_findings({
            "tenant_id": tenant_id,
            "domain": "data_protection_and_privacy",
            "posture_category": "data_protection",
        }, auth_headers=fwd_headers),
    )

    datasec_data = (datasec_resp[0] if datasec_resp else None)
    if not isinstance(datasec_data, dict):
        datasec_data = {}
    if not isinstance(check_findings, list):
        check_findings = []
    if not isinstance(dlp_check_findings, list):
        dlp_check_findings = []

    # ── Determine if datasec engine returned real data ──────────────────────
    _has_datasec = bool(
        safe_get(datasec_data, "catalog", []) or
        safe_get(datasec_data, "findings", [])
    )
    datasec_empty = is_empty_or_health(datasec_data) or not _has_datasec

    # ── When datasec engine is empty, build from check findings ────────────
    if datasec_empty:
        if check_findings:
            split = _split_by_module(check_findings)
            datasec_data = {
                "findings": split["findings"],
                "catalog": split["catalog"],
                "classifications": [],
                "dlp_violations": split["dlp"],
                "encryption_status": split["encryption"],
                "residency": split["residency"],
                "activity": split["activity"],
                "lineage": {},
                "summary": split["summary"],
            }

    summary = safe_get(datasec_data, "summary", {})

    # ── Catalog ─────────────────────────────────────────────────────────────
    raw_catalog = safe_get(datasec_data, "catalog", [])
    catalog = [normalize_datastore(s) for s in raw_catalog]
    filtered_catalog = apply_global_filters(catalog, provider, account, region)

    # ── Classifications ──────────────────────────────────────────────────────
    raw_class = safe_get(datasec_data, "classifications", [])
    classifications = [normalize_classification(c) for c in raw_class]

    # ── Residency ────────────────────────────────────────────────────────────
    raw_residency = safe_get(datasec_data, "residency", [])
    residency = [normalize_residency(r) for r in raw_residency]

    # ── Activity ─────────────────────────────────────────────────────────────
    raw_activity = safe_get(datasec_data, "activity", [])
    if isinstance(raw_activity, dict):
        flat = []
        for events_list in raw_activity.values():
            if isinstance(events_list, list):
                flat.extend(events_list)
        raw_activity = flat
    elif not isinstance(raw_activity, list):
        raw_activity = []
    activity = [normalize_access_activity(a) for a in raw_activity]
    monitoring = activity

    # ── DLP violations ───────────────────────────────────────────────────────
    # Prefer datasec engine DLP; fall back to check data_protection category.
    # Check engine findings already have provider/account_id/region/service —
    # skip normalize_dlp_violation so those fields are preserved for the UI.
    raw_dlp = safe_get(datasec_data, "dlp_violations", [])
    if not raw_dlp:
        raw_dlp = dlp_check_findings  # dedicated parallel fetch, no pagination gaps
    # Only normalise when data came from the datasec engine (has no rule_id)
    if raw_dlp and raw_dlp[0].get("rule_id"):
        dlp = raw_dlp  # check-engine findings — preserve all fields
    else:
        dlp = [normalize_dlp_violation(v) for v in raw_dlp]

    # ── Encryption status ────────────────────────────────────────────────────
    encryption = safe_get(datasec_data, "encryption_status", [])
    if not encryption and check_findings:
        # Use check encryption findings as a passable encryption list
        encryption = [f for f in check_findings if (f.get("posture_category") or "").lower() == "encryption"]
    if isinstance(encryption, list):
        for enc_item in encryption:
            if isinstance(enc_item, dict) and "rotation" not in enc_item:
                config = enc_item.get("config") or enc_item.get("resource_config") or {}
                if isinstance(config, dict):
                    rotation_enabled = config.get("KeyRotationEnabled") or config.get("key_rotation_enabled")
                    if rotation_enabled is True:
                        enc_item["rotation"] = "Enabled"
                    elif rotation_enabled is False:
                        enc_item["rotation"] = "Disabled"
                    else:
                        enc_item["rotation"] = "Unknown"
                else:
                    enc_item["rotation"] = "Unknown"

    # ── Lineage ──────────────────────────────────────────────────────────────
    lineage = safe_get(datasec_data, "lineage", {})
    if not isinstance(lineage, dict):
        lineage = {}
    if "lineage_chains" not in lineage:
        # Convert lineage_graph {resource_id: [flow, ...]} → lineage_chains array
        lineage_graph = lineage.get("lineage_graph", {})
        chains: list = []
        if isinstance(lineage_graph, dict):
            for res_id, flows in lineage_graph.items():
                if not isinstance(flows, list):
                    continue
                for j, flow in enumerate(flows):
                    if not isinstance(flow, dict):
                        continue
                    src = flow.get("source") or {}
                    dst = flow.get("destination") or {}
                    chains.append({
                        "chain_id": f"{str(res_id)[:12]}-{j}",
                        "risk": flow.get("risk_level") or "medium",
                        "source": {"name": src.get("name") or src.get("resource_id") or str(src)[:40]},
                        "sink":   {"name": dst.get("name") or dst.get("resource_id") or str(dst)[:40]},
                        "encryption_at_rest":     bool(flow.get("encryption_at_rest", False)),
                        "encryption_in_transit":  bool(flow.get("encryption_in_transit", False)),
                        "data_classification":    flow.get("data_classification", ""),
                        "flow_type":              flow.get("flow_type", ""),
                    })
        lineage["lineage_chains"] = chains

    # ── Findings ─────────────────────────────────────────────────────────────
    # Prefer datasec findings; fall back to check findings
    raw_findings = safe_get(datasec_data, "findings", [])
    if not raw_findings and check_findings:
        raw_findings = check_findings

    # ── KPI derivation ───────────────────────────────────────────────────────
    total_stores = safe_get(summary, "total_stores", None)
    if total_stores is None:
        total_stores = len(filtered_catalog) if filtered_catalog else len(raw_findings)

    sensitive = sum(1 for d in filtered_catalog if d.get("classification") in ("PII", "PHI", "PCI", "Confidential"))
    unencrypted = sum(1 for d in filtered_catalog if not d.get("encryption") or d.get("encryption") == "None")
    public_access = sum(1 for d in filtered_catalog if d.get("public_access"))
    classified = sum(1 for d in filtered_catalog if d.get("classification"))
    encrypted = len(filtered_catalog) - unencrypted
    sensitive_exposed = safe_get(summary, "sensitive_exposed", None)
    if sensitive_exposed is None:
        sensitive_exposed = sum(1 for d in filtered_catalog if d.get("classification") and d.get("public_access"))

    classified_pct = safe_get(summary, "classified_pct", None)
    if classified_pct is None:
        classified_pct = round((classified / len(filtered_catalog) * 100), 1) if filtered_catalog else 0

    encrypted_pct = safe_get(summary, "encrypted_pct", None)
    if encrypted_pct is None:
        encrypted_pct = round((encrypted / len(filtered_catalog) * 100), 1) if filtered_catalog else 0

    posture_score = safe_get(summary, "data_risk_score", 0) or safe_get(summary, "posture_score", 0)
    if not posture_score and raw_findings:
        sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(sev_weights.get((f.get("severity") or "medium").lower(), 2) for f in raw_findings)
        posture_score = min(100, round((total_weight / (len(raw_findings) * 4)) * 100))

    # ── Page context tabs (reflects what actually has data) ─────────────────
    page_ctx = datasec_page_context({})
    page_ctx["brief"] = f"{total_stores} data stores monitored — {sensitive} contain sensitive data"
    page_ctx["tabs"] = [
        {"id": "catalog",   "label": "Data Catalog", "count": len(filtered_catalog) or len(raw_findings)},
        {"id": "findings",  "label": "Findings",     "count": len(raw_findings)},
        {"id": "dlp",       "label": "DLP",          "count": len(dlp)},
        {"id": "residency", "label": "Data Residency","count": len(residency)},
        {"id": "access",    "label": "Access Monitoring", "count": len(monitoring)},
    ]

    # ── Scan trend with chart dataKeys ────────────────────────────────────────
    raw_trend = safe_get(datasec_data, "scan_trend", [])
    color_map = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6"}
    active_scan_trend = []
    for pt in (raw_trend if isinstance(raw_trend, list) else []):
        sev_pt = pt.get("by_severity") or {}
        active_scan_trend.append({
            "date":     pt.get("scan_date") or pt.get("date", ""),
            "critical": sev_pt.get("critical", pt.get("critical", 0)),
            "high":     sev_pt.get("high",     pt.get("high",     0)),
            "medium":   sev_pt.get("medium",   pt.get("medium",   0)),
            "low":      sev_pt.get("low",      pt.get("low",      0)),
            "passRate": pt.get("pass_rate") or pt.get("passRate", 0),
            "total":    pt.get("total_findings") or pt.get("total", 0),
        })

    first_pt  = active_scan_trend[0]  if active_scan_trend else {}
    last_pt   = active_scan_trend[-1] if active_scan_trend else {}
    first_obj = {k: first_pt.get(k, 0) for k in ("date", "critical", "high", "total", "passRate")}
    last_obj  = {k: last_pt.get(k, 0)  for k in ("date", "critical", "high", "total", "passRate")}

    # ── Active module scores (data domains) ───────────────────────────────────
    domain_breakdown = safe_get(datasec_data, "domain_breakdown", [])
    active_module_scores = [
        {
            "key":   d.get("domain", ""),
            "label": d.get("domain", "").replace("_", " ").title(),
            "score": d.get("score", 0),
            "pass":  (d.get("score") or 0) >= 70,
        }
        for d in (domain_breakdown if isinstance(domain_breakdown, list) else [])
    ]

    # ── Donut slices ──────────────────────────────────────────────────────────
    sev_counts = {
        "critical": sum(1 for f in raw_findings if (f.get("severity") or "").lower() == "critical"),
        "high":     sum(1 for f in raw_findings if (f.get("severity") or "").lower() == "high"),
        "medium":   sum(1 for f in raw_findings if (f.get("severity") or "").lower() == "medium"),
        "low":      sum(1 for f in raw_findings if (f.get("severity") or "").lower() == "low"),
    }
    donut_slices = [
        {"name": sev.title(), "value": cnt, "color": color_map[sev]}
        for sev, cnt in sev_counts.items() if cnt > 0
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": datasec_filter_schema(),
        "kpiGroups": [
            {
                "title": "Data Exposure",
                "items": [
                    {"label": "Stores Monitored", "value": total_stores},
                    {"label": "Sensitive Stores", "value": sensitive},
                    {"label": "Public Access", "value": public_access},
                    {"label": "Sensitive Exposed", "value": sensitive_exposed},
                    {"label": "Posture Score", "value": posture_score, "suffix": "/100"},
                ],
            },
            {
                "title": "Data Protection",
                "items": [
                    {"label": "Encrypted", "value": encrypted_pct, "suffix": "%"},
                    {"label": "Classified", "value": classified_pct, "suffix": "%"},
                    {"label": "Unencrypted", "value": unencrypted},
                    {"label": "DLP Violations", "value": len(dlp)},
                ],
            },
        ],
        "catalog": filtered_catalog,
        "classifications": classifications,
        "lineage": lineage,
        "residency": residency,
        "activity": activity,
        "findings": raw_findings,
        "dlp": dlp,
        "encryption": encryption,
        "accessMonitoring": monitoring,
        "domainBreakdown": domain_breakdown,
        "db":              domain_breakdown,
        "scanTrend":       active_scan_trend,
        "activeScanTrend": active_scan_trend,
        "activeModuleScores": active_module_scores,
        "donutSlices":     donut_slices,
        "first":           first_obj,
        "last":            last_obj,
        # ARCH-04: unified findings from security_findings table (fallback source)
        "securityFindings": read_findings(
            tenant_id=tenant_id, source_engines=["datasec"],
            provider=provider.lower() if provider else None,
            account_id=account, region=region, limit=500,
        )["findings"],
    }
