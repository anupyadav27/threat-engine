"""BFF view: /inventory page + asset detail + blast-radius.

List view: 3 parallel calls (inventory/ui-data + threat/ui-data + onboarding/ui-data).
Asset detail: 4 parallel calls (inventory + check + threat + compliance per resource).
Blast radius: inventory graph + parallel posture enrichment per node.

Adds resilience: cross-engine enrichment with threat data for findings counts,
provider enrichment from cloud_accounts, and fallback when inventory engine is sparse.
"""

import asyncio
import datetime
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query

from ._shared import ENGINE_URLS, ENGINE_TIMEOUTS, DEFAULT_TIMEOUT, fetch_many, safe_get
from ._transforms import normalize_asset, apply_global_filters, _safe_upper

logger = logging.getLogger("api-gateway.bff")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/inventory")
async def view_inventory(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    """Asset list + summary for the inventory page."""

    # ── 3 parallel calls instead of 4 ────────────────────────────────────
    results = await fetch_many([
        ("inventory",  "/api/v1/inventory/ui-data",  {"tenant_id": tenant_id, "scan_run_id": scan_run_id, "limit": str(limit), "offset": str(offset)}),
        ("threat",     "/api/v1/threat/ui-data",     {"tenant_id": tenant_id, "scan_run_id": "latest", "limit": "0"}),
        ("onboarding", "/api/v1/onboarding/ui-data", {"tenant_id": tenant_id}),
    ])

    inventory_data, threat_data, onboarding_data = results

    # Safely unwrap responses
    inventory_data = inventory_data if isinstance(inventory_data, dict) else {}
    threat_data = threat_data if isinstance(threat_data, dict) else {}
    onboarding_data = onboarding_data if isinstance(onboarding_data, dict) else {}

    # ── Extract inventory fields ─────────────────────────────────────────
    summary_resp = inventory_data.get("summary", {})
    if not isinstance(summary_resp, dict):
        summary_resp = {}

    # Normalize assets
    raw_assets = inventory_data.get("assets", [])
    if not isinstance(raw_assets, list):
        raw_assets = []
    assets = [normalize_asset(a) for a in raw_assets]

    # ── Build account->provider mapping from onboarding ──────────────────
    raw_accounts = onboarding_data.get("accounts", [])
    if not isinstance(raw_accounts, list):
        raw_accounts = []
    account_provider_map: Dict[str, str] = {}
    default_provider = ""
    for a in raw_accounts:
        acct_id = a.get("account_id", "")
        prov = (a.get("provider") or a.get("csp") or "").lower()
        if acct_id and prov:
            account_provider_map[acct_id] = prov
            if not default_provider:
                default_provider = prov

    # Enrich assets with provider when missing
    for asset in assets:
        if not asset.get("provider"):
            acct = asset.get("account_id", "")
            asset["provider"] = account_provider_map.get(acct, default_provider)

    # Apply scope filters
    filtered = apply_global_filters(assets, provider, account, region)

    # ── KPI derivation ───────────────────────────────────────────────────
    total = len(filtered)
    now = datetime.datetime.utcnow()
    week_ago = now - datetime.timedelta(days=7)
    new_this_week = sum(1 for a in filtered if a.get("created_at") and str(a["created_at"]) > week_ago.isoformat())
    unmanaged = sum(1 for a in filtered if not a.get("tags") or len(a.get("tags", {})) == 0)
    exposed = sum(1 for a in filtered if a.get("internet_exposed") or a.get("public"))
    critical = sum(1 for a in filtered if (
        (isinstance(a.get("findings"), dict) and a["findings"].get("critical", 0) > 0)
        or a.get("severity") == "critical"
    ))
    drift_count = summary_resp.get("total_drift", 0)

    # Enrich with threat data when inventory is sparse
    threat_summary = threat_data.get("summary", {})
    if isinstance(threat_summary, dict):
        by_sev = threat_summary.get("by_severity", {}) or threat_summary.get("threats_by_severity", {})
    else:
        by_sev = {}
    if not critical and isinstance(by_sev, dict):
        critical = by_sev.get("critical", 0)

    # ── Provider breakdown ───────────────────────────────────────────────
    by_provider: Dict[str, int] = {}
    for a in filtered:
        p = (a.get("provider") or "unknown").upper()
        by_provider[p] = by_provider.get(p, 0) + 1

    # If no assets from inventory, derive from cloud accounts
    if not by_provider:
        for a in raw_accounts:
            prov = _safe_upper(a.get("provider") or a.get("csp"))
            resources = a.get("total_resources", 0) or 0
            if prov:
                by_provider[prov] = by_provider.get(prov, 0) + resources
        total = sum(by_provider.values())

    # Also try summary-level by_provider if available and more complete
    if not by_provider:
        summary_by_provider = summary_resp.get("assets_by_provider", {})
        if isinstance(summary_by_provider, dict) and summary_by_provider:
            for prov_key, count in summary_by_provider.items():
                by_provider[prov_key.upper()] = count if isinstance(count, int) else 0
            if not total:
                total = sum(by_provider.values())

    # ── Service breakdown ────────────────────────────────────────────────
    by_service: Dict[str, int] = {}
    for a in filtered:
        svc = a.get("service") or a.get("resource_type", "other")
        by_service[svc] = by_service.get(svc, 0) + 1

    # Fall back to summary-level by_service if asset-level is empty
    if not by_service:
        summary_by_service = summary_resp.get("assets_by_service", {})
        if isinstance(summary_by_service, dict):
            by_service = {k: v for k, v in summary_by_service.items() if isinstance(v, int)}

    return {
        "kpi": {
            "totalAssets": total or summary_resp.get("total_assets", 0),
            "newThisWeek": new_this_week,
            "unmanagedAssets": unmanaged,
            "exposedAssets": exposed,
            "criticalFindings": critical,
            "driftCount": drift_count,
        },
        "assets": filtered,
        "total": inventory_data.get("total", len(filtered)),
        "has_more": inventory_data.get("has_more", False),
        "summary": summary_resp,
        "byProvider": by_provider,
        "byService": dict(sorted(by_service.items(), key=lambda x: x[1], reverse=True)[:15]),
    }


# ── Asset Detail View ─────────────────────────────────────────────────────


@router.get("/inventory/asset/{resource_uid:path}")
async def view_asset_detail(
    resource_uid: str,
    tenant_id: str = Query(...),
    scan_run_id: str = Query("latest"),
):
    """Asset detail with cross-engine enrichment via HTTP fan-out.

    Assembles the full asset picture from 4 engines in parallel:
    - inventory: base asset data + drift info
    - check: severity counts + detailed misconfig findings
    - threat: MITRE ATT&CK findings + severity counts
    - compliance: framework compliance findings per resource

    The :path converter is greedy, so sub-route suffixes are dispatched
    manually (same pattern used by the inventory engine).
    """
    # ── Sub-route dispatch (greedy :path swallows suffixes) ────────────
    if resource_uid.endswith("/blast-radius"):
        actual_uid = resource_uid[: -len("/blast-radius")]
        return await view_blast_radius(
            resource_uid=actual_uid,
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
        )

    # ── 4 parallel calls ──────────────────────────────────────────────
    results = await fetch_many([
        ("inventory",  f"/api/v1/inventory/assets/{resource_uid}",
         {"tenant_id": tenant_id, "scan_run_id": scan_run_id}),
        ("check",      f"/api/v1/check/findings/resource/{resource_uid}",
         {"tenant_id": tenant_id}),
        ("threat",     f"/api/v1/threat/findings/resource/{resource_uid}",
         {"tenant_id": tenant_id}),
        ("compliance", f"/api/v1/compliance/findings/resource/{resource_uid}",
         {"tenant_id": tenant_id}),
    ])

    inventory_data, check_data, threat_data, compliance_data = results

    # Safely unwrap — failed calls return None
    inventory_data = inventory_data if isinstance(inventory_data, dict) else {}
    check_data = check_data if isinstance(check_data, dict) else {}
    threat_data = threat_data if isinstance(threat_data, dict) else {}
    compliance_data = compliance_data if isinstance(compliance_data, dict) else {}

    return {
        "asset": inventory_data,
        "check_findings": check_data.get("findings", []),
        "check_severity": check_data.get("severity_counts", {}),
        "threat_findings": threat_data.get("findings", []),
        "threat_severity": threat_data.get("severity_counts", {}),
        "compliance_findings": compliance_data.get("findings", []),
        "drift": inventory_data.get("drift_info", {}),
        "relationships": inventory_data.get("relationships", []),
    }


# ── Blast Radius View ─────────────────────────────────────────────────────


async def _fetch_posture_for_nodes(
    node_uids: List[str],
    tenant_id: str,
) -> Dict[str, Dict[str, Any]]:
    """Batch-fetch check + threat severity counts for a set of resource_uids.

    Makes 2×N parallel HTTP calls (one check + one threat per node).
    Returns {resource_uid: {"check": {sev_counts}, "threat": {sev_counts}}}.
    """
    import httpx

    if not node_uids:
        return {}

    posture: Dict[str, Dict[str, Any]] = {
        uid: {"check": {}, "threat": {}} for uid in node_uids
    }

    async with httpx.AsyncClient() as client:
        tasks = []
        task_meta: List[tuple] = []  # (uid, engine_name)

        for uid in node_uids:
            for engine, path_tpl in [
                ("check",  "/api/v1/check/findings/resource/{}"),
                ("threat", "/api/v1/threat/findings/resource/{}"),
            ]:
                base = ENGINE_URLS.get(engine, "")
                url = f"{base}{path_tpl.format(uid)}"
                timeout = ENGINE_TIMEOUTS.get(engine, DEFAULT_TIMEOUT)
                tasks.append(
                    client.get(url, params={"tenant_id": tenant_id}, timeout=timeout)
                )
                task_meta.append((uid, engine))

        # Gather all — exceptions are caught individually
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (uid, engine), resp in zip(task_meta, responses):
            if isinstance(resp, Exception):
                logger.debug("Blast-radius posture %s/%s failed: %s", engine, uid, resp)
                continue
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    posture[uid][engine] = data.get("severity_counts", {})
                except Exception:
                    pass

    return posture


@router.get("/inventory/asset/{resource_uid:path}/blast-radius")
async def view_blast_radius(
    resource_uid: str,
    tenant_id: str = Query(...),
    scan_run_id: str = Query("latest"),
    max_depth: int = Query(3, ge=1, le=5),
):
    """Blast-radius graph with per-node posture enrichment.

    Step 1: Get the relationship graph from inventory engine (recursive CTE).
    Step 2: Collect all unique node resource_uids.
    Step 3: Fan out to check + threat engines for severity counts per node.
    Step 4: Merge posture data into each graph node.
    """
    # Step 1: Get graph from inventory engine
    graph_results = await fetch_many([
        ("inventory",
         f"/api/v1/inventory/assets/{resource_uid}/blast-radius",
         {"tenant_id": tenant_id, "scan_run_id": scan_run_id,
          "max_depth": str(max_depth)}),
    ])

    graph_data = graph_results[0]
    if not isinstance(graph_data, dict):
        graph_data = {"nodes": [], "edges": [], "center": resource_uid,
                      "max_depth": max_depth, "total_nodes": 0, "total_edges": 0}

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not nodes:
        return graph_data

    # Step 2: Collect unique resource_uids from nodes
    node_uids = list({
        n.get("resource_uid") or n.get("id", "")
        for n in nodes
        if n.get("resource_uid") or n.get("id")
    })

    # Step 3: Parallel posture fetch (check + threat per node)
    posture_map = await _fetch_posture_for_nodes(node_uids, tenant_id)

    # Step 4: Enrich nodes with posture badges
    for node in nodes:
        uid = node.get("resource_uid") or node.get("id", "")
        node_posture = posture_map.get(uid, {})

        check_sev = node_posture.get("check", {})
        threat_sev = node_posture.get("threat", {})

        node["posture"] = {
            "check": check_sev,
            "threat": threat_sev,
            "total_critical": check_sev.get("critical", 0) + threat_sev.get("critical", 0),
            "total_high": check_sev.get("high", 0) + threat_sev.get("high", 0),
        }

    return {
        "nodes": nodes,
        "edges": edges,
        "center": resource_uid,
        "max_depth": graph_data.get("max_depth", max_depth),
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }
