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


# ── Drift Timeline Transform ──────────────────────────────────────────────

# Maps field names/paths to UI category groups
_FIELD_CATEGORIES: Dict[str, str] = {
    # Security
    "security_groups": "security", "sg": "security",
    "public_access": "security", "public": "security",
    "encryption": "security", "encrypted": "security", "encryption_status": "security",
    "ssl": "security", "tls": "security", "kms": "security",
    "iam_role": "security", "iam_policy": "security", "iam": "security",
    "access_control": "security", "acl": "security", "policy": "security",
    "mfa": "security", "logging": "security", "versioning": "security",
    "firewall": "security", "waf": "security",
    # Network
    "subnet_id": "network", "subnet": "network",
    "vpc_id": "network", "vpc": "network",
    "private_ip": "network", "public_ip": "network", "ip_address": "network",
    "cidr": "network", "route_table": "network", "dns": "network",
    "load_balancer": "network", "port": "network", "protocol": "network",
    "endpoint": "network", "internet_gateway": "network",
    "network_interface": "network", "nat_gateway": "network",
    # Tags
    "tags": "tags", "environment": "tags", "costcenter": "tags",
    "owner": "tags", "name": "tags", "project": "tags",
    "team": "tags", "department": "tags", "application": "tags",
    # Config
    "instance_type": "config", "instance_class": "config",
    "storage": "config", "size": "config", "capacity": "config",
    "engine": "config", "engine_version": "config", "runtime": "config",
    "monitoring": "config", "backup": "config", "retention": "config",
    "replicas": "config", "multi_az": "config", "availability_zone": "config",
    "region": "config", "ami": "config", "image": "config",
    "state": "config", "status": "config",
}

# Order for display
_CATEGORY_ORDER = ["security", "network", "tags", "config"]

# Severity weights for drift scoring
_CATEGORY_SEVERITY_WEIGHT = {"security": 3, "network": 2, "tags": 1, "config": 1}


def _classify_field(field_path: str) -> str:
    """Map a changed field path to a UI category."""
    lower = field_path.lower().replace(".", "_").replace("/", "_")
    # Direct lookup
    if lower in _FIELD_CATEGORIES:
        return _FIELD_CATEGORIES[lower]
    # Check if any known prefix matches
    for key, cat in _FIELD_CATEGORIES.items():
        if key in lower:
            return cat
    # Tags sub-keys (e.g. tags.CostCenter)
    if lower.startswith("tags"):
        return "tags"
    return "config"  # default bucket


def _extract_field_changes(change: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract individual field-level changes from a drift change record.

    Handles multiple changes_summary formats:
      - {"field": {"before": x, "after": y}}
      - {"changes": [{"path": p, "before": x, "after": y}]}
      - {} (fall back to change_type label)
    """
    summary = change.get("changes_summary", {})
    if not isinstance(summary, dict):
        summary = {}

    fields: List[Dict[str, Any]] = []

    # Format A: {"changes": [{"path": ..., "before": ..., "after": ...}]}
    if "changes" in summary and isinstance(summary["changes"], list):
        for c in summary["changes"]:
            fields.append({
                "field": c.get("path", "unknown"),
                "category": _classify_field(c.get("path", "")),
                "before": c.get("before"),
                "after": c.get("after"),
            })
    else:
        # Format B: {"field_name": {"before": x, "after": y}}
        for field_name, diff in summary.items():
            if isinstance(diff, dict) and ("before" in diff or "after" in diff):
                fields.append({
                    "field": field_name,
                    "category": _classify_field(field_name),
                    "before": diff.get("before"),
                    "after": diff.get("after"),
                })

    # Fallback: if no field-level detail, create a synthetic entry.
    # This covers asset_added (new resource), asset_removed (gone),
    # and asset_changed when the old detector only wrote "metadata changed".
    if not fields:
        raw_type = change.get("change_type", "modified")
        if "add" in raw_type:
            fields.append({
                "field": "resource",
                "category": "config",
                "before": None,
                "after": "New resource discovered",
            })
        elif "remov" in raw_type:
            fields.append({
                "field": "resource",
                "category": "config",
                "before": "Resource existed",
                "after": None,
            })
        else:
            fields.append({
                "field": "configuration",
                "category": "config",
                "before": "(previous version)",
                "after": "(current version)",
            })

    return fields


def _build_drift_timeline(
    raw_drift: Dict[str, Any],
) -> Dict[str, Any]:
    """Transform raw engine drift_info into a grouped timeline for the UI.

    Groups changes by scan transition, categorises fields, and computes
    a summary table — ready for the timeline component.
    """
    changes = raw_drift.get("changes", [])
    if not changes:
        return {
            "last_check": raw_drift.get("last_check"),
            "has_drift": False,
            "scans": [],
            "transitions": [],
            "summary": {"modified": 0, "added": 0, "removed": 0},
            "total": 0,
        }

    # ── Group changes by scan transition ──────────────────────────────
    # Each unique (scan_run_id, previous_scan_id) pair = one transition
    from collections import OrderedDict
    transitions_map: Dict[str, Dict[str, Any]] = OrderedDict()

    for c in changes:
        scan_id = c.get("scan_run_id", "")
        prev_id = c.get("previous_scan_id", "")
        key = f"{scan_id}|{prev_id}"

        if key not in transitions_map:
            transitions_map[key] = {
                "scan_run_id": scan_id,
                "previous_scan_id": prev_id,
                "detected_at": c.get("detected_at"),
                "field_changes": [],
                "counts": {"modified": 0, "added": 0, "removed": 0},
            }

        change_type = c.get("change_type", "modified")
        # Normalise change_type to one of modified/added/removed
        if "add" in change_type:
            ct = "added"
        elif "remov" in change_type:
            ct = "removed"
        else:
            ct = "modified"

        transitions_map[key]["counts"][ct] = (
            transitions_map[key]["counts"].get(ct, 0) + 1
        )

        # Extract field-level diffs
        for field in _extract_field_changes(c):
            field["change_type"] = ct
            field["severity"] = c.get("severity", "medium")
            transitions_map[key]["field_changes"].append(field)

    # ── Build per-transition category groups ──────────────────────────
    transitions = []
    for t in transitions_map.values():
        by_category: Dict[str, List[Dict[str, Any]]] = {}
        for fc in t["field_changes"]:
            cat = fc.get("category", "config")
            by_category.setdefault(cat, []).append(fc)

        # Sort categories in display order
        ordered_cats = []
        for cat in _CATEGORY_ORDER:
            if cat in by_category:
                ordered_cats.append({
                    "category": cat,
                    "fields": by_category[cat],
                })
        # Any remaining categories not in the standard order
        for cat, fields in by_category.items():
            if cat not in _CATEGORY_ORDER:
                ordered_cats.append({"category": cat, "fields": fields})

        # Compute drift severity for this transition
        severity_score = sum(
            _CATEGORY_SEVERITY_WEIGHT.get(fc.get("category", "config"), 1)
            for fc in t["field_changes"]
        )
        if severity_score >= 6:
            drift_severity = "high"
        elif severity_score >= 3:
            drift_severity = "medium"
        else:
            drift_severity = "low"

        transitions.append({
            "scan_run_id": t["scan_run_id"],
            "previous_scan_id": t["previous_scan_id"],
            "detected_at": t["detected_at"],
            "categories": ordered_cats,
            "counts": t["counts"],
            "drift_severity": drift_severity,
            "total_fields_changed": len(t["field_changes"]),
        })

    # ── Collect unique scan IDs for the timeline rail ─────────────────
    scan_ids_seen: Dict[str, Optional[str]] = OrderedDict()
    for t in transitions:
        if t["scan_run_id"]:
            scan_ids_seen.setdefault(t["scan_run_id"], t["detected_at"])
        if t["previous_scan_id"]:
            scan_ids_seen.setdefault(t["previous_scan_id"], None)

    scans = [
        {"scan_run_id": sid, "detected_at": ts}
        for sid, ts in scan_ids_seen.items()
    ]

    # ── Grand summary ─────────────────────────────────────────────────
    total_counts = {"modified": 0, "added": 0, "removed": 0}
    for t in transitions:
        for k in total_counts:
            total_counts[k] += t["counts"].get(k, 0)

    return {
        "last_check": raw_drift.get("last_check"),
        "has_drift": True,
        "scans": scans,
        "transitions": transitions,
        "summary": total_counts,
        "total": raw_drift.get("total", len(changes)),
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

    # ── Transform drift into timeline view ───────────────────────────
    raw_drift = inventory_data.get("drift_info", {})
    if not isinstance(raw_drift, dict):
        raw_drift = {}
    drift_timeline = _build_drift_timeline(raw_drift)

    return {
        "asset": inventory_data,
        "check_findings": check_data.get("findings", []),
        "check_severity": check_data.get("severity_counts", {}),
        "check_posture": check_data.get("posture_by_domain", {}),
        "threat_findings": threat_data.get("findings", []),
        "threat_severity": threat_data.get("severity_counts", {}),
        "compliance_findings": compliance_data.get("findings", []),
        "drift": drift_timeline,
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
