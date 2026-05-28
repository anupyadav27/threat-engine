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
from collections import defaultdict
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query, Request

from ._auth import _parse_auth_context, resolve_tenant_id
from ._shared import ENGINE_URLS, ENGINE_TIMEOUTS, DEFAULT_TIMEOUT, fetch_many, fetch_scan_trend
from ._transforms import normalize_asset, apply_global_filters, _safe_upper
from ._page_context import inventory_page_context, inventory_filter_schema
from ._common_schemas import InventoryViewResponse

logger = logging.getLogger("api-gateway.bff")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


# ── Batch enrichment helpers (per-asset findings + risk) ─────────────────────

async def _batch_check_severity(
    resource_uids: List[str],
    tenant_id: str,
    auth_headers: Optional[Dict[str, str]],
) -> Dict[str, Dict[str, int]]:
    """POST to check engine's batch-severity endpoint to get per-resource finding counts.

    Returns: { resource_uid: {"critical": N, "high": N, "medium": N, "low": N} }
    Empty dict on failure — never raises (best-effort enrichment).
    """
    if not resource_uids:
        return {}
    url = f"{ENGINE_URLS['check']}/api/v1/check/findings/batch-severity"
    body = {"tenant_id": tenant_id, "resource_uids": resource_uids}
    headers = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update(auth_headers)
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=body, headers=headers, timeout=15.0)
            if resp.status_code != 200:
                logger.warning("BFF inventory batch-severity -> %s", resp.status_code)
                return {}
            data = resp.json()
            results = data.get("results") if isinstance(data, dict) else None
            return results if isinstance(results, dict) else {}
    except Exception as exc:
        logger.warning("BFF inventory batch-severity failed: %s", exc)
        return {}


def _resource_short_id(uid: str) -> str:
    """Extract trailing resource identifier from any UID format.

    Bridges the risk engine's compact UIDs ("ebs:ap-south-1:acct:snap-XXX")
    and the inventory engine's ARNs ("arn:aws:ebs:ap-south-1:acct:snapshot/snap-XXX")
    by returning the last path/colon segment, e.g. "snap-XXX".
    """
    if not uid:
        return ""
    last = uid.rsplit("/", 1)[-1]
    last = last.rsplit(":", 1)[-1]
    return last.lower()


async def _risk_top_assets(
    tenant_id: str,
    auth_headers: Optional[Dict[str, str]],
    limit: int = 50,
) -> Dict[str, Dict[str, Any]]:
    """Fetch top-N risk-scored assets from risk engine.

    Returns: lookup keyed by both the full risk-engine UID AND the
    trailing short-id (e.g. "snap-XXX"), so the inventory merge can match
    either format. Each value: {"blast_radius_score", "compound_risk_score",
    "risk_scenario", "threat_count"}. Best-effort — empty dict on failure.
    """
    url = f"{ENGINE_URLS['risk']}/api/v1/risk/assets/top"
    # Engine caps limit at 50.
    params = {"tenant_id": tenant_id, "limit": str(min(limit, 50))}
    headers = {}
    if auth_headers:
        headers.update(auth_headers)
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, params=params, headers=headers, timeout=8.0)
            if resp.status_code != 200:
                return {}
            data = resp.json()
            items = data.get("assets") if isinstance(data, dict) else None
            if not isinstance(items, list):
                items = data.get("items") if isinstance(data, dict) else data
            if not isinstance(items, list):
                return {}
            out: Dict[str, Dict[str, Any]] = {}
            for it in items:
                uid = it.get("resource_uid") or it.get("resource_id")
                if not uid:
                    continue
                # Risk engine surfaces a generic "risk_score" — treat it as the
                # blast-radius proxy until per-scenario decomposition lands.
                rscore = int(it.get("blast_radius_score") or it.get("risk_score") or 0)
                cscore = int(it.get("compound_risk_score") or it.get("compound_risk") or 0)
                # Compound risk is a function of overlapping scenarios per asset:
                # if the engine doesn't surface it explicitly, derive a proxy
                # from threat_count (capped at 100).
                if not cscore:
                    cscore = min(int(it.get("threat_count") or 0) * 25, 100)
                payload = {
                    "blast_radius_score": rscore,
                    "compound_risk_score": cscore,
                    "risk_scenario": it.get("scenario"),
                    "threat_count": int(it.get("threat_count") or 0),
                }
                out[uid] = payload
                short = _resource_short_id(uid)
                if short and short not in out:
                    out[short] = payload
            return out
    except Exception as exc:
        logger.info("BFF inventory risk-top fetch skipped: %s", exc)
        return {}


async def _batch_rsp_posture(
    resource_uids: List[str],
    auth_headers: Optional[Dict[str, str]],
) -> Dict[str, Dict[str, Any]]:
    """POST to DI engine's batch-posture endpoint to get RSP signals per asset.

    Returns: { resource_uid: { overall_posture_score, is_internet_exposed,
               can_access_pii, data_classification, is_on_attack_path,
               attack_path_count, highest_path_severity, has_active_cdr_actor,
               is_crown_jewel, blast_radius_count, ... } }
    Best-effort — empty dict on failure.
    """
    if not resource_uids:
        return {}
    url = f"{ENGINE_URLS['di']}/api/v1/di/batch-posture"
    body = {"resource_uids": resource_uids[:500]}
    headers = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update(auth_headers)
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=body, headers=headers, timeout=15.0)
            if resp.status_code != 200:
                logger.warning("BFF inventory batch-posture -> %s", resp.status_code)
                return {}
            data = resp.json()
            posture = data.get("posture") if isinstance(data, dict) else None
            return posture if isinstance(posture, dict) else {}
    except Exception as exc:
        logger.warning("BFF inventory batch-posture failed: %s", exc)
        return {}


def _type_from_arn(arn: str) -> str:
    """Derive a human-readable resource type from an AWS ARN.

    e.g. arn:aws:ec2:...:security-group/sg-xxx  → 'ec2.security-group'
         arn:aws:s3:::bucket-name               → 's3.bucket'
         arn:aws:iam::123:role/MyRole           → 'iam.role'
    """
    if not arn or not arn.startswith("arn:"):
        return "Resource"
    parts = arn.split(":")
    if len(parts) < 6:
        return "Resource"
    service = parts[2]          # ec2, s3, iam, rds, …
    resource_part = parts[-1]   # e.g. security-group/sg-xxx or bucket-name
    if "/" in resource_part:
        rtype = resource_part.split("/")[0]   # security-group, role, subnet, …
        return f"{service}.{rtype}"
    if resource_part:
        return f"{service}.{resource_part}"
    return service or "Resource"


@router.get("/inventory", response_model=InventoryViewResponse, response_model_exclude_none=False)
async def view_inventory(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
    limit: int = Query(2000, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    """Asset list + summary for the inventory page."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many([
        ("di",  "/api/v1/di/ui-data",  {"scan_run_id": scan_run_id, "limit": str(min(limit, 2000)), "offset": str(offset)}),
        ("attack_path", "/api/v1/threat/ui-data",     {"tenant_id": tenant_id, "scan_run_id": "latest", "limit": str(limit)}),
        ("onboarding", "/api/v1/cloud-accounts", {"tenant_id": tenant_id}),
    ], auth_headers=fwd_headers)

    inventory_data, threat_data, onboarding_data = results

    # Safely unwrap responses
    inventory_data = inventory_data if isinstance(inventory_data, dict) else {}
    threat_data = threat_data if isinstance(threat_data, dict) else {}
    onboarding_data = onboarding_data if isinstance(onboarding_data, dict) else {}

    # ── Build threat-findings lookup: resource_uid → {critical,high,medium,low,risk_score}
    threat_by_resource: Dict[str, Dict[str, Any]] = {}
    raw_threats = threat_data.get("threats", []) or threat_data.get("detections", []) or []
    if not isinstance(raw_threats, list):
        raw_threats = []
    risk_map = {"critical": 95, "high": 75, "medium": 50, "low": 25}
    for t in raw_threats:
        uid = t.get("resource_uid", "")
        if not uid:
            continue
        sev = (t.get("severity") or "medium").lower()
        if uid not in threat_by_resource:
            threat_by_resource[uid] = {
                "critical": 0, "high": 0, "medium": 0, "low": 0,
                "risk_score": 0, "total": 0,
            }
        entry = threat_by_resource[uid]
        if sev in entry:
            entry[sev] += 1
        entry["total"] += 1
        score = t.get("risk_score") or risk_map.get(sev, 50)
        if score > entry["risk_score"]:
            entry["risk_score"] = score

    # ── Extract inventory fields ─────────────────────────────────────────
    summary_resp = inventory_data.get("summary", {})
    if not isinstance(summary_resp, dict):
        summary_resp = {}

    # Normalize assets
    raw_assets = inventory_data.get("assets", [])
    if not isinstance(raw_assets, list):
        raw_assets = []
    assets = [normalize_asset(a) for a in raw_assets]

    # ── Enrich each asset with threat findings counts + risk score ────────
    for asset in assets:
        uid = asset.get("resource_uid", "")
        threat_info = threat_by_resource.get(uid)
        if threat_info:
            # Merge findings counts — overlay onto whatever normalize_asset produced
            existing_findings = asset.get("findings") or {}
            asset["findings"] = {
                "critical": existing_findings.get("critical", 0) + threat_info["critical"],
                "high": existing_findings.get("high", 0) + threat_info["high"],
                "medium": existing_findings.get("medium", 0) + threat_info["medium"],
                "low": existing_findings.get("low", 0) + threat_info["low"],
            }
            # Use highest risk score between existing and threat
            existing_risk = asset.get("risk_score") or 0
            asset["risk_score"] = max(existing_risk, threat_info["risk_score"])
            # Derive severity from highest non-zero findings bucket
            if asset["findings"]["critical"] > 0:
                asset["severity"] = "critical"
            elif asset["findings"]["high"] > 0:
                asset["severity"] = "high"
            elif asset["findings"]["medium"] > 0:
                asset["severity"] = "medium"
            elif asset["findings"]["low"] > 0:
                asset["severity"] = "low"

    # ── Batch-enrich with check findings + risk scores + RSP posture ──────
    asset_uids = [a.get("resource_uid") for a in assets if a.get("resource_uid")]
    check_severity_map, risk_top_map, rsp_map = await asyncio.gather(
        _batch_check_severity(asset_uids, tenant_id, fwd_headers),
        _risk_top_assets(tenant_id, fwd_headers, limit=min(limit, 1000)),
        _batch_rsp_posture(asset_uids, fwd_headers),
    )

    for asset in assets:
        uid = asset.get("resource_uid", "")
        if not uid:
            continue
        cs = check_severity_map.get(uid)
        if cs:
            existing = asset.get("findings") or {}
            asset["findings"] = {
                "critical": existing.get("critical", 0) + int(cs.get("critical", 0) or 0),
                "high": existing.get("high", 0) + int(cs.get("high", 0) or 0),
                "medium": existing.get("medium", 0) + int(cs.get("medium", 0) or 0),
                "low": existing.get("low", 0) + int(cs.get("low", 0) or 0),
            }
            f = asset["findings"]
            if f["critical"] > 0:
                asset["severity"] = "critical"
            elif f["high"] > 0 and asset.get("severity") not in ("critical",):
                asset["severity"] = "high"
            elif f["medium"] > 0 and asset.get("severity") not in ("critical", "high"):
                asset["severity"] = "medium"
            elif f["low"] > 0 and not asset.get("severity"):
                asset["severity"] = "low"
        rt = risk_top_map.get(uid) or risk_top_map.get(_resource_short_id(uid))
        if rt:
            asset["blast_radius_score"] = rt.get("blast_radius_score", 0)
            asset["compound_risk_score"] = rt.get("compound_risk_score", 0)
            if rt.get("risk_scenario"):
                asset["risk_scenario"] = rt["risk_scenario"]
        # Merge RSP posture signals — these power the Orca-style table columns
        rsp = rsp_map.get(uid)
        if rsp:
            asset["overall_posture_score"] = rsp.get("overall_posture_score", 0)
            # Prefer RSP is_internet_exposed (written by network engine) over heuristic
            asset["is_internet_exposed"] = rsp.get("is_internet_exposed", asset.get("internet_exposed", False))
            asset["can_access_pii"] = rsp.get("can_access_pii", False)
            asset["data_classification"] = rsp.get("data_classification", "unknown")
            asset["is_on_attack_path"] = rsp.get("is_on_attack_path", False)
            asset["attack_path_count"] = rsp.get("attack_path_count", 0)
            asset["highest_path_severity"] = rsp.get("highest_path_severity")
            asset["has_active_cdr_actor"] = rsp.get("has_active_cdr_actor", False)
            asset["is_crown_jewel"] = rsp.get("is_crown_jewel", False)
            asset["blast_radius_count"] = rsp.get("blast_radius_count", 0)
            asset["vuln_critical_count"] = rsp.get("vuln_critical_count", 0)
            asset["has_known_exploit"] = rsp.get("has_known_exploit", False)
            asset["is_encrypted_at_rest"] = rsp.get("is_encrypted_at_rest", False)
            asset["has_active_cdr_actor"] = rsp.get("has_active_cdr_actor", False)

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

    # Sort high-priority assets to the top so the first page surfaces
    # findings/exposure rather than alphabetical no-finding noise.
    _sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def _priority_key(a: Dict[str, Any]) -> tuple:
        f = a.get("findings") or {}
        finding_total = (
            int(f.get("critical", 0) or 0) * 1000
            + int(f.get("high", 0) or 0) * 100
            + int(f.get("medium", 0) or 0) * 10
            + int(f.get("low", 0) or 0)
        )
        sev_w = _sev_weight.get((a.get("severity") or "").lower(), 0)
        risk = int(a.get("risk_score") or 0)
        blast = int(a.get("blast_radius_score") or 0)
        exposed = 1 if (a.get("internet_exposed") or a.get("public")) else 0
        return (-finding_total, -sev_w, -risk, -blast, -exposed)

    filtered.sort(key=_priority_key)

    # ── KPI derivation ───────────────────────────────────────────────────
    total = len(filtered)
    now = datetime.datetime.now(datetime.timezone.utc)
    week_ago = now - datetime.timedelta(days=7)
    new_this_week = sum(1 for a in filtered if a.get("created_at") and str(a["created_at"]) > week_ago.isoformat())
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

    total_assets = total or summary_resp.get("total_assets", 0)
    providers_count = len(by_provider)
    services_count = len(by_service)
    regions_count = len(set(a.get("region", "") for a in filtered if a.get("region")))

    page_ctx = inventory_page_context({"total_assets": total_assets})
    page_ctx["tabs"] = [
        {"id": "assets", "label": "Assets", "count": total_assets},
        {"id": "graph", "label": "Graph", "count": 0},
    ]

    # Fetch real scan trend from onboarding DB (best-effort; returns [] on failure)
    scan_trend = fetch_scan_trend(tenant_id) if tenant_id else []

    return {
        "pageContext": page_ctx,
        "filterSchema": inventory_filter_schema(),
        "kpiGroups": [
            {
                "title": "Asset Coverage",
                "items": [
                    {"label": "Total Assets", "value": total_assets},
                    {"label": "Providers", "value": providers_count},
                    {"label": "Regions", "value": regions_count},
                    {"label": "Services", "value": services_count},
                ],
            },
            {
                "title": "Asset Health",
                "items": [
                    {"label": "New This Week", "value": new_this_week},
                    {"label": "Drift Detected", "value": drift_count},
                    {"label": "Exposed Assets", "value": exposed},
                    {"label": "Critical Findings", "value": critical},
                ],
            },
        ],
        "assets": filtered,
        "total": inventory_data.get("total", len(filtered)),
        "has_more": inventory_data.get("has_more", False),
        "summary": summary_resp,
        "scanTrend": scan_trend,
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

    raw_type = change.get("change_type", "modified")
    is_added = "add" in raw_type
    is_removed = "remov" in raw_type

    # Format A: {"changes": [{"path": ..., "before": ..., "after": ...}]}
    if "changes" in summary and isinstance(summary["changes"], list):
        for c in summary["changes"]:
            fields.append({
                "field": c.get("path", "unknown"),
                "category": _classify_field(c.get("path", "")),
                "before": c.get("before"),
                "after": c.get("after"),
                "context": c.get("context"),
            })
    # Format C: {"snapshot": {"name": ..., "resource_type": ..., "region": ..., "account_id": ...}}
    # Emitted by DriftDetector for ASSET_ADDED and ASSET_REMOVED
    elif "snapshot" in summary and isinstance(summary["snapshot"], dict):
        snap = summary["snapshot"]
        label_map = {
            "name": "Resource Name",
            "resource_type": "Resource Type",
            "region": "Region",
            "account_id": "Account",
        }
        for key in ("name", "resource_type", "region", "account_id"):
            value = snap.get(key)
            if not value:
                continue
            fields.append({
                "field": label_map.get(key, key),
                "category": _classify_field(key),
                "before": value if is_removed else None,
                "after": value if is_added else None,
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
        if is_added:
            fields.append({
                "field": "resource",
                "category": "config",
                "before": None,
                "after": "New resource discovered",
            })
        elif is_removed:
            fields.append({
                "field": "resource",
                "category": "config",
                "before": "Resource existed",
                "after": None,
            })
        else:
            fields.append({
                "field": "cloud_configuration",
                "category": "config",
                "before": None,
                "after": "Configuration properties updated",
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
    request: Request,
    resource_uid: str,
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
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    # ── Sub-route dispatch (greedy :path swallows suffixes) ────────────
    if resource_uid.endswith("/blast-radius"):
        actual_uid = resource_uid[: -len("/blast-radius")]
        return await view_blast_radius(request=request, resource_uid=actual_uid, max_depth=3)

    if resource_uid.endswith("/cdr"):
        actual_uid = resource_uid[: -len("/cdr")]
        return await view_asset_cdr(request=request, resource_uid=actual_uid)

    if resource_uid.endswith("/posture"):
        actual_uid = resource_uid[: -len("/posture")]
        return await view_asset_posture(request=request, resource_uid=actual_uid)

    if resource_uid.endswith("/findings"):
        actual_uid = resource_uid[: -len("/findings")]
        return await view_asset_findings(request=request, resource_uid=actual_uid)

    if resource_uid.endswith("/panel"):
        actual_uid = resource_uid[: -len("/panel")]
        return await view_asset_panel(
            request=request,
            resource_uid=actual_uid,
            findings_status="open",
            findings_page=1,
            findings_page_size=50,
        )

    # Encode resource_uid for use in URL paths — '/' in ARNs must be %2F so
    # FastAPI's {param:path} routes don't split on them.
    from urllib.parse import quote as _quote
    enc_uid = _quote(resource_uid, safe="")

    # ── 5 parallel calls (asset + relationships fetched separately) ────
    # DI engine is the primary source for single-asset detail and relationships.
    # Legacy inventory paths kept as comments for rollback reference:
    #   ("inventory", f"/api/v1/inventory/assets/{enc_uid}", {"tenant_id": ..., "scan_run_id": ...})
    #   ("inventory", f"/api/v1/inventory/assets/{enc_uid}/relationships", {"tenant_id": ..., ...})
    results = await fetch_many([
        ("di",         f"/api/v1/di/assets/{enc_uid}",
         {"scan_run_id": scan_run_id} if scan_run_id and scan_run_id != "latest" else {}),
        ("check",      f"/api/v1/check/findings/resource/{enc_uid}",
         {"tenant_id": tenant_id}),
        ("attack_path", f"/api/v1/threat/findings/resource/{enc_uid}",
         {"tenant_id": tenant_id}),
        ("compliance", f"/api/v1/compliance/findings/resource/{enc_uid}",
         {"tenant_id": tenant_id, "scan_run_id": scan_run_id}),
        ("di",         "/api/v1/di/relationships",
         {"source_uid": enc_uid, **({"scan_run_id": scan_run_id} if scan_run_id and scan_run_id != "latest" else {})}),
        ("di",         f"/api/v1/di/assets/{enc_uid}/posture", {}),
    ], auth_headers=fwd_headers)

    inventory_data, check_data, threat_data, compliance_data, rels_data, posture_data = results

    # Safely unwrap — failed calls return None
    inventory_data = inventory_data if isinstance(inventory_data, dict) else {}
    check_data = check_data if isinstance(check_data, dict) else {}
    threat_data = threat_data if isinstance(threat_data, dict) else {}
    compliance_data = compliance_data if isinstance(compliance_data, dict) else {}
    rels_data = rels_data if isinstance(rels_data, dict) else {}

    # ── Normalize relationships for the frontend table ─────────────
    raw_rels = rels_data.get("relationships", [])
    relationships = []
    for r in raw_rels:
        # Support both from_uid/to_uid and source/target field names
        from_uid = r.get("from_uid") or r.get("source") or ""
        to_uid = r.get("to_uid") or r.get("target") or ""
        rel_type = r.get("relation_type") or r.get("relationship_type") or "related_to"
        if from_uid == resource_uid:
            related = to_uid
            rtype = r.get("to_resource_type") or _type_from_arn(to_uid)
            direction = "outbound"
        else:
            related = from_uid
            rtype = r.get("from_resource_type") or _type_from_arn(from_uid)
            direction = "inbound"
        if related:
            relationships.append({
                "relationship_type": rel_type,
                "related_resource": related,
                "related_type": rtype,
                "direction": direction,
            })

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
        "relationships": relationships,
        "posture": posture_data if isinstance(posture_data, dict) else {},
    }


# ── Blast Radius View ─────────────────────────────────────────────────────



_jny03_audit_logger = logging.getLogger("api-gateway.audit")


def _jny03_emit_cdr_audit(
    *,
    endpoint: str,
    user_id: str,
    tenant_id: Optional[str],
    target: str,
    target_field: str,
    result: int,
    request: Request,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Emit a SOC2/ISO27001-grade audit log line for CIEM sensitive-data access.

    JSON-serialized for log-aggregation parseability. Includes top-5 identity
    ARNs on 200 to prove what was viewed (CSA CCM LOG-08).
    """
    import json as _json
    top_arns: List[str] = []
    if findings:
        for f in findings[:50]:
            if not isinstance(f, dict):
                continue
            arn = f.get("actor_principal") or f.get("principal") or f.get("identity_arn")
            if arn and arn not in top_arns:
                top_arns.append(arn)
            if len(top_arns) >= 5:
                break
    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "user_id": user_id,
        "tenant_id": tenant_id,
        "endpoint": endpoint,
        target_field: target,
        "result": result,
        "request_id": (
            request.headers.get("X-Request-Id")
            or request.headers.get("X-Correlation-Id")
            or getattr(request.state, "request_id", None)
        ),
        "top_5_identity_arns": top_arns,
    }
    _jny03_audit_logger.info(_json.dumps(payload))


async def view_asset_cdr(request: Request, resource_uid: str) -> Dict[str, Any]:
    """BFF view: CIEM identity data for a specific asset.

    Security pattern (sequential — NOT parallel):
      1. Verify asset_id belongs to the caller's tenant via inventory engine.
      2. Only after ownership confirmed, call CIEM engine with resource_uid.

    Permission gate: cdr:sensitive — analyst+ only. Viewer returns 403.
    tenant_id sourced exclusively from AuthContext (never from query param).
    """
    _audit_endpoint = f"/api/v1/views/inventory/asset/{resource_uid}/cdr"
    ctx = _parse_auth_context(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    _audit_user = getattr(ctx, "user_id", "unknown")
    _audit_tenant = resolve_tenant_id(request)

    if "cdr:sensitive" not in ctx.permissions:
        _jny03_emit_cdr_audit(
            endpoint=_audit_endpoint, user_id=_audit_user, tenant_id=_audit_tenant,
            target=resource_uid, target_field="asset_id", result=403, request=request,
        )
        raise HTTPException(
            status_code=403,
            detail="You need Analyst access to view identity entitlements",
        )

    tenant_id = _audit_tenant
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    from urllib.parse import quote as _quote
    enc_uid = _quote(resource_uid, safe="")

    # Step 1 — sequential: verify asset belongs to this tenant.
    # DI engine is the primary source; tenant scoping is enforced via AuthContext.
    inv_resp = await fetch_many(
        [("di", f"/api/v1/di/assets/{enc_uid}", {})],
        auth_headers=fwd_headers,
    )
    inv_asset = inv_resp[0] if inv_resp else None
    if not isinstance(inv_asset, dict) or not inv_asset.get("resource_uid"):
        _jny03_emit_cdr_audit(
            endpoint=_audit_endpoint, user_id=_audit_user, tenant_id=_audit_tenant,
            target=resource_uid, target_field="asset_id", result=403, request=request,
        )
        raise HTTPException(status_code=403, detail="Asset not found or access denied")
    if tenant_id and inv_asset.get("tenant_id") not in (tenant_id, None):
        _jny03_emit_cdr_audit(
            endpoint=_audit_endpoint, user_id=_audit_user, tenant_id=_audit_tenant,
            target=resource_uid, target_field="asset_id", result=403, request=request,
        )
        raise HTTPException(status_code=403, detail="Asset not found or access denied")

    confirmed_uid = inv_asset.get("resource_uid") or resource_uid

    # Step 2 — ONLY after ownership confirmed: call CIEM engine
    cdr_results = await fetch_many(
        [("cdr", "/api/v1/cdr/findings", {"resource_uid": confirmed_uid, "tenant_id": tenant_id, "limit": "500"})],
        auth_headers=fwd_headers,
    )
    cdr_raw = cdr_results[0] if cdr_results else None

    findings: List[Dict[str, Any]] = []
    if isinstance(cdr_raw, dict):
        findings = cdr_raw.get("findings") or cdr_raw.get("data") or []
    elif isinstance(cdr_raw, list):
        findings = cdr_raw

    # Aggregate by actor_principal
    by_principal: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "action_categories": set(),
        "last_event_time": None,
        "finding_count": 0,
        "service": None,
        "identity_type": "unknown",
    })

    for f in findings:
        if not isinstance(f, dict):
            continue
        principal = f.get("actor_principal") or f.get("principal") or ""
        if not principal:
            continue
        rec = by_principal[principal]
        sev = (f.get("severity") or "").lower()
        if sev in rec["severities"]:
            rec["severities"][sev] += 1
        cat = f.get("action_category") or f.get("category") or ""
        if cat:
            rec["action_categories"].add(cat.lower())
        evt = f.get("event_time") or f.get("last_event_time")
        if evt and (rec["last_event_time"] is None or evt > rec["last_event_time"]):
            rec["last_event_time"] = evt
        rec["finding_count"] += 1
        if not rec["service"] and f.get("service"):
            rec["service"] = f.get("service")
        if not rec.get("identity_type") or rec["identity_type"] == "unknown":
            rec["identity_type"] = f.get("identity_type") or f.get("actor_type") or "unknown"

    def _privilege_level(cats: set) -> str:
        if "admin" in cats or "write" in cats:
            return "admin"
        if "read" in cats and len(cats) > 1:
            return "power"
        return "readonly"

    def _risk_score(sevs: dict) -> int:
        return min(100, sevs["critical"] * 25 + sevs["high"] * 10 + sevs["medium"] * 2)

    def _last_used_days(evt_time: Optional[str]) -> Optional[int]:
        if not evt_time:
            return None
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(evt_time.replace("Z", "+00:00"))
            delta = datetime.now(timezone.utc) - dt
            return delta.days
        except Exception:
            return None

    identities = []
    for arn, rec in by_principal.items():
        priv = _privilege_level(rec["action_categories"])
        score = _risk_score(rec["severities"])
        identities.append({
            "identity_arn": arn,
            "identity_type": rec["identity_type"],
            "privilege_level": priv,
            "last_used_days": _last_used_days(rec["last_event_time"]),
            "risk_score": score,
            "finding_count": rec["finding_count"],
            "over_privileged": priv == "admin" or score >= 75,
        })

    identities.sort(key=lambda x: x["risk_score"], reverse=True)
    truncated = len(identities) > 100
    over_privileged_count = sum(1 for i in identities if i["over_privileged"])

    _jny03_emit_cdr_audit(
        endpoint=_audit_endpoint, user_id=_audit_user, tenant_id=_audit_tenant,
        target=resource_uid, target_field="asset_id", result=200, request=request,
        findings=identities[:5],
    )

    return {
        "identities": identities[:100],
        "totalIdentities": len(identities),
        "overPrivilegedCount": over_privileged_count,
        "truncated": truncated,
    }


async def view_asset_posture(request: Request, resource_uid: str) -> Dict[str, Any]:
    """Maps RSP columns into the dimension-keyed format expected by PostureTabs component.

    Returns: { network, iam, encryption, data, database, api_security } — each a flat
    dict of posture signals for that security dimension.
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    from urllib.parse import quote as _quote
    enc_uid = _quote(resource_uid, safe="")

    results = await fetch_many([
        ("di", f"/api/v1/di/assets/{enc_uid}/posture", {}),
    ], auth_headers=fwd_headers)
    rsp = results[0]
    if not isinstance(rsp, dict) or "detail" in rsp:
        raise HTTPException(status_code=404, detail="Posture data not found for asset")

    iam_d = rsp.get("iam_detail") or {}
    net_d = rsp.get("network_detail") or {}

    return {
        "network": {
            "is_internet_exposed":  rsp.get("is_internet_exposed"),
            "entry_point_type":     net_d.get("entry_point_type"),
            "waf_protected":        rsp.get("has_waf"),
            "is_onprem_reachable":  net_d.get("is_onprem_reachable"),
            "is_in_private_subnet": rsp.get("is_in_private_subnet"),
            "exposure_score":       rsp.get("network_exposure_score"),
        },
        "iam": {
            "attached_role_arn":       iam_d.get("role_arn"),
            "is_admin_role":           rsp.get("is_admin_role"),
            "has_wildcard_policy":     rsp.get("role_has_wildcard_policy"),
            "mfa_required":            rsp.get("mfa_enforced"),
            "has_permission_boundary": rsp.get("has_permission_boundary"),
            "cross_account":           rsp.get("role_allows_cross_account"),
            "iam_reachable_count":     rsp.get("blast_radius_count"),
        },
        "encryption": {
            "volume_encrypted":  rsp.get("is_encrypted_at_rest"),
            "in_transit_tls":    rsp.get("is_encrypted_in_transit"),
            "encryption_type":   "KMS-Managed" if rsp.get("has_kms_managed_key") else None,
            "cert_days_to_expiry": rsp.get("cert_days_remaining") if rsp.get("has_valid_certificate") else None,
            "tls_version":       rsp.get("tls_version"),
        },
        "data": {
            "data_classification": rsp.get("data_classification"),
            "can_access_pii":      rsp.get("can_access_pii"),
            "can_write_data":      None,
            "exfil_path_exists":   rsp.get("has_exfil_path"),
            "pii_store_count":     rsp.get("reachable_pii_store_count"),
        },
        "database": {
            "connected_db_uids": rsp.get("connected_db_uids"),
            "db_auth_type":      rsp.get("db_auth_type"),
            "db_same_vpc":       None,
        },
        "api_security": {
            "api_security_score":            rsp.get("api_security_score"),
            "api_auth_type":                 rsp.get("api_auth_type"),
            "api_has_waf":                   rsp.get("api_has_waf"),
            "api_has_rate_limit":            rsp.get("api_has_rate_limit"),
            "api_publicly_accessible":       rsp.get("api_publicly_accessible"),
            "api_deprecated_version_active": rsp.get("api_deprecated_version_active"),
            "api_detail":                    rsp.get("api_detail"),
        },
    }


async def view_asset_findings(request: Request, resource_uid: str) -> Dict[str, Any]:
    """Unified security findings for a single asset, formatted for FindingsPanel."""
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    from urllib.parse import quote as _quote
    enc_uid = _quote(resource_uid, safe="")

    results = await fetch_many([
        ("di", f"/api/v1/di/assets/{enc_uid}/findings", {"page_size": "50", "status": "open"}),
    ], auth_headers=fwd_headers)
    raw = results[0]
    if not isinstance(raw, dict):
        return {"findings": [], "total": 0, "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}}

    findings = raw.get("data", [])
    total = raw.get("total", len(findings))
    by_sev: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = (f.get("severity") or "").lower()
        if s in by_sev:
            by_sev[s] += 1

    return {"findings": findings, "total": total, "by_severity": by_sev}


@router.get("/inventory/asset/{resource_uid:path}/blast-radius")
async def view_blast_radius(
    request: Request,
    resource_uid: str,
    max_depth: int = Query(3, ge=1, le=5),
):
    """Blast-radius from Neo4j (threat engine graph).

    Calls GET /api/v1/graph/blast-radius/{resource_uid} on the threat engine
    which queries the Neo4j Aura graph for reachable resources via attack edges.
    Normalises the Neo4j response into the UI-expected format:
      nodes[], edges[], origin, total_impacted, impact_summary, toxic_combos
    """
    tenant_id = resolve_tenant_id(request)
    from urllib.parse import quote
    import httpx as _httpx
    import json as _json

    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    # Safely resolve max_depth to a plain int — when called from sub-route dispatch
    # (not via FastAPI dependency injection) the default value is the raw Query()
    # descriptor object rather than an int, which causes Pydantic serialization errors.
    depth = max_depth if isinstance(max_depth, int) else 3

    _EMPTY = {
        "nodes": [], "edges": [],
        "origin": resource_uid, "center": resource_uid,
        "total_impacted": 0, "total_nodes": 0, "total_edges": 0,
        "impact_summary": {}, "toxic_combos": [], "toxic_count": 0,
        "max_depth": depth,
    }

    # ── Call Neo4j blast radius via attack-path engine ─────────────────────────
    threat_base = ENGINE_URLS.get("attack_path", "")
    safe_uid = quote(resource_uid, safe="/:@!$&'()*+,;=")
    neo4j_url = f"{threat_base}/api/v1/graph/blast-radius/{safe_uid}"
    neo4j_params = {"tenant_id": tenant_id, "max_hops": str(depth)}
    _blast_headers: Dict[str, str] = {}
    if fwd_headers:
        _blast_headers.update(fwd_headers)
    try:
        async with _httpx.AsyncClient() as _client:
            _resp = await _client.get(
                neo4j_url, params=neo4j_params,
                headers=_blast_headers,
                timeout=ENGINE_TIMEOUTS.get("attack_path", DEFAULT_TIMEOUT)
            )
            if _resp.status_code != 200:
                logger.warning("Neo4j blast radius %s -> %s", neo4j_url, _resp.status_code)
                return _EMPTY
            raw = _resp.json()
    except Exception as _e:
        logger.warning("Neo4j blast radius call failed for %s: %s", resource_uid, _e)
        return _EMPTY

    # Ensure plain Python dicts (guard against any serialization issues)
    try:
        raw = _json.loads(_json.dumps(raw, default=str))
    except Exception:
        pass

    # ── Normalise Neo4j response → UI format ───────────────────────────────
    # Neo4j response shape:
    #   { source_resource, reachable_count, reachable_resources[], depth_distribution, resources_with_threats }
    reachable: List[Dict[str, Any]] = raw.get("reachable_resources", [])
    if not isinstance(reachable, list):
        reachable = []

    depth_dist: Dict = raw.get("depth_distribution", {})
    reachable_count: int = raw.get("reachable_count", len(reachable))

    if not reachable:
        return _EMPTY

    # Build nodes list (UI expects: id, resource_uid, name, type, hop, category, posture)
    nodes: List[Dict[str, Any]] = []
    impact_summary: Dict[str, int] = {}

    for r in reachable:
        uid = r.get("uid", "")
        rtype = r.get("resource_type", "")
        # Derive category from resource_type prefix (e.g. "ec2.instance" → "compute")
        svc = rtype.split(".")[0].lower() if rtype else ""
        category = _SERVICE_TO_CATEGORY.get(svc, "other")
        hop = r.get("hops", 1)
        finding_count = r.get("finding_count", 0)
        threats = r.get("threats", [])

        critical_high = int(r.get("critical_high_findings") or 0)
        node: Dict[str, Any] = {
            "id": uid,
            "resource_uid": uid,
            "name": r.get("name") or uid.rsplit("/", 1)[-1].rsplit(":", 1)[-1],
            "type": rtype,
            "resource_type": rtype,
            "hop": hop,
            "category": category,
            "risk_score": r.get("risk_score") or 0,
            "posture": {
                "check": {"findings": finding_count, "critical_high": critical_high},
                "threat": {"detections": len(threats)},
                "total_critical": len(threats),
                "total_high": critical_high,
            },
        }
        nodes.append(node)
        impact_summary[category] = impact_summary.get(category, 0) + 1

    # Build minimal edges (origin → each hop-1 node; deeper edges are implied)
    edges: List[Dict[str, Any]] = []
    for node in nodes:
        edges.append({
            "source": resource_uid if node["hop"] == 1 else "",
            "target": node["resource_uid"],
            "relation_type": "reachable",
            "hop": node["hop"],
        })

    # ── Toxic combination detection (two-signal model) ────────────────────
    # A reachable node is only toxic when BOTH sides of the chain carry active
    # risk — origin AND target must each have their own signal.  Being merely
    # reachable (e.g. every Lambda has an IAM role) is NOT a toxic combo.
    #
    # Origin signal  : origin has active threat detections OR critical/high findings
    # Target signal  : target has active threat detections OR critical/high findings
    # Toxic          : origin_has_risk AND target_has_risk
    #
    # This prevents the IAM-role noise problem: a properly-configured IAM role
    # with no findings or threats will never be flagged as toxic regardless of
    # how many resources can reach it.
    origin_threats: List = raw.get("origin_threats") or []
    origin_critical_high: int = int(raw.get("origin_critical_high_findings") or 0)
    origin_has_risk = bool(origin_threats) or origin_critical_high > 0

    toxic_combos: List[Dict[str, Any]] = []
    for r in reachable:
        target_threatened  = bool(r.get("threats"))
        target_critical    = int(r.get("critical_high_findings") or 0) > 0
        target_has_risk    = target_threatened or target_critical

        if not (origin_has_risk and target_has_risk):
            continue

        conditions: List[str] = []
        if target_threatened:
            conditions.append(f"{len(r['threats'])} active threat(s)")
        if target_critical:
            conditions.append(f"{r['critical_high_findings']} critical/high finding(s)")

        toxic_combos.append({
            "resource_uid": r.get("uid", ""),
            "resource_type": r.get("resource_type", ""),
            "conditions": conditions,
            "severity": "critical" if target_threatened else "high",
            "total_critical": len(r.get("threats") or []),
            "total_high": int(r.get("critical_high_findings") or 0),
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "origin": resource_uid,
        "center": resource_uid,
        "total_impacted": reachable_count,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "impact_summary": impact_summary,
        "toxic_combos": toxic_combos,
        "toxic_count": len(toxic_combos),
        "resources_with_threats": raw.get("resources_with_threats", 0),
        "depth_distribution": depth_dist,
        "max_depth": depth,
        # Origin risk signals — exposed for UI debug / future use
        "origin_has_risk": origin_has_risk,
        "origin_threat_count": len(origin_threats),
        "origin_critical_high_findings": origin_critical_high,
    }


# Service prefix → UI category mapping for blast radius nodes
_SERVICE_TO_CATEGORY: Dict[str, str] = {
    "ec2": "compute", "lambda": "compute", "ecs": "compute", "eks": "compute",
    "fargate": "compute", "lightsail": "compute", "batch": "compute",
    "s3": "storage", "efs": "storage", "ebs": "storage", "glacier": "storage",
    "rds": "database", "dynamodb": "database", "elasticache": "database",
    "redshift": "database", "docdb": "database", "neptune": "database",
    "opensearch": "database", "elasticsearch": "database",
    "iam": "identity", "cognito": "identity", "sso": "identity",
    "kms": "encryption", "secretsmanager": "encryption", "acm": "encryption",
    "vpc": "network", "elb": "network", "elbv2": "network", "elasticloadbalancingv2": "network",
    "cloudfront": "network", "apigateway": "network", "wafv2": "network",
    "sns": "messaging", "sqs": "messaging", "kinesis": "messaging",
    "cloudtrail": "observability", "guardduty": "observability", "inspector2": "observability",
    "sagemaker": "ml", "bedrock": "ml",
}


# ── Architecture Graph View (posture-enriched) ───────────────────────────


async def _batch_posture_for_nodes(
    resource_uids: List[str],
    tenant_id: str,
) -> Dict[str, Dict[str, Any]]:
    """Fetch check + threat severity counts for many resources in 2 batch calls.

    Uses the batch-severity endpoints (POST) on check + threat engines
    instead of making 2×N individual GET calls. Falls back gracefully
    if batch endpoints are unavailable.
    """
    import httpx

    if not resource_uids:
        return {}

    payload = {"resource_uids": resource_uids, "tenant_id": tenant_id}
    check_base = ENGINE_URLS.get("check", "")
    attack_path_base = ENGINE_URLS.get("attack_path", "")
    check_timeout = ENGINE_TIMEOUTS.get("check", DEFAULT_TIMEOUT)
    attack_path_timeout = ENGINE_TIMEOUTS.get("attack_path", DEFAULT_TIMEOUT)

    check_map: Dict[str, Dict[str, int]] = {}
    threat_map: Dict[str, Dict[str, int]] = {}

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            client.post(
                f"{check_base}/api/v1/check/findings/batch-severity",
                json=payload,
                timeout=check_timeout,
            ),
            client.post(
                f"{attack_path_base}/api/v1/threat/findings/batch-severity",
                json=payload,
                timeout=attack_path_timeout,
            ),
            return_exceptions=True,
        )

        check_resp, threat_resp = results

        if not isinstance(check_resp, Exception) and check_resp.status_code == 200:
            try:
                check_map = check_resp.json().get("results", {})
            except Exception:
                pass
        else:
            logger.debug("Batch check severity failed: %s", check_resp)

        if not isinstance(threat_resp, Exception) and threat_resp.status_code == 200:
            try:
                threat_map = threat_resp.json().get("results", {})
            except Exception:
                pass
        else:
            logger.debug("Batch threat severity failed: %s", threat_resp)

    # Build unified posture map keyed by resource_uid
    posture: Dict[str, Dict[str, Any]] = {}
    all_uids = set(resource_uids)

    for uid in all_uids:
        short_id = uid.rsplit("/", 1)[-1]
        # Match by full UID first, then short ID
        check = check_map.get(uid) or check_map.get(short_id) or {}
        threat = threat_map.get(uid) or threat_map.get(short_id) or {}
        posture[uid] = {
            "check": {
                "critical": check.get("critical", 0),
                "high": check.get("high", 0),
                "medium": check.get("medium", 0),
                "low": check.get("low", 0),
            },
            "threat": {
                "critical": threat.get("critical", 0),
                "high": threat.get("high", 0),
                "medium": threat.get("medium", 0),
                "low": threat.get("low", 0),
            },
        }

    return posture


@router.get("/inventory/taxonomy")
async def view_inventory_taxonomy(
    request: Request,
    csp: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    min_priority: int = Query(5, ge=1, le=5),
):
    """Taxonomy classifications from resource_inventory_identifier.

    Passthrough to inventory engine's /api/v1/inventory/taxonomy endpoint.
    Used by the UI to know how to group/color/nest resources in architecture diagrams.
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    params: Dict[str, str] = {"min_priority": str(min_priority)}
    if csp:
        params["csp"] = csp
    if category:
        params["category"] = category

    results = await fetch_many([
        ("di", "/api/v1/di/taxonomy", params),
    ], auth_headers=fwd_headers)

    data = results[0]
    if not isinstance(data, dict):
        return {"total": 0, "classifications": [], "categories_summary": {}}
    return data



@router.get("/inventory/graph")
async def view_inventory_graph(
    request: Request,
    depth: int = Query(5, ge=1, le=10),
    limit: int = Query(2000, ge=1, le=5000),
    provider: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
):
    """Architecture graph view — inventory graph + cross-engine posture enrichment.

    Step 1: Get graph from inventory engine (recursive BFS traversal + exposure).
    Step 2: Batch-fetch check + threat severity counts for all nodes (2 calls total).
    Step 3: Merge posture data into each node.
    Step 4: Return enriched response ready for the architecture diagram UI.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    # Step 1: Get graph from inventory engine
    params: Dict[str, str] = {
        "tenant_id": tenant_id,
        "depth": str(depth),
        "limit": str(limit),
    }
    if provider:
        params["provider"] = provider
    if service:
        params["service"] = service

    graph_results = await fetch_many([
        ("di", "/api/v1/di/graph", params),
    ], auth_headers=fwd_headers)

    graph_data = graph_results[0]
    if not isinstance(graph_data, dict) or "nodes" not in graph_data:
        return {
            "nodes": [],
            "links": [],
            "exposure": [],
            "meta": {"total_nodes": 0, "total_links": 0, "enriched": False},
        }

    nodes = graph_data.get("nodes", [])
    links = graph_data.get("links", [])
    exposure = graph_data.get("exposure", [])

    if not nodes:
        return {
            "nodes": nodes,
            "links": links,
            "exposure": exposure,
            "meta": {"total_nodes": 0, "total_links": 0, "enriched": False},
        }

    # Step 2: Collect resource UIDs (skip synthetic nodes)
    resource_uids = [
        n["id"] for n in nodes
        if n.get("id") and not n.get("synthetic")
    ]

    # Step 3: Batch posture enrichment (2 calls instead of 2×N)
    posture_map = await _batch_posture_for_nodes(resource_uids, tenant_id)

    # Step 4: Enrich each node with posture data
    for node in nodes:
        uid = node.get("id", "")
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
        "links": links,
        "exposure": exposure,
        "meta": {
            "total_nodes": len(nodes),
            "total_links": len(links),
            "enriched": True,
        },
    }


# ── DI-05: CIEM identity risk summary for a specific inventory asset ─────────


def _infer_principal_type(arn: str) -> str:
    if not arn:
        return "unknown"
    a = arn.lower()
    if ":role/" in a:
        return "role"
    if ":user/" in a:
        return "user"
    if ":assumed-role/" in a:
        return "assumed-role"
    if ".amazonaws.com" in a:
        return "service"
    return "unknown"


def _aggregate_by_principal(findings: list) -> list:
    groups: Dict[str, list] = defaultdict(list)
    for f in findings:
        principal = f.get("actor_principal") or "unknown"
        groups[principal].append(f)

    identities = []
    for principal, items in groups.items():
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in items:
            sev = (item.get("severity") or "low").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        categories = {(item.get("action_category") or "").lower() for item in items}
        if "admin" in categories:
            privilege_level = "admin"
        elif "write" in categories or "data_access" in categories:
            privilege_level = "power"
        else:
            privilege_level = "readonly"

        risk_score = min(
            100,
            sev_counts["critical"] * 25 + sev_counts["high"] * 10 + sev_counts["medium"] * 2
        )

        event_times = []
        for item in items:
            et = item.get("event_time")
            if et:
                try:
                    dt = datetime.datetime.fromisoformat(et.replace("Z", "+00:00"))
                    event_times.append(dt)
                except ValueError:
                    pass
        now = datetime.datetime.now(datetime.timezone.utc)
        last_used_days = None
        if event_times:
            most_recent = max(event_times)
            last_used_days = (now - most_recent).days

        principal_type = items[0].get("principal_type") or _infer_principal_type(principal)

        identities.append({
            "identity_arn": principal,
            "identity_type": principal_type,
            "privilege_level": privilege_level,
            "last_used_days": last_used_days,
            "risk_score": risk_score,
            "finding_count": len(items),
        })

    identities.sort(key=lambda x: x["risk_score"], reverse=True)
    return identities


_di05_audit_logger = logging.getLogger("api-gateway.audit")


# ── Asset panel (slide-in Layer 2) ────────────────────────────────────────────

@router.get("/inventory/asset/{resource_uid:path}/panel")
async def view_asset_panel(
    resource_uid: str,
    request: Request,
    findings_status: str = Query("open"),
    findings_page: int = Query(1, ge=1),
    findings_page_size: int = Query(50, ge=1, le=200),
):
    """Slide-in panel data for a single asset — 5 parallel sub-calls.

    Returns: asset detail, posture signals, paginated open findings,
             check severity summary, and compliance score snapshot.
    Called by: AssetPanel.jsx (Layer 2 slide-in drawer).
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else {}

    di_base = ENGINE_URLS["di"]
    check_base = ENGINE_URLS["check"]
    compliance_base = ENGINE_URLS["compliance"]

    from urllib.parse import quote as _qp
    enc_uid = _qp(resource_uid, safe="")

    findings_params = {
        "status": findings_status,
        "page": str(findings_page),
        "page_size": str(findings_page_size),
    }

    # Fetch asset detail, posture, ALL findings (larger page for Alerts tab extraction),
    # and compliance snapshot in parallel. The check engine call is omitted — its
    # resource_uid format (type:region:discovery_id) never matches DI ARN UIDs, so we
    # derive check_summary and check_findings directly from security_findings.
    all_findings_params = {
        "status": findings_status,
        "page": "1",
        "page_size": "200",  # pull more so Alerts tab has full check findings list
    }

    results = await fetch_many(
        [
            ("di",         f"/api/v1/di/assets/{enc_uid}",          {}),
            ("di",         f"/api/v1/di/assets/{enc_uid}/posture",   {}),
            ("di",         f"/api/v1/di/assets/{enc_uid}/findings",  all_findings_params),
            ("compliance", f"/api/v1/compliance/findings/resource/{enc_uid}", {"tenant_id": tenant_id}),
        ],
        auth_headers=fwd_headers,
    )

    asset_raw, posture_raw, findings_raw, compliance_raw = results

    # asset — 404 if not found
    if not isinstance(asset_raw, dict) or not asset_raw.get("resource_uid"):
        raise HTTPException(status_code=404, detail="Asset not found")

    # posture — None-safe (may not exist yet)
    posture = posture_raw if isinstance(posture_raw, dict) else {}

    # findings from security_findings table (DI engine)
    findings_data = findings_raw if isinstance(findings_raw, dict) else {}
    all_findings = findings_data.get("data", [])
    findings_total = findings_data.get("total", 0)

    # Paginate for the Findings tab (non-check findings)
    page_start = (findings_page - 1) * findings_page_size
    findings = all_findings[page_start: page_start + findings_page_size]

    # Derive check findings and severity summary from security_findings
    # (source_engine='check' = misconfiguration findings from check engine)
    check_findings = [f for f in all_findings if (f.get("source_engine") or "") == "check"]
    _sev_count: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in check_findings:
        sev = (f.get("severity") or "low").lower()
        if sev in _sev_count:
            _sev_count[sev] += 1
    check_summary = {**_sev_count, "total": sum(_sev_count.values())}

    # compliance snapshot (best-effort)
    compliance_score = None
    if isinstance(compliance_raw, dict):
        compliance_score = (
            compliance_raw.get("overall_score")
            or compliance_raw.get("score")
            or compliance_raw.get("compliance_score")
        )

    return {
        "asset": asset_raw,
        "posture": posture,
        "findings": {
            "data": findings,
            "total": findings_total,
            "page": findings_page,
            "page_size": findings_page_size,
        },
        "check_summary": check_summary,
        "check_findings": check_findings,
        "compliance_score": compliance_score,
    }
