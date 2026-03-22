"""BFF view: /datasec page.

Uses the datasec engine's /ui-data endpoint which returns all data security
data pre-organized: catalog, classifications, dlp_violations, encryption_status,
residency, activity, lineage, and a summary with KPI-ready metrics.

Previous approach made 7 calls (catalog, classification, lineage, residency,
activity, findings, inventory/assets). Now uses 1 call: datasec/ui-data.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import (
    normalize_datastore, normalize_classification, normalize_dlp_violation,
    normalize_residency, normalize_access_activity, apply_global_filters,
)

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/datasec")
async def view_datasec(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    csp: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the data security page needs."""

    effective_csp = csp or (provider.lower() if provider else "aws")

    results = await fetch_many([
        ("datasec", "/api/v1/data-security/ui-data", {
            "tenant_id": tenant_id,
            "csp": effective_csp,
            "scan_id": scan_id,
        }),
    ])

    datasec_data = results[0]
    if not isinstance(datasec_data, dict):
        datasec_data = {}

    summary = safe_get(datasec_data, "summary", {})

    # Normalize catalog
    raw_catalog = safe_get(datasec_data, "catalog", [])
    catalog = [normalize_datastore(s) for s in raw_catalog]

    # Apply scope filters
    filtered_catalog = apply_global_filters(catalog, provider, account, region)

    # Classifications
    raw_class = safe_get(datasec_data, "classifications", [])
    classifications = [normalize_classification(c) for c in raw_class]

    # Residency
    raw_residency = safe_get(datasec_data, "residency", [])
    residency = [normalize_residency(r) for r in raw_residency]

    # Activity
    raw_activity = safe_get(datasec_data, "activity", [])
    if isinstance(raw_activity, dict):
        # Handle dict-keyed activity (by resource_id) — flatten to list
        flat = []
        for events_list in raw_activity.values():
            if isinstance(events_list, list):
                flat.extend(events_list)
        raw_activity = flat
    elif not isinstance(raw_activity, list):
        raw_activity = []
    activity = [normalize_access_activity(a) for a in raw_activity]
    # Access monitoring = same source as activity (no separate endpoint)
    monitoring = activity

    # DLP violations — pre-organized by datasec/ui-data
    raw_dlp = safe_get(datasec_data, "dlp_violations", [])
    dlp = [normalize_dlp_violation(v) for v in raw_dlp]

    # Encryption status — pre-organized by datasec/ui-data
    encryption = safe_get(datasec_data, "encryption_status", [])

    # Lineage
    lineage = safe_get(datasec_data, "lineage", {})

    # Raw findings for the output (derive from all finding-like data if not in response)
    raw_findings = safe_get(datasec_data, "findings", [])

    # KPI derivation — prefer pre-computed summary from ui-data, fall back to catalog-derived
    total_stores = safe_get(summary, "total_stores", None)
    if total_stores is None:
        total_stores = len(filtered_catalog)

    sensitive = sum(1 for d in filtered_catalog if d.get("classification") in ("PII", "PHI", "PCI", "Confidential"))
    unencrypted = sum(1 for d in filtered_catalog if not d.get("encryption") or d.get("encryption") == "None")
    public_access = sum(1 for d in filtered_catalog if d.get("public_access"))
    classified = sum(1 for d in filtered_catalog if d.get("classification"))
    encrypted = len(filtered_catalog) - unencrypted
    sensitive_exposed = safe_get(summary, "sensitive_exposed", None)
    if sensitive_exposed is None:
        sensitive_exposed = sum(1 for d in filtered_catalog if d.get("classification") and d.get("public_access"))

    # Use summary percentages if available, else derive from catalog
    classified_pct = safe_get(summary, "classified_pct", None)
    if classified_pct is None:
        classified_pct = round((classified / len(filtered_catalog) * 100), 1) if filtered_catalog else 0

    encrypted_pct = safe_get(summary, "encrypted_pct", None)
    if encrypted_pct is None:
        encrypted_pct = round((encrypted / len(filtered_catalog) * 100), 1) if filtered_catalog else 0

    # Data risk score from summary or derived from findings
    data_risk_score = safe_get(summary, "data_risk_score", 0)
    if not data_risk_score and raw_findings:
        sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(sev_weights.get((f.get("severity") or "medium").lower(), 2) for f in raw_findings)
        data_risk_score = min(100, round((total_weight / (len(raw_findings) * 4)) * 100))

    return {
        "kpi": {
            "dataStoresMonitored": total_stores,
            "sensitiveDataStores": sensitive,
            "unencryptedStores": unencrypted,
            "publicAccessStores": public_access,
            "dlpViolations": len(dlp),
            "classifiedPct": classified_pct,
            "encryptedPct": encrypted_pct,
            "sensitiveExposed": sensitive_exposed,
            "dataRiskScore": data_risk_score,
        },
        "catalog": filtered_catalog,
        "classifications": classifications,
        "lineage": lineage,
        "residency": residency,
        "activity": activity,
        "findings": raw_findings,
        "dlp": dlp,
        "encryption": encryption,
        "accessMonitoring": monitoring,
    }
