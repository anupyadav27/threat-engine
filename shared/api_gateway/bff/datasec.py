"""BFF view: /datasec page.

Uses the datasec engine's /ui-data endpoint which returns all data security
data pre-organized: catalog, classifications, dlp_violations, encryption_status,
residency, activity, lineage, and a summary with KPI-ready metrics.

Previous approach made 7 calls (catalog, classification, lineage, residency,
activity, findings, inventory/assets). Now uses 1 call: datasec/ui-data.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get, mock_fallback, is_empty_or_health
from ._transforms import (
    normalize_datastore, normalize_classification, normalize_dlp_violation,
    normalize_residency, normalize_access_activity, apply_global_filters,
)
from ._page_context import datasec_page_context, datasec_filter_schema

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

    # Mock fallback when engine data is empty
    if is_empty_or_health(datasec_data):
        m = mock_fallback("datasec")
        if m is not None:
            return m

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
    if isinstance(encryption, list):
        for enc_item in encryption:
            if isinstance(enc_item, dict) and "rotation" not in enc_item:
                # Derive rotation from resource config if available
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

    # Data security posture score from summary or derived from findings
    posture_score = safe_get(summary, "data_risk_score", 0) or safe_get(summary, "posture_score", 0)
    if not posture_score and raw_findings:
        sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(sev_weights.get((f.get("severity") or "medium").lower(), 2) for f in raw_findings)
        posture_score = min(100, round((total_weight / (len(raw_findings) * 4)) * 100))

    page_ctx = datasec_page_context({})
    page_ctx["brief"] = f"{total_stores} data stores monitored — {sensitive} contain sensitive data"
    page_ctx["tabs"] = [
        {"id": "catalog", "label": "Data Catalog", "count": len(filtered_catalog)},
        {"id": "classifications", "label": "Classifications", "count": len(classifications)},
        {"id": "findings", "label": "Findings", "count": len(raw_findings)},
        {"id": "encryption", "label": "Encryption", "count": len(encryption) if isinstance(encryption, list) else 0},
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
    }
