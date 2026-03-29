"""BFF view: /encryption page.

Uses the encryption engine's /ui-data endpoint which returns all encryption
data pre-organized: keys, certificates, encrypted resources, findings, and
a summary with KPI-ready metrics.

Single call to engine-encryption/api/v1/encryption/ui-data.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get, mock_fallback, is_empty_or_health
from ._transforms import apply_global_filters
from ._page_context import encryption_page_context, encryption_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/encryption")
async def view_encryption(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the encryption security page needs."""

    results = await fetch_many([
        ("encryption", "/api/v1/encryption/ui-data", {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
        }),
    ])

    enc_data = results[0]
    if not isinstance(enc_data, dict):
        enc_data = {}

    # Mock fallback when engine data is empty
    if is_empty_or_health(enc_data):
        m = mock_fallback("encryption")
        if m is not None:
            return m

    summary = safe_get(enc_data, "summary", {})

    # ── Resources ────────────────────────────────────────────────────────────
    raw_resources = safe_get(enc_data, "resources", [])
    filtered_resources = apply_global_filters(raw_resources, provider, account, region)

    # ── Keys ─────────────────────────────────────────────────────────────────
    keys = safe_get(enc_data, "keys", [])

    # ── Certificates ─────────────────────────────────────────────────────────
    certificates = safe_get(enc_data, "certificates", [])

    # ── Findings ─────────────────────────────────────────────────────────────
    raw_findings = safe_get(enc_data, "findings", [])
    filtered_findings = apply_global_filters(raw_findings, provider, account, region)

    # ── KPI derivation ───────────────────────────────────────────────────────
    total_resources = safe_get(summary, "total_resources", None)
    if total_resources is None:
        total_resources = len(filtered_resources)

    encrypted_resources = safe_get(summary, "encrypted_resources", None)
    if encrypted_resources is None:
        encrypted_resources = sum(
            1 for r in filtered_resources
            if r.get("encryption_status") in ("encrypted", "Encrypted", True)
            or r.get("encrypted") is True
        )

    encrypted_pct = safe_get(summary, "encrypted_pct", None)
    if encrypted_pct is None:
        encrypted_pct = round(
            (encrypted_resources / total_resources * 100), 1
        ) if total_resources else 0

    keys_count = safe_get(summary, "keys_count", len(keys))
    certs_count = safe_get(summary, "certificates_count", len(certificates))

    expiring_certs = safe_get(summary, "expiring_certificates_30d", None)
    if expiring_certs is None:
        expiring_certs = sum(
            1 for c in certificates if c.get("expiring_within_30d")
        )

    # Posture score from summary or derived from findings
    posture_score = safe_get(summary, "posture_score", 0)
    if not posture_score and filtered_findings:
        sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(
            sev_weights.get((f.get("severity") or "medium").lower(), 2)
            for f in filtered_findings
        )
        max_weight = len(filtered_findings) * 4
        posture_score = max(0, 100 - round((total_weight / max_weight) * 100)) if max_weight else 100

    # Findings by severity
    by_severity = safe_get(summary, "by_severity", {})
    if not by_severity and filtered_findings:
        by_severity = {}
        for f in filtered_findings:
            sev = (f.get("severity") or "medium").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

    # ── Page context ─────────────────────────────────────────────────────────
    page_ctx = encryption_page_context(summary)
    page_ctx["brief"] = (
        f"{total_resources} resources monitored — "
        f"{encrypted_pct}% encrypted, {expiring_certs} certificates expiring"
    )
    # ── Secrets ─────────────────────────────────────────────────────────────
    secrets = safe_get(enc_data, "secrets", [])
    if not secrets:
        secrets = safe_get(enc_data, "secrets_inventory", [])

    page_ctx["tabs"] = [
        {"id": "resources", "label": "Resources", "count": len(filtered_resources)},
        {"id": "keys", "label": "Keys", "count": len(keys)},
        {"id": "certificates", "label": "Certificates", "count": len(certificates)},
        {"id": "secrets", "label": "Secrets", "count": len(secrets)},
        {"id": "findings", "label": "Findings", "count": len(filtered_findings)},
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": encryption_filter_schema(),
        "kpiGroups": [
            {
                "title": "Encryption Posture",
                "items": [
                    {"label": "Posture Score", "value": posture_score, "suffix": "/100"},
                    {"label": "Encrypted", "value": encrypted_pct, "suffix": "%"},
                    {"label": "Total Resources", "value": total_resources},
                    {"label": "Encrypted Resources", "value": encrypted_resources},
                ],
            },
            {
                "title": "Key & Certificate Management",
                "items": [
                    {"label": "Keys", "value": keys_count},
                    {"label": "Certificates", "value": certs_count},
                    {"label": "Expiring Certs (30d)", "value": expiring_certs},
                ],
            },
            {
                "title": "Findings by Severity",
                "items": [
                    {"label": "Critical", "value": by_severity.get("critical", 0)},
                    {"label": "High", "value": by_severity.get("high", 0)},
                    {"label": "Medium", "value": by_severity.get("medium", 0)},
                    {"label": "Low", "value": by_severity.get("low", 0)},
                ],
            },
        ],
        "data": {
            "resources": filtered_resources,
            "keys": keys,
            "certificates": certificates,
            "secrets": secrets,
            "findings": filtered_findings,
        },
        # Flat aliases so UI can read data.findings, data.keys, etc.
        "overview": filtered_resources,
        "findings": filtered_findings,
        "keys": keys,
        "certificates": certificates,
        "secrets": secrets,
        # Flat kpis array for UI KPI card rendering
        "kpis": [
            {"key": "posture_score", "label": "Posture Score", "value": posture_score, "suffix": "/100"},
            {"key": "pct_encrypted", "label": "Encrypted", "value": encrypted_pct, "suffix": "%"},
            {"key": "total_resources", "label": "Total Resources", "value": total_resources},
            {"key": "encrypted_resources", "label": "Encrypted Resources", "value": encrypted_resources},
            {"key": "total_keys", "label": "Keys", "value": keys_count},
            {"key": "total_certs", "label": "Certificates", "value": certs_count},
            {"key": "expiring_certs", "label": "Expiring Certs (30d)", "value": expiring_certs},
            {"key": "critical", "label": "Critical", "value": by_severity.get("critical", 0)},
            {"key": "high", "label": "High", "value": by_severity.get("high", 0)},
            {"key": "medium", "label": "Medium", "value": by_severity.get("medium", 0)},
            {"key": "low", "label": "Low", "value": by_severity.get("low", 0)},
        ],
    }
