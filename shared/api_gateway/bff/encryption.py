"""BFF view: /encryption page.

Uses the encryption engine's /ui-data endpoint which returns all encryption
data pre-organized: keys, certificates, encrypted resources, findings, and
a summary with KPI-ready metrics.

Single call to engine-encryption/api/v1/encryption/ui-data.
"""

from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, fetch_all_check_findings, safe_get, is_empty_or_health, BFFMeta
from .schemas.encryption import EncryptionResponse
from ._transforms import apply_global_filters
from ._page_context import encryption_page_context, encryption_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/encryption", response_model=EncryptionResponse, response_model_exclude_none=False)
async def view_encryption(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    tenant_ids: Optional[str] = Query(None),
    account_ids: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the encryption security page needs."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("encryption")

    results = await fetch_many([
        ("encryption", "/api/v1/encryption/ui-data", {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
        }),
    ], auth_headers=fwd_headers)

    enc_data = results[0]
    meta.record_engine("encryption", "/api/v1/encryption/ui-data", enc_data)
    if not isinstance(enc_data, dict):
        enc_data = {}

    # Fallback: check engine (data_protection_and_privacy domain) when engine has no data
    _has_enc_data = (
        safe_get(enc_data, "findings", []) or
        safe_get(enc_data, "keys", []) or
        safe_get(enc_data, "resources", []) or
        safe_get(enc_data, "certificates", [])
    )
    if is_empty_or_health(enc_data) or not _has_enc_data:
        check_raw = await fetch_all_check_findings({
            "tenant_id": tenant_id,
            "domain": "data_protection_and_privacy",
        }, auth_headers=fwd_headers)
        if check_raw:
            meta.set_fallback("encryption engine returned no data; using check engine data_protection_and_privacy domain")
            # Filter to encryption-specific findings by rule_id keywords
            _enc_keywords = ("encrypt", "kms", "tls", "ssl", "cert", "key", "secret", "vault")
            enc_findings = [
                f for f in check_raw
                if any(kw in (f.get("rule_id") or "").lower() for kw in _enc_keywords)
            ] or check_raw  # fall back to all data_protection findings if none match
            enc_data = {
                "findings": enc_findings,
                "resources": enc_findings,
                "summary": {},
            }
        else:
            meta.warn("Both encryption engine and check engine fallback returned no data")

    summary = safe_get(enc_data, "summary", {})

    # ── Resources ────────────────────────────────────────────────────────────
    raw_resources = safe_get(enc_data, "resources", [])
    filtered_resources = apply_global_filters(raw_resources, provider, account, region)

    # ── Keys ─────────────────────────────────────────────────────────────────
    keys = safe_get(enc_data, "keys", []) or safe_get(enc_data, "key_inventory", [])

    # ── Certificates ─────────────────────────────────────────────────────────
    certificates = safe_get(enc_data, "certificates", []) or safe_get(enc_data, "cert_inventory", [])

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

    keys_count = safe_get(summary, "keys_count", None) or safe_get(summary, "total_keys", len(keys))
    certs_count = safe_get(summary, "certificates_count", None) or safe_get(summary, "total_certificates", len(certificates))

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
        {"id": "findings",     "label": "Findings",     "count": len(filtered_findings)},
        {"id": "keys",         "label": "Keys",         "count": len(keys)},
        {"id": "certificates", "label": "Certificates", "count": len(certificates)},
        {"id": "secrets",      "label": "Secrets",      "count": len(secrets)},
    ]

    # -- Enrich findings rows with required table columns -----------------------
    color_map = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#3b82f6'}
    enriched_findings = []
    for f in filtered_findings:
        uid = f.get('resource_arn') or f.get('resource_uid') or ''
        sev = (f.get('severity') or 'medium').lower()
        enriched_findings.append({
            **f,
            'resource_name':       f.get('resource_name') or uid.rsplit('/', 1)[-1] or uid,
            'severity':            sev,
            'status':              f.get('status') or f.get('result') or 'FAIL',
            'title':               f.get('title') or f.get('rule_name') or f.get('description') or '',
            'rule_id':             f.get('rule_id', ''),
            'account_id':          f.get('account_id') or f.get('account', ''),
            'region':              f.get('region', ''),
            'provider':            f.get('provider', ''),
            'service':             f.get('service') or f.get('aws_service', ''),
            'encryption_domain':   f.get('encryption_domain') or f.get('domain', ''),
            'encryption_status':   f.get('encryption_status', ''),
            'resource_type':       f.get('resource_type', ''),
            'finding_id':          str(f.get('finding_id') or f.get('id') or ''),
            # Key and certificate table columns
            'key_id':              f.get('key_id') or f.get('key_arn') or uid.rsplit('/', 1)[-1] or uid,
            'algorithm':           f.get('algorithm') or f.get('encryption_algorithm', ''),
            'alias':               f.get('alias') or f.get('key_alias', ''),
            'key_type':            f.get('key_type') or f.get('key_usage', ''),
            'key_algorithm':       f.get('key_algorithm') or f.get('key_spec', ''),
            'domain':              f.get('domain') or f.get('encryption_domain', ''),
            'last_rotated':        f.get('last_rotated') or f.get('last_rotation_date', ''),
            'rotation_enabled':    f.get('rotation_enabled', False),
            'rotation_compliant':  f.get('rotation_compliant', False),
            'transit_enforced':    f.get('transit_enforced', False),
            'expires_at':          f.get('expires_at') or f.get('expiry_date', ''),
            'days_until_expiry':   f.get('days_until_expiry') or f.get('days_to_expiry'),
            'issuer':              f.get('issuer') or f.get('certificate_issuer', ''),
            'priority':            f.get('priority', 'medium'),
            'priority_score':      f.get('priority_score', 0),
            'original':            {'account': f.get('account_id') or f.get('account', ''),
                                    'encryption_domain': f.get('encryption_domain', ''),
                                    'rule_id': f.get('rule_id', ''),
                                    'container_service': f.get('container_service') or f.get('service', ''),
                                    'db_service':        f.get('db_service', ''),
                                    'network_layer':     f.get('network_layer') or f.get('layer', ''),
                                    'security_domain':   f.get('security_domain') or f.get('domain', '')},
            'meta':                {'color': color_map.get(sev, '#6b7280'), 'label': sev.title()},
        })

    # -- Normalize key_inventory rows to match frontend accessorKeys --------------
    enriched_keys = []
    for k in keys:
        alg = k.get('encryption_algorithms')
        if isinstance(alg, list):
            alg = ', '.join(str(a) for a in alg) if alg else ''
        enriched_keys.append({
            **k,
            'alias':            k.get('alias') or k.get('key_alias') or '',
            'key_type':         k.get('key_type') or k.get('key_spec') or k.get('key_usage') or '',
            'algorithm':        k.get('algorithm') or alg or '',
            'status':           k.get('status') or k.get('key_state') or '',
            'rotation_enabled': k.get('rotation_enabled', False),
        })

    # -- Normalize cert_inventory rows to match frontend accessorKeys ------------
    enriched_certs = []
    for c in certificates:
        enriched_certs.append({
            **c,
            'domain':           c.get('domain') or c.get('domain_name') or '',
            'status':           c.get('status') or c.get('cert_status') or '',
            'expires_at':       c.get('expires_at') or c.get('not_after') or '',
            'days_until_expiry': c.get('days_until_expiry'),
            'key_algorithm':    c.get('key_algorithm') or '',
            'issuer':           c.get('issuer') or '',
        })

    # -- Normalize secrets_inventory rows to match frontend accessorKeys ---------
    enriched_secrets = []
    for s in secrets:
        enriched_secrets.append({
            **s,
            'name':             s.get('name') or s.get('secret_name') or '',
            'type':             s.get('type') or s.get('secret_type') or '',
            'rotation_enabled': s.get('rotation_enabled', False),
            'last_rotated':     s.get('last_rotated') or s.get('last_rotated_date') or '',
            'severity':         s.get('severity') or 'medium',
        })

    # -- Scan trend with chart dataKeys -----------------------------------------
    raw_trend = safe_get(enc_data, "scan_trend", [])
    scan_trend = []
    for pt in raw_trend:
        sev_pt = pt.get("by_severity") or {}
        total_pt = pt.get("total_resources") or pt.get("total", 0)
        enc_pt   = pt.get("encrypted_resources") or pt.get("encrypted", 0)
        scan_trend.append({
            "date":            pt.get("scan_date") or pt.get("date", ""),
            "critical":        sev_pt.get("critical", pt.get("critical", 0)),
            "high":            sev_pt.get("high",     pt.get("high",     0)),
            "medium":          sev_pt.get("medium",   pt.get("medium",   0)),
            "low":             sev_pt.get("low",      pt.get("low",      0)),
            "passRate":        pt.get("pass_rate") or pt.get("passRate",
                                   round(enc_pt / total_pt * 100) if total_pt else 0),
            "total":           total_pt,
            "unencrypted":     total_pt - enc_pt,
            "expiring_certs":  pt.get("expiring_certs", 0),
        })

    first_pt = scan_trend[0]  if scan_trend else {}
    last_pt  = scan_trend[-1] if scan_trend else {}
    first_obj = {k: first_pt.get(k, 0) for k in ("date", "critical", "high", "total")}
    last_obj  = {k: last_pt.get(k, 0)  for k in ("date", "critical", "high", "total")}

    # -- Donut slices -----------------------------------------------------------
    donut_slices = [
        {"name": sev.title(), "value": by_severity.get(sev, 0), "color": color_map[sev]}
        for sev in ("critical", "high", "medium", "low")
        if by_severity.get(sev, 0) > 0
    ]

    # -- Active module scores (encryption domains) ------------------------------
    enc_modules = [
        ("at_rest",        "Encryption at Rest"),
        ("in_transit",     "Encryption in Transit"),
        ("key_management", "Key Management"),
        ("certificate",    "Certificate Lifecycle"),
    ]
    module_scores_raw = safe_get(enc_data, "module_scores") or safe_get(summary, "module_scores") or {}
    active_module_scores = [
        {
            "key":   key,
            "label": label,
            "score": module_scores_raw.get(key, 0),
            "pass":  (module_scores_raw.get(key) or 0) >= 70,
        }
        for key, label in enc_modules
    ]

    # -- DB domain breakdown (security domain rows) ----------------------------
    domain_breakdown = safe_get(enc_data, "domain_breakdown", [])
    db_domains = domain_breakdown if isinstance(domain_breakdown, list) else []

    meta.expect_fields(
        enc_data,
        ["findings", "resources", "summary"],
        context="encryption engine ui-data",
    )

    return {
        "pageContext": page_ctx,
        "filterSchema": encryption_filter_schema(),
        "kpiGroups": [
            {
                "title": "Encryption Posture",
                "items": [
                    {"label": "Posture Score",   "value": posture_score, "suffix": "/100"},
                    {"label": "Total Findings",  "value": len(enriched_findings)},
                    {"label": "Total Resources", "value": total_resources},
                    {"label": "Unencrypted",     "value": total_resources - encrypted_resources},
                    {"label": "Expiring Certs",  "value": expiring_certs},
                    {"label": "Weak Keys",       "value": 0},
                    {"label": "Critical",        "value": by_severity.get("critical", 0)},
                    {"label": "High",            "value": by_severity.get("high", 0)},
                    {"label": "Medium",          "value": by_severity.get("medium", 0)},
                    {"label": "Low",             "value": by_severity.get("low", 0)},
                ],
            },
            {
                "title": "Key & Certificate Management",
                "items": [
                    {"label": "Keys",                 "value": keys_count},
                    {"label": "Certificates",         "value": certs_count},
                    {"label": "Expiring Certs (30d)", "value": expiring_certs},
                ],
            },
        ],
        "overview":      filtered_resources,
        "findings":      enriched_findings,
        "keys":          enriched_keys,
        "certificates":  enriched_certs,
        "secrets":       enriched_secrets,
        "sm_entries":    enriched_secrets,
        "kpis": [
            {"key": "posture_score",        "label": "Posture Score",        "value": posture_score,    "suffix": "/100"},
            {"key": "pct_encrypted",        "label": "Encrypted",            "value": encrypted_pct,    "suffix": "%"},
            {"key": "total_resources",      "label": "Total Resources",      "value": total_resources},
            {"key": "encrypted_resources",  "label": "Encrypted Resources",  "value": encrypted_resources},
            {"key": "total_keys",           "label": "Keys",                 "value": keys_count},
            {"key": "total_certs",          "label": "Certificates",         "value": certs_count},
            {"key": "expiring_certs",       "label": "Expiring Certs (30d)", "value": expiring_certs},
            {"key": "critical", "label": "Critical", "value": by_severity.get("critical", 0)},
            {"key": "high",     "label": "High",     "value": by_severity.get("high",     0)},
            {"key": "medium",   "label": "Medium",   "value": by_severity.get("medium",   0)},
            {"key": "low",      "label": "Low",      "value": by_severity.get("low",      0)},
        ],
        "scanTrend":          scan_trend,
        "activeScanTrend":    scan_trend,
        "first":              first_obj,
        "last":               last_obj,
        "donutSlices":        donut_slices,
        "activeModuleScores": active_module_scores,
        "domainBreakdown":    domain_breakdown,
        "db":                 db_domains,
        "_meta":              meta.to_dict(),
    }
