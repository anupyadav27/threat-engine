import logging
from typing import Any, Dict, List

import psycopg2.extras

logger = logging.getLogger("api_security.posture_signals")

_UPSERT_SQL = """
    INSERT INTO resource_security_posture (
        resource_uid, scan_run_id, tenant_id,
        api_auth_type,
        api_has_waf,
        api_has_rate_limit,
        api_publicly_accessible,
        api_deprecated_version_active,
        api_security_score,
        api_detail
    ) VALUES (
        %(resource_uid)s, %(scan_run_id)s, %(tenant_id)s,
        %(api_auth_type)s,
        %(api_has_waf)s,
        %(api_has_rate_limit)s,
        %(api_publicly_accessible)s,
        %(api_deprecated_version_active)s,
        %(api_security_score)s,
        %(api_detail)s
    )
    ON CONFLICT (resource_uid, scan_run_id, tenant_id) DO UPDATE SET
        api_auth_type                 = EXCLUDED.api_auth_type,
        api_has_waf                   = EXCLUDED.api_has_waf,
        api_has_rate_limit            = EXCLUDED.api_has_rate_limit,
        api_publicly_accessible       = EXCLUDED.api_publicly_accessible,
        api_deprecated_version_active = EXCLUDED.api_deprecated_version_active,
        api_security_score            = EXCLUDED.api_security_score,
        api_detail                    = EXCLUDED.api_detail
"""

_SEVERITY_SCORE_PENALTY = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 5,
}


def write_api_posture_signals(
    inv_conn,
    findings: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> None:
    """Aggregate findings per resource and upsert posture signals into
    resource_security_posture (threat_engine_inventory DB).
    """
    if not findings:
        return

    by_resource: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        uid = f.get("resource_uid", "")
        if uid:
            by_resource.setdefault(uid, []).append(f)

    rows = [
        _build_row(uid, res_findings, scan_run_id, tenant_id)
        for uid, res_findings in by_resource.items()
    ]

    with inv_conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, _UPSERT_SQL, rows, page_size=200)
    inv_conn.commit()
    logger.info(f"Posture signals: upserted {len(rows)} resource rows")


def _build_row(
    resource_uid: str,
    findings: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> Dict[str, Any]:
    has_waf = any(f.get("has_waf") for f in findings)
    has_rate_limit = any(f.get("has_rate_limit") for f in findings)
    is_public = any(f.get("is_publicly_accessible") for f in findings)
    is_deprecated = any(f.get("is_deprecated_version") for f in findings)

    auth_type = None
    for f in findings:
        if f.get("auth_type") and f["auth_type"] != "none":
            auth_type = f["auth_type"]

    score = 100
    for f in findings:
        sev = f.get("severity", "low")
        score -= _SEVERITY_SCORE_PENALTY.get(sev, 0)
    score = max(0, score)

    rule_ids = list({f.get("rule_id", "") for f in findings if f.get("rule_id")})
    api_names = list({f.get("api_name", "") for f in findings if f.get("api_name")})
    owasp_cats = list({f.get("owasp_api_category", "") for f in findings if f.get("owasp_api_category")})

    api_detail = {
        "finding_count": len(findings),
        "rule_ids": rule_ids[:20],
        "api_names": api_names[:10],
        "owasp_categories_hit": owasp_cats,   # matches PostureTabs APISecurityPanel
    }

    return {
        "resource_uid":                resource_uid,
        "scan_run_id":                 scan_run_id,
        "tenant_id":                   tenant_id,
        "api_auth_type":               auth_type,
        "api_has_waf":                 has_waf,
        "api_has_rate_limit":          has_rate_limit,
        "api_publicly_accessible":     is_public,
        "api_deprecated_version_active": is_deprecated,
        "api_security_score":          score,
        "api_detail":                  psycopg2.extras.Json(api_detail),
    }
