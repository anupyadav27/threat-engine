import logging
from typing import Any, Dict, List

import psycopg2.extras

logger = logging.getLogger("api_security.db_writer")

_BATCH_SIZE = 200

_INSERT_SQL = """
    INSERT INTO api_security_findings (
        scan_run_id, tenant_id, account_id, provider, region,
        resource_uid, resource_type, severity, status,
        rule_id, finding_source,
        owasp_api_category, owasp_api_label,
        api_gateway_id, api_name, api_stage, api_version, api_protocol,
        auth_type, has_waf, has_rate_limit,
        is_publicly_accessible, is_deprecated_version,
        backend_url, backend_is_internal_ip,
        cdr_actor_hash, cdr_event_count, cdr_first_event_at, cdr_last_event_at,
        mitre_technique_id, mitre_tactic,
        title, description, remediation, evidence,
        first_seen_at, last_seen_at
    ) VALUES (
        %(scan_run_id)s, %(tenant_id)s, %(account_id)s, %(provider)s, %(region)s,
        %(resource_uid)s, %(resource_type)s, %(severity)s, 'open',
        %(rule_id)s, %(finding_source)s,
        %(owasp_api_category)s, %(owasp_api_label)s,
        %(api_gateway_id)s, %(api_name)s, %(api_stage)s, %(api_version)s, %(api_protocol)s,
        %(auth_type)s, %(has_waf)s, %(has_rate_limit)s,
        %(is_publicly_accessible)s, %(is_deprecated_version)s,
        %(backend_url)s, %(backend_is_internal_ip)s,
        %(cdr_actor_hash)s, %(cdr_event_count)s, %(cdr_first_event_at)s, %(cdr_last_event_at)s,
        %(mitre_technique_id)s, %(mitre_tactic)s,
        %(title)s, %(description)s, %(remediation)s, %(evidence)s,
        NOW(), NOW()
    )
    ON CONFLICT (rule_id, resource_uid, scan_run_id, tenant_id)
    DO UPDATE SET
        severity               = EXCLUDED.severity,
        status                 = 'open',
        last_seen_at           = NOW(),
        owasp_api_category     = EXCLUDED.owasp_api_category,
        has_waf                = EXCLUDED.has_waf,
        has_rate_limit         = EXCLUDED.has_rate_limit,
        is_publicly_accessible = EXCLUDED.is_publicly_accessible,
        auth_type              = EXCLUDED.auth_type,
        evidence               = EXCLUDED.evidence
"""


class APISecWriter:
    def __init__(self, apisec_conn):
        self._conn = apisec_conn

    def write(self, findings: List[Dict[str, Any]], scan_run_id: str, tenant_id: str) -> int:
        if not findings:
            return 0

        rows = [self._normalize(f, scan_run_id, tenant_id) for f in findings]
        written = 0

        with self._conn.cursor() as cur:
            for i in range(0, len(rows), _BATCH_SIZE):
                batch = rows[i: i + _BATCH_SIZE]
                psycopg2.extras.execute_batch(cur, _INSERT_SQL, batch, page_size=_BATCH_SIZE)
                written += len(batch)

        self._conn.commit()
        logger.info(f"APISecWriter: committed {written} findings")
        return written

    @staticmethod
    def _normalize(f: Dict[str, Any], scan_run_id: str, tenant_id: str) -> Dict[str, Any]:
        evidence = f.get("evidence") or {}
        if isinstance(evidence, str):
            try:
                import json as _json
                evidence = _json.loads(evidence)
            except Exception:
                evidence = {"raw": evidence}

        return {
            "scan_run_id":            scan_run_id,
            "tenant_id":              tenant_id,
            "account_id":             f.get("account_id", ""),
            "provider":               f.get("provider", "aws"),
            "region":                 f.get("region", ""),
            "resource_uid":           f.get("resource_uid", ""),
            "resource_type":          f.get("resource_type", ""),
            "severity":               f.get("severity", "low"),
            "rule_id":                f.get("rule_id", ""),
            "finding_source":         f.get("finding_source", "config"),
            "owasp_api_category":     f.get("owasp_api_category", ""),
            "owasp_api_label":        f.get("owasp_api_label", ""),
            "api_gateway_id":         f.get("api_gateway_id", ""),
            "api_name":               f.get("api_name", ""),
            "api_stage":              f.get("api_stage", ""),
            "api_version":            f.get("api_version", ""),
            "api_protocol":           f.get("api_protocol", "REST"),
            "auth_type":              f.get("auth_type", "none"),
            "has_waf":                bool(f.get("has_waf", False)),
            "has_rate_limit":         bool(f.get("has_rate_limit", False)),
            "is_publicly_accessible": bool(f.get("is_publicly_accessible", False)),
            "is_deprecated_version":  bool(f.get("is_deprecated_version", False)),
            "backend_url":            f.get("backend_url", ""),
            "backend_is_internal_ip": bool(f.get("backend_is_internal_ip", False)),
            "cdr_actor_hash":         f.get("cdr_actor_hash"),
            "cdr_event_count":        int(f.get("cdr_event_count", 0)),
            "cdr_first_event_at":     f.get("cdr_first_event_at"),
            "cdr_last_event_at":      f.get("cdr_last_event_at"),
            "mitre_technique_id":     f.get("mitre_technique_id"),
            "mitre_tactic":           f.get("mitre_tactic"),
            "title":                  f.get("title", ""),
            "description":            f.get("description", ""),
            "remediation":            f.get("remediation", ""),
            "evidence":               psycopg2.extras.Json(evidence),
        }
