"""Shared utility for upserting rows into security_findings table.

Called once per scan after engine completes writing to its own findings table.
Uses batch executemany in 500-row chunks to avoid DB overload on large tenants.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TypedDict

logger = logging.getLogger(__name__)

_ALLOWED_ENGINES = frozenset({
    'check', 'iam', 'network', 'datasec', 'vuln', 'cdr', 'container', 'api_security',
    'dbsec', 'encryption', 'ai_security', 'secops',
})

_INSERT_SQL = """
INSERT INTO security_findings (
    source_engine, source_finding_id, resource_uid, scan_run_id, tenant_id,
    account_id, provider, resource_type, finding_type, severity, rule_id,
    title, description, epss_score, cvss_score, in_kev,
    mitre_technique_id, mitre_tactic, detail, status, first_seen_at
) VALUES (
    %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s
)
ON CONFLICT (source_engine, source_finding_id, tenant_id) DO UPDATE SET
    last_seen_at  = NOW(),
    scan_run_id   = EXCLUDED.scan_run_id,
    severity      = EXCLUDED.severity,
    status        = EXCLUDED.status,
    detail        = EXCLUDED.detail,
    updated_at    = NOW()
"""


class FindingRow(TypedDict, total=False):
    """TypedDict for a single finding row to upsert into security_findings.

    Required fields: source_finding_id, resource_uid, finding_type, severity, title.
    All other fields are optional.
    """

    source_finding_id: str      # required
    resource_uid: str           # required
    finding_type: str           # required: misconfig|cve|iam_violation|cdr_event|data_risk|network_exposure
    severity: str               # required: critical|high|medium|low
    title: str                  # required
    account_id: Optional[str]
    provider: Optional[str]
    resource_type: Optional[str]
    rule_id: Optional[str]
    description: Optional[str]
    epss_score: Optional[float]
    cvss_score: Optional[float]
    in_kev: bool
    mitre_technique_id: Optional[str]
    mitre_tactic: Optional[str]
    detail: Optional[Dict[str, Any]]
    status: str
    first_seen_at: Optional[Any]


def upsert_findings(
    conn: Any,
    findings: List[FindingRow],
    source_engine: str,
    tenant_id: str,
    scan_run_id: str,
    batch_size: int = 500,
) -> int:
    """Upsert a list of findings into security_findings table.

    Args:
        conn: psycopg2 connection (caller responsible for lifecycle).
        findings: list of FindingRow dicts.
        source_engine: must be in {'check','iam','network','datasec','vuln','cdr'}.
        tenant_id: tenant scope — injected by caller from scan auth context.
        scan_run_id: pipeline run ID.
        batch_size: rows per executemany batch (default 500).

    Returns:
        Total count of rows upserted.

    Raises:
        ValueError: if source_engine not in allowed set, or tenant_id is None.
    """
    if source_engine not in _ALLOWED_ENGINES:
        raise ValueError(
            f"upsert_findings: unknown source_engine '{source_engine}'. "
            f"Allowed: {sorted(_ALLOWED_ENGINES)}"
        )
    if not tenant_id:
        raise ValueError("upsert_findings: tenant_id must not be None/empty")
    if not findings:
        return 0

    total = 0
    cur = conn.cursor()

    now = datetime.now(timezone.utc)

    for i in range(0, len(findings), batch_size):
        chunk = findings[i : i + batch_size]
        rows = []
        for f in chunk:
            detail_val = f.get("detail")
            if detail_val is not None and isinstance(detail_val, (dict, list)):
                detail_val = json.dumps(detail_val)

            rows.append((
                source_engine,
                f["source_finding_id"],
                f["resource_uid"],
                scan_run_id,
                tenant_id,
                f.get("account_id"),
                f.get("provider"),
                f.get("resource_type"),
                f["finding_type"],
                f["severity"],
                f.get("rule_id"),
                f.get("title"),
                f.get("description"),
                f.get("epss_score"),
                f.get("cvss_score"),
                bool(f.get("in_kev", False)),
                f.get("mitre_technique_id"),
                f.get("mitre_tactic"),
                detail_val,
                f.get("status", "open"),
                f.get("first_seen_at") or now,
            ))

        cur.executemany(_INSERT_SQL, rows)
        conn.commit()
        total += len(chunk)

    logger.info("upsert_findings: engine=%s tenant=%s upserted=%d", source_engine, tenant_id, total)
    return total
