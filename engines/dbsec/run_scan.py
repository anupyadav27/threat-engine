"""
DBSec Engine — K8s Job entry point.

Runs as a K8s Job on spot nodes. Invoked by the API pod via:
    python run_scan.py --scan-run-id <id>

Pipeline:
  1. Resolve orchestration metadata from scan_runs table
  2. Load DB resources from discovery_findings
  3. Run 5-pillar analysis via CSP provider
  4. Write findings to dbsec_findings
"""

import argparse
import logging
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(__file__))

from engine_common.logger import setup_logger

logger = setup_logger(__name__, engine_name="dbsec-scanner")


def _get_scan_metadata(scan_run_id: str) -> dict:
    """Resolve scan metadata from scan_runs in onboarding DB."""
    try:
        from engine_common.db_connections import get_onboarding_conn
        conn = get_onboarding_conn()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT tenant_id, account_id, provider, credential_ref, credential_type
                   FROM scan_runs WHERE scan_run_id = %s""",
                (scan_run_id,),
            )
            row = cur.fetchone()
        conn.close()
        if row:
            return {
                "tenant_id": row[0] or "default-tenant",
                "account_id": row[1] or "",
                "provider": (row[2] or "aws").lower(),
                "credential_ref": row[3] or "",
                "credential_type": row[4] or "",
            }
    except Exception as exc:
        logger.warning("Could not resolve scan metadata from scan_runs: %s", exc)

    # Fallback: use environment variables
    return {
        "tenant_id": os.getenv("TENANT_ID", "default-tenant"),
        "account_id": os.getenv("ACCOUNT_ID", ""),
        "provider": os.getenv("PROVIDER", "aws").lower(),
        "credential_ref": os.getenv("CREDENTIAL_REF", ""),
        "credential_type": os.getenv("CREDENTIAL_TYPE", ""),
    }


def _emit_dbsec_findings(scan_run_id: str, tenant_id: str) -> None:
    """Read dbsec_findings and upsert rows into security_findings (inventory DB).

    Args:
        scan_run_id: Pipeline run identifier for the completed scan.
        tenant_id: Tenant scope — ensures multi-tenant isolation.
    """
    from engine_common.security_findings_writer import upsert_findings
    from engine_common.db_connections import get_dbsec_conn, get_inventory_conn

    with get_dbsec_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    finding_id::text AS source_finding_id,
                    tenant_id,
                    account_id,
                    provider,
                    region,
                    resource_uid,
                    resource_type,
                    rule_id,
                    severity,
                    status,
                    title,
                    description,
                    remediation,
                    first_seen_at,
                    last_seen_at
                FROM dbsec_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                  AND LOWER(severity) IN ('critical', 'high', 'medium', 'low', 'info')
                """,
                (scan_run_id, tenant_id),
            )
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()

    if not rows:
        return

    _sev_map = {"info": "low"}

    findings = []
    for row in rows:
        d = dict(zip(cols, row))
        sev = (d.get("severity") or "medium").lower()
        findings.append({
            "source_finding_id": d["source_finding_id"],
            "resource_uid":      d.get("resource_uid", ""),
            "finding_type":      "database_security",
            "severity":          _sev_map.get(sev, sev),
            "title":             d.get("title", ""),
            "account_id":        d.get("account_id", ""),
            "provider":          d.get("provider", ""),
            "resource_type":     d.get("resource_type", ""),
            "rule_id":           d.get("rule_id", ""),
            "description":       d.get("description"),
            "detail":            {"posture_category": "database_security", "remediation": d.get("remediation")},
            "status":            (d.get("status") or "open").lower(),
            "first_seen_at":     d.get("first_seen_at"),
        })

    with get_inventory_conn() as iconn:
        written = upsert_findings(
            conn=iconn,
            findings=findings,
            source_engine="dbsec",
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
        )
    logger.info("security_findings: wrote %d DBSec rows", written)


def main() -> None:
    """Run DBSec 5-pillar scan for a given scan_run_id."""
    parser = argparse.ArgumentParser(description="DBSec Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()
    scan_run_id = args.scan_run_id

    logger.info("DBSec scanner starting scan_run_id=%s", scan_run_id)

    def _handle_sigterm(*_):
        logger.warning("SIGTERM received — aborting DBSec scan %s", scan_run_id)
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        metadata = _get_scan_metadata(scan_run_id)
        tenant_id = metadata["tenant_id"]
        account_id = metadata["account_id"]
        provider = metadata["provider"]
        credential_ref = metadata["credential_ref"]
        credential_type = metadata["credential_type"]

        logger.info(
            "DBSec scan: tenant=%s account=%s provider=%s",
            tenant_id, account_id, provider,
        )

        from engine_common.db_connections import get_dbsec_conn, get_discoveries_conn, get_check_conn
        from dbsec_engine.providers import get_provider
        from dbsec_engine.storage.dbsec_db_writer import save_findings_to_db

        discoveries_conn = get_discoveries_conn()
        check_conn = get_check_conn()
        dbsec_conn = get_dbsec_conn()

        try:
            provider_impl = get_provider(provider)
            findings = provider_impl.analyze(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                discoveries_conn=discoveries_conn,
                check_conn=check_conn,
            )

            if findings:
                for f in findings:
                    f["credential_ref"] = credential_ref
                    f["credential_type"] = credential_type
                written = save_findings_to_db(findings, dbsec_conn)
                logger.info(
                    "DBSec scan completed: scan_run_id=%s provider=%s "
                    "findings=%d written=%d",
                    scan_run_id, provider, len(findings), written,
                )
            else:
                logger.info(
                    "DBSec scan completed: scan_run_id=%s provider=%s 0 findings "
                    "(no DB resources in discovery_findings for this scan_run_id)",
                    scan_run_id, provider,
                )
        finally:
            discoveries_conn.close()
            check_conn.close()
            dbsec_conn.close()

        # Write DBSec posture signals to resource_security_posture (inventory DB)
        try:
            from engine_common.db_connections import get_inventory_conn as _get_inv_conn

            _rsp_by_uid: dict = {}
            for _f in (findings or []):
                _uid = _f.get("resource_uid", "")
                if not _uid:
                    continue
                if _uid not in _rsp_by_uid:
                    _rsp_by_uid[_uid] = {
                        "resource_type": _f.get("resource_type", ""),
                        "account_id": _f.get("account_id", account_id),
                        "region": _f.get("region", ""),
                        "db_auth_type": None,
                    }
                # auth info lives in pillar_detail (finding_data mirrors it in current writer)
                if _f.get("pillar") == "authentication" and not _rsp_by_uid[_uid]["db_auth_type"]:
                    _pd = _f.get("pillar_detail") or _f.get("finding_data") or {}
                    _check = _pd.get("check", "") if isinstance(_pd, dict) else ""
                    if _pd.get("iam_auth_enabled") or "iam_controlled" in _check:
                        _rsp_by_uid[_uid]["db_auth_type"] = "IAM"
                    elif _pd.get("auth_token_enabled"):
                        _rsp_by_uid[_uid]["db_auth_type"] = "token"
                    elif not _pd.get("iam_auth_enabled") and "iam_auth_enabled" in _check:
                        _rsp_by_uid[_uid]["db_auth_type"] = "password"
                    elif "master_username" in _check or "password" in _check:
                        _rsp_by_uid[_uid]["db_auth_type"] = "password"
                    elif _check:
                        _rsp_by_uid[_uid]["db_auth_type"] = _check

            if _rsp_by_uid:
                _inv_conn = _get_inv_conn()
                try:
                    with _inv_conn.cursor() as _cur:
                        _cur.execute(
                            "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                            (tenant_id, tenant_id),
                        )
                        _rows = [
                            (
                                tenant_id, scan_run_id, _m["account_id"],
                                provider, _m["region"], _uid,
                                _m["resource_type"], _m["db_auth_type"],
                            )
                            for _uid, _m in _rsp_by_uid.items()
                        ]
                        _cur.executemany(
                            """INSERT INTO resource_security_posture
                               (tenant_id, scan_run_id, account_id, provider, region,
                                resource_uid, resource_type, db_auth_type)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                               ON CONFLICT (resource_uid, tenant_id) DO UPDATE SET
                                   scan_run_id  = EXCLUDED.scan_run_id,
                                   db_auth_type = EXCLUDED.db_auth_type,
                                   updated_at   = NOW()""",
                            _rows,
                        )
                        _inv_conn.commit()
                    logger.info("Posture: wrote %d DBSec rows to resource_security_posture", len(_rows))
                finally:
                    _inv_conn.close()
        except Exception as _posture_err:
            logger.warning("DBSec posture write failed (non-fatal): %s", _posture_err)

        # Write DBSec findings to shared security_findings table (non-fatal)
        try:
            _emit_dbsec_findings(scan_run_id, tenant_id)
        except Exception as _sf_err:
            logger.warning("DBSec security_findings write skipped: %s", _sf_err)

        # Retention: keep last N scans in DB
        try:
            from engine_common.retention import run_retention
            run_retention("dbsec", scan_run_id)
        except Exception as ret_err:
            logger.warning("Retention cleanup skipped: %s", ret_err)

    except Exception as exc:
        logger.error("DBSec scan FAILED: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
