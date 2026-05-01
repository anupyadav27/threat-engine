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
