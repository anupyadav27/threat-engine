"""
Migration: di_009_copy_posture_and_findings

Copy security_findings and resource_security_posture from threat_engine_inventory
into threat_engine_di using ON CONFLICT DO UPDATE so re-runs are idempotent.

Run AFTER di_008_posture_and_findings.sql has been applied.

Usage (from any pod with both INVENTORY_DB_* and DI_DB_* env vars):
    python3 di_009_copy_posture_and_findings.py
"""

import os
import logging
import psycopg2
import psycopg2.extras

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("di_009")

BATCH_SIZE = 500


def _inv_conn():
    return psycopg2.connect(
        host=os.environ["INVENTORY_DB_HOST"],
        port=int(os.getenv("INVENTORY_DB_PORT", "5432")),
        dbname=os.environ["INVENTORY_DB_NAME"],
        user=os.environ["INVENTORY_DB_USER"],
        password=os.environ["INVENTORY_DB_PASSWORD"],
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def _di_conn():
    return psycopg2.connect(
        host=os.environ["DI_DB_HOST"],
        port=int(os.getenv("DI_DB_PORT", "5432")),
        dbname=os.environ["DI_DB_NAME"],
        user=os.environ["DI_DB_USER"],
        password=os.environ["DI_DB_PASSWORD"],
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def _copy_security_findings(src, dst):
    logger.info("Copying security_findings …")
    with src.cursor(cursor_factory=psycopg2.extras.RealDictCursor, name="sf_cursor") as cur:
        cur.execute("""
            SELECT source_engine, source_finding_id, resource_uid, scan_run_id,
                   tenant_id, account_id, provider, resource_type, finding_type,
                   severity, rule_id, title, description, epss_score, cvss_score,
                   in_kev, mitre_technique_id, mitre_tactic, detail, status,
                   first_seen_at, last_seen_at
            FROM security_findings
        """)

        total = 0
        while True:
            rows = cur.fetchmany(BATCH_SIZE)
            if not rows:
                break
            with dst.cursor() as wcur:
                psycopg2.extras.execute_values(
                    wcur,
                    """
                    INSERT INTO security_findings (
                        source_engine, source_finding_id, resource_uid, scan_run_id,
                        tenant_id, account_id, provider, resource_type, finding_type,
                        severity, rule_id, title, description, epss_score, cvss_score,
                        in_kev, mitre_technique_id, mitre_tactic, detail, status,
                        first_seen_at, last_seen_at
                    ) VALUES %s
                    ON CONFLICT (source_engine, source_finding_id, tenant_id)
                    DO UPDATE SET
                        last_seen_at  = EXCLUDED.last_seen_at,
                        scan_run_id   = EXCLUDED.scan_run_id,
                        severity      = EXCLUDED.severity,
                        status        = EXCLUDED.status,
                        detail        = EXCLUDED.detail,
                        updated_at    = NOW()
                    """,
                    [
                        (
                            r["source_engine"], r["source_finding_id"], r["resource_uid"],
                            r["scan_run_id"], r["tenant_id"], r["account_id"], r["provider"],
                            r["resource_type"], r["finding_type"], r["severity"], r["rule_id"],
                            r["title"], r["description"], r["epss_score"], r["cvss_score"],
                            r["in_kev"], r["mitre_technique_id"], r["mitre_tactic"],
                            psycopg2.extras.Json(r["detail"]) if isinstance(r["detail"], dict) else r["detail"],
                            r["status"], r["first_seen_at"], r["last_seen_at"],
                        )
                        for r in rows
                    ],
                )
            dst.commit()
            total += len(rows)
            logger.info("  security_findings: %d copied", total)

    logger.info("security_findings copy complete: %d rows", total)
    return total


def _copy_resource_security_posture(src, dst):
    logger.info("Copying resource_security_posture …")
    # Fetch column names first via a separate cursor (named cursors don't
    # populate cur.description until the first fetchmany, which is too late).
    with src.cursor() as meta_cur:
        meta_cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'resource_security_posture'
              AND table_schema = 'public'
            ORDER BY ordinal_position
        """)
        cols = [row[0] for row in meta_cur.fetchall()]

    with src.cursor(cursor_factory=psycopg2.extras.RealDictCursor, name="rsp_cursor") as cur:
        cur.execute("""
            SELECT * FROM resource_security_posture
        """)
        # Remove DB-managed columns we don't copy
        skip = {"posture_id", "created_at", "updated_at"}
        copy_cols = [c for c in cols if c not in skip]

        total = 0
        while True:
            rows = cur.fetchmany(BATCH_SIZE)
            if not rows:
                break

            values = []
            for r in rows:
                row_vals = []
                for c in copy_cols:
                    v = r.get(c)
                    if c in ("network_detail", "iam_detail", "connected_db_uids", "cdr_ttps", "api_detail") and isinstance(v, dict):
                        v = psycopg2.extras.Json(v)
                    row_vals.append(v)
                values.append(row_vals)

            col_list = ", ".join(copy_cols)
            with dst.cursor() as wcur:
                psycopg2.extras.execute_values(
                    wcur,
                    f"""
                    INSERT INTO resource_security_posture ({col_list})
                    VALUES %s
                    ON CONFLICT (resource_uid, tenant_id)
                    DO UPDATE SET
                        scan_run_id           = EXCLUDED.scan_run_id,
                        overall_posture_score = EXCLUDED.overall_posture_score,
                        is_internet_exposed   = EXCLUDED.is_internet_exposed,
                        is_crown_jewel        = EXCLUDED.is_crown_jewel,
                        is_on_attack_path     = EXCLUDED.is_on_attack_path,
                        updated_at            = NOW()
                    """,
                    values,
                )
            dst.commit()
            total += len(rows)
            logger.info("  resource_security_posture: %d copied", total)

    logger.info("resource_security_posture copy complete: %d rows", total)
    return total


def main():
    src = _inv_conn()
    dst = _di_conn()
    try:
        sf_count = _copy_security_findings(src, dst)
        rsp_count = _copy_resource_security_posture(src, dst)
        logger.info("MIGRATION COMPLETE: di_009 — security_findings=%d, resource_security_posture=%d", sf_count, rsp_count)
    finally:
        src.close()
        dst.close()


if __name__ == "__main__":
    main()
