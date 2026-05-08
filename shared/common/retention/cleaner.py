"""
Retention cleaner: orchestrates archive → delete cycle for one engine table.

Flow per table (non-partitioned):
  1. Get all distinct scan_run_ids ordered newest → oldest
  2. DB window  [0 : keep_in_db]          → keep in DB, skip
  3. S3 window  [keep_in_db : keep_in_db+keep_in_s3] → archive to S3 if not already there
  4. Old window [keep_in_db+keep_in_s3 :] → delete from S3 + delete from DB
  5. Delete from DB all scans outside DB window

Flow per table (partitioned, e.g. partition_by="provider"):
  Same logic applied independently per partition value.
  Each provider keeps its own 5 slots — AWS eviction never touches Azure slots.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Optional

from .archiver import archive_scan, delete_s3_scan

logger = logging.getLogger(__name__)


def _ordered_scan_runs(conn, table: str, timestamp_col: str) -> List[str]:
    """Return scan_run_ids ordered newest → oldest by MIN(timestamp_col)."""
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT scan_run_id
            FROM {table}
            WHERE scan_run_id IS NOT NULL
            GROUP BY scan_run_id
            ORDER BY MIN({timestamp_col}) DESC
            """,
        )
        return [r[0] for r in cur.fetchall()]


def _ordered_scan_runs_partitioned(
    conn, table: str, timestamp_col: str, partition_col: str
) -> Dict[str, List[str]]:
    """Return {partition_value → [scan_run_ids newest→oldest]} for per-partition retention.

    Scan IDs with NULL partition value are grouped under the key '__null__'.
    """
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT COALESCE({partition_col}::text, '__null__'), scan_run_id
            FROM {table}
            WHERE scan_run_id IS NOT NULL
            GROUP BY {partition_col}, scan_run_id
            ORDER BY {partition_col}, MIN({timestamp_col}) DESC
            """,
        )
        result: Dict[str, List[str]] = defaultdict(list)
        for partition_val, scan_id in cur.fetchall():
            result[partition_val].append(scan_id)
        return dict(result)


def clean_table(
    conn,
    engine: str,
    table: str,
    timestamp_col: str,
    keep_in_db: int = 5,
    keep_in_s3: int = 5,
    s3_bucket: Optional[str] = None,
    s3_prefix: Optional[str] = None,
    partition_by: Optional[str] = None,
) -> dict:
    """Run archive + delete for one table. Returns summary dict.

    If partition_by is set (e.g. 'provider'), retention limits are applied
    independently per partition value so different CSPs never evict each other.
    """
    if partition_by:
        return _clean_table_partitioned(
            conn, engine, table, timestamp_col,
            keep_in_db, keep_in_s3, s3_bucket, s3_prefix, partition_by,
        )

    # ── Non-partitioned (original behaviour) ──────────────────────────────
    all_scans = _ordered_scan_runs(conn, table, timestamp_col)
    if not all_scans:
        return {"table": table, "total": 0, "archived": 0, "deleted_db": 0}

    db_window         = all_scans[:keep_in_db]
    s3_window         = all_scans[keep_in_db : keep_in_db + keep_in_s3]
    old_scans         = all_scans[keep_in_db + keep_in_s3 :]
    to_delete_from_db = all_scans[keep_in_db:]

    logger.info(
        "[retention] %s.%s — total=%d keep_db=%d archive_s3=%d purge=%d",
        engine, table, len(all_scans), len(db_window), len(s3_window), len(old_scans),
    )

    archived = _archive_and_purge(
        conn, engine, table, s3_window, old_scans, s3_bucket, s3_prefix
    )

    deleted_db = _delete_from_db(conn, table, to_delete_from_db, engine)

    return {
        "table": table,
        "total_scans": len(all_scans),
        "kept_in_db": len(db_window),
        "archived_to_s3": archived,
        "deleted_from_db": deleted_db,
    }


def _clean_table_partitioned(
    conn,
    engine: str,
    table: str,
    timestamp_col: str,
    keep_in_db: int,
    keep_in_s3: int,
    s3_bucket: Optional[str],
    s3_prefix: Optional[str],
    partition_col: str,
) -> dict:
    """Apply retention independently per partition value (e.g. per provider)."""
    partitions = _ordered_scan_runs_partitioned(conn, table, timestamp_col, partition_col)
    if not partitions:
        return {"table": table, "total": 0, "archived": 0, "deleted_db": 0}

    total_scans = sum(len(v) for v in partitions.values())
    all_to_delete: List[str] = []
    all_s3_window: List[str] = []
    all_old_scans: List[str] = []

    for part_val, scans in partitions.items():
        db_window = scans[:keep_in_db]
        s3_window = scans[keep_in_db : keep_in_db + keep_in_s3]
        old_scans = scans[keep_in_db + keep_in_s3 :]
        to_delete = scans[keep_in_db:]

        logger.info(
            "[retention] %s.%s [%s=%s] — total=%d keep_db=%d archive_s3=%d purge=%d",
            engine, table, partition_col, part_val,
            len(scans), len(db_window), len(s3_window), len(old_scans),
        )

        all_s3_window.extend(s3_window)
        all_old_scans.extend(old_scans)
        all_to_delete.extend(to_delete)

    archived = _archive_and_purge(
        conn, engine, table, all_s3_window, all_old_scans, s3_bucket, s3_prefix
    )
    deleted_db = _delete_from_db(conn, table, all_to_delete, engine)

    return {
        "table": table,
        "total_scans": total_scans,
        "partitions": list(partitions.keys()),
        "kept_in_db": total_scans - len(all_to_delete),
        "archived_to_s3": archived,
        "deleted_from_db": deleted_db,
    }


def _archive_and_purge(
    conn, engine: str, table: str,
    s3_window: List[str], old_scans: List[str],
    s3_bucket: Optional[str], s3_prefix: Optional[str],
) -> int:
    """Archive s3_window scans and purge old_scans from S3. Returns archived count."""
    archived = 0
    for scan_id in s3_window:
        try:
            result = archive_scan(conn, engine, table, scan_id, s3_bucket, s3_prefix)
            if not result.get("skipped"):
                archived += 1
        except Exception as e:
            logger.error(
                "[retention] archive failed %s.%s scan=%s: %s",
                engine, table, scan_id[:8], e,
            )
    for scan_id in old_scans:
        try:
            delete_s3_scan(engine, table, scan_id, s3_bucket, s3_prefix)
        except Exception as e:
            logger.warning(
                "[retention] S3 delete failed %s.%s scan=%s: %s",
                engine, table, scan_id[:8], e,
            )
    return archived


def _delete_from_db(conn, table: str, to_delete: List[str], engine: str) -> int:
    """Delete rows from table for the given scan_run_ids. Returns deleted row count."""
    if not to_delete:
        return 0
    with conn.cursor() as cur:
        cur.execute(
            f"DELETE FROM {table} WHERE scan_run_id = ANY(%s)",
            (to_delete,),
        )
        deleted_db = cur.rowcount
    conn.commit()
    logger.info(
        "[retention] deleted %d rows from %s.%s (%d old scans)",
        deleted_db, engine, table, len(to_delete),
    )
    return deleted_db
