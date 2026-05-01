"""
Archive a single table + scan_run_id to S3 as gzipped JSONL.

S3 key layout:
  {prefix}/{engine}/{table}/scan_run_id={scan_run_id}/data.jsonl.gz

Idempotent: if the S3 object already exists it is skipped.
"""

import gzip
import io
import json
import logging
import os
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from .policy import DEFAULT_S3_BUCKET, DEFAULT_S3_PREFIX

logger = logging.getLogger(__name__)


def _s3_key(engine: str, table: str, scan_run_id: str, prefix: str) -> str:
    return f"{prefix}/{engine}/{table}/scan_run_id={scan_run_id}/data.jsonl.gz"


def _already_archived(s3_client, bucket: str, key: str) -> bool:
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise


def archive_scan(
    conn,
    engine: str,
    table: str,
    scan_run_id: str,
    s3_bucket: Optional[str] = None,
    s3_prefix: Optional[str] = None,
) -> dict:
    """Export all rows for scan_run_id → S3 gzipped JSONL.

    Returns:
        {"s3_key": str, "row_count": int, "skipped": bool}

    Never raises — caller decides what to do with the result.
    """
    bucket = s3_bucket or os.getenv("ARCHIVE_S3_BUCKET", DEFAULT_S3_BUCKET)
    prefix = s3_prefix or os.getenv("ARCHIVE_S3_PREFIX", DEFAULT_S3_PREFIX)
    key = _s3_key(engine, table, scan_run_id, prefix)

    s3 = boto3.client("s3")

    if _already_archived(s3, bucket, key):
        logger.info("[retention] already archived: s3://%s/%s", bucket, key)
        return {"s3_key": key, "row_count": 0, "skipped": True}

    with conn.cursor() as cur:
        cur.execute(f"SELECT * FROM {table} WHERE scan_run_id = %s", (scan_run_id,))
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()

    if not rows:
        logger.info("[retention] no rows to archive: %s.%s scan=%s", engine, table, scan_run_id[:8])
        return {"s3_key": None, "row_count": 0, "skipped": False}

    # Serialize to gzipped JSONL
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        for row in rows:
            record = {}
            for col, val in zip(cols, row):
                if hasattr(val, "isoformat"):
                    val = val.isoformat()
                record[col] = val
            gz.write((json.dumps(record, default=str) + "\n").encode())

    buf.seek(0)
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=buf.getvalue(),
        ContentType="application/x-ndjson",
        ContentEncoding="gzip",
        Metadata={
            "engine": engine,
            "table": table,
            "scan_run_id": scan_run_id,
            "row_count": str(len(rows)),
        },
    )

    logger.info(
        "[retention] archived %d rows from %s.%s → s3://%s/%s",
        len(rows), engine, table, bucket, key,
    )
    return {"s3_key": key, "row_count": len(rows), "skipped": False}


def delete_s3_scan(
    engine: str,
    table: str,
    scan_run_id: str,
    s3_bucket: Optional[str] = None,
    s3_prefix: Optional[str] = None,
) -> int:
    """Delete S3 objects for a scan_run_id. Returns number of objects deleted."""
    bucket = s3_bucket or os.getenv("ARCHIVE_S3_BUCKET", DEFAULT_S3_BUCKET)
    prefix = s3_prefix or os.getenv("ARCHIVE_S3_PREFIX", DEFAULT_S3_PREFIX)
    obj_prefix = f"{prefix}/{engine}/{table}/scan_run_id={scan_run_id}/"

    s3 = boto3.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=obj_prefix)
    objects = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
    if not objects:
        return 0

    s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    logger.info("[retention] deleted %d S3 objects: %s", len(objects), obj_prefix)
    return len(objects)
