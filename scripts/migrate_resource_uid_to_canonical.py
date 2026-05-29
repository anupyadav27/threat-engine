#!/usr/bin/env python3
"""
RID-01 Backfill Migration — Canonical Resource ID Standardisation
=================================================================
Converts short-form resource_uid values in all engine tables to canonical format.

Short-form (old):   "ec2:ap-south-1:588989875114:sg-008801ad"
Canonical (new):    "arn:aws:ec2:ap-south-1:588989875114:security-group/sg-008801ad"

K8s UUID (old):     "bce7271e-43e7-4b8c-a591-25ad887aa62e"
Canonical (new):    "k8s/vulnerability-eks-cluster/default/secret/db-credentials"

Usage:
    # Dry run — show counts only, no writes
    python3 migrate_resource_uid_to_canonical.py --dry-run

    # Apply to all tables
    python3 migrate_resource_uid_to_canonical.py --apply

    # Apply to one table only
    python3 migrate_resource_uid_to_canonical.py --apply --table discovery_findings

Note: K8s UUID backfill is SKIPPED — UUIDs are opaque with no cluster/namespace/name
      encoded in them. New scans will write canonical UIDs. Old UUID rows are left as-is
      and will be superseded on next discovery run.
"""

import argparse
import logging
import os
import re
import sys

import psycopg2
import psycopg2.extras

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared', 'common'))

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# UUID pattern — K8s legacy UIDs (skip, cannot backfill without cluster context)
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

# Short-form AWS pattern: {service}:{region}:{account}:{resource-id}
_SHORT_AWS_RE = re.compile(r'^[a-z0-9]+:[a-z0-9-]+:\d{12}:.+$')

# GCP legacy selfLink: https://www.googleapis.com/{api}/{version}/{path}
_GCP_SELFLINK_RE = re.compile(r'^https://www\.googleapis\.com/([^/]+)/[^/]+/(.+)$')

# Already canonical — starts with one of these prefixes
_CANONICAL_PREFIXES = ('arn:', 'k8s/', 'azure/', '/subscriptions/', '//', 'ocid1.', 'acs:', 'crn:')

BATCH_SIZE = 500


# ── Table → DB connection env var mapping ────────────────────────────────────

# (db_prefix, uid_col, type_col)
TABLE_DB_MAP = {
    'discovery_findings':        ('DISCOVERIES', 'resource_uid', 'resource_type'),
    'inventory_findings':        ('INVENTORY',   'resource_uid', 'resource_type'),
    'resource_security_posture': ('INVENTORY',   'resource_uid', 'resource_type'),
    'check_findings':            ('CHECK',        'resource_uid', 'resource_type'),
    'attack_path_nodes':         ('ATTACK_PATH',  'node_uid',    'node_type'),
    'security_findings':         ('INVENTORY',   'resource_uid', 'resource_type'),
}


def get_conn(db_prefix: str) -> psycopg2.extensions.connection:
    prefix = db_prefix.upper()
    # Fall back to SHARED_DB_PASSWORD when engine-specific password is not set
    password = os.environ.get(f'{prefix}_DB_PASSWORD') or os.environ.get('SHARED_DB_PASSWORD', '')
    return psycopg2.connect(
        host=os.environ[f'{prefix}_DB_HOST'],
        port=os.environ.get(f'{prefix}_DB_PORT', '5432'),
        dbname=os.environ[f'{prefix}_DB_NAME'],
        user=os.environ[f'{prefix}_DB_USER'],
        password=password,
    )


def is_short_aws(uid: str) -> bool:
    return bool(_SHORT_AWS_RE.match(uid)) and not uid.startswith('arn:')


def is_uuid(uid: str) -> bool:
    return bool(_UUID_RE.match(uid))


def is_canonical(uid: str) -> bool:
    return any(uid.startswith(p) for p in _CANONICAL_PREFIXES)


def is_gcp_selflink(uid: str) -> bool:
    return bool(_GCP_SELFLINK_RE.match(uid))


def normalize_gcp_selflink(uid: str) -> str:
    """Convert https://www.googleapis.com/{api}/{ver}/{path} → //{api}.googleapis.com/{path}."""
    m = _GCP_SELFLINK_RE.match(uid)
    if m:
        return f"//{m.group(1)}.googleapis.com/{m.group(2)}"
    return uid


def normalize_aws_uid(uid: str, resource_type: str = '') -> str:
    """Convert short-form AWS UID to full ARN."""
    try:
        from resource_id import normalize_resource_uid
        return normalize_resource_uid(
            resource_uid=uid,
            resource_type=resource_type,
            provider='aws',
        )
    except Exception:
        return uid


def _apply_updates(conn, table: str, uid_col: str, updates: list, counts: dict) -> None:
    """Apply a batch of (new_uid, ctid) updates.

    On unique constraint conflict: the canonical UID already exists — the old row
    is a stale duplicate. Delete it instead of updating.
    """
    try:
        cur = conn.cursor()
        psycopg2.extras.execute_values(
            cur,
            f"UPDATE {table} SET {uid_col} = data.new_uid "
            f"FROM (VALUES %s) AS data(new_uid, ctid) "
            f"WHERE {table}.ctid = data.ctid::tid",
            updates,
        )
        counts['updated'] += len(updates)
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        # Fallback: apply row by row, deleting stale duplicates on conflict
        for new_uid, ctid in updates:
            try:
                cur = conn.cursor()
                cur.execute(
                    f"UPDATE {table} SET {uid_col} = %s WHERE ctid = %s::tid",
                    (new_uid, ctid),
                )
                counts['updated'] += 1
                conn.commit()
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                # Canonical already exists — delete the stale old row
                cur = conn.cursor()
                cur.execute(f"DELETE FROM {table} WHERE ctid = %s::tid", (ctid,))
                counts['updated'] += 1
                conn.commit()
            except Exception as e:
                conn.rollback()
                counts['errors'] += 1
                logger.warning("Row %s skip: %s", ctid, e)


def migrate_table(
    conn: psycopg2.extensions.connection,
    table: str,
    uid_col: str = 'resource_uid',
    type_col: str = 'resource_type',
    dry_run: bool = True,
) -> dict:
    """Backfill one table. Returns counts dict."""
    counts = {'scanned': 0, 'short_aws': 0, 'gcp_selflink': 0, 'uuid_skipped': 0, 'already_canonical': 0, 'updated': 0, 'errors': 0}

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # Count total
        cur.execute(f"SELECT COUNT(*) AS n FROM {table} WHERE {uid_col} IS NOT NULL")
        total = cur.fetchone()['n']
        counts['scanned'] = total
        logger.info("Table %s: %d rows to check", table, total)

        # Fetch all UIDs in batches
        offset = 0
        updates = []

        while offset < total:
            cur.execute(
                f"SELECT ctid, {uid_col}, {type_col} FROM {table} "
                f"WHERE {uid_col} IS NOT NULL "
                f"ORDER BY ctid LIMIT %s OFFSET %s",
                (BATCH_SIZE, offset),
            )
            rows = cur.fetchall()
            offset += len(rows)

            for row in rows:
                uid = row[uid_col] or ''
                rtype = row.get(type_col) or ''

                if is_canonical(uid):
                    counts['already_canonical'] += 1
                    continue

                if is_uuid(uid):
                    counts['uuid_skipped'] += 1
                    continue

                if is_short_aws(uid):
                    new_uid = normalize_aws_uid(uid, rtype)
                    if new_uid != uid and is_canonical(new_uid):
                        counts['short_aws'] += 1
                        updates.append((new_uid, row['ctid']))
                    continue

                if is_gcp_selflink(uid):
                    new_uid = normalize_gcp_selflink(uid)
                    if new_uid != uid and is_canonical(new_uid):
                        counts['gcp_selflink'] += 1
                        updates.append((new_uid, row['ctid']))
                    continue

            # Apply batch — handle unique constraint conflicts by deleting stale old row
            if not dry_run and updates:
                _apply_updates(conn, table, uid_col, updates, counts)
                updates = []

        if not dry_run and updates:
            _apply_updates(conn, table, uid_col, updates, counts)

    return counts


def main():
    parser = argparse.ArgumentParser(description='Backfill resource_uid to canonical format')
    parser.add_argument('--dry-run', action='store_true', default=False)
    parser.add_argument('--apply', action='store_true', default=False)
    parser.add_argument('--table', default=None, help='Single table to migrate (default: all)')
    args = parser.parse_args()

    if not args.dry_run and not args.apply:
        parser.error('Specify --dry-run or --apply')

    dry_run = not args.apply
    mode = 'DRY RUN' if dry_run else 'APPLY'
    logger.info("=== Resource UID Backfill Migration — %s ===", mode)

    tables = [args.table] if args.table else list(TABLE_DB_MAP.keys())

    for table in tables:
        table_cfg = TABLE_DB_MAP.get(table)
        if not table_cfg:
            logger.warning("Unknown table %s — skipping", table)
            continue

        db_prefix, uid_col, type_col = table_cfg

        try:
            conn = get_conn(db_prefix)
        except KeyError as e:
            logger.warning("Missing env var %s for table %s — skipping", e, table)
            continue
        except Exception as e:
            logger.warning("Cannot connect for table %s: %s — skipping", table, e)
            continue

        try:
            counts = migrate_table(conn, table, uid_col=uid_col, type_col=type_col, dry_run=dry_run)
            logger.info(
                "%-35s scanned=%-6d short_aws=%-5d gcp_selflink=%-5d uuid_skipped=%-5d already_canonical=%-6d updated=%-5d errors=%-3d",
                table,
                counts['scanned'], counts['short_aws'], counts['gcp_selflink'], counts['uuid_skipped'],
                counts['already_canonical'], counts['updated'], counts['errors'],
            )
        except Exception as e:
            logger.error("Table %s failed: %s", table, e)
            conn.rollback()
        finally:
            conn.close()

    logger.info("=== Migration %s complete ===", mode)


if __name__ == '__main__':
    main()
