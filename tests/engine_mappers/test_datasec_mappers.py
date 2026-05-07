"""Local test harness for datasec discovery_db_reader._extract_metadata.

The audit (commit 115da3fa9) flagged 77 stale-key hits in datasec — the
highest of any engine — most pointed at this metadata extraction helper.
This harness pins behaviour for the canonical S3 / RDS / DynamoDB shapes
including the VersioningConfiguration→VersioningStatus catalog flatten.

  python3 tests/engine_mappers/test_datasec_mappers.py
  python3 -m pytest tests/engine_mappers/test_datasec_mappers.py -v
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# Stub engine_common (datasec discovery_db_reader imports it at module top)
if "engine_common" not in sys.modules:
    fake = types.ModuleType("engine_common")
    sys.modules["engine_common"] = fake
    db_mod = types.ModuleType("engine_common.db_connections")
    db_mod.get_discoveries_conn = lambda: None  # never called from _extract_metadata
    sys.modules["engine_common.db_connections"] = db_mod

sys.path.insert(0, str(ROOT / "engines" / "datasec"))

from data_security_engine.input.discovery_db_reader import _extract_metadata  # noqa: E402

FIXTURE_DIR = ROOT / "tests" / "dcat_fixtures"


def _load(name):
    with (FIXTURE_DIR / name).open() as fh:
        return json.load(fh)


def _row_meta(rows, discovery_id):
    """Apply _extract_metadata to the first row matching the discovery_id."""
    matches = [r for r in rows if r["discovery_id"] == discovery_id]
    assert matches, f"no row with discovery_id={discovery_id}"
    return matches, [
        _extract_metadata(
            r.get("raw_response", {}),
            r.get("emitted_fields", {}),
            r.get("service", ""),
            r.get("discovery_id", ""),
        )
        for r in matches
    ]


def test_s3_metadata_flat_versioning_status():
    """Catalog flattens VersioningConfiguration.Status → VersioningStatus.
    Both shapes must resolve versioning_enabled=True."""
    rows = _load("aws_s3_list_buckets.json")
    flat_rows, metas = _row_meta(rows, "aws.s3.list_buckets")
    flat_meta = next(m for r, m in zip(flat_rows, metas) if r["resource_uid"].endswith("my-bucket"))
    assert flat_meta["name"] == "my-bucket"
    assert flat_meta["versioning_enabled"] is True, "flat VersioningStatus dropped"
    assert flat_meta["encryption_at_rest"] is True
    assert flat_meta["tags"]["Owner"] == "data-platform"
    assert flat_meta["owner"] == "data-platform"
    assert flat_meta["creation_date"] == "2024-01-01T00:00:00Z"
    print("✓ datasec S3 flat VersioningStatus + tags + encryption pass")


def test_s3_metadata_nested_versioning_fallback():
    """Pre-DCAT data still has VersioningConfiguration.Status nested.
    Regression for commit 115da3fa9 nested fallback."""
    rows = _load("aws_s3_list_buckets.json")
    legacy_row = next(
        r for r in rows
        if r["discovery_id"] == "aws.s3.list_buckets"
        and r["resource_uid"].endswith("legacy-nested-bucket")
    )
    meta = _extract_metadata(
        legacy_row["raw_response"], legacy_row.get("emitted_fields", {}),
        legacy_row["service"], legacy_row["discovery_id"],
    )
    assert meta["versioning_enabled"] is True, (
        "nested VersioningConfiguration.Status fallback dropped"
    )
    print("✓ datasec S3 nested VersioningConfiguration.Status fallback passes")


def test_rds_metadata_storage_conversion():
    """RDS AllocatedStorage is in GB; size_bytes must be converted to bytes."""
    rows = _load("aws_s3_list_buckets.json")
    rds = next(r for r in rows if r["service"] == "rds")
    meta = _extract_metadata(
        rds["raw_response"], rds.get("emitted_fields", {}),
        rds["service"], rds["discovery_id"],
    )
    assert meta["name"] == "mydb"
    assert meta["size_bytes"] == 100 * 1024 * 1024 * 1024  # 100 GB → bytes
    assert meta["encryption_at_rest"] is True
    assert meta["backup_enabled"] is True  # BackupRetentionPeriod = 7 > 0
    assert meta["is_public"] is False
    assert meta["creation_date"] == "2024-02-01T00:00:00Z"
    assert meta["tags"]["Owner"] == "ops"
    print("✓ datasec RDS storage GB→bytes conversion + tag list parse")


def test_dynamodb_metadata_record_count():
    """DynamoDB ItemCount must populate record_count."""
    rows = _load("aws_s3_list_buckets.json")
    ddb = next(r for r in rows if r["service"] == "dynamodb")
    meta = _extract_metadata(
        ddb["raw_response"], ddb.get("emitted_fields", {}),
        ddb["service"], ddb["discovery_id"],
    )
    assert meta["name"] == "mytable"
    assert meta["record_count"] == 12345
    assert meta["tags"] == {}
    assert meta["owner"] == ""  # no owner tag
    print("✓ datasec DynamoDB ItemCount → record_count")


def test_metadata_handles_empty_inputs():
    """Empty raw + empty emitted should not crash."""
    meta = _extract_metadata({}, {}, "s3", "aws.s3.list_buckets")
    assert meta["name"] == ""
    assert meta["size_bytes"] == 0
    assert meta["tags"] == {}
    assert meta["versioning_enabled"] is False
    assert meta["encryption_at_rest"] is False
    print("✓ datasec _extract_metadata handles empty input")


if __name__ == "__main__":
    tests = [
        test_s3_metadata_flat_versioning_status,
        test_s3_metadata_nested_versioning_fallback,
        test_rds_metadata_storage_conversion,
        test_dynamodb_metadata_record_count,
        test_metadata_handles_empty_inputs,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as exc:
            print(f"✗ {t.__name__}: {exc}")
            failed += 1
        except Exception as exc:
            print(f"✗ {t.__name__}: {type(exc).__name__}: {exc}")
            failed += 1
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(0 if failed == 0 else 1)
