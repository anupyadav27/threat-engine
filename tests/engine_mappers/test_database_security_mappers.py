"""Local test harness for database-security engine mappers.

Validates build_db_inventory against canonical discovery_findings fixtures.
Regression coverage for nested-envelope flatten fixes from commit 115da3fa9
(PointInTimeRecoveryDescription, BillingModeSummary).

  python3 tests/engine_mappers/test_database_security_mappers.py
  python3 -m pytest tests/engine_mappers/test_database_security_mappers.py -v
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "engines" / "database-security"))

# Stub engine_common so rule_categorizer's lazy DB import doesn't crash if ever
# triggered. With check_findings=[] / [] the lazy code path stays cold.
if "engine_common" not in sys.modules:
    fake = types.ModuleType("engine_common")
    sys.modules["engine_common"] = fake
    sys.modules["engine_common.category_loader"] = types.ModuleType("engine_common.category_loader")
    sys.modules["engine_common.db_connections"] = types.ModuleType("engine_common.db_connections")

from database_security_engine.analyzer.inventory_builder import build_db_inventory  # noqa: E402

FIXTURE_DIR = ROOT / "tests" / "dcat_fixtures"


def _load(name: str) -> list:
    with (FIXTURE_DIR / name).open() as fh:
        return json.load(fh)


def _by_uid(inv, uid):
    matches = [e for e in inv if e["resource_uid"] == uid]
    assert matches, f"no entry for {uid}"
    return matches[0]


# ── Tests ────────────────────────────────────────────────────────────


def test_db_inventory_full_population():
    """RDS / DynamoDB extractors should populate every primary column."""
    rows = _load("aws_dynamodb_describe_table.json")
    inv = build_db_inventory(rows, [], [])
    # 3 live DBs (orders, legacy-nested, prod-mysql); snapshot must be skipped
    assert len(inv) == 3, f"expected 3 DB resources (snapshot filtered), got {len(inv)} → {[e['resource_uid'] for e in inv]}"

    rds = _by_uid(inv, "arn:aws:rds:us-east-1:111:db:prod-mysql")
    assert rds["db_engine"] == "mysql"
    assert rds["db_engine_version"] == "8.0.32"
    assert rds["instance_class"] == "db.r5.large"
    assert rds["encryption_at_rest"] is True
    assert rds["iam_auth_enabled"] is True
    assert rds["backup_enabled"] is True
    assert rds["multi_az"] is True
    assert rds["vpc_id"] == "vpc-1"
    assert rds["allocated_storage_gb"] == 200

    ddb = _by_uid(inv, "arn:aws:dynamodb:us-east-1:111:table/orders")
    assert ddb["db_engine"] == "dynamodb"
    assert ddb["encryption_at_rest"] is True
    assert ddb["backup_enabled"] is True, "flat PointInTimeRecoveryStatus dropped"
    assert ddb["billing_mode"] == "PAY_PER_REQUEST", "flat BillingMode dropped"
    print("✓ DB inventory full-population (RDS + DynamoDB flat) passes")


def test_db_inventory_nested_dynamodb_fallback():
    """Pre-DCAT data still has PointInTimeRecoveryDescription / BillingModeSummary
    nested. Both fallbacks must still resolve. Regression for commit 115da3fa9.
    """
    rows = _load("aws_dynamodb_describe_table.json")
    inv = build_db_inventory(rows, [], [])
    legacy = _by_uid(inv, "arn:aws:dynamodb:us-east-1:111:table/legacy-nested")
    assert legacy["backup_enabled"] is True, (
        "PointInTimeRecoveryDescription nested fallback dropped"
    )
    assert legacy["billing_mode"] == "PROVISIONED", (
        f"BillingModeSummary nested fallback dropped — got {legacy['billing_mode']}"
    )
    print("✓ DB inventory nested DynamoDB envelope fallback passes")


def test_db_inventory_skips_snapshot_resource_type():
    """Snapshots must be skipped via the _SKIP_RESOURCE_TYPES set."""
    rows = _load("aws_dynamodb_describe_table.json")
    inv = build_db_inventory(rows, [], [])
    uids = {e["resource_uid"] for e in inv}
    assert "arn:aws:rds:us-east-1:111:snapshot:my-snap" not in uids
    print("✓ DB inventory skips snapshot resource_types")


def test_db_inventory_arrival_order_independence():
    """Reverse the input order — output must be deterministic."""
    rows = _load("aws_dynamodb_describe_table.json")
    inv_a = build_db_inventory(rows, [], [])
    inv_b = build_db_inventory(list(reversed(rows)), [], [])
    set_a = {(e["resource_uid"], e["db_engine"], e["encryption_at_rest"]) for e in inv_a}
    set_b = {(e["resource_uid"], e["db_engine"], e["encryption_at_rest"]) for e in inv_b}
    assert set_a == set_b, f"order-dependent output:\n  A={set_a}\n  B={set_b}"
    print("✓ DB inventory order-independent")


# ── Runner ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_db_inventory_full_population,
        test_db_inventory_nested_dynamodb_fallback,
        test_db_inventory_skips_snapshot_resource_type,
        test_db_inventory_arrival_order_independence,
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
