#!/usr/bin/env python3
"""
Shared pytest fixtures for the catalog/rule/tests suite.

Fixtures defined here are available to all test modules in this directory.
"""

import csv
import shutil
import sys
from pathlib import Path

import pytest

# ── ensure repo root is on sys.path ──────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

# ── Path constants ────────────────────────────────────────────────────────────

REPO_ROOT = _REPO_ROOT

CSV_PATH = REPO_ROOT / "catalog" / "complaince_csv" / "cis_technology_compliance_rules.csv"

# Generated output directories for postgresql
_PG_GENERATED_DIRS = [
    REPO_ROOT / "catalog" / "rule" / "database_rule_check" / "postgresql",
    REPO_ROOT / "catalog" / "rule" / "database_rule_ciem" / "postgresql",
    REPO_ROOT / "catalog" / "rule" / "database_rule_metadata" / "postgresql",
    REPO_ROOT / "catalog" / "discovery_generator_data" / "database" / "postgresql",
]


# ── pytest CLI option ────────────────────────────────────────────────────────


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add --clean option to wipe generated postgresql directories before tests."""
    parser.addoption(
        "--clean",
        action="store_true",
        default=False,
        help="Delete generated postgresql output directories before running tests.",
    )


# ── Session-scoped autouse fixture ────────────────────────────────────────────


@pytest.fixture(scope="session", autouse=True)
def clean_if_requested(request: pytest.FixtureRequest) -> None:
    """Optionally wipe generated postgresql output directories.

    Activated when pytest is run with ``--clean``.
    """
    if request.config.getoption("--clean"):
        for d in _PG_GENERATED_DIRS:
            if d.exists():
                shutil.rmtree(d)
                print(f"[CLEAN] Deleted {d}")


# ── Module-scoped CSV fixtures ────────────────────────────────────────────────


@pytest.fixture(scope="module")
def repo_root() -> Path:
    """Return the absolute path to the repository root.

    Returns:
        Absolute Path pointing to the threat-engine repo root.
    """
    return REPO_ROOT


@pytest.fixture(scope="module")
def csv_path() -> Path:
    """Return the absolute path to the CIS Technology compliance CSV.

    Returns:
        Absolute Path to ``catalog/complaince_csv/cis_technology_compliance_rules.csv``.
    """
    return CSV_PATH


@pytest.fixture(scope="module")
def postgres_csv_rows() -> list[dict]:
    """Load all postgresql rows from the CIS Technology compliance CSV.

    Returns:
        List of row dicts where ``benchmark_subcategory == "postgresql"``.

    Raises:
        pytest.Failed: When the CSV file does not exist.
    """
    if not CSV_PATH.exists():
        pytest.fail(f"CSV not found at {CSV_PATH}")

    with open(CSV_PATH, newline="", encoding="utf-8") as fh:
        return [
            r for r in csv.DictReader(fh)
            if r["benchmark_subcategory"] == "postgresql"
        ]


@pytest.fixture(scope="module")
def postgres_deduped_rows(postgres_csv_rows: list[dict]) -> list[dict]:
    """Return postgresql rows after applying the generator's two-level dedup.

    Dedup level 1: by unique_compliance_id (keep highest framework_version).
    Dedup level 2: by (tech, section, title) (keep highest framework_version).
    This matches the dedup logic in generate_tech_rules.load_and_dedup_csv.

    Args:
        postgres_csv_rows: All raw postgresql rows from the CSV.

    Returns:
        Deduplicated list of postgresql rows.
    """
    # Level 1: dedup by unique_compliance_id
    best_uid: dict[str, dict] = {}
    for row in postgres_csv_rows:
        uid = row.get("unique_compliance_id", "").strip()
        if not uid:
            continue
        if uid not in best_uid:
            best_uid[uid] = row
        else:
            if row.get("framework_version", "") > best_uid[uid].get("framework_version", ""):
                best_uid[uid] = row

    # Level 2: dedup by (tech, section, title)
    best_title: dict[tuple[str, str, str], dict] = {}
    for row in best_uid.values():
        t = row.get("benchmark_subcategory", "").strip()
        s = row.get("section", "").strip()
        title = row.get("title", "").strip()
        key = (t, s, title)
        if key not in best_title:
            best_title[key] = row
        else:
            if row.get("framework_version", "") > best_title[key].get("framework_version", ""):
                best_title[key] = row

    return list(best_title.values())


@pytest.fixture(scope="module")
def postgres_automated_count(postgres_deduped_rows: list[dict]) -> int:
    """Count automated rows after dedup.

    Args:
        postgres_deduped_rows: Deduplicated postgresql rows.

    Returns:
        Count of rows with automation_type == "automated".
    """
    return sum(
        1 for r in postgres_deduped_rows
        if r["automation_type"].strip().lower() == "automated"
    )


@pytest.fixture(scope="module")
def postgres_total_count(postgres_deduped_rows: list[dict]) -> int:
    """Total row count after dedup.

    Args:
        postgres_deduped_rows: Deduplicated postgresql rows.

    Returns:
        Total number of deduplicated rows.
    """
    return len(postgres_deduped_rows)
