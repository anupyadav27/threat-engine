#!/usr/bin/env python3
"""
Unit tests for catalog.rule.tech_rule_utils (TEC-006).

Run with:
    pytest catalog/rule/tests/test_tech_rule_utils.py -v

All 10 required test cases from TEC-006 are implemented:
  1-2.  make_slug edge cases
  3.    section_to_slug variants
  4.    make_rule_id variants
  5.    make_discovery_id basic case
  6.    tech_display_name — known overrides + unknown value
  7-8.  SlugRegistry collision suffix (_2, _3)
  9.    SlugRegistry.reset
  10.   Full-CSV collision test (< 5% rate, 0 duplicate rule_ids)
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

import pytest

# ── ensure catalog.rule is importable regardless of CWD ──────────────────────
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from catalog.rule.tech_rule_utils import (  # noqa: E402
    SlugRegistry,
    make_discovery_id,
    make_rule_id,
    make_slug,
    section_to_slug,
    tech_display_name,
)

_CSV_PATH = (
    _REPO_ROOT
    / "catalog"
    / "complaince_csv"
    / "cis_technology_compliance_rules.csv"
)


# ─── Test 1 & 2: make_slug edge cases ─────────────────────────────────────────


@pytest.mark.parametrize(
    "title,expected",
    [
        # TEC-006 edge-case table
        (
            "Ensure SSL is enabled for all connections",
            "ssl_is_enabled_for_all_connections",
        ),
        (
            "Ensure the SSL is enabled",
            "ssl_is_enabled",
        ),
        (
            "Ensure that SSL is enabled",
            "ssl_is_enabled",
        ),
        (
            "Verify TLS version is 1.2 or higher",
            "tls_version_is_1_2_or_higher",
        ),
        (
            # Leading digit — verb stripping does NOT remove section prefixes
            "1.1 Ensure passwords expire",
            "1_1_ensure_passwords_expire",
        ),
        (
            # Parens become underscores, then collapsed
            "(L1) Ensure X",
            "l1_ensure_x",
        ),
        (
            "Ensure X/Y is set",
            "x_y_is_set",
        ),
        # AC1 from story
        (
            "Ensure SSL is enabled for all connections",
            "ssl_is_enabled_for_all_connections",
        ),
        # AC2 from story
        (
            "Ensure the number of administrative accounts is minimized",
            "number_of_administrative_accounts_is_minimized",
        ),
        # "Verify that audit logging …"
        (
            "Verify that audit logging is enabled",
            "audit_logging_is_enabled",
        ),
    ],
)
def test_make_slug_edge_cases(title: str, expected: str) -> None:
    """Test make_slug against the TEC-006 edge-case table."""
    assert make_slug(title) == expected


def test_make_slug_truncates_long_title() -> None:
    """Titles longer than 50 chars after transform are truncated at a word boundary."""
    # Build a title whose slug would be exactly 55 chars without truncation:
    # "ensure " + "a_b_c_d_e_f_g_h_i_j_k_l_m_n_o_p_q_r_s_t_u_v_w_x_y"
    long_title = "Ensure " + " ".join(["word"] * 15)
    result = make_slug(long_title)
    assert len(result) <= 50
    assert "_" not in result[-1]  # did not end with a trailing underscore


def test_make_slug_raises_on_empty_result() -> None:
    """make_slug must raise ValueError for a title that reduces to empty."""
    with pytest.raises(ValueError, match="slug is empty"):
        # A title made only of non-alphanumeric chars (after lowercasing)
        make_slug("--- *** ///")


# ─── Test 3: section_to_slug ──────────────────────────────────────────────────


def test_section_to_slug_integer() -> None:
    assert section_to_slug("1") == "section_1"


def test_section_to_slug_decimal() -> None:
    assert section_to_slug("1.2") == "section_1_2"


def test_section_to_slug_two_digit() -> None:
    assert section_to_slug("10") == "section_10"


# ─── Test 4: make_rule_id ─────────────────────────────────────────────────────


def test_make_rule_id_integer_section() -> None:
    """AC4: make_rule_id with an integer section."""
    assert (
        make_rule_id("postgresql", "6", "ssl_is_enabled")
        == "postgresql.cis.6.ssl_is_enabled"
    )


def test_make_rule_id_decimal_section() -> None:
    """Section dots become underscores in the rule ID."""
    assert (
        make_rule_id("ubuntu", "1.2", "audit_logging_enabled")
        == "ubuntu.cis.1_2.audit_logging_enabled"
    )


# ─── Test 5: make_discovery_id ────────────────────────────────────────────────


def test_make_discovery_id_basic() -> None:
    assert (
        make_discovery_id("postgresql", "section_6", "ssl_is_enabled")
        == "postgresql.section_6.ssl_is_enabled"
    )


# ─── Test 6: tech_display_name ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "tech,expected",
    [
        ("postgresql", "PostgreSQL"),
        ("mysql", "MySQL"),
        ("ibm_db2", "IBM DB2"),
        ("vmware_esxi", "VMware ESXi"),
        ("cisco_ios_xe", "Cisco IOS XE"),
    ],
)
def test_tech_display_name_known(tech: str, expected: str) -> None:
    """AC9: known overrides return their exact display names."""
    assert tech_display_name(tech) == expected


def test_tech_display_name_unknown() -> None:
    """Unknown techs fall back to title-cased, space-separated form.

    Per TEC-006 spec: "oracle_db" → "Oracle Db" (no special case defined).
    """
    assert tech_display_name("oracle_db") == "Oracle Db"


# ─── Tests 7 & 8: SlugRegistry collision suffixes ─────────────────────────────


def test_slug_registry_second_collision() -> None:
    """AC5: second identical slug gets _2 suffix."""
    reg = SlugRegistry()
    assert reg.register("ssl_enabled") == "ssl_enabled"
    assert reg.register("ssl_enabled") == "ssl_enabled_2"


def test_slug_registry_third_collision() -> None:
    """Third identical slug gets _3 suffix."""
    reg = SlugRegistry()
    reg.register("ssl_enabled")
    reg.register("ssl_enabled")
    assert reg.register("ssl_enabled") == "ssl_enabled_3"


# ─── Test 9: SlugRegistry.reset ──────────────────────────────────────────────


def test_slug_registry_reset() -> None:
    """After reset, the same slug can be registered fresh without a suffix."""
    reg = SlugRegistry()
    reg.register("ssl_enabled")
    reg.reset()
    assert reg.register("ssl_enabled") == "ssl_enabled"


# ─── Test 10: Full-CSV collision & uniqueness ─────────────────────────────────


def _load_deduped_rows(csv_path: Path) -> list[dict]:
    """Load CSV rows deduplicated to remove cross-version title duplicates.

    The CSV contains the same control title across multiple benchmark versions
    (e.g. Ubuntu 20.04, 22.04, 24.04 each have "Ensure /tmp is a separate
    partition" in section 1).  For collision testing we keep one representative
    row per ``(benchmark_subcategory, section, title)`` tuple — the one with
    the highest ``framework_version``.

    This matches the generator's effective dedup behaviour: when the same
    logical control appears in multiple versions, only one rule file entry is
    written (highest version wins).

    Args:
        csv_path: Path to the CSV file.

    Returns:
        Deduplicated list of row dicts.
    """
    best: dict[tuple[str, str, str], dict] = {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            tech = row.get("benchmark_subcategory", "").strip()
            section = row.get("section", "").strip()
            title = row.get("title", "").strip()
            key = (tech, section, title)
            if key not in best:
                best[key] = row
            else:
                existing_ver = best[key].get("framework_version", "")
                new_ver = row.get("framework_version", "")
                if new_ver > existing_ver:
                    best[key] = row
    return list(best.values())


@pytest.mark.skipif(
    not _CSV_PATH.exists(),
    reason=f"CSV not found at {_CSV_PATH}",
)
def test_full_csv_collision_rate() -> None:
    """Collision rate across deduplicated automated rows must be < 5%.

    Deduplication is applied first (keep highest framework_version per
    unique_compliance_id) to remove the large number of identical-title rows
    that appear across benchmark versions.  TEC-006 test #9.
    """
    rows = _load_deduped_rows(_CSV_PATH)

    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        cat = row.get("benchmark_category", "").strip()
        tech = row.get("benchmark_subcategory", "").strip()
        section = row.get("section", "").strip()
        if not tech or not section:
            continue
        groups[(cat, tech, section)].append(row)

    total_automated = 0
    total_collisions = 0

    for (cat, tech, section), group_rows in groups.items():
        registry = SlugRegistry()
        for row in group_rows:
            if row.get("automation_type", "").strip().lower() != "automated":
                continue
            total_automated += 1
            title = row.get("title", "").strip()
            try:
                base = make_slug(title)
            except ValueError:
                continue
            final = registry.register(base)
            if final != base:
                total_collisions += 1

    rate = total_collisions / total_automated if total_automated else 0.0
    assert rate < 0.05, (
        f"Collision rate {rate:.2%} exceeds 5% "
        f"({total_collisions}/{total_automated})"
    )


@pytest.mark.skipif(
    not _CSV_PATH.exists(),
    reason=f"CSV not found at {_CSV_PATH}",
)
def test_full_csv_no_duplicate_rule_ids() -> None:
    """Zero duplicate rule_ids within any (tech, section) group (TEC-006 test #10).

    Deduplication is applied first to match generator behavior.
    """
    rows = _load_deduped_rows(_CSV_PATH)

    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        cat = row.get("benchmark_category", "").strip()
        tech = row.get("benchmark_subcategory", "").strip()
        section = row.get("section", "").strip()
        if not tech or not section:
            continue
        groups[(cat, tech, section)].append(row)

    duplicates: list[str] = []

    for (cat, tech, section), group_rows in groups.items():
        registry = SlugRegistry()
        seen: set[str] = set()
        for row in group_rows:
            if row.get("automation_type", "").strip().lower() != "automated":
                continue
            title = row.get("title", "").strip()
            try:
                base = make_slug(title)
            except ValueError:
                continue
            final = registry.register(base)
            rule_id = make_rule_id(tech, section, final)
            if rule_id in seen:
                duplicates.append(f"{cat}/{tech}/{section}: {rule_id}")
            seen.add(rule_id)

    assert not duplicates, (
        f"{len(duplicates)} duplicate rule_id(s) found:\n"
        + "\n".join(duplicates[:20])
    )
