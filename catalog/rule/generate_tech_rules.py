#!/usr/bin/env python3
"""
Generate YAML rule files for CIS Technology Compliance benchmarks.

This is the single entry point for re-generating all tech rules from the CSV at
``catalog/complaince_csv/cis_technology_compliance_rules.csv``.

Each row in the CSV is classified into one of three output types:

1. **check rule + discovery YAML** — ``automation_type=automated`` and no CIEM
   keyword in title/description.
2. **CIEM rule** — ``automation_type=automated`` AND one or more CIEM keywords
   present.
3. **metadata stub** — ``automation_type=manual``.

Usage::

    python3 catalog/rule/generate_tech_rules.py --category linux --dry-run
    python3 catalog/rule/generate_tech_rules.py --category database --tech postgresql --apply
    python3 catalog/rule/generate_tech_rules.py --category database --tech postgresql \\
        --section 3 --dry-run

Exactly one of ``--dry-run`` or ``--apply`` must be given.  Both together, or
neither, exit with code 1.
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path
from typing import NamedTuple

# ─── Repository paths ────────────────────────────────────────────────────────

BASE = Path("/Users/apple/Desktop/threat-engine")
CSV_PATH = BASE / "catalog" / "complaince_csv" / "cis_technology_compliance_rules.csv"
RULE_DIR = BASE / "catalog" / "rule"
DISCOVERY_DIR = BASE / "catalog" / "discovery_generator_data"

# ─── Imports from TEC-006 utility module ─────────────────────────────────────

sys.path.insert(0, str(BASE))
from catalog.rule.tech_rule_utils import (  # noqa: E402
    SlugRegistry,
    make_ciem_rule_id,
    make_discovery_id,
    make_rule_id,
    make_slug,
    section_to_slug,
    tech_display_name,
)

# ─── CIEM keyword routing ─────────────────────────────────────────────────────

# A row is routed to CIEM (not check+discovery) when automation_type=automated
# AND any of these keywords appear in title OR description (case-insensitive).
CIEM_KEYWORDS: list[str] = [
    "login",
    "logon",
    "sign-in",
    "authentication failure",
    "brute force",
    "brute",
    "privilege escalation",
    "privilege",
    "sudo",
    "audit log",
    "audit",
    "event log",
    "change event",
    "access event",
    "access",
    "config change",
    "admin grant",
]

# ─── Row classification result types ─────────────────────────────────────────

OUTPUT_CHECK = "automated_config"
OUTPUT_CIEM = "automated_ciem"
OUTPUT_MANUAL = "manual"


class ClassifiedRow(NamedTuple):
    """A CSV row enriched with classification results."""

    row: dict
    output_type: str  # OUTPUT_CHECK | OUTPUT_CIEM | OUTPUT_MANUAL
    rule_id: str
    slug: str
    section_slug: str


# ─── Template stub imports ────────────────────────────────────────────────────
# These will raise NotImplementedError until TEC-002 through TEC-005 complete.

def _import_templates() -> tuple:
    """Import render functions from template modules (stubs until TEC-002–005).

    Returns:
        Tuple of (render_discovery, render_check_rules, render_ciem_rules,
        render_metadata) — each may be a stub that raises NotImplementedError.
    """
    render_discovery = render_check_rules = render_ciem_rules = render_metadata = None

    try:
        from catalog.rule.tech_templates.render_discovery import render_discovery  # type: ignore
    except ImportError:
        pass

    try:
        from catalog.rule.tech_templates.render_check import render_check_rules  # type: ignore
    except ImportError:
        pass

    try:
        from catalog.rule.tech_templates.render_ciem import render_ciem_rules  # type: ignore
    except ImportError:
        pass

    try:
        from catalog.rule.tech_templates.render_metadata import render_metadata  # type: ignore
    except ImportError:
        pass

    return render_discovery, render_check_rules, render_ciem_rules, render_metadata


# ─── Write stubs (used until TEC-002–005 are implemented) ────────────────────


def write_discovery_yaml(
    category: str,
    tech: str,
    section: str,
    rows: list["ClassifiedRow"],
    dry_run: bool,
) -> str | None:
    """Write or stub-print the discovery YAML for one (tech, section).

    Args:
        category: Benchmark category, e.g. ``"database"``.
        tech: Technology key, e.g. ``"postgresql"``.
        section: Raw section string, e.g. ``"3"``.
        rows: ClassifiedRow items for this section (check-routed only).
        dry_run: If True, only print the would-write path.

    Returns:
        The output path string if written, else None.
    """
    sec_slug = section_to_slug(section)
    out_path = (
        DISCOVERY_DIR / category / tech / f"step6_{sec_slug}.discovery.yaml"
    )
    print(f"  [STUB] would write discovery YAML: {out_path.relative_to(BASE)}")
    return None


def write_check_rule_yaml(
    category: str,
    tech: str,
    section: str,
    rows: list["ClassifiedRow"],
    dry_run: bool,
) -> str | None:
    """Write or stub-print the check rule YAML for one (tech, section).

    Args:
        category: Benchmark category.
        tech: Technology key.
        section: Raw section string.
        rows: ClassifiedRow items for this section (check-routed only).
        dry_run: If True, only print the would-write path.

    Returns:
        The output path string if written, else None.
    """
    out_path = (
        RULE_DIR
        / f"{category}_rule_check"
        / tech
        / f"{tech}_cis_section_{section}.rules.yaml"
    )
    print(f"  [STUB] would write check rule YAML: {out_path.relative_to(BASE)}")
    return None


def write_ciem_yaml(
    category: str,
    tech: str,
    rows: list["ClassifiedRow"],
    dry_run: bool,
) -> str | None:
    """Write or stub-print the CIEM rule YAML for a tech.

    Args:
        category: Benchmark category.
        tech: Technology key.
        rows: All CIEM-routed ClassifiedRow items for this tech.
        dry_run: If True, only print the would-write path.

    Returns:
        The output path string if written, else None.
    """
    out_path = (
        RULE_DIR / f"{category}_rule_ciem" / tech / f"{tech}_ciem_rules.yaml"
    )
    print(f"  [STUB] would write CIEM YAML: {out_path.relative_to(BASE)}")
    return None


def write_metadata_yaml(
    category: str,
    tech: str,
    rows: list["ClassifiedRow"],
    dry_run: bool,
) -> str | None:
    """Write or stub-print the metadata YAML for a tech.

    Args:
        category: Benchmark category.
        tech: Technology key.
        rows: All ClassifiedRow items for this tech.
        dry_run: If True, only print the would-write path.

    Returns:
        The output path string if written, else None.
    """
    out_path = (
        RULE_DIR
        / f"{category}_rule_metadata"
        / tech
        / f"{tech}_metadata.yaml"
    )
    print(f"  [STUB] would write metadata YAML: {out_path.relative_to(BASE)}")
    return None


# ─── CSV loading & deduplication ─────────────────────────────────────────────


def load_and_dedup_csv(
    csv_path: Path,
    category: str | None,
    tech: str | None,
    section: str | None,
) -> tuple[list[dict], dict[str, int]]:
    """Load the CSV, apply filters and dedup, return rows + dedup counts per tech.

    Dedup rule: when the same ``unique_compliance_id`` appears more than once
    (across framework versions), keep the row with the highest
    ``framework_version`` string.

    Warn once per tech if duplicates are removed.

    Args:
        csv_path: Path to the CSV file.
        category: Optional benchmark_category filter.
        tech: Optional benchmark_subcategory filter.
        section: Optional section filter.

    Returns:
        Tuple of (filtered_rows, {tech: dedup_count}).
    """
    # First pass — read all rows and dedup by unique_compliance_id
    best: dict[str, dict] = {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            uid = row.get("unique_compliance_id", "").strip()
            if not uid:
                continue
            if uid not in best:
                best[uid] = row
            else:
                existing_ver = best[uid].get("framework_version", "")
                new_ver = row.get("framework_version", "")
                if new_ver > existing_ver:
                    best[uid] = row

    uid_rows = list(best.values())

    # Second pass — dedup by (tech, section, slug) keeping highest framework_version.
    # This collapses the same logical control that appears in multiple benchmark
    # versions (e.g. PostgreSQL 14/15/16/17 all share many identical titles in the
    # same section) so the generator does not emit duplicate rule_id values.
    # Keying on the normalised slug (via make_slug) ensures that titles differing
    # only in capitalisation or trailing punctuation
    # (e.g. "Is Set To" vs "Is Set to", or a trailing period) collapse to one rule.
    best_by_title: dict[tuple[str, str, str], dict] = {}
    for row in uid_rows:
        t = row.get("benchmark_subcategory", "").strip()
        s = row.get("section", "").strip()
        title = row.get("title", "").strip()
        try:
            title_slug = make_slug(title)
        except ValueError:
            title_slug = title.lower()
        key = (t, s, title_slug)
        if key not in best_by_title:
            best_by_title[key] = row
        else:
            existing_ver = best_by_title[key].get("framework_version", "")
            new_ver = row.get("framework_version", "")
            if new_ver > existing_ver:
                best_by_title[key] = row

    all_rows = list(best_by_title.values())

    # Count pre-dedup duplicates per tech (rows dropped by uid dedup)
    dedup_counts: dict[str, int] = defaultdict(int)
    with open(csv_path, newline="", encoding="utf-8") as fh:
        raw_count: dict[str, int] = defaultdict(int)
        for row in csv.DictReader(fh):
            t = row.get("benchmark_subcategory", "").strip()
            if t:
                raw_count[t] += 1
    deduped_count: dict[str, int] = defaultdict(int)
    for row in all_rows:
        t = row.get("benchmark_subcategory", "").strip()
        if t:
            deduped_count[t] += 1
    for t in raw_count:
        dropped = raw_count[t] - deduped_count[t]
        if dropped > 0:
            dedup_counts[t] = dropped

    # Apply filters
    filtered: list[dict] = []
    for row in all_rows:
        if category and row.get("benchmark_category", "").strip() != category:
            continue
        if tech and row.get("benchmark_subcategory", "").strip() != tech:
            continue
        if section and row.get("section", "").strip() != section:
            continue
        filtered.append(row)

    return filtered, dedup_counts


# ─── Row classification ───────────────────────────────────────────────────────


def _has_ciem_keyword(title: str, description: str) -> bool:
    """Return True if any CIEM keyword appears in title or description.

    Args:
        title: Rule title string.
        description: Rule description string.

    Returns:
        True when at least one keyword matches.
    """
    combined = (title + " " + description).lower()
    return any(kw in combined for kw in CIEM_KEYWORDS)


def classify_row(
    row: dict,
    registry: SlugRegistry,
) -> ClassifiedRow | None:
    """Classify a single CSV row and produce a ClassifiedRow.

    Args:
        row: A raw CSV row dict.
        registry: The SlugRegistry for the current ``(tech, section)`` scope.

    Returns:
        A ClassifiedRow, or None if the row should be skipped.
    """
    uid = row.get("unique_compliance_id", "").strip()
    tech = row.get("benchmark_subcategory", "").strip()
    section = row.get("section", "").strip()
    title = row.get("title", "").strip()
    description = row.get("description", "").strip()
    automation_type = row.get("automation_type", "").strip().lower()

    if not tech or not section:
        print(f"[SKIP] row {uid} — missing required field")
        return None

    if not title:
        print(f"[SKIP] row {uid} — empty title")
        return None

    # Generate slug
    try:
        base_slug = make_slug(title)
    except ValueError as exc:
        print(f"[SKIP] row {uid} — slug error: {exc}")
        return None

    final_slug = registry.register(base_slug)
    sec_slug = section_to_slug(section)

    # Routing
    if automation_type == "manual":
        rule_id = make_rule_id(tech, section, final_slug)
        return ClassifiedRow(
            row=row,
            output_type=OUTPUT_MANUAL,
            rule_id=rule_id,
            slug=final_slug,
            section_slug=sec_slug,
        )

    if _has_ciem_keyword(title, description):
        rule_id = make_ciem_rule_id(tech, final_slug)
        return ClassifiedRow(
            row=row,
            output_type=OUTPUT_CIEM,
            rule_id=rule_id,
            slug=final_slug,
            section_slug=sec_slug,
        )

    # Default: automated config check
    rule_id = make_rule_id(tech, section, final_slug)
    return ClassifiedRow(
        row=row,
        output_type=OUTPUT_CHECK,
        rule_id=rule_id,
        slug=final_slug,
        section_slug=sec_slug,
    )


# ─── Summary table ────────────────────────────────────────────────────────────


def print_summary_table(
    stats: dict[str, dict[str, int]],
) -> None:
    """Print a box-drawing summary table to stdout.

    Args:
        stats: ``{tech: {OUTPUT_CHECK: N, OUTPUT_CIEM: N, OUTPUT_MANUAL: N}}``.
    """
    col_tech = max((len(t) for t in stats), default=4)
    col_tech = max(col_tech, len("tech"))

    header = (
        f"{'tech':<{col_tech}}  "
        f"{'total':>7}  "
        f"{'automated_config':>16}  "
        f"{'automated_ciem':>14}  "
        f"{'manual':>6}"
    )
    sep = "-" * len(header)

    print()
    print(sep)
    print(header)
    print(sep)
    for tech in sorted(stats):
        s = stats[tech]
        total = s[OUTPUT_CHECK] + s[OUTPUT_CIEM] + s[OUTPUT_MANUAL]
        print(
            f"{tech:<{col_tech}}  "
            f"{total:>7}  "
            f"{s[OUTPUT_CHECK]:>16}  "
            f"{s[OUTPUT_CIEM]:>14}  "
            f"{s[OUTPUT_MANUAL]:>6}"
        )
    print(sep)
    print()


# ─── Core generation logic ────────────────────────────────────────────────────


def group_and_classify(
    rows: list[dict],
    dedup_counts: dict[str, int],
) -> tuple[
    dict[str, dict[str, list[ClassifiedRow]]],  # {tech: {section: [rows]}}
    dict[str, dict[str, int]],                  # {tech: {type: count}}
]:
    """Group CSV rows by (tech, section) and classify each row.

    Also emits dedup warnings per tech and skip messages per row.

    Args:
        rows: Pre-filtered, deduplicated CSV rows.
        dedup_counts: Number of duplicate rows dropped per tech.

    Returns:
        Tuple of (grouped_rows, stats_per_tech).
    """
    # Warn about duplicates
    warned_techs: set[str] = set()
    for t, n in dedup_counts.items():
        if n > 0:
            print(f"[WARN] {n} duplicate unique_compliance_ids deduplicated for {t}")
            warned_techs.add(t)

    # Group rows by (tech, section)
    grouped: dict[str, dict[str, list[ClassifiedRow]]] = defaultdict(
        lambda: defaultdict(list)
    )
    stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {OUTPUT_CHECK: 0, OUTPUT_CIEM: 0, OUTPUT_MANUAL: 0}
    )

    # Build per-(tech, section) registries
    registries: dict[tuple[str, str], SlugRegistry] = {}

    for row in rows:
        tech = row.get("benchmark_subcategory", "").strip()
        section = row.get("section", "").strip()
        if not tech or not section:
            uid = row.get("unique_compliance_id", "?")
            print(f"[SKIP] row {uid} — missing required field")
            continue

        key = (tech, section)
        if key not in registries:
            registries[key] = SlugRegistry()

        classified = classify_row(row, registries[key])
        if classified is None:
            continue

        grouped[tech][section].append(classified)
        stats[tech][classified.output_type] += 1

    return grouped, stats


def apply_writes(
    category: str,
    grouped: dict[str, dict[str, list[ClassifiedRow]]],
    dry_run: bool,
    render_discovery,
    render_check_rules,
    render_ciem_rules,
    render_metadata,
) -> tuple[int, int]:
    """Invoke render functions or stubs for each tech/section combination.

    When a render function raises ``NotImplementedError``, the write is skipped
    with a ``[STUB]`` message.  Any other exception is caught, logged as
    ``[ERROR]``, and processing continues.

    Args:
        category: Benchmark category being processed.
        grouped: Output of :func:`group_and_classify`.
        dry_run: When True, stub writes are printed; when False, files are
            written (still stubs in this sprint since templates are not yet
            implemented).
        render_discovery: Render function or None.
        render_check_rules: Render function or None.
        render_ciem_rules: Render function or None.
        render_metadata: Render function or None.

    Returns:
        Tuple of (files_written, error_count).
    """
    # Import output-path helpers from renderer modules (available since TEC-002–005)
    try:
        from catalog.rule.tech_templates.render_discovery import (  # type: ignore
            discovery_output_path,
        )
        from catalog.rule.tech_templates.render_check import (  # type: ignore
            check_rule_output_path,
        )
        from catalog.rule.tech_templates.render_ciem import (  # type: ignore
            ciem_rule_output_path,
        )
        from catalog.rule.tech_templates.render_metadata import (  # type: ignore
            metadata_output_path,
        )
    except ImportError:
        discovery_output_path = check_rule_output_path = ciem_rule_output_path = metadata_output_path = None  # type: ignore

    def _write_yaml(path: "Path", content: str) -> None:
        """Create parent directories and write *content* to *path*."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    files_written = 0
    errors = 0

    for tech, sections in sorted(grouped.items()):
        print(f"\n── {tech_display_name(tech)} ({tech}) ──")

        # Collect all CIEM rows for the tech (across sections)
        all_ciem: list[ClassifiedRow] = []
        all_rows: list[ClassifiedRow] = []

        for section, classified_rows in sorted(sections.items()):
            check_rows = [r for r in classified_rows if r.output_type == OUTPUT_CHECK]
            ciem_rows = [r for r in classified_rows if r.output_type == OUTPUT_CIEM]
            all_ciem.extend(ciem_rows)
            all_rows.extend(classified_rows)

            if check_rows:
                # Discovery YAML
                try:
                    if render_discovery is not None:
                        result = render_discovery(
                            category=category,
                            tech=tech,
                            section=section,
                            rows=check_rows,
                        )
                        if result:
                            if not dry_run and discovery_output_path is not None:
                                out = discovery_output_path(category, tech, section)
                                _write_yaml(out, result)
                            files_written += 1
                    else:
                        raise NotImplementedError
                except NotImplementedError:
                    print(
                        f"  [STUB] {tech} section {section}"
                        f" — render_discovery not yet implemented"
                    )
                except Exception as exc:
                    print(f"  [ERROR] {tech} section {section} — {exc}")
                    errors += 1

                # Check rule YAML
                try:
                    if render_check_rules is not None:
                        result = render_check_rules(
                            category=category,
                            tech=tech,
                            section=section,
                            rows=check_rows,
                        )
                        if result:
                            if not dry_run and check_rule_output_path is not None:
                                out = check_rule_output_path(category, tech, section)
                                _write_yaml(out, result)
                            files_written += 1
                    else:
                        raise NotImplementedError
                except NotImplementedError:
                    print(
                        f"  [STUB] {tech} section {section}"
                        f" — render_check_rules not yet implemented"
                    )
                except Exception as exc:
                    print(f"  [ERROR] {tech} section {section} — {exc}")
                    errors += 1

        # CIEM YAML (per tech, all sections combined)
        if all_ciem:
            try:
                if render_ciem_rules is not None:
                    result = render_ciem_rules(
                        category=category,
                        tech=tech,
                        rows=all_ciem,
                    )
                    if result:
                        if not dry_run and ciem_rule_output_path is not None:
                            out = ciem_rule_output_path(category, tech)
                            _write_yaml(out, result)
                        files_written += 1
                else:
                    raise NotImplementedError
            except NotImplementedError:
                print(
                    f"  [STUB] {tech} — render_ciem_rules not yet implemented"
                )
            except Exception as exc:
                print(f"  [ERROR] {tech} (ciem) — {exc}")
                errors += 1

        # Metadata YAML (per tech, all rows)
        if all_rows:
            try:
                if render_metadata is not None:
                    result = render_metadata(
                        category=category,
                        tech=tech,
                        rows=all_rows,
                    )
                    if result:
                        if not dry_run and metadata_output_path is not None:
                            out = metadata_output_path(category, tech)
                            _write_yaml(out, result)
                        files_written += 1
                else:
                    raise NotImplementedError
            except NotImplementedError:
                print(
                    f"  [STUB] {tech} — render_metadata not yet implemented"
                )
            except Exception as exc:
                print(f"  [ERROR] {tech} (metadata) — {exc}")
                errors += 1

    return files_written, errors


# ─── CLI ──────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="generate_tech_rules",
        description="Generate YAML rule files from CIS Technology compliance CSV.",
    )
    parser.add_argument(
        "--category",
        required=True,
        metavar="CATEGORY",
        help=(
            "Benchmark category to process "
            "(e.g. linux, database, networking, web_server, container, "
            "virtualization, cloud_saas, devops, data)"
        ),
    )
    parser.add_argument(
        "--tech",
        default=None,
        metavar="TECH",
        help="Limit to one benchmark_subcategory within the category.",
    )
    parser.add_argument(
        "--section",
        default=None,
        metavar="SECTION",
        help='Limit to one section number (e.g. "1", "3").',
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary table only; do not write any files.",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Write output files (delegates to template renderers).",
    )
    return parser


def main() -> None:
    """Entry point for the tech rule generator.

    Raises:
        SystemExit(1): When neither or both of --dry-run / --apply are given.
    """
    parser = _build_parser()
    args = parser.parse_args()

    # Validate mode
    if not args.dry_run and not args.apply:
        parser.error(
            "Exactly one of --dry-run or --apply must be provided.\n"
            "  --dry-run   Print summary table without writing any files.\n"
            "  --apply     Write output files to disk."
        )

    print(f"Category : {args.category}")
    if args.tech:
        print(f"Tech     : {args.tech}")
    if args.section:
        print(f"Section  : {args.section}")
    print(f"Mode     : {'dry-run' if args.dry_run else 'apply'}")
    print()

    # Load and filter CSV
    if not CSV_PATH.exists():
        print(f"[ERROR] CSV not found: {CSV_PATH}", file=sys.stderr)
        sys.exit(1)

    rows, dedup_counts = load_and_dedup_csv(
        CSV_PATH, args.category, args.tech, args.section
    )

    if not rows:
        print(
            f"[WARN] No rows found for category={args.category!r}"
            + (f", tech={args.tech!r}" if args.tech else "")
            + (f", section={args.section!r}" if args.section else "")
        )
        print("Done. Written: 0 files. Errors: 0.")
        sys.exit(0)

    # Group and classify
    grouped, stats = group_and_classify(rows, dedup_counts)

    # Always print the summary table (even in --apply mode)
    print_summary_table(stats)

    if args.dry_run:
        total = sum(
            s[OUTPUT_CHECK] + s[OUTPUT_CIEM] + s[OUTPUT_MANUAL]
            for s in stats.values()
        )
        print(f"Dry run complete. {total} rows classified. 0 files written.")
        sys.exit(0)

    # --apply mode: import template renderers and write files
    render_discovery, render_check_rules, render_ciem_rules, render_metadata = (
        _import_templates()
    )

    files_written, errors = apply_writes(
        category=args.category,
        grouped=grouped,
        dry_run=args.dry_run,
        render_discovery=render_discovery,
        render_check_rules=render_check_rules,
        render_ciem_rules=render_ciem_rules,
        render_metadata=render_metadata,
    )

    print(f"\nDone. Written: {files_written} files. Errors: {errors}.")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
