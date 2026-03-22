#!/usr/bin/env python3
"""
Rename files in each GCP service folder with step prefix based on pipeline sequence.

Sequence:
  step1  — operation_registry.json
  step2  — {service}_discovery.yaml
  step3  — gcp_dependencies_with_python_names_fully_enriched.json
  step4  — minimal_operations_list.json
  step5  — resource_inventory_report.json
  step6  — resource_operations_prioritized.json
  step7  — name_identifier.json
  step8  — dependency_index.json
  step9  — adjacency.json
  step10 — direct_vars.json
  step11 — field_operator_value_table.csv
  step12 — validation_report.json
"""

import os
import re
from pathlib import Path

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# Ordered step mapping — (step_label, match_pattern)
# Pattern is either an exact filename or a regex for service-named files
STEP_MAP = [
    ('step1',  'operation_registry.json'),
    ('step2',  r'.+_discovery\.yaml'),              # {service}_discovery.yaml
    ('step3',  'gcp_dependencies_with_python_names_fully_enriched.json'),
    ('step4',  'minimal_operations_list.json'),
    ('step5',  'resource_inventory_report.json'),
    ('step6',  'resource_operations_prioritized.json'),
    ('step7',  'name_identifier.json'),
    ('step8',  'dependency_index.json'),
    ('step9',  'adjacency.json'),
    ('step10', 'direct_vars.json'),
    ('step11', 'field_operator_value_table.csv'),
    ('step12', 'validation_report.json'),
]

# Pre-compile regex patterns
def match_step(filename: str) -> str:
    """Return the step label for a given filename, or '' if not matched."""
    for step, pattern in STEP_MAP:
        if pattern.startswith('.') or '*' in pattern or '+' in pattern or '\\' in pattern:
            if re.fullmatch(pattern, filename):
                return step
        else:
            if filename == pattern:
                return step
    return ''


def rename_service(service_dir: Path, dry_run: bool = False) -> int:
    renamed = 0
    for fpath in sorted(service_dir.iterdir()):
        if not fpath.is_file():
            continue
        fname = fpath.name

        # Skip files already prefixed
        if re.match(r'^step\d+_', fname):
            continue

        step = match_step(fname)
        if not step:
            continue  # unknown file — leave untouched

        new_name = f"{step}_{fname}"
        new_path = fpath.parent / new_name

        if not dry_run:
            fpath.rename(new_path)
        else:
            print(f"  [DRY] {fname}  →  {new_name}")

        renamed += 1
    return renamed


def run(dry_run: bool = False):
    print("=" * 70)
    print(f"GCP service file renamer  {'[DRY RUN]' if dry_run else '[LIVE]'}")
    print("=" * 70)

    service_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and not d.name.endswith('.py')
        and not d.name.endswith('.md')
    )

    total_renamed = 0
    for sdir in service_dirs:
        count = rename_service(sdir, dry_run=dry_run)
        if count:
            total_renamed += count
            if dry_run:
                print(f"  {sdir.name}: {count} files")

    print()
    print(f"Total files {'to rename' if dry_run else 'renamed'}: {total_renamed}")
    print("=" * 70)


if __name__ == '__main__':
    import sys
    dry = '--dry-run' in sys.argv
    run(dry_run=dry)
