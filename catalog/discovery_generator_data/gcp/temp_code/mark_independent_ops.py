#!/usr/bin/env python3
"""
Mark each operation in step2_read_operation_registry.json as
  "independent": true   — all required_params are ALWAYS_AVAILABLE
                          (no prior API call needed; op is a root)
  "independent": false  — consumes entities or has required_params
                          that must come from a prior API call

Rewrites step2_read_operation_registry.json in-place for every service.
"""

import json
from pathlib import Path

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# Params GCP always has from context — no prior API call needed
ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent', 'name',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId',
    'customerId',
}


def mark_service(svc_dir: Path) -> tuple[int, int] | None:
    """
    Returns (independent_count, dependent_count) or None if no registry.
    """
    read_path = svc_dir / 'step2_read_operation_registry.json'
    if not read_path.exists():
        return None

    reg = json.load(open(read_path))
    ops = reg.get('operations', {})
    if not ops:
        return None

    independent = dependent = 0

    for op_key, op in ops.items():
        req = op.get('required_params', []) or []
        consumes = op.get('consumes', []) or []

        # Check if any consumes entry has required=True and an entity that
        # is NOT always available (i.e. must come from another op)
        has_external_consume = any(
            c.get('required', False) and
            c.get('param', '') not in ALWAYS_AVAILABLE
            for c in consumes
        )

        # Root = all required_params are ALWAYS_AVAILABLE AND no external consumes
        is_independent = (
            all(p in ALWAYS_AVAILABLE for p in req)
            and not has_external_consume
        )

        op['independent'] = is_independent

        if is_independent:
            independent += 1
        else:
            dependent += 1

    # Write back
    with open(read_path, 'w') as f:
        json.dump(reg, f, indent=2)

    return independent, dependent


def run():
    print('=' * 70)
    print('Marking independent/dependent in step2_read_operation_registry.json')
    print('=' * 70)

    service_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
    )

    processed = skipped = 0
    total_independent = total_dependent = 0

    for sdir in service_dirs:
        result = mark_service(sdir)
        if result is None:
            skipped += 1
            continue

        ind, dep = result
        total_independent += ind
        total_dependent   += dep
        processed += 1
        print(f'  ✓ {sdir.name}: {ind} independent, {dep} dependent')

    print()
    print(f'Processed:        {processed} services')
    print(f'Skipped:          {skipped} (no read registry)')
    print(f'Total independent:{total_independent}')
    print(f'Total dependent:  {total_dependent}')
    print(f'Total read ops:   {total_independent + total_dependent}')
    print('=' * 70)


if __name__ == '__main__':
    run()
