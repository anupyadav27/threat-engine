#!/usr/bin/env python3
"""
Split step1_operation_registry.json into:
  - step2_read_operation_registry.json  (read_list, read_get, other)
  - step2_write_operation_registry.json (write_create, write_update, write_delete, write_apply)

Works for ALL services regardless of step1 format (new or old).
Overwrites any existing step2 files.
"""

import json
from pathlib import Path

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

READ_KINDS  = {'read_list', 'read_get', 'other'}
WRITE_KINDS = {'write_create', 'write_update', 'write_delete', 'write_apply'}

def split_service(svc_dir: Path) -> dict:
    step1_path = svc_dir / 'step1_operation_registry.json'
    if not step1_path.exists():
        return {'status': 'skip', 'reason': 'no step1'}

    data = json.load(open(step1_path))
    ops  = data.get('operations', {})
    if not ops:
        return {'status': 'skip', 'reason': 'empty ops'}

    read_ops  = {k: v for k, v in ops.items() if v.get('kind', '') in READ_KINDS}
    write_ops = {k: v for k, v in ops.items() if v.get('kind', '') in WRITE_KINDS}

    # Build common header fields
    header = {
        'service':     data.get('service', svc_dir.name),
        'version':     data.get('version', ''),
        'csp':         data.get('csp', 'gcp'),
        'title':       data.get('title', ''),
        'description': data.get('description', ''),
        'documentation': data.get('documentation', data.get('documentationLink', '')),
        'base_url':    data.get('base_url', data.get('baseUrl', '')),
        'data_source': data.get('data_source', 'unknown'),
    }

    # Write step2_read
    read_registry = {
        **header,
        'total_operations': len(read_ops),
        'operations': read_ops,
    }
    with open(svc_dir / 'step2_read_operation_registry.json', 'w') as f:
        json.dump(read_registry, f, indent=2)

    # Write step2_write
    write_registry = {
        **header,
        'total_operations': len(write_ops),
        'operations': write_ops,
    }
    with open(svc_dir / 'step2_write_operation_registry.json', 'w') as f:
        json.dump(write_registry, f, indent=2)

    return {'status': 'ok', 'read': len(read_ops), 'write': len(write_ops)}


def run():
    print('=' * 70)
    print('Splitting step1 → step2_read + step2_write for all services')
    print('=' * 70)
    print()

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step1_operation_registry.json').exists()
    )

    total_services = total_read = total_write = 0
    skipped = []

    for svc_dir in all_dirs:
        result = split_service(svc_dir)
        if result['status'] == 'skip':
            skipped.append((svc_dir.name, result['reason']))
            continue
        total_services += 1
        total_read     += result['read']
        total_write    += result['write']
        print(f'  ✓ {svc_dir.name}: {result["read"]} read / {result["write"]} write')

    print()
    print('=' * 70)
    print(f'Services split:    {total_services}')
    print(f'Total read ops:    {total_read}')
    print(f'Total write ops:   {total_write}')
    print(f'Total ops:         {total_read + total_write}')
    if skipped:
        print(f'Skipped:           {len(skipped)}')
        for s, r in skipped:
            print(f'  {s}: {r}')
    print('=' * 70)


if __name__ == '__main__':
    run()
