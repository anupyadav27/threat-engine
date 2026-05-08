#!/usr/bin/env python3
"""
Enrich step2_read_operation_registry.json with resource path information.

For each operation, add at the TOP LEVEL:
  "resource_path":    "//compute.googleapis.com/projects/{project}/zones/{zone}/disks/{disk}"
  "resource_id_param": "disk"           (the last path param — the resource's own identifier)
  "parent_params":    ["project","zone"] (the hierarchy above it, in order)

This allows building a GCP full resource name (GRN / ARN equivalent) for any resource:
  //compute.googleapis.com/projects/my-project/zones/us-central1-a/disks/my-disk

The resource_path comes from the operation's HTTP path, which IS the resource address.
For list ops: the path is the collection path (no resource ID param at end).
For get ops:  the path is the individual resource path (resource ID param at end).

source values in produces[]:
  "output" → the list/collection field (e.g. response.datasets — what you iterate over)
  "item"   → a field on each individual resource item (e.g. item.diskType)

The entity identifier should match the resource's own ID param path for lookup.
"""

import json
import re
from pathlib import Path

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')


def clean_path(path: str) -> str:
    """Remove version prefix and method suffix, normalize {+param} → {param}."""
    # Remove version prefix: v1/, v2/, v1beta1/, etc.
    path = re.sub(r'^v\d+[a-zA-Z0-9]*/', '', path)
    # Remove method suffix like :batchGet, :getIamPolicy
    path = re.sub(r':[a-zA-Z]+$', '', path)
    # Normalize {+param} → {param}
    path = re.sub(r'\{\+(\w+)\}', r'{\1}', path)
    return path


def extract_path_params(path: str) -> list[str]:
    """Extract all {param} names from a path in order."""
    return re.findall(r'\{[+]?(\w+)\}', path)


def build_resource_path(service: str, path: str) -> str:
    """Build GCP full resource name pattern (ARN equivalent).

    Format: //service.googleapis.com/clean_path
    e.g.  //compute.googleapis.com/projects/{project}/zones/{zone}/disks/{disk}
    """
    clean = clean_path(path)
    if clean:
        return f'//{service}.googleapis.com/{clean}'
    return f'//{service}.googleapis.com'


def enrich_service(svc_dir: Path) -> tuple[int, int] | None:
    """
    Returns (ops_enriched, ops_skipped) or None if no registry.
    """
    read_path = svc_dir / 'step2_read_operation_registry.json'
    if not read_path.exists():
        return None

    reg = json.load(open(read_path))
    ops = reg.get('operations', {})
    if not ops:
        return None

    service = reg.get('service', svc_dir.name)
    enriched = skipped = 0

    for op_key, op in ops.items():
        http_path = op.get('path', '')
        if not http_path:
            skipped += 1
            continue

        # Build resource_path: full GCP resource name pattern
        resource_path = build_resource_path(service, http_path)

        # Extract path params in order
        params = extract_path_params(http_path)

        # resource_id_param = last path param (the resource's own ID)
        # e.g. {disk} in projects/{project}/zones/{zone}/disks/{disk}
        resource_id_param = params[-1] if params else None

        # parent_params = all path params before the last one (the hierarchy)
        # e.g. [project, zone] for the disk example above
        parent_params = params[:-1] if len(params) > 1 else []

        # Add to op — insert after 'path' key for readability
        op['resource_path']     = resource_path
        op['resource_id_param'] = resource_id_param
        op['parent_params']     = parent_params

        enriched += 1

    # Write back
    with open(read_path, 'w') as f:
        json.dump(reg, f, indent=2)

    return enriched, skipped


def run():
    print('=' * 70)
    print('Enriching step2_read_operation_registry.json with resource paths')
    print('=' * 70)

    service_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
    )

    processed = skipped_svc = 0
    total_enriched = total_skipped = 0

    for sdir in service_dirs:
        result = enrich_service(sdir)
        if result is None:
            skipped_svc += 1
            continue

        enc, skp = result
        total_enriched += enc
        total_skipped  += skp
        processed += 1
        status = f'{enc} ops enriched'
        if skp:
            status += f', {skp} skipped (no path)'
        print(f'  ✓ {sdir.name}: {status}')

    print()
    print(f'Processed:       {processed} services')
    print(f'Skipped:         {skipped_svc} (no read registry)')
    print(f'Ops enriched:    {total_enriched}')
    print(f'Ops skipped:     {total_skipped}')
    print('=' * 70)

    # Show example output
    print()
    print('── Example output (compute/disks.get) ──────────────────────────────')
    ex = Path('/Users/apple/Desktop/data_pythonsdk/gcp/compute/step2_read_operation_registry.json')
    if ex.exists():
        d = json.load(open(ex))
        op = d['operations'].get('gcp.compute.disks.get', {})
        for field in ['path', 'resource_path', 'resource_id_param', 'parent_params', 'required_params']:
            print(f'  {field}: {op.get(field)}')
    print()
    print('── Example output (bigquery/datasets.list) ─────────────────────────')
    ex2 = Path('/Users/apple/Desktop/data_pythonsdk/gcp/bigquery/step2_read_operation_registry.json')
    if ex2.exists():
        d2 = json.load(open(ex2))
        op2 = d2['operations'].get('gcp.bigquery.datasets.list', {})
        for field in ['path', 'resource_path', 'resource_id_param', 'parent_params', 'required_params']:
            print(f'  {field}: {op2.get(field)}')
    print()
    print('── Example output (adexperiencereport/sites.get) ───────────────────')
    ex3 = Path('/Users/apple/Desktop/data_pythonsdk/gcp/adexperiencereport/step2_read_operation_registry.json')
    if ex3.exists():
        d3 = json.load(open(ex3))
        op3 = d3['operations'].get('gcp.adexperiencereport.sites.get', {})
        for field in ['path', 'resource_path', 'resource_id_param', 'parent_params', 'required_params']:
            print(f'  {field}: {op3.get(field)}')


if __name__ == '__main__':
    run()
