#!/usr/bin/env python3
"""
Step-4: Field Index Generator
Build step4_fields_produced_index.json for each GCP service.

Inverted index:  field_path → producer ops (prefer independent producers)
                            → if producer is not independent, attach the
                              dependency chain that reaches an independent root.

INPUT (per service directory):
  step2_read_operation_registry.json
  step2_write_operation_registry.json   (optional)
  step3_read_operation_dependency_chain_independent.json

OUTPUT (per service directory):
  step4_fields_produced_index.json

SCHEMA:
{
  "csp": "gcp",
  "service": "...",
  "version": "...",
  "generated_at": "<iso8601>",
  "total_fields": <int>,
  "stats": {
    "preferred_independent": <int>,
    "preferred_chained": <int>,
    "preferred_unresolved": <int>,
    "total_producers": <int>
  },
  "fields": {
    "<field_path>": {
      "field_path": "<field_path>",
      "producers": [
        {
          "op": "...",
          "service": "...",
          "kind": "...",
          "independent": <bool>,
          "http": {"verb": "...", "path": "..."},
          "python_call": "...",
          "produces_type": "<type|null>",
          "is_id": <bool>,
          "score": <float>,
          "chain_to_independent": {
            "target_op": "...",
            "chain_length": <int>,
            "hop_distance": <int>,
            "execution_steps": [ ... ]
          } | null,
          "notes": "<optional>"
        }
      ],
      "preferred": {
        "strategy": "independent_first" | "shortest_chain" | "first_available",
        "op": "<chosen producer op>",
        "chain_to_independent": { ... } | null
      }
    }
  }
}
"""

import json
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from typing import Optional

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ─────────────────────────────────────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────────────────────────────────────

def score_producer(op_entry: dict) -> float:
    """
    Deterministic score for producer selection:
      +50  if independent
      +10  if kind == read_list
      +6   if kind == read_get
      +2   if kind starts with write_
      -N   chain_length if dependent and chain exists
      -20  if dependent and chain missing
    """
    s = 0.0
    if op_entry.get('independent', False):
        s += 50
    kind = op_entry.get('kind', '')
    if kind == 'read_list':
        s += 10
    elif kind == 'read_get':
        s += 6
    elif kind.startswith('write_'):
        s += 2

    if not op_entry.get('independent', False):
        chain = op_entry.get('chain_to_independent')
        if chain:
            s -= chain.get('chain_length', 0)
        else:
            s -= 20

    return s


# ─────────────────────────────────────────────────────────────────────────────
# PREFERRED SELECTION
# ─────────────────────────────────────────────────────────────────────────────

def choose_preferred(producers: list[dict]) -> dict:
    """
    Rules:
    1. Any independent producer → pick highest score among them (independent_first)
    2. No independent → pick smallest chain_length (shortest_chain)
    3. Fallback → first_available
    """
    if not producers:
        return {'strategy': 'first_available', 'op': None, 'chain_to_independent': None}

    independent_prods = [p for p in producers if p.get('independent')]
    if independent_prods:
        best = max(independent_prods, key=lambda p: (p['score'], -ord(p['op'][0])))
        # tie-break on lex smallest op
        best = min(
            [p for p in independent_prods if p['score'] == best['score']],
            key=lambda p: p['op'],
        )
        return {
            'strategy': 'independent_first',
            'op': best['op'],
            'chain_to_independent': None,
        }

    # No independent — pick shortest chain
    chained = [p for p in producers if p.get('chain_to_independent') is not None]
    if chained:
        best = min(chained, key=lambda p: (
            p['chain_to_independent'].get('chain_length', 999),
            p['op'],
        ))
        return {
            'strategy': 'shortest_chain',
            'op': best['op'],
            'chain_to_independent': best['chain_to_independent'],
        }

    # Fallback
    best = min(producers, key=lambda p: p['op'])
    return {
        'strategy': 'first_available',
        'op': best['op'],
        'chain_to_independent': best.get('chain_to_independent'),
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN INDEX BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_fields_index_for_service(
    read_path: Path,
    write_path: Optional[Path],
    chains_path: Optional[Path],
) -> dict | None:
    """Build step4_fields_produced_index.json for a single service."""
    if not read_path.exists():
        return None

    s2r = json.load(open(read_path))
    ops_read  = s2r.get('operations', {})
    service   = s2r.get('service', read_path.parent.name)
    version   = s2r.get('version', '')

    # Merge write registry ops (optional)
    ops_write = {}
    if write_path and write_path.exists():
        s2w = json.load(open(write_path))
        ops_write = s2w.get('operations', {})

    all_ops = {**ops_read, **ops_write}
    if not all_ops:
        return None

    # Load step3 chains
    chains_by_op: dict[str, dict] = {}
    if chains_path and chains_path.exists():
        s3 = json.load(open(chains_path))
        chains_by_op = s3.get('chains', {})

    # ── Build inverted field index ─────────────────────────────────────────
    # field_path → list of raw producer records
    field_producers: dict[str, list] = defaultdict(list)

    for op_key, op in all_ops.items():
        kind        = op.get('kind', '')
        independent = op.get('independent', False)
        http_info   = op.get('http', {})
        python_call = op.get('python_call', '')
        outputs     = op.get('outputs', {})
        produces    = outputs.get('produces_fields', [])

        # Chain from step3 (only meaningful for dependent ops)
        chain_entry = None
        if not independent:
            c = chains_by_op.get(op_key)
            if c:
                chain_entry = {
                    'target_op':       c.get('target_op', op_key),
                    'chain_length':    c.get('chain_length', 1),
                    'hop_distance':    c.get('hop_distance', 999),
                    'execution_steps': c.get('execution_steps', []),
                }

        # Add every produces_field path
        for pf in produces:
            field_path   = pf.get('path', '')
            produces_type = pf.get('type', None)
            is_id        = pf.get('is_id', False)
            if not field_path:
                continue

            notes = pf.get('note', '')
            if not independent and chain_entry is None:
                notes = (notes + ' | missing_chain').strip(' |')

            field_producers[field_path].append({
                'op':          op_key,
                'service':     service,
                'kind':        kind,
                'independent': independent,
                'http': {
                    'verb': http_info.get('verb', 'GET'),
                    'path': http_info.get('path', ''),
                },
                'python_call':   python_call,
                'produces_type': produces_type,
                'is_id':         is_id,
                '_chain':        chain_entry,  # temp key, removed after scoring
                'notes':         notes,
            })

        # Also synthesize list_field[].id_field if outputs have it and it's
        # not already in produces_fields
        list_field = outputs.get('list_field')
        id_field   = outputs.get('id_field')
        if list_field and id_field and kind == 'read_list':
            synthetic_path = f'{list_field}[].{id_field}'
            # Only add if not already present
            existing_paths = {pf.get('path', '') for pf in produces}
            if synthetic_path not in existing_paths:
                notes = (
                    f'synthetic: Iterate response["{list_field}"][], '
                    f'extract item["{id_field}"]'
                )
                field_producers[synthetic_path].append({
                    'op':          op_key,
                    'service':     service,
                    'kind':        kind,
                    'independent': independent,
                    'http': {
                        'verb': http_info.get('verb', 'GET'),
                        'path': http_info.get('path', ''),
                    },
                    'python_call':   python_call,
                    'produces_type': 'string',
                    'is_id':         True,
                    '_chain':        chain_entry,
                    'notes':         notes,
                })

    # ── Build final fields dict ────────────────────────────────────────────
    result_fields: dict[str, dict] = {}
    total_producers = 0

    for field_path in sorted(field_producers.keys()):
        raw_list = field_producers[field_path]

        # Score each producer
        for entry in raw_list:
            entry['chain_to_independent'] = entry.pop('_chain')
            entry['score'] = score_producer(entry)

        # Sort: highest score first, then lexicographic op name for ties
        producers = sorted(
            raw_list,
            key=lambda p: (-p['score'], p['op']),
        )

        preferred = choose_preferred(producers)
        total_producers += len(producers)

        result_fields[field_path] = {
            'field_path': field_path,
            'producers':  producers,
            'preferred':  preferred,
        }

    if not result_fields:
        return None

    # ── Stats ─────────────────────────────────────────────────────────────
    n_ind = sum(
        1 for f in result_fields.values()
        if f['preferred']['strategy'] == 'independent_first'
    )
    n_chain = sum(
        1 for f in result_fields.values()
        if f['preferred']['strategy'] == 'shortest_chain'
    )
    n_first = sum(
        1 for f in result_fields.values()
        if f['preferred']['strategy'] == 'first_available'
    )

    return {
        'csp':          'gcp',
        'service':      service,
        'version':      version,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'total_fields': len(result_fields),
        'stats': {
            'preferred_independent': n_ind,
            'preferred_chained':     n_chain,
            'preferred_unresolved':  n_first,
            'total_producers':       total_producers,
        },
        'fields': result_fields,
    }


# ─────────────────────────────────────────────────────────────────────────────
# RUN ALL SERVICES
# ─────────────────────────────────────────────────────────────────────────────

def run_all():
    """Run for every service under BASE_DIR."""
    print('=' * 70)
    print('Building step4_fields_produced_index.json for all GCP services')
    print('=' * 70)

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step2_read_operation_registry.json').exists()
    )

    built = skipped = 0
    total_fields = total_prods = 0
    grand_ind = grand_chain = grand_first = 0

    for svc_dir in all_dirs:
        read_path   = svc_dir / 'step2_read_operation_registry.json'
        write_path  = svc_dir / 'step2_write_operation_registry.json'
        chains_path = svc_dir / 'step3_read_operation_dependency_chain_independent.json'

        result = build_fields_index_for_service(read_path, write_path, chains_path)
        if not result:
            print(f'  ⏭  {svc_dir.name}: nothing to index')
            skipped += 1
            continue

        out_path = svc_dir / 'step4_fields_produced_index.json'
        with open(out_path, 'w') as f:
            json.dump(result, f, indent=2)

        stats = result['stats']
        built        += 1
        total_fields += result['total_fields']
        total_prods  += stats['total_producers']
        grand_ind    += stats['preferred_independent']
        grand_chain  += stats['preferred_chained']
        grand_first  += stats['preferred_unresolved']

        print(f'  ✓ {svc_dir.name:42s} '
              f'{result["total_fields"]:5d} fields  '
              f'ind={stats["preferred_independent"]:4d}  '
              f'chain={stats["preferred_chained"]:4d}  '
              f'unresolved={stats["preferred_unresolved"]:3d}')

    print()
    print('=' * 70)
    print(f'Services built   : {built}')
    print(f'Skipped          : {skipped}')
    print(f'Total fields     : {total_fields}')
    print(f'Total producers  : {total_prods}')
    print(f'Preferred independent : {grand_ind}')
    print(f'Preferred chained     : {grand_chain}')
    print(f'Preferred unresolved  : {grand_first}')
    print('=' * 70)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def run_cli():
    parser = argparse.ArgumentParser(
        description='Build Step-4 Field Index for GCP operations'
    )
    parser.add_argument(
        '--read', type=Path,
        help='Path to step2_read_operation_registry.json',
    )
    parser.add_argument(
        '--write', type=Path, default=None,
        help='Path to step2_write_operation_registry.json (optional)',
    )
    parser.add_argument(
        '--chains', type=Path, default=None,
        help='Path to step3_read_operation_dependency_chain_independent.json',
    )
    parser.add_argument(
        '--out', type=Path,
        help='Output path for step4_fields_produced_index.json',
    )
    parser.add_argument(
        '--all', action='store_true',
        help='Run for all services under BASE_DIR (ignores other args)',
    )

    args = parser.parse_args()

    if args.all or (not args.read and not args.out):
        run_all()
        return

    if not args.read or not args.out:
        parser.print_help()
        sys.exit(1)

    result = build_fields_index_for_service(args.read, args.write, args.chains)
    if not result:
        print('ERROR: no fields produced — check input files')
        sys.exit(1)

    with open(args.out, 'w') as f:
        json.dump(result, f, indent=2)

    stats = result['stats']
    print(f'Written: {args.out}')
    print(f'  Total fields     : {result["total_fields"]}')
    print(f'  Total producers  : {stats["total_producers"]}')
    print(f'  Preferred independent : {stats["preferred_independent"]}')
    print(f'  Preferred chained     : {stats["preferred_chained"]}')
    print(f'  Preferred unresolved  : {stats["preferred_unresolved"]}')

    # Print first 2 fields as example snippet
    fields = result.get('fields', {})
    print('\n── Example output (first 2 fields) ──')
    for i, (fp, fdata) in enumerate(list(fields.items())[:2]):
        print(json.dumps({fp: fdata}, indent=2)[:800])
        if i < 1:
            print('...')


if __name__ == '__main__':
    run_cli()
