#!/usr/bin/env python3
"""
validate_aws_check_vars_vs_discovery.py
=========================================
For every AWS check rule, verify that the `var:` field it checks is
actually emitted by the corresponding final_discovery_v1.yaml.

Logic:
  rule.var = "item.Tags"
    → top-level field = "Tags"
    → PASS if "Tags" in emit.item keys for that op
    → also PASS if op has no item block (stub — runtime-only)

Exit code: 0 if no hard misses, 1 if there are MISS entries.
"""

import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
CHECK_DIR = ROOT / 'catalog/rule/aws_rule_check'
GEN_DIR   = ROOT / 'catalog/discovery_generator/aws'

SERVICE_ALIASES: Dict[str, str] = {'acm_pca': 'acm-pca'}
# ──────────────────────────────────────────────────────────────────────────────


def _load_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}


# ── 1. Extract all var paths from a conditions block (handles nested all/any) ─

def extract_vars(conditions) -> List[str]:
    if not conditions:
        return []
    if isinstance(conditions, dict):
        if 'var' in conditions:
            return [conditions['var']]
        result = []
        for key in ('all', 'any', 'not'):
            sub = conditions.get(key)
            if isinstance(sub, list):
                for item in sub:
                    result.extend(extract_vars(item))
            elif isinstance(sub, dict):
                result.extend(extract_vars(sub))
        return result
    if isinstance(conditions, list):
        result = []
        for c in conditions:
            result.extend(extract_vars(c))
        return result
    return []


# ── 2. Load check rules for a service → {for_each_op: [var_path, ...]} ───────

def load_check_vars(svc: str) -> Dict[str, List[str]]:
    f = CHECK_DIR / svc / f'{svc}.checks.yaml'
    if not f.exists():
        return {}
    data   = _load_yaml(f)
    result: Dict[str, List[str]] = defaultdict(list)
    for rule in data.get('checks', []):
        fe   = rule.get('for_each', '')
        cond = rule.get('conditions')
        if fe and cond:
            for v in extract_vars(cond):
                if v and v not in result[fe]:
                    result[fe].append(v)
    return dict(result)


# ── 3. Load ALL emit fields across ALL final_discovery yamls (global index) ───

def load_all_emit_fields() -> Dict[str, Set[str]]:
    """
    Scan ALL final_discovery_v1.yaml files and build a global index:
      {discovery_id → set_of_top_level_keys_in_emit_item}
    Stub/empty ops flagged with '__stub__'.
    """
    result: Dict[str, Set[str]] = {}
    for yaml_path in GEN_DIR.glob('*/final_discovery_v1.yaml'):
        data = _load_yaml(yaml_path)
        for disc in data.get('discovery', []):
            did  = disc.get('discovery_id', '')
            if not did:
                continue
            emit = disc.get('emit', {})
            item = emit.get('item', {})
            items_for = emit.get('items_for', '')

            if not item and not items_for:
                # No emitted item structure — stub, can't static-verify
                result[did] = {'__stub__'}
            elif not item:
                # Has items_for but no item fields — also stub
                result[did] = {'__stub__'}
            else:
                keys: Set[str] = set()
                for field_key in item.keys():
                    top = field_key.split('.')[0].split('[')[0]
                    keys.add(top)
                    keys.add(field_key)
                result[did] = keys
    return result


# ── 4. Check a var against emit fields ───────────────────────────────────────

def check_var(var: str, emit_keys: Set[str]) -> str:
    """
    Returns 'PASS', 'STUB' (stub op — can't statically verify), or 'MISS'.
    """
    if '__stub__' in emit_keys:
        return 'STUB'

    # Special: bare "item" reference → always valid (uses the whole item object)
    if var.strip() == 'item':
        return 'PASS'

    # Strip leading "item." prefix
    path = var.removeprefix('item.').strip()
    top  = path.split('.')[0].split('[')[0]

    # Direct match: top-level key present in emit
    if top in emit_keys or path in emit_keys or var in emit_keys:
        return 'PASS'

    # Special: Tags.key patterns → Tags is the top-level
    if top == 'Tags' and 'Tags' in emit_keys:
        return 'PASS'

    return 'MISS'


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

check_services = sorted(d.name for d in CHECK_DIR.iterdir() if d.is_dir())

# Counters
total_vars = pass_count = miss_count = stub_count = skip_count = 0

miss_details: List[Tuple[str, str, str, str]] = []  # (svc, op, var, reason)
stub_details: List[Tuple[str, str, str]]       = []  # (svc, op, var)

svc_summary: List[Tuple[str, str, int, int, int, int]] = []

# Load global emit index once
global_emit_fields = load_all_emit_fields()
print(f'Global discovery index: {len(global_emit_fields)} ops across all services\n')

for svc in check_services:
    gen_svc    = SERVICE_ALIASES.get(svc, svc)
    check_vars = load_check_vars(svc)

    if not check_vars:
        continue   # empty / no check rules

    svc_pass = svc_miss = svc_stub = svc_skip = 0

    for op, vars_ in check_vars.items():
        # Global lookup — op might be in a different service's discovery yaml
        keys = global_emit_fields.get(op, set())

        if not keys:
            # Try dash↔underscore normalization (e.g. acm-pca ↔ acm_pca)
            alt_op = op.replace('-', '_') if '-' in op else op.replace('_', '-', 1)
            keys = global_emit_fields.get(alt_op, set())

        if not keys:
            # op not in ANY final_discovery yaml
            for v in vars_:
                svc_skip += 1
                skip_count += 1
            continue

        for v in vars_:
            total_vars += 1
            result = check_var(v, keys)
            if result == 'PASS':
                svc_pass += 1
                pass_count += 1
            elif result == 'STUB':
                svc_stub += 1
                stub_count += 1
                stub_details.append((svc, op, v))
            else:
                svc_miss += 1
                miss_count += 1
                miss_details.append((svc, op, v, f'top={v.removeprefix("item.").split(".")[0]} not in emit'))

    svc_summary.append((svc, gen_svc, svc_pass, svc_miss, svc_stub, svc_skip))


# ── Print report ──────────────────────────────────────────────────────────────

print('═' * 75)
print('AWS  Check-rule var → discovery emit field validation')
print('═' * 75)
print(f'{"Service":<28} {"Gen-svc":<22} {"PASS":>5} {"MISS":>5} {"STUB":>5} {"SKIP":>5}')
print('-' * 75)

for svc, gen_svc, sp, sm, sa, ss in svc_summary:
    flag = ' !' if sm > 0 else ''
    print(f'{svc:<28} {gen_svc:<22} {sp:>5} {sm:>5} {sa:>5} {ss:>5}{flag}')

print('═' * 75)
print(f'{"TOTAL":<28} {"":<22} {pass_count:>5} {miss_count:>5} {stub_count:>5} {skip_count:>5}')
print()
print('Legend: PASS=field in emit  MISS=field not found  STUB=stub op(runtime-only)  SKIP=no discovery yaml')

if miss_details:
    print()
    print('─' * 75)
    print('MISSES — check-rule vars not found in discovery emit:')
    print('─' * 75)
    last_svc = ''
    for svc, op, var, reason in sorted(miss_details):
        if svc != last_svc:
            print(f'\n  [{svc}]')
            last_svc = svc
        print(f'    op={op}')
        print(f'    var={var}  ({reason})')

if stub_details and '--show-stubs' in sys.argv:
    print()
    print('─' * 75)
    print('STUB — ops with no emit.item (fields verified at runtime, not statically):')
    print('─' * 75)
    for svc, op, var in stub_details[:30]:
        print(f'  [{svc}] {op}  var={var}')
    if len(stub_details) > 30:
        print(f'  ... and {len(stub_details)-30} more')

print()
sys.exit(1 if miss_count > 0 else 0)
