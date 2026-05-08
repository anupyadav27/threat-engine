#!/usr/bin/env python3
"""
generate_master_read_ops.py
============================
Build {csp}_master_read_ops.csv for every supported CSP.

One row per unique read operation per CSP.

Sources (per CSP):
  1. {csp}_master_field_catalog.csv  → op metadata, fields, types, operators,
                                       chain_ops_with_fields
  2. final_discovery_v1.yaml files   → resource_type + resource_id_param (RII)
     (AWS, GCP, K8s only — others have no RII yaml)
  3. *.checks.yaml files             → rule_count + check_rule_yaml
     (AliCloud: step7_*.checks.yaml in discovery_generator/
      IBM: no check rules — CIEM only)

Output columns (23) per CSP:
  csp, service, producing_op, op_kind, is_independent,
  root_op, chain_ops, chain_length, hop_distance,
  chain_ops_with_fields,
  python_call, http_path,
  produced_fields,        ← unique field names, pipe-sep
  fields_types,           ← FieldName:type, pipe-sep
  fields_operators,       ← FieldName:op1,op2,op3, pipe-sep
  resource_type, resource_id_field, resource_id_param,
  rule_count, check_rule_yaml,
  is_active, updated_at

Usage:
    python generate_master_read_ops.py                     # all CSPs, dry-run
    python generate_master_read_ops.py --apply             # all CSPs, write
    python generate_master_read_ops.py --csp aws           # single CSP, dry-run
    python generate_master_read_ops.py --csp gcp --apply   # single CSP, write
Rule data (rule_count, check_rule_yaml) is intentionally left empty by default.
Run with --with-rules to populate those columns from *.checks.yaml files.
"""

import csv
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import yaml

# ──────────────────────────────────────────────────────────────────────────────
ROOT      = Path('/Users/apple/Desktop/threat-engine')
GEN_DIR   = ROOT / 'catalog/discovery_generator'
RULE_DIR  = ROOT / 'catalog/rule'

COLUMNS = [
    'csp', 'service', 'producing_op', 'op_kind', 'is_independent',
    'root_op', 'chain_ops', 'chain_length', 'hop_distance',
    'chain_ops_with_fields',
    'python_call', 'http_path',
    'produced_fields',
    'fields_types',
    'fields_operators',
    'resource_type', 'resource_id_field', 'resource_id_param',
    'rule_count', 'check_rule_yaml',
    'is_active', 'updated_at',
]

META_COLS = [
    'csp', 'service', 'op_kind', 'is_independent',
    'root_op', 'chain_ops', 'chain_length', 'hop_distance',
    'chain_ops_with_fields',
    'python_call', 'http_path',
]

# ──────────────────────────────────────────────────────────────────────────────
# CSP config: describes where each CSP's sources live
# ──────────────────────────────────────────────────────────────────────────────
# rii_yaml_name: filename pattern for discovery yaml containing RII block
#   'final_discovery_v1.yaml'  → AWS, GCP, K8s  (in {csp_dir}/{svc}/)
#   None                       → no RII yaml for this CSP
# rii_id_param_field: field in each RII entry that maps to resource_id_param
#   AWS has 'resource_id_param'; GCP/K8s use 'identifier_field'
# check_rule_base: base dir for *.checks.yaml files
# check_rule_pattern: glob relative to check_rule_base to find check files
#   '{svc}/{svc}.checks.yaml'   → standard rule_check dirs
#   None                        → no CSPM check rules (IBM)
# alicloud_checks: special flag — step7 files live in discovery_generator

CSP_CONFIG: Dict[str, dict] = {
    'aws': {
        'master_csv':          GEN_DIR / 'aws/aws_master_field_catalog.csv',
        'output_csv':          GEN_DIR / 'aws/aws_master_read_ops.csv',
        'csp_gen_dir':         GEN_DIR / 'aws',
        'rii_yaml_name':       'final_discovery_v1.yaml',
        'rii_id_param_field':  'resource_id_param',
        'check_rule_dir':      RULE_DIR / 'aws_rule_check',
        'check_rule_pattern':  '{svc}/{svc}.checks.yaml',
        'alicloud_checks':     False,
    },
    'azure': {
        'master_csv':          GEN_DIR / 'azure/azure_master_field_catalog.csv',
        'output_csv':          GEN_DIR / 'azure/azure_master_read_ops.csv',
        'csp_gen_dir':         GEN_DIR / 'azure',
        'rii_yaml_name':       None,
        'rii_id_param_field':  None,
        'check_rule_dir':      RULE_DIR / 'azure_rule_check',
        'check_rule_pattern':  '{svc}/{svc}.checks.yaml',
        'alicloud_checks':     False,
    },
    'gcp': {
        'master_csv':          GEN_DIR / 'gcp/gcp_master_field_catalog.csv',
        'output_csv':          GEN_DIR / 'gcp/gcp_master_read_ops.csv',
        'csp_gen_dir':         GEN_DIR / 'gcp',
        'rii_yaml_name':       'final_discovery_v1.yaml',
        'rii_id_param_field':  'identifier_field',
        'check_rule_dir':      RULE_DIR / 'gcp_rule_check',
        'check_rule_pattern':  '{svc}/{svc}.checks.yaml',
        'alicloud_checks':     False,
    },
    'oci': {
        'master_csv':          GEN_DIR / 'oci/oci_master_field_catalog.csv',
        'output_csv':          GEN_DIR / 'oci/oci_master_read_ops.csv',
        'csp_gen_dir':         GEN_DIR / 'oci',
        'rii_yaml_name':       None,
        'rii_id_param_field':  None,
        'check_rule_dir':      RULE_DIR / 'oci_rule_check',
        'check_rule_pattern':  '{svc}/{svc}.checks.yaml',
        'alicloud_checks':     False,
    },
    'alicloud': {
        'master_csv':          GEN_DIR / 'alicloud/alicloud_master_field_catalog.csv',
        'output_csv':          GEN_DIR / 'alicloud/alicloud_master_read_ops.csv',
        'csp_gen_dir':         GEN_DIR / 'alicloud',
        'rii_yaml_name':       None,
        'rii_id_param_field':  None,
        'check_rule_dir':      GEN_DIR / 'alicloud',   # step7 files are here
        'check_rule_pattern':  '{svc}/step7_{svc}.checks.yaml',
        'alicloud_checks':     True,
    },
    'k8s': {
        'master_csv':          GEN_DIR / 'k8s/k8s_master_field_catalog.csv',
        'output_csv':          GEN_DIR / 'k8s/k8s_master_read_ops.csv',
        'csp_gen_dir':         GEN_DIR / 'k8s',
        'rii_yaml_name':       'final_discovery_v1.yaml',
        'rii_id_param_field':  'identifier_field',
        'check_rule_dir':      RULE_DIR / 'k8s_rule_check',
        'check_rule_pattern':  '{svc}/{svc}.checks.yaml',
        'alicloud_checks':     False,
    },
    'ibm': {
        'master_csv':          GEN_DIR / 'ibm/ibm_master_field_catalog.csv',
        'output_csv':          GEN_DIR / 'ibm/ibm_master_read_ops.csv',
        'csp_gen_dir':         GEN_DIR / 'ibm',
        'rii_yaml_name':       None,
        'rii_id_param_field':  None,
        'check_rule_dir':      None,   # no CSPM check rules
        'check_rule_pattern':  None,
        'alicloud_checks':     False,
    },
}


# ──────────────────────────────────────────────────────────────────────────────
def _load_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}


# ──────────────────────────────────────────────────────────────────────────────
# SOURCE 1: GROUP BY producing_op from master_field_catalog.csv
# ──────────────────────────────────────────────────────────────────────────────

def build_ops_from_master_csv(master_csv: Path) -> Dict[str, dict]:
    """
    Returns {producing_op → aggregated_row} from master_field_catalog.csv.
    Deduplicates produced_fields; accumulates types and operators.
    """
    ops: Dict[str, dict] = {}

    for row in csv.DictReader(master_csv.open()):
        op = row.get('producing_op', '').strip()
        if not op:
            continue

        if op not in ops:
            ops[op] = {col: row.get(col, '') for col in META_COLS}
            ops[op]['producing_op']     = op
            ops[op]['_fields_seen']     = {}   # field → {type, operators}
            ops[op]['resource_id_field'] = ''

        field = row.get('field_path', '').strip()
        if field and field not in ops[op]['_fields_seen']:
            ops[op]['_fields_seen'][field] = {
                'type':      row.get('field_type', '').strip(),
                'operators': row.get('operators', '').strip(),
            }

        if row.get('is_id', '').strip().lower() == 'yes' and field:
            ops[op]['resource_id_field'] = field

    # Flatten _fields_seen
    for op, d in ops.items():
        seen = d.pop('_fields_seen')
        d['produced_fields']  = '|'.join(seen.keys())
        d['fields_types']     = '|'.join(
            f"{f}:{m['type']}" for f, m in seen.items() if m['type']
        )
        d['fields_operators'] = '|'.join(
            f"{f}:{m['operators']}" for f, m in seen.items() if m['operators']
        )

    return ops


# ──────────────────────────────────────────────────────────────────────────────
# SOURCE 2: RII from final_discovery_v1.yaml files
# ──────────────────────────────────────────────────────────────────────────────

def build_rii_map(csp_gen_dir: Path, yaml_name: str,
                  id_param_field: str) -> Dict[str, dict]:
    """
    Returns {identifier_op → {resource_type, resource_id_param}}
    by scanning all {svc}/final_discovery_v1.yaml files.
    """
    rii_map: Dict[str, dict] = {}

    for svc_dir in sorted(csp_gen_dir.iterdir()):
        if not svc_dir.is_dir():
            continue
        yaml_path = svc_dir / yaml_name
        if not yaml_path.exists():
            continue
        data = _load_yaml(yaml_path)
        for rii in data.get('inventory_resource_identifiers') or []:
            id_op    = (rii.get('identifier_op') or '').strip()
            res_type = (rii.get('resource_type') or '').strip()
            id_param = (rii.get(id_param_field) or '').strip()
            if id_op:
                rii_map[id_op] = {
                    'resource_type':    res_type,
                    'resource_id_param': id_param,
                }

    return rii_map


# ──────────────────────────────────────────────────────────────────────────────
# SOURCE 3: Check rules → {for_each_op → [rule dicts]}
# ──────────────────────────────────────────────────────────────────────────────

def build_rules_by_op(check_rule_dir: Optional[Path],
                      pattern: Optional[str]) -> Dict[str, List[dict]]:
    """
    Returns {for_each_op → [rule dicts]} by scanning check rule yaml files.
    Pattern '{svc}/{svc}.checks.yaml' or '{svc}/step7_{svc}.checks.yaml'
    """
    rules_by_op: Dict[str, List[dict]] = defaultdict(list)

    if not check_rule_dir or not pattern or not check_rule_dir.exists():
        return rules_by_op

    for svc_dir in sorted(check_rule_dir.iterdir()):
        if not svc_dir.is_dir():
            continue
        svc = svc_dir.name
        checks_path = svc_dir / pattern.replace('{svc}', svc).split('/')[-1]
        # Resolve full path
        rel = pattern.replace('{svc}', svc)
        checks_path = check_rule_dir / rel
        if not checks_path.exists():
            continue
        data = _load_yaml(checks_path)
        for rule in data.get('checks', []):
            fe = (rule.get('for_each') or '').strip()
            if fe:
                rules_by_op[fe].append(rule)

    return rules_by_op


# ──────────────────────────────────────────────────────────────────────────────
# ASSEMBLE rows for one CSP
# ──────────────────────────────────────────────────────────────────────────────

def generate_for_csp(csp: str, cfg: dict, apply: bool) -> None:
    print(f'\n{"═"*60}')
    print(f'CSP: {csp.upper()}')
    print('═' * 60)

    master_csv = cfg['master_csv']
    if not master_csv.exists():
        print(f'  SKIP — master CSV not found: {master_csv}')
        return

    # Source 1
    print(f'  Loading master field catalog ...')
    ops = build_ops_from_master_csv(master_csv)
    print(f'  {len(ops)} ops from {master_csv.name}')

    # Source 2
    rii_map: Dict[str, dict] = {}
    if cfg['rii_yaml_name']:
        print(f'  Loading RII ...')
        rii_map = build_rii_map(
            cfg['csp_gen_dir'],
            cfg['rii_yaml_name'],
            cfg['rii_id_param_field'],
        )
        print(f'  {len(rii_map)} RII entries')

    # Source 3 — only loaded when --with-rules is passed
    rules_by_op: Dict[str, List[dict]] = defaultdict(list)
    if WITH_RULES:
        print(f'  Loading check rules ...')
        rules_by_op = build_rules_by_op(cfg['check_rule_dir'], cfg['check_rule_pattern'])
        total_rules = sum(len(v) for v in rules_by_op.values())
        print(f'  {total_rules} rules across {len(rules_by_op)} ops')
    else:
        print(f'  Skipping check rules (pass --with-rules to populate)')

    # Assemble
    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    output_rows: List[dict] = []

    for op, d in sorted(ops.items()):
        rii        = rii_map.get(op, {})
        rules      = rules_by_op.get(op, [])
        rule_count = len(rules) if WITH_RULES else 0

        check_rule_yaml = ''
        if WITH_RULES and rules:
            try:
                check_rule_yaml = yaml.dump(
                    rules,
                    default_flow_style=False,
                    allow_unicode=True,
                    indent=2,
                    sort_keys=True,
                ).strip()
            except Exception:
                check_rule_yaml = ''

        output_rows.append({
            'csp':                   d['csp'],
            'service':               d['service'],
            'producing_op':          op,
            'op_kind':               d['op_kind'],
            'is_independent':        d['is_independent'],
            'root_op':               d['root_op'],
            'chain_ops':             d['chain_ops'],
            'chain_length':          d['chain_length'],
            'hop_distance':          d['hop_distance'],
            'chain_ops_with_fields': d['chain_ops_with_fields'],
            'python_call':           d['python_call'],
            'http_path':             d['http_path'],
            'produced_fields':       d['produced_fields'],
            'fields_types':          d['fields_types'],
            'fields_operators':      d['fields_operators'],
            'resource_type':         rii.get('resource_type', ''),
            'resource_id_field':     d['resource_id_field'],
            'resource_id_param':     rii.get('resource_id_param', ''),
            'rule_count':            rule_count,
            'check_rule_yaml':       check_rule_yaml,
            'is_active':             'true',
            'updated_at':            now_ts,
        })

    # Stats
    total     = len(output_rows)
    indep     = sum(1 for r in output_rows if r['is_independent'] == 'Yes')
    with_rii  = sum(1 for r in output_rows if r['resource_type'])
    with_rules= sum(1 for r in output_rows if r['rule_count'] > 0)
    max_r     = max(output_rows, key=lambda r: r['rule_count']) if output_rows else None
    max_f     = max(output_rows, key=lambda r: r['produced_fields'].count('|')) if output_rows else None

    print(f'\n  Total ops:            {total}')
    print(f'  independent:          {indep}')
    print(f'  dependent:            {total - indep}')
    print(f'  Ops with RII:         {with_rii}')
    print(f'  Ops with rules:       {with_rules}')
    if max_r:
        print(f'  Max rules on one op:  {max_r["rule_count"]:>4}  ({max_r["producing_op"]})')
    if max_f:
        print(f'  Max fields on one op: {max_f["produced_fields"].count("|")+1:>4}  ({max_f["producing_op"]})')

    # Write
    output_csv = cfg['output_csv']
    if apply:
        with output_csv.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(output_rows)
        print(f'\n  Wrote {total:,} rows → {output_csv}')
    else:
        print(f'\n  Would write {total:,} rows → {output_csv}')


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

APPLY       = '--apply' in sys.argv
WITH_RULES  = '--with-rules' in sys.argv   # populate rule_count + check_rule_yaml

# --csp <name> to run a single CSP
target_csp: Optional[str] = None
if '--csp' in sys.argv:
    idx = sys.argv.index('--csp')
    if idx + 1 < len(sys.argv):
        target_csp = sys.argv[idx + 1].lower()

if not APPLY:
    print('*** DRY RUN — pass --apply to write CSVs ***')
if not WITH_RULES:
    print('*** rule_count + check_rule_yaml left empty — pass --with-rules to populate ***')

if target_csp:
    if target_csp not in CSP_CONFIG:
        print(f'Unknown CSP: {target_csp}. Available: {list(CSP_CONFIG.keys())}')
        sys.exit(1)
    csps_to_run = {target_csp: CSP_CONFIG[target_csp]}
else:
    csps_to_run = CSP_CONFIG

for csp, cfg in csps_to_run.items():
    generate_for_csp(csp, cfg, APPLY)

print('\nDone.')
