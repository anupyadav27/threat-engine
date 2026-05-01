#!/usr/bin/env python3
"""
Rebuild step4_name_identifier.json from the YAML as source of truth.

Logic:
  1. Parse step2_{service}_discovery.yaml
     → each discovery entry has: discovery_id, calls[].action, emit.items_for, emit.item{}
  2. Parse step3_gcp_dependencies JSON
     → know which discovery_ids / operations are independent vs dependent
  3. For each YAML entry:
     - Extract the emitted item fields (keys of emit.item)
     - Score: does it emit identifier fields? (name, id, selfLink, *Reference, *Id, uid...)
     - Tag as independent or dependent
  4. Pick best independent entry → identifier_discovery_id, identifier_call, identifier_fields
     Fallback to best dependent entry if no independent has identifier fields
  5. Build uniform_name template using the pattern + identifier fields
  6. Write enriched step4_name_identifier.json
"""

import json
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ── Identifier field scoring ──────────────────────────────────────────────────
# Tier 1: explicit, universally meaningful GCP identifiers
TIER1_ID_FIELDS = {
    'name', 'id', 'selfLink', 'uid', 'resourceName',
}

# Tier 2: reference objects that contain the composite key
TIER2_REF_FIELDS = {
    'datasetReference', 'tableReference', 'jobReference',
    'projectReference', 'instanceReference', 'clusterReference',
    'bucketReference', 'topicReference', 'subscriptionReference',
    'diskReference', 'networkReference', 'subnetworkReference',
    'instanceGroupReference', 'backendServiceReference',
}

# Tier 3: component identifiers (useful but partial)
TIER3_COMPONENT_FIELDS = {
    'projectId', 'project', 'datasetId', 'tableId', 'jobId',
    'instanceId', 'clusterId', 'bucketId', 'bucket',
    'zone', 'region', 'location', 'namespace', 'namespaceId',
    'accountId', 'userId', 'resourceId', 'subscriptionId', 'topicId',
}

# Suffix patterns that indicate identifier fields
ID_SUFFIX_PATTERNS = re.compile(
    r'(name|Id|Arn|Link|Reference|Uid|Uri|Url|Key|Handle)$', re.IGNORECASE
)

# Fields that are almost certainly NOT useful identifiers (skip for template fallback)
NON_IDENTIFIER_FIELDS = {
    'kind', 'etag', 'nextPageToken', 'pageToken', 'warning', 'warnings',
    'unreachables', 'unreachable', 'totalItems', 'pageInfo',
}

def score_item_fields(item_fields: List[str]) -> Tuple[int, List[str]]:
    """
    Score a set of emitted item fields by how well they identify the resource.
    Returns (score, matched_id_fields).
    """
    matched = []
    score = 0
    for f in item_fields:
        if f in TIER1_ID_FIELDS:
            score += 10
            matched.append(f)
        elif f in TIER2_REF_FIELDS:
            score += 7
            matched.append(f)
        elif f in TIER3_COMPONENT_FIELDS:
            score += 4
            matched.append(f)
        elif ID_SUFFIX_PATTERNS.search(f):
            score += 2
            matched.append(f)
    return score, matched


# ── Pattern param extraction ──────────────────────────────────────────────────
def parse_pattern_params(pattern: str) -> List[str]:
    return [p.lstrip('+') for p in re.findall(r'\{[+]?([^}]+)\}', pattern)]


def build_uniform_name_template(pattern: str, identifier_fields: List[str]) -> str:
    """
    Build a Jinja2-style uniform name template.
    e.g. pattern = '//svc.googleapis.com/projects/{projectId}/datasets/{datasetId}'
         identifier_fields = ['datasetReference', 'id']
    → '//svc.googleapis.com/projects/{{ item.projectId }}/datasets/{{ item.datasetId }}'
    or if fields cover it: '{{ item.name }}'

    Strategy:
    - If 'name' or 'selfLink' is an identifier field → use that directly
      (GCP name fields are already full resource paths)
    - Otherwise fill pattern params with {{ item.X }} from matched fields
    """
    # Best case: name or selfLink is already the full resource path
    for f in ('name', 'selfLink', 'resourceName'):
        if f in identifier_fields:
            return f'{{{{ item.{f} }}}}'

    # Fill pattern params with item fields
    result = pattern
    params = parse_pattern_params(pattern)
    for param in params:
        # Find best matching field
        best_field = None
        param_lower = param.lower()
        # Direct match
        for f in identifier_fields:
            if f.lower() == param_lower or f.lower() == param_lower + 'id':
                best_field = f
                break
        # Partial match
        if not best_field:
            for f in identifier_fields:
                if param_lower in f.lower() or f.lower() in param_lower:
                    best_field = f
                    break
        # Any field
        if not best_field and identifier_fields:
            best_field = identifier_fields[0]

        placeholder = f'{{{{ item.{best_field} }}}}' if best_field else f'{{{{{param}}}}}'
        result = re.sub(r'\{[+]?' + re.escape(param) + r'\}', placeholder, result)

    return result


# ── YAML parsing ──────────────────────────────────────────────────────────────
def parse_yaml_entries(yaml_path: Path) -> List[dict]:
    """Parse discovery YAML and return list of entry dicts."""
    with open(yaml_path, 'r') as f:
        doc = yaml.safe_load(f)
    return doc.get('discovery', [])


# ── Dependency classification ─────────────────────────────────────────────────
def load_independent_ops(deps_path: Path, service: str) -> Set[str]:
    """
    Return set of operation short names that are independent.
    e.g. {'datasets.list', 'projects.list', ...}
    """
    if not deps_path.exists():
        return set()
    deps = json.load(open(deps_path))
    svc_data = deps.get(service, deps)
    indep = set()
    for op in svc_data.get('independent', []):
        indep.add(op.get('operation', ''))
        indep.add(op.get('python_method', ''))
    return indep


def discovery_id_to_short(discovery_id: str) -> str:
    """
    gcp.bigquery.datasets.list → datasets.list
    gcp.accessapproval.folders.approvalRequests.list → folders.approvalRequests.list
    """
    parts = discovery_id.split('.')
    # Drop 'gcp' and service name (first two parts)
    return '.'.join(parts[2:]) if len(parts) > 2 else discovery_id


def is_independent(discovery_id: str, action: str, indep_ops: Set[str]) -> bool:
    """Check if a YAML entry is an independent operation."""
    short = discovery_id_to_short(discovery_id)
    # Try the discovery_id short form
    if short in indep_ops:
        return True
    # Try action directly
    if action in indep_ops:
        return True
    # Try leaf method name
    leaf = short.split('.')[-1] if '.' in short else short
    action_leaf = action.split('.')[-1] if '.' in action else action
    for op in indep_ops:
        op_leaf = op.split('.')[-1] if '.' in op else op
        if op_leaf == leaf or op_leaf == action_leaf:
            return True
    return False


# ── Per-resource grouping ─────────────────────────────────────────────────────
def get_resource_name(discovery_id: str) -> str:
    """
    gcp.bigquery.datasets.list → datasets
    gcp.accessapproval.folders.approvalRequests.list → approvalRequests
    """
    parts = discovery_id_to_short(discovery_id).split('.')
    # Second-to-last part is the resource (last is the method)
    return parts[-2] if len(parts) >= 2 else parts[0]


# ── Main enrichment ───────────────────────────────────────────────────────────
def enrich_service(svc_dir: Path) -> Optional[dict]:
    service = svc_dir.name

    # Find YAML
    yaml_files = list(svc_dir.glob('step2_*_discovery.yaml'))
    if not yaml_files:
        return None
    yaml_path = yaml_files[0]

    # Load existing name_identifier for pattern / metadata
    ni_path = svc_dir / 'step4_name_identifier.json'
    ni_existing = json.load(open(ni_path)) if ni_path.exists() else {}

    deps_path = svc_dir / 'step3_gcp_dependencies_with_python_names_fully_enriched.json'
    indep_ops = load_independent_ops(deps_path, service)

    # Parse YAML entries
    try:
        entries = parse_yaml_entries(yaml_path) or []
    except Exception as e:
        return None

    pattern = ni_existing.get('pattern', f'//{service}.googleapis.com/{{+name}}')
    id_params = parse_pattern_params(pattern)

    # ── Score every YAML entry ────────────────────────────────────────────────
    scored = []
    for entry in entries:
        did   = entry.get('discovery_id', '')
        calls = entry.get('calls', [])
        action = calls[0].get('action', '') if calls else ''
        emit   = entry.get('emit', {})
        items_for = emit.get('items_for', '')
        item_fields = list(emit.get('item', {}).keys())

        indep = is_independent(did, action, indep_ops)
        score, id_fields = score_item_fields(item_fields)

        scored.append({
            'discovery_id':   did,
            'action':         action,
            'items_for':      items_for,
            'item_fields':    item_fields,
            'identifier_fields': id_fields,
            'score':          score,
            'is_independent': indep,
            'resource':       get_resource_name(did),
        })

    # ── Pick best independent, fallback to best dependent ────────────────────
    # Sort key: (-tier1_count, -total_score) — strongly prefer entries with
    # Tier1 fields (name, id, selfLink) over Tier2/3 matches
    def tier1_count(s):
        return sum(1 for f in s['identifier_fields'] if f in TIER1_ID_FIELDS)

    def sort_key(s):
        return (-tier1_count(s), -s['score'])

    indep_scored = sorted(
        [s for s in scored if s['is_independent'] and s['score'] > 0],
        key=sort_key
    )
    dep_scored = sorted(
        [s for s in scored if not s['is_independent'] and s['score'] > 0],
        key=sort_key
    )

    best_indep = indep_scored[0] if indep_scored else None
    best_dep   = dep_scored[0]   if dep_scored   else None

    # If no scored independent, take any independent with most item fields
    if not best_indep:
        any_indep = sorted(
            [s for s in scored if s['is_independent']],
            key=lambda x: -len(x['item_fields'])
        )
        best_indep = any_indep[0] if any_indep else None

    if not best_dep:
        any_dep = sorted(
            [s for s in scored if not s['is_independent']],
            key=lambda x: -len(x['item_fields'])
        )
        best_dep = any_dep[0] if any_dep else None

    # Winner: independent preferred UNLESS dependent has far better score
    # (e.g. independent has 0 Tier1 fields, dependent has name/id)
    indep_t1 = tier1_count(best_indep) if best_indep else 0
    dep_t1   = tier1_count(best_dep)   if best_dep   else 0

    if best_indep and (indep_t1 > 0 or dep_t1 == 0):
        winner = best_indep
    elif best_dep and dep_t1 > indep_t1:
        winner = best_dep   # dependent has clearly better identifier fields
    else:
        winner = best_indep or best_dep

    source_type = 'independent' if (winner and winner['is_independent']) else \
                  ('dependent' if winner else 'none')

    # ── Build uniform name template ───────────────────────────────────────────
    uniform_name_template = ''
    if winner and winner['identifier_fields']:
        uniform_name_template = build_uniform_name_template(
            pattern, winner['identifier_fields']
        )
    elif winner:
        # Fall back: pick the best available item field as the identifier
        # Prefer fields that at least look like identifiers (not metadata)
        fallback_field = None
        for f in winner['item_fields']:
            if f not in NON_IDENTIFIER_FIELDS:
                fallback_field = f
                break
        if fallback_field:
            uniform_name_template = f'{{{{ item.{fallback_field} }}}}'

    # ── Per-resource breakdown ────────────────────────────────────────────────
    resources: Dict[str, dict] = {}
    for s in scored:
        res = s['resource']
        if res not in resources:
            resources[res] = {
                'resource':           res,
                'best_independent':   None,
                'best_dependent':     None,
                'identifier_fields':  [],
                'uniform_name_template': '',
            }
        r = resources[res]
        if s['is_independent']:
            if r['best_independent'] is None or s['score'] > scored[0]['score']:
                r['best_independent'] = s['discovery_id']
                if s['identifier_fields']:
                    r['identifier_fields'] = s['identifier_fields']
        else:
            if r['best_dependent'] is None or s['score'] > 0:
                r['best_dependent'] = s['discovery_id']
                if not r['identifier_fields'] and s['identifier_fields']:
                    r['identifier_fields'] = s['identifier_fields']

        # Build per-resource uniform name
        if r['identifier_fields'] and not r['uniform_name_template']:
            r['uniform_name_template'] = build_uniform_name_template(
                pattern, r['identifier_fields']
            )

    # ── Build output ──────────────────────────────────────────────────────────
    out = {
        'service':                   service,
        'resource':                  ni_existing.get('resource'),
        'identifier_type':           ni_existing.get('identifier_type', 'name'),
        'pattern':                   pattern,
        'identifier_params':         id_params,

        # Winner
        'identifier_source_type':    source_type,
        'identifier_discovery_id':   winner['discovery_id']  if winner else None,
        'identifier_call':           winner['action']         if winner else None,
        'identifier_items_for':      winner['items_for']      if winner else None,
        'identifier_fields':         winner['identifier_fields'] if winner else [],
        'uniform_name_template':     uniform_name_template,

        # Best independent details
        'best_independent': {
            'discovery_id':      best_indep['discovery_id']      if best_indep else None,
            'call':              best_indep['action']             if best_indep else None,
            'items_for':         best_indep['items_for']         if best_indep else None,
            'identifier_fields': best_indep['identifier_fields'] if best_indep else [],
            'all_item_fields':   best_indep['item_fields']       if best_indep else [],
        },

        # Best dependent details
        'best_dependent': {
            'discovery_id':      best_dep['discovery_id']      if best_dep else None,
            'call':              best_dep['action']             if best_dep else None,
            'items_for':         best_dep['items_for']         if best_dep else None,
            'identifier_fields': best_dep['identifier_fields'] if best_dep else [],
            'all_item_fields':   best_dep['item_fields']       if best_dep else [],
        },

        # All YAML entries scored
        'all_discovery_entries': [
            {
                'discovery_id':      s['discovery_id'],
                'call':              s['action'],
                'items_for':         s['items_for'],
                'is_independent':    s['is_independent'],
                'identifier_fields': s['identifier_fields'],
                'score':             s['score'],
                'all_item_fields':   s['item_fields'],
            }
            for s in sorted(scored, key=lambda x: (-x['score'], x['discovery_id']))
        ],

        # Per-resource
        'resources': list(resources.values()),
    }
    return out


def run_all(base_dir: Path):
    print('=' * 70)
    print('Rebuilding step4_name_identifier.json from YAML (source of truth)')
    print('=' * 70)

    service_dirs = sorted(
        d for d in base_dir.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and not d.name.endswith('.py') and not d.name.endswith('.md')
    )

    done = skipped = 0
    counts = {'independent': 0, 'dependent': 0, 'none': 0}

    for sdir in service_dirs:
        result = enrich_service(sdir)
        if result is None:
            skipped += 1
            continue

        out_path = sdir / 'step4_name_identifier.json'
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)

        st = result['identifier_source_type']
        counts[st] = counts.get(st, 0) + 1
        done += 1

        if done <= 8 or done % 50 == 0:
            tmpl = result.get('uniform_name_template') or '—'
            did  = result.get('identifier_discovery_id') or '—'
            flds = result.get('identifier_fields') or []
            print(f'  ✓ {sdir.name}')
            print(f'      [{st}] {did}')
            print(f'      fields={flds}  template={tmpl}')

    print()
    print(f'Done:    {done}')
    print(f'Skipped: {skipped}')
    print(f'Source breakdown:')
    for k, v in counts.items():
        print(f'  {k}: {v}')
    print('=' * 70)


if __name__ == '__main__':
    run_all(BASE_DIR)
