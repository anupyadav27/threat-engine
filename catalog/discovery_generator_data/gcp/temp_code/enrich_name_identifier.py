#!/usr/bin/env python3
"""
Enrich step4_name_identifier.json for all GCP services.

Logic:
  1. Parse the pattern to extract the identifier param names
     e.g. "projects/{projectId}/datasets/{datasetId}/tables/{tableId}"
     → identifiers = ['projectId', 'datasetId', 'tableId']

  2. For each independent method, check if its produces[] item fields
     CONTAIN all the required identifier fields.
     Score = how many identifiers it can produce + prefer list over get
     + prefer fewer required_params (simpler to call).

  3. If no independent method can produce all identifiers, fall back to
     dependent methods with the same scoring.

  4. Write back:
     - best_independent_method   (or null)
     - best_dependent_method     (or null)
     - identifier_source_method  (the winner — independent preferred)
     - identifier_source_type    ("independent" | "dependent" | "none")
     - identifier_fields         list of field paths that carry the identifiers
     - resources[]               per-resource breakdown with their best method
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ── identifier field name aliases ────────────────────────────────────────────
# Pattern params like {+name} → look for 'name' field in produces
# Pattern params like {projectId} → look for 'projectId', 'project', 'project_id'
PARAM_ALIASES: Dict[str, List[str]] = {
    'name':        ['name', 'selfLink', 'id', 'resourceName', 'reviewedSite',
                    'displayName', 'fullName', 'qualifiedName', 'uniqueId'],
    'projectid':   ['projectId', 'project', 'project_id', 'projectNumber'],
    'project':     ['projectId', 'project', 'project_id', 'projectNumber'],
    'datasetid':   ['datasetId', 'dataset', 'dataset_id'],
    'tableid':     ['tableId', 'table', 'table_id'],
    'bucketid':    ['bucket', 'bucketId', 'name'],
    'bucket':      ['bucket', 'bucketId', 'name'],
    'instanceid':  ['instanceId', 'instance', 'name', 'id'],
    'instance':    ['instanceId', 'instance', 'name', 'id'],
    'zoneid':      ['zone', 'zoneId'],
    'zone':        ['zone', 'zoneId', 'name'],
    'region':      ['region', 'regionId', 'name'],
    'locationid':  ['location', 'locationId'],
    'location':    ['location', 'locationId'],
    'clusterid':   ['clusterId', 'cluster', 'name', 'id'],
    'id':          ['id', 'name', 'selfLink', 'uid'],
    'parent':      ['name', 'parent', 'resourceName'],
    'resource':    ['name', 'id', 'selfLink', 'resourceName'],
}

# Fields that are strong universal identifiers — always useful
STRONG_ID_FIELDS = {
    'name', 'id', 'selfLink', 'resourceName', 'uid',
    'projectId', 'project', 'datasetId', 'tableId',
    'bucket', 'instanceId', 'zone', 'region', 'location',
    'clusterId', 'namespaceId', 'namespace',
}


def parse_pattern_params(pattern: str) -> List[str]:
    """
    Extract parameter names from a URL pattern.
    e.g. 'projects/{projectId}/datasets/{+datasetId}' → ['projectId', 'datasetId']
    """
    raw = re.findall(r'\{[+]?([^}]+)\}', pattern)
    # Strip leading + from params like {+name}
    return [p.lstrip('+') for p in raw]


def get_item_field_paths(operation: dict) -> Set[str]:
    """Return set of field path names produced as 'item' source."""
    return {
        p['path']
        for p in operation.get('produces', [])
        if p.get('source') == 'item' and p.get('path')
    }

def get_output_field_paths(operation: dict) -> Set[str]:
    """Return set of field path names produced as 'output' source (collection keys)."""
    return {
        p['path']
        for p in operation.get('produces', [])
        if p.get('source') == 'output' and p.get('path')
    }


def fields_cover_identifier(item_fields: Set[str], id_param: str) -> bool:
    """Check if produced fields can satisfy an identifier parameter."""
    lower = id_param.lower()
    # Direct match
    if id_param in item_fields:
        return True
    # Alias match
    for alias in PARAM_ALIASES.get(lower, []):
        if alias in item_fields:
            return True
    # Fuzzy: if any field contains the param name
    for f in item_fields:
        if lower in f.lower():
            return True
    return False


def covering_fields(item_fields: Set[str], id_param: str) -> List[str]:
    """Return the actual field(s) from item_fields that cover an id_param."""
    lower = id_param.lower()
    result = []
    if id_param in item_fields:
        result.append(id_param)
        return result
    for alias in PARAM_ALIASES.get(lower, []):
        if alias in item_fields:
            result.append(alias)
    if not result:
        for f in item_fields:
            if lower in f.lower():
                result.append(f)
    return result[:2]  # cap at 2


def score_method(op_key: str, operation: dict, id_params: List[str]) -> Tuple[int, int, int, List[str]]:
    """
    Score how well this method covers the required identifiers.
    Returns (coverage_score, is_list, -required_params_count, matched_fields)
    Higher is better.
    """
    item_fields = get_item_field_paths(operation)
    matched = []
    covered = 0
    for param in id_params:
        if fields_cover_identifier(item_fields, param):
            covered += 1
            matched.extend(covering_fields(item_fields, param))

    # Bonus: even if param-mapping failed, count strong ID fields present
    if covered == 0:
        strong_present = item_fields & STRONG_ID_FIELDS
        if strong_present:
            covered = 1  # partial credit
            matched.extend(sorted(strong_present)[:2])

    is_list = 1 if operation.get('kind') == 'read_list' else 0
    req_params = len(operation.get('required_params') or [])

    return (covered, is_list, -req_params, list(dict.fromkeys(matched)))  # deduplicate


def find_operation(method_short: str, service: str, operations: Dict[str, dict]) -> Optional[dict]:
    """
    Resolve a short method name (e.g. 'notifications.list') to its full operation dict.
    Three strategies:
    1. Exact:   gcp.{service}.{method_short}
    2. Suffix:  any key ending with '.{method_short}' (handles nested resources)
    3. Case-insensitive suffix fallback
    """
    exact = f"gcp.{service}.{method_short}"
    if exact in operations:
        return operations[exact]

    suffix       = f".{method_short}"
    suffix_lower = suffix.lower()
    candidates   = []
    for k, v in operations.items():
        if k.endswith(suffix) or k.lower().endswith(suffix_lower):
            candidates.append((k, v))

    if not candidates:
        return None
    # Prefer shortest key = least-nested / most general resource path
    candidates.sort(key=lambda x: len(x[0]))
    return candidates[0][1]


def best_method_for_ids(
    methods: List[str],
    operations: Dict[str, dict],
    id_params: List[str],
    service: str,
) -> Optional[Tuple[str, List[str]]]:
    """
    Find the best method from a list that covers the most identifier params.
    Returns (method_key_short, matched_fields) or None.
    """
    best_score = (-1, 0, 0)
    best_key   = None
    best_fields: List[str] = []

    for method_short in methods:
        op = find_operation(method_short, service, operations)
        if not op:
            continue

        covered, is_list, neg_req, matched = score_method(method_short, op, id_params)
        score = (covered, is_list, neg_req)
        if score > best_score:
            best_score = score
            best_key   = method_short
            best_fields = matched

    return (best_key, best_fields) if best_key else None


def extract_resources_from_methods(methods: List[str]) -> Dict[str, List[str]]:
    """Group methods by resource name (first part before the dot)."""
    resources: Dict[str, List[str]] = {}
    for m in methods:
        parts = m.split('.')
        resource = parts[0] if parts else 'unknown'
        resources.setdefault(resource, []).append(m)
    return resources


def enrich_service(svc_dir: Path) -> dict:
    service = svc_dir.name

    ni_path = svc_dir / 'step4_name_identifier.json'
    reg_path = svc_dir / 'step1_operation_registry.json'

    if not ni_path.exists():
        return None

    ni = json.load(open(ni_path))
    operations = {}
    if reg_path.exists():
        reg = json.load(open(reg_path))
        operations = reg.get('operations', {})

    # ── 1. Parse identifier params from pattern ──────────────────────────────
    pattern = ni.get('pattern', '')
    id_params = parse_pattern_params(pattern)

    # Also parse resource_identifiers field as additional hint
    raw_ids = ni.get('resource_identifiers', '')
    for rid in re.split(r'[;,\s]+', raw_ids):
        rid = rid.lstrip('+').strip()
        if rid and rid not in id_params:
            id_params.append(rid)

    id_params = list(dict.fromkeys(id_params))  # deduplicate, keep order

    # ── 2. Score independent methods ─────────────────────────────────────────
    indep_methods = ni.get('resource_independent_methods', [])
    dep_methods   = ni.get('resource_dependent_methods', [])

    indep_result = best_method_for_ids(indep_methods, operations, id_params, service)
    dep_result   = best_method_for_ids(dep_methods,   operations, id_params, service)

    best_indep_method  = indep_result[0] if indep_result else None
    best_indep_fields  = indep_result[1] if indep_result else []
    best_dep_method    = dep_result[0]   if dep_result   else None
    best_dep_fields    = dep_result[1]   if dep_result   else []

    # ── 3. Choose winner: prefer independent ─────────────────────────────────
    if best_indep_method:
        source_method = best_indep_method
        source_type   = 'independent'
        source_fields = best_indep_fields
    elif best_dep_method:
        source_method = best_dep_method
        source_type   = 'dependent'
        source_fields = best_dep_fields
    else:
        source_method = None
        source_type   = 'none'
        source_fields = []

    # ── 4. Per-resource breakdown ─────────────────────────────────────────────
    all_methods = indep_methods + dep_methods
    resource_groups = extract_resources_from_methods(all_methods)

    resources_detail = []
    for res_name, res_methods in sorted(resource_groups.items()):
        # Split into indep/dep for this resource
        res_indep = [m for m in res_methods if m in indep_methods]
        res_dep   = [m for m in res_methods if m in dep_methods]

        ri = best_method_for_ids(res_indep, operations, id_params, service)
        rd = best_method_for_ids(res_dep,   operations, id_params, service)

        if ri:
            rm, rf, rt = ri[0], ri[1], 'independent'
        elif rd:
            rm, rf, rt = rd[0], rd[1], 'dependent'
        else:
            rm, rf, rt = None, [], 'none'

        resources_detail.append({
            'resource':              res_name,
            'best_method':           rm,
            'method_source_type':    rt,
            'identifier_fields':     rf,
            'independent_methods':   res_indep,
            'dependent_methods':     res_dep,
        })

    # ── 5. Build enriched output ──────────────────────────────────────────────
    enriched = {
        'service':                   service,
        'resource':                  ni.get('resource'),
        'identifier_type':           ni.get('identifier_type', 'name'),
        'pattern':                   pattern,
        'identifier_params':         id_params,
        'resource_identifiers':      ni.get('resource_identifiers'),

        # Best method selection
        'best_independent_method':   best_indep_method,
        'best_independent_fields':   best_indep_fields,
        'best_dependent_method':     best_dep_method,
        'best_dependent_fields':     best_dep_fields,

        # Winner
        'identifier_source_method':  source_method,
        'identifier_source_type':    source_type,
        'identifier_fields':         source_fields,

        # Full method lists
        'resource_independent_methods': indep_methods,
        'resource_dependent_methods':   dep_methods,
        'total_independent':            len(indep_methods),
        'total_dependent':              len(dep_methods),

        # Per-resource detail
        'resources':                 resources_detail,
    }
    return enriched


def run_all(base_dir: Path):
    print("=" * 70)
    print("Enriching step4_name_identifier.json for all GCP services")
    print("=" * 70)

    service_dirs = sorted(
        d for d in base_dir.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and not d.name.endswith('.py') and not d.name.endswith('.md')
    )

    done = 0
    skipped = 0
    source_type_counts = {'independent': 0, 'dependent': 0, 'none': 0}

    for sdir in service_dirs:
        enriched = enrich_service(sdir)
        if enriched is None:
            skipped += 1
            continue

        out_path = sdir / 'step4_name_identifier.json'
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(enriched, f, indent=2)

        st = enriched.get('identifier_source_type', 'none')
        source_type_counts[st] = source_type_counts.get(st, 0) + 1
        done += 1

        if done <= 8 or done % 50 == 0:
            src = enriched.get('identifier_source_method') or '—'
            flds = enriched.get('identifier_fields') or []
            print(f"  ✓ {sdir.name}: [{st}] {src} → fields: {flds[:3]}")

    print()
    print(f"Done:    {done}")
    print(f"Skipped: {skipped}")
    print(f"Source type breakdown:")
    for k, v in source_type_counts.items():
        print(f"  {k}: {v}")
    print("=" * 70)


if __name__ == '__main__':
    run_all(BASE_DIR)
