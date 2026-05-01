#!/usr/bin/env python3
"""
Build step1_api_driven_registry.json — API-driven operation registry.

This replaces the fragmented step1..4 files with a SINGLE unified registry
per service that answers every question needed to execute any operation:

  1. What do I call?          → method, http, python_call
  2. What do I pass?          → inputs.required[] with full template + per-slot source
  3. What do I get back?      → outputs.produces_fields[] in dot-path notation
  4. Can I call it standalone? → independent
  5. What do I need first?    → dependency_hints[] per param

Structure per operation:
{
  "op":      "gcp.container.projects.locations.clusters.list",
  "service": "container",
  "kind":    "read_list",                      // read_list | read_get | other
  "http": {
    "verb": "GET",
    "path": "/v1/{+parent}/clusters",
    "pattern": "^projects/[^/]+/locations/[^/]+$"  // from required param if name/parent
  },
  "python_call": "svc.projects().locations().clusters().list(**params).execute()",
  "inputs": {
    "required": [
      {
        "param":    "parent",
        "type":     "string",
        "template": "projects/{project}/locations/{location}",
        "slots": [
          { "slot": "project",  "source": "always_available" },
          { "slot": "location", "source": "always_available" }
        ],
        "description": "..."
      }
    ],
    "optional": ["pageSize", "pageToken"]
  },
  "outputs": {
    "response_schema": "ListClustersResponse",
    "list_field":  "clusters",           // for read_list: the array field
    "id_field":    "name",               // the identity field inside each item
    "id_is_full_resource_name": true,    // item.name = full resource path?
    "produces_fields": [                 // dot-path notation
      { "path": "clusters[].name",     "type": "string", "is_id": true  },
      { "path": "clusters[].location", "type": "string", "is_id": false },
      { "path": "clusters[].status",   "type": "string", "is_id": false },
      { "path": "nextPageToken",        "type": "string", "is_id": false }
    ]
  },
  "independent": true,
  "dependency_hints": [
    {
      "param": "parent",
      "can_come_from": [
        {
          "kind":     "known_format",
          "template": "projects/{project}/locations/{location}",
          "slots": [
            { "slot": "project",  "source": "always_available" },
            { "slot": "location", "source": "always_available" }
          ]
        }
      ]
    }
  ]
}
"""

import json
import re
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId',
    'customerId', 'accountId',
}

# Literal segment in resource path → always-available param name
SEGMENT_TO_ALWAYS = {
    'projects':       'project',
    'locations':      'location',
    'regions':        'region',
    'zones':          'zone',
    'organizations':  'organizationId',
    'folders':        'folderId',
    'billingAccounts':'billingAccountId',
    'customers':      'customerId',
    'accounts':       'accountId',
}

# Fields to skip in produces_fields (pagination / noise)
SKIP_FIELDS = {'nextPageToken', 'kind', 'etag', 'unreachable', 'warnings'}

# ─────────────────────────────────────────────────────────────────────────────
# PATTERN PARSER
# ─────────────────────────────────────────────────────────────────────────────

def _is_var_segment(seg: str) -> bool:
    """Is this path segment a regex variable (not a literal)?"""
    return seg in ('[^/]+', '[^/]*', '.*', '.+', '__VAR__')


def singularize(word: str) -> str:
    if word.endswith('ies'):
        return word[:-3] + 'y'
    if word.endswith('sses'):
        return word[:-2]
    if word.endswith('ses'):
        return word[:-2]
    if word.endswith('s') and not word.endswith('ss'):
        return word[:-1]
    return word


def parse_pattern(pattern: str) -> tuple[str, list[dict]]:
    """
    Parse a regex pattern like ^projects/[^/]+/locations/[^/]+/clusters/[^/]+$
    into:
      template: "projects/{project}/locations/{location}/clusters/{clusterId}"
      slots:    [
                  {"slot":"project",   "source":"always_available", "after":"projects"},
                  {"slot":"location",  "source":"always_available", "after":"locations"},
                  {"slot":"clusterId", "source":"from_list_op",     "after":"clusters"},
                ]
    """
    if not pattern:
        return '', []

    # Strip anchors
    clean = pattern.lstrip('^').rstrip('$')
    # Normalize all variable markers to __VAR__ BEFORE splitting on '/'
    # so that [^/]+ doesn't get split into '[^' and ']+' on the '/' inside it
    clean = re.sub(r'\[\^/\]\+', '__VAR__', clean)
    clean = re.sub(r'\[\^/\]\*', '__VAR__', clean)
    clean = re.sub(r'\.\*',      '__VAR__', clean)
    clean = re.sub(r'\.\+',      '__VAR__', clean)
    raw_parts = clean.split('/')

    template_parts = []
    slots = []
    prev_literal = None

    for part in raw_parts:
        if _is_var_segment(part):
            # Determine slot name from the preceding literal segment
            if prev_literal and prev_literal in SEGMENT_TO_ALWAYS:
                slot_name = SEGMENT_TO_ALWAYS[prev_literal]
                source = 'always_available'
            elif prev_literal:
                # resource-specific: clusters → clusterId, repositories → repositoryId
                slot_name = singularize(prev_literal) + 'Id'
                source = 'from_list_op'
            else:
                slot_name = 'resourceId'
                source = 'unknown'

            template_parts.append('{' + slot_name + '}')
            slots.append({
                'slot':         slot_name,
                'source':       source,
                'after_segment': prev_literal or '',
            })
        else:
            # literal segment — keep as-is
            template_parts.append(part)
            prev_literal = part

    template = '/'.join(template_parts)
    return template, slots


def is_full_resource_name(id_field_value_sample: str | None, pattern: str) -> bool:
    """
    Heuristic: does the id_field hold a full resource name (contains '/')?
    We detect this if pattern has multiple variable slots — meaning the value
    itself is already a full path like 'projects/x/locations/y/clusters/z'.
    """
    # If pattern has multiple [^/]+ → the field itself IS the full path
    var_count = len(re.findall(r'\[\^/\]\+', pattern))
    return var_count >= 2


# ─────────────────────────────────────────────────────────────────────────────
# TIERED SLOT RESOLVER
# ─────────────────────────────────────────────────────────────────────────────

def build_list_ops_info(all_ops: dict) -> dict:
    """
    Pre-compute info about all read_list ops:
      { op_key: { 'resource': last-segment-before-method,
                  'list_field': ..., 'id_field': ...,
                  'item_fields': [...] } }
    """
    result = {}
    for lk, lop in all_ops.items():
        if lop.get('kind') != 'read_list':
            continue
        parts = lk.split('.')
        # resource = second-to-last part (e.g. 'clusters' in ...clusters.list)
        resource = parts[-2] if len(parts) >= 2 else ''
        rf = lop.get('response_fields', {})
        list_field = None
        id_field = None
        item_fields = []
        for fname, finfo in rf.items():
            if finfo.get('type') == 'array' and finfo.get('id_field'):
                list_field = fname
                id_field = finfo['id_field']
                item_fields = finfo.get('item_fields', [])
                break
        if not list_field:
            for fname, finfo in rf.items():
                if finfo.get('type') == 'array' and fname not in ('unreachable',):
                    list_field = fname
                    id_field = finfo.get('id_field', 'name')
                    item_fields = finfo.get('item_fields', [])
                    break
        result[lk] = {
            'resource':    resource,
            'list_field':  list_field,
            'id_field':    id_field,
            'item_fields': item_fields,
        }
    return result


def resolve_list_op_for_slot(
    after_segment: str,
    slot_name: str,
    list_ops_info: dict,
) -> tuple[str | None, dict | None, int]:
    """
    5-tier resolver: find which list op can provide a slot value.

    Returns: (op_key, op_info, tier)  — tier=5 means external_input (no match)

    Tier 1 — exact resource match: resource == after_segment
             e.g. after_segment='clusters' matches resource='clusters'

    Tier 2 — suffix / plural / camelCase suffix match:
             e.g. after_segment='sites' matches resource='violatingSites'
             (violatingSites ends with 'Sites', singular='Site' ≈ 'site')

    Tier 3 — slot_name appears in item_fields of list op
             e.g. slot_name='siteId', item_fields=['reviewedSite','lastChangeTime']
             → 'site' appears in 'reviewedSite'

    Tier 4 — id_field base name matches slot base
             e.g. slot_name='siteId' → base='site'; id_field='reviewedSite' → base='site'

    Tier 5 — no match (external_input)
    """
    if not after_segment and not slot_name:
        return None, None, 5

    after_lower = after_segment.lower()
    slot_base   = slot_name.replace('Id', '').lower()  # e.g. 'clusterId' → 'cluster'

    # ── Tier 1: exact resource match ─────────────────────────────────────────
    for lk, li in list_ops_info.items():
        if li['resource'] == after_segment:
            return lk, li, 1

    # ── Tier 2: suffix / plural / camelCase suffix match ─────────────────────
    # "violatingSites".lower() ends with "sites" (=after_lower)
    # or singular of resource == singular of after_segment
    after_singular = singularize(after_lower)
    for lk, li in list_ops_info.items():
        res_lower = li['resource'].lower()
        res_singular = singularize(res_lower)
        if (res_lower.endswith(after_lower)          # violatingSites ends with 'sites'
                or after_lower.endswith(res_lower)   # after is longer suffix of resource
                or res_singular == after_singular):  # both singular to same word
            return lk, li, 2

    # ── Tier 3: slot_name base appears in item_fields ────────────────────────
    for lk, li in list_ops_info.items():
        for f in li.get('item_fields', []):
            if slot_base in f.lower():
                return lk, li, 3

    # ── Tier 4: id_field base matches slot base ───────────────────────────────
    for lk, li in list_ops_info.items():
        id_f = li.get('id_field', '') or ''
        # strip common prefixes/suffixes: 'reviewedSite' → 'site'
        id_base = id_f.lower()
        # strip 'reviewed', 'managed', 'hosted', etc. — take last camelCase word
        # simple heuristic: find longest suffix that matches slot_base
        if id_base.endswith(slot_base) or slot_base.endswith(id_base):
            return lk, li, 4
        # also try singularize
        if singularize(id_base) == singularize(slot_base):
            return lk, li, 4

    return None, None, 5


TIER_CONFIDENCE = {
    1: 'exact',
    2: 'suffix_match',
    3: 'field_match',
    4: 'id_base_match',
    5: 'external_input',
}


# ─────────────────────────────────────────────────────────────────────────────
# PRODUCES FIELDS
# ─────────────────────────────────────────────────────────────────────────────

def build_produces_fields(op: dict, op_key: str) -> dict:
    """
    Build the outputs section:
      list_field, id_field, id_is_full_resource_name, produces_fields[]
    """
    kind          = op.get('kind', '')
    response_flds = op.get('response_fields', {})

    result = {
        'response_schema':          op.get('response_schema', ''),
        'list_field':               None,
        'id_field':                 None,
        'id_is_full_resource_name': False,
        'produces_fields':          [],
    }

    if kind == 'read_list':
        # Find the array field with id_field set
        list_field = None
        id_field   = None
        for fname, finfo in response_flds.items():
            if finfo.get('type') == 'array' and finfo.get('id_field'):
                list_field = fname
                id_field   = finfo['id_field']
                break
        # Fallback: first array field
        if not list_field:
            for fname, finfo in response_flds.items():
                if finfo.get('type') == 'array' and fname not in ('unreachable',):
                    list_field = fname
                    id_field   = finfo.get('id_field', 'name')
                    break

        result['list_field'] = list_field
        result['id_field']   = id_field

        # Is the id_field a full resource name?
        # id_field == 'name' strongly implies full resource path in GCP
        result['id_is_full_resource_name'] = (id_field == 'name') or (id_field == 'selfLink')

        if list_field:
            finfo      = response_flds.get(list_field, {})
            item_flds  = finfo.get('item_fields', [])

            # id field first
            if id_field:
                result['produces_fields'].append({
                    'path':  f'{list_field}[].{id_field}',
                    'type':  'string',
                    'is_id': True,
                    'note':  'resource identity — use to call .get() or as parent/name param',
                })

            # remaining item fields (top useful ones, skip id again)
            for f in item_flds:
                if f == id_field:
                    continue
                if f in SKIP_FIELDS:
                    continue
                result['produces_fields'].append({
                    'path':  f'{list_field}[].{f}',
                    'type':  'string',
                    'is_id': False,
                })

        # Also include top-level non-array fields (like nextPageToken)
        for fname, finfo in response_flds.items():
            if finfo.get('type') != 'array' and fname not in SKIP_FIELDS:
                result['produces_fields'].append({
                    'path': fname,
                    'type': finfo.get('type', 'string'),
                    'is_id': False,
                })

    elif kind == 'read_get':
        for fname, finfo in response_flds.items():
            if fname in SKIP_FIELDS:
                continue
            result['produces_fields'].append({
                'path':  fname,
                'type':  finfo.get('type', 'string'),
                'is_id': fname in ('name', 'selfLink', 'id'),
            })

    return result


# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY HINTS
# ─────────────────────────────────────────────────────────────────────────────

def build_dependency_hints(
    op: dict,
    op_key: str,
    all_ops: dict,
    list_ops_info: dict,
) -> list[dict]:
    """
    For each required param, build dependency_hints showing:
      1. known_format  — if param can be built from ALWAYS_AVAILABLE slots
      2. from_list_op  — if a list op in this service produces the value
                         (uses 5-tier resolver for robust matching)
      3. from_get_op   — if a get op produces it as a response field
    """
    hints = []
    req   = op.get('required_params', {})

    for pname, pinfo in req.items():
        pattern = pinfo.get('pattern', '')
        can_come_from = []

        # ── classify param source ────────────────────────────────────────────
        is_composite_path = bool(re.search(r'(?<!\[)[^[]*/', pattern))

        # ── always_available: check param name FIRST regardless of pattern ──
        if pname in ALWAYS_AVAILABLE:
            can_come_from.append({
                'kind':  'always_available',
                'param': pname,
            })

        # ── parse composite path pattern → template + slots ──────────────────
        if pattern and is_composite_path and pname not in ALWAYS_AVAILABLE:
            template, slots = parse_pattern(pattern)

            # known_format (always useful even if partial)
            can_come_from.append({
                'kind':     'known_format',
                'template': template,
                'slots':    slots,
            })

            # ── find list ops for each from_list_op slot using tiered resolver ──
            for slot in slots:
                if slot['source'] != 'from_list_op':
                    continue
                after_seg = slot['after_segment']  # e.g. 'clusters', 'sites'
                slot_name = slot['slot']           # e.g. 'clusterId', 'siteId'

                lk, li, tier = resolve_list_op_for_slot(after_seg, slot_name, list_ops_info)

                if tier < 5 and lk and li:
                    can_come_from.append({
                        'kind':          'from_list_op',
                        'op':            lk,
                        'match_tier':    tier,
                        'match_confidence': TIER_CONFIDENCE[tier],
                        'list_field':    li['list_field'],
                        'id_field':      li['id_field'],
                        'produces_slot': slot_name,
                        'note': (
                            f'[tier {tier}/{TIER_CONFIDENCE[tier]}] '
                            f'call {lk}, iterate response["{li["list_field"]}"][], '
                            f'extract item["{li["id_field"]}"] → fill slot {{{slot_name}}}'
                        ),
                    })
                else:
                    # No match — external input needed
                    can_come_from.append({
                        'kind':          'external_input',
                        'slot':          slot_name,
                        'after_segment': after_seg,
                        'note': (
                            f'No list op found for slot {{{slot_name}}} '
                            f'(after_segment="{after_seg}") — must supply externally'
                        ),
                    })

        elif pname not in ALWAYS_AVAILABLE:
            # No composite path — simple single-value param
            # Use tiered resolver: treat pname itself as the slot_name
            # and pname.replace('Id','') as after_segment
            after_seg = pname.replace('Id', '')
            lk, li, tier = resolve_list_op_for_slot(after_seg, pname, list_ops_info)

            if tier < 5 and lk and li:
                can_come_from.append({
                    'kind':          'from_list_op',
                    'op':            lk,
                    'match_tier':    tier,
                    'match_confidence': TIER_CONFIDENCE[tier],
                    'list_field':    li['list_field'],
                    'id_field':      li['id_field'],
                    'produces_slot': pname,
                    'note': (
                        f'[tier {tier}/{TIER_CONFIDENCE[tier]}] '
                        f'call {lk}, iterate response["{li["list_field"]}"][], '
                        f'extract item["{li["id_field"]}"] → use as "{pname}"'
                    ),
                })
            else:
                # Also scan get ops for this param as response field
                for gk, gop in all_ops.items():
                    if gk == op_key:
                        continue
                    if gop.get('kind') == 'read_get':
                        rf = gop.get('response_fields', {})
                        if pname in rf:
                            can_come_from.append({
                                'kind':  'from_get_op',
                                'op':    gk,
                                'field': pname,
                                'note':  f'response field "{pname}" from {gk}',
                            })

                if not can_come_from:
                    can_come_from.append({
                        'kind': 'external_input',
                        'slot': pname,
                        'note': f'No producer found for "{pname}" — must supply externally',
                    })

        if can_come_from:
            hints.append({
                'param':        pname,
                'can_come_from': can_come_from,
            })

    return hints


# ─────────────────────────────────────────────────────────────────────────────
# INPUTS BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_inputs(op: dict) -> dict:
    """Build inputs section with template + slots for each required param."""
    req      = op.get('required_params', {})
    optional = list(op.get('optional_params', {}).keys())

    required_list = []
    for pname, pinfo in req.items():
        pattern  = pinfo.get('pattern', '')
        template = ''
        slots    = []

        # A pattern is a composite resource path only if it has a literal '/'
        # OUTSIDE of character class brackets — e.g. ^projects/[^/]+/locations/[^/]+$
        # ^[^/]+$ has '/' only inside [...] so is NOT a composite path
        is_composite_path = bool(re.search(r'(?<!\[)[^[]*/', pattern))

        if pname in ALWAYS_AVAILABLE:
            # Always check ALWAYS_AVAILABLE first regardless of pattern
            # e.g. projectId with pattern ^[^/]+$ is still always_available
            template = '{' + pname + '}'
            slots    = [{'slot': pname, 'source': 'always_available', 'after_segment': ''}]
        elif pattern and is_composite_path:
            # Composite resource path param — parse into named slots
            # e.g. parent with pattern ^projects/[^/]+/locations/[^/]+$
            template, slots = parse_pattern(pattern)
        else:
            # Simple non-path param — comes from a prior list/get op
            # e.g. datasetId, tableId, clusterId — use param name as slot name directly
            template = '{' + pname + '}'
            slots    = [{'slot': pname, 'source': 'from_list_op', 'after_segment': pname.replace('Id','')}]

        required_list.append({
            'param':       pname,
            'type':        pinfo.get('type', 'string'),
            'location':    pinfo.get('location', 'path'),
            'template':    template,
            'slots':       slots,
            'pattern':     pattern,
            'description': pinfo.get('description', '')[:120],
        })

    return {
        'required': required_list,
        'optional': optional,
    }


# ─────────────────────────────────────────────────────────────────────────────
# INDEPENDENCE CHECK
# ─────────────────────────────────────────────────────────────────────────────

def compute_independence(op: dict) -> bool:
    """
    An op is independent if ALL required param slots are always_available.
    This correctly handles composite params like parent='projects/X/locations/Y'
    where both slots {project} and {location} are always_available.
    """
    req = op.get('required_params', {})
    if not req:
        return True

    for pname, pinfo in req.items():
        pattern = pinfo.get('pattern', '')

        is_composite_path = bool(re.search(r'(?<!\[)[^[]*/', pattern))
        if pname in ALWAYS_AVAILABLE:
            pass  # ok — always available regardless of pattern
        elif pattern and is_composite_path:
            _, slots = parse_pattern(pattern)
            for slot in slots:
                if slot['source'] != 'always_available':
                    return False
        else:
            return False

    return True


# ─────────────────────────────────────────────────────────────────────────────
# MAIN BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_registry_for_service(svc_dir: Path) -> dict | None:
    s1_path = svc_dir / 'step1_api_driven_registry.json'
    if not s1_path.exists():
        return None

    s1      = json.load(open(s1_path))
    ops     = s1.get('operations', {})
    service = s1.get('service', svc_dir.name)
    version = s1.get('version', '')

    if not ops:
        return None

    # Pre-compute list_ops_info for tiered slot resolver
    list_ops_info = build_list_ops_info(ops)

    registry_ops = {}

    for op_key, op in ops.items():
        kind = op.get('kind', '')

        # ── independence (re-computed correctly) ─────────────────────────────
        independent = compute_independence(op)

        # ── inputs ────────────────────────────────────────────────────────────
        inputs = build_inputs(op)

        # ── outputs ───────────────────────────────────────────────────────────
        outputs = build_produces_fields(op, op_key)

        # ── dependency_hints ─────────────────────────────────────────────────
        dep_hints = build_dependency_hints(op, op_key, ops, list_ops_info)

        registry_ops[op_key] = {
            'op':          op_key,
            'service':     service,
            'kind':        kind,
            'http': {
                'verb':    op.get('http_method', 'GET'),
                'path':    '/' + op.get('path', '').lstrip('/'),
            },
            'python_call':  op.get('python_call', ''),
            'description':  op.get('description', '')[:200],
            'inputs':       inputs,
            'outputs':      outputs,
            'independent':  independent,
            'dependency_hints': dep_hints,
            'scopes':       op.get('scopes', []),
            'paginated':    op.get('paginated', False),
        }

    # Split by kind for summary stats
    n_list  = sum(1 for o in registry_ops.values() if o['kind'] == 'read_list')
    n_get   = sum(1 for o in registry_ops.values() if o['kind'] == 'read_get')
    n_write = sum(1 for o in registry_ops.values() if o['kind'].startswith('write_'))
    n_other = len(registry_ops) - n_list - n_get - n_write
    n_ind   = sum(1 for o in registry_ops.values() if o['independent'])

    return {
        'service':  service,
        'version':  version,
        'csp':      'gcp',
        'title':    s1.get('title', ''),
        'stats': {
            'total_ops':    len(registry_ops),
            'read_list':    n_list,
            'read_get':     n_get,
            'write':        n_write,
            'other':        n_other,
            'independent':  n_ind,
            'dependent':    len(registry_ops) - n_ind,
        },
        'operations': registry_ops,
    }


# ─────────────────────────────────────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────────────────────────────────────

def run():
    print('=' * 70)
    print('Building step1_api_driven_registry.json for all GCP services')
    print('  (with 5-tier slot resolver for dependency_hints)')
    print('=' * 70)
    print()

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / 'step1_api_driven_registry.json').exists()
    )

    built         = 0
    skipped       = 0
    total_ops     = 0
    total_ind     = 0
    total_dep     = 0

    for svc_dir in all_dirs:
        result = build_registry_for_service(svc_dir)
        if not result:
            print(f'  ⏭  {svc_dir.name}: no step1 — skipping')
            skipped += 1
            continue

        out_path = svc_dir / 'step1_api_driven_registry.json'
        with open(out_path, 'w') as f:
            json.dump(result, f, indent=2)

        stats = result['stats']
        built      += 1
        total_ops  += stats['total_ops']
        total_ind  += stats['independent']
        total_dep  += stats['dependent']

        print(f'  ✓ {svc_dir.name:40s}  '
              f'{stats["total_ops"]:4d} ops  '
              f'ind={stats["independent"]:3d}  '
              f'dep={stats["dependent"]:3d}  '
              f'list={stats["read_list"]:3d}  '
              f'get={stats["read_get"]:3d}')

    print()
    print('=' * 70)
    print(f'Services built : {built}')
    print(f'Skipped        : {skipped}')
    print(f'Total ops      : {total_ops}')
    print(f'Independent    : {total_ind}')
    print(f'Dependent      : {total_dep}')
    print('=' * 70)


if __name__ == '__main__':
    run()
