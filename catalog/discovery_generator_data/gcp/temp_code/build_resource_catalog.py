#!/usr/bin/env python3
"""
Step-6: Resource Catalog — Inventory + Identifier Enrichment
Build step5_resource_catalog_inventory_enrich.json for each GCP service.

INPUT (per service directory):
  step2_read_operation_registry.json
  step2_write_operation_registry.json   (optional)
  step3_read_operation_dependency_chain_independent.json

OUTPUT (per service directory):
  step5_resource_catalog_inventory_enrich.json

SCHEMA:
{
  "csp": "gcp",
  "generated_at": "<iso8601>",
  "anchors": { "fixed": ["project_id","org_id","folder_id","location","zone","region"] },
  "services": {
    "<service>": {
      "version": "<version>",
      "resources": {
        "<resource_type>": {
          "resource_type": "<resource_type>",
          "pattern_type": "PROJECT_GLOBAL"|"ZONAL"|"REGIONAL"|"LOCATION"|"CONSTRUCTED",
          "identifier": {
            "kind": "full_name"|"tuple"|"constructed",
            "full_identifier": { "template": "...", "built_from_parts": [...], "notes": "" },
            "parts": [...],
            "part_sources": { "<part>": { "op": "...", "field_path": "...", "transform": "..." } },
            "transforms": [...]
          },
          "inventory":        { "ops": [...] },
          "inventory_enrich": { "ops": [...] },
          "confidence": <float>,
          "notes": ""
        }
      }
    }
  }
}
"""

import json
import re
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

ANCHORS = ["project_id", "org_id", "folder_id", "location", "zone", "region"]

FULL_NAME_FIELDS = {"name", "selfLink", "resourceName", "fullResourceName"}

ANCHOR_SEGMENTS = {
    "projects":      "project_id",
    "locations":     "location",
    "zones":         "zone",
    "regions":       "region",
    "organizations": "org_id",
    "folders":       "folder_id",
}

# ─────────────────────────────────────────────────────────────────────────────
# LOW-LEVEL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resource_type_from_op(op_key: str) -> str:
    """gcp.service.resource.verb → 'resource'"""
    parts = op_key.split('.')
    return parts[-2] if len(parts) >= 3 else parts[-1]


def _op_http(op: dict) -> dict:
    return op.get('http', {'verb': 'GET', 'path': ''})


def _get_required_params(op: dict) -> dict:
    """Return required params as {pname: pinfo} dict (handles both formats)."""
    inputs = op.get('inputs', {})
    req_list = inputs.get('required', [])
    if req_list:
        return {r['param']: r for r in req_list}
    return op.get('required_params', {})


def _get_list_field(op: dict) -> Optional[str]:
    return op.get('outputs', {}).get('list_field')


def _get_id_field(op: dict) -> Optional[str]:
    return op.get('outputs', {}).get('id_field')


def _get_produces_fields(op: dict) -> list:
    return op.get('outputs', {}).get('produces_fields', [])


def _extract_template_from_path(http_path: str) -> str:
    """Strip version prefix, normalise {+x} → {x}."""
    path = re.sub(r'^/v\d+[^/]*/|^/[^/]+/', '', http_path)
    path = re.sub(r'\{[+*]?(\w+)\}', r'{\1}', path)
    return path


def _parts_from_template(template: str) -> list:
    return re.findall(r'\{(\w+)\}', template)


def _detect_pattern_type(http_path: str) -> str:
    for kw, pt in [('/zones/', 'ZONAL'), ('/regions/', 'REGIONAL'),
                   ('/locations/', 'LOCATION'), ('/projects/', 'PROJECT_GLOBAL')]:
        if kw in http_path:
            return pt
    return 'CONSTRUCTED'


def _anchor_parts_from_path(http_path: str) -> list:
    result = []
    for seg, anchor in ANCHOR_SEGMENTS.items():
        if f'/{seg}/' in http_path:
            result.append(anchor)
    return result


def _get_chain(op_key: str, chains: dict) -> Optional[dict]:
    """Return step3 chain for op_key; None if independent or missing."""
    c = chains.get(op_key)
    if c is None or c.get('independent', False):
        return None
    return c


# ─────────────────────────────────────────────────────────────────────────────
# RESOURCE GROUPING  (core insight: use step3 chains to pair list → get)
# ─────────────────────────────────────────────────────────────────────────────

def _group_resources(all_ops: dict, chains: dict) -> dict:
    """
    Group ops into resource buckets: resource_type → {inv: [...], enrich: [...]}.

    Strategy:
      1. For every read_get op, look up its step3 chain.
         The first independent list op in execution_steps is the canonical
         inventory op → group them together under the get op's resource_type.
      2. Any remaining (ungrouped) list op becomes its own resource_type.

    Returns {resource_type: {'inv': [(key, op)], 'enrich': [(key, op)]}}.
    """
    groups: dict[str, dict] = {}

    # Track which list ops are already claimed by a get op
    claimed_list_ops: set = set()

    # Pass 1: process get ops (enrich), pull in their inventory list op from chains
    for op_key, op in sorted(all_ops.items()):
        kind = op.get('kind', '')
        if kind not in ('read_get',) and not op_key.endswith('.get'):
            continue

        rtype = _resource_type_from_op(op_key)
        if rtype not in groups:
            groups[rtype] = {'inv': [], 'enrich': []}

        groups[rtype]['enrich'].append((op_key, op))

        # Find inventory ops from step3 chain
        chain = chains.get(op_key)
        if chain and not chain.get('independent', False):
            steps = chain.get('execution_steps', [])
            for step in steps:
                step_op_key = step.get('op', '')
                step_kind   = step.get('kind', '')
                step_ind    = step.get('independent', False)
                if step_op_key == op_key:
                    continue  # skip the get op itself
                if step_kind == 'read_list' or step_op_key.endswith('.list'):
                    if step_op_key in all_ops:
                        groups[rtype]['inv'].append((step_op_key, all_ops[step_op_key]))
                        claimed_list_ops.add(step_op_key)

    # Pass 2: add any unclaimed list ops as their own resource_type
    for op_key, op in sorted(all_ops.items()):
        kind = op.get('kind', '')
        if op_key in claimed_list_ops:
            continue
        if kind not in ('read_list',) and not op_key.endswith('.list'):
            continue

        rtype = _resource_type_from_op(op_key)
        if rtype not in groups:
            groups[rtype] = {'inv': [], 'enrich': []}

        # Only add if not already present (may have been added via chain lookup)
        existing_keys = {k for k, _ in groups[rtype]['inv']}
        if op_key not in existing_keys:
            groups[rtype]['inv'].append((op_key, op))

    # Deduplicate: remove duplicate inv entries per resource_type
    for rtype in groups:
        seen = set()
        deduped = []
        for ok, op in groups[rtype]['inv']:
            if ok not in seen:
                deduped.append((ok, op))
                seen.add(ok)
        groups[rtype]['inv'] = deduped

    return groups


# ─────────────────────────────────────────────────────────────────────────────
# IDENTIFIER BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _build_identifier(
    resource_type: str,
    inv_pairs: list,
    enrich_pairs: list,
) -> dict:
    """
    Determine identifier kind, full_identifier, parts, part_sources, transforms.

    Rules:
      full_name  — enrich HTTP path has /projects/|/zones/|/regions/|/locations/
                   AND enrich requires 'name' param
      full_name  — inventory produces a field in FULL_NAME_FIELDS (name/selfLink/…)
      constructed — enrich requires a param that can't be directly found in
                    inventory output by the same name (needs URL encoding / prefix)
      tuple      — fallback
    """
    identifier = {
        "kind": "tuple",
        "full_identifier": {"template": "", "built_from_parts": [], "notes": ""},
        "parts": [],
        "part_sources": {},
        "transforms": [],
    }

    inv_op_key, inv_op     = inv_pairs[0]   if inv_pairs   else (None, None)
    enrich_op_key, enrich_op = enrich_pairs[0] if enrich_pairs else (None, None)

    if inv_op is None and enrich_op is None:
        return identifier

    # ── Inventory outputs ─────────────────────────────────────────────────
    list_field = _get_list_field(inv_op) if inv_op else None
    id_field   = _get_id_field(inv_op)   if inv_op else None
    produces   = _get_produces_fields(inv_op) if inv_op else []

    id_field_path = None
    if list_field and id_field:
        id_field_path = f"{list_field}[].{id_field}"
    elif id_field:
        id_field_path = id_field

    # Prefer an is_id=True field or a known full-name field
    for pf in produces:
        fp = pf.get('path', '')
        last_tok = fp.split('.')[-1] if fp else ''
        if pf.get('is_id') or last_tok in FULL_NAME_FIELDS:
            id_field_path = fp
            if pf.get('is_id'):
                id_field = last_tok
            break

    id_last = (id_field or '').split('.')[-1] if id_field else ''

    # ── Enrich op analysis ────────────────────────────────────────────────
    enrich_req  = _get_required_params(enrich_op) if enrich_op else {}
    enrich_path = _op_http(enrich_op).get('path', '') if enrich_op else ''
    raw_template = _extract_template_from_path(enrich_path)
    template_parts = _parts_from_template(raw_template)

    has_gcp_hierarchy = any(
        seg in enrich_path
        for seg in ['/projects/', '/locations/', '/zones/', '/regions/']
    )
    inv_produces_full_name = any(
        pf.get('path', '').split('.')[-1] in FULL_NAME_FIELDS
        for pf in produces
    )

    # ── Decide kind ───────────────────────────────────────────────────────
    if has_gcp_hierarchy and 'name' in enrich_req:
        identifier['kind'] = 'full_name'
    elif inv_produces_full_name:
        identifier['kind'] = 'full_name'
    elif enrich_req and id_field and id_last not in FULL_NAME_FIELDS:
        # Enrich needs a param; inventory has id_field under a different name
        first_enrich_param = next(iter(enrich_req), None)
        if first_enrich_param and first_enrich_param != id_last:
            identifier['kind'] = 'constructed'
        else:
            identifier['kind'] = 'tuple'
    else:
        identifier['kind'] = 'tuple'

    # ── Build parts & part_sources ────────────────────────────────────────
    parts: list = []
    part_sources: dict = {}
    transforms: list = []

    anchor_parts = _anchor_parts_from_path(enrich_path)
    for ap in anchor_parts:
        if ap not in parts:
            parts.append(ap)
            part_sources[ap] = {"op": "service_anchor", "field_path": ap, "transform": None}

    # ── kind-specific logic ───────────────────────────────────────────────
    if identifier['kind'] == 'full_name':
        # Template from enrich op path
        if raw_template and raw_template != '{name}':
            identifier['full_identifier']['template'] = raw_template
        elif enrich_path:
            identifier['full_identifier']['template'] = raw_template
        identifier['full_identifier']['built_from_parts'] = template_parts
        identifier['full_identifier']['notes'] = (
            "Full resource name; anchor parts are user-provided service anchors."
        )

        # Map each template part to its source
        for tp in template_parts:
            if tp == 'name':
                continue
            if tp in part_sources:
                continue
            tp_lower = tp.lower()
            if 'project' in tp_lower:
                anchor = 'project_id'
            elif 'location' in tp_lower:
                anchor = 'location'
            elif 'zone' in tp_lower:
                anchor = 'zone'
            elif 'region' in tp_lower:
                anchor = 'region'
            elif 'org' in tp_lower or 'organization' in tp_lower:
                anchor = 'org_id'
            elif 'folder' in tp_lower:
                anchor = 'folder_id'
            else:
                anchor = None

            if anchor:
                parts.append(tp)
                part_sources[tp] = {"op": "service_anchor", "field_path": anchor, "transform": None}
            else:
                parts.append(tp)
                part_sources[tp] = {
                    "op": inv_op_key or "",
                    "field_path": id_field_path or id_field or tp,
                    "transform": None,
                }

    elif identifier['kind'] == 'constructed':
        # e.g. abusiveexperiencereport: reviewedSite → url_encode → sites/{encoded}
        enrich_param = next(iter(enrich_req), 'name')

        # Get resource segment from enrich path (e.g. "sites" from /v1/{+name} with template sites/{siteId})
        # Try to read from dependency_hints if available
        resource_seg = resource_type  # default
        enrich_hints = enrich_op.get('dependency_hints', []) if enrich_op else []
        for hint in enrich_hints:
            for src in hint.get('can_come_from', []):
                tmpl = src.get('template', '')
                if tmpl:
                    seg_match = re.match(r'^([^/\{]+)/', tmpl)
                    if seg_match:
                        resource_seg = seg_match.group(1)
                        break

        id_part = id_last or id_field or resource_type
        url_encoded_var = f"url_encoded_{id_part}"

        if id_field_path:
            parts.append(id_part)
            part_sources[id_part] = {
                "op": inv_op_key or "",
                "field_path": id_field_path,
                "transform": None,
            }
            transforms.append({
                "from": id_field_path,
                "fn": "url_encode",
                "to": url_encoded_var,
            })
            transforms.append({
                "from": url_encoded_var,
                "fn": f"prefix:{resource_seg}/",
                "to": enrich_param,
            })
            transforms.append({
                "build": "full_id",
                "template": f"{resource_seg}/{{{url_encoded_var}}}",
            })
            full_template = f"{resource_seg}/{{{url_encoded_var}}}"
        else:
            full_template = f"{resource_seg}/{{{resource_type}Id}}"

        identifier['full_identifier']['template'] = full_template
        identifier['full_identifier']['built_from_parts'] = [id_field_path or id_field or resource_type]
        identifier['transforms'] = transforms

    else:  # tuple
        if id_field:
            id_part = id_last if id_last else id_field
            parts.append(id_part)
            part_sources[id_part] = {
                "op": inv_op_key or enrich_op_key or "",
                "field_path": id_field_path or id_field,
                "transform": None,
            }
        if raw_template:
            identifier['full_identifier']['template'] = raw_template
        identifier['full_identifier']['notes'] = "Tuple identifier; anchor parts are user-provided."

    identifier['parts'] = parts
    identifier['part_sources'] = part_sources
    if transforms:
        identifier['transforms'] = transforms

    return identifier


# ─────────────────────────────────────────────────────────────────────────────
# PRODUCES MAP  (inventory output)
# ─────────────────────────────────────────────────────────────────────────────

def _build_produces_map(op: dict) -> dict:
    """{ logical_key → field_path } from op outputs."""
    result = {}
    list_field = _get_list_field(op)
    id_field   = _get_id_field(op)

    if list_field and id_field:
        result[id_field] = f"{list_field}[].{id_field}"

    for pf in _get_produces_fields(op):
        fp = pf.get('path', '')
        if not fp:
            continue
        last = fp.split('.')[-1].replace('[]', '')
        result[last] = fp

    return result


# ─────────────────────────────────────────────────────────────────────────────
# ENRICH PARAM MAPPING
# ─────────────────────────────────────────────────────────────────────────────

def _map_enrich_params(enrich_op: dict, identifier: dict, inv_produces: dict) -> dict:
    """{ param → { from_identifier: "..." } }"""
    req = _get_required_params(enrich_op)
    result = {}
    kind = identifier.get('kind', 'tuple')
    transforms = identifier.get('transforms', [])
    transform_targets = {t.get('to') for t in transforms if 'to' in t}

    for pname in req:
        if pname == 'name' and kind == 'full_name':
            result[pname] = {"from_identifier": "full_id"}
        elif pname in transform_targets:
            result[pname] = {"from_identifier": f"transforms → {pname}"}
        elif pname in (identifier.get('parts') or []):
            result[pname] = {"from_identifier": pname}
        elif pname in inv_produces:
            result[pname] = {"from_identifier": inv_produces[pname]}
        else:
            # Try slot-based lookup from dependency_hints
            hints = enrich_op.get('dependency_hints', [])
            from_hint = None
            for hint in hints:
                if hint.get('param') == pname:
                    for src in hint.get('can_come_from', []):
                        if src.get('kind') == 'from_list_op':
                            from_hint = (
                                f"{src.get('op','')} → "
                                f"{src.get('list_field','[]')}"
                                f"[].{src.get('id_field','')}"
                            )
                            break
                    break
            if from_hint:
                result[pname] = {"from_identifier": from_hint}
            else:
                result[pname] = {"from_identifier": pname}

    return result


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE
# ─────────────────────────────────────────────────────────────────────────────

def _confidence(inv_pairs: list, enrich_pairs: list, identifier: dict) -> float:
    score = 0.0
    if inv_pairs:                                           score += 0.30
    if enrich_pairs:                                        score += 0.30
    if identifier.get('kind', 'tuple') != 'tuple':         score += 0.20
    if identifier.get('full_identifier', {}).get('template'): score += 0.10
    if identifier.get('part_sources'):                      score += 0.10
    return round(min(score, 1.0), 2)


# ─────────────────────────────────────────────────────────────────────────────
# BUILD CATALOG FOR ONE SERVICE
# ─────────────────────────────────────────────────────────────────────────────

def build_catalog_for_service(
    read_path: Path,
    write_path: Optional[Path],
    chains_path: Optional[Path],
) -> Optional[dict]:
    if not read_path.exists():
        return None

    s2r      = json.load(open(read_path))
    ops_read = s2r.get('operations', {})
    service  = s2r.get('service', read_path.parent.name)
    version  = s2r.get('version', '')

    ops_write = {}
    if write_path and write_path.exists():
        ops_write = json.load(open(write_path)).get('operations', {})

    all_ops = {**ops_read, **ops_write}
    if not all_ops:
        return None

    chains: dict = {}
    if chains_path and chains_path.exists():
        chains = json.load(open(chains_path)).get('chains', {})

    # ── Group ops by resource_type ─────────────────────────────────────────
    groups = _group_resources(all_ops, chains)

    # ── Build per-resource entries ─────────────────────────────────────────
    resources: dict = {}

    for rtype in sorted(groups.keys()):
        inv_pairs    = groups[rtype]['inv']
        enrich_pairs = groups[rtype]['enrich']

        if not inv_pairs and not enrich_pairs:
            continue

        identifier = _build_identifier(rtype, inv_pairs, enrich_pairs)

        # Pattern type — prefer enrich path, fall back to inventory
        pattern_type = 'CONSTRUCTED'
        for _, op in enrich_pairs + inv_pairs:
            pt = _detect_pattern_type(_op_http(op).get('path', ''))
            if pt != 'CONSTRUCTED':
                pattern_type = pt
                break
        if identifier['kind'] == 'constructed':
            pattern_type = 'CONSTRUCTED'

        # ── inventory ops ─────────────────────────────────────────────────
        inv_entries = []
        inv_produces_combined: dict = {}
        for op_key, op in inv_pairs:
            pm = _build_produces_map(op)
            inv_produces_combined.update(pm)
            chain = _get_chain(op_key, chains)
            inv_entries.append({
                "op":          op_key,
                "kind":        op.get('kind', ''),
                "independent": op.get('independent', False),
                "http":        _op_http(op),
                "python_call": op.get('python_call', ''),
                "produces":    pm,
                "chain_to_independent": chain,
            })

        # ── inventory_enrich ops ──────────────────────────────────────────
        enrich_entries = []
        for op_key, op in enrich_pairs:
            req_mapped = _map_enrich_params(op, identifier, inv_produces_combined)
            chain = _get_chain(op_key, chains)
            enrich_entries.append({
                "op":              op_key,
                "kind":            op.get('kind', ''),
                "independent":     op.get('independent', False),
                "http":            _op_http(op),
                "python_call":     op.get('python_call', ''),
                "required_params": req_mapped,
                "chain_to_independent": chain,
            })

        notes = ""
        if not inv_pairs:
            notes = "No inventory (list) ops found; enrich only."
        elif not enrich_pairs:
            notes = "No enrich (get) ops found; inventory only."

        resources[rtype] = {
            "resource_type":    rtype,
            "pattern_type":     pattern_type,
            "identifier":       identifier,
            "inventory":        {"ops": inv_entries},
            "inventory_enrich": {"ops": enrich_entries},
            "confidence":       _confidence(inv_pairs, enrich_pairs, identifier),
            "notes":            notes,
        }

    if not resources:
        return None

    return {"service": service, "version": version, "resources": resources}


# ─────────────────────────────────────────────────────────────────────────────
# RUN ALL SERVICES
# ─────────────────────────────────────────────────────────────────────────────

def run_all():
    print('=' * 70)
    print('Building step5_resource_catalog_inventory_enrich.json — all GCP services')
    print('=' * 70)

    all_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir()
        and not d.name.startswith('.')
        and (d / 'step2_read_operation_registry.json').exists()
    )

    built = skipped = 0
    total_resources = 0

    for svc_dir in all_dirs:
        read_path   = svc_dir / 'step2_read_operation_registry.json'
        write_path  = svc_dir / 'step2_write_operation_registry.json'
        chains_path = svc_dir / 'step3_read_operation_dependency_chain_independent.json'

        svc_result = build_catalog_for_service(read_path, write_path, chains_path)
        if not svc_result:
            print(f'  ⏭  {svc_dir.name}: nothing to catalog')
            skipped += 1
            continue

        out_doc = {
            "csp": "gcp",
            "generated_at": _now_iso(),
            "anchors": {"fixed": ANCHORS},
            "services": {svc_result["service"]: {
                "version": svc_result["version"],
                "resources": svc_result["resources"],
            }},
        }

        out_path = svc_dir / 'step5_resource_catalog_inventory_enrich.json'
        with open(out_path, 'w') as f:
            json.dump(out_doc, f, indent=2)

        nr = len(svc_result['resources'])
        total_resources += nr
        built += 1
        print(f'  ✓ {svc_dir.name:42s} {nr:4d} resource type(s)')

    print()
    print('=' * 70)
    print(f'Services built   : {built}')
    print(f'Skipped          : {skipped}')
    print(f'Total resources  : {total_resources}')
    print('=' * 70)


# ─────────────────────────────────────────────────────────────────────────────
# SINGLE-SERVICE RUN
# ─────────────────────────────────────────────────────────────────────────────

def run_single(read_path: Path, write_path: Optional[Path],
               chains_path: Optional[Path], out_path: Path):
    svc_result = build_catalog_for_service(read_path, write_path, chains_path)
    if not svc_result:
        print('ERROR: no resources cataloged — check input files')
        sys.exit(1)

    out_doc = {
        "csp": "gcp",
        "generated_at": _now_iso(),
        "anchors": {"fixed": ANCHORS},
        "services": {svc_result["service"]: {
            "version": svc_result["version"],
            "resources": svc_result["resources"],
        }},
    }

    with open(out_path, 'w') as f:
        json.dump(out_doc, f, indent=2)

    print(f'Written: {out_path}')
    print(f'  Service        : {svc_result["service"]}')
    print(f'  Resource types : {len(svc_result["resources"])}')
    print('\n── Sample output ──')
    for i, (rtype, rdata) in enumerate(list(svc_result['resources'].items())[:3]):
        snippet = json.dumps({rtype: rdata}, indent=2)
        print(snippet[:1800])
        if i < 2:
            print('...\n')


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Build Step-6 Resource Catalog (Inventory + Identifier Enrichment)'
    )
    parser.add_argument('--read',   type=Path, help='step2_read_operation_registry.json')
    parser.add_argument('--write',  type=Path, default=None)
    parser.add_argument('--chains', type=Path, default=None,
                        help='step3_read_operation_dependency_chain_independent.json')
    parser.add_argument('--out',    type=Path, help='Output catalog JSON path')
    parser.add_argument('--all',    action='store_true',
                        help='Run for all services under BASE_DIR')

    args = parser.parse_args()

    if args.all or (not args.read and not args.out):
        run_all()
        return

    if not args.read or not args.out:
        parser.print_help()
        sys.exit(1)

    run_single(args.read, args.write, args.chains, args.out)


if __name__ == '__main__':
    main()
