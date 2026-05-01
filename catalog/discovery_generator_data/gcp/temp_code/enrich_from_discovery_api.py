#!/usr/bin/env python3
"""
Enrich GCP service data files using the live GCP Discovery API.

For each service folder, this script:

1. Fetches the live Discovery API document (schemas, methods, parameters)
2. Enriches operation_registry.json with:
   - Real item-level field names (from response schemas) in 'produces'
   - Real optional_params from discovery
   - Accurate 'kind' classification
   - Response schema reference
3. Enriches gcp_dependencies_with_python_names_fully_enriched.json with:
   - Real optional_params (not just empty [])
   - Real item_fields_count (actual schema property count)
   - Accurate independent vs dependent classification
4. Rewrites the _discovery.yaml with full item: field blocks

Usage:
    python3 enrich_from_discovery_api.py [--service SERVICE] [--dry-run] [--verbose]
"""

import os
import sys
import json
import re
import argparse
import traceback
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip3 install pyyaml"); sys.exit(1)

try:
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("ERROR: google-api-python-client not installed. Run: pip3 install google-api-python-client"); sys.exit(1)

GCP_DIR = Path(__file__).parent

# --------------------------------------------------------------------- #
# Helpers                                                                #
# --------------------------------------------------------------------- #

def camel_to_snake(name: str) -> str:
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def snake_to_camel(name: str) -> str:
    return re.sub(r'_([a-z])', lambda m: m.group(1).upper(), name)

def classify_kind(http_method: str, method_name: str) -> str:
    n = method_name.lower()
    if n in ('list', 'aggregatedlist', 'search', 'listsites', 'listviolatingsites',
             'listnetworkendpoints'):
        return 'read_list'
    if http_method == 'GET':
        return 'read_get'
    if http_method in ('POST', 'PUT', 'PATCH'):
        if n in ('create', 'insert', 'register', 'enable', 'provision', 'add'):
            return 'write_create'
        if n in ('update', 'patch', 'set', 'modify', 'reset', 'change', 'replace'):
            return 'write_update'
        if n in ('delete', 'remove', 'terminate', 'disable', 'destroy', 'undelete',
                 'batchdelete'):
            return 'write_delete'
        if n in ('attach', 'associate', 'grant', 'revoke', 'tag', 'authorize'):
            return 'write_apply'
        return 'other'
    if http_method == 'DELETE':
        return 'write_delete'
    return 'other'

def is_side_effect(kind: str) -> bool:
    return kind.startswith('write_') or kind == 'other'

def is_independent(method_name: str, required_params: List[str],
                   consumes_entities: List[dict]) -> bool:
    """
    A method is 'independent' if it has no required params that come from
    prior operation outputs (i.e., it can be called without any prior discovery).
    Heuristic: if required_params only includes 'projectId' or nothing, it's independent.
    """
    non_project = [p for p in required_params
                   if p not in ('projectId', 'project', 'project_id')]
    return len(non_project) == 0

def resolve_ref_fields(ref_name: str, schemas: dict, depth: int = 0) -> List[str]:
    """Recursively resolve a $ref to get its top-level property names."""
    if depth > 2 or not ref_name:
        return []
    schema = schemas.get(ref_name, {})
    fields = []
    for prop_name, prop in schema.get('properties', {}).items():
        fields.append(prop_name)
    return fields

def get_list_key_and_item_fields(resp_ref: str, schemas: dict
                                  ) -> Tuple[Optional[str], List[str]]:
    """
    For a list response schema, find:
    - The array property name (list key)
    - The item-level fields of the array elements
    """
    schema = schemas.get(resp_ref, {})
    for prop_name, prop in schema.get('properties', {}).items():
        if prop.get('type') == 'array' and '$ref' in prop.get('items', {}):
            item_ref = prop['items']['$ref']
            item_fields = resolve_ref_fields(item_ref, schemas)
            return prop_name, item_fields
    # Fallback: if no array, return all props as item fields directly
    return None, list(schema.get('properties', {}).keys())

def get_item_fields(resp_ref: str, schemas: dict) -> List[str]:
    """For a get/describe response, return the direct property names."""
    return resolve_ref_fields(resp_ref, schemas)


# --------------------------------------------------------------------- #
# Fetch Discovery Document                                               #
# --------------------------------------------------------------------- #

_doc_cache: Dict[str, dict] = {}

def fetch_discovery_doc(service_name: str, version: str) -> Optional[dict]:
    cache_key = f"{service_name}:{version}"
    if cache_key in _doc_cache:
        return _doc_cache[cache_key]
    try:
        svc = build(service_name, version, cache_discovery=False)
        doc = svc._rootDesc
        _doc_cache[cache_key] = doc
        return doc
    except Exception as e:
        return None

def get_service_version(service_dir: Path) -> str:
    """Get the API version from operation_registry.json or discovery YAML."""
    reg = service_dir / "operation_registry.json"
    if reg.exists():
        with open(reg) as f:
            data = json.load(f)
        v = data.get("version", "")
        if v:
            return v
    yaml_path = service_dir / f"{service_dir.name}_discovery.yaml"
    if yaml_path.exists():
        with open(yaml_path) as f:
            content = yaml.safe_load(f)
        module = content.get("services", {}).get("module", "")
        m = re.search(r"'([^']+)'\s*\)", module)
        if m:
            return m.group(1)
    return "v1"


# --------------------------------------------------------------------- #
# Iterate all methods from a discovery document                         #
# --------------------------------------------------------------------- #

def iter_methods(resources: dict, prefix: str = ""):
    """Yield (resource_path, method_name, method_dict) for all nested resources."""
    for res_name, res in resources.items():
        full_res = f"{prefix}{res_name}" if not prefix else f"{prefix}.{res_name}"
        for method_name, method in res.get('methods', {}).items():
            yield full_res, method_name, method
        # Recurse into sub-resources
        if 'resources' in res:
            yield from iter_methods(res['resources'], full_res)


# --------------------------------------------------------------------- #
# Build enriched operation_registry.json                                #
# --------------------------------------------------------------------- #

def build_enriched_registry(service_name: str, doc: dict,
                              existing_registry: dict) -> dict:
    schemas = doc.get('schemas', {})
    resources = doc.get('resources', {})
    version = doc.get('version', 'v1')

    kind_rules = {
        "read_list": ["list", "aggregatedlist"],
        "read_get": ["get", "describe"],
        "write_create": ["create", "insert", "provision", "enable", "register"],
        "write_update": ["update", "patch", "modify", "set", "change", "reset"],
        "write_delete": ["delete", "remove", "terminate", "destroy", "disable"],
        "write_apply": ["attach", "associate", "add", "grant", "revoke", "tag", "authorize"],
        "other": ["default"]
    }

    new_operations = {}

    for res_path, method_name, method in iter_methods(resources):
        op_key = f"gcp.{service_name}.{res_path}.{method_name}"
        http_method = method.get('httpMethod', 'GET')
        path = method.get('path', '')
        description = method.get('description', '')
        parameters = method.get('parameters', {})
        resp = method.get('response', {})
        resp_ref = resp.get('$ref', '')

        # params
        required_params = [k for k, v in parameters.items() if v.get('required')]
        optional_params = [k for k, v in parameters.items() if not v.get('required')]
        # Also check path params
        path_params = re.findall(r'\{[+]?(\w+)\}', path)
        for p in path_params:
            if p not in required_params:
                required_params.append(p)

        # kind
        kind = classify_kind(http_method, method_name)
        side_effect = is_side_effect(kind)

        # python_method
        python_method = camel_to_snake(method_name)

        # produces: build from response schema
        produces = []
        consumes = []

        # consumes: required params
        for p in required_params:
            entity_name = f"gcp.{service_name}.{res_path}.{camel_to_snake(p)}"
            consumes.append({
                "entity": entity_name,
                "param": p,
                "required": True,
                "source": "internal"
            })

        # produces: output + item fields
        if resp_ref and kind in ('read_list', 'read_get', 'other'):
            if kind == 'read_list':
                list_key, item_fields = get_list_key_and_item_fields(resp_ref, schemas)
                if list_key:
                    # output path (the collection)
                    output_entity = f"gcp.{service_name}.{res_path}.{camel_to_snake(list_key)}"
                    produces.append({
                        "entity": output_entity,
                        "source": "output",
                        "path": list_key
                    })
                    # item-level fields
                    for field in item_fields:
                        field_entity = f"gcp.{service_name}.{res_path}.{camel_to_snake(field)}"
                        produces.append({
                            "entity": field_entity,
                            "source": "item",
                            "path": field
                        })
                else:
                    # No array wrapper; treat resp directly
                    for field in item_fields:
                        field_entity = f"gcp.{service_name}.{res_path}.{camel_to_snake(field)}"
                        produces.append({
                            "entity": field_entity,
                            "source": "item",
                            "path": field
                        })
            else:  # read_get
                item_fields = get_item_fields(resp_ref, schemas)
                if item_fields:
                    # output = the response itself (resource path)
                    res_parts = res_path.split('.')
                    output_entity = f"gcp.{service_name}.{res_path}.{camel_to_snake(res_parts[-1])}"
                    produces.append({
                        "entity": output_entity,
                        "source": "output",
                        "path": res_parts[-1]
                    })
                    for field in item_fields:
                        field_entity = f"gcp.{service_name}.{res_path}.{camel_to_snake(field)}"
                        produces.append({
                            "entity": field_entity,
                            "source": "item",
                            "path": field
                        })

        op_entry = {
            "kind": kind,
            "side_effect": side_effect,
            "path": path,
            "httpMethod": http_method,
            "description": description,
            "response_schema": resp_ref if resp_ref else None,
            "sdk": {
                "method": method_name,
                "python_method": python_method
            },
            "consumes": consumes,
            "produces": produces,
        }
        if required_params:
            op_entry["required_params"] = required_params
        if optional_params:
            op_entry["optional_params"] = optional_params

        new_operations[op_key] = op_entry

    return {
        "service": service_name,
        "version": version,
        "csp": "gcp",
        "data_quality": "enriched_from_live_api",
        "kind_rules": kind_rules,
        "entity_aliases": {},
        "overrides": {"param_aliases": {}, "consumes": {}, "produces": {}},
        "operations": new_operations,
        "_metadata": {"total_operations": len(new_operations)}
    }


# --------------------------------------------------------------------- #
# Build enriched gcp_dependencies_with_python_names_fully_enriched.json #
# --------------------------------------------------------------------- #

def build_enriched_dependencies(service_name: str, doc: dict,
                                  registry: dict) -> dict:
    schemas = doc.get('schemas', {})
    resources = doc.get('resources', {})
    ops = registry.get('operations', {})

    independent = []
    dependent = []

    for res_path, method_name, method in iter_methods(resources):
        op_key = f"gcp.{service_name}.{res_path}.{method_name}"
        http_method = method.get('httpMethod', 'GET')
        path = method.get('path', '')
        parameters = method.get('parameters', {})
        resp = method.get('response', {})
        resp_ref = resp.get('$ref', '')

        required_params = [k for k, v in parameters.items() if v.get('required')]
        optional_params = [k for k, v in parameters.items() if not v.get('required')]
        path_params = re.findall(r'\{[+]?(\w+)\}', path)
        for p in path_params:
            if p not in required_params:
                required_params.append(p)

        kind = classify_kind(http_method, method_name)
        python_method = camel_to_snake(method_name)

        # Count actual item fields from schema
        item_fields_count = 0
        if resp_ref:
            if kind == 'read_list':
                _, item_fields = get_list_key_and_item_fields(resp_ref, schemas)
                item_fields_count = len(item_fields)
            else:
                item_fields = get_item_fields(resp_ref, schemas)
                item_fields_count = len(item_fields)

        entry = {
            "operation": f"{res_path}.{method_name}",
            "python_method": python_method,
            "kind": kind,
            "http_method": http_method,
            "path": path,
            "required_params": required_params,
            "optional_params": optional_params,
            "response_schema": resp_ref if resp_ref else None,
            "item_fields_count": item_fields_count
        }

        if is_independent(method_name, required_params, []):
            independent.append(entry)
        else:
            dependent.append(entry)

    return {
        service_name: {
            "service": service_name,
            "csp": "gcp",
            "data_quality": "enriched_from_live_api",
            "total_operations": len(independent) + len(dependent),
            "independent": independent,
            "dependent": dependent
        }
    }


# --------------------------------------------------------------------- #
# Build enriched _discovery.yaml                                        #
# --------------------------------------------------------------------- #

def build_enriched_yaml(service_name: str, version: str, doc: dict,
                         registry: dict, existing_yaml: dict) -> dict:
    """
    Produce an enriched YAML discovery dict by merging:
    - existing YAML structure (discovery IDs, calls)
    - new produces/field data from registry
    """
    ops = registry.get('operations', {})
    schemas = doc.get('schemas', {})

    new_discovery = []

    # Build a map of existing discovery entries keyed by ID
    existing_map = {e['discovery_id']: e for e in existing_yaml.get('discovery', [])}

    # Also add any NEW operations from the live API not in existing YAML
    seen_ids = set()

    for op_key, op in ops.items():
        kind = op.get('kind', '')
        # Only emit read operations in YAML (consistent with existing pattern)
        if kind not in ('read_list', 'read_get'):
            continue

        # Derive the discovery_id
        # op_key = gcp.service.resource.method
        parts = op_key.split('.')
        # Keep existing discovery_id format if it exists
        if op_key in existing_map:
            existing_entry = existing_map[op_key]
            discovery_id = op_key
        else:
            # Try snake_case version
            snake_key = '.'.join(parts[:-1] + [camel_to_snake(parts[-1]).replace('_', '_')])
            if snake_key in existing_map:
                existing_entry = existing_map[snake_key]
                discovery_id = snake_key
            else:
                # Brand new - synthesize entry
                existing_entry = None
                discovery_id = op_key

        if discovery_id in seen_ids:
            continue
        seen_ids.add(discovery_id)

        # Build calls block
        if existing_entry:
            calls = existing_entry.get('calls', [])
        else:
            # Synthesize action from resource path
            res_parts = op_key.replace(f'gcp.{service_name}.', '').rsplit('.', 1)
            action = f"{res_parts[0]}.{res_parts[1]}" if len(res_parts) == 2 else res_parts[0]
            calls = [{"action": action, "save_as": "response", "on_error": "continue"}]

        # Build emit block from produces
        produces = op.get('produces', [])
        output_path = None
        item_fields = []

        for p in produces:
            if p.get('source') == 'output' and not output_path:
                output_path = p.get('path', '')
            elif p.get('source') == 'item':
                item_fields.append(p.get('path', ''))

        emit = {"as": "item"}
        if output_path:
            emit["items_for"] = "{{ response." + output_path + " }}"
        else:
            emit["items_for"] = "{{ response }}"

        if item_fields:
            emit["item"] = {f: "{{ item." + f + " }}" for f in item_fields}

        entry = {
            "discovery_id": discovery_id,
            "calls": calls,
            "emit": emit
        }
        new_discovery.append(entry)

    # Preserve any existing entries not matched by registry
    for did, existing_entry in existing_map.items():
        if did not in seen_ids:
            new_discovery.append(existing_entry)

    return {
        "version": existing_yaml.get('version', '1.0'),
        "provider": "gcp",
        "service": service_name,
        "services": existing_yaml.get('services', {
            "client": service_name,
            "module": f"googleapiclient.discovery.build('{service_name}', '{version}')"
        }),
        "discovery": new_discovery,
        "checks": []
    }


# --------------------------------------------------------------------- #
# YAML writer                                                            #
# --------------------------------------------------------------------- #

def write_yaml_file(yaml_path: Path, content: dict):
    lines = []
    lines.append(f"version: '{content['version']}'")
    lines.append(f"provider: {content['provider']}")
    lines.append(f"service: {content['service']}")
    lines.append("services:")
    lines.append(f"  client: {content['services']['client']}")
    lines.append(f"  module: {content['services']['module']}")
    lines.append("discovery:")

    for entry in content.get("discovery", []):
        lines.append(f"- discovery_id: {entry['discovery_id']}")
        lines.append("  calls:")
        for call in entry.get("calls", []):
            lines.append(f"  - action: {call['action']}")
            lines.append(f"    save_as: {call['save_as']}")
            lines.append(f"    on_error: {call['on_error']}")
        emit = entry.get("emit", {})
        lines.append("  emit:")
        lines.append(f"    as: {emit.get('as', 'item')}")
        lines.append(f"    items_for: '{emit.get('items_for', '{{ response }}')}'" )
        if "item" in emit:
            lines.append("    item:")
            for field, tmpl in emit["item"].items():
                lines.append(f"      {field}: '{tmpl}'")

    lines.append("checks: []")
    lines.append("")

    with open(yaml_path, "w") as f:
        f.write("\n".join(lines))


# --------------------------------------------------------------------- #
# Process one service                                                    #
# --------------------------------------------------------------------- #

def process_service(service_dir: Path, dry_run: bool = False,
                    verbose: bool = False) -> dict:
    service_name = service_dir.name
    result = {"service": service_name, "status": "unknown",
              "ops_total": 0, "ops_with_fields": 0, "error": None}

    # Load existing files
    yaml_path = service_dir / f"{service_name}_discovery.yaml"
    reg_path = service_dir / "operation_registry.json"
    dep_path = service_dir / "gcp_dependencies_with_python_names_fully_enriched.json"

    existing_yaml = {}
    if yaml_path.exists():
        with open(yaml_path) as f:
            existing_yaml = yaml.safe_load(f) or {}

    existing_registry = {}
    if reg_path.exists():
        with open(reg_path) as f:
            existing_registry = json.load(f)

    # Get version
    version = get_service_version(service_dir)
    if not version:
        version = "v1"

    # Fetch live discovery document
    if verbose:
        print(f"  Fetching {service_name} v{version}...")

    doc = fetch_discovery_doc(service_name, version)
    if doc is None:
        result["status"] = "no_api_doc"
        result["error"] = f"Could not fetch discovery for {service_name} {version}"
        return result

    try:
        # 1. Build enriched operation_registry.json
        new_registry = build_enriched_registry(service_name, doc, existing_registry)

        # 2. Build enriched dependencies JSON
        new_deps = build_enriched_dependencies(service_name, doc, new_registry)

        # 3. Build enriched YAML
        new_yaml = build_enriched_yaml(service_name, version, doc,
                                        new_registry, existing_yaml)

        # Count stats
        ops = new_registry.get("operations", {})
        result["ops_total"] = len(ops)
        result["ops_with_fields"] = sum(
            1 for op in ops.values() if op.get("produces")
        )

        if not dry_run:
            # Write operation_registry.json
            with open(reg_path, "w") as f:
                json.dump(new_registry, f, indent=2)

            # Write gcp_dependencies_with_python_names_fully_enriched.json
            with open(dep_path, "w") as f:
                json.dump(new_deps, f, indent=2)

            # Write YAML
            write_yaml_file(yaml_path, new_yaml)

        result["status"] = "done"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        if verbose:
            traceback.print_exc()

    return result


# --------------------------------------------------------------------- #
# Main                                                                   #
# --------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Enrich GCP YAML + JSON files using live GCP Discovery API"
    )
    parser.add_argument("--service", help="Only process this service folder name")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch + compute but don't write files")
    parser.add_argument("--verbose", action="store_true",
                        help="Print detailed progress")
    args = parser.parse_args()

    services_to_process = []
    if args.service:
        d = GCP_DIR / args.service
        if not d.is_dir():
            print(f"ERROR: {d} not found"); sys.exit(1)
        services_to_process = [d]
    else:
        for item in sorted(GCP_DIR.iterdir()):
            if item.is_dir() and not item.name.startswith(('.', '_')):
                services_to_process.append(item)

    total = len(services_to_process)
    prefix = "[DRY-RUN] " if args.dry_run else ""
    print(f"{prefix}Enriching {total} GCP service directories using live Discovery API...")
    print()

    counters = {k: 0 for k in ("done", "no_api_doc", "error", "ops_total", "ops_with_fields")}

    for i, svc_dir in enumerate(services_to_process, 1):
        r = process_service(svc_dir, dry_run=args.dry_run, verbose=args.verbose)
        status = r["status"]
        counters[status] = counters.get(status, 0) + 1
        counters["ops_total"] += r.get("ops_total", 0)
        counters["ops_with_fields"] += r.get("ops_with_fields", 0)

        # Always print per-service line
        err_suffix = f"  ⚠ {r['error']}" if r.get("error") else ""
        print(f"  {prefix}[{i:>3}/{total}] {r['service']:<40} "
              f"{status:<12}  ops={r.get('ops_total',0):>3}  "
              f"enriched={r.get('ops_with_fields',0):>3}{err_suffix}")

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Total service dirs:      {total}")
    print(f"  Successfully enriched:   {counters.get('done', 0)}")
    print(f"  No Discovery API doc:    {counters.get('no_api_doc', 0)}")
    print(f"  Errors:                  {counters.get('error', 0)}")
    print(f"  Total operations found:  {counters['ops_total']}")
    print(f"  Ops with field data:     {counters['ops_with_fields']}")
    if args.dry_run:
        print()
        print("  [DRY RUN - no files were written]")
    print("=" * 60)


if __name__ == "__main__":
    main()
