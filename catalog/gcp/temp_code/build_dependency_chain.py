#!/usr/bin/env python3
"""
Build step4_dependency_chain.json for every GCP service.

Source: step2_read_operation_registry.json (read ops only)

Output format mirrors AWS dependency_index.json:
{
  "service": "bigquery",
  "csp": "gcp",
  "read_only": true,
  "roots": [
    {
      "op": "gcp.bigquery.projects.list",
      "produces": ["gcp.bigquery.projects.etag", ...]
    }
  ],
  "entity_paths": {
    "gcp.bigquery.datasets.dataset_id": [
      {
        "operations": ["gcp.bigquery.datasets.list", "gcp.bigquery.datasets.get"],
        "produces": {
          "gcp.bigquery.datasets.list": ["gcp.bigquery.datasets.dataset_id"],
          "gcp.bigquery.datasets.get":  ["gcp.bigquery.datasets.dataset_id"]
        },
        "consumes": {
          "gcp.bigquery.datasets.list": ["gcp.bigquery.projects.project_id"],
          "gcp.bigquery.datasets.get":  ["gcp.bigquery.datasets.dataset_id",
                                          "gcp.bigquery.projects.project_id"]
        },
        "external_inputs": []   # entities that must come from outside this chain
      }
    ]
  }
}

Chain logic:
  - ROOT op  = required_params is empty  OR  all required_params are in ALWAYS_AVAILABLE
  - ALWAYS_AVAILABLE = {projectId, project, parent} (GCP always knows these from context)
  - entity namespace = {service}.{resource}_{snake_field}
    (from produces[].entity in step2_read registry)
  - consumes namespace = same (from consumes[].entity)
  - external_inputs = consumes entities that no read op in this service produces
"""

import json
import re
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')

# Params GCP always has available without a prior call
ALWAYS_AVAILABLE = {
    'projectId', 'project', 'parent', 'name',
    'location', 'region', 'zone',
    'organizationId', 'folderId', 'billingAccountId',
    'customerId',
}

def snake(s: str) -> str:
    """camelCase → snake_case."""
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', s)
    s = re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s)
    return s.lower()

def param_to_entity(service: str, param: str, op_key: str) -> str:
    """
    Convert a required param name to an entity name.
    e.g. service=bigquery, param=datasetId, op=gcp.bigquery.datasets.get
      → gcp.bigquery.datasets.dataset_id
    Try to use consumes[].entity from the op itself first.
    """
    return f"gcp.{service}.{snake(param)}"

def build_chain(svc_dir: Path) -> dict | None:
    service = svc_dir.name
    read_path = svc_dir / 'step2_read_operation_registry.json'
    if not read_path.exists():
        return None

    reg = json.load(open(read_path))
    ops = reg.get('operations', {})
    if not ops:
        return None

    # ── Index every op ──────────────────────────────────────────────────────
    # op_info[op_key] = {
    #   required_params: [...],
    #   consumes_entities: [entity, ...],   # from consumes[].entity
    #   produces_entities: [entity, ...],   # from produces[].entity (item + output)
    # }
    op_info = {}
    for op_key, op in ops.items():
        req = op.get('required_params', []) or []
        consumes = op.get('consumes', []) or []
        produces = op.get('produces', []) or []

        # Gather entities this op consumes
        cons_entities = []
        for c in consumes:
            ent = c.get('entity', '')
            if ent:
                cons_entities.append(ent)
            else:
                # Fallback: build entity from param name
                param = c.get('param', '')
                if param:
                    cons_entities.append(f"gcp.{service}.{snake(param)}")

        # Gather entities this op produces
        prod_entities = []
        for p in produces:
            ent = p.get('entity', '')
            if ent:
                prod_entities.append(ent)

        op_info[op_key] = {
            'required_params':    req,
            'consumes_entities':  cons_entities,
            'produces_entities':  prod_entities,
        }

    # ── Build set of all produced entities across this service ───────────────
    all_produced: set[str] = set()
    for info in op_info.values():
        all_produced.update(info['produces_entities'])

    # ── Identify ROOT ops ─────────────────────────────────────────────────────
    roots = []
    for op_key, info in op_info.items():
        req = info['required_params']
        # Root = no required params, or all required params are always available
        if all(p in ALWAYS_AVAILABLE for p in req):
            roots.append({
                'op': op_key,
                'produces': info['produces_entities'],
            })

    # ── Build entity_paths ────────────────────────────────────────────────────
    # entity → list of {operations, produces, consumes, external_inputs}
    # An entity can be produced by multiple ops, so we group them.
    entity_to_ops: dict[str, list[str]] = defaultdict(list)
    for op_key, info in op_info.items():
        for ent in info['produces_entities']:
            entity_to_ops[ent].append(op_key)

    entity_paths: dict[str, list] = {}
    for entity, producing_ops in sorted(entity_to_ops.items()):
        path_entry = {
            'operations': producing_ops,
            'produces': {},
            'consumes': {},
            'external_inputs': [],
        }

        external: set[str] = set()
        for op_key in producing_ops:
            info = op_info[op_key]
            # produces: entities this op emits that include this entity
            path_entry['produces'][op_key] = [
                e for e in info['produces_entities'] if e == entity
            ]
            # consumes: all entities this op needs
            path_entry['consumes'][op_key] = info['consumes_entities']
            # external: consumed entities not produced by any read op in this service
            for e in info['consumes_entities']:
                if e not in all_produced:
                    external.add(e)

        path_entry['external_inputs'] = sorted(external)
        entity_paths[entity] = [path_entry]

    return {
        'service':   service,
        'csp':       'gcp',
        'read_only': True,
        'roots':     roots,
        'entity_paths': entity_paths,
    }


def run():
    print('=' * 70)
    print('Building step4_dependency_chain.json for all GCP services')
    print('=' * 70)

    service_dirs = sorted(
        d for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and not d.name.endswith('.py') and not d.name.endswith('.md')
    )

    built = skipped = 0
    total_roots = total_entities = 0

    for sdir in service_dirs:
        chain = build_chain(sdir)
        if chain is None:
            skipped += 1
            continue

        # Remove old step4 gcp_dependencies file and write new dependency_chain
        for old in sdir.glob('step4_gcp_dependencies*.json'):
            old.unlink()

        out_path = sdir / 'step4_dependency_chain.json'
        with open(out_path, 'w') as f:
            json.dump(chain, f, indent=2)

        r = len(chain['roots'])
        e = len(chain['entity_paths'])
        total_roots   += r
        total_entities += e
        built += 1
        print(f'  ✓ {sdir.name}: {r} roots  {e} entities')

    print()
    print(f'Built:           {built} services')
    print(f'Skipped:         {skipped} (no read registry)')
    print(f'Total roots:     {total_roots}')
    print(f'Total entities:  {total_entities}')
    print('=' * 70)


if __name__ == '__main__':
    run()
