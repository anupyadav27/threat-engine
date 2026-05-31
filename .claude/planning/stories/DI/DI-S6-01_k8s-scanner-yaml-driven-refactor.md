# DI-S6-01 — K8s Scanner: YAML-Driven Dispatch (Option B Refactor)
**Sprint**: DI-S6 | **Type**: Tech Debt / Architecture | **Status**: Planned
**Points**: 5 | **Priority**: Medium (blocks K8s scan accuracy permanently)

---

## Problem

The K8s scanner uses **hardcoded Python handlers** per resource type with hand-written
`_discovery_id` strings:

```python
@k8s_handler('pod')
def _scan_pods(core_v1, apps_v1, ...):
    pod_list = core_v1.list_pod_for_all_namespaces()
    item['_discovery_id'] = 'k8s.pod.list_pods'   # ← hand-written, drifts from DB
```

All other CSPs (AWS, Azure, GCP, OCI, AliCloud) read their ops from the DB's
`rule_discoveries.discoveries_data` at runtime. The `_discovery_id` is then always
in sync with the DB because it comes from the same source.

**Consequence**: K8s `_discovery_id` tags drift from DB `discovery_id` values.
The DI enumerator's filter silently drops all K8s items → 0 rows written.
Every time the DB is updated (new rule, renamed op), the Python file must also
be manually updated — a maintenance trap.

---

## Goal

Make the K8s scanner **data-driven** like the AWS scanner:

1. At runtime, read `rule_discoveries.discoveries_data` for `provider='k8s'`
2. Map the `action` field in each discovery op to a typed K8s client method
3. Call the method, serialize the result, tag with `_discovery_id` from the DB record
4. No hardcoded handler functions for resource enumeration

---

## Current Architecture (to be replaced)

```
DB: rule_discoveries (provider=k8s, service=pod)
    discoveries_data[0].action = 'list_pod_for_all_namespaces'
    discoveries_data[0].discovery_id = 'k8s.pod.list_pod_for_all_namespaces'

K8s Scanner today:
    @k8s_handler('pod')
    def _scan_pods(...):
        core_v1.list_pod_for_all_namespaces()   # hardcoded call
        item['_discovery_id'] = 'k8s.pod.list_pods'   # WRONG — hand-written
```

---

## Target Architecture

```
DB: rule_discoveries (provider=k8s, service=pod)
    discoveries_data[0].action = 'list_pod_for_all_namespaces'
    discoveries_data[0].discovery_id = 'k8s.pod.list_pod_for_all_namespaces'
          ↓
K8s Scanner (refactored):
    ACTION_DISPATCH = {
        'list_pod_for_all_namespaces':           ('core_v1', 'list_pod_for_all_namespaces'),
        'list_deployment_for_all_namespaces':    ('apps_v1', 'list_deployment_for_all_namespaces'),
        'list_namespace':                        ('core_v1', 'list_namespace'),
        'list_service_for_all_namespaces':       ('core_v1', 'list_service_for_all_namespaces'),
        'list_role_for_all_namespaces':          ('rbac_v1', 'list_role_for_all_namespaces'),
        ... (all K8s actions)
    }

    scan_service(service, region, config):
        for op in config['discovery']:
            client_name, method = ACTION_DISPATCH[op['action']]
            result = getattr(self.<client_name>, method)()
            for item in result.items:
                serialized = _serialize_k8s_object(item)
                serialized['_discovery_id'] = op['discovery_id']   # FROM DB ✓
```

---

## Implementation Plan

### Step 1 — Audit all K8s actions in DB
```sql
SELECT service,
       d->>'action' as action,
       d->>'discovery_id' as discovery_id
FROM rule_discoveries,
     jsonb_array_elements(discoveries_data) AS d
WHERE provider = 'k8s'
ORDER BY service, action;
```
Produce a full table of `action → (client, method)` mappings needed.

### Step 2 — Build ACTION_DISPATCH table
Map every `action` string from the DB to a `(client_attr, method_name)` tuple.
Clients needed:
- `core_v1` → `client.CoreV1Api()`
- `apps_v1` → `client.AppsV1Api()`
- `rbac_v1` → `client.RbacAuthorizationV1Api()`
- `networking_v1` → `client.NetworkingV1Api()`
- `batch_v1` → `client.BatchV1Api()`
- `admissionreg_v1` → `client.AdmissionregistrationV1Api()`
- `storage_v1` → `client.StorageV1Api()`

### Step 3 — Refactor `scan_service()`
Replace `K8S_SERVICE_HANDLERS` dict dispatch with:
```python
async def scan_service(self, service, region, config, skip_dependents=False):
    items = []
    for op in config.get('discovery', []):
        action = op.get('action') or op.get('calls', [{}])[0].get('action')
        if action not in ACTION_DISPATCH:
            logger.warning("No K8s dispatch for action=%s", action)
            continue
        client_attr, method = ACTION_DISPATCH[action]
        k8s_client = getattr(self, client_attr)
        result = k8s_client.__getattribute__(method)()
        for raw in result.items:
            item = _serialize_k8s_object(raw)
            item['_discovery_id'] = op['discovery_id']   # from DB
            item['resource_type'] = op.get('resource_type', f'k8s/{service}')
            items.append(item)
    return items, {}
```

### Step 4 — Preserve serialization helpers
`_serialize_k8s_object()`, `_enrich_k8s_item()`, and auth logic stay unchanged.
Only the dispatch mechanism changes.

### Step 5 — Remove hardcoded handler functions
Delete all `@k8s_handler` decorated functions and the `K8S_SERVICE_HANDLERS` dict.
Keep: auth, serialization, `_extract_uid_from_k8s_item()`.

### Step 6 — Test with all 5 DI-S5-07 services
```bash
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id e0f65d09-d974-4357-987e-59db7e50bed1 \
   --services pod,deployment,service,namespace,role \
   > /tmp/di_scan_k8s.log 2>&1 & disown && echo started"
```
Expected: rows > 0, zero AuthErrors, UIDs start with `k8s://`.

---

## Acceptance Criteria

- [ ] No `@k8s_handler` decorated functions remain in `service_scanner.py`
- [ ] `_discovery_id` on every returned item matches `discoveries_data[].discovery_id` in DB exactly
- [ ] All 5 DI-S5-07 services (pod/deployment/service/namespace/role) write rows with canonical `k8s://` UIDs
- [ ] Zero `_discovery_id` mismatch drops in enumerator logs
- [ ] engine-discoveries K8s scan still works (services still dispatched correctly)
- [ ] New image built and deployed (v-di-s6-1 or equivalent)

---

## Gotchas

1. **Namespaced vs cluster-scoped actions**: some K8s API methods require a `namespace` param
   (e.g. `list_namespaced_pod(namespace='default')`), others are cluster-scoped
   (`list_pod_for_all_namespaces()`). The dispatch table must record which variant to call.

2. **`discoveries_data` format**: K8s records use `calls[0].action` not `action` directly
   (see rule_discoveries rows above). Normalize on read.

3. **Typed result objects**: K8s client returns typed objects (not dicts). `_serialize_k8s_object()`
   handles this — keep it exactly as is.

4. **engine-discoveries impact**: the `@k8s_handler` dispatch is only used when `scan_service()`
   is called with `config={'discovery': [...]}`. Both DI engine and discoveries engine call it
   this way. Once refactored, both engines benefit.

5. **Missing actions in dispatch table**: any DB action not in `ACTION_DISPATCH` logs a warning
   and skips. This is safe — same behavior as current missing handler.

---

## Files to Change

| File | Change |
|------|--------|
| `engines/discoveries/providers/kubernetes/scanner/service_scanner.py` | Replace `@k8s_handler` pattern with `ACTION_DISPATCH` table + dynamic `scan_service()` |
| `deployment/aws/eks/engines/engine-di.yaml` | Update image tag |

No DB changes, no schema changes, no BFF changes.

---

## Interim Fix (already in place)

While this story is pending, the Option A quick fix (aligning the 5 hand-written strings to DB values)
is **NOT applied** — the partial edit was intentionally stopped.

The K8s scan (scan_run_id `e0f65d09-d974-4357-987e-59db7e50bed1`) currently produces 0 rows
due to the `_discovery_id` mismatch. Re-run this scan after DI-S6-01 ships.