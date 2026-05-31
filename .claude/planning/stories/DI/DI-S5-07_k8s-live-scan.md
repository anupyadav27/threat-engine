# DI-S5-07 — K8s Live Scan Validation
**Sprint**: DI-S5 | **Points**: 3 | **Status**: Pending

## Goal
Prove end-to-end DI scan for Kubernetes produces canonical UIDs
(`k8s://{cluster_id}/{Kind}/{namespace}/{uid_or_name}`) in `asset_inventory`. The EKS cluster
already running (`vulnerability-eks-cluster`) is the test target — no extra resource cost.

## Test Resource
**K8s Namespace + ConfigMap** (free, already running cluster). Creates an identifiable resource
that the scanner will discover and that produces a predictable UID.

```bash
# Provision test namespace + configmap
kubectl create namespace cspm-di-test
kubectl create configmap cspm-di-test-config \
  --from-literal=key=cspm-di-test-value \
  -n cspm-di-test
kubectl label namespace cspm-di-test cspm-di-test=true
```

```bash
# Teardown
kubectl delete namespace cspm-di-test
# ConfigMap is deleted with namespace
```

## Pre-requisites
- K8s kubeconfig / IRSA credentials available in engine-di pod (IRSA via engine-sa service account)
- `scan_runs` record created for k8s (see below)
- K8s Python client (`kubernetes`) installed in engine-di image (verified in DI-S1-03)

## Create scan_runs Record
```python
kubectl exec -n threat-engine-engines deployment/engine-di -- python3 -c "
import psycopg2, os, uuid
conn = psycopg2.connect(
    host=os.environ['ONBOARDING_DB_HOST'],
    port=os.environ['ONBOARDING_DB_PORT'],
    dbname=os.environ['ONBOARDING_DB_NAME'],
    user=os.environ['ONBOARDING_DB_USER'],
    password=os.environ['ONBOARDING_DB_PASSWORD'],
)
cur = conn.cursor()
scan_run_id = str(uuid.uuid4())
# account_id for K8s = cluster identifier (EKS cluster ARN or cluster name)
cur.execute('''
    INSERT INTO scan_runs
      (scan_run_id, tenant_id, account_id, provider, credential_type, credential_ref, status)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
''', (scan_run_id, 'test-tenant-002', 'vulnerability-eks-cluster', 'k8s',
      'in_cluster', 'in_cluster', 'pending'))
conn.commit()
print('scan_run_id:', scan_run_id)
"
```

## Trigger Scan
```bash
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <K8S_SCAN_RUN_ID> \
   > /tmp/di_scan_k8s.log 2>&1 & disown && echo 'started'"
```

## Validation Checklist

```sql
-- 1. rows written for k8s
SELECT provider, count(*) as rows, count(DISTINCT resource_type) as types
FROM asset_inventory
WHERE scan_run_id = '<K8S_SCAN_RUN_ID>'
GROUP BY provider;
-- Expected: provider=k8s, rows > 50 (all running pods/deployments/svc/configmaps), types > 5

-- 2. canonical K8s UIDs
SELECT count(*) as non_canonical
FROM asset_inventory
WHERE scan_run_id = '<K8S_SCAN_RUN_ID>'
  AND provider = 'k8s'
  AND resource_uid NOT LIKE 'k8s://%';
-- Expected: 0

-- 3. test namespace appears
SELECT resource_uid, resource_name, resource_type
FROM asset_inventory
WHERE scan_run_id = '<K8S_SCAN_RUN_ID>'
  AND resource_type = 'k8s.namespace'
  AND resource_name = 'cspm-di-test';
-- Expected: 1 row with uid: k8s://vulnerability-eks-cluster/Namespace/default/cspm-di-test (or similar)

-- 4. test configmap appears
SELECT resource_uid, resource_name, resource_type
FROM asset_inventory
WHERE scan_run_id = '<K8S_SCAN_RUN_ID>'
  AND resource_type = 'k8s.configmap'
  AND resource_name = 'cspm-di-test-config';
-- Expected: 1 row

-- 5. uid format verification (flat metadata keys embedded correctly)
SELECT resource_uid FROM asset_inventory
WHERE scan_run_id = '<K8S_SCAN_RUN_ID>'
  AND provider = 'k8s'
LIMIT 5;
-- Expected: k8s://{cluster_id}/{Kind}/{namespace}/{uid_or_name}
-- Confirms Strategy 3 in uid_builder.py reads flat "metadata.uid"/"metadata.name" keys correctly
```

## Acceptance Criteria
- [ ] `asset_inventory` has > 50 rows for `provider=k8s` (all cluster workloads)
- [ ] All UIDs start with `k8s://` (0 non-canonical)
- [ ] Test namespace `cspm-di-test` appears in `asset_inventory`
- [ ] Test configmap `cspm-di-test-config` appears in `asset_inventory`
- [ ] UID format confirms cluster_id/Kind/namespace/uid structure
- [ ] Phase 0 scans `global` region (K8s has no regions), dispatch log shows `provider=k8s`

## Definition of Done
- [ ] All 5 SQL checks documented with actual values
- [ ] Test namespace + configmap provisioned, found in scan, torn down
- [ ] Results recorded in `DI-S5-07_k8s_results.md`

## Notes
- **K8s regions**: Always `global` — `_get_scan_regions()` returns `["global"]` for K8s
- **uid_template Strategy 3**: K8s YAML emits flat keys `metadata.uid`, `metadata.name`,
  `metadata.namespace` (not nested dicts). uid_builder.py Strategy 3 checks these flat keys
  and assembles `k8s://{account_id}/{kind}/{namespace}/{uid_val}`
- **credential_type**: `in_cluster` — engine-di pod uses IRSA (engine-sa service account)
  which has K8s API access within the cluster
- **account_id for K8s**: Use cluster name or EKS ARN. This becomes the first path component
  in the `k8s://` UID
- **RBAC for K8s scan**: engine-sa needs `get`/`list`/`watch` on all resource types.
  Check existing ClusterRole bindings before scan.
- **No extra cost**: Uses the already-running `vulnerability-eks-cluster` (EKS control plane
  pricing is fixed regardless of extra namespace)