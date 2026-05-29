# RID-01 — Resource ID Standardisation

## Status
`done`

## Priority
`P0` — Blocks AP-FIX-01 (attack-path canvas) and any future cross-engine join work.

## Goal
Replace all short-form / UUID / synthetic `resource_uid` values written by the
discovery engine with canonical resource IDs produced by `shared/common/resource_id.py`.
All downstream engines (check, IAM, network, inventory, CDR, attack-path) read
`resource_uid` — they do not generate it — so fixing the write path in discovery
automatically fixes every downstream join.

## Background
`shared/common/resource_id.py` was created (replaces deleted `arn.py`) with:
- `make_resource_id(csp, service, resource_type, region, account, name, **kwargs)` — universal entry point
- Per-CSP builder classes: `_AWSBuilder`, `_AzureBuilder`, `_GCPBuilder`, `_OCIBuilder`, `_AliCloudBuilder`, `_IBMBuilder`, `_K8sBuilder`
- Backward-compat functions kept: `normalize_resource_uid`, `parse_arn`, `is_arn`, `host_to_resource_uid`, `get_identifier_pattern`, `preload_identifier_patterns`

Current problem per CSP:
| CSP | Current resource_uid format | Should be |
|-----|---------------------------|-----------|
| AWS | `ec2:ap-south-1:588989875114:sg-xxx` (short-form) | `arn:aws:ec2:ap-south-1:588989875114:security-group/sg-xxx` |
| K8s | `bce7271e-43e7-4b8c-a591-25ad887aa62e` (K8s native UUID — opaque) | `k8s/cluster-id/default/secret/db-creds` |
| Azure | varies | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.{svc}/{type}/{name}` |
| GCP | varies | `//compute.googleapis.com/projects/{proj}/locations/{region}/{type}s/{name}` |
| OCI | OCID (already correct if stored as-is) | `ocid1.instance.oc1.ap-mumbai-1.xxx` |
| AliCloud | varies | `acs:{service}:{region}:{account}:{type}/{name}` |
| IBM | CRN (already correct if stored as-is) | `crn:v1:bluemix:public:{service}:{region}:{account}::{type}:{name}` |

## Acceptance Criteria

### Phase 1 — Discovery engine write path
- [ ] AWS: every row written to `discovery_findings` has `resource_uid` = full ARN
      (calls `normalize_resource_uid()` from `engine_common.resource_id`)
- [ ] K8s: every row written to `discovery_findings` has `resource_uid` =
      `k8s/{cluster_id}/{namespace}/{kind}/{name}` — NOT `metadata.uid` UUID
- [ ] Azure: `resource_uid` = ARM resource ID format
- [ ] GCP: `resource_uid` = GCP resource name format
- [ ] OCI: `resource_uid` = OCID (pass-through if already OCID)
- [ ] AliCloud: `resource_uid` = ACS ARN format
- [ ] IBM: `resource_uid` = CRN (pass-through if already CRN)

### Phase 2 — Backfill migration
- [ ] Migration script `scripts/migrate_resource_uid_to_canonical.py` runs on all tables:
  - `discovery_findings`
  - `inventory_findings`
  - `resource_security_posture`
  - `check_findings`
  - `attack_path_nodes`
  - `security_findings`
- [ ] Script is idempotent — safe to run twice
- [ ] Script logs count of rows updated per table

### Phase 3 — Verify joins
- [ ] After migration: `discovery_findings JOIN resource_security_posture ON resource_uid` returns rows
- [ ] `check_findings JOIN discovery_findings ON resource_uid` returns rows
- [ ] Neo4j node `n.resource_uid` matches `resource_security_posture.resource_uid` for same resource

## Technical Notes

### AWS fix — `engines/discoveries/providers/aws/aws_utils/extraction.py`
The extraction utility already has a `normalize_resource_uid()` call path (via old `arn.py`,
now `resource_id.py`). Verify it is called for every resource type before writing.
Key: must handle IAM (no region), S3 (no region, no account), global services.

### K8s fix — `engines/discoveries/providers/kubernetes/scanner/service_scanner.py`
In `_enrich_k8s_item()` (line ~161), change:
```python
# BEFORE
uid = metadata.get('uid', '')       # K8s UUID — opaque, changes on recreate
item['resource_uid'] = uid

# AFTER
from engine_common.resource_id import make_resource_id
cluster_id = self.cluster_name or self.account_id
item['resource_uid'] = make_resource_id(
    csp='k8s',
    service=item.get('apiVersion', 'core').split('/')[0],
    resource_type=kind,
    region='',
    account=cluster_id,
    name=name,
    namespace=namespace,
)
# => "k8s/vulnerability-eks-cluster/default/secret/db-credentials"
```

### Backfill migration approach
For each table, run a SELECT of all rows with short-form UIDs, compute the canonical UID
using `make_resource_id()`, and UPDATE in batches of 500. Short-form UIDs are identified by:
- Not starting with `arn:`, `k8s/`, `azure/`, `//`, `ocid1.`, `acs:`, `crn:`
- Matching pattern `{service}:{region}:{account}:{resource-id}` (4-part colon-separated)
- Being a UUID (K8s legacy)

## Files to Change

### Phase 1 (discovery write path)
- `engines/discoveries/providers/aws/aws_utils/extraction.py` — verify `normalize_resource_uid()` called for all types
- `engines/discoveries/providers/kubernetes/scanner/service_scanner.py` — change UUID to `make_resource_id(csp='k8s', ...)`
- `engines/discoveries/providers/azure/` — add `make_resource_id(csp='azure', ...)` call
- `engines/discoveries/providers/gcp/` — add `make_resource_id(csp='gcp', ...)` call
- `engines/discoveries/providers/oci/` — verify OCID pass-through
- `engines/discoveries/providers/alicloud/` — add `make_resource_id(csp='alicloud', ...)` call
- `engines/discoveries/providers/ibm/` — verify CRN pass-through

### Phase 2 (backfill)
- `scripts/migrate_resource_uid_to_canonical.py` — new backfill script

## Images to Build After Fix
- `engine-discoveries` — write path changed

## No Changes Needed In
- `engine-check`, `engine-iam`, `engine-network`, `engine-datasec`, `engine-cdr`,
  `engine-inventory`, `engine-attack-path`, `engine-risk` — all read `resource_uid`,
  never generate it. Once discovery writes correct values, all joins work automatically.

## Dependency
None — this is the foundation story. All other cross-engine stories depend on this.

## Unblocks
- **AP-FIX-01** — Attack path VirtualNode + internet exposure fixes
- Future: resource graph joins, posture accuracy, Neo4j node matching