# Graph Pipeline Fixes — Sprint Planning

Deferred from threat_v1 incident fix session (2026-05-13).
These are structural Neo4j graph issues that prevent T2/T3 patterns from generating
meaningful incidents even after the CDR loader and T2 activation fixes land.

---

## Current Graph State (verified 2026-05-14)

| Edge/Property | Count | Status |
|---|---|---|
| `TRIGGERED_ON` | seeded via CDRLoader MERGE | DONE (phase15) |
| `ASSUMES` | written via inventory_relationships | DONE (phase16) |
| `INTERNET_CONNECTED` | VirtualNode sentinel for internet_exposed resources | DONE (phase16) |
| `HAS_MISCONFIG` | 8918+ | OK |
| `internet_exposed=true` | 295+ | OK |
| `is_crown_jewel=true` | 91 (heuristic seed) | DONE (phase16 CrownJewelClassifier) |
| `is_admin_role=true` | 76 rules tagged, 0 CloudTrail/Cognito wrongly tagged | DONE (phase16 SQL patch) |
| Incidents API (RBAC) | 0 incidents shown, endpoint 200 OK | DONE (phase20) |

---

## Issue 1: ASSUMES edges have NULL resource_uid — CLOSED

**Status**: DONE (phase16 — MATCH→MERGE rewrite; `ON CREATE SET` props on target nodes)

Edge builder uses MERGE not MATCH for ASSUMES target nodes. The `ON CREATE SET` block
sets `resource_type`, `account_id`, `region`, `tenant_id` when the target node is newly
created. ARN normalization for `assumed-role/` → base role ARN is still pending
(low priority — T2 patterns work via CDR actor MERGE which links to the node when CDR
logs flow after CDR_SCANNER_IMAGE fix).

---

## Issue 2: CONNECTED_TO edges = 0 — RECLASSIFIED

**Status**: RECLASSIFIED — edge_builder.py deliberately does NOT create generic CONNECTED_TO edges.

**Decision (phase16)**: Typed edges (ASSUMES, INTERNET_CONNECTED, ROUTES_TO, etc.) are
the correct semantic model for a property graph. A generic CONNECTED_TO edge fights the
data model, breaks pattern selectivity, and causes cartesian-product noise in T2/T3 queries.

The `internet_connected` relation_type now writes `[:INTERNET_CONNECTED]` edges to a
virtual `Internet:VirtualNode {resource_uid: 'internet:0.0.0.0/0'}` sentinel. T2 patterns
use this — not CONNECTED_TO.

Patterns that needed CONNECTED_TO have been rewritten to use INTERNET_CONNECTED or ASSUMES.

---

## Issue 3: is_admin_role wrongly set on CloudTrail/Cognito — CLOSED

**Status**: DONE — SQL patch applied in phase16.

Verified 2026-05-14: `SELECT count(*) FROM rule_metadata WHERE (rule_id LIKE 'aws-cloudtrail-%' OR rule_id LIKE 'aws-cognito-%') AND threat_flags @> '["is_admin_role"]'` = **0**.

Total `is_admin_role` rules: **76** (IAM/RBAC/privilege-escalation rules only — correct).

---

## Issue 4: is_crown_jewel = 0 — CLOSED

**Status**: DONE — CrownJewelClassifier seeded 91 crown jewels (phase16).

Heuristic: `resource_type IN ['S3Bucket','RDSInstance','DynamoDBTable', ...]` and SPLIT_PART
JOIN fix to handle `s3.bucket`→`bucket` format mismatch. 91 nodes in Neo4j with `is_crown_jewel=true`.

DataSec-backed seeding (using `datasec_findings.classification_label`) is the correct long-term
approach and should be done in the next datasec sprint.

---

## Issue 5: CDR scanner ImagePullBackOff — FIXED (2026-05-14)

**Root cause**: `CDR_SCANNER_IMAGE` env var was `v-cdr-internal1` but only `v-cdr-internal-auth1`
exists on Docker Hub. All `log-collection-scan` jobs were in `ImagePullBackOff`.

**Fix**: Updated env var to `v-cdr-internal-auth1` via `kubectl set env` and updated
`deployment/aws/eks/engines/engine-cdr.yaml`. Stale ImagePullBackOff jobs cleaned up
(`kubectl delete jobs -l app=log-collection-scanner`).

After the next CDR cron fires (~hourly), expect new `cdr_findings` rows with ARN-format
`resource_uid` values. Verify with:
```sql
SELECT COUNT(*), MAX(created_at) FROM cdr_findings WHERE created_at > NOW() - INTERVAL '2 hours';
```

---

## Issue 6 (NEW): threat-v1 RBAC Depends injection broken — FIXED (phase20, 2026-05-14)

**Root cause**: `auth: Any = require_permission("threat:read")` used the raw function returned
by `require_permission()` as the default value, not `Depends(...)`. FastAPI only injects
dependency when the default is `Depends(callable)`. Result: `auth` was the function object,
not an `AuthContext` — all endpoints returned 500.

**Secondary bug**: `auth.tenant_id` — the real `AuthContext` uses `engine_tenant_id` not `tenant_id`.

**Fix (phase20)**:
1. All endpoints changed to `auth: Any = Depends(require_permission("threat:read"))`
2. All `auth.tenant_id` changed to `getattr(auth, "engine_tenant_id", None) or getattr(auth, "tenant_id", None)`
3. Fallback `require_permission` stub in routes.py updated to return raw function (not `Depends`)
   since endpoints now wrap it themselves.

Image: `yadavanup84/engine-threat-v1:v-threat-v1-phase20` deployed 2026-05-14.

---

## Remaining Work (next sprint)

| # | Issue | Effort | Impact |
|---|---|---|---|
| 1 | `assumed-role/` → base role ARN normalization in edge_builder | S | Better T2 ASSUMES quality |
| 2 | DataSec-backed crown jewel seeding from `datasec_findings` | M | More accurate T3 triggers |
| 3 | Verify CDR findings flow after scanner image fix | S | Enable CDR-correlated T2 incidents |
| 4 | Re-trigger full pipeline scan after CDR flows | S | Validate T2/T3 incident counts improve |
