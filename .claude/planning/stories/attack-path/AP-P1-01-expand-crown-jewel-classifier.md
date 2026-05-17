# Story AP-P1-01: Expand CrownJewelClassifier

## Status: ready

## Metadata
- **Phase**: P1 — Crown Jewels
- **Epic**: Attack Path Engine
- **Points**: 3
- **Priority**: P1
- **Depends on**: AP-P0-01 (posture table exists), AP-P0-02 (posture_writer utility), AP-P0-03 (posture signals populated)
- **Blocks**: AP-P2-03 (BFS must start from classified crown jewels), AP-P1-02 (override API reads this classifier's output)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer must sign off. bmad-security-po must confirm crown jewel criteria match PRD section 4 (FR1).

## User Story

As the attack-path engine, I want the CrownJewelClassifier to auto-classify all qualifying resource types as crown jewels and write `is_crown_jewel=true` both as a Neo4j node property and to `resource_security_posture`, so that the reverse BFS traversal starts from a complete and accurate set of high-value assets.

## Context

The existing `engines/threat/threat_engine/graph/crown_jewel_classifier.py` has a basic Cypher heuristic seed (phase16). It needs to be expanded to cover all resource types in the classification table from architecture doc section 4.3, write results to `resource_security_posture` via the new posture_writer utility, and respect manual overrides from the `crown_jewel_overrides` table.

Crown jewel classification quality is the single most important input to attack path completeness. If a PII database is not classified as a crown jewel, ALL paths to that database are silently dropped from the result.

Manual overrides (from `crown_jewel_overrides` table, created in AP-P2-01) always take precedence: if `is_crown_jewel=false` override exists, skip auto-classification for that resource.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
ID.AM-2 (software assets inventoried), ID.RA-2 (threat intelligence informing asset criticality)

**CSA CCM v4 Domain(s)**
- DSP-07 (Data Classification), IVS-03 (Migration Security), IAM-09 (Access Control)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | classifier | Under-classification: admin IAM role not tagged as crown jewel → path to it dropped from results | Classification criteria are exhaustive (architecture doc section 4.3); unit test verifies each resource type |
| Tampering | manual override | Analyst maliciously tags PII bucket as non-crown-jewel to suppress attack paths | Override stored with `set_by` email; audit log; RBAC requires attack_path:write (tenant_admin or above) |
| Elevation | classifier | Over-classification: logging bucket tagged as crown jewel → noise paths generated | Partial condition for storage buckets: ONLY if data_classification IN (pii, financial, credentials) |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1530 | Data from Cloud Storage Object | Storage buckets with PII/financial data classified as crown jewels |
| T1552.001 | Credentials in Files | secretsmanager.secret and ssm.parameter (SecureString) always crown jewels |
| T1098 | Account Manipulation | Admin IAM roles and users with wildcard policies classified as crown jewels |

## Acceptance Criteria

### Functional
- [ ] AC-1: File `engines/threat/threat_engine/graph/crown_jewel_classifier.py` updated with complete classification table covering all resource types from architecture doc section 4.3
- [ ] AC-2: Storage resources (s3.bucket, blob.container, gcs.bucket, oci.object_storage) classified as crown jewels ONLY when `data_classification IN ('pii', 'financial', 'credentials')` — not for all storage resources
- [ ] AC-3: Database resources (rds.instance, aurora.cluster, cloud_sql.instance, oci.autonomous_db) always classified as crown jewels regardless of data classification
- [ ] AC-4: Secrets resources (secretsmanager.secret, ssm.parameter with SecureString) always classified
- [ ] AC-5: IAM resources (iam.role, iam.user) classified when `is_admin_role=true OR has_wildcard_policy=true` (signals read from `resource_security_posture`)
- [ ] AC-6: K8s cluster resources (eks.cluster, aks.cluster, gke.cluster) always classified
- [ ] AC-7: Container registry resources (ecr.repository, acr.registry, gcr.repository) always classified
- [ ] AC-8: AI/ML resources (sagemaker.endpoint, bedrock.model) always classified
- [ ] AC-9: Data warehouse and search resources (redshift.cluster, elasticsearch.domain) always classified
- [ ] AC-10: KMS resources (kms.key, key_vault.key) always classified
- [ ] AC-11: After classification run, Neo4j nodes for matching resources have property `is_crown_jewel: true` and `crown_jewel_type: <type>` set via MERGE/SET
- [ ] AC-12: After classification run, `resource_security_posture` rows for classified resources have `is_crown_jewel=true` and `crown_jewel_type` populated (written via posture_writer)
- [ ] AC-13: Crown jewel recall ≥ 90% against known-sensitive resources in test tenant (manual verification step in DoD)
- [ ] AC-14: `crown_jewel_overrides` table checked BEFORE auto-classification — manual `is_crown_jewel=false` override suppresses auto-classification for that resource_uid/tenant_id pair

### Security (must pass bmad-security-reviewer)
- [ ] AC-15: All Neo4j queries include `tenant_id: $tid` property filter — no cross-tenant crown jewel leakage
- [ ] AC-16: posture_writer called with correct `tenant_id` from scan context — not from resource properties
- [ ] AC-17: Classification does not use `json.loads()` on JSONB posture fields
- [ ] AC-18: Override lookup queries `crown_jewel_overrides WHERE tenant_id = $tid AND resource_uid = $uid` — tenant-scoped

## Technical Notes

**File to modify**: `engines/threat/threat_engine/graph/crown_jewel_classifier.py`

The classifier runs at the start of each attack-path scan (called from `run_scan.py`). It:
1. Reads `resource_security_posture` for all resources in the current (scan_run_id, tenant_id)
2. Reads `crown_jewel_overrides` for the tenant — these always win
3. For each resource, evaluates auto-classification criteria
4. Writes `is_crown_jewel` and `crown_jewel_type` to Neo4j via MERGE ... SET
5. Writes same signals back to `resource_security_posture` via posture_writer

**crown_jewel_type values** (from PRD section 4, FR1):
- `data` — storage buckets with PII/financial/credentials
- `secrets` — secretsmanager, ssm SecureString, key vault secrets
- `identity` — admin IAM roles, users with wildcard policies
- `infra_control` — K8s clusters, cloudformation stacks with admin permissions
- `ai_model` — SageMaker endpoints, Bedrock models
- `code` — container registries
- `data_warehouse` — redshift, elasticsearch
- `encryption_control` — KMS keys, key vault keys

**Cypher for setting crown jewel property**:
```cypher
MATCH (r:Resource {tenant_id: $tid, uid: $uid})
SET r.is_crown_jewel = true, r.crown_jewel_type = $type
```

Use MERGE on the node before SET if the node might not exist yet.

Note: `crown_jewel_overrides` table is created in AP-P2-01. If AP-P2-01 has not shipped, the classifier must gracefully handle a missing overrides table (catch exception, log warning, continue with auto-classification).

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/threat/threat_engine/graph/crown_jewel_classifier.py` (modify)

## Definition of Done
- [ ] crown_jewel_classifier.py updated with all resource types from architecture doc
- [ ] Unit tests added for each resource type classification condition
- [ ] Classifier reads and applies manual overrides from crown_jewel_overrides (or gracefully skips if table absent)
- [ ] After running classifier on test tenant: Neo4j `MATCH (n:Resource {is_crown_jewel: true}) RETURN count(n)` returns > 0
- [ ] After running: `resource_security_posture` has `is_crown_jewel=true` rows
- [ ] Recall check: at least 3 known-sensitive resources in test tenant are correctly classified
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-security-po: crown jewel criteria confirmed against PRD FR1