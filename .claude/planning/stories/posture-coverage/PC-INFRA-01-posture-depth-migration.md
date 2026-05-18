# Story PC-INFRA-01: DB Migration — New resource_security_posture Columns for Depth Analysis

## Status: done

## Metadata
- **Phase**: Infrastructure Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 2
- **Priority**: P1 — must land before PC-DEPTH-01 and PC-DEPTH-05 engine code can write posture signals
- **Depends on**: PC-P0-01 (migration 024 applied — container/vuln/AI columns exist)
- **Blocks**: PC-DEPTH-01 (IAM escalation posture write), PC-DEPTH-05 (ECR/EKS posture write)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer — schema change on multi-tenant inventory DB

## User Story

As a platform engineer, I want the `resource_security_posture` table extended with IAM privilege escalation path signals and container EKS/ECR depth signals so that the IAM escalation detector (PC-DEPTH-01) and the container EKS/ECR analyzer (PC-DEPTH-05) can write their computed signals into the posture row for each resource.

## Context

### What Migrations 023 and 024 Already Cover

Migration 023 created the base table. Migration 024 (`024_resource_security_posture_v2.sql`) added:
- Container: `has_privileged_container`, `k8s_rbac_overpermissive`, `container_network_policy_missing`, `image_has_critical_cve`, `container_security_score`
- Vulnerability: `vuln_critical_count`, `vuln_high_count`, `has_known_exploit`, `epss_max`
- AI Security: `has_shadow_ai_service`, `ai_model_publicly_accessible`, `ai_training_data_has_pii`
- Composite flags: `unencrypted_pii_store`, `internet_exposed_with_pii`, `admin_role_without_mfa`, `exploitable_exposed_resource`, `cdr_active_on_unencrypted`

### What Is Still Missing

These columns are required by PC-DEPTH stories but not in any existing migration:

**From PC-DEPTH-01 (IAM privilege escalation paths):**
- `has_priv_escalation_path BOOLEAN` — identity has a detectable escalation path to admin
- `priv_escalation_hop_count SMALLINT` — shortest escalation path (1=direct, 2=one-hop, 3+=chained)
- `priv_escalation_cdr_confirmed BOOLEAN` — CDR confirms escalation path was traversed in last 30 days

**From PC-DEPTH-05 (Container EKS/ECR depth):**
- `ecr_scan_on_push_enabled BOOLEAN` — FALSE when any ECR repo under this resource is missing scan-on-push
- `eks_node_ami_outdated BOOLEAN` — TRUE when any EKS node group AMI is > 60 days old

These two groups are independent and written by different engines (IAM engine writes escalation columns; container engine writes ECR/EKS columns).

## Migration File

**Path:** `shared/database/migrations/027_posture_depth_columns.sql`

**Target DB:** `threat_engine_inventory` (same DB as migrations 023 and 024)

```sql
-- ============================================================================
-- Migration: 027_posture_depth_columns
-- Database:  threat_engine_inventory
-- Purpose:   Add IAM escalation path signals and container EKS/ECR depth
--            signals to resource_security_posture.
--            Written by IAM engine (escalation) and container-security engine (ECR/EKS).
-- ============================================================================

BEGIN;

-- ============================================================================
-- IAM Escalation dimension (written by IAM engine after escalation_detector.py)
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS has_priv_escalation_path      BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS priv_escalation_hop_count     SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS priv_escalation_cdr_confirmed BOOLEAN  NOT NULL DEFAULT FALSE;

-- ============================================================================
-- Container ECR/EKS depth signals (written by container-security engine)
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS ecr_scan_on_push_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- Default TRUE = assume safe; set FALSE when a missing scan-on-push finding detected
    ADD COLUMN IF NOT EXISTS eks_node_ami_outdated     BOOLEAN NOT NULL DEFAULT FALSE;

-- ============================================================================
-- Partial indexes — keeps query cost low on high-cardinality posture table
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_rsp_priv_escalation
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE has_priv_escalation_path = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_priv_escalation_cdr
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE priv_escalation_cdr_confirmed = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_ecr_no_scan
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE ecr_scan_on_push_enabled = FALSE;

CREATE INDEX IF NOT EXISTS idx_rsp_eks_ami_outdated
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE eks_node_ami_outdated = TRUE;

COMMIT;

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: 027_posture_depth_columns'; END; $$;
```

## Engine Writer Updates Required

After migration applies, update the posture writer in each engine:

### IAM engine — `engines/iam/iam_engine/writers/posture_writer.py`

Add to the escalation findings aggregation loop:

```python
if any escalation finding for this resource_uid:
    posture_update["has_priv_escalation_path"] = True
    posture_update["priv_escalation_hop_count"] = min(f["hop_count"] for f in escalation_findings)
    posture_update["priv_escalation_cdr_confirmed"] = any(
        f.get("cdr_active") for f in escalation_findings
    )
```

### Container engine — `engines/container-security/container_engine/writers/posture_writer.py`

```python
if any ecr_scan_off_finding for this resource_uid:
    posture_update["ecr_scan_on_push_enabled"] = False

if any ami_outdated_finding for this resource_uid:
    posture_update["eks_node_ami_outdated"] = True
```

## Acceptance Criteria

- [ ] AC-1: Migration applies cleanly to `threat_engine_inventory` DB — kubectl logs end with "MIGRATION COMPLETE: 027_posture_depth_columns"
- [ ] AC-2: `\d resource_security_posture` confirms all 5 new columns with correct types and defaults
- [ ] AC-3: `ecr_scan_on_push_enabled` defaults to TRUE (not FALSE) — safe default means "assume scanning enabled until detected otherwise"
- [ ] AC-4: `priv_escalation_hop_count` defaults to 0 (not NULL) — avoids NULL comparison issues in attack-path engine
- [ ] AC-5: All 4 partial indexes created
- [ ] AC-6: Migration is idempotent — running twice does not error
- [ ] AC-7: No existing rows affected — all new columns get their defaults, existing posture data unchanged

## Definition of Done
- [ ] Migration file committed at `shared/database/migrations/027_posture_depth_columns.sql`
- [ ] Applied to EKS RDS `threat_engine_inventory` DB via kubectl exec pattern
- [ ] kubectl logs confirm "MIGRATION COMPLETE"
- [ ] IAM engine posture writer updated to write 3 new escalation columns
- [ ] Container engine posture writer updated to write 2 new ECR/EKS columns
