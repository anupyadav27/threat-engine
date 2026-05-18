# Story PC-P0-01: DB Migration — Extend resource_security_posture with Container, Vulnerability, AI-Security, and Composite Columns

## Status: done

## Metadata
- **Phase**: P0 — Foundation (schema first)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P0
- **Depends on**: AP-P0-01 (resource_security_posture table exists — migration 023 applied)
- **Blocks**: PC-P1-03, PC-P1-04, PC-P1-07, PC-P2-04
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer — schema change touches multi-tenant inventory DB

## User Story

As a platform engineer, I want the `resource_security_posture` table extended with container security, vulnerability, AI-security, and cross-engine composite signal columns so that all domain engines can write their signals into a single merged row and the attack-path engine can compute composite risk flags without joining multiple engine DBs at traversal time.

## Context

Migration 023 created `resource_security_posture` with dimensions for: network, IAM, encryption, datasec, dbsec, CDR, and attack-path. Four signal groups are missing:

1. **Container security** — no columns. Container engine has check findings but nowhere to write posture signals.
2. **Vulnerability** — no columns. Vuln engine has `scan_vulnerabilities` with EPSS scores and CVE counts but nowhere to write per-resource summaries.
3. **AI Security** — no columns. Shadow AI, publicly accessible model endpoints, and PII in training data have no posture representation.
4. **Cross-engine composite flags** — computed by attack-path engine after all engines finish. These boolean flags encode the dangerous combinations (e.g. internet-exposed + PII + active CDR actor) as precomputed columns so the risk engine reads a single flag instead of joining 4 tables.

This migration lives in `shared/database/migrations/` and targets **`threat_engine_inventory` DB** (same DB as migration 023).

## Migration File

**Path:** `shared/database/migrations/024_resource_security_posture_v2.sql`

```sql
BEGIN;

-- ============================================================================
-- Container Security dimension (written by container-security engine)
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS has_privileged_container        BOOLEAN   NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS image_has_critical_cve          BOOLEAN   NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS k8s_rbac_overpermissive         BOOLEAN   NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS container_network_policy_missing BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS container_security_score        SMALLINT  NOT NULL DEFAULT 0;

-- ============================================================================
-- Vulnerability dimension (written by vulnerability engine)
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS vuln_critical_count    INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS vuln_high_count        INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS has_known_exploit      BOOLEAN      NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS epss_max               NUMERIC(5,4) NOT NULL DEFAULT 0;
    -- epss_max: 0.0000–1.0000 (probability of exploitation in next 30 days)

-- ============================================================================
-- AI Security dimension (written by ai-security engine)
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS has_shadow_ai_service          BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS ai_model_publicly_accessible   BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS ai_training_data_has_pii       BOOLEAN  NOT NULL DEFAULT FALSE;

-- ============================================================================
-- Cross-engine composite flags (written by attack-path engine post-merge)
-- These encode the dangerous combinations discovered after all engines write.
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS unencrypted_pii_store          BOOLEAN  NOT NULL DEFAULT FALSE,
    -- TRUE when: data_classification IN ('pii','phi','pci') AND NOT is_encrypted_at_rest
    ADD COLUMN IF NOT EXISTS internet_exposed_with_pii      BOOLEAN  NOT NULL DEFAULT FALSE,
    -- TRUE when: is_internet_exposed = TRUE AND data_classification IN ('pii','phi','pci')
    ADD COLUMN IF NOT EXISTS admin_role_without_mfa         BOOLEAN  NOT NULL DEFAULT FALSE,
    -- TRUE when: is_admin_role = TRUE AND mfa_enforced = FALSE
    ADD COLUMN IF NOT EXISTS exploitable_exposed_resource   BOOLEAN  NOT NULL DEFAULT FALSE,
    -- TRUE when: is_internet_exposed = TRUE AND has_known_exploit = TRUE
    ADD COLUMN IF NOT EXISTS cdr_active_on_unencrypted      BOOLEAN  NOT NULL DEFAULT FALSE;
    -- TRUE when: has_active_cdr_actor = TRUE AND is_encrypted_at_rest = FALSE

-- ============================================================================
-- Partial indexes on new high-value boolean columns
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_rsp_privileged_container
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE has_privileged_container = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_known_exploit
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE has_known_exploit = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_unencrypted_pii
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE unencrypted_pii_store = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_internet_pii
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE internet_exposed_with_pii = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_admin_no_mfa
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE admin_role_without_mfa = TRUE;

COMMIT;

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: 024_resource_security_posture_v2'; END; $$;
```

## Acceptance Criteria

- [ ] AC-1: Migration applies cleanly to `threat_engine_inventory` DB with no errors — check kubectl logs end with "MIGRATION COMPLETE"
- [ ] AC-2: All 16 new columns exist with correct types and `DEFAULT FALSE` / `DEFAULT 0` as specified
- [ ] AC-3: No existing rows are affected — all new columns get defaults, existing data unchanged
- [ ] AC-4: 5 new partial indexes created — verify with `\d resource_security_posture`
- [ ] AC-5: `posture_writer.py` `_JSONB_COLS` frozenset does NOT need updating (no new JSONB columns in this migration)
- [ ] AC-6: Migration is idempotent — running twice does not error (all use `ADD COLUMN IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`)

## Definition of Done
- [ ] Migration file committed at `shared/database/migrations/024_resource_security_posture_v2.sql`
- [ ] Migration applied to EKS RDS `threat_engine_inventory` DB via kubectl exec pattern
- [ ] kubectl logs confirm "MIGRATION COMPLETE"
- [ ] `\d resource_security_posture` output confirms all 16 new columns present