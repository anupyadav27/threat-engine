# Story AP-P2-01: DB Migration — Attack-Path Engine Tables

## Status: ready

## Metadata
- **Phase**: P2 — Attack Path Engine Core
- **Epic**: Attack Path Engine
- **Points**: 3
- **Priority**: P0
- **Depends on**: AP-P0-01 (posture table migration pattern established)
- **Blocks**: AP-P2-02 (engine scaffold writes to these tables), AP-P1-02 (override API writes to crown_jewel_overrides), AP-P2-06 (writer.py writes to attack_paths + attack_path_nodes + attack_path_history)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-architect must review DDL. bmad-security-reviewer must sign off before merge.

## User Story

As the attack-path engine, I want the four attack-path tables (`attack_paths`, `attack_path_nodes`, `attack_path_history`, `crown_jewel_overrides`) created in a new `threat_engine_attack_path` database so that I can persist discovered paths, per-hop evidence, history, and manual overrides.

## Context

The attack-path engine needs its own database (`threat_engine_attack_path`) following the platform's pattern of one DB per engine. This story creates all four tables in a single migration file.

This is DDL only — no application code ships in this story.

Note: The `threat_engine_attack_path` database itself must be created before running this migration (equivalent to how other engine DBs are provisioned). If the DB does not exist, the migration will fail at connection time — check with the infra team that the DB is provisioned.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [ ] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
PR.DS-1 (data-at-rest integrity via path_id PK), PR.DS-2 (schema compatibility)

**CSA CCM v4 Domain(s)**
- DSP-07 (Data Classification), IVS-01 (Infrastructure Security), GRC-06 (Audit Logging for crown_jewel_overrides)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | attack_paths | Cross-tenant path leakage via path_id guessing | path_id is sha256 hash (not sequential int); all queries enforce WHERE tenant_id = $tid |
| Repudiation | crown_jewel_overrides | Analyst denies tagging a resource — no audit trail | set_by VARCHAR NOT NULL + created_at + updated_at always populated |
| DoS | attack_path_history | History table grows unbounded across all scans | Retention policy is application-level concern (future work); index on (path_id, recorded_at DESC) enables range deletes |

## MITRE ATT&CK Techniques Addressed
N/A — DDL only.

## Acceptance Criteria

### Functional
- [ ] AC-1: Migration file `shared/database/migrations/024_attack_path_engine_tables.sql` created
- [ ] AC-2: `attack_paths` table created with all columns from architecture doc section 7.2 — `path_id VARCHAR(64) PRIMARY KEY` (sha256 hash), all JSONB columns (node_uids, node_types, edge_types, hop_categories), all scoring columns, all lifecycle columns
- [ ] AC-3: `attack_path_nodes` table created with all columns from architecture doc section 7.3 — FK to `attack_paths(path_id)`, hop_index, node_uid, traversal_reason, policy_statement JSONB, sg_rule JSONB, misconfigs JSONB, cves JSONB, threat_detections JSONB
- [ ] AC-4: `attack_path_history` table created with all columns from architecture doc section 7.4 — path_id (NOT FK — history kept after path deleted), scan_run_id UUID, score, node_uids JSONB
- [ ] AC-5: `crown_jewel_overrides` table created with all columns from architecture doc section 7.5 — UNIQUE(resource_uid, tenant_id), set_by VARCHAR NOT NULL
- [ ] AC-6: All indexes defined in architecture doc sections 7.2–7.5 created (idx_ap_tenant_scan, idx_ap_severity, idx_ap_crown_jewel, idx_ap_choke_node, idx_ap_representative, idx_apn_path_id, idx_apn_node_uid, idx_aph_path_trend, idx_aph_tenant)
- [ ] AC-7: Migration is idempotent — CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS throughout
- [ ] AC-8: Migration wrapped in BEGIN/COMMIT
- [ ] AC-9: Migration ends with `RAISE NOTICE 'MIGRATION COMPLETE: 024_attack_path_engine_tables'`

### Standard Column Check (attack_paths)
- [ ] AC-10: `attack_paths` contains: `scan_run_id UUID NOT NULL`, `tenant_id VARCHAR(255) NOT NULL`, `account_id`, `provider`, `first_seen_at TIMESTAMPTZ DEFAULT NOW()`, `last_seen_at TIMESTAMPTZ DEFAULT NOW()`, `status VARCHAR(20) DEFAULT 'active'`
- [ ] AC-11: `attack_path_nodes` contains: `tenant_id VARCHAR(255) NOT NULL`, `node_uid VARCHAR(512) NOT NULL`, `hop_index INTEGER NOT NULL`

### Security (must pass bmad-security-reviewer)
- [ ] AC-12: No nullable `tenant_id` in any table
- [ ] AC-13: No plaintext credentials in migration SQL
- [ ] AC-14: All timestamp columns are TIMESTAMPTZ (not TIMESTAMP without timezone)
- [ ] AC-15: `attack_path_nodes.path_id` FK has appropriate ON DELETE behavior declared (CASCADE recommended so orphaned hop rows are cleaned up if a path is deleted)
- [ ] AC-16: `crown_jewel_overrides.set_by` is NOT NULL — audit trail requires it

## Technical Notes

**Migration filename**: `024_attack_path_engine_tables.sql`
**Target DB**: `threat_engine_attack_path` (new database — must be provisioned before migration)

Apply via:
```bash
kubectl cp /tmp/024_attack_path_engine_tables.sql \
  threat-engine-engines/<attack-path-pod>:/tmp/024.sql
kubectl exec -n threat-engine-engines <attack-path-pod> -- \
  psql -h $ATTACK_PATH_DB_HOST -U $ATTACK_PATH_DB_USER -d $ATTACK_PATH_DB_NAME \
  -f /tmp/024.sql
```

Note: The attack-path pod (engine scaffold) must be deployed first (AP-P2-02) before this migration can be applied via kubectl exec. However, the migration FILE can be committed before the engine is deployed.

**path_id generation** (for reference in writer.py later):
```python
import hashlib
path_id = hashlib.sha256("|".join(node_uids).encode()).hexdigest()
```

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/database/migrations/024_attack_path_engine_tables.sql` (create new)

## Definition of Done
- [ ] Migration SQL file committed to `shared/database/migrations/`
- [ ] Migration applied to `threat_engine_attack_path` DB
- [ ] `\dt` shows all 4 tables
- [ ] `\di attack_path*` shows all expected indexes
- [ ] UNIQUE constraint on crown_jewel_overrides(resource_uid, tenant_id) verified
- [ ] FK from attack_path_nodes.path_id to attack_paths.path_id verified
- [ ] Migration logs end with "MIGRATION COMPLETE: 024_attack_path_engine_tables"
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-security-architect: DDL sign-off recorded