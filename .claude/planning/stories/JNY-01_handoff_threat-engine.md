# JNY-01 Handoff — threat-engine specialist (CONSULTED)

**To:** cspm-db-engineer (R), bmad-security-architect (A)
**From:** threat-engine specialist
**Re:** `mitre_technique_reference` schema + seed for TechniqueDetailModal

## 1. Verdict
**APPROVE WITH CHANGES** — schema is directionally correct but missing two engine-required columns and an indexing strategy on `threat_findings`. Seed must be a bundled snapshot, not runtime fetch.

## 2. Required schema changes
- **Add `is_subtechnique BOOLEAN NOT NULL DEFAULT FALSE`** — denormalized flag derived from `parent_id IS NOT NULL`. Lets BFF filter parent-only listings without a self-join. Cheap and avoids a recursive CTE on the hot path.
- **Add `kill_chain_phases JSONB NOT NULL DEFAULT '[]'::jsonb`** — `tactic_ids` alone loses the MITRE kill-chain ordering. The Threat Center attack-path UI sorts techniques by kill-chain phase; without phase ordering we re-derive it client-side.
- **Add `tenant_id UUID` — NO. Reject.** This is a global reference table. Keep it tenant-agnostic; per-tenant filtering happens on `threat_findings` only. (Calling out because someone will ask.)
- **Change `technique_id VARCHAR(16)` → `VARCHAR(20)`** — defensive. Future MITRE has gone to 4-digit subs (e.g., `T1078.0042` is plausible). Negligible cost, avoids a future migration.
- **Add `revoked BOOLEAN NOT NULL DEFAULT FALSE` and `deprecated BOOLEAN NOT NULL DEFAULT FALSE`** — STIX feed marks revoked techniques. We must keep them (historical findings reference them) but exclude from new mappings/UI dropdowns.
- **Add `CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3,4})?$')`** — enforce format at write time so the join column is clean.
- **Make `parent_id` a soft FK to self** — `FOREIGN KEY (parent_id) REFERENCES mitre_technique_reference(technique_id) ON DELETE SET NULL DEFERRABLE`. Required for sub-technique rollup correctness.

## 3. Required indexes
On the new table — proposed are fine, plus add:
```sql
CREATE INDEX IF NOT EXISTS idx_mtr_not_revoked
  ON mitre_technique_reference(technique_id) WHERE revoked = FALSE AND deprecated = FALSE;
```

**Critical — on `threat_findings` (existing table) for the "Affected count" KPI:**
```sql
-- Per-tenant per-technique count is the hottest BFF query; we currently have no covering index
CREATE INDEX IF NOT EXISTS idx_threat_findings_tenant_technique
  ON threat_findings(tenant_id, mitre_technique)
  WHERE status = 'OPEN';

-- Supports the parent-rollup variant (LIKE 'T1078%' pattern). Do NOT use LIKE — see §4.
-- Instead, populate a generated column threat_findings.mitre_parent_technique
-- and index that:
ALTER TABLE threat_findings
  ADD COLUMN mitre_parent_technique VARCHAR(20)
  GENERATED ALWAYS AS (split_part(mitre_technique, '.', 1)) STORED;

CREATE INDEX IF NOT EXISTS idx_threat_findings_tenant_parent_technique
  ON threat_findings(tenant_id, mitre_parent_technique)
  WHERE status = 'OPEN';
```
We do **not** have a suitable index today — `threat_findings` is currently indexed on `(tenant_id, scan_run_id)` and `finding_id`. The technique count query does a partition scan per tenant.

## 4. Sub-technique handling decision — **BOTH (rollup + exact)**
- TechniqueDetailModal MUST show two counts:
  - **Exact:** `WHERE mitre_technique = 'T1078.004'`
  - **Rollup (parent + all subs):** `WHERE mitre_parent_technique = 'T1078'`
- Reason: rules emit at different granularities. Rule R-IAM-014 emits `T1078`; rule R-IAM-022 emits `T1078.004`. Showing only one count under-reports.
- Implementation: use the new generated column `mitre_parent_technique` (above) — never `LIKE 'T1078%'` (won't use index, also matches `T10780`).
- `parent_id` in the reference table powers the "Sub-techniques" list section of the modal: `SELECT technique_id, name FROM mitre_technique_reference WHERE parent_id = $1 AND revoked = FALSE`.

## 5. Seed strategy — **bundled STIX snapshot, refreshed by threat engine cron**
- **Version:** MITRE ATT&CK Enterprise **v15.1** (current GA as of 2026-05). Bundle the JSON STIX 2.1 file at `/Users/apple/Desktop/threat-engine/engines/threat/data/mitre/enterprise-attack-v15.1.json` (~6 MB).
- **Why bundle, not runtime:** cold-start of threat engine pod is currently ~8s; pulling 6 MB STIX from `attack.mitre.org` adds 3-5s and a network failure mode on every pod restart. Unacceptable for a Stage-4 pipeline engine.
- **Seed loader:** idempotent `INSERT ... ON CONFLICT (technique_id) DO UPDATE` script run by Alembic migration `post_deploy` hook (same pattern as the 102 pre-loaded techniques mentioned in the engine memory).
- **Refresh cadence:** monthly cron in **threat engine** (not a new service) — `0 3 1 * *` UTC. Calls `update_mitre_reference()` which downloads STIX, diffs by `last_modified`, upserts changes. Logs to `threat_analysis` table for audit.
- **Do NOT** put the cron in onboarding/discovery — wrong domain. Threat engine owns the MITRE mapping authority.

## 6. scan_id vs scan_run_id — confirmed clean for technique detail flow
The technique detail BFF reads:
- `mitre_technique_reference` (no scan column — global)
- `threat_findings` filtered by `tenant_id` + `mitre_technique` (no scan filter on the modal — it shows current open findings)
- Optional drilldown to latest `scan_run_id` per tenant: `SELECT scan_run_id FROM threat_findings WHERE tenant_id=$1 ORDER BY last_seen_at DESC LIMIT 1`

**Leak risks I checked:**
- `threat_detections` table — confirmed uses `scan_run_id`, no `threat_scan_id` column. Safe.
- Any BFF that joins `threat_findings` → `threat_detections` — must use `scan_run_id`. There's at least one legacy view (`threat_attack_paths`) that historically referenced `threat_scan_id`; verify it's been migrated before exposing technique-detail rollup that crosses both tables.
- **Action for cspm-db-engineer:** grep `threat_scan_id` across BFF + engine before merging — it should not exist. If it does, that's a separate ticket, not part of JNY-01.

## 7. Open questions for cspm-db-engineer (R)
- Do we ALTER `threat_findings` to add the generated `mitre_parent_technique` column in this migration, or split into JNY-01a? My recommendation: **same migration** — the index is useless without the column, and the BFF endpoint depends on it.
- Migration ordering: seed runs after `CREATE TABLE` — confirm Alembic `op.execute()` for the bulk insert handles 600+ rows in one transaction (it does, but flag for review).
- Should seed loader live in `engines/threat/seed/` or `shared/database/seeds/`? I prefer engine-local since threat owns the cron.
- Postgres version on RDS — confirm ≥12 for generated columns (I believe we're on 15, please verify).

## 8. Open questions for bmad-security-architect (A)
- Does `mitigations JSONB` (denormalized) satisfy the compliance-control mapping requirement, or do we need a separate `mitre_technique_control_map` join table for ATT&CK ↔ NIST 800-53 / CIS Controls traceability? I lean denormalized for v1, normalized in v2 once Risk engine consumes it.
- D3FEND mappings — STIX doesn't carry these natively. Source: MITRE D3FEND API. Are we OK with the JSONB column being empty at v1 and backfilled in a follow-up story?
- Revoked-technique policy: hide in dropdowns but keep historical findings linked? (My recommendation; needs your sign-off because it affects the "Affected count" semantics.)
