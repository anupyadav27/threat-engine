# DI-14: DB Schema — Add Missing Columns (Migrations from Gap Report)

## Track
Track 3 — DB Schema Alignment

## Priority
P1 — depends on DI-13 (gap report must be run first)

## Story
As a backend engineer, I need to add missing columns to engine databases that the BFF queries but that don't exist in the DB, so that engines can write data to them and the BFF can read back non-NULL values.

## Background

DI-13 produces a gap report. This story converts the gaps into concrete ALTER TABLE migrations. The specific columns are only known after DI-13 runs, but based on known bugs we can pre-define the high-confidence ones below.

## Pre-Identified Migrations (High Confidence)

### Migration 1: threat_detections — index on tenant_id + scan_run_id

Location: threat engine DB

```sql
-- Ensure index exists for BFF query performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_detections_tenant_scan
    ON threat_detections(tenant_id, scan_run_id);

-- Ensure index for MITRE queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_detections_mitre
    ON threat_detections USING GIN(mitre_tactics);
```

Apply via:
```bash
kubectl cp /tmp/threat_idx.sql threat-engine-engines/$(kubectl get pod -n threat-engine-engines -l app=engine-threat -o name | head -1 | cut -d/ -f2):/tmp/threat_idx.sql
kubectl exec -n threat-engine-engines deployment/engine-threat -- psql -h $THREAT_DB_HOST -U $THREAT_DB_USER -d $THREAT_DB_NAME -f /tmp/threat_idx.sql
```

### Migration 2: compliance_scores — if score column is missing or wrong type

```sql
ALTER TABLE compliance_scores
    ADD COLUMN IF NOT EXISTS overall_score INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pass_count INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS fail_count INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS total_controls INTEGER DEFAULT 0;
```

### Migration 3: risk_scenarios — if blast_radius column missing

```sql
ALTER TABLE risk_scenarios
    ADD COLUMN IF NOT EXISTS blast_radius INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS resource_count INTEGER DEFAULT 0;
```

### Migration 4: inventory resource_inventory — drift columns

```sql
ALTER TABLE resource_inventory
    ADD COLUMN IF NOT EXISTS drift_detected BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS drift_details JSONB DEFAULT '{}';
```

## Process for DI-13-Driven Migrations

After running DI-13, for each "MISSING" column:

1. Check if it's a new column (never existed) vs. renamed column (exists with old name)
2. If new: `ALTER TABLE ... ADD COLUMN IF NOT EXISTS ...`
3. If renamed: `ALTER TABLE ... RENAME COLUMN old_name TO new_name` (only if no data yet)
4. If type mismatch: `ALTER TABLE ... ALTER COLUMN name TYPE new_type USING name::new_type`

## File Structure

Each migration should be a separate `.sql` file:

```
/Users/apple/Desktop/threat-engine/shared/database/migrations/
    DI-14-threat-indexes.sql
    DI-14-compliance-columns.sql
    DI-14-risk-columns.sql
    DI-14-inventory-drift.sql
```

## Acceptance Criteria

- [ ] DI-13 gap report has been reviewed before starting this story
- [ ] Each identified missing column has a corresponding ALTER TABLE or CREATE INDEX
- [ ] All SQL uses `IF NOT EXISTS` / `IF EXISTS` guards for idempotency
- [ ] Migrations applied to staging, verified with `\d table_name` in psql
- [ ] No existing data is lost (only ADD COLUMN, not DROP COLUMN)
- [ ] After migration: DI-13 script reports zero "MISSING" columns for updated tables

## Rollback Plan
All migrations are ADD COLUMN only. Rollback = `ALTER TABLE ... DROP COLUMN IF EXISTS new_col;` — safe to run.

## Definition of Done
- Migration SQL files committed
- Applied to staging cluster
- DI-13 re-run confirms no missing columns
