-- Migration: CDR-01_ciem_to_cdr_rename
-- Target DB: threat_engine_ciem (will be renamed to threat_engine_cdr in deploy step)
-- Purpose: Rename all CIEM tables and indexes to CDR equivalents.
-- Run AFTER scaling down all pods connected to this DB.
-- The ALTER DATABASE rename runs separately in the deploy script.

BEGIN;

-- Tables
ALTER TABLE IF EXISTS ciem_findings             RENAME TO cdr_findings;
ALTER TABLE IF EXISTS ciem_actor_daily_stats    RENAME TO cdr_actor_daily_stats;
ALTER TABLE IF EXISTS ciem_baselines            RENAME TO cdr_baselines;
ALTER TABLE IF EXISTS ciem_report               RENAME TO cdr_report;
ALTER TABLE IF EXISTS ciem_collection_watermark RENAME TO cdr_collection_watermark;

-- Indexes on cdr_findings (previously ciem_findings)
ALTER INDEX IF EXISTS idx_cf_heatmap          RENAME TO idx_cdr_heatmap;
ALTER INDEX IF EXISTS idx_cf_rule_source      RENAME TO idx_cdr_rule_source;
ALTER INDEX IF EXISTS idx_cf_actor_source     RENAME TO idx_cdr_actor_source;
ALTER INDEX IF EXISTS idx_cf_actor_timeline   RENAME TO idx_cdr_actor_timeline;
ALTER INDEX IF EXISTS idx_cf_finding_data_gin RENAME TO idx_cdr_finding_data_gin;
ALTER INDEX IF EXISTS idx_cf_actor_hour       RENAME TO idx_cdr_actor_hour;

-- Indexes on cdr_actor_daily_stats (previously ciem_actor_daily_stats)
ALTER INDEX IF EXISTS idx_cads_tenant_date    RENAME TO idx_cdr_ads_tenant_date;
ALTER INDEX IF EXISTS idx_cads_entity         RENAME TO idx_cdr_ads_entity;

COMMIT;
