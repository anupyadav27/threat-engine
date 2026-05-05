-- Migration: ciem_ui_gaps_001
-- Target DB: threat_engine_ciem
-- Purpose: Indexes required for CIEM investigation journey UI performance

BEGIN;

-- Heatmap Stage 1: GROUP BY (account_id × actor_principal_type × severity)
CREATE INDEX IF NOT EXISTS idx_cf_heatmap
    ON ciem_findings (tenant_id, account_id, actor_principal_type, severity);

-- Stage 1 identity table: COUNT FILTER (WHERE rule_source = 'log_correlation'/'baseline')
CREATE INDEX IF NOT EXISTS idx_cf_rule_source
    ON ciem_findings (tenant_id, rule_source);

CREATE INDEX IF NOT EXISTS idx_cf_actor_source
    ON ciem_findings (tenant_id, actor_principal, rule_source);

-- Stage 2 behavioral timeline: ORDER BY event_time ASC for a single principal
CREATE INDEX IF NOT EXISTS idx_cf_actor_timeline
    ON ciem_findings (tenant_id, actor_principal, event_time ASC);

-- Stage 2 + Stage 3: JSONB path lookups on finding_data (contributing_steps, anomalies)
CREATE INDEX IF NOT EXISTS idx_cf_finding_data_gin
    ON ciem_findings USING GIN (finding_data);

-- Stage 2 time-of-day heatmap: EXTRACT(HOUR) without seq scan
ALTER TABLE ciem_findings
    ADD COLUMN IF NOT EXISTS event_hour SMALLINT
    GENERATED ALWAYS AS (EXTRACT(HOUR FROM (event_time AT TIME ZONE 'UTC'))::smallint) STORED;

CREATE INDEX IF NOT EXISTS idx_cf_actor_hour
    ON ciem_findings (tenant_id, actor_principal, event_hour);

COMMIT;
