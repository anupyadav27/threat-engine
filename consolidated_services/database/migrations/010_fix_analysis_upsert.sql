-- Migration 010: Fix threat_analysis upsert behaviour
-- Problem: analysis_id is random uuid4, so ON CONFLICT (analysis_id) never fires on rerun.
--          Each rerun inserts duplicate analyses instead of updating existing ones.
-- Fix:     Add UNIQUE constraint on (detection_id, analysis_type) — the natural key.
--          One analysis per detection per type; reruns update in place.

-- 1. Remove duplicate analyses (keep the latest per detection_id + analysis_type)
DELETE FROM threat_analysis
WHERE analysis_id NOT IN (
    SELECT DISTINCT ON (detection_id, analysis_type) analysis_id
    FROM threat_analysis
    ORDER BY detection_id, analysis_type, created_at DESC
);

-- 2. Add the unique constraint
ALTER TABLE threat_analysis
    ADD CONSTRAINT uq_detection_analysis_type UNIQUE (detection_id, analysis_type);
