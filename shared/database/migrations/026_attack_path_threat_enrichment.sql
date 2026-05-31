BEGIN;

ALTER TABLE attack_paths
    ADD COLUMN IF NOT EXISTS confidence_level VARCHAR(20) NOT NULL DEFAULT 'speculative'
        CHECK (confidence_level IN ('confirmed', 'likely', 'speculative')),
    ADD COLUMN IF NOT EXISTS attack_name TEXT,
    ADD COLUMN IF NOT EXISTS attack_technique_chain JSONB,
    ADD COLUMN IF NOT EXISTS threat_pattern_ids JSONB,
    ADD COLUMN IF NOT EXISTS attack_story TEXT;

CREATE INDEX IF NOT EXISTS idx_ap_confidence ON attack_paths (tenant_id, confidence_level);

COMMENT ON COLUMN attack_paths.confidence_level IS 'confirmed=T3 match, likely=T2 match, speculative=no pattern match';
COMMENT ON COLUMN attack_paths.attack_name IS 'Human-readable name from matching threat pattern (e.g. EC2 Lateral Movement to PII Store)';
COMMENT ON COLUMN attack_paths.attack_technique_chain IS 'Ordered array of MITRE technique IDs covering each hop';
COMMENT ON COLUMN attack_paths.threat_pattern_ids IS 'Array of threat_scenario_incident UUIDs that validated this path';
COMMENT ON COLUMN attack_paths.attack_story IS 'Step-by-step attack scenario narrative';

COMMIT;

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: 026_attack_path_threat_enrichment'; END $$;
