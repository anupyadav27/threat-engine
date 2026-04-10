-- Migration: 022_disable_azure_noise_services.sql
-- Disable Azure rule_discoveries entries that produce no security value.
-- These services return billing, health, or operational data only — not
-- security posture findings.
--
-- Run once against the check DB (where rule_discoveries lives).
-- Idempotent: ON CONFLICT / WHERE clause safe to re-run.

UPDATE rule_discoveries
SET
    is_enabled      = false,
    disabled_reason = 'non-security: billing/monitoring/health API'
WHERE
    provider = 'azure'
    AND service IN (
        'consumption',              -- Azure Cost Management billing data
        'costmanagement',           -- Cost Management APIs
        'insights/metricDefinitions',  -- ARM metric metadata only
        'insights/activityLogs',    -- Activity log reader (SIEM, not posture)
        'advisor',                  -- Azure Advisor recommendations (ops)
        'resourcehealth',           -- Resource health events (ops)
        'maintenance',              -- Maintenance window config (ops)
        'locks'                     -- Resource locks (management plane only)
    );

-- Verify: expect 8 rows updated
-- SELECT COUNT(*) FROM rule_discoveries
-- WHERE provider = 'azure'
--   AND is_enabled = false
--   AND disabled_reason LIKE 'non-security%';
