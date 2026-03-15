-- ============================================================================
-- Migration 014: Support New Engines & Non-CSP Source Types
-- Tasks 0.4.1 [Seq 42 | DE] + 0.4.2 [Seq 43 | DE]
-- ============================================================================
--
-- TWO CHANGES:
--
-- 1. Extend cloud_accounts to support non-CSP source types (GitHub, GitLab,
--    Docker Hub, etc.) so the onboarding flow works for all new engines.
--    The existing provider column ('aws','azure','gcp','oci','alicloud','ibm','k8s')
--    gets new values: 'github', 'gitlab', 'dockerhub', 'bitbucket'
--    The existing credential_type column ('iam_role','access_key') gets new values:
--    'pat' (Personal Access Token), 'oauth_app', 'service_account_key'
--
-- 2. Extend scan_orchestration.engines_requested / update_orchestration_engine_scan_id()
--    to support the 5 new engine scan_id columns. This follows the exact same
--    pattern as the 7 existing *_scan_id columns. We only add the scan_id columns
--    because that's all the orchestrator needs — each engine tracks its own status
--    internally in its own DB.
--
-- Idempotent: All ALTER TABLE ADD COLUMN IF NOT EXISTS
-- Rollback:   DROP COLUMN for each added column
-- ============================================================================


-- ============================================================================
-- PART 1: New engine scan_id columns on scan_orchestration
-- ============================================================================
-- Follows the exact same pattern as discovery_scan_id, check_scan_id, etc.
-- Each engine writes its scan_id when it starts (via update_orchestration_engine_scan_id).
-- Other engines read this to know "has engine X run for this orchestration?"

ALTER TABLE scan_orchestration
  ADD COLUMN IF NOT EXISTS container_scan_id    VARCHAR(255),
  ADD COLUMN IF NOT EXISTS network_scan_id      VARCHAR(255),
  ADD COLUMN IF NOT EXISTS supplychain_scan_id  VARCHAR(255),
  ADD COLUMN IF NOT EXISTS api_scan_id          VARCHAR(255),
  ADD COLUMN IF NOT EXISTS risk_scan_id         VARCHAR(255);

COMMENT ON COLUMN scan_orchestration.container_scan_id IS 'engine_container scan ID — written when engine starts';
COMMENT ON COLUMN scan_orchestration.network_scan_id IS 'engine_network scan ID — written when engine starts';
COMMENT ON COLUMN scan_orchestration.supplychain_scan_id IS 'engine_supplychain scan ID — written when engine starts';
COMMENT ON COLUMN scan_orchestration.api_scan_id IS 'engine_api scan ID — written when engine starts';
COMMENT ON COLUMN scan_orchestration.risk_scan_id IS 'engine_risk scan ID — written when engine starts';


-- ============================================================================
-- PART 2: Indexes for new scan_id columns
-- ============================================================================
-- Same pattern as idx_orchestration_discovery, idx_orchestration_check, etc.

CREATE INDEX IF NOT EXISTS idx_orchestration_container
    ON scan_orchestration(container_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_network
    ON scan_orchestration(network_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_supplychain
    ON scan_orchestration(supplychain_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_api
    ON scan_orchestration(api_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_risk
    ON scan_orchestration(risk_scan_id);


-- ============================================================================
-- PART 3: Extend cloud_accounts for non-CSP source types
-- ============================================================================
-- cloud_accounts.provider currently allows: aws, azure, gcp, oci, alicloud, ibm, k8s
-- cloud_accounts.credential_type currently allows: iam_role, access_key
--
-- For new engines we need to onboard non-CSP sources:
--
--   provider='github'    + credential_type='pat'  → engine_supplychain scans repos
--   provider='gitlab'    + credential_type='pat'  → engine_supplychain scans repos
--   provider='dockerhub' + credential_type='pat'  → engine_container scans images
--   provider='bitbucket' + credential_type='oauth_app' → future
--
-- No schema change needed — provider and credential_type are VARCHAR(50),
-- not ENUMs. New values just work. But we add a CHECK constraint comment
-- documenting the valid values.
--
-- For GitHub/GitLab accounts:
--   account_id  = org name or group ID (e.g. 'my-org')
--   account_name = display name (e.g. 'My Org GitHub')
--   credential_ref = Secrets Manager path (e.g. 'threat-engine/github-token')
--
-- The scan flow remains identical:
--   cloud_accounts → schedule triggers → scan_orchestration row created
--   → engines read orchestration_id → get provider/credentials → do their work

COMMENT ON COLUMN cloud_accounts.provider IS
    'Source type: aws, azure, gcp, oci, alicloud, ibm, k8s, github, gitlab, dockerhub, bitbucket';
COMMENT ON COLUMN cloud_accounts.credential_type IS
    'Auth method: iam_role, access_key, pat (Personal Access Token), oauth_app, service_account_key';


-- ============================================================================
-- PART 4: Add source_type column to cloud_accounts (optional grouping)
-- ============================================================================
-- Helps UI/API distinguish between cloud providers and code/container sources.
-- Existing rows default to 'csp' (Cloud Service Provider).

ALTER TABLE cloud_accounts
  ADD COLUMN IF NOT EXISTS source_type VARCHAR(50) DEFAULT 'csp';

COMMENT ON COLUMN cloud_accounts.source_type IS
    'Source category: csp (cloud provider), scm (source code management), '
    'registry (container/package registry). Used by UI to group accounts.';

-- Backfill: all existing rows are CSP accounts
UPDATE cloud_accounts SET source_type = 'csp' WHERE source_type IS NULL;

-- Index for filtering by source_type
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_source_type
    ON cloud_accounts(source_type);
