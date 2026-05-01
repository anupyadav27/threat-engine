-- ============================================================================
-- Migration 004: Add service_scan_attempts table to discoveries DB
--
-- Tracks per-service, per-region discovery outcomes so that failures
-- (AccessDenied, OptInRequired, timeouts) are visible in the API instead of
-- being silently dropped in pod logs.
--
-- status values:
--   scanned      — API call succeeded, resources may or may not have been found
--   unavailable  — service not enabled in this region (OptInRequired, etc.)
--   access_denied — IAM permission missing
--   failed       — unexpected error (network, timeout, bug)
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS service_scan_attempts (
    id                  BIGSERIAL PRIMARY KEY,
    scan_run_id         VARCHAR(255) NOT NULL,
    service             VARCHAR(128) NOT NULL,
    region              VARCHAR(64)  NOT NULL,
    status              VARCHAR(32)  NOT NULL DEFAULT 'scanned',
    discoveries_count   INTEGER      NOT NULL DEFAULT 0,
    error_code          VARCHAR(128),
    error_message       TEXT,
    scan_duration_ms    INTEGER,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT service_scan_attempts_uq UNIQUE (scan_run_id, service, region)
);

-- Index for the primary query pattern: all results for a given scan
CREATE INDEX IF NOT EXISTS idx_ssa_scan_run_id  ON service_scan_attempts (scan_run_id);
-- Index for debugging: find all scans that failed a specific service
CREATE INDEX IF NOT EXISTS idx_ssa_service_status ON service_scan_attempts (service, status);

COMMENT ON TABLE service_scan_attempts IS
    'Per-service-region outcome of each discovery scan. '
    'Populated by DiscoveryEngine after Phase 1 completes. '
    'Allows operators to see which services returned 0 results vs which failed with errors.';

COMMIT;
