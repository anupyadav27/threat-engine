-- Migration: Add Service Scan Tracking
-- Date: 2026-02-20
-- Purpose: Track all service scan attempts (successful, unavailable, failed)
--          to distinguish between services not enabled vs services with no resources

-- Create service_scan_attempts table
CREATE TABLE IF NOT EXISTS service_scan_attempts (
    id SERIAL PRIMARY KEY,
    discovery_scan_id VARCHAR(255) NOT NULL,
    service VARCHAR(100) NOT NULL,
    region VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,  -- 'scanned', 'unavailable', 'access_denied', 'failed'
    discoveries_count INTEGER DEFAULT 0,
    error_code VARCHAR(100),
    error_message TEXT,
    scan_duration_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_scan_attempt
        FOREIGN KEY (discovery_scan_id)
        REFERENCES discovery_report(discovery_scan_id)
        ON DELETE CASCADE,

    CONSTRAINT unique_scan_attempt
        UNIQUE (discovery_scan_id, service, region)
);

-- Create indexes for common queries
CREATE INDEX idx_scan_attempt_scan_id ON service_scan_attempts(discovery_scan_id);
CREATE INDEX idx_scan_attempt_status ON service_scan_attempts(status);
CREATE INDEX idx_scan_attempt_service ON service_scan_attempts(service);
CREATE INDEX idx_scan_attempt_region ON service_scan_attempts(region);

-- Comments for documentation
COMMENT ON TABLE service_scan_attempts IS 'Tracks all service scan attempts including unavailable/failed scans';
COMMENT ON COLUMN service_scan_attempts.status IS 'Status: scanned (successful), unavailable (OptInRequired), access_denied (permissions), failed (error)';
COMMENT ON COLUMN service_scan_attempts.discoveries_count IS 'Number of resources discovered (0 if service unavailable or empty)';
COMMENT ON COLUMN service_scan_attempts.error_code IS 'AWS error code: OptInRequired, AccessDenied, etc.';
COMMENT ON COLUMN service_scan_attempts.scan_duration_ms IS 'Time taken to scan service in milliseconds';
