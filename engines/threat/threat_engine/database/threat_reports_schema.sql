-- Threat Reports Table
-- Stores full threat report JSON (cspm_threat_report.v1) per scan.
-- Use engine_threat schema with search_path = engine_threat,engine_shared.

CREATE TABLE IF NOT EXISTS threat_reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_run_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL,
    report_data JSONB NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, scan_run_id)
);

CREATE INDEX IF NOT EXISTS idx_threat_reports_tenant_scan ON threat_reports(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_threat_reports_generated_at ON threat_reports(generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_reports_cloud ON threat_reports(cloud);
CREATE INDEX IF NOT EXISTS idx_threat_reports_data_gin ON threat_reports USING gin(report_data);
