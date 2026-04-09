-- SecOps Fix Engine Schema
-- Database: threat_engine_secops (extends existing secops schema)
-- Table: secops_remediation

CREATE TABLE IF NOT EXISTS secops_remediation (
    remediation_id      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relational keys — map back to secops engine tables
    secops_scan_id      UUID         NOT NULL
                            REFERENCES secops_report(secops_scan_id) ON DELETE CASCADE,
    finding_id          BIGINT       NOT NULL
                            REFERENCES secops_findings(id) ON DELETE CASCADE,
    orchestration_id    UUID,                           -- from secops_report.orchestration_id
    tenant_id           VARCHAR(255) NOT NULL,
    customer_id         VARCHAR(255),
    rule_id             VARCHAR(512),                   -- from secops_findings.rule_id

    -- Finding context (denormalised for query speed — avoids joins on hot path)
    file_path           VARCHAR(1024),
    line_number         INTEGER,
    language            VARCHAR(64),
    severity            VARCHAR(32),

    -- Rule match result
    match_layer         VARCHAR(32),                    -- exact / cwe / regex / unmatched
    matched_rule_id     VARCHAR(512),                   -- rule_id from secrets_docs that matched

    -- Fix details
    original_code       TEXT,                           -- offending line(s) from source file
    suggested_fix       TEXT,                           -- rewritten safe line(s)
    fix_explanation     TEXT,                           -- human-readable why + how
    compliant_example   TEXT,                           -- from rule metadata examples.compliant

    -- Git patch info
    repo_url            VARCHAR(1024),                  -- from secops_report.repo_url
    fix_branch          VARCHAR(255),                   -- secops-fix/{secops_scan_id}
    pr_url              VARCHAR(1024),                  -- raised PR link (if available)

    -- Status tracking
    status              VARCHAR(32)  DEFAULT 'pending', -- pending/matched/fix_generated/applied/failed/skipped
    error_message       TEXT,

    created_at          TIMESTAMPTZ  DEFAULT now(),
    updated_at          TIMESTAMPTZ  DEFAULT now()
);

-- ── UNIQUE constraint ─────────────────────────────────────────────────────────
-- Required for ON CONFLICT (finding_id) DO UPDATE in writer.py.
-- One remediation row per finding — re-running remediation on the same scan
-- updates the existing row rather than creating duplicates.
ALTER TABLE secops_remediation
    ADD CONSTRAINT IF NOT EXISTS uq_remediation_finding UNIQUE (finding_id);

-- Indexes for common access patterns
CREATE INDEX IF NOT EXISTS idx_rem_scan_id    ON secops_remediation(secops_scan_id);
CREATE INDEX IF NOT EXISTS idx_rem_finding    ON secops_remediation(finding_id);
CREATE INDEX IF NOT EXISTS idx_rem_orch       ON secops_remediation(orchestration_id)
                                              WHERE orchestration_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rem_tenant     ON secops_remediation(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rem_status     ON secops_remediation(status);
CREATE INDEX IF NOT EXISTS idx_rem_rule       ON secops_remediation(rule_id);
CREATE INDEX IF NOT EXISTS idx_rem_severity   ON secops_remediation(severity);

-- Auto-update updated_at on row change
CREATE OR REPLACE FUNCTION update_remediation_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_remediation_updated_at ON secops_remediation;
CREATE TRIGGER trg_remediation_updated_at
    BEFORE UPDATE ON secops_remediation
    FOR EACH ROW EXECUTE FUNCTION update_remediation_updated_at();
