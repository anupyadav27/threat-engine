-- iam_policy_statements: Parsed IAM policy statements for posture analysis
-- Database: threat_engine_iam
-- Created by IAM Engine Uplift (2026-03-21)

CREATE TABLE IF NOT EXISTS iam_policy_statements (
    statement_id VARCHAR(255) PRIMARY KEY,
    iam_scan_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    account_id VARCHAR(50),
    policy_arn TEXT,
    policy_name VARCHAR(255),
    policy_type VARCHAR(20) NOT NULL,            -- managed | inline | trust
    is_aws_managed BOOLEAN DEFAULT FALSE,
    attached_to_arn TEXT,                         -- Role/User/Group ARN
    attached_to_type VARCHAR(20),                -- role | user | group
    sid VARCHAR(255),
    effect VARCHAR(10) NOT NULL,                 -- Allow | Deny
    actions TEXT[] NOT NULL,
    resources TEXT[] NOT NULL,
    conditions JSONB,
    principals TEXT[],                            -- For trust policies
    is_admin BOOLEAN DEFAULT FALSE,              -- Action:* + Resource:*
    is_wildcard_principal BOOLEAN DEFAULT FALSE,
    has_external_id BOOLEAN,                     -- For trust policies
    is_cross_account BOOLEAN,                    -- For trust policies
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_tenant_stmt FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_iam_stmts_scan ON iam_policy_statements(iam_scan_id);
CREATE INDEX IF NOT EXISTS idx_iam_stmts_tenant ON iam_policy_statements(tenant_id);
CREATE INDEX IF NOT EXISTS idx_iam_stmts_policy_arn ON iam_policy_statements(policy_arn);
CREATE INDEX IF NOT EXISTS idx_iam_stmts_attached ON iam_policy_statements(attached_to_arn);
CREATE INDEX IF NOT EXISTS idx_iam_stmts_admin ON iam_policy_statements(is_admin) WHERE is_admin = TRUE;
CREATE INDEX IF NOT EXISTS idx_iam_stmts_type ON iam_policy_statements(policy_type);
