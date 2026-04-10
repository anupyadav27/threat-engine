-- =============================================================================
-- AI Security Engine Schema
-- Database: threat_engine_ai_security
-- Port: 8032 | Layer 2
-- =============================================================================

-- -----------------------------------------------------------------------------
-- tenants — Tenant registry (FK requirement for all engine tables)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(500),
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- ai_security_rules — Rule definitions for AI/ML security evaluation
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_security_rules (
    rule_id         VARCHAR(50) PRIMARY KEY,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium',
    category        VARCHAR(100) NOT NULL,       -- model_security, endpoint_security, data_pipeline, ai_governance, prompt_security, access_control
    subcategory     VARCHAR(100),
    condition       JSONB NOT NULL,
    condition_type  VARCHAR(50) DEFAULT 'field_check',  -- field_check, threshold, composite, pattern_match
    frameworks      TEXT[] DEFAULT '{}',          -- AI_ACT, NIST_AI_RMF, ISO_42001, SOC2, GDPR
    mitre_techniques TEXT[] DEFAULT '{}',         -- T1195.003, T1565.002, etc.
    remediation     TEXT,
    is_active       BOOLEAN DEFAULT true,
    provider        TEXT[] DEFAULT '{aws,azure,gcp}',
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- ai_security_input_transformed — Stage 1 ETL output
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_security_input_transformed (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255),

    -- Resource identification
    resource_id             VARCHAR(500),
    resource_type           VARCHAR(100),        -- sagemaker_endpoint, sagemaker_model, sagemaker_notebook, bedrock_model, lambda_ml, s3_ml_artifact, openai_endpoint
    resource_uid            TEXT,
    resource_name           VARCHAR(500),

    -- ML service details
    ml_service              VARCHAR(100),        -- sagemaker, bedrock, rekognition, comprehend, textract, polly, transcribe, translate, kendra, personalize, forecast, fraud_detector, lookout
    model_type              VARCHAR(100),        -- llm, classification, regression, nlp, cv, generative, custom
    framework               VARCHAR(100),        -- pytorch, tensorflow, huggingface, xgboost, sklearn, custom
    model_version           VARCHAR(100),
    deployment_type         VARCHAR(50),         -- realtime, serverless, batch, edge

    -- Security posture
    is_vpc_isolated         BOOLEAN DEFAULT false,
    encryption_at_rest      BOOLEAN DEFAULT false,
    encryption_in_transit   BOOLEAN DEFAULT false,
    iam_role_arn            VARCHAR(1000),
    has_model_card          BOOLEAN DEFAULT false,
    has_monitoring          BOOLEAN DEFAULT false,
    has_data_capture        BOOLEAN DEFAULT false,
    is_public_endpoint      BOOLEAN DEFAULT false,
    auth_type               VARCHAR(50),         -- iam, api_key, none, cognito, custom
    network_isolation       BOOLEAN DEFAULT false,

    -- Training data security
    training_data_sources   JSONB DEFAULT '[]',  -- [{source, encryption, access_control}]
    training_data_encrypted BOOLEAN DEFAULT false,
    training_vpc_isolated   BOOLEAN DEFAULT false,

    -- Model artifact security
    artifact_bucket         VARCHAR(500),
    artifact_encrypted      BOOLEAN DEFAULT false,
    artifact_versioned      BOOLEAN DEFAULT false,

    -- Prompt/LLM specific
    has_guardrails          BOOLEAN DEFAULT false,
    has_content_filter      BOOLEAN DEFAULT false,
    has_input_validation    BOOLEAN DEFAULT false,
    has_output_filtering    BOOLEAN DEFAULT false,
    max_token_limit         INTEGER,
    rate_limit_configured   BOOLEAN DEFAULT false,

    -- Runtime stats (from log_collector)
    invocations_24h         INTEGER DEFAULT 0,
    error_rate_pct          DECIMAL(5,2) DEFAULT 0,
    avg_latency_ms          INTEGER DEFAULT 0,
    anomalous_inputs_24h    INTEGER DEFAULT 0,

    -- Metadata
    account_id              VARCHAR(255),
    region                  VARCHAR(50),
    provider                VARCHAR(20) DEFAULT 'aws',
    tags                    JSONB DEFAULT '{}',
    created_at              TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ai_sec_transformed_scan ON ai_security_input_transformed (scan_run_id);
CREATE INDEX idx_ai_sec_transformed_resource ON ai_security_input_transformed (resource_type, ml_service);

-- -----------------------------------------------------------------------------
-- ai_security_findings — Stage 2 evaluation results
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_security_findings (
    finding_id              VARCHAR(255) PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255),
    rule_id                 VARCHAR(50) NOT NULL,
    resource_id             VARCHAR(500),
    resource_type           VARCHAR(100),
    resource_uid            TEXT,
    ml_service              VARCHAR(100),
    model_type              VARCHAR(100),
    severity                VARCHAR(20) NOT NULL,
    status                  VARCHAR(20) NOT NULL DEFAULT 'FAIL',   -- PASS, FAIL, SKIP, ERROR
    category                VARCHAR(100),
    title                   VARCHAR(500),
    detail                  TEXT,
    remediation             TEXT,
    frameworks              TEXT[] DEFAULT '{}',
    mitre_techniques        TEXT[] DEFAULT '{}',
    account_id              VARCHAR(255),
    region                  VARCHAR(50),
    provider                VARCHAR(20) DEFAULT 'aws',
    first_seen_at           TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at            TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ai_sec_findings_scan ON ai_security_findings (scan_run_id);
CREATE INDEX idx_ai_sec_findings_severity ON ai_security_findings (severity, status);
CREATE INDEX idx_ai_sec_findings_rule ON ai_security_findings (rule_id);
CREATE INDEX idx_ai_sec_findings_category ON ai_security_findings (category);

-- -----------------------------------------------------------------------------
-- ai_security_inventory — Discovered ML/AI resources
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_security_inventory (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255),
    resource_id             VARCHAR(500),
    resource_type           VARCHAR(100),
    resource_uid            TEXT,
    resource_name           VARCHAR(500),
    ml_service              VARCHAR(100),
    model_type              VARCHAR(100),
    framework               VARCHAR(100),
    deployment_type         VARCHAR(50),
    is_public_endpoint      BOOLEAN DEFAULT false,
    auth_type               VARCHAR(50),
    has_guardrails          BOOLEAN DEFAULT false,
    risk_score              INTEGER DEFAULT 0,     -- 0-100
    account_id              VARCHAR(255),
    region                  VARCHAR(50),
    provider                VARCHAR(20) DEFAULT 'aws',
    tags                    JSONB DEFAULT '{}',
    created_at              TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ai_sec_inventory_scan ON ai_security_inventory (scan_run_id);

-- -----------------------------------------------------------------------------
-- ai_security_report — Stage 3 scan summary
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_security_report (
    scan_run_id             VARCHAR(255) PRIMARY KEY,
    tenant_id               VARCHAR(255),
    account_id              VARCHAR(255),
    provider                VARCHAR(50) DEFAULT 'aws',

    -- Counts
    total_ml_resources      INTEGER DEFAULT 0,
    total_findings          INTEGER DEFAULT 0,
    critical_findings       INTEGER DEFAULT 0,
    high_findings           INTEGER DEFAULT 0,
    medium_findings         INTEGER DEFAULT 0,
    low_findings            INTEGER DEFAULT 0,
    pass_count              INTEGER DEFAULT 0,
    fail_count              INTEGER DEFAULT 0,

    -- Coverage metrics
    vpc_isolation_pct       DECIMAL(5,2) DEFAULT 0,
    encryption_rest_pct     DECIMAL(5,2) DEFAULT 0,
    encryption_transit_pct  DECIMAL(5,2) DEFAULT 0,
    model_card_pct          DECIMAL(5,2) DEFAULT 0,
    monitoring_pct          DECIMAL(5,2) DEFAULT 0,
    guardrails_pct          DECIMAL(5,2) DEFAULT 0,

    -- Breakdowns
    category_breakdown      JSONB DEFAULT '{}',     -- {model_security: {pass: N, fail: N}, ...}
    service_breakdown       JSONB DEFAULT '{}',     -- {sagemaker: N, bedrock: N, ...}
    framework_compliance    JSONB DEFAULT '{}',     -- {AI_ACT: {pass: N, fail: N}, ...}
    top_failing_rules       JSONB DEFAULT '[]',
    risk_score              INTEGER DEFAULT 0,       -- 0-100

    -- Timing
    started_at              TIMESTAMP,
    completed_at            TIMESTAMP,
    scan_duration_ms        INTEGER,
    status                  VARCHAR(50) DEFAULT 'completed',
    error_message           TEXT,
    created_at              TIMESTAMP DEFAULT NOW()
);
