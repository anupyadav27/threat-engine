-- Migration: account_providers + account_types + account_provider_type_map
-- Creates three reference tables that serve as the authoritative source of truth
-- for all valid provider strings and account_type values.
-- Other engines can query these via the onboarding engine's REST API
-- (GET /api/v1/providers, GET /api/v1/account-types).
--
-- Apply:
--   kubectl exec -n threat-engine-engines deployment/engine-onboarding -- \
--       python3 -c "$(cat scripts/apply_migration_inline.py)" \
--       onboarding_reference_tables_001.sql

BEGIN;

-- ── 1. account_providers ────────────────────────────────────────────────────
-- Authoritative list of all connector/integration types.

CREATE TABLE IF NOT EXISTS account_providers (
    provider            VARCHAR(50)     NOT NULL,
    display_name        VARCHAR(100)    NOT NULL,
    category            VARCHAR(50)     NOT NULL,
    -- cloud_csp | database | code_security | agent
    credential_models   JSONB           NOT NULL DEFAULT '[]'::jsonb,
    -- list of valid credential_type strings for this provider
    -- e.g. ["iam_role","access_key"] for aws
    description         TEXT,
    logo_key            VARCHAR(100),
    -- frontend asset key (e.g. "aws", "azure") — matches existing wizard icons
    is_active           BOOLEAN         NOT NULL DEFAULT true,
    display_order       SMALLINT        NOT NULL DEFAULT 100,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT account_providers_pkey PRIMARY KEY (provider)
);

-- ── 2. account_types ───────────────────────────────────────────────────────
-- Authoritative list of scanning purposes and which engines they trigger.

CREATE TABLE IF NOT EXISTS account_types (
    account_type        VARCHAR(50)     NOT NULL,
    display_name        VARCHAR(100)    NOT NULL,
    description         TEXT,
    engines_triggered   JSONB           NOT NULL DEFAULT '[]'::jsonb,
    -- ordered list of engine names that run for this account_type
    is_active           BOOLEAN         NOT NULL DEFAULT true,
    display_order       SMALLINT        NOT NULL DEFAULT 100,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT account_types_pkey PRIMARY KEY (account_type)
);

-- ── 3. account_provider_type_map ───────────────────────────────────────────
-- Many-to-many: which account_types a provider can serve.
-- is_default = true means this account_type is auto-selected when caller
-- omits account_type (replaces PROVIDER_TO_ACCOUNT_TYPE dict in constants.py).

CREATE TABLE IF NOT EXISTS account_provider_type_map (
    provider            VARCHAR(50)     NOT NULL
                            REFERENCES account_providers(provider) ON DELETE CASCADE,
    account_type        VARCHAR(50)     NOT NULL
                            REFERENCES account_types(account_type) ON DELETE CASCADE,
    is_default          BOOLEAN         NOT NULL DEFAULT false,

    CONSTRAINT account_provider_type_map_pkey PRIMARY KEY (provider, account_type)
);

CREATE INDEX IF NOT EXISTS idx_prov_type_map_provider
    ON account_provider_type_map(provider);
CREATE INDEX IF NOT EXISTS idx_prov_type_map_type
    ON account_provider_type_map(account_type);

-- ── 4. Seed account_types ──────────────────────────────────────────────────

INSERT INTO account_types (account_type, display_name, description, engines_triggered, display_order)
VALUES
    ('cloud_csp',     'Cloud (CSP)',
     'Full cloud security posture scan covering resources, compliance, IAM, network, data security.',
     '["discovery","check","inventory","threat","compliance","iam","datasec","network-security","risk"]',
     10),
    ('vulnerability', 'Vulnerability',
     'CVE scanning of servers and containers via the CSPM agent installed on target hosts.',
     '["vulnerability"]',
     20),
    ('database',      'Database',
     'Database security posture: access control, encryption, audit logging, backup policy.',
     '["dbsec"]',
     30),
    ('code_security', 'Code / VCS',
     'SAST, DAST, SCA and IaC scanning of code repositories.',
     '["secops"]',
     40),
    ('middleware',    'Middleware',
     'Application server and message-queue security via the CSPM agent.',
     '["check"]',
     50)
ON CONFLICT (account_type) DO UPDATE SET
    display_name      = EXCLUDED.display_name,
    description       = EXCLUDED.description,
    engines_triggered = EXCLUDED.engines_triggered,
    display_order     = EXCLUDED.display_order,
    updated_at        = NOW();

-- ── 5. Seed account_providers ─────────────────────────────────────────────

INSERT INTO account_providers (provider, display_name, category, credential_models, description, logo_key, display_order)
VALUES
    -- Cloud CSPs
    ('aws',       'Amazon Web Services',  'cloud_csp',
     '["iam_role","access_key"]',
     'AWS account — scanned via IAM role assumption or access key.',
     'aws', 10),

    ('azure',     'Microsoft Azure',      'cloud_csp',
     '["service_principal"]',
     'Azure subscription — scanned via Entra ID service principal.',
     'azure', 20),

    ('gcp',       'Google Cloud',         'cloud_csp',
     '["service_account"]',
     'GCP project — scanned via service account JSON key.',
     'gcp', 30),

    ('oci',       'Oracle Cloud',         'cloud_csp',
     '["api_key"]',
     'OCI tenancy — scanned via OCI API key pair.',
     'oci', 40),

    ('alicloud',  'Alibaba Cloud',        'cloud_csp',
     '["access_key"]',
     'AliCloud account — scanned via RAM access key.',
     'alicloud', 50),

    ('ibm',       'IBM Cloud',            'cloud_csp',
     '["api_key"]',
     'IBM Cloud account — scanned via IBM Cloud API key.',
     'ibm', 60),

    ('k8s',       'Kubernetes',           'cloud_csp',
     '["kubeconfig","in_cluster"]',
     'Kubernetes cluster — scanned via kubeconfig or in-cluster service account.',
     'k8s', 70),

    -- Databases
    ('postgres',  'PostgreSQL',           'database',
     '["connection_string","username_password"]',
     'PostgreSQL database — scanned via direct connection.',
     'postgres', 80),

    ('mysql',     'MySQL',                'database',
     '["connection_string","username_password"]',
     'MySQL / MariaDB database — scanned via direct connection.',
     'mysql', 90),

    ('mssql',     'SQL Server',           'database',
     '["connection_string","username_password"]',
     'Microsoft SQL Server — scanned via TDS protocol.',
     'mssql', 100),

    ('mongodb',   'MongoDB',              'database',
     '["connection_string","username_password"]',
     'MongoDB — scanned via mongo wire protocol.',
     'mongodb', 110),

    ('oracle',    'Oracle Database',      'database',
     '["connection_string","username_password"]',
     'Oracle Database — scanned via OCI driver.',
     'oracle', 120),

    -- VCS / Code Security
    ('github',    'GitHub',               'code_security',
     '["token","github_app"]',
     'GitHub organization or repository — scanned via personal access token or GitHub App.',
     'github', 130),

    ('gitlab',    'GitLab',              'code_security',
     '["token"]',
     'GitLab group or project — scanned via personal access token.',
     'gitlab', 140),

    ('bitbucket', 'Bitbucket',           'code_security',
     '["token","app_password"]',
     'Bitbucket workspace — scanned via app password.',
     'bitbucket', 150),

    -- Agent-based
    ('agent',     'CSPM Agent',          'agent',
     '["agent_token"]',
     'Software agent installed on target host — phones home; no cloud API credentials required.',
     'agent', 160)

ON CONFLICT (provider) DO UPDATE SET
    display_name      = EXCLUDED.display_name,
    category          = EXCLUDED.category,
    credential_models = EXCLUDED.credential_models,
    description       = EXCLUDED.description,
    logo_key          = EXCLUDED.logo_key,
    display_order     = EXCLUDED.display_order,
    updated_at        = NOW();

-- ── 6. Seed account_provider_type_map ─────────────────────────────────────

INSERT INTO account_provider_type_map (provider, account_type, is_default)
VALUES
    -- Cloud CSPs → cloud_csp (only option, default)
    ('aws',       'cloud_csp',     true),
    ('azure',     'cloud_csp',     true),
    ('gcp',       'cloud_csp',     true),
    ('oci',       'cloud_csp',     true),
    ('alicloud',  'cloud_csp',     true),
    ('ibm',       'cloud_csp',     true),
    ('k8s',       'cloud_csp',     true),

    -- Databases → database (only option, default)
    ('postgres',  'database',      true),
    ('mysql',     'database',      true),
    ('mssql',     'database',      true),
    ('mongodb',   'database',      true),
    ('oracle',    'database',      true),

    -- VCS → code_security (only option, default)
    ('github',    'code_security', true),
    ('gitlab',    'code_security', true),
    ('bitbucket', 'code_security', true),

    -- Agent → vulnerability (default) or middleware
    ('agent',     'vulnerability', true),
    ('agent',     'middleware',    false)

ON CONFLICT (provider, account_type) DO UPDATE SET
    is_default = EXCLUDED.is_default;

-- ── 7. FK constraints on cloud_accounts ────────────────────────────────────
-- Add FK references so cloud_accounts.provider and .account_type stay in sync
-- with the reference tables. Use NOT VALID to avoid a full table lock.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'cloud_accounts'
          AND constraint_name = 'fk_cloud_accounts_provider'
    ) THEN
        ALTER TABLE cloud_accounts
            ADD CONSTRAINT fk_cloud_accounts_provider
            FOREIGN KEY (provider)
            REFERENCES account_providers(provider)
            NOT VALID;
    END IF;
END $$;

ALTER TABLE cloud_accounts VALIDATE CONSTRAINT fk_cloud_accounts_provider;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'cloud_accounts'
          AND constraint_name = 'fk_cloud_accounts_account_type'
    ) THEN
        ALTER TABLE cloud_accounts
            ADD CONSTRAINT fk_cloud_accounts_account_type
            FOREIGN KEY (account_type)
            REFERENCES account_types(account_type)
            NOT VALID;
    END IF;
END $$;

ALTER TABLE cloud_accounts VALIDATE CONSTRAINT fk_cloud_accounts_account_type;

COMMIT;
