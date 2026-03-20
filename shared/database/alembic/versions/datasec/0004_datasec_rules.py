"""Add datasec_rules and datasec_sensitive_data_types tables.

Revision ID: 0004_datasec_rules
Revises: 0003_drop_resource_arn
Database: threat_engine_datasec

Creates:
1. datasec_rules          - rule definitions for data security checks
2. datasec_sensitive_data_types - reference table of detectable sensitive data types
"""
from alembic import op
from sqlalchemy import text

revision = "0004_datasec_rules"
down_revision = "0003_drop_resource_arn"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    # ── 1. datasec_rules table ────────────────────────────────────────────
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS datasec_rules (
            id              SERIAL PRIMARY KEY,
            rule_id         VARCHAR(255)   NOT NULL,
            csp             VARCHAR(20)    NOT NULL DEFAULT 'aws',
            service         VARCHAR(100)   NOT NULL,
            resource_type   VARCHAR(100),
            category        VARCHAR(100)   NOT NULL,
            subcategory     VARCHAR(100),
            severity        VARCHAR(20)    NOT NULL DEFAULT 'medium',
            title           TEXT           NOT NULL,
            description     TEXT,
            remediation     TEXT,
            condition       JSONB          NOT NULL DEFAULT '{}'::jsonb,
            condition_type  VARCHAR(50)    DEFAULT 'field_check',
            compliance_frameworks JSONB    DEFAULT '[]'::jsonb,
            sensitive_data_types  JSONB    DEFAULT '[]'::jsonb,
            domain          VARCHAR(100),
            check_rule_id   VARCHAR(255),
            tenant_id       VARCHAR(255),
            is_active       BOOLEAN        NOT NULL DEFAULT TRUE,
            version         VARCHAR(50)    DEFAULT '1.0',
            created_at      TIMESTAMPTZ    DEFAULT NOW(),
            updated_at      TIMESTAMPTZ    DEFAULT NOW(),
            CONSTRAINT uq_datasec_rule UNIQUE (rule_id, csp, tenant_id)
        )
    """))

    # Indexes
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_datasec_rules_csp_active "
        "ON datasec_rules (csp, is_active)"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_datasec_rules_category "
        "ON datasec_rules (category)"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_datasec_rules_service_csp "
        "ON datasec_rules (service, csp)"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_datasec_rules_tenant "
        "ON datasec_rules (tenant_id)"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_datasec_rules_severity "
        "ON datasec_rules (severity)"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_datasec_rules_condition "
        "ON datasec_rules USING GIN (condition)"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_datasec_rules_compliance "
        "ON datasec_rules USING GIN (compliance_frameworks)"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_datasec_rules_sensitive_types "
        "ON datasec_rules USING GIN (sensitive_data_types)"
    ))

    # ── 2. datasec_sensitive_data_types table ─────────────────────────────
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS datasec_sensitive_data_types (
            id                  SERIAL PRIMARY KEY,
            category            VARCHAR(50)    NOT NULL,
            type_key            VARCHAR(100)   NOT NULL,
            display_name        VARCHAR(200)   NOT NULL,
            detection_pattern   TEXT,
            confidence_weight   DECIMAL(3,2)   DEFAULT 0.80,
            is_active           BOOLEAN        DEFAULT TRUE,
            CONSTRAINT uq_datasec_data_type UNIQUE (category, type_key)
        )
    """))

    # ── 3. Seed sensitive data types (26 rows) ────────────────────────────
    conn.execute(text("""
        INSERT INTO datasec_sensitive_data_types
            (category, type_key, display_name, detection_pattern, confidence_weight)
        VALUES
            -- PII (8)
            ('PII', 'ssn',            'Social Security Number',  '\\d{3}-\\d{2}-\\d{4}',                    0.95),
            ('PII', 'email',          'Email Address',           '[\\w.-]+@[\\w.-]+\\.\\w+',                 0.90),
            ('PII', 'phone',          'Phone Number',            '\\+?\\d[\\d\\s()-]{7,}',                   0.85),
            ('PII', 'address',        'Physical Address',        NULL,                                       0.80),
            ('PII', 'name',           'Person Name',             NULL,                                       0.70),
            ('PII', 'dob',            'Date of Birth',           '\\d{4}-\\d{2}-\\d{2}',                     0.85),
            ('PII', 'passport',       'Passport Number',         '[A-Z]{1,2}\\d{6,9}',                       0.90),
            ('PII', 'driver_license', 'Driver License Number',   '[A-Z0-9]{5,15}',                           0.85),
            -- PCI (4)
            ('PCI', 'credit_card',    'Credit Card Number',      '\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}', 0.95),
            ('PCI', 'cvv',            'Card Verification Value', '\\d{3,4}',                                 0.80),
            ('PCI', 'cardholder_name','Cardholder Name',         NULL,                                       0.75),
            ('PCI', 'track_data',     'Magnetic Track Data',     NULL,                                       0.95),
            -- PHI (5)
            ('PHI', 'medical_record', 'Medical Record Number',   '[A-Z]{2,3}\\d{6,10}',                      0.90),
            ('PHI', 'patient_id',     'Patient Identifier',      NULL,                                       0.85),
            ('PHI', 'diagnosis',      'Diagnosis Code',          '[A-Z]\\d{2}\\.?\\d{0,2}',                  0.90),
            ('PHI', 'prescription',   'Prescription Data',       NULL,                                       0.85),
            ('PHI', 'insurance_id',   'Insurance Identifier',    NULL,                                       0.80),
            -- Financial (3)
            ('Financial', 'bank_account',   'Bank Account Number',   '\\d{8,17}',                            0.85),
            ('Financial', 'routing_number', 'Routing Number',        '\\d{9}',                               0.90),
            ('Financial', 'tax_id',         'Tax Identifier',        '\\d{2}-\\d{7}',                        0.90),
            -- Credentials (4)
            ('Credentials', 'api_key',      'API Key',              '[A-Za-z0-9_-]{20,}',                    0.85),
            ('Credentials', 'password',     'Password',             NULL,                                    0.90),
            ('Credentials', 'token',        'Authentication Token', '[A-Za-z0-9_.-]{20,}',                   0.85),
            ('Credentials', 'certificate',  'Certificate / Private Key', '-----BEGIN',                       0.95),
            -- Internal (2)
            ('Internal', 'employee_id',  'Employee Identifier',   '[A-Z]{1,3}\\d{4,8}',                     0.75),
            ('Internal', 'internal_ip',  'Internal IP Address',   '(10|172\\.(1[6-9]|2\\d|3[01])|192\\.168)\\.\\d+\\.\\d+', 0.80)
        ON CONFLICT (category, type_key) DO NOTHING
    """))

    # ── 4. RLS on datasec_rules (match existing pattern) ──────────────────
    conn.execute(text(
        "ALTER TABLE datasec_rules ENABLE ROW LEVEL SECURITY"
    ))
    conn.execute(text("""
        DO $$ BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE tablename = 'datasec_rules' AND policyname = 'tenant_isolation'
            ) THEN
                EXECUTE 'CREATE POLICY tenant_isolation ON datasec_rules '
                     || 'USING (tenant_id = current_setting(''app.tenant_id'', TRUE) '
                     || 'OR tenant_id IS NULL)';
            END IF;
        END $$
    """))


def downgrade():
    conn = op.get_bind()
    conn.execute(text("DROP POLICY IF EXISTS tenant_isolation ON datasec_rules"))
    conn.execute(text("ALTER TABLE datasec_rules DISABLE ROW LEVEL SECURITY"))
    conn.execute(text("DROP TABLE IF EXISTS datasec_sensitive_data_types"))
    conn.execute(text("DROP TABLE IF EXISTS datasec_rules"))
