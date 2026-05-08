-- ============================================================
-- Seed: CIS PostgreSQL 15 Benchmark Rules
-- Target DB: threat_engine_tech
-- Table: tech_rule_metadata
-- ============================================================

BEGIN;

-- ── Helper: also insert catalog discovery entries ────────────
INSERT INTO tech_rule_discoveries (rule_id, tech_type, tech_category, discovery_id, display_name, action_type, yaml_path)
VALUES
  ('db.postgres.cis.1.1',  'postgres', 'db', 'db.postgres.auth.password_encryption',             'Password Encryption Setting',          'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.1.2',  'postgres', 'db', 'db.postgres.auth.pg_hba_rules',                   'pg_hba.conf Auth Methods',             'query_table',   'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.1.3',  'postgres', 'db', 'db.postgres.auth.superuser_accounts',             'Superuser Accounts',                   'query_table',   'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.3.1',  'postgres', 'db', 'db.postgres.logging.log_connections',             'log_connections Setting',              'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.3.2',  'postgres', 'db', 'db.postgres.logging.log_disconnections',          'log_disconnections Setting',           'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.3.3',  'postgres', 'db', 'db.postgres.logging.log_duration',                'log_duration Setting',                 'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.3.4',  'postgres', 'db', 'db.postgres.logging.log_line_prefix',             'log_line_prefix Setting',              'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.3.5',  'postgres', 'db', 'db.postgres.logging.log_statement',               'log_statement Setting',                'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.5.1',  'postgres', 'db', 'db.postgres.encryption.ssl_enabled',              'SSL Enabled',                          'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.5.2',  'postgres', 'db', 'db.postgres.encryption.ssl_min_protocol',         'SSL Minimum Protocol',                 'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.6.1',  'postgres', 'db', 'db.postgres.network.listen_addresses',            'Listen Addresses',                     'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.7.1',  'postgres', 'db', 'db.postgres.hardening.idle_timeout',              'Idle Transaction Timeout',             'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.7.2',  'postgres', 'db', 'db.postgres.hardening.statement_timeout',         'Statement Timeout',                    'query_setting', 'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'),
  ('db.postgres.cis.pgaudit', 'postgres', 'db', 'db.postgres.logging.pgaudit_installed',        'pgaudit Extension',                    'query_table',   'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml')
ON CONFLICT (discovery_id) DO NOTHING;


-- ── Check rules ──────────────────────────────────────────────
INSERT INTO tech_rule_metadata
  (rule_id, tech_type, tech_category, title, severity,
   cis_benchmark, cis_section, nist_controls, soc2_criteria,
   remediation, rule_metadata, is_active)
VALUES

-- CIS 1.1 — Password encryption
(
  'db.postgres.cis.1.1', 'postgres', 'db',
  'Ensure password_encryption is set to scram-sha-256',
  'high',
  'CIS PostgreSQL 15 Benchmark', '1.1',
  '["IA-5", "IA-5(1)"]',
  '["CC6.1", "CC6.7"]',
  'Run: ALTER SYSTEM SET password_encryption = ''scram-sha-256''; SELECT pg_reload_conf();',
  '{"check": {"expected_key": "password_encryption", "expected_value": "scram-sha-256", "operator": "eq"}}',
  true
),

-- CIS 1.2 — pg_hba trust check (any row with auth_method=trust is a FAIL)
(
  'db.postgres.cis.1.2', 'postgres', 'db',
  'Ensure pg_hba.conf does not use trust authentication',
  'critical',
  'CIS PostgreSQL 15 Benchmark', '1.2',
  '["IA-2", "IA-5"]',
  '["CC6.1"]',
  'Edit pg_hba.conf and replace "trust" with "scram-sha-256" or "md5". Reload with SELECT pg_reload_conf();',
  '{"check": {"expected_key": "auth_method", "expected_value": "trust", "operator": "ne"}}',
  true
),

-- CIS 1.3 — Only 1 superuser (postgres itself)
(
  'db.postgres.cis.1.3', 'postgres', 'db',
  'Ensure only one superuser account exists',
  'high',
  'CIS PostgreSQL 15 Benchmark', '1.3',
  '["AC-6", "AC-6(5)"]',
  '["CC6.3"]',
  'REVOKE SUPERUSER from any accounts that do not require superuser access.',
  '{}',
  true
),

-- CIS 3.1 — log_connections = on
(
  'db.postgres.cis.3.1', 'postgres', 'db',
  'Ensure log_connections is enabled',
  'medium',
  'CIS PostgreSQL 15 Benchmark', '3.1',
  '["AU-2", "AU-12"]',
  '["CC7.2"]',
  'ALTER SYSTEM SET log_connections = on; SELECT pg_reload_conf();',
  '{"check": {"expected_key": "log_connections", "expected_value": "on", "operator": "eq"}}',
  true
),

-- CIS 3.2 — log_disconnections = on
(
  'db.postgres.cis.3.2', 'postgres', 'db',
  'Ensure log_disconnections is enabled',
  'medium',
  'CIS PostgreSQL 15 Benchmark', '3.2',
  '["AU-2", "AU-12"]',
  '["CC7.2"]',
  'ALTER SYSTEM SET log_disconnections = on; SELECT pg_reload_conf();',
  '{"check": {"expected_key": "log_disconnections", "expected_value": "on", "operator": "eq"}}',
  true
),

-- CIS 3.3 — log_duration = on
(
  'db.postgres.cis.3.3', 'postgres', 'db',
  'Ensure log_duration is enabled',
  'medium',
  'CIS PostgreSQL 15 Benchmark', '3.3',
  '["AU-2"]',
  '["CC7.2"]',
  'ALTER SYSTEM SET log_duration = on; SELECT pg_reload_conf();',
  '{"check": {"expected_key": "log_duration", "expected_value": "on", "operator": "eq"}}',
  true
),

-- CIS 3.4 — log_line_prefix must include %m %u %d %r
(
  'db.postgres.cis.3.4', 'postgres', 'db',
  'Ensure log_line_prefix captures timestamp, user, db, and remote host',
  'medium',
  'CIS PostgreSQL 15 Benchmark', '3.4',
  '["AU-3"]',
  '["CC7.2"]',
  'ALTER SYSTEM SET log_line_prefix = ''%m [%p] %u@%d %r ''; SELECT pg_reload_conf();',
  '{"check": {"expected_key": "log_line_prefix", "expected_value": "%m", "operator": "contains"}}',
  true
),

-- CIS 3.5 — log_statement = ddl or all
(
  'db.postgres.cis.3.5', 'postgres', 'db',
  'Ensure log_statement is set to ddl or all',
  'medium',
  'CIS PostgreSQL 15 Benchmark', '3.5',
  '["AU-2", "AU-12"]',
  '["CC7.2"]',
  'ALTER SYSTEM SET log_statement = ''ddl''; SELECT pg_reload_conf();',
  '{"check": {"expected_key": "log_statement", "expected_value": ["ddl", "all"], "operator": "in"}}',
  true
),

-- CIS 5.1 — SSL must be on
(
  'db.postgres.cis.5.1', 'postgres', 'db',
  'Ensure SSL is enabled for all connections',
  'high',
  'CIS PostgreSQL 15 Benchmark', '5.1',
  '["SC-8", "SC-8(1)", "SC-28"]',
  '["CC6.7"]',
  'Set ssl = on in postgresql.conf and restart PostgreSQL. Generate or install a valid TLS certificate.',
  '{"check": {"expected_key": "ssl", "expected_value": "on", "operator": "eq"}}',
  true
),

-- CIS 5.2 — TLS version >= 1.2
(
  'db.postgres.cis.5.2', 'postgres', 'db',
  'Ensure ssl_min_protocol_version is TLSv1.2 or higher',
  'high',
  'CIS PostgreSQL 15 Benchmark', '5.2',
  '["SC-8(1)"]',
  '["CC6.7"]',
  'ALTER SYSTEM SET ssl_min_protocol_version = ''TLSv1.2''; SELECT pg_reload_conf();',
  '{"check": {"expected_key": "ssl_min_protocol_version", "expected_value": ["TLSv1.2", "TLSv1.3"], "operator": "in"}}',
  true
),

-- CIS 6.1 — listen_addresses should not be '*'
(
  'db.postgres.cis.6.1', 'postgres', 'db',
  'Ensure listen_addresses is not set to wildcard (*)',
  'high',
  'CIS PostgreSQL 15 Benchmark', '6.1',
  '["CM-7", "SC-7"]',
  '["CC6.6"]',
  'Set listen_addresses to specific interface IPs or ''localhost'' in postgresql.conf and restart.',
  '{"check": {"expected_key": "listen_addresses", "expected_value": "*", "operator": "ne"}}',
  true
),

-- CIS 7.1 — idle_in_transaction_session_timeout > 0
(
  'db.postgres.cis.7.1', 'postgres', 'db',
  'Ensure idle_in_transaction_session_timeout is set',
  'medium',
  'CIS PostgreSQL 15 Benchmark', '7.1',
  '["AC-12", "SC-10"]',
  '["CC6.8"]',
  'ALTER SYSTEM SET idle_in_transaction_session_timeout = ''60000''; -- 60 seconds',
  '{"check": {"expected_key": "idle_in_transaction_session_timeout", "expected_value": "0", "operator": "ne"}}',
  true
),

-- CIS 7.2 — statement_timeout > 0
(
  'db.postgres.cis.7.2', 'postgres', 'db',
  'Ensure statement_timeout is set to prevent long-running queries',
  'low',
  'CIS PostgreSQL 15 Benchmark', '7.2',
  '["AC-12"]',
  '["CC6.8"]',
  'ALTER SYSTEM SET statement_timeout = ''300000''; -- 5 minutes',
  '{"check": {"expected_key": "statement_timeout", "expected_value": "0", "operator": "ne"}}',
  true
),

-- pgaudit — should be installed for full audit trail
(
  'db.postgres.cis.pgaudit', 'postgres', 'db',
  'Ensure pgaudit extension is installed for detailed SQL audit logging',
  'medium',
  'CIS PostgreSQL 15 Benchmark', '3.6',
  '["AU-2", "AU-12"]',
  '["CC7.2"]',
  'CREATE EXTENSION pgaudit; then set pgaudit.log = ''write,ddl'' in postgresql.conf.',
  '{"check": {"expected_key": "is_installed", "expected_value": true, "operator": "eq"}}',
  true
)

ON CONFLICT (rule_id) DO UPDATE SET
  title        = EXCLUDED.title,
  severity     = EXCLUDED.severity,
  nist_controls = EXCLUDED.nist_controls,
  soc2_criteria = EXCLUDED.soc2_criteria,
  remediation  = EXCLUDED.remediation,
  rule_metadata = EXCLUDED.rule_metadata,
  is_active    = EXCLUDED.is_active;


-- ── Control mappings ─────────────────────────────────────────
INSERT INTO tech_rule_control_mapping (rule_id, framework, control_id, control_name)
VALUES
  ('db.postgres.cis.1.1',  'nist_800_53', 'IA-5',   'Authenticator Management'),
  ('db.postgres.cis.1.1',  'pci_dss_v4',  '8.3.6',  'Strong cryptography for passwords'),
  ('db.postgres.cis.1.2',  'nist_800_53', 'IA-2',   'Identification and Authentication'),
  ('db.postgres.cis.1.3',  'nist_800_53', 'AC-6',   'Least Privilege'),
  ('db.postgres.cis.3.1',  'nist_800_53', 'AU-2',   'Event Logging'),
  ('db.postgres.cis.3.1',  'hipaa',       '164.312(b)', 'Audit Controls'),
  ('db.postgres.cis.5.1',  'nist_800_53', 'SC-8',   'Transmission Confidentiality and Integrity'),
  ('db.postgres.cis.5.1',  'pci_dss_v4',  '4.2.1',  'Strong cryptography for data in transit'),
  ('db.postgres.cis.6.1',  'nist_800_53', 'CM-7',   'Least Functionality'),
  ('db.postgres.cis.7.1',  'nist_800_53', 'AC-12',  'Session Termination')
ON CONFLICT (rule_id, framework, control_id) DO NOTHING;

COMMIT;
