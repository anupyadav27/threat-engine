-- ============================================================
-- Seed: CIS MySQL 8.0 Benchmark Rules
-- Target DB: threat_engine_tech
-- Tables: tech_rule_discoveries, tech_rule_metadata, tech_rule_control_mapping
-- ============================================================

BEGIN;

-- ── Discovery linkage entries ────────────────────────────────
INSERT INTO tech_rule_discoveries (rule_id, tech_type, tech_category, discovery_id, display_name, action_type, yaml_path)
VALUES
  ('db.mysql.cis.4.1',  'mysql', 'db', 'db.mysql.security.local_infile',             'local_infile Setting',             'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.4.3a', 'mysql', 'db', 'db.mysql.security.validate_password_policy', 'Password Validation Policy',       'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.4.3b', 'mysql', 'db', 'db.mysql.security.validate_password_length', 'Password Minimum Length',          'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.4.5',  'mysql', 'db', 'db.mysql.security.max_connect_errors',       'max_connect_errors Setting',       'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.5.1',  'mysql', 'db', 'db.mysql.auth.anonymous_account_count',     'Anonymous Account Count',          'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.5.2',  'mysql', 'db', 'db.mysql.auth.empty_password_count',        'Empty Password User Count',        'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.5.3',  'mysql', 'db', 'db.mysql.auth.wildcard_host_count',         'Wildcard Host User Count',         'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.5.4',  'mysql', 'db', 'db.mysql.auth.file_priv_count',             'FILE Privilege User Count',        'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.5.5',  'mysql', 'db', 'db.mysql.auth.super_priv_count',            'SUPER Privilege User Count',       'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.6.1',  'mysql', 'db', 'db.mysql.logging.log_error',                 'log_error Setting',                'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.6.2',  'mysql', 'db', 'db.mysql.logging.general_log',               'general_log Setting',              'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.6.3',  'mysql', 'db', 'db.mysql.logging.slow_query_log',            'slow_query_log Setting',           'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.6.4',  'mysql', 'db', 'db.mysql.logging.long_query_time',           'long_query_time Setting',          'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.6.5',  'mysql', 'db', 'db.mysql.logging.log_raw',                   'log_raw Setting',                  'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.6.6',  'mysql', 'db', 'db.mysql.logging.audit_plugin',              'Audit Plugin Status',              'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.8.1',  'mysql', 'db', 'db.mysql.encryption.require_secure_transport','require_secure_transport Setting', 'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml'),
  ('db.mysql.cis.8.2',  'mysql', 'db', 'db.mysql.encryption.tls_version',            'TLS Version Setting',              'query_table', 'catalog/discovery_generator_data/db/mysql/step6_discovery.yaml')
ON CONFLICT (discovery_id) DO NOTHING;


-- ── Check rules ──────────────────────────────────────────────
INSERT INTO tech_rule_metadata
  (rule_id, tech_type, tech_category, title, severity,
   cis_benchmark, cis_section, nist_controls, soc2_criteria,
   remediation, rule_metadata, is_active)
VALUES

-- CIS 4.1 — Disable local_infile
(
  'db.mysql.cis.4.1', 'mysql', 'db',
  'Ensure local_infile is disabled',
  'high',
  'CIS MySQL 8.0 Benchmark', '4.1',
  '["CM-7", "AC-3"]',
  '["CC6.1"]',
  'Add local_infile=OFF to [mysqld] section in my.cnf and restart MySQL.',
  '{"check": {"expected_key": "local_infile", "expected_value": 0, "operator": "eq"}}',
  true
),

-- CIS 4.3a — Password validation policy
(
  'db.mysql.cis.4.3a', 'mysql', 'db',
  'Ensure validate_password.policy is MEDIUM or STRONG',
  'high',
  'CIS MySQL 8.0 Benchmark', '4.3',
  '["IA-5", "IA-5(1)"]',
  '["CC6.1"]',
  'SET GLOBAL validate_password.policy = MEDIUM; or add to my.cnf: validate_password.policy=MEDIUM',
  '{"check": {"expected_key": "validate_password_policy", "expected_value": ["MEDIUM", "STRONG", 1, 2], "operator": "in"}}',
  true
),

-- CIS 4.3b — Password minimum length
(
  'db.mysql.cis.4.3b', 'mysql', 'db',
  'Ensure validate_password.length is 14 or greater',
  'medium',
  'CIS MySQL 8.0 Benchmark', '4.3',
  '["IA-5(1)"]',
  '["CC6.1"]',
  'SET GLOBAL validate_password.length = 14; or add validate_password.length=14 to my.cnf.',
  '{"check": {"expected_key": "validate_password_length", "expected_value": 14, "operator": "gte"}}',
  true
),

-- CIS 4.5 — max_connect_errors
(
  'db.mysql.cis.4.5', 'mysql', 'db',
  'Ensure max_connect_errors is set to prevent brute force',
  'medium',
  'CIS MySQL 8.0 Benchmark', '4.5',
  '["AC-7", "SC-5"]',
  '["CC6.1"]',
  'SET GLOBAL max_connect_errors = 100; or add max_connect_errors=100 to my.cnf.',
  '{"check": {"expected_key": "max_connect_errors", "expected_value": 18446744073709551615, "operator": "ne"}}',
  true
),

-- CIS 5.1 — No anonymous accounts
(
  'db.mysql.cis.5.1', 'mysql', 'db',
  'Ensure no anonymous accounts exist in MySQL',
  'critical',
  'CIS MySQL 8.0 Benchmark', '5.1',
  '["IA-2", "AC-2"]',
  '["CC6.1"]',
  'DELETE FROM mysql.user WHERE User = ''''; FLUSH PRIVILEGES;',
  '{"check": {"expected_key": "anonymous_count", "expected_value": 0, "operator": "eq"}}',
  true
),

-- CIS 5.2 — No users with empty passwords
(
  'db.mysql.cis.5.2', 'mysql', 'db',
  'Ensure no active user accounts have empty passwords',
  'critical',
  'CIS MySQL 8.0 Benchmark', '5.2',
  '["IA-5", "IA-5(1)"]',
  '["CC6.1"]',
  'ALTER USER ''username''@''host'' IDENTIFIED BY ''strong_password''; for each empty-password account.',
  '{"check": {"expected_key": "empty_password_count", "expected_value": 0, "operator": "eq"}}',
  true
),

-- CIS 5.3 — No wildcard host users
(
  'db.mysql.cis.5.3', 'mysql', 'db',
  'Ensure no user account uses wildcard (%) as host',
  'high',
  'CIS MySQL 8.0 Benchmark', '5.3',
  '["AC-3", "CM-7"]',
  '["CC6.6"]',
  'ALTER USER ''user''@''%'' RENAME TO ''user''@''specific_ip''; restrict to known hosts.',
  '{"check": {"expected_key": "wildcard_host_count", "expected_value": 0, "operator": "eq"}}',
  true
),

-- CIS 5.4 — FILE privilege restricted
(
  'db.mysql.cis.5.4', 'mysql', 'db',
  'Ensure FILE privilege is not granted to non-administrative users',
  'high',
  'CIS MySQL 8.0 Benchmark', '5.4',
  '["AC-6", "AC-6(5)"]',
  '["CC6.3"]',
  'REVOKE FILE ON *.* FROM ''username''@''host''; for each non-root user with FILE privilege.',
  '{"check": {"expected_key": "file_priv_count", "expected_value": 0, "operator": "eq"}}',
  true
),

-- CIS 5.5 — SUPER privilege restricted to root
(
  'db.mysql.cis.5.5', 'mysql', 'db',
  'Ensure SUPER privilege is restricted to root account only',
  'critical',
  'CIS MySQL 8.0 Benchmark', '5.5',
  '["AC-6", "AC-6(5)"]',
  '["CC6.3"]',
  'REVOKE SUPER ON *.* FROM ''user''@''host''; for all non-root superusers.',
  '{"check": {"expected_key": "super_priv_count", "expected_value": 0, "operator": "eq"}}',
  true
),

-- CIS 6.1 — log_error must be set
(
  'db.mysql.cis.6.1', 'mysql', 'db',
  'Ensure log_error is set to a valid error log file',
  'medium',
  'CIS MySQL 8.0 Benchmark', '6.1',
  '["AU-2", "AU-12"]',
  '["CC7.2"]',
  'Set log_error=/var/log/mysql/error.log in my.cnf and restart MySQL.',
  '{"check": {"expected_key": "log_error", "expected_value": "", "operator": "ne"}}',
  true
),

-- CIS 6.2 — general_log OFF
(
  'db.mysql.cis.6.2', 'mysql', 'db',
  'Ensure general_log is disabled in production',
  'medium',
  'CIS MySQL 8.0 Benchmark', '6.2',
  '["AU-9"]',
  '["CC7.2"]',
  'SET GLOBAL general_log = OFF; or add general_log=OFF to my.cnf.',
  '{"check": {"expected_key": "general_log", "expected_value": 0, "operator": "eq"}}',
  true
),

-- CIS 6.3 — slow_query_log ON
(
  'db.mysql.cis.6.3', 'mysql', 'db',
  'Ensure slow_query_log is enabled',
  'low',
  'CIS MySQL 8.0 Benchmark', '6.3',
  '["AU-2"]',
  '["CC7.2"]',
  'SET GLOBAL slow_query_log = ON; or add slow_query_log=ON to my.cnf.',
  '{"check": {"expected_key": "slow_query_log", "expected_value": 1, "operator": "eq"}}',
  true
),

-- CIS 6.4 — long_query_time <= 2
(
  'db.mysql.cis.6.4', 'mysql', 'db',
  'Ensure long_query_time is set to 2 seconds or less',
  'low',
  'CIS MySQL 8.0 Benchmark', '6.4',
  '["AU-2"]',
  '["CC7.2"]',
  'SET GLOBAL long_query_time = 2; or add long_query_time=2 to my.cnf.',
  '{"check": {"expected_key": "long_query_time", "expected_value": 2, "operator": "lte"}}',
  true
),

-- CIS 6.5 — log_raw OFF (prevents passwords appearing in logs)
(
  'db.mysql.cis.6.5', 'mysql', 'db',
  'Ensure log_raw is disabled to prevent credential exposure in logs',
  'high',
  'CIS MySQL 8.0 Benchmark', '6.5',
  '["AU-9", "IA-5"]',
  '["CC6.1", "CC7.2"]',
  'Set log_raw=OFF in my.cnf. Do not enable this setting in production.',
  '{"check": {"expected_key": "log_raw", "expected_value": 0, "operator": "eq"}}',
  true
),

-- CIS 6.6 — Audit plugin installed
(
  'db.mysql.cis.6.6', 'mysql', 'db',
  'Ensure an audit logging plugin is installed and active',
  'medium',
  'CIS MySQL 8.0 Benchmark', '6.6',
  '["AU-2", "AU-12"]',
  '["CC7.2"]',
  'Install the audit_log plugin: INSTALL PLUGIN audit_log SONAME ''audit_log.so''; configure in my.cnf.',
  '{"check": {"expected_key": "audit_plugin_count", "expected_value": 0, "operator": "gt"}}',
  true
),

-- CIS 8.1 — require_secure_transport ON
(
  'db.mysql.cis.8.1', 'mysql', 'db',
  'Ensure require_secure_transport is enabled to enforce TLS connections',
  'high',
  'CIS MySQL 8.0 Benchmark', '8.1',
  '["SC-8", "SC-8(1)"]',
  '["CC6.7"]',
  'SET GLOBAL require_secure_transport = ON; or add require_secure_transport=ON to my.cnf.',
  '{"check": {"expected_key": "require_secure_transport", "expected_value": 1, "operator": "eq"}}',
  true
),

-- CIS 8.2 — TLS version excludes weak versions
(
  'db.mysql.cis.8.2', 'mysql', 'db',
  'Ensure tls_version does not include TLSv1 or TLSv1.1',
  'high',
  'CIS MySQL 8.0 Benchmark', '8.2',
  '["SC-8(1)"]',
  '["CC6.7"]',
  'Set tls_version=TLSv1.2,TLSv1.3 in my.cnf and restart MySQL.',
  '{"check": {"expected_key": "tls_version", "expected_value": "TLSv1.1", "operator": "not_contains"}}',
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
  ('db.mysql.cis.4.1',  'nist_800_53', 'CM-7',       'Least Functionality'),
  ('db.mysql.cis.4.1',  'pci_dss_v4',  '8.2.1',      'All user IDs and authentication factors are managed'),
  ('db.mysql.cis.4.3a', 'nist_800_53', 'IA-5',       'Authenticator Management'),
  ('db.mysql.cis.4.3a', 'pci_dss_v4',  '8.3.6',      'Minimum password complexity and strength'),
  ('db.mysql.cis.4.3b', 'nist_800_53', 'IA-5(1)',    'Password-based Authentication'),
  ('db.mysql.cis.5.1',  'nist_800_53', 'IA-2',       'Identification and Authentication'),
  ('db.mysql.cis.5.2',  'nist_800_53', 'IA-5',       'Authenticator Management'),
  ('db.mysql.cis.5.2',  'pci_dss_v4',  '8.2.2',      'All user accounts must have strong credentials'),
  ('db.mysql.cis.5.3',  'nist_800_53', 'AC-3',       'Access Enforcement'),
  ('db.mysql.cis.5.4',  'nist_800_53', 'AC-6',       'Least Privilege'),
  ('db.mysql.cis.5.5',  'nist_800_53', 'AC-6(5)',    'Privileged Accounts'),
  ('db.mysql.cis.5.5',  'pci_dss_v4',  '7.2.5',      'All application and system accounts are managed'),
  ('db.mysql.cis.6.1',  'nist_800_53', 'AU-2',       'Event Logging'),
  ('db.mysql.cis.6.2',  'nist_800_53', 'AU-9',       'Protection of Audit Information'),
  ('db.mysql.cis.6.3',  'nist_800_53', 'AU-2',       'Event Logging'),
  ('db.mysql.cis.6.5',  'nist_800_53', 'AU-9',       'Protection of Audit Information'),
  ('db.mysql.cis.6.6',  'nist_800_53', 'AU-12',      'Audit Record Generation'),
  ('db.mysql.cis.6.6',  'hipaa',       '164.312(b)', 'Audit Controls'),
  ('db.mysql.cis.8.1',  'nist_800_53', 'SC-8',       'Transmission Confidentiality and Integrity'),
  ('db.mysql.cis.8.1',  'pci_dss_v4',  '4.2.1',      'Strong cryptography for data in transit'),
  ('db.mysql.cis.8.2',  'nist_800_53', 'SC-8(1)',    'Cryptographic Protection')
ON CONFLICT (rule_id, framework, control_id) DO NOTHING;

COMMIT;
