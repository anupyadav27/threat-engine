-- ============================================================================
-- DEPRECATED — Supply Chain Engine removed. Do not run.
-- SBOM and dependency scanning moving to SecOps SCA module.
-- See engines/supplychain/DEPRECATED.md
-- ============================================================================
-- Supply Chain Engine Rule Seed Data — Task 3.2 [Seq 64 | DE]
-- 8 rules: 2 Malicious, 3 Provenance, 1 Dep Confusion, 2 License
-- CVE rules removed — CVE scanning centralized in Vulnerability Engine
-- Uses ON CONFLICT to allow re-running safely
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Vulnerability Rules — REMOVED
-- SC-CVE-001 and SC-CVE-002 have been centralized in the Vulnerability Engine.
-- To deactivate any existing CVE rules in the DB:
UPDATE supplychain_rules SET is_active = FALSE WHERE rule_id IN ('SC-CVE-001', 'SC-CVE-002');

-- ---------------------------------------------------------------------------
-- Malicious Package Rules — SC-MAL-001 to SC-MAL-002
-- ---------------------------------------------------------------------------

INSERT INTO supplychain_rules (
    rule_id, title, description, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, csp, is_active
) VALUES (
    'SC-MAL-001',
    'Known malicious package detected',
    'A dependency has been identified as malicious in threat intelligence feeds (e.g., npm malware advisories, PyPI safety DB). It may contain backdoors, data exfiltration, or cryptominers.',
    'malicious', 'critical',
    'field_check',
    '{"field": "is_malicious", "operator": "eq", "value": true}'::jsonb,
    '["package_name", "package_version", "purl", "malicious_indicators"]'::jsonb,
    '["PCI-DSS", "SOC2", "NIST_800-53"]'::jsonb,
    'Immediately remove the malicious package and audit all systems where it was installed. Check for indicators of compromise.',
    ARRAY['all'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title, condition = EXCLUDED.condition, updated_at = NOW();

INSERT INTO supplychain_rules (
    rule_id, title, description, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, csp, is_active
) VALUES (
    'SC-MAL-002',
    'Package name typosquatting pattern detected',
    'The package name closely resembles a popular package (e.g., "reqeusts" vs "requests"), which is a common supply chain attack vector.',
    'malicious', 'high',
    'field_check',
    '{"field": "is_typosquat_suspect", "operator": "eq", "value": true}'::jsonb,
    '["package_name", "package_version", "purl"]'::jsonb,
    '["PCI-DSS", "SOC2"]'::jsonb,
    'Verify the package name is correct and not a typosquatting variant. Replace with the legitimate package if misidentified.',
    ARRAY['all'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title, condition = EXCLUDED.condition, updated_at = NOW();

-- ---------------------------------------------------------------------------
-- Provenance Rules — SC-PROV-001 to SC-PROV-003
-- ---------------------------------------------------------------------------

INSERT INTO supplychain_rules (
    rule_id, title, description, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, csp, is_active
) VALUES (
    'SC-PROV-001',
    'Dependency pinned to inexact version',
    'A dependency uses a version range (e.g., ^1.0, ~2.3, >=1.0) instead of an exact pinned version. This can lead to unexpected behavior when transitive dependencies update.',
    'provenance', 'medium',
    'field_check',
    '{"field": "is_pinned", "operator": "eq", "value": false}'::jsonb,
    '["package_name", "package_version", "purl"]'::jsonb,
    '["SOC2", "ISO27001"]'::jsonb,
    'Pin all dependencies to exact versions in lock files (package-lock.json, requirements.txt with ==, go.sum).',
    ARRAY['all'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title, condition = EXCLUDED.condition, updated_at = NOW();

INSERT INTO supplychain_rules (
    rule_id, title, description, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, csp, is_active
) VALUES (
    'SC-PROV-002',
    'Abandoned package (>2 years without update)',
    'A dependency has not been updated in over 2 years (730 days), indicating it may be abandoned and no longer receiving security patches.',
    'provenance', 'medium',
    'field_check',
    '{"field": "days_since_update", "operator": "gt", "value": 730}'::jsonb,
    '["package_name", "package_version", "last_published_at", "days_since_update"]'::jsonb,
    '["SOC2", "ISO27001"]'::jsonb,
    'Evaluate whether the package is still maintained. Consider replacing with an actively maintained alternative.',
    ARRAY['all'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title, condition = EXCLUDED.condition, updated_at = NOW();

INSERT INTO supplychain_rules (
    rule_id, title, description, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, csp, is_active
) VALUES (
    'SC-PROV-003',
    'Package not signed (no provenance attestation)',
    'The package lacks a cryptographic signature or provenance attestation, making it impossible to verify its integrity and origin.',
    'provenance', 'low',
    'field_check',
    '{"field": "is_signed", "operator": "eq", "value": false}'::jsonb,
    '["package_name", "package_version", "purl"]'::jsonb,
    '["NIST_800-53", "ISO27001"]'::jsonb,
    'Prefer packages with provenance attestations (e.g., npm provenance, sigstore). Consider self-hosting packages that lack signatures.',
    ARRAY['all'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title, condition = EXCLUDED.condition, updated_at = NOW();

-- ---------------------------------------------------------------------------
-- Dependency Confusion — SC-CONF-001
-- ---------------------------------------------------------------------------

INSERT INTO supplychain_rules (
    rule_id, title, description, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, csp, is_active
) VALUES (
    'SC-CONF-001',
    'Internal package name exists on public registry',
    'An internal/private package name also exists on a public registry (npm, PyPI). An attacker could publish a higher-version malicious package to the public registry, causing dependency confusion.',
    'dep_confusion', 'high',
    'field_check',
    '{"field": "public_registry_exists", "operator": "eq", "value": true}'::jsonb,
    '["package_name", "package_version", "source_type", "source_id"]'::jsonb,
    '["NIST_800-53", "SOC2"]'::jsonb,
    'Register the internal package name on the public registry as a placeholder, or configure package managers to use scoped registries that prevent public fallback.',
    ARRAY['all'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title, condition = EXCLUDED.condition, updated_at = NOW();

-- ---------------------------------------------------------------------------
-- License Rules — SC-LIC-001 to SC-LIC-002
-- ---------------------------------------------------------------------------

INSERT INTO supplychain_rules (
    rule_id, title, description, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, csp, is_active
) VALUES (
    'SC-LIC-001',
    'Copyleft license (GPL) in commercial product',
    'A dependency uses a copyleft license (GPL, AGPL, LGPL) which may require the entire product to be open-sourced under the same license terms.',
    'license', 'high',
    'field_check',
    '{"field": "license_category", "operator": "eq", "value": "copyleft"}'::jsonb,
    '["package_name", "package_version", "license", "license_category"]'::jsonb,
    '["ISO27001"]'::jsonb,
    'Review license compatibility. Replace with a permissively licensed alternative (MIT, Apache-2.0, BSD) or consult legal counsel.',
    ARRAY['all'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title, condition = EXCLUDED.condition, updated_at = NOW();

INSERT INTO supplychain_rules (
    rule_id, title, description, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, csp, is_active
) VALUES (
    'SC-LIC-002',
    'Unknown or unrecognized license',
    'A dependency has a license that cannot be identified or categorized. This may pose legal risks as the usage terms are unclear.',
    'license', 'medium',
    'field_check',
    '{"field": "license_category", "operator": "eq", "value": "unknown"}'::jsonb,
    '["package_name", "package_version", "license"]'::jsonb,
    '["ISO27001"]'::jsonb,
    'Investigate the license of the package. Contact the maintainer for clarification or replace with a package with a known license.',
    ARRAY['all'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title, condition = EXCLUDED.condition, updated_at = NOW();
