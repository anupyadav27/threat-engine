-- Migration: IAM and Data Security Views
-- Purpose: Create filtered views for IAM and DataSec engines using metadata
-- Run in: threat_engine_check database

-- ============================================================================
-- IAM SECURITY VIEWS
-- ============================================================================

-- IAM Security Posture (all IAM-related checks)
CREATE OR REPLACE VIEW iam_security_posture AS
SELECT 
    cr.scan_id,
    cr.tenant_id,
    cr.resource_id,
    cr.resource_type,
    cr.resource_arn,
    cr.hierarchy_id as account_id,
    cr.rule_id,
    cr.status,
    cr.finding_data,
    cr.scan_timestamp as created_at,
    -- Rule metadata
    rm.severity,
    rm.title,
    rm.description,
    rm.remediation,
    rm.threat_category,
    rm.risk_score
FROM check_results cr
JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
WHERE rm.service = 'iam'
ORDER BY cr.scan_id, cr.resource_id, rm.severity;

COMMENT ON VIEW iam_security_posture IS
'IAM Security checks filtered from check_results.
Use for IAM engine UI - shows all IAM-related checks with metadata.';

-- IAM Summary by Resource
CREATE OR REPLACE VIEW iam_resource_summary AS
SELECT 
    cr.scan_id,
    cr.tenant_id,
    cr.resource_id,
    cr.resource_type,
    cr.hierarchy_id as account_id,
    COUNT(*) as total_iam_checks,
    COUNT(*) FILTER (WHERE cr.status = 'PASS') as passed,
    COUNT(*) FILTER (WHERE cr.status = 'FAIL') as failed,
    COUNT(*) FILTER (WHERE cr.status = 'WARN') as warnings,
    ROUND(
        (COUNT(*) FILTER (WHERE cr.status = 'PASS')::DECIMAL / NULLIF(COUNT(*), 0) * 100),
        2
    ) as iam_score,
    COUNT(*) FILTER (WHERE rm.severity = 'critical' AND cr.status = 'FAIL') as critical_failures,
    COUNT(*) FILTER (WHERE rm.severity = 'high' AND cr.status = 'FAIL') as high_failures,
    jsonb_agg(cr.rule_id) FILTER (WHERE cr.status = 'FAIL') as failed_rules
FROM check_results cr
JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
WHERE rm.service = 'iam'
GROUP BY cr.scan_id, cr.tenant_id, cr.resource_id, cr.resource_type, cr.hierarchy_id
ORDER BY failed DESC;

COMMENT ON VIEW iam_resource_summary IS
'IAM security summary per resource. 
Shows: total IAM checks, pass/fail counts, failed rules array.';

-- IAM Threats (from threat engine, filtered)
CREATE OR REPLACE VIEW iam_threats_view AS
SELECT 
    t.*
FROM dblink(
    'host=localhost port=5432 dbname=threat_engine_threat user=threat_user password=threat_password',
    'SELECT threat_id, scan_run_id, tenant_id, severity, category, title, description, 
            misconfig_count, affected_resource_count, primary_rule_id, status, first_seen_at
     FROM threats WHERE category = ''identity'''
) AS t(
    threat_id text, scan_run_id text, tenant_id text, severity text, category text,
    title text, description text, misconfig_count int, affected_resource_count int,
    primary_rule_id text, status text, first_seen_at timestamptz
);

COMMENT ON VIEW iam_threats_view IS
'Identity/IAM threats from threat engine (requires dblink extension).
Alternative: Query threat DB directly with category=identity filter.';

-- ============================================================================
-- DATA SECURITY VIEWS
-- ============================================================================

-- Data Security Posture (all data security-related checks)
CREATE OR REPLACE VIEW data_security_posture AS
SELECT 
    cr.scan_id,
    cr.tenant_id,
    cr.resource_id,
    cr.resource_type,
    cr.resource_arn,
    cr.hierarchy_id as account_id,
    cr.rule_id,
    cr.status,
    cr.finding_data,
    cr.scan_timestamp as created_at,
    -- Rule metadata
    rm.severity,
    rm.title,
    rm.description,
    rm.remediation,
    rm.data_security,
    -- Extract data security details
    rm.data_security->>'priority' as datasec_priority,
    rm.data_security->'modules' as datasec_modules,
    rm.data_security->'categories' as datasec_categories,
    rm.data_security->>'sensitive_data_context' as sensitive_context
FROM check_results cr
JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
WHERE rm.data_security IS NOT NULL
  AND (rm.data_security->>'applicable')::boolean = true
ORDER BY cr.scan_id, 
         CASE rm.data_security->>'priority'
             WHEN 'high' THEN 1
             WHEN 'medium' THEN 2
             WHEN 'low' THEN 3
             ELSE 4
         END,
         cr.resource_id;

COMMENT ON VIEW data_security_posture IS
'Data security checks filtered from check_results.
Use for DataSec engine UI - shows encryption, access control, logging, classification.';

-- Data Security by Module
CREATE OR REPLACE VIEW datasec_by_module AS
SELECT 
    cr.scan_id,
    cr.tenant_id,
    cr.resource_type,
    rm.data_security->'modules' as modules,
    rm.data_security->>'priority' as priority,
    COUNT(*) as total_checks,
    COUNT(*) FILTER (WHERE cr.status = 'PASS') as passed,
    COUNT(*) FILTER (WHERE cr.status = 'FAIL') as failed,
    ROUND(
        (COUNT(*) FILTER (WHERE cr.status = 'PASS')::DECIMAL / NULLIF(COUNT(*), 0) * 100),
        2
    ) as security_score
FROM check_results cr
JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
WHERE (rm.data_security->>'applicable')::boolean = true
GROUP BY cr.scan_id, cr.tenant_id, cr.resource_type, rm.data_security->'modules', rm.data_security->>'priority'
ORDER BY failed DESC;

COMMENT ON VIEW datasec_by_module IS
'Data security grouped by module (encryption, access_governance, activity_monitoring, etc.).
Shows pass/fail per module type.';

-- Data Security Resource Summary
CREATE OR REPLACE VIEW datasec_resource_summary AS
SELECT 
    cr.scan_id,
    cr.tenant_id,
    cr.resource_id,
    cr.resource_type,
    cr.hierarchy_id as account_id,
    COUNT(*) as total_datasec_checks,
    COUNT(*) FILTER (WHERE cr.status = 'PASS') as passed,
    COUNT(*) FILTER (WHERE cr.status = 'FAIL') as failed,
    COUNT(*) FILTER (WHERE rm.data_security->>'priority' = 'high' AND cr.status = 'FAIL') as high_priority_failures,
    jsonb_agg(DISTINCT rm.data_security->'modules') FILTER (WHERE cr.status = 'FAIL') as failing_modules,
    jsonb_agg(cr.rule_id) FILTER (WHERE cr.status = 'FAIL') as failed_rules
FROM check_results cr
JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
WHERE (rm.data_security->>'applicable')::boolean = true
GROUP BY cr.scan_id, cr.tenant_id, cr.resource_id, cr.resource_type, cr.hierarchy_id
ORDER BY high_priority_failures DESC, failed DESC;

COMMENT ON VIEW datasec_resource_summary IS
'Data security summary per resource.
Shows: total data security checks, failed modules, priority failures.';

-- ============================================================================
-- COMBINED IAM + DATA SECURITY SUMMARY
-- ============================================================================

CREATE OR REPLACE VIEW security_posture_summary AS
SELECT 
    scan_id,
    tenant_id,
    COUNT(*) FILTER (WHERE service = 'iam') as iam_total_checks,
    COUNT(*) FILTER (WHERE service = 'iam' AND status = 'FAIL') as iam_failures,
    COUNT(*) FILTER (WHERE data_security IS NOT NULL) as datasec_total_checks,
    COUNT(*) FILTER (WHERE data_security IS NOT NULL AND status = 'FAIL') as datasec_failures,
    ROUND(
        (COUNT(*) FILTER (WHERE service = 'iam' AND status = 'PASS')::DECIMAL / 
         NULLIF(COUNT(*) FILTER (WHERE service = 'iam'), 0) * 100),
        2
    ) as iam_score,
    ROUND(
        (COUNT(*) FILTER (WHERE data_security IS NOT NULL AND status = 'PASS')::DECIMAL / 
         NULLIF(COUNT(*) FILTER (WHERE data_security IS NOT NULL), 0) * 100),
        2
    ) as datasec_score
FROM (
    SELECT cr.scan_id, cr.tenant_id, cr.status, rm.service, rm.data_security
    FROM check_results cr
    JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
) sub
GROUP BY scan_id, tenant_id;

COMMENT ON VIEW security_posture_summary IS
'Overall IAM and Data Security summary per scan.
Shows: total checks, failures, scores for both domains.';

-- ============================================================================
-- VIEWS CREATED
-- ============================================================================
SELECT 'IAM and Data Security views created in check DB' as status;
