-- Migration: Compliance Analysis Views
-- Purpose: Create views for compliance analysis by service, resource, and framework
-- These views JOIN compliance_control_mappings with check_results

-- Note: These views query across databases (compliance + check)
-- For split-DB setup, create these views after setting up foreign data wrapper or dblink
-- For now, documented for manual execution in check DB

-- ============================================================================
-- VIEW 1: Resource Compliance Status
-- Shows for each resource: which compliance frameworks apply and pass/fail status
-- ============================================================================
COMMENT ON TABLE compliance_control_mappings IS 
'Use this view in Check DB (threat_engine_check) to see resource compliance:

CREATE OR REPLACE VIEW resource_compliance_status AS
SELECT 
    cr.resource_uid,
    cr.resource_type,
    cr.hierarchy_id as account_id,
    cr.scan_id,
    ccm.compliance_framework,
    ccm.requirement_id,
    ccm.requirement_name,
    ccm.service as compliance_service,
    COUNT(*) as total_checks,
    COUNT(*) FILTER (WHERE cr.status = ''PASS'') as passed_checks,
    COUNT(*) FILTER (WHERE cr.status = ''FAIL'') as failed_checks,
    ROUND(
        (COUNT(*) FILTER (WHERE cr.status = ''PASS'')::DECIMAL / NULLIF(COUNT(*), 0) * 100), 
        2
    ) as compliance_score
FROM check_results cr
JOIN compliance_control_mappings ccm ON cr.rule_id = ANY(ccm.rule_ids)
WHERE cr.scan_id = ''check_20260129_162625''
GROUP BY 
    cr.resource_uid, cr.resource_type, cr.hierarchy_id, cr.scan_id,
    ccm.compliance_framework, ccm.requirement_id, ccm.requirement_name, ccm.service
ORDER BY cr.resource_uid, ccm.compliance_framework;
';

-- ============================================================================
-- VIEW 2: Service Compliance Summary  
-- Shows compliance status grouped by service
-- ============================================================================
COMMENT ON COLUMN compliance_control_mappings.service IS 
'Use this view in Check DB to see service-level compliance:

CREATE OR REPLACE VIEW service_compliance_summary AS
SELECT 
    ccm.compliance_framework,
    ccm.service,
    COUNT(DISTINCT ccm.requirement_id) as total_controls,
    COUNT(DISTINCT cr.resource_uid) as resources_evaluated,
    COUNT(*) as total_check_results,
    COUNT(*) FILTER (WHERE cr.status = ''PASS'') as passed,
    COUNT(*) FILTER (WHERE cr.status = ''FAIL'') as failed,
    ROUND(
        (COUNT(*) FILTER (WHERE cr.status = ''PASS'')::DECIMAL / NULLIF(COUNT(*), 0) * 100), 
        2
    ) as compliance_score
FROM compliance_control_mappings ccm
CROSS JOIN LATERAL unnest(ccm.rule_ids) AS rule_id
LEFT JOIN check_results cr ON cr.rule_id = rule_id AND cr.scan_id = ''check_20260129_162625''
WHERE ccm.service IS NOT NULL
GROUP BY ccm.compliance_framework, ccm.service
ORDER BY ccm.compliance_framework, compliance_score;
';

-- ============================================================================
-- VIEW 3: Framework Control Status
-- Shows for each framework control: how many resources passed/failed
-- ============================================================================
CREATE OR REPLACE VIEW framework_control_status AS
SELECT 
    ccm.compliance_framework,
    ccm.requirement_id,
    ccm.requirement_name,
    ccm.service,
    array_length(ccm.rule_ids, 1) as mapped_rules_count,
    ccm.rule_ids as mapped_rule_ids
FROM compliance_control_mappings ccm
ORDER BY ccm.compliance_framework, ccm.requirement_id;

COMMENT ON VIEW framework_control_status IS
'Shows framework controls with their mapped rule IDs.
JOIN with check_results to get actual pass/fail status:

SELECT 
    fcs.*,
    COUNT(cr.*) as total_checks,
    COUNT(cr.*) FILTER (WHERE cr.status = ''PASS'') as passed,
    COUNT(cr.*) FILTER (WHERE cr.status = ''FAIL'') as failed
FROM framework_control_status fcs
CROSS JOIN LATERAL unnest(fcs.mapped_rule_ids) AS rule_id
LEFT JOIN check_results cr ON cr.rule_id = rule_id AND cr.scan_id = ''check_123''
GROUP BY fcs.compliance_framework, fcs.requirement_id, fcs.requirement_name, 
         fcs.service, fcs.mapped_rules_count, fcs.mapped_rule_ids;
';

-- ============================================================================
-- VIEW 4: Top Failing Compliance Areas
-- Shows which services/frameworks have most compliance failures
-- ============================================================================
CREATE OR REPLACE VIEW top_failing_compliance_areas AS
SELECT 
    ccm.compliance_framework,
    ccm.service,
    COUNT(DISTINCT ccm.requirement_id) as total_controls,
    COUNT(DISTINCT ccm.unique_compliance_id) as total_mappings
FROM compliance_control_mappings ccm
WHERE ccm.service IS NOT NULL AND ccm.service != ''
GROUP BY ccm.compliance_framework, ccm.service
ORDER BY total_controls DESC;

-- ============================================================================
-- VIEW 5: Multi-Cloud Framework Summary
-- Shows frameworks and their technology coverage
-- ============================================================================
CREATE OR REPLACE VIEW multi_cloud_framework_summary AS
SELECT 
    compliance_framework,
    technology,
    framework_version,
    COUNT(*) as total_controls,
    COUNT(*) FILTER (WHERE automation_type = 'automated') as automated_controls,
    COUNT(DISTINCT service) as services_covered
FROM compliance_control_mappings
GROUP BY compliance_framework, technology, framework_version
ORDER BY total_controls DESC;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================

SELECT 'Compliance views created. Total control mappings: ' || COUNT(*)::text 
FROM compliance_control_mappings;
