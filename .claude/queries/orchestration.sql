-- Database: threat_engine_onboarding

-- Get orchestration status (all engine scan IDs)
SELECT orchestration_id, overall_status, started_at, completed_at,
       discovery_scan_id, inventory_scan_id, check_scan_id,
       threat_scan_id, compliance_scan_id, iam_scan_id, datasec_scan_id,
       engines_completed
FROM scan_orchestration
WHERE orchestration_id = $1;

-- Latest orchestrations for tenant
SELECT orchestration_id, overall_status, started_at, completed_at
FROM scan_orchestration
WHERE tenant_id = $1
ORDER BY started_at DESC LIMIT 5;

-- Running scans
SELECT orchestration_id, tenant_id, overall_status, started_at, engines_completed
FROM scan_orchestration
WHERE overall_status = 'running';
