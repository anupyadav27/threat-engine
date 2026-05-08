-- Database: threat_engine_discoveries

-- Top services by finding count
SELECT service, resource_type, COUNT(*) c
FROM discovery_findings
WHERE discovery_scan_id = $1
GROUP BY service, resource_type
ORDER BY c DESC LIMIT 30;

-- Total findings per scan
SELECT COUNT(*) total, COUNT(DISTINCT service) services, COUNT(DISTINCT region) regions
FROM discovery_findings WHERE discovery_scan_id = $1;

-- Sample resource_uid for a service
SELECT resource_uid, resource_type, region
FROM discovery_findings
WHERE discovery_scan_id = $1 AND service = $2 LIMIT 5;

-- Active vs inactive discoveries (RUN AGAINST threat_engine_check!)
SELECT provider, COUNT(*) total,
       COUNT(*) FILTER (WHERE is_active = true) active,
       COUNT(*) FILTER (WHERE is_active = false) inactive
FROM rule_discoveries GROUP BY provider;

-- Cross-engine: find discovery_scan_id from scan_run_id
SELECT DISTINCT discovery_scan_id, scan_run_id, COUNT(*) findings
FROM discovery_findings
WHERE scan_run_id = $1
GROUP BY discovery_scan_id, scan_run_id;

-- Multi-CSP scan summary by provider
SELECT provider, COUNT(*) total, COUNT(DISTINCT service) services,
       COUNT(DISTINCT region) regions, COUNT(DISTINCT account_id) accounts
FROM discovery_findings
WHERE scan_run_id = $1
GROUP BY provider ORDER BY total DESC;

-- Top resources with no check coverage (potential rule gaps)
SELECT df.service, df.resource_type, COUNT(*) resources
FROM discovery_findings df
LEFT JOIN check_findings cf ON cf.resource_uid = df.resource_uid
  AND cf.scan_run_id = df.scan_run_id
WHERE df.scan_run_id = $1 AND cf.resource_uid IS NULL
GROUP BY df.service, df.resource_type ORDER BY resources DESC LIMIT 20;
-- NOTE: above JOIN runs cross-DB — use only with MCP server or kubectl exec
