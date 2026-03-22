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
