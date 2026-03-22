-- Database: threat_engine_check

-- Findings by status and severity
SELECT status, severity, COUNT(*) c
FROM check_findings WHERE check_scan_id = $1
GROUP BY status, severity ORDER BY status, c DESC;

-- Failed checks by service
SELECT service, COUNT(*) c
FROM check_findings WHERE check_scan_id = $1 AND status = 'FAIL'
GROUP BY service ORDER BY c DESC;

-- Rule metadata stats
SELECT COUNT(*) total_rules, COUNT(DISTINCT service) services FROM rule_metadata;
