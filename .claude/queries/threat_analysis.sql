-- Database: threat_engine_threat

-- Threat summary by severity
SELECT severity, COUNT(*) c, AVG(risk_score) avg_risk
FROM threat_findings WHERE threat_scan_id = $1
GROUP BY severity ORDER BY c DESC;

-- MITRE technique distribution
SELECT mitre_technique, mitre_tactic, COUNT(*) c, AVG(risk_score) avg_risk
FROM threat_findings WHERE threat_scan_id = $1
GROUP BY 1,2 ORDER BY c DESC LIMIT 20;

-- Risk score distribution
SELECT CASE WHEN risk_score < 25 THEN 'low (0-24)'
            WHEN risk_score < 50 THEN 'medium (25-49)'
            WHEN risk_score < 75 THEN 'high (50-74)'
            ELSE 'critical (75-100)' END AS risk_band, COUNT(*) c
FROM threat_findings WHERE threat_scan_id = $1 GROUP BY 1 ORDER BY 1;

-- Detections with resource counts
SELECT detection_id, technique_id, tactic, severity,
       jsonb_array_length(affected_resources) as resources
FROM threat_detections WHERE scan_run_id = $1
ORDER BY severity DESC LIMIT 20;
