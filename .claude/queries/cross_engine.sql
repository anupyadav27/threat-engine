-- Cross-engine scan summary
-- Run each query against its respective database

-- threat_engine_discoveries:
SELECT COUNT(*) as discovery_findings FROM discovery_findings WHERE discovery_scan_id = $1;

-- threat_engine_check:
SELECT COUNT(*) as check_total, COUNT(*) FILTER (WHERE status='FAIL') as failures
FROM check_findings WHERE check_scan_id = $1;

-- threat_engine_inventory:
SELECT COUNT(*) as assets FROM inventory_findings WHERE inventory_scan_id = $1;
SELECT COUNT(*) as relationships FROM inventory_relationships WHERE inventory_scan_id = $1;

-- threat_engine_threat:
SELECT COUNT(*) as threats FROM threat_findings WHERE threat_scan_id = $1;
SELECT COUNT(*) as detections FROM threat_detections WHERE scan_run_id = $1;

-- threat_engine_compliance:
SELECT report_data->'posture_summary' as posture FROM compliance_report WHERE compliance_scan_id = $1;

-- threat_engine_iam:
SELECT COUNT(*) as iam_findings FROM iam_findings WHERE iam_scan_id = $1;

-- threat_engine_datasec:
SELECT COUNT(*) as datasec_findings FROM datasec_findings WHERE datasec_scan_id = $1;
