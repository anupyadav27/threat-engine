-- Database: threat_engine_inventory

-- Assets by type
SELECT resource_type, COUNT(*) c FROM inventory_findings
WHERE inventory_scan_id = $1 GROUP BY resource_type ORDER BY c DESC;

-- Relationships by type
SELECT relation_type, COUNT(*) c FROM inventory_relationships
WHERE inventory_scan_id = $1 GROUP BY relation_type ORDER BY c DESC;

-- Assets with most relationships
SELECT f.resource_uid, f.resource_type, f.service, COUNT(r.id) as rels
FROM inventory_findings f
LEFT JOIN inventory_relationships r
  ON (r.source_uid = f.resource_uid OR r.target_uid = f.resource_uid)
  AND r.inventory_scan_id = f.inventory_scan_id
WHERE f.inventory_scan_id = $1
GROUP BY 1,2,3 ORDER BY rels DESC LIMIT 20;
