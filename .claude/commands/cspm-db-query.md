# /cspm-db-query

Run a SQL query against a CSPM engine database via kubectl exec.

## Usage
```
/cspm-db-query <db-name> "<sql>"
```

Example:
```
/cspm-db-query threat_engine_check "SELECT COUNT(*) FROM check_findings WHERE scan_run_id='abc123'"
/cspm-db-query threat_engine_threat "SELECT severity, COUNT(*) FROM threat_findings WHERE tenant_id='xyz' GROUP BY severity"
```

## Database reference

| DB Name | Engine | Host |
|---------|--------|------|
| `threat_engine_onboarding` | onboarding | postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com |
| `threat_engine_discoveries` | discoveries | same |
| `threat_engine_inventory` | inventory | same |
| `threat_engine_check` | check | same |
| `threat_engine_threat` | threat | same |
| `threat_engine_compliance` | compliance | same |
| `threat_engine_iam` | iam | same |
| `threat_engine_datasec` | datasec | same |
| `threat_engine_network` | network | same |
| `threat_engine_risk` | risk | same |
| `threat_engine_ciem` | ciem | same |
| `threat_engine_billing` | billing | same |
| `vulnerability_db` | vulnerability, secops-sca | same |

## Method
RDS is not publicly accessible — run via kubectl exec into a pod that has DB access:
```bash
# Write SQL to temp file, copy to pod, exec psql
kubectl cp /tmp/query.sql threat-engine-engines/<pod>:/tmp/query.sql
kubectl exec -n threat-engine-engines <pod> -- psql -h $DB_HOST -U $DB_USER -d <db-name> -f /tmp/query.sql

# Or inline Python
kubectl exec -n threat-engine-engines deployment/<engine> -- python3 -c "
import psycopg2, os
conn = psycopg2.connect(host=os.environ['DB_HOST'], dbname='<db-name>', user=os.environ['DB_USER'], password=os.environ['DB_PASSWORD'])
cur = conn.cursor()
cur.execute('<sql>')
print(cur.fetchall())
conn.close()
"
```
