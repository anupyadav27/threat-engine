# Update All Engines for Database-First Architecture

## Strategy

All engines must:
1. **Connect to PostgreSQL databases** (not files/S3)
2. **Write scan results directly to DB** during scans
3. **Read from DB** for downstream processing (Compliance reads from ConfigScan DB, Threat reads from ConfigScan DB, etc.)

## Database Connections by Engine

### ConfigScan Engines (AWS, Azure, GCP, Alicloud, OCI, IBM)
**Database:** threat_engine_configscan  
**Writes:** scans, discoveries, check_results  
**Needs env:**
- `DATABASE_URL=postgresql://postgres:password@host:5432/threat_engine_configscan`
- `CONFIGSCAN_DB_HOST`, `CONFIGSCAN_DB_NAME`, `CONFIGSCAN_DB_USER`, `CONFIGSCAN_DB_PASSWORD` (already set via envFrom)

### Compliance Engine
**Database:** threat_engine_compliance (writes) + threat_engine_configscan (reads check_results)  
**Writes:** report_index, finding_index, compliance_scans  
**Reads:** check_results from configscan DB  
**Needs env:**
- `DATABASE_URL` for compliance DB
- `CONFIGSCAN_DB_*` to read check_results

### Threat Engine
**Database:** threat_engine_threat (writes) + threat_engine_configscan (reads check_results, discoveries)  
**Writes:** threat_scans, threat_detections, threat_analysis  
**Reads:** check_results, discoveries from configscan DB  
**Needs env:**
- `DATABASE_URL` for threat DB
- `CONFIGSCAN_DB_*` to read check data

### Inventory Engine  
**Database:** threat_engine_inventory (writes) + threat_engine_configscan (reads discoveries)  
**Writes:** inventory_run_index, asset_index_latest, relationship_index_latest  
**Reads:** discoveries from configscan DB  
**Needs env:**
- `DATABASE_URL` for inventory DB
- `CONFIGSCAN_DB_*` to read discoveries

## Implementation

All engines already have `envFrom` that loads DB config. Now adding `DATABASE_URL` to each:

```yaml
env:
  - name: DATABASE_URL
    value: "postgresql://postgres:PASSWORD@HOST:5432/DB_NAME"
```

This ensures engines know to write to DB, not just files.
