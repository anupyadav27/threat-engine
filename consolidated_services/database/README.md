# Consolidated Database Management

This directory contains centralized database management for all engines and CSPs in the threat-engine platform.

## Directory Structure

```
consolidated_services/database/
├── README.md                    # This file
├── schemas/                     # Database schema definitions
│   ├── discoveries_schema.sql  # Discovery engine (discovery_report, discovery_findings, discovery_history, rule_definitions)
│   ├── check_schema.sql        # Check engine (check_report, check_findings, rule_checks, rule_metadata)
│   ├── inventory_schema.sql    # Inventory engine (inventory_report, inventory_scans, inventory_findings, inventory_relationships, inventory_drift, inventory_asset_*)
│   ├── threat_schema.sql       # Threat engine (threat_report, threat_findings, threat_detections, threat_analysis, mitre_technique_reference, threat_intelligence, threat_hunt_*)
│   ├── compliance_schema.sql   # Compliance engine (compliance_report, compliance_findings, compliance_frameworks, compliance_controls, compliance_assessments, rule_control_mapping, remediation_tracking)
│   ├── iam_schema.sql          # IAM engine (iam_report, iam_findings)
│   ├── datasec_schema.sql      # DataSec engine (datasec_report, datasec_findings)
│   └── shared_schema.sql       # Shared tables across engines
├── connections/                 # Database connection management
│   ├── __init__.py             # Connection factory
│   ├── base_connection.py      # Base connection class
│   ├── postgres_connection.py  # PostgreSQL connection handler
│   └── connection_pool.py      # Connection pooling
├── migrations/                  # Database migrations
│   ├── __init__.py
│   ├── migration_runner.py     # Migration execution
│   └── versions/               # Migration versions
└── config/                     # Database configuration
    ├── __init__.py
    ├── database_config.py      # Configuration management
    └── credentials.py          # Credential management
```

## Naming Convention

All engines follow a consistent `{engine}_*` naming pattern:

| Engine | Report Table | Findings Table | Scan ID Column | Database |
|--------|-------------|----------------|----------------|----------|
| Discovery | `discovery_report` | `discovery_findings` | `discovery_scan_id` | `threat_engine_discoveries` |
| Check | `check_report` | `check_findings` | `check_scan_id` | `threat_engine_check` |
| Inventory | `inventory_report` | `inventory_findings` | `inventory_scan_id` | `threat_engine_inventory` |
| Threat | `threat_report` | `threat_findings` | `threat_scan_id` | `threat_engine_threat` |
| Compliance | `compliance_report` | `compliance_findings` | `compliance_scan_id` | `threat_engine_compliance` |
| IAM | `iam_report` | `iam_findings` | `iam_scan_id` | `threat_engine_iam` |
| DataSec | `datasec_report` | `datasec_findings` | `datasec_scan_id` | `threat_engine_datasec` |

## Pipeline Flow

```
Discovery → Check → Inventory → Threat → Compliance + IAM + DataSec (parallel)
```

Each engine's report table links upstream via `{upstream_engine}_scan_id` columns.

## Usage

### For Discovery Engine:
```python
from consolidated_services.database.config.database_config import get_discovery_config

config = get_discovery_config()
conn = psycopg2.connect(config.connection_string)
cur = conn.cursor()
cur.execute("SELECT * FROM discovery_findings WHERE tenant_id = %s", (tenant_id,))
```

### For Check Engine:
```python
from consolidated_services.database.config.database_config import get_check_config

config = get_check_config()
conn = psycopg2.connect(config.connection_string)
cur = conn.cursor()
cur.execute("SELECT * FROM check_findings WHERE tenant_id = %s", (tenant_id,))
```

### For Any Engine:
```python
from consolidated_services.database.config.database_config import get_database_config

config = get_database_config("discovery")  # or "check", "threat", "inventory", etc.
conn_string = config.connection_string
```

## Connection Configuration

Database connections are configured through environment variables:
- `DISCOVERY_DB_HOST/PORT/NAME/USER/PASSWORD` - Discovery engine database
- `CHECK_DB_HOST/PORT/NAME/USER/PASSWORD` - Check engine database
- `THREAT_DB_HOST/PORT/NAME/USER/PASSWORD` - Threat engine database
- `INVENTORY_DB_HOST/PORT/NAME/USER/PASSWORD` - Inventory engine database
- `COMPLIANCE_DB_HOST/PORT/NAME/USER/PASSWORD` - Compliance engine database
- `IAM_DB_HOST/PORT/NAME/USER/PASSWORD` - IAM engine database
- `DATASEC_DB_HOST/PORT/NAME/USER/PASSWORD` - DataSec engine database
- `SHARED_DB_HOST/PORT/NAME/USER/PASSWORD` - Shared/onboarding database

## Migration Management

Migrations are managed centrally and can be run for all engines:
```bash
python -m consolidated_services.database.migrations.migration_runner --engine discovery
python -m consolidated_services.database.migrations.migration_runner --all
```
