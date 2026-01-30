# Consolidated Database Management

This directory contains centralized database management for all engines and CSPs in the threat-engine platform.

## Directory Structure

```
consolidated_services/database/
├── README.md                    # This file
├── schemas/                     # Database schema definitions
│   ├── configscan_schema.sql   # ConfigScan engine schema (from proven engine_configscan_aws)
│   ├── compliance_schema.sql   # Compliance engine schema
│   ├── inventory_schema.sql    # Inventory engine schema
│   ├── threat_schema.sql       # Threat engine schema
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

## Benefits of Centralized Database Management

1. **Single Source of Truth**: All database schemas in one location
2. **Consistent Connection Management**: Unified connection pooling and configuration
3. **Simplified Credential Management**: Centralized credential storage and rotation
4. **Easy Migration Management**: Single place for all database migrations
5. **Better Testing**: Consistent database setup across all engines
6. **Improved Security**: Centralized security controls and monitoring

## Usage

### For ConfigScan Service:
```python
from consolidated_services.database.connections import get_configscan_connection

async def scan_function():
    async with get_configscan_connection() as conn:
        await conn.execute("SELECT * FROM scans")
```

### For Other Engines:
```python
from consolidated_services.database.connections import get_compliance_connection
from consolidated_services.database.connections import get_inventory_connection
```

## Schema Management

All schemas are based on proven, production-tested schemas from the original engines:
- `configscan_schema.sql` - Based on `engine_configscan_aws/database/schema.sql`
- Other schemas will be consolidated from their respective engines

## Connection Configuration

Database connections are configured through environment variables:
- `CONFIGSCAN_DATABASE_URL` - ConfigScan database connection
- `COMPLIANCE_DATABASE_URL` - Compliance database connection
- `INVENTORY_DATABASE_URL` - Inventory database connection
- `SHARED_DATABASE_URL` - Shared database connection

## Migration Management

Migrations are managed centrally and can be run for all engines:
```bash
python -m consolidated_services.database.migrations.migration_runner --engine configscan
python -m consolidated_services.database.migrations.migration_runner --all
```