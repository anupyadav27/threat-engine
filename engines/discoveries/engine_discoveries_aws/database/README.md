# CSPM Database Structure

## Overview
PostgreSQL database for multi-tenant CSPM SaaS platform supporting:
- Customer → Tenant (per CSP) → Hierarchy (Account/Project/etc.) → Resources
- Discovery storage with drift detection
- Check results storage
- Historical tracking

## Setup

### 1. Create Database
```bash
createdb cspm_db
```

### 2. Run Schema
```bash
psql -d cspm_db -f schema.sql
```

### 3. Configure Connection
Set environment variables:
```bash
export CSPM_DB_HOST=localhost
export CSPM_DB_PORT=5432
export CSPM_DB_NAME=cspm_db
export CSPM_DB_USER=postgres
export CSPM_DB_PASSWORD=your_password
```

Or create `secrets/db_config.json`:
```json
{
  "host": "localhost",
  "port": 5432,
  "database": "cspm_db",
  "user": "postgres",
  "password": "your_password"
}
```

## Schema Structure

### Core Tables
- `customers` - Top-level customer records
- `tenants` - Per-CSP tenant records
- `csp_hierarchies` - Account/Project/Subscription/etc.
- `scans` - Scan execution records

### Discovery Tables
- `discoveries` - Current discovery results
- `discovery_history` - Historical discovery data for drift detection

### Check Tables
- `checks` - Check metadata (default + custom)
- `check_results` - Check execution results

### Drift Detection
- `drift_detections` - Configuration drift alerts

## Usage

See `engine/database_manager.py` for Python API.

