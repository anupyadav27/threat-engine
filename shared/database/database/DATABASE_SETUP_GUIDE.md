# Threat Engine Database Setup Guide

This guide covers setting up the **single PostgreSQL database** used by all Threat Engine components.

## Overview

Threat Engine uses **one PostgreSQL database** with **engine-specific schemas**:

- **engine_shared**: Tenants, customers, cross-engine data
- **engine_configscan**: Scans, discoveries, check_results, csp_hierarchies
- **engine_compliance**: report_index, finding_index
- **engine_inventory**: inventory_run_index, asset_index_latest, relationship_index_latest
- **engine_threat**: threat_reports
- **engine_onboarding**, **engine_userportal**, **engine_adminportal**, **engine_secops**: Additional engine schemas

## Quick Setup

### Prerequisites

1. **PostgreSQL 12+** installed and running
2. **psql** command-line client

### Run Setup

```bash
# Ensure PostgreSQL is running (e.g. brew services start postgresql)

# Apply schema (default DB: postgres; use -d <db> if different)
psql -U postgres -d postgres -f scripts/init-databases.sql

# Or with your OS user (e.g. macOS Homebrew)
psql -U $(whoami) -d postgres -f scripts/init-databases.sql
```

### Verify

```bash
psql -U postgres -d postgres -c "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'engine_%' ORDER BY 1;"
```

You should see `engine_adminportal`, `engine_compliance`, `engine_configscan`, `engine_inventory`, `engine_onboarding`, `engine_secops`, `engine_shared`, `engine_threat`, `engine_userportal`.

## Database Schemas (Single DB)

### engine_shared

- `customers`, `tenants` — Multi-tenant structure (canonical)

### engine_configscan

- `scans`, `csp_hierarchies`, `discoveries`, `discovery_history`, `check_results`

### engine_compliance

- `report_index`, `finding_index`

### engine_inventory

- `inventory_run_index`, `asset_index_latest`, `relationship_index_latest`

### engine_threat

- `threat_reports`

## Connection

- **Host:** `localhost` (or your DB host)
- **Port:** `5432`
- **Database:** `postgres` (or the DB you ran `init-databases.sql` against)
- **User / Password:** Your PostgreSQL user (e.g. `postgres` or your OS user; set via your PG setup)

Applications use `search_path` or schema-qualified names (e.g. `engine_configscan.scans`) when connecting to this single database.

## Docker (Alternative)

Use a Postgres image and mount `init-databases.sql` as init script:

```yaml
services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: postgres
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-databases.sql:/docker-entrypoint-initdb.d/01-init.sql:ro
```

Then connect to `postgresql://postgres:postgres@localhost:5432/postgres`.

## Troubleshooting

**Connection refused**

- Ensure PostgreSQL is running: `brew services list | grep postgresql` or `pg_isready -h localhost -p 5432`

**Permission denied**

- Use a user that can create schemas/tables in the target DB: `psql -U postgres -c "\du"`

**Schema / table errors**

- Re-run `init-databases.sql` (it uses `CREATE IF NOT EXISTS`). For a clean slate, drop and recreate the database, then run the script again.

## Development Workflow

1. Start PostgreSQL locally.
2. Run `psql -U postgres -d postgres -f scripts/init-databases.sql`.
3. Configure apps to use the single DB (and engine_* schemas where relevant).
4. Use `psql` or a GUI (e.g. DBeaver) to inspect `engine_*` schemas and tables.
