# Local PostgreSQL Database Setup

## Overview

This document describes the local PostgreSQL database setup for all engines in the threat-engine workspace.

## Databases

### 1. Compliance Engine Database
**Database Name**: `compliance_engine`

**Tables**:
- `tenants` - Tenant information
- `report_index` - Compliance reports metadata
- `finding_index` - Individual findings from scans
- `compliance_framework_mappings` - Rule to framework control mappings
- `compliance_scan_results` - Scan results by framework/control
- `compliance_scores` - Aggregated compliance scores
- `compliance_trends` - Historical compliance trends

### 2. Onboarding Engine Database
**Database Name**: `threat_engine`

**Tables**:
- `tenants` - Tenant information
- `providers` - Cloud service providers (AWS, Azure, GCP, etc.)
- `accounts` - Cloud accounts per provider
- `schedules` - Scan schedules
- `executions` - Scan execution history
- `scan_results` - Scan results metadata

## Setup Instructions

### Prerequisites

1. **Install PostgreSQL** (if not already installed):
   ```bash
   brew install postgresql@14
   ```

2. **Start PostgreSQL**:
   ```bash
   brew services start postgresql@14
   ```

3. **Verify PostgreSQL is running**:
   ```bash
   pg_isready -h localhost -p 5432
   ```

### Default Connection Settings

- **Host**: `localhost`
- **Port**: `5432`
- **User**: `postgres`
- **Password**: `postgres`

To use different settings, set environment variables:
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=postgres
export DB_PASSWORD=your_password
```

### Run Setup Script

```bash
./setup-local-databases.sh
```

This script will:
1. ✅ Check PostgreSQL connection
2. ✅ Drop existing databases (clean deployment)
3. ✅ Create new databases
4. ✅ Create all required tables
5. ✅ Create indexes
6. ✅ Verify setup

## Connection Strings

### Compliance Engine
```
postgresql://postgres:postgres@localhost:5432/compliance_engine
```

### Onboarding Engine
```
postgresql://postgres:postgres@localhost:5432/threat_engine
```

## Environment Variables

### Compliance Engine
```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/compliance_engine"
```

### Onboarding Engine
```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/threat_engine"
```

## Testing

### Test Compliance Engine Connection
```bash
psql -h localhost -p 5432 -U postgres -d compliance_engine -c "SELECT COUNT(*) FROM tenants;"
```

### Test Onboarding Engine Connection
```bash
psql -h localhost -p 5432 -U postgres -d threat_engine -c "SELECT COUNT(*) FROM tenants;"
```

### List All Tables
```bash
# Compliance Engine
psql -h localhost -p 5432 -U postgres -d compliance_engine -c "\dt"

# Onboarding Engine
psql -h localhost -p 5432 -U postgres -d threat_engine -c "\dt"
```

## Clean Deployment

The setup script performs a **clean deployment** by:
1. Dropping existing databases (if they exist)
2. Creating fresh databases
3. Creating all tables from scratch

**⚠️ Warning**: This will delete all existing data. Use with caution in production.

## Troubleshooting

### PostgreSQL Not Running
```bash
# Check status
brew services list | grep postgresql

# Start service
brew services start postgresql@14

# Or manually
pg_ctl -D /usr/local/var/postgresql@14 start
```

### Connection Refused
- Check if PostgreSQL is listening on port 5432
- Verify firewall settings
- Check PostgreSQL configuration (`postgresql.conf`)

### Permission Denied
- Ensure user has CREATE DATABASE privileges
- Check `pg_hba.conf` for authentication settings

### Database Already Exists
The script will drop and recreate databases. If you want to keep existing data, modify the script to skip the drop step.

## Next Steps

After database setup:
1. ✅ Test connections from both engines
2. ✅ Run test inserts to verify tables
3. ✅ Configure engines to use local databases
4. ✅ Test full workflow (onboarding → scan → compliance report)

