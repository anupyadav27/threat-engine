# Database Module - DynamoDB

## Overview

This module uses **AWS DynamoDB** for all data storage. PostgreSQL is no longer used.

## Files

- `dynamodb_tables.py` - Table definitions and creation functions
- `dynamodb_operations.py` - CRUD operations for all entities

## Legacy Files (Removed)

The following files have been removed as they are no longer needed:
- ~~`models.py`~~ - Old SQLAlchemy models (PostgreSQL) - **REMOVED**
- ~~`connection.py`~~ - Old PostgreSQL connection - **REMOVED**
- ~~`schema.sql`~~ - Old PostgreSQL schema - **REMOVED**
- ~~`migrations/`~~ - Old PostgreSQL migrations - **REMOVED**

## Usage

```python
from onboarding.database.dynamodb_operations import (
    create_tenant, get_tenant, create_account, get_account
)

# Create tenant
tenant = create_tenant("acme-corp", "Acme Corporation")

# Create account
account = create_account(
    provider_id=provider_id,
    tenant_id=tenant_id,
    account_name="Production Account"
)
```

## Setup

See `AWS_SERVICES_SETUP.md` for DynamoDB table creation.

## Tables

- `threat-engine-tenants` - Tenant information
- `threat-engine-providers` - Cloud provider configurations
- `threat-engine-accounts` - Account details
- `threat-engine-schedules` - Scan schedules
- `threat-engine-executions` - Execution history
- `threat-engine-scan-results` - Scan results

All tables use **PAY_PER_REQUEST** billing mode (on-demand pricing).
