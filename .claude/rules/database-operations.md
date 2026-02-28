---
paths:
  - "consolidated_services/database/**/*.py"
  - "engine_*/database/**/*.py"
  - "engine_*/**/database*.py"
---

# Database Operation Standards

## Query Safety (CRITICAL)

### Parameterized Queries Only
**NEVER** use string concatenation or f-strings for SQL queries.

❌ **WRONG:**
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
query = "SELECT * FROM users WHERE name = '" + username + "'"
```

✅ **CORRECT:**
```python
# psycopg2
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SQLAlchemy
query = select(User).where(User.id == user_id)
result = session.execute(query)
```

### Connection Management
- **Use connection pooling**: Reuse database connections
- **Set timeouts**: Configure query and connection timeouts
- **Handle disconnects**: Implement retry logic with exponential backoff
- **Close resources**: Always use context managers or try/finally

Example:
```python
from contextlib import contextmanager
from psycopg2.pool import ThreadedConnectionPool

pool = ThreadedConnectionPool(
    minconn=5,
    maxconn=20,
    host=DB_HOST,
    database=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD,
    connect_timeout=10
)

@contextmanager
def get_db_connection():
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)

# Usage
with get_db_connection() as conn:
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM table WHERE id = %s", (id,))
        result = cursor.fetchall()
```

## Schema Standards

### Table Naming
- **Lowercase with underscores**: `discovery_findings`, `check_report`
- **Plural for data tables**: `discoveries`, `findings`, `reports`
- **Singular for reference tables**: `rule_metadata`, `framework_definition`
- **Prefix for related tables**: `threat_findings`, `threat_detections`

### Column Naming
- **Lowercase with underscores**: `resource_uid`, `created_at`
- **UUID primary keys**: Use `<entity>_id` format (e.g., `discovery_scan_id`)
- **Timestamps**: `created_at`, `updated_at`, `deleted_at` (use `_at` suffix)
- **Boolean flags**: Use `is_` or `has_` prefix (e.g., `is_active`, `has_findings`)
- **Foreign keys**: Match referenced column name (e.g., `tenant_id` references `tenants.tenant_id`)

### Data Types
- **IDs**: UUID (`uuid` type in PostgreSQL)
- **Timestamps**: `TIMESTAMP WITH TIME ZONE` (always use timezone-aware)
- **JSON data**: `JSONB` (indexed, queryable)
- **Arrays**: Use PostgreSQL array types when appropriate
- **Enums**: Define as PostgreSQL ENUMs or use CHECK constraints

Example schema:
```sql
CREATE TABLE discovery_findings (
    finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    discovery_scan_id UUID NOT NULL REFERENCES discovery_report(discovery_scan_id),
    tenant_id UUID NOT NULL,
    resource_uid VARCHAR(512) NOT NULL,
    resource_type VARCHAR(128) NOT NULL,
    emitted_fields JSONB,
    raw_response JSONB,
    config_hash VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_discovery_findings_scan_id ON discovery_findings(discovery_scan_id);
CREATE INDEX idx_discovery_findings_tenant ON discovery_findings(tenant_id);
CREATE INDEX idx_discovery_findings_resource_uid ON discovery_findings(resource_uid);
CREATE INDEX idx_discovery_findings_emitted_fields ON discovery_findings USING GIN(emitted_fields);
```

## Indexing Strategy

### When to Add Indexes
- **Foreign keys**: Always index foreign key columns
- **WHERE clauses**: Columns frequently used in WHERE conditions
- **JOIN conditions**: Columns used in JOIN operations
- **ORDER BY**: Columns used for sorting
- **Unique constraints**: Columns that must be unique

### Index Types
- **B-tree** (default): General purpose, equality and range queries
- **GIN**: JSONB columns, array containment
- **GIST**: Geometric data, full-text search
- **Hash**: Equality only (rarely used)

Example:
```sql
-- B-tree for foreign keys and filters
CREATE INDEX idx_check_findings_rule_id ON check_findings(rule_id);

-- GIN for JSONB searches
CREATE INDEX idx_check_findings_data ON check_findings USING GIN(finding_data);

-- Composite index for common query patterns
CREATE INDEX idx_findings_tenant_scan ON check_findings(tenant_id, check_scan_id);
```

## Migration Standards

### Migration Files
- **Naming**: `YYYYMMDD_HHMM_description.sql` (e.g., `20250220_1400_add_threat_intelligence_table.sql`)
- **Atomic changes**: One logical change per migration
- **Reversible**: Include both UP and DOWN migrations
- **Tested**: Test both forward and rollback migrations

Example migration:
```sql
-- UP Migration
BEGIN;

CREATE TABLE threat_intelligence (
    intel_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(255) NOT NULL,
    threat_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_threat_intelligence_source ON threat_intelligence(source);

COMMIT;

-- DOWN Migration
BEGIN;

DROP INDEX IF EXISTS idx_threat_intelligence_source;
DROP TABLE IF EXISTS threat_intelligence;

COMMIT;
```

### Migration Execution
```bash
# Dry-run (test without applying)
python migrate.py --dry-run

# Apply migrations
python migrate.py --apply

# Rollback last migration
python migrate.py --rollback
```

## Transaction Management

### ACID Principles
- **Atomic**: All operations succeed or all fail
- **Consistent**: Database remains in valid state
- **Isolated**: Transactions don't interfere
- **Durable**: Committed changes persist

### Transaction Patterns
```python
# Explicit transaction with rollback
from psycopg2 import connect

conn = connect(DB_URL)
try:
    cursor = conn.cursor()

    # Multiple operations in single transaction
    cursor.execute("INSERT INTO scan_orchestration (...) VALUES (%s, %s)", (val1, val2))
    cursor.execute("UPDATE schedules SET last_run = %s WHERE id = %s", (now, schedule_id))

    conn.commit()
except Exception as e:
    conn.rollback()
    raise
finally:
    conn.close()
```

## Performance Best Practices

### Query Optimization
- **SELECT specific columns**: Avoid `SELECT *`
- **LIMIT results**: Use pagination for large result sets
- **Use EXPLAIN**: Analyze query plans with `EXPLAIN ANALYZE`
- **Batch operations**: Use bulk inserts instead of individual INSERTs
- **Avoid N+1 queries**: Use JOINs or batch fetching

Example bulk insert:
```python
# Efficient bulk insert
values = [(uid1, type1), (uid2, type2), (uid3, type3)]
cursor.executemany(
    "INSERT INTO discoveries (resource_uid, resource_type) VALUES (%s, %s)",
    values
)
```

### Database Monitoring
- **Log slow queries**: Set `log_min_duration_statement` in PostgreSQL
- **Monitor connection pool**: Track active/idle connections
- **Track query patterns**: Identify frequently run queries
- **Alert on errors**: Monitor connection failures, timeouts

## Security Requirements

### Access Control
- **Least privilege**: Grant minimum required permissions
- **Separate users**: Different users for read/write/admin operations
- **Rotate credentials**: Regular password rotation via Secrets Manager
- **Audit logs**: Enable PostgreSQL audit logging

### Data Protection
- **Encryption at rest**: RDS encryption enabled
- **Encryption in transit**: Force SSL/TLS connections only
- **Sensitive data masking**: Hash or encrypt PII/PHI in database
- **Backup encryption**: Ensure backups are encrypted

## Important Notes
- Never commit database passwords or connection strings
- Use environment variables or AWS Secrets Manager for credentials
- Test migrations on staging database before production
- Monitor query performance and optimize slow queries
- Keep database schemas version controlled in Git
