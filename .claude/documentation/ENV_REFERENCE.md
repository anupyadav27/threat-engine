# Environment Variables Reference

> All configuration variables across the CSPM platform. 139 variables organized by category.

---

## Database Configuration

### General Settings (all engines)

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_USER` | `postgres` | Database user |
| `DB_PASSWORD` | `` | Database password |
| `DB_SSL_MODE` | `prefer` | SSL mode (prefer/require/disable) |
| `DB_POOL_SIZE` | `10` | Connection pool size |
| `DB_MAX_OVERFLOW` | `20` | Max overflow connections |
| `DB_POOL_TIMEOUT` | `30` | Pool timeout (seconds) |
| `DB_POOL_RECYCLE` | `3600` | Connection recycle time (seconds) |
| `DB_SCHEMA` | varies | Schema search path (comma-separated) |
| `DATABASE_URL` | - | Full connection URL (overrides individual settings) |
| `USE_CENTRALIZED_DB` | `true` | Use consolidated database mode |

### Per-Engine Database Variables

Each engine has its own set of DB variables. Pattern: `{ENGINE}_DB_{SETTING}`

| Engine Prefix | Actual RDS DB Name | Default User |
|--------------|-------------------|-------------|
| `CHECK_DB_` | `threat_engine_check` | `postgres` |
| `THREAT_DB_` | `threat` | `postgres` |
| `INVENTORY_DB_` | `threat_engine_inventory` | `postgres` |
| `COMPLIANCE_DB_` | `threat_engine_compliance` | `postgres` |
| `DISCOVERIES_DB_` | `discoveries` | `postgres` |
| `ONBOARDING_DB_` | `threat_engine_onboarding` | `postgres` |
| `DATASEC_DB_` | `threat_engine_datasec` | `postgres` |
| `IAM_DB_` | `threat_engine_iam` | `postgres` |
| `SECOPS_DB_` | `threat_engine_secops` | `postgres` |
| `SHARED_DB_` | `shared` (deprecated) | `postgres` |

Each prefix supports: `_HOST`, `_PORT`, `_NAME`, `_USER`, `_PASSWORD`

---

## Neo4j Graph Database

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `neo4j+s://17ec5cbb.databases.neo4j.io` | Neo4j connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `` | Neo4j password |
| `NEO4J_DATABASE` | `neo4j` | Neo4j database name |
| `NEO4J_MAX_CONNECTION_LIFETIME` | `3600` | Max connection lifetime (seconds) |
| `NEO4J_MAX_CONNECTION_POOL_SIZE` | `50` | Connection pool size |

---

## Service URLs

### Engine Endpoints

| Variable | Default | Used By |
|----------|---------|---------|
| `THREAT_ENGINE_URL` | `http://localhost:8020` | API Gateway, Admin/User portal |
| `COMPLIANCE_ENGINE_URL` | `http://localhost:8010` | API Gateway, Admin/User portal |
| `INVENTORY_ENGINE_URL` | `http://localhost:8022` | API Gateway, Admin/User portal |
| `ONBOARDING_ENGINE_URL` | `http://localhost:8010` | API Gateway, Onboarding |
| `RULE_ENGINE_URL` | `http://localhost:8011` | API Gateway, Onboarding |
| `DATASEC_ENGINE_URL` | `http://localhost:8004` | Admin/User portal |
| `SECOPS_ENGINE_URL` | `http://localhost:8009` | User portal |
| `API_GATEWAY_URL` | `http://api-gateway:8000` | User portal, Onboarding |

### K8s Internal Service DNS (production)

In EKS, engines are accessed via ClusterIP service DNS names (namespace `threat-engine-engines`):

| Engine | K8s Service DNS | Container Port |
|--------|----------------|----------------|
| onboarding | `engine-onboarding.threat-engine-engines.svc.cluster.local` | 8008 |
| discoveries | `engine-discoveries.threat-engine-engines.svc.cluster.local` | 8001 |
| check | `engine-check.threat-engine-engines.svc.cluster.local` | 8002 |
| inventory | `engine-inventory.threat-engine-engines.svc.cluster.local` | 8022 |
| compliance | `engine-compliance.threat-engine-engines.svc.cluster.local` | 8010 |
| threat | `engine-threat.threat-engine-engines.svc.cluster.local` | 8020 |
| iam | `engine-iam.threat-engine-engines.svc.cluster.local` | 8003 |
| datasec | `engine-datasec.threat-engine-engines.svc.cluster.local` | 8004 |
| secops | `engine-secops.threat-engine-engines.svc.cluster.local` | 8009 |

---

## AWS & Cloud Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | `ap-south-1` | AWS region |
| `AWS_PROFILE` | - | AWS CLI profile name |
| `AWS_ROLE_ARN` | - | IAM role ARN for cross-account |
| `AWS_ROLE_SESSION_NAME` | `compliance-session` | Session name for assumed role |
| `AWS_EXTERNAL_ID` | - | External ID for assume role |
| `AWS_WEB_IDENTITY_TOKEN_FILE` | - | Web identity token file path (IRSA) |
| `ASSUMED_ROLE_DURATION` | `3600` | Assumed role duration (seconds) |
| `PLATFORM_AWS_ACCOUNT_ID` | `` | Platform AWS account ID |

---

## Storage & Output

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_TYPE` | `local` | Storage backend (local/s3) |
| `USE_S3` | `false` | Enable S3 storage |
| `S3_BUCKET` | `cspm-lgtech` | S3 bucket name |
| `OUTPUT_DIR` | `/output` | Output directory for scan results |
| `WORKSPACE_ROOT` | - | Root workspace directory |
| `THREAT_REPORTS_DIR` | `./threat_reports` | Threat report output |
| `SCAN_INPUT_PATH` | `/app/scan_input` | SecOps scan input path |
| `SCAN_OUTPUT_PATH` | `/app/scan_output` | SecOps scan output path |

---

## API & Server

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8000` | Server port |
| `API_HOST` | `0.0.0.0` | API server bind host |
| `API_PORT` | `8000` | API server port |
| `IAM_ENGINE_PORT` | `8003` | IAM engine port |
| `DATASEC_ENGINE_PORT` | `8004` | DataSec engine port |

---

## Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL) |
| `LOG_FORMAT` | `human` | Log format (human/json) |
| `LOG_MAX_BYTES` | `104857600` | Max log file size (100MB) |
| `LOG_BACKUP_COUNT` | `10` | Number of backup log files |
| `HOSTNAME` | `default` | Hostname for log streams |
| `CLOUDWATCH_LOG_GROUP` | - | CloudWatch log group |
| `ELK_ENDPOINT` | - | ELK/Elasticsearch endpoint |
| `DATADOG_API_KEY` | - | Datadog API key |

---

## Scheduler Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULER_INTERVAL_SECONDS` | `60` | Scheduler check interval |
| `ENGINE_SCAN_POLL_INTERVAL_SECONDS` | `10` | Scan polling interval |
| `ENGINE_SCAN_MAX_WAIT_SECONDS` | `3600` | Max wait for scan completion |

---

## Check & Discovery Engine

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECK_MODE` | `` | Check engine mode |
| `DISCOVERY_MODE` | `` | Discovery engine mode |
| `MAX_DISCOVERY_WORKERS` | `50` | Max discovery worker threads |
| `MAX_CHECK_WORKERS` | `50` | Max check worker threads |
| `MAX_SERVICE_WORKERS` | `10` | Max service worker threads |
| `MAX_REGION_WORKERS` | `5` | Max region worker threads |
| `FOR_EACH_MAX_WORKERS` | `50` | Max for-each workers |
| `MAX_ITEMS_PER_DISCOVERY` | `100000` | Safety limit per discovery |
| `OPERATION_TIMEOUT` | `600` | Operation timeout (10 min) |
| `RESULTS_NDJSON_MODE` | `finding` | Output mode (finding/asset) |
| `COLLECT_RAW_DISCOVERIES` | - | Collect raw discovery data |
| `USER_RULES_DIR` | - | Custom rules directory |
| `USE_DATABASE` | `false` | Store discoveries in DB |
| `THREAT_USE_DATABASE` | `true` | Use DB for threat engine |

### Boto3 Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BOTO_MAX_ATTEMPTS` | `5` | Max retry attempts |
| `BOTO_RETRY_MODE` | `adaptive` | Retry mode |
| `BOTO_READ_TIMEOUT` | `120` | Read timeout (seconds) |
| `BOTO_CONNECT_TIMEOUT` | `10` | Connect timeout (seconds) |
| `BOTO_MAX_POOL_CONNECTIONS` | `100` | Max connection pool size |
| `COMPLIANCE_MAX_RETRIES` | `5` | Max compliance retries |
| `COMPLIANCE_BASE_DELAY` | `0.8` | Base retry delay |
| `COMPLIANCE_BACKOFF_FACTOR` | `2.0` | Retry backoff factor |

---

## DynamoDB & Secrets Manager (Onboarding)

| Variable | Default | Description |
|----------|---------|-------------|
| `DYNAMODB_TENANTS_TABLE` | `threat-engine-tenants` | Tenants table |
| `DYNAMODB_PROVIDERS_TABLE` | `threat-engine-providers` | Providers table |
| `DYNAMODB_ACCOUNTS_TABLE` | `threat-engine-accounts` | Accounts table |
| `DYNAMODB_SCHEDULES_TABLE` | `threat-engine-schedules` | Schedules table |
| `DYNAMODB_EXECUTIONS_TABLE` | `threat-engine-executions` | Executions table |
| `SECRETS_MANAGER_PREFIX` | `threat-engine` | Secrets Manager prefix |
| `SECRETS_MANAGER_KMS_KEY_ID` | - | KMS key for encryption |

---

## Django Portal Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | - (required) | Django secret key |
| `ADMIN_SECRET_KEY` | `django-insecure-...` | Admin portal secret key |
| `DEBUG` | `False` | Django debug mode |
| `ALLOWED_HOSTS` | `*` | Comma-separated allowed hosts |
| `FRONTEND_URL` | - | Frontend application URL |
| `REDIS_URL` | `redis://localhost:6379/1` | Redis connection URL |
| `CELERY_BROKER_URL` | (falls back to REDIS_URL) | Celery broker URL |
| `CELERY_RESULT_BACKEND` | (falls back to REDIS_URL) | Celery result backend |
| `CORS_ALLOWED_ORIGINS` | `` | CORS allowed origins |

### Authentication (SAML/Okta)

| Variable | Default | Description |
|----------|---------|-------------|
| `ACCESS_TOKEN_LIFETIME_MINUTES` | `15` | JWT access token lifetime |
| `REFRESH_TOKEN_LIFETIME_DAYS` | `7` | JWT refresh token lifetime |
| `SAML_AUDIENCE` | - | SAML audience identifier |
| `SAML_CALLBACK_URL` | - | SAML callback URL |
| `OKTA_ISSUER` | - | Okta SAML issuer URL |
| `OKTA_ENTRYPOINT` | - | Okta SAML entrypoint |
| `OKTA_LOGOUT` | - | Okta logout URL |

---

## Quick Start `.env` Template

```bash
# Database (required)
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password

# Neo4j (optional, for security graph)
NEO4J_URI=neo4j+s://your-instance.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password

# AWS (required for cloud scanning)
AWS_REGION=ap-south-1
AWS_ROLE_ARN=arn:aws:iam::ACCOUNT:role/your-role

# Storage
S3_BUCKET=your-bucket
USE_S3=true

# Logging
LOG_LEVEL=INFO

# Ports (defaults)
PORT=8000
```

See `config.env.template` in the repo root for a complete template.
