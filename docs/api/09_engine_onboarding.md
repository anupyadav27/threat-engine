# engine_onboarding — Account Onboarding & Scan Scheduling

> Port: **8010** | Docker: `yadavanup84/onboarding-engine:latest`
> Database: PostgreSQL (threat_engine_onboarding) + AWS Secrets Manager

---

## Folder Structure

```
engine_onboarding/
├── main.py                             # FastAPI app + router includes
├── config.py                           # Configuration
├── api/
│   ├── health.py                       # Health check routes
│   ├── onboarding.py                   # Account onboarding routes (16 endpoints)
│   ├── credentials.py                  # Credential management routes (3 endpoints)
│   └── schedules.py                    # Schedule management routes (9 endpoints)
├── database/
│   ├── connection.py                   # DB connection
│   ├── connection_config/
│   │   └── database_config.py          # DB config factory
│   ├── models.py                       # SQLAlchemy models
│   └── postgres_operations.py          # DB CRUD operations
├── models/
│   ├── account.py                      # Account data model
│   ├── credential.py                   # Credential model
│   ├── provider.py                     # Cloud provider model
│   ├── schedule.py                     # Schedule model
│   └── tenant.py                       # Tenant model
├── notifications/
│   └── webhook_sender.py              # Webhook notifications
├── orchestrator/
│   └── engine_orchestrator.py         # Full scan pipeline orchestration
├── scheduler/
│   ├── main.py                         # Scheduler entry point
│   ├── cron_parser.py                  # CRON expression parser
│   ├── notifications.py               # Schedule notifications
│   ├── scheduler_service.py           # Core scheduler logic
│   └── task_executor.py               # Execute scheduled tasks
├── storage/
│   ├── encryption.py                   # Credential encryption
│   └── secrets_manager_storage.py     # AWS Secrets Manager integration
├── utils/
│   ├── engine_client.py               # HTTP client for engine calls
│   └── helpers.py                      # Utility functions
└── validators/
    ├── base_validator.py               # Base validator
    ├── aws_validator.py                # AWS credential validation
    ├── azure_validator.py              # Azure validation
    ├── gcp_validator.py                # GCP validation
    ├── alicloud_validator.py           # AliCloud validation
    ├── ibm_validator.py                # IBM validation
    └── oci_validator.py                # OCI validation
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Onboard Account** | `POST /onboarding/{provider}/init`, `POST .../validate` | Multi-step account setup |
| **Auth Methods** | `GET /onboarding/{provider}/auth-methods` | Available auth for provider |
| **CloudFormation** | `GET /onboarding/aws/cloudformation-template` | IAM role setup template |
| **Account List** | `GET /onboarding/accounts` | All onboarded accounts |
| **Account Detail** | `GET /onboarding/accounts/{id}` | Account configuration |
| **Account Health** | `GET /onboarding/accounts/{id}/health` | Connection health |
| **Account Stats** | `GET /onboarding/accounts/{id}/statistics` | Scan statistics |
| **Tenant Management** | `POST /onboarding/tenants`, `GET /onboarding/tenants` | Manage tenants |
| **Provider Management** | `POST /onboarding/providers`, `GET /onboarding/providers` | Manage providers |
| **Credentials** | `POST /accounts/{id}/credentials` | Store encrypted credentials |
| **Validate Credentials** | `GET /accounts/{id}/credentials/validate` | Re-validate stored creds |
| **Schedule List** | `GET /schedules` | All scan schedules |
| **Schedule Detail** | `GET /schedules/{id}` | Schedule configuration |
| **Create Schedule** | `POST /schedules` | Create CRON schedule |
| **Manual Trigger** | `POST /schedules/{id}/trigger` | Trigger scan immediately |
| **Execution History** | `GET /schedules/{id}/executions` | Past schedule runs |
| **Execution Status** | `GET /schedules/{id}/executions/{eid}/status` | Execution detail |

---

## Endpoint Reference

### Health (prefix: `/api/v1/health`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/health/ready` | Readiness probe |
| GET | `/api/v1/health/live` | Liveness probe |

### Onboarding (prefix: `/api/v1/onboarding`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/onboarding/{provider}/auth-methods` | Available auth methods |
| POST | `/api/v1/onboarding/{provider}/init` | Initialize account onboarding |
| GET | `/api/v1/onboarding/aws/cloudformation-template` | Get CF template |
| POST | `/api/v1/onboarding/{provider}/validate` | Validate and activate account |
| POST | `/api/v1/onboarding/{provider}/validate-json` | Validate from JSON |
| GET | `/api/v1/onboarding/accounts` | List all accounts |
| GET | `/api/v1/onboarding/accounts/{account_id}` | Get account details |
| DELETE | `/api/v1/onboarding/accounts/{account_id}` | Remove account |
| POST | `/api/v1/onboarding/tenants` | Create tenant |
| GET | `/api/v1/onboarding/tenants` | List tenants |
| GET | `/api/v1/onboarding/tenants/{tenant_id}` | Get tenant |
| POST | `/api/v1/onboarding/providers` | Create provider |
| GET | `/api/v1/onboarding/providers` | List providers |
| GET | `/api/v1/onboarding/providers/{provider_id}` | Get provider |
| GET | `/api/v1/onboarding/accounts/{account_id}/health` | Account health |
| GET | `/api/v1/onboarding/accounts/{account_id}/statistics` | Account stats |

### Credentials (prefix: `/api/v1/accounts`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/accounts/{account_id}/credentials` | Store credentials |
| GET | `/api/v1/accounts/{account_id}/credentials/validate` | Re-validate credentials |
| DELETE | `/api/v1/accounts/{account_id}/credentials` | Delete credentials |

### Schedules (prefix: `/api/v1/schedules`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/schedules` | Create schedule |
| GET | `/api/v1/schedules` | List schedules |
| GET | `/api/v1/schedules/{schedule_id}` | Get schedule details |
| PUT | `/api/v1/schedules/{schedule_id}` | Update schedule |
| POST | `/api/v1/schedules/{schedule_id}/trigger` | Manual trigger |
| DELETE | `/api/v1/schedules/{schedule_id}` | Delete schedule |
| GET | `/api/v1/schedules/{schedule_id}/executions` | Execution history |
| GET | `/api/v1/schedules/{schedule_id}/executions/{eid}/status` | Execution status |
| GET | `/api/v1/schedules/{schedule_id}/statistics` | Schedule statistics |

### Supported Providers

| Provider | Validator | Auth Methods |
|----------|-----------|-------------|
| AWS | aws_validator.py | IAM Role (CrossAccount), Access Keys, CloudFormation |
| Azure | azure_validator.py | Service Principal, Managed Identity |
| GCP | gcp_validator.py | Service Account Key, Workload Identity |
| AliCloud | alicloud_validator.py | Access Keys, RAM Role |
| IBM | ibm_validator.py | API Key |
| OCI | oci_validator.py | API Key, Instance Principal |
