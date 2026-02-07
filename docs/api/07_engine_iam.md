# engine_iam — IAM Security Engine

> Port: **8003** | Docker: `yadavanup84/iam-engine:latest`
> Database: PostgreSQL (threat_engine_iam)

---

## Folder Structure

```
engine_iam/iam_engine/
├── api_server.py                       # FastAPI (8 endpoints)
├── enricher/
│   └── finding_enricher.py             # Enrich IAM findings with context
├── input/
│   ├── check_db_reader.py              # Read from check DB
│   ├── rule_db_reader.py               # Read from rule DB
│   └── threat_db_reader.py             # Read from threat DB
├── mapper/
│   └── rule_to_module_mapper.py        # Map rules to IAM modules
├── reporter/
│   └── iam_reporter.py                 # Generate IAM reports
└── storage/
    ├── iam_db_writer.py                # Write to IAM DB
    └── report_storage.py               # File storage
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **IAM Dashboard** | `POST /scan` | Run IAM security scan |
| **IAM Findings** | `GET /findings` | All IAM findings with filters |
| **IAM Modules** | `GET /modules` | List IAM analysis modules |
| **Module Rules** | `GET /modules/{m}/rules` | Rules per module |
| **Rule Detail** | `GET /rules/{id}` | Individual rule details |
| **Rule IDs** | `GET /rule-ids` | All IAM-related rule IDs |

---

## Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Root endpoint |
| GET | `/health` | Health check |
| POST | `/api/v1/iam-security/scan` | Run IAM security scan |
| GET | `/api/v1/iam-security/findings` | IAM findings (filterable) |
| GET | `/api/v1/iam-security/rules/{rule_id}` | Rule detail |
| GET | `/api/v1/iam-security/modules` | List IAM modules |
| GET | `/api/v1/iam-security/modules/{module}/rules` | Rules by module |
| GET | `/api/v1/iam-security/rule-ids` | All IAM rule IDs |

### Modules

| Module | Description |
|--------|-------------|
| access_management | Least privilege analysis |
| credential_management | Password/key rotation |
| identity_governance | User/role lifecycle |
| privilege_escalation | Escalation path detection |
| cross_account | Cross-account access risks |
