# engine_datasec — Data Security Engine

> Port: **8004** | Docker: `yadavanup84/datasec-engine:latest`
> Database: PostgreSQL (threat_engine_datasec)

---

## Folder Structure

```
engine_datasec/data_security_engine/
├── api_server.py                       # FastAPI (17 endpoints)
├── analyzer/
│   ├── activity_analyzer.py            # Data access activity analysis
│   ├── classification_analyzer.py      # PII/PCI/PHI classification
│   ├── lineage_analyzer.py             # Data lineage tracking
│   └── residency_analyzer.py           # Data residency compliance
├── enricher/
│   └── finding_enricher.py             # Enrich findings with context
├── input/
│   ├── check_db_reader.py              # Read from check DB
│   ├── rule_db_reader.py               # Read from rule DB
│   └── threat_db_reader.py             # Read from threat DB
├── mapper/
│   └── rule_to_module_mapper.py        # Map rules to datasec modules
├── reporter/
│   └── data_security_reporter.py       # Generate reports
└── storage/
    ├── datasec_db_writer.py            # Write to datasec DB
    └── report_storage.py               # File storage
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Data Security Dashboard** | `POST /scan` | Run data security scan |
| **Data Catalog** | `GET /catalog` | All data stores with classification |
| **Data Classification** | `GET /classification` | PII, PCI, PHI detection results |
| **Data Lineage** | `GET /lineage` | Data flow visualization |
| **Data Residency** | `GET /residency` | Geographic compliance |
| **Access Governance** | `GET /governance/{id}` | Who can access what |
| **Protection Status** | `GET /protection/{id}` | Encryption, backup, versioning |
| **Findings** | `GET /findings` | All data security findings |
| **Activity Monitor** | `GET /activity` | Data access patterns |
| **Compliance** | `GET /compliance` | Data compliance status |
| **Account View** | `GET /accounts/{id}` | Account-level data security |
| **Service View** | `GET /services/{service}` | Service-level data security |

---

## Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Root endpoint |
| GET | `/health` | Health check |
| POST | `/api/v1/data-security/scan` | Run data security scan |
| GET | `/api/v1/data-security/catalog` | Data catalog |
| GET | `/api/v1/data-security/classification` | Data classification (PII/PCI/PHI) |
| GET | `/api/v1/data-security/lineage` | Data lineage |
| GET | `/api/v1/data-security/residency` | Data residency compliance |
| GET | `/api/v1/data-security/activity` | Activity monitoring |
| GET | `/api/v1/data-security/compliance` | Data compliance status |
| GET | `/api/v1/data-security/findings` | Security findings |
| GET | `/api/v1/data-security/governance/{resource_id}` | Access governance |
| GET | `/api/v1/data-security/protection/{resource_id}` | Protection status |
| GET | `/api/v1/data-security/rules/{rule_id}` | Rule detail |
| GET | `/api/v1/data-security/modules` | List modules |
| GET | `/api/v1/data-security/modules/{module}/rules` | Rules by module |
| GET | `/api/v1/data-security/accounts/{account_id}` | Account data security |
| GET | `/api/v1/data-security/services/{service}` | Service data security |

### Modules

| Module | Description |
|--------|-------------|
| classification | PII, PCI, PHI data detection |
| lineage | Data flow tracking |
| residency | Geographic data compliance |
| activity | Access pattern monitoring |
| governance | Access control analysis |
| protection | Encryption & backup status |
