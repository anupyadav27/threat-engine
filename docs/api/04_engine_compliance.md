# engine_compliance — Compliance Reporting Engine

> Port: **8021** | Docker: `yadavanup84/compliance-engine:latest`
> Database: PostgreSQL (threat_engine_check — reads check_findings + rule_metadata)

---

## Folder Structure

```
engine_compliance/compliance_engine/
├── api_server.py                       # FastAPI (34 endpoints)
├── aggregator/
│   ├── result_aggregator.py            # Aggregate findings by framework/control
│   └── score_calculator.py             # Calculate compliance scores
├── database/
│   └── connection/
│       └── database_config.py          # DB connection factory
├── exporter/
│   ├── csv_exporter.py                 # CSV export
│   ├── db_exporter.py                  # DB export
│   ├── excel_exporter.py               # Excel export
│   ├── json_exporter.py                # JSON export
│   └── pdf_exporter.py                 # PDF report generation
├── loader/
│   ├── check_db_loader.py             # Load from check DB
│   ├── consolidated_csv_loader.py     # Load from CSV
│   ├── metadata_loader.py             # Load rule metadata
│   ├── threat_db_loader.py            # Load from threat DB
│   └── threat_engine_loader.py        # Load from threat engine
├── mapper/
│   ├── db_rule_mapper.py              # Map rules to frameworks (DB)
│   ├── framework_loader.py            # Load framework definitions
│   └── rule_mapper.py                 # Rule-to-control mapping
├── reporter/
│   ├── enterprise_reporter.py         # Enterprise-grade reports
│   ├── executive_dashboard.py         # Executive summary
│   ├── framework_report.py            # Per-framework reports
│   ├── grouping_helper.py             # Group findings
│   └── resource_drilldown.py          # Resource-level details
├── schemas/
│   └── enterprise_report_schema.py    # Pydantic report models
└── storage/
    ├── compliance_db_writer.py        # Write reports to DB
    ├── evidence_manager.py            # Evidence collection
    ├── report_storage.py              # File-based storage
    └── trend_tracker.py               # Track compliance trends
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Compliance Dashboard** | `GET /dashboard` | Overall compliance posture |
| **Framework List** | `GET /frameworks/all` | All supported frameworks |
| **Framework Detail** | `GET /framework-detail/{fw}` | Framework compliance status |
| **Framework Structure** | `GET /framework/{fw}/structure` | Controls tree |
| **Control Detail** | `GET /control-detail/{fw}/{ctrl}` | Control findings + resources |
| **Controls Grouped** | `GET /framework/{fw}/controls/grouped` | Controls by domain |
| **Resources Grouped** | `GET /framework/{fw}/resources/grouped` | Resources by compliance |
| **Resource Compliance** | `GET /resource/{uid}/compliance` | Per-resource compliance |
| **Resource Drilldown** | `GET /resource/drilldown` | Deep resource analysis |
| **Generate Report** | `POST /generate`, `POST /generate/from-check-db` | Generate compliance report |
| **Report List** | `GET /reports` | List all reports |
| **Report Detail** | `GET /report/{id}` | Full report |
| **Export PDF** | `GET /framework/{fw}/download/pdf` | Download PDF |
| **Export Excel** | `GET /framework/{fw}/download/excel` | Download Excel |
| **Trends** | `GET /trends` | Compliance trends over time |
| **Account View** | `GET /accounts/{id}` | Account compliance |
| **Search Controls** | `GET /controls/search` | Search across controls |

---

## Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/compliance/generate` | Generate compliance report |
| POST | `/api/v1/compliance/generate/direct` | Generate direct report |
| POST | `/api/v1/compliance/generate/from-threat-engine` | Generate from threat engine data |
| POST | `/api/v1/compliance/generate/from-check-db` | Generate from check DB |
| POST | `/api/v1/compliance/generate/from-threat-db` | Generate from threat DB |
| POST | `/api/v1/compliance/generate/enterprise` | Enterprise report |
| POST | `/api/v1/compliance/generate/detailed` | Detailed report |
| POST | `/api/v1/compliance/mock/generate` | Mock report (testing) |
| GET | `/api/v1/compliance/report/{report_id}` | Get report |
| GET | `/api/v1/compliance/report/{report_id}/export` | Export report |
| GET | `/api/v1/compliance/reports` | List reports |
| GET | `/api/v1/compliance/reports/{report_id}/status` | Report status |
| DELETE | `/api/v1/compliance/reports/{report_id}` | Delete report |
| GET | `/api/v1/compliance/dashboard` | Dashboard data |
| GET | `/api/v1/compliance/frameworks` | List frameworks |
| GET | `/api/v1/compliance/frameworks/all` | All frameworks with details |
| GET | `/api/v1/compliance/framework/{fw}/status` | Framework status |
| GET | `/api/v1/compliance/framework/{fw}/detailed` | Framework detailed |
| GET | `/api/v1/compliance/framework-detail/{fw}` | Framework detail view |
| GET | `/api/v1/compliance/framework/{fw}/structure` | Framework control tree |
| GET | `/api/v1/compliance/framework/{fw}/controls/grouped` | Controls grouped |
| GET | `/api/v1/compliance/framework/{fw}/resources/grouped` | Resources grouped |
| GET | `/api/v1/compliance/control-detail/{fw}/{ctrl}` | Control detail |
| GET | `/api/v1/compliance/framework/{fw}/control/{ctrl}` | Control info |
| GET | `/api/v1/compliance/resource/{uid}/compliance` | Resource compliance |
| GET | `/api/v1/compliance/resource/drilldown` | Resource drilldown |
| GET | `/api/v1/compliance/accounts/{account_id}` | Account compliance |
| GET | `/api/v1/compliance/trends` | Compliance trends |
| GET | `/api/v1/compliance/controls/search` | Search controls |
| GET | `/api/v1/compliance/framework/{fw}/download/pdf` | Download PDF |
| GET | `/api/v1/compliance/framework/{fw}/download/excel` | Download Excel |
| GET | `/api/v1/compliance/report/{id}/download/pdf` | Report PDF |
| GET | `/api/v1/compliance/report/{id}/download/excel` | Report Excel |
| GET | `/api/v1/health` | Health check |

### Supported Frameworks

CIS AWS, NIST 800-53, SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR, AWS Well-Architected, and custom frameworks.
