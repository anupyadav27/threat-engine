# engine_pythonsdk — Python SDK Service

> Port: **8000** | Code: `engine_pythonsdk/pythonsdk_service/`
> Purpose: AWS service metadata, field definitions, and boto3 data provider

---

## Folder Structure

```
engine_pythonsdk/pythonsdk_service/
├── api_server.py                       # FastAPI (13 endpoints)
├── data/                               # Pre-processed service data
├── loaders/
│   ├── service_loader.py               # Load AWS service definitions
│   └── boto3_loader.py                 # Load boto3 metadata
├── models/
│   ├── service_model.py                # Service data model
│   └── field_model.py                  # Field metadata model
└── generators/
    └── enhancement_generator.py        # Generate field enhancements
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Service Browser** | `GET /services` | List all AWS services |
| **Service Detail** | `GET /service/{name}` | Service fields + operations |
| **Field Metadata** | `GET /field-metadata` | All field definitions |
| **Security Fields** | `GET /fields/security` | Security-relevant fields |
| **Compliance Fields** | `GET /fields/compliance/{cat}` | Compliance-tagged fields |
| **Operations** | `GET /operations` | Available API operations |
| **Boto3 Data** | `GET /boto3/{service}` | Raw boto3 metadata |
| **YAML Gen** | `GET /yaml/{service}` | Generate discovery YAML |

---

## Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/services` | List all AWS services |
| GET | `/api/v1/service/{name}` | Get service detail |
| GET | `/api/v1/field-metadata` | All field metadata |
| GET | `/api/v1/fields/security` | Security fields |
| GET | `/api/v1/fields/compliance/{category}` | Compliance fields by category |
| GET | `/api/v1/operations` | Available operations |
| GET | `/api/v1/operation/{name}` | Operation detail |
| GET | `/api/v1/references/{type}` | Resource references |
| GET | `/api/v1/relationships/{type}` | Resource relationships |
| GET | `/api/v1/boto3/{service}` | Boto3 service data |
| GET | `/api/v1/yaml/{service}` | Generated discovery YAML |
| POST | `/api/v1/admin/load-data` | Load/reload service data |
| POST | `/api/v1/admin/generate-enhancements` | Generate field enhancements |
