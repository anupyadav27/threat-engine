# engine_rule — YAML Rule Builder (Multi-CSP)

> Port: **8011** | Docker: `yadavanup84/rule-engine:latest`
> Database: PostgreSQL (threat_engine_check — rule_metadata table)

---

## Folder Structure

```
engine_rule/
├── api_server.py                       # FastAPI (23 endpoints)
├── api.py                              # Core API logic
├── cli.py                              # CLI interface
├── config.py                           # Configuration
├── core/
│   ├── data_loader.py                  # Load provider data
│   ├── dependency_resolver.py          # Resolve rule dependencies
│   ├── field_mapper.py                 # Map fields to checks
│   ├── metadata_generator.py           # Generate rule metadata
│   ├── provider_validator.py           # Validate provider config
│   ├── rule_comparator.py              # Compare/diff rules
│   └── yaml_generator.py              # Generate YAML output
├── models/
│   ├── discovery_chain.py              # Discovery chain model
│   ├── field_selection.py              # Field selection model
│   └── rule.py                         # Rule data model
├── providers/
│   ├── plugin_base.py                  # Base provider plugin
│   ├── aws/adapter.py                  # AWS provider
│   ├── azure/adapter.py                # Azure provider
│   ├── gcp/adapter.py                  # GCP provider
│   ├── alicloud/adapter.py             # AliCloud provider
│   ├── ibm/adapter.py                  # IBM Cloud provider
│   ├── oci/adapter.py                  # Oracle Cloud provider
│   └── k8s/adapter.py                  # Kubernetes provider
└── utils/
    └── validators.py                   # Input validators
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Rule Browser** | `GET /rules`, `GET /rules/search` | Filterable rule list |
| **Rule Detail** | `GET /rules/{rule_id}` | Full rule YAML + metadata |
| **Rule Editor** | `PUT /rules/{rule_id}`, `POST /rules/validate` | Edit + validate rules |
| **Rule Creator** | `POST /rules/generate`, `POST /rules/preview` | AI-generate or preview rules |
| **Templates** | `GET /rules/templates`, `POST /rules/templates/{id}/create` | Rule templates |
| **Provider Browser** | `GET /providers`, `GET /providers/{p}/services` | Browse CSP services |
| **Service Fields** | `GET /providers/{p}/services/{s}/fields` | Available check fields |
| **Service Capabilities** | `GET /providers/{p}/services/{s}/capabilities` | What can be checked |
| **Statistics** | `GET /rules/statistics` | Rule counts by provider/service |
| **Import/Export** | `POST /rules/import`, `GET /rules/export` | Bulk operations |

---

## Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/providers` | List cloud providers (aws, azure, gcp, oci, alicloud, ibm, k8s) |
| GET | `/api/v1/providers/status` | Status for all providers |
| GET | `/api/v1/providers/{provider}/status` | Status for one provider |
| GET | `/api/v1/providers/{provider}/services` | List services for provider |
| GET | `/api/v1/providers/{provider}/services/{service}/fields` | Fields for service |
| GET | `/api/v1/providers/{provider}/services/{service}/rules` | Rules for service |
| GET | `/api/v1/providers/{provider}/services/{service}/capabilities` | Service capabilities |
| POST | `/api/v1/rules/validate` | Validate rule YAML |
| POST | `/api/v1/rules/generate` | AI-generate rule from description |
| POST | `/api/v1/rules/preview` | Preview YAML without saving |
| GET | `/api/v1/rules` | List all rules (filterable) |
| GET | `/api/v1/rules/search` | Full-text search rules |
| GET | `/api/v1/rules/{rule_id}` | Get rule detail |
| PUT | `/api/v1/rules/{rule_id}` | Update rule |
| DELETE | `/api/v1/rules/{rule_id}` | Delete rule |
| POST | `/api/v1/rules/{rule_id}/copy` | Clone/duplicate rule |
| POST | `/api/v1/rules/bulk-delete` | Delete multiple rules |
| GET | `/api/v1/rules/export` | Export rules (JSON/YAML) |
| POST | `/api/v1/rules/import` | Import rules |
| GET | `/api/v1/rules/templates` | Get rule templates |
| POST | `/api/v1/rules/templates/{template_id}/create` | Create from template |
| GET | `/api/v1/rules/statistics` | Rule statistics |
| GET | `/api/v1/health` | Health check |

### Supported Providers

| Provider | Services | Rules |
|----------|----------|-------|
| AWS | 40+ (s3, iam, ec2, rds, lambda, etc.) | 500+ |
| Azure | 20+ | 200+ |
| GCP | 15+ | 150+ |
| AliCloud | 10+ | 100+ |
| IBM Cloud | 10+ | 80+ |
| OCI | 10+ | 80+ |
| Kubernetes | 5+ | 50+ |
