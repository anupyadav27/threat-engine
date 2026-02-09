# engine_inventory — Asset Inventory & Relationships

> Port: **8022** | Docker: `yadavanup84/inventory-engine:latest`
> Database: PostgreSQL (threat_engine_inventory)

---

## Folder Structure

```
engine_inventory/inventory_engine/
├── api/
│   ├── api_server.py                   # FastAPI (20+ endpoints)
│   ├── data_loader.py                  # Load data from various sources
│   ├── inventory_db_loader.py          # Database loader
│   └── orchestrator.py                 # Scan orchestration
├── connectors/
│   ├── aws_connector.py               # AWS API connector
│   ├── check_db_reader.py             # Read from check DB
│   ├── discovery_db_reader.py          # Read from discovery DB
│   ├── discovery_reader.py             # Legacy NDJSON reader
│   └── discovery_reader_factory.py     # Factory for readers
├── database/
│   └── connection/
│       └── database_config.py          # DB connection factory
├── drift/
│   └── drift_detector.py              # Inventory drift detection
├── normalizer/
│   ├── asset_normalizer.py            # Normalize asset data
│   ├── relationship_builder.py         # Build resource relationships
│   └── resource_classifier.py          # Classify resource types
├── relationship_engine/
│   ├── builder.py                      # Relationship graph builder
│   ├── discovery.py                    # Discover relationships
│   └── storage.py                      # Store relationships
├── schemas/
│   ├── asset_schema.py                # Asset Pydantic models
│   ├── drift_schema.py                # Drift models
│   ├── relationship_schema.py          # Relationship models
│   └── summary_schema.py              # Summary models
└── index/
    └── index_writer.py                # Search index writer
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Asset Inventory** | `GET /assets` | Filterable/paginated asset table |
| **Asset Detail** | `GET /assets/{uid}` | Full resource details |
| **Asset Relationships** | `GET /assets/{uid}/relationships` | Connected resources |
| **Asset Drift** | `GET /assets/{uid}/drift` | Change history over time |
| **Asset Graph** | `GET /graph` | Visual relationship graph (nodes + edges) |
| **Drift Detection** | `GET /drift` | Drift records between scans |
| **Run Scan** | `POST /scan`, `POST /scan/discovery` | Trigger inventory scan |
| **Scan History** | `GET /scans` | List available scans |
| **Scan Summary** | `GET /runs/{id}/summary` | Per-scan overview |
| **Account View** | `GET /accounts/{id}` | Account-level asset summary |
| **Service View** | `GET /services/{service}` | Service-level breakdown |
| **Relationships** | `GET /relationships` | All relationships with filters |

---

## Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Root endpoint |
| GET | `/health` | Health check |
| POST | `/api/v1/inventory/scan` | Run inventory scan (sync) |
| POST | `/api/v1/inventory/scan/async` | Run inventory scan (async) |
| POST | `/api/v1/inventory/scan/discovery` | Scan from discovery data (sync) |
| POST | `/api/v1/inventory/scan/discovery/async` | Scan from discovery data (async) |
| GET | `/api/v1/inventory/jobs/{job_id}` | Poll async job status |
| GET | `/api/v1/inventory/runs/{scan_run_id}/summary` | Scan run summary |
| GET | `/api/v1/inventory/runs/latest/summary` | Latest scan summary |
| GET | `/api/v1/inventory/assets` | List assets (filterable, paginated) |
| GET | `/api/v1/inventory/assets/{resource_uid}` | Get asset by UID |
| GET | `/api/v1/inventory/assets/{resource_uid}/relationships` | Asset relationships |
| GET | `/api/v1/inventory/assets/{resource_uid}/drift` | Asset drift history |
| GET | `/api/v1/inventory/graph` | Graph visualization (nodes/edges) |
| GET | `/api/v1/inventory/drift` | Drift records |
| GET | `/api/v1/inventory/accounts/{account_id}` | Account summary |
| GET | `/api/v1/inventory/services/{service}` | Service summary |
| GET | `/api/v1/inventory/scans` | List discovery scans |
| GET | `/api/v1/inventory/runs/{scan_run_id}/drift` | Drift for specific scan |
| GET | `/api/v1/inventory/relationships` | List relationships |

### Database Tables

| Table | Description |
|-------|-------------|
| `inventory_findings` | Normalized asset records (resource_uid, type, config, tags) |
| `inventory_relationships` | Resource-to-resource relationships (from_uid, to_uid, type) |
| `inventory_scans` | Scan metadata |
| `inventory_drift` | Configuration change records |
