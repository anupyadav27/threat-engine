# Inventory Engine

Cloud Resource Inventory Discovery and Graph Building Engine.

## Overview

The Inventory Engine discovers cloud/Kubernetes/VMware resources, normalizes them into a canonical asset model, builds relationships (graph edges), and publishes immutable scan artifacts. These artifacts are consumed by downstream engines (Misconfiguration, Threat, Compliance) and by the UI.

## Architecture

```
inventory-engine/
├── inventory_engine/
│   ├── schemas/
│   │   ├── asset_schema.py          # cspm_asset.v1 schema
│   │   ├── relationship_schema.py  # cspm_relationship.v1 schema
│   │   ├── drift_schema.py         # cspm_drift.v1 schema
│   │   └── summary_schema.py       # Scan summary
│   ├── connectors/
│   │   └── aws_connector.py        # AWS resource collector
│   ├── normalizer/
│   │   ├── asset_normalizer.py     # Raw → Asset normalization
│   │   └── relationship_builder.py # Asset → Relationship building
│   ├── drift/
│   │   └── drift_detector.py       # Change detection
│   ├── graph/
│   │   └── neo4j_loader.py         # Neo4j graph loading
│   ├── index/
│   │   ├── index_writer.py         # DB index writer
│   │   └── database_schema.sql    # Postgres schema
│   ├── api/
│   │   ├── orchestrator.py        # Scan orchestration
│   │   └── api_server.py          # FastAPI server
│   └── __init__.py
├── Dockerfile
├── requirements.txt
└── README.md
```

## Output Artifacts

Each scan produces:

- **normalized/assets.ndjson**: One JSON object per asset (cspm_asset.v1)
- **normalized/relationships.ndjson**: One JSON object per relationship (cspm_relationship.v1)
- **normalized/summary.json**: Scan overview with counts
- **normalized/drift.ndjson**: Change detection results (optional)
- **raw/{provider}/{account}/{region}/{service}.json**: Raw collector outputs

## Storage Layout

### S3 Structure
```
s3://cspm-lgtech/inventory/{tenant_id}/{scan_run_id}/
  raw/
    aws/{account_id}/{region}/{service}.json
  normalized/
    assets.ndjson
    relationships.ndjson
    summary.json
    drift.ndjson
```

### Local Structure
```
engines-output/inventory-engine/output/{tenant_id}/{scan_run_id}/
  raw/
    aws/{account_id}/{region}/{service}.json
  normalized/
    assets.ndjson
    relationships.ndjson
    summary.json
    drift.ndjson
```

## API Endpoints

### POST `/api/v1/inventory/scan`

Run inventory scan.

**Request:**
```json
{
  "tenant_id": "tnt_123",
  "providers": ["aws"],
  "accounts": ["588989875114"],
  "regions": ["us-east-1"],
  "services": ["s3", "ec2", "iam"],
  "previous_scan_id": "inv_abc123"  // Optional for drift detection
}
```

**Response:**
```json
{
  "scan_run_id": "inv_xyz789",
  "status": "completed",
  "total_assets": 150,
  "total_relationships": 300,
  "total_drift": 5,
  "artifact_paths": {
    "assets": "s3://.../assets.ndjson",
    "relationships": "s3://.../relationships.ndjson",
    "summary": "s3://.../summary.json"
  }
}
```

### GET `/api/v1/inventory/runs/{scan_run_id}/summary`

Get scan summary.

### GET `/api/v1/inventory/assets`

List assets with filters (provider, region, resource_type).

### GET `/api/v1/inventory/assets/{resource_uid}`

Get asset details.

### GET `/api/v1/inventory/assets/{resource_uid}/relationships`

Get asset relationships (graph edges).

## Environment Variables

- `USE_S3`: Set to `"true"` to use S3 storage (default: `"false"`)
- `S3_BUCKET`: S3 bucket name (default: `cspm-lgtech`)
- `INVENTORY_OUTPUT_DIR`: Local output directory
- `DATABASE_URL`: PostgreSQL connection string (for indexes)
- `NEO4J_URI`: Neo4j connection URI (for graph)
- `NEO4J_USERNAME`: Neo4j username
- `NEO4J_PASSWORD`: Neo4j password
- `PORT`: API server port (default: `8000`)

## Port Mapping

- **Local**: Port 8005 (host) → 8000 (container)
- **EKS**: Port 80 (service) → 8000 (container)

## Integration

The inventory engine integrates with:

1. **ConfigScan Engines**: Provides asset context for misconfig findings
2. **Threat Engine**: Provides asset graph for threat correlation
3. **Compliance Engine**: Provides asset inventory for compliance reporting
4. **Neo4j**: Graph database for relationship queries
5. **PostgreSQL**: Index database for fast UI queries

## Next Steps

1. **Expand AWS Connector**: Add more services (Lambda, ECS, EKS, etc.)
2. **Add Azure/GCP Connectors**: Multi-cloud support
3. **Enhance Relationship Building**: More relationship types
4. **UI Integration**: Complete API endpoints for UI queries
5. **GraphQL API**: Add GraphQL endpoint for flexible queries

