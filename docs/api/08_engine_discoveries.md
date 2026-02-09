# engine_discoveries — AWS Resource Discovery

> Port: **8002** | Docker: `yadavanup84/discoveries-engine:latest`
> Database: PostgreSQL (threat_engine_discoveries)

---

## Folder Structure

```
engine_discoveries/engine_discoveries_aws/
├── api_server.py                       # FastAPI (8 endpoints)
├── Dockerfile                          # Container definition
├── auth/
│   └── aws_auth.py                     # AWS credential management
├── database/
│   ├── connection/
│   │   └── database_config.py          # DB connection factory
│   └── migrations/                     # Schema migrations
├── engine/
│   ├── discovery_engine.py             # Core discovery orchestrator
│   ├── database_manager.py             # DB operations
│   └── service_scanner.py              # Per-service scanner
├── services/
│   └── {40+ AWS services}/             # Per-service discovery configs
│       └── discover.py                 # Service-specific discovery logic
└── utils/
    ├── aws_service_registry.py         # Service registry
    ├── discovery_output_manager.py     # Output formatting
    ├── exception_manager.py            # Error handling
    ├── metadata_loader.py              # Load metadata
    ├── ndjson_writer.py                # NDJSON output
    ├── organizations_scanner.py        # AWS Organizations
    └── progress_monitor.py             # Scan progress
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Run Discovery** | `POST /discovery` | Trigger AWS resource discovery |
| **Discovery Status** | `GET /discovery/{id}/status` | Real-time scan progress |
| **Discovery History** | `GET /discoveries` | List past discoveries |
| **Available Services** | `GET /services` | AWS services that can be scanned |
| **Health** | `GET /health` | Engine health |

---

## Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/discovery` | Create and run discovery scan |
| GET | `/api/v1/discovery/{discovery_scan_id}/status` | Get discovery status |
| GET | `/api/v1/discoveries` | List all discoveries |
| GET | `/api/v1/services` | List available AWS services |
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/health/ready` | Readiness probe |
| GET | `/api/v1/health/live` | Liveness probe |
| GET | `/api/v1/metrics` | Prometheus metrics |

### POST /api/v1/discovery

**Request:**
```json
{
  "tenant_id": "588989875114",
  "scan_run_id": "ece8c3a6-...",
  "cloud": "aws",
  "accounts": ["588989875114"],
  "regions": ["ap-south-1"],
  "services": ["s3", "iam", "ec2", "rds", "lambda"]
}
```

**Response:**
```json
{
  "discovery_scan_id": "d1e2f3g4-...",
  "status": "running",
  "tenant_id": "588989875114"
}
```

### Supported AWS Services (40+)

s3, iam, ec2, rds, lambda, dynamodb, sns, sqs, cloudfront, cloudtrail, cloudwatch, config, efs, elasticache, elasticsearch, elb, elbv2, glacier, kms, redshift, route53, secretsmanager, ses, ssm, vpc, waf, backup, codebuild, codepipeline, ecr, ecs, eks, guardduty, inspector, kinesis, macie, organizations, sagemaker, and more.
