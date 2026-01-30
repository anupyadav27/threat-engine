# Data Security Engine

Comprehensive Data Security module for CSPM tools - providing data discovery, classification, access governance, protection, lineage, activity monitoring, residency, and compliance capabilities.

## Overview

The Data Security Engine is a critical component of the threat-engine ecosystem, providing enterprise-grade data security capabilities similar to Wiz, Orca Security, and other leading CSPM platforms. It integrates seamlessly with existing engines (ConfigScan, Inventory, Threat, Compliance) to deliver unified data security insights.

## Features

### 🔍 Data Discovery & Classification
- Automatically discover data stores (S3, RDS, DynamoDB, etc.)
- Classify sensitive data (PII, PCI, PHI, Financial)
- Pattern-based and ML-powered classification
- Classification tagging and metadata enrichment

### 🔐 Data Access Governance
- IAM policy analysis for data resources
- Access pattern analysis
- Privileged access identification
- Least-privilege recommendations

### 🛡️ Data Protection & Encryption
- Encryption status detection (at-rest, in-transit)
- KMS key rotation monitoring
- Encryption gap analysis
- Protection recommendations

### 🔗 Data Lineage
- Track data flows across services
- Map ETL pipelines and transformations
- Impact analysis for changes
- Cross-service dependency tracking

### 📊 Data Activity Monitoring
- Real-time access event tracking
- Anomaly detection (unusual patterns)
- Geographic anomaly detection
- Alert generation and notifications

### 🌍 Data Residency
- Geographic location tracking
- Residency policy enforcement
- Cross-border transfer detection
- Region compliance mapping

### ✅ Data Compliance
- GDPR, CCPA, HIPAA compliance checks
- Data retention policy enforcement
- Right to deletion tracking
- Compliance audit trails

## Architecture

### Key Design: Reuse & Enrich

**The Data Security Engine reuses existing configScan rules** from the centralized rule database (`engines-input/aws-configScan-engine/input/rule_db/default/services/`) and enriches metadata files with `data_security` sections. No new YAML rules are created - we reuse the extensive rule base and add data-specific analysis on top.

**Key Components:**
- **Rule Database Reader**: Reads enriched metadata from rule_db
- **ConfigScan Reader**: Reads findings from configScan output
- **Rule Mapper**: Maps findings to data security modules
- **Finding Enricher**: Adds data_security context to findings
- **Analyzers**: Python-based analyzers for classification, lineage, residency, activity
- **Reporter**: Generates unified data security reports

See [UPDATED_ARCHITECTURE_PLAN.md](./UPDATED_ARCHITECTURE_PLAN.md) and [DEPENDENCIES_AND_INTEGRATION.md](./DEPENDENCIES_AND_INTEGRATION.md) for detailed architecture.

## Quick Start

### Prerequisites

- Python 3.9+
- AWS credentials configured (for AWS scanning)
- Access to threat-engine repository structure

### Local Development

```bash
# Install dependencies
cd data-security-engine
pip install -r requirements.txt

# Run API server
python -m uvicorn data_security_engine.api_server:app --reload --port 8000
```

### Docker

```bash
# Build image
docker build -t data-security-engine:latest .

# Run container
docker run -p 8006:8000 \
  -e USE_S3=false \
  -e SCAN_RESULTS_DIR=/data \
  -v /path/to/engines-output:/data \
  data-security-engine:latest
```

## API Endpoints

### POST `/api/v1/data-security/scan`
Trigger comprehensive data security scan.

**Request:**
```json
{
  "csp": "aws",
  "scan_id": "full_scan_all",
  "tenant_id": "tenant-123",
  "include_classification": true,
  "include_lineage": true,
  "include_residency": true,
  "include_activity": true
}
```

**Response:**
Returns complete data security report with:
- Enriched configScan findings (with data_security context)
- Classification results (PII/PCI/PHI detection)
- Lineage mapping (data flows)
- Residency compliance status
- Activity monitoring (anomalies)

### GET `/api/v1/data-security/catalog`
Get discovered data catalog.

### GET `/api/v1/data-security/governance/{resource_id}`
Get access governance analysis.

### GET `/api/v1/data-security/protection/{resource_id}`
Get encryption/protection status.

### GET `/api/v1/data-security/rules/{rule_id}`
Get data security information for a rule (with enriched metadata).

### GET `/api/v1/data-security/modules/{module}/rules`
Get all rules for a specific data security module.

## Integration

### With Rule Database (Source of Truth)
- **Location**: `engines-input/aws-configScan-engine/input/rule_db/default/services/`
- **Enrichment**: Metadata files enriched with `data_security` sections
- **Reuse**: 100% reuse of existing configScan rules (no duplication)

### With ConfigScan Engines
- **Reads**: `engines-output/{csp}-configScan-engine/output/{scan_id}/results.ndjson` (findings)
- **Reads**: `engines-output/{csp}-configScan-engine/output/{scan_id}/inventory_*.ndjson` (assets)
- **Reuses**: All data-related rules from configScan (S3, RDS, DynamoDB encryption, access, logging, etc.)

### With Inventory Engine
Uses asset inventory for resource context and relationships.

### With Threat Engine
Shares data security findings to enhance threat detection.

### With Compliance Engine
Provides data-specific compliance insights.

## Output Format

### Data Catalog (Discovery)
```json
{
  "schema_version": "cspm_data_catalog.v1",
  "data_store_id": "arn:aws:s3:::my-bucket",
  "data_store_type": "s3_bucket",
  "classification": ["PII", "PCI"],
  "sensitivity_score": 8.5,
  "metadata": {...}
}
```

### Access Governance
```json
{
  "schema_version": "cspm_access_governance.v1",
  "data_resource_id": "arn:aws:s3:::my-bucket",
  "access_grants": [...],
  "public_access": false,
  "compliance_status": "non_compliant"
}
```

### Data Security Report
```json
{
  "schema_version": "cspm_data_security_report.v1",
  "scan_context": {...},
  "summary": {
    "total_data_stores": 150,
    "classified_resources": 45,
    "encryption_coverage": 85.0,
    "compliance_score": 72.5
  },
  "findings": [...],
  "recommendations": [...]
}
```

## Storage Layout

### S3 Structure
```
s3://cspm-lgtech/data-security-engine/output/{tenant_id}/{scan_run_id}/
  discovery/
    data_catalog.ndjson
  governance/
    access_analysis.ndjson
  protection/
    encryption_status.ndjson
  reports/
    data_security_report.json
```

### Local Structure
```
engines-output/data-security-engine/output/{tenant_id}/{scan_run_id}/
  [same structure as S3]
```

## Environment Variables

- `USE_S3`: Set to `"true"` to use S3 storage (default: `"false"`)
- `S3_BUCKET`: S3 bucket name (default: `cspm-lgtech`)
- `SCAN_RESULTS_DIR`: Local output directory
- `PORT`: API server port (default: `8000`)

## Port Mapping

- **Local**: Port 8006 (host) → 8000 (container)
- **EKS**: Port 80 (service) → 8000 (container)

## Implementation Status

### Completed ✅
- ✅ Phase 1: Metadata Enrichment - Script created, S3 rules enriched (54 rules)
- ✅ Phase 2: Core Engine - Input readers, rule mapper, finding enricher
- ✅ Phase 3: Analyzers - Classification, lineage, residency, activity analyzers
- ✅ Phase 4: Reporting & API - Unified reporter and FastAPI server

### In Progress
- ⏳ Metadata enrichment for RDS, DynamoDB, Redshift
- ⏳ Testing and integration validation

See [UPDATED_ARCHITECTURE_PLAN.md](./UPDATED_ARCHITECTURE_PLAN.md) for detailed implementation plan.

## Contributing

Follow the same patterns and conventions used in the threat-engine repository:
- Use FastAPI for API servers
- Output NDJSON for scan results
- Follow schema versioning conventions
- Include comprehensive error handling

## License

Same license as threat-engine repository.

## References

- [Threat Engine README](../threat-engine/README.md)
- [Inventory Engine README](../inventory-engine/README.md)
- [Compliance Engine Architecture](../compliance-engine/ARCHITECTURE.md)

