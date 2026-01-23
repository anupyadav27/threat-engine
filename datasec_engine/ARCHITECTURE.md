# Data Security Engine Architecture

## Overview

The Data Security Engine is a comprehensive CSPM data security module that provides data discovery, classification, access governance, protection, lineage tracking, activity monitoring, residency management, and compliance reporting. It integrates seamlessly with the existing threat-engine ecosystem.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Data Security Engine                              │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. Data Discovery & Classification Module                    │  │
│  │     - Catalog data stores (S3, RDS, DynamoDB, etc.)          │  │
│  │     - Automatic classification (PII, PCI, PHI, etc.)         │  │
│  │     - Sensitive data patterns & ML-based detection            │  │
│  │     - Classification tagging & metadata enrichment            │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  2. Data Access Governance Module                             │  │
│  │     - IAM policy analysis (who can access what)              │  │
│  │     - Access pattern analysis                                 │  │
│  │     - Privileged access identification                        │  │
│  │     - Access review & remediation                             │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  3. Data Protection & Encryption Module                       │  │
│  │     - Encryption status detection (at-rest, in-transit)      │  │
│  │     - KMS key rotation & management                           │  │
│  │     - Encryption gap analysis                                 │  │
│  │     - Encryption recommendations                              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  4. Data Lineage Module                                       │  │
│  │     - Data flow mapping (ETL, pipelines, transformations)    │  │
│  │     - Cross-service dependencies                             │  │
│  │     - Data source tracking                                    │  │
│  │     - Impact analysis (change impact)                         │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  5. Data Activity Monitoring Module                           │  │
│  │     - CloudTrail/CloudWatch Logs analysis                    │  │
│  │     - Access event detection                                 │  │
│  │     - Anomaly detection (unusual access patterns)            │  │
│  │     - Real-time alerts & notifications                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  6. Data Residency Module                                     │  │
│  │     - Geographic location tracking                            │  │
│  │     - Residency policy compliance                             │  │
│  │     - Cross-border data transfer detection                    │  │
│  │     - Region compliance mapping                               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  7. Data Compliance Module                                    │  │
│  │     - GDPR, CCPA, HIPAA compliance checks                    │  │
│  │     - Data retention policy enforcement                       │  │
│  │     - Right to deletion tracking                              │  │
│  │     - Compliance reporting & audit trails                     │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Integration Layer                                 │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │ ConfigScan   │  │  Inventory   │  │   Threat     │            │
│  │  Engines     │  │   Engine     │  │   Engine     │            │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘            │
│         │                  │                  │                     │
│         └──────────────────┼──────────────────┘                     │
│                            │                                        │
│                    ┌───────▼────────┐                               │
│                    │  Shared Data   │                               │
│                    │   (S3/NDJSON)  │                               │
│                    └────────────────┘                               │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Design

### 1. Data Discovery & Classification

**Purpose**: Automatically discover data stores and classify sensitive data.

**Components**:
- `discovery/scan_scanner.py`: Scan cloud resources for data stores
- `discovery/classifier.py`: Classify data using patterns/ML
- `discovery/tagger.py`: Apply classification tags/metadata
- `schemas/discovery_schema.py`: Data catalog schema

**Data Stores Supported**:
- **AWS**: S3, RDS, DynamoDB, Redshift, DocumentDB, ElastiCache, EBS, EFS, Glue Data Catalog
- **Azure**: Blob Storage, SQL Database, Cosmos DB, Data Lake
- **GCP**: Cloud Storage, BigQuery, Cloud SQL, Firestore
- **Others**: Databases, object storage, data warehouses

**Classification Categories**:
- PII (Personally Identifiable Information)
- PCI (Payment Card Industry data)
- PHI (Protected Health Information)
- Financial data
- Intellectual Property
- Credentials/Secrets
- Custom patterns (regex, ML models)

**Output Schema**: `cspm_data_catalog.v1`
```json
{
  "data_store_id": "arn:aws:s3:::my-bucket",
  "data_store_type": "s3_bucket",
  "classification": ["PII", "PCI"],
  "sensitivity_score": 8.5,
  "sample_data": {...},
  "classification_confidence": 0.95,
  "metadata": {...}
}
```

### 2. Data Access Governance

**Purpose**: Analyze and govern who has access to what data.

**Components**:
- `governance/access_analyzer.py`: Analyze IAM policies for data access
- `governance/privilege_detector.py`: Identify excessive privileges
- `governance/policy_reviewer.py`: Review and suggest remediation
- `schemas/governance_schema.py`: Access governance schema

**Analysis Capabilities**:
- IAM policy → data resource mapping
- Principal → data access matrix
- Privilege escalation risks
- Public access detection
- Cross-account access analysis
- Service account permissions

**Output Schema**: `cspm_access_governance.v1`
```json
{
  "data_resource_id": "arn:aws:s3:::my-bucket",
  "access_grants": [
    {
      "principal": "arn:aws:iam::123456789012:user/admin",
      "permissions": ["s3:GetObject", "s3:PutObject"],
      "access_type": "explicit",
      "risk_level": "high"
    }
  ],
  "public_access": false,
  "compliance_status": "non_compliant"
}
```

### 3. Data Protection & Encryption

**Purpose**: Monitor encryption status and recommend improvements.

**Components**:
- `protection/encryption_scanner.py`: Scan encryption status
- `protection/kms_analyzer.py`: Analyze KMS key usage
- `protection/gap_analyzer.py`: Identify encryption gaps
- `schemas/protection_schema.py`: Protection status schema

**Checks**:
- Encryption at rest (S3, RDS, EBS, etc.)
- Encryption in transit (TLS/SSL)
- KMS key rotation status
- Encryption key access policies
- Encryption algorithm strength

**Output Schema**: `cspm_data_protection.v1`
```json
{
  "data_resource_id": "arn:aws:s3:::my-bucket",
  "encryption_at_rest": {
    "enabled": true,
    "algorithm": "AES256",
    "kms_key_id": "arn:aws:kms:...",
    "rotation_enabled": true
  },
  "encryption_in_transit": {
    "enforced": true,
    "tls_version": "1.2+"
  },
  "protection_score": 9.0
}
```

### 4. Data Lineage

**Purpose**: Track data flow and dependencies across services.

**Components**:
- `lineage/flow_mapper.py`: Map data flows between services
- `lineage/dependency_tracker.py`: Track dependencies
- `lineage/impact_analyzer.py`: Analyze change impact
- `schemas/lineage_schema.py`: Lineage graph schema

**Lineage Sources**:
- ETL job logs (Glue, EMR, Data Pipeline)
- CloudTrail data access events
- S3 event notifications
- Database replication logs
- API gateway logs
- Inventory engine relationships

**Output Schema**: `cspm_data_lineage.v1`
```json
{
  "data_resource_id": "arn:aws:s3:::output-bucket/data.json",
  "lineage": {
    "upstream": [
      {
        "resource_id": "arn:aws:s3:::source-bucket/raw.csv",
        "relationship": "transformed_from",
        "transformation": "ETL job: glue-job-123"
      }
    ],
    "downstream": [
      {
        "resource_id": "arn:aws:redshift:...:cluster:prod",
        "relationship": "consumed_by",
        "transformation": "COPY command"
      }
    ]
  }
}
```

### 5. Data Activity Monitoring

**Purpose**: Monitor data access events and detect anomalies.

**Components**:
- `monitoring/event_collector.py`: Collect CloudTrail/log events
- `monitoring/anomaly_detector.py`: Detect unusual patterns
- `monitoring/alert_manager.py`: Generate alerts
- `schemas/monitoring_schema.py`: Activity monitoring schema

**Event Sources**:
- CloudTrail (S3, DynamoDB, RDS API calls)
- CloudWatch Logs
- VPC Flow Logs
- Database audit logs
- Application logs

**Detection Capabilities**:
- Unusual access patterns
- Bulk data exfiltration
- Off-hours access
- Geographic anomalies
- Failed access attempts
- Privileged user activity

**Output Schema**: `cspm_data_activity.v1`
```json
{
  "event_id": "evt_123",
  "timestamp": "2024-01-15T10:30:00Z",
  "data_resource_id": "arn:aws:s3:::my-bucket",
  "principal": "arn:aws:iam::123456789012:user/alice",
  "action": "s3:GetObject",
  "ip_address": "203.0.113.42",
  "location": "US",
  "anomaly_score": 8.5,
  "risk_level": "high",
  "alert_triggered": true
}
```

### 6. Data Residency

**Purpose**: Track data location and enforce residency policies.

**Components**:
- `residency/location_tracker.py`: Track data geographic location
- `residency/policy_enforcer.py`: Enforce residency policies
- `residency/transfer_detector.py`: Detect cross-border transfers
- `schemas/residency_schema.py`: Residency schema

**Capabilities**:
- Region/availability zone tracking
- Residency policy definition
- Policy compliance checking
- Cross-border transfer detection
- Replication location tracking

**Output Schema**: `cspm_data_residency.v1`
```json
{
  "data_resource_id": "arn:aws:s3:::my-bucket",
  "primary_region": "us-east-1",
  "replication_regions": ["eu-west-1"],
  "residency_policy": {
    "allowed_regions": ["us-east-1", "us-west-2"],
    "policy_name": "US-only-residency"
  },
  "compliance_status": "compliant",
  "cross_border_transfers": []
}
```

### 7. Data Compliance

**Purpose**: Ensure data handling meets regulatory requirements.

**Components**:
- `compliance/gdpr_checker.py`: GDPR compliance checks
- `compliance/ccpa_checker.py`: CCPA compliance checks
- `compliance/hipaa_checker.py`: HIPAA compliance checks
- `compliance/audit_generator.py`: Generate compliance reports
- `schemas/compliance_schema.py`: Data compliance schema

**Compliance Frameworks**:
- GDPR (General Data Protection Regulation)
- CCPA (California Consumer Privacy Act)
- HIPAA (Health Insurance Portability and Accountability Act)
- PCI DSS (Payment Card Industry Data Security Standard)
- SOX (Sarbanes-Oxley Act)
- Custom regulatory requirements

**Output Schema**: `cspm_data_compliance.v1`
```json
{
  "data_resource_id": "arn:aws:s3:::my-bucket",
  "compliance_frameworks": {
    "GDPR": {
      "compliant": false,
      "violations": [
        {
          "article": "Article 32",
          "requirement": "Encryption of personal data",
          "status": "FAIL"
        }
      ]
    }
  },
  "overall_compliance_score": 65.0
}
```

## Data Flow

```
1. ConfigScan Engine Output (NDJSON)
   ↓
2. Data Discovery Scanner
   → Discovers data stores (S3, RDS, etc.)
   → Outputs: data_catalog.ndjson
   ↓
3. Classification Engine
   → Classifies discovered data
   → Outputs: classified_data.ndjson
   ↓
4. Data Security Analyzers (parallel)
   → Access Governance Analyzer
   → Protection Scanner
   → Lineage Mapper
   → Activity Monitor
   → Residency Tracker
   → Compliance Checker
   ↓
5. Data Security Report Generator
   → Aggregates all findings
   → Generates unified report
   → Outputs: data_security_report.json
```

## Directory Structure

```
data-security-engine/
├── data_security_engine/
│   ├── schemas/
│   │   ├── discovery_schema.py
│   │   ├── governance_schema.py
│   │   ├── protection_schema.py
│   │   ├── lineage_schema.py
│   │   ├── monitoring_schema.py
│   │   ├── residency_schema.py
│   │   ├── compliance_schema.py
│   │   └── report_schema.py
│   ├── discovery/
│   │   ├── scan_scanner.py
│   │   ├── classifier.py
│   │   └── tagger.py
│   ├── governance/
│   │   ├── access_analyzer.py
│   │   ├── privilege_detector.py
│   │   └── policy_reviewer.py
│   ├── protection/
│   │   ├── encryption_scanner.py
│   │   ├── kms_analyzer.py
│   │   └── gap_analyzer.py
│   ├── lineage/
│   │   ├── flow_mapper.py
│   │   ├── dependency_tracker.py
│   │   └── impact_analyzer.py
│   ├── monitoring/
│   │   ├── event_collector.py
│   │   ├── anomaly_detector.py
│   │   └── alert_manager.py
│   ├── residency/
│   │   ├── location_tracker.py
│   │   ├── policy_enforcer.py
│   │   └── transfer_detector.py
│   ├── compliance/
│   │   ├── gdpr_checker.py
│   │   ├── ccpa_checker.py
│   │   ├── hipaa_checker.py
│   │   └── audit_generator.py
│   ├── reporter/
│   │   └── data_security_reporter.py
│   ├── connectors/
│   │   ├── aws_connector.py
│   │   ├── azure_connector.py
│   │   └── gcp_connector.py
│   └── api_server.py
├── Dockerfile
├── requirements.txt
└── README.md
```

## API Endpoints

### POST `/api/v1/data-security/scan`
Trigger comprehensive data security scan.

**Request:**
```json
{
  "tenant_id": "tenant-123",
  "scan_run_id": "scan-456",
  "cloud": "aws",
  "accounts": ["123456789012"],
  "regions": ["us-east-1"],
  "modules": [
    "discovery",
    "governance",
    "protection",
    "lineage",
    "monitoring",
    "residency",
    "compliance"
  ]
}
```

### GET `/api/v1/data-security/catalog`
Get data catalog (discovered data stores).

### GET `/api/v1/data-security/governance/{resource_id}`
Get access governance analysis for a resource.

### GET `/api/v1/data-security/protection/{resource_id}`
Get encryption/protection status for a resource.

### GET `/api/v1/data-security/lineage/{resource_id}`
Get data lineage graph for a resource.

### GET `/api/v1/data-security/activity/{resource_id}`
Get recent activity for a resource.

### GET `/api/v1/data-security/compliance/{resource_id}`
Get compliance status for a resource.

### GET `/api/v1/data-security/report/{report_id}`
Get comprehensive data security report.

## Integration Points

### With ConfigScan Engines
- **Input**: Scan results NDJSON (identifies data resources)
- **Location**: `engines-output/{csp}-configScan-engine/output/`

### With Inventory Engine
- **Input**: Asset inventory (provides resource metadata)
- **Usage**: Enriches data discovery with asset context

### With Threat Engine
- **Input**: Threat findings (data-related threats)
- **Output**: Enhanced threats with data security context

### With Compliance Engine
- **Input**: Compliance mappings (data compliance requirements)
- **Output**: Data-specific compliance findings

## Storage Layout

### S3 Structure
```
s3://cspm-lgtech/data-security-engine/output/{tenant_id}/{scan_run_id}/
  discovery/
    data_catalog.ndjson
    classified_data.ndjson
  governance/
    access_analysis.ndjson
  protection/
    encryption_status.ndjson
  lineage/
    data_lineage.ndjson
  monitoring/
    activity_events.ndjson
    anomalies.ndjson
  residency/
    location_map.ndjson
  compliance/
    compliance_status.ndjson
  reports/
    data_security_report.json
```

### Local Structure
```
engines-output/data-security-engine/output/{tenant_id}/{scan_run_id}/
  [same structure as S3]
```

## Next Steps (Implementation Phases)

### Phase 1: Foundation (Weeks 1-2)
- Set up project structure
- Implement data discovery module
- Basic classification (pattern-based)
- AWS S3 discovery

### Phase 2: Core Modules (Weeks 3-5)
- Access governance analyzer
- Encryption scanner
- Basic data lineage
- AWS-focused implementation

### Phase 3: Advanced Features (Weeks 6-8)
- Activity monitoring
- Anomaly detection
- Data residency tracking
- Compliance checkers

### Phase 4: Multi-Cloud & Polish (Weeks 9-10)
- Azure connector
- GCP connector
- ML-based classification
- Performance optimization
- Documentation

## Technology Stack

- **Language**: Python 3.9+
- **Framework**: FastAPI
- **Data Processing**: Pandas, PySpark (for large datasets)
- **ML/Classification**: scikit-learn, regex patterns
- **Graph/Lineage**: NetworkX, Neo4j (optional)
- **Cloud SDKs**: boto3 (AWS), azure-sdk, google-cloud-sdk
- **Storage**: S3, local NDJSON files
- **Database**: PostgreSQL (optional, for indexes)
- **Containerization**: Docker

