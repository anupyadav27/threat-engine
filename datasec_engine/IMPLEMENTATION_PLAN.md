# Data Security Engine - Implementation Plan

## Overview

This document outlines the step-by-step implementation plan for building the Data Security Engine, aligned with the threat-engine architecture and following industry best practices from tools like Wiz, Orca Security, and Lacework.

## Implementation Phases

### Phase 1: Foundation & Data Discovery (Weeks 1-2)

#### Week 1: Project Setup & S3 Discovery

**Tasks**:
1. **Project Structure Setup**
   - Create `data-security-engine/` directory
   - Set up Python package structure (`data_security_engine/`)
   - Create initial schemas directory
   - Set up `requirements.txt` with dependencies
   - Create `Dockerfile` (aligned with threat-engine pattern)

2. **Core Schema Definitions**
   - `schemas/discovery_schema.py`: Data catalog schema
   - `schemas/report_schema.py`: Unified report schema
   - Define `cspm_data_catalog.v1` schema

3. **AWS S3 Discovery**
   - Implement `discovery/scan_scanner.py` for S3 buckets
   - Use boto3 to list buckets and objects
   - Extract metadata (region, encryption, versioning, etc.)
   - Output to NDJSON format

4. **Basic Classification (Pattern-Based)**
   - Implement `discovery/classifier.py`
   - Common PII patterns (SSN, email, credit card, etc.)
   - Basic regex-based classification
   - Classification confidence scoring

**Deliverables**:
- ✅ Project structure created
- ✅ Basic S3 discovery working
- ✅ Simple pattern-based classification
- ✅ NDJSON output generation

**Files to Create**:
```
data-security-engine/
├── data_security_engine/
│   ├── __init__.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── discovery_schema.py
│   │   └── report_schema.py
│   ├── discovery/
│   │   ├── __init__.py
│   │   ├── scan_scanner.py
│   │   └── classifier.py
│   └── api_server.py
├── Dockerfile
├── requirements.txt
└── README.md
```

#### Week 2: Expand Discovery & Basic Governance

**Tasks**:
1. **Extended Data Store Discovery**
   - RDS databases (encryption status, backups)
   - DynamoDB tables
   - Redshift clusters
   - EBS volumes
   - DocumentDB, ElastiCache

2. **Enhanced Classification**
   - PCI DSS pattern detection
   - HIPAA/PHI patterns
   - Financial data patterns
   - Custom pattern support

3. **Access Governance Foundation**
   - `governance/access_analyzer.py`: Parse IAM policies
   - Map IAM policies to S3 buckets
   - Identify public access (bucket policies, ACLs)
   - Basic privilege detection

4. **API Server Setup**
   - FastAPI server structure (similar to threat-engine)
   - `/api/v1/data-security/scan` endpoint
   - `/api/v1/data-security/catalog` endpoint

**Deliverables**:
- ✅ Multi-resource discovery (S3, RDS, DynamoDB)
- ✅ Enhanced classification
- ✅ Basic access governance analysis
- ✅ Working API endpoints

---

### Phase 2: Core Security Modules (Weeks 3-5)

#### Week 3: Data Protection & Encryption

**Tasks**:
1. **Encryption Scanner**
   - `protection/encryption_scanner.py`
   - Check S3 encryption (SSE-S3, SSE-KMS, SSE-C)
   - RDS encryption status
   - EBS encryption status
   - DynamoDB encryption

2. **KMS Analysis**
   - `protection/kms_analyzer.py`
   - Key rotation status
   - Key access policies
   - Key usage tracking
   - Encryption algorithm strength

3. **Gap Analysis**
   - `protection/gap_analyzer.py`
   - Identify unencrypted resources
   - Recommend encryption improvements
   - Generate remediation suggestions

**Deliverables**:
- ✅ Encryption status scanning
- ✅ KMS key analysis
- ✅ Protection gap reporting

#### Week 4: Data Access Governance Deep Dive

**Tasks**:
1. **Advanced Access Analysis**
   - Cross-account access detection
   - Service account permissions
   - Conditional IAM policies
   - Resource-based policies (S3 bucket policies)

2. **Privilege Escalation Detection**
   - `governance/privilege_detector.py`
   - Detect IAM policies allowing privilege escalation
   - Identify overly permissive policies
   - Risk scoring for access grants

3. **Policy Review & Remediation**
   - `governance/policy_reviewer.py`
   - Generate least-privilege recommendations
   - Policy optimization suggestions
   - Compliance alignment checks

**Deliverables**:
- ✅ Comprehensive access governance analysis
- ✅ Privilege escalation detection
- ✅ Policy remediation recommendations

#### Week 5: Data Lineage Foundation

**Tasks**:
1. **Basic Lineage Mapping**
   - `lineage/flow_mapper.py`
   - Map S3 → ETL → Data Warehouse flows
   - Use CloudTrail events for data access tracking
   - S3 event notifications (PUT, COPY events)

2. **Dependency Tracking**
   - `lineage/dependency_tracker.py`
   - Track dependencies using inventory engine output
   - Build lineage graph (upstream/downstream)
   - Simple transformation tracking

3. **Integration with Inventory Engine**
   - Read from inventory engine relationships
   - Enhance with data-specific relationships
   - Output lineage graph in NDJSON

**Deliverables**:
- ✅ Basic data lineage mapping
- ✅ Dependency graph construction
- ✅ Integration with inventory engine

---

### Phase 3: Advanced Features (Weeks 6-8)

#### Week 6: Data Activity Monitoring

**Tasks**:
1. **Event Collection**
   - `monitoring/event_collector.py`
   - Collect CloudTrail events (S3, DynamoDB, RDS)
   - Parse CloudWatch Logs
   - VPC Flow Logs integration (for data access patterns)

2. **Basic Anomaly Detection**
   - `monitoring/anomaly_detector.py`
   - Statistical anomaly detection (volume, frequency)
   - Off-hours access detection
   - Geographic anomaly detection (unusual locations)

3. **Alert Generation**
   - `monitoring/alert_manager.py`
   - Generate alerts for anomalies
   - Risk scoring for activities
   - Alert aggregation

**Deliverables**:
- ✅ Activity event collection
- ✅ Basic anomaly detection
- ✅ Alert generation system

#### Week 7: Data Residency & Compliance Foundation

**Tasks**:
1. **Location Tracking**
   - `residency/location_tracker.py`
   - Track S3 bucket regions
   - RDS region mapping
   - Replication region detection (S3 cross-region replication)

2. **Residency Policy Enforcement**
   - `residency/policy_enforcer.py`
   - Define residency policies (JSON/YAML)
   - Check compliance against policies
   - Detect cross-border data transfers

3. **Basic Compliance Checks**
   - `compliance/gdpr_checker.py`: Basic GDPR checks
   - Encryption requirements
   - Data retention policies
   - Right to deletion capability

**Deliverables**:
- ✅ Data residency tracking
- ✅ Policy enforcement
- ✅ Basic GDPR compliance checks

#### Week 8: Reporting & Integration

**Tasks**:
1. **Unified Report Generator**
   - `reporter/data_security_reporter.py`
   - Aggregate findings from all modules
   - Generate comprehensive reports
   - Export formats (JSON, CSV)

2. **Integration with Threat Engine**
   - Share data security findings with threat engine
   - Enhanced threat detection with data context
   - Unified reporting

3. **API Enhancements**
   - All module-specific endpoints
   - Report generation endpoints
   - Query/filter capabilities

**Deliverables**:
- ✅ Unified reporting system
- ✅ Threat engine integration
- ✅ Complete API surface

---

### Phase 4: Multi-Cloud & Optimization (Weeks 9-10)

#### Week 9: Azure & GCP Support

**Tasks**:
1. **Azure Connector**
   - `connectors/azure_connector.py`
   - Blob Storage discovery
   - SQL Database encryption checks
   - Azure AD access analysis

2. **GCP Connector**
   - `connectors/gcp_connector.py`
   - Cloud Storage discovery
   - BigQuery data classification
   - Cloud SQL encryption checks

3. **Multi-Cloud Schema Alignment**
   - Unified schema across clouds
   - Cloud-specific adapter patterns

**Deliverables**:
- ✅ Azure data security scanning
- ✅ GCP data security scanning
- ✅ Multi-cloud unified schema

#### Week 10: ML Classification & Performance

**Tasks**:
1. **ML-Based Classification (Optional)**
   - Train simple models for data classification
   - Improve classification accuracy
   - Reduce false positives

2. **Performance Optimization**
   - Parallel scanning for large accounts
   - Caching mechanisms
   - Incremental scanning support

3. **Documentation & Testing**
   - Complete API documentation
   - Unit tests
   - Integration tests
   - User guide

**Deliverables**:
- ✅ ML-enhanced classification (optional)
- ✅ Optimized performance
- ✅ Complete documentation

---

## Technical Decisions

### Schema Versioning
- Follow `cspm_data_*` schema naming (aligned with threat-engine)
- Version schemas: `cspm_data_catalog.v1`, `cspm_data_governance.v1`, etc.
- Backward compatibility considerations

### Data Storage
- **Primary**: NDJSON files (aligned with configScan engines)
- **Secondary**: S3 (when USE_S3=true)
- **Optional**: PostgreSQL for queryable indexes

### API Design
- Follow FastAPI patterns from threat-engine
- RESTful endpoints
- Consistent error handling
- OpenAPI/Swagger documentation

### Classification Approach
- **Phase 1**: Regex patterns (fast, simple)
- **Phase 2**: Pattern libraries (common PII, PCI patterns)
- **Phase 3+**: ML models (improved accuracy)

### Performance Targets
- Scan 1000 S3 buckets: < 5 minutes
- Classify 10K objects: < 10 minutes
- Generate full report: < 15 minutes

---

## Dependencies

### Core Python Libraries
```
fastapi>=0.104.0
uvicorn>=0.24.0
pydantic>=2.0.0
boto3>=1.28.0
pandas>=2.0.0
python-dateutil>=2.8.0
```

### Optional/Advanced
```
scikit-learn>=1.3.0  # ML classification
networkx>=3.0  # Lineage graphs
neo4j>=5.0  # Graph database (optional)
```

---

## Success Metrics

1. **Coverage**: Discover 100% of data stores in scanned accounts
2. **Classification Accuracy**: >90% for common PII patterns
3. **Performance**: Full account scan completes in <30 minutes
4. **Integration**: Seamless integration with threat-engine ecosystem
5. **API Response Time**: <2 seconds for catalog queries

---

## Risk Mitigation

1. **Large Account Performance**: Implement pagination, parallel scanning
2. **Cloud API Rate Limits**: Implement exponential backoff, request throttling
3. **False Positives**: Iterative pattern refinement, ML improvement
4. **Multi-Cloud Complexity**: Abstract cloud-specific logic into connectors
5. **Data Privacy**: Never store actual data content, only metadata/patterns

---

## Next Steps After Phase 4

1. **Advanced Lineage**: Integration with ETL tools (Glue, Airflow)
2. **Real-time Monitoring**: Stream processing for live activity monitoring
3. **Remediation Automation**: Auto-fix capabilities for common issues
4. **Custom Compliance**: Framework builder for custom regulations
5. **Data Catalog UI**: Web interface for data discovery and management

