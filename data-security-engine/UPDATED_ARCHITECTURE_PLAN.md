# Data Security Engine - Updated Architecture Plan

## Overview

Data Security Engine provides comprehensive data security capabilities (discovery, classification, access governance, protection, lineage, activity monitoring, residency, compliance) by **reusing and enriching** existing configScan rules from the centralized rule database.

## Key Design Decisions

### 1. Rule Reuse Strategy ✅

**DO NOT CREATE NEW RULES** - Reuse existing configScan rules:
- Source: `engines-input/aws-configScan-engine/input/rule_db/default/services/`
- This is the **single source of truth** for all engines
- Both configScan and data-security-engine read from same rule_db

### 2. Metadata Enrichment Approach ✅

**Enrich existing metadata files** in rule_db with `data_security` sections:
- Add `data_security` field to relevant metadata files
- Map rules to data security modules
- Add compliance context (GDPR, PCI, HIPAA)
- No duplication - enrich at source

### 3. Services of Interest

**Primary Data Storage Services:**
- `s3/` - Object storage (64 metadata files)
- `rds/` - Relational databases (63 metadata files)
- `dynamodb/` - NoSQL databases (23 metadata files)
- `redshift/` - Data warehouse (52 metadata files)
- `glacier/` - Archive storage (27 metadata files)

**Supporting Services:**
- `cloudtrail/` - Audit logs (43 metadata files)
- `kms/` - Encryption keys (49 metadata files)
- `macie/` - Data classification (14 metadata files)

## Architecture

### Rule Database Structure (Source of Truth)

```
engines-input/aws-configScan-engine/input/rule_db/default/services/
├── s3/
│   ├── rules/s3.yaml                    # Rule logic (unchanged)
│   └── metadata/
│       ├── aws.s3.bucket.encryption_at_rest_enabled.yaml  # ENRICHED with data_security
│       ├── aws.s3.bucket.public_access_configured.yaml    # ENRICHED
│       ├── aws.s3.bucket.server_access_logging_enabled.yaml  # ENRICHED
│       └── ...
├── rds/
│   ├── rules/rds.yaml
│   └── metadata/                        # ENRICHED metadata files
├── dynamodb/
└── redshift/
```

### Data Security Engine Structure

```
data-security-engine/
├── data_security_engine/
│   ├── input/
│   │   ├── rule_db_reader.py           # Reads from engines-input/rule_db
│   │   └── configscan_reader.py        # Reads configScan output (findings)
│   ├── mapper/
│   │   └── rule_to_module_mapper.py    # Maps rule_ids to data security modules
│   ├── enricher/
│   │   └── finding_enricher.py         # Enriches findings with data_security context
│   ├── analyzer/
│   │   ├── classification_analyzer.py  # NEW: PII/PCI/PHI detection (not in configScan)
│   │   ├── lineage_analyzer.py        # NEW: Data flow tracking
│   │   ├── residency_analyzer.py      # NEW: Geographic policy checks
│   │   └── activity_analyzer.py       # NEW: Anomaly detection
│   ├── reporter/
│   │   └── data_security_reporter.py   # Generates unified reports
│   └── api_server.py
├── config/
│   └── rule_module_mapping.yaml        # Maps rule_ids to data security modules
└── scripts/
    └── enrich_metadata.py              # Script to add data_security to metadata files
```

## Metadata Enrichment Format

### Before (Current Metadata)

```yaml
rule_id: aws.s3.bucket.encryption_at_rest_enabled
service: s3
resource: bucket
requirement: Encryption at Rest
title: Create immutable backup copies
scope: s3.bucket.backup_recovery
domain: resilience_and_disaster_recovery
subcategory: malware_protection
rationale: Backups must be stored in immutable format...
severity: medium
compliance:
  - iso27001_2022_multi_cloud_A.8.11_0066
  - nist_800_53_rev5_multi_cloud_SC-28_1_1280
description: Verifies that Amazon S3 bucket has encryption...
remediation: Enable S3 bucket encryption at rest...
```

### After (Enriched with Data Security)

```yaml
rule_id: aws.s3.bucket.encryption_at_rest_enabled
service: s3
resource: bucket
requirement: Encryption at Rest
title: Create immutable backup copies
scope: s3.bucket.backup_recovery
domain: resilience_and_disaster_recovery
subcategory: malware_protection
rationale: Backups must be stored in immutable format...
severity: medium
compliance:
  - iso27001_2022_multi_cloud_A.8.11_0066
  - nist_800_53_rev5_multi_cloud_SC-28_1_1280

# NEW: Data Security Module Mapping
data_security:
  applicable: true
  modules:
    - data_protection_encryption
    - data_compliance
  categories:
    - encryption_at_rest
    - sensitive_data_protection
  priority: high
  impact:
    gdpr: "Article 32 - Encryption requirement for personal data"
    pci: "Requirement 3.4 - Render PAN unreadable via encryption"
    hipaa: "§164.312(a)(2)(iv) - Encryption of ePHI at rest"
  sensitive_data_context: |
    Encryption at rest is mandatory for all buckets containing:
    - PII (personally identifiable information)
    - PCI data (credit card information)
    - PHI (protected health information)
    - Financial records
  related_data_checks:
    - aws.s3.bucket.default_encryption_configured
    - aws.s3.bucket.kms_encryption_configured

description: Verifies that Amazon S3 bucket has encryption...
remediation: Enable S3 bucket encryption at rest...
```

## Rule-to-Module Mapping

### Data Security Modules

#### 1. Data Protection & Encryption

**Rules to Enrich:**
- `aws.s3.bucket.encryption_at_rest_enabled`
- `aws.s3.bucket.s3_encrypted_at_rest`
- `aws.s3.bucket.default_encryption_configured`
- `aws.s3.bucket.kms_encryption_configured`
- `aws.s3.bucket.cmk_cmek_configured`
- `aws.rds.db_instance.encryption_at_rest_enabled`
- `aws.dynamodb.table.encryption_enabled`
- `aws.redshift.cluster.encryption_enabled`

**Services:** S3, RDS, DynamoDB, Redshift, KMS

#### 2. Data Access Governance

**Rules to Enrich:**
- `aws.s3.bucket.public_access_configured`
- `aws.s3.bucket.block_public_access_enabled`
- `aws.s3.bucketpolicy.no_public_principals_configured`
- `aws.s3.bucket.rbac_least_privilege`
- `aws.rds.db_instance.publicly_accessible`
- `aws.dynamodb.table.public_access_restricted`

**Services:** S3, RDS, DynamoDB, IAM

#### 3. Data Activity Monitoring

**Rules to Enrich:**
- `aws.s3.bucket.server_access_logging_enabled`
- `aws.s3.bucket.access_logging_enabled`
- `aws.s3.bucket.object_level_write_logging_enabled`
- `aws.cloudtrail.trail.logging_enabled`
- `aws.rds.db_instance.audit_logging_enabled`

**Services:** S3, CloudTrail, RDS, CloudWatch

#### 4. Data Residency

**Rules to Enrich:**
- Region-based checks (use inventory region info)
- Cross-region replication rules
- Geographic restriction policies

**Services:** All storage services (region from inventory)

#### 5. Data Compliance

**Rules to Enrich:**
- `aws.s3.bucket.retention_days_minimum`
- `aws.s3.bucket.lifecycle_policy_configured`
- `aws.s3.bucket.immutable_or_worm_enabled_if_supported`
- `aws.rds.db_instance.backup_retention_period`

**Services:** S3, RDS, Glacier

#### 6. Data Classification

**Partially Covered:**
- `aws.s3.macie_classification_jobs_status.macie_classification_jobs_status_configured` (checks Macie config, not actual classification)

**NEW Checks Needed:**
- Actual PII/PCI/PHI detection in object content (Python-based, not YAML rules)

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│           Rule Database (Single Source of Truth)             │
│  engines-input/.../rule_db/default/services/                │
│  ├── s3/metadata/*.yaml (ENRICHED with data_security)       │
│  ├── rds/metadata/*.yaml (ENRICHED)                         │
│  └── ...                                                     │
└─────────────────┬───────────────────────────────────────────┘
                  │
      ┌───────────┴───────────┐
      │                       │
┌─────▼──────┐       ┌────────▼─────────┐
│ ConfigScan │       │ Data Security    │
│ Engine     │       │ Engine           │
└─────┬──────┘       └────────┬─────────┘
      │                       │
      │ Reads rules           │ Reads enriched rules
      │                       │
      ▼                       ▼
┌─────────────────────────────────────────┐
│     ConfigScan Output                   │
│  engines-output/.../configScan-engine/  │
│  ├── results.ndjson                     │
│  ├── inventory_*.ndjson                 │
│  └── raw/                               │
└─────────────┬───────────────────────────┘
              │
              │ Data Security Engine reads:
              │ - Findings from results.ndjson
              │ - Assets from inventory
              │ - Enriched metadata from rule_db
              │
              ▼
┌─────────────────────────────────────────┐
│     Data Security Analysis              │
│  - Reuse configScan findings            │
│  - Map to data security modules         │
│  - Add classification (NEW)             │
│  - Add lineage tracking (NEW)           │
│  - Add residency checks (NEW)           │
│  - Add activity monitoring (NEW)        │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│     Data Security Output                │
│  engines-output/data-security-engine/   │
│  └── data_security_report.json          │
└─────────────────────────────────────────┘
```

## Implementation Phases

### Phase 1: Metadata Enrichment (Weeks 1-2)

**Task 1.1: Identify Rules to Enrich**
- Create script to scan rule_db services (s3, rds, dynamodb, redshift)
- Identify rules relevant to data security modules
- Generate mapping: rule_id → data_security module

**Task 1.2: Enrich Metadata Files**
- Add `data_security` sections to identified metadata files
- Start with S3 rules (most comprehensive)
- Then RDS, DynamoDB, Redshift

**Task 1.3: Create Mapping Configuration**
- Create `config/rule_module_mapping.yaml`
- Document all enriched rules and their mappings

**Deliverables:**
- ✅ Enriched metadata files in rule_db (S3, RDS, DynamoDB)
- ✅ Mapping configuration file
- ✅ Documentation of enrichment process

### Phase 2: Data Security Engine - Core (Weeks 3-4)

**Task 2.1: Input Readers**
- `rule_db_reader.py` - Read enriched metadata from rule_db
- `configscan_reader.py` - Read configScan findings/inventory

**Task 2.2: Rule Mapper**
- `rule_to_module_mapper.py` - Map findings to data security modules
- Use enriched metadata `data_security.modules` field

**Task 2.3: Finding Enricher**
- `finding_enricher.py` - Add data_security context to findings
- Enrich with module categories, compliance impact

**Deliverables:**
- ✅ Input readers working
- ✅ Rule mapper functional
- ✅ Findings enriched with data_security context

### Phase 3: Data-Specific Analyzers (Weeks 5-7)

**Task 3.1: Classification Analyzer (NEW)**
- Python-based PII/PCI/PHI detection
- Scan S3 objects for sensitive data patterns
- Not YAML rules - direct API calls + pattern matching

**Task 3.2: Lineage Analyzer (NEW)**
- Track data flows using CloudTrail logs
- Build data flow graphs
- Map transformations (S3 → ETL → Redshift)

**Task 3.3: Residency Analyzer (NEW)**
- Geographic location tracking
- Policy enforcement checks
- Cross-border transfer detection

**Task 3.4: Activity Analyzer (NEW)**
- Anomaly detection on access logs
- Unusual pattern identification
- Real-time alert generation

**Deliverables:**
- ✅ Classification working for S3
- ✅ Basic lineage tracking
- ✅ Residency policy checks
- ✅ Activity anomaly detection

### Phase 4: Reporting & Integration (Weeks 8-9)

**Task 4.1: Unified Reporter**
- Aggregate enriched configScan findings
- Combine with new analysis (classification, lineage, etc.)
- Generate comprehensive data security reports

**Task 4.2: API Server**
- FastAPI endpoints for data security queries
- Report generation endpoints
- Query/filter capabilities

**Task 4.3: Integration Testing**
- Test with real configScan output
- Verify enriched metadata usage
- End-to-end data flow validation

**Deliverables:**
- ✅ Unified reporting system
- ✅ Working API endpoints
- ✅ Integration with configScan tested

### Phase 5: Documentation & Polish (Week 10)

**Task 5.1: Documentation**
- Update architecture docs
- API documentation
- User guide

**Task 5.2: Performance Optimization**
- Optimize classification scanning
- Cache enriched metadata
- Parallel processing

**Deliverables:**
- ✅ Complete documentation
- ✅ Performance optimized
- ✅ Ready for production

## Key Benefits of This Approach

1. **Single Source of Truth** - Rule database is shared, no duplication
2. **Consistency** - Both engines use same rules and metadata
3. **Maintainability** - Enrich once, benefit all engines
4. **Extensibility** - Easy to add new data security categories
5. **Efficiency** - Reuse existing extensive rule base

## Files to Create/Modify

### Modify (Enrich Existing Metadata)
- `engines-input/.../rule_db/default/services/s3/metadata/*.yaml` - Add `data_security` sections
- `engines-input/.../rule_db/default/services/rds/metadata/*.yaml` - Add `data_security` sections
- `engines-input/.../rule_db/default/services/dynamodb/metadata/*.yaml` - Add `data_security` sections

### Create (New Files)
- `data-security-engine/data_security_engine/input/rule_db_reader.py`
- `data-security-engine/data_security_engine/mapper/rule_to_module_mapper.py`
- `data-security-engine/data_security_engine/analyzer/classification_analyzer.py`
- `data-security-engine/scripts/enrich_metadata.py`
- `data-security-engine/config/rule_module_mapping.yaml`

## Success Metrics

1. **Metadata Enrichment**: 80%+ of data-relevant rules enriched
2. **Rule Reuse**: 100% reuse of configScan rules (no duplication)
3. **Module Coverage**: All 6 data security modules covered
4. **Integration**: Seamless reading from rule_db and configScan output

