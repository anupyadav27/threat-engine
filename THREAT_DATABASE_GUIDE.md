# Threat Database - Complete Guide

## Overview

The threat engine now uses **normalized tables** with **metadata-driven threat categorization**:

- **489 threats** detected from 6,089 check failures
- Each threat = 1 database row (queryable!)
- Threat categories from `rule_metadata` (not code patterns)
- Proper links to rule metadata for titles/descriptions

---

## Database Structure

### Connection Info (DBeaver)
```
Database: threat_engine_threat
Host: localhost
Port: 5432
Username: threat_user
Password: threat_password
```

### Tables

| Table | Rows | Purpose |
|-------|------|---------|
| **threat_scans** | 1 | Scan summaries (total counts) |
| **threats** | 489 | Individual threats (one row each) |
| **threat_resources** | 489 | Threat→Resource mappings |
| **drift_records** | 0 | Config & check status drift (populated on 2nd+ scan) |

---

## Current Data (check_20260129_162625)

### Threat Summary
- **Total**: 489 threats
- **Critical**: 6 threats
- **High**: 347 threats
- **Medium**: 136 threats

### By Category
- **Identity**: 240 threats (IAM users, roles, policies)
- **Misconfiguration**: 134 threats (encryption, backup, versioning)
- **Exposure**: 94 threats (public access, internet-facing)
- **Data Exfiltration**: 21 threats (S3 logging/encryption issues)

---

## DBeaver Queries

### 1. View All Critical/High Threats
```sql
SELECT 
    threat_id,
    category,
    severity,
    title,
    misconfig_count,
    primary_rule_id
FROM threats
WHERE severity IN ('critical', 'high')
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        ELSE 3 
    END,
    misconfig_count DESC;
```

### 2. Threats by Category
```sql
-- Identity threats
SELECT * FROM threats WHERE category = 'identity';

-- Exposure threats
SELECT * FROM threats WHERE category = 'exposure';

-- Data exfiltration threats
SELECT * FROM threats WHERE category = 'data_exfiltration';

-- Misconfiguration threats
SELECT * FROM threats WHERE category = 'misconfiguration';
```

### 3. Resources with Most Threats
```sql
SELECT 
    tr.resource_uid,
    tr.resource_type,
    tr.account_id,
    COUNT(DISTINCT t.threat_id) as threat_count,
    string_agg(DISTINCT t.category, ', ') as threat_categories,
    string_agg(DISTINCT t.severity, ', ') as severities
FROM threat_resources tr
JOIN threats t ON tr.threat_id = t.threat_id
GROUP BY tr.resource_uid, tr.resource_type, tr.account_id
ORDER BY threat_count DESC
LIMIT 20;
```

### 4. Specific Resource Analysis
```sql
-- Example: cspm-lgtech S3 bucket has 4 threats!
SELECT 
    t.threat_id,
    t.category,
    t.severity,
    t.misconfig_count,
    tr.failed_rule_ids
FROM threats t
JOIN threat_resources tr ON t.threat_id = tr.threat_id
WHERE tr.resource_uid = 'arn:aws:s3:::cspm-lgtech';
```

### 5. Link Threats to Rule Metadata (Cross-DB Query)
```sql
-- First connect to threat_engine_threat, then:
SELECT 
    t.threat_id,
    t.category,
    t.severity,
    t.primary_rule_id,
    t.misconfig_count
FROM threats t
WHERE t.primary_rule_id IS NOT NULL
LIMIT 10;

-- Then connect to threat_engine_check to see rule details:
SELECT 
    rule_id,
    title,
    description,
    remediation,
    threat_category,
    risk_score,
    threat_tags
FROM rule_metadata
WHERE rule_id = 'aws.iam.group.has_users_configured';
```

### 6. Threat Statistics by Severity
```sql
SELECT 
    severity,
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE category = 'identity') as identity,
    COUNT(*) FILTER (WHERE category = 'exposure') as exposure,
    COUNT(*) FILTER (WHERE category = 'data_exfiltration') as data_exfil,
    COUNT(*) FILTER (WHERE category = 'misconfiguration') as misconfig
FROM threats
GROUP BY severity
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        ELSE 4 
    END;
```

### 7. Failed Rules Per Resource
```sql
SELECT 
    tr.resource_uid,
    tr.resource_type,
    t.category,
    jsonb_array_length(tr.failed_rule_ids) as failed_rule_count,
    tr.failed_rule_ids
FROM threat_resources tr
JOIN threats t ON tr.threat_id = tr.threat_id
WHERE jsonb_array_length(tr.failed_rule_ids) > 10
ORDER BY failed_rule_count DESC;
```

### 8. Check Status for Specific Resource (from Check DB)
```sql
-- Connect to: threat_engine_check

SELECT 
    cr.rule_id,
    cr.status,
    cr.resource_uid,
    rm.severity,
    rm.title,
    rm.threat_category
FROM check_results cr
LEFT JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
WHERE cr.resource_uid = 'arn:aws:s3:::cspm-lgtech'
  AND cr.scan_id = 'check_20260129_162625'
ORDER BY 
    cr.status,
    CASE rm.severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        ELSE 3 
    END;
```

### 9. Drift Records (when available)
```sql
SELECT 
    drift_id,
    resource_uid,
    resource_type,
    config_drift_detected,
    check_status_drift_detected,
    newly_failed_rules,
    newly_passed_rules,
    threat_id
FROM drift_records
WHERE tenant_id = 'test-tenant'
ORDER BY detected_at DESC;
```

---

## API Endpoints (Alternative to DBeaver)

### Setup Port-Forward
```bash
kubectl -n threat-engine-local port-forward svc/threat-service 8020:8020 &
```

### Query Examples
```bash
# Get scan summary
curl "http://localhost:8020/api/v1/threat/scans/check_20260129_162625/summary?tenant_id=test-tenant" | jq

# Get specific threat detail
curl "http://localhost:8020/api/v1/threat/threats/thr_6c62dc6f8119b715?tenant_id=test-tenant" | jq

# Get threats for specific resource
curl "http://localhost:8020/api/v1/threat/resources/arn:aws:s3:::cspm-lgtech/threats?tenant_id=test-tenant" | jq

# Get resource posture (from check DB)
curl "http://localhost:8020/api/v1/threat/resources/arn:aws:s3:::cspm-lgtech/posture?tenant_id=test-tenant" | jq
```

---

## Key Insights from Your Data

### High-Risk Resource: cspm-lgtech S3 Bucket
- **4 different threat types**:
  1. Exposure (high) - 9 public access misconfigs
  2. Data Exfiltration (high) - 12 encryption/logging issues
  3. Misconfiguration (high) - 31 security best practices
  4. Identity (high) - 1 IAM replication role issue

- **Total**: 53 failed checks out of 56 total checks
- **Only 3 passing checks** - needs immediate remediation!

### Critical Identity Threats
- 6 IAM users with 12 misconfigs each
- Primary issue: `aws.iam.group.has_users_configured`
- Users: administrator, ajay, ayushjha, cs_admin_central, ekspod_users, lgtech_admin

---

## Compliance Engine Input

**Question: Should Compliance use check_results or threats?**

**Answer: Use `check_results` table** ✅

**Why:**
- Compliance frameworks map to specific rules (1-to-1)
- Example: CIS AWS 1.2.1 maps to `aws.iam.root.mfa_enabled`
- Compliance needs ALL results (PASS + FAIL) to calculate % compliant
- Threats are grouped/aggregated - loses per-rule granularity

**Compliance Query Example:**
```sql
-- Connect to threat_engine_check
SELECT 
    cr.rule_id,
    cr.status,
    rm.compliance_frameworks,
    rm.severity
FROM check_results cr
JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
WHERE cr.scan_id = 'check_20260129_162625'
  AND rm.compliance_frameworks ? 'cis_aws'  -- Has CIS framework
ORDER BY cr.status, rm.severity;
```

---

## Benefits of Metadata-Driven Approach

✅ **More Threats Detected**: 489 vs 239 (105% increase!)
✅ **Accurate Categorization**: From rule authors, not regex patterns
✅ **Queryable**: Filter by category, severity, resource in DBeaver
✅ **Maintainable**: Update metadata YAML → auto-reflects in threats
✅ **Linked**: `primary_rule_id` → `rule_metadata` for full context
✅ **Scalable**: No 7MB JSON blobs, each threat is a row

**Your threat database is now production-ready!**
