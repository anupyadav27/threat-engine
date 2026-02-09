# CSPM Platform — Sample API Requests & Responses

## Base URL
```
BASE = http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
```

---

## 1. ONBOARDING

### List Tenants
```http
GET /gateway/api/v1/onboarding/tenants
```
```json
{
  "tenants": [
    {
      "tenant_id": "25a38d4f-...",
      "tenant_name": "Acme Corp",
      "description": "Production tenant",
      "created_at": "2026-01-15T10:30:00Z"
    }
  ]
}
```

### Create Tenant
```http
POST /gateway/api/v1/onboarding/tenants
Content-Type: application/json

{
  "tenant_name": "New Corp",
  "description": "New customer tenant"
}
```
```json
{
  "tenant_id": "b7c91e3a-...",
  "tenant_name": "New Corp",
  "description": "New customer tenant",
  "created_at": "2026-02-09T12:00:00Z"
}
```

### List Accounts
```http
GET /gateway/api/v1/onboarding/accounts?tenant_id=25a38d4f-...&provider_type=aws
```
```json
{
  "accounts": [
    {
      "account_id": "acc-001",
      "account_name": "Production AWS",
      "account_number": "123456789012",
      "provider_type": "aws",
      "status": "active",
      "onboarding_status": "completed",
      "created_at": "2026-01-20T08:00:00Z",
      "last_validated_at": "2026-02-09T06:00:00Z"
    }
  ]
}
```

### Initialize Onboarding (AWS)
```http
POST /gateway/api/v1/onboarding/aws/init
Content-Type: application/json

{
  "tenant_id": "25a38d4f-...",
  "account_name": "Production AWS",
  "auth_method": "iam_role"
}
```
```json
{
  "onboarding_id": "onb-abc123",
  "account_id": "acc-002",
  "provider": "aws",
  "auth_method": "iam_role",
  "account_name": "Production AWS",
  "external_id": "cspm-ext-9f8e7d6c",
  "cloudformation_template_url": "/api/v1/onboarding/aws/cloudformation-template?external_id=cspm-ext-9f8e7d6c"
}
```

### Validate Credentials
```http
POST /gateway/api/v1/onboarding/aws/validate
Content-Type: application/json

{
  "account_id": "acc-002",
  "auth_method": "iam_role",
  "credentials": {
    "role_arn": "arn:aws:iam::123456789012:role/CSPMRole"
  }
}
```
```json
{
  "success": true,
  "message": "Credentials validated successfully",
  "account_id": "acc-002",
  "account_number": "123456789012"
}
```

### Account Health
```http
GET /gateway/api/v1/onboarding/accounts/acc-002/health
```
```json
{
  "account_id": "acc-002",
  "health_status": "healthy",
  "credentials_valid": true,
  "last_validation": "2026-02-09T06:00:00Z",
  "last_scan": "2026-02-09T08:00:00Z",
  "last_scan_status": "completed",
  "issues": []
}
```

---

## 2. ORCHESTRATION (Run Full Scan)

### Start Orchestrated Scan
```http
POST /gateway/gateway/orchestrate
Content-Type: application/json

{
  "customer_id": "cust-001",
  "tenant_id": "tnt_local_test",
  "provider": "aws",
  "hierarchy_id": "123456789012"
}
```
```json
{
  "orchestration_id": "27047875-910e-4267-bd4e-5fc232bc53a5",
  "status": "completed",
  "tenant_id": "tnt_local_test",
  "provider": "aws",
  "engines": {
    "discovery": {
      "status": "completed",
      "scan_id": "disc-a1b2c3",
      "findings_count": 3121
    },
    "check": {
      "status": "completed",
      "scan_id": "chk-d4e5f6",
      "findings_count": 1847
    },
    "threat": {
      "status": "completed",
      "scan_id": "thr-g7h8i9",
      "threats_found": 247
    },
    "inventory": {
      "status": "completed",
      "scan_id": "inv-j0k1l2",
      "assets_count": 3121,
      "relationships_count": 5432
    },
    "compliance": {
      "status": "completed",
      "scan_id": "cmp-m3n4o5"
    },
    "iam": {
      "status": "completed",
      "scan_id": "iam-p6q7r8",
      "findings_count": 65
    },
    "datasec": {
      "status": "completed",
      "scan_id": "ds-s9t0u1",
      "findings_count": 23
    }
  }
}
```

---

## 3. INVENTORY

### List Assets (paginated)
```http
GET /gateway/api/v1/inventory/assets?tenant_id=tnt_local_test&provider=aws&limit=3&offset=0
```
```json
{
  "assets": [
    {
      "resource_uid": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
      "resource_type": "aws_instance",
      "resource_name": "web-server-prod",
      "provider": "aws",
      "account_id": "123456789012",
      "region": "us-east-1",
      "service": "ec2",
      "tags": {"Environment": "production", "Team": "platform"},
      "configuration": {"instance_type": "t3.medium", "state": "running"},
      "scan_run_id": "inv-j0k1l2",
      "created_at": "2026-02-09T08:15:00Z"
    },
    {
      "resource_uid": "arn:aws:s3:::prod-data-bucket",
      "resource_type": "aws_s3_bucket",
      "resource_name": "prod-data-bucket",
      "provider": "aws",
      "account_id": "123456789012",
      "region": "us-east-1",
      "service": "s3",
      "tags": {"DataClass": "confidential"},
      "configuration": {"versioning": true, "encryption": "AES256"}
    }
  ],
  "total": 3121,
  "has_more": true
}
```

### Asset Relationships
```http
GET /gateway/api/v1/inventory/assets/arn:aws:ec2:us-east-1:123456789012:instance%2Fi-0abc123/relationships?tenant_id=tnt_local_test&depth=2
```
```json
{
  "resource_uid": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
  "relationships": {
    "belongs_to": [
      {"resource_uid": "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-abc", "resource_type": "aws_subnet"}
    ],
    "secured_by": [
      {"resource_uid": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123", "resource_type": "aws_security_group"}
    ],
    "uses": [
      {"resource_uid": "arn:aws:iam::123456789012:role/ec2-role", "resource_type": "aws_iam_role"}
    ]
  },
  "total_relationships": 3
}
```

### Graph Data (for visualization)
```http
GET /gateway/api/v1/inventory/graph?tenant_id=tnt_local_test&resource_uid=arn:aws:ec2:...&depth=2&limit=50
```
```json
{
  "nodes": [
    {"id": "arn:aws:ec2:...:instance/i-0abc", "type": "aws_instance", "label": "web-server-prod"},
    {"id": "arn:aws:ec2:...:subnet/subnet-abc", "type": "aws_subnet", "label": "subnet-abc"},
    {"id": "arn:aws:ec2:...:vpc/vpc-123", "type": "aws_vpc", "label": "prod-vpc"},
    {"id": "arn:aws:ec2:...:sg/sg-123", "type": "aws_security_group", "label": "web-sg"}
  ],
  "edges": [
    {"from": "arn:aws:ec2:...:instance/i-0abc", "to": "arn:aws:ec2:...:subnet/subnet-abc", "relation": "belongs_to"},
    {"from": "arn:aws:ec2:...:subnet/subnet-abc", "to": "arn:aws:ec2:...:vpc/vpc-123", "relation": "belongs_to"},
    {"from": "arn:aws:ec2:...:instance/i-0abc", "to": "arn:aws:ec2:...:sg/sg-123", "relation": "secured_by"}
  ]
}
```

### Drift Detection
```http
GET /gateway/api/v1/inventory/drift?tenant_id=tnt_local_test&baseline_scan=inv-prev&compare_scan=inv-latest&change_type=modified
```
```json
{
  "baseline_scan": "inv-prev",
  "compare_scan": "inv-latest",
  "summary": {
    "added": 5,
    "modified": 12,
    "removed": 2
  },
  "records": [
    {
      "resource_uid": "arn:aws:ec2:...:sg/sg-123",
      "change_type": "modified",
      "field_changes": [
        {"field": "ingress_rules", "old_value": "22/tcp from 10.0.0.0/8", "new_value": "22/tcp from 0.0.0.0/0"}
      ]
    }
  ]
}
```

---

## 4. THREATS

### Threat Distribution
```http
GET /gateway/api/v1/threat/analytics/distribution?tenant_id=tnt_local_test&scan_run_id=thr-g7h8i9
```
```json
{
  "total_threats": 247,
  "by_severity": {"critical": 12, "high": 89, "medium": 134, "low": 22},
  "by_category": {"network_exposure": 45, "encryption": 67, "access_control": 89, "logging": 46}
}
```

### Prioritized Threats (Top N)
```http
GET /gateway/api/v1/threat/analysis/prioritized?tenant_id=tnt_local_test&top_n=5
```
```json
{
  "threats": [
    {
      "detection_id": "det-001",
      "title": "Public S3 Bucket with Sensitive Data",
      "severity": "critical",
      "risk_score": 9.8,
      "verdict": "true_positive",
      "resource_uid": "arn:aws:s3:::prod-data-bucket",
      "blast_radius": 15,
      "mitre_tactics": ["TA0001 - Initial Access"]
    },
    {
      "detection_id": "det-002",
      "title": "Unencrypted RDS Instance",
      "severity": "high",
      "risk_score": 8.5,
      "verdict": "true_positive",
      "resource_uid": "arn:aws:rds:us-east-1:...:db/prod-db"
    }
  ]
}
```

### Threat Detail
```http
GET /gateway/api/v1/threat/threats/det-001?tenant_id=tnt_local_test
```
```json
{
  "detection_id": "det-001",
  "title": "Public S3 Bucket with Sensitive Data",
  "description": "S3 bucket prod-data-bucket has public read access and contains files classified as confidential",
  "severity": "critical",
  "category": "data_exposure",
  "status": "open",
  "resource_uid": "arn:aws:s3:::prod-data-bucket",
  "account_id": "123456789012",
  "region": "us-east-1",
  "service": "s3",
  "mitre_tactics": ["TA0001 - Initial Access", "TA0009 - Collection"],
  "mitre_techniques": ["T1530 - Data from Cloud Storage"],
  "evidence": {
    "bucket_acl": "public-read",
    "block_public_access": false,
    "objects_count": 15432
  },
  "affected_resources": [
    {"resource_uid": "arn:aws:s3:::prod-data-bucket", "type": "aws_s3_bucket"}
  ],
  "remediation": {
    "steps": [
      "Enable S3 Block Public Access on the bucket",
      "Review and restrict bucket policy",
      "Enable server-side encryption (SSE-S3 or SSE-KMS)"
    ],
    "priority": "immediate"
  },
  "created_at": "2026-02-09T08:20:00Z"
}
```

### Attack Paths
```http
GET /gateway/api/v1/graph/attack-paths?tenant_id=tnt_local_test&max_hops=5&min_severity=high
```
```json
{
  "attack_paths": [
    {
      "path_id": "ap-001",
      "start": "Internet",
      "end": "arn:aws:rds:...:db/prod-db",
      "severity": "critical",
      "hops": [
        {"resource": "Internet", "type": "external"},
        {"resource": "arn:aws:ec2:...:sg/sg-web", "type": "aws_security_group", "vulnerability": "port 22 open to 0.0.0.0/0"},
        {"resource": "arn:aws:ec2:...:i-0abc123", "type": "aws_instance"},
        {"resource": "arn:aws:ec2:...:sg/sg-db", "type": "aws_security_group"},
        {"resource": "arn:aws:rds:...:db/prod-db", "type": "aws_rds_instance"}
      ],
      "risk_score": 9.2
    }
  ]
}
```

### Trend Data
```http
GET /gateway/api/v1/threat/analytics/trend?tenant_id=tnt_local_test&days=30
```
```json
{
  "tenant_id": "tnt_local_test",
  "days": 30,
  "data_points": [
    {"date": "2026-01-10", "critical": 15, "high": 92, "medium": 140, "low": 25, "total": 272},
    {"date": "2026-01-17", "critical": 14, "high": 90, "medium": 138, "low": 24, "total": 266},
    {"date": "2026-01-24", "critical": 13, "high": 88, "medium": 135, "low": 23, "total": 259},
    {"date": "2026-01-31", "critical": 12, "high": 89, "medium": 134, "low": 22, "total": 257},
    {"date": "2026-02-07", "critical": 12, "high": 89, "medium": 134, "low": 22, "total": 247}
  ],
  "trend_direction": "improving"
}
```

### Threat Hunting
```http
POST /gateway/api/v1/hunt/execute
Content-Type: application/json

{
  "tenant_id": "tnt_local_test",
  "predefined_id": "internet-exposed-databases"
}
```
```json
{
  "hunt_id": "hunt-001",
  "query_name": "internet-exposed-databases",
  "execution_time_ms": 234,
  "results": [
    {
      "resource_uid": "arn:aws:rds:...:db/prod-db",
      "finding": "RDS instance reachable from internet via 2-hop path",
      "path": ["Internet", "sg-web (port 22 open)", "i-0abc123", "sg-db", "prod-db"],
      "risk_score": 9.2
    }
  ],
  "total_results": 1
}
```

---

## 5. COMPLIANCE

### Dashboard Summary
```http
GET /gateway/api/v1/compliance/dashboard?tenant_id=tnt_local_test
```
```json
{
  "scan_id": "cmp-m3n4o5",
  "tenant_id": "tnt_local_test",
  "overall_score": 76.3,
  "frameworks": {"total": 5, "passing": 2, "partial": 2, "failing": 1},
  "framework_scores": [
    {"framework": "HIPAA", "score": 78.0, "total_controls": 45, "passed": 35, "failed": 10},
    {"framework": "PCI-DSS", "score": 85.0, "total_controls": 52, "passed": 44, "failed": 8},
    {"framework": "SOC2", "score": 72.0, "total_controls": 61, "passed": 44, "failed": 17},
    {"framework": "CIS-AWS", "score": 81.0, "total_controls": 98, "passed": 79, "failed": 19},
    {"framework": "GDPR", "score": 65.0, "total_controls": 40, "passed": 26, "failed": 14}
  ]
}
```

### Framework Detail
```http
GET /gateway/api/v1/compliance/framework-detail/HIPAA?tenant_id=tnt_local_test
```
```json
{
  "framework": "HIPAA",
  "scan_id": "cmp-m3n4o5",
  "summary": {
    "total_controls": 45,
    "passed_controls": 35,
    "failed_controls": 10,
    "partial_controls": 0,
    "score": 78.0
  },
  "controls": [
    {
      "control_id": "164.312(a)(1)",
      "control_title": "Access Control - Unique User Identification",
      "status": "fail",
      "affected_resources": 3,
      "description": "Assign a unique name and/or number for identifying and tracking user identity"
    },
    {
      "control_id": "164.312(a)(2)(iv)",
      "control_title": "Access Control - Encryption and Decryption",
      "status": "pass",
      "affected_resources": 0
    }
  ]
}
```

### Control Detail (drill down)
```http
GET /gateway/api/v1/compliance/control-detail/HIPAA/164.312(a)(1)?tenant_id=tnt_local_test
```
```json
{
  "control_id": "164.312(a)(1)",
  "control_title": "Access Control - Unique User Identification",
  "framework": "HIPAA",
  "status": "fail",
  "failed_resource_count": 3,
  "passed_resource_count": 12,
  "affected_resources": [
    {
      "resource_uid": "arn:aws:iam::123456789012:user/shared-admin",
      "resource_type": "aws_iam_user",
      "check_id": "iam-001",
      "check_status": "FAIL",
      "message": "IAM user shared-admin has no MFA enabled and is shared across teams"
    }
  ]
}
```

---

## 6. IAM SECURITY

### IAM Findings
```http
GET /gateway/api/v1/iam-security/findings?csp=aws&scan_id=chk-d4e5f6&tenant_id=tnt_local_test&module=privilege_escalation
```
```json
{
  "findings": [
    {
      "finding_id": "iam-f001",
      "module": "privilege_escalation",
      "severity": "critical",
      "resource_uid": "arn:aws:iam::123456789012:role/dev-role",
      "title": "Role allows iam:PassRole + lambda:CreateFunction (privilege escalation path)",
      "description": "This role can create Lambda functions and pass any role, enabling privilege escalation",
      "status": "open",
      "remediation": "Restrict iam:PassRole to specific resource ARNs"
    }
  ],
  "summary": {
    "total": 12,
    "critical": 3,
    "high": 9
  }
}
```

---

## 7. DATA SECURITY

### Data Catalog
```http
GET /gateway/api/v1/data-security/catalog?csp=aws&scan_id=chk-d4e5f6&account_id=123456789012
```
```json
{
  "data_stores": [
    {
      "resource_uid": "arn:aws:s3:::prod-data-bucket",
      "service": "s3",
      "region": "us-east-1",
      "classification": ["PII", "PCI"],
      "encryption": "SSE-S3",
      "access_level": "private",
      "size_estimate": "45 GB",
      "last_accessed": "2026-02-09T07:00:00Z"
    },
    {
      "resource_uid": "arn:aws:rds:...:db/prod-db",
      "service": "rds",
      "region": "us-east-1",
      "classification": ["PII", "PHI"],
      "encryption": "none",
      "access_level": "private",
      "size_estimate": "120 GB"
    }
  ]
}
```

### Classification
```http
GET /gateway/api/v1/data-security/classification?csp=aws&scan_id=chk-d4e5f6&tenant_id=tnt_local_test
```
```json
{
  "classifications": [
    {
      "resource_uid": "arn:aws:s3:::prod-data-bucket",
      "categories": ["PII", "PCI"],
      "confidence": 0.92,
      "pii_types": ["email", "ssn", "phone"],
      "pci_types": ["card_number", "cvv"]
    }
  ]
}
```

---

## 8. CODE SECURITY (SecOps)

### Run Scan
```http
POST /secops/api/v1/secops/scan
Content-Type: application/json

{
  "tenant_id": "tnt_local_test",
  "repo_url": "https://github.com/juice-shop/juice-shop.git",
  "branch": "master"
}
```
```json
{
  "secops_scan_id": "f6b3aea2-9e1d-4536-beef-c09fbc6e133c",
  "orchestration_id": null,
  "tenant_id": "tnt_local_test",
  "project_name": "juice-shop",
  "status": "completed",
  "summary": {
    "files_scanned": 10,
    "total_findings": 212,
    "total_errors": 205,
    "findings_persisted": 212,
    "languages": ["ruby", "docker", "javascript"]
  },
  "findings_count": 212
}
```

### Get Findings (filtered)
```http
GET /secops/api/v1/secops/scan/f6b3aea2-9e1d-4536-beef-c09fbc6e133c/findings?severity=high
```
```json
{
  "secops_scan_id": "f6b3aea2-9e1d-4536-beef-c09fbc6e133c",
  "total": 201,
  "findings": [
    {
      "id": 1,
      "file_path": "Dockerfile",
      "language": "docker",
      "rule_id": "pulling_image_based_its",
      "severity": "high",
      "message": "Pulling image based on its digest is security sensitive",
      "line_number": 1,
      "status": "violation"
    },
    {
      "id": 2,
      "file_path": "Dockerfile",
      "language": "docker",
      "rule_id": "allowing_shell_scripts_execution",
      "severity": "high",
      "message": "Allowing shell scripts execution is security sensitive",
      "line_number": 5,
      "status": "violation"
    }
  ]
}
```

### Rule Stats
```http
GET /secops/api/v1/secops/rules/stats
```
```json
{
  "total_rules": 2454,
  "by_scanner": {
    "java": 712,
    "csharp": 416,
    "python": 340,
    "c": 313,
    "javascript": 293,
    "cpp": 148,
    "go": 70,
    "terraform": 52,
    "docker": 33,
    "cloudformation": 26,
    "azure": 25,
    "kubernetes": 11,
    "ansible": 10,
    "ruby": 5
  },
  "by_severity": {
    "high": 1670,
    "low": 525,
    "medium": 157,
    "critical": 102
  }
}
```

---

## 9. PLATFORM HEALTH

### Gateway Services
```http
GET /gateway/gateway/services
```
```json
{
  "services": [
    {"name": "discovery", "url": "http://engine-discoveries:80", "prefix": "/api/v1/discovery", "healthy": true},
    {"name": "check", "url": "http://engine-check:80", "prefix": "/api/v1/check", "healthy": true},
    {"name": "threat", "url": "http://engine-threat:80", "prefix": "/api/v1/threat", "healthy": true},
    {"name": "iam", "url": "http://engine-iam:80", "prefix": "/api/v1/iam-security", "healthy": true},
    {"name": "datasec", "url": "http://engine-datasec:80", "prefix": "/api/v1/data-security", "healthy": true},
    {"name": "inventory", "url": "http://engine-inventory:80", "prefix": "/api/v1/inventory", "healthy": true},
    {"name": "compliance", "url": "http://engine-compliance:80", "prefix": "/api/v1/compliance", "healthy": true},
    {"name": "secops", "url": "http://engine-secops:80", "prefix": "/api/v1/secops", "healthy": true},
    {"name": "onboarding", "url": "http://engine-onboarding:80", "prefix": "/api/v1/onboarding", "healthy": true}
  ]
}
```
