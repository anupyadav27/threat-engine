# Security Practices

> Authentication, credential management, secrets handling, and security configuration.

---

## Authentication Architecture

### API Authentication
- Tenant-based isolation via `tenant_id` in request body/headers
- All database queries filtered by `tenant_id`
- API Gateway routes requests to backend engines

### User Portal Authentication
- JWT tokens (access + refresh)
- SAML/SSO integration (Okta)
- Access token lifetime: 15 minutes
- Refresh token lifetime: 7 days

### Cloud Credential Management
- Credentials encrypted and stored in AWS Secrets Manager
- Prefix: `threat-engine/{account_id}`
- KMS encryption for secrets at rest
- Cross-account access via IAM AssumeRole

---

## IAM & IRSA (EKS)

### Service Account
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aws-engine-sa
  namespace: threat-engine-engines
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::588989875114:role/threat-engine-platform-role
```

### IAM Roles
| Role | Purpose |
|------|---------|
| `threat-engine-platform-role` | All engines — RDS, S3, Secrets Manager access |
| `secops-s3-access-role` | SecOps scanner — S3 read/write for scan files |
| `cspm-eks-role` | EKS service account — Pod identity |

### Required Permissions
```json
{
  "Effect": "Allow",
  "Action": [
    "rds:DescribeDBInstances",
    "s3:GetObject", "s3:PutObject", "s3:ListBucket",
    "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue",
    "sts:AssumeRole",
    "iam:ListRoles", "iam:ListPolicies",
    "ec2:DescribeInstances", "ec2:DescribeSecurityGroups"
  ]
}
```

---

## Pod Security

### Security Context (all pods)
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  readOnlyRootFilesystem: true
```

### Network Policies
- Engines communicate via ClusterIP services
- Only API Gateway exposed via LoadBalancer
- Database connections restricted to engine pods

---

## Secrets Management

### Kubernetes Secrets

| Secret | Contents |
|--------|----------|
| `database-credentials` | DB_HOST, DB_PORT, DB_USER, DB_PASSWORD |
| `neo4j-credentials` | NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD |
| `encryption-keys` | ENCRYPTION_KEY, JWT_SECRET |
| `s3-credentials` | AWS access keys (if not using IRSA) |

### Secret Rotation
- Database passwords: Rotate quarterly
- API keys: Rotate on team member changes
- Encryption keys: Rotate annually
- JWT secrets: Rotate on security events

---

## Data Protection

### Encryption
| Data | At Rest | In Transit |
|------|---------|-----------|
| PostgreSQL (RDS) | AES-256 (AWS managed) | SSL/TLS required |
| Neo4j (Aura) | AES-256 (managed) | TLS (neo4j+s://) |
| S3 | SSE-S3 | HTTPS |
| Secrets Manager | KMS | HTTPS |
| Redis | Not encrypted | Internal only |

### Tenant Isolation
- All database queries include `WHERE tenant_id = ?`
- No cross-tenant data access possible through API
- Separate credential storage per account in Secrets Manager

---

## Security Scanning

### What We Scan

| Target | Scanner | Coverage |
|--------|---------|----------|
| AWS resources | engine_discoveries + engine_check | 40+ services, 1000+ rules |
| IAM policies | engine_iam | Privilege escalation, least privilege |
| Data stores | engine_datasec | PII/PCI/PHI, encryption, access |
| IaC/Code | engine_secops | Terraform, CF, Docker, K8s, Python, Java |

### What We Don't Scan
- Runtime behavior (no agent-based scanning)
- Network traffic (no packet capture)
- Container images (no vulnerability scanning — use separate tools)

---

## Security Headers

### API Gateway
```python
# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure in production
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)
```

### Recommended Production Headers
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

---

## Incident Response

### Security Events to Monitor
1. Failed authentication attempts (>5 in 1 minute)
2. Cross-tenant data access attempts
3. Unusual scan patterns (frequency, scope)
4. Database query anomalies
5. S3 access from unexpected IPs

### Log Audit Trail
- All API requests logged with correlation ID
- Database operations logged via `engine_common/logger.py`
- AWS CloudTrail for cloud API calls
- K8s audit logs for cluster operations
