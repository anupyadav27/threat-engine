# AWS Deployment

Production deployment on AWS using EKS, RDS, and S3.

## Architecture

```
┌─────────────────────────────────────────┐
│         AWS EKS Cluster                 │
│  ┌──────────────┐  ┌──────────────┐   │
│  │ ConfigScan   │  │ Compliance   │   │
│  │ Engines      │  │ Engine       │   │
│  └──────┬───────┘  └──────┬───────┘   │
│         │                  │           │
│  ┌──────▼──────────────────▼───────┐  │
│  │  Rule Engine  │  Onboarding      │  │
│  └───────────────┴──────────────────┘  │
└─────────────────────────────────────────┘
         │                    │
         ▼                    ▼
┌─────────────────┐  ┌─────────────────┐
│   RDS PostgreSQL │  │   S3 Buckets    │
│  (Multi-AZ)      │  │  cspm-lgtech    │
└─────────────────┘  └─────────────────┘
```

## Components

### 1. EKS Cluster
- **Name**: `vulnerability-eks-cluster`
- **Region**: `ap-south-1` (Mumbai)
- **Namespace**: `threat-engine-engines`
- **Node Groups**: Managed node groups

### 2. RDS PostgreSQL
- **Instance Type**: `db.t3.medium` (or larger for production)
- **Multi-AZ**: Enabled for production
- **Databases**:
  - `compliance_engine`
  - `threat_engine`
- **Backup**: Automated backups enabled

### 3. S3 Buckets
- **Bucket**: `cspm-lgtech`
- **Structure**:
  - `{csp}-configScan-engine/output/`
  - `compliance-engine/output/`
  - `rule-engine/output/`

### 4. IAM Roles
- **IRSA**: IAM Roles for Service Accounts
- **Permissions**: S3, RDS, Secrets Manager

## Setup

### Prerequisites
```bash
# AWS CLI configured
# kubectl configured for EKS
# Terraform (optional, for infrastructure)
```

### 1. Setup RDS
```bash
cd deployment/aws/rds
./create-rds.sh
```

### 2. Setup S3
```bash
cd deployment/aws/s3
./setup-s3.sh
```

### 3. Deploy to EKS
```bash
cd deployment/aws/eks
./deploy-to-eks.sh
```

## Configuration

### Database Connection
```bash
export DATABASE_URL="postgresql://user:pass@rds-endpoint.ap-south-1.rds.amazonaws.com:5432/threat_engine"
```

### S3 Configuration
```bash
export S3_BUCKET="cspm-lgtech"
export AWS_REGION="ap-south-1"
```

### EKS Configuration
```bash
export EKS_CLUSTER_NAME="vulnerability-eks-cluster"
export AWS_REGION="ap-south-1"
aws eks update-kubeconfig --name $EKS_CLUSTER_NAME --region $AWS_REGION
```

## Services

### LoadBalancer Services
- ConfigScan Engines: AWS NLB
- Compliance Engine: AWS NLB
- Rule Engine: AWS NLB
- Onboarding Engine: AWS NLB

### Access
```bash
# Get LoadBalancer endpoints
kubectl get svc -n threat-engine-engines

# Access via LoadBalancer DNS
curl http://<loadbalancer-dns>/api/v1/health
```

## Security

### IRSA (IAM Roles for Service Accounts)
- Each service has its own IAM role
- Pods assume roles via service accounts
- No AWS credentials in pods

### Secrets Management
- RDS credentials: AWS Secrets Manager
- API keys: AWS Secrets Manager
- Kubernetes secrets: Encrypted at rest

## Monitoring

### CloudWatch
- Container logs
- Metrics
- Alarms

### RDS Monitoring
- Performance Insights
- Enhanced Monitoring
- CloudWatch metrics

## Cost Optimization

- Use spot instances for non-critical workloads
- Right-size RDS instances
- Enable S3 lifecycle policies
- Use reserved instances for RDS (production)

## Disaster Recovery

- RDS automated backups
- S3 versioning
- Multi-AZ RDS
- EKS cluster backups (via Velero)

## Scaling

### Horizontal Pod Autoscaling
```bash
kubectl autoscale deployment compliance-engine -n threat-engine-engines --min=2 --max=10 --cpu-percent=80
```

### RDS Scaling
- Vertical: Change instance type
- Read replicas: For read-heavy workloads

