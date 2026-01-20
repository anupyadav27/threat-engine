# Deployment Configurations

This directory contains deployment configurations for different environments.

## Structure

```
deployment/
├── local/              # Local development deployment
│   ├── docker-compose/ # Docker Compose for local services
│   ├── kubernetes/    # Local Kubernetes (Docker Desktop)
│   ├── postgres/      # Local PostgreSQL setup
│   └── scripts/       # Local deployment scripts
│
├── aws/               # AWS production deployment
│   ├── eks/          # EKS cluster configurations
│   ├── rds/          # RDS database configurations
│   ├── s3/           # S3 bucket configurations
│   └── scripts/      # AWS deployment scripts
│
└── common/            # Shared configurations
    ├── configs/      # Common config files
    └── scripts/       # Shared scripts
```

## Deployment Types

### 1. Local Deployment (`local/`)

**Purpose**: Local development and testing

**Components**:
- PostgreSQL (local instance)
- Docker Desktop Kubernetes
- Local services (no cloud dependencies)

**Use Cases**:
- Development
- Local testing
- CI/CD testing
- Quick prototyping

**Requirements**:
- Docker Desktop
- PostgreSQL (local or Docker)
- kubectl
- Local file system for outputs

### 2. AWS Deployment (`aws/`)

**Purpose**: Production deployment on AWS

**Components**:
- EKS cluster
- RDS PostgreSQL
- S3 buckets
- IAM roles and policies
- LoadBalancers

**Use Cases**:
- Production
- Staging
- Multi-tenant SaaS
- Scalable deployments

**Requirements**:
- AWS account
- EKS cluster
- RDS instance
- S3 buckets
- IAM permissions

## Quick Start

### Local Deployment
```bash
cd deployment/local
./scripts/deploy-local.sh
```

### AWS Deployment
```bash
cd deployment/aws
./scripts/deploy-aws.sh
```

## Environment Variables

### Local
- `DATABASE_URL=postgresql://postgres:postgres@localhost:5432/threat_engine`
- `OUTPUT_DIR=/path/to/local/output`
- `KUBECONFIG=~/.kube/config` (Docker Desktop)

### AWS
- `DATABASE_URL=postgresql://user:pass@rds-endpoint:5432/threat_engine`
- `S3_BUCKET=cspm-lgtech`
- `AWS_REGION=ap-south-1`
- `EKS_CLUSTER_NAME=vulnerability-eks-cluster`

## Migration Path

1. **Develop Locally** → Use `local/` deployment
2. **Test on AWS** → Use `aws/` deployment with staging resources
3. **Deploy to Production** → Use `aws/` deployment with production resources

