# Deployment Summary

## Overview

The deployment folder is organized into two main deployment types:

1. **Local Deployment** - For development and local testing
2. **AWS Deployment** - For production on AWS EKS + RDS

## Structure

```
deployment/
├── local/                    # Local development
│   ├── docker-compose/       # Docker Compose setup
│   ├── kubernetes/          # Local K8s (Docker Desktop)
│   ├── postgres/            # Local PostgreSQL setup
│   └── scripts/             # Local deployment scripts
│
├── aws/                      # AWS production
│   ├── eks/                 # EKS configurations
│   ├── rds/                 # RDS configurations
│   ├── s3/                  # S3 configurations
│   └── scripts/             # AWS deployment scripts
│
└── common/                   # Shared configurations
    ├── configs/             # Common config files
    └── scripts/             # Shared scripts
```

## Quick Start

### Local Deployment

#### Option 1: Docker Compose
```bash
cd deployment/local/docker-compose
docker-compose up -d
```

#### Option 2: Kubernetes (Docker Desktop)
```bash
cd deployment/local
./scripts/deploy-local.sh kubernetes
```

#### Option 3: Manual Setup
```bash
# Setup PostgreSQL
cd deployment/local/postgres
./setup-postgres.sh

# Deploy to Kubernetes
cd deployment/local/kubernetes
kubectl apply -f .
```

### AWS Deployment
```bash
cd deployment/aws
./scripts/deploy-aws.sh
```

## Key Differences

### Local Deployment
- ✅ PostgreSQL: Local instance or Docker container
- ✅ Storage: Local filesystem (`engines-output/`)
- ✅ Kubernetes: Docker Desktop
- ✅ Services: ClusterIP (port-forward for access)
- ✅ No S3: All outputs to local filesystem
- ✅ No LoadBalancers: Use port-forwarding

### AWS Deployment
- ✅ PostgreSQL: RDS (Multi-AZ for production)
- ✅ Storage: S3 buckets
- ✅ Kubernetes: EKS cluster
- ✅ Services: LoadBalancer (AWS NLB)
- ✅ S3: All outputs to S3
- ✅ IRSA: IAM Roles for Service Accounts
- ✅ Secrets: AWS Secrets Manager

## Database Setup

### Local
```bash
# Setup databases
cd deployment/local/postgres
./setup-postgres.sh

# Or use workspace script
cd ../..
./setup-local-databases.sh
```

### AWS
```bash
# Create RDS instance
cd deployment/aws/rds
./create-rds.sh

# Setup databases
./setup-databases.sh
```

## Configuration Files

### Environment Variables

**Local** (`deployment/common/configs/database.env.example`):
```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/threat_engine
OUTPUT_DIR=/path/to/engines-output
```

**AWS** (`deployment/common/configs/aws.env.example`):
```bash
DATABASE_URL=postgresql://user:pass@rds-endpoint:5432/threat_engine
S3_BUCKET=cspm-lgtech
AWS_REGION=ap-south-1
```

## Migration Path

1. **Develop Locally** → Use `local/` deployment
   - Fast iteration
   - No cloud costs
   - Easy debugging

2. **Test on AWS** → Use `aws/` deployment
   - Staging environment
   - Test cloud integrations
   - Validate S3/RDS access

3. **Deploy to Production** → Use `aws/` deployment
   - Production EKS cluster
   - Production RDS
   - Production S3 buckets

## Services

### Core Engines
- **AWS ConfigScan Engine** (Port 8000 local / 80 EKS)
- **Compliance Engine** (Port 8001 local / 80 EKS)
- **Rule Engine** (Port 8002 local / 80 EKS)
- **Onboarding Engine** (Port 8003 local / 80 EKS)
- **Threat Engine** (Port 8004 local / 80 EKS)
- **Inventory Engine** (Port 8005 local / 80 EKS) - NEW

### Port Mapping
- All services listen on port 8000 inside containers
- Local: Host ports 8000-8004 map to container port 8000
- EKS: ClusterIP services expose port 80 → container port 8000
- EKS: LoadBalancer services expose port 80 → container port 8000

## Next Steps

1. ✅ Choose deployment type (local or AWS)
2. ✅ Setup prerequisites
3. ✅ Run deployment script
4. ✅ Verify services
5. ✅ Test workflows

