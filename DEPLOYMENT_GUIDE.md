# Deployment Guide - Threat Engine Onboarding & APIs

## Overview

This guide covers deploying the complete onboarding system with all compliance engines and the YAML rule builder as containerized services in Kubernetes.

## Architecture

```
┌─────────────────────────────────────────┐
│         UI (Frontend)                   │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│    Onboarding API (ClusterIP)           │
│    - Account onboarding                 │
│    - Credential management              │
│    - Schedule management                │
└──────────────┬──────────────────────────┘
               │
    ┌──────────┼──────────┐
    │          │          │
┌───▼───┐ ┌───▼───┐ ┌───▼──────┐
│ AWS   │ │ Azure │ │ YAML     │
│ Engine│ │ Engine│ │ Builder  │
│ API   │ │ API   │ │ API      │
└───────┘ └───────┘ └──────────┘
    │          │          │
┌───▼──────────▼──────────▼──────┐
│  Scheduler Service             │
│  (Background worker)           │
└────────────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│    AWS Services                          │
│    - DynamoDB (metadata)                │
│    - Secrets Manager (credentials)       │
│    - KMS (encryption)                    │
└──────────────────────────────────────────┘
```

## Prerequisites

- Docker and Docker Compose (for local development)
- Kubernetes cluster (EKS for production)
- kubectl configured
- Docker registry for images

## Directory Structure

```
/Users/apple/Desktop/
├── onboarding/                    # Onboarding module (moved here)
│   ├── api/
│   ├── database/
│   ├── scheduler/
│   └── ...
└── threat-engine/                 # Threat engine engines
    ├── aws_compliance_python_engine/
    ├── azure_compliance_python_engine/
    ├── gcp_compliance_python_engine/
    ├── alicloud_compliance_python_engine/
    ├── oci_compliance_python_engine/
    ├── ibm_compliance_python_engine/
    ├── yaml-rule-builder/
    └── kubernetes/
```

## Local Development Setup

### 1. Prerequisites

- AWS CLI configured with appropriate credentials
- AWS region set (default: `ap-south-1`)
- DynamoDB tables created (run `python -c "from onboarding.database.dynamodb_tables import create_tables; create_tables()"`)
- KMS key for Secrets Manager encryption

### 2. Set Environment Variables

Create `.env` file:

```bash
AWS_REGION=ap-south-1
PLATFORM_AWS_ACCOUNT_ID=<your-aws-account-id>
SECRETS_MANAGER_PREFIX=threat-engine
SECRETS_MANAGER_KMS_KEY_ID=<kms-key-arn>
```

### 3. Initialize DynamoDB Tables

```bash
cd /Users/apple/Desktop/onboarding
python -c "from onboarding.database.dynamodb_tables import create_tables; create_tables()"
```

### 4. Run Services Locally

```bash
# Onboarding API
cd /Users/apple/Desktop/onboarding
pip install -r requirements.txt
python main.py

# AWS Engine API (separate terminal)
cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine
pip install -r requirements.txt fastapi uvicorn
python api_server.py

# YAML Rule Builder API (separate terminal)
cd /Users/apple/Desktop/threat-engine/yaml-rule-builder
pip install -r requirements.txt fastapi uvicorn
python api_server.py
```

## Kubernetes Deployment

### 1. Build Docker Images

```bash
# Build onboarding API (from onboarding directory)
cd /Users/apple/Desktop/onboarding
docker build -t your-registry/onboarding-api:latest -f Dockerfile .

# Build engine images (from threat-engine directory)
cd /Users/apple/Desktop/threat-engine
docker build -t your-registry/aws-compliance-engine:latest -f aws_compliance_python_engine/Dockerfile .
docker build -t your-registry/azure-compliance-engine:latest -f azure_compliance_python_engine/Dockerfile .
docker build -t your-registry/gcp-compliance-engine:latest -f gcp_compliance_python_engine/Dockerfile .
docker build -t your-registry/alicloud-compliance-engine:latest -f alicloud_compliance_python_engine/Dockerfile .
docker build -t your-registry/oci-compliance-engine:latest -f oci_compliance_python_engine/Dockerfile .
docker build -t your-registry/ibm-compliance-engine:latest -f ibm_compliance_python_engine/Dockerfile .
docker build -t your-registry/yaml-rule-builder:latest -f yaml-rule-builder/Dockerfile .
docker build -t your-registry/scheduler-service:latest -f onboarding/scheduler/Dockerfile .

# Push to registry
docker push your-registry/onboarding-api:latest
# ... push all images
```

### 2. Update Kubernetes Manifests

Update image names in all deployment files:
- Replace `your-registry/` with your actual registry
- Update `PLATFORM_AWS_ACCOUNT_ID` in `kubernetes/configmaps/platform-config.yaml`
- Update secrets in `kubernetes/secrets/`

### 3. Create Namespace

```bash
kubectl create namespace threat-engine-engines
```

### 4. Create Secrets (if needed)

```bash
# S3 credentials (if not using IRSA)
kubectl apply -f kubernetes/secrets/s3-credentials.yaml
```

### 5. Create ConfigMaps

```bash
kubectl apply -f kubernetes/configmaps/platform-config.yaml
```

### 6. Setup AWS Services

Ensure DynamoDB tables and KMS key are created:
- DynamoDB tables are created automatically on first API call
- KMS key should be created in AWS Console

### 7. Deploy Engines

```bash
# Deploy all engines
kubectl apply -f kubernetes/engines/

# Verify services
kubectl get svc -n threat-engine-engines
```

### 8. Setup S3 Output Folders

```bash
cd /Users/apple/Desktop/threat-engine
./setup-s3-folders.sh
./setup-s3-iam-permissions.sh threat-engine-platform-role
```

### 9. Deploy Onboarding API

```bash
kubectl apply -f kubernetes/onboarding/onboarding-deployment.yaml

# Verify
kubectl get pods -n threat-engine-engines -l app=onboarding-api
```

### 10. Deploy Scheduler

```bash
kubectl apply -f kubernetes/scheduler/scheduler-deployment.yaml

# Check logs
kubectl logs -f deployment/scheduler-service -n threat-engine-engines
```

## Service Discovery

All services communicate via Kubernetes DNS:

- Onboarding API: `http://onboarding-api.threat-engine-engines.svc.cluster.local`
- AWS Engine: `http://aws-compliance-engine.threat-engine-engines.svc.cluster.local`
- Azure Engine: `http://azure-compliance-engine.threat-engine-engines.svc.cluster.local`
- YAML Builder: `http://yaml-rule-builder.threat-engine-engines.svc.cluster.local`

## Testing

### Test Onboarding API

```bash
# Health check
curl http://onboarding-api.threat-engine-engines.svc.cluster.local/api/v1/health

# Initialize AWS onboarding
curl -X POST http://onboarding-api.threat-engine-engines.svc.cluster.local/api/v1/onboarding/aws/init \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "test-tenant-id",
    "account_name": "Test Account",
    "auth_method": "iam_role"
  }'
```

### Test Engine APIs

```bash
# AWS Engine health
curl http://aws-compliance-engine.threat-engine-engines.svc.cluster.local/api/v1/health

# List services
curl http://aws-compliance-engine.threat-engine-engines.svc.cluster.local/api/v1/services
```

## AWS Services Configuration

The system uses:
- **DynamoDB**: For storing tenants, accounts, schedules, and scan results
- **Secrets Manager**: For storing encrypted credentials
- **KMS**: For encryption keys
- **S3**: For engine output storage

All services are configured via ConfigMap and use IAM roles for authentication.

## Monitoring

- Check pod status: `kubectl get pods -n threat-engine-engines`
- View logs: `kubectl logs -f deployment/onboarding-api -n threat-engine-engines`
- Check scheduler: `kubectl logs -f deployment/scheduler-service -n threat-engine-engines`

## Troubleshooting

- **DynamoDB connection errors**: Check IAM permissions and AWS region
- **Secrets Manager errors**: Verify KMS key permissions
- **Engine API timeouts**: Increase resource limits
- **Scheduler not running**: Check DynamoDB connectivity and logs
- **S3 sync failures**: Verify IAM permissions and bucket access

