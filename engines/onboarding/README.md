# Threat Engine Onboarding Module

Complete onboarding, credential management, and scheduling system for multi-cloud compliance scanning.

## 🏗️ Architecture

- **Onboarding API**: FastAPI service for account onboarding and management
- **Scheduler Service**: Background service for scheduled scan execution
- **DynamoDB**: AWS DynamoDB for storing tenants, accounts, schedules, and execution history
- **Secrets Manager**: AWS Secrets Manager for secure credential storage (encrypted with KMS)
- **KMS**: AWS KMS for encryption key management
- **Engine APIs**: FastAPI wrappers for all compliance engines (AWS, Azure, GCP, AliCloud, OCI, IBM)
- **YAML Rule Builder API**: FastAPI wrapper for rule generation

## 🚀 Quick Start

### Prerequisites

- AWS Account with DynamoDB, Secrets Manager, and KMS access
- Python 3.11+
- Docker (for building images)
- kubectl (for EKS deployment)

### 1. Setup AWS Services

```bash
# Create DynamoDB tables
python3 -c "from onboarding.database.dynamodb_tables import create_tables; create_tables()"

# Create KMS key (see AWS_SERVICES_SETUP.md)
aws kms create-key --description "Threat Engine Secrets" --region ap-south-1
```

### 2. Configure Environment

```bash
export AWS_REGION=ap-south-1
export SECRETS_MANAGER_PREFIX=threat-engine
export SECRETS_MANAGER_KMS_KEY_ID=alias/threat-engine-secrets
export PLATFORM_AWS_ACCOUNT_ID=588989875114
```

### 3. Run Locally

```bash
cd /Users/apple/Desktop/onboarding
pip install -r requirements.txt
python main.py
```

API will be available at `http://localhost:8000`

### 4. Deploy to EKS

```bash
# Build and push images
./push-images.sh

# Deploy
kubectl apply -f ../threat-engine/kubernetes/configmaps/platform-config.yaml
kubectl apply -f ../threat-engine/kubernetes/onboarding/onboarding-deployment.yaml
kubectl apply -f ../threat-engine/kubernetes/scheduler/scheduler-deployment.yaml
```

## 🌐 API Access

### Production URL
```
http://a2d474d5fbb694ac5a295b05ba4ee566-8ce5ff8e72034235.elb.ap-south-1.amazonaws.com
```

### Interactive Documentation
- **Swagger UI**: http://a2d474d5fbb694ac5a295b05ba4ee566-8ce5ff8e72034235.elb.ap-south-1.amazonaws.com/docs
- **ReDoc**: http://a2d474d5fbb694ac5a295b05ba4ee566-8ce5ff8e72034235.elb.ap-south-1.amazonaws.com/redoc

### Health Check
```
GET /api/v1/health
```

## 📚 API Endpoints

### Onboarding
- `GET /api/v1/onboarding/{provider}/methods` - Get available auth methods
- `POST /api/v1/onboarding/{provider}/init` - Initialize account onboarding
- `GET /api/v1/onboarding/aws/cloudformation-template` - Get CloudFormation template
- `POST /api/v1/onboarding/{provider}/validate` - Validate credentials
- `POST /api/v1/onboarding/aws/validate-json` - Validate from CloudFormation JSON
- `GET /api/v1/onboarding/accounts` - List accounts
- `GET /api/v1/onboarding/accounts/{account_id}` - Get account details
- `DELETE /api/v1/onboarding/accounts/{account_id}` - Delete account

### Credentials
- `POST /api/v1/accounts/{account_id}/credentials` - Store credentials
- `GET /api/v1/accounts/{account_id}/credentials/validate` - Re-validate credentials
- `DELETE /api/v1/accounts/{account_id}/credentials` - Delete credentials

### Schedules
- `POST /api/v1/schedules` - Create schedule
- `GET /api/v1/schedules` - List schedules
- `GET /api/v1/schedules/{schedule_id}` - Get schedule details
- `PUT /api/v1/schedules/{schedule_id}` - Update schedule
- `POST /api/v1/schedules/{schedule_id}/trigger` - Manual trigger
- `DELETE /api/v1/schedules/{schedule_id}` - Delete schedule
- `GET /api/v1/schedules/{schedule_id}/executions` - Get execution history

## 🔐 Supported Providers & Authentication

### AWS
- **IAM Role** (Recommended): Secure cross-account role assumption
- **Access Key**: IAM user credentials

### Azure
- **Service Principal**: Azure AD service principal

### GCP
- **Service Account**: Service account JSON key

### AliCloud
- **Access Key**: AccessKey ID and Secret

### OCI
- **User Principal**: User OCID with API key

### IBM
- **API Key**: IBM Cloud API key

## 📖 Documentation

- **[UI_TEAM_HANDOVER.md](UI_TEAM_HANDOVER.md)** - Complete API documentation for UI team
- **[AWS_SERVICES_SETUP.md](AWS_SERVICES_SETUP.md)** - AWS services setup guide
- **[AWS_ARCHITECTURE.md](AWS_ARCHITECTURE.md)** - Architecture details
- **[DEPLOY_TO_EKS.md](DEPLOY_TO_EKS.md)** - EKS deployment guide
- **[EXTERNAL_ACCESS.md](EXTERNAL_ACCESS.md)** - External access configuration
- **[ACCESS_GUIDE.md](ACCESS_GUIDE.md)** - Access methods guide

## 🗄️ Data Storage

### DynamoDB Tables
- `threat-engine-tenants` - Tenant information
- `threat-engine-providers` - Cloud provider configurations
- `threat-engine-accounts` - Account details
- `threat-engine-schedules` - Scan schedules
- `threat-engine-executions` - Execution history
- `threat-engine-scan-results` - Scan results

### Secrets Manager
- Credentials stored with prefix: `threat-engine/{account_id}`
- Encrypted with KMS key: `alias/threat-engine-secrets`
- Automatic rotation support

## 🔧 Configuration

### Environment Variables

```bash
# AWS Services
AWS_REGION=ap-south-1
SECRETS_MANAGER_PREFIX=threat-engine
SECRETS_MANAGER_KMS_KEY_ID=alias/threat-engine-secrets

# Platform
PLATFORM_AWS_ACCOUNT_ID=588989875114

# API
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=INFO

# Scheduler
SCHEDULER_INTERVAL_SECONDS=60

# Engine URLs (for EKS)
AWS_ENGINE_URL=http://aws-compliance-engine.threat-engine-engines.svc.cluster.local
# ... (other engines)
```

## 🧪 Testing

### Local Testing
```bash
# Test AWS setup
python3 test_aws_setup.py

# Test API locally
python3 test_local.py
```

### Health Check
```bash
curl http://a2d474d5fbb694ac5a295b05ba4ee566-8ce5ff8e72034235.elb.ap-south-1.amazonaws.com/api/v1/health
```

## 📦 Project Structure

```
onboarding/
├── api/                    # FastAPI endpoints
│   ├── onboarding.py       # Account onboarding
│   ├── credentials.py      # Credential management
│   ├── schedules.py        # Schedule management
│   └── health.py           # Health checks
├── database/               # DynamoDB operations
│   ├── dynamodb_tables.py  # Table definitions
│   └── dynamodb_operations.py  # CRUD operations
├── storage/                # Credential storage
│   └── secrets_manager_storage.py  # Secrets Manager integration
├── scheduler/              # Scheduler service
│   ├── scheduler_service.py
│   ├── task_executor.py
│   └── main.py
├── validators/             # Credential validators
├── models/                 # Pydantic models
├── utils/                  # Utilities
└── templates/              # CloudFormation templates
```

## 🚢 Deployment

### Docker Images
- `yadavanup84/threat-engine-onboarding-api:latest`
- `yadavanup84/threat-engine-scheduler:latest`

### Kubernetes
- **Namespace**: `threat-engine-engines`
- **Service**: `onboarding-api` (ClusterIP + LoadBalancer)
- **Replicas**: Onboarding API (2), Scheduler (1)

## 🔒 Security

- ✅ Credentials encrypted with AWS KMS
- ✅ Secrets stored in AWS Secrets Manager
- ✅ IAM role-based access (IRSA)
- ✅ No credentials in code or environment variables
- ✅ Automatic key rotation

## 📊 Features

- Multi-tenant support
- Multiple authentication methods per CSP
- Secure credential storage (AWS Secrets Manager + KMS)
- Scheduled scan execution
- Execution history tracking
- CloudFormation template generation
- RESTful API with OpenAPI documentation

## 🆘 Support

- **API Documentation**: See [UI_TEAM_HANDOVER.md](UI_TEAM_HANDOVER.md)
- **Deployment Issues**: See [DEPLOY_TO_EKS.md](DEPLOY_TO_EKS.md)
- **AWS Setup**: See [AWS_SERVICES_SETUP.md](AWS_SERVICES_SETUP.md)

---

**Version**: 1.0.0  
**Last Updated**: 2026-01-03
