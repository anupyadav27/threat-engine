# Testing Guide - Onboarding API

## Prerequisites

1. **AWS Credentials** - Configure AWS credentials for DynamoDB and Secrets Manager:
   ```bash
   export AWS_REGION=ap-south-1
   export AWS_ACCESS_KEY_ID=your-key
   export AWS_SECRET_ACCESS_KEY=your-secret
   ```

2. **DynamoDB Tables** - Ensure tables are created:
   ```bash
   python3 -c "from onboarding.database.dynamodb_tables import create_tables; create_tables()"
   ```

3. **Python Dependencies** - Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Local Testing

### 1. Start Onboarding API

```bash
cd /Users/apple/Desktop/onboarding
python main.py
```

API will be available at `http://localhost:8000`

### 2. Test Health Endpoint

```bash
curl http://localhost:8000/api/v1/health
```

Expected response:
```json
{
  "status": "healthy",
  "dynamodb": "connected",
  "secrets_manager": "connected",
  "version": "1.0.0"
}
```

### 3. Run Test Scripts

**Test AWS Setup:**
```bash
python3 test_aws_setup.py
```

**Test Local API:**
```bash
python3 test_local.py
```

**Quick Test (with service startup):**
```bash
./quick_test.sh
```

## API Testing

### Test Onboarding Flow

**1. Get Available Methods:**
```bash
curl http://localhost:8000/api/v1/onboarding/aws/methods
```

**2. Initialize Onboarding:**
```bash
curl -X POST http://localhost:8000/api/v1/onboarding/aws/init \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "test-tenant-123",
    "account_name": "Test Account"
  }'
```

**3. Get CloudFormation Template:**
```bash
# Use external_id from init response
curl "http://localhost:8000/api/v1/onboarding/aws/cloudformation-template?external_id=YOUR_EXTERNAL_ID"
```

**4. Validate Account (with test credentials):**
```bash
curl -X POST http://localhost:8000/api/v1/onboarding/aws/validate \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "account-uuid-from-init",
    "auth_method": "iam_role",
    "credentials": {
      "role_arn": "arn:aws:iam::123456789012:role/TestRole",
      "external_id": "test-external-id",
      "account_number": "123456789012"
    }
  }'
```

## Integration Testing

### Test with Multiple Services

**Start all services:**
```bash
./start_local_services.sh
```

This starts:
- Onboarding API on port 8000
- AWS Engine API on port 8001
- YAML Rule Builder API on port 8002

**Run integration tests:**
```bash
python3 test_local.py
```

## EKS Testing

### Test Deployed API

**Get LoadBalancer URL:**
```bash
kubectl get svc onboarding-api-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

**Test health:**
```bash
curl http://<loadbalancer-url>/api/v1/health
```

**Port forward (alternative):**
```bash
kubectl port-forward svc/onboarding-api 8000:80 -n threat-engine-engines
curl http://localhost:8000/api/v1/health
```

## Test Scenarios

### Scenario 1: AWS IAM Role Onboarding

1. Initialize onboarding → Get `onboarding_id`, `account_id`, `external_id`
2. Download CloudFormation template
3. Deploy CloudFormation in AWS account
4. Copy CloudFormation JSON output
5. Validate using `validate-json` endpoint
6. Verify account is active

### Scenario 2: AWS Access Key Onboarding

1. Initialize onboarding
2. Enter Access Key ID and Secret Key
3. Validate using `validate` endpoint
4. Verify account is active

### Scenario 3: Schedule Management

1. Create a schedule
2. List schedules
3. Trigger schedule manually
4. View execution history

## Troubleshooting

### DynamoDB Connection Issues

**Error:** `dynamodb: disconnected`

**Solution:**
```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify tables exist
aws dynamodb list-tables --region ap-south-1 | grep threat-engine

# Create tables if missing
python3 -c "from onboarding.database.dynamodb_tables import create_tables; create_tables()"
```

### Secrets Manager Issues

**Error:** `secrets_manager: disconnected`

**Solution:**
```bash
# Check KMS key
aws kms describe-key --key-id alias/threat-engine-secrets --region ap-south-1

# Check IAM permissions
aws iam list-attached-role-policies --role-name threat-engine-platform-role
```

### API Not Starting

**Check logs:**
```bash
python main.py
# Look for import errors or configuration issues
```

**Verify environment:**
```bash
echo $AWS_REGION
echo $SECRETS_MANAGER_PREFIX
```

## Test Data Cleanup

**Clean up test data:**
```python
from onboarding.database.dynamodb_operations import dynamodb, TENANTS_TABLE

# Delete test tenant
table = dynamodb.Table(TENANTS_TABLE)
table.delete_item(Key={'tenant_id': 'test-tenant-id'})
```

**Clean up secrets:**
```python
from onboarding.storage.secrets_manager_storage import secrets_manager_storage

# Delete test secret
secrets_manager_storage.delete('test-account-id')
```

## Automated Testing

### Run All Tests

```bash
# Test AWS setup
python3 test_aws_setup.py

# Test API locally
python3 test_local.py

# Test with services
./quick_test.sh
```

### Expected Results

- ✅ All DynamoDB tables accessible
- ✅ KMS key accessible
- ✅ Secrets Manager accessible
- ✅ IAM permissions correct
- ✅ API endpoints responding
- ✅ Health check passing

---

**See Also:**
- [README.md](README.md) - Main documentation
- [QUICK_START.md](QUICK_START.md) - Quick start guide
- [UI_TEAM_HANDOVER.md](UI_TEAM_HANDOVER.md) - API documentation
