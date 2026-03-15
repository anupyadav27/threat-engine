# CSP Account Onboarding Guide

This guide explains how to onboard your Cloud Service Provider (CSP) accounts to the Threat Engine using local credentials.

---

## Quick Start

### Step 1: Collect Local Credentials

Run this script to discover all CSP credentials configured on your local system:

```bash
cd /Users/apple/Desktop/threat-engine
./scripts/collect_local_credentials.sh
```

**What it does:**
- ✅ Checks AWS CLI profiles and validates them
- ✅ Lists Azure subscriptions (if logged in)
- ✅ Lists GCP projects (if logged in)
- ✅ Finds service account keys
- ✅ Saves summary to `local_credentials.txt`

**Output:**
```
==========================================
Collecting CSP Credentials from Local System
==========================================

1. Checking AWS Credentials...
✅ AWS CLI found
Profile: default
  Account ID: 588989875114
  ✅ Valid credentials

Profile: prod
  Account ID: 123456789012
  ✅ Valid credentials

2. Checking Azure Credentials...
✅ Azure CLI found
✅ Azure logged in
...
```

---

### Step 2: Test Onboarding API

Onboard an AWS account using your local AWS CLI credentials:

```bash
# Use default AWS profile
./scripts/test_onboarding_api.sh

# OR specify a profile
AWS_PROFILE=prod ./scripts/test_onboarding_api.sh
```

**What it does:**
1. ✅ Gets AWS credentials from local AWS CLI profile
2. ✅ Creates account via API (`POST /api/v1/cloud-accounts`)
3. ✅ Deploys with credentials (`PATCH /api/v1/cloud-accounts/{id}/deployment`)
   - **Automatically stores credentials in AWS Secrets Manager**
   - **Database stores only the reference: `threat-engine/account/{account_id}`**
4. ✅ Validates credentials (`POST /api/v1/cloud-accounts/{id}/validate-credentials`)
5. ✅ Creates schedule (`POST /api/v1/cloud-accounts/{id}/validate`)
6. ✅ Verifies in database
7. ✅ Verifies in Secrets Manager

**Expected Output:**
```
==========================================
Testing Onboarding API
==========================================

Step 1: Collecting AWS credentials...
✅ AWS Account ID: 588989875114
✅ Access Key: AKIA...
✅ Region: ap-south-1

Step 2: Creating account via API...
✅ Account created with status: pending

Step 3: Deploying account with credentials...
✅ Account deployed successfully
✅ Credential reference: threat-engine/account/588989875114

Step 4: Validating credentials...
✅ Credentials validated successfully

Step 5: Final validation and scheduling...
✅ Account is now ACTIVE and scheduled

Step 6: Verifying in database...
Account found in database:
  Account ID: 588989875114
  Status: active
  Credential Ref: threat-engine/account/588989875114
  Validation Status: valid
  Schedule Enabled: True

Step 7: Verifying credentials in Secrets Manager...
✅ Secret found in Secrets Manager
```

---

## How It Works

### Architecture

```
┌─────────────────┐
│  Local System   │
│  AWS CLI        │
│  ~/.aws/        │
└────────┬────────┘
         │
         │ 1. Read credentials
         ↓
┌─────────────────┐
│  Test Script    │
│  Extract keys   │
└────────┬────────┘
         │
         │ 2. API Call with credentials
         ↓
┌─────────────────────────┐
│  Onboarding API         │
│  /deployment endpoint   │
└────────┬────────────────┘
         │
         │ 3. Store credentials
         ↓
┌─────────────────────────┐
│  AWS Secrets Manager    │
│  threat-engine/account/ │
│  {account_id}           │
└─────────────────────────┘
         │
         │ 4. Store reference only
         ↓
┌─────────────────────────┐
│  PostgreSQL Database    │
│  cloud_accounts table   │
│  credential_ref field   │
└─────────────────────────┘
         │
         │ 5. Engines retrieve
         ↓
┌─────────────────────────┐
│  All Engines            │
│  Discovery, Check, etc  │
│  Use credential_ref     │
└─────────────────────────┘
```

### Credential Flow

**For Access Key Method:**

1. **User provides:** Access Key ID + Secret Access Key
2. **API stores in Secrets Manager:**
   ```json
   {
     "credential_type": "aws_access_key",
     "credentials": {
       "access_key_id": "AKIA...",
       "secret_access_key": "..."
     },
     "account_id": "588989875114",
     "created_at": "2026-02-17T..."
   }
   ```
3. **Database stores:** `credential_ref = "threat-engine/account/588989875114"`
4. **Engines retrieve:** Call Secrets Manager with the reference

**For IAM Role Method:**

1. **User provides:** Role ARN + External ID
2. **API stores in Secrets Manager:**
   ```json
   {
     "credential_type": "iam_role",
     "credentials": {
       "role_arn": "arn:aws:iam::123456789012:role/ThreatEngineRole",
       "external_id": "threat-engine-prod"
     },
     "account_id": "123456789012",
     "created_at": "2026-02-17T..."
   }
   ```
3. **Database stores:** `credential_ref = "threat-engine/account/123456789012"`
4. **Engines retrieve:** Call Secrets Manager, then assume role

---

## Manual Onboarding (Using curl)

If you prefer to onboard manually without the script:

### Step 1: Create Account

```bash
curl -X POST http://localhost:8008/api/v1/cloud-accounts \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "588989875114",
    "customer_id": "my-company",
    "customer_email": "security@company.com",
    "tenant_id": "production",
    "tenant_name": "Production Environment",
    "account_name": "AWS Production Account",
    "provider": "aws",
    "credential_type": "aws_access_key"
  }'
```

### Step 2: Deploy with Credentials

**For Access Key:**
```bash
curl -X PATCH http://localhost:8008/api/v1/cloud-accounts/588989875114/deployment \
  -H "Content-Type: application/json" \
  -d '{
    "credential_type": "aws_access_key",
    "credentials": {
      "access_key_id": "AKIA...",
      "secret_access_key": "..."
    }
  }'
```

**For IAM Role:**
```bash
curl -X PATCH http://localhost:8008/api/v1/cloud-accounts/588989875114/deployment \
  -H "Content-Type: application/json" \
  -d '{
    "credential_type": "iam_role",
    "credentials": {
      "role_arn": "arn:aws:iam::588989875114:role/ThreatEngineRole",
      "external_id": "my-external-id"
    }
  }'
```

### Step 3: Validate Credentials

```bash
curl -X POST http://localhost:8008/api/v1/cloud-accounts/588989875114/validate-credentials
```

### Step 4: Create Schedule

```bash
curl -X POST http://localhost:8008/api/v1/cloud-accounts/588989875114/validate \
  -H "Content-Type: application/json" \
  -d '{
    "cron_expression": "0 2 * * *",
    "include_regions": ["ap-south-1", "us-east-1"],
    "include_services": ["ec2", "s3", "iam", "rds"],
    "engines_requested": ["discovery", "check", "inventory", "threat"]
  }'
```

---

## Onboarding Multiple Accounts

### From Different AWS Profiles

```bash
# Onboard default profile
AWS_PROFILE=default ./scripts/test_onboarding_api.sh

# Onboard production profile
AWS_PROFILE=prod ./scripts/test_onboarding_api.sh

# Onboard development profile
AWS_PROFILE=dev ./scripts/test_onboarding_api.sh
```

### Batch Onboarding

Create a simple loop:

```bash
#!/bin/bash
for profile in default prod dev staging; do
    echo "Onboarding profile: $profile"
    AWS_PROFILE=$profile ./scripts/test_onboarding_api.sh
    echo "---"
    sleep 2
done
```

---

## Verification

### Check Account in API

```bash
# List all accounts
curl http://localhost:8008/api/v1/cloud-accounts | jq '.count'

# Get specific account
curl http://localhost:8008/api/v1/cloud-accounts/588989875114 | jq .

# Filter by tenant
curl "http://localhost:8008/api/v1/cloud-accounts?tenant_id=production" | jq .
```

### Check Database

```bash
kubectl exec -n threat-engine-engines deployment/engine-onboarding -- python3 -c "
import psycopg2
conn = psycopg2.connect(
    host='postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com',
    user='postgres',
    password='jtv2BkJF8qoFtAKP',
    dbname='threat_engine_onboarding'
)
cur = conn.cursor()
cur.execute('SELECT account_id, account_name, account_status, credential_ref FROM cloud_accounts')
for row in cur.fetchall():
    print(f'{row[0]} | {row[1]} | {row[2]} | {row[3]}')
"
```

### Check Secrets Manager

```bash
# List all secrets
aws secretsmanager list-secrets \
  --region ap-south-1 \
  --query 'SecretList[?starts_with(Name, `threat-engine/account/`)].Name'

# Get specific secret (metadata only)
aws secretsmanager describe-secret \
  --secret-id threat-engine/account/588989875114 \
  --region ap-south-1

# Get secret value (SENSITIVE!)
aws secretsmanager get-secret-value \
  --secret-id threat-engine/account/588989875114 \
  --region ap-south-1 \
  --query SecretString \
  --output text | jq .
```

---

## Troubleshooting

### Error: "Cannot connect to API"

```bash
# Check if port-forward is running
ps aux | grep port-forward

# Restart port-forward
pkill -f "port-forward.*8008"
kubectl port-forward -n threat-engine-engines svc/engine-onboarding 8008:80 &
sleep 3
```

### Error: "Account already exists"

The account is already onboarded. To update it:

```bash
# Update credentials
curl -X PATCH http://localhost:8008/api/v1/cloud-accounts/{account_id}/deployment \
  -H "Content-Type: application/json" \
  -d '{...new credentials...}'
```

### Error: "Credential validation failed"

Check the validation errors:

```bash
curl -X POST http://localhost:8008/api/v1/cloud-accounts/{account_id}/validate-credentials | jq '.errors'
```

Common issues:
- Invalid access key/secret
- IAM role not assumable (check trust policy)
- Missing permissions (need EC2 describe permissions for validation)

---

## Security Best Practices

### 1. Credential Storage
- ✅ **Never commit credentials to git**
- ✅ **Credentials stored encrypted in Secrets Manager**
- ✅ **Database stores only references**
- ✅ **Use IAM roles when possible** (more secure than access keys)

### 2. Access Keys
- ⚠️ Rotate regularly (every 90 days)
- ⚠️ Use least privilege IAM policies
- ⚠️ Monitor usage with CloudTrail

### 3. IAM Roles
- ✅ Preferred method (no long-lived credentials)
- ✅ Use external ID for additional security
- ✅ Restrict trust policy to platform account only

### 4. Secrets Manager
- Encryption: AWS managed KMS key (default)
- Optional: Custom KMS key via `SECRETS_MANAGER_KMS_KEY_ID`
- Recovery: 7-day window for deleted secrets
- Rotation: Can be enabled for automatic rotation

---

## Next Steps

After onboarding accounts:

1. **Verify accounts are active:**
   ```bash
   curl http://localhost:8008/api/v1/cloud-accounts | jq '.accounts[] | {account_id, account_status}'
   ```

2. **Trigger adhoc scans** (when orchestrator is ready):
   ```bash
   # Via orchestrator API
   curl -X POST http://orchestrator:8080/api/v1/scans/trigger \
     -H "Content-Type: application/json" \
     -d '{
       "account_id": "588989875114",
       "trigger_type": "manual",
       "engines": ["discovery", "check", "inventory"]
     }'
   ```

3. **Wait for scheduled scans:**
   - Schedules run based on cron expression
   - Default: Daily at 2 AM (`0 2 * * *`)
   - Check next run time in database: `schedule_next_run_at`

---

## Files Reference

- `collect_local_credentials.sh` - Discover local CSP credentials
- `test_onboarding_api.sh` - Test onboarding with AWS credentials
- `README_ONBOARDING.md` - This file

---

**Happy Onboarding! 🎉**
