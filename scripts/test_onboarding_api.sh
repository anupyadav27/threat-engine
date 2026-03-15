#!/bin/bash
# Test Onboarding API with real credentials

set -e

# Configuration
API_URL="${API_URL:-http://localhost:8008}"
AWS_PROFILE="${AWS_PROFILE:-default}"

echo "=========================================="
echo "Testing Onboarding API"
echo "=========================================="
echo ""
echo "API URL: $API_URL"
echo "AWS Profile: $AWS_PROFILE"
echo ""

# Start port-forward if needed
echo "Setting up port-forward..."
pkill -f "port-forward.*8008" 2>/dev/null || true
kubectl port-forward -n threat-engine-engines svc/engine-onboarding 8008:80 > /dev/null 2>&1 &
sleep 3
echo "✅ Port-forward ready"
echo ""

# Test 1: Get AWS credentials from local profile
echo "Step 1: Collecting AWS credentials from profile '$AWS_PROFILE'..."
echo "----------------------------------------"

# Get account ID
AWS_ACCOUNT_ID=$(AWS_PROFILE=$AWS_PROFILE aws sts get-caller-identity --query Account --output text)
if [ $? -ne 0 ]; then
    echo "❌ Failed to get AWS account ID. Is AWS CLI configured?"
    exit 1
fi
echo "✅ AWS Account ID: $AWS_ACCOUNT_ID"

# Get credentials
AWS_ACCESS_KEY=$(AWS_PROFILE=$AWS_PROFILE aws configure get aws_access_key_id)
AWS_SECRET_KEY=$(AWS_PROFILE=$AWS_PROFILE aws configure get aws_secret_access_key)
AWS_REGION=$(AWS_PROFILE=$AWS_PROFILE aws configure get region || echo "ap-south-1")

echo "✅ Access Key: ${AWS_ACCESS_KEY:0:10}..."
echo "✅ Region: $AWS_REGION"
echo ""

# Test 2: Create account via API
echo "Step 2: Creating account via API..."
echo "----------------------------------------"

CREATE_RESPONSE=$(curl -s -X POST $API_URL/api/v1/cloud-accounts \
  -H "Content-Type: application/json" \
  -d "{
    \"account_id\": \"$AWS_ACCOUNT_ID\",
    \"customer_id\": \"local-test\",
    \"customer_email\": \"test@local.dev\",
    \"tenant_id\": \"local-tenant\",
    \"tenant_name\": \"Local Test Tenant\",
    \"account_name\": \"AWS Account from Local CLI\",
    \"provider\": \"aws\",
    \"credential_type\": \"aws_access_key\"
  }")

echo "$CREATE_RESPONSE" | jq .
echo ""

# Check if creation succeeded
ACCOUNT_STATUS=$(echo "$CREATE_RESPONSE" | jq -r '.account_status // "error"')
if [ "$ACCOUNT_STATUS" != "pending" ] && [ "$ACCOUNT_STATUS" != "error" ]; then
    echo "✅ Account created with status: $ACCOUNT_STATUS"
elif echo "$CREATE_RESPONSE" | grep -q "already exists"; then
    echo "⚠️  Account already exists, continuing..."
else
    echo "❌ Failed to create account"
    exit 1
fi
echo ""

# Test 3: Deploy with credentials
echo "Step 3: Deploying account with credentials..."
echo "----------------------------------------"
echo "This will store credentials in AWS Secrets Manager"
echo ""

DEPLOY_RESPONSE=$(curl -s -X PATCH $API_URL/api/v1/cloud-accounts/$AWS_ACCOUNT_ID/deployment \
  -H "Content-Type: application/json" \
  -d "{
    \"credential_type\": \"aws_access_key\",
    \"credentials\": {
      \"access_key_id\": \"$AWS_ACCESS_KEY\",
      \"secret_access_key\": \"$AWS_SECRET_KEY\"
    }
  }")

echo "$DEPLOY_RESPONSE" | jq .
echo ""

# Check deployment status
ONBOARDING_STATUS=$(echo "$DEPLOY_RESPONSE" | jq -r '.account_onboarding_status // "error"')
if [ "$ONBOARDING_STATUS" = "deployed" ]; then
    echo "✅ Account deployed successfully"
else
    echo "❌ Deployment may have failed, check response above"
fi

CREDENTIAL_REF=$(echo "$DEPLOY_RESPONSE" | jq -r '.credential_ref // "none"')
echo "✅ Credential reference: $CREDENTIAL_REF"
echo ""

# Test 4: Validate credentials
echo "Step 4: Validating credentials..."
echo "----------------------------------------"

VALIDATE_RESPONSE=$(curl -s -X POST $API_URL/api/v1/cloud-accounts/$AWS_ACCOUNT_ID/validate-credentials)

echo "$VALIDATE_RESPONSE" | jq .
echo ""

VALIDATION_SUCCESS=$(echo "$VALIDATE_RESPONSE" | jq -r '.success // false')
if [ "$VALIDATION_SUCCESS" = "true" ]; then
    echo "✅ Credentials validated successfully"
else
    echo "❌ Credential validation failed"
    echo "Errors: $(echo "$VALIDATE_RESPONSE" | jq -r '.errors // []')"
fi
echo ""

# Test 5: Final validation and scheduling
echo "Step 5: Final validation and scheduling..."
echo "----------------------------------------"

FINAL_RESPONSE=$(curl -s -X POST $API_URL/api/v1/cloud-accounts/$AWS_ACCOUNT_ID/validate \
  -H "Content-Type: application/json" \
  -d '{
    "cron_expression": "0 2 * * *",
    "include_regions": ["'$AWS_REGION'", "us-east-1"],
    "include_services": ["ec2", "s3", "iam", "rds", "lambda"],
    "engines_requested": ["discovery", "check", "inventory", "threat", "compliance", "iam", "datasec"]
  }')

echo "$FINAL_RESPONSE" | jq .
echo ""

FINAL_STATUS=$(echo "$FINAL_RESPONSE" | jq -r '.account_status // "error"')
if [ "$FINAL_STATUS" = "active" ]; then
    echo "✅ Account is now ACTIVE and scheduled"
else
    echo "⚠️  Account status: $FINAL_STATUS"
fi
echo ""

# Test 6: Verify in database
echo "Step 6: Verifying in database..."
echo "----------------------------------------"

kubectl exec -n threat-engine-engines deployment/engine-onboarding -- python3 -c "
import psycopg2
from psycopg2.extras import RealDictCursor

conn = psycopg2.connect(
    host='postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com',
    user='postgres',
    password='jtv2BkJF8qoFtAKP',
    dbname='threat_engine_onboarding',
    port=5432
)
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute('''
    SELECT account_id, account_name, account_status,
           credential_type, credential_ref,
           credential_validation_status,
           schedule_enabled, schedule_cron_expression
    FROM cloud_accounts
    WHERE account_id = %s
''', ('$AWS_ACCOUNT_ID',))
row = cur.fetchone()
if row:
    print('Account found in database:')
    print(f'  Account ID: {row[\"account_id\"]}')
    print(f'  Name: {row[\"account_name\"]}')
    print(f'  Status: {row[\"account_status\"]}')
    print(f'  Credential Type: {row[\"credential_type\"]}')
    print(f'  Credential Ref: {row[\"credential_ref\"]}')
    print(f'  Validation Status: {row[\"credential_validation_status\"]}')
    print(f'  Schedule Enabled: {row[\"schedule_enabled\"]}')
    print(f'  Cron Expression: {row[\"schedule_cron_expression\"]}')
else:
    print('Account NOT found in database!')
cur.close()
conn.close()
" 2>/dev/null

echo ""

# Test 7: Verify credentials in Secrets Manager
echo "Step 7: Verifying credentials in AWS Secrets Manager..."
echo "----------------------------------------"

SECRET_VALUE=$(aws secretsmanager get-secret-value \
  --secret-id "threat-engine/account/$AWS_ACCOUNT_ID" \
  --region ap-south-1 \
  --query SecretString \
  --output text 2>/dev/null)

if [ $? -eq 0 ]; then
    echo "✅ Secret found in Secrets Manager"
    echo "$SECRET_VALUE" | jq '{credential_type, account_id, created_at}'
else
    echo "❌ Secret not found in Secrets Manager"
fi
echo ""

# Summary
echo "=========================================="
echo "ONBOARDING TEST COMPLETE"
echo "=========================================="
echo ""
echo "Account ID: $AWS_ACCOUNT_ID"
echo "API URL: $API_URL"
echo ""
echo "Next steps:"
echo "1. Check the account in the API: curl $API_URL/api/v1/cloud-accounts/$AWS_ACCOUNT_ID | jq ."
echo "2. Trigger an adhoc scan (once orchestrator is ready)"
echo "3. Onboard more accounts by changing AWS_PROFILE environment variable"
echo ""
echo "Examples:"
echo "  AWS_PROFILE=prod ./scripts/test_onboarding_api.sh"
echo "  AWS_PROFILE=dev ./scripts/test_onboarding_api.sh"
echo ""
