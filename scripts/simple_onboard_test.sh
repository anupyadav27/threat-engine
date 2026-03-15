#!/bin/bash
# Simple onboarding test

set -e

API_URL="http://localhost:8008"

echo "=========================================="
echo "Simple Onboarding Test"
echo "=========================================="
echo ""

# Setup port-forward
echo "Setting up port-forward..."
pkill -f "port-forward.*8008" 2>/dev/null || true
kubectl port-forward -n threat-engine-engines svc/engine-onboarding 8008:80 > /dev/null 2>&1 &
sleep 3
echo "✅ Port-forward ready"
echo ""

# Get AWS account info
echo "Getting AWS account info..."
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_ACCESS_KEY=$(aws configure get aws_access_key_id)
AWS_SECRET_KEY=$(aws configure get aws_secret_access_key)
AWS_REGION=$(aws configure get region || echo "ap-south-1")

echo "✅ Account ID: $AWS_ACCOUNT_ID"
echo "✅ Access Key: ${AWS_ACCESS_KEY:0:10}..."
echo "✅ Region: $AWS_REGION"
echo ""

# Create account
echo "Creating account..."
curl -s -X POST $API_URL/api/v1/cloud-accounts \
  -H "Content-Type: application/json" \
  -d "{
    \"account_id\": \"$AWS_ACCOUNT_ID\",
    \"customer_id\": \"local-test\",
    \"customer_email\": \"test@local.dev\",
    \"tenant_id\": \"local\",
    \"tenant_name\": \"Local Test\",
    \"account_name\": \"AWS Local Account\",
    \"provider\": \"aws\",
    \"credential_type\": \"aws_access_key\"
  }" | jq '{account_id, account_status}'

echo ""

# Deploy with credentials
echo "Deploying with credentials (storing in Secrets Manager)..."
curl -s -X PATCH $API_URL/api/v1/cloud-accounts/$AWS_ACCOUNT_ID/deployment \
  -H "Content-Type: application/json" \
  -d "{
    \"credential_type\": \"aws_access_key\",
    \"credentials\": {
      \"access_key_id\": \"$AWS_ACCESS_KEY\",
      \"secret_access_key\": \"$AWS_SECRET_KEY\"
    }
  }" | jq '{account_id, account_onboarding_status, credential_ref}'

echo ""

echo "✅ Onboarding complete!"
echo ""
echo "Verify with:"
echo "  curl $API_URL/api/v1/cloud-accounts/$AWS_ACCOUNT_ID | jq ."
echo ""
