#!/bin/bash
#
# Complete User Flow Test Script
# Tests: Tenant → Provider → Account → Credentials → Scan
#
# Usage:
#   ./scripts/test_complete_user_flow.sh [aws|azure|gcp]
#   Default: aws
#
# Prerequisites:
#   - Onboarding engine running at http://localhost:30010
#   - ConfigScan engine running at http://localhost:30002
#   - AWS credentials available (via AWS CLI config or env vars)
#

set -e

PROVIDER="${1:-aws}"
ONBOARDING_URL="${ONBOARDING_URL:-http://localhost:30010}"
CONFIGSCAN_URL="${CONFIGSCAN_URL:-http://localhost:30002}"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Complete User Flow Test${NC}"
echo -e "${BLUE}Provider: ${PROVIDER}${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Create Tenant
echo -e "${YELLOW}Step 1: Creating Tenant...${NC}"
TENANT_RESPONSE=$(curl -s -X POST "${ONBOARDING_URL}/api/v1/onboarding/tenants" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_name": "test-tenant-'$(date +%s)'",
    "description": "Test tenant for user flow"
  }')

TENANT_ID=$(echo "$TENANT_RESPONSE" | grep -o '"tenant_id":"[^"]*' | cut -d'"' -f4)

if [ -z "$TENANT_ID" ]; then
  echo -e "${RED}❌ Failed to create tenant${NC}"
  echo "$TENANT_RESPONSE" | jq '.' 2>/dev/null || echo "$TENANT_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✅ Tenant created: ${TENANT_ID}${NC}"
echo ""

# Step 2: Create Provider
echo -e "${YELLOW}Step 2: Creating Provider (${PROVIDER})...${NC}"
PROVIDER_RESPONSE=$(curl -s -X POST "${ONBOARDING_URL}/api/v1/onboarding/providers" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"${TENANT_ID}\",
    \"provider_type\": \"${PROVIDER}\"
  }")

PROVIDER_ID=$(echo "$PROVIDER_RESPONSE" | grep -o '"provider_id":"[^"]*' | cut -d'"' -f4)

if [ -z "$PROVIDER_ID" ]; then
  echo -e "${RED}❌ Failed to create provider${NC}"
  echo "$PROVIDER_RESPONSE" | jq '.' 2>/dev/null || echo "$PROVIDER_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✅ Provider created: ${PROVIDER_ID}${NC}"
echo ""

# Step 3: Get Auth Methods
echo -e "${YELLOW}Step 3: Getting available auth methods...${NC}"
METHODS_RESPONSE=$(curl -s -X GET "${ONBOARDING_URL}/api/v1/onboarding/${PROVIDER}/auth-methods")
echo "$METHODS_RESPONSE" | jq '.' 2>/dev/null || echo "$METHODS_RESPONSE"
echo ""

# Step 4: Initialize Account Onboarding
echo -e "${YELLOW}Step 4: Initializing account onboarding...${NC}"
ACCOUNT_NAME="test-account-$(date +%s)"
INIT_RESPONSE=$(curl -s -X POST "${ONBOARDING_URL}/api/v1/onboarding/${PROVIDER}/init" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"${TENANT_ID}\",
    \"account_name\": \"${ACCOUNT_NAME}\",
    \"provider_id\": \"${PROVIDER_ID}\",
    \"auth_method\": \"access_key\"
  }")

ACCOUNT_ID=$(echo "$INIT_RESPONSE" | grep -o '"account_id":"[^"]*' | cut -d'"' -f4)

if [ -z "$ACCOUNT_ID" ]; then
  echo -e "${RED}❌ Failed to initialize account${NC}"
  echo "$INIT_RESPONSE" | jq '.' 2>/dev/null || echo "$INIT_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✅ Account initialized: ${ACCOUNT_ID}${NC}"
echo ""

# Step 5: Get AWS Credentials from CLI config or environment
echo -e "${YELLOW}Step 5: Retrieving AWS credentials...${NC}"

if [ "$PROVIDER" = "aws" ]; then
  # Try to get credentials from AWS CLI config
  AWS_PROFILE="${AWS_PROFILE:-default}"
  
  # Check if AWS CLI is available
  if command -v aws &> /dev/null; then
    echo "Using AWS CLI profile: ${AWS_PROFILE}"
    
    # Try to get credentials from AWS CLI
    AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id --profile "$AWS_PROFILE" 2>/dev/null || echo "")
    AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key --profile "$AWS_PROFILE" 2>/dev/null || echo "")
    
    # Fallback to environment variables
    if [ -z "$AWS_ACCESS_KEY_ID" ]; then
      AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
      AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
    fi
    
    # Get account number
    if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
      export AWS_ACCESS_KEY_ID
      export AWS_SECRET_ACCESS_KEY
      ACCOUNT_NUMBER=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")
    fi
  else
    # Use environment variables directly
    AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}"
    AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}"
    
    if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
      export AWS_ACCESS_KEY_ID
      export AWS_SECRET_ACCESS_KEY
      ACCOUNT_NUMBER=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")
    fi
  fi
  
  if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo -e "${RED}❌ AWS credentials not found${NC}"
    echo "Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables"
    echo "Or configure AWS CLI: aws configure"
    exit 1
  fi
  
  echo -e "${GREEN}✅ AWS credentials retrieved${NC}"
  if [ -n "$ACCOUNT_NUMBER" ]; then
    echo "Account Number: ${ACCOUNT_NUMBER}"
  fi
  echo ""
  
  # Step 6: Store Credentials
  echo -e "${YELLOW}Step 6: Storing credentials...${NC}"
  CREDENTIALS_RESPONSE=$(curl -s -X POST "${ONBOARDING_URL}/api/v1/accounts/${ACCOUNT_ID}/credentials" \
    -H "Content-Type: application/json" \
    -d "{
      \"credential_type\": \"aws_access_key\",
      \"credentials\": {
        \"access_key_id\": \"${AWS_ACCESS_KEY_ID}\",
        \"secret_access_key\": \"${AWS_SECRET_ACCESS_KEY}\"
      }
    }")
  
  echo "$CREDENTIALS_RESPONSE" | jq '.' 2>/dev/null || echo "$CREDENTIALS_RESPONSE"
  echo ""
  
  # Step 7: Validate Credentials
  echo -e "${YELLOW}Step 7: Validating credentials...${NC}"
  VALIDATE_RESPONSE=$(curl -s -X POST "${ONBOARDING_URL}/api/v1/onboarding/${PROVIDER}/validate" \
    -H "Content-Type: application/json" \
    -d "{
      \"account_id\": \"${ACCOUNT_ID}\",
      \"auth_method\": \"access_key\",
      \"credentials\": {
        \"credential_type\": \"aws_access_key\",
        \"access_key_id\": \"${AWS_ACCESS_KEY_ID}\",
        \"secret_access_key\": \"${AWS_SECRET_ACCESS_KEY}\"
      }
    }")
  
  echo "$VALIDATE_RESPONSE" | jq '.' 2>/dev/null || echo "$VALIDATE_RESPONSE"
  
  VALIDATION_SUCCESS=$(echo "$VALIDATE_RESPONSE" | grep -o '"success":[^,}]*' | cut -d':' -f2 | tr -d ' ')
  
  if [ "$VALIDATION_SUCCESS" != "true" ]; then
    echo -e "${RED}❌ Credential validation failed${NC}"
    exit 1
  fi
  
  echo -e "${GREEN}✅ Credentials validated${NC}"
  echo ""
  
  # Step 8: Create Schedule
  echo -e "${YELLOW}Step 8: Creating scan schedule...${NC}"
  SCHEDULE_RESPONSE=$(curl -s -X POST "${ONBOARDING_URL}/api/v1/schedules" \
    -H "Content-Type: application/json" \
    -d "{
      \"tenant_id\": \"${TENANT_ID}\",
      \"account_id\": \"${ACCOUNT_ID}\",
      \"name\": \"Test Schedule\",
      \"schedule_type\": \"interval\",
      \"interval_seconds\": 3600,
      \"regions\": [\"us-east-1\"],
      \"services\": [\"ec2\", \"s3\"]
    }")
  
  SCHEDULE_ID=$(echo "$SCHEDULE_RESPONSE" | grep -o '"schedule_id":"[^"]*' | cut -d'"' -f4)
  
  if [ -z "$SCHEDULE_ID" ]; then
    echo -e "${RED}❌ Failed to create schedule${NC}"
    echo "$SCHEDULE_RESPONSE" | jq '.' 2>/dev/null || echo "$SCHEDULE_RESPONSE"
    exit 1
  fi
  
  echo -e "${GREEN}✅ Schedule created: ${SCHEDULE_ID}${NC}"
  echo ""
  
  # Step 9: Trigger Scan
  echo -e "${YELLOW}Step 9: Triggering scan...${NC}"
  TRIGGER_RESPONSE=$(curl -s -X POST "${ONBOARDING_URL}/api/v1/schedules/${SCHEDULE_ID}/trigger" \
    -H "Content-Type: application/json")
  
  EXECUTION_ID=$(echo "$TRIGGER_RESPONSE" | grep -o '"execution_id":"[^"]*' | cut -d'"' -f4)
  
  if [ -z "$EXECUTION_ID" ]; then
    echo -e "${RED}❌ Failed to trigger scan${NC}"
    echo "$TRIGGER_RESPONSE" | jq '.' 2>/dev/null || echo "$TRIGGER_RESPONSE"
    exit 1
  fi
  
  echo -e "${GREEN}✅ Scan triggered: ${EXECUTION_ID}${NC}"
  echo "$TRIGGER_RESPONSE" | jq '.' 2>/dev/null || echo "$TRIGGER_RESPONSE"
  echo ""
  
  # Step 10: Monitor Scan Status
  echo -e "${YELLOW}Step 10: Monitoring scan status...${NC}"
  echo "Execution ID: ${EXECUTION_ID}"
  echo "Polling for status updates (this may take a while)..."
  echo ""
  
  MAX_WAIT=300  # 5 minutes
  ELAPSED=0
  POLL_INTERVAL=10
  
  while [ $ELAPSED -lt $MAX_WAIT ]; do
    STATUS_RESPONSE=$(curl -s -X GET "${ONBOARDING_URL}/api/v1/schedules/${SCHEDULE_ID}/executions/${EXECUTION_ID}/status")
    STATUS=$(echo "$STATUS_RESPONSE" | grep -o '"status":"[^"]*' | cut -d'"' -f4)
    
    echo -n "Status: ${STATUS} (${ELAPSED}s) ... "
    
    if [ "$STATUS" = "completed" ]; then
      echo -e "${GREEN}✅ Scan completed!${NC}"
      echo ""
      echo "$STATUS_RESPONSE" | jq '.' 2>/dev/null || echo "$STATUS_RESPONSE"
      break
    elif [ "$STATUS" = "failed" ]; then
      echo -e "${RED}❌ Scan failed${NC}"
      echo ""
      echo "$STATUS_RESPONSE" | jq '.' 2>/dev/null || echo "$STATUS_RESPONSE"
      exit 1
    fi
    
    echo ""
    sleep $POLL_INTERVAL
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
  done
  
  if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo -e "${YELLOW}⚠️  Scan still running after ${MAX_WAIT}s (timeout)${NC}"
    echo "Check status manually:"
    echo "  curl ${ONBOARDING_URL}/api/v1/schedules/${SCHEDULE_ID}/executions/${EXECUTION_ID}/status"
  fi
  
  echo ""
  echo -e "${BLUE}========================================${NC}"
  echo -e "${GREEN}✅ Complete User Flow Test Finished${NC}"
  echo -e "${BLUE}========================================${NC}"
  echo ""
  echo "Summary:"
  echo "  Tenant ID: ${TENANT_ID}"
  echo "  Provider ID: ${PROVIDER_ID}"
  echo "  Account ID: ${ACCOUNT_ID}"
  echo "  Schedule ID: ${SCHEDULE_ID}"
  echo "  Execution ID: ${EXECUTION_ID}"
  echo ""
  
else
  echo -e "${YELLOW}Provider ${PROVIDER} not yet implemented in test script${NC}"
  echo "Only AWS is currently supported for automated testing"
  exit 1
fi
