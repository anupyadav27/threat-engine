#!/bin/bash
# OCI Onboarding Script

API_URL="http://localhost:8008"
OCI_CONFIG="$HOME/.oci/config"

echo "=========================================="
echo "OCI Tenancy Onboarding"
echo "=========================================="
echo ""

# Check if config exists
if [ ! -f "$OCI_CONFIG" ]; then
    echo "Error: OCI config not found at $OCI_CONFIG"
    exit 1
fi

# Read from config
TENANCY_OCID=$(grep "^tenancy" "$OCI_CONFIG" | cut -d'=' -f2 | tr -d ' ')
USER_OCID=$(grep "^user" "$OCI_CONFIG" | cut -d'=' -f2 | tr -d ' ')
REGION=$(grep "^region" "$OCI_CONFIG" | cut -d'=' -f2 | tr -d ' ')
KEY_FILE=$(grep "^key_file" "$OCI_CONFIG" | cut -d'=' -f2 | tr -d ' ')

echo "Configuration Found:"
echo "  Tenancy: $TENANCY_OCID"
echo "  User: $USER_OCID"
echo "  Region: $REGION"
echo "  Key File: $KEY_FILE"
echo ""

# Check if key file exists
if [ ! -f "$KEY_FILE" ]; then
    echo "Error: Private key file not found: $KEY_FILE"
    exit 1
fi

# Get fingerprint - prompt user
echo "Please enter your OCI API Key Fingerprint"
echo "(Get it from OCI Console > User Settings > API Keys)"
read -p "Fingerprint: " FINGERPRINT

echo ""

# Setup port-forward
echo "Setting up port-forward..."
pkill -f "port-forward.*8008" 2>/dev/null || true
kubectl port-forward -n threat-engine-engines svc/engine-onboarding 8008:80 > /dev/null 2>&1 &
sleep 3

# Phase 1: Create account
echo "Phase 1: Creating account..."
curl -s -X POST $API_URL/api/v1/cloud-accounts \
  -H "Content-Type: application/json" \
  -d "{
    \"account_id\": \"$TENANCY_OCID\",
    \"customer_id\": \"local-test\",
    \"customer_email\": \"test@local.dev\",
    \"tenant_id\": \"local\",
    \"tenant_name\": \"Local Test\",
    \"account_name\": \"OCI Tenancy\",
    \"provider\": \"oci\",
    \"credential_type\": \"oci_api_key\"
  }" | jq '{account_id, account_status}'

echo ""

# Read private key and escape for JSON
PRIVATE_KEY=$(cat "$KEY_FILE" | jq -Rs .)

# Phase 2: Deploy credentials
echo "Phase 2: Deploying credentials..."
curl -s -X PATCH $API_URL/api/v1/cloud-accounts/$TENANCY_OCID/deployment \
  -H "Content-Type: application/json" \
  -d "{
    \"credential_type\": \"oci_api_key\",
    \"credentials\": {
      \"user_ocid\": \"$USER_OCID\",
      \"tenancy_ocid\": \"$TENANCY_OCID\",
      \"region\": \"$REGION\",
      \"fingerprint\": \"$FINGERPRINT\",
      \"private_key\": $PRIVATE_KEY
    }
  }" | jq '{account_id, account_onboarding_status, credential_ref}'

echo ""

# Phase 3: Verify
echo "Phase 3: Verifying account..."
curl -s $API_URL/api/v1/cloud-accounts/$TENANCY_OCID | jq '{
  account_id,
  provider,
  credential_ref,
  account_onboarding_status
}'

echo ""
echo "OCI onboarding complete!"
echo ""
