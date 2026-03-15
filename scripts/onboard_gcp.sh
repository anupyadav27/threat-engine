#!/bin/bash
# GCP Onboarding Script

API_URL="http://localhost:8008"
GCP_PROJECT="test-215908"

echo "=========================================="
echo "GCP Project Onboarding"
echo "=========================================="
echo ""

# Check authentication
echo "Checking authentication..."
if ! gcloud projects list --limit=1 &>/dev/null; then
    echo "Authentication expired. Please run:"
    echo "  gcloud auth login"
    exit 1
fi

echo "Authenticated successfully"
echo ""

# Set project
gcloud config set project $GCP_PROJECT 2>/dev/null || true

echo "Project ID: $GCP_PROJECT"
echo ""

# Create service account
SA_NAME="threat-engine-$(date +%s)"
SA_EMAIL="$SA_NAME@$GCP_PROJECT.iam.gserviceaccount.com"

echo "Creating Service Account..."
gcloud iam service-accounts create "$SA_NAME" \
  --display-name "Threat Engine Service Account" \
  --project="$GCP_PROJECT"

echo "Service Account created: $SA_EMAIL"
echo ""

# Grant viewer role
echo "Granting Viewer role..."
gcloud projects add-iam-policy-binding "$GCP_PROJECT" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/viewer" \
  --quiet

echo "Role granted"
echo ""

# Create key
KEY_FILE="/tmp/gcp-threat-engine-key.json"
echo "Creating key file..."
gcloud iam service-accounts keys create "$KEY_FILE" \
  --iam-account="$SA_EMAIL" \
  --project="$GCP_PROJECT"

echo "Key created: $KEY_FILE"
echo ""

# Setup port-forward
echo "Setting up port-forward..."
pkill -f "port-forward.*8008" 2>/dev/null || true
kubectl port-forward -n threat-engine-engines svc/engine-onboarding 8008:80 > /dev/null 2>&1 &
sleep 3
echo ""

# Read key
GCP_KEY=$(cat "$KEY_FILE")

# Phase 1: Create account
echo "Phase 1: Creating account..."
curl -s -X POST $API_URL/api/v1/cloud-accounts \
  -H "Content-Type: application/json" \
  -d "{
    \"account_id\": \"$GCP_PROJECT\",
    \"customer_id\": \"local-test\",
    \"customer_email\": \"test@local.dev\",
    \"tenant_id\": \"local\",
    \"tenant_name\": \"Local Test\",
    \"account_name\": \"GCP Project $GCP_PROJECT\",
    \"provider\": \"gcp\",
    \"credential_type\": \"gcp_service_account\"
  }" | jq '{account_id, account_status}'

echo ""

# Phase 2: Deploy credentials
echo "Phase 2: Deploying credentials..."
curl -s -X PATCH $API_URL/api/v1/cloud-accounts/$GCP_PROJECT/deployment \
  -H "Content-Type: application/json" \
  -d "{
    \"credential_type\": \"gcp_service_account\",
    \"credentials\": $GCP_KEY
  }" | jq '{account_id, account_onboarding_status, credential_ref}'

echo ""

# Phase 3: Verify
echo "Phase 3: Verifying account..."
curl -s $API_URL/api/v1/cloud-accounts/$GCP_PROJECT | jq '{
  account_id,
  provider,
  credential_ref,
  account_onboarding_status
}'

echo ""

# Cleanup
echo "Cleaning up key file..."
rm -f "$KEY_FILE"

echo ""
echo "GCP onboarding complete!"
echo ""
echo "Summary:"
echo "  Project: $GCP_PROJECT"
echo "  Service Account: $SA_EMAIL"
echo "  Credentials: Stored in Secrets Manager"
echo ""
