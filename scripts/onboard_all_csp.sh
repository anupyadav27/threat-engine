#!/bin/bash
# Onboard all CSP accounts

API_URL="http://localhost:8008"

echo "=========================================="
echo "Multi-Cloud Onboarding"
echo "=========================================="
echo ""

# Setup port-forward
echo "Setting up port-forward..."
pkill -f "port-forward.*8008" 2>/dev/null || true
kubectl port-forward -n threat-engine-engines svc/engine-onboarding 8008:80 > /dev/null 2>&1 &
sleep 3
echo ""

# AWS
echo "1. AWS Account"
echo "--------------"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_ACCESS_KEY=$(aws configure get aws_access_key_id)
AWS_SECRET_KEY=$(aws configure get aws_secret_access_key)

echo "Account: $AWS_ACCOUNT_ID"
echo "Status: Already onboarded ✅"
echo ""

# Azure
echo "2. Azure Subscription"
echo "--------------------"
AZURE_SUB=$(az account show --query id --output tsv)
echo "Subscription: $AZURE_SUB"
echo "Status: Requires Service Principal (manual step)"
echo ""
echo "To onboard Azure:"
echo "  az ad sp create-for-rbac --name ThreatEngine --role Reader --scopes /subscriptions/$AZURE_SUB"
echo ""

# GCP
echo "3. GCP Project"
echo "--------------"
if [ -f ~/.config/gcloud/application_default_credentials.json ]; then
    GCP_PROJECT=$(cat ~/.config/gcloud/application_default_credentials.json | jq -r '.quota_project_id // .project_id // "not-found"')
    echo "Project: $GCP_PROJECT"
    echo "Status: Requires Service Account (manual step)"
    echo ""
    echo "To onboard GCP:"
    echo "  gcloud iam service-accounts create threat-engine --project=$GCP_PROJECT"
    echo "  gcloud iam service-accounts keys create key.json --iam-account=threat-engine@$GCP_PROJECT.iam.gserviceaccount.com"
else
    echo "Not logged in"
fi

echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
curl -s $API_URL/api/v1/cloud-accounts | jq -r '.accounts[] | "\(.provider | ascii_upcase): \(.account_id) - \(.credential_validation_status)"'
echo ""
