#!/bin/bash

# Setup IAM Role for Service Account (IRSA) for SecOps Scanner
# This script helps create the IAM role and trust policy for S3 access

set -e

# Configuration
ROLE_NAME="secops-s3-access-role"
POLICY_NAME="SecOpsS3Policy"
BUCKET_NAME="cspm-lgtech"
REGION="ap-south-1"

echo "=========================================="
echo "SecOps Scanner IAM Role Setup"
echo "=========================================="

# Get account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "AWS Account ID: $ACCOUNT_ID"

# Get cluster name
echo ""
read -p "Enter your EKS cluster name: " CLUSTER_NAME

# Get OIDC provider ID
echo "Fetching OIDC provider ID..."
OIDC_ID=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION --query "cluster.identity.oidc.issuer" --output text | cut -d '/' -f 5)
echo "OIDC Provider ID: $OIDC_ID"

if [ -z "$OIDC_ID" ]; then
    echo "ERROR: Could not find OIDC provider. Make sure your cluster has IRSA enabled."
    exit 1
fi

OIDC_PROVIDER_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/oidc.eks.${REGION}.amazonaws.com/id/${OIDC_ID}"
echo "OIDC Provider ARN: $OIDC_PROVIDER_ARN"

# Check if role exists
if aws iam get-role --role-name $ROLE_NAME &> /dev/null; then
    echo ""
    echo "Role $ROLE_NAME already exists. Updating trust policy..."
    UPDATE_EXISTING=true
else
    echo ""
    echo "Creating IAM role: $ROLE_NAME"
    UPDATE_EXISTING=false
fi

# Create trust policy
TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "${OIDC_PROVIDER_ARN}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.${REGION}.amazonaws.com/id/${OIDC_ID}:sub": "system:serviceaccount:secops-engine:secops-scanner-sa"
        }
      }
    }
  ]
}
EOF
)

if [ "$UPDATE_EXISTING" = true ]; then
    echo "Updating trust policy..."
    aws iam update-assume-role-policy \
        --role-name $ROLE_NAME \
        --policy-document "$TRUST_POLICY"
else
    aws iam create-role \
        --role-name $ROLE_NAME \
        --assume-role-policy-document "$TRUST_POLICY" \
        --description "IAM role for SecOps Scanner to access S3"
fi

# Create S3 policy
S3_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${BUCKET_NAME}",
        "arn:aws:s3:::${BUCKET_NAME}/*"
      ]
    }
  ]
}
EOF
)

echo ""
echo "Creating/updating S3 policy..."
aws iam put-role-policy \
    --role-name $ROLE_NAME \
    --policy-name $POLICY_NAME \
    --policy-document "$S3_POLICY"

# Get role ARN
ROLE_ARN=$(aws iam get-role --role-name $ROLE_NAME --query 'Role.Arn' --output text)

echo ""
echo "=========================================="
echo "Setup completed!"
echo "=========================================="
echo ""
echo "Role ARN: $ROLE_ARN"
echo ""
echo "Update serviceaccount.yaml with this ARN:"
echo "  eks.amazonaws.com/role-arn: $ROLE_ARN"
echo ""
echo "Or run this command to update automatically:"
echo "  sed -i.bak 's|arn:aws:iam::YOUR_ACCOUNT_ID:role/secops-s3-access-role|$ROLE_ARN|g' serviceaccount.yaml"

