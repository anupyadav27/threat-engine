#!/bin/bash

# Setup IAM permissions for S3 access
# Usage: ./setup-s3-iam-permissions.sh [role-name]

set -e

ROLE_NAME="${1:-threat-engine-platform-role}"
POLICY_NAME="threat-engine-s3-cspm-lgtech-access"
POLICY_FILE="/Users/apple/Desktop/threat-engine/kubernetes/iam/s3-access-policy.json"

echo "=========================================="
echo "Setting up S3 IAM Permissions"
echo "=========================================="

# Check if role exists
if ! aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
    echo "❌ Role '$ROLE_NAME' not found!"
    echo ""
    echo "Available roles:"
    aws iam list-roles --query "Roles[?contains(RoleName, 'threat') || contains(RoleName, 'platform') || contains(RoleName, 'eks')].RoleName" --output table
    exit 1
fi

echo "✅ Found role: $ROLE_NAME"

# Create policy if it doesn't exist
POLICY_ARN=$(aws iam list-policies --scope Local --query "Policies[?PolicyName=='${POLICY_NAME}'].Arn" --output text 2>/dev/null)

if [ -z "$POLICY_ARN" ]; then
    echo "Creating IAM policy: $POLICY_NAME"
    POLICY_ARN=$(aws iam create-policy \
        --policy-name "$POLICY_NAME" \
        --policy-document "file://${POLICY_FILE}" \
        --query 'Policy.Arn' \
        --output text)
    echo "✅ Policy created: $POLICY_ARN"
else
    echo "✅ Policy already exists: $POLICY_ARN"
    echo "Updating policy..."
    aws iam create-policy-version \
        --policy-arn "$POLICY_ARN" \
        --policy-document "file://${POLICY_FILE}" \
        --set-as-default &>/dev/null || echo "Policy version may be the same"
fi

# Attach policy to role
echo ""
echo "Attaching policy to role: $ROLE_NAME"
aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$POLICY_ARN" || echo "Policy may already be attached"

echo ""
echo "✅ S3 permissions configured!"
echo ""
echo "Role: $ROLE_NAME"
echo "Policy: $POLICY_ARN"
echo "S3 Bucket: s3://cspm-lgtech/"
echo ""
echo "Permissions granted:"
echo "  - s3:PutObject"
echo "  - s3:GetObject"
echo "  - s3:ListBucket"
echo "  - s3:DeleteObject"
echo "  - s3:PutObjectAcl"
echo "  - s3:GetObjectAcl"

