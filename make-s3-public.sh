#!/bin/bash

# Make S3 bucket and all objects public
# Usage: ./make-s3-public.sh

set -e

BUCKET="cspm-lgtech"
REGION="ap-south-1"

echo "=========================================="
echo "Making S3 bucket public: ${BUCKET}"
echo "=========================================="

# Check if bucket exists
if ! aws s3 ls "s3://${BUCKET}" &>/dev/null; then
    echo "❌ Bucket '${BUCKET}' not found!"
    exit 1
fi

echo "✅ Bucket found: ${BUCKET}"

# Step 0: Check and disable account-level public access block (if needed)
echo ""
echo "Step 0: Checking account-level public access block settings..."
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

if aws s3control get-public-access-block --account-id "${ACCOUNT_ID}" &>/dev/null; then
    ACCOUNT_BLOCK=$(aws s3control get-public-access-block --account-id "${ACCOUNT_ID}" --query 'PublicAccessBlockConfiguration.BlockPublicPolicy' --output text)
    if [ "${ACCOUNT_BLOCK}" = "True" ]; then
        echo "⚠️  Account-level BlockPublicPolicy is enabled. Attempting to disable..."
        echo "   (This requires s3control:PutPublicAccessBlock permission)"
        aws s3control put-public-access-block \
            --account-id "${ACCOUNT_ID}" \
            --public-access-block-configuration \
            "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" \
            2>&1 && echo "✅ Account-level public access block disabled" || echo "⚠️  Could not disable account-level settings (may need admin permissions)"
        sleep 3
    fi
else
    echo "✅ No account-level public access block found"
fi

# Step 1: Disable public access block settings
echo ""
echo "Step 1: Disabling public access block settings..."

# First, check if public access block exists and delete it if needed
if aws s3api get-public-access-block --bucket "${BUCKET}" --region "${REGION}" &>/dev/null; then
    echo "Removing existing public access block..."
    aws s3api delete-public-access-block --bucket "${BUCKET}" --region "${REGION}"
    sleep 2
fi

# Now set it to allow all public access
aws s3api put-public-access-block \
    --bucket "${BUCKET}" \
    --public-access-block-configuration \
    "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" \
    --region "${REGION}"

# Verify the settings
sleep 2
echo "Verifying public access block settings..."
aws s3api get-public-access-block --bucket "${BUCKET}" --region "${REGION}"

echo "✅ Public access block disabled"

# Step 2: Set bucket policy for public read access
echo ""
echo "Step 2: Setting bucket policy for public read access..."

BUCKET_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${BUCKET}/*"
    },
    {
      "Sid": "PublicListBucket",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::${BUCKET}"
    }
  ]
}
EOF
)

echo "${BUCKET_POLICY}" | aws s3api put-bucket-policy \
    --bucket "${BUCKET}" \
    --policy file:///dev/stdin \
    --region "${REGION}"

echo "✅ Bucket policy set for public access"

# Step 3: Set bucket ACL to public-read
echo ""
echo "Step 3: Setting bucket ACL to public-read..."
aws s3api put-bucket-acl \
    --bucket "${BUCKET}" \
    --acl public-read \
    --region "${REGION}" || echo "⚠️  ACL may not be modifiable (using bucket policy instead)"

# Step 4: Update existing objects to public-read
echo ""
echo "Step 4: Updating existing objects to public-read..."
echo "This may take a while depending on the number of objects..."

OBJECT_COUNT=$(aws s3 ls "s3://${BUCKET}/" --recursive --summarize 2>/dev/null | grep "Total Objects" | awk '{print $3}' || echo "0")

if [ "${OBJECT_COUNT}" != "0" ]; then
    echo "Found ${OBJECT_COUNT} objects. Updating ACLs..."
    
    # Use s3api to update ACLs for all objects
    aws s3 ls "s3://${BUCKET}/" --recursive | while read -r line; do
        KEY=$(echo "$line" | awk '{print $4}')
        if [ -n "$KEY" ]; then
            aws s3api put-object-acl \
                --bucket "${BUCKET}" \
                --key "${KEY}" \
                --acl public-read \
                --region "${REGION}" 2>/dev/null || true
        fi
    done
    
    echo "✅ Existing objects updated to public-read"
else
    echo "No existing objects found"
fi

# Step 5: Configure bucket for future uploads to be public
echo ""
echo "Step 5: Configuring default ACL for future uploads..."
# This is done via the bucket policy, but we can also set a default ACL
aws s3api put-bucket-ownership-controls \
    --bucket "${BUCKET}" \
    --ownership-controls Rules=[{ObjectOwnership=BucketOwnerPreferred}] \
    --region "${REGION}" 2>/dev/null || echo "⚠️  Ownership controls may already be set"

echo ""
echo "=========================================="
echo "✅ S3 bucket is now public!"
echo "=========================================="
echo ""
echo "Bucket: s3://${BUCKET}"
echo "Region: ${REGION}"
echo ""
echo "Public URLs will be in format:"
echo "  https://${BUCKET}.s3.${REGION}.amazonaws.com/path/to/object"
echo "  or"
echo "  https://s3.${REGION}.amazonaws.com/${BUCKET}/path/to/object"
echo ""
echo "You can test with:"
echo "  curl https://${BUCKET}.s3.${REGION}.amazonaws.com/path/to/object"
echo ""

