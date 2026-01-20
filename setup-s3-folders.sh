#!/bin/bash

# Setup S3 folder structure for all engines
# Usage: ./setup-s3-folders.sh

set -e

BUCKET="cspm-lgtech"
REGION="ap-south-1"

echo "=========================================="
echo "Setting up S3 folder structure"
echo "=========================================="

# Check if bucket exists
if ! aws s3 ls "s3://${BUCKET}" &>/dev/null; then
    echo "Creating bucket: ${BUCKET}"
    aws s3 mb "s3://${BUCKET}" --region "${REGION}"
fi

# Create folder structure for each engine
ENGINES=(
    "aws-compliance-engine/output"
    "azure-compliance-engine/output"
    "gcp-compliance-engine/output"
    "alicloud-compliance-engine/output"
    "oci-compliance-engine/output"
    "ibm-compliance-engine/output"
    "yaml-rule-builder/output"
)

for engine_path in "${ENGINES[@]}"; do
    echo "Creating folder: ${engine_path}"
    echo "test" | aws s3 cp - "s3://${BUCKET}/${engine_path}/.keep" \
        --region "${REGION}" 2>/dev/null || echo "Folder may already exist"
done

echo ""
echo "✅ S3 folder structure created!"
echo ""
echo "Bucket: s3://${BUCKET}"
echo "Folders:"
for engine_path in "${ENGINES[@]}"; do
    echo "  - s3://${BUCKET}/${engine_path}/"
done

