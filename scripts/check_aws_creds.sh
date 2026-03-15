#!/bin/bash
# Simple AWS credential checker

echo "=========================================="
echo "AWS Credentials Check"
echo "=========================================="
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not installed"
    exit 1
fi

echo "✅ AWS CLI found"
echo ""

# List profiles
echo "AWS Profiles from ~/.aws/credentials:"
echo "--------------------------------------"
if [ -f ~/.aws/credentials ]; then
    grep '^\[' ~/.aws/credentials | sed 's/\[//g' | sed 's/\]//g'
    echo ""
    
    # Test default profile
    echo "Testing default profile..."
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "✅ Default profile works!"
        echo "   Account ID: $ACCOUNT_ID"
    else
        echo "❌ Default profile failed"
    fi
else
    echo "❌ No ~/.aws/credentials file found"
fi

echo ""
echo "=========================================="
