#!/bin/bash
# Collect CSP credentials from local system

echo "=========================================="
echo "Collecting CSP Credentials from Local System"
echo "=========================================="
echo ""

OUTPUT_FILE="local_credentials.txt"
> $OUTPUT_FILE

echo "Credentials collected on: $(date)" >> $OUTPUT_FILE
echo "=========================================" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# 1. AWS Credentials
echo "1. Checking AWS Credentials..."
echo "1. AWS CREDENTIALS" >> $OUTPUT_FILE
echo "==================" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

if command -v aws &> /dev/null; then
    echo "✅ AWS CLI found"

    # List AWS profiles
    echo "AWS Profiles:" >> $OUTPUT_FILE
    if [ -f ~/.aws/credentials ]; then
        grep '^\[' ~/.aws/credentials | sed 's/\[//g' | sed 's/\]//g' >> $OUTPUT_FILE
        echo "" >> $OUTPUT_FILE

        # For each profile, get account ID
        while IFS= read -r profile; do
            profile=$(echo "$profile" | sed 's/\[//g' | sed 's/\]//g')
            echo "Profile: $profile" >> $OUTPUT_FILE

            # Get account ID
            account_id=$(AWS_PROFILE=$profile aws sts get-caller-identity --query Account --output text 2>/dev/null)
            if [ $? -eq 0 ]; then
                echo "  Account ID: $account_id" >> $OUTPUT_FILE
                echo "  ✅ Valid credentials"
            else
                echo "  ❌ Cannot validate credentials" >> $OUTPUT_FILE
                echo "  ⚠️  Invalid credentials"
            fi
            echo "" >> $OUTPUT_FILE
        done < <(grep '^\[' ~/.aws/credentials)
    else
        echo "No AWS credentials file found" >> $OUTPUT_FILE
        echo "⚠️  No AWS credentials file"
    fi
else
    echo "❌ AWS CLI not installed"
    echo "AWS CLI not installed" >> $OUTPUT_FILE
fi

echo "" >> $OUTPUT_FILE

# 2. Azure Credentials
echo ""
echo "2. Checking Azure Credentials..."
echo "2. AZURE CREDENTIALS" >> $OUTPUT_FILE
echo "====================" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

if command -v az &> /dev/null; then
    echo "✅ Azure CLI found"

    # Check if logged in
    account_info=$(az account show 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "$account_info" >> $OUTPUT_FILE
        echo "✅ Azure logged in"

        # List subscriptions
        echo "" >> $OUTPUT_FILE
        echo "Azure Subscriptions:" >> $OUTPUT_FILE
        az account list --query "[].{Name:name, ID:id, State:state}" --output table >> $OUTPUT_FILE 2>/dev/null
    else
        echo "Not logged in to Azure" >> $OUTPUT_FILE
        echo "⚠️  Not logged in to Azure"
    fi
else
    echo "❌ Azure CLI not installed"
    echo "Azure CLI not installed" >> $OUTPUT_FILE
fi

echo "" >> $OUTPUT_FILE

# 3. GCP Credentials
echo ""
echo "3. Checking GCP Credentials..."
echo "3. GCP CREDENTIALS" >> $OUTPUT_FILE
echo "==================" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

if command -v gcloud &> /dev/null; then
    echo "✅ GCloud CLI found"

    # Get active account
    active_account=$(gcloud config get-value account 2>/dev/null)
    if [ -n "$active_account" ]; then
        echo "Active Account: $active_account" >> $OUTPUT_FILE
        echo "✅ GCloud logged in as: $active_account"

        # List projects
        echo "" >> $OUTPUT_FILE
        echo "GCP Projects:" >> $OUTPUT_FILE
        gcloud projects list --format="table(projectId,name)" 2>/dev/null >> $OUTPUT_FILE
    else
        echo "Not logged in to GCP" >> $OUTPUT_FILE
        echo "⚠️  Not logged in to GCP"
    fi
else
    echo "❌ GCloud CLI not installed"
    echo "GCloud CLI not installed" >> $OUTPUT_FILE
fi

echo "" >> $OUTPUT_FILE

# 4. Check for service account keys
echo ""
echo "4. Checking for Service Account Keys..."
echo "4. SERVICE ACCOUNT KEYS" >> $OUTPUT_FILE
echo "=======================" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# GCP service accounts
if [ -d ~/.config/gcloud ]; then
    echo "GCP Service Account Keys:" >> $OUTPUT_FILE
    find ~/.config/gcloud -name "*.json" -type f 2>/dev/null | while read -r file; do
        echo "  - $file" >> $OUTPUT_FILE
    done
    echo "✅ Checked GCP service accounts"
else
    echo "No GCP config directory" >> $OUTPUT_FILE
fi

echo "" >> $OUTPUT_FILE

# Azure service principals (check for credentials)
if [ -f ~/.azure/credentials ]; then
    echo "Azure credentials file found" >> $OUTPUT_FILE
    echo "✅ Found Azure credentials file"
else
    echo "No Azure credentials file" >> $OUTPUT_FILE
fi

echo "" >> $OUTPUT_FILE
echo "=========================================" >> $OUTPUT_FILE
echo "Collection complete!" >> $OUTPUT_FILE

echo ""
echo "=========================================="
echo "✅ Credential collection complete!"
echo "=========================================="
echo ""
echo "Summary saved to: $OUTPUT_FILE"
echo ""
echo "Next steps:"
echo "1. Review the file: cat $OUTPUT_FILE"
echo "2. Use the test_onboarding_api.sh script to onboard accounts"
echo ""
