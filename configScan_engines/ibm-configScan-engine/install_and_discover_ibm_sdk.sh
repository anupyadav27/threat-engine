#!/bin/bash
# Install IBM Cloud SDK packages and run discovery

set -e

echo "================================================================================"
echo "IBM Cloud SDK Installation and Discovery"
echo "================================================================================"
echo

# Common IBM Cloud SDK packages
IBM_PACKAGES=(
    "ibm-vpc"
    "ibm-platform-services"
    "ibm-schematics"
    "ibm-cloud-sdk-core"
    "ibm-watson"
    "ibmcloudsql"
    "ibm-cloudant"
    "ibm-cos-sdk"
    "ibm-db"
    "ibm-iam-identity"
    "ibm-resource-controller"
    "ibm-resource-manager"
    "ibm-container-registry"
    "ibm-key-protect"
    "ibm-secrets-manager"
    "ibm-cloud-databases"
    "ibm-code-engine"
    "ibm-functions"
    "ibm-appid"
    "ibm-cloudant"
)

echo "📦 Installing IBM Cloud SDK packages..."
echo

for package in "${IBM_PACKAGES[@]}"; do
    echo "Installing $package..."
    pip install "$package" || echo "⚠️  Failed to install $package (may not exist)"
done

echo
echo "================================================================================"
echo "Running IBM SDK Discovery"
echo "================================================================================"
echo

# Run the discovery script
cd "$(dirname "$0")"
python3 discover_and_generate_all_ibm_services.py

echo
echo "================================================================================"
echo "✅ Complete!"
echo "================================================================================"

