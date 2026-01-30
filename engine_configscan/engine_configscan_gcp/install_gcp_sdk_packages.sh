#!/bin/bash
# Install GCP SDK packages for discovery

echo "Installing GCP SDK packages..."
echo "This may take a while..."

# Common GCP packages
PACKAGES=(
    "google-cloud-storage"
    "google-cloud-compute"
    "google-cloud-container"
    "google-cloud-bigquery"
    "google-cloud-dns"
    "google-cloud-iam"
    "google-cloud-kms"
    "google-cloud-logging"
    "google-cloud-monitoring"
    "google-cloud-resource-manager"
    "google-cloud-sql"
    "google-cloud-functions"
    "google-cloud-pubsub"
    "google-cloud-dataproc"
    "google-cloud-dataflow"
    "google-cloud-spanner"
    "google-cloud-firestore"
    "google-cloud-bigtable"
    "google-cloud-secret-manager"
    "google-cloud-asset"
    "google-cloud-security-center"
    "google-cloud-recommender"
    "google-cloud-service-usage"
    "google-cloud-artifact-registry"
    "google-cloud-appengine"
)

# Install packages
for package in "${PACKAGES[@]}"; do
    echo "Installing $package..."
    pip install "$package" || echo "Failed to install $package"
done

# Also try to install all google-cloud-* packages if available
echo ""
echo "Attempting to install all google-cloud-* packages..."
pip install $(pip search google-cloud- 2>/dev/null | grep "^google-cloud-" | awk '{print $1}' | tr '\n' ' ') 2>/dev/null || echo "Could not auto-discover all packages"

echo ""
echo "Installation complete!"
echo "Run discovery script to generate catalog."

