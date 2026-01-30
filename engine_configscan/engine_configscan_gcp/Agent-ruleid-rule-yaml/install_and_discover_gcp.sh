#!/bin/bash
# Install GCP SDK packages and run discovery

set -e

echo "================================================================================"
echo "GCP SDK Package Installation and Discovery"
echo "================================================================================"
echo ""

# Check if we're in the right directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Step 1: Discover installed packages
echo "Step 1: Discovering installed GCP SDK packages..."
python3 << 'PYTHON_SCRIPT'
import subprocess
import json
import sys

def discover_installed():
    """Discover installed google-cloud-* packages"""
    try:
        result = subprocess.run(
            ['python3', '-m', 'pip', 'list', '--format=json'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            packages = json.loads(result.stdout)
            gcp_packages = [
                p['name'] for p in packages 
                if p['name'].startswith('google-cloud-')
            ]
            return gcp_packages
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    return []

installed = discover_installed()
print(f"Found {len(installed)} installed packages")
if installed:
    print(f"  {', '.join(installed[:10])}")
    if len(installed) > 10:
        print(f"  ... and {len(installed) - 10} more")
PYTHON_SCRIPT

echo ""
echo "Step 2: Installing common GCP SDK packages..."
echo ""

# Common packages to install
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
    "google-cloud-build"
    "google-cloud-scheduler"
    "google-cloud-tasks"
    "google-cloud-workflows"
    "google-cloud-datacatalog"
)

INSTALLED=0
FAILED=0

for package in "${PACKAGES[@]}"; do
    echo -n "  Installing $package... "
    if python3 -m pip install --quiet "$package" 2>/dev/null; then
        echo "✓"
        ((INSTALLED++))
    else
        echo "✗ (may already be installed or not available)"
        ((FAILED++))
    fi
done

echo ""
echo "  Installed: $INSTALLED, Failed/Skipped: $FAILED"
echo ""

# Step 3: Run discovery
echo "Step 3: Running service discovery..."
echo ""

if [ -f "discover_and_generate_all_gcp_services.py" ]; then
    python3 discover_and_generate_all_gcp_services.py
else
    echo "  Error: discover_and_generate_all_gcp_services.py not found"
    exit 1
fi

echo ""
echo "================================================================================"
echo "Complete!"
echo "================================================================================"

