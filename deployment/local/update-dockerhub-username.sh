#!/bin/bash
# Update Docker Hub username in all Kubernetes manifests
# Usage: ./update-dockerhub-username.sh YOUR_DOCKERHUB_USERNAME

set -e

DOCKERHUB_USER="${1}"

if [ -z "$DOCKERHUB_USER" ]; then
    echo "Error: Please provide your Docker Hub username"
    echo "Usage: $0 YOUR_DOCKERHUB_USERNAME"
    exit 1
fi

echo "Updating all deployment files with Docker Hub username: $DOCKERHUB_USER"

# Find and replace in all yaml files
find kubernetes -name "*.yaml" -type f -exec sed -i '' "s/YOUR_DOCKERHUB_USERNAME/$DOCKERHUB_USER/g" {} \;

echo "✓ All files updated!"
echo ""
echo "Updated files:"
find kubernetes -name "*.yaml" -type f | grep -E "(deployment|scheduler)" | sort

