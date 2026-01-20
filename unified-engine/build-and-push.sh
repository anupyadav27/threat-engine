#!/bin/bash

# Build and push unified engine Docker image
# Usage: ./build-and-push.sh

set -e

IMAGE_NAME="yadavanup84/threat-engine-unified"
IMAGE_TAG="${1:-latest}"

echo "=========================================="
echo "Building Unified Engine Docker Image"
echo "=========================================="
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

# Build from project root
cd "$(dirname "$0")/.."

echo "Building Docker image..."
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" \
  -f unified-engine/Dockerfile .

echo ""
echo "✅ Build complete!"
echo ""
echo "Pushing to Docker Hub..."
docker push "${IMAGE_NAME}:${IMAGE_TAG}"

echo ""
echo "✅ Push complete!"
echo ""
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "To deploy to EKS:"
echo "  kubectl apply -f kubernetes/engines/unified-engine-deployment-dev.yaml"

