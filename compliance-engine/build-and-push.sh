#!/bin/bash

# Build and push compliance engine Docker image
# Usage: ./build-and-push.sh

set -e

IMAGE_NAME="yadavanup84/threat-engine-compliance-engine"
IMAGE_TAG="${1:-latest}"

echo "=========================================="
echo "Building Compliance Engine Docker Image"
echo "=========================================="
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

# Build from project root
cd "$(dirname "$0")/.."

echo "Building Docker image..."
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" \
  -f compliance-engine/Dockerfile .

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
echo "  kubectl apply -f kubernetes/engines/compliance-engine-deployment.yaml"

