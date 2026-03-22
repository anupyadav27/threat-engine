#!/bin/bash
# Build and push onboarding engine Docker image

set -e

DOCKER_USERNAME="yadavanup84"
IMAGE_NAME="threat-engine-onboarding"
DATE_TAG=$(date +%Y%m%d-%H%M%S)

echo "=========================================="
echo "Building Onboarding Engine Docker Image"
echo "=========================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi

# Build image from root directory (build context)
echo "🏗️  Building image from /Users/apple/Desktop/threat-engine..."
cd /Users/apple/Desktop/threat-engine

docker build -f engine_onboarding/Dockerfile \
  -t $DOCKER_USERNAME/$IMAGE_NAME:latest \
  -t $DOCKER_USERNAME/$IMAGE_NAME:$DATE_TAG \
  .

echo ""
echo "✅ Image built successfully!"
echo "   - $DOCKER_USERNAME/$IMAGE_NAME:latest"
echo "   - $DOCKER_USERNAME/$IMAGE_NAME:$DATE_TAG"
echo ""

# Login to Docker Hub
echo "🔐 Logging in to Docker Hub..."
docker login -u $DOCKER_USERNAME

# Push images
echo ""
echo "📤 Pushing images to Docker Hub..."
docker push $DOCKER_USERNAME/$IMAGE_NAME:latest
docker push $DOCKER_USERNAME/$IMAGE_NAME:$DATE_TAG

echo ""
echo "=========================================="
echo "✅ Build and Push Complete!"
echo "=========================================="
echo ""
echo "Images pushed:"
echo "  - $DOCKER_USERNAME/$IMAGE_NAME:latest"
echo "  - $DOCKER_USERNAME/$IMAGE_NAME:$DATE_TAG"
echo ""
echo "Next steps:"
echo "  1. Update Kubernetes deployment:"
echo "     kubectl set image deployment/engine-onboarding engine-onboarding=$DOCKER_USERNAME/$IMAGE_NAME:$DATE_TAG -n threat-engine-engines"
echo ""
echo "  2. Or rollout restart:"
echo "     kubectl rollout restart deployment/engine-onboarding -n threat-engine-engines"
echo ""
