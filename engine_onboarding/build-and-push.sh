#!/bin/bash
# Build and push Docker images for onboarding service

set -e

DOCKER_USERNAME="yadavanup84"
REGISTRY="docker.io"

echo "=========================================="
echo "Building and Pushing Docker Images"
echo "=========================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi

# Login to Docker Hub
echo "🔐 Logging in to Docker Hub..."
docker login -u $DOCKER_USERNAME

# Build onboarding API image
echo ""
echo "🏗️  Building onboarding-api image..."
cd /Users/apple/Desktop/onboarding
docker build -t $DOCKER_USERNAME/threat-engine-onboarding-api:latest .
docker tag $DOCKER_USERNAME/threat-engine-onboarding-api:latest $DOCKER_USERNAME/threat-engine-onboarding-api:$(date +%Y%m%d)

# Build scheduler image
echo ""
echo "🏗️  Building scheduler image..."
cd /Users/apple/Desktop/onboarding/scheduler
if [ -f "Dockerfile" ]; then
    docker build -t $DOCKER_USERNAME/threat-engine-scheduler:latest .
    docker tag $DOCKER_USERNAME/threat-engine-scheduler:latest $DOCKER_USERNAME/threat-engine-scheduler:$(date +%Y%m%d)
else
    echo "⚠️  Scheduler Dockerfile not found. Using onboarding image for scheduler."
    docker tag $DOCKER_USERNAME/threat-engine-onboarding-api:latest $DOCKER_USERNAME/threat-engine-scheduler:latest
fi

# Push images
echo ""
echo "📤 Pushing images to Docker Hub..."
docker push $DOCKER_USERNAME/threat-engine-onboarding-api:latest
docker push $DOCKER_USERNAME/threat-engine-onboarding-api:$(date +%Y%m%d)

if docker images | grep -q "$DOCKER_USERNAME/threat-engine-scheduler:latest"; then
    docker push $DOCKER_USERNAME/threat-engine-scheduler:latest
    docker push $DOCKER_USERNAME/threat-engine-scheduler:$(date +%Y%m%d)
fi

echo ""
echo "=========================================="
echo "✅ Images built and pushed successfully!"
echo "=========================================="
echo ""
echo "Images:"
echo "  - $DOCKER_USERNAME/threat-engine-onboarding-api:latest"
echo "  - $DOCKER_USERNAME/threat-engine-scheduler:latest"
echo ""
echo "Next: Deploy to EKS using kubectl apply"

