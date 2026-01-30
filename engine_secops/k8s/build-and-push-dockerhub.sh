#!/bin/bash

# Build and push SecOps Scanner to Docker Hub
# Usage: ./build-and-push-dockerhub.sh [DOCKERHUB_USERNAME] [TAG]

set -e

# Get Docker Hub username
if [ -z "$1" ]; then
    read -p "Enter your Docker Hub username: " DOCKERHUB_USER
else
    DOCKERHUB_USER=$1
fi

# Get tag (default: latest)
TAG=${2:-latest}
IMAGE_NAME="secops-scanner"
FULL_IMAGE_NAME="${DOCKERHUB_USER}/${IMAGE_NAME}:${TAG}"

echo "=========================================="
echo "Building and Pushing to Docker Hub"
echo "=========================================="
echo "Docker Hub User: $DOCKERHUB_USER"
echo "Image: $FULL_IMAGE_NAME"
echo ""

# Check if logged in to Docker Hub
if ! docker info | grep -q "Username"; then
    echo "Logging in to Docker Hub..."
    docker login
fi

# Build image
echo "Building Docker image..."
cd ../scanner_engine
docker build -t ${IMAGE_NAME}:${TAG} .
docker tag ${IMAGE_NAME}:${TAG} ${FULL_IMAGE_NAME}

# Push to Docker Hub
echo "Pushing to Docker Hub..."
docker push ${FULL_IMAGE_NAME}

echo ""
echo "=========================================="
echo "Build and push completed!"
echo "=========================================="
echo ""
echo "Image: $FULL_IMAGE_NAME"
echo ""
echo "Update deployment.yaml with:"
echo "  image: $FULL_IMAGE_NAME"
echo ""
echo "Or run this command:"
echo "  sed -i.bak 's|image: secops-scanner:latest|image: $FULL_IMAGE_NAME|g' deployment.yaml"



