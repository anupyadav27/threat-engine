#!/bin/bash
# Complete Build and Deploy Pipeline for Onboarding Engine

set -e

DOCKER_USERNAME="yadavanup84"
IMAGE_NAME="threat-engine-onboarding-api"
DATE_TAG=$(date +%Y%m%d-%H%M%S)
NAMESPACE="threat-engine-engines"

echo "=========================================="
echo "Onboarding Engine - Build & Deploy"
echo "=========================================="
echo ""
echo "Docker Image: $DOCKER_USERNAME/$IMAGE_NAME"
echo "Tags: latest, $DATE_TAG"
echo "Namespace: $NAMESPACE"
echo ""

# Step 1: Check prerequisites
echo "Step 1/5: Checking prerequisites..."
echo ""

# Check Docker
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi
echo "✅ Docker is running"

# Check kubectl
if ! kubectl cluster-info > /dev/null 2>&1; then
    echo "❌ Cannot connect to Kubernetes cluster"
    exit 1
fi
echo "✅ kubectl connected to cluster"
echo ""

# Step 2: Build Docker image
echo "Step 2/5: Building Docker image..."
echo ""
echo "Build context: /Users/apple/Desktop/threat-engine"
echo "Dockerfile: engine_onboarding/Dockerfile"
echo ""

cd /Users/apple/Desktop/threat-engine

docker build -f engine_onboarding/Dockerfile \
  -t $DOCKER_USERNAME/$IMAGE_NAME:latest \
  -t $DOCKER_USERNAME/$IMAGE_NAME:$DATE_TAG \
  .

echo ""
echo "✅ Image built successfully!"
echo ""

# Step 3: Push to Docker Hub
echo "Step 3/5: Pushing image to Docker Hub..."
echo ""

# Login to Docker Hub
echo "🔐 Logging in to Docker Hub..."
docker login -u $DOCKER_USERNAME

# Push images
echo "📤 Pushing images..."
docker push $DOCKER_USERNAME/$IMAGE_NAME:latest
docker push $DOCKER_USERNAME/$IMAGE_NAME:$DATE_TAG

echo ""
echo "✅ Images pushed successfully!"
echo "   - $DOCKER_USERNAME/$IMAGE_NAME:latest"
echo "   - $DOCKER_USERNAME/$IMAGE_NAME:$DATE_TAG"
echo ""

# Step 4: Update Kubernetes deployment
echo "Step 4/5: Updating Kubernetes deployment..."
echo ""

# Apply ConfigMaps if exists
if [ -f "engine_onboarding/deployment/kubernetes/threat-engine-db-config.yaml" ]; then
    echo "📋 Applying ConfigMap..."
    kubectl apply -f engine_onboarding/deployment/kubernetes/threat-engine-db-config.yaml
fi

# Apply Deployment
echo "🚀 Applying Deployment..."
kubectl apply -f engine_onboarding/deployment/kubernetes/engine-onboarding.yaml

# Force pull latest image with timestamped tag to ensure refresh
echo "🔄 Forcing image pull (using $DATE_TAG)..."
kubectl set image deployment/engine-onboarding \
  engine-onboarding=$DOCKER_USERNAME/$IMAGE_NAME:$DATE_TAG \
  -n $NAMESPACE

echo ""
echo "✅ Deployment updated"
echo ""

# Step 5: Wait for rollout
echo "Step 5/5: Waiting for rollout to complete..."
echo ""

kubectl rollout status deployment/engine-onboarding -n $NAMESPACE --timeout=5m

echo ""
echo "=========================================="
echo "✅ BUILD AND DEPLOY COMPLETE!"
echo "=========================================="
echo ""

# Show status
echo "📊 Current Status:"
echo ""
kubectl get pods -n $NAMESPACE -l app=engine-onboarding -o wide

echo ""
kubectl get svc -n $NAMESPACE -l app=engine-onboarding

echo ""
echo "=========================================="
echo "Next Steps:"
echo "=========================================="
echo ""
echo "1. Check logs:"
echo "   kubectl logs -f deployment/engine-onboarding -n $NAMESPACE"
echo ""
echo "2. Port forward for testing:"
echo "   kubectl port-forward -n $NAMESPACE svc/engine-onboarding 8008:80"
echo ""
echo "3. Test API endpoints:"
echo "   curl http://localhost:8008/"
echo "   curl http://localhost:8008/api/v1/health"
echo "   curl http://localhost:8008/api/v1/cloud-accounts"
echo ""
echo "4. Get service endpoint:"
echo "   SERVICE_IP=\$(kubectl get svc engine-onboarding -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')"
echo "   echo \"Service endpoint: http://\$SERVICE_IP\""
echo ""
