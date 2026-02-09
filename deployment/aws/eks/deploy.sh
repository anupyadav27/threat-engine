#!/bin/bash
# deploy.sh - Deploy all engines to EKS with uniform naming
# Usage: ./deploy.sh [--active-only]

set -e

NAMESPACE="threat-engine-engines"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo "  CSPM Platform - EKS Deployment"
echo "  Namespace: $NAMESPACE"
echo "============================================"

# Check prerequisites
echo ""
echo "[1/6] Checking prerequisites..."
kubectl cluster-info > /dev/null 2>&1 || { echo "ERROR: kubectl not connected to cluster"; exit 1; }
aws sts get-caller-identity > /dev/null 2>&1 || { echo "ERROR: AWS CLI not configured"; exit 1; }
echo "  ✓ kubectl connected"
echo "  ✓ AWS CLI configured"

# Ensure namespace exists
echo ""
echo "[2/6] Ensuring namespace exists..."
kubectl get namespace $NAMESPACE > /dev/null 2>&1 || kubectl create namespace $NAMESPACE
echo "  ✓ Namespace $NAMESPACE ready"

# Apply service account with IRSA
echo ""
echo "[3/6] Applying service account (IRSA)..."
kubectl apply -f "$SCRIPT_DIR/01-service-account.yaml"
echo "  ✓ engine-sa with IRSA applied"

# Apply configmaps (existing ones)
echo ""
echo "[4/6] Applying configmaps and secrets..."
kubectl apply -f "$SCRIPT_DIR/configmaps/" 2>/dev/null || echo "  (no configmap changes)"
echo "  ✓ ConfigMaps applied"

# Deploy API Gateway
echo ""
echo "[5/6] Deploying API Gateway..."
kubectl apply -f "$SCRIPT_DIR/api-gateway.yaml"
echo "  ✓ api-gateway deployed"

# Deploy engines
echo ""
echo "[6/6] Deploying engines..."

# Core engines
for engine in engine-threat engine-discoveries engine-check engine-inventory engine-onboarding engine-secops; do
    echo "  Deploying $engine..."
    kubectl apply -f "$SCRIPT_DIR/engines/${engine}.yaml"
done

if [ "$1" != "--active-only" ]; then
    # Additional engines
    for engine in engine-compliance engine-iam engine-datasec engine-rule; do
        echo "  Deploying $engine..."
        kubectl apply -f "$SCRIPT_DIR/engines/${engine}.yaml"
    done
fi

echo ""
echo "============================================"
echo "  Deployment complete! Waiting for pods..."
echo "============================================"
echo ""

# Wait for active pods
sleep 5
kubectl get pods -n $NAMESPACE -o wide
echo ""
kubectl get services -n $NAMESPACE
echo ""
echo "To check health: kubectl logs -n $NAMESPACE -l tier=engine --tail=5"
echo "To scale up:     kubectl scale deployment engine-compliance --replicas=1 -n $NAMESPACE"
