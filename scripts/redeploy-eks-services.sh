#!/bin/bash
# Redeploy all services to EKS with updated configuration
# This script:
# 1. Updates ConfigMap with DATABASE_URL
# 2. Initializes RDS schema
# 3. Deploys yaml-rule-builder
# 4. Updates onboarding deployment (with integrated scheduler)
# 5. Removes separate scheduler deployment
# 6. Verifies all services

set -e

NAMESPACE="threat-engine-engines"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     EKS Services Redeployment                                    ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Check kubectl access
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ kubectl not configured or cluster not accessible"
    echo "   Run: aws eks update-kubeconfig --name vulnerability-eks-cluster --region ap-south-1"
    exit 1
fi

echo "✅ kubectl configured"
echo ""

# Step 1: Update ConfigMap with DATABASE_URL
echo "📝 Step 1: Updating ConfigMap with DATABASE_URL..."
kubectl patch configmap platform-config -n "$NAMESPACE" --type merge -p '{
  "data": {
    "database-url": "postgresql://threatengine:v-nKrqSta17I8UA1IPzIgoiJHPIE-zPm20V7D857yVU@postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432/vulnerability_db"
  }
}' || {
    echo "⚠️  ConfigMap patch failed, trying apply..."
    kubectl apply -f "$PROJECT_ROOT/kubernetes/configmaps/platform-config.yaml"
}
echo "✅ ConfigMap updated"
echo ""

# Step 2: Initialize RDS Schema
echo "📝 Step 2: Initializing RDS PostgreSQL schema..."
if [ -f "$PROJECT_ROOT/scripts/init-rds-schema.sh" ]; then
    cd "$PROJECT_ROOT"
    echo "   Running schema initialization..."
    "$PROJECT_ROOT/scripts/init-rds-schema.sh" || {
        echo "⚠️  Schema initialization failed. Continuing anyway..."
        echo "   You can run it manually later: ./scripts/init-rds-schema.sh"
    }
else
    echo "⚠️  Schema initialization script not found. Skipping..."
    echo "   Run manually: ./scripts/init-rds-schema.sh"
fi
echo ""

# Step 3: Deploy YAML Rule Builder
echo "📝 Step 3: Deploying yaml-rule-builder..."
kubectl apply -f "$PROJECT_ROOT/kubernetes/engines/yaml-rule-builder-deployment.yaml"
echo "✅ yaml-rule-builder deployment applied"
echo "   Waiting for pod to be ready..."
kubectl wait --for=condition=ready pod -l app=yaml-rule-builder -n "$NAMESPACE" --timeout=120s || echo "⚠️  Pod not ready yet, continuing..."
echo ""

# Step 4: Update Onboarding Deployment (with integrated scheduler)
echo "📝 Step 4: Updating onboarding-api deployment (with integrated scheduler)..."
kubectl apply -f "$PROJECT_ROOT/kubernetes/onboarding/onboarding-deployment.yaml"
echo "✅ onboarding-api deployment updated"
echo "   Waiting for rollout..."
kubectl rollout status deployment/onboarding-api -n "$NAMESPACE" --timeout=300s
echo ""

# Step 5: Remove Separate Scheduler Deployment
echo "📝 Step 5: Removing separate scheduler deployment..."
if kubectl get deployment scheduler-service -n "$NAMESPACE" &> /dev/null; then
    kubectl delete deployment scheduler-service -n "$NAMESPACE"
    echo "✅ scheduler-service deployment removed"
else
    echo "ℹ️  scheduler-service deployment not found (already removed or never existed)"
fi
echo ""

# Step 6: Verify Services
echo "📝 Step 6: Verifying all services..."
echo ""

echo "Deployments:"
kubectl get deployments -n "$NAMESPACE" -o wide
echo ""

echo "Pods:"
kubectl get pods -n "$NAMESPACE" -o wide
echo ""

echo "Services:"
kubectl get svc -n "$NAMESPACE"
echo ""

# Check pod status
echo "📊 Pod Status Summary:"
kubectl get pods -n "$NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.status.containerStatuses[0].ready}{"\n"}{end}' | while read -r name phase ready; do
    if [ "$ready" == "true" ] && [ "$phase" == "Running" ]; then
        echo "  ✅ $name: Running"
    else
        echo "  ⚠️  $name: $phase (Ready: $ready)"
    fi
done
echo ""

# Test health endpoints
echo "🔍 Testing health endpoints..."
ONBOARDING_POD=$(kubectl get pod -l app=onboarding-api -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ ! -z "$ONBOARDING_POD" ]; then
    echo "   Testing onboarding-api health..."
    kubectl exec "$ONBOARDING_POD" -n "$NAMESPACE" -- \
      curl -s http://localhost:8000/api/v1/health | python3 -m json.tool 2>/dev/null || \
      kubectl exec "$ONBOARDING_POD" -n "$NAMESPACE" -- curl -s http://localhost:8000/api/v1/health
    echo ""
fi

AWS_ENGINE_POD=$(kubectl get pod -l app=aws-compliance-engine -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ ! -z "$AWS_ENGINE_POD" ]; then
    echo "   Testing aws-compliance-engine health..."
    kubectl exec "$AWS_ENGINE_POD" -n "$NAMESPACE" -- \
      curl -s http://localhost:8000/api/v1/health | python3 -m json.tool 2>/dev/null || \
      kubectl exec "$AWS_ENGINE_POD" -n "$NAMESPACE" -- curl -s http://localhost:8000/api/v1/health
    echo ""
fi

YAML_BUILDER_POD=$(kubectl get pod -l app=yaml-rule-builder -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ ! -z "$YAML_BUILDER_POD" ]; then
    echo "   Testing yaml-rule-builder health..."
    kubectl exec "$YAML_BUILDER_POD" -n "$NAMESPACE" -- \
      curl -s http://localhost:8000/api/v1/health | python3 -m json.tool 2>/dev/null || \
      kubectl exec "$YAML_BUILDER_POD" -n "$NAMESPACE" -- curl -s http://localhost:8000/api/v1/health
    echo ""
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     ✅ Redeployment Complete!                                   ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Summary:"
echo "  ✅ ConfigMap updated with DATABASE_URL"
echo "  ✅ RDS schema initialized (if script ran successfully)"
echo "  ✅ yaml-rule-builder deployed"
echo "  ✅ onboarding-api updated (scheduler integrated)"
echo "  ✅ scheduler-service removed (now part of onboarding)"
echo ""
echo "🌐 External Access (if LoadBalancers exist):"
kubectl get svc -n "$NAMESPACE" -o jsonpath='{range .items[?(@.spec.type=="LoadBalancer")]}{.metadata.name}{": "}{.status.loadBalancer.ingress[0].hostname}{"\n"}{end}' 2>/dev/null || echo "  No LoadBalancers found"
echo ""
echo "📝 Next Steps:"
echo "  1. Verify all pods are running: kubectl get pods -n $NAMESPACE"
echo "  2. Check logs: kubectl logs -f deployment/onboarding-api -n $NAMESPACE"
echo "  3. Test API endpoints"
echo "  4. Verify scheduler is running (check logs for 'Scheduler started')"
echo ""

