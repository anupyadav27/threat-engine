#!/bin/bash
set -e

echo "🐳 Testing K8s Engine with Docker Desktop"
echo "=========================================="
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found"
    exit 1
fi

# Check context
CONTEXT=$(kubectl config current-context 2>/dev/null || echo "none")
echo "Current context: $CONTEXT"

if [ "$CONTEXT" != "docker-desktop" ]; then
    echo "⚠️  Not using docker-desktop context"
    echo "   Available contexts:"
    kubectl config get-contexts
    echo ""
    read -p "Switch to docker-desktop? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kubectl config use-context docker-desktop
    else
        echo "Continuing with current context: $CONTEXT"
    fi
fi

# Verify cluster
echo ""
echo "📊 Cluster Info:"
kubectl cluster-info | grep -E "control plane|CoreDNS|running at" || kubectl cluster-info
echo ""

# Show nodes
echo "🖥️  Nodes:"
kubectl get nodes
echo ""

# Run engine with mocks first
echo "🧪 Test 1: Running with mock data..."
cd /Users/apple/Desktop/threat-engine/k8_engine
source venv/bin/activate
python3 run_yaml_scan.py --mock-dir mocks/ --components apiserver --verbose | head -20
echo ""

# Run against real cluster
echo "🔍 Test 2: Running against real cluster..."
python3 run_yaml_scan.py --components pod namespace rbac --verbose
echo ""

echo "✅ Tests complete!"
echo "📁 Results in: output/$(ls -t output/ | head -1)/"
echo ""
echo "To view results:"
echo "  ls -lh output/\$(ls -t output/ | head -1)/checks/"
