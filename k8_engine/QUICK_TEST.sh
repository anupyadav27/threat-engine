#!/bin/bash
# Quick test script for K8s engine on local Mac

set -e

echo "🚀 K8s Engine Local Test Script"
echo "================================"
echo ""

# Check if we're in the right directory
if [ ! -f "run_yaml_scan.py" ]; then
    echo "❌ Error: Please run this script from the k8_engine directory"
    exit 1
fi

echo "📦 Step 1: Installing Python dependencies..."
pip3 install -q -r requirements.txt
echo "   ✅ Dependencies installed"
echo ""

echo "🧪 Step 2: Testing with mock data (no cluster needed)..."
echo "   Testing API Server checks..."
python3 run_yaml_scan.py --mock-dir mocks/ --components apiserver --verbose | head -30
echo ""
echo "   ✅ Mock test completed"
echo ""

echo "🔍 Step 3: Checking for local cluster..."
if kubectl cluster-info &>/dev/null; then
    echo "   ✅ Cluster detected!"
    echo ""
    echo "📊 Cluster info:"
    kubectl cluster-info
    echo ""
    kubectl get nodes
    echo ""
    
    echo "🔎 Step 4: Running real cluster scan..."
    echo "   Components: pod, namespace, rbac"
    python3 run_yaml_scan.py --components pod namespace rbac --verbose
    echo ""
    echo "   ✅ Cluster scan completed"
    echo ""
    
    echo "📁 Results saved to: output/"
    ls -lh output/ | tail -5
else
    echo "   ⚠️  No cluster detected"
    echo ""
    echo "   To test against a real cluster:"
    echo "   1. Start Docker Desktop"
    echo "   2. Run: minikube start"
    echo "   3. Re-run this script"
    echo ""
    echo "   For now, we tested with mock data ✅"
fi

echo ""
echo "✨ Test complete! Check LOCAL_TESTING_GUIDE.md for more details."

