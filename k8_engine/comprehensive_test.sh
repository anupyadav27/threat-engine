#!/bin/bash
# Comprehensive K8s Engine Test Script
# Tests all checks by deploying various resources

set -e

echo "🧪 K8s Engine - Comprehensive Test Suite"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
echo "📋 Checking prerequisites..."
command -v kubectl >/dev/null 2>&1 || { echo "❌ kubectl not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "❌ python3 not found"; exit 1; }

# Verify cluster
CONTEXT=$(kubectl config current-context)
echo "✅ Cluster: $CONTEXT"
kubectl get nodes || { echo "❌ Cluster not accessible"; exit 1; }
echo ""

# Create test namespace
TEST_NS="k8s-engine-test"
echo "📦 Creating test namespace: $TEST_NS"
kubectl create namespace $TEST_NS --dry-run=client -o yaml | kubectl apply -f -
echo ""

# Deploy test resources
echo "🚀 Deploying test resources..."
echo ""

# 1. Insecure Pod (will FAIL many checks)
echo "1️⃣  Deploying insecure pod..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
  namespace: $TEST_NS
  labels:
    app: test
    security: bad
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
      runAsUser: 0
    env:
    - name: DATABASE_PASSWORD
      value: "hardcoded-password-123"
    - name: API_KEY
      value: "secret-api-key-456"
    ports:
    - containerPort: 80
EOF

# 2. Secure Pod (will PASS checks)
echo "2️⃣  Deploying secure pod..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: $TEST_NS
  labels:
    app: test
    security: good
  annotations:
    backup: "enabled"
    security-scan: "passed"
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: nginx
    image: nginx:1.21
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL
    resources:
      limits:
        cpu: 100m
        memory: 128Mi
      requests:
        cpu: 50m
        memory: 64Mi
    ports:
    - containerPort: 8080
EOF

# 3. Deployment
echo "3️⃣  Deploying deployment..."
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
  namespace: $TEST_NS
spec:
  replicas: 2
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
    spec:
      containers:
      - name: app
        image: nginx:alpine
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
EOF

# 4. Service
echo "4️⃣  Deploying service..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: test-service
  namespace: $TEST_NS
spec:
  type: ClusterIP
  selector:
    app: test-app
  ports:
  - port: 80
    targetPort: 80
EOF

# 5. NetworkPolicy
echo "5️⃣  Deploying network policy..."
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-netpol
  namespace: $TEST_NS
spec:
  podSelector:
    matchLabels:
      app: test-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: test-app
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: test-app
EOF

# 6. ConfigMap
echo "6️⃣  Deploying configmap..."
kubectl create configmap test-config \
  --from-literal=key1=value1 \
  --from-literal=key2=value2 \
  -n $TEST_NS \
  --dry-run=client -o yaml | kubectl apply -f -

# 7. Secret
echo "7️⃣  Deploying secret..."
kubectl create secret generic test-secret \
  --from-literal=password=insecure123 \
  --from-literal=apikey=secret456 \
  -n $TEST_NS \
  --dry-run=client -o yaml | kubectl apply -f -

# 8. ServiceAccount
echo "8️⃣  Deploying service account..."
kubectl create serviceaccount test-sa -n $TEST_NS --dry-run=client -o yaml | kubectl apply -f -

# 9. Overly permissive ClusterRole
echo "9️⃣  Deploying RBAC resources..."
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-wildcard-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: test-cluster-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: test-sa
  namespace: $TEST_NS
EOF

# 10. Ingress (if controller available)
echo "🔟 Deploying ingress..."
cat <<EOF | kubectl apply -f - 2>/dev/null || echo "⚠️  Ingress controller not available, skipping"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-ingress
  namespace: $TEST_NS
spec:
  rules:
  - host: test.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: test-service
            port:
              number: 80
EOF

echo ""
echo "⏳ Waiting for resources to be ready..."
sleep 5
kubectl wait --for=condition=Ready pod/insecure-pod -n $TEST_NS --timeout=60s 2>/dev/null || echo "⚠️  insecure-pod not ready"
kubectl wait --for=condition=Ready pod/secure-pod -n $TEST_NS --timeout=60s 2>/dev/null || echo "⚠️  secure-pod not ready"

echo ""
echo "📊 Deployed resources:"
kubectl get all,networkpolicies,ingress -n $TEST_NS
echo ""

# Run comprehensive scan
echo "🔍 Running comprehensive security scan..."
echo ""
cd /Users/apple/Desktop/threat-engine/k8_engine
source venv/bin/activate

# Scan all components
echo "Scanning all components..."
python3 run_yaml_scan.py --verbose

LATEST=$(ls -t output/ | head -1)
echo ""
echo "✅ Scan complete!"
echo ""
echo "📊 Results Summary:"
echo "=================="

# Summarize results
for file in output/$LATEST/checks/*.json; do
    component=$(basename $file .json | sed 's/_checks//')
    python3 << PYEOF
import json
with open("$file") as f:
    data = json.load(f)
    checks = data['checks']
    total = len(checks)
    pass_count = sum(1 for c in checks if c['status'] == 'PASS')
    fail_count = sum(1 for c in checks if c['status'] == 'FAIL')
    skip_count = sum(1 for c in checks if c['status'] == 'SKIP')
    error_count = sum(1 for c in checks if c['status'] == 'ERROR')
    
    print(f"\n{component.upper()}:")
    print(f"  Total:  {total}")
    print(f"  ✅ PASS:  {pass_count}")
    print(f"  ❌ FAIL:  {fail_count}")
    print(f"  ⚠️  SKIP:  {skip_count}")
    print(f"  🔴 ERROR: {error_count}")
PYEOF
done

echo ""
echo "📁 Full results: output/$LATEST/"
echo ""

# Show sample findings
echo "🔍 Sample Security Findings:"
echo "==========================="
python3 << 'PYEOF'
import json
import glob

for check_file in sorted(glob.glob("output/*/checks/*_checks.json"))[:3]:
    with open(check_file) as f:
        data = json.load(f)
        component = check_file.split('/')[-1].replace('_checks.json', '')
        checks = data['checks']
        fails = [c for c in checks if c['status'] == 'FAIL']
        
        if fails:
            print(f"\n{component.upper()} - Top 5 Issues:")
            for check in fails[:5]:
                print(f"  ❌ {check['severity']}: {check['check_name']}")
                print(f"     {check['status_extended'][:80]}...")
PYEOF

echo ""
echo ""
read -p "🗑️  Clean up test resources? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "🧹 Cleaning up..."
    
    # Delete namespace (cascades to all resources in it)
    kubectl delete namespace $TEST_NS --grace-period=0 --force 2>/dev/null || true
    
    # Delete cluster-level RBAC
    kubectl delete clusterrole test-wildcard-role 2>/dev/null || true
    kubectl delete clusterrolebinding test-cluster-admin-binding 2>/dev/null || true
    
    echo "✅ Cleanup complete!"
else
    echo ""
    echo "⚠️  Test resources preserved in namespace: $TEST_NS"
    echo "   To clean up later, run:"
    echo "   kubectl delete namespace $TEST_NS"
    echo "   kubectl delete clusterrole test-wildcard-role"
    echo "   kubectl delete clusterrolebinding test-cluster-admin-binding"
fi

echo ""
echo "✨ Test suite complete!"
echo ""
echo "📖 To view detailed results:"
echo "   cd /Users/apple/Desktop/threat-engine/k8_engine"
echo "   cat output/$LATEST/checks/pod_checks.json | python3 -m json.tool | less"

