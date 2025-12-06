# Testing K8s Engine with Docker Desktop Kubernetes

## Why Docker Desktop Kubernetes?

✅ **Easier than Minikube**
- Already running (Docker Desktop is open)
- Single-node cluster built-in
- No additional tools needed
- Native macOS integration
- Access to control plane components

---

## Step 1: Enable Kubernetes in Docker Desktop

### Enable via GUI:
1. **Open Docker Desktop**
2. Click **Settings** (gear icon)
3. Go to **Kubernetes** tab
4. ✅ Check **Enable Kubernetes**
5. Click **Apply & Restart**
6. Wait 2-3 minutes for Kubernetes to start

### Verify it's enabled:
```bash
# Check if Docker Desktop context exists
kubectl config get-contexts

# Should see:
# docker-desktop   docker-desktop   docker-desktop   
# minikube         minikube         minikube        
```

---

## Step 2: Switch to Docker Desktop Context

```bash
# Switch to docker-desktop context
kubectl config use-context docker-desktop

# Verify you're connected
kubectl cluster-info

# Should show:
# Kubernetes control plane is running at https://kubernetes.docker.internal:6443
# CoreDNS is running at https://kubernetes.docker.internal:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

# Check nodes
kubectl get nodes

# Should show:
# NAME             STATUS   ROLES           AGE   VERSION
# docker-desktop   Ready    control-plane   ...   v1.29.x
```

---

## Step 3: Run K8s Engine Against Docker Desktop

```bash
cd /Users/apple/Desktop/threat-engine/k8_engine
source venv/bin/activate

# Test control plane components (works better than minikube!)
python3 run_yaml_scan.py --components apiserver etcd scheduler --verbose

# Test workload security
python3 run_yaml_scan.py --components pod rbac namespace --verbose

# Test everything
python3 run_yaml_scan.py --verbose
```

---

## Step 4: Deploy Test Workloads

### Create Test Namespace
```bash
kubectl create namespace security-test
```

### Deploy Insecure Pod (Should FAIL checks)
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
  namespace: security-test
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
      value: "hardcoded-secret-123"
    - name: API_KEY
      value: "insecure-api-key"
EOF
```

### Deploy Secure Pod (Should PASS checks)
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: security-test
  labels:
    app: test
    security: good
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: nginx
    image: nginx:latest
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
EOF
```

### Deploy RBAC Test Resources
```bash
# Create overly permissive cluster role
kubectl create clusterrole wildcard-admin \
  --verb='*' \
  --resource='*'

# Bind to a service account
kubectl create serviceaccount test-sa -n security-test
kubectl create clusterrolebinding test-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=security-test:test-sa
```

### Deploy Network Policy
```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: security-test
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector: {}
  egress:
  - to:
    - podSelector: {}
EOF
```

---

## Step 5: Run Comprehensive Security Scan

### Scan Everything
```bash
cd /Users/apple/Desktop/threat-engine/k8_engine
source venv/bin/activate

# Full scan
python3 run_yaml_scan.py --verbose
```

### Scan Specific Components
```bash
# Pod security (should catch the insecure pod)
python3 run_yaml_scan.py --components pod core --verbose

# RBAC (should catch wildcard permissions and cluster-admin usage)
python3 run_yaml_scan.py --components rbac --verbose

# Network policies
python3 run_yaml_scan.py --components network --verbose

# Secrets and ConfigMaps
python3 run_yaml_scan.py --components secret configmap --verbose

# Control plane
python3 run_yaml_scan.py --components apiserver etcd scheduler controllermanager --verbose
```

---

## Expected Results

### Pod Security Checks
The engine should detect in `insecure-pod`:
- ❌ FAIL: Privileged container detected (HIGH)
- ❌ FAIL: Host network enabled (HIGH)
- ❌ FAIL: Host PID enabled (HIGH)
- ❌ FAIL: Host IPC enabled (HIGH)
- ❌ FAIL: Running as root (MEDIUM)
- ❌ FAIL: Secrets in environment variables (MEDIUM)
- ❌ FAIL: Privilege escalation allowed (HIGH)

The engine should show for `secure-pod`:
- ✅ PASS: No privileged containers
- ✅ PASS: Host namespaces disabled
- ✅ PASS: Running as non-root
- ✅ PASS: Read-only root filesystem
- ✅ PASS: All capabilities dropped

### RBAC Checks
Should detect:
- ❌ FAIL: Wildcard permissions in use (HIGH)
- ❌ FAIL: Cluster-admin binding (MEDIUM)
- ⚠️  WARN: Overly permissive service accounts

### Network Checks
Should show:
- ✅ PASS: Network policies defined
- ℹ️  INFO: Policy applies to all pods in namespace

---

## Viewing Results

### Console Output
```bash
# Results are printed to console
python3 run_yaml_scan.py --components pod --verbose
```

### JSON Output
```bash
# Results saved to timestamped directory
cd /Users/apple/Desktop/threat-engine/k8_engine
LATEST=$(ls -t output/ | head -1)

# View pod checks
cat output/$LATEST/checks/pod_checks.json | python3 -m json.tool | less

# View RBAC checks
cat output/$LATEST/checks/rbac_checks.json | python3 -m json.tool | less

# View all checks
ls -lh output/$LATEST/checks/
```

### Summary Statistics
```bash
# Count by status
cat output/$LATEST/checks/*.json | \
  python3 -c "import sys, json; data = json.load(sys.stdin); \
  checks = data['checks']; \
  from collections import Counter; \
  print(Counter(c['status'] for c in checks))"
```

---

## Advantages of Docker Desktop Kubernetes

✅ **Better than Minikube for testing:**
1. **Already running** - Docker Desktop is already open
2. **True single-node** - Real control plane access
3. **Native integration** - Better macOS performance
4. **Easier networking** - localhost access works better
5. **Persistent** - Survives Docker Desktop restarts
6. **LoadBalancer support** - Can expose services easily

✅ **Full access to control plane:**
- API server configuration checks work
- etcd checks work
- Scheduler and controller manager checks work
- Better than managed clusters (EKS/GKE/AKS)

---

## Quick Test Script

Save this as `test_docker_desktop.sh`:

```bash
#!/bin/bash
set -e

echo "🐳 Testing K8s Engine with Docker Desktop"
echo "=========================================="
echo ""

# Check context
CONTEXT=$(kubectl config current-context)
if [ "$CONTEXT" != "docker-desktop" ]; then
    echo "⚠️  Current context: $CONTEXT"
    echo "   Switching to docker-desktop..."
    kubectl config use-context docker-desktop
fi

# Verify cluster
echo "📊 Cluster Info:"
kubectl cluster-info | grep -E "control plane|CoreDNS"
echo ""

# Show nodes
echo "🖥️  Nodes:"
kubectl get nodes
echo ""

# Create test namespace if not exists
kubectl create namespace security-test --dry-run=client -o yaml | kubectl apply -f -

# Deploy test workload
echo "📦 Deploying test workloads..."
kubectl run insecure-nginx --image=nginx \
  --namespace=security-test \
  --overrides='{"spec":{"hostNetwork":true,"containers":[{"name":"nginx","image":"nginx","securityContext":{"privileged":true}}]}}' \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl run secure-nginx --image=nginx \
  --namespace=security-test \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000},"containers":[{"name":"nginx","image":"nginx","securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"capabilities":{"drop":["ALL"]}}}]}}' \
  --dry-run=client -o yaml | kubectl apply -f -

# Wait for pods
echo "⏳ Waiting for pods..."
kubectl wait --for=condition=Ready pod/insecure-nginx -n security-test --timeout=30s || true
kubectl wait --for=condition=Ready pod/secure-nginx -n security-test --timeout=30s || true

echo ""
echo "🔍 Running K8s Security Scan..."
echo ""

# Activate venv and run scan
cd /Users/apple/Desktop/threat-engine/k8_engine
source venv/bin/activate
python3 run_yaml_scan.py --components pod rbac --verbose

echo ""
echo "✅ Test complete!"
echo "📁 Results in: output/$(ls -t output/ | head -1)/"
```

Make it executable:
```bash
chmod +x test_docker_desktop.sh
./test_docker_desktop.sh
```

---

## Cleanup

### Remove Test Resources
```bash
# Delete test namespace (removes all test pods)
kubectl delete namespace security-test

# Delete test RBAC
kubectl delete clusterrole wildcard-admin
kubectl delete clusterrolebinding test-binding
```

### Switch Back to Minikube (if needed)
```bash
kubectl config use-context minikube
```

### Disable Kubernetes (optional)
1. Docker Desktop Settings
2. Kubernetes tab
3. Uncheck "Enable Kubernetes"
4. Apply & Restart

---

## Troubleshooting

### "Unable to connect to the server"
```bash
# Solution: Check Kubernetes is enabled in Docker Desktop
# Settings → Kubernetes → Enable Kubernetes → Apply & Restart
```

### "The connection to the server was refused"
```bash
# Wait a few minutes for Kubernetes to start
# Check Docker Desktop dashboard - should show "Kubernetes is running"
```

### "Context not found"
```bash
# Kubernetes not enabled yet in Docker Desktop
# Enable it: Settings → Kubernetes → Enable
```

---

## Next Steps

1. **Enable Kubernetes** in Docker Desktop (if not already)
2. **Switch context:** `kubectl config use-context docker-desktop`
3. **Verify cluster:** `kubectl get nodes`
4. **Deploy test workloads** (see Step 4 above)
5. **Run engine:** `python3 run_yaml_scan.py --verbose`
6. **Review results:** `ls -lh output/$(ls -t output/ | head -1)/checks/`

---

## Comparison

| Feature | Docker Desktop K8s | Minikube | Mock Data |
|---------|-------------------|----------|-----------|
| Setup Time | 2-3 min | 3-5 min | 0 min ✅ |
| Control Plane Access | ✅ Full | ⚠️ Limited | ✅ Full (mocked) |
| Workload Testing | ✅ Yes | ✅ Yes | ❌ No |
| Performance | ✅ Native | ⚠️ VM | ✅ Instant |
| Persistence | ✅ Yes | ⚠️ Sometimes | N/A |
| Complexity | ✅ Simple | ⚠️ Moderate | ✅ Simple |

**Recommendation:** Use **Docker Desktop Kubernetes** for real testing, **Mock Data** for quick validation.

---

Ready to test! Just enable Kubernetes in Docker Desktop and run the engine! 🚀

