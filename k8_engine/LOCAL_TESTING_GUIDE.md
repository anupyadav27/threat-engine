# Local K8s Testing Guide - Mac

## Quick Start

### 1. Start Minikube Cluster

```bash
# Start minikube with sufficient resources
minikube start --cpus=2 --memory=4096 --driver=docker

# Verify cluster is running
kubectl cluster-info
kubectl get nodes
```

### 2. Install Python Dependencies

```bash
cd /Users/apple/Desktop/threat-engine/k8_engine
pip3 install -r requirements.txt
```

### 3. Run K8s Engine Against Local Cluster

```bash
# Run all checks
python3 run_yaml_scan.py --verbose

# Run specific components
python3 run_yaml_scan.py --components apiserver etcd scheduler --verbose

# Run workload checks (requires some pods)
python3 run_yaml_scan.py --components pod rbac namespace --verbose
```

---

## Testing Scenarios

### Scenario 1: Control Plane Checks (Minikube)

**Note:** Minikube is a managed cluster, so control plane checks (apiserver, etcd, scheduler) may skip or show limited results since control plane pods are managed.

```bash
# Test control plane components
python3 run_yaml_scan.py --components apiserver etcd scheduler controllermanager --verbose

# Expected: Many checks will show SKIP status for managed clusters
```

### Scenario 2: Workload Security Checks

First, deploy some test workloads:

```bash
# Create a test namespace
kubectl create namespace test-security

# Deploy a test pod with security issues (for testing)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
  namespace: test-security
spec:
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true  # Security issue!
      allowPrivilegeEscalation: true
    env:
    - name: SECRET_KEY
      value: "hardcoded-secret"  # Security issue!
EOF

# Deploy a secure pod
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: test-security
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities:
        drop:
        - ALL
EOF
```

Now scan workloads:

```bash
# Scan pods
python3 run_yaml_scan.py --components pod core --verbose

# Should detect:
# - Privileged containers
# - Secrets in environment variables
# - Missing security contexts
```

### Scenario 3: RBAC Checks

```bash
# Create test RBAC resources
kubectl create clusterrole test-wildcard-role \
  --verb=get,list,watch \
  --resource='*'

kubectl create clusterrolebinding test-admin-binding \
  --clusterrole=cluster-admin \
  --user=test-user

# Scan RBAC
python3 run_yaml_scan.py --components rbac --verbose

# Should detect:
# - Wildcard permissions
# - Cluster-admin usage
```

### Scenario 4: Network Policy Checks

```bash
# Check if network policies exist
kubectl get networkpolicies --all-namespaces

# Create a test network policy
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: test-security
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

# Scan network
python3 run_yaml_scan.py --components network --verbose
```

### Scenario 5: Secret Management

```bash
# Create test secrets
kubectl create secret generic test-secret \
  --from-literal=password=insecure123 \
  -n test-security

# Scan secrets
python3 run_yaml_scan.py --components secret configmap --verbose
```

---

## Understanding Minikube Results

### Control Plane Components
Minikube runs control plane components in the `kube-system` namespace:

```bash
# View control plane pods
kubectl get pods -n kube-system

# You should see:
# - kube-apiserver
# - etcd
# - kube-controller-manager
# - kube-scheduler
```

### What Works on Minikube
✅ **Fully Testable:**
- Pod security checks
- RBAC checks
- Network policy checks
- Secret/ConfigMap checks
- Namespace checks
- Service checks
- Workload checks

⚠️ **Limited on Minikube (Managed Control Plane):**
- API server configuration checks (may skip)
- etcd configuration checks (may skip)
- Scheduler configuration checks (may skip)

### Mock Testing Alternative

If control plane checks aren't working, use mocks:

```bash
# Test with mock data (no cluster needed)
python3 run_yaml_scan.py \
  --mock-dir mocks/ \
  --components apiserver etcd \
  --verbose
```

---

## Example Test Commands

### Quick Security Scan
```bash
# Basic security scan of workloads
python3 run_yaml_scan.py \
  --components pod rbac network secret \
  --verbose
```

### Comprehensive Scan
```bash
# Scan everything (may take a minute)
python3 run_yaml_scan.py --verbose
```

### Specific Service Test
```bash
# Test just RBAC
python3 run_yaml_scan.py --components rbac --verbose

# Test just pods
python3 run_yaml_scan.py --components pod --verbose
```

### With Output to File
```bash
# Save results to timestamped directory
python3 run_yaml_scan.py \
  --components pod rbac network \
  --verbose \
  --output-dir ./test-results
```

---

## Expected Output Format

### Console Output
```
Loaded 15 YAML definition files from services/
Skipping apiserver due to applicability: provider=unknown, managed=True

Check Results:
[PASS] k8s.pod.security.privileged_containers_check - Minimize Privileged Containers
[FAIL] k8s.pod.security.host_network_disabled - Host Network Disabled
[SKIP] k8s.rbac.cluster_admin_usage - Rbac Cluster Admin Usage

Total checks: 150
```

### JSON Output
Results saved to:
```
output/20251204_160000/
├── inventory/
│   ├── pod_inventory.json
│   ├── rbac_inventory.json
│   └── network_inventory.json
└── checks/
    ├── pod_checks.json
    ├── rbac_checks.json
    └── network_checks.json
```

---

## Troubleshooting

### Issue: "No cluster detected"
```bash
# Check minikube status
minikube status

# If not running, start it
minikube start

# Verify kubectl can connect
kubectl get nodes
```

### Issue: "Permission denied"
```bash
# Check kubeconfig
kubectl config view

# Use specific kubeconfig
python3 run_yaml_scan.py \
  --kubeconfig ~/.kube/config \
  --context minikube
```

### Issue: "No resources found"
```bash
# Deploy some test workloads first
kubectl create deployment nginx --image=nginx -n default
kubectl expose deployment nginx --port=80 -n default

# Then run scan
python3 run_yaml_scan.py --components pod service
```

### Issue: Control plane checks show SKIP
This is normal for minikube (managed cluster). Options:
1. Use mock data: `--mock-dir mocks/`
2. Test on self-managed cluster (kubeadm, kind with exposed control plane)
3. Focus on workload checks which work fully on minikube

---

## Cleanup

### Remove Test Resources
```bash
# Delete test namespace and all resources
kubectl delete namespace test-security

# Delete test RBAC
kubectl delete clusterrole test-wildcard-role
kubectl delete clusterrolebinding test-admin-binding
```

### Stop Minikube
```bash
# Stop minikube (keeps the cluster)
minikube stop

# Delete minikube cluster completely
minikube delete
```

---

## Performance Tips

### For Faster Scans
```bash
# Scan only specific namespaces (future enhancement)
kubectl get pods -n test-security

# Scan specific components
python3 run_yaml_scan.py --components pod rbac

# Use mock data for development
python3 run_yaml_scan.py --mock-dir mocks/
```

### For Complete Coverage
```bash
# Deploy diverse workloads first
kubectl create deployment test-deploy --image=nginx
kubectl create job test-job --image=busybox -- echo "test"
kubectl create cronjob test-cron --image=busybox --schedule="*/5 * * * *" -- echo "test"

# Then run comprehensive scan
python3 run_yaml_scan.py
```

---

## Next Steps

1. **Start minikube:** `minikube start`
2. **Install dependencies:** `pip3 install -r requirements.txt`
3. **Deploy test workloads:** See Scenario 2 above
4. **Run first scan:** `python3 run_yaml_scan.py --components pod --verbose`
5. **Review results:** Check console output and `output/` directory
6. **Iterate:** Deploy more resources, run more checks

---

## Reference

- **Minikube Docs:** https://minikube.sigs.k8s.io/docs/
- **K8s Security:** https://kubernetes.io/docs/concepts/security/
- **Pod Security Standards:** https://kubernetes.io/docs/concepts/security/pod-security-standards/

Happy testing! 🚀

