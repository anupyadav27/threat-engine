#!/bin/bash
# Full Test - All K8s Services and Resources

set -e

echo "🎯 K8s Engine - Full Service Test"
echo "=================================="
echo ""

TEST_NS="k8s-full-test"

# Create namespace
echo "📦 Creating namespace: $TEST_NS"
kubectl create namespace $TEST_NS --dry-run=client -o yaml | kubectl apply -f -
echo ""

echo "🚀 Deploying comprehensive test resources..."
echo ""

# Deploy resources for EACH service type
cat <<'EOF' | kubectl apply -f -
---
# Namespace with labels and resource quotas
apiVersion: v1
kind: Namespace
metadata:
  name: k8s-full-test-2
  labels:
    env: test
    security: high
---
# Resource Quota
apiVersion: v1
kind: ResourceQuota
metadata:
  name: test-quota
  namespace: k8s-full-test
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
---
# LimitRange
apiVersion: v1
kind: LimitRange
metadata:
  name: test-limits
  namespace: k8s-full-test
spec:
  limits:
  - max:
      cpu: "2"
      memory: 2Gi
    min:
      cpu: 100m
      memory: 128Mi
    type: Container
---
# ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: k8s-full-test
data:
  app.properties: |
    server.port=8080
    db.host=localhost
  config.yaml: |
    logging: debug
---
# Secret
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: k8s-full-test
type: Opaque
stringData:
  password: "test123"
  api-key: "abc123"
---
# ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: k8s-full-test
---
# Role
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: k8s-full-test
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
# RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: k8s-full-test
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: k8s-full-test
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
---
# ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-cluster-reader
rules:
- apiGroups: [""]
  resources: ["nodes", "namespaces"]
  verbs: ["get", "list"]
---
# ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: test-cluster-read
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: k8s-full-test
roleRef:
  kind: ClusterRole
  name: test-cluster-reader
  apiGroup: rbac.authorization.k8s.io
---
# PersistentVolumeClaim
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-pvc
  namespace: k8s-full-test
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
---
# Pod with various security contexts
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-1
  namespace: k8s-full-test
  labels:
    app: test
    tier: frontend
spec:
  serviceAccountName: app-sa
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 200m
        memory: 256Mi
    volumeMounts:
    - name: config
      mountPath: /config
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: config
    configMap:
      name: app-config
  - name: tmp
    emptyDir: {}
---
# Insecure Pod
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
  namespace: k8s-full-test
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
    env:
    - name: PASSWORD
      value: "hardcoded"
---
# Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: k8s-full-test
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.21
        resources:
          requests:
            cpu: 50m
            memory: 64Mi
          limits:
            cpu: 100m
            memory: 128Mi
---
# StatefulSet
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
  namespace: k8s-full-test
spec:
  serviceName: db
  replicas: 2
  selector:
    matchLabels:
      app: database
  template:
    metadata:
      labels:
        app: database
    spec:
      containers:
      - name: db
        image: postgres:13-alpine
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: app-secret
              key: password
---
# DaemonSet
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-monitor
  namespace: k8s-full-test
spec:
  selector:
    matchLabels:
      app: monitor
  template:
    metadata:
      labels:
        app: monitor
    spec:
      containers:
      - name: monitor
        image: busybox
        command: ["sh", "-c", "while true; do echo monitoring; sleep 3600; done"]
---
# Service - ClusterIP
apiVersion: v1
kind: Service
metadata:
  name: web-service
  namespace: k8s-full-test
spec:
  type: ClusterIP
  selector:
    app: web
  ports:
  - port: 80
    targetPort: 80
---
# Service - NodePort
apiVersion: v1
kind: Service
metadata:
  name: web-nodeport
  namespace: k8s-full-test
spec:
  type: NodePort
  selector:
    app: web
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30080
---
# NetworkPolicy - Default Deny
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: k8s-full-test
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# NetworkPolicy - Allow specific
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web
  namespace: k8s-full-test
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 80
---
# Ingress
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-ingress
  namespace: k8s-full-test
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: app.test.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-service
            port:
              number: 80
---
# Job
apiVersion: batch/v1
kind: Job
metadata:
  name: batch-job
  namespace: k8s-full-test
spec:
  template:
    spec:
      containers:
      - name: job
        image: busybox
        command: ["sh", "-c", "echo Job completed"]
      restartPolicy: Never
---
# CronJob
apiVersion: batch/v1
kind: CronJob
metadata:
  name: scheduled-job
  namespace: k8s-full-test
spec:
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cron
            image: busybox
            command: ["sh", "-c", "echo Cron job"]
          restartPolicy: OnFailure
---
# HorizontalPodAutoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-hpa
  namespace: k8s-full-test
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-app
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 80
---
# PodDisruptionBudget
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web-pdb
  namespace: k8s-full-test
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: web
EOF

echo "✅ Resources deployed"
echo ""

echo "⏳ Waiting for resources to be ready..."
sleep 10

echo ""
echo "📊 Deployed Resources:"
kubectl get all,pvc,configmap,secret,networkpolicy,ingress,pdb,hpa -n k8s-full-test

echo ""
echo "🔍 Running COMPREHENSIVE SCAN - ALL SERVICES..."
echo ""

cd /Users/apple/Desktop/threat-engine/k8_engine
source venv/bin/activate

# Run scan for ALL components (no --components filter)
python3 run_yaml_scan.py --verbose

LATEST=$(ls -t output/ | head -1)

echo ""
echo "✅ FULL SCAN COMPLETE!"
echo ""
echo "📊 RESULTS BY SERVICE:"
echo "====================="
echo ""

for file in output/$LATEST/checks/*.json; do
    if [ -f "$file" ]; then
        component=$(basename $file .json | sed 's/_checks//')
        echo "$component:"
        python3 -c "
import json
with open('$file') as f:
    checks = json.load(f)['checks']
    total = len(checks)
    pass_c = sum(1 for c in checks if c['status'] == 'PASS')
    fail_c = sum(1 for c in checks if c['status'] == 'FAIL')
    skip_c = sum(1 for c in checks if c['status'] == 'SKIP')
    error_c = sum(1 for c in checks if c['status'] == 'ERROR')
    print(f'  Total: {total:4d} | PASS: {pass_c:4d} | FAIL: {fail_c:4d} | SKIP: {skip_c:4d} | ERROR: {error_c:4d}')
"
    fi
done

echo ""
echo "📁 Full results in: output/$LATEST/"
echo ""
echo "📈 Summary Statistics:"
python3 << 'PYEOF'
import json
import glob
from collections import Counter

total_checks = 0
all_status = Counter()
all_severity = Counter()

for f in glob.glob("output/*/checks/*_checks.json"):
    with open(f) as file:
        checks = json.load(file)['checks']
        total_checks += len(checks)
        all_status.update(c['status'] for c in checks)
        all_severity.update(c['severity'] for c in checks)

print(f"\n🎯 TOTAL CHECKS ACROSS ALL SERVICES: {total_checks}")
print(f"\n📊 Status Distribution:")
for status, count in all_status.most_common():
    pct = (count/total_checks)*100
    print(f"  {status:8s}: {count:5d} ({pct:5.1f}%)")

print(f"\n⚠️  Severity Distribution:")
for sev, count in all_severity.most_common():
    pct = (count/total_checks)*100
    print(f"  {sev:8s}: {count:5d} ({pct:5.1f}%)")
PYEOF

echo ""
read -p "🗑️  Clean up all test resources? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🧹 Cleaning up..."
    kubectl delete namespace k8s-full-test k8s-full-test-2 --grace-period=0 --force 2>/dev/null || true
    kubectl delete clusterrole test-cluster-reader 2>/dev/null || true
    kubectl delete clusterrolebinding test-cluster-read 2>/dev/null || true
    echo "✅ Cleanup complete!"
else
    echo "⚠️  Resources preserved. To clean up later:"
    echo "   kubectl delete namespace k8s-full-test k8s-full-test-2"
    echo "   kubectl delete clusterrole test-cluster-reader"
    echo "   kubectl delete clusterrolebinding test-cluster-read"
fi

echo ""
echo "✨ Full service test complete!"

