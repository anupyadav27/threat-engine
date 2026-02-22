# Onboarding Engine Deployment

Complete deployment configuration and scripts for the Threat Engine Onboarding service.

---

## 📁 Directory Structure

```
deployment/
├── README.md                           # This file
├── build-and-deploy.sh                 # Complete build & deploy pipeline
├── deploy.sh                           # Deploy only (uses existing image)
└── kubernetes/
    ├── engine-onboarding.yaml          # Kubernetes deployment & service
    └── threat-engine-db-config.yaml    # ConfigMap for database config
```

---

## 🚀 Quick Deploy

### Option 1: Full Build & Deploy (Recommended)

Builds Docker image, pushes to registry, and deploys to EKS:

```bash
cd /Users/apple/Desktop/threat-engine
./engine_onboarding/deployment/build-and-deploy.sh
```

This will:
1. ✅ Build Docker image from latest code
2. ✅ Push to Docker Hub (yadavanup84/threat-engine-onboarding)
3. ✅ Apply Kubernetes manifests
4. ✅ Wait for rollout to complete
5. ✅ Show deployment status

### Option 2: Deploy Only

If image is already built and pushed:

```bash
./engine_onboarding/deployment/deploy.sh
```

---

## 🔧 Manual Deployment Steps

### 1. Build Docker Image

```bash
cd /Users/apple/Desktop/threat-engine

docker build -f engine_onboarding/Dockerfile \
  -t yadavanup84/threat-engine-onboarding:latest \
  .
```

### 2. Push to Docker Hub

```bash
docker login -u yadavanup84
docker push yadavanup84/threat-engine-onboarding:latest
```

### 3. Apply Kubernetes Manifests

```bash
# Apply ConfigMap
kubectl apply -f engine_onboarding/deployment/kubernetes/threat-engine-db-config.yaml

# Apply Deployment & Service
kubectl apply -f engine_onboarding/deployment/kubernetes/engine-onboarding.yaml
```

### 4. Verify Deployment

```bash
# Check pod status
kubectl get pods -n threat-engine-engines -l app=engine-onboarding

# Check service
kubectl get svc -n threat-engine-engines -l app=engine-onboarding

# Check logs
kubectl logs -f deployment/engine-onboarding -n threat-engine-engines
```

---

## 🧪 Testing After Deployment

### Port Forward (Local Testing)

```bash
kubectl port-forward -n threat-engine-engines svc/engine-onboarding 8008:80

# Test endpoints
curl http://localhost:8008/
curl http://localhost:8008/api/v1/health
```

### Test New Cloud Accounts API

```bash
# Phase 1: Create Account
curl -X POST http://localhost:8008/api/v1/cloud-accounts \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "test-customer-001",
    "customer_email": "test@example.com",
    "tenant_id": "test-tenant-001",
    "tenant_name": "Test Tenant",
    "account_id": "123456789012",
    "account_name": "Test AWS Account",
    "provider": "aws",
    "credential_type": "iam_role",
    "credential_ref": "pending"
  }'

# Phase 2: Deploy (with IAM Role)
curl -X PATCH http://localhost:8008/api/v1/cloud-accounts/123456789012/deployment \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "123456789012",
    "onboarding_id": "arn:aws:cloudformation:...",
    "credential_ref": "arn:aws:iam::123456789012:role/ThreatEngineRole"
  }'

# Phase 2.5: Validate Credentials
curl -X POST http://localhost:8008/api/v1/cloud-accounts/123456789012/validate-credentials

# Phase 3: Validate & Create Schedule
curl -X POST http://localhost:8008/api/v1/cloud-accounts/123456789012/validate \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "123456789012",
    "cron_expression": "0 2 * * *",
    "include_regions": ["ap-south-1"],
    "engines_requested": ["discovery", "check", "inventory"]
  }'

# Get Account
curl http://localhost:8008/api/v1/cloud-accounts/123456789012
```

---

## 🔐 Storing Test Credentials in Secrets Manager

### AWS Account for Testing

To test the complete flow with real AWS credentials:

#### Option 1: Using AWS CLI

```bash
# Store access key credentials
aws secretsmanager create-secret \
  --name "threat-engine/account/588989875114" \
  --description "Test AWS account credentials" \
  --secret-string '{
    "credential_type": "aws_access_key",
    "credentials": {
      "access_key_id": "AKIA...",
      "secret_access_key": "..."
    },
    "account_id": "588989875114",
    "created_at": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
  }' \
  --region ap-south-1

# Verify secret was created
aws secretsmanager get-secret-value \
  --secret-id "threat-engine/account/588989875114" \
  --region ap-south-1
```

#### Option 2: Using Onboarding API

```bash
# Use the deployment endpoint with credentials
curl -X PATCH http://localhost:8008/api/v1/cloud-accounts/588989875114/deployment \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "588989875114",
    "onboarding_id": "test-deployment",
    "credentials": {
      "access_key_id": "AKIA...",
      "secret_access_key": "..."
    }
  }'

# This will automatically:
# 1. Store credentials in Secrets Manager
# 2. Set credential_ref = "threat-engine/account/588989875114"
# 3. Update account status to "deployed"
```

---

## 📊 Monitoring

### View Logs

```bash
# Follow logs
kubectl logs -f deployment/engine-onboarding -n threat-engine-engines

# Last 100 lines
kubectl logs deployment/engine-onboarding -n threat-engine-engines --tail=100

# Logs from specific pod
kubectl logs engine-onboarding-<pod-id> -n threat-engine-engines
```

### Check Pod Status

```bash
# Detailed pod info
kubectl describe pod -l app=engine-onboarding -n threat-engine-engines

# Resource usage
kubectl top pod -l app=engine-onboarding -n threat-engine-engines
```

### Check Events

```bash
kubectl get events -n threat-engine-engines \
  --field-selector involvedObject.name=engine-onboarding \
  --sort-by='.lastTimestamp'
```

---

## 🔄 Update Deployment

### Update to Latest Code

```bash
# Build and deploy latest
./engine_onboarding/deployment/build-and-deploy.sh
```

### Restart Pods (No Code Changes)

```bash
kubectl rollout restart deployment/engine-onboarding -n threat-engine-engines
```

### Rollback to Previous Version

```bash
kubectl rollout undo deployment/engine-onboarding -n threat-engine-engines
```

---

## 🐛 Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n threat-engine-engines -l app=engine-onboarding

# Check pod events
kubectl describe pod -l app=engine-onboarding -n threat-engine-engines

# Check logs
kubectl logs -l app=engine-onboarding -n threat-engine-engines --all-containers
```

### Database Connection Issues

```bash
# Check ConfigMap
kubectl get configmap threat-engine-db-config -n threat-engine-engines -o yaml

# Check Secret
kubectl get secret threat-engine-db-passwords -n threat-engine-engines

# Test connection from pod
kubectl exec -it deployment/engine-onboarding -n threat-engine-engines -- \
  python3 -c "from engine_onboarding.database.connection import check_connection; print(check_connection())"
```

### API Not Responding

```bash
# Check service
kubectl get svc engine-onboarding -n threat-engine-engines

# Check endpoints
kubectl get endpoints engine-onboarding -n threat-engine-engines

# Port forward and test
kubectl port-forward -n threat-engine-engines svc/engine-onboarding 8008:80
curl http://localhost:8008/api/v1/health
```

---

## 📝 Environment Variables

Key environment variables configured in deployment:

| Variable | Value | Description |
|----------|-------|-------------|
| `PORT` | 8008 | API server port |
| `SHARED_DB_NAME` | threat_engine_onboarding | Onboarding database name |
| `DB_SCHEMA` | public | Database schema |
| `AWS_REGION` | ap-south-1 | AWS region |
| `SECRETS_MANAGER_PREFIX` | threat-engine | Secrets prefix |
| `SCHEDULER_INTERVAL_SECONDS` | 60 | Scheduler check interval |

---

## 🎯 Service Endpoints

### Internal (Cluster)

```
http://engine-onboarding.threat-engine-engines.svc.cluster.local
```

### External (if LoadBalancer configured)

```bash
# Get external endpoint
kubectl get svc engine-onboarding -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

---

## ✅ Deployment Checklist

- [ ] Code changes committed
- [ ] Build script executed successfully
- [ ] Docker image pushed to registry
- [ ] Kubernetes manifests updated
- [ ] Deployment applied
- [ ] Pods running and healthy
- [ ] Health check passing
- [ ] Database connection working
- [ ] API endpoints tested
- [ ] Logs showing no errors
- [ ] Test credentials stored in Secrets Manager
- [ ] End-to-end flow tested

---

## 📚 Related Documentation

- Main project: `/Users/apple/Desktop/threat-engine/`
- Database schema: `engine_onboarding/database/schemas/onboarding_schema.sql`
- API documentation: `COMPLETE_INTEGRATION_SUMMARY.md`
- Credential validation: `CREDENTIAL_VALIDATION_COMPLETE.md`

---

## 🆘 Support

For issues or questions:
1. Check logs: `kubectl logs -f deployment/engine-onboarding -n threat-engine-engines`
2. Review documentation in project root
3. Verify database connectivity
4. Check Secrets Manager access
