# Quick Deploy Guide - Threat Engine on EKS

## ✅ Already Completed

1. **EKS Cluster Setup**
   - Cluster: `vulnerability-eks-cluster` (Mumbai, ap-south-1)
   - OIDC Provider: Enabled
   - Namespace: `threat-engine-engines` created

2. **IRSA Configuration**
   - Platform IAM Role: `threat-engine-platform-role`
   - Service Account: `aws-compliance-engine-sa` (with IRSA annotation)
   - Policy: Allows assuming customer IAM roles

3. **Kubernetes Resources**
   - Secrets: database-credentials, encryption-keys
   - ConfigMap: platform-config (with AWS account ID: 588989875114)
   - Database: PostgreSQL StatefulSet deployed

4. **Docker Hub Configuration**
   - All deployment manifests updated to use Docker Hub format
   - Image names: `YOUR_DOCKERHUB_USERNAME/threat-engine-*`

## 🚀 Next Steps (You Need to Do)

### 1. Replace Docker Hub Username

Replace `YOUR_DOCKERHUB_USERNAME` in all deployment files:

```bash
cd /Users/apple/Desktop/threat-engine
export DOCKERHUB_USER="your-dockerhub-username"
find kubernetes -name "*.yaml" -type f -exec sed -i '' "s/YOUR_DOCKERHUB_USERNAME/$DOCKERHUB_USER/g" {} \;
```

### 2. Build and Push Images

```bash
cd /Users/apple/Desktop/threat-engine/kubernetes
./build-and-push-images.sh your-dockerhub-username
```

**OR** manually build and push each image (see `DEPLOYMENT_STEPS.md`)

### 3. Wait for Database

```bash
kubectl wait --for=condition=ready pod -l app=postgres -n threat-engine-engines --timeout=300s
```

### 4. Initialize Database Schema

```bash
# Copy schema to pod
kubectl cp /Users/apple/Desktop/onboarding/database/schema.sql \
  threat-engine-engines/$(kubectl get pod -l app=postgres -n threat-engine-engines -o jsonpath='{.items[0].metadata.name}'):/tmp/schema.sql

# Execute schema
kubectl exec -it $(kubectl get pod -l app=postgres -n threat-engine-engines -o jsonpath='{.items[0].metadata.name}') \
  -n threat-engine-engines -- \
  psql -U threatengine -d threatengine -f /tmp/schema.sql
```

### 5. Deploy Everything

```bash
cd /Users/apple/Desktop/threat-engine

# Deploy all engines
kubectl apply -f kubernetes/engines/

# Deploy onboarding API
kubectl apply -f kubernetes/onboarding/onboarding-deployment.yaml

# Deploy scheduler
kubectl apply -f kubernetes/scheduler/scheduler-deployment.yaml
```

### 6. Verify

```bash
# Check all pods
kubectl get pods -n threat-engine-engines

# Check services
kubectl get svc -n threat-engine-engines

# Test health endpoints
kubectl run curl-test --image=curlimages/curl:latest --rm -it --restart=Never -- \
  curl http://onboarding-api.threat-engine-engines.svc.cluster.local/api/v1/health
```

## 📋 Image List (Docker Hub)

After building, you'll have these images:
- `your-username/threat-engine-onboarding-api:latest`
- `your-username/threat-engine-scheduler:latest`
- `your-username/threat-engine-aws-compliance:latest`
- `your-username/threat-engine-azure-compliance:latest`
- `your-username/threat-engine-gcp-compliance:latest`
- `your-username/threat-engine-alicloud-compliance:latest`
- `your-username/threat-engine-oci-compliance:latest`
- `your-username/threat-engine-ibm-compliance:latest`
- `your-username/threat-engine-yaml-rule-builder:latest`

## 🔧 Current Configuration

- **Cluster**: vulnerability-eks-cluster
- **Region**: ap-south-1 (Mumbai)
- **Platform AWS Account**: 588989875114
- **Platform IAM Role**: threat-engine-platform-role
- **Service Account**: aws-compliance-engine-sa
- **Namespace**: threat-engine-engines
- **Database**: PostgreSQL 15 (StatefulSet)

## 📚 Full Documentation

See `DEPLOYMENT_STEPS.md` for detailed instructions.

