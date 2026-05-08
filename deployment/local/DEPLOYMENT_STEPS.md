# EKS Deployment Steps for Threat Engine

## Prerequisites Completed ✅

1. ✅ EKS Cluster: `vulnerability-eks-cluster` (Mumbai, ap-south-1)
2. ✅ OIDC Provider: Enabled
3. ✅ Platform IAM Role: `threat-engine-platform-role` with IRSA
4. ✅ Service Account: `aws-compliance-engine-sa` with IRSA annotation
5. ✅ Namespace: `threat-engine-engines` created
6. ✅ Secrets & ConfigMaps: Deployed
7. ✅ Database: PostgreSQL StatefulSet deployed

## Step 1: Build and Push Docker Images

### Option A: Use the build script

```bash
cd /Users/apple/Desktop/threat-engine/kubernetes
./build-and-push-images.sh YOUR_DOCKERHUB_USERNAME
```

### Option B: Manual build (if you prefer)

```bash
# Login to Docker Hub
docker login

# Set your Docker Hub username
export DOCKERHUB_USER="your-username"

# Build and push onboarding API
cd /Users/apple/Desktop/onboarding
docker build -t $DOCKERHUB_USER/threat-engine-onboarding-api:latest -f Dockerfile .
docker push $DOCKERHUB_USER/threat-engine-onboarding-api:latest

# Build and push scheduler
docker build -t $DOCKERHUB_USER/threat-engine-scheduler:latest -f scheduler/Dockerfile .
docker push $DOCKERHUB_USER/threat-engine-scheduler:latest

# Build and push all engines (from threat-engine directory)
cd /Users/apple/Desktop/threat-engine
docker build -t $DOCKERHUB_USER/threat-engine-aws-compliance:latest -f aws_compliance_python_engine/Dockerfile .
docker build -t $DOCKERHUB_USER/threat-engine-azure-compliance:latest -f azure_compliance_python_engine/Dockerfile .
docker build -t $DOCKERHUB_USER/threat-engine-gcp-compliance:latest -f gcp_compliance_python_engine/Dockerfile .
docker build -t $DOCKERHUB_USER/threat-engine-alicloud-compliance:latest -f alicloud_compliance_python_engine/Dockerfile .
docker build -t $DOCKERHUB_USER/threat-engine-oci-compliance:latest -f oci_compliance_python_engine/Dockerfile .
docker build -t $DOCKERHUB_USER/threat-engine-ibm-compliance:latest -f ibm_compliance_python_engine/Dockerfile .
docker build -t $DOCKERHUB_USER/threat-engine-yaml-rule-builder:latest -f yaml-rule-builder/Dockerfile .

# Push all
docker push $DOCKERHUB_USER/threat-engine-aws-compliance:latest
docker push $DOCKERHUB_USER/threat-engine-azure-compliance:latest
docker push $DOCKERHUB_USER/threat-engine-gcp-compliance:latest
docker push $DOCKERHUB_USER/threat-engine-alicloud-compliance:latest
docker push $DOCKERHUB_USER/threat-engine-oci-compliance:latest
docker push $DOCKERHUB_USER/threat-engine-ibm-compliance:latest
docker push $DOCKERHUB_USER/threat-engine-yaml-rule-builder:latest
```

## Step 2: Update Kubernetes Manifests with Your Docker Hub Username

Replace `YOUR_DOCKERHUB_USERNAME` in all deployment files:

```bash
cd /Users/apple/Desktop/threat-engine
export DOCKERHUB_USER="your-username"

# Update all deployment files
find kubernetes -name "*.yaml" -type f -exec sed -i '' "s/YOUR_DOCKERHUB_USERNAME/$DOCKERHUB_USER/g" {} \;
```

Or manually edit each file:
- `kubernetes/onboarding/onboarding-deployment.yaml`
- `kubernetes/scheduler/scheduler-deployment.yaml`
- `kubernetes/engines/*-deployment.yaml`

## Step 3: Wait for Database to be Ready

```bash
kubectl wait --for=condition=ready pod -l app=postgres -n threat-engine-engines --timeout=300s
```

## Step 4: Initialize Database Schema

```bash
# Wait for postgres to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n threat-engine-engines --timeout=300s

# Copy schema file to pod and execute
kubectl cp /Users/apple/Desktop/onboarding/database/schema.sql threat-engine-engines/$(kubectl get pod -l app=postgres -n threat-engine-engines -o jsonpath='{.items[0].metadata.name}'):/tmp/schema.sql

# Execute schema
kubectl exec -it $(kubectl get pod -l app=postgres -n threat-engine-engines -o jsonpath='{.items[0].metadata.name}') -n threat-engine-engines -- psql -U threatengine -d threatengine -f /tmp/schema.sql
```

## Step 5: Deploy All Engines

```bash
cd /Users/apple/Desktop/threat-engine
kubectl apply -f kubernetes/engines/
```

Verify:
```bash
kubectl get pods -n threat-engine-engines -l tier=engine
```

## Step 6: Deploy Onboarding API

```bash
kubectl apply -f kubernetes/onboarding/onboarding-deployment.yaml
```

Verify:
```bash
kubectl get pods -n threat-engine-engines -l app=onboarding-api
```

## Step 7: Deploy Scheduler

```bash
kubectl apply -f kubernetes/scheduler/scheduler-deployment.yaml
```

Verify:
```bash
kubectl get pods -n threat-engine-engines -l app=scheduler-service
kubectl logs -f deployment/scheduler-service -n threat-engine-engines
```

## Step 8: Verify All Services

```bash
# Check all pods
kubectl get pods -n threat-engine-engines

# Check all services
kubectl get svc -n threat-engine-engines

# Test onboarding API health
kubectl run curl-test --image=curlimages/curl:latest --rm -it --restart=Never -- curl http://onboarding-api.threat-engine-engines.svc.cluster.local/api/v1/health

# Test AWS engine health
kubectl run curl-test --image=curlimages/curl:latest --rm -it --restart=Never -- curl http://aws-compliance-engine.threat-engine-engines.svc.cluster.local/api/v1/health
```

## Troubleshooting

### Check pod logs
```bash
kubectl logs -f <pod-name> -n threat-engine-engines
```

### Check service account
```bash
kubectl get serviceaccount aws-compliance-engine-sa -n threat-engine-engines -o yaml
```

### Test IRSA (from AWS engine pod)
```bash
kubectl exec -it <aws-engine-pod> -n threat-engine-engines -- aws sts get-caller-identity
```

### Check database connection
```bash
kubectl exec -it $(kubectl get pod -l app=postgres -n threat-engine-engines -o jsonpath='{.items[0].metadata.name}') -n threat-engine-engines -- psql -U threatengine -d threatengine -c "\dt"
```

## Current Configuration

- **Cluster**: vulnerability-eks-cluster (ap-south-1)
- **Namespace**: threat-engine-engines
- **Platform AWS Account**: 588989875114
- **Platform IAM Role**: threat-engine-platform-role
- **Service Account**: aws-compliance-engine-sa (with IRSA)
- **Database**: PostgreSQL 15 (StatefulSet)
- **Image Registry**: Docker Hub (YOUR_DOCKERHUB_USERNAME)

