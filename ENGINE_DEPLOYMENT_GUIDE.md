# Threat Engine Deployment Guide

## Overview

This guide covers deploying all threat engine services (AWS, Azure, GCP, AliCloud, OCI, IBM) and the YAML Rule Builder to EKS.

## Prerequisites

- Docker Hub account: `yadavanup84`
- EKS cluster configured and accessible
- `kubectl` configured for your EKS cluster
- Docker installed and running

## Quick Deploy

### Option 1: Automated (All at Once)

```bash
cd /Users/apple/Desktop/threat-engine

# Build and push all images (takes 10-20 minutes)
./build-and-push-engines.sh

# Deploy all engines
./deploy-all-engines.sh
```

### Option 2: Step by Step

#### 1. Build and Push Images

**AWS Engine:**
```bash
cd /Users/apple/Desktop/threat-engine
docker build -f aws_compliance_python_engine/Dockerfile -t yadavanup84/threat-engine-aws-compliance:latest .
docker push yadavanup84/threat-engine-aws-compliance:latest
```

**Azure Engine:**
```bash
docker build -f azure_compliance_python_engine/Dockerfile -t yadavanup84/threat-engine-azure-compliance:latest .
docker push yadavanup84/threat-engine-azure-compliance:latest
```

**GCP Engine:**
```bash
docker build -f gcp_compliance_python_engine/Dockerfile -t yadavanup84/threat-engine-gcp-compliance:latest .
docker push yadavanup84/threat-engine-gcp-compliance:latest
```

**AliCloud Engine:**
```bash
docker build -f alicloud_compliance_python_engine/Dockerfile -t yadavanup84/threat-engine-alicloud-compliance:latest .
docker push yadavanup84/threat-engine-alicloud-compliance:latest
```

**OCI Engine:**
```bash
docker build -f oci_compliance_python_engine/Dockerfile -t yadavanup84/threat-engine-oci-compliance:latest .
docker push yadavanup84/threat-engine-oci-compliance:latest
```

**IBM Engine:**
```bash
docker build -f ibm_compliance_python_engine/Dockerfile -t yadavanup84/threat-engine-ibm-compliance:latest .
docker push yadavanup84/threat-engine-ibm-compliance:latest
```

**YAML Rule Builder:**
```bash
docker build -f yaml-rule-builder/Dockerfile -t yadavanup84/threat-engine-yaml-rule-builder:latest .
docker push yadavanup84/threat-engine-yaml-rule-builder:latest
```

#### 2. Deploy to EKS

```bash
# Deploy AWS Engine
kubectl apply -f kubernetes/engines/aws-engine-deployment.yaml

# Deploy Azure Engine
kubectl apply -f kubernetes/engines/azure-engine-deployment.yaml

# Deploy GCP Engine
kubectl apply -f kubernetes/engines/gcp-engine-deployment.yaml

# Deploy AliCloud Engine
kubectl apply -f kubernetes/engines/alicloud-engine-deployment.yaml

# Deploy OCI Engine
kubectl apply -f kubernetes/engines/oci-engine-deployment.yaml

# Deploy IBM Engine
kubectl apply -f kubernetes/engines/ibm-engine-deployment.yaml

# Deploy YAML Rule Builder
kubectl apply -f kubernetes/engines/yaml-rule-builder-deployment.yaml
```

## Verify Deployment

### Check Pods

```bash
# All engines
kubectl get pods -n threat-engine-engines -l tier=engine

# YAML Rule Builder
kubectl get pods -n threat-engine-engines -l app=yaml-rule-builder

# All services
kubectl get pods -n threat-engine-engines
```

### Check Services

```bash
kubectl get svc -n threat-engine-engines
```

Expected services:
- `aws-compliance-engine` (ClusterIP)
- `azure-compliance-engine` (ClusterIP)
- `gcp-compliance-engine` (ClusterIP)
- `alicloud-compliance-engine` (ClusterIP)
- `oci-compliance-engine` (ClusterIP)
- `ibm-compliance-engine` (ClusterIP)
- `yaml-rule-builder` (ClusterIP)

### Check Logs

```bash
# AWS Engine
kubectl logs -n threat-engine-engines -l app=aws-compliance-engine --tail=50

# YAML Rule Builder
kubectl logs -n threat-engine-engines -l app=yaml-rule-builder --tail=50
```

### Test Health Endpoints

```bash
# Port forward to test
kubectl port-forward -n threat-engine-engines svc/aws-compliance-engine 8000:80

# In another terminal
curl http://localhost:8000/api/v1/health
```

## Service URLs (Internal)

All services are accessible within the cluster via:

- `http://aws-compliance-engine.threat-engine-engines.svc.cluster.local`
- `http://azure-compliance-engine.threat-engine-engines.svc.cluster.local`
- `http://gcp-compliance-engine.threat-engine-engines.svc.cluster.local`
- `http://alicloud-compliance-engine.threat-engine-engines.svc.cluster.local`
- `http://oci-compliance-engine.threat-engine-engines.svc.cluster.local`
- `http://ibm-compliance-engine.threat-engine-engines.svc.cluster.local`
- `http://yaml-rule-builder.threat-engine-engines.svc.cluster.local`

## End-to-End Flow

### 1. User Onboarding (via Onboarding API)
```
POST /api/v1/onboarding/aws/init
→ Returns account_id, external_id
```

### 2. Deploy CloudFormation (in AWS account)
```
→ Get Role ARN from CloudFormation outputs
```

### 3. Validate Account (via Onboarding API)
```
POST /api/v1/onboarding/aws/validate-json
→ Account activated
```

### 4. Create Schedule (via Onboarding API)
```
POST /api/v1/schedules
→ Schedule created
```

### 5. Scheduler Triggers Scan
```
→ Calls AWS Engine API
POST http://aws-compliance-engine/api/v1/scan
```

### 6. Get Scan Results
```
GET http://aws-compliance-engine/api/v1/scan/{scan_id}/results
```

### 7. Generate Rules (via YAML Rule Builder)
```
POST http://yaml-rule-builder/api/v1/rules/generate
```

## Troubleshooting

### Image Pull Errors

If pods show `ErrImagePull` or `ImagePullBackOff`:

1. Verify image exists:
   ```bash
   docker pull yadavanup84/threat-engine-aws-compliance:latest
   ```

2. Check Docker Hub repository is public

3. Restart deployment:
   ```bash
   kubectl rollout restart deployment/aws-compliance-engine -n threat-engine-engines
   ```

### Pod Not Starting

1. Check pod events:
   ```bash
   kubectl describe pod <pod-name> -n threat-engine-engines
   ```

2. Check logs:
   ```bash
   kubectl logs <pod-name> -n threat-engine-engines
   ```

### Health Check Failing

1. Verify API server is running:
   ```bash
   kubectl exec -it <pod-name> -n threat-engine-engines -- curl http://localhost:8000/api/v1/health
   ```

2. Check environment variables:
   ```bash
   kubectl exec -it <pod-name> -n threat-engine-engines -- env
   ```

## Scaling

To scale engines:

```bash
# Scale AWS Engine to 5 replicas
kubectl scale deployment aws-compliance-engine -n threat-engine-engines --replicas=5

# Scale YAML Rule Builder to 3 replicas
kubectl scale deployment yaml-rule-builder -n threat-engine-engines --replicas=3
```

## Resource Limits

Current resource limits:
- **Engines**: 512Mi-2Gi memory, 250m-1000m CPU
- **YAML Rule Builder**: 256Mi-512Mi memory, 100m-500m CPU

Adjust in deployment YAML files if needed.

## Cleanup

To remove all engines:

```bash
kubectl delete -f kubernetes/engines/aws-engine-deployment.yaml
kubectl delete -f kubernetes/engines/azure-engine-deployment.yaml
kubectl delete -f kubernetes/engines/gcp-engine-deployment.yaml
kubectl delete -f kubernetes/engines/alicloud-engine-deployment.yaml
kubectl delete -f kubernetes/engines/oci-engine-deployment.yaml
kubectl delete -f kubernetes/engines/ibm-engine-deployment.yaml
kubectl delete -f kubernetes/engines/yaml-rule-builder-deployment.yaml
```

---

**Last Updated:** 2026-01-03

