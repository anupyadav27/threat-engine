# Compliance Engine Deployment Guide

## Prerequisites

1. **Docker** installed and configured
2. **kubectl** configured to access EKS cluster
3. **AWS CLI** configured with appropriate permissions
4. **S3 bucket** `cspm-lgtech` exists with scan results

## Step 1: Build and Push Docker Image

```bash
cd /Users/apple/Desktop/threat-engine
./compliance-engine/build-and-push.sh
```

Or manually:

```bash
cd /Users/apple/Desktop/threat-engine
docker build -t yadavanup84/threat-engine-compliance-engine:latest \
  -f compliance-engine/Dockerfile .
docker push yadavanup84/threat-engine-compliance-engine:latest
```

## Step 2: Deploy to EKS

```bash
kubectl apply -f kubernetes/engines/compliance-engine-deployment.yaml
```

## Step 3: Verify Deployment

```bash
# Check deployment status
kubectl get deployment compliance-engine -n threat-engine-engines

# Check pods
kubectl get pods -n threat-engine-engines -l app=compliance-engine

# Check logs
kubectl logs -n threat-engine-engines -l app=compliance-engine --tail=50

# Check service
kubectl get svc compliance-engine -n threat-engine-engines
kubectl get svc compliance-engine-lb -n threat-engine-engines
```

## Step 4: Get LoadBalancer Endpoint

```bash
# Get external endpoint
kubectl get svc compliance-engine-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'

# Or get full service details
kubectl get svc compliance-engine-lb -n threat-engine-engines
```

## Step 5: Test with Existing Scan Results

### Find Available Scan IDs

```bash
# List scan IDs in S3
aws s3 ls s3://cspm-lgtech/aws-compliance-engine/output/ | grep PRE

# Or from within the pod
kubectl exec -n threat-engine-engines -l app=compliance-engine -- \
  aws s3 ls s3://cspm-lgtech/aws-compliance-engine/output/
```

### Test API Endpoints

```bash
# Get LoadBalancer URL
LB_URL=$(kubectl get svc compliance-engine-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Health check
curl http://${LB_URL}/api/v1/health

# Generate compliance report
curl -X POST http://${LB_URL}/api/v1/compliance/generate \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "YOUR_SCAN_ID_HERE",
    "csp": "aws"
  }'

# Get framework status
curl "http://${LB_URL}/api/v1/compliance/framework/CIS%20AWS%20Foundations%20Benchmark/status?scan_id=YOUR_SCAN_ID&csp=aws"
```

## Port Forward (Alternative Access)

If LoadBalancer is not ready, use port-forward:

```bash
kubectl port-forward -n threat-engine-engines \
  deployment/compliance-engine 8000:8000

# Then test locally
curl http://localhost:8000/api/v1/health
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod events
kubectl describe pod -n threat-engine-engines -l app=compliance-engine

# Check logs
kubectl logs -n threat-engine-engines -l app=compliance-engine
```

### S3 Access Issues

```bash
# Test S3 access from pod
kubectl exec -n threat-engine-engines -l app=compliance-engine -- \
  aws s3 ls s3://cspm-lgtech/

# Check service account
kubectl get sa aws-compliance-engine-sa -n threat-engine-engines -o yaml
```

### Image Pull Errors

```bash
# Verify image exists
docker pull yadavanup84/threat-engine-compliance-engine:latest

# Check image pull secrets if using private registry
kubectl get secrets -n threat-engine-engines
```

## Update Deployment

After code changes:

```bash
# 1. Rebuild and push
./compliance-engine/build-and-push.sh

# 2. Restart deployment
kubectl rollout restart deployment/compliance-engine -n threat-engine-engines

# 3. Watch rollout
kubectl rollout status deployment/compliance-engine -n threat-engine-engines
```

## Resource Requirements

Current deployment:
- **Memory**: 512Mi request, 2Gi limit
- **CPU**: 200m request, 1000m limit
- **Replicas**: 1

Adjust in `kubernetes/engines/compliance-engine-deployment.yaml` if needed.

