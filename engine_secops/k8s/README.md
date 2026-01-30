# SecOps Scanner - EKS Deployment Guide

This directory contains Kubernetes manifests to deploy the SecOps Scanner to an EKS cluster in Mumbai (ap-south-1).

## Architecture

- **Main Service**: FastAPI scanner API (port 8000)
- **S3 Integration**: Sidecar container syncs `scan_input` and `scan_output` with S3
- **Internal Communication**: ClusterIP service for inter-pod communication
- **External Access**: LoadBalancer/Ingress for browser access

## Prerequisites

1. **EKS Cluster** in Mumbai (ap-south-1)
2. **kubectl** configured to access your cluster
3. **AWS Load Balancer Controller** (optional, for Ingress)
4. **IAM Role for Service Account (IRSA)** with S3 permissions
5. **ECR Repository** for Docker images
6. **S3 Bucket**: `s3://cspm-lgtech/secops/` with `input/` and `output/` folders

## Setup Steps

### 1. Create IAM Role for S3 Access (IRSA)

Create an IAM role with S3 permissions and trust policy for your EKS cluster:

```bash
# Replace YOUR_ACCOUNT_ID and YOUR_CLUSTER_NAME
export ACCOUNT_ID=YOUR_ACCOUNT_ID
export CLUSTER_NAME=YOUR_CLUSTER_NAME
export REGION=ap-south-1
export NAMESPACE=secops-engine
export SERVICE_ACCOUNT=secops-scanner-sa

# Create IAM role
aws iam create-role \
  --role-name secops-s3-access-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::'${ACCOUNT_ID}':oidc-provider/oidc.eks.'${REGION}'.amazonaws.com/id/YOUR_OIDC_ID"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.'${REGION}'.amazonaws.com/id/YOUR_OIDC_ID:sub": "system:serviceaccount:'${NAMESPACE}':'${SERVICE_ACCOUNT}'"
        }
      }
    }]
  }'

# Attach S3 policy
aws iam attach-role-policy \
  --role-name secops-s3-access-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

# Or create custom policy for specific bucket
aws iam put-role-policy \
  --role-name secops-s3-access-role \
  --policy-name SecOpsS3Policy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::cspm-lgtech",
        "arn:aws:s3:::cspm-lgtech/secops/*"
      ]
    }]
  }'
```

Get the role ARN and update `serviceaccount.yaml`:

```bash
ROLE_ARN=$(aws iam get-role --role-name secops-s3-access-role --query 'Role.Arn' --output text)
echo "Role ARN: $ROLE_ARN"
```

### 2. Update ServiceAccount

Edit `serviceaccount.yaml` and replace:
```yaml
eks.amazonaws.com/role-arn: arn:aws:iam::YOUR_ACCOUNT_ID:role/secops-s3-access-role
```

### 3. Build and Push Docker Image

```bash
cd ../scanner_engine

# Build image
docker build -t secops-scanner:latest .

# Tag for ECR
export AWS_ACCOUNT_ID=YOUR_ACCOUNT_ID
export AWS_REGION=ap-south-1
docker tag secops-scanner:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/secops-scanner:latest

# Login to ECR
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Push to ECR
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/secops-scanner:latest
```

### 4. Update Deployment Image

Edit `deployment.yaml` and replace:
```yaml
image: YOUR_ACCOUNT_ID.dkr.ecr.ap-south-1.amazonaws.com/secops-scanner:latest
```

### 5. Update ConfigMap (if needed)

Edit `configmap.yaml` to adjust:
- `S3_BUCKET`: Default is `cspm-lgtech`
- `S3_PREFIX`: Default is `secops`
- `SYNC_INTERVAL`: Default is 60 seconds

### 6. Deploy to EKS

```bash
cd k8s

# Deploy everything
./deploy.sh

# Or destroy old service first
./deploy.sh destroy-old
```

## Verification

### Check Pods
```bash
kubectl get pods -n secops-engine
```

### Check Services
```bash
kubectl get svc -n secops-engine
```

### Check Logs
```bash
# Scanner API logs
kubectl logs -f -n secops-engine deployment/secops-scanner -c scanner-api

# S3 sync logs
kubectl logs -f -n secops-engine deployment/secops-scanner -c s3-sync
```

### Test Health Endpoint
```bash
# Get ClusterIP service endpoint
kubectl get svc -n secops-engine secops-scanner

# Port forward for testing
kubectl port-forward -n secops-engine svc/secops-scanner 8000:8000

# Test in another terminal
curl http://localhost:8000/health
```

### Get External Endpoint
```bash
# LoadBalancer
kubectl get svc -n secops-engine secops-scanner-external

# Ingress (if ALB controller is installed)
kubectl get ingress -n secops-engine
```

## S3 Integration

The S3 sync sidecar container:
- **Downloads** from `s3://cspm-lgtech/secops/input/` → `/app/scan_input/`
- **Uploads** from `/app/scan_output/` → `s3://cspm-lgtech/secops/output/`
- Syncs every 60 seconds (configurable via ConfigMap)

### Manual S3 Operations

```bash
# Upload test files to S3 input
aws s3 cp test-project.zip s3://cspm-lgtech/secops/input/test-project/

# Check S3 output
aws s3 ls s3://cspm-lgtech/secops/output/
```

## Service Communication

### Internal (ClusterIP)
- Service name: `secops-scanner`
- Port: `8000`
- Other pods can access: `http://secops-scanner.secops-engine.svc.cluster.local:8000`

### External Access
- **LoadBalancer**: Use `secops-scanner-external` service
- **Ingress**: Configure domain in `ingress.yaml`

## Troubleshooting

### Pods not starting
```bash
kubectl describe pod -n secops-engine <pod-name>
kubectl logs -n secops-engine <pod-name> -c scanner-api
kubectl logs -n secops-engine <pod-name> -c s3-sync
```

### S3 sync issues
- Check IAM role permissions
- Verify ServiceAccount annotation
- Check S3 bucket exists and has correct structure
- Review s3-sync container logs

### Service not accessible
- Check LoadBalancer status: `kubectl get svc -n secops-engine`
- Verify security groups allow traffic
- Check Ingress controller is installed

## Scaling

```bash
# Scale deployment
kubectl scale deployment secops-scanner -n secops-engine --replicas=3

# Auto-scaling (requires metrics server)
kubectl autoscale deployment secops-scanner -n secops-engine --min=2 --max=10 --cpu-percent=70
```

## Cleanup

```bash
# Delete all resources
kubectl delete namespace secops-engine

# Or delete individual resources
kubectl delete -f .
```

## Configuration Reference

### Environment Variables (ConfigMap)
- `SCAN_INPUT_PATH`: Local input directory (default: `/app/scan_input`)
- `SCAN_OUTPUT_PATH`: Local output directory (default: `/app/scan_output`)
- `S3_BUCKET`: S3 bucket name (default: `cspm-lgtech`)
- `S3_PREFIX`: S3 prefix/folder (default: `secops`)
- `S3_REGION`: AWS region (default: `ap-south-1`)
- `SYNC_INTERVAL`: Sync interval in seconds (default: `60`)

### Resource Limits
- Scanner API: 512Mi-2Gi memory, 250m-1000m CPU
- S3 Sync: 128Mi-256Mi memory, 100m-200m CPU

