# Quick Start Guide - EKS Deployment

## Prerequisites Checklist

- [ ] EKS cluster in Mumbai (ap-south-1)
- [ ] kubectl configured: `kubectl cluster-info`
- [ ] AWS CLI configured: `aws sts get-caller-identity`
- [ ] S3 bucket exists: `s3://cspm-lgtech/secops/` with `input/` and `output/` folders
- [ ] ECR repository created (or Docker registry access)

## Quick Deployment (5 Steps)

### Step 1: Setup IAM Role
```bash
cd k8s
./setup-iam.sh
# Follow prompts and update serviceaccount.yaml with the role ARN
```

### Step 2: Build & Push Docker Image
```bash
cd ../scanner_engine
docker build -t secops-scanner:latest .

# Tag and push to ECR
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_REGION=ap-south-1
docker tag secops-scanner:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/secops-scanner:latest

aws ecr get-login-password --region ${AWS_REGION} | \
  docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/secops-scanner:latest
```

### Step 3: Update Deployment Image
Edit `k8s/deployment.yaml`:
```yaml
image: YOUR_ACCOUNT_ID.dkr.ecr.ap-south-1.amazonaws.com/secops-scanner:latest
```

### Step 4: Deploy
```bash
cd k8s

# Deploy (destroys old 'secops' service if exists)
./deploy.sh destroy-old

# Or just deploy
./deploy.sh
```

### Step 5: Verify
```bash
# Check pods
kubectl get pods -n secops-engine

# Check services
kubectl get svc -n secops-engine

# Get external endpoint
kubectl get svc -n secops-engine secops-scanner-external

# Test health
kubectl port-forward -n secops-engine svc/secops-scanner 8000:8000
curl http://localhost:8000/health
```

## Service Endpoints

### Internal (ClusterIP)
- **Service**: `secops-scanner.secops-engine.svc.cluster.local:8000`
- **Use**: Other pods in the cluster

### External (LoadBalancer)
- **Service**: `secops-scanner-external`
- **Get URL**: `kubectl get svc -n secops-engine secops-scanner-external`
- **Use**: Browser access, external services

### Ingress (if ALB controller installed)
- **Get URL**: `kubectl get ingress -n secops-engine`
- **Configure domain**: Edit `ingress.yaml`

## Common Commands

```bash
# View logs
kubectl logs -f -n secops-engine deployment/secops-scanner -c scanner-api
kubectl logs -f -n secops-engine deployment/secops-scanner -c s3-sync

# Scale
kubectl scale deployment secops-scanner -n secops-engine --replicas=3

# Restart
kubectl rollout restart deployment secops-scanner -n secops-engine

# Delete
kubectl delete namespace secops-engine
```

## S3 Structure

```
s3://cspm-lgtech/secops/
├── input/          # Projects to scan (uploaded by Jenkins/external)
│   └── project-name/
│       └── ...files...
└── output/         # Scan results (synced from pods)
    └── project-name/
        ├── scan_results_YYYYMMDD_HHMMSS.json
        └── scan_results_latest.json
```

## Troubleshooting

**Pods not starting?**
```bash
kubectl describe pod -n secops-engine <pod-name>
kubectl logs -n secops-engine <pod-name> -c scanner-api
```

**S3 sync not working?**
```bash
# Check IAM role
kubectl describe sa -n secops-engine secops-scanner-sa

# Check S3 sync logs
kubectl logs -n secops-engine deployment/secops-scanner -c s3-sync

# Verify S3 bucket
aws s3 ls s3://cspm-lgtech/secops/
```

**Service not accessible?**
```bash
# Check LoadBalancer status
kubectl get svc -n secops-engine secops-scanner-external

# Check security groups (allow port 80/8000)
# Check Ingress (if using)
kubectl describe ingress -n secops-engine
```

