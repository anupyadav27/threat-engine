# EKS Cost Optimization Guide

## Current Cost Drivers

### 1. LoadBalancer Services (NLB)
Each LoadBalancer service creates an AWS Network Load Balancer (~$0.0225/hour = ~$16/month each)

**Current LoadBalancers**:
- `compliance-engine-lb`
- `onboarding-api-lb`
- `yaml-rule-builder-lb`
- `aws-compliance-engine-lb` (if exists)

**Cost**: ~$64/month for 4 LoadBalancers

### 2. Control Plane Logging (if enabled)
CloudWatch Logs for EKS control plane (~$0.50/GB ingested)

### 3. EKS Extended Support (if on old version)
Paid support for Kubernetes versions beyond standard support lifecycle

### 4. EKS Add-ons (if any paid add-ons)
Some add-ons have additional costs

## Cost Reduction Steps

### Step 1: Remove Unnecessary LoadBalancers

**Option A: Use ClusterIP + Port Forward (Dev)**
```bash
# Scale down LoadBalancer services
kubectl scale deployment compliance-engine --replicas=0 -n threat-engine-engines
kubectl delete svc compliance-engine-lb -n threat-engine-engines
kubectl delete svc onboarding-api-lb -n threat-engine-engines
kubectl delete svc yaml-rule-builder-lb -n threat-engine-engines

# Use port-forward for access
kubectl port-forward -n threat-engine-engines svc/compliance-engine 8000:80
```

**Option B: Keep Only One LoadBalancer (Unified)**
```bash
# Deploy unified engine with single LoadBalancer
kubectl apply -f kubernetes/engines/unified-engine-deployment-dev.yaml

# Remove individual LoadBalancers
kubectl delete svc compliance-engine-lb -n threat-engine-engines
kubectl delete svc yaml-rule-builder-lb -n threat-engine-engines
```

**Savings**: ~$48/month (3 LoadBalancers removed)

### Step 2: Disable Control Plane Logging (if enabled)

```bash
# Check current logging
aws eks describe-cluster --name vulnerability-eks-cluster --region ap-south-1 \
  --query 'cluster.logging'

# Disable logging
aws eks update-cluster-config \
  --name vulnerability-eks-cluster \
  --region ap-south-1 \
  --logging '{"enable":[]}'
```

**Savings**: ~$5-20/month (depending on log volume)

### Step 3: Check and Remove Extended Support (if applicable)

```bash
# Check cluster version
aws eks describe-cluster --name vulnerability-eks-cluster --region ap-south-1 \
  --query 'cluster.version'

# If version is old (requiring extended support), upgrade to supported version
# Extended support is automatically removed when you upgrade to a supported version
```

**Note**: Extended support is only needed for Kubernetes versions beyond standard support. If you're on 1.28+, you don't need extended support.

### Step 4: Review and Remove Unnecessary Add-ons

```bash
# List add-ons
aws eks list-addons --cluster-name vulnerability-eks-cluster --region ap-south-1

# Remove unnecessary add-ons (if any)
# aws eks delete-addon --cluster-name vulnerability-eks-cluster --addon-name <addon-name> --region ap-south-1
```

### Step 5: Optimize Node Resources

```bash
# Check current node configuration
kubectl get nodes -o wide
kubectl top nodes

# Consider:
# - Using smaller instance types if resources are underutilized
# - Enabling cluster autoscaling to scale down during low usage
```

## Recommended Dev Environment Setup

### Minimal Cost Configuration

1. **Single LoadBalancer** (unified engine) or **No LoadBalancer** (port-forward only)
2. **Control Plane Logging**: Disabled
3. **Extended Support**: Not needed (use supported K8s version)
4. **Add-ons**: Only essential (vpc-cni, kube-proxy, core-dns)
5. **Node Group**: Single t3.medium (or smaller if possible)

### Estimated Monthly Cost

**Before Optimization**:
- EKS Control Plane: $73/month
- LoadBalancers (4×): ~$64/month
- Node (t3.medium): ~$30/month
- Control Plane Logging: ~$10/month
- **Total**: ~$177/month

**After Optimization**:
- EKS Control Plane: $73/month
- LoadBalancer (1× or 0×): ~$16/month or $0
- Node (t3.medium): ~$30/month
- Control Plane Logging: $0
- **Total**: ~$119/month (with 1 LB) or ~$103/month (no LB)

**Savings**: ~$58-74/month (33-42% reduction)

## Quick Cost Reduction Script

```bash
#!/bin/bash
# Quick cost reduction for dev environment

echo "=== Removing LoadBalancers ==="
kubectl delete svc compliance-engine-lb -n threat-engine-engines --ignore-not-found
kubectl delete svc yaml-rule-builder-lb -n threat-engine-engines --ignore-not-found
# Keep onboarding-api-lb if needed, or remove it too

echo "=== Disabling Control Plane Logging ==="
aws eks update-cluster-config \
  --name vulnerability-eks-cluster \
  --region ap-south-1 \
  --logging '{"enable":[]}' \
  --no-cli-pager

echo "=== Cost optimization complete! ==="
echo "Savings: ~$48-58/month"
```

## Access After Removing LoadBalancers

### Option 1: Port Forward (Recommended for Dev)
```bash
# Compliance Engine
kubectl port-forward -n threat-engine-engines svc/compliance-engine 8000:80

# YAML Builder
kubectl port-forward -n threat-engine-engines svc/yaml-rule-builder 8001:80

# Onboarding API
kubectl port-forward -n threat-engine-engines svc/onboarding-api 8002:80
```

### Option 2: Use Unified Engine with Single LoadBalancer
Deploy unified engine which exposes all services through one LoadBalancer.

### Option 3: Ingress Controller (if needed)
Deploy an Ingress controller (NGINX/Traefik) with a single LoadBalancer to route to all services.

## Monitoring Costs

```bash
# Check AWS Cost Explorer
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=SERVICE \
  --filter file://eks-filter.json
```

## Notes

- **Dev Environment**: Remove LoadBalancers, use port-forward
- **Staging/Prod**: Keep LoadBalancers but consolidate to unified engine
- **Extended Support**: Only needed for K8s versions beyond standard support (typically 3+ years old)
- **Control Plane Logging**: Useful for debugging but adds cost; disable in dev

