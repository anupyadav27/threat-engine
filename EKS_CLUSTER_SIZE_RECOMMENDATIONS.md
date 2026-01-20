# EKS Cluster Size Recommendations

## Current Resource Requirements

### Threat Engines (7 services)

| Service | Replicas | CPU Request | CPU Limit | Memory Request | Memory Limit |
|---------|----------|-------------|-----------|----------------|--------------|
| AWS Compliance Engine | 1 | 250m | 1000m | 512Mi | 2Gi |
| Azure Compliance Engine | 2 | 250m | 1000m | 512Mi | 2Gi |
| GCP Compliance Engine | 2 | 250m | 1000m | 512Mi | 2Gi |
| AliCloud Compliance Engine | 2 | 250m | 1000m | 512Mi | 2Gi |
| OCI Compliance Engine | 2 | 250m | 1000m | 512Mi | 2Gi |
| IBM Compliance Engine | 2 | 250m | 1000m | 512Mi | 2Gi |
| YAML Rule Builder | 1 | 100m | 500m | 256Mi | 512Mi |

**Total Engines (Current Deployment):**
- CPU Requests: 350m (0.35 cores)
- CPU Limits: 1,500m (1.5 cores)
- Memory Requests: 768Mi (~0.75Gi)
- Memory Limits: 2,560Mi (~2.5Gi)

**Note:** Current deployment only has AWS Engine (1 replica) and YAML Rule Builder (1 replica) active. Other engines are not currently deployed.

### Onboarding & Scheduler

| Service | Replicas | CPU Request | CPU Limit | Memory Request | Memory Limit |
|---------|----------|-------------|-----------|----------------|--------------|
| Onboarding API | 2 | 200m | 500m | 256Mi | 512Mi |
| Scheduler Service | 1 | 100m | 500m | 128Mi | 256Mi |

**Total Onboarding:**
- CPU Requests: 500m (0.5 cores)
- CPU Limits: 1,500m (1.5 cores)
- Memory Requests: 640Mi (~0.625Gi)
- Memory Limits: 1,280Mi (~1.25Gi)

### Grand Total

**All Services Combined (Current Deployment):**
- **CPU Requests**: 750m (0.75 cores) - AWS Engine (1) + YAML Builder (1) + Onboarding API (2)
- **CPU Limits**: 2,500m (2.5 cores)
- **Memory Requests**: 1,280Mi (~1.25Gi)
- **Memory Limits**: 3,584Mi (~3.5Gi)

**With 20% System Overhead:**
- **CPU**: ~0.9 cores
- **Memory**: ~1.5Gi

**Note:** For full production deployment with all 7 engines, see recommended configurations below.

## Recommended Node Configurations

### Option 1: Small/Development (Minimum)

**Node Type**: `m5.xlarge`
- **vCPU**: 4 cores
- **Memory**: 16Gi RAM
- **Nodes**: 2 nodes
- **Total**: 8 vCPU, 32Gi RAM
- **Cost**: ~$0.192/hour (~$140/month)

**Pros:**
- Cost-effective for development
- Sufficient for light workloads

**Cons:**
- Limited headroom for scaling
- May experience resource constraints during peak loads

### Option 2: Medium/Production (Recommended)

**Node Type**: `m5.2xlarge`
- **vCPU**: 8 cores
- **Memory**: 32Gi RAM
- **Nodes**: 2-3 nodes
- **Total**: 16-24 vCPU, 64-96Gi RAM
- **Cost**: ~$0.384/hour/node (~$280/month/node)

**Pros:**
- Good balance of cost and performance
- Adequate headroom for scaling
- Can handle peak loads comfortably
- Supports high availability (multiple nodes)

**Cons:**
- Higher cost than minimum

### Option 3: Large/High-Performance

**Node Type**: `m5.4xlarge`
- **vCPU**: 16 cores
- **Memory**: 64Gi RAM
- **Nodes**: 2 nodes
- **Total**: 32 vCPU, 128Gi RAM
- **Cost**: ~$0.768/hour/node (~$560/month/node)

**Pros:**
- Excellent performance
- Large headroom for scaling
- Can handle heavy concurrent scans

**Cons:**
- Higher cost
- May be overkill for current needs

## Scaling Recommendations

### Horizontal Scaling (More Nodes)

**For High Availability:**
- Minimum 2 nodes per availability zone
- 3 nodes total (multi-AZ)

**For Performance:**
- Add nodes as workload increases
- Use Cluster Autoscaler for automatic scaling

### Vertical Scaling (Larger Nodes)

**If pods are pending:**
- Upgrade to `m5.2xlarge` or `m5.4xlarge`
- Better for CPU/memory-intensive scans

### Pod Replica Adjustments

**To reduce resource requirements:**

```yaml
# Reduce replicas for non-critical engines
aws-compliance-engine: 3 → 2 replicas
azure-compliance-engine: 2 → 1 replica
gcp-compliance-engine: 2 → 1 replica
# ... etc
```

**To increase availability:**

```yaml
# Keep critical services at 2+ replicas
aws-compliance-engine: 3 replicas (keep)
onboarding-api: 2 replicas (keep)
yaml-rule-builder: 2 replicas (keep)
```

## Cost Optimization

### Spot Instances

Use Spot Instances for non-critical workloads:
- **Savings**: 50-90% cost reduction
- **Risk**: Can be interrupted
- **Best for**: Engines (can restart), not for onboarding API

### Reserved Instances

For predictable workloads:
- **Savings**: 30-50% cost reduction
- **Commitment**: 1-3 years
- **Best for**: Production workloads

### Right-Sizing

Monitor actual usage:
```bash
kubectl top nodes
kubectl top pods -n threat-engine-engines
```

Adjust resource requests/limits based on actual usage.

## Quick Start Recommendations

### Development/Testing
- **2x m5.xlarge** nodes
- **Total**: 8 vCPU, 32Gi RAM
- **Cost**: ~$280/month

### Production
- **3x m5.2xlarge** nodes (multi-AZ)
- **Total**: 24 vCPU, 96Gi RAM
- **Cost**: ~$840/month

### High-Performance
- **2x m5.4xlarge** nodes
- **Total**: 32 vCPU, 128Gi RAM
- **Cost**: ~$1,120/month

## Current Cluster Status

If pods are pending with "Insufficient cpu/memory":
1. **Quick fix**: Scale down non-critical replicas
2. **Short-term**: Upgrade node instance type
3. **Long-term**: Add more nodes or use Cluster Autoscaler

## Monitoring

Check resource usage:
```bash
# Node resources
kubectl top nodes

# Pod resources
kubectl top pods -n threat-engine-engines --all-namespaces

# Resource requests vs usage
kubectl describe nodes
```

---

**Last Updated**: 2026-01-03

