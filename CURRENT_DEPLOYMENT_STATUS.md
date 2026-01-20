# Current Deployment Status

**Generated**: $(date)

## Summary

- **Total Pods**: 4
- **Total Containers**: 7
- **Total Deployments**: 4
- **LoadBalancers**: 1 (onboarding-api-lb) - Cost optimized
- **Control Plane Logging**: Disabled - Cost optimized

## Deployment Details

### 1. AWS Compliance Engine
- **Pods**: 1
- **Replicas**: 1
- **Containers per Pod**: 3
  - `aws-engine` (main)
  - `s3-sync` (sidecar)
  - `user-rules-sync` (sidecar)
- **Status**: Running
- **Age**: 10 days

### 2. Compliance Engine
- **Pods**: 1
- **Replicas**: 1
- **Containers per Pod**: 1
  - `compliance-engine` (main)
- **Status**: Running
- **Age**: 111 minutes

### 3. YAML Rule Builder
- **Pods**: 1
- **Replicas**: 1
- **Containers per Pod**: 2
  - `yaml-builder` (main)
  - `s3-sync` (sidecar)
- **Status**: Running
- **Age**: 3 days

### 4. Onboarding API
- **Pods**: 1
- **Replicas**: 1
- **Containers per Pod**: 1
  - `onboarding` (main)
- **Status**: Running
- **Age**: Updated

## Container Count by Service

| Service | Pods | Containers/Pod | Total Containers |
|---------|------|---------------|-------------------|
| AWS Compliance Engine | 1 | 3 | 3 |
| Compliance Engine | 1 | 1 | 1 |
| YAML Rule Builder | 1 | 2 | 2 |
| Onboarding API | 1 | 1 | 1 |
| **TOTAL** | **4** | - | **7** |

## Resource Optimization Opportunity

### Current State
- **3 separate engine pods** (AWS, Compliance, YAML)
- **8 total containers** across all pods
- **Multiple sidecar containers** for S3 sync

### With Unified Engine
- **1 unified engine pod** (all 3 engines)
- **~4 total containers** (unified + sidecars)
- **Resource savings**: ~20% reduction

## Services

### ClusterIP Services
- `aws-compliance-engine` → AWS Engine (port 80)
- `compliance-engine` → Compliance Engine (port 80)
- `yaml-rule-builder` → YAML Builder (port 80)
- `onboarding-api` → Onboarding API (port 80)

### LoadBalancer Services
- `aws-compliance-engine-lb` → AWS Engine (external)
- `compliance-engine-lb` → Compliance Engine (external)
- `yaml-rule-builder-lb` → YAML Builder (external)
- `onboarding-api-lb` → Onboarding API (external)

## Next Steps

To consolidate and save resources:

1. **Deploy unified engine**:
   ```bash
   kubectl apply -f kubernetes/engines/unified-engine-deployment-dev.yaml
   ```

2. **Verify unified engine is running**:
   ```bash
   kubectl get pods -n threat-engine-engines -l app=unified-engine
   ```

3. **Scale down individual engines** (optional):
   ```bash
   kubectl scale deployment aws-compliance-engine --replicas=0 -n threat-engine-engines
   kubectl scale deployment compliance-engine --replicas=0 -n threat-engine-engines
   kubectl scale deployment yaml-rule-builder --replicas=0 -n threat-engine-engines
   ```

## Commands to Check Status

```bash
# All pods
kubectl get pods -n threat-engine-engines

# All deployments
kubectl get deployments -n threat-engine-engines

# Container count per pod
kubectl get pods -n threat-engine-engines -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].name}{"\n"}{end}'

# Resource usage
kubectl top pods -n threat-engine-engines
```

