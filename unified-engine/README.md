# Unified Engine - Dev Environment

## Overview

A single container that runs all engines together to save resources in dev environment:
- **AWS Compliance Engine** (port 8000)
- **Compliance Engine** (port 8001)
- **YAML Rule Builder** (port 8002)

## Resource Savings

**Before (Separate Containers)**:
- AWS Engine: 256Mi memory, 100m CPU
- Compliance Engine: 256Mi memory, 100m CPU
- YAML Builder: 128Mi memory, 50m CPU
- **Total**: ~640Mi memory, 250m CPU

**After (Unified Container)**:
- Unified Engine: 512Mi memory, 200m CPU
- **Savings**: ~128Mi memory, 50m CPU (20% reduction)

## Build and Deploy

```bash
# Build and push
cd /Users/apple/Desktop/threat-engine
./unified-engine/build-and-push.sh

# Deploy to EKS
kubectl apply -f kubernetes/engines/unified-engine-deployment-dev.yaml
```

## Services

The unified engine exposes 3 services:

1. **unified-engine-aws** (ClusterIP)
   - Routes to port 8000 (AWS Compliance Engine)
   - Use: `http://unified-engine-aws.threat-engine-engines.svc.cluster.local`

2. **unified-engine-compliance** (ClusterIP)
   - Routes to port 8001 (Compliance Engine)
   - Use: `http://unified-engine-compliance.threat-engine-engines.svc.cluster.local`

3. **unified-engine-yaml** (ClusterIP)
   - Routes to port 8002 (YAML Rule Builder)
   - Use: `http://unified-engine-yaml.threat-engine-engines.svc.cluster.local`

4. **unified-engine-lb** (LoadBalancer)
   - Exposes all 3 ports externally:
     - Port 8000: AWS Engine
     - Port 8001: Compliance Engine
     - Port 8002: YAML Builder

## Access

### Via LoadBalancer

```bash
LB_URL=$(kubectl get svc unified-engine-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# AWS Engine
curl http://${LB_URL}:8000/api/v1/health

# Compliance Engine
curl http://${LB_URL}:8001/api/v1/health

# YAML Builder
curl http://${LB_URL}:8002/api/v1/health
```

### Via ClusterIP Services

```bash
# From within cluster
curl http://unified-engine-aws.threat-engine-engines.svc.cluster.local/api/v1/health
curl http://unified-engine-compliance.threat-engine-engines.svc.cluster.local/api/v1/health
curl http://unified-engine-yaml.threat-engine-engines.svc.cluster.local/api/v1/health
```

## Process Management

The unified engine uses **supervisord** to manage all 3 processes:
- Automatic restart on failure
- Centralized logging
- Process monitoring

Logs are available at:
- `/var/log/supervisor/aws-engine.out.log`
- `/var/log/supervisor/compliance-engine.out.log`
- `/var/log/supervisor/yaml-builder.out.log`

## Verification

```bash
# Check pod status
kubectl get pods -n threat-engine-engines -l app=unified-engine

# Check all services are running
kubectl exec -n threat-engine-engines -l app=unified-engine -- \
  supervisorctl status

# Check logs
kubectl logs -n threat-engine-engines -l app=unified-engine
```

## Migration from Separate Containers

To switch from separate containers to unified:

1. **Deploy unified engine**:
   ```bash
   kubectl apply -f kubernetes/engines/unified-engine-deployment-dev.yaml
   ```

2. **Update service references**:
   - Change `aws-compliance-engine` → `unified-engine-aws`
   - Change `compliance-engine` → `unified-engine-compliance`
   - Change `yaml-rule-builder` → `unified-engine-yaml`

3. **Scale down old deployments** (optional):
   ```bash
   kubectl scale deployment aws-compliance-engine --replicas=0 -n threat-engine-engines
   kubectl scale deployment compliance-engine --replicas=0 -n threat-engine-engines
   kubectl scale deployment yaml-rule-builder --replicas=0 -n threat-engine-engines
   ```

## Notes

- **Dev Only**: This is optimized for dev environments with limited resources
- **Production**: Use separate containers for better isolation and scaling
- **Resource Limits**: Can be adjusted in `unified-engine-deployment-dev.yaml`

