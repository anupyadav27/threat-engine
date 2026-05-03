# /cspm-k8s-status

Check Kubernetes deployment status for all CSPM engines.

## Usage
```
/cspm-k8s-status
/cspm-k8s-status <engine-name>
```

## What it runs

```bash
# All engines
kubectl get deployments -n threat-engine-engines

# Specific engine
kubectl get deployment <engine-name> -n threat-engine-engines
kubectl rollout status deployment/<engine-name> -n threat-engine-engines
kubectl get pods -l app=<engine-name> -n threat-engine-engines
```

## Engine name reference

| Engine | K8s Name |
|--------|----------|
| Discoveries | engine-discoveries |
| Inventory | engine-inventory |
| Check | engine-check |
| Threat | engine-threat |
| Compliance | engine-compliance |
| IAM | engine-iam |
| DataSec | engine-datasec |
| Network | engine-network |
| CIEM | engine-ciem |
| Risk | engine-risk |
| SecOps | engine-secops |
| Vulnerability | engine-vulnerability |
| Onboarding | engine-onboarding |
| CNAPP | engine-cnapp |
| CWPP | engine-cwpp |
| Container Sec | engine-container-sec |
| Encryption | engine-encryption |
| DBSec | engine-dbsec |
| AI Security | engine-ai-security |
| Billing | engine-billing |
| Platform Admin | engine-platform-admin |
| Pipeline Monitor | engine-pipeline-monitor |

## Quick pod log access
```bash
kubectl logs -f -l app=<engine-name> -n threat-engine-engines --tail=100
```
