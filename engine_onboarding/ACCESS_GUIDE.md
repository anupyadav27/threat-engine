# Access Guide - Onboarding API & Scheduler

## Quick Access

### 1. Port Forwarding (Local Development)

**Onboarding API:**
```bash
kubectl port-forward svc/onboarding-api 8000:80 -n threat-engine-engines
```

Then access:
- **Health Check:** http://localhost:8000/api/v1/health
- **API Documentation:** http://localhost:8000/docs
- **OpenAPI Spec:** http://localhost:8000/openapi.json

**Scheduler:**
The scheduler doesn't have an HTTP endpoint. Check logs:
```bash
kubectl logs -f deployment/scheduler-service -n threat-engine-engines
```

### 2. Internal Cluster Access

From other pods/services in the cluster:

**Onboarding API:**
```
http://onboarding-api.threat-engine-engines.svc.cluster.local
```

**Service Details:**
- Service Name: `onboarding-api`
- Namespace: `threat-engine-engines`
- Port: `80`
- Type: `ClusterIP` (internal only)

### 3. Direct Pod Access

**Execute commands in pod:**
```bash
# Get pod name
kubectl get pods -n threat-engine-engines -l app=onboarding-api

# Execute shell
kubectl exec -it <pod-name> -n threat-engine-engines -- /bin/bash

# Test from inside pod
kubectl exec -it <pod-name> -n threat-engine-engines -- \
  curl http://localhost:8000/api/v1/health
```

### 4. View Logs

**Onboarding API:**
```bash
# Follow logs
kubectl logs -f deployment/onboarding-api -n threat-engine-engines

# Last 100 lines
kubectl logs --tail=100 deployment/onboarding-api -n threat-engine-engines

# Specific pod
kubectl logs <pod-name> -n threat-engine-engines
```

**Scheduler:**
```bash
# Follow logs
kubectl logs -f deployment/scheduler-service -n threat-engine-engines

# Last 100 lines
kubectl logs --tail=100 deployment/scheduler-service -n threat-engine-engines
```

## API Endpoints

### Health Check
```bash
curl http://localhost:8000/api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "dynamodb": "connected",
  "secrets_manager": "connected",
  "version": "1.0.0"
}
```

### Onboarding Endpoints

**List available auth methods:**
```bash
curl http://localhost:8000/api/v1/onboarding/aws/methods
```

**Initialize onboarding:**
```bash
curl -X POST http://localhost:8000/api/v1/onboarding/aws/init \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "test-tenant",
    "account_name": "Test Account"
  }'
```

**List accounts:**
```bash
curl http://localhost:8000/api/v1/onboarding/accounts?tenant_id=test-tenant
```

### Schedule Endpoints

**List schedules:**
```bash
curl http://localhost:8000/api/v1/schedules?tenant_id=test-tenant
```

**Create schedule:**
```bash
curl -X POST http://localhost:8000/api/v1/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "test-tenant",
    "account_id": "account-id",
    "name": "Daily Scan",
    "schedule_type": "cron",
    "cron_expression": "0 2 * * *"
  }'
```

## Service Information

**Get service details:**
```bash
kubectl get svc onboarding-api -n threat-engine-engines -o yaml
```

**Get endpoints:**
```bash
kubectl get endpoints onboarding-api -n threat-engine-engines
```

## Testing from Inside Cluster

If you have a test pod or another service in the cluster:

```bash
# Create a test pod
kubectl run curl-test --image=curlimages/curl -it --rm -- \
  curl http://onboarding-api.threat-engine-engines.svc.cluster.local/api/v1/health
```

## Setting Up Ingress (Optional)

To expose the API externally, create an Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: onboarding-api-ingress
  namespace: threat-engine-engines
spec:
  rules:
  - host: onboarding.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: onboarding-api
            port:
              number: 80
```

## Troubleshooting

**Check if service is running:**
```bash
kubectl get pods -n threat-engine-engines -l app=onboarding-api
```

**Check service endpoints:**
```bash
kubectl get endpoints onboarding-api -n threat-engine-engines
```

**Describe service:**
```bash
kubectl describe svc onboarding-api -n threat-engine-engines
```

**Test connectivity from pod:**
```bash
kubectl exec -it <pod-name> -n threat-engine-engines -- \
  curl -v http://onboarding-api.threat-engine-engines.svc.cluster.local/api/v1/health
```

---

**Quick Reference:**
- **Local Access:** `kubectl port-forward svc/onboarding-api 8000:80 -n threat-engine-engines`
- **Internal URL:** `http://onboarding-api.threat-engine-engines.svc.cluster.local`
- **Health:** `http://localhost:8000/api/v1/health`
- **Docs:** `http://localhost:8000/docs`

