# Browser Access Guide

## Quick Access

**Onboarding Engine:**
- Health: http://localhost:30010/api/v1/health
- API Base: http://localhost:30010

**ConfigScan AWS Engine:**
- Health: http://localhost:30002/api/v1/health
- API Base: http://localhost:30002

## Port Forwarding Setup

Docker Desktop Kubernetes NodePort services may not be accessible directly. Use port forwarding:

### Option 1: Manual Port Forward (Current)

```bash
# Onboarding
kubectl port-forward -n threat-engine-local svc/onboarding-external 30010:8010

# ConfigScan AWS
kubectl port-forward -n threat-engine-local svc/configscan-aws-external 30002:8002
```

### Option 2: Use Access Script

```bash
./deployment/local-k8s/access-services.sh
```

This script sets up port forwarding for all services automatically.

## Verify Access

**Test in browser:**
1. Open: http://localhost:30010/api/v1/health
2. Should see JSON response with status: "healthy"

**Test with curl:**
```bash
curl http://localhost:30010/api/v1/health | python3 -m json.tool
```

## Troubleshooting

**If port forwarding stops:**
```bash
# Check if running
ps aux | grep "kubectl port-forward"

# Restart
pkill -f "kubectl port-forward"
kubectl port-forward -n threat-engine-local svc/onboarding-external 30010:8010 &
```

**If service not responding:**
```bash
# Check pod status
kubectl get pods -n threat-engine-local

# Check logs
kubectl logs -n threat-engine-local -l app=onboarding-service --tail=20
```
