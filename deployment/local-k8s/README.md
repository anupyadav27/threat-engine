# Local Kubernetes Deployment Guide

This guide explains how to deploy Threat Engine services to local Kubernetes (Docker Desktop).

## Prerequisites

1. **Docker Desktop** with Kubernetes enabled
2. **kubectl** installed and configured
3. **PostgreSQL** running locally (or accessible via `host.docker.internal`)
4. **Database initialized** (single-DB with engine_* schemas):
   ```bash
   psql -U postgres -d postgres -f scripts/init-databases.sql
   # or: ./deployment/local-k8s/setup-database.sh
   ```

## Quick Start

### 1. Deploy All Services

```bash
cd deployment/local-k8s
./deploy-engines.sh
```

This will:
- Build Docker images
- Deploy to Kubernetes
- Wait for services to be ready
- Check health endpoints
- Show status and access URLs

### 2. Check Status

```bash
./deploy-engines.sh status
```

### 3. Check Health

```bash
./deploy-engines.sh health
```

### 4. View Logs

```bash
# Onboarding logs
kubectl logs -f -l app=onboarding-service -n threat-engine-local

# ConfigScan AWS logs
kubectl logs -f -l app=configscan-aws-service -n threat-engine-local
```

## Manual Deployment Steps

### Step 1: Build Images

```bash
# Build onboarding image
docker build -t threat-engine/onboarding-service:local \
    -f ../../engine_onboarding/Dockerfile \
    ../../

# Build configscan AWS image
docker build -t threat-engine/configscan-aws-service:local \
    -f ../../engine_configscan/engine_configscan_aws/Dockerfile \
    ../../
```

### Step 2: Deploy to Kubernetes

```bash
# Deploy onboarding
kubectl apply -f onboarding-deployment.yaml

# Deploy configscan AWS
kubectl apply -f configscan-aws-deployment.yaml
```

### Step 3: Verify Deployment

```bash
# Check deployments
kubectl get deployments -n threat-engine-local

# Check pods
kubectl get pods -n threat-engine-local

# Check services
kubectl get services -n threat-engine-local
```

## Accessing Services

### ClusterIP (Internal)

- **Onboarding**: `http://onboarding-service.threat-engine-local.svc.cluster.local:8010`
- **ConfigScan AWS**: `http://configscan-aws-service.threat-engine-local.svc.cluster.local:8002`

### NodePort (External)

- **Onboarding**: `http://localhost:30010`
- **ConfigScan AWS**: `http://localhost:30002`

### Health Endpoints

- **Onboarding Health**: `http://localhost:30010/api/v1/health`
- **ConfigScan AWS Health**: `http://localhost:30002/api/v1/health`

## Configuration

### Database Connection

The deployments use `host.docker.internal` to connect to PostgreSQL running on the host machine. Update the ConfigMaps if your PostgreSQL is running elsewhere:

```yaml
# In onboarding-deployment.yaml or configscan-aws-deployment.yaml
DATABASE_URL: "postgresql://user:password@host.docker.internal:5432/database"
```

### Environment Variables

All configuration is in ConfigMaps. To update:

1. Edit the ConfigMap:
   ```bash
   kubectl edit configmap onboarding-config -n threat-engine-local
   ```

2. Restart the deployment:
   ```bash
   kubectl rollout restart deployment onboarding-service -n threat-engine-local
   ```

## Health Checks

### Liveness Probe

Checks if the service is alive:
- **Onboarding**: `/api/v1/health/live`
- **ConfigScan AWS**: `/api/v1/health/live`

### Readiness Probe

Checks if the service is ready to accept traffic (includes database check):
- **Onboarding**: `/api/v1/health/ready`
- **ConfigScan AWS**: `/api/v1/health/ready`

### Full Health Check

Comprehensive health check with database connectivity:
- **Onboarding**: `/api/v1/health`
- **ConfigScan AWS**: `/api/v1/health`

## Troubleshooting

### Pods Not Starting

1. Check pod status:
   ```bash
   kubectl get pods -n threat-engine-local
   kubectl describe pod <pod-name> -n threat-engine-local
   ```

2. Check logs:
   ```bash
   kubectl logs <pod-name> -n threat-engine-local
   ```

### Database Connection Issues

1. Verify PostgreSQL is accessible:
   ```bash
   # From host
   psql -h localhost -U shared_user -d threat_engine_shared
   ```

2. Check database URL in ConfigMap:
   ```bash
   kubectl get configmap onboarding-config -n threat-engine-local -o yaml
   ```

3. Test connection from pod:
   ```bash
   kubectl exec -it <pod-name> -n threat-engine-local -- \
     python3 -c "import psycopg2; conn = psycopg2.connect('postgresql://shared_user:shared_password@host.docker.internal:5432/threat_engine_shared'); print('Connected!')"
   ```

### Health Check Failures

1. Check if database is accessible:
   ```bash
   kubectl exec -it <pod-name> -n threat-engine-local -- curl http://localhost:8010/api/v1/health
   ```

2. Verify database credentials in Secret:
   ```bash
   kubectl get secret onboarding-db-secret -n threat-engine-local -o yaml
   ```

### Image Pull Errors

If using local images, ensure:
1. Images are built: `docker images | grep threat-engine`
2. ImagePullPolicy is set to `IfNotPresent` in deployment

## Cleanup

### Remove All Deployments

```bash
./deploy-engines.sh cleanup
```

Or manually:

```bash
kubectl delete -f onboarding-deployment.yaml
kubectl delete -f configscan-aws-deployment.yaml
```

### Remove Namespace

```bash
kubectl delete namespace threat-engine-local
```

## Next Steps

1. **Test API Endpoints**: Use curl or Postman to test the deployed services
2. **Monitor Logs**: Watch logs for any issues
3. **Scale Services**: Adjust replica counts in deployment files
4. **Add More Engines**: Follow the same pattern for other engines

## Production Considerations

For production deployments:

1. **Use Persistent Volumes**: Replace `emptyDir` with PVCs for scan results
2. **Resource Limits**: Adjust based on workload
3. **Secrets Management**: Use proper secret management (e.g., Sealed Secrets, External Secrets)
4. **Monitoring**: Add Prometheus metrics and Grafana dashboards
5. **Ingress**: Use Ingress controller instead of NodePort
6. **High Availability**: Increase replicas and use PodDisruptionBudgets
