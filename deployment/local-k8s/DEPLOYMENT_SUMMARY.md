# Local Kubernetes Deployment Summary

## ✅ What's Been Created

### 1. **Updated Health Check Endpoints**
- **Onboarding Engine** (`engine_onboarding/api/health.py`):
  - `/api/v1/health` - Full health check with database connectivity
  - `/api/v1/health/ready` - Kubernetes readiness probe
  - `/api/v1/health/live` - Kubernetes liveness probe

- **ConfigScan AWS Engine** (`engine_configscan/engine_configscan_aws/api_server.py`):
  - `/api/v1/health` - Full health check with database connectivity
  - `/api/v1/health/ready` - Kubernetes readiness probe
  - `/api/v1/health/live` - Kubernetes liveness probe

### 2. **Kubernetes Deployment Files**

#### Onboarding Engine
- **File**: `onboarding-deployment.yaml`
- **Components**:
  - Namespace: `threat-engine-local`
  - ConfigMap: `onboarding-config`
  - Secret: `onboarding-db-secret`
  - Deployment: `onboarding-service` (1 replica)
  - Service (ClusterIP): `onboarding-service:8010`
  - Service (NodePort): `onboarding-external:30010`

#### ConfigScan AWS Engine
- **File**: `configscan-aws-deployment.yaml`
- **Components**:
  - ConfigMap: `configscan-aws-config`
  - Secret: `configscan-aws-db-secret`
  - Secret: `configscan-aws-credentials` (optional)
  - Deployment: `configscan-aws-service` (1 replica)
  - Service (ClusterIP): `configscan-aws-service:8002`
  - Service (NodePort): `configscan-aws-external:30002`

### 3. **Deployment Scripts**

#### Main Deployment Script
- **File**: `deploy-engines.sh`
- **Commands**:
  - `./deploy-engines.sh` - Full deployment (build + deploy)
  - `./deploy-engines.sh build` - Build Docker images only
  - `./deploy-engines.sh deploy` - Deploy to Kubernetes
  - `./deploy-engines.sh status` - Show deployment status
  - `./deploy-engines.sh health` - Check service health
  - `./deploy-engines.sh cleanup` - Remove all deployments

#### Test Script
- **File**: `test-services.sh`
- **Tests**:
  - Health endpoints
  - Readiness probes
  - Liveness probes
  - Database connectivity from pods

### 4. **Documentation**
- `README.md` - Comprehensive deployment guide
- `DEPLOYMENT_SUMMARY.md` - This file

## 🚀 Quick Start

### Prerequisites Check

1. **PostgreSQL Running Locally**
   ```bash
   # Verify PostgreSQL is running
   psql postgres -c "SELECT version();"
   ```

2. **Database initialized** (single-DB)
   ```bash
   cd /Users/apple/Desktop/threat-engine
   psql -U postgres -d postgres -f scripts/init-databases.sql
   # or: ./deployment/local-k8s/setup-database.sh
   ```

3. **Docker Desktop Kubernetes Enabled**
   ```bash
   # Verify Kubernetes is running
   kubectl cluster-info
   ```

### Deploy Everything

```bash
cd /Users/apple/Desktop/threat-engine/deployment/local-k8s
./deploy-engines.sh
```

This will:
1. ✅ Check prerequisites
2. ✅ Build Docker images
3. ✅ Deploy to Kubernetes
4. ✅ Wait for services to be ready
5. ✅ Check health endpoints
6. ✅ Show status and access URLs

### Test Services

```bash
# Test all endpoints
./test-services.sh

# Or test manually
curl http://localhost:30010/api/v1/health
curl http://localhost:30002/api/v1/health
```

## 📊 Service Access

### Onboarding Engine
- **Internal**: `http://onboarding-service.threat-engine-local.svc.cluster.local:8010`
- **External**: `http://localhost:30010`
- **Health**: `http://localhost:30010/api/v1/health`
- **API Docs**: `http://localhost:30010/docs`

### ConfigScan AWS Engine
- **Internal**: `http://configscan-aws-service.threat-engine-local.svc.cluster.local:8002`
- **External**: `http://localhost:30002`
- **Health**: `http://localhost:30002/api/v1/health`
- **API Docs**: `http://localhost:30002/docs`

## 🔍 Monitoring & Debugging

### View Logs
```bash
# Onboarding logs
kubectl logs -f -l app=onboarding-service -n threat-engine-local

# ConfigScan AWS logs
kubectl logs -f -l app=configscan-aws-service -n threat-engine-local
```

### Check Pod Status
```bash
kubectl get pods -n threat-engine-local
kubectl describe pod <pod-name> -n threat-engine-local
```

### Check Services
```bash
kubectl get services -n threat-engine-local
kubectl get endpoints -n threat-engine-local
```

### Database Connectivity Test
```bash
# From onboarding pod
kubectl exec -it <onboarding-pod> -n threat-engine-local -- \
  python3 -c "from engine_onboarding.database.connection import check_connection; print('OK' if check_connection() else 'FAILED')"

# From configscan pod
kubectl exec -it <configscan-pod> -n threat-engine-local -- \
  python3 -c "from engine.database_manager import DatabaseManager; db = DatabaseManager(); print('OK' if db._get_connection() else 'FAILED')"
```

## 🔧 Configuration

### Database Connection

The deployments use `host.docker.internal` to connect to PostgreSQL on the host. To change:

1. Edit ConfigMap:
   ```bash
   kubectl edit configmap onboarding-config -n threat-engine-local
   kubectl edit configmap configscan-aws-config -n threat-engine-local
   ```

2. Or edit Secret:
   ```bash
   kubectl edit secret onboarding-db-secret -n threat-engine-local
   kubectl edit secret configscan-aws-db-secret -n threat-engine-local
   ```

3. Restart deployment:
   ```bash
   kubectl rollout restart deployment onboarding-service -n threat-engine-local
   kubectl rollout restart deployment configscan-aws-service -n threat-engine-local
   ```

### Environment Variables

All configuration is in ConfigMaps. Key variables:

**Onboarding:**
- `DATABASE_URL` - PostgreSQL connection string
- `API_PORT` - Service port (default: 8010)
- `SCHEDULER_INTERVAL_SECONDS` - Scheduler polling interval

**ConfigScan AWS:**
- `DATABASE_URL` - PostgreSQL connection string
- `PORT` - Service port (default: 8002)
- `MAX_CONCURRENT_SCANS` - Max parallel scans
- `AWS_REGION` - Default AWS region

## 🧪 Testing

### Health Check Tests

```bash
# Test onboarding health
curl http://localhost:30010/api/v1/health | jq

# Test configscan health
curl http://localhost:30002/api/v1/health | jq

# Test readiness
curl http://localhost:30010/api/v1/health/ready
curl http://localhost:30002/api/v1/health/ready

# Test liveness
curl http://localhost:30010/api/v1/health/live
curl http://localhost:30002/api/v1/health/live
```

### API Tests

```bash
# Onboarding - List tenants
curl http://localhost:30010/api/v1/onboarding/tenants

# ConfigScan - List services
curl http://localhost:30002/api/v1/services
```

## 🗑️ Cleanup

### Remove Deployments

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

## 📝 Next Steps

1. **Test the Deployments**: Run `./test-services.sh` to verify everything works
2. **Check Database Connectivity**: Verify both engines can connect to their databases
3. **Test API Endpoints**: Use curl or Postman to test the APIs
4. **Monitor Logs**: Watch logs for any issues
5. **Add More Engines**: Follow the same pattern for other engines (Azure, GCP, etc.)

## 🐛 Troubleshooting

### Common Issues

1. **Pods Not Starting**
   - Check logs: `kubectl logs <pod-name> -n threat-engine-local`
   - Check events: `kubectl describe pod <pod-name> -n threat-engine-local`

2. **Database Connection Failed**
   - Verify PostgreSQL is running: `psql postgres -c "SELECT 1;"`
   - Check database URL in ConfigMap/Secret
   - Test connection from pod (see Database Connectivity Test above)

3. **Health Check Failures**
   - Check if database is accessible
   - Verify health endpoint is responding: `curl http://localhost:30010/api/v1/health`
   - Check pod logs for errors

4. **Image Pull Errors**
   - Ensure images are built: `docker images | grep threat-engine`
   - Check ImagePullPolicy is set to `IfNotPresent`

## 📚 Additional Resources

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Docker Desktop Kubernetes](https://docs.docker.com/desktop/kubernetes/)
- [PostgreSQL Connection Strings](https://www.postgresql.org/docs/current/libpq-connect.html)

---

**Ready to deploy!** Run `./deploy-engines.sh` to get started.
