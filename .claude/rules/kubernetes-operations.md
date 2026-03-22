---
paths:
  - "deployment/aws/eks/**/*.yaml"
  - "deployment/aws/eks/**/*.json"
---

# Kubernetes Configuration Standards

## EKS Deployment Manifests

### Required Fields
- **Resource limits and requests**: Always specify CPU and memory
- **Health checks**: Both liveness and readiness probes required
- **Labels**: Include `app`, `version`, `component`, `managed-by`
- **Annotations**: Document deployment metadata
- **Image digests**: Use specific image tags (never `latest` in production)

Example:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: engine-discoveries
  namespace: threat-engine-engines
  labels:
    app: engine-discoveries
    version: v1.0.0
    component: scanner
    managed-by: kubectl
spec:
  replicas: 1
  selector:
    matchLabels:
      app: engine-discoveries
  template:
    metadata:
      labels:
        app: engine-discoveries
    spec:
      containers:
      - name: engine-discoveries
        image: yadavanup84/engine-discoveries-aws:v1.0.0
        resources:
          requests:
            cpu: 250m
            memory: 512Mi
          limits:
            cpu: 500m
            memory: 1Gi
        livenessProbe:
          httpGet:
            path: /api/v1/health/live
            port: 8001
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /api/v1/health/ready
            port: 8001
          initialDelaySeconds: 10
          periodSeconds: 10
```

### Configuration Management
- **ConfigMaps**: Use for non-sensitive configuration
- **Secrets**: Use for credentials, API keys, passwords
- **Environment variables**: Reference ConfigMaps/Secrets, never hardcode
- **Volume mounts**: For config files that need to be updated without pod restart

### RBAC Configuration
- **Service accounts**: Create dedicated service accounts per engine
- **Roles**: Define minimal permissions (least privilege)
- **RoleBindings**: Bind service accounts to roles explicitly
- **ClusterRoles**: Only for cluster-wide operations (use sparingly)

### Validation Before Apply
```bash
# Dry-run validation
kubectl apply --dry-run=client -f deployment.yaml

# Schema validation
kubectl apply --dry-run=server -f deployment.yaml

# YAML linting
yamllint deployment.yaml
```

### Naming Conventions
- Deployments: `engine-<name>`
- Services: `engine-<name>` or `<name>-service`
- ConfigMaps: `<component>-config`
- Secrets: `<component>-secrets`
- Namespaces: `threat-engine-<environment>`

### Security Best Practices
- **Non-root containers**: Set `runAsNonRoot: true`
- **Read-only root filesystem**: Set `readOnlyRootFilesystem: true` when possible
- **Drop capabilities**: Drop all, add only what's needed
- **Network policies**: Define ingress/egress rules
- **Pod security policies**: Enforce security standards

Example security context:
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  capabilities:
    drop:
    - ALL
  readOnlyRootFilesystem: true
```

## Important Notes
- Always test in staging namespace before production
- Monitor rollout status: `kubectl rollout status deployment/<name>`
- Check logs immediately after deployment: `kubectl logs -f -l app=<name>`
- Use `kubectl describe` to debug pod issues
