# DevOps Guide — Threat Engine UI (CSPM Portal)

> **Audience:** DevOps engineers and platform teams responsible for building, deploying, and operating the CSPM Portal frontend and its Django backend on AWS EKS.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Repository Layout](#3-repository-layout)
4. [Docker — Build & Push](#4-docker--build--push)
5. [Environment Variables](#5-environment-variables)
6. [Kubernetes Manifests](#6-kubernetes-manifests)
7. [Deploying to EKS](#7-deploying-to-eks)
8. [GitHub Actions CI/CD Pipeline](#8-github-actions-cicd-pipeline)
9. [Rollback Procedure](#9-rollback-procedure)
10. [Health Checks & Readiness](#10-health-checks--readiness)
11. [Ingress & Routing](#11-ingress--routing)
12. [Secrets Management](#12-secrets-management)
13. [Resource Sizing](#13-resource-sizing)
14. [Monitoring & Alerting](#14-monitoring--alerting)
15. [Scaling](#15-scaling)
16. [Troubleshooting](#16-troubleshooting)
17. [Runbook — Common Operations](#17-runbook--common-operations)

---

## 1. Architecture Overview

```
Internet
   │
   ▼
AWS NLB (a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com)
   │
   ▼
nginx Ingress Controller (threat-engine-engines namespace)
   ├─ /ui/*  ──────────────────► cspm-frontend  :3000  (Next.js — no URL rewrite)
   └─ /cspm(/|$)(.*)  ─────────► cspm-backend   :8000  (Django — prefix stripped → /$2)
```

| Component | Image | Port | Namespace |
|-----------|-------|------|-----------|
| Next.js frontend | `yadavanup84/threat-engine-ui:latest` | 3000 | threat-engine-engines |
| Django backend | `yadavanup84/cspm-django-backend:latest` | 8000 | threat-engine-engines |
| PostgreSQL (RDS) | AWS RDS (external) | 5432 | — |

**EKS Cluster:** `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster`
**Region:** `ap-south-1` (Mumbai)

---

## 2. Prerequisites

### Local tools

| Tool | Minimum version | Purpose |
|------|----------------|---------|
| Docker | 24+ | Build & push images |
| kubectl | 1.28+ | Cluster operations |
| aws CLI | 2.x | EKS context, Secrets Manager |
| Node.js | 20 LTS | Local dev only |
| helm | 3.x | (Optional) chart inspection |

### AWS access

```bash
# Authenticate to EKS
aws eks update-kubeconfig \
  --region ap-south-1 \
  --name vulnerability-eks-cluster

# Verify context
kubectl config current-context
# → arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster
```

### DockerHub access

```bash
docker login -u yadavanup84
# Enter DockerHub access token when prompted
```

---

## 3. Repository Layout

```
threat-engine/
├── ui_samples/                         # ← Next.js CSPM frontend
│   ├── Dockerfile                      # Multi-stage production build
│   ├── .env.local.example             # Template for local env vars
│   ├── next.config.mjs                # basePath: /ui, standalone output
│   ├── src/
│   │   ├── app/                       # Next.js App Router pages
│   │   ├── components/                # Shared React components
│   │   └── lib/                       # Utilities, API helpers, contexts
│   └── docs/
│       ├── USER_GUIDE.md
│       ├── DEVELOPER_GUIDE.md
│       └── DEVOPS_GUIDE.md            # ← You are here
│
├── cspm-backend-master/               # Django REST API
│   └── Dockerfile
│
├── .github/
│   └── workflows/
│       └── deploy-ui.yml              # CI/CD pipeline
│
└── deployment/
    └── aws/eks/engines/
        ├── cspm-portal.yaml           # Frontend + backend Deployments & Services
        └── cspm-portal-ingress.yaml   # Ingress rules
```

---

## 4. Docker — Build & Push

### 4.1 Frontend (Next.js)

The Dockerfile at `ui_samples/Dockerfile` uses a **three-stage multi-stage build**:

| Stage | Base | Purpose |
|-------|------|---------|
| `deps` | `node:20-alpine` | Install production dependencies |
| `builder` | `node:20-alpine` | `next build` with baked env vars |
| `runner` | `node:20-alpine` | Minimal runtime image |

> **Important:** `NEXT_PUBLIC_*` variables are baked into the JavaScript bundle at build time. They **cannot** be changed at runtime without a rebuild.

```bash
cd /Users/apple/Desktop/threat-engine/ui_samples

# Build (bakes ELB URL into bundle)
docker build \
  --build-arg NEXT_PUBLIC_API_BASE=http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/cspm \
  --build-arg NEXT_PUBLIC_AUTH_URL=http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/cspm \
  --build-arg NEXT_PUBLIC_TENANT_ID=5a8b072b-8867-4476-a52f-f331b1cbacb3 \
  -t yadavanup84/threat-engine-ui:latest \
  -t yadavanup84/threat-engine-ui:$(git rev-parse --short HEAD) \
  .

# Push both tags
docker push yadavanup84/threat-engine-ui:latest
docker push yadavanup84/threat-engine-ui:$(git rev-parse --short HEAD)
```

### 4.2 Backend (Django)

```bash
cd /Users/apple/Desktop/threat-engine/cspm-backend-master

docker build \
  -t yadavanup84/cspm-django-backend:latest \
  -t yadavanup84/cspm-django-backend:$(git rev-parse --short HEAD) \
  .

docker push yadavanup84/cspm-django-backend:latest
docker push yadavanup84/cspm-django-backend:$(git rev-parse --short HEAD)
```

### 4.3 Local smoke-test before pushing

```bash
docker run --rm -p 3000:3000 \
  -e HOSTNAME=0.0.0.0 \
  -e PORT=3000 \
  yadavanup84/threat-engine-ui:latest

curl -sf http://localhost:3000/ui | head -20
```

---

## 5. Environment Variables

### 5.1 Frontend — build-time (`NEXT_PUBLIC_*`)

Baked into the JS bundle during `next build`. Pass as `--build-arg` to `docker build`.

| Variable | Example | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_BASE` | `http://<ELB>/cspm` | Base URL for Django backend API calls |
| `NEXT_PUBLIC_AUTH_URL` | `http://<ELB>/cspm` | Auth endpoint base (login, logout, CSRF) |
| `NEXT_PUBLIC_TENANT_ID` | `5a8b072b-...` | Default tenant for multi-tenant API calls |

### 5.2 Frontend — runtime (Pod env vars)

| Variable | Value | Description |
|----------|-------|-------------|
| `HOSTNAME` | `0.0.0.0` | Next.js server bind address |
| `PORT` | `3000` | Next.js listen port |
| `NODE_ENV` | `production` | Disables dev overlays |

### 5.3 Backend — runtime (Pod env vars)

| Variable | Source | Description |
|----------|--------|-------------|
| `SECRET_KEY` | `cspm-portal-secret` K8s Secret | Django secret key |
| `DEBUG` | `"False"` | Production mode |
| `ALLOWED_HOSTS` | `"*"` | Allow all hosts (nginx terminates TLS) |
| `FRONTEND_URL` | `http://<ELB>/ui` | CORS allowed origin |
| `DB_NAME` | `"cspm"` | PostgreSQL database |
| `DB_HOST` | `threat-engine-db-config` ConfigMap | RDS hostname |
| `DB_PORT` | `"5432"` | PostgreSQL port |
| `DB_USER` | `"postgres"` | DB username |
| `DB_PASSWORD` | `threat-engine-db-passwords` Secret | DB password |
| `DB_SSLMODE` | `"require"` | Enforce TLS to RDS |
| `AWS_REGION` | `platform-config` ConfigMap | AWS region |
| `*_ENGINE_URL` | cluster-local SVC | Internal engine service URLs |

---

## 6. Kubernetes Manifests

All manifests live in `deployment/aws/eks/engines/`:

```
cspm-portal.yaml
├── Deployment: cspm-backend   (Django, port 8000)
│   ├── initContainer: migrate (runs Django migrations on startup)
│   └── container: cspm-backend
├── Service: cspm-backend      (ClusterIP :80 → pod :8000)
├── Deployment: cspm-frontend  (Next.js, port 3000)
│   └── container: cspm-frontend
└── Service: cspm-frontend     (ClusterIP :80 → pod :3000)

cspm-portal-ingress.yaml
├── Ingress: cspm-frontend-ingress  (/ui → cspm-frontend:80, no rewrite)
└── Ingress: cspm-backend-ingress   (/cspm(/|$)(.*) → cspm-backend:80, rewrite /$2)
```

---

## 7. Deploying to EKS

### 7.1 Full deploy (initial or manifest changes)

```bash
MANIFEST_DIR=/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines

kubectl apply -f ${MANIFEST_DIR}/cspm-portal.yaml
kubectl apply -f ${MANIFEST_DIR}/cspm-portal-ingress.yaml

kubectl rollout status deployment/cspm-frontend -n threat-engine-engines
kubectl rollout status deployment/cspm-backend  -n threat-engine-engines
```

### 7.2 Image-only update (most common)

Both pods use `imagePullPolicy: Always` + `:latest` tag. A rollout restart forces a fresh image pull:

```bash
kubectl rollout restart deployment/cspm-frontend -n threat-engine-engines
kubectl rollout restart deployment/cspm-backend  -n threat-engine-engines

kubectl get pods -n threat-engine-engines -l tier=portal -w
```

### 7.3 Pinned-tag deploy (recommended for stability)

```bash
kubectl set image deployment/cspm-frontend \
  cspm-frontend=yadavanup84/threat-engine-ui:abc1234 \
  -n threat-engine-engines

kubectl set image deployment/cspm-backend \
  cspm-backend=yadavanup84/cspm-django-backend:abc1234 \
  -n threat-engine-engines
```

### 7.4 Verify deployment

```bash
ELB=a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com

kubectl get pods    -n threat-engine-engines -l tier=portal
kubectl get svc     -n threat-engine-engines | grep cspm
kubectl get ingress -n threat-engine-engines | grep cspm

curl -sf http://${ELB}/cspm/health   # → {"status": "ok"}
curl -sf -o /dev/null -w "%{http_code}" http://${ELB}/ui  # → 200
```

---

## 8. GitHub Actions CI/CD Pipeline

The pipeline at `.github/workflows/deploy-ui.yml` automates:
**code push → Docker build → push to DockerHub → rolling deploy to EKS**

### 8.1 Required GitHub Secrets

Configure in **GitHub → Repository Settings → Secrets → Actions**:

| Secret Name | Value |
|------------|-------|
| `DOCKERHUB_USERNAME` | `yadavanup84` |
| `DOCKERHUB_TOKEN` | DockerHub access token (not password) |
| `AWS_ACCESS_KEY_ID` | IAM user key with EKS describe/update permissions |
| `AWS_SECRET_ACCESS_KEY` | Corresponding IAM secret |
| `ELB_HOST` | `a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com` |
| `TENANT_ID` | `5a8b072b-8867-4476-a52f-f331b1cbacb3` |

### 8.2 IAM permissions required for GitHub Actions

The AWS IAM user/role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters"
      ],
      "Resource": "arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster"
    }
  ]
}
```

The EKS cluster RBAC must also allow this IAM user to `kubectl apply` and `kubectl rollout`. Add to `aws-auth` ConfigMap if needed:

```bash
kubectl edit configmap aws-auth -n kube-system
```

### 8.3 Pipeline triggers

| Trigger | Condition |
|---------|-----------|
| Automatic | Push to `main` with changes in `ui_samples/**` or `deployment/aws/eks/engines/cspm-portal*.yaml` |
| Manual | GitHub Actions UI → "Run workflow" |

### 8.4 Pipeline flow

```
git push → main (ui_samples/** changed)
          │
          ▼
    ┌─────────────────┐
    │  build-frontend │
    │  docker build   │
    │  docker push    │
    │  :latest + :sha │
    └────────┬────────┘
             │ on success
             ▼
    ┌──────────────────────────────────┐
    │           deploy                 │
    │  aws configure-credentials       │
    │  aws eks update-kubeconfig       │
    │  kubectl apply manifests         │
    │  kubectl rollout restart ×2      │
    │  kubectl rollout status (5min)   │
    │  curl smoke test (/health + /ui) │
    └──────────────────────────────────┘
```

### 8.5 Manual trigger: skip build

To redeploy without rebuilding (e.g., apply a manifest change only):

1. Go to **GitHub → Actions → Deploy CSPM UI to EKS**
2. Click **Run workflow**
3. Set `Skip Docker build` → `true`
4. Click **Run workflow**

### 8.6 Branch protection (recommended)

Protect `main` with:
- Required status checks: `Build Frontend`, `Deploy to EKS`
- Require pull request reviews before merging
- Restrict force-pushes

---

## 9. Rollback Procedure

### 9.1 Quick rollback (< 60 seconds)

Kubernetes retains the previous ReplicaSet:

```bash
# View history
kubectl rollout history deployment/cspm-frontend -n threat-engine-engines
kubectl rollout history deployment/cspm-backend  -n threat-engine-engines

# Roll back to previous revision
kubectl rollout undo deployment/cspm-frontend -n threat-engine-engines
kubectl rollout undo deployment/cspm-backend  -n threat-engine-engines

# Or roll back to a specific revision
kubectl rollout undo deployment/cspm-frontend \
  --to-revision=3 -n threat-engine-engines

kubectl rollout status deployment/cspm-frontend -n threat-engine-engines
```

### 9.2 Image-tag rollback

```bash
# Pin to a known-good SHA
kubectl set image deployment/cspm-frontend \
  cspm-frontend=yadavanup84/threat-engine-ui:abc1234 \
  -n threat-engine-engines

kubectl rollout status deployment/cspm-frontend -n threat-engine-engines
```

### 9.3 Full manifest rollback from git

```bash
git show HEAD~1:deployment/aws/eks/engines/cspm-portal.yaml \
  | kubectl apply -f -
```

---

## 10. Health Checks & Readiness

### Kubernetes probes (from manifests)

**Frontend (Next.js)**
```yaml
livenessProbe:   { httpGet: { path: /ui, port: 3000 }, initialDelaySeconds: 20, periodSeconds: 15 }
readinessProbe:  { httpGet: { path: /ui, port: 3000 }, initialDelaySeconds: 10, periodSeconds: 10 }
```

**Backend (Django)**
```yaml
livenessProbe:   { httpGet: { path: /health, port: 8000 }, initialDelaySeconds: 30, periodSeconds: 15 }
readinessProbe:  { httpGet: { path: /health, port: 8000 }, initialDelaySeconds: 15, periodSeconds: 10 }
```

### Manual health checks

```bash
ELB=a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com

curl http://${ELB}/cspm/health      # Django → {"status": "ok"}
curl -I http://${ELB}/ui            # Next.js → HTTP/1.1 200 OK

# Direct pod bypass (no ingress)
POD=$(kubectl get pod -n threat-engine-engines -l app=cspm-backend -o name | head -1)
kubectl exec -n threat-engine-engines ${POD} -- curl -sf localhost:8000/health
```

---

## 11. Ingress & Routing

| Path | Service | Rewrite | Notes |
|------|---------|---------|-------|
| `/ui` (prefix) | `cspm-frontend:80` | None | Next.js `basePath: '/ui'` handles prefix |
| `/cspm(/\|$)(.*)` | `cspm-backend:80` | `/$2` | Strips `/cspm` prefix before Django |

### Timeouts (both ingresses)

```
proxy-read-timeout:  120s
proxy-send-timeout:  120s
proxy-body-size:     50m
ssl-redirect:        false (NLB terminates TLS)
```

---

## 12. Secrets Management

### Kubernetes Secrets in use

| Secret | Key | Used by |
|--------|-----|---------|
| `cspm-portal-secret` | `SECRET_KEY` | Django — session signing |
| `threat-engine-db-passwords` | `ONBOARDING_DB_PASSWORD` | Django DB connection |

### Rotate Django `SECRET_KEY`

```bash
DJANGO_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")

kubectl create secret generic cspm-portal-secret \
  --from-literal=SECRET_KEY="${DJANGO_SECRET}" \
  --namespace=threat-engine-engines \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart Django to pick up new key (invalidates all sessions)
kubectl rollout restart deployment/cspm-backend -n threat-engine-engines
```

> ⚠️ Rotating `SECRET_KEY` logs out **all** active users.

### Rotate DB password

1. Update `threat-engine/rds-credentials` → `ONBOARDING_DB_PASSWORD` in AWS Secrets Manager
2. Force External Secrets sync:
   ```bash
   kubectl annotate externalsecret threat-engine-db-passwords \
     force-sync=$(date +%s) --overwrite -n threat-engine-engines
   ```
3. Restart Django: `kubectl rollout restart deployment/cspm-backend -n threat-engine-engines`

---

## 13. Resource Sizing

| Component | CPU Request | CPU Limit | Mem Request | Mem Limit |
|-----------|------------|-----------|-------------|-----------|
| cspm-frontend | 100m | 500m | 256Mi | 512Mi |
| cspm-backend | 250m | 1000m | 512Mi | 1Gi |

### Scale replicas

```bash
kubectl scale deployment cspm-frontend --replicas=2 -n threat-engine-engines
kubectl scale deployment cspm-backend  --replicas=2 -n threat-engine-engines
```

### Horizontal Pod Autoscaler

```bash
kubectl autoscale deployment cspm-frontend \
  --min=1 --max=4 --cpu-percent=70 -n threat-engine-engines

kubectl autoscale deployment cspm-backend \
  --min=1 --max=4 --cpu-percent=75 -n threat-engine-engines
```

---

## 14. Monitoring & Alerting

### Pod logs

```bash
# Follow backend logs
kubectl logs -n threat-engine-engines -l app=cspm-backend -f

# Errors only
kubectl logs -n threat-engine-engines -l app=cspm-backend \
  | grep -iE "error|exception|traceback"

# Frontend last 100 lines
kubectl logs -n threat-engine-engines -l app=cspm-frontend --tail=100
```

### Events

```bash
kubectl get events -n threat-engine-engines \
  --sort-by='.lastTimestamp' | grep -i cspm
```

### Resource usage

```bash
kubectl top pods -n threat-engine-engines -l tier=portal
kubectl top nodes
```

### OpenTelemetry integration

Add to `cspm-portal.yaml` backend container env to enable tracing:

```yaml
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: "http://otel-collector.threat-engine-engines.svc.cluster.local:4317"
- name: OTEL_SERVICE_NAME
  value: "cspm-backend"
```

---

## 15. Scaling

Both deployments use `RollingUpdate` with `maxSurge: 1` / `maxUnavailable: 0` — guaranteeing **zero-downtime deploys**.

```bash
# Scale up for load testing
kubectl scale deployment cspm-frontend --replicas=3 -n threat-engine-engines
kubectl scale deployment cspm-backend  --replicas=3 -n threat-engine-engines

# Restore after test
kubectl scale deployment cspm-frontend --replicas=1 -n threat-engine-engines
kubectl scale deployment cspm-backend  --replicas=1 -n threat-engine-engines
```

---

## 16. Troubleshooting

### Pod stuck in `Pending`

```bash
kubectl describe pod <pod-name> -n threat-engine-engines
```

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ImagePullBackOff` | DockerHub rate limit or wrong image | Check image name; `docker login` |
| `Insufficient cpu` | Node capacity full | Scale down other workloads or add node |
| `Unschedulable` | Taint/toleration mismatch | CSPM pods don't use spot-scanner nodes |

### Django migration fails (initContainer error)

```bash
kubectl logs <cspm-backend-pod> -c migrate -n threat-engine-engines
```

Common causes:
- DB not reachable → check `threat-engine-db-config` ConfigMap
- Wrong password → check `threat-engine-db-passwords` Secret
- DB `cspm` doesn't exist → `psql -U postgres -c "CREATE DATABASE cspm;"`

### Next.js 404 on `/ui`

```bash
kubectl get pods    -n threat-engine-engines -l app=cspm-frontend
kubectl describe ingress cspm-frontend-ingress -n threat-engine-engines

# Port-forward to test directly (bypassing ingress)
kubectl port-forward svc/cspm-frontend 3000:80 -n threat-engine-engines
curl http://localhost:3000/ui
```

### Login returns 403 CSRF

The Django backend requires CSRF. Verify the frontend:
1. Calls `GET /cspm/api/auth/csrf/` before login (to set cookie)
2. Sends `X-CSRFToken` header on `POST /cspm/api/auth/login/`
3. All fetch calls include `credentials: 'include'`

### Wrong API URL baked into bundle

```bash
kubectl exec -n threat-engine-engines \
  $(kubectl get pod -l app=cspm-frontend -n threat-engine-engines -o name | head -1) \
  -- env | grep NEXT_PUBLIC
```

`NEXT_PUBLIC_*` vars are baked at **build time** — if wrong, rebuild the image with correct `--build-arg` values.

---

## 17. Runbook — Common Operations

### Deploy a hotfix

```bash
# Build and push hotfix image
docker build -t yadavanup84/threat-engine-ui:hotfix-$(date +%Y%m%d) \
  /Users/apple/Desktop/threat-engine/ui_samples
docker push yadavanup84/threat-engine-ui:hotfix-$(date +%Y%m%d)

# Set the new image
kubectl set image deployment/cspm-frontend \
  cspm-frontend=yadavanup84/threat-engine-ui:hotfix-$(date +%Y%m%d) \
  -n threat-engine-engines

kubectl rollout status deployment/cspm-frontend -n threat-engine-engines
```

### Add a runtime env var to backend

```bash
kubectl patch deployment cspm-backend -n threat-engine-engines \
  --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/env/-",
         "value":{"name":"MY_VAR","value":"my-value"}}]'
```

> For `NEXT_PUBLIC_*` frontend vars — runtime patches don't work. Full image rebuild required.

### Check DB connectivity from backend pod

```bash
POD=$(kubectl get pod -n threat-engine-engines -l app=cspm-backend -o name | head -1)
kubectl exec -n threat-engine-engines ${POD} -- \
  python manage.py dbshell -- -c "\dt cspm.*"
```

### Force-sync External Secret (after rotating DB password in Secrets Manager)

```bash
kubectl annotate externalsecret threat-engine-db-passwords \
  force-sync=$(date +%s) --overwrite -n threat-engine-engines

kubectl get externalsecret threat-engine-db-passwords -n threat-engine-engines -w
```

### View all CSPM resources at a glance

```bash
kubectl get all -n threat-engine-engines -l tier=portal
```

---

*DEVOPS_GUIDE.md — Threat Engine CSPM Portal v1.0 | Last updated: 2026-03-07*
