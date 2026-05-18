# Story APISEC-S1-04: K8s Deployment/Service + Dockerfile + requirements.txt

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 3
- **Depends on**: APISEC-S1-03
- **Blocks**: APISEC-S1-13 (Argo needs the service DNS name to be live)
- **Security Gate**: bmad-security-reviewer (SLSA: pinned base image, no latest tag)

## `engines/api-security/Dockerfile`

```dockerfile
FROM python:3.11.9-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy shared engine_common first (build context = repo root)
COPY shared/common/ /app/engine_common/

# Copy engine source
COPY engines/api-security/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engines/api-security/ .

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8035

CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8035", "--workers", "1"]
```

Build command (repo root as context):
```bash
docker build -t yadavanup84/engine-api-security:v-apisec-1 \
  -f engines/api-security/Dockerfile .
```

## `engines/api-security/requirements.txt`

```
fastapi==0.111.0
uvicorn[standard]==0.29.0
psycopg2-binary==2.9.9
pydantic==2.7.1
python-jose[cryptography]==3.3.0
httpx==0.27.0
```

## `deployment/aws/eks/engines/engine-api-security.yaml`

```yaml
# =============================================================================
# API Security Engine — Port 8035 | Pipeline Step 5
# =============================================================================
apiVersion: apps/v1
kind: Deployment
metadata:
  name: engine-api-security
  namespace: threat-engine-engines
  labels:
    app: engine-api-security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: engine-api-security
  template:
    metadata:
      labels:
        app: engine-api-security
    spec:
      serviceAccountName: engine-sa
      containers:
        - name: engine-api-security
          image: yadavanup84/engine-api-security:v-apisec-1
          imagePullPolicy: Always
          ports:
            - containerPort: 8035
          envFrom:
            - configMapRef:
                name: threat-engine-db-config
            - secretRef:
                name: threat-engine-db-passwords
          env:
            - name: API_SECURITY_DB_NAME
              value: "threat_engine_api_security"
            - name: CHECK_DB_NAME
              value: "threat_engine_check"
            - name: CDR_DB_NAME
              value: "threat_engine_cdr"
            - name: INVENTORY_DB_NAME
              value: "threat_engine_inventory"
            - name: DISCOVERIES_DB_NAME
              value: "threat_engine_discoveries"
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "1Gi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /api/v1/health/live
              port: 8035
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /api/v1/health/ready
              port: 8035
            initialDelaySeconds: 5
            periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: engine-api-security
  namespace: threat-engine-engines
  labels:
    app: engine-api-security
spec:
  selector:
    app: engine-api-security
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8035
```

## Acceptance Criteria

- [ ] AC-1: `docker build` completes with no errors using repo root as build context
- [ ] AC-2: `kubectl apply -f deployment/aws/eks/engines/engine-api-security.yaml` creates Deployment + Service
- [ ] AC-3: `kubectl rollout status deployment/engine-api-security -n threat-engine-engines` succeeds
- [ ] AC-4: Post-deploy image tag check — `kubectl get pods -n threat-engine-engines -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[0].image' | grep api-security` shows `v-apisec-1`
- [ ] AC-5: `kubectl logs -l app=engine-api-security -n threat-engine-engines` shows uvicorn startup line, no import errors
- [ ] AC-6: Port-forward smoke: `kubectl port-forward svc/engine-api-security 8035:80 -n threat-engine-engines` then `python3 -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8035/api/v1/health/live').read())"` returns `{"status":"ok"}`
- [ ] AC-7: Base image is pinned (`python:3.11.9-slim`) — no `latest` tag in Dockerfile

## Definition of Done
- [ ] Dockerfile committed at `engines/api-security/Dockerfile`
- [ ] K8s manifest committed at `deployment/aws/eks/engines/engine-api-security.yaml`
- [ ] Image pushed: `docker push yadavanup84/engine-api-security:v-apisec-1`
- [ ] Deployment live in EKS, health endpoint responding
