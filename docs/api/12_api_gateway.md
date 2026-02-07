# api_gateway — Unified API Entry Point

> Port: **8000** | Docker: `threat-engine/api-gateway:latest`
> Type: Reverse proxy / service router

---

## Folder Structure

```
api_gateway/
├── main.py                             # FastAPI gateway (6+ endpoints)
├── Dockerfile                          # Container with healthcheck
├── orchestration.py                    # Scan pipeline orchestration
├── requirements.txt                    # Dependencies
├── sidecar/                            # Sidecar proxy configs
└── __init__.py
```

---

## Gateway Architecture

```
  Client Request
       │
       ▼
  API Gateway (:8000)
       │
       ├── /gateway/*           → Gateway self (health, services)
       │
       ├── /api/v1/threat/*     → Threat Engine (:8020)
       ├── /api/v1/graph/*      → Threat Engine (:8020)
       ├── /api/v1/intel/*      → Threat Engine (:8020)
       ├── /api/v1/hunt/*       → Threat Engine (:8020)
       │
       ├── /api/v1/check/*      → Check Engine (:8001)
       ├── /api/v1/discovery/*  → Discoveries Engine (:8002)
       ├── /api/v1/inventory/*  → Inventory Engine (:8022)
       ├── /api/v1/compliance/* → Compliance Engine (:8021)
       │
       ├── /api/v1/rules/*      → Rule Engine (:8011)
       ├── /api/v1/providers/*  → Rule Engine (:8011)
       │
       ├── /api/v1/iam-*        → IAM Engine (:8003)
       ├── /api/v1/data-*       → DataSec Engine (:8004)
       │
       ├── /api/v1/onboarding/* → Onboarding Engine (:8010)
       ├── /api/v1/schedules/*  → Onboarding Engine (:8010)
       ├── /api/v1/accounts/*   → Onboarding Engine (:8010)
       │
       └── /api/v1/secops/*     → SecOps Engine
```

---

## Gateway Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Root with service list |
| GET | `/gateway/health` | Gateway health status |
| GET | `/gateway/services` | List all registered services |
| POST | `/gateway/services/{name}/health-check` | Force health check on service |
| GET | `/gateway/configscan/csps` | List supported CSPs |
| GET | `/gateway/configscan/route-test` | Test CSP routing |
| POST | `/gateway/orchestrate` | Orchestrate full scan pipeline |

---

## Service Registry

| Service Name | Internal URL | Port |
|-------------|-------------|------|
| configscan-aws | http://aws-configscan-engine | 8000 |
| configscan-azure | http://azure-configscan-engine | 8000 |
| configscan-gcp | http://gcp-configscan-engine | 8000 |
| configscan-alicloud | http://alicloud-configscan-engine | 8000 |
| configscan-ibm | http://ibm-configscan-engine | 8000 |
| configscan-oci | http://oci-configscan-engine | 8000 |
| threat | http://threat-engine | 8020 |
| check | http://core-engine-service | 8001 |
| inventory | http://inventory-engine | 8022 |
| compliance | http://compliance-engine | 8021 |
| onboarding | http://onboarding-engine | 8010 |
| rule | http://rule-engine | 8011 |

---

## Orchestration Pipeline

The `/gateway/orchestrate` endpoint triggers a full scan pipeline:

```
1. Discovery Scan   → engine_discoveries
2. Check Scan       → engine_check
3. Inventory Build  → engine_inventory
4. Threat Detection → engine_threat
5. Compliance Report → engine_compliance
6. Graph Build      → engine_threat (Neo4j)
```

---

## Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY api_gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api_gateway/*.py ./
COPY api_gateway/ ./
COPY engine_common/ ./engine_common
RUN groupadd -r gateway && useradd -r -g gateway gateway
RUN chown -R gateway:gateway /app
USER gateway
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/gateway/health || exit 1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
```
