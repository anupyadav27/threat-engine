# Local Deployment

Local development and testing deployment using Docker Desktop Kubernetes and local PostgreSQL.

## Architecture

```
┌─────────────────────────────────────────┐
│      Docker Desktop Kubernetes          │
│  ┌──────────────┐  ┌──────────────┐   │
│  │ ConfigScan   │  │ Compliance   │   │
│  │ Engines      │  │ Engine       │   │
│  └──────┬───────┘  └──────┬───────┘   │
│         │                  │           │
│  ┌──────▼──────────────────▼───────┐  │
│  │  Rule Engine  │  Onboarding      │  │
│  └───────────────┴──────────────────┘  │
└─────────────────────────────────────────┘
         │                    │
         ▼                    ▼
┌─────────────────┐  ┌─────────────────┐
│ Local PostgreSQL │  │ Local Filesystem│
│  (Docker/Port)   │  │  engines-output/│
└─────────────────┘  └─────────────────┘
```

## Components

### 1. PostgreSQL (Local)
- **Type**: Local PostgreSQL or Docker container
- **Port**: 5432
- **Databases**:
  - `compliance_engine`
  - `threat_engine`

### 2. Kubernetes (Docker Desktop)
- **Type**: Docker Desktop Kubernetes
- **Namespace**: `threat-engine-local`
- **Services**: All engines as ClusterIP

### 3. Storage
- **Type**: Local filesystem
- **Path**: `engines-output/`
- **No S3**: All outputs go to local filesystem

## Setup

### Prerequisites
```bash
# Install Docker Desktop
# Install kubectl
# Install PostgreSQL (or use Docker)
```

### 1. Setup PostgreSQL
```bash
cd deployment/local/postgres
./setup-postgres.sh
```

### 2. Deploy to Kubernetes
```bash
cd deployment/local/kubernetes
kubectl apply -f .
```

### 3. Or Use Docker Compose
```bash
cd deployment/local/docker-compose
docker-compose up -d
```

## Configuration

### Database Connection
```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/threat_engine"
```

### Output Directory
```bash
export OUTPUT_DIR="/Users/apple/Desktop/threat-engine/engines-output"
```

### Kubernetes Context
```bash
kubectl config use-context docker-desktop
```

## Services

### Port Forwarding (Local Access)
```bash
# ConfigScan Engines
kubectl port-forward -n threat-engine-local svc/aws-configScan-engine 8000:80

# Compliance Engine
kubectl port-forward -n threat-engine-local svc/compliance-engine 8001:80

# Rule Engine
kubectl port-forward -n threat-engine-local svc/rule-engine 8002:80

# Onboarding Engine
kubectl port-forward -n threat-engine-local svc/onboarding-engine 8003:80
```

## Testing

### Test Database Connection
```bash
psql postgresql://postgres:postgres@localhost:5432/compliance_engine -c "SELECT 1;"
```

### Test Services
```bash
curl http://localhost:8000/api/v1/health  # ConfigScan Engine
curl http://localhost:8001/api/v1/health  # Compliance Engine
curl http://localhost:8002/api/v1/health  # Rule Engine
curl http://localhost:8003/api/v1/health  # Onboarding Engine
```

## Cleanup

```bash
# Remove Kubernetes resources
kubectl delete namespace threat-engine-local

# Stop Docker Compose
cd deployment/local/docker-compose
docker-compose down

# Clean PostgreSQL (optional)
cd deployment/local/postgres
./cleanup-postgres.sh
```

