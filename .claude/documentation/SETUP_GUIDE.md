# Setup Guide — Local Development

> Step-by-step guide to set up the CSPM platform for local development.

---

## Prerequisites

| Requirement | Version | Purpose |
|------------|---------|---------|
| Python | 3.11+ | Engine runtime |
| Docker | 24+ | Container builds |
| Docker Compose | 2.20+ | Local orchestration |
| PostgreSQL | 15+ | Database (or use Docker) |
| pip | 23+ | Python package manager |
| AWS CLI | 2.x | Cloud scanning (optional) |
| kubectl | 1.28+ | K8s deployment (optional) |
| Node.js | 18+ | User portal UI (optional) |

---

## Option 1: Docker Compose (Recommended)

### 1. Clone the repository

```bash
git clone <repo-url>
cd threat-engine
```

### 2. Configure environment

```bash
cp config.env.template .env
# Edit .env with your database password, AWS credentials, etc.
```

### 3. Start all services

```bash
cd deployment
docker-compose up -d
```

This starts:
- PostgreSQL on port 5432
- Redis on port 6379
- API Gateway on port 8000
- Core Engine on port 8001
- ConfigScan on port 8002
- Platform Service on port 8003
- Data SecOps on port 8004

### 4. Initialize databases

```bash
# Run schema migrations
PGPASSWORD=your_password psql -h localhost -U postgres -f scripts/init-databases.sql
```

### 5. Verify

```bash
curl http://localhost:8000/gateway/health
# {"status": "healthy", "services": {...}}
```

---

## Option 2: Individual Engine (For Development)

### 1. Set up Python environment

```bash
cd threat-engine
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: .\venv\Scripts\activate  # Windows
```

### 2. Install engine dependencies

```bash
# Example: threat engine
pip install -r engine_threat/requirements.txt
```

### 3. Set environment variables

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=postgres
export DB_PASSWORD=your_password
export CHECK_DB_NAME=threat_engine_check
export THREAT_DB_NAME=threat_engine_threat
export INVENTORY_DB_NAME=threat_engine_inventory
export LOG_LEVEL=DEBUG
```

### 4. Run the engine

```bash
python -m uvicorn threat_engine.api_server:app --host 0.0.0.0 --port 8020 --reload
```

### 5. Access API docs

Open http://localhost:8020/docs for Swagger UI.

---

## Database Setup

### Create databases

```sql
-- Connect to PostgreSQL
psql -h localhost -U postgres

-- Create databases (use actual production DB names)
CREATE DATABASE threat_engine_check;
CREATE DATABASE threat;               -- NOT threat_engine_threat
CREATE DATABASE threat_engine_inventory;
CREATE DATABASE threat_engine_compliance;
CREATE DATABASE discoveries;          -- NOT threat_engine_discoveries
CREATE DATABASE threat_engine_onboarding;
CREATE DATABASE threat_engine_datasec;
CREATE DATABASE threat_engine_iam;
CREATE DATABASE threat_engine_secops;
CREATE DATABASE shared;               -- deprecated, keep for compatibility

-- Create users (optional, can use postgres user)
CREATE USER check_user WITH PASSWORD 'check_password';
CREATE USER threat_user WITH PASSWORD 'threat_password';
CREATE USER inventory_user WITH PASSWORD 'inventory_password';

-- Grant access
GRANT ALL PRIVILEGES ON DATABASE threat_engine_check TO check_user;
GRANT ALL PRIVILEGES ON DATABASE threat_engine_threat TO threat_user;
GRANT ALL PRIVILEGES ON DATABASE threat_engine_inventory TO inventory_user;
```

### Run schema migrations

```bash
# Run Alembic migrations (preferred — tracks applied migrations)
export DB_PASSWORD=your_password
export RDS_HOST=localhost

for DB in check compliance discoveries inventory threat iam datasec secops onboarding; do
  DATABASE_URL="postgresql://postgres:${DB_PASSWORD}@${RDS_HOST}/threat_engine_${DB}" \
    alembic -c shared/database/alembic.ini upgrade head
done

# Or apply raw SQL schemas (one-time setup only)
# Files are in shared/database/schemas/
```

### Load rule metadata

```bash
cd consolidated_services/database/scripts
python populate_rule_metadata.py
# This loads 9,943 security rules into rule_metadata table
```

---

## Neo4j Setup (Optional)

For security graph features (attack paths, blast radius, threat hunting):

### Option A: Neo4j Aura (SaaS)
1. Create account at https://neo4j.com/cloud/aura/
2. Create a free instance
3. Set environment variables:
```bash
export NEO4J_URI=neo4j+s://your-instance.databases.neo4j.io
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=your_password
```

### Option B: Local Neo4j (Docker)
```bash
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_password \
  neo4j:5
```
```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=your_password
```

---

## AWS Credentials (For Cloud Scanning)

### Option A: IAM Role (Recommended for EKS)
```bash
export AWS_ROLE_ARN=arn:aws:iam::ACCOUNT_ID:role/cspm-scan-role
```

### Option B: Access Keys (Local dev)
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGION=ap-south-1
```

### Option C: AWS Profile
```bash
export AWS_PROFILE=cspm-profile
```

---

## Running Tests

```bash
# Install test dependencies
pip install -r tests/requirements.txt

# Run all tests
python -m pytest tests/ -v

# Run specific engine tests
python -m pytest tests/test_api_gateway.py -v

# Run integration tests
cd tests
bash run_all_integration_tests.sh
```

---

## Building Docker Images

```bash
# Build threat engine
docker build -f engine_threat/Dockerfile -t threat-engine:latest .

# Build from repo root (important — context needs engine_common and consolidated_services)
docker build -f engine_check/Dockerfile -t check-engine:latest .
docker build -f engine_inventory/Dockerfile -t inventory-engine:latest .

# Push to DockerHub
docker tag threat-engine:latest yadavanup84/threat-engine:latest
docker push yadavanup84/threat-engine:latest
```

---

## First Scan (End-to-End)

Once everything is running:

```bash
# 1. Create a tenant
curl -X POST http://localhost:8010/api/v1/onboarding/tenants \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "my-org"}'

# 2. Onboard AWS account
curl -X POST http://localhost:8010/api/v1/onboarding/aws/init \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "YOUR_TENANT_ID", "account_id": "AWS_ACCOUNT_ID"}'

# 3. Run discovery
curl -X POST http://localhost:8001/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "YOUR_TENANT", "cloud": "aws", "accounts": ["AWS_ACCOUNT"]}'

# 4. Run check scan
curl -X POST http://localhost:8002/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "YOUR_TENANT", "scan_run_id": "DISCOVERY_SCAN_ID"}'

# 5. Generate threat report
curl -X POST http://localhost:8020/api/v1/threat/generate \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "YOUR_TENANT", "scan_run_id": "SCAN_RUN_ID", "cloud": "aws"}'

# 6. Build security graph
curl -X POST http://localhost:8020/api/v1/graph/build \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "YOUR_TENANT"}'
```

---

## IDE Setup

### VS Code (Recommended)

```json
// .vscode/settings.json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true
}
```

### PyCharm
1. Set project interpreter to `venv/bin/python`
2. Mark `engine_common/` and `consolidated_services/` as source roots
3. Set `PYTHONPATH=/path/to/threat-engine`

---

## Common Issues

| Issue | Solution |
|-------|----------|
| `psycopg2` build fails | Install `psycopg2-binary` instead |
| Port already in use | Check `lsof -i :8020` and kill process |
| DB connection refused | Ensure PostgreSQL is running and accepting connections |
| AWS credential error | Run `aws sts get-caller-identity` to verify credentials |
| Docker build context error | Build from repo root, not engine directory |
| Module not found | Set `PYTHONPATH=/path/to/threat-engine` |

See [Troubleshooting Guide](TROUBLESHOOTING.md) for more details.
