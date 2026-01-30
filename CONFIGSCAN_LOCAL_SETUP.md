# 🚀 ConfigScan Service - Local Setup Guide

This guide walks you through setting up and running the **consolidated ConfigScan service** locally against a PostgreSQL database.

## 📋 Prerequisites

1. **PostgreSQL** installed and running
   ```bash
   # macOS
   brew install postgresql
   brew services start postgresql
   
   # Or check if running
   pg_isready -h localhost -p 5432
   ```

2. **Python 3.11+** installed
   ```bash
   python3 --version
   ```

3. **Git repository** cloned and current directory set to project root
   ```bash
   cd /Users/apple/Desktop/threat-engine
   ```

## 🗄️ Step 1: Set up ConfigScan Database

Run the automated database setup:

```bash
# First time setup
./scripts/run-configscan-local.sh setup
```

**This script will:**
- ✅ Run `scripts/init-databases.sql` (single-DB, `engine_*` schemas)
- ✅ Set up `engine_configscan` tables (scans, discoveries, check_results, etc.) and `engine_shared` (tenants, customers)
- ✅ Create Python virtual environment and install dependencies
- ✅ Generate `.env` configuration file

**Manual Database Setup (if needed):**
```bash
psql -U postgres -d postgres -f scripts/init-databases.sql
# Or: psql -U $(whoami) -d postgres -f scripts/init-databases.sql
```

## 🚀 Step 2: Start ConfigScan Service

Start the service:

```bash
./scripts/run-configscan-local.sh start
```

The service will start on **http://localhost:8002**

**Expected Output:**
```
🚀 ConfigScan Service Starting...

Service URL: http://localhost:8002
Health Check: http://localhost:8002/health
API Docs: http://localhost:8002/docs

Press Ctrl+C to stop
```

## 🧪 Step 3: Test the Service

In a **new terminal**, run the test suite:

```bash
./scripts/test-configscan-service.py
```

**Expected Test Results:**
```
🧪 Starting ConfigScan Service Tests
==================================================
🔍 Testing health endpoint...
✅ Health check passed: healthy
   Available scanners: ['aws', 'azure', 'gcp']

🔍 Testing service info...
✅ Service info: configscan-service v2.0.0

🔍 Testing scanner availability...
✅ Scanner registry loaded
   ✅ AWS Scanner
      Services: s3, ec2, iam, vpc, rds
      Regions: us-east-1, us-west-2, eu-west-1...

🔍 Testing database connection...
✅ Database connection working
   Found 0 scans for tenant test-tenant-aws

🔍 Testing scan creation...
✅ Scan creation successful: configscan-abc123

==================================================
🧪 Test Results: 6/6 tests passed
🎉 All tests passed! ConfigScan service is working correctly.
```

## 📡 Step 4: Test API Endpoints

### Health Check
```bash
curl http://localhost:8002/health
```

### Service Info
```bash
curl http://localhost:8002/
```

### Available Scanners
```bash
curl http://localhost:8002/scanners
```

### Create a Test Scan
```bash
curl -X POST http://localhost:8002/scan \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "test-tenant-aws",
    "customer_id": "test-customer-1", 
    "csp": "aws",
    "account_id": "123456789012",
    "regions": ["us-east-1"],
    "services": ["s3", "ec2"],
    "scan_type": "discovery",
    "mock_scan": true
  }'
```

### Get Scan Status
```bash
# Replace {scan_id} with the ID from the previous response
curl http://localhost:8002/scans/{scan_id}
```

### List Scans
```bash
curl "http://localhost:8002/scans?tenant_id=test-tenant-aws"
```

## 🌐 Step 5: API Documentation

Open the interactive API documentation:
- **Swagger UI**: http://localhost:8002/docs
- **ReDoc**: http://localhost:8002/redoc

## 🔧 Configuration

The service configuration is stored in:
```
consolidated_services/configscan_service/.env
```

**Key Configuration Options:**
```env
# Database (single-DB, engine_configscan schema)
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres
DB_SCHEMA=engine_configscan,engine_shared

# Service
PORT=8002
ENVIRONMENT=development
LOG_LEVEL=DEBUG

# CSP Credentials (add for real scans)
# AWS_ACCESS_KEY_ID=your-key
# AWS_SECRET_ACCESS_KEY=your-secret
# AZURE_SUBSCRIPTION_ID=your-subscription
# GCP_PROJECT_ID=your-project
```

## 📊 Database Structure (single-DB, engine_* schemas)

ConfigScan uses the `postgres` database with these schemas/tables:

- **`engine_shared.customers`** - Customer accounts
- **`engine_shared.tenants`** - Tenant/CSP relationships  
- **`engine_configscan.csp_hierarchies`** - Account/Project hierarchies
- **`engine_configscan.scans`** - Scan execution records
- **`engine_configscan.discoveries`** - Resource discovery results
- **`engine_configscan.check_results`** - Compliance check results
- **`engine_configscan.discovery_history`** - Change tracking

**Test Data Included:**
- Customer: `test-customer-1`, `test-customer-2`
- Tenants: `test-tenant-aws`, `test-tenant-azure`, `test-tenant-gcp`
- Hierarchies: Pre-configured accounts/projects for each CSP

## 🔍 Troubleshooting

### Service Won't Start
```bash
# Check if PostgreSQL is running
pg_isready -h localhost -p 5432

# Test database connection
./scripts/run-configscan-local.sh test-db

# Reset database if needed
./scripts/run-configscan-local.sh reset-db
```

### Import Errors
```bash
# Reinstall dependencies
cd consolidated_services/configscan_service
source venv/bin/activate
pip install -r requirements.txt
```

### Database Connection Issues
```bash
# Check engine_* schemas exist (single-DB)
psql -U postgres -d postgres -c "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'engine_%' ORDER BY 1;"

# Test connection
psql -U postgres -d postgres -c "SELECT 1"
```

### Port Already in Use
```bash
# Kill any process using port 8002
lsof -ti:8002 | xargs kill -9

# Or change port in .env file
echo "PORT=8003" >> consolidated_services/configscan_service/.env
```

## 📝 Logs

Service logs are displayed in the terminal. For persistent logging:

```bash
# Run with log file
./scripts/run-configscan-local.sh start 2>&1 | tee configscan.log
```

## 🎯 Next Steps

Once ConfigScan is running successfully:

1. **Add Real CSP Credentials** to `.env` for actual scanning
2. **Test with Real CSP Accounts** using the API endpoints
3. **Set up Core Engine Service** following similar steps
4. **Configure API Gateway** to route to local services

## 🚀 Production Deployment

When ready for production:

```bash
# Build Docker image
cd consolidated_services/configscan_service
docker build -t threat-engine/configscan-service:latest .

# Deploy to Kubernetes
kubectl apply -f ../../deployment/kubernetes/configscan-service-deployment.yaml
```

---

**🎉 Your ConfigScan service is now running locally and ready for testing!**

Access the service at **http://localhost:8002** and use the interactive documentation at **http://localhost:8002/docs** to explore all available endpoints.