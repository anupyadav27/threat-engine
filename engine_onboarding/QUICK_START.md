# Quick Start - Local Testing

## One-Command Test

```bash
cd /Users/apple/Desktop/onboarding
./quick_test.sh
```

This script will:
1. Start PostgreSQL database
2. Initialize database schema
3. Start all three services (Onboarding, AWS Engine, YAML Builder)
4. Run automated tests

## Manual Step-by-Step

### 1. Start Database

```bash
cd /Users/apple/Desktop/onboarding
docker-compose -f docker-compose.db.yml up -d
```

### 2. Initialize Database Schema

```bash
cd /Users/apple/Desktop/onboarding
python3 -c "from onboarding.database.connection import init_db; init_db()"
```

### 3. Start Services (3 terminals)

**Terminal 1 - Onboarding API:**
```bash
cd /Users/apple/Desktop/onboarding
python3 main.py
```

**Terminal 2 - AWS Engine API:**
```bash
cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine
PORT=8001 python3 api_server.py
```

**Terminal 3 - YAML Rule Builder API:**
```bash
cd /Users/apple/Desktop/threat-engine/yaml-rule-builder
PORT=8002 python3 api_server.py
```

### 4. Run Tests

**Terminal 4:**
```bash
cd /Users/apple/Desktop/onboarding
python3 test_local.py
```

## Test What You'll See

The test script will verify:

✅ **Onboarding API** - Health check, tenant creation, AWS onboarding initialization  
✅ **AWS Engine API** - Health check, service listing, scan creation, metrics  
✅ **YAML Rule Builder** - Health check, service listing, field retrieval, rule validation, rule generation

## Expected Output

```
======================================================================
Threat Engine Local Testing
======================================================================

[1] Testing Onboarding API Health
✓ Onboarding API is healthy: {'status': 'healthy', 'service': 'onboarding-api'}

[2] Testing AWS Engine API Health
✓ AWS Engine API is healthy: {'status': 'healthy', 'provider': 'aws', 'version': '1.0.0'}

[3] Testing YAML Rule Builder API Health
✓ YAML Rule Builder API is healthy: {'status': 'healthy', 'service': 'yaml-rule-builder', 'version': '1.0.0'}

[4] Creating Test Tenant
✓ Tenant created: <tenant-id>

[5] Initializing AWS Account Onboarding
✓ AWS onboarding initialized: {'account_id': '...', 'external_id': '...'}

...
```

## Troubleshooting

### Database Connection Error
```bash
# Check if database is running
docker ps | grep postgres

# Check connection
psql -h localhost -U threatengine -d threatengine -c "SELECT 1;"
```

### Port Already in Use
```bash
# Find what's using the port
lsof -i :8000
lsof -i :8001
lsof -i :8002

# Kill the process or use different ports
```

### Import Errors
```bash
# Make sure you're in the right directory
cd /Users/apple/Desktop/onboarding

# Install dependencies
pip install -r requirements.txt
```

## Next: Test with Real Credentials

Once basic tests pass, you can test with real AWS credentials:

1. Deploy CloudFormation template to get Role ARN and External ID
2. Update test script with real credentials
3. Run actual scans

See `TESTING_GUIDE.md` for detailed instructions.

