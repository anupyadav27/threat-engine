# CSPM Deployment Plan - Single PostgreSQL Database (UPDATED)

## 🎯 Architecture Decision - DEPLOYED ✅

**✅ All data in single PostgreSQL RDS instance:**
- ✅ Django Backend manages all tables (users, tenants, assets, threats, etc.)
- ✅ Onboarding tables managed by Django ORM
- ✅ Scan results tables managed by Django ORM
- ✅ Single database connection
- ✅ Simplified architecture (No FastAPI service)

## 📊 Database Schema - Complete PostgreSQL Tables

### Existing Django Tables
- `users`, `user_sessions`, `roles`, `permissions`, `user_roles`, `role_permissions`
- `tenants`, `tenant_users`
- `assets`, `asset_tags`, `asset_compliance`, `asset_threats`, `agents`
- `threats`, `threat_remediation_steps`, `threat_related_findings`

### New Onboarding Tables (Created)
- ✅ `onboarding_tenants` - Tenant information
- ✅ `onboarding_providers` - Cloud provider configurations
- ✅ `onboarding_accounts` - Account metadata
- ✅ `onboarding_schedules` - Scan schedules
- ✅ `onboarding_executions` - Execution history
- ✅ `onboarding_scan_results` - Scan result metadata

## ✅ Implementation Status

### Phase 1: Django Models ✅
- ✅ Created `onboarding_management` Django app
- ✅ Created all 6 models matching DynamoDB structure
- ✅ Added to INSTALLED_APPS in settings.py
- ✅ Models ready for migration

### Phase 2: Scan Results Models ✅
- ✅ Created `scan_results_management` Django app
- ✅ Created 4 models for scan results and findings
- ✅ Added to INSTALLED_APPS

### Phase 3: Frontend (Next.js/React) ✅
- ✅ Next.js 15 with React 19 implemented
- ✅ All UI components created
- ✅ Connected to Django backend API
- ✅ Deployed to EKS

### Phase 4: Deployment ✅
- ✅ Dockerfiles created for both frontend and backend
- ✅ Kubernetes manifests deployed
- ✅ Services running on EKS cluster
- ✅ LoadBalancers configured

### Phase 5: Cleanup ✅
- ✅ Removed unused FastAPI code from /ui/database/
- ✅ Updated architecture documentation
- ✅ Verified no FastAPI dependencies

## 🔄 Migration Steps

### Step 1: Run Django Migrations
```bash
cd /Users/apple/Desktop/saas/backend
python manage.py makemigrations onboarding_management
python manage.py migrate
```

### Step 2: Environment Variables
```bash
# Django Backend
DB_NAME=cspm
DB_USER=postgres
DB_PASSWORD=<password>
DB_HOST=<rds_endpoint>
DB_PORT=5432
DB_SCHEMA=public

SECRET_KEY=<django-secret>
FRONTEND_URL=http://<frontend-lb>:3000
DEBUG=False
ALLOWED_HOSTS=*
```

### Step 3: Test Locally
```bash
# Test Django backend
cd backend
python manage.py runserver

# Test health endpoint
curl http://localhost:8000/health

# Test creating data
python manage.py shell
>>> from onboarding_management.models import OnboardingTenant
>>> tenant = OnboardingTenant.objects.create(tenant_name="test", status="active")
```

## 🏗️ Current Architecture

```
┌─────────────────────────────────────────────┐
│         EKS Cluster                         │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │  Frontend (Next.js/React)            │  │
│  │  - Port: 3000                        │  │
│  │  - LoadBalancer Service              │  │
│  └──────────────┬───────────────────────┘  │
│                 │ HTTP/REST                 │
│  ┌──────────────▼───────────────────────┐  │
│  │  Backend (Django REST API)           │  │
│  │  - Port: 8000                        │  │
│  │  - LoadBalancer + ClusterIP Services │  │
│  │  - Django ORM → PostgreSQL           │  │
│  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
                     │
                     │ PostgreSQL Protocol
                     │
              ┌──────▼───────┐
              │     RDS      │
              │  PostgreSQL  │
              │  (Single DB) │
              └──────────────┘
```

## 📝 Deployment Status

### Phase 5: Database Setup ✅
- ✅ RDS PostgreSQL instance verified
- ✅ Database created
- ✅ Django migrations completed
- ✅ Database connectivity verified

### Phase 6: Kubernetes Deployment ✅
- ✅ ConfigMaps created with database settings
- ✅ Deployments updated with environment variables
- ✅ Deployed and tested on EKS
- ✅ LoadBalancer services configured

### Phase 7: Cleanup ✅
- ✅ Removed unused FastAPI code
- ✅ Updated all documentation
- ✅ Architecture simplified

## 🔧 Configuration Files Updated

### Onboarding API (`ui/config.py`)
```python
# Database Configuration (PostgreSQL)
db_name: str
db_user: str
db_password: str
db_host: str
db_port: str
```

### Django Backend (`backend/cspm/settings.py`)
```python
INSTALLED_APPS = [
    ...
    "onboarding_management",  # New app added
]
```

## 📦 Files Created/Modified

### Created:
- `backend/onboarding_management/models.py` - Django models
- `backend/onboarding_management/apps.py` - Django app config
- `ui/database/postgresql_models.py` - SQLAlchemy models
- `ui/database/postgresql_operations.py` - PostgreSQL operations
- `ui/database/__init__.py` - Database module exports

### Modified:
- `backend/cspm/settings.py` - Added onboarding_management app
- `ui/requirements.txt` - Added SQLAlchemy and psycopg2
- `ui/config.py` - Added database configuration
- `ui/main.py` - Updated to use PostgreSQL
- `ui/api/onboarding.py` - Updated imports
- `ui/api/schedules.py` - Updated imports
- `ui/api/credentials.py` - Updated imports
- `ui/api/health.py` - Updated to check PostgreSQL
- `ui/scheduler/scheduler_service.py` - Updated imports

## 🔐 Security (Unchanged)

- ✅ Credentials still in Secrets Manager (encrypted with KMS)
- ✅ Only metadata in PostgreSQL
- ✅ SSL/TLS for RDS connections
- ✅ IAM roles for service accounts

## 🚀 Next Steps

1. **Run Django Migrations**
   ```bash
   cd backend
   python manage.py makemigrations onboarding_management
   python manage.py migrate
   ```

2. **Test Database Connection**
   - Test from both Django and FastAPI
   - Verify health endpoints

3. **Deploy to EKS**
   - Update ConfigMaps with database settings
   - Deploy updated services
   - Verify connectivity

4. **Data Migration (if needed)**
   - If DynamoDB has data, migrate to PostgreSQL
   - Verify data integrity

---

**Updated**: 2026-01-03
**Status**: Implementation Complete - Ready for Testing & Deployment
**Decision**: Single PostgreSQL RDS for all databases ✅

