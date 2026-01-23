# Database Migration Summary - DynamoDB to PostgreSQL

## ✅ Migration Complete

All onboarding data has been migrated from DynamoDB to PostgreSQL. The Django backend now manages all data in a single PostgreSQL RDS database.

## 📋 What Changed

### Before
- **Planned**: Separate DynamoDB for onboarding data
- **Django Backend**: Used PostgreSQL for data storage
- **Two separate databases**: DynamoDB + PostgreSQL (planned)

### After
- **Single Architecture**: All data in PostgreSQL (via Django ORM)
- **Django Backend**: Manages all tables including onboarding
- **Single database**: PostgreSQL RDS only
- **Unified Models**: Django models for all data

## 🗄️ Database Tables

### New Tables Created
All tables are in the `public` schema:

1. **onboarding_tenants**
   - Stores tenant information
   - Fields: id, tenant_name, description, status, created_at, updated_at

2. **onboarding_providers**
   - Stores cloud provider configurations
   - Fields: id, tenant_id, provider_type, status, created_at, updated_at

3. **onboarding_accounts**
   - Stores account metadata
   - Fields: id, provider_id, tenant_id, account_name, account_number, status, onboarding_status, last_validated_at, created_at, updated_at

4. **onboarding_schedules**
   - Stores scan schedules
   - Fields: id, tenant_id, account_id, name, description, schedule_type, cron_expression, interval_seconds, timezone, regions, services, exclude_services, status, enabled, last_run_at, next_run_at, run_count, success_count, failure_count, notify_on_success, notify_on_failure, notification_channels, created_at, updated_at

5. **onboarding_executions**
   - Stores execution history
   - Fields: id, schedule_id, account_id, started_at, completed_at, status, scan_id, total_checks, passed_checks, failed_checks, error_message, triggered_by, execution_time_seconds, created_at

6. **onboarding_scan_results**
   - Stores scan result metadata
   - Fields: id, account_id, execution_id, status, started_at, completed_at, metadata, created_at

## 📦 Code Changes

### Django Backend
- ✅ Created `onboarding_management` app
- ✅ Created 6 Django models for onboarding data
- ✅ Created `scan_results_management` app
- ✅ Created 4 Django models for scan results
- ✅ Added to INSTALLED_APPS
- ✅ Migrations completed
- ✅ All data managed through Django ORM

## 🔧 Environment Variables

### Required for Django Backend
```bash
# Database
DB_NAME=cspm
DB_USER=postgres
DB_PASSWORD=<password>
DB_HOST=<rds_endpoint>
DB_PORT=5432
DB_SCHEMA=public

# Frontend URL
FRONTEND_URL=http://<frontend-lb>:3000

# Security
SECRET_KEY=<django-secret-key>
DEBUG=False
ALLOWED_HOSTS=*
```

## 🚀 Deployment Steps

### 1. Run Django Migrations
```bash
cd /Users/apple/Desktop/saas/backend
python manage.py makemigrations onboarding_management
python manage.py migrate
```

### 2. Verify Tables Created
```sql
-- Connect to PostgreSQL
\dt onboarding_*

-- Should show:
-- onboarding_tenants
-- onboarding_providers
-- onboarding_accounts
-- onboarding_schedules
-- onboarding_executions
-- onboarding_scan_results
```

### 3. Test Django Backend
```bash
cd /Users/apple/Desktop/saas/backend
python manage.py runserver

# Test health endpoint
curl http://localhost:8000/health

# Should return:
# {"status": "ok"}
```

## 📊 Data Migration (If Needed)

If you have existing data in DynamoDB, you'll need to migrate it:

1. Export data from DynamoDB
2. Transform to match PostgreSQL schema
3. Import into PostgreSQL
4. Verify data integrity

**Note**: For fresh deployments, this step is not needed.

## ✅ Benefits

1. **Simplified Architecture**
   - Single database to manage
   - One connection pool
   - Easier backups

2. **Cost Savings**
   - No DynamoDB costs
   - Single RDS instance

3. **Better Relationships**
   - Can link onboarding data with Django data
   - Foreign keys between tables
   - Complex queries possible

4. **Easier Operations**
   - Single point of backup/restore
   - Unified monitoring
   - Simpler troubleshooting

## 🔐 Security

- ✅ Credentials still in Secrets Manager (encrypted with KMS)
- ✅ Only metadata in PostgreSQL
- ✅ SSL/TLS for RDS connections
- ✅ IAM roles for service accounts

## 📝 Files Created/Modified

### Created
- `backend/onboarding_management/models.py` - Onboarding data models
- `backend/onboarding_management/apps.py` - App configuration
- `backend/scan_results_management/models.py` - Scan results models
- `backend/scan_results_management/apps.py` - App configuration

### Modified
- `backend/cspm/settings.py` - Added new apps to INSTALLED_APPS
- All Django migrations created and applied

### Removed (Cleanup)
- `ui/database/postgresql_models.py` - Unused FastAPI models
- `ui/database/postgresql_operations.py` - Unused operations
- `ui/database/scan_results_models.py` - Unused models

## 🎯 Status

1. ✅ Code migration complete
2. ✅ Django migrations completed
3. ✅ Database connectivity verified
4. ✅ Deployed to EKS
5. ✅ All APIs working

---

**Migration Date**: 2026-01-03
**Updated**: 2026-01-16
**Status**: ✅ Complete - All services operational with PostgreSQL RDS

