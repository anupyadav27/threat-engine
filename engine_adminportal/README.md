# Admin Portal Backend

Django REST API backend for the CSPM Admin Portal providing real-time tenant monitoring, analytics, and management capabilities.

## Features

- **Real-time Tenant Monitoring** - Aggregate and monitor all tenants with live metrics
- **Analytics & Metrics** - Platform-wide analytics, compliance scores, scan statistics
- **User & Tenant Management** - Full CRUD operations for users and tenants
- **System Health Monitoring** - Monitor all engines, database, and services
- **Audit & Compliance** - Complete audit trail of admin actions

## Architecture

- **Framework:** Django 4.2 + Django REST Framework
- **Database:** PostgreSQL (shared with main backend)
- **Caching:** Redis
- **Task Queue:** Celery with Redis broker
- **Port:** 8001

## Project Structure

```
engine_adminportal/
├── admin_portal/          # Django project settings
├── apps/
│   ├── admin_monitoring/  # Real-time monitoring
│   ├── admin_analytics/   # Analytics & reporting
│   ├── admin_management/  # User/tenant management
│   ├── admin_audit/       # Audit logging
│   └── engine_integration/ # Engine clients
├── common/                # Shared utilities
├── requirements.txt
└── Dockerfile
```

## Setup

### Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export DB_NAME=cspm
export DB_USER=postgres
export DB_PASSWORD=your_password
export DB_HOST=localhost
export DB_PORT=5432
export REDIS_URL=redis://localhost:6379/1
export ADMIN_SECRET_KEY=your-secret-key
```

3. Run migrations:
```bash
python manage.py migrate
```

4. Start development server:
```bash
python manage.py runserver 0.0.0.0:8001
```

5. Start Celery worker (in separate terminal):
```bash
celery -A admin_portal worker --loglevel=info
```

6. Start Celery beat (in separate terminal):
```bash
celery -A admin_portal beat --loglevel=info
```

## API Endpoints

### Monitoring
- `GET /api/admin/tenants/` - List all tenants
- `GET /api/admin/tenants/{id}/status` - Tenant status
- `GET /api/admin/tenants/{id}/metrics` - Tenant metrics
- `GET /api/admin/dashboard/overview` - Dashboard overview

### Analytics
- `GET /api/admin/analytics/overview` - Platform overview
- `GET /api/admin/analytics/compliance` - Compliance stats
- `GET /api/admin/analytics/scans` - Scan statistics
- `GET /api/admin/analytics/trends` - Time-series trends
- `GET /api/admin/analytics/tenants/comparison` - Compare tenants

### Management
- `GET /api/admin/users/` - List users
- `POST /api/admin/users/` - Create user
- `PUT /api/admin/users/{id}/` - Update user
- `DELETE /api/admin/users/{id}/` - Deactivate user
- `GET /api/admin/users/{id}/tenants` - User's tenants
- `POST /api/admin/users/{id}/assign-tenant` - Assign tenant

### Health
- `GET /api/admin/health/engines` - Engine health
- `GET /api/admin/health/database` - DB health
- `GET /api/admin/health/summary` - System health

### Audit
- `GET /api/admin/audit/logs` - Audit logs
- `GET /api/admin/audit/logs/users/{id}` - User audit trail
- `GET /api/admin/audit/logs/tenants/{id}` - Tenant audit trail
- `GET /api/admin/audit/alerts` - System alerts

## Authentication

All endpoints require authentication. Use the same authentication mechanism as the main backend (JWT tokens or session-based).

## Permissions

- **super_admin** - Full access
- **admin** - User/tenant management, read-only system health
- **support_admin** - Read-only access, can view tenant data

## Background Tasks

Celery tasks run periodically:
- **Aggregate Tenant Metrics** - Every 30 seconds
- **Health Check Engines** - Every 60 seconds
- **Calculate Analytics** - Every 5 minutes
- **Cleanup Old Metrics** - Daily

## Deployment

See Kubernetes manifests in `kubernetes/admin-backend/` (or update path if moved):
- `admin-backend-deployment.yaml` - Main API service
- `admin-backend-service.yaml` - LoadBalancer service
- `celery-worker-deployment.yaml` - Celery worker
- `celery-beat-deployment.yaml` - Celery beat scheduler

## Database Migrations

Run migrations to create admin-specific tables:
```bash
python manage.py makemigrations
python manage.py migrate
```

This creates:
- `admin_metrics` - Cached metrics
- `admin_audit_logs` - Audit trail
- `admin_dashboards` - Saved dashboards
- `admin_alerts` - System alerts
- `admin_tenant_quotas` - Tenant quotas
