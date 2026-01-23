# CSPM API Endpoints Guide

## ⚠️ Important: Root URL Returns 404

If you visit the root URL directly, you'll see "Not Found". This is **normal** - Django only responds to specific API endpoints.

## 🌐 Frontend UI (Main Application)

**Access the UI here:**
```
http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com
```

This is the main web interface for the CSPM system.

## 🔌 Django Backend API

**Base URL:**
```
http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com
```

### Available Endpoints

#### Health Check
```bash
GET /health
curl http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/health

# Response: {"status": "healthy", "database": "connected"}
```

#### Authentication
```bash
# Get CSRF token
GET /api/auth/csrf/
curl http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/api/auth/csrf/

# Login
POST /api/auth/login/
curl -X POST http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Logout
POST /api/auth/logout/

# Refresh token
POST /api/auth/refresh/

# SAML Login
GET /api/auth/saml/login/
```

#### Tenant Management
```bash
# List tenants
GET /api/tenants/
curl http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/api/tenants/

# Get specific tenant
GET /api/tenants/{id}/

# Create tenant
POST /api/tenants/

# Update tenant
PUT /api/tenants/{id}/

# Delete tenant
DELETE /api/tenants/{id}/
```

#### Asset Management
```bash
# List assets
GET /api/assets/
curl http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/api/assets/

# Get asset
GET /api/assets/{id}/

# Create asset
POST /api/assets/

# Update asset
PUT /api/assets/{id}/
```

#### Threat Management
```bash
# List threats
GET /api/threats/
curl http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/api/threats/

# Get threat
GET /api/threats/{id}/
```

## 🔌 Onboarding API

**Base URL:**
```
http://a6ef376d197c54f9490ecb723e7f1910-493327827.ap-south-1.elb.amazonaws.com
```

### Interactive Documentation
```
http://a6ef376d197c54f9490ecb723e7f1910-493327827.ap-south-1.elb.amazonaws.com/docs
```

### Available Endpoints

#### Health Check
```bash
GET /api/v1/health
curl http://a6ef376d197c54f9490ecb723e7f1910-493327827.ap-south-1.elb.amazonaws.com/api/v1/health

# Response: {"status": "healthy", "postgresql": "connected", "version": "1.0.0"}
```

#### Account Management
```bash
# List accounts
GET /api/v1/onboarding/accounts

# Get account
GET /api/v1/onboarding/accounts/{account_id}

# Create account
POST /api/v1/onboarding/accounts

# Update account
PUT /api/v1/onboarding/accounts/{account_id}

# Delete account
DELETE /api/v1/onboarding/accounts/{account_id}
```

#### Schedule Management
```bash
# List schedules
GET /api/v1/onboarding/schedules

# Create schedule
POST /api/v1/onboarding/schedules

# Update schedule
PUT /api/v1/onboarding/schedules/{schedule_id}

# Delete schedule
DELETE /api/v1/onboarding/schedules/{schedule_id}

# Trigger manual scan
POST /api/v1/onboarding/schedules/{schedule_id}/trigger
```

#### Credential Management
```bash
# Store credentials
POST /api/v1/credentials/store

# Retrieve credentials
GET /api/v1/credentials/{credential_id}

# Delete credentials
DELETE /api/v1/credentials/{credential_id}
```

## 🧪 Quick Test Commands

```bash
# Test all health endpoints
echo "=== Testing Health Endpoints ==="
echo ""
echo "Django Backend:"
curl http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/health
echo ""
echo ""
echo "Onboarding API:"
curl http://a6ef376d197c54f9490ecb723e7f1910-493327827.ap-south-1.elb.amazonaws.com/api/v1/health
echo ""
```

## 📱 Access from Frontend

The frontend UI at:
```
http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com
```

Should be configured to call these backend APIs. If the UI can't connect to the backend, you may need to update the frontend's API configuration.

## 🔍 Debugging

If an endpoint returns 404:

1. **Check if endpoint exists:**
   ```bash
   kubectl logs -n cspm deployment/django-backend --tail=50
   ```

2. **Check URL patterns:**
   ```bash
   kubectl exec -n cspm deployment/django-backend -- python manage.py show_urls
   ```

3. **Check service routing:**
   ```bash
   kubectl get svc -n cspm
   kubectl describe svc django-backend-external -n cspm
   ```

## ⚠️ Why Root URL (/) Returns "Not Found"

Django is configured to only respond to specific API routes like:
- `/health`
- `/api/auth/...`
- `/api/tenants/...`
- etc.

**The root path `/` intentionally returns 404** because no route is defined for it.

**To access the application, use the Frontend UI URL instead!**

---

See `ACCESS_URLS.md` for the complete list of URLs and testing commands.

