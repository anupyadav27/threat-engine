# Engine User Portal (Web UI + Backend API)

> Multi-tenant SaaS portal with Django REST Framework backend and Next.js frontend for managing cloud security posture, compliance, and vulnerabilities.

---

## Overview

The User Portal is the primary user-facing interface for the CSPM platform. It provides:

- **Backend:** Django REST Framework API with JWT authentication, SAML/SSO (Okta), and multi-tenant isolation
- **Frontend:** Next.js (React) dashboard with pages for assets, threats, compliance, vulnerabilities, and settings

**Backend Port:** `8000` (Django)
**Frontend Port:** `3000` (Next.js)

---

## Architecture

```
  Browser (Next.js UI, port 3000)
        |
        v
  +----------------------------+
  |   Django Backend (port 8000)|
  |                              |
  |  Authentication (JWT/SAML)   |
  |  Tenant Management           |
  |  Engine API Proxying          |
  +----------------------------+
        |
        v
  Engine APIs (via HTTP clients)
  PostgreSQL (user/tenant data)
```

---

## Directory Structure

```
engine_userportal/
├── create_user.py              # Utility: create admin user
├── kubernetes/                 # K8s deployment manifests
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   └── configmap.yaml
├── backend/                    # Django REST API
│   ├── manage.py               # Django management command
│   ├── requirements.txt        # Python dependencies
│   ├── Dockerfile              # Container build
│   ├── cspm/                   # Django project config
│   │   ├── settings.py         # Database, auth, engine URLs
│   │   ├── urls.py             # Root URL routing
│   │   ├── wsgi.py             # WSGI entry point
│   │   ├── asgi.py             # ASGI entry point
│   │   └── health.py           # Health check endpoint
│   ├── user_auth/              # Authentication & JWT
│   │   ├── models.py           # Custom user model
│   │   ├── views.py            # Login, logout, token refresh
│   │   ├── urls.py             # Auth URL patterns
│   │   ├── serializers.py      # User serializers
│   │   ├── auth.py             # Cookie-based token auth
│   │   └── permissions.py      # Tenant-scoped permissions
│   ├── tenant_management/      # Multi-tenant management
│   │   ├── models.py           # Tenant, customer models
│   │   ├── views.py            # CRUD operations
│   │   ├── urls.py
│   │   └── serializers.py
│   ├── access_management/      # RBAC access control
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── assets_management/      # Asset inventory views
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── threats_management/     # Threat detection views
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── onboarding_management/  # Cloud account onboarding
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── scan_results_management/ # Scan results views
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── inventory_management/   # Inventory engine proxy
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── compliance_management/  # Compliance engine proxy
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── datasec_management/     # DataSec engine proxy
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── check_results_management/ # Check results views
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── discovery_results_management/ # Discovery results
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── secops_management/      # SecOps engine proxy
│   │   ├── models.py
│   │   ├── views.py            # Proxies to engine_secops API
│   │   └── urls.py
│   ├── vunerabilities_management/ # Vulnerability views
│   │   ├── models.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── audit_logs/             # Audit trail
│   │   ├── models.py
│   │   └── views.py
│   └── utils/
│       └── engine_clients.py   # HTTP clients for engine APIs
└── ui/                         # Next.js Frontend
    ├── package.json            # Node.js dependencies
    ├── next.config.mjs         # Next.js configuration
    ├── Dockerfile              # Frontend container build
    ├── compose.yaml            # Docker Compose for UI
    ├── public/
    │   ├── login-illustration.svg
    │   └── loader.svg
    └── src/
        ├── app/                # Next.js App Router pages
        │   ├── page.jsx        # Home / landing page
        │   ├── layout.js       # Root layout
        │   ├── auth/
        │   │   ├── login/      # Login page
        │   │   └── forget-password/
        │   ├── dashboard/      # Main dashboard
        │   ├── assets/         # Asset inventory page
        │   ├── threats/        # Threat detection page
        │   ├── policies/       # Policy management
        │   ├── compliances/    # Compliance reports
        │   ├── vulnerabilities/ # Vulnerability management
        │   ├── secops/         # SecOps scanner page
        │   ├── reports/        # Report generation
        │   ├── notifications/  # Alerts & notifications
        │   ├── profile/        # User profile
        │   ├── settings/
        │   │   ├── tenants/    # Tenant management
        │   │   └── users/      # User management
        │   └── test/           # Test pages
        ├── context/
        │   └── appContext/     # React context (auth, tenant state)
        ├── css/
        │   └── globals.css
        └── scss/
            ├── components/     # Component styles
            └── pages/          # Page-specific styles
```

---

## Backend API Endpoints

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login (returns JWT access + refresh tokens) |
| `POST` | `/api/auth/logout` | Logout (invalidate tokens) |
| `POST` | `/api/auth/token/refresh` | Refresh access token |
| `GET` | `/api/auth/me` | Get current user info |

### Management APIs

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/api/tenants/` | List / create tenants |
| `GET/POST` | `/api/assets/` | List / create assets |
| `GET/POST` | `/api/threats/` | List / view threats |
| `GET` | `/api/inventory/` | Inventory data (proxied) |
| `GET` | `/api/compliance/` | Compliance data (proxied) |
| `GET` | `/api/datasec/` | Data security data (proxied) |
| `GET` | `/api/secops/scans` | SecOps scans (proxied to engine_secops) |
| `GET` | `/health` | Health check |

---

## Authentication

### JWT Tokens

| Token | Lifetime | Storage |
|-------|----------|---------|
| Access Token | 15 minutes | HTTP-only cookie |
| Refresh Token | 7 days | HTTP-only cookie |

### SAML/SSO (Okta)

The backend supports SAML 2.0 integration with Okta for enterprise SSO:

- SAML assertion consumer service
- Automatic user provisioning from SAML attributes
- Tenant mapping from SAML claims

---

## Multi-Tenant Architecture

- Every user belongs to a tenant
- All API queries are automatically scoped by `tenant_id`
- Tenant-aware permissions via custom `TenantScopedPermission`
- No cross-tenant data access through the API

---

## Engine Integration

The backend proxies requests to engine APIs using HTTP clients:

```python
# utils/engine_clients.py
class EngineClient:
    THREAT_ENGINE_URL = settings.THREAT_ENGINE_URL    # http://engine-threat:8020
    COMPLIANCE_URL = settings.COMPLIANCE_ENGINE_URL    # http://engine-compliance:8005
    DATASEC_URL = settings.DATASEC_ENGINE_URL          # http://engine-datasec:8006
    INVENTORY_URL = settings.INVENTORY_ENGINE_URL      # http://engine-inventory:8004
    ONBOARDING_URL = settings.ONBOARDING_ENGINE_URL    # http://engine-onboarding:8010
    SECOPS_URL = settings.SECOPS_ENGINE_URL            # http://engine-secops:8000
```

---

## Configuration

### Backend Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string |
| `SECRET_KEY` | - | Django secret key |
| `DEBUG` | `False` | Debug mode |
| `ALLOWED_HOSTS` | `*` | Allowed hosts |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | CORS origins |
| `THREAT_ENGINE_URL` | `http://localhost:8020` | Threat engine URL |
| `COMPLIANCE_ENGINE_URL` | `http://localhost:8005` | Compliance engine URL |
| `DATASEC_ENGINE_URL` | `http://localhost:8006` | DataSec engine URL |
| `INVENTORY_ENGINE_URL` | `http://localhost:8004` | Inventory engine URL |
| `ONBOARDING_ENGINE_URL` | `http://localhost:8010` | Onboarding engine URL |
| `SECOPS_ENGINE_URL` | `http://localhost:8000` | SecOps engine URL |
| `USE_API_GATEWAY` | `false` | Route through API Gateway |
| `SAML_ENTITY_ID` | - | SAML entity ID (Okta) |
| `SAML_SSO_URL` | - | SAML SSO URL |

### Frontend Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend API URL |

---

## Running Locally

### Backend

```bash
cd engine_userportal/backend

# Install dependencies
pip install -r requirements.txt

# Set environment
export DATABASE_URL=postgresql://postgres:password@localhost:5432/cspm_portal
export SECRET_KEY=your-secret-key
export DEBUG=True

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Run server
python manage.py runserver 0.0.0.0:8000
```

### Frontend

```bash
cd engine_userportal/ui

# Install dependencies
npm install

# Set environment
echo 'NEXT_PUBLIC_API_URL=http://localhost:8000' > .env.local

# Run dev server
npm run dev
```

---

## Docker

### Backend

```bash
docker build -t userportal-backend -f engine_userportal/backend/Dockerfile engine_userportal/backend/
docker run -p 8000:8000 -e DATABASE_URL=... userportal-backend
```

### Frontend

```bash
docker build -t userportal-ui -f engine_userportal/ui/Dockerfile engine_userportal/ui/
docker run -p 3000:3000 userportal-ui
```

---

## UI Pages

| Page | Route | Description |
|------|-------|-------------|
| Login | `/auth/login` | Authentication page |
| Dashboard | `/dashboard` | Overview metrics and charts |
| Assets | `/assets` | Cloud resource inventory |
| Threats | `/threats` | Threat detections and analysis |
| Policies | `/policies` | Security policy management |
| Compliance | `/compliances` | Compliance framework reports |
| Vulnerabilities | `/vulnerabilities` | Vulnerability findings |
| SecOps | `/secops` | Code/IaC vulnerability scans |
| Reports | `/reports` | Generated reports |
| Notifications | `/notifications` | Alerts and notifications |
| Settings > Tenants | `/settings/tenants` | Tenant management |
| Settings > Users | `/settings/users` | User management |
| Profile | `/profile` | User profile settings |

---

## Django Apps

| App | Purpose | Has Models |
|-----|---------|------------|
| `user_auth` | JWT authentication, SAML SSO | Yes (Custom User) |
| `tenant_management` | Multi-tenant CRUD | Yes (Tenant, Customer) |
| `access_management` | RBAC permissions | Yes |
| `assets_management` | Asset inventory views | Yes |
| `threats_management` | Threat display | Yes |
| `onboarding_management` | Cloud account setup | Yes |
| `scan_results_management` | Scan results | Yes |
| `inventory_management` | Inventory proxy | No (API proxy) |
| `compliance_management` | Compliance proxy | No (API proxy) |
| `datasec_management` | DataSec proxy | No (API proxy) |
| `secops_management` | SecOps proxy | No (API proxy) |
| `check_results_management` | Check results | Yes |
| `discovery_results_management` | Discovery results | Yes |
| `vunerabilities_management` | Vulnerability data | Yes |
| `audit_logs` | Audit trail | Yes |
