# CSPM Platform - Architecture Summary

**Last Updated:** 2026-01-16  
**Status:** ✅ Deployed and Operational

---

## 🏗️ Architecture Overview

Your CSPM (Cloud Security Posture Management) platform uses a **modern, industry-standard architecture**:

```
Users (Browser)
      ↓
Next.js Frontend (Port 3000)
      ↓ HTTP/REST API
Django Backend (Port 8000)
      ↓ PostgreSQL Protocol
PostgreSQL RDS Database
```

---

## 📁 Project Structure

### `/ui/` - Frontend
- **Technology:** Next.js 15.5.4 + React 19
- **Styling:** SCSS + Tailwind CSS
- **Port:** 3000
- **Purpose:** User interface for security dashboard, asset management, threats, vulnerabilities

### `/backend/` - Backend API
- **Technology:** Django 4.2 + Django REST Framework
- **Database:** PostgreSQL (via Django ORM)
- **Port:** 8000
- **Purpose:** All business logic, authentication, data management

### Database
- **Type:** PostgreSQL RDS
- **Port:** 5432
- **Schema:** public
- **Management:** Django migrations

---

## 🎨 Features Implemented

### Authentication & Authorization
- ✅ Local username/password authentication
- ✅ SAML 2.0 SSO (Okta integration)
- ✅ Role-Based Access Control (RBAC)
- ✅ Multi-tenant architecture
- ✅ Session management with JWT-like tokens

### Security Management
- ✅ **Asset Management:** Track cloud resources across providers
- ✅ **Threat Management:** Security threat database with remediation
- ✅ **Vulnerability Tracking:** Scan and monitor vulnerabilities
- ✅ **Compliance Monitoring:** Track compliance frameworks
- ✅ **Scan Results:** Store and display security scan findings

### User Management
- ✅ User creation and management
- ✅ Role assignment
- ✅ Permission management
- ✅ Tenant-user relationships

### Multi-Cloud Support
- ✅ AWS
- ✅ Azure
- ✅ GCP
- ✅ AliCloud
- ✅ OCI
- ✅ IBM Cloud

---

## 🗄️ Database Tables

### User & Access Management
- `users` - User accounts
- `user_sessions` - Active sessions
- `roles` - Role definitions
- `permissions` - Permission definitions
- `user_roles` - User-role mappings
- `role_permissions` - Role-permission mappings

### Multi-Tenancy
- `tenants` - Tenant/organization data
- `tenant_users` - Tenant-user relationships with roles

### Asset Management
- `assets` - Cloud asset inventory
- `asset_tags` - Asset tagging
- `asset_compliance` - Asset compliance status
- `asset_threats` - Asset-threat relationships
- `agents` - Monitoring agents

### Security & Threats
- `threats` - Threat intelligence database
- `threat_remediation_steps` - Remediation guidance
- `threat_related_findings` - Threat-finding relationships

### Onboarding & Scanning
- `onboarding_tenants` - Cloud account onboarding
- `onboarding_providers` - Provider configurations
- `onboarding_accounts` - Cloud account metadata
- `onboarding_schedules` - Scan schedules
- `onboarding_executions` - Scan execution history
- `onboarding_scan_results` - Scan result metadata

### Scan Results & Findings
- `scan_results` - Detailed scan metadata
- `scan_findings` - Individual security findings
- `scan_findings_assets` - Finding-asset links
- `compliance_summary` - Compliance scores by framework

---

## 🚀 Deployment Architecture

### Kubernetes (EKS)
```yaml
Namespace: cspm

Services:
  - Frontend Service (LoadBalancer)
    - Exposes Next.js UI on port 3000
  
  - Backend Service (LoadBalancer)
    - Exposes Django API on port 8000
  
  - Backend Internal (ClusterIP)
    - Internal pod-to-pod communication

Deployments:
  - cspm-frontend-deployment
  - django-backend-deployment

ConfigMaps:
  - Database configuration
  - Application settings

Secrets:
  - Database credentials
  - Django secret key
```

### External Services
- **PostgreSQL RDS:** Managed database (port 5432)
- **AWS Secrets Manager:** Credential storage (optional)

---

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/login/` - User login
- `POST /api/auth/logout/` - User logout
- `POST /api/auth/saml/` - SAML SSO

### Tenants
- `GET /api/tenants/` - List tenants
- `POST /api/tenants/` - Create tenant
- `GET /api/tenants/{id}/` - Get tenant details

### Assets
- `GET /api/assets/` - List assets
- `POST /api/assets/` - Create asset
- `GET /api/assets/{id}/` - Get asset details

### Threats
- `GET /api/threats/` - List threats
- `POST /api/threats/` - Create threat
- `GET /api/threats/{id}/` - Get threat details

### Health Check
- `GET /health` - Backend health status

---

## 🔐 Security Features

### Authentication
- Password hashing (Django's built-in)
- SAML 2.0 SSO support
- Session-based authentication
- Token refresh mechanism

### Authorization
- Role-Based Access Control (RBAC)
- Tenant-scoped permissions
- Fine-grained permission system

### Data Security
- PostgreSQL with SSL/TLS
- Environment-based configuration
- Secrets management via Kubernetes secrets

---

## 🛠️ Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Frontend Framework | Next.js | 15.5.4 |
| Frontend Library | React | 19.1.0 |
| Styling | SCSS + Tailwind | Latest |
| Charts | Chart.js | 4.5.1 |
| Backend Framework | Django | 4.2+ |
| REST API | Django REST Framework | 3.14+ |
| Database | PostgreSQL | 13+ |
| Container Platform | Kubernetes (EKS) | Latest |
| Container Runtime | Docker | Latest |
| Orchestration | Kubernetes | 1.28+ |

---

## 📊 Best Practices Implemented

### ✅ Architecture
- Separation of concerns (frontend/backend)
- RESTful API design
- Single database principle (simplified)
- Microservices-ready architecture

### ✅ Security
- SAML SSO for enterprise authentication
- RBAC for authorization
- Multi-tenant data isolation
- Environment-based secrets

### ✅ Development
- Django migrations for schema management
- Django admin for data management
- Modular app structure
- Clean code organization

### ✅ Deployment
- Containerized applications
- Kubernetes orchestration
- LoadBalancer services for external access
- ConfigMaps and Secrets for configuration

---

## 🎯 Access Information

### Frontend
- **URL:** `http://[ELB-DNS]:3000`
- **Login:** See `LOGIN_CREDENTIALS.md`

### Backend API
- **URL:** `http://[ELB-DNS]:8000`
- **Health:** `http://[ELB-DNS]:8000/health`
- **Admin:** `http://[ELB-DNS]:8000/admin`

### Database
- **Host:** RDS endpoint
- **Port:** 5432
- **Database:** cspm
- **Schema:** public

---

## 📚 Documentation Files

- `ARCHITECTURE_REVIEW.md` - Detailed architecture review
- `MIGRATION_SUMMARY.md` - Database migration history
- `DEPLOYMENT_PLAN_UPDATED.md` - Deployment procedures
- `API_ENDPOINTS.md` - API endpoint documentation
- `ACCESS_URLS.md` - Access URLs and credentials
- `LOGIN_CREDENTIALS.md` - User credentials
- `CODEBASE_CLEANUP_REPORT.md` - Recent cleanup changes

---

## 🔄 Recent Changes (2026-01-16)

### Cleanup Completed
- ✅ Removed unused FastAPI code from `/ui/database/`
- ✅ Updated all documentation to reflect actual architecture
- ✅ Clarified that `/ui/` is Next.js frontend (not FastAPI)
- ✅ Verified single database architecture (PostgreSQL only)

---

## 💡 Recommendations

### Naming Clarity
Consider renaming `/ui/` → `/frontend/` to avoid confusion about its purpose.

### Future Enhancements
1. Add API versioning (`/api/v1/`, `/api/v2/`)
2. Implement TypeScript for frontend
3. Add OpenAPI/Swagger documentation
4. Implement rate limiting
5. Add comprehensive logging and monitoring

---

**Summary:** You have a solid, production-ready CSPM platform with modern stack (Next.js + Django + PostgreSQL) deployed on Kubernetes!


