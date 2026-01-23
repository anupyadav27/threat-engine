# CSPM Architecture Review & Understanding

## 📁 Repository Structure

### `/ui` - Frontend (Next.js/React)

**Technology Stack:**
- Next.js 15.5.4 (React 19)
- SCSS + Tailwind CSS for styling
- Chart.js for data visualization
- Formik + Yup for form validation
- Context API for state management

**Key Features:**
- User authentication (login, SSO)
- Dashboard with security metrics
- Asset management interface
- Threat and vulnerability tracking
- Compliance reporting
- Multi-tenant management
- User and role management
- Real-time notifications

**Current Status:**
- ✅ Dockerfile exists (Node.js based)
- ✅ All components implemented
- ✅ Connected to Django backend API
- ✅ Deployed to EKS

---

### `/backend` - Django REST API

**Technology Stack:**
- Django REST Framework
- PostgreSQL (RDS) for data storage
- SAML authentication support (Okta)

**Key Apps:**
1. **user_auth** - User authentication and authorization
   - Users, Roles, Permissions
   - User sessions
   - SAML SSO integration

2. **tenant_management** - Multi-tenant support
   - Tenants
   - Tenant-user relationships

3. **assets_management** - Cloud asset tracking
   - Assets (compute, storage, database, network, security)
   - Asset tags
   - Asset compliance links
   - Asset threats
   - Agents

4. **threats_management** - Threat intelligence
   - Threats
   - Remediation steps
   - Threat-finding relationships

5. **access_management** - Access control
6. **audit_logs** - Audit logging
7. **vunerabilities_management** - Vulnerability tracking

**Data Storage:**
- Uses PostgreSQL (RDS) - **REQUIRES RDS SETUP**
- Multiple tables with relationships
- Uses UUIDs as primary keys

**Current Status:**
- ✅ Django project structure complete
- ✅ Models defined
- ✅ Settings configured for PostgreSQL
- ✅ Dockerfile exists
- ✅ requirements.txt exists
- ✅ Kubernetes manifests ready
- ✅ Deployed to EKS

---

## 🔗 Service Communication

### Application Flow
```
Users (Browser) → Next.js Frontend (Port 3000) → Django Backend API (Port 8000) → PostgreSQL RDS
```

### Kubernetes Services
- **Frontend Service (LoadBalancer):** External access to Next.js UI
- **Backend Service (LoadBalancer):** API access for frontend and external clients
- **Internal Service (ClusterIP):** Pod-to-pod communication within cluster

---

## 🗄️ Database Architecture

### PostgreSQL (RDS) - Django Backend

**Required Tables:**
- `users` - User accounts
- `user_sessions` - Active sessions
- `roles`, `permissions`, `user_roles`, `role_permissions` - RBAC
- `tenants` - Multi-tenant data
- `tenant_users` - Tenant-user mapping
- `assets`, `asset_tags`, `asset_compliance`, `asset_threats` - Asset management
- `agents` - Agent tracking
- `threats`, `threat_remediation_steps`, `threat_related_findings` - Threat management

**Connection Requirements:**
- Host: RDS endpoint
- Port: 5432
- Database: PostgreSQL 13+
- SSL: Recommended
- Schema: public (default)

### Additional PostgreSQL Tables - Onboarding & Scan Results

**Onboarding Tables:**
- `onboarding_tenants` - Tenant metadata for cloud account onboarding
- `onboarding_providers` - Cloud provider configurations
- `onboarding_accounts` - Cloud account details
- `onboarding_schedules` - Scan scheduling configuration
- `onboarding_executions` - Execution history
- `onboarding_scan_results` - Scan result metadata

**Scan Results Tables:**
- `scan_results` - Main scan metadata
- `scan_findings` - Individual compliance check results
- `scan_findings_assets` - Links findings to assets
- `compliance_summary` - Compliance framework summaries

**Status:** All tables in PostgreSQL RDS (single database architecture)

---

## 🚀 Deployment Architecture

### EKS Cluster Setup

```
┌─────────────────────────────────────────────┐
│         EKS Cluster                         │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │  Namespace: cspm                       │  │
│  │                                        │  │
│  │  ┌──────────────────────────────────┐ │  │
│  │  │  Frontend (Next.js/React)        │ │  │
│  │  │  - Deployment                    │ │  │
│  │  │  - Service (LoadBalancer)        │ │  │
│  │  │  - Port: 3000                    │ │  │
│  │  └──────────────────────────────────┘ │  │
│  │                 ↓ HTTP/REST            │  │
│  │  ┌──────────────────────────────────┐ │  │
│  │  │  Backend (Django REST API)       │ │  │
│  │  │  - Deployment                    │ │  │
│  │  │  - Service (LoadBalancer)        │ │  │
│  │  │  - Service (ClusterIP)           │ │  │
│  │  │  - Port: 8000                    │ │  │
│  │  └──────────────────────────────────┘ │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
                     │
                     │ PostgreSQL Protocol
                     │
              ┌──────▼───────┐
              │     RDS      │
              │  PostgreSQL  │
              │   (Port 5432)│
              └──────────────┘
```

### Service Types

1. **LoadBalancer Services** (External Access)
   - `cspm-frontend-service` - Next.js UI (http://[ELB-DNS]:3000)
   - `django-backend-service` - Django API (http://[ELB-DNS]:8000)

2. **ClusterIP Services** (Internal)
   - `django-backend-internal` - Pod-to-pod communication within cluster

---

## 📋 Current Status

### ✅ Completed
1. ✅ Frontend (Next.js/React) fully implemented and deployed
2. ✅ Django backend with complete model definitions
3. ✅ PostgreSQL RDS database (single database architecture)
4. ✅ All Dockerfiles created
5. ✅ Kubernetes manifests deployed
6. ✅ Services running on EKS cluster
7. ✅ Multi-tenant architecture implemented
8. ✅ RBAC and authentication working
9. ✅ Asset and threat management functional

### 🎯 Architecture Highlights
- **Single Database:** All data in PostgreSQL (no DynamoDB)
- **Modern Stack:** Next.js 15 + React 19 + Django 4.2
- **Cloud-Native:** Containerized and deployed on EKS
- **Secure:** SAML SSO, RBAC, encrypted secrets

---

## 🎯 Access Information

### Frontend Access
- URL: http://[LoadBalancer-ELB-DNS]:3000
- Login with credentials from LOGIN_CREDENTIALS.md

### Backend API Access
- URL: http://[LoadBalancer-ELB-DNS]:8000
- Health Check: http://[LoadBalancer-ELB-DNS]:8000/health
- API Endpoints: See API_ENDPOINTS.md

### Database Access
- Host: RDS endpoint from AWS Console
- Port: 5432
- Database: cspm
- Schema: public

---

**Last Updated**: 2026-01-16
**Status**: ✅ Deployed and Operational

