# CSPM Access URLs

## 🌐 Frontend UI

**Main Application URL:**
```
http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com
```

Open this URL in your browser to access the CSPM frontend interface.

## 🔌 Backend APIs

### Django Backend API
**Base URL:**
```
http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com
```

**Health Check:**
```bash
curl http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/health
```

**API Endpoints:**
- `/api/auth/` - Authentication
- `/api/tenants/` - Tenant management
- `/api/assets/` - Asset management
- `/api/threats/` - Threat management

### Onboarding API
**Base URL:**
```
http://a6ef376d197c54f9490ecb723e7f1910-493327827.ap-south-1.elb.amazonaws.com
```

**Health Check:**
```bash
curl http://a6ef376d197c54f9490ecb723e7f1910-493327827.ap-south-1.elb.amazonaws.com/api/v1/health
```

**API Documentation:**
```
http://a6ef376d197c54f9490ecb723e7f1910-493327827.ap-south-1.elb.amazonaws.com/docs
```

**API Endpoints:**
- `/api/v1/onboarding/accounts` - Account management
- `/api/v1/onboarding/schedules` - Schedule management
- `/api/v1/credentials` - Credential management

## 📊 Deployment Summary

### Namespaces

| Namespace | Pods | Status | Purpose |
|-----------|------|--------|---------|
| cspm | 3 | ✅ Running | Backend APIs (newly deployed) |
| cspm-ui | 1 | ✅ Running | Frontend UI (existing) |

### All Running Services

```bash
# View all services
kubectl get svc --all-namespaces | grep -E "cspm|LoadBalancer"
```

## 🎯 Quick Access

### Open Frontend UI
```bash
# macOS
open http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com

# Linux
xdg-open http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com

# Or just copy/paste in browser:
http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com
```

### Test Backend APIs
```bash
# Django health
curl http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/health

# Onboarding API health
curl http://a6ef376d197c54f9490ecb723e7f1910-493327827.ap-south-1.elb.amazonaws.com/api/v1/health

# Onboarding API docs (interactive)
open http://a6ef376d197c54f9490ecb723e7f1910-493327827.ap-south-1.elb.amazonaws.com/docs
```

## 🔍 Get URLs Anytime

```bash
# Frontend UI
kubectl get svc cspm-ui -n cspm-ui -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'

# Django Backend
kubectl get svc django-backend-external -n cspm -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'

# Onboarding API
kubectl get svc onboarding-api-external -n cspm -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

## ⚠️ Important Notes

1. **HTTP Only:** All endpoints are HTTP (not HTTPS)
   - For production, set up SSL/TLS certificates
   - Use AWS Certificate Manager + ALB Ingress

2. **Public Access:** LoadBalancers are publicly accessible
   - Consider adding security groups
   - Add authentication if needed

3. **Frontend Configuration:** 
   - UI may need to be configured to point to the new backend URLs
   - Check if API endpoints are hardcoded in the frontend

## 🔧 If Frontend Can't Connect to Backend

The frontend UI might be configured to connect to old backend URLs. To fix:

1. Check frontend configuration
2. Update API URLs to point to new backends
3. Rebuild frontend if needed

Let me know if you need help updating frontend configuration!

---
**Last Updated:** 2026-01-16 21:10

