# Kubernetes Service Endpoints for Container Communication

**Date:** 2026-01-17  
**Purpose:** Service DNS names and endpoints for EKS container-to-container communication

---

## 🎯 **Service Endpoints**

### **1. Backend Service (Django)**

**Service Name:** `django-backend`  
**Namespace:** `cspm`  
**Type:** ClusterIP  
**Port:** `8000`

#### **DNS Endpoints (Use these in your containers):**

```bash
# Full DNS name (works from any namespace)
http://django-backend.cspm.svc.cluster.local:8000

# Short name (works from same namespace)
http://django-backend:8000

# Namespace-qualified (works from any namespace)
http://django-backend.cspm:8000
```

#### **ClusterIP:**
```
10.100.146.175:8000
```

---

### **2. Frontend Service (UI)**

**Service Name:** `cspm-ui`  
**Namespace:** `cspm-ui`  
**Type:** LoadBalancer  
**Port:** `80`

#### **DNS Endpoints (Use these in your containers):**

```bash
# Full DNS name (works from any namespace)
http://cspm-ui.cspm-ui.svc.cluster.local:80

# Short name (works from same namespace)
http://cspm-ui:80

# Namespace-qualified (works from any namespace)
http://cspm-ui.cspm-ui:80
```

#### **ClusterIP:**
```
10.100.66.54:80
```

---

## 📝 **Usage Examples**

### **From Backend Container (cspm namespace):**

```python
# Python example
import requests

# Call frontend (cross-namespace)
frontend_url = "http://cspm-ui.cspm-ui.svc.cluster.local:80"
response = requests.get(f"{frontend_url}/api/health")

# Call another backend service (same namespace)
backend_url = "http://django-backend:8000"
response = requests.get(f"{backend_url}/api/health")
```

### **From Frontend Container (cspm-ui namespace):**

```javascript
// JavaScript/Next.js example

// Call backend API (cross-namespace)
const backendUrl = process.env.BACKEND_URL || 
  "http://django-backend.cspm.svc.cluster.local:8000";

fetch(`${backendUrl}/api/health`)
  .then(res => res.json())
  .then(data => console.log(data));
```

### **Environment Variables (Recommended):**

```yaml
# In your deployment YAML
env:
  - name: BACKEND_URL
    value: "http://django-backend.cspm.svc.cluster.local:8000"
  - name: FRONTEND_URL
    value: "http://cspm-ui.cspm-ui.svc.cluster.local:80"
```

---

## 🔗 **Service Communication Matrix**

| From Container | To Service | DNS Name | Port |
|----------------|------------|----------|------|
| **Backend** (cspm) | Backend | `django-backend` or `django-backend.cspm` | 8000 |
| **Backend** (cspm) | Frontend | `cspm-ui.cspm-ui` | 80 |
| **Frontend** (cspm-ui) | Backend | `django-backend.cspm` | 8000 |
| **Frontend** (cspm-ui) | Frontend | `cspm-ui` or `cspm-ui.cspm-ui` | 80 |

---

## ✅ **Quick Reference**

### **Backend API Endpoint:**
```
http://django-backend.cspm.svc.cluster.local:8000
```

### **Frontend Endpoint:**
```
http://cspm-ui.cspm-ui.svc.cluster.local:80
```

---

## 🚀 **Best Practices**

1. **Use DNS names, not IPs** - ClusterIPs can change
2. **Use full DNS names for cross-namespace** - Most reliable
3. **Set environment variables** - Makes it configurable
4. **Use short names within same namespace** - Cleaner code
5. **Always include port** - Required for service communication

---

## 📋 **Current Service Status**

```bash
# Check services
kubectl get services -n cspm
kubectl get services -n cspm-ui

# Test connectivity from a pod
kubectl exec -it <pod-name> -n <namespace> -- curl http://django-backend.cspm.svc.cluster.local:8000/health
```

---

**Status:** ✅ Ready for container-to-container communication


