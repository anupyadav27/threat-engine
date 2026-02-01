# EKS Mumbai - Service Endpoints & Access Guide

## Userportal (Already Deployed)

**Frontend UI (Login):**
```
http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com
```

**Login Credentials:**
- Email: `ayushajha11@gmail.com`
- Password: `Ayush@6112`

**Backend API (Django):**
```
http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com
```

**Status:** ✅ Both running. Login API tested and working.

**Why login might fail in browser:**
- Frontend may have hardcoded backend URLs that don't match current LoadBalancer
- Browser CORS/cookie issues
- Check browser console (F12) for API call errors

---

## Threat Engine Services (threat-engine-engines namespace)

### Public LoadBalancers (External Access)

| Service | External URL | Purpose |
|---------|--------------|---------|
| **Compliance** | aa1dc74e1d6ba4e60828e848961b0486-f791c5ca954eb41a.elb.ap-south-1.amazonaws.com | Compliance aggregator & reports |
| **Threat** | a4aec66fec6c2428bad95b5e2a3e79f2-1432128278.ap-south-1.amazonaws.com | Threat detection & analysis |
| **Inventory** | ad32c3340d6464bb9ad7a77b7e2628f4-236930058.ap-south-1.elb.amazonaws.com | Asset inventory & relationships |
| **Onboarding** | a2d474d5fbb694ac5a295b05ba4ee566-8ce5ff8e72034235.elb.ap-south-1.amazonaws.com | Account/credential onboarding |
| **YAML Rule Builder** | a3eb51946b3844b6fab26d8edae58faf-5e3a6f719e23be38.elb.ap-south-1.amazonaws.com | Custom rule builder |

### Cluster-Internal Services (Pod-to-Pod Communication)

| Service | Internal DNS | Port | Purpose |
|---------|-------------|------|---------|
| **AWS Engine** | aws-compliance-engine.threat-engine-engines.svc.cluster.local | 80 | AWS configscan |
| **Azure Engine** | azure-compliance-engine.threat-engine-engines.svc.cluster.local | 80 | Azure configscan |
| **GCP Engine** | gcp-compliance-engine.threat-engine-engines.svc.cluster.local | 80 | GCP configscan |
| **Alicloud Engine** | alicloud-compliance-engine.threat-engine-engines.svc.cluster.local | 80 | Alicloud configscan |
| **OCI Engine** | oci-compliance-engine.threat-engine-engines.svc.cluster.local | 80 | OCI configscan |
| **IBM Engine** | ibm-compliance-engine.threat-engine-engines.svc.cluster.local | 80 | IBM configscan |
| **Compliance** | compliance-engine.threat-engine-engines.svc.cluster.local | 80 | Compliance aggregator |
| **Threat** | threat-engine.threat-engine-engines.svc.cluster.local | 80 | Threat detection |
| **Inventory** | inventory-engine.threat-engine-engines.svc.cluster.local | 80 | Asset inventory |
| **Onboarding** | onboarding-api.threat-engine-engines.svc.cluster.local | 80 | Onboarding API |
| **Scheduler** | N/A (no service) | - | Background scheduler |
| **YAML Builder** | yaml-rule-builder.threat-engine-engines.svc.cluster.local | 80 | Rule builder |

---

## API Gateway (Not Yet Deployed)

API Gateway service is available at `api_gateway/` but **not deployed to EKS**.

To deploy:
1. Build image: `docker build -t yadavanup84/threat-engine-api-gateway:latest -f api_gateway/Dockerfile .`
2. Create deployment YAML in `deployment/aws/eks/api-gateway/`
3. Configure service routes to point to the cluster-internal services above

---

## Test Engine APIs

**Health checks:**
```bash
# AWS Engine
curl http://aws-compliance-engine.threat-engine-engines.svc.cluster.local/api/v1/health

# Compliance Engine  
curl http://aa1dc74e1d6ba4e60828e848961b0486-f791c5ca954eb41a.elb.ap-south-1.amazonaws.com/api/v1/health

# Onboarding API (external)
curl http://a2d474d5fbb694ac5a295b05ba4ee566-8ce5ff8e72034235.elb.ap-south-1.amazonaws.com/api/v1/health
```

**API docs (FastAPI interactive):**
```bash
# Onboarding (has Swagger UI)
open http://a2d474d5fbb694ac5a295b05ba4ee566-8ce5ff8e72034235.elb.ap-south-1.amazonaws.com/docs

# Compliance
open http://aa1dc74e1d6ba4e60828e848961b0486-f791c5ca954eb41a.elb.ap-south-1.amazonaws.com/docs
```

---

## RDS Database Access (DBeaver)

**Host:** postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com  
**Port:** 5432  
**Username:** postgres  
**Password:** `apXuHV%2OSyRWK62`  
**SSL:** require (cert: `/Users/apple/.postgresql/root.crt`)

**Databases:**
- `threat_engine_shared` - Tenants, customers, orchestration
- `threat_engine_configscan` - Scans, discoveries, check_results, rule_metadata
- `threat_engine_compliance` - Compliance outputs, control mappings
- `threat_engine_inventory` - Asset inventory
- `threat_engine_threat` - Threat intelligence

---

## Troubleshooting Userportal Login

**Login API works** (tested via curl), but browser login may fail if:

1. **Frontend can't reach backend** - check browser console (F12) for CORS/network errors
2. **Backend URL mismatch** - frontend might be configured with old backend URL
3. **Cookie/session issues** - try incognito mode

**Quick test:**
```bash
# Test login from command line (should return token)
curl -X POST http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "ayushajha11@gmail.com", "password": "Ayush@6112"}'
```

**If still failing:** Check frontend logs:
```bash
kubectl logs -n cspm-ui deployment/cspm-ui
```

Or verify frontend is pointing to correct backend URL in its configuration.
