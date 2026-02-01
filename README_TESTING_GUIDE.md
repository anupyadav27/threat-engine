# 🧪 Testing Guide - Database-First Architecture

**Engines:** Check + Discoveries  
**Database:** RDS (6 separate databases)  
**S3:** cspm-lgtech bucket (input/output sync)

---

## ✅ **System Status**

```
✅ engine-check-aws:        2/2 Running → RDS threat_engine_check
✅ engine-discoveries-aws:  2/2 Running → RDS threat_engine_discoveries
✅ api-gateway:             1/1 Running
```

---

## 🔄 **Test Flow: discoveries → check → compliance → threat**

### **Step 1: Run Discoveries Scan**

```bash
# Port forward
kubectl port-forward -n threat-engine-engines svc/engine-discoveries-aws 9001:80

# Run IAM discovery
curl -X POST http://localhost:9001/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "test-flow-001",
    "tenant_id": "test-flow-001",
    "provider": "aws",
    "hierarchy_id": "588989875114",
    "include_services": ["iam"],
    "include_regions": ["us-east-1"],
    "use_database": true
  }'

# Response: {"discovery_scan_id": "abc-123-xyz", "status": "running"}
# Save the discovery_scan_id!
```

**Verify in RDS:**
```sql
psql -h postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
  -U postgres -d threat_engine_discoveries \
  -c "SELECT scan_id, COUNT(*) as discoveries FROM discoveries GROUP BY scan_id ORDER BY scan_id DESC LIMIT 5;"
```

---

### **Step 2: Run Check Scan**

```bash
# Port forward
kubectl port-forward -n threat-engine-engines svc/engine-check-aws 9002:80

# Run checks (use discovery_scan_id from Step 1)
curl -X POST http://localhost:9002/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "discovery_scan_id": "abc-123-xyz",
    "customer_id": "test-flow-001",
    "tenant_id": "test-flow-001",
    "provider": "aws",
    "include_services": ["iam"]
  }'
```

**Verify in RDS:**
```sql
psql -h postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
  -U postgres -d threat_engine_check \
  -c "SELECT scan_id, status, COUNT(*) FROM check_results GROUP BY scan_id, status ORDER BY scan_id DESC LIMIT 10;"
```

---

### **Step 3: Use API Gateway Orchestrator** (Recommended)

```bash
# Get API Gateway LB URL
API_URL="http://a10e7f35b06794b81a4eec47e2e5da52-458521735.ap-south-1.elb.amazonaws.com"

# Run full orchestrated scan (all engines in sequence)
curl -X POST ${API_URL}/api/v1/orchestrate/scan \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "test-orchestrated-001",
    "tenant_id": "test-orchestrated-001",
    "provider": "aws",
    "services": ["iam", "s3"],
    "regions": ["us-east-1"],
    "engines": ["discoveries", "check", "compliance", "threat"]
  }'

# Check status
curl ${API_URL}/api/v1/orchestrate/scan/<scan-id>/status
```

---

## 📊 **Verify Data in RDS**

```sql
-- Check Database
\c threat_engine_check
SELECT COUNT(*) FROM rule_metadata;      -- Should be 1918
SELECT COUNT(*) FROM check_results;       -- Increases after check scans

-- Discoveries Database
\c threat_engine_discoveries
SELECT COUNT(*) FROM rule_definitions;    -- Should be 2501
SELECT COUNT(*) FROM discoveries;         -- Increases after discovery scans

-- Compliance Database
\c threat_engine_compliance
SELECT COUNT(*) FROM compliance_control_mappings;  -- Should be 960
```

---

## 📦 **Verify S3 Sync**

```bash
# Check if output is being synced
aws s3 ls s3://cspm-lgtech/engine_output/check-aws/ --recursive
aws s3 ls s3://cspm-lgtech/engine_output/discoveries-aws/ --recursive

# Check sidecar logs
kubectl logs -n threat-engine-engines -l app=engine-check-aws -c s3-sync --tail=20
kubectl logs -n threat-engine-engines -l app=engine-discoveries-aws -c s3-sync --tail=20
```

---

## 🎯 **Quick Health Checks**

```bash
# Check Engine
kubectl port-forward -n threat-engine-engines svc/engine-check-aws 9002:80 &
curl http://localhost:9002/api/v1/health

# Discoveries Engine
kubectl port-forward -n threat-engine-engines svc/engine-discoveries-aws 9001:80 &
curl http://localhost:9001/api/v1/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "provider": "aws",
  "version": "1.0.0",
  "database": "connected",
  "database_details": {}
}
```

---

**All systems ready for testing!** 🚀
