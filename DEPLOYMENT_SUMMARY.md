# EKS Mumbai Deployment - Summary & Status

## Deployment Complete ✅

**Cluster:** vulnerability-eks-cluster (ap-south-1)  
**Namespace:** threat-engine-engines  
**Date:** 2026-01-30

---

## What Was Done

### 1. S3 & RDS Setup
- ✅ S3 bucket `cspm-lgtech` (ap-south-1) - verified, engine prefixes created
- ✅ Vul DB backup: `s3://cspm-lgtech/vul-db-backup/vulnerability_db_20260130_140717.sql` (~1.87 GB)
- ✅ RDS databases created on postgres-vulnerability-db (5 threat_engine_* databases):
  - threat_engine_shared (14 tables - tenants, providers, accounts, schedules, executions, scan_results, orchestration, audit)
  - threat_engine_configscan (10 tables - scans, discoveries, check_results, rule_metadata)
  - threat_engine_compliance (12 tables - reports, findings, controls, mappings)
  - threat_engine_inventory (10 tables - assets, relationships, collections)
  - threat_engine_threat (11 tables - threats, detections, analysis, hunt)

### 2. Docker Images
- ✅ All 13 images built and pushed to Docker Hub (yadavanup84):
  - 6 CSP engines (AWS, Azure, GCP, OCI, IBM, Alicloud*)
  - Compliance, Threat, Inventory engines
  - Onboarding API, Scheduler, YAML Rule Builder
  - **API Gateway** (NEW)

### 3. K8s Deployment
- ✅ ConfigMaps: platform-config, s3-mount-config, threat-engine-db-config
- ✅ Secrets: database-credentials, threat-engine-db-passwords, s3-credentials, aws-scan-credentials
- ✅ Service Accounts: aws-compliance-engine-sa, threat-engine-sa, inventory-engine-sa
- ✅ All deployments set to **replicas: 1** (minimal resources for dev)

### 4. Running Services (11/13 pods)

| Service | Status | Port | External URL |
|---------|--------|------|--------------|
| AWS Engine | ✅ Running | 80 | aws-compliance-engine.svc.cluster.local |
| Azure Engine | ✅ Running | 80 | azure-compliance-engine.svc.cluster.local |
| GCP Engine | ✅ Running | 80 | gcp-compliance-engine.svc.cluster.local |
| OCI Engine | ✅ Running | 80 | oci-compliance-engine.svc.cluster.local |
| IBM Engine | ✅ Running | 80 | ibm-compliance-engine.svc.cluster.local |
| Alicloud Engine | ⚠️  CrashLoop | - | (auth module issue) |
| Compliance Engine | ✅ Running | 80 | aa1dc74e1d6ba4e60828e848961b0486-f791c5ca954eb41a.elb.ap-south-1.amazonaws.com |
| Threat Engine | ✅ Running | 80 | a4aec66fec6c2428bad95b5e2a3e79f2-1432128278.ap-south-1.amazonaws.com |
| Inventory Engine | ✅ Running | 80 | ad32c3340d6464bb9ad7a77b7e2628f4-236930058.ap-south-1.elb.amazonaws.com |
| Scheduler | ✅ Running | - | (background service) |
| YAML Rule Builder | ✅ Running | 80 | a3eb51946b3844b6fab26d8edae58faf-5e3a6f719e23be38.elb.ap-south-1.amazonaws.com |
| **API Gateway** | ✅ Running | 80 | a10e7f35b06794b81a4eec47e2e5da52-458521735.ap-south-1.elb.amazonaws.com |
| Onboarding API | ⚠️  Pending | - | (being replaced) |

---

## Test Scan Executed

**Scan ID:** `bcee5097-b2b9-47b7-a0c0-b690c5a873b6`  
**Status:** Running (0% complete, 0/104 services)  
**Account:** 588989875114  
**Regions:** ap-south-1  
**Services:** S3, EC2, IAM  
**Output:** `/output/bcee5097-b2b9-47b7-a0c0-b690c5a873b6/` (discoveries.ndjson, results.ndjson created)

### Why Database is Empty

**The AWS engine writes scan results to files** (/output/*.ndjson) but **does not automatically upload to the database**. The DatabaseUploadEngine exists but needs to be called explicitly (line 127-164 in api_server.py shows it's only used in a specific endpoint, not automatically after scans).

**Two options:**
1. **Wait for scan to complete** and trigger database upload via API
2. **Modify engine** to auto-upload to DB after scan completion

---

## Access Information

### RDS (DBeaver)
- **Host:** postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
- **Port:** 5432
- **Username:** postgres
- **Password:** `apXuHV%2OSyRWK62`
- **SSL Cert:** /Users/apple/.postgresql/root.crt
- **Databases:** threat_engine_shared, threat_engine_configscan, threat_engine_compliance, threat_engine_inventory, threat_engine_threat

### Userportal (cspm/cspm-ui namespaces)
- **UI:** http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com
- **Login:** ayushajha11@gmail.com / Ayush@6112
- **Backend:** http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com

### API Gateway (Orchestration)
- **URL:** http://a10e7f35b06794b81a4eec47e2e5da52-458521735.ap-south-1.elb.amazonaws.com
- **Health:** /gateway/health
- **Services:** /gateway/services
- **Orchestrate:** POST /gateway/orchestrate
- **Docs:** Not available (FastAPI docs not enabled in current build)

### Individual Engine APIs
All accessible at `<engine-name>.threat-engine-engines.svc.cluster.local:80` (cluster-internal)

---

## Current Blocker

**Database upload is manual** - scan results are in files but not in database tables. Need to either:
1. Call database upload API endpoint after scan completes, or
2. Engines need modification to auto-upload to DB after each scan

Once scan completes and uploads to DB, the Compliance/Threat/Inventory engines can process the data.
