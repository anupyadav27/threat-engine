# GCP Service Validation Tracker

## Progress Tracking

**Last Updated:** 2025-12-06

### 📊 Overview

**Total Services:** 48  
**Total Checks:** 1,557  
**Validated Services:** 0  
**Pending Services:** 48  

---

## 📋 All Services

| Service | Total Checks | Status | Validated Date |
|---------|--------------|--------|----------------|
| accessapproval | 1 | ⏳ PENDING | - |
| aiplatform | 183 | ⏳ PENDING | - |
| apigateway | 19 | ⏳ PENDING | - |
| apigee | 11 | ⏳ PENDING | - |
| apikeys | 5 | ⏳ PENDING | - |
| appengine | 8 | ⏳ PENDING | - |
| artifactregistry | 15 | ⏳ PENDING | - |
| asset | 11 | ⏳ PENDING | - |
| backupdr | 25 | ⏳ PENDING | - |
| bigquery | 71 | ⏳ PENDING | - |
| bigtable | 4 | ⏳ PENDING | - |
| billing | 17 | ⏳ PENDING | - |
| certificatemanager | 5 | ⏳ PENDING | - |
| cloudfunctions | 15 | ⏳ PENDING | - |
| cloudidentity | 8 | ⏳ PENDING | - |
| cloudkms | 18 | ⏳ PENDING | - |
| cloudsql | 84 | ⏳ PENDING | - |
| compute | 270 | ⏳ PENDING | - |
| container | 130 | ⏳ PENDING | - |
| datacatalog | 146 | ⏳ PENDING | - |
| dataflow | 31 | ⏳ PENDING | - |
| dataproc | 25 | ⏳ PENDING | - |
| datastudio | 4 | ⏳ PENDING | - |
| dlp | 10 | ⏳ PENDING | - |
| dns | 19 | ⏳ PENDING | - |
| elasticsearch | 4 | ⏳ PENDING | - |
| endpoints | 5 | ⏳ PENDING | - |
| essentialcontacts | 1 | ⏳ PENDING | - |
| filestore | 3 | ⏳ PENDING | - |
| firestore | 11 | ⏳ PENDING | - |
| gcs | 60 | ⏳ PENDING | - |
| healthcare | 4 | ⏳ PENDING | - |
| iam | 81 | ⏳ PENDING | - |
| logging | 48 | ⏳ PENDING | - |
| monitoring | 46 | ⏳ PENDING | - |
| multi | 1 | ⏳ PENDING | - |
| notebooks | 12 | ⏳ PENDING | - |
| osconfig | 13 | ⏳ PENDING | - |
| pubsub | 27 | ⏳ PENDING | - |
| resourcemanager | 52 | ⏳ PENDING | - |
| secretmanager | 24 | ⏳ PENDING | - |
| securitycenter | 38 | ⏳ PENDING | - |
| services | 3 | ⏳ PENDING | - |
| spanner | 1 | ⏳ PENDING | - |
| storage | 60 | ⏳ PENDING | - |
| trace | 3 | ⏳ PENDING | - |
| workflows | 3 | ⏳ PENDING | - |
| workspace | 1 | ⏳ PENDING | - |

---

## 🔍 Validation Workflow

For each service, follow the inline prompt in the YAML file:

1. Run: `export GCP_ENGINE_FILTER_SERVICES="<service>" && python engine/gcp_engine.py > output/test_<service>.json 2>&1`
2. Analyze output - check for inventories, main_checks, errors
3. Fix issues in discovery and checks sections
4. Re-run engine and verify output
5. Update this tracker: change status to ✅ VALIDATED and add date

---

## 📝 Notes

- Each service has metadata files under `services/<service>/metadata/`
- Each metadata file represents one security check
- Total check count = number of YAML files in metadata folder
- All services have inline prompts for validation guidance

