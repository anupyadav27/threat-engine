# UI & API Status Summary - ConfigScan & Threat Engine

## Current Status

### ✅ Threat Engine - Check Results
**Status**: ✅ **COMPLETE**

**Implemented:**
- ✅ API Endpoints: 11 endpoints for check results (`/api/v1/checks/*`)
- ✅ UI Mockups: 8 comprehensive screens (`UI_CHECKS_MOCKUP.md`)
- ✅ Database Queries: Optimized queries with NDJSON fallback
- ✅ Pydantic Models: Complete response models
- ✅ Documentation: Full API docs and quick start guide

**Files:**
- `threat_engine/api/check_router.py` - Check results API
- `threat_engine/database/check_queries.py` - Database queries
- `threat_engine/schemas/check_models.py` - Pydantic models
- `UI_CHECKS_MOCKUP.md` - UI screen designs
- `CHECK_API_README.md` - Documentation

---

### ❌ Threat Engine - Discovery Results
**Status**: ❌ **MISSING**

**What's Needed:**
- ❌ API Endpoints for discovery results viewing
- ❌ UI Mockups for discovery results
- ❌ Database queries for discovery data
- ❌ Pydantic models for discovery responses

**Discovery Data Available:**
- ✅ NDJSON files: `engines-output/aws-configScan-engine/output/configscan/discoveries/`
- ✅ Database table: `discoveries` (if uploaded)
- ✅ Structure: Well-defined schema with `scan_id`, `discovery_id`, `emitted_fields`, etc.

---

### ⚠️ ConfigScan Engine - API Server
**Status**: ⚠️ **PARTIAL**

**Current:**
- ✅ `api_server.py` exists - For running scans (POST /api/v1/scan)
- ✅ Scan management endpoints (status, results, cancel)
- ❌ No discovery results viewing endpoints
- ❌ No UI mockups

**Purpose:**
- Currently used for **triggering scans**, not viewing results
- Results viewing should be in threat-engine (unified UI)

---

## Recommendation

### Option 1: Add Discovery Results to Threat Engine (Recommended)
**Rationale:**
- Threat engine already has check results UI/API
- Unified place for viewing all scan results
- Consistent user experience
- Discovery and check results are related (checks use discovery data)

**What to Add:**
1. Discovery results API router (`threat_engine/api/discovery_router.py`)
2. Discovery database queries (`threat_engine/database/discovery_queries.py`)
3. Discovery Pydantic models (`threat_engine/schemas/discovery_models.py`)
4. Discovery UI mockups (`UI_DISCOVERY_MOCKUP.md`)
5. NDJSON reader for discoveries (similar to check results)

**Endpoints Needed:**
- `GET /api/v1/discoveries/dashboard` - Discovery scan overview
- `GET /api/v1/discoveries/scans` - List discovery scans
- `GET /api/v1/discoveries/scans/{id}` - Scan details
- `GET /api/v1/discoveries/scans/{id}/services` - Service breakdown
- `GET /api/v1/discoveries/scans/{id}/services/{svc}` - Service discovery details
- `GET /api/v1/discoveries/resources/{arn}` - All discoveries for resource
- `GET /api/v1/discoveries/search` - Search discoveries

### Option 2: Keep ConfigScan API Separate
**Rationale:**
- Each engine has its own API
- Separation of concerns

**What to Add:**
1. Discovery results endpoints in `configScan_engines/aws-configScan-engine/api_server.py`
2. UI mockups in `configScan_engines/aws-configScan-engine/UI_DISCOVERY_MOCKUP.md`

---

## Current Architecture

```
ConfigScan Engine
├── Discovery Engine → NDJSON files / Database
├── Check Engine → NDJSON files / Database
└── API Server → Scan management only

Threat Engine
├── Check Results API → ✅ Complete
├── Discovery Results API → ❌ Missing
└── Threat Detection API → ✅ Complete
```

---

## Next Steps

**Recommended**: Implement discovery results viewing in threat-engine to match check results implementation.

**Benefits:**
1. Unified UI for all scan results
2. Consistent API patterns
3. Reuse existing infrastructure (database queries, NDJSON readers)
4. Better user experience (one place for all results)
