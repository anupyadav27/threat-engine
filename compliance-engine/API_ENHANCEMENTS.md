# Compliance Engine - API Enhancements

## ✅ Added Missing Endpoints for UI Support

Date: January 18, 2026

---

## 📋 New Endpoints Added

### 1. Account-Specific Compliance
```
GET /api/v1/compliance/accounts/{account_id}?scan_id={scan_id}&csp={csp}
```
**Purpose**: Get compliance status for a specific account across all frameworks  
**Response**: Account-level compliance summary with framework breakdown  
**UI Screen**: Account Compliance View

---

### 2. Compliance Trends
```
GET /api/v1/compliance/trends?csp={csp}&account_id={account_id}&framework={framework}&days={days}
```
**Purpose**: Get historical compliance trends over time  
**Response**: Trend data points and trend direction (improving/degrading/stable)  
**UI Screen**: Compliance Trends & History  
**Note**: Requires both `account_id` and `framework` for trend data

---

### 3. Control Detail
```
GET /api/v1/compliance/framework/{framework}/control/{control_id}?scan_id={scan_id}&csp={csp}
```
**Purpose**: Get detailed information about a specific compliance control  
**Response**: Control status, affected resources, evidence, and remediation steps  
**UI Screen**: Control Detail View

---

### 4. List Reports
```
GET /api/v1/compliance/reports?tenant_id={tenant_id}&csp={csp}&limit={limit}&offset={offset}
```
**Purpose**: List generated compliance reports with pagination  
**Response**: Paginated list of reports with metadata  
**UI Screen**: Enterprise Report Generator, Report Export

---

### 5. Report Status
```
GET /api/v1/compliance/reports/{report_id}/status
```
**Purpose**: Get generation status for a compliance report  
**Response**: Report status and metadata  
**UI Screen**: Enterprise Report Generator (for async generation)

---

### 6. Delete Report
```
DELETE /api/v1/compliance/reports/{report_id}
```
**Purpose**: Delete a compliance report  
**Response**: Deletion confirmation  
**UI Screen**: Report Export & Download

---

### 7. List Frameworks
```
GET /api/v1/compliance/frameworks?csp={csp}&scan_id={scan_id}
```
**Purpose**: List available compliance frameworks for a CSP  
**Response**: List of framework names  
**UI Screen**: Framework Compliance Detail, Enterprise Report Generator  
**Note**: If `scan_id` is provided, returns frameworks found in that scan

---

### 8. Search Controls
```
GET /api/v1/compliance/controls/search?query={query}&framework={framework}&csp={csp}&scan_id={scan_id}
```
**Purpose**: Search for controls across frameworks  
**Response**: Matching controls with framework and control IDs  
**UI Screen**: Framework Compliance Detail (search functionality)

---

## 🔄 Enhanced Existing Endpoints

### Generate Report - Trend Tracking
The `/api/v1/compliance/generate` endpoint now automatically records compliance scores to the trend tracker when reports are generated. This enables historical trend analysis.

---

## 📊 Complete Endpoint List

### Compliance Engine API (16 endpoints total)

1. `POST /api/v1/compliance/generate` - Generate compliance report
2. `POST /api/v1/compliance/generate/direct` - Generate from direct input
3. `POST /api/v1/compliance/generate/enterprise` - Generate enterprise report
4. `GET /api/v1/compliance/report/{report_id}` - Get report by ID
5. `GET /api/v1/compliance/report/{report_id}/export` - Export report (JSON/PDF/CSV)
6. `GET /api/v1/compliance/framework/{framework}/status` - Framework status
7. `GET /api/v1/compliance/framework/{framework}/control/{control_id}` - Control detail ⭐ NEW
8. `GET /api/v1/compliance/resource/drilldown` - Resource drill-down
9. `GET /api/v1/compliance/accounts/{account_id}` - Account compliance ⭐ NEW
10. `GET /api/v1/compliance/trends` - Compliance trends ⭐ NEW
11. `GET /api/v1/compliance/reports` - List reports ⭐ NEW
12. `GET /api/v1/compliance/reports/{report_id}/status` - Report status ⭐ NEW
13. `DELETE /api/v1/compliance/reports/{report_id}` - Delete report ⭐ NEW
14. `GET /api/v1/compliance/frameworks` - List frameworks ⭐ NEW
15. `GET /api/v1/compliance/controls/search` - Search controls ⭐ NEW
16. `GET /api/v1/health` - Health check

---

## 🎯 UI Coverage

All screens from `UI_SCREENS_MOCKUP.md` now have corresponding API endpoints:

- ✅ Executive Compliance Dashboard
- ✅ Framework Compliance Detail
- ✅ Control Detail View
- ✅ Account Compliance View
- ✅ Resource Compliance Drill-down
- ✅ Compliance Trends & History
- ✅ Enterprise Report Generator
- ✅ Report Export & Download

---

## 📝 Implementation Notes

1. **Trend Tracking**: Uses in-memory `TrendTracker` class. For production, should use database storage.

2. **Report Storage**: Currently uses in-memory dictionary. For production, should use Redis or database.

3. **Framework Listing**: Falls back to common frameworks list if framework loader doesn't support listing all frameworks.

4. **Control Search**: Requires `scan_id` to search in actual scan results. Framework-level search would need framework definitions loaded.

---

## 🚀 Next Steps

1. **Database Integration**: Replace in-memory storage with database for:
   - Report storage
   - Trend tracking
   - Historical data

2. **Framework Definitions**: Enhance framework loader to support listing all available frameworks without requiring scan results.

3. **Control Metadata**: Add control titles and descriptions to search functionality.

4. **Testing**: Add unit tests for new endpoints.

5. **Documentation**: Update Swagger/OpenAPI docs with new endpoints.

---

## ✅ Status

**All UI-required endpoints are now implemented!**

The compliance engine API is ready to serve all screens defined in the UI mockup document.



