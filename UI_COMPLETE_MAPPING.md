# Threat Engine - Complete UI/API Architecture

## Overview

All engines now have database-driven APIs ready for UI integration.

---

## Engine UI Documentation Files

| Engine | UI File Location | API Port | Database |
|--------|------------------|----------|----------|
| **Compliance** | `engine_compliance/UI_API_MAPPING.md` | 8010 | threat_engine_compliance |
| **Threat** | `engine_threat/UI_API_MAPPING.md` | 8020 | threat_engine_threat |
| **Inventory** | `engine_inventory/UI_API_MAPPING.md` | 8022 | threat_engine_inventory |
| **Check** | Backend service (no UI) | 8002 | threat_engine_check |
| **Discovery** | Backend service (no UI) | 8001 | threat_engine_discoveries |

---

## UI Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Frontend (React/Vue)                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Dashboard      Threats      Inventory      Compliance       │
│     │              │             │              │            │
│     └──────────────┴─────────────┴──────────────┘            │
│                          │                                    │
│                     API Gateway                               │
│                    (Port 8000)                                │
└───────────────────────────┬──────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
   Compliance          Threat              Inventory
   Service             Service             Service
   (8010)              (8020)              (8022)
        │                   │                   │
        ↓                   ↓                   ↓
   compliance_DB       threat_DB          inventory_DB
```

---

## Key UI Endpoints by Engine

### Compliance Engine (Port 8010)
**Primary Views:**
- Dashboard: `/api/v1/compliance/dashboard`
- Framework Detail: `/api/v1/compliance/framework-detail/{framework}`
- Control Detail: `/api/v1/compliance/control-detail/{framework}/{control_id}`
- Resource Compliance: `/api/v1/compliance/resource/{resource_uid}/compliance`

**Database**: `threat_engine_compliance`
- Main View: `compliance_control_detail` (362 controls)
- Data: 23,998 resource compliance records

---

### Threat Engine (Port 8020)
**Primary Views:**
- Dashboard: `/api/v1/threat/scans/{scan_run_id}/summary`
- Threat List: `/api/v1/threat/threats` (filterable by severity, category)
- Threat Detail: `/api/v1/threat/threats/{threat_id}`
- Resource Threats: `/api/v1/threat/resources/{resource_uid}/threats`
- Resource Posture: `/api/v1/threat/resources/{resource_uid}/posture`
- Drift: `/api/v1/threat/drift`

**Database**: `threat_engine_threat`
- Main Table: `threats` (489 rows)
- Supporting: `threat_resources`, `threat_scans`, `drift_records`

---

### Inventory Engine (Port 8022)
**Primary Views:**
- Dashboard: `/api/v1/inventory/runs/latest/summary`
- Asset List: `/api/v1/inventory/assets` (filterable)
- Asset Detail: `/api/v1/inventory/assets/{resource_uid}`
- Relationships: `/api/v1/inventory/relationships`
- Asset Relationships: `/api/v1/inventory/assets/{resource_uid}/relationships`

**Database**: `threat_engine_inventory`
- Main Tables: `asset_index_latest` (287 assets), `relationship_index_latest` (97)

---

## Cross-Engine UI Features

### Resource 360° View
**Shows data from all engines for a single resource**

**API Calls**:
```javascript
// 1. Asset details (Inventory)
const asset = await fetch(`/api/v1/inventory/assets/${resource_uid}?tenant_id=${tenant}`)

// 2. Threats affecting this resource (Threat)
const threats = await fetch(`/api/v1/threat/resources/${resource_uid}/threats?tenant_id=${tenant}`)

// 3. Check posture (Threat - queries Check DB)
const posture = await fetch(`/api/v1/threat/resources/${resource_uid}/posture?tenant_id=${tenant}`)

// 4. Compliance status (Compliance)
const compliance = await fetch(`/api/v1/compliance/resource/${resource_uid}/compliance?tenant_id=${tenant}`)
```

**Shows**:
- Asset metadata & tags (Inventory)
- Relationships to other assets (Inventory)
- Security threats (Threat: 4 threats for cspm-lgtech bucket)
- Check results (Threat/Check: 56 checks, 53 failed)
- Compliance status (Compliance: 12 frameworks, 119 controls)

---

## Database Query Patterns

### Pattern 1: Dashboard Summary
```sql
-- Scan summary
SELECT * FROM {engine}_scans
WHERE tenant_id = 'test-tenant'
ORDER BY generated_at DESC
LIMIT 1;
```

### Pattern 2: List with Filters
```sql
-- Threats, assets, controls
SELECT * FROM {main_table}
WHERE tenant_id = 'test-tenant'
  AND {filter_column} = {filter_value}
ORDER BY {sort_column}
LIMIT {page_size} OFFSET {offset};
```

### Pattern 3: Detail View
```sql
-- Get item + related items
SELECT main.* FROM {main_table} main
LEFT JOIN {related_table} rel ON main.id = rel.main_id
WHERE main.id = {item_id};
```

### Pattern 4: Aggregations
```sql
-- Group by for charts
SELECT 
    {group_column},
    COUNT(*) as count
FROM {table}
GROUP BY {group_column}
ORDER BY count DESC;
```

---

## UI Component → Database Mapping

| UI Component | Query Type | Database Source |
|--------------|------------|-----------------|
| **Pie Chart** (threats by category) | GROUP BY | `threats` table |
| **Bar Chart** (assets by type) | GROUP BY | `asset_index_latest` |
| **Line Chart** (compliance trend) | Time series | Multiple scans |
| **Table** (threat list) | SELECT with filters | `threats` table |
| **Detail Panel** | JOIN | Multiple tables |
| **Search** | WHERE clauses | Indexed columns |

---

## Port-Forward for UI Testing

```bash
# Port-forward all services
kubectl -n threat-engine-local port-forward svc/compliance-service 8010:8010 &
kubectl -n threat-engine-local port-forward svc/threat-service 8020:8020 &
kubectl -n threat-engine-local port-forward svc/inventory-service 8022:8022 &

# Test endpoints
curl "http://localhost:8010/api/v1/compliance/dashboard?tenant_id=test-tenant" | jq
curl "http://localhost:8020/api/v1/threat/scans/check_20260129_162625/summary?tenant_id=test-tenant" | jq
curl "http://localhost:8022/api/v1/inventory/runs/latest/summary?tenant_id=test-tenant" | jq
```

---

## UI Files Structure

```
threat-engine/
├── engine_compliance/
│   ├── UI_API_MAPPING.md ⭐ (compliance UI guide)
│   ├── COMPLIANCE_UI_API_MAPPING.md (API reference)
│   └── UI_SCREENS_MOCKUP.md (original mockups)
│
├── engine_threat/
│   └── UI_API_MAPPING.md ⭐ (threat UI guide)
│
├── engine_inventory/
│   └── UI_API_MAPPING.md ⭐ (inventory UI guide)
│
└── UI_COMPLETE_MAPPING.md (this file - master index)
```

---

## Next Steps for UI Development

1. **Frontend Framework**: React/Vue/Angular
2. **API Client**: Use service ports (8010, 8020, 8022)
3. **State Management**: Redux/Vuex for caching
4. **Charts**: Chart.js/D3.js for visualizations
5. **Real-time**: WebSocket for scan progress

**All APIs are production-ready and database-backed!**
