# Gap Analysis: Engine Data vs UI Needs

---

## Gap Matrix

### ✅ Data Available (No Changes Needed)

| UI Need | Engine Endpoint | Response Field | Notes |
|---------|----------------|---------------|-------|
| Threat list | `/api/v1/threat/ui-data` | `.threats[]` | 200 limit, paginated |
| Severity summary | `/api/v1/threat/ui-data` | `.summary` | total, crit, high, med, low |
| MITRE matrix | `/api/v1/threat/ui-data` | `.mitre_matrix[]` | technique_id, tactics[], count |
| 30-day trend | `/api/v1/threat/ui-data` | `.trend[]` | date, total, by_severity |
| Attack chains | `/api/v1/threat/ui-data` | `.attack_paths[]` | From Neo4j |
| Threat intel | `/api/v1/threat/ui-data` | `.threat_intel[]` | From threat_intelligence table |
| Single threat | `/api/v1/threat/{id}` | full finding | All fields from threat_findings |
| Affected assets | `/api/v1/threat/{id}/assets` | `.affected_assets[]` | |
| Supporting findings | `/api/v1/threat/{id}/misconfig-findings` | `.misconfig_findings[]` | Check engine cross-ref |
| Remediation | `/api/v1/threat/{id}/remediation` | `.steps[]` | From finding_data JSONB |
| Distribution | `/api/v1/threat/analytics/distribution` | `.distribution` | by_severity, by_category, by_status |
| Trend analytics | `/api/v1/threat/analytics/trend` | `.trend_data[]` | With summary |
| Patterns | `/api/v1/threat/analytics/patterns` | `.patterns[]` | Misconfig correlations |
| Attack paths | `/api/v1/graph/attack-paths` | `.attack_paths[]` | Neo4j query |
| Blast radius | `/api/v1/graph/blast-radius/{uid}` | full graph | Neo4j traversal |
| Graph summary | `/api/v1/graph/summary` | node/edge counts | Neo4j stats |
| Internet exposed | `/api/v1/graph/internet-exposed` | `.exposed_resources[]` | Neo4j query |
| Toxic combos | `/api/v1/graph/toxic-combinations` | `.toxic_combinations[]` | Neo4j query |
| Toxic matrix | `/api/v1/graph/toxic-combinations/matrix` | matrix object | Neo4j co-occurrence |
| Intel feed | `/api/v1/intel` | `.threat_intel[]` | From threat_intelligence |
| Hunt queries | `/api/v1/hunt/queries` | `.queries[]` | From threat_hunt_queries |
| Top services | `/api/v1/threat/ui-data` | `.summary.by_service` | Per-service breakdown |
| By account | `/api/v1/threat/ui-data` | `.summary.by_account` | Per-account breakdown |
| By region | `/api/v1/threat/ui-data` | `.summary.by_region` | Per-region breakdown |

### 🟡 Data Available, Needs BFF Enrichment

| UI Need | Source | Transform Needed |
|---------|--------|-----------------|
| KPI deltas (change vs prev scan) | Fetch 2 scan summaries | BFF computes diff |
| `hasAttackPath` flag per threat | attack_paths + threats | BFF sets boolean from resource_uid Set |
| `isInternetExposed` flag per threat | internet_exposed + threats | BFF sets boolean from resource_uid Set |
| topMitreTechniques | mitre_matrix | BFF flattens + sorts by count |
| accountHeatmap | summary.by_account | BFF restructures for table |
| byProvider | onboarding ui-data + threats | BFF maps account→provider |
| Exposure context (detail page) | internet_exposed + threat | BFF derives from graph data |
| Timeline (detail page) | threat first_seen_at + scan timestamps | BFF builds synthetic timeline |
| MITRE technique description | mitre_technique_reference table | Engine JOIN or new endpoint |
| SLA status (detail page) | first_seen_at + severity | BFF computes via SLA_THRESHOLDS |

### 🔴 Data Missing (Changes Required)

| UI Need | What's Missing | Fix | Priority |
|---------|---------------|-----|----------|
| **assignee** | No column in threat_findings | DB migration: `ALTER TABLE threat_findings ADD assignee VARCHAR(255)` | P1 |
| **notes** | No column in threat_findings | DB migration: `ALTER TABLE threat_findings ADD notes TEXT` | P1 |
| **PATCH /threat/{id}** | Endpoint exists but assignee/notes not in schema | Update PATCH handler after migration | P1 |
| **hasSensitiveData** flag | No cross-engine datasec connector | Optional: fetch from datasec or skip for v1 | P3 |
| **environment** tag | Not stored as separate field | Derive from tags or account metadata | P2 |
| **MITRE standalone endpoint** | `mitre_technique_reference` table exists but no dedicated GET endpoint | Add `GET /api/v1/mitre/{technique_id}` | P2 |

---

## BFF Module Status

| BFF File | Exists? | Action |
|----------|---------|--------|
| `bff/threats.py` | ✅ EXISTS | UPDATE — add topServices, deltas, flags |
| `bff/threat_detail.py` | ❌ | CREATE — replaces client-side list filter hack |
| `bff/threat_analytics.py` | ❌ | CREATE — aggregates from ui-data + analytics endpoints |
| `bff/threat_attack_paths.py` | ❌ | CREATE — wraps graph/attack-paths with normalization |
| `bff/threat_blast_radius.py` | ❌ | CREATE — wraps 3 graph endpoints |
| `bff/threat_graph.py` | ❌ | CREATE — wraps inventory graph endpoint |
| `bff/threat_hunting.py` | ❌ | CREATE — wraps intel + hunt/queries |
| `bff/threat_internet_exposed.py` | ❌ | CREATE — wraps graph/internet-exposed + categorization |
| `bff/threat_toxic_combos.py` | ❌ | CREATE — wraps 2 graph endpoints |

---

## Database Migration Summary

```sql
-- Migration: Add workflow columns to threat_findings
ALTER TABLE threat_findings ADD COLUMN IF NOT EXISTS assignee VARCHAR(255);
ALTER TABLE threat_findings ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE threat_findings ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE threat_findings ADD COLUMN IF NOT EXISTS status_changed_by VARCHAR(255);

-- Index for assignee queries
CREATE INDEX IF NOT EXISTS idx_tf_assignee ON threat_findings(assignee) WHERE assignee IS NOT NULL;
```

---

## Neo4j Graph Database

The threat engine uses Neo4j for graph-based queries (attack paths, blast radius, toxic combinations, internet exposure).

- **Username:** neo4j
- **Graph endpoints:** All routes under `/api/v1/graph/*` query Neo4j
- **Graph build:** `POST /api/v1/graph/build` populates Neo4j from PostgreSQL data
- **Required for:** Pages 4-8 (Attack Paths, Blast Radius, Internet Exposed, Toxic Combos, Graph Explorer)

---

## Engine Endpoint Changes

| Change | Priority | Effort |
|--------|----------|--------|
| Update PATCH `/api/v1/threat/{id}` to handle assignee, notes | P1 | Low |
| Add `GET /api/v1/mitre/{technique_id}` endpoint | P2 | Low |
| Add `resolved_count` to ui-data summary | P2 | Low |
| Ensure attack_paths includes resource_uid for matching | P2 | Low |
