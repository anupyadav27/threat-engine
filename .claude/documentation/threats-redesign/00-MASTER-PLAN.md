# Threats Module — Master Redesign Plan

> **Date:** 2026-03-17
> **Status:** Planning
> **Benchmark:** Wiz, Orca Security, Prisma Cloud, Lacework

---

## Executive Summary

The Threats module is the **crown jewel** of the CSPM platform. Unlike a Findings page (atomic rule violations), the Threats module presents **contextualized risk scenarios** — combining misconfigurations, identity weaknesses, exposure vectors, and resource relationships into actionable intelligence.

This plan covers a full-stack redesign across **5 layers**:

```
┌─────────────────────────────────────────────────────┐
│  Layer 5: UI Pages (Next.js)                        │
│  9 pages × enterprise-grade components              │
├─────────────────────────────────────────────────────┤
│  Layer 4: BFF (1 file per page, modular)            │
│  Normalization, aggregation, enrichment             │
├─────────────────────────────────────────────────────┤
│  Layer 3: Threat Engine API (FastAPI)               │
│  60+ routes, unified UI-data endpoint               │
├─────────────────────────────────────────────────────┤
│  Layer 2: Database (PostgreSQL + Neo4j)             │
│  9 tables, 180+ columns, GIN indexes               │
├─────────────────────────────────────────────────────┤
│  Layer 1: Data Pipeline                             │
│  Check → Threat → Analysis → Graph                  │
└─────────────────────────────────────────────────────┘
```

---

## Module Architecture

### Page Structure (9 pages)

| # | Page | Route | BFF File | Purpose |
|---|------|-------|----------|---------|
| 1 | **Threat Dashboard** | `/threats` | `bff/threats.py` | Overview KPIs, MITRE matrix, trend, top threats |
| 2 | **Threat Detail** | `/threats/[threatId]` | `bff/threat_detail.py` | Full context for single threat |
| 3 | **Analytics** | `/threats/analytics` | `bff/threat_analytics.py` | Distribution, trends, top services, patterns |
| 4 | **Attack Paths** | `/threats/attack-paths` | `bff/threat_attack_paths.py` | Visual attack chains, step-by-step |
| 5 | **Blast Radius** | `/threats/blast-radius` | `bff/threat_blast_radius.py` | Force-directed graph, impact analysis |
| 6 | **Graph Explorer** | `/threats/graph` | `bff/threat_graph.py` | Full security graph, node/edge filtering |
| 7 | **Hunting** | `/threats/hunting` | `bff/threat_hunting.py` | IOCs, hunt queries, intelligence |
| 8 | **Internet Exposed** | `/threats/internet-exposed` | `bff/threat_internet_exposed.py` | Public resources, exposure paths |
| 9 | **Toxic Combinations** | `/threats/toxic-combinations` | `bff/threat_toxic_combos.py` | Compound risk, co-occurrence matrix |

### BFF Modular Pattern (1:1 page mapping)

```
shared/api_gateway/bff/
├── threats.py                  # /views/threats (dashboard)
├── threat_detail.py            # /views/threats/{id}
├── threat_analytics.py         # /views/threats/analytics
├── threat_attack_paths.py      # /views/threats/attack-paths
├── threat_blast_radius.py      # /views/threats/blast-radius
├── threat_graph.py             # /views/threats/graph
├── threat_hunting.py           # /views/threats/hunting
├── threat_internet_exposed.py  # /views/threats/internet-exposed
├── threat_toxic_combos.py      # /views/threats/toxic-combinations
└── _transforms.py              # Shared normalizers (existing)
```

---

## Implementation Phases

### Phase 1 — Foundation (Make it load) ⏱ Week 1
- **P1-DB**: Add `assignee`, `notes` columns to `threat_findings`
- **P1-BFF**: Wire BFF threats route into `views.py` gateway prefix
- **P1-BFF**: Create `threat_detail.py` BFF (replaces client-side list filtering)
- **P1-TRANSFORM**: Fix MITRE data shape (array of objects, not strings)
- **P1-TRANSFORM**: Normalize camelCase consistently in BFF layer

### Phase 2 — Core Pages (Enterprise UI) ⏱ Week 2
- **P2-UI**: Redesign threats dashboard (see `01-THREAT-DASHBOARD.md`)
- **P2-UI**: Redesign threat detail page (see `02-THREAT-DETAIL.md`)
- **P2-UI**: Redesign analytics page (see `03-ANALYTICS.md`)
- **P2-BFF**: Create `threat_analytics.py` BFF

### Phase 3 — Graph & Paths ⏱ Week 3
- **P3-UI**: Redesign attack paths (see `04-ATTACK-PATHS.md`)
- **P3-UI**: Redesign blast radius (see `05-BLAST-RADIUS.md`)
- **P3-UI**: Redesign internet exposed (see `06-INTERNET-EXPOSED.md`)
- **P3-BFF**: Create BFF modules for each

### Phase 4 — Advanced ⏱ Week 4
- **P4-UI**: Redesign toxic combinations (see `07-TOXIC-COMBINATIONS.md`)
- **P4-UI**: Redesign graph explorer (see `08-GRAPH-EXPLORER.md`)
- **P4-UI**: Redesign hunting (see `09-HUNTING.md`)
- **P4-BFF**: Create remaining BFF modules

### Phase 5 — Polish & Integration ⏱ Week 5
- **P5**: Cross-page navigation (finding ↔ threat ↔ asset ↔ graph)
- **P5**: Empty state handling
- **P5**: Loading skeletons
- **P5**: Error boundaries
- **P5**: Performance optimization (virtualized lists, lazy tabs)

---

## Data Flow Summary

```
UI Page Request
  │
  ▼
BFF Module (1:1 per page)
  │  ├── fetch_many() → parallel engine calls
  │  ├── normalize_*() → camelCase field mapping
  │  └── enrich() → cross-engine joins
  │
  ▼
Engine API (60+ routes)
  │  ├── /api/v1/threat/ui-data      → unified data (threats BFF)
  │  ├── /api/v1/threat/{id}         → single threat (detail BFF)
  │  ├── /api/v1/threat/analytics/*  → charts (analytics BFF)
  │  ├── /api/v1/graph/*             → Neo4j queries (graph pages)
  │  └── /api/v1/intel/*             → threat intel (hunting BFF)
  │
  ▼
Database
  ├── threat_findings      → primary findings (3,900 rows)
  ├── threat_report        → scan metadata
  ├── threat_detections    → real-time detections (193)
  ├── threat_analysis      → blast radius, attack chains
  ├── threat_intelligence  → IOC feeds
  ├── threat_hunt_queries  → hunt definitions
  ├── threat_hunt_results  → hunt execution results
  └── Neo4j               → graph (attack paths, toxic combos)
      Connection: bolt://neo4j:7687 (in-cluster)
      Username: neo4j
```

---

## Detailed Documents

| Doc | Content |
|-----|---------|
| `01-THREAT-DASHBOARD.md` | UI blocks, JSON contract, BFF mapping |
| `02-THREAT-DETAIL.md` | UI blocks, JSON contract, BFF mapping |
| `03-ANALYTICS.md` | UI blocks, JSON contract, BFF mapping |
| `04-ATTACK-PATHS.md` | UI blocks, JSON contract, BFF mapping |
| `05-BLAST-RADIUS.md` | UI blocks, JSON contract, BFF mapping |
| `06-INTERNET-EXPOSED.md` | UI blocks, JSON contract, BFF mapping |
| `07-TOXIC-COMBINATIONS.md` | UI blocks, JSON contract, BFF mapping |
| `08-GRAPH-EXPLORER.md` | UI blocks, JSON contract, BFF mapping |
| `09-HUNTING.md` | UI blocks, JSON contract, BFF mapping |
| `10-DATA-CONTRACTS.md` | Complete JSON schemas for all 9 pages |
| `11-USER-STORIES.md` | Epics, stories, acceptance criteria |
| `12-AGENT-DEFINITIONS.md` | Agent SDK configs for each task |
| `13-GAP-ANALYSIS.md` | Engine ↔ UI ↔ DB gap matrix |
