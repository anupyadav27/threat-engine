# Changelog

All notable changes to the CSPM Threat Engine platform.

---

## [Unreleased]

### Added
- **Security Graph (Neo4j)** — Attack path analysis, blast radius, toxic combinations, threat hunting
- **Threat Analysis** — Composite risk scoring (0-100), verdict classification, attack chain builder
- **Threat Intelligence** — IOC/TTP ingestion, MITRE technique correlation
- **Threat Hunting** — 5 predefined hunts, custom Cypher queries, saved hunts with results
- **Neo4j Integration** — Graph builder populates from PostgreSQL, graph queries via API
- **Comprehensive API Documentation** — Per-engine docs with folder structures, endpoints, sample responses
- **Cluster & deployment details** — EKS config, K8s services, HPA, resource limits documented

### Changed
- **Threat pipeline** — Auto-runs analysis after detection in `/generate` endpoint
- **API routes** — Analysis endpoints moved before wildcard to prevent route conflicts
- **Rule metadata** — MITRE technique/tactic columns added, loaded from PostgreSQL instead of 42MB YAML
- **Graph builder** — Fixed column name `cf.id AS finding_id` and severity from `rm.severity` JOIN

### Removed
- **threat_rules.yaml** — 42MB file replaced by PostgreSQL `rule_metadata` table
- **131 root MD files** — Temp documentation cleaned up
- **data_pythonsdk/** — 12,000+ data files removed (not needed in repo)
- **data_compliance/** — 109 data files removed
- **archive/ directories** — Removed from all engine folders

---

## [1.0.0] - 2025-02-05

### Added
- **Database-first architecture** — All engines read/write PostgreSQL
- **Multi-provider rule loading** — Rules loaded from DB instead of local YAML
- **MITRE ATT&CK mapping** — 46 techniques mapped to security rules
- **Metadata enrichment** — JOIN check_findings with rule_metadata for severity, MITRE
- **Misconfig normalizer** — Normalize findings with MITRE JSONB handling
- **Threat detector** — Group findings by resource, assign MITRE techniques
- **API server** — FastAPI with 60+ endpoints
- **Docker support** — Dockerfile + docker-compose for all engines
- **EKS deployment** — Kubernetes manifests for production

### Initial Engines
- engine_discoveries (AWS resource discovery)
- engine_check (compliance checking)
- engine_inventory (asset inventory)
- engine_threat (threat detection)
- engine_compliance (compliance reporting)
- engine_rule (YAML rule builder)
- engine_onboarding (account management)
- engine_datasec (data security)
- engine_iam (IAM security)
- engine_secops (IaC scanning)
- api_gateway (service routing)
