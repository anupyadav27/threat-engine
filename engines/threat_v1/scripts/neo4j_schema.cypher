// ============================================================================
// threat_v1 Neo4j Graph Schema
// ============================================================================
//
// USE threat_v1
//
// IMPORTANT: This schema targets the NAMED DATABASE "threat_v1" on the
// existing Neo4j Aura instance (neo4j+s://17ec5cbb.databases.neo4j.io).
// It does NOT use the default database — all GraphBuilder connections must
// specify database="threat_v1" in the driver session call.
//
// Apply this file ONCE on a fresh threat_v1 named database, or idempotently
// after verifying each index/constraint does not already exist.
//
// Execution:
//   neo4j-admin cypher-shell -u neo4j -p <pass> \
//     --database threat_v1 --file neo4j_schema.cypher
//
// CP-1 Security Rules encoded in this file:
//   CP1-01  All compiled Cypher MUST include $tenant_id or $tid param.
//           Every node label below has a tenant_id index to enforce this.
//   CP1-02  actor_principal (PII) is NEVER stored on any Neo4j node.
//           CDRActor stores only actor_hash (sha256) + actor_principal_type.
//   SR-003  CDREvent carries tenant_id as a first-class property so that
//           a MATCH on (:CDREvent) without Resource traversal is still
//           filterable by tenant_id. The CI linter must reject any compiled
//           Cypher that MATCHes CDREvent without a $tenant_id/$tid filter.
//
// ============================================================================


// ============================================================================
// SECTION 1 — CONSTRAINTS
// Constraints are created before indexes so that the UNIQUE backing index
// is created implicitly and does not conflict with an explicit index create.
// ============================================================================

// ----------------------------------------------------------------------------
// Resource — cloud asset node imported from inventory engine
// Uniqueness: one resource per (resource_uid, tenant_id) pair.
// ----------------------------------------------------------------------------
CREATE CONSTRAINT constraint_resource_uid_tenant IF NOT EXISTS
FOR (r:Resource)
REQUIRE (r.resource_uid, r.tenant_id) IS NODE KEY;

// ----------------------------------------------------------------------------
// MisconfigFinding — imported from check_findings + rule_metadata
// ----------------------------------------------------------------------------
CREATE CONSTRAINT constraint_misconfig_finding_id_tenant IF NOT EXISTS
FOR (m:MisconfigFinding)
REQUIRE (m.finding_id, m.tenant_id) IS NODE KEY;

// ----------------------------------------------------------------------------
// VulnFinding — imported from scan_vulnerabilities + cve_attack_mappings
// ----------------------------------------------------------------------------
CREATE CONSTRAINT constraint_vuln_finding_id_tenant IF NOT EXISTS
FOR (v:VulnFinding)
REQUIRE (v.finding_id, v.tenant_id) IS NODE KEY;

// ----------------------------------------------------------------------------
// CDREvent — imported from cdr_findings
// Note on PII (CP1-02 / SR-003): actor_principal (raw email/ARN) is NEVER
// stored here. Only actor_principal_type (e.g. 'IAMUser', 'AssumedRole') is
// stored. The CDRActor node stores actor_hash (sha256 of actor_principal).
// ----------------------------------------------------------------------------
CREATE CONSTRAINT constraint_cdr_event_id_tenant IF NOT EXISTS
FOR (e:CDREvent)
REQUIRE (e.finding_id, e.tenant_id) IS NODE KEY;

// ----------------------------------------------------------------------------
// CDRActor — de-duplicated actor identity node
// actor_hash = sha256(actor_principal) — NEVER the raw actor_principal value.
// This satisfies CP1-02: PII does not enter the graph store at any point.
// Uniqueness: one actor node per (actor_hash, tenant_id).
// ----------------------------------------------------------------------------
CREATE CONSTRAINT constraint_cdr_actor_hash_tenant IF NOT EXISTS
FOR (a:CDRActor)
REQUIRE (a.actor_hash, a.tenant_id) IS NODE KEY;

// ----------------------------------------------------------------------------
// ThreatIncident — deduplicated incident node
// dedup_key mirrors the PostgreSQL GENERATED STORED column so cross-store
// lookups remain consistent.
// ----------------------------------------------------------------------------
CREATE CONSTRAINT constraint_threat_incident_dedup_key IF NOT EXISTS
FOR (i:ThreatIncident)
REQUIRE i.dedup_key IS UNIQUE;


// ============================================================================
// SECTION 2 — INDEXES
// These supplement the constraint backing indexes with range/lookup indexes
// on frequently filtered properties.
// ============================================================================

// ----------------------------------------------------------------------------
// Resource indexes
// ----------------------------------------------------------------------------

// Primary lookup by resource_uid (joins from Postgres findings)
CREATE INDEX idx_resource_uid IF NOT EXISTS
FOR (r:Resource) ON (r.resource_uid);

// Tenant isolation — CP1-01: every label must have this index so that the
// $tenant_id parameter in every compiled Cypher uses an indexed lookup.
CREATE INDEX idx_resource_tenant_id IF NOT EXISTS
FOR (r:Resource) ON (r.tenant_id);

// Attack path queries: filter resources that are crown jewels
// (Tier 3 target candidates)
CREATE INDEX idx_resource_is_crown_jewel IF NOT EXISTS
FOR (r:Resource) ON (r.is_crown_jewel);

// PathTagger writes on_attack_path=true after Tier 3 confirmation;
// BFF threat_graph view filters on this flag
CREATE INDEX idx_resource_on_attack_path IF NOT EXISTS
FOR (r:Resource) ON (r.on_attack_path);

// Tier 1 matcher reads these aggregated boolean flags directly;
// indexes keep sub-10ms per-pattern latency achievable
CREATE INDEX idx_resource_internet_exposed IF NOT EXISTS
FOR (r:Resource) ON (r.internet_exposed);

CREATE INDEX idx_resource_is_admin_role IF NOT EXISTS
FOR (r:Resource) ON (r.is_admin_role);

CREATE INDEX idx_resource_environment IF NOT EXISTS
FOR (r:Resource) ON (r.environment);

CREATE INDEX idx_resource_provider IF NOT EXISTS
FOR (r:Resource) ON (r.provider);

CREATE INDEX idx_resource_resource_type IF NOT EXISTS
FOR (r:Resource) ON (r.resource_type);

// ----------------------------------------------------------------------------
// MisconfigFinding indexes
// ----------------------------------------------------------------------------

// Tenant isolation — mandatory on every label (CP1-01)
CREATE INDEX idx_misconfig_tenant_id IF NOT EXISTS
FOR (m:MisconfigFinding) ON (m.tenant_id);

// PatternCompiler generates Cypher that matches on rule_id to find
// check_rules_failing conditions
CREATE INDEX idx_misconfig_rule_id IF NOT EXISTS
FOR (m:MisconfigFinding) ON (m.rule_id);

CREATE INDEX idx_misconfig_severity IF NOT EXISTS
FOR (m:MisconfigFinding) ON (m.severity);

CREATE INDEX idx_misconfig_status IF NOT EXISTS
FOR (m:MisconfigFinding) ON (m.status);

// ----------------------------------------------------------------------------
// VulnFinding indexes
// ----------------------------------------------------------------------------

// Tenant isolation — mandatory on every label (CP1-01)
CREATE INDEX idx_vuln_tenant_id IF NOT EXISTS
FOR (v:VulnFinding) ON (v.tenant_id);

// CVE ID lookups (Tier 2/3 conditions on specific CVEs)
CREATE INDEX idx_vuln_cve_id IF NOT EXISTS
FOR (v:VulnFinding) ON (v.cve_id);

CREATE INDEX idx_vuln_severity IF NOT EXISTS
FOR (v:VulnFinding) ON (v.severity);

// ----------------------------------------------------------------------------
// CDREvent indexes
// ----------------------------------------------------------------------------

// Tenant isolation — CP1-01 + SR-003: first-class tenant_id on CDREvent
// so a direct MATCH (:CDREvent) can still be filtered without Resource hop
CREATE INDEX idx_cdr_event_tenant_id IF NOT EXISTS
FOR (e:CDREvent) ON (e.tenant_id);

CREATE INDEX idx_cdr_event_rule_id IF NOT EXISTS
FOR (e:CDREvent) ON (e.rule_id);

CREATE INDEX idx_cdr_event_severity IF NOT EXISTS
FOR (e:CDREvent) ON (e.severity);

// event_time is used in cdr_watch.window_minutes range filter
CREATE INDEX idx_cdr_event_time IF NOT EXISTS
FOR (e:CDREvent) ON (e.event_time);

// resource_uid lookback: CDRLoader links events to Resource nodes via
// resource_uid before writing the edge; index supports this join
CREATE INDEX idx_cdr_event_resource_uid IF NOT EXISTS
FOR (e:CDREvent) ON (e.resource_uid);

// ----------------------------------------------------------------------------
// CDRActor indexes
//
// CP1-02 (PII protection): actor_principal MUST NOT be stored as a node
// property. GraphBuilder (CDRLoader) computes actor_hash =
// hashlib.sha256(actor_principal.encode()).hexdigest() before MERGE.
// actor_principal is used only as the hash input and immediately discarded.
// Only actor_hash and actor_principal_type are written to the graph.
// ----------------------------------------------------------------------------

// Tenant isolation — mandatory on every label (CP1-01)
CREATE INDEX idx_cdr_actor_tenant_id IF NOT EXISTS
FOR (a:CDRActor) ON (a.tenant_id);

// Dedup lookup: CDRLoader MERGEs on (actor_hash, tenant_id)
CREATE INDEX idx_cdr_actor_hash IF NOT EXISTS
FOR (a:CDRActor) ON (a.actor_hash);

// ----------------------------------------------------------------------------
// ThreatIncident indexes
// ----------------------------------------------------------------------------

// Tenant isolation — mandatory on every label (CP1-01)
CREATE INDEX idx_threat_incident_tenant_id IF NOT EXISTS
FOR (i:ThreatIncident) ON (i.tenant_id);

// dedup_key lookup — used by IncidentDeduper to find existing open incidents
CREATE INDEX idx_threat_incident_dedup_key IF NOT EXISTS
FOR (i:ThreatIncident) ON (i.dedup_key);

// List queries filter by severity + status (BFF threat_center view)
CREATE INDEX idx_threat_incident_severity IF NOT EXISTS
FOR (i:ThreatIncident) ON (i.severity);

CREATE INDEX idx_threat_incident_status IF NOT EXISTS
FOR (i:ThreatIncident) ON (i.status);

// incident_class is the primary filter in Zone A sidebar
CREATE INDEX idx_threat_incident_class IF NOT EXISTS
FOR (i:ThreatIncident) ON (i.incident_class);

CREATE INDEX idx_threat_incident_risk_score IF NOT EXISTS
FOR (i:ThreatIncident) ON (i.risk_score);


// ============================================================================
// SECTION 3 — NODE LABEL PROPERTY CONTRACTS
// These comments are the authoritative property contracts for each node label.
// Neo4j does not enforce property schemas natively; enforcement happens via:
//   (a) GraphBuilder MERGE statements that always set required properties
//   (b) S1-08 integration test that asserts required properties are present
//   (c) Cypher parameterization linter (S2-02, S3-05) checks in CI
// ============================================================================

// ----------------------------------------------------------------------------
// (:Resource) — cloud asset from inventory engine
//
// Required properties (set by GraphBuilder ResourceResolver + loaders):
//   resource_uid        : String  — unique resource identifier (ARN/OCID/etc)
//   tenant_id           : String  — tenant scope (CP1-01 mandatory)
//   account_id          : String  — cloud account / subscription ID
//   provider            : String  — 'aws' | 'azure' | 'gcp' | 'oci' | 'alicloud'
//   region              : String  — cloud region
//   resource_type       : String  — e.g. 'EC2Instance', 'S3Bucket', 'IAMRole'
//   resource_name       : String  — human-readable name or display label
//   last_seen_at        : DateTime — from inventory last_seen_at
//
// Aggregated boolean flags (set by respective loaders; default false):
//   internet_exposed    : Boolean — from network/inventory exposure analysis
//   has_critical_cve    : Boolean — from VulnLoader (cvss >= 9.0)
//   has_high_misconfig  : Boolean — from MisconfigLoader (severity IN [critical,high])
//   is_admin_role       : Boolean — from IAM findings / CrownJewelClassifier
//   is_crown_jewel      : Boolean — from CrownJewelClassifier (asset_category=crown_jewel)
//   cdr_actor_seen      : Boolean — from CDRLoader (any CDREvent node attached)
//   on_attack_path      : Boolean — set by PathTagger after Tier 3 match
//
// Optional properties:
//   environment         : String  — 'production' | 'staging' | 'development'
//   asset_category      : String  — from resource_inventory_identifier
//   risk_score          : Integer — 0..100, from risk engine (if available)
//
// Additional runtime type labels applied at MERGE time (examples):
//   EC2Instance, S3Bucket, IAMRole, RDSInstance, LambdaFunction, KMSKey,
//   SecretsManagerSecret, EKSCluster, ServiceAccount, VPC, Subnet
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// (:MisconfigFinding) — from check_findings JOIN rule_metadata
//
// Required properties:
//   finding_id          : String  — check_findings.finding_id (sha256 truncated)
//   tenant_id           : String  — CP1-01 mandatory
//   rule_id             : String  — e.g. 'aws-ec2-imdsv2-not-required'
//   title               : String  — rule_metadata.check_title
//   severity            : String  — 'critical' | 'high' | 'medium' | 'low'
//   status              : String  — 'FAIL' | 'WARN'
//   mitre_techniques    : List<String>  — MITRE technique IDs (Sprint 0 tagging)
//   mitre_tactics       : List<String>  — MITRE tactic IDs (e.g. 'TA0001')
//   threat_category     : String  — from rule_metadata.threat_category
//   resource_uid        : String  — linked resource (also has FAILED_CHECK edge)
//   scan_run_id         : String  — from check_findings.scan_run_id
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// (:VulnFinding) — from scan_vulnerabilities JOIN cve_attack_mappings
//
// Required properties:
//   finding_id          : String  — scan_vulnerabilities primary key
//   tenant_id           : String  — CP1-01 mandatory
//   cve_id              : String  — e.g. 'CVE-2021-44228'
//   package_name        : String  — affected package
//   severity            : String  — 'critical' | 'high' | 'medium' | 'low'
//   cvss_score          : Float   — NVD CVSS v3 base score
//   mitre_techniques    : List<String>  — T1190 inferred for CVSS>=9.0 NETWORK
//   resource_uid        : String  — linked resource (also has HAS_CVE edge)
//   scan_run_id         : String  — from scan_vulnerabilities.scan_run_id
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// (:CDREvent) — from cdr_findings
//
// SECURITY (CP1-02 / SR-003):
//   actor_principal (raw email / IAM ARN / service account name) is PII.
//   It MUST NOT be stored as a node property in Neo4j.
//   CDRLoader must:
//     1. Compute actor_hash = sha256(actor_principal) before any MERGE
//     2. Write actor_hash to CDRActor node (not CDREvent)
//     3. Write only actor_principal_type to CDREvent (not the raw value)
//     4. Set tenant_id on every CDREvent node (SR-003)
//
// Required properties:
//   finding_id          : String  — cdr_findings.finding_id
//   tenant_id           : String  — CP1-01 + SR-003 mandatory
//   rule_id             : String  — CDR rule that fired
//   title               : String  — human-readable event description
//   severity            : String  — 'critical' | 'high' | 'medium' | 'low'
//   actor_principal_type: String  — 'IAMUser' | 'AssumedRole' | 'Service' etc.
//                                   NOT the raw actor_principal value (PII)
//   mitre_techniques    : List<String>  — MITRE technique IDs
//   resource_uid        : String  — linked resource (also has TRIGGERED edge)
//   event_time          : DateTime — from cdr_findings.event_time
//   scan_run_id         : String  — from cdr_findings.scan_run_id
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// (:CDRActor) — de-duplicated actor identity
//
// SECURITY (CP1-02):
//   actor_hash = sha256(actor_principal.encode('utf-8')).hexdigest()
//   The raw actor_principal value is NEVER written to this node or any
//   other Neo4j node. This is enforced structurally: CDRLoader computes
//   the hash before calling MERGE, and the hash is the only identifier used.
//   actor_principal_type describes the category of principal without revealing
//   the specific identity (e.g. 'AssumedRole' not 'arn:aws:sts::...:role/...').
//
// Required properties:
//   actor_hash          : String  — sha256(actor_principal) hex digest
//   tenant_id           : String  — CP1-01 mandatory
//   actor_principal_type: String  — 'IAMUser' | 'AssumedRole' | 'Service' | etc.
//   first_seen          : DateTime — earliest CDREvent event_time for this actor
//   last_seen           : DateTime — latest CDREvent event_time for this actor
//   event_count         : Integer — total CDR events attributed to this actor
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// (:ThreatIncident) — deduplicated incident (mirrors threat_incidents table)
//
// Required properties:
//   incident_id         : String  — threat_incidents.incident_id (UUID)
//   tenant_id           : String  — CP1-01 mandatory
//   incident_class      : String  — 'posture' | 'suspicious' | 'active'
//   severity            : String  — 'critical' | 'high' | 'medium' | 'low'
//   title               : String  — human-readable incident title
//   risk_score          : Integer — 0..100
//   entry_resource_uid  : String  — entry point resource
//   dedup_key           : String  — sha256(incident_class|entry_uid|tenant_id)
//   status              : String  — 'open' | 'suspicious' | 'active' | 'resolved'
// ----------------------------------------------------------------------------


// ============================================================================
// SECTION 4 — RELATIONSHIP TYPE CONTRACTS
// Neo4j does not enforce relationship schemas. These comments are the
// authoritative contracts used by GraphBuilder and the S1-08 integration test.
// ============================================================================

// (:Resource)-[:FAILED_CHECK]->(:MisconfigFinding)
//   Created by: MisconfigLoader
//   Properties: none required
//   Meaning: this Resource has a FAIL/WARN finding from the check engine

// (:Resource)-[:HAS_CVE]->(:VulnFinding)
//   Created by: VulnLoader
//   Properties: none required
//   Meaning: this Resource is affected by this CVE

// (:Resource)-[:TRIGGERED]->(:CDREvent)
//   Created by: CDRLoader
//   Properties: none required
//   Meaning: a CDR detection event was observed on this resource

// (:CDREvent)-[:PERFORMED_BY]->(:CDRActor)
//   Created by: CDRLoader
//   Properties: none required
//   Meaning: the CDR event was attributed to this actor (by actor_hash)

// (:Resource)-[:CONNECTED_TO]->(:Resource)
//   Created by: EdgeBuilder (from inventory_relationships)
//   Properties:
//     relation_type          : String  — from inventory_relationships.relation_type
//     attack_path_category   : String  — 'lateral_movement' | 'exposure' | etc.
//   Meaning: lateral movement / network connectivity edge

// (:Resource)-[:CONTAINS]->(:Resource)
//   Created by: EdgeBuilder
//   Properties:
//     relation_type          : String
//   Meaning: parent/child containment (VPC→Subnet, EKSCluster→Pod, etc.)

// (:ThreatIncident)-[:INVOLVES]->(:Resource)
//   Created by: IncidentWriter (after PatternExecutor)
//   Properties:
//     hop_position : Integer — position in attack path (0=entry, N=target)
//   Meaning: this resource is part of the incident's attack path

// (:ThreatIncident)-[:MATCHED]->(:MisconfigFinding)
//   Created by: IncidentWriter
//   Properties: none required
//   Meaning: this misconfig finding contributed evidence to the incident


// ============================================================================
// END OF SCHEMA
// ============================================================================
//
// Post-apply verification queries (run in Neo4j Browser against threat_v1 DB):
//
//   SHOW CONSTRAINTS;
//   SHOW INDEXES;
//
// Expected: 5 NODE KEY constraints, 1 UNIQUE constraint, ~30 indexes
//
// S1-08 integration test asserts:
//   - Resource node count >= 1
//   - MisconfigFinding node count >= 1
//   - At least 1 FAILED_CHECK edge present
//   - All Resource nodes have tenant_id property
//   - No Resource nodes visible without $tenant_id filter
//   - CDREvent nodes have tenant_id property (SR-003)
