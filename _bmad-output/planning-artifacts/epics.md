# threat-engine — Demo-Ready Full Platform Sprint
# Generated: 2026-05-02
# Owner: Anup Yadav
# Goal: Complete end-to-end demo experience for demo@cspm.local
#       Every page renders real data or is flagged with a clear gap story.
#       Multi-tenant (4 tenants) · Multi-CSP (AWS, Azure, GCP, OCI, AliCloud, K8s)

---

## Epic 1: Demo Baseline — Auth, Tenant Selector & Session

Goal: demo@cspm.local can log in, see tenant selector, switch tenants, and persist session correctly.

### Story 1.1: Demo Login & Session Cookie Flow
Verify demo@cspm.local / Demo@12345 logs in via the Django auth endpoint, receives an access_token cookie, and is redirected to /dashboard. Confirm that all 4 tenants appear in the tenant selector dropdown. The selected tenant sets the `X-Tenant-ID` context header used by all engine API calls.

Acceptance Criteria:
- Login succeeds, session cookie set, redirect to /dashboard
- Tenant selector shows: anup's Organization, Multi-Cloud Platform, Test Tenant 002, Tenant 1
- Switching tenants reloads dashboard data scoped to the new engine_tenant_id
- platform_admin role confirmed via /gateway/api/v1/auth/me endpoint

### Story 1.2: Auth Flows — Signup, Invite, Forgot Password
Verify that auth/signup, auth/invite/[token], auth/forgot-password, and auth/reset-password pages render and function. These are pre-login paths that must work for the onboarding demo flow.

Acceptance Criteria:
- /auth/login renders and accepts demo@cspm.local credentials
- /auth/signup renders (can be a waitlist/invite-only stub)
- /auth/forgot-password renders and submits an email request
- /auth/reset-password renders with a valid token parameter

---

## Epic 2: Dashboard — Posture Score & Multi-Cloud Summary

Goal: /dashboard shows real posture scores, finding counts by severity, CSP distribution charts, and trending data sourced from the engine DBs.

### Story 2.1: Dashboard — Overall Posture Score Card
The posture score card at the top of /dashboard should show a 0-100 score derived from check_findings + threat_findings per tenant. The BFF view handler at /gateway/api/v1/views/dashboard must aggregate data from check and threat engines.

Acceptance Criteria:
- Posture score card renders with numeric score per active tenant
- Score changes when tenant is switched
- Score is NOT hardcoded — derived from live DB counts

### Story 2.2: Dashboard — Findings by Severity Bar Chart
The severity breakdown (Critical / High / Medium / Low / Info) bar chart on /dashboard must reflect live check_findings counts for the active tenant across all CSPs.

Acceptance Criteria:
- Chart shows counts for each severity level
- Tenant switch updates counts
- Empty CSPs show zero bars, not errors

### Story 2.3: Dashboard — CSP Distribution Donut Chart
Show the split of findings by cloud provider (AWS, Azure, GCP, OCI, AliCloud, K8s) for the active tenant as a donut/pie chart.

Acceptance Criteria:
- Donut segments per CSP rendered with correct CSP colors from CLOUD_PROVIDERS constant
- Tenant "Multi-Cloud Platform" shows AWS + K8s + OCI + GCP + AliCloud + Azure segments
- Hovering shows count + percentage

### Story 2.4: Dashboard — Scan History Timeline
Show the last 10 scan runs for the active tenant with timestamps and status (success/failed/running). Pulling from scan_orchestration table via the onboarding engine BFF.

Acceptance Criteria:
- Timeline list shows scan_run_id, started_at, status, engines_requested
- Clicking a scan_run navigates to /scans/[scanId]
- At least 3 historical scans visible for Multi-Cloud Platform and anup's Organization

### Story 2.5: Dashboard — Top 10 At-Risk Resources Widget
Show top 10 resources with the highest combined finding severity score (critical×4 + high×3 ...) sourced from check_findings or risk engine for the active tenant.

Acceptance Criteria:
- List shows resource_uid, resource_type, provider, severity count
- Clicking a resource navigates to /inventory/[assetId]
- Works for both my-tenant and 00000000...

---

## Epic 3: Onboarding — Accounts, Wizard, Tenants, Users, Scans

Goal: The onboarding section shows real cloud accounts, allows new account onboarding via wizard, and shows users/tenants for the demo admin.

### Story 3.1: Onboarding — Cloud Accounts List
/onboarding renders all cloud accounts linked to the active tenant from the onboarding engine. Each account shows CSP, account_id, credential_type, status, and last scan date.

Acceptance Criteria:
- At least 6 accounts visible across the 2 main tenants (one per CSP)
- Account status shows "active" or "pending"
- "Trigger Scan" button per account
- Account click navigates to /onboarding/accounts/[accountId]

### Story 3.2: Onboarding — Account Detail Page
/onboarding/accounts/[accountId] shows account metadata, credential info (masked), linked scan history, and a per-engine findings summary for that account.

Acceptance Criteria:
- Account metadata: CSP, region(s), credential_ref (masked), created_at
- Last 5 scan runs for this account
- Finding counts by engine (discoveries, check, threat, compliance)

### Story 3.3: Onboarding — Wizard Multi-CSP Flow
/onboarding/wizard shows a step-by-step wizard for adding a new cloud account. Steps: Choose CSP → Enter credentials → Validate → Select engines → Confirm.

Acceptance Criteria:
- CSP picker shows AWS, Azure, GCP, OCI, AliCloud, K8s with icons
- AWS step accepts access_key_id + secret_access_key or IAM role ARN
- Azure step accepts tenant_id + client_id + client_secret
- GCP step accepts service account JSON upload
- Validate step calls /onboarding/api/v1/credentials/validate
- Confirm creates account and triggers initial discovery scan

### Story 3.4: Onboarding — Users Management
/onboarding/users shows all users in the platform for platform_admin role. Includes invite flow.

Acceptance Criteria:
- List shows demo@cspm.local, admin@cspm.local, yadav.anup@gmail.com with roles
- "Invite User" button opens email + role selection modal
- Role picker shows: platform_admin, org_admin, tenant_admin, analyst, viewer

### Story 3.5: Onboarding — Tenants Management
/onboarding/tenants shows all 4 tenants with their engine_tenant_id, status, member count, and account count.

Acceptance Criteria:
- Table shows: anup's Organization, Multi-Cloud Platform, Test Tenant 002, Tenant 1
- engine_tenant_id displayed (or tooltipped)
- Member count and cloud account count per tenant
- "Manage" opens tenant detail

### Story 3.6: Scans — History, Detail & Trigger
/scans shows scan run history per tenant. /scans/[scanId] shows per-engine status for that run.

Acceptance Criteria:
- Scan list filterable by tenant, CSP, status
- Scan detail shows each engine's status (pending/running/done/failed), findings count, duration
- "Re-trigger Scan" button triggers via Argo workflow API
- scan_run_id displays as a copyable chip

### Story 3.7: Onboarding — Getting Started Page
/onboarding/getting-started is the first-run experience after login. Shows progress checklist: Add Account → Run Scan → View Dashboard → Invite Team.

Acceptance Criteria:
- Checklist items marked ✓ when completed (persisted per user)
- "Add Account" links to /onboarding/wizard
- Demo account shows 3/4 steps complete

---

## Epic 4: Inventory — Assets, Architecture & Graph

Goal: /inventory shows the full asset list across all CSPs; /inventory/graph shows the Neo4j relationship graph; /inventory/architecture shows containment hierarchy.

### Story 4.1: Inventory — Asset Table with Multi-CSP Filters
/inventory shows all discovered resources for the active tenant, filterable by provider, resource_type, region, and severity.

Acceptance Criteria:
- Table shows: resource_uid, resource_type, provider, region, account_id, last_seen_at
- Filter by provider: AWS, Azure, GCP, OCI, AliCloud, K8s dropdowns
- Filter by resource_type (multi-select)
- Pagination with 50 rows per page
- Total asset count by provider shown in header chips

### Story 4.2: Inventory — Asset Detail Page
/inventory/[assetId] shows full asset metadata, related findings, and linked relationships.

Acceptance Criteria:
- Resource attributes from discovery_findings JSONB details
- Related check_findings for this resource_uid (severity list)
- Related threat_findings for this resource_uid
- Linked resources (parent/children via inventory relationships)

### Story 4.3: Inventory — Architecture (Containment) Graph
/inventory/architecture shows containment hierarchy: CSP Account → Region → VPC/VNet → Subnet → EC2/VM/Pod etc.

Acceptance Criteria:
- Tree/graph renders for AWS (VPC → Subnet → EC2/RDS/Lambda)
- Renders for K8s (Cluster → Namespace → Deployment → Pod)
- Nodes color-coded by severity of findings
- Clickable nodes navigate to asset detail

### Story 4.4: Inventory — Security Relationship Graph (Neo4j)
/inventory/graph shows the security relationship graph powered by Neo4j Aura (neo4j+s://17ec5cbb.databases.neo4j.io). Shows CONNECTS_TO, CONTAINS, HAS_ROLE, HAS_POLICY relationships.

Acceptance Criteria:
- Graph loads within 5 seconds for demo tenant
- Node types: Resource, Identity, Policy, Finding
- Edge types: CONTAINS, CONNECTS_TO, HAS_ROLE, EXPOSES
- Filter panel: node type, CSP, severity
- Clicking a node shows sidebar with entity details

---

## Epic 5: Threat Detection & Attack Paths (PRIORITY)

Goal: /threats and all sub-pages render real MITRE ATT&CK findings; /threats/attack-paths shows graphical attack chains; attack path must be navigable end-to-end.

### Story 5.1: Threats — Detection Table
/threats shows all threat_findings for the active tenant with MITRE technique, severity, resource, CSP, and status. Currently has data for AWS (6442), K8s (2061), Azure (177), GCP (64), OCI (52), AliCloud (64).

Acceptance Criteria:
- Table shows: technique_id, technique_name, tactic, resource_uid, provider, severity, status
- Filter by provider, tactic, severity
- Findings count displayed per CSP in header
- Row click navigates to /threats/[threatId]

### Story 5.2: Threats — Threat Detail Page
/threats/[threatId] shows full finding detail: MITRE ATT&CK technique, affected resource, evidence/description, remediation steps, and links to related check/compliance findings.

Acceptance Criteria:
- MITRE technique rendered with tactic → technique hierarchy
- Affected resource links to /inventory/[assetId]
- "Related Findings" section shows check_findings for same resource
- Remediation panel shows recommended action
- Severity badge, status chip (open/resolved/suppressed)

### Story 5.3: Threats — Attack Paths (PRIORITY FEATURE)
/threats/attack-paths shows graphical attack chain visualization: entry point → lateral movement → target. Must show real attack paths derived from the threat engine's attack_chain data.

Acceptance Criteria:
- DAG graph renders at least 5 attack paths for Multi-Cloud Platform tenant (AWS)
- Each path shows: entry_node → step_nodes → target_node with severity coloring
- Node labels show resource_type + technique_id
- Clicking a node opens resource/finding sidebar
- Filter by CSP, entry technique, severity
- K8s attack paths visible (has 2061 K8s threat findings)
- Export attack path as PNG / PDF button

### Story 5.4: Threats — Toxic Combinations
/threats/toxic-combinations shows correlated high-risk finding pairs that together create elevated exposure (e.g., public S3 + overpermissioned IAM role).

Acceptance Criteria:
- At least 10 toxic combination entries for Multi-Cloud Platform AWS
- Each combo shows: resource_a + resource_b, combined_risk_score, narrative
- Filter by CSP, severity
- Clicking a combo shows detail with individual findings

### Story 5.5: Threats — Threat Graph (D3 Node Graph)
/threats/graph shows a D3/Cytoscape force-directed graph of threat findings linked to resources and attack paths.

Acceptance Criteria:
- Graph renders up to 200 nodes without crashing
- Nodes: threats (red), resources (blue), identities (purple)
- Edges: TARGETS, EXPLOITS, COMPROMISES
- Zoom/pan controls
- Legend overlay

### Story 5.6: Threats — Timeline View
/threats/timeline shows a chronological Gantt-style timeline of when threat findings first_seen_at and last_seen_at, grouped by day.

Acceptance Criteria:
- Timeline spans last 30 days
- Each bar represents a threat finding
- Color-coded by severity
- Clicking a bar navigates to threat detail
- Tenant-aware, CSP-filterable

### Story 5.7: Threats — Blast Radius
/threats/blast-radius shows the blast radius analysis from the risk engine: which resources are reachable from a compromised entry point.

Acceptance Criteria:
- Blast radius circle visualization: inner = directly compromised, outer rings = lateral reach
- Sourced from risk_engine (risk_scenarios + risk_summary tables)
- Threat entry point selector dropdown
- "Affected Resources" list on the right with severity + resource_type

---

## Epic 6: Compliance — Frameworks, Matrix & Remediation

Goal: /compliance shows all 19 compliance frameworks with real scores; /compliance/matrix shows multi-cloud heatmap; framework detail shows control-by-control pass/fail.

### Story 6.1: Compliance — Framework List with Scores
/compliance shows all 19 frameworks (CIS_AWS, CIS_AZURE, CIS_GCP, CIS_K8S, CIS_OCI, CIS_ALICLOUD, CIS_IBM, PCI_DSS, HIPAA, GDPR, SOC2, ISO27001_2022, CANADA_PBMM, RBI_BANK, RBI_NBFC, NIST_800_53, NIST_800_171, FedRAMP_Moderate, CISA_CE) with a compliance percentage score per active tenant.

Data state: compliance_findings currently has NULL provider for 00000000 AWS findings — this is a known data quality bug (Story 14.1 will fix). For demo, use my-tenant which has clean framework mappings.

Acceptance Criteria:
- Framework cards show: framework name, score %, pass/fail counts
- At least 10 frameworks show non-zero scores for my-tenant
- Framework score = (PASS / total) × 100 from compliance_findings
- "View Details" navigates to /compliance/[framework]

### Story 6.2: Compliance — Framework Detail Page
/compliance/[framework] (e.g., /compliance/CIS_AWS) shows control-level breakdown: each control with PASS/FAIL/SKIPPED status, affected resources, and remediation links.

Acceptance Criteria:
- Control list grouped by section (e.g., 1.x Identity, 2.x Logging...)
- Each control: control_id, control_name, status, resource count
- Clicking a control expands to show affected resource_uids
- "View Failing Resources" links to filtered check/compliance findings
- Pass percentage progress bar per section

### Story 6.3: Compliance — Multi-Cloud Heatmap Matrix
/compliance/matrix shows a CSP × Framework heatmap: rows = frameworks, columns = CSPs (AWS, Azure, GCP, OCI, AliCloud, K8s). Cells show compliance % with red→yellow→green coloring.

Acceptance Criteria:
- 6×19 matrix renders (or 6×10 for frameworks with data)
- Color scale: <50% red, 50-80% yellow, >80% green
- Cell hover shows exact score
- Click on cell filters to that CSP's framework detail

### Story 6.4: Compliance — Remediation Queue
/compliance/remediation shows FAIL findings ordered by priority (framework criticality × severity) as an actionable queue.

Acceptance Criteria:
- List shows: control_id, framework, severity, resource_uid, provider
- Ordered by composite priority score
- "Mark Resolved" action updates finding status
- Filter by framework, CSP, severity

---

## Epic 7: Security Posture — Misconfig, IAM, Network, Data Security

Goal: All 4 security posture sub-pages render real data for all CSPs.

### Story 7.1: Misconfig — Check Findings Table
/misconfig shows check_findings for the active tenant across all CSPs. Currently has 18948 K8s + 9631 AWS + 4203 AWS-my-tenant findings.

Acceptance Criteria:
- Table: rule_id, rule_name, resource_uid, resource_type, provider, region, severity, status
- Filter by CSP, severity, status (PASS/FAIL/SKIP)
- Row click → /check/[provider]/[checkId] detail page
- Bulk actions: suppress, mark resolved
- Export to CSV

### Story 7.2: Misconfig — Check Finding Detail
/check/[provider]/[checkId] shows full check finding: rule definition, resource, evidence, remediation guidance, and compliance framework mappings.

Acceptance Criteria:
- Rule title, description, rationale
- Affected resource with link to inventory
- Raw evidence (JSON from check_findings.details)
- Remediation steps with code example
- Framework controls this rule maps to (from rule_control_mapping)

### Story 7.3: IAM Security — Identity Posture Dashboard
/iam shows IAM posture metrics: over-privileged identities, stale credentials, cross-account access, root account usage. Currently has: my-tenant (AWS 10k, Azure 10k, OCI 10k, AliCloud 5k, GCP 5k, K8s 5k).

Acceptance Criteria:
- Summary cards: total identities, overprivileged count, stale creds, MFA disabled
- Findings table with provider filter
- Filter by provider, finding type, severity
- At least 5 CSPs have data visible

### Story 7.4: Network Security — 7-Layer Topology Dashboard
/network-security shows network security findings from the network engine (Layer 1 = check-based, Layer 2 = topology). Currently has data in network_findings for AWS, K8s, OCI, Azure, GCP, AliCloud.

Acceptance Criteria:
- Layer summary cards: L1 Isolation, L2 Reachability, L3 ACL, L4 SG Rules, L5 LB, L6 WAF, L7 Monitoring
- Findings table filterable by layer, CSP, severity
- Topology diagram for AWS (VPC → Subnet segmentation view)
- Non-AWS CSPs show flat topology (known gap — flagged in Story 7.5)

### Story 7.5: Network Security — Non-AWS 7-Layer Refactor [FLAG]
Azure, GCP, OCI, and AliCloud network providers currently use flat implementations and do not follow the 7-layer sub-module structure. This story tracks the refactor.

Acceptance Criteria:
- Azure network provider (`providers/azure.py`) refactored to 7-layer model
- GCP network provider refactored to 7-layer model
- OCI and AliCloud flagged as in-progress with a placeholder sub-layer stub
- All non-AWS topology pages show at least L1+L4 data

### Story 7.6: Data Security — Classification & Sensitivity
/datasec shows data classification findings: sensitive data stores, encryption status, access policies. Engine runs on AWS, Azure.

Acceptance Criteria:
- Summary: total sensitive resources, unencrypted stores, public data stores
- Table: resource_uid, data_type, sensitivity_level, encryption_status, provider
- Provider filter (AWS, Azure)
- Click → datasec finding detail

### Story 7.7: Data Security — Lineage Graph
/datasec/lineage shows the data flow lineage graph: where sensitive data originates, moves, and is consumed.

Acceptance Criteria:
- Graph renders for AWS S3/RDS lineage nodes
- Node types: Source, Transform, Sink
- Edge labels: READS_FROM, WRITES_TO, COPIES_TO
- At least 1 lineage path visible for Multi-Cloud Platform AWS

---

## Epic 8: CIEM — Cloud Identity & Entitlement Management

Goal: /ciem shows entitlement analysis, over-privileged roles, cross-account privilege escalation paths across all CSPs.

### Story 8.1: CIEM — Entitlement Dashboard
/ciem shows CIEM findings for the active tenant: unused permissions, wildcard policies, cross-account roles, privilege escalation paths.

Current data: CIEM findings in ciem engine log analysis tables (not check_findings). Verify CIEM engine has data for my-tenant + 00000000.

Acceptance Criteria:
- Summary cards: over-privileged identities, unused permission count, privilege escalation paths found, cross-account risks
- Findings table: identity_id, permission_type, risk_type, provider, severity
- Filter by provider (all 6 CSPs)
- At least AWS + Azure + GCP data visible

### Story 8.2: CIEM — Privilege Escalation Paths
CIEM privilege escalation path graph: show identity → permission → resource chains where an identity can escalate to admin/root.

Acceptance Criteria:
- Graph shows at least 3 escalation paths for AWS tenant
- Path nodes: IAM user/role → permission → target resource
- Color: red = direct path, orange = indirect
- Clicking a path shows step-by-step escalation narrative

### Story 8.3: CIEM — Unused Permissions Cleanup
CIEM findings table filtered to "unused in last 90 days" — actionable list for permission trimming.

Acceptance Criteria:
- Table: identity, permission, last_used, days_since_use, risk_level
- Filter by CSP, identity_type (user/role/service_account)
- "Mark Reviewed" status action
- Export to CSV for remediation workflow

---

## Epic 9: Enterprise Security Pillars — Encryption, DBSec, Container, AI Security

Goal: All 4 enterprise engine pages render real data for available CSPs.

### Story 9.1: Encryption — Key Management Overview
/encryption shows encryption posture: CMK vs. AWS-managed keys, unencrypted resources, key rotation status across AWS, Azure, GCP, OCI.

Acceptance Criteria:
- Summary: total encryption keys, rotation enabled %, unencrypted critical resources
- Table: key_id, provider, key_type, rotation_enabled, associated_resources, severity
- Provider filter
- At least AWS + Azure data visible

### Story 9.2: Encryption — Key Detail Page
/encryption/key-detail shows details for a specific encryption key: metadata, rotation history, associated resources, policy.

Acceptance Criteria:
- Key metadata: key_id, type, creation_date, next_rotation_date
- Associated resource list (S3 buckets, RDS, EBS using this key)
- Policy JSON viewer
- Risk indicators (if key has broad access)

### Story 9.3: Database Security — DB Posture Dashboard
/database-security shows database security findings: public accessibility, unencrypted DBs, weak auth, audit logging disabled across all CSPs.

Acceptance Criteria:
- Summary: public DBs, unencrypted DBs, audit logging disabled count
- Table: db_instance, provider, engine_type, severity, finding_type
- Filter by provider, db_engine_type (RDS/CosmosDB/CloudSQL/etc.)
- At least AWS + Azure + GCP visible

### Story 9.4: Container Security — Container Posture
/container-security shows container security findings: image vulnerabilities, privileged containers, root containers, missing network policies.

Acceptance Criteria:
- Summary: total containers scanned, critical vulnerabilities, privileged count
- Table: container_name, cluster, namespace, severity, finding_type
- Filter by cluster (K8s clusters in scope)
- Image CVE count column

### Story 9.5: AI Security — AI Model & Service Posture
/ai-security shows findings related to AI/ML services: SageMaker, Vertex AI, Azure ML — access controls, data exposure, model integrity.

Acceptance Criteria:
- Summary: AI services discovered, findings by severity
- Table: service_name, provider, finding_type, severity
- At least AWS SageMaker findings visible
- No 403 errors for platform_admin role

---

## Epic 10: Vulnerability — Dashboard, Scans, CVE Explorer, Agents

Goal: /vulnerability and all sub-pages show real CVE data from the vulnerability engine.

### Story 10.1: Vulnerability — Main Dashboard
/vulnerability shows aggregate vulnerability posture: CVE counts by severity, EPSS score distribution, affected assets count, SLA breach tracking.

Acceptance Criteria:
- Cards: Critical CVEs, High CVEs, EPSS >70 count, SLA breached count
- Severity donut chart
- Top 10 CVEs by EPSS score list
- Asset coverage: % of resources scanned

### Story 10.2: Vulnerability — Scans List & Detail
/vulnerability/scans lists all vulnerability scans per tenant. /vulnerability/scans/[scanId] shows findings for that scan.

Acceptance Criteria:
- Scan list: scan_id, started_at, completed_at, resource_count, cve_count, status
- Scan detail: CVE table with cve_id, severity, EPSS, affected_package, fix_version
- Filter by severity, fixed/unfixed
- "Trigger New Scan" button

### Story 10.3: Vulnerability — CVE Explorer
/vulnerability/cves shows a searchable CVE database filtered to CVEs affecting the tenant's resources.

Acceptance Criteria:
- Search by CVE ID (e.g., CVE-2024-xxxx)
- Filter by severity, EPSS threshold, affected asset
- CVE detail: NVD description, CVSS score, EPSS score, affected packages, fix available
- "Affected Assets" list per CVE

### Story 10.4: Vulnerability — Agents
/vulnerability/agents lists deployed vulnerability scanning agents (spot scanner pods). Shows status, last_scan, resource_count.

Acceptance Criteria:
- Agent list: agent_id, node, status, last_scan, scan_count
- "Deploy Agent" triggers spot scanner pod via K8s API
- Agent logs accessible

---

## Epic 11: Code Security — SecOps IaC & DAST

Goal: /secops and all sub-pages show IaC scanning results across all 14 supported languages.

### Story 11.1: SecOps — IaC Findings Dashboard
/secops shows IaC scan findings: misconfigurations in Terraform, CloudFormation, Kubernetes YAML, Helm, Ansible, Pulumi, ARM, Bicep, CDK, OpenAPI, Dockerfile, GitHub Actions, Kustomize, Serverless.

Acceptance Criteria:
- Summary: total projects scanned, critical findings, frameworks covered
- Findings table: rule_id, file_path, line_number, severity, provider, language
- Filter by language/framework, severity
- At least 2 IaC languages have findings

### Story 11.2: SecOps — Scan Detail
/secops/[scanId] shows findings for a specific IaC scan: file tree with annotated issues, finding count per file.

Acceptance Criteria:
- File tree with finding badges
- Finding detail: code snippet, line number, rule description, remediation
- CWE/CVE mapping where applicable

### Story 11.3: SecOps — Projects
/secops/projects shows all IaC project repositories that have been scanned (linked to Git repos or file uploads).

Acceptance Criteria:
- Project list: project_name, repo_url, last_scan, finding_count, risk_score
- Clicking project shows scan history

### Story 11.4: SecOps — Reports
/secops/reports shows scan summary reports exportable as PDF/HTML.

Acceptance Criteria:
- Report list: report_id, project, date, finding_summary
- "Generate Report" button
- PDF download triggers

### Story 11.5: SecOps — DAST Scan Detail
/secops/dast/[scanId] shows Dynamic Application Security Test results.

Acceptance Criteria:
- DAST findings: endpoint, vulnerability_type, severity, evidence
- Status: open/confirmed/false_positive

---

## Epic 12: Risk & CNAPP

Goal: /risk shows risk scores and blast radius; /cnapp shows unified cross-pillar risk view; /cwpp shows workload protection.

### Story 12.1: Risk — Risk Scoring Dashboard
/risk shows risk scenarios and risk summary: attack surface score, blast radius score, overall risk score per tenant.

Acceptance Criteria:
- Overall risk score (0-100) gauge chart
- Attack surface area chart by CSP
- Top 10 risk scenarios: scenario_name, score, contributing_factors
- Trend line (score over last 30 days)

### Story 12.2: Risk — Blast Radius Detail
Drill-down from /risk into a specific resource's blast radius: what can an attacker reach from this entry point.

Acceptance Criteria:
- Entry point resource selector
- Reachable resources list: resource_uid, hops, access_type
- Radius visualization (concentric circles)

### Story 12.3: CNAPP — Unified Risk View
/cnapp shows correlated findings across all pillars (check + threat + vuln + iam + network) into a single risk score per resource.

Acceptance Criteria:
- Resource table with composite CNAPP score
- Score breakdown: check_score, threat_score, vuln_score, iam_score, network_score
- Filter by CSP, score threshold

### Story 12.4: CWPP — Workload Protection
/cwpp shows Cloud Workload Protection: runtime threats, container escapes, suspicious process activity.

Acceptance Criteria:
- Workload findings: pod/instance, finding_type, severity
- Filter by cluster, namespace
- At least K8s workload data visible

---

## Epic 13: Policies, Rules & Settings

Goal: Policy management, rule CRUD, and platform/user/tenant settings pages all function for demo admin.

### Story 13.1: Policies — Policy List & Detail
/policies shows all active security policies for the tenant. /policies/add allows creating a new policy.

Acceptance Criteria:
- Policy list: policy_name, scope, rule_count, status, created_by
- Add policy form: name, scope (tenant/account), linked rules (multi-select)
- Policy detail shows linked rules and compliance framework mappings

### Story 13.2: Rule Management
/rules shows all YAML-based check rules registered in the rule engine DB. Allows enabling/disabling rules per tenant.

Acceptance Criteria:
- Rule table: rule_id, title, provider, severity, status (active/inactive)
- Filter by CSP, severity, service
- Toggle active/inactive per rule (calls rule engine API)
- At least 100 rules visible (rule catalog loaded from DB)

### Story 13.3: Settings — Platform Config
/settings shows platform-level settings for platform_admin: session timeout, SMTP config, SSO config placeholder.

Acceptance Criteria:
- Session timeout field (default 8h)
- SMTP config (sender email, SMTP host)
- Current SSO config placeholder (links to IDP management)

### Story 13.4: Settings — User Management
/settings/users shows all platform users with roles and tenant memberships.

Acceptance Criteria:
- User table: email, role, tenants, status, last_login
- "Add User" → /settings/users/add with invite form
- "Edit Role" inline for platform_admin

### Story 13.5: Settings — Tenant Management
/settings/tenants shows all tenants with engine_tenant_id, status, plan.

Acceptance Criteria:
- Tenant table: name, engine_tenant_id, status, plan, member_count
- Edit tenant metadata
- "Deactivate" tenant action (requires confirmation)

### Story 13.6: Notifications — Alert Configuration
/settings/notifications (or /notifications) shows alert rules: severity thresholds, email/Slack destinations.

Acceptance Criteria:
- Alert rules list: trigger (severity + engine), destination, status
- Add alert rule form
- Test notification button

### Story 13.7: Reports — Scheduled & On-Demand
/reports shows available compliance/posture reports, allows generating new ones.

Acceptance Criteria:
- Report types: Executive Summary, Compliance Report, Vulnerability Report, Threat Summary
- "Generate Now" triggers background job
- Download PDF/JSON when ready

---

## Epic 14: Multi-CSP Data Gap Remediation

Goal: Ensure every engine has findings for every CSP that the demo admin needs to showcase. Flag what's missing and create stories to fix data gaps.

### Story 14.1: Compliance — Fix NULL Provider Bug for tenant 00000000
compliance_findings for tenant 00000000-0000-0000-0000-000000000001 has provider=NULL and compliance_framework=NULL for 4341+2476 rows. This makes the compliance page show blank for Multi-Cloud Platform. Root cause: compliance engine not writing provider/framework fields when ingesting from check_findings.

Acceptance Criteria:
- Backfill script runs and sets provider from check_findings.provider for matching scan_run_id + resource_uid
- Compliance page for Multi-Cloud Platform tenant shows AWS framework scores
- All new compliance_findings inserts include non-null provider and compliance_framework

### Story 14.2: Threat — Add Azure/AliCloud/GCP/OCI/K8s Findings for test-tenant-002
test-tenant-002 currently has only AWS check_findings and zero threat/compliance/network findings. For demo, either trigger a re-scan or backfill with realistic synthetic threat findings.

Acceptance Criteria:
- test-tenant-002 has at least 50 threat findings across 3+ CSPs
- Compliance framework CIS_AWS has data for test-tenant-002
- Network engine has at least 20 findings for test-tenant-002

### Story 14.3: K8s — Compliance Coverage for tenant 00000000
tenant 00000000-0000-0000-0000-000000000001 has 1412 K8s discovery findings and 18948 K8s check findings but zero K8s compliance_findings with CIS_K8S framework. Re-run compliance engine for K8s scan_run_id for this tenant.

Acceptance Criteria:
- CIS_K8S compliance findings present for tenant 00000000
- Compliance matrix cell for K8s × CIS_K8S shows non-zero score

### Story 14.4: Threat — Fill Azure/K8s Gaps for my-tenant
my-tenant has 0 Azure threat findings and 0 K8s compliance_findings in the 00000000 tenant. Trigger threat engine for Azure scan_run_id.

Acceptance Criteria:
- my-tenant Azure threat findings > 20
- my-tenant K8s compliance_findings with CIS_K8S > 0

### Story 14.5: CIEM — Verify All CSP Coverage
CIEM engine has log-based data. Verify CIEM findings exist for AWS, Azure, GCP, AliCloud, OCI for both my-tenant and 00000000.

Acceptance Criteria:
- CIEM findings for 5 CSPs in at least 1 tenant
- CIEM page shows provider distribution chart

### Story 14.6: Encryption/DBSec/Container/AI — AWS + Azure Coverage Verification
These enterprise engines should have data for AWS and Azure at minimum. Verify findings exist and pages render.

Acceptance Criteria:
- encryption_findings: AWS + Azure rows in at least 1 tenant
- dbsec_findings: AWS + Azure + GCP rows
- container_sec_findings: K8s + AWS rows
- ai_security_findings: AWS rows

---

## Epic 15: UI Polish — Empty States, Error Boundaries & Loading Skeletons

Goal: Every page handles empty data gracefully with an appropriate empty state. No raw JSON errors or blank white screens in the demo.

### Story 15.1: Add Empty State Components to All Engine Pages
Each engine page (compliance, threats, network, iam, ciem, datasec, encryption, dbsec, container, ai-security) must show a meaningful empty state when the engine returns 0 findings, instead of a blank area or console error.

Acceptance Criteria:
- Empty state: icon + "No findings for this tenant/CSP" + "Trigger Scan" CTA
- Applies to: /compliance, /threats, /network-security, /iam, /ciem, /datasec, /encryption, /database-security, /container-security, /ai-security

### Story 15.2: Loading Skeletons for Dashboard & Heavy Pages
/dashboard, /inventory, /threats, /compliance must show skeleton loading cards while BFF data loads, preventing layout shift.

Acceptance Criteria:
- Skeleton cards match the shape of the real content
- Minimum 300ms display (prevents flash)
- Skeleton disappears on data arrival, not timeout

### Story 15.3: Error Boundary — Engine Timeout Handling
If a BFF engine call times out (>10s) or returns 5xx, the page must show a recoverable error state rather than crashing.

Acceptance Criteria:
- Error boundary wraps each engine data section independently
- Error state: "Unable to load [Engine] data — Retry" button
- One failing engine does not block other sections from rendering

### Story 15.4: Tenant Scope Guard — Prevent Cross-Tenant Data Leaks
All BFF view handlers must validate that the requested tenant_id matches the session's TenantUsers membership. A platform_admin can access all tenants; lower roles are restricted.

Acceptance Criteria:
- Non-admin user requesting a tenant they don't belong to receives 403
- platform_admin can switch to any tenant without 403
- API responses never include engine_tenant_id in the response body (use platform tenant UUID only)
