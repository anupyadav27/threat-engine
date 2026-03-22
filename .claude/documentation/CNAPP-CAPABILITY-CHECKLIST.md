# CNAPP / CSPM Comprehensive Capability Checklist

> **Purpose**: Gap-analysis reference for evaluating a CSPM/CNAPP platform against industry standards.
> **Based on**: Gartner 2025 CNAPP Market Guide, Forrester Wave Q1 2026, and feature analysis of Wiz, Prisma Cloud/Cortex Cloud, Orca Security, and Fortinet FortiCNAPP (Lacework).
> **Created**: 2026-03-19

---

## How to Use This Checklist

For each capability, mark status as:
- **[FULL]** -- Fully implemented and production-ready
- **[PARTIAL]** -- Some implementation exists, gaps remain
- **[PLANNED]** -- On roadmap but not yet built
- **[NONE]** -- Not implemented, not planned
- **[N/A]** -- Not applicable to the platform's scope

---

## 1. CSPM -- Cloud Security Posture Management

### 1.1 Asset Visibility & Inventory
- [ ] Multi-cloud resource discovery (AWS, Azure, GCP, OCI, AliCloud, IBM)
- [ ] Automatic asset enumeration across all regions and accounts
- [ ] Real-time or near-real-time asset inventory updates
- [ ] Asset classification and tagging (by type, criticality, owner, environment)
- [ ] Shadow IT / unmanaged resource detection
- [ ] Asset relationship mapping (dependencies, parent-child, network adjacency)
- [ ] Resource lifecycle tracking (creation, modification, deletion history)
- [ ] Multi-account / organization hierarchy support
- [ ] Asset search and filtering (by any attribute, tag, or property)
- [ ] SBOM (Software Bill of Materials) for deployed workloads

### 1.2 Misconfiguration Detection
- [ ] Predefined misconfiguration rules (500+ out-of-box)
- [ ] Custom rule authoring (YAML/JSON/Rego/OPA)
- [ ] Severity classification (Critical / High / Medium / Low / Info)
- [ ] Auto-discovery of new resource types and configuration drift
- [ ] Service-specific deep checks (IAM policies, S3 buckets, security groups, etc.)
- [ ] Cross-resource misconfiguration correlation (e.g., public S3 + no encryption)
- [ ] Configuration drift detection from baseline
- [ ] Real-time change detection (CloudTrail/Activity Log event-driven)
- [ ] Suppression / exception management (mute known-acceptable findings)
- [ ] Evidence collection (snapshot of misconfigured state for audit)

### 1.3 Compliance Monitoring
- [ ] Framework library (CIS Benchmarks, NIST 800-53, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2, SOX, FedRAMP, MITRE ATT&CK, CSA CCM)
- [ ] 100+ framework mappings (industry, regulatory, custom)
- [ ] Custom framework authoring
- [ ] Control-to-finding mapping (which findings violate which controls)
- [ ] Compliance scoring (per-framework, per-account, per-resource-type)
- [ ] Compliance trend tracking over time
- [ ] Exportable compliance reports (PDF, CSV, JSON)
- [ ] Audit-ready evidence packages
- [ ] Multi-tenant compliance views (per customer / business unit)
- [ ] Continuous compliance monitoring (not just point-in-time)
- [ ] Compliance gap analysis with prioritized remediation

### 1.4 Risk Scoring & Prioritization
- [ ] Contextual risk scoring (0-100 or equivalent) per finding
- [ ] Risk aggregation per resource, account, and organization
- [ ] Risk factors: severity, exploitability, blast radius, data sensitivity, exposure
- [ ] Environmental context (internet-facing, production vs. dev, data classification)
- [ ] Noise reduction (de-duplication, suppression of low-signal alerts)
- [ ] Risk trending over time (improving or degrading posture)
- [ ] Executive risk dashboards
- [ ] Risk SLA tracking (time-to-remediate by severity)

---

## 2. CWPP -- Cloud Workload Protection Platform

### 2.1 Vulnerability Management
- [ ] Agentless vulnerability scanning (SideScanning / snapshot-based)
- [ ] Agent-based vulnerability scanning (for real-time coverage)
- [ ] OS-level CVE detection (Linux, Windows)
- [ ] Application-level dependency scanning (libraries, packages)
- [ ] Container image vulnerability scanning (pre-deployment)
- [ ] Registry scanning (ECR, ACR, GCR, Docker Hub, Harbor)
- [ ] Running container vulnerability scanning (post-deployment)
- [ ] VM / host vulnerability scanning
- [ ] Serverless function vulnerability scanning (Lambda, Cloud Functions)
- [ ] Vulnerability severity scoring (CVSS, EPSS, exploitability context)
- [ ] Reachability analysis (is the vulnerable code actually reachable/exploitable?)
- [ ] Patch availability tracking
- [ ] Zero-day vulnerability alerting
- [ ] CVE database integration (NVD, vendor advisories)
- [ ] Vulnerability trending and SLA tracking

### 2.2 Runtime Protection
- [ ] Real-time workload monitoring (eBPF sensor or equivalent)
- [ ] Behavioral anomaly detection (unexpected process execution, file access)
- [ ] File integrity monitoring (FIM)
- [ ] Process execution monitoring and allowlisting
- [ ] Network connection monitoring (unexpected outbound, lateral movement)
- [ ] Runtime threat detection (cryptomining, reverse shells, privilege escalation)
- [ ] Automated response / kill / quarantine capabilities
- [ ] Runtime policy enforcement (block vs. alert modes)
- [ ] Memory protection and exploit detection
- [ ] Drift detection (container image vs. running state)

### 2.3 Host & VM Security
- [ ] CIS benchmark scanning for OS hardening
- [ ] Malware detection
- [ ] Intrusion detection (host-based IDS)
- [ ] Log collection and analysis from hosts
- [ ] Patch management integration

---

## 3. CIEM -- Cloud Infrastructure Entitlement Management

### 3.1 Identity Inventory & Visibility
- [ ] Complete identity inventory (users, roles, service accounts, federated identities)
- [ ] Cross-cloud identity mapping (unified view across AWS IAM, Azure AD, GCP IAM)
- [ ] Machine identity discovery (service accounts, instance profiles, managed identities)
- [ ] Third-party / federated identity visibility (SSO, SAML, OIDC providers)
- [ ] API key and access key inventory
- [ ] Identity-to-resource access mapping (who can access what)

### 3.2 Permissions Analysis
- [ ] Effective permissions calculation (net permissions after all policies)
- [ ] Over-privileged identity detection
- [ ] Unused permissions identification (permissions granted but never used)
- [ ] Least-privilege recommendations (right-size policies)
- [ ] Cross-account access analysis
- [ ] Privilege escalation path detection
- [ ] Policy simulation (what-if analysis for policy changes)
- [ ] Permission boundaries and guardrails validation
- [ ] Admin / root account usage monitoring
- [ ] MFA enforcement validation

### 3.3 Identity Threat Detection
- [ ] Anomalous identity behavior detection (unusual API calls, new regions)
- [ ] Impossible travel detection
- [ ] Credential compromise detection
- [ ] Dormant account identification
- [ ] Identity-based attack path analysis

---

## 4. DSPM -- Data Security Posture Management

### 4.1 Sensitive Data Discovery
- [ ] Automated scanning of cloud storage (S3, Blob, GCS, etc.)
- [ ] Database content scanning (RDS, DynamoDB, BigQuery, etc.)
- [ ] Structured and unstructured data discovery
- [ ] Data classification by sensitivity (PII, PHI, PCI, IP, credentials)
- [ ] Custom data classifier definitions (regex, ML-based patterns)
- [ ] Data lineage and flow mapping (where data moves, who accesses it)
- [ ] Shadow data discovery (copies, backups, exports in unexpected locations)
- [ ] Data-at-rest encryption status
- [ ] Data retention and lifecycle policy validation

### 4.2 Data Access Governance
- [ ] Who has access to sensitive data (identity-to-data mapping)
- [ ] Excessive data access permissions
- [ ] Cross-account / cross-region data exposure
- [ ] Public data exposure detection (public S3 buckets with sensitive data)
- [ ] Data exfiltration risk scoring
- [ ] Compliance mapping for data regulations (GDPR, CCPA, HIPAA)

---

## 5. Threat Detection & Response

### 5.1 Cloud Detection and Response (CDR)
- [ ] Cloud-native log analysis (CloudTrail, Azure Activity Log, GCP Audit Log)
- [ ] Real-time event-driven detection (streaming, not batch)
- [ ] Pre-built detection rules (credential theft, data exfiltration, persistence)
- [ ] Custom detection rule authoring
- [ ] MITRE ATT&CK for Cloud mapping
- [ ] Multi-signal correlation (combine misconfig + identity + network + vulnerability)
- [ ] Alert severity and confidence scoring
- [ ] Alert de-duplication and grouping
- [ ] Investigation timeline (chronological event chain)
- [ ] Threat intelligence feed integration (IOC, TTP matching)

### 5.2 Attack Path Analysis
- [ ] Automated attack path discovery (graph-based)
- [ ] Multi-factor attack paths (vulnerability + misconfiguration + identity + network)
- [ ] Internet-exposure-rooted attack paths
- [ ] Lateral movement path detection
- [ ] Crown-jewel-aware paths (paths leading to sensitive data or critical assets)
- [ ] Attack path visualization (interactive graph)
- [ ] Blast radius estimation (impact if resource compromised)
- [ ] Prioritized remediation (fix one node, break multiple paths)

### 5.3 Anomaly Detection
- [ ] Behavioral baselines per identity, resource, and account
- [ ] ML-based anomaly detection (API call patterns, network traffic)
- [ ] Cryptomining detection
- [ ] Data exfiltration detection
- [ ] Enumeration / reconnaissance detection
- [ ] Privilege escalation attempt detection
- [ ] LLM jacking / AI abuse detection (for AI workloads)

---

## 6. Application Security (AppSec / Shift-Left)

### 6.1 IaC Scanning
- [ ] Terraform scanning
- [ ] CloudFormation scanning
- [ ] ARM template scanning
- [ ] Kubernetes manifests / Helm chart scanning
- [ ] Pulumi, Ansible, Chef, Puppet support
- [ ] Custom policy-as-code (OPA/Rego)
- [ ] Pre-commit hooks and IDE integration
- [ ] CI/CD pipeline integration (GitHub Actions, GitLab CI, Jenkins, etc.)
- [ ] Drift detection (IaC definition vs. deployed state)
- [ ] Fix suggestions (auto-generate corrected IaC)

### 6.2 Software Composition Analysis (SCA)
- [ ] Open-source dependency vulnerability scanning
- [ ] License compliance checking
- [ ] Transitive dependency analysis
- [ ] SBOM generation (SPDX, CycloneDX)
- [ ] Reachability analysis (is vulnerable function actually called?)
- [ ] Package reputation scoring
- [ ] Automated PR-based fix suggestions

### 6.3 Static Application Security Testing (SAST)
- [ ] Source code vulnerability detection
- [ ] Multi-language support (Python, Java, Go, JS/TS, C#, etc.)
- [ ] Custom rule authoring
- [ ] IDE plugin integration
- [ ] CI/CD pipeline integration

### 6.4 Secrets Detection
- [ ] Hard-coded secrets in source code (API keys, passwords, tokens)
- [ ] Secrets in IaC templates
- [ ] Secrets in container images
- [ ] Secrets in environment variables and config files
- [ ] Pre-commit scanning (prevent secrets from entering repo)
- [ ] Historical secret scanning (secrets in git history)
- [ ] Integration with secrets managers (Vault, AWS Secrets Manager, etc.)

### 6.5 CI/CD Pipeline Security
- [ ] Pipeline configuration scanning (insecure pipeline definitions)
- [ ] Build artifact integrity verification
- [ ] Supply chain security (SLSA framework compliance)
- [ ] Admission control (block deployments that fail policy)
- [ ] Deployment gate integration (approval workflows)
- [ ] Container image signing and verification
- [ ] Pipeline-to-production traceability

---

## 7. Container & Kubernetes Security

### 7.1 Container Security
- [ ] Image vulnerability scanning (build-time)
- [ ] Image configuration scanning (Dockerfile best practices)
- [ ] Registry scanning and continuous monitoring
- [ ] Runtime container monitoring
- [ ] Container drift detection (running image vs. approved image)
- [ ] Malware scanning in images
- [ ] Base image risk assessment (outdated, unsupported base images)
- [ ] Container privilege analysis (--privileged, capabilities)

### 7.2 KSPM -- Kubernetes Security Posture Management
- [ ] Cluster misconfiguration detection (CIS Kubernetes Benchmark)
- [ ] RBAC analysis (over-permissive roles, cluster-admin usage)
- [ ] Network policy analysis (missing or overly permissive)
- [ ] Pod security standards/policy enforcement
- [ ] Secrets management in Kubernetes (secrets at rest encryption)
- [ ] Admission controller / webhook integration (OPA Gatekeeper, Kyverno)
- [ ] Multi-cluster visibility and management
- [ ] Kubernetes API audit log analysis
- [ ] Service mesh security (Istio, Linkerd)
- [ ] Helm chart and manifest scanning

### 7.3 Serverless Security
- [ ] Function vulnerability scanning (Lambda, Cloud Functions, Azure Functions)
- [ ] Function permission analysis (over-privileged execution roles)
- [ ] Event source security (trigger configuration risks)
- [ ] Cold start / warm pool security considerations
- [ ] Function-level runtime monitoring

---

## 8. Network Security

### 8.1 Cloud Network Posture
- [ ] Security group / NSG rule analysis
- [ ] Network ACL analysis
- [ ] VPC / VNet configuration assessment
- [ ] Public IP and internet exposure inventory
- [ ] VPC peering and transit gateway analysis
- [ ] Firewall rule review (Cloud Firewall, WAF rules)
- [ ] DNS configuration security (dangling DNS, subdomain takeover)
- [ ] Load balancer and CDN configuration security
- [ ] VPN and Direct Connect configuration review

### 8.2 Network Threat Detection
- [ ] VPC Flow Log analysis
- [ ] Network anomaly detection (unusual traffic patterns)
- [ ] Lateral movement detection
- [ ] Egress traffic monitoring (data exfiltration indicators)
- [ ] DDoS detection and alerting
- [ ] East-west traffic visibility (micro-segmentation validation)

---

## 9. API Security

- [ ] API endpoint discovery and inventory
- [ ] API authentication and authorization analysis
- [ ] API misconfiguration detection (open endpoints, missing rate limits)
- [ ] API traffic monitoring and anomaly detection
- [ ] GraphQL and REST API security
- [ ] API gateway configuration analysis
- [ ] OWASP API Top 10 coverage
- [ ] Shadow / undocumented API detection

---

## 10. External Attack Surface Management (EASM)

- [ ] External asset discovery (internet-facing resources)
- [ ] Exposed service detection (open ports, services)
- [ ] Certificate monitoring (expiration, weak ciphers)
- [ ] Domain and subdomain enumeration
- [ ] Cloud resource exposure correlation (internal risk + external exposure)
- [ ] Brand impersonation / phishing domain detection
- [ ] Third-party risk visibility

---

## 11. AI Security Posture Management (AI-SPM)

- [ ] AI/ML model inventory (deployed models, training pipelines)
- [ ] AI workload misconfiguration detection
- [ ] Training data exposure risks
- [ ] Model access control analysis
- [ ] Prompt injection detection
- [ ] Data leakage via AI services
- [ ] AI service API security (Bedrock, SageMaker, Azure OpenAI, Vertex AI)
- [ ] Shadow AI detection (unauthorized AI service usage)
- [ ] AI bias and fairness monitoring
- [ ] LLM jacking detection

---

## 12. Remediation & Response

### 12.1 Automated Remediation
- [ ] One-click remediation for common misconfigurations
- [ ] Auto-remediation policies (auto-fix on detection)
- [ ] Remediation playbooks (step-by-step for manual fixes)
- [ ] IaC fix generation (PR with corrected Terraform/CloudFormation)
- [ ] Remediation verification (confirm fix was applied)
- [ ] Rollback capability (undo remediation if it breaks things)
- [ ] Remediation SLA tracking and escalation

### 12.2 Workflow & Integration
- [ ] Ticketing integration (Jira, ServiceNow, PagerDuty)
- [ ] SIEM/SOAR integration (Splunk, Sentinel, Chronicle, XSOAR)
- [ ] Notification channels (Slack, Teams, email, webhooks)
- [ ] Bidirectional sync (finding status synced with ticket status)
- [ ] Custom workflow automation (runbooks, Lambda triggers)
- [ ] Role-based finding assignment (route to correct team)

### 12.3 AI-Assisted Operations
- [ ] Natural language investigation (ask questions about findings in plain English)
- [ ] AI-generated remediation guidance
- [ ] AI-powered alert triage and prioritization
- [ ] Predictive risk analysis (predict what will become a problem)
- [ ] AI agent-driven autonomous remediation

---

## 13. Governance & Multi-Tenancy

- [ ] Multi-tenant architecture (tenant isolation, per-tenant policies)
- [ ] RBAC for platform users (admin, analyst, viewer, custom roles)
- [ ] Organization hierarchy support (org, account, project, environment)
- [ ] Policy-as-code governance (enforce guardrails via policy)
- [ ] Approval workflows for sensitive actions
- [ ] Audit logging (who did what, when, on the platform itself)
- [ ] SSO / SAML / OIDC integration for platform login
- [ ] Tenant-scoped dashboards and reports

---

## 14. Reporting & Dashboards

- [ ] Executive summary dashboards (posture overview, risk trends)
- [ ] Per-engine drill-down dashboards (compliance, threats, vulnerabilities)
- [ ] Per-account and per-cloud-provider views
- [ ] Historical trend analysis and charts
- [ ] Scheduled report generation (daily/weekly/monthly)
- [ ] Exportable reports (PDF, CSV, JSON, HTML)
- [ ] Custom report builder
- [ ] API access to all data (for external BI tools)
- [ ] Real-time data refresh (not stale cached views)

---

## 15. Platform & Architecture

### 15.1 Multi-Cloud Support
- [ ] AWS (full service coverage)
- [ ] Azure (full service coverage)
- [ ] GCP (full service coverage)
- [ ] OCI (Oracle Cloud)
- [ ] AliCloud
- [ ] IBM Cloud
- [ ] On-premises / hybrid environment support

### 15.2 Deployment & Operations
- [ ] SaaS deployment model
- [ ] Self-hosted / on-premises deployment option
- [ ] Agentless scanning (primary mode)
- [ ] Optional agent for runtime (eBPF-based)
- [ ] API-first architecture (all features accessible via API)
- [ ] High availability and fault tolerance
- [ ] Horizontal scalability (handle 100K+ resources)
- [ ] Data residency controls (regional data storage)

### 15.3 Integration Ecosystem
- [ ] Cloud provider native integrations (AWS Organizations, Azure Management Groups, GCP Organization)
- [ ] Identity provider integration (Okta, Azure AD, etc.)
- [ ] SIEM integration (Splunk, Sentinel, Chronicle, QRadar)
- [ ] SOAR integration (XSOAR, Swimlane, Tines)
- [ ] Ticketing (Jira, ServiceNow, Freshservice)
- [ ] Communication (Slack, Teams, PagerDuty, Opsgenie)
- [ ] CI/CD (GitHub, GitLab, Jenkins, Azure DevOps, CircleCI)
- [ ] Registry (ECR, ACR, GCR, Docker Hub, Harbor, JFrog)
- [ ] Secrets managers (Vault, AWS Secrets Manager, Azure Key Vault)
- [ ] Terraform Cloud / Spacelift / Env0

---

## Summary: Gartner's CNAPP Must-Haves (2025)

Per Gartner's 2025 Market Guide, a complete CNAPP must include:

| # | Capability | Category |
|---|-----------|----------|
| 1 | CSPM (misconfiguration + compliance) | Posture |
| 2 | CWPP (workload vulnerability + runtime) | Workload |
| 3 | CIEM (identity + entitlement analysis) | Identity |
| 4 | Container & Kubernetes security | Workload |
| 5 | IaC scanning | Shift-left |
| 6 | Container image scanning | Shift-left |
| 7 | Attack path analysis | Risk |
| 8 | Multi-cloud support (AWS + Azure + GCP + K8s minimum) | Platform |
| 9 | SIEM/SOAR/SOC integration | Integration |
| 10 | Unified risk prioritization across all signals | Risk |

**Emerging must-haves** (trending toward required):
- DSPM (data security posture)
- AI-SPM (AI security posture)
- CDR (cloud detection & response)
- EASM (external attack surface management)
- GenAI-assisted investigation and remediation
- Runtime protection (eBPF-based)
- SCA and secrets detection

---

## Sources

- [Gartner 2025 Market Guide for CNAPP](https://www.gartner.com/en/documents/5605291)
- [Orca Security: 2025 Gartner CNAPP Market Guide Takeaways](https://orca.security/resources/blog/gartner-2025-market-guide-for-cnapp/)
- [Wiz: Unpacking the 2025 Gartner Market Guide for CNAPP](https://www.wiz.io/blog/unpacking-cnapp-gartner-market-guide)
- [Wiz: Forrester Wave CNAPP Q1 2026](https://www.wiz.io/blog/forrester-wave-cnapp-2026)
- [Wiz: CNAPP 101](https://www.wiz.io/academy/cloud-security/what-is-a-cloud-native-application-protection-platform-cnapp)
- [Palo Alto Networks: 5 Must-Haves for CNAPP](https://www.paloaltonetworks.com/prisma/cloud/cnapp-5-must-have)
- [Orca Security CNAPP Platform](https://orca.security/platform/cnapp-cloud-security-platform/)
- [Fortinet FortiCNAPP](https://www.fortinet.com/products/forticnapp)
- [Aqua Security: CNAPP According to Gartner](https://www.aquasec.com/cloud-native-academy/cnapp/cnapp-gartner/)
- [CyCognito: 6 Pillars of CNAPP](https://www.cycognito.com/learn/cloud-security/cnapp/)
- [Sysdig: 2025 Gartner CNAPP Market Guide](https://www.sysdig.com/blog/2025-gartner-cnapp-market-guide)
- [Microsoft Security: What is CNAPP](https://www.microsoft.com/en-us/security/business/security-101/what-is-cnapp)
- [Wiz: DSPM Overview](https://www.wiz.io/academy/data-security/data-security-posture-management-dspm)
- [Palo Alto Networks: What is DSPM](https://www.paloaltonetworks.com/cyberpedia/what-is-dspm)
- [AccuKnox: Top CNAPP Vendors 2026](https://accuknox.com/blog/cnapp-vendors)
- [Upwind: 2025 Gartner CNAPP Market Guide Takeaways](https://www.upwind.io/feed/2025-gartner-market-guide-for-cloud-native-application-protection-platforms-5-takeaways-that-we-believe-matter)
