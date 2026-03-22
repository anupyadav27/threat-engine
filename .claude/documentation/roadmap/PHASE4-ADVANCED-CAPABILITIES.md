# Phase 4: Advanced Capabilities — Roadmap

> **Status:** NOT STARTED — Document for future planning
> **Prerequisites:** Phases 1-3 should be substantially complete
> **Created:** 2026-03-19

---

## Overview

Phase 4 adds differentiating capabilities that move the platform beyond standard CNAPP into next-gen territory. These are features that Wiz, Prisma Cloud, and Orca are building in 2025-2026.

---

## 4a. Cloud Detection & Response (CDR)

**Goal:** Real-time threat detection from cloud audit logs (currently everything is batch/scan-based).

**What it does:**
- Stream CloudTrail events (via EventBridge → SQS/Kinesis)
- Stream Azure Activity Log events (via Event Hub)
- Stream GCP Audit Log events (via Pub/Sub)
- Real-time detection rules: credential theft, data exfil, persistence, privilege escalation
- Investigation timeline: chronological event chain per incident

**Why it matters:**
- Current threat engine only runs during scans (batch)
- CDR detects IN BETWEEN scans — e.g., "root login from new IP at 3am"
- Gartner lists CDR as "emerging required" for CNAPP

**Architecture:**
- New `engines/cdr/` engine
- Event streaming: CloudTrail → EventBridge → SQS → CDR worker
- Detection rules: YAML-based pattern matching on event fields
- Output: `threat_detections` table (same as current, tagged `source=cdr`)
- Alert: immediate notification via Phase 3c integrations

**Effort:** Large (6-8 weeks)

---

## 4b. Container Image Scanning

**Goal:** Scan container images in registries for vulnerabilities before deployment.

**What it does:**
- Registry scanning: ECR, ACR, GCR, Docker Hub, Harbor
- Image layer analysis: OS packages (dpkg, rpm, apk) + app dependencies
- CVE matching against NVD + vendor advisories
- SBOM generation (CycloneDX/SPDX format)
- Admission control: block deploys of images with critical CVEs
- Continuous monitoring: re-scan existing images when new CVEs are published

**Architecture:**
- Extend `vulnerability/` subsystem (already has CVE DB)
- New `engines/container/` engine
- Trivy or Grype as scanning backend
- Registry webhook for push-triggered scans
- Results in `container_scan_findings` table

**Effort:** Large (4-6 weeks)

---

## 4c. Effective Permissions Calculation (Advanced CIEM)

**Goal:** Calculate what an IAM identity can ACTUALLY do (net effect of all policies).

**What it does:**
- Policy simulation: resolve allow/deny across inline + managed + boundary + SCP
- Unused permissions: cross-reference CloudTrail usage vs granted permissions
- Right-sizing: recommend minimal policy based on actual usage
- Privilege escalation paths: identify chains (assume role → attach policy → escalate)
- Cross-account access: map trust relationships between accounts

**Why it matters:**
- Current IAM engine has 57 rules but doesn't compute effective permissions
- Wiz and Prisma Cloud both have full CIEM with privilege escalation paths
- Identity is the #1 attack vector in cloud (per CrowdStrike 2025)

**Architecture:**
- Extend `engines/iam/` with policy simulator
- IAM policy grammar parser (AWS IAM policy language)
- CloudTrail usage data ingestion (last 90 days of API calls)
- Permission graph in Neo4j (identity → permission → resource)

**Effort:** Large (6-8 weeks)

---

## 4d. Agentless Vulnerability Scanning (CWPP)

**Goal:** Scan running workloads for OS/app vulnerabilities without installing agents.

**What it does:**
- Snapshot-based: create EBS snapshot → mount → scan filesystem
- OS CVE detection: match installed packages against NVD
- Application dependency scanning: Python/Node/Java/Go packages
- Malware detection: YARA rules on filesystem
- Secrets detection: scan filesystem for exposed credentials

**Why it matters:**
- Gartner requires CWPP as CNAPP component
- Agentless is preferred (no agent management overhead)
- Wiz pioneered this approach ("SideScanning")

**Architecture:**
- Lambda-based scanner: triggered per snapshot
- Cross-account role assumption for read-only EBS access
- NVD + vendor advisory database sync (daily)
- Results in `vulnerability_findings` table

**Effort:** Large (6-8 weeks)

---

## 4e. AI Security Posture Management (AI-SPM)

**Goal:** Discover and secure AI/ML workloads in cloud environments.

**What it does:**
- AI workload inventory: SageMaker, Bedrock, Azure OpenAI, Vertex AI
- Model access control: who can invoke models, data access policies
- Training data exposure: S3 buckets with training data — public? encrypted?
- Prompt injection detection: monitor model invocation logs
- Shadow AI: detect unauthorized AI service usage
- LLM jacking: detect credential misuse for AI model access

**Why it matters:**
- AI-SPM is Gartner's newest "emerging required" category (2025)
- AI workloads have unique risks (training data poisoning, model theft)
- AWS Bedrock + SageMaker usage is growing rapidly

**Architecture:**
- Extend discovery engine with AI service catalog entries
- New check rules for AI services (SageMaker endpoint auth, Bedrock guardrails)
- MITRE ATLAS mapping (AI-specific threat framework)

**Effort:** Medium (3-4 weeks for basic, 8+ for comprehensive)

---

## 4f. External Attack Surface Management (EASM)

**Goal:** Discover and assess internet-facing assets from outside the cloud boundary.

**What it does:**
- DNS enumeration: discover all subdomains
- Port scanning: identify open services on public IPs
- Certificate monitoring: expiration, weak ciphers, CT log monitoring
- Technology fingerprinting: identify tech stack from HTTP responses
- Dangling DNS detection: subdomains pointing to deprovisioned resources
- Correlation: match external assets to internal cloud inventory

**Architecture:**
- New `engines/easm/` engine
- Scheduled external scans (no cloud credentials needed)
- Public DNS + certificate transparency log analysis
- Results correlated with inventory_findings

**Effort:** Medium-Large (4-5 weeks)

---

## 4g. Runtime Protection (eBPF)

**Goal:** Real-time workload protection via kernel-level monitoring.

**What it does:**
- Process execution monitoring: detect unexpected processes
- File integrity monitoring: detect changes to critical files
- Network connection monitoring: detect C2 callbacks, lateral movement
- Cryptomining detection: detect CPU/GPU mining processes
- Container escape detection: detect namespace breakouts

**Why it matters:**
- Most advanced CNAPP capability
- Sysdig, Aqua, Falco specialize in this
- Requires agent deployment (DaemonSet in K8s)

**Architecture:**
- eBPF-based agent (Tetragon or custom)
- DaemonSet deployment in customer K8s clusters
- Event streaming to CDR engine (Phase 4a)
- Policy enforcement: alert vs block mode

**Effort:** Very Large (10+ weeks)

---

## 4h. GenAI-Assisted Investigation

**Goal:** Natural language security investigation copilot.

**What it does:**
- "What's the riskiest resource in my environment?"
- "Show me all attack paths to production databases"
- "Why is this S3 bucket flagged as critical?"
- AI-generated remediation guidance
- Automated root cause analysis
- Predictive risk analysis

**Architecture:**
- Claude API integration (Anthropic SDK)
- RAG over security findings + graph data
- Tool-use: Claude calls threat/inventory/compliance APIs
- Context: tenant findings, MITRE knowledge, cloud best practices

**Effort:** Medium (3-4 weeks for MVP)

---

## Priority Order

Based on competitive differentiation and customer demand:

1. **4a CDR** — biggest gap (batch-only detection is a dealbreaker)
2. **4c Effective Permissions** — identity is #1 attack vector
3. **4b Container Scanning** — Gartner required
4. **4d Agentless Vuln Scanning** — Gartner required (CWPP)
5. **4h GenAI Investigation** — high customer delight, relatively quick
6. **4e AI-SPM** — trending, but niche audience
7. **4f EASM** — nice-to-have, not core
8. **4g Runtime** — massive effort, defer unless customer-driven
