# Phase 3: CNAPP Expansion — Roadmap

> **Status:** NOT STARTED — Document for future planning
> **Prerequisites:** Phase 1 (foundation fixes) and Phase 2 (intelligence layer) must be complete
> **Created:** 2026-03-19

---

## Overview

Phase 3 expands the platform from a CSPM to a true CNAPP by adding capabilities required by Gartner's 2025 CNAPP Market Guide.

---

## 3a. SIEM/SOAR Integration (Gartner Required)

**Goal:** Send findings/alerts to external SIEM/SOAR platforms.

**Scope:**
- Webhook-based integration (generic HTTP POST for any SIEM)
- Pre-built connectors: Splunk HEC, Azure Sentinel, Google Chronicle, AWS Security Hub
- Event format: CEF (Common Event Format) or OCSF (Open Cybersecurity Schema Framework)
- Bidirectional: finding status sync (SIEM acknowledges → our status updates)

**Implementation approach:**
- New `shared/integrations/` module with pluggable connectors
- Event bus pattern: engines publish events → integration worker dispatches
- Webhook retry with exponential backoff
- Configuration stored in `integration_configs` table (per-tenant)

**Effort:** Medium (2-3 weeks)

---

## 3b. Azure + GCP Check Rules (Multi-Cloud)

**Goal:** Extend check engine rules beyond AWS to Azure and GCP.

**Current state:**
- Discovery engine: Azure/GCP catalog exists in `catalog/` (service definitions)
- Check engine: Only AWS rules in `engines/check/engine_check_aws/`
- Rule YAML format is CSP-agnostic — same structure works for any cloud

**Scope:**
- `engines/check/engine_check_azure/` — 100+ Azure rules (NSGs, Storage, Key Vault, etc.)
- `engines/check/engine_check_gcp/` — 100+ GCP rules (Firewall, GCS, IAM, etc.)
- Map rules to same compliance frameworks (CIS Azure/GCP benchmarks)
- Populate rule_metadata with MITRE ATT&CK mappings for Azure/GCP

**Effort:** Large (4-6 weeks per cloud)

---

## 3c. Notification Integrations

**Goal:** Alert teams when critical findings are detected.

**Scope:**
- Slack webhook (channel-based alerts)
- Microsoft Teams webhook
- PagerDuty (severity-based routing)
- Email (SMTP/SES)
- Generic webhook (custom endpoints)

**Implementation approach:**
- Notification rules: "IF severity=critical AND threat_category=exposure THEN notify Slack #security"
- Per-tenant notification configs
- Rate limiting (don't spam 16K findings — aggregate)
- Digest mode: daily/weekly summary emails

**Effort:** Small-Medium (1-2 weeks)

---

## 3d. Remediation Automation

**Goal:** One-click fix for common misconfigurations.

**Scope (Phase 1 — safe remediations only):**
- S3: Block public access, enable encryption, enable versioning
- SG: Remove 0.0.0.0/0 ingress rules
- IAM: Remove unused access keys, enable MFA requirement
- RDS: Enable encryption, disable public accessibility
- CloudTrail: Enable logging, enable log file validation

**Implementation approach:**
- `engines/remediation/` — new engine
- Remediation playbooks in YAML (pre/post checks, rollback)
- Dry-run mode (show what would change)
- Approval workflow (analyst approves before execution)
- Audit trail (who remediated what, when)
- AWS SDK calls with least-privilege IAM role

**Effort:** Medium-Large (3-4 weeks)

---

## 3e. Threat Intelligence Feeds

**Goal:** Populate `threat_intelligence` table with external threat data.

**Scope:**
- STIX/TAXII feed ingestion
- AWS GuardDuty integration (import findings)
- AlienVault OTX (free IOC feed)
- MITRE ATT&CK updates (technique library sync)
- IOC correlation: match IP/domain/hash indicators against discovery data

**Implementation approach:**
- Feed worker: scheduled task pulls from feeds
- Normalize to `threat_intelligence` table schema
- Cross-reference with `threat_findings` (enrich with intel context)
- Expiration management (auto-deactivate stale IOCs)

**Effort:** Medium (2-3 weeks)

---

## Dependencies

```
Phase 1 (Foundation) → Phase 2 (Intelligence) → Phase 3 (Expansion)
                                                      ↓
                                               Can be parallel:
                                               3a (SIEM) | 3c (Notifications) | 3e (Threat Intel)
                                               3b (Azure/GCP) is independent
                                               3d (Remediation) needs 3b for multi-cloud
```
