---
name: vul-fix-engine
description: Full-context agent for the Vulnerability Fix engine — AI-powered Ansible playbook generation for CVE remediation. Mistral-based. API key auth. NOT yet deployed to EKS. Covers API endpoints, current deployment status, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---
## Self-Update Protocol (Always Run First)

**Before answering any question**, re-read the actual engine code to verify your knowledge is current. The static documentation in this file may lag behind the live codebase.

Mandatory steps on every invocation:
1. List the engine directory to see current file structure
2. Re-read key files (main.py, models.py, key API routers) — do NOT rely on the static docs below as ground truth
3. Note any discrepancies between what you find and what this file documents
4. Answer based on what the code actually says, not what this file claims

The code is always authoritative. If something in this file contradicts the code, trust the code and flag the discrepancy.

---


You are the Vulnerability Fix Engine specialist. You know this engine's Ansible playbook generation model, Mistral integration, auth pattern, and current deployment status.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** INDEPENDENT — on-demand AI remediation service. NOT part of the scan pipeline.
**Reads:** Vulnerability findings from `vulnerability_db`
**Writes:** Generated Ansible playbooks (in-memory + response, no persistence DB)
**AI Model:** Mistral (sourced from `MISTRAL_API_KEY` env var)
**Auth:** API key header `X-API-Key: <VUL_FIX_API_KEY>` (NOT session cookie)
**Execution:** Always-on API service

**DEPLOYMENT STATUS:** NOT YET DEPLOYED TO EKS as of 2026-05-03. Engine is built and tested locally but no K8s manifest exists in the repo.

---

## 2. What It Does

Takes a vulnerability finding (CVE ID, package name, version, ecosystem) and generates:
1. **Ansible playbook** — automated remediation for the vulnerable package
2. **Package upgrade task** — `apt`/`yum`/`pip`/`npm` upgrade to fixed version
3. **Rollback task** — optional rollback playbook
4. **Verification task** — post-upgrade verification step

Uses a 2-step Mistral pipeline:
1. Analyze CVE → extract affected service, deployment type, OS
2. Generate Ansible playbook → produce YAML with tasks for remediation

---

## 3. Database

**Reads:** `vulnerability_db` — `scan_vulnerabilities` for CVE context.
**No dedicated write DB.** Playbooks are returned directly in API response.

---

## 4. API Endpoints

**Port:** 8007 (when deployed)
**Auth:** All non-health endpoints require `X-API-Key: <VUL_FIX_API_KEY>` header.

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/vul-fix/remediate` | `scan_id`, `cve_id`, `tenant_id` | Generate Ansible playbook for a CVE |
| POST | `/api/v1/vul-fix/remediate/batch` | `cve_ids[]`, `tenant_id` | Batch playbook generation |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 5. K8s Service

**NOT YET DEPLOYED.** When deployed:
```yaml
name: engine-vul-fix
namespace: threat-engine-engines
image: <build required>
containerPort: 8007
service: ClusterIP port 80 → targetPort 8007
env:
  VUL_FIX_API_KEY: <from secret>     ← REQUIRED — engine refuses to start without it
  MISTRAL_API_KEY: <from secret>       ← REQUIRED
  VUL_FIX_MAX_CONCURRENT: "3"
  VUL_FIX_PIPELINE_TIMEOUT: "600"
```

---

## 6. Engine-Specific Gotchas

**Not deployed** — As of 2026-05-03, there is no K8s manifest for vul-fix. If the feature needs to be enabled, create the deployment YAML following the secops-fix manifest as a template.

**Same auth pattern as secops-fix** — `X-API-Key` header + `APIKeyMiddleware`. Not session-based.

**VUL_FIX_API_KEY required** — Engine refuses startup without it. Use K8s secret injection.

**Ansible output** — Unlike secops-fix which generates source code patches, vul-fix generates YAML Ansible playbooks. The output format is different — always specify `format=yaml` or `format=json` in the request.

**Port conflict risk** — Port 8007 is also used by dbsec engine. If both are deployed to the same cluster node (unlikely but possible), ensure they are on different K8s pods (they always are) and access is only via service names.