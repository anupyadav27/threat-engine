# SecOps Engine — SBOM & DAST Migration Plan

**Status:** Planned (to be implemented after current engine stabilization)
**Date:** 2026-03-03
**Decision:** SBOM generation and DAST scanning belong in the SecOps engine, not in Container or API engines.

---

## Rationale

The SecOps engine is the single authority for code-level and application-level security analysis (SAST, IaC scanning). SBOM generation (Software Bill of Materials) and DAST (Dynamic Application Security Testing) are natural extensions of this responsibility:

- **SBOM** is fundamentally about enumerating software components — whether from source code lockfiles, container image layers, or build artifacts. Centralizing SBOM generation in SecOps avoids duplication across Container and Supply Chain engines.
- **DAST** is runtime application testing (sending HTTP requests, checking for OWASP vulnerabilities). It complements SAST (static analysis) and belongs alongside it in SecOps.

### Current State (What Exists Today)

| Capability | Current Location | What It Does |
|-----------|-----------------|--------------|
| Container SBOM extraction | `engines/container/reporter/container_reporter.py` | Extracts package list from Trivy `raw_trivy_output` → writes to `container_sbom` table |
| Supply Chain SBOM | `engines/supplychain/reporter/supplychain_reporter.py` | Builds SBOM manifests (SPDX/CycloneDX) from dependency scanning → `sbom_manifests` + `sbom_components` tables |
| Trivy scanner | `shared/external_collector/scanners/trivy_scanner.py` | Runs Trivy binary on container images, returns CVE list + SBOM |
| DAST scanning | — | Does not exist anywhere in the codebase |

### Target State (After Migration)

| Capability | New Location | What Changes |
|-----------|-------------|-------------|
| Source code SBOM | `engines/secops/scanner_engine/sbom/` | Parse lockfiles (requirements.txt, package-lock.json, go.sum, Cargo.lock, pom.xml, Gemfile.lock, etc.) during SAST scan → generate SPDX/CycloneDX SBOM |
| Container SBOM | `engines/secops/scanner_engine/sbom/` | Read Trivy output from `registry_images` table (Tier 3) → extract package inventory → unified SBOM format |
| SBOM aggregation | `engines/secops/scanner_engine/sbom/` | Merge source-level + container-level SBOMs into single per-project SBOM |
| DAST scanning | `engines/secops/scanner_engine/dast/` | New module: send HTTP requests to running endpoints, evaluate OWASP Top 10, auth/rate-limit checks |
| DAST rule engine | `engines/secops/scanner_engine/dast/rules/` | DAST-specific rules with OWASP/CWE mappings, severity, remediation |

---

## Migration Tasks

### Phase A: SBOM in SecOps

#### A1. Source Code SBOM Generation (NEW)
- Add lockfile parsers for each language already supported by SecOps:
  - Python: `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `setup.py`
  - JavaScript/Node: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  - Go: `go.sum`, `go.mod`
  - Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
  - Ruby: `Gemfile.lock`
  - C#: `packages.config`, `*.csproj` (PackageReference)
  - Rust: `Cargo.lock`
- Output: package name, version, type, license (where available), PURL, CPE
- Store in new `secops_sbom_components` table

#### A2. SBOM Output Format
- Support SPDX 2.3 and CycloneDX 1.5 JSON output
- Add API endpoint: `GET /api/v1/secops/scan/{id}/sbom?format=spdx|cyclonedx`
- Include in SARIF output as tool component

#### A3. Container SBOM Integration
- Read Trivy output from `registry_images` (Tier 3 external collector)
- Extract OS packages, application packages from Trivy JSON
- Merge with source-level SBOM for complete picture
- Note: Trivy remains in external_collector (Tier 3) — SecOps only reads its output

#### A4. Deprecate SBOM in Container & Supply Chain Engines
- Container engine: Remove SBOM extraction from `container_reporter.py`
- Supply Chain engine: Remove `sbom_manifests`/`sbom_components` writes from `supplychain_reporter.py`
- Keep tables for backward compatibility; add deprecation comments
- Both engines reference SecOps SBOM via cross-engine scan_id

### Phase B: DAST in SecOps

#### B1. DAST Scanner Module (NEW)
- New module: `engines/secops/scanner_engine/dast/`
- Accepts target URL(s) or auto-discovers from API inventory (engine_api output)
- Sends HTTP requests to test for common vulnerabilities
- Runs as optional scan phase alongside SAST

#### B2. DAST Rule Set
- OWASP API Top 10 rules (complements engine_api's static analysis):
  - Broken Authentication (API2)
  - Excessive Data Exposure (API3)
  - Lack of Resources & Rate Limiting (API4)
  - Broken Function Level Authorization (API5)
  - Security Misconfiguration (API7)
  - Injection (API8)
- OWASP Web Top 10 rules:
  - XSS (reflected, stored)
  - CSRF
  - Open Redirect
  - SSRF
  - XXE
  - Insecure Deserialization
- Store in `secops_rule_metadata` with `rule_type = 'dast'`

#### B3. DAST Data Sources
- **Input 1:** API inventory from `engine_api` (endpoints, auth config, rate limits)
- **Input 2:** Target URLs from scan request
- **Input 3:** OpenAPI/Swagger specs (auto-discover endpoints)

#### B4. DAST Findings Integration
- Write to existing `secops_findings` table with `scan_type = 'dast'`
- Include in SARIF output alongside SAST findings
- Severity mapping: OWASP risk rating → CRITICAL/HIGH/MEDIUM/LOW

---

## Database Changes

### New Tables (in `threat_engine_secops`)

```sql
-- SBOM components discovered from source code and container images
CREATE TABLE IF NOT EXISTS secops_sbom_components (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secops_scan_id  UUID NOT NULL,
    tenant_id       VARCHAR(100) NOT NULL,
    source_type     VARCHAR(50) NOT NULL,  -- 'lockfile', 'container_image', 'manifest'
    source_path     TEXT,                   -- e.g. 'requirements.txt', 'nginx:1.25'
    package_name    VARCHAR(500) NOT NULL,
    package_version VARCHAR(200),
    package_type    VARCHAR(50),           -- pip, npm, go, maven, gem, deb, rpm, apk
    license         VARCHAR(200),
    purl            TEXT,                   -- Package URL (pkg:npm/lodash@4.17.21)
    cpe             TEXT,                   -- CPE identifier
    is_direct       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- SBOM manifests (one per scan, aggregated)
CREATE TABLE IF NOT EXISTS secops_sbom_manifests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secops_scan_id  UUID NOT NULL,
    tenant_id       VARCHAR(100) NOT NULL,
    format          VARCHAR(20) NOT NULL,  -- 'spdx' or 'cyclonedx'
    version         VARCHAR(20),           -- format version
    component_count INTEGER DEFAULT 0,
    sbom_json       JSONB,                 -- Full SBOM document
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

### Existing Table Changes

```sql
-- Add scan_type to secops_findings for DAST vs SAST distinction
ALTER TABLE secops_findings ADD COLUMN IF NOT EXISTS
    scan_type VARCHAR(20) DEFAULT 'sast';  -- 'sast', 'dast', 'sca'

-- Add sbom_generated flag to secops_report
ALTER TABLE secops_report ADD COLUMN IF NOT EXISTS
    sbom_generated BOOLEAN DEFAULT FALSE;

ALTER TABLE secops_report ADD COLUMN IF NOT EXISTS
    sbom_component_count INTEGER DEFAULT 0;

ALTER TABLE secops_report ADD COLUMN IF NOT EXISTS
    dast_findings_count INTEGER DEFAULT 0;
```

---

## API Changes

### New Endpoints

```
GET  /api/v1/secops/scan/{id}/sbom?format=spdx|cyclonedx
     → Returns SBOM document in requested format

POST /api/v1/secops/scan
     → Extended request body:
     {
       "repo_url": "...",
       "enable_sast": true,        // default: true
       "enable_sbom": true,        // default: true (NEW)
       "enable_dast": false,       // default: false (NEW)
       "dast_target_url": "...",   // required if enable_dast=true
       "quality_gate": { ... }
     }

GET  /api/v1/secops/scan/{id}/findings?scan_type=sast|dast|sca
     → Filter findings by scan type
```

---

## Relationship to Other Engines

| Engine | Before Migration | After Migration |
|--------|-----------------|-----------------|
| **Container** | Extracts SBOM from Trivy, stores in `container_sbom` | **DEPRECATED** — K8s pod security + ECR posture fully covered by Check Engine. SBOM handled by SecOps. |
| **Supply Chain** | Generates SBOM manifests, stores in `sbom_manifests`/`sbom_components` | **DEPRECATED** — SBOM generation, dependency scanning, malicious package detection all belong in SecOps SCA module. See `engines/supplychain/DEPRECATED.md`. |
| **API Security** | Static OWASP API Top 10 evaluation | **DEPRECATED** — Static API posture already covered by Check Engine (53 AWS API Gateway rules). Dynamic (DAST) testing planned for SecOps. See `engines/api/DEPRECATED.md`. |
| **Vulnerability** | CVE matching from NVD/OSV | Unchanged — remains single CVE authority. SecOps SCA findings reference Vulnerability Engine for CVE enrichment. |

---

## Implementation Priority

1. **A1 + A2** — Source code SBOM (highest value, aligns with SCA in roadmap item #4)
2. **A4** — Deprecate SBOM in Container/SupplyChain (clean separation)
3. **A3** — Container SBOM integration (merge Trivy output)
4. **B1 + B2** — DAST scanner and rules (new capability)
5. **B3 + B4** — DAST data sources and findings integration

---

## References

- [SecOps Improvement Roadmap](./SECOPS_IMPROVEMENT_ROADMAP.md) — Items #4 (SCA) and "Optional/Later" (container image scanning)
- [New Engines Architecture](../../.claude/documentation/NEW_ENGINES_ARCHITECTURE.md)
- Container SBOM reference: `engines/container/reporter/container_reporter.py`
- Supply Chain SBOM reference: `engines/supplychain/reporter/supplychain_reporter.py`
- Trivy scanner reference: `shared/external_collector/scanners/trivy_scanner.py`
