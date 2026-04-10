# SBOM Engine — SecOps SBOM Platform

## What is this?

SBOM Engine is a security service that answers one simple question:

> **"What software is running on our systems, and is any of it vulnerable?"**

It does this by building a **Software Bill of Materials (SBOM)** — a complete inventory
of every software package in your application — and then checking each one against a
vulnerability database.

Think of an SBOM like the **ingredients list on a food packet**.
Just as a food label tells you exactly what is inside and flags allergens,
an SBOM tells you exactly what software packages are inside your application
and flags security vulnerabilities.

---

## Why do we need this?

Modern applications are built on hundreds of open-source packages.
When a vulnerability like Log4Shell (CVE-2021-44228) is discovered,
you need to answer immediately:

- Do we use Log4j anywhere?
- Which version?
- Which servers are affected?
- Is there a fix available?

Without an SBOM, answering these questions takes days.
With SBOM Engine, it takes seconds.

---

## How it fits into the existing platform

We already have two other engines running:

```
┌─────────────────────────────────────────────────────────────────┐
│                       What we already have                      │
├─────────────────┬───────────────────────────────────────────────┤
│  vul_engine     │ Scans OS packages (RPM, DEB), Windows         │
│                 │ software, databases, middleware                │
├─────────────────┼───────────────────────────────────────────────┤
│  osv_engine     │ Scans language packages (pip, npm, go, maven) │
│                 │ against the OSV / GitHub Advisory Database    │
├─────────────────┼───────────────────────────────────────────────┤
│  sbom_engine    │ NEW — full SBOM platform for SecOps           │
│  (this service) │ Ingest, generate, store, diff, and report     │
└─────────────────┴───────────────────────────────────────────────┘
```

**sbom_engine does NOT replace the others.**
It is a completely independent service that reads from the same vulnerability
database (osv_advisory and cves tables) but has its own tables, its own API,
and its own port (8002).

---

## Key Concepts (Plain English)

### SBOM (Software Bill of Materials)
A machine-readable list of every software package in an application,
including name, version, license, and checksums.

**This platform generates SBOMs itself — no external tool required.**
You provide a Git repository URL. The engine clones it, reads every dependency
file directly from the source code, and builds the complete component inventory.

The output is always **CycloneDX 1.5** — the OWASP industry standard format,
required by the US Executive Order 14028 for federal software contracts.

The platform also accepts pre-built CycloneDX or SPDX files as an alternative
input path (for cases where you already have an SBOM from another source).

### VEX (Vulnerability Exploitability eXchange)
A formal statement that says "yes, this CVE exists in our dependency,
but we are NOT affected because..." with a documented reason.

Example: Your application uses the `requests` library which has CVE-2023-32681
(a redirect vulnerability), but your code never follows HTTP redirects.
You create a VEX statement with status `not_affected` and justification
`code_not_reachable`. That CVE is then suppressed from all future reports
for your application.

### SBOM Diff
Every time you scan your application, SBOM Engine keeps the previous scan.
The diff endpoint compares two SBOMs and tells you exactly what changed:
- Which packages were added or removed
- Which packages changed version
- Which new vulnerabilities appeared
- Which old vulnerabilities were resolved

---

## Architecture

```
                         ┌─────────────────────────────────┐
  Syft / Trivy /         │                                 │
  cdxgen output ────────►│         SBOM Engine             │
                         │         (port 8002)             │
  vul_agent package ────►│                                 │
  discovery              │  ┌───────────┐ ┌─────────────┐ │
                         │  │   Parse   │ │   Enrich    │ │
  Direct API call ──────►│  │ CycloneDX │ │ with vulns  │ │
                         │  │   SPDX    │ │             │ │
                         │  └─────┬─────┘ └──────┬──────┘ │
                         │        │               │        │
                         │  ┌─────▼───────────────▼──────┐ │
                         │  │      Generate CycloneDX    │ │
                         │  │   License Check    VEX     │ │
                         │  │   Compliance Report  Diff  │ │
                         │  └────────────────────────────┘ │
                         └──────────────┬──────────────────┘
                                        │
                    reads (never writes)│ writes
                    ┌───────────────────┼──────────────────┐
                    ▼                   ▼                  ▼
             osv_advisory          sbom_documents    sbom_vex_statements
             (264k rows)           sbom_components
             cves (NVD)
```

---

## Database Tables

SBOM Engine creates 3 new tables. It reads from `osv_advisory` and `cves`
but never modifies them.

### sbom_documents
One row per SBOM. This is the master record.

| Column | Example | Meaning |
|--------|---------|---------|
| sbom_id | urn:uuid:abc-123 | Unique ID for this SBOM |
| host_id | prod-server-01 | Which server or pipeline sent it |
| application_name | myapp | Name of the application |
| sbom_format | CycloneDX | CycloneDX or SPDX |
| spec_version | 1.5 | Format version |
| component_count | 142 | Total packages found |
| vulnerability_count | 7 | How many vulnerable packages |
| source | syft | Which tool generated it |
| parent_sbom_id | urn:uuid:xyz-456 | Link to previous scan (for diff) |
| raw_document | {...} | Full original SBOM JSON stored here |

### sbom_components
One row per package per SBOM. Stores EVERY package, not just vulnerable ones.

| Column | Example | Meaning |
|--------|---------|---------|
| sbom_id | urn:uuid:abc-123 | Links to sbom_documents |
| name | requests | Package name |
| version | 2.28.0 | Installed version |
| purl | pkg:pypi/requests@2.28.0 | Standard package identifier |
| ecosystem | PyPI | Package manager ecosystem |
| licenses | ["Apache-2.0"] | License(s) declared |
| is_vulnerable | true | Was a vulnerability found? |
| vulnerability_ids | ["CVE-2023-32681"] | Which CVEs apply |

### sbom_vex_statements
One row per "this CVE does not affect us" decision.

| Column | Example | Meaning |
|--------|---------|---------|
| vulnerability_id | CVE-2023-32681 | The CVE being addressed |
| component_purl | pkg:pypi/requests@2.28.0 | The specific package |
| status | not_affected | Our assessment |
| justification | code_not_reachable | Why we are not affected |
| impact_statement | We never follow redirects | Human explanation |
| created_by | security-team | Who made this decision |

---

## API Endpoints

Base URL: `http://<server>:8002`
Authentication: `Authorization: Bearer <api-key>` or `X-API-Key: <api-key>`
Interactive docs: `http://<server>:8002/api/docs`

### SBOM Endpoints  `/api/v1/sbom/`

| Method | Path | What it does |
|--------|------|--------------|
| **POST** | **`/scan-repo`** | **Point at a Git repo URL — engine clones and builds SBOM itself** |
| POST | `/generate` | Build an SBOM from a package list you provide directly |
| POST | `/upload` | Upload a pre-built CycloneDX or SPDX file (alternative input) |
| GET | `/` | List all SBOMs (filter by host_id) |
| GET | `/{sbom_id}` | Get a specific SBOM (summary, cyclonedx, or raw format) |
| GET | `/host/{host_id}` | Get the latest SBOM for a specific server |
| GET | `/{sbom_id}/diff/{other_sbom_id}` | Compare two SBOMs |
| DELETE | `/{sbom_id}` | Delete an SBOM |

**Dependency files the engine detects and parses automatically:**

| Language/Ecosystem | Files Parsed |
|--------------------|-------------|
| Python (PyPI) | `requirements*.txt`, `Pipfile.lock`, `pyproject.toml` |
| JavaScript (npm) | `package-lock.json`, `package.json`, `yarn.lock` |
| Go | `go.mod` |
| Rust (crates.io) | `Cargo.lock`, `Cargo.toml` |
| Java (Maven) | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| Ruby (RubyGems) | `Gemfile.lock` |
| .NET (NuGet) | `*.csproj`, `packages.config` |
| PHP (Packagist) | `composer.lock` |

### VEX Endpoints  `/api/v1/vex/`

| Method | Path | What it does |
|--------|------|--------------|
| POST | `/` | Create a VEX statement (suppress a false positive) |
| GET | `/` | List VEX statements |
| GET | `/{vulnerability_id}` | Get all VEX statements for a specific CVE |
| DELETE | `/{id}` | Delete a VEX statement |

### Compliance Endpoints  `/api/v1/compliance/`

| Method | Path | What it does |
|--------|------|--------------|
| GET | `/{sbom_id}` | Full compliance report with policy pass/fail |
| GET | `/{sbom_id}/licenses` | License risk breakdown |
| GET | `/{sbom_id}/vulnerabilities` | All vulnerabilities for this SBOM |
| POST | `/{sbom_id}/policy` | Run compliance with custom policy rules |

---

## Complete Workflow Examples

### Example 1 — Scan a Git Repository (Primary Flow)

**Step 1:** Point SBOM Engine at your Git repository:
```bash
curl -X POST "http://sbom-engine:8002/api/v1/sbom/scan-repo" \
     -H "Authorization: Bearer sbom-api-key-2024" \
     -H "Content-Type: application/json" \
     -d '{
       "git_url":          "https://github.com/yourorg/myapp",
       "branch":           "main",
       "host_id":          "myapp-prod",
       "application_name": "myapp"
     }'
```

The engine will:
1. Clone the repository (shallow, no history — fast)
2. Find all dependency files: `requirements.txt`, `package.json`, `go.mod`, `pom.xml`, etc.
3. Parse every file to extract package name, version, and ecosystem
4. Look up every package against the vulnerability database (264k+ advisories)
5. Enrich each vulnerability with EPSS score + CISA KEV status + composite risk score
6. Store the full inventory (all components, not just vulnerable ones)
7. Return a standard CycloneDX 1.5 document

**Response:**
```json
{
  "sbom_id": "urn:uuid:abc-123",
  "repo_url": "https://github.com/yourorg/myapp",
  "commit_sha": "a1b2c3d4...",
  "languages": ["Python", "JavaScript/Node.js"],
  "detected_files": [
    { "path": "requirements.txt",       "type": "requirements_txt", "count": 18 },
    { "path": "api/package-lock.json",  "type": "package_lock_json", "count": 124 }
  ],
  "components": 142,
  "vulnerable_components": 3,
  "cyclonedx": { ... full CycloneDX 1.5 with vulnerabilities section ... }
}
```

**Step 2:** Check compliance before deploying:
```bash
curl "http://sbom-engine:8002/api/v1/compliance/urn:uuid:abc-123?policy_preset=strict" \
     -H "Authorization: Bearer sbom-api-key-2024"
```

**Response:**
```json
{
  "compliance": {
    "overall_status": "fail",
    "policy_results": [
      { "policy": "NO_CRITICAL_VULNS", "status": "fail",
        "message": "2 CRITICAL vulnerabilities found" },
      { "policy": "ALL_COMPONENTS_LICENSED", "status": "warn",
        "message": "3 components with no declared license" }
    ]
  }
}
```

CI/CD fails the build because overall_status is `fail`.

---

### Example 2 — Checking What Changed Between Deployments

After a new deployment, compare the new SBOM against the previous one:

```bash
curl "http://sbom-engine:8002/api/v1/sbom/urn:uuid:new-123/diff/urn:uuid:old-456" \
     -H "Authorization: Bearer sbom-api-key-2024"
```

**Response:**
```json
{
  "components_added":   2,
  "components_removed": 1,
  "components_changed": 3,
  "added": [
    { "name": "spring-boot", "version": "3.2.0" }
  ],
  "removed": [
    { "name": "log4j", "version": "2.14.1" }
  ],
  "changed": [
    { "name": "requests", "version_before": "2.28.0", "version_after": "2.31.0" }
  ],
  "new_vulnerabilities":      ["CVE-2024-12345"],
  "resolved_vulnerabilities": ["CVE-2021-44228"]
}
```

---

### Example 3 — Suppressing a False Positive with VEX

Security team reviews findings and determines a CVE does not apply:

```bash
curl -X POST "http://sbom-engine:8002/api/v1/vex/" \
     -H "Authorization: Bearer sbom-api-key-2024" \
     -H "Content-Type: application/json" \
     -d '{
       "vulnerability_id": "CVE-2023-32681",
       "component_purl":   "pkg:pypi/requests@2.28.0",
       "sbom_id":          "urn:uuid:abc-123",
       "status":           "not_affected",
       "justification":    "code_not_reachable",
       "impact_statement": "Our application never follows HTTP redirects with auth headers",
       "created_by":       "security-team"
     }'
```

From this point on, CVE-2023-32681 is suppressed from all reports and
compliance checks for this package. The decision is recorded permanently
with a reason and who made it.

---

### Example 4 — License Compliance Check

```bash
curl "http://sbom-engine:8002/api/v1/compliance/urn:uuid:abc-123/licenses" \
     -H "Authorization: Bearer sbom-api-key-2024"
```

**Response:**
```json
{
  "summary": {
    "total_components": 142,
    "permissive_count": 128,
    "weak_copyleft_count": 8,
    "strong_copyleft_count": 2,
    "unknown_count": 4,
    "top_licenses": [
      { "license": "MIT",        "count": 67 },
      { "license": "Apache-2.0", "count": 45 },
      { "license": "BSD-3-Clause","count": 16 }
    ],
    "flagged_components": [
      {
        "name": "copyleft-lib", "version": "1.0",
        "licenses": ["GPL-3.0"],
        "flags": ["strong copyleft — review before distribution"]
      }
    ]
  }
}
```

---

## License Categories Explained

| Category | Examples | Risk |
|----------|----------|------|
| **Permissive** | MIT, Apache-2.0, BSD, ISC | Low — use freely |
| **Weak Copyleft** | LGPL, MPL, EPL | Medium — changes to this library must be shared |
| **Strong Copyleft** | GPL-2.0, GPL-3.0, AGPL | High — your entire application may need to be open-sourced |
| **Proprietary** | Commercial, All Rights Reserved | High — verify you have a license |
| **Unknown** | Anything unrecognised | Review needed |

---

## Compliance Policy Presets

Three presets are available. You can also send a fully custom policy.

| Policy Rule | Default | Strict | Lenient |
|-------------|---------|--------|---------|
| No CRITICAL vulnerabilities | FAIL | FAIL | Skip |
| No HIGH vulns with available patch | FAIL | FAIL | Skip |
| No strong copyleft (GPL/AGPL) | Skip | WARN | Skip |
| All components must have a license | WARN | WARN | Skip |
| No unrecognised licenses | Skip | WARN | Skip |
| Max CRITICAL count allowed | 0 | 0 | unlimited |
| Max HIGH count allowed | unlimited | 0 | unlimited |

**Result values:**
- `pass` — policy check passed
- `fail` — policy check failed (blocks deployment in CI/CD)
- `warn` — issue found but not blocking
- `skip` — policy rule is disabled

---

## How Vulnerability Matching Works

When a package is found in the SBOM, SBOM Engine checks it as follows:

```
Package: requests 2.28.0 (PyPI)
         │
         ▼
Query osv_advisory table:
  SELECT * FROM osv_advisory
  WHERE LOWER(pkg_name) = 'requests'
  AND   LOWER(ecosystem) = 'pypi'
  → Returns: GHSA-j8r2-6x86-q33q
             affected_ranges: [{"introduced":"2.0.0","fixed":"2.31.0"}]
         │
         ▼
Version check: is 2.28.0 in range [2.0.0, 2.31.0) ?
  2.0.0 <= 2.28.0 < 2.31.0  → YES, affected
         │
         ▼
CVSS score missing from osv_advisory?
  → Check cves table (NVD data):
    SELECT COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score)
    FROM cves WHERE cve_id = 'CVE-2023-32681'
    → Returns: 6.1 (MEDIUM)
         │
         ▼
VEX check: is there a not_affected statement
           for (CVE-2023-32681, pkg:pypi/requests@2.28.0)?
  → No VEX found → report the vulnerability
         │
         ▼
Component marked: is_vulnerable = true
                  vulnerability_ids = ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"]
```

---

## Deployment

### Local (Docker Compose)
```bash
cd d:/Project/Vulnerability
docker build -f sbom_engine/Dockerfile -t ajaychaudhary86/sbom_engine:latest .
DB_PASSWORD=<password> docker-compose -f sbom_engine/docker-compose.sbom-engine.yml up
```

Service available at: `http://localhost:8002`
API docs at: `http://localhost:8002/api/docs`

### Kubernetes (AWS EKS)
```bash
# Create the secret first (already exists for other engines)
kubectl create secret generic vulnerability-db-secret \
  --from-literal=DB_PASSWORD=<password>

# Deploy
kubectl apply -f sbom_engine/deployment.yaml

# Check status
kubectl get pods -l app=sbom-engine
kubectl logs -l app=sbom-engine
```

---

## Port Reference

| Service | Port | Purpose |
|---------|------|---------|
| vul_engine | 8000 | OS / middleware vulnerability scanning |
| osv_engine | 8001 | Language package vulnerability scanning |
| **sbom_engine** | **8002** | **SBOM platform (this service)** |

---

## Files in This Directory

```
sbom_engine/
├── main.py                           Application entry point
├── Dockerfile                        Container build file
├── docker-compose.sbom-engine.yml    Local development
├── deployment.yaml                   Kubernetes deployment
├── requirements.txt                  Python dependencies
├── README.md                         This document
│
├── api/routes/
│   ├── sbom.py                       Upload, generate, list, diff endpoints
│   ├── vex.py                        VEX statement endpoints
│   └── compliance.py                 Compliance and license report endpoints
│
├── core/
│   ├── config.py                     Configuration from environment variables
│   ├── auth.py                       API key authentication
│   ├── database.py                   Database connection and all queries
│   ├── sbom_parser.py                Parses CycloneDX and SPDX input
│   ├── sbom_generator.py             Generates CycloneDX 1.5 output
│   ├── vuln_enricher.py              Matches packages to vulnerabilities
│   ├── license_checker.py            Classifies and analyses licenses
│   └── compliance_engine.py          Runs policy checks
│
└── db/
    └── create_sbom_tables.sql        Creates the 3 SBOM tables on startup
```

---

## Summary

| Capability | How |
|-----------|-----|
| Accept SBOMs from Syft, Trivy, cdxgen | POST /api/v1/sbom/upload |
| Generate SBOMs from package lists | POST /api/v1/sbom/generate |
| Store complete component inventory | sbom_components table |
| Find vulnerable packages | osv_advisory + cves lookup |
| Track changes between scans | parent_sbom_id + diff endpoint |
| Suppress false positives | VEX statements |
| Check license compliance | GPL/LGPL/MIT classification |
| Enforce security policy | Compliance engine with presets |
| Output standard CycloneDX 1.5 | All responses in CycloneDX format |
