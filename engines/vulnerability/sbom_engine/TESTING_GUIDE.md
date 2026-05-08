# SBOM Engine — Testing Guide

**Service URL:** `http://a51f0ee45336749ada26775a04a1eed6-1195814996.ap-south-1.elb.amazonaws.com:8002`
**API Key:** `sbom-api-key-2024`

---

## Step 1 — Verify the service is running

Open this in your browser or run the curl command:

```
http://a51f0ee45336749ada26775a04a1eed6-1195814996.ap-south-1.elb.amazonaws.com:8002/health
```

```bash
curl http://a51f0ee45336749ada26775a04a1eed6-1195814996.ap-south-1.elb.amazonaws.com:8002/health
```

Expected response:
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "1.0.0"
}
```

---

## Step 2 — Open Swagger UI

Open this URL in your browser:

```
http://a51f0ee45336749ada26775a04a1eed6-1195814996.ap-south-1.elb.amazonaws.com:8002/api/docs
```

You will see all API endpoints grouped into 4 sections:
- **SBOM** — scan repos, list, view, diff, delete SBOMs
- **VEX** — create/manage Vulnerability Exploitability eXchange statements
- **Compliance** — NTIA completeness score, composite risk report
- **Alerts & Threat Intel** — background monitor alerts, EPSS/KEV lookup

---

## Step 3 — Authenticate

1. Click the **Authorize** button (top-right, padlock icon)
2. In the **X-API-Key** field enter:
   ```
   sbom-api-key-2024
   ```
3. Click **Authorize** → **Close**

All requests from this point will include the API key automatically.

---

## Step 4 — Scan a Git repository

1. Click **SBOM** → `POST /api/v1/sbom/scan-repo`
2. Click **Try it out**
3. Paste one of the test payloads below into the Request body field
4. Click **Execute**
5. Scroll down to see the **Response body**

### Test Payload — Python repo
```json
{
  "git_url": "https://github.com/psf/requests.git",
  "application_name": "requests-library",
  "host_id": "test-host-python"
}
```

### Test Payload — Node.js repo
```json
{
  "git_url": "https://github.com/expressjs/express.git",
  "application_name": "express-framework",
  "host_id": "test-host-nodejs"
}
```

### Test Payload — Go repo
```json
{
  "git_url": "https://github.com/gin-gonic/gin.git",
  "application_name": "gin-framework",
  "host_id": "test-host-go"
}
```

### Test Payload — Java / Maven repo
```json
{
  "git_url": "https://github.com/spring-projects/spring-petclinic.git",
  "application_name": "spring-petclinic",
  "host_id": "test-host-java"
}
```

### Test Payload — Mixed (Python + already scanned in session test)
```json
{
  "git_url": "https://github.com/tiangolo/fastapi.git",
  "application_name": "fastapi-framework",
  "host_id": "test-host-fastapi"
}
```

### What you will see in the response

```json
{
  "sbom_id": "urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "repo_url": "https://github.com/...",
  "commit_sha": "abc1234...",
  "branch": "default",
  "application_name": "...",
  "languages": ["Python"],
  "detected_files": [
    { "path": "requirements.txt", "type": "requirements_txt", "count": 12 }
  ],
  "components": 12,
  "vulnerable_components": 3,
  "cyclonedx": { ... full CycloneDX 1.5 document ... }
}
```

> **Note:** Copy the `sbom_id` value — you will need it in the steps below.

---

## Step 5 — View the stored SBOM

### Summary view (recommended first look)

`GET /api/v1/sbom/{sbom_id}`

1. Click **SBOM** → `GET /api/v1/sbom/{sbom_id}`
2. Click **Try it out**
3. Paste your `sbom_id` (e.g. `urn:uuid:3eb029fc-47ed-4556-8e9c-234c6a4da737`)
4. Leave `format` as `summary`
5. Click **Execute**

Returns: component count, vulnerable components list, license summary.

### Full CycloneDX 1.5 document

Same endpoint, change `format` to `cyclonedx` — returns the complete standard SBOM document.

### List all SBOMs stored so far

`GET /api/v1/sbom/`

No parameters needed. Returns all SBOM documents with their metadata.

---

## Step 6 — Check NTIA compliance score

`GET /api/v1/compliance/{sbom_id}/ntia`

1. Click **Compliance** → `GET /api/v1/compliance/{sbom_id}/ntia`
2. Click **Try it out** → paste your `sbom_id`
3. Click **Execute**

Returns a score from 0–100% across the 7 NTIA minimum elements required by US Executive Order 14028:

| Element | What it checks |
|---|---|
| Supplier name | Is the component supplier known? |
| Component name | Is every component named? |
| Version | Does every component have a version? |
| Unique identifier | Does every component have a PURL? |
| Dependency relationships | Are relationships mapped? |
| SBOM author | Is the tool/author recorded? |
| Timestamp | Is the creation time recorded? |

Score thresholds:
- **71–100%** → Compliant
- **41–70%** → Partially compliant
- **0–40%** → Non-compliant

---

## Step 7 — View composite risk report

`GET /api/v1/compliance/{sbom_id}/risk`

1. Click **Compliance** → `GET /api/v1/compliance/{sbom_id}/risk`
2. Click **Try it out** → paste your `sbom_id`
3. Click **Execute**

For each CVE found, returns:

| Field | Meaning |
|---|---|
| `composite_risk` | Score 0–10 combining CVSS + EPSS + KEV |
| `priority` | IMMEDIATE / HIGH / MEDIUM / LOW |
| `sla` | Recommended fix deadline (24h / 72h / 2 weeks / next release) |
| `epss_score` | Probability of exploitation in next 30 days (FIRST.org) |
| `in_cisa_kev` | True = being actively exploited right now (CISA catalog) |

---

## Step 8 — Look up threat intel for a specific CVE

`GET /api/v1/alerts/threat-intel/{cve_id}`

1. Click **Alerts & Threat Intel** → `GET /api/v1/alerts/threat-intel/{cve_id}`
2. Click **Try it out**
3. Enter a CVE ID found in your scan (e.g. `CVE-2025-62727`)
4. Click **Execute**

Returns EPSS score, percentile, CISA KEV status, and a plain-English interpretation of the risk level.

---

## Step 9 — Diff two SBOMs (version comparison)

Scan the same repo twice (or scan two different versions), then compare:

`GET /api/v1/sbom/{sbom_id}/diff/{other_sbom_id}`

Returns:
- Components added / removed / version-changed between the two scans
- New vulnerabilities introduced
- Vulnerabilities resolved

---

## Step 10 — Create a VEX statement (suppress a false positive)

If a CVE is detected but does not actually affect this application (e.g. the vulnerable code path is not reachable), document it:

`POST /api/v1/vex/`

```json
{
  "sbom_id": "urn:uuid:your-sbom-id-here",
  "vulnerability_id": "CVE-2025-54121",
  "component_purl": "pkg:pypi/starlette@0.46.0",
  "component_name": "starlette",
  "status": "not_affected",
  "justification": "code_not_reachable",
  "impact_statement": "This application does not use multipart file uploads so the vulnerable code path in Starlette is never reached.",
  "created_by": "security-team"
}
```

Valid `justification` values:
- `code_not_present`
- `code_not_reachable`
- `requires_configuration`
- `requires_privilege`
- `protected_by_compiler`
- `protected_at_runtime`
- `protected_at_perimeter`
- `protected_by_mitigating_control`

---

## Quick reference — curl commands

If you prefer curl over Swagger UI, here are ready-to-run commands:

```bash
BASE="http://a51f0ee45336749ada26775a04a1eed6-1195814996.ap-south-1.elb.amazonaws.com:8002"
KEY="sbom-api-key-2024"

# Health check
curl $BASE/health

# Scan a repo
curl -X POST $BASE/api/v1/sbom/scan-repo \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"git_url":"https://github.com/psf/requests.git","application_name":"requests","host_id":"test-01"}'

# List all SBOMs
curl -H "X-API-Key: $KEY" $BASE/api/v1/sbom/

# Get SBOM summary  (replace SBOM_ID)
curl -H "X-API-Key: $KEY" "$BASE/api/v1/sbom/SBOM_ID"

# NTIA compliance score
curl -H "X-API-Key: $KEY" "$BASE/api/v1/compliance/SBOM_ID/ntia"

# Composite risk report
curl -H "X-API-Key: $KEY" "$BASE/api/v1/compliance/SBOM_ID/risk"

# Threat intel for a CVE
curl -H "X-API-Key: $KEY" "$BASE/api/v1/alerts/threat-intel/CVE-2025-62727"

# List alerts from background monitor
curl -H "X-API-Key: $KEY" "$BASE/api/v1/alerts/"
```

---

## Supported dependency files (auto-detected)

The engine scans the full repository and automatically detects:

| Ecosystem | Files detected |
|---|---|
| Python | `requirements*.txt`, `Pipfile.lock`, `pyproject.toml`, `setup.cfg` |
| Node.js | `package-lock.json`, `package.json`, `yarn.lock` |
| Go | `go.mod` |
| Rust | `Cargo.lock`, `Cargo.toml` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| Ruby | `Gemfile.lock` |
| .NET | `*.csproj`, `packages.config` |
| PHP | `composer.lock` |

Lock files always take precedence over manifest files (exact resolved versions).

---

## Private repository support

The engine accepts an optional `git_token` field in the scan request.
The token is used **only** during the git clone and is **never** logged, stored in the
database, or returned in any API response.

### How it works in the SecOps platform

The **SecOps Orchestrator** (separate service, under development by the platform team)
is the single owner of all git credentials. The flow is:

```
AWS Secrets Manager
      │
      │  GetSecretValue("sbom-engine/git/<credential_name>")
      ▼
SecOps Orchestrator  ──── POST /api/v1/sbom/scan-repo ────▶  SBOM Engine
  (fetches token)            { git_url, git_token }            (clone + scan)
                              internal VPC only
```

The token travels **only on the internal EKS network** between the orchestrator and
the SBOM engine — it is never exposed on the internet.

### Secret format in AWS Secrets Manager

Each secret is stored under the key `sbom-engine/git/<credential_name>`:

```json
{
  "token":    "ghp_xxxxxxxxxxxxxxxxxxxx",
  "username": "",
  "provider": "github"
}
```

Valid `provider` values: `github`, `gitlab`, `bitbucket`, `azure`, `generic`

`username` is only needed for Bitbucket App Passwords and some self-hosted servers.

### Token injection per provider

The engine automatically constructs the correct authenticated URL based on the
git host in the URL:

| Provider | Authenticated URL format |
|---|---|
| GitHub / GitHub Enterprise | `https://<token>@github.com/...` |
| GitLab / GitLab self-hosted | `https://oauth2:<token>@gitlab.com/...` |
| Bitbucket Cloud | `https://x-token-auth:<token>@bitbucket.org/...` |
| Azure DevOps | `https://<username>:<token>@dev.azure.com/...` |
| Self-hosted (Gitea, Forgejo) | `https://<username>:<token>@<host>/...` |

### Testing private repos manually (Swagger UI or curl)

During testing, the token can be passed directly in the request body.
In production, this is done by the SecOps Orchestrator — never by end users.

**Swagger UI:** add `git_token` to the `POST /scan-repo` request body:

```json
{
  "git_url": "https://github.com/myorg/private-repo.git",
  "application_name": "my-private-app",
  "host_id": "test-host",
  "git_token": "ghp_your_token_here"
}
```

**curl:**
```bash
curl -X POST $BASE/api/v1/sbom/scan-repo \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "git_url": "https://github.com/myorg/private-repo.git",
    "application_name": "my-private-app",
    "host_id": "test-host",
    "git_token": "ghp_your_token_here"
  }'
```

### Orchestrator integration (platform team)

See [TODO.md](TODO.md) — **Item 1** for the full implementation spec including
AWS Secrets Manager setup, IAM permissions, and the orchestrator call pattern.

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `401 Unauthorized` | Missing or wrong API key | Use `sbom-api-key-2024` in Authorize first |
| `400 Invalid Git URL` | Bad URL format | URL must start with `https://` or `git@` |
| `400 Token auth requires HTTPS` | SSH URL + token provided | Use HTTPS URL with token, or omit token for SSH |
| `422 Git clone failed` | Wrong token / repo not found | Verify token has `repo` read scope |
| `422 Git clone failed` | Public repo, no token needed | Remove `git_token` from request |
| `No dependency manifests found` | Repo has no supported files | Check the supported files table above |
| Response takes 30–60s | Normal — git clone + scan + enrichment | Wait for it, large repos take longer |
