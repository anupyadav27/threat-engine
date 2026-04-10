# VulFix Engine

Ansible-based CVE remediation engine. Reads vulnerability findings from the organization's
`vulnerability_db`, calls **Mistral AI** to generate production-ready Ansible playbooks,
validates them with yamllint/ansible-lint, and pushes the playbooks as a new branch in the
organization's existing Ansible Git repository. A pull request is opened for human review.

**No playbook is executed automatically.** Every generated fix goes through human review
before anyone can run it.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Running Locally](#running-locally)
- [Docker](#docker)
- [API Reference](#api-reference)
- [Request & Response Examples](#request--response-examples)
- [Generated Playbook Quality](#generated-playbook-quality)
- [Applying a Playbook](#applying-a-playbook)
- [Database Tables Read](#database-tables-read)
- [Security Design](#security-design)
- [Project Structure](#project-structure)

---

## How It Works

```
vulnerability_db
  └─ scans + scan_vulnerabilities + cves
        │
        ▼
  [1] Read scan findings
        │  scan_id, hostname, OS, CVEs per package
        ▼
  [2] Clone org's Ansible repo (shallow, depth=1)
        │  Detects: role-based vs flat, become_method, FQCN requirement,
        │            inventory group for target host, existing task snippets,
        │            group_vars, ansible.cfg settings
        ▼
  [3] Mistral AI — one call per unique package
        │  Input:  CVEs, CVSS scores, OS, env_type, repo context
        │  Output: complete Ansible playbook YAML
        ▼
  [4] Validate
        │  Layer 1: yamllint (always — pure Python)
        │  Layer 2: ansible-lint (Linux/Docker only; skipped gracefully on Windows)
        │  On errors: retry AI up to 2 times with error context fed back
        ▼
  [5] Push to Git
        │  Branch: vulfix/{scan_id}
        │  Files:  vulfix/{scan_id}/patch_{package}.yml
        │           vulfix/{scan_id}/README.md
        ▼
  [6] Open PR on GitHub / GitLab
        │  Human reviews and runs:
        │    ansible-playbook patch_nginx.yml --check --diff
        │    ansible-playbook patch_nginx.yml
        ▼
  Done — no code executed without explicit human approval
```

---

## Architecture

```
vul_fix/
  engine/
    api_server.py           — FastAPI app, CORS, APIKeyMiddleware, startup checks
    middleware/
      auth.py               — X-API-Key enforcement on all non-health endpoints
    routers/
      remediation.py        — POST /remediate + GET /remediate/{scan_id}
      health.py             — /live, /ready probes
    core/
      git_connector.py      — Shallow-clone + analyse org Ansible repo
      ai_fixer.py           — Mistral AI prompt engineering + retry logic
      ansible_validator.py  — yamllint + ansible-lint validation
      git_pusher.py         — Branch creation, file commit, PR opening
    db/
      db_config.py          — PostgreSQL connection pool (psycopg2)
      fetcher.py            — Read scans, CVEs, fixed-version hints
      writer.py             — Drop legacy table only (no writes — Git is the store)
    models/
      remediation.py        — Pydantic request/response models with input validation
    Dockerfile
    requirements.txt
  tests/
    run_test.py             — Local end-to-end test (local bare git repo)
    run_test_github.py      — Full GitHub end-to-end test with real PR
```

**Port**: `8007`

**Concurrency**: `VUL_FIX_MAX_CONCURRENT` (default 3) simultaneous pipeline runs
controlled by `asyncio.Semaphore`.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| Python | 3.11+ |
| PostgreSQL | `vulnerability_db` on RDS (read-only access: `scans`, `scan_vulnerabilities`, `cves`, `agents`) |
| Mistral AI API key | `console.mistral.ai` — model `mistral-medium` or better |
| Git token | GitHub/GitLab PAT with `Contents: Write` + `Pull Requests: Write` scopes |
| Org Ansible repo | Must already exist with `main` (or specified) base branch |
| yamllint | Installed via `requirements.txt` (always runs) |
| ansible-lint | Linux/Docker only; installed in Docker image; skipped on Windows |

---

## Configuration

Copy `engine/.env.template` → `engine/.env` and fill in all values:

```env
# ── PostgreSQL (vulnerability_db) ─────────────────────────────────────────────
VUL_DB_HOST=<rds-hostname>.rds.amazonaws.com
VUL_DB_PORT=5432
VUL_DB_NAME=vulnerability_db
VUL_DB_USER=postgres
VUL_DB_PASSWORD=<password>

# ── Mistral AI ─────────────────────────────────────────────────────────────────
MISTRAL_API_KEY=<your-mistral-key>
MISTRAL_MODEL=mistral-medium        # or mistral-large for better quality
MISTRAL_TIMEOUT=90                  # seconds

# ── API security ───────────────────────────────────────────────────────────────
VUL_FIX_API_KEY=<strong-random-key>  # clients send this in X-API-Key header

# ── Git ─────────────────────────────────────────────────────────────────────────
# Injected via Kubernetes secret in production; set here for local dev only
GIT_TOKEN=<github-or-gitlab-pat>

# ── Optional tuning ────────────────────────────────────────────────────────────
VUL_FIX_PORT=8007
VUL_FIX_MAX_CONCURRENT=3           # max simultaneous pipeline runs
ALLOWED_ORIGINS=*                   # comma-separated CORS origins
```

> **Security note**: `GIT_TOKEN` is read exclusively from the environment — it is never
> accepted in the request body. Store it in a Kubernetes secret in production.

---

## Running Locally

```bash
cd vul_fix/engine

# Install dependencies
pip install -r requirements.txt

# Start the server
python api_server.py
# or
uvicorn api_server:app --host 0.0.0.0 --port 8007 --reload

# Interactive API docs
open http://localhost:8007/docs
```

### Running the end-to-end tests

**Local test** (uses a temporary bare git repo — no GitHub required):

```bash
cd vul_fix/engine
python ../tests/run_test.py [scan_id]
# e.g.
python ../tests/run_test.py 15032026_017
```

**GitHub test** (creates a real branch and PR on your GitHub repo):

```bash
cd vul_fix/engine
python ../tests/run_test_github.py [scan_id]
# e.g.
python ../tests/run_test_github.py 15032026_017
```

Both tests load real scan data from `vulnerability_db`, call Mistral AI, validate the
playbooks, and push to git. The GitHub test creates an actual PR you can open and review.

---

## Docker

```bash
# Build (from the vul_fix/ directory)
docker build -f engine/Dockerfile -t vulfixengine:latest .

# Run
docker run -d \
  --name vulfixengine \
  -p 8007:8007 \
  -e VUL_DB_HOST=<host> \
  -e VUL_DB_PORT=5432 \
  -e VUL_DB_NAME=vulnerability_db \
  -e VUL_DB_USER=postgres \
  -e VUL_DB_PASSWORD=<password> \
  -e MISTRAL_API_KEY=<key> \
  -e GIT_TOKEN=<pat> \
  -e VUL_FIX_API_KEY=<api-key> \
  vulfixengine:latest

# Check health
curl http://localhost:8007/api/v1/health/live
```

The Docker image compiles `psycopg2` from source (with `libpq-dev`) for production
stability, and installs `ansible-core 2.17.7` + `ansible-lint 24.9.2` for full
two-layer validation.

---

## API Reference

All endpoints except health probes require the `X-API-Key` header.

### Health probes (no auth)

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/health/live` | Liveness — returns 200 if process is alive |
| GET | `/api/v1/health/ready` | Readiness — returns 200 when DB pool is ready |

### Remediation endpoints (X-API-Key required)

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/vul-fix/remediate` | Trigger full remediation pipeline |
| GET | `/api/v1/vul-fix/remediate/{scan_id}` | Get scan metadata |

---

## Request & Response Examples

### POST `/api/v1/vul-fix/remediate`

**Request:**

```json
{
  "scan_id": "15032026_017",
  "git_repo_url": "https://github.com/your-org/ansible-playbooks.git",
  "base_branch": "main",
  "severity_filter": ["CRITICAL", "HIGH"],
  "max_packages": 10,
  "create_pr": true
}
```

| Field | Required | Default | Description |
|---|---|---|---|
| `scan_id` | Yes | — | Scan ID from `vulnerability_db.scans`. Pattern: `[a-zA-Z0-9_-]{1,100}` |
| `git_repo_url` | Yes | — | `https://` or `file://` URL of org's Ansible repo |
| `base_branch` | No | `main` | Branch to create the fix branch from |
| `severity_filter` | No | `["CRITICAL","HIGH"]` | Which severities to remediate |
| `max_packages` | No | `10` | Maximum packages to generate playbooks for |
| `create_pr` | No | `true` | Whether to open a PR/MR after pushing |

> `git_token` is **not** a request field — it is read from `GIT_TOKEN` env var only.

**Response:**

```json
{
  "scan_id": "15032026_017",
  "status": "completed",
  "branch": "vulfix/15032026_017",
  "branch_url": "https://github.com/your-org/ansible-playbooks/tree/vulfix/15032026_017",
  "pr_url": "https://github.com/your-org/ansible-playbooks/pull/42",
  "playbooks": [
    {
      "package": "nginx",
      "file": "vulfix/15032026_017/patch_nginx.yml",
      "cves": ["CVE-2024-49368", "CVE-2024-49366"],
      "highest_severity": "HIGH",
      "lint_passed": true
    },
    {
      "package": "login",
      "file": "vulfix/15032026_017/patch_login.yml",
      "cves": ["CVE-2020-8907", "CVE-2020-8933", "CVE-2012-10001"],
      "highest_severity": "CRITICAL",
      "lint_passed": true
    }
  ],
  "severity_counts": {"CRITICAL": 5, "HIGH": 2},
  "how_to_run": "ansible-playbook vulfix/15032026_017/patch_nginx.yml --check --diff"
}
```

### GET `/api/v1/vul-fix/remediate/{scan_id}`

Returns the scan metadata (host, OS, agent, CVE counts) from `vulnerability_db`.
The playbooks themselves are in Git — the response contains the branch and PR URLs.

---

## Generated Playbook Quality

Every generated playbook follows a strict, validated structure:

```yaml
---
# CVE IDs: CVE-2024-49368 (CVSS 9.8), CVE-2024-49366 (CVSS 7.5)
# Severity: HIGH
# Generated by VulFix Engine v2

- name: Patch vulnerable nginx package (CVE-2024-49368, CVE-2024-49366)
  hosts: all                         # or specific group from inventory
  become: true

  tasks:
    # 1. Gather facts FIRST — so we know the current version before touching anything
    - name: Gather package facts
      ansible.builtin.package_facts:
        manager: auto

    # 2. Debug — visible in ansible output for audit trail
    - name: Debug current nginx version
      ansible.builtin.debug:
        msg: "Current nginx version: {{ ansible_facts.packages['nginx'][0].version }}"

    # 3. Refresh cache
    - name: Update apt package cache
      ansible.builtin.apt:
        update_cache: true

    # 4. Patch — state: latest when no confirmed fixed version is known
    - name: Upgrade nginx to latest secure version
      ansible.builtin.apt:
        name: nginx
        state: latest
        update_cache: false
      notify: Restart nginx

    # 5. Gather facts again to capture the new version
    - name: Gather package facts after upgrade
      ansible.builtin.package_facts:
        manager: auto

    # 6. Assert — fail the play if version did not change (patch failed silently)
    - name: Assert nginx is no longer on vulnerable version
      ansible.builtin.assert:
        that: ansible_facts.packages['nginx'][0].version != vulnerable_version
        fail_msg: "CRITICAL: nginx is still on vulnerable version {{ vulnerable_version }}"
        success_msg: "nginx patched successfully"

  handlers:
    - name: Restart nginx
      ansible.builtin.service:
        name: nginx
        state: restarted
```

**What the AI does:**
- Uses **FQCN** (`ansible.builtin.*`) automatically when required by the repo's Ansible version
- Adapts `become_method` from the repo's `ansible.cfg`
- Targets the correct **inventory group** by matching the scanned host to `hosts.ini`
- Uses `state: latest` when no confirmed fixed version exists — never invents a version number
- Adds a **Dockerfile remediation comment** for container environments (`env_type=docker`)
- Writes handlers as **debug messages** when services are unknown, not as disabled (`when: false`) handlers

**Validation layers:**

| Layer | Tool | When |
|---|---|---|
| 1 | `yamllint` | Always (pure Python, cross-platform) |
| 2 | `ansible-lint` | Linux/Docker; gracefully skipped on Windows or if not installed |
| Retry | AI re-prompt | Up to 2 retries if validation fails; error context fed back to AI |

Even if validation warnings remain after retries, the playbook is still pushed for human review — it is never silently dropped.

---

## Applying a Playbook

After the PR is opened, a human reviewer should:

```bash
# 1. Checkout the fix branch
git fetch origin
git checkout vulfix/15032026_017

# 2. Dry-run FIRST — mandatory before any real execution
ansible-playbook vulfix/15032026_017/patch_nginx.yml --check --diff

# 3. Review the diff output carefully

# 4. Execute only after approval
ansible-playbook vulfix/15032026_017/patch_nginx.yml

# 5. For containers: rebuild and redeploy the image
#    (runtime apt-get upgrades are not persistent in containers)
```

The PR description includes these steps and explains the Docker persistence requirement.

---

## Database Tables Read

The engine reads from `vulnerability_db` (never writes):

| Table | Used for |
|---|---|
| `scans` | Scan metadata: `scan_id`, `hostname`, `os_name`, `os_version`, `env_type`, `vul_agent_id` |
| `scan_vulnerabilities` | Per-CVE findings: `package_name`, `package_version`, `severity`, `cvss_v3_score` |
| `cves` | CVE details: `cve_id`, `description`, fixed version hints |
| `agents` | Agent metadata for `vul_agent_id` resolution |

No tables are written. No data is stored by this engine. Git is the only output store.

---

## Security Design

| Concern | Mitigation |
|---|---|
| Authentication | `X-API-Key` header enforced on all non-health endpoints via `APIKeyMiddleware` |
| Git token exposure | `GIT_TOKEN` from env var only — never in request body or logs (masked to last 4 chars) |
| Path traversal | `scan_id` validated against `^[a-zA-Z0-9_-]{1,100}$`; file paths sanitized with `Path(...).name` |
| Shell injection | `target_hosts_override` blocks `;|&\`$()<>` characters |
| URL injection | `git_repo_url` must start with `https://` or `file://` |
| Rate limiting | `asyncio.Semaphore(VUL_FIX_MAX_CONCURRENT)` limits concurrent pipeline runs |
| No auto-execution | Playbooks are committed to a branch — execution requires explicit human action |
| Non-root container | Docker image runs as `vulfixuser` (UID 1001) |
| Build tool cleanup | `gcc` and `build-essential` purged from Docker image after `psycopg2` compilation |

---

## Project Structure

```
vul_fix/
├── engine/
│   ├── api_server.py           Main FastAPI application
│   ├── Dockerfile              Production Docker image
│   ├── requirements.txt        Python dependencies
│   ├── .env.template           Environment variable template
│   ├── middleware/
│   │   └── auth.py             X-API-Key authentication middleware
│   ├── routers/
│   │   ├── remediation.py      Core pipeline endpoint
│   │   └── health.py           Liveness + readiness probes
│   ├── core/
│   │   ├── git_connector.py    Clone + analyse org Ansible repo
│   │   ├── ai_fixer.py         Mistral AI playbook generation
│   │   ├── ansible_validator.py  yamllint + ansible-lint validation
│   │   └── git_pusher.py       Branch push + PR creation
│   ├── db/
│   │   ├── db_config.py        Connection pool
│   │   ├── fetcher.py          Read scans and CVEs
│   │   └── writer.py           Drop legacy table (one-time cleanup)
│   └── models/
│       └── remediation.py      Pydantic request/response schemas
└── tests/
    ├── run_test.py             Local test (temporary bare repo)
    └── run_test_github.py      GitHub end-to-end test (real PR)
```
