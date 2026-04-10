# SecOps Fix Engine

AI-powered source code remediation engine for SAST (Static Application Security Testing)
findings. Reads security findings from the `threat_engine_secops` database — produced by the
SecOps scanner — calls **Mistral AI** with full file context to generate corrected source code,
commits the patched files to a new fix branch, and pushes it for human review.

The SecOps scanner identifies *what* is wrong (rule, line, severity). This engine generates
*how to fix it* and commits that fix to a branch for developer review and testing before merge.

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
- [Fix Quality and Strategy](#fix-quality-and-strategy)
- [Database Schema](#database-schema)
- [Applying a Fix](#applying-a-fix)
- [Security Design](#security-design)
- [Project Structure](#project-structure)

---

## How It Works

```
SecOps Scanner
  └─ secops_report + secops_findings + secops_rule_metadata
        │
        ▼
  [1] Read findings for scan_id
        │  file_path, line_number, rule_id, severity, message, language
        ▼
  [2] Batch-fetch rule metadata (single DB round-trip)
        │  secops_rule_metadata → title, description, recommendation,
        │  compliant_example, impact, references
        ▼
  [3] Clone source repo (shallow, depth=1)
        │  Read actual source files — AI needs the full file context,
        │  not just the flagged line
        ▼
  [4] Group findings per file
        │  One Mistral AI call per file (not per finding)
        │  AI sees: full file + all issues in that file + rule guidance
        ▼
  [5] Mistral AI returns corrected full file
        │  AI fixes only the listed issues — preserves all other code exactly
        ▼
  [6] Write corrected files → create fix branch → commit → push
        │  Branch: secops-fix/{scan_id[:8]}
        ▼
  [7] Record all results in secops_remediation table
        │  status: applied / fix_generated / failed / skipped
        ▼
  Developer reviews diff, tests in staging, merges if satisfied
```

---

## Architecture

```
secops_fix/
  engine/
    api_server.py           — FastAPI app, startup checks, CORS
    routers/
      remediation.py        — POST /remediate + GET /remediate/{scan_id}
      findings.py           — GET /findings/{scan_id} + /findings/{scan_id}/summary
      health.py             — /live, /ready probes
    core/
      ai_fixer.py           — Mistral AI integration (per-file, full-context)
      git_patcher.py        — Clone, write fixes, commit, push fix branch
    db/
      db_config.py          — PostgreSQL connection (psycopg2)
      fetcher.py            — Read findings, scan report, rule metadata
      writer.py             — Write remediation rows, update status
      schema.sql            — secops_remediation table DDL
    models/
      finding.py            — SecOpsFinding + ScanReport Pydantic models
      fix_result.py         — FixResult model (per-finding fix outcome)
      remediation.py        — RemediationRequest / RemediationSummary / RemediationStatus
    Dockerfile
    requirements.txt
  test_engine.py            — End-to-end integration test
```

**Port**: `8006`

---

## Prerequisites

| Requirement | Detail |
|---|---|
| Python | 3.11+ |
| PostgreSQL | `threat_engine_secops` DB with tables: `secops_report`, `secops_findings`, `secops_rule_metadata`, `secops_remediation` |
| SecOps scanner | Must have completed a scan and populated `secops_findings` for the requested `secops_scan_id` |
| Mistral AI API key | `console.mistral.ai` — model `mistral-medium` or better |
| Git token | GitHub/GitLab PAT with `Contents: Write` scope (for pushing fix branch) |
| Source repo | The repo URL recorded in `secops_report.repo_url` must be accessible |

### Database setup

Run the schema migration once before first use:

```bash
psql -h <db-host> -U postgres -d threat_engine_secops \
     -f secops_fix/engine/db/schema.sql
```

This creates the `secops_remediation` table, indexes, and `updated_at` trigger.

---

## Configuration

Set the following environment variables (or add to a `.env` file):

```env
# ── API security ────────────────────────────────────────────────────────────────
SECOPS_FIX_API_KEY=<strong-random-key>   # clients send in X-API-Key header (required)

# ── PostgreSQL (threat_engine_secops) ──────────────────────────────────────────
DB_HOST=<rds-hostname>.rds.amazonaws.com
DB_PORT=5432
DB_NAME=threat_engine_secops
DB_USER=postgres
DB_PASSWORD=<password>

# ── Mistral AI ─────────────────────────────────────────────────────────────────
MISTRAL_API_KEY=<your-mistral-key>
MISTRAL_MODEL=mistral-medium        # or mistral-large for higher accuracy
MISTRAL_TIMEOUT=120                 # seconds (files can be large)

# ── Optional tuning ─────────────────────────────────────────────────────────────
SECOPS_FIX_PORT=8006
SECOPS_FIX_MAX_CONCURRENT=3         # max simultaneous pipeline runs
SECOPS_FIX_PIPELINE_TIMEOUT=600     # per-run wall-clock limit in seconds
ALLOWED_ORIGINS=*                   # comma-separated CORS origins (restrict in prod)
```

> `SECOPS_FIX_API_KEY` and `MISTRAL_API_KEY` are **required** — the engine exits
> immediately at startup if either is missing.
>
> The Git repo token (`repo_token`) is passed **per request** in the `X-Repo-Token`
> header — the engine never stores or logs it.

---

## Running Locally

```bash
cd secops_fix/engine

# Install dependencies
pip install -r requirements.txt

# Start the server
python api_server.py
# or
uvicorn api_server:app --host 0.0.0.0 --port 8006 --reload

# Interactive API docs
open http://localhost:8006/docs
```

### Running the end-to-end test

```bash
cd secops_fix
python test_engine.py
```

The test exercises the full pipeline: reads a scan from DB, fetches rule metadata,
clones the source repo, calls Mistral AI, and pushes a fix branch.

---

## Docker

```bash
# Build (from the secops_fix/ directory)
docker build -f engine/Dockerfile -t secops-fix-engine:latest .

# Run
docker run -d \
  --name secops-fix \
  -p 8006:8006 \
  -e DB_HOST=<host> \
  -e DB_PORT=5432 \
  -e DB_NAME=threat_engine_secops \
  -e DB_USER=postgres \
  -e DB_PASSWORD=<password> \
  -e MISTRAL_API_KEY=<key> \
  secops-fix-engine:latest

# Check health
curl http://localhost:8006/api/v1/health/live
```

---

## API Reference

### Health probes (no auth required)

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/health/live` | Liveness — returns 200 if process is alive |
| GET | `/api/v1/health/ready` | Readiness — returns 200 when DB is reachable |
| GET | `/api/v1/health` | Full health with DB status and AI config |

### Remediation

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/secops-fix/remediate` | Trigger AI remediation for a completed scan |
| GET | `/api/v1/secops-fix/remediate/{secops_scan_id}` | Get remediation status and summary |

### Findings (read-only view of scanner output)

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/secops-fix/findings/{secops_scan_id}` | List all findings for a scan |
| GET | `/api/v1/secops-fix/findings/{secops_scan_id}/summary` | Count by severity and status |

---

## Request & Response Examples

### POST `/api/v1/secops-fix/remediate`

**Required headers:**

| Header | Description |
|---|---|
| `X-API-Key` | Engine API key (`SECOPS_FIX_API_KEY` env var) |
| `X-Repo-Token` | Git PAT with `Contents: Write` on the source repo — never in body or logs |

**Request body:**

```json
{
  "secops_scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "tenant_id": "acme-corp",
  "repo_url": "https://github.com/acme-corp/backend-api.git",
  "source_branch": "main",
  "severity_filter": ["critical", "high"]
}
```

| Field | Required | Description |
|---|---|---|
| `secops_scan_id` | Yes | UUID — must exist in `secops_report` table |
| `tenant_id` | Yes | Tenant identifier |
| `repo_url` | Yes | `https://` URL of the source code repository |
| `source_branch` | No (default: `main`) | Branch to create the fix branch from |
| `orchestration_id` | No | UUID — for linking to the scan orchestration run |
| `severity_filter` | No (default: all) | `["critical","high","medium","low","info"]` |

> `repo_token` is **not** a body field — pass it in the `X-Repo-Token` header so it is
> subject to header-scrubbing by proxies and never appears in request-body logs.

**Response:**

```json
{
  "secops_scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "total_findings": 12,
  "matched": 12,
  "fix_generated": 9,
  "applied": 9,
  "failed": 1,
  "skipped": 2,
  "fix_branch": "secops-fix/a1b2c3d4",
  "pr_url": null,
  "remediations": [
    {
      "remediation_id": "uuid",
      "secops_scan_id": "a1b2c3d4-...",
      "finding_id": 1042,
      "rule_id": "hardcoded-credentials",
      "file_path": "src/config/database.py",
      "line_number": 47,
      "match_layer": "direct",
      "status": "applied",
      "fix_branch": "secops-fix/a1b2c3d4",
      "pr_url": null,
      "error_message": null,
      "created_at": "2026-04-09T10:30:00Z"
    }
  ]
}
```

**Response field meanings:**

| Field | Meaning |
|---|---|
| `matched` | Findings that had rule metadata found in `secops_rule_metadata` |
| `fix_generated` | Findings where Mistral AI produced a corrected file |
| `applied` | Findings whose corrected files were committed to the fix branch |
| `failed` | Findings where AI fix generation or git commit failed |
| `skipped` | Findings excluded by severity filter or missing file path |
| `fix_branch` | Git branch name — `null` if no patchable fixes were found |
| `match_layer` | `direct` = rule found in DB; `no_rule_metadata` = AI used finding message only |

### GET `/api/v1/secops-fix/findings/{secops_scan_id}`

Returns the raw findings from `secops_findings` for the scan — the same data the scanner
wrote, before any remediation. Useful for reviewing what was found before triggering a fix.

```json
[
  {
    "id": 1042,
    "secops_scan_id": "a1b2c3d4-...",
    "file_path": "src/config/database.py",
    "language": "python",
    "rule_id": "hardcoded-credentials",
    "severity": "critical",
    "message": "Hardcoded password found at line 47",
    "line_number": 47,
    "status": "open"
  }
]
```

---

## Fix Quality and Strategy

### Full-file AI context

The engine does not send just the flagged line to Mistral AI. It sends the **entire file**
along with all flagged issues in that file — so the AI sees imports, class structure,
function signatures, and surrounding logic. This produces fixes that:

- Preserve code style and indentation exactly
- Do not duplicate imports that already exist
- Use the right variable or config pattern for that codebase
- Fix multiple issues in a single coherent pass

### One API call per file

Rather than one Mistral call per finding (expensive, context-unaware), the engine groups
all findings from the same file and sends one call. This is cheaper and higher quality.

### Rule metadata as AI hints

Each finding's `rule_id` is looked up in `secops_rule_metadata` in a single batch query.
The engine passes `title`, `description`, `recommendation`, and a language-matched
`compliant_example` to the AI as structured hints — so the AI knows not just *what* is
wrong but *what the correct pattern looks like* for that organization's stack.

If a `rule_id` is not found in the metadata table, the AI falls back to the raw `message`
field from the scanner — the fix is still attempted.

### Example: hardcoded credentials fix

**Before** (flagged by scanner at line 47):
```python
# src/config/database.py
DB_PASSWORD = "my-secret-password-123"
```

**After** (AI-corrected full file committed to fix branch):
```python
# src/config/database.py
import os
DB_PASSWORD = os.getenv("DB_PASSWORD")
```

The AI returns the complete corrected file. The engine writes it back and stages it for commit.

### Fallback: line-level regex patch

For findings where AI correction was not available (file not found in repo, AI timeout),
the engine falls back to a line-level regex replacement using `suggested_fix` from the
rule metadata. Files already corrected by AI are never overwritten by the regex fallback.

---

## Database Schema

### Tables read (SecOps scanner output — read-only)

| Table | Key columns | Purpose |
|---|---|---|
| `secops_report` | `secops_scan_id`, `repo_url`, `branch`, `project_name` | Scan metadata and repo location |
| `secops_findings` | `secops_scan_id`, `file_path`, `line_number`, `rule_id`, `severity`, `message`, `language` | Per-finding scanner output |
| `secops_rule_metadata` | `rule_id`, `title`, `description`, `recommendation`, `examples`, `references` | Rule library — single source of truth |

### Table written (fix engine output)

**`secops_remediation`** — one row per finding, updated as the pipeline progresses:

| Column | Type | Description |
|---|---|---|
| `remediation_id` | UUID | Primary key |
| `secops_scan_id` | UUID | FK → `secops_report` |
| `finding_id` | BIGINT | FK → `secops_findings` |
| `rule_id` | VARCHAR | Rule that fired |
| `file_path` | VARCHAR | Relative path to the file |
| `line_number` | INTEGER | Line number of the finding |
| `language` | VARCHAR | Programming language |
| `severity` | VARCHAR | `critical` / `high` / `medium` / `low` |
| `match_layer` | VARCHAR | `direct` or `no_rule_metadata` |
| `fix_explanation` | TEXT | Human-readable description of the fix |
| `compliant_example` | TEXT | Safe code example from rule metadata |
| `fix_branch` | VARCHAR | `secops-fix/{scan_id[:8]}` |
| `status` | VARCHAR | `pending` → `applied` / `fix_generated` / `failed` / `skipped` |
| `created_at` | TIMESTAMPTZ | Row creation time |
| `updated_at` | TIMESTAMPTZ | Auto-updated on any row change |

### Useful queries

```sql
-- All remediations for a scan
SELECT file_path, line_number, rule_id, severity, status, fix_branch
FROM secops_remediation
WHERE secops_scan_id = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
ORDER BY severity, file_path, line_number;

-- Summary counts
SELECT status, COUNT(*) FROM secops_remediation
WHERE secops_scan_id = 'a1b2c3d4-...'
GROUP BY status;

-- Applied fixes (committed to branch)
SELECT file_path, line_number, rule_id, fix_explanation
FROM secops_remediation
WHERE secops_scan_id = 'a1b2c3d4-...'
  AND status = 'applied';

-- Findings the AI could not patch
SELECT file_path, line_number, rule_id, error_message
FROM secops_remediation
WHERE secops_scan_id = 'a1b2c3d4-...'
  AND status IN ('failed', 'skipped');
```

---

## Applying a Fix

After the fix branch is pushed, the developer should:

```bash
# 1. Fetch and review the fix branch
git fetch origin
git checkout secops-fix/a1b2c3d4
git diff main

# 2. Review every changed file — do not merge blindly
#    The AI preserves code style but human eyes catch context issues

# 3. Run your test suite against the fix branch
pytest tests/
npm test
# etc.

# 4. If satisfied, merge via PR
#    (or create a PR manually if the engine did not open one)

# 5. Verify in staging before production
```

> The fix branch name is `secops-fix/{first-8-chars-of-scan-id}`.
> Example: scan `a1b2c3d4-e5f6-...` → branch `secops-fix/a1b2c3d4`.

---

## Security Design

| Concern | Mitigation |
|---|---|
| Credential handling | `repo_token` accepted per-request; never logged, never stored in DB |
| Token injection | `_inject_token()` strips any existing credentials from URL before injecting fresh token |
| Token logging | All logged URLs pass through `_mask_token()` — replaces embedded token with `***` |
| Path traversal (read) | File path normalized with `os.path.realpath()` and checked to be inside repo root |
| Path traversal (write) | AI-corrected files validated with same `realpath` guard before writing |
| AI output | AI returns full file content — engine writes only to files that already exist in the repo |
| Input validation | `secops_scan_id` must match UUID regex; `repo_url` must start with `https://`; `source_branch` checked against `[a-zA-Z0-9._/\-]{1,100}` |
| No auto-merge | Fix branch is pushed; no merge, no deploy is triggered by this engine |
| Non-root container | Docker image runs as `secopsfix` (UID 1001) |

---

## Project Structure

```
secops_fix/
├── engine/
│   ├── api_server.py           Main FastAPI application
│   ├── Dockerfile              Production Docker image
│   ├── requirements.txt        Python dependencies
│   ├── routers/
│   │   ├── remediation.py      Core pipeline: fetch → AI → commit → push
│   │   ├── findings.py         Read-only view of scanner findings
│   │   └── health.py           Liveness + readiness probes
│   ├── core/
│   │   ├── ai_fixer.py         Mistral AI per-file fix generation
│   │   └── git_patcher.py      Clone, patch, commit, push fix branch
│   ├── db/
│   │   ├── db_config.py        Connection management
│   │   ├── fetcher.py          Read findings, scan report, rule metadata
│   │   ├── writer.py           Write remediation rows + status updates
│   │   └── schema.sql          secops_remediation DDL (run once)
│   └── models/
│       ├── finding.py          SecOpsFinding + ScanReport schemas
│       ├── fix_result.py       Per-finding fix outcome
│       └── remediation.py      API request/response schemas
├── deployment/
│   └── secops-fix-engine.yaml  Kubernetes Deployment + Service manifest
└── test_engine.py              End-to-end integration test
```
