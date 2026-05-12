# Vulnerability Agent Enrollment — Feature Plan
**Version:** 1.7  
**Author:** Ajay  
**Status:** Ready for Team Review  
**Date:** 2026-05-12

---

## 1. Problem Statement

Currently the vulnerability agent has a hardcoded `"ajay4141"` fallback for `vul_agent_id`. There is no formal enrollment process — any agent can submit scans to the engine with no identity verification. This means:

- No tenant/account isolation at the agent level
- No ability to revoke or audit individual agents
- Fake scan results can be submitted by anyone

---

## 2. Goal

Enforce a **provision → download → register → scan** lifecycle so that:
- Agent identity comes from the onboarding engine (already exists — `agent_registrations` table)
- Scan submissions are authenticated with a permanent secret key issued at register time
- The engine rejects scans from unknown or revoked agents
- User experience is completely frictionless — download a ZIP, run it, done
- **User never sees, copies, or types a token or key**

---

## 3. End-to-End Flow — Key Values

> Read this first. It shows every value, where it is born, and where it is reused
> across the full journey from account onboarding through to portal viewing results.

```
Legend
  [CREATE]  — value is born at this step
  [REUSE]   — value was created earlier; passed through unchanged
  [REMOVE]  — value is deleted from config after use (consumed)
  ════════  — database write
  ────────  — value flows between services
```

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PHASE 1 — ONBOARDING   (done once — admin adds cloud account to CSPM)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Admin onboards AWS/Azure/GCP account  →  Onboarding engine
                                              ╔══════════════════════════════╗
                                              ║  cloud_accounts              ║
                                              ║  [CREATE] tenant_id          ║
                                              ║  [CREATE] account_id         ║
                                              ║  [CREATE] customer_id        ║
                                              ║           account_type       ║
                                              ║           status = 'active'  ║
                                              ╚══════════════════════════════╝


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PHASE 2 — PROVISION   (admin clicks "Download Agent" in portal)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Portal ─── account_id ──► Onboarding: issue_agent_token(account_id)
                                              ╔══════════════════════════════════╗
                                              ║  agent_registrations             ║
                                              ║  [REUSE]  tenant_id              ║
                                              ║  [REUSE]  account_id             ║
                                              ║  [CREATE] agent_id  "agnt-3f8a" ║ ← stable identity
                                              ║  [CREATE] token_hash             ║ ← SHA256(raw_token)
                                              ║           status = 'pending'     ║
                                              ║           expires_at = +30 min   ║
                                              ╚══════════════════════════════════╝
                         ◄── { raw_token, agent_id } ──────────────────────────

  Portal builds ZIP  (raw_token + agent_id + binary never touch user screen)
                                              ┌──────────────────────────────────┐
                                              │  agent_config.json  (in ZIP)     │
                                              │  [REUSE]  tenant_id              │
                                              │  [REUSE]  agent_id  "agnt-3f8a" │
                                              │  [CREATE] registration_token     │ ← raw_token, 30-min
                                              │  [CREATE] binary_sha256          │ ← integrity hash
                                              │           engine_url             │
                                              └──────────────────────────────────┘

  Portal uploads ZIP to S3  →  generates 10-min pre-signed URL  →  browser downloads


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PHASE 3 — REGISTER   (agent runs for the first time on the server)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Agent reads agent_config.json
  Agent verifies binary: sha256(this file) == binary_sha256  →  safe to run

  Agent ─── { registration_token, agent_id } ──► Vul Engine: /register

  Vul Engine ─── SHA256(token) ──► Onboarding: validate-token
               ◄── { agent_id, account_id, tenant_id, expires_at } ──
                                              ╔══════════════════════════════════╗
                                              ║  vul_agent_sessions  (vul DB)    ║
                                              ║  [REUSE]  agent_id  "agnt-3f8a" ║
                                              ║  [REUSE]  account_id             ║
                                              ║  [REUSE]  tenant_id              ║
                                              ║  [CREATE] api_key_hash           ║ ← SHA256(agent_api_key)
                                              ║           status = 'active'      ║
                                              ║           hostname               ║
                                              ╚══════════════════════════════════╝
               ◄── { agent_api_key } ──────────────────────────────────────────

  Agent updates agent_config.json on disk:
                                              ┌──────────────────────────────────┐
                                              │  agent_config.json  (updated)    │
                                              │  [REUSE]  tenant_id              │
                                              │  [REUSE]  agent_id  "agnt-3f8a" │
                                              │  [CREATE] agent_api_key          │ ← permanent scan key
                                              │  [REMOVE] registration_token     │ ← consumed, deleted
                                              │  [REMOVE] binary_sha256          │ ← no longer needed
                                              └──────────────────────────────────┘


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PHASE 4 — SCAN   (every run from now on — no onboarding call needed)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Agent ─── { agent_id, agent_api_key, findings } ──► Vul Engine: /scan
                                                           │
                                                           │  local check (fast)
                                                           ▼
                                                       vul_agent_sessions
                                                       agent_id + api_key_hash
                                                       + status = 'active'  →  PASS
                                                       any mismatch         →  403
                                              ╔══════════════════════════════════════╗
                                              ║  scans                               ║
                                              ║  [REUSE] account_id                  ║
                                              ║  [REUSE] tenant_id                   ║
                                              ║  [REUSE] scan_run_id (orchestrator)  ║
                                              ╚══════════════════════════════════════╝
                                              ╔══════════════════════════════════════╗
                                              ║  scan_vulnerabilities                ║
                                              ║  [REUSE]  account_id                 ║
                                              ║  [REUSE]  tenant_id                  ║
                                              ║  [REUSE]  scan_run_id                ║
                                              ║  [CREATE] finding_id                 ║
                                              ║  [CREATE] CVE, severity, CVSS        ║
                                              ║  [CREATE] resource_uid               ║
                                              ╚══════════════════════════════════════╝


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PHASE 5 — PORTAL READS RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Portal query (via BFF → Vul Engine):
    WHERE account_id = "a-def..."   ← from onboarding (REUSE)
      AND tenant_id  = "t-abc..."   ← from auth context (REUSE)
    → returns scan_vulnerabilities rows for that account
```

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 VALUE LIFECYCLE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Value               Born in          Lives in                     Travels to
  ─────────────────── ──────────────── ──────────────────────────── ──────────────────────────
  tenant_id           onboarding       cloud_accounts               → all vul tables (denorm)
  account_id          onboarding       cloud_accounts               → agent_registrations
                                                                      → vul_agent_sessions
                                                                      → scans, scan_vulns (FK)
  agent_id            onboarding       agent_registrations          → agent_config.json
   "agnt-xxxxxxxx"                     vul_agent_sessions           → scan payload
  registration_token  onboarding       agent_config.json only       → /register call  (CONSUMED)
   (30-min window)                     (never stored plain in DB)
  binary_sha256       portal           agent_config.json only       → self-check at startup
                                                                      (REMOVED after register)
  agent_api_key       vul engine       agent_config.json only       → every scan header (Bearer)
   (permanent)                         (never stored plain in DB)
  api_key_hash        vul engine       vul_agent_sessions           scan gate check
  scan_run_id         orchestrator     scans, scan_vulnerabilities  cross-engine correlation
  CVE / findings      vul agent        scan_vulnerabilities         portal results view
```

---

## 4. Core Design Principle

**The onboarding engine already creates agent identity. We do not create a new one.**

When a tenant onboards a `vulnerability` (or `database` / `middleware`) account, they call the
onboarding engine's `issue_agent_token` endpoint. This creates a row in `agent_registrations`
with a short readable `agent_id` (format: `agnt-xxxxxxxx`) linked to `account_id`.

```
agent_registrations (already exists in onboarding DB):
  registration_id  UUID PK
  agent_id         VARCHAR  — e.g. "agnt-3f8a1b2c"  ← the agent's stable identity
  account_id       UUID FK → cloud_accounts.account_id
  tenant_id        VARCHAR
  token_hash       VARCHAR(64)  — SHA256 of registration token (30-min window)
  status           'pending' → 'connected' → 'disconnected'
  agent_hostname   VARCHAR
  agent_version    VARCHAR
  issued_at, activated_at, last_heartbeat_at, expires_at
```

The `agent_id` is NOT the `account_id` — it is a separate short identifier generated per
registration. Multiple re-provisions of the same account create new `agent_id` values.

---

## 5. Design Decisions (Agreed)

| Decision | Choice | Reason |
|----------|--------|--------|
| Where does agent identity come from? | `agent_registrations.agent_id` — created by onboarding's `issue_agent_token` | Already exists; purpose-built for agent identity |
| When is identity created? | Portal "Download Agent" click → calls onboarding `issue_agent_token` | Ties enrollment to tenant/account at download time |
| How does user activate the agent? | Pre-configured ZIP — `agent_id` + `registration_token` silently in `agent_config.json` | Zero friction; user never touches a token or key |
| Any manual token/key option? | **No** — one flow only | Keep it simple |
| Is there a register step? | **Yes** — needed to exchange `registration_token` → `agent_api_key` | Registration token is one-time/30-min; api_key is the permanent scan credential |
| Registration token window? | 30 minutes (existing `expires_at = NOW()+30min` in onboarding) | Short window for initial handshake only; permanent key issued on registration |
| Scan authentication? | `agent_id` + `agent_api_key` (issued at register, stored in vul engine DB) | api_key is a secret; agent_id alone is not |
| Where is scan auth stored? | `vul_agent_sessions` table in vul engine DB | Vul engine must not write to onboarding DB; local table enables fast scan gate |
| Does vul engine call onboarding on every scan? | **No** — only once at register time | Avoid coupling on hot scan path; vul_agent_sessions is the local authority |
| Binary integrity? | SHA256 hash embedded in `agent_config.json`; agent self-verifies at startup | Detects tampered binary before any network call |
| Binary hosting? | S3 bucket (managed by dev team) | Simple; portal fetches at download time |
| Download delivery? | Pre-signed S3 URL (10-min expiry) for per-provision ZIP | Portal assembles ZIP + config in memory, uploads to temp S3 path, returns time-limited URL |
| Multi-server / cloud fleet? | Same config deployed to all servers for the account | Cloud-native; no hostname binding; admin manages at account level |
| Revoke? | Set `vul_agent_sessions.status = 'revoked'` → entire fleet stops immediately | One click; api_key cryptographically enforced |

---

## 6. Complete User Journey

```
STEP 1 — Portal Admin clicks "Download Agent"
──────────────────────────────────────────────

  Portal UI: Admin selects onboarded vulnerability account + platform → clicks Download
       │
       ▼
  Portal BFF → calls onboarding engine:
               POST /api/v1/accounts/{account_id}/agent-token
               (existing endpoint: issue_agent_token)
       │
       ▼
  Onboarding engine:
  ① Validates account exists + account_type ∈ ('vulnerability', 'database', 'middleware')
  ② Generates: raw_token = uuid4()
  ③ Creates agent_registrations row:
       agent_id        = "agnt-" + uuid4()[:8]      ← stable readable identity
       token_hash      = SHA256(raw_token)
       status          = 'pending'
       expires_at      = NOW() + 30 minutes          ← short registration window
       account_id, tenant_id
  ④ Returns { raw_token, agent_id } to portal

  Portal backend:
  ① Receives { raw_token, agent_id }
  ② Fetches binary from S3 (permanent store):
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent        (Linux)
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent.exe    (Windows)
  ③ Computes binary SHA256 hash
  ④ Creates agent_config.json:
       {
         "agent_id":            "agnt-3f8a1b2c",   ← identity from onboarding
         "registration_token":  "uuid4-raw",        ← one-time, 30-min window
         "binary_sha256":       "abcdef...",        ← integrity check
         "engine_url":          "https://vul-engine.internal",
         "tenant_id":           "tenant-uuid"
       }
  ⑤ Zips binary + config in memory
  ⑥ Uploads ZIP to temp S3 path:
       s3://cspm-agent-binaries/downloads/{uuid}/vul-agent-{platform}.zip
       (S3 lifecycle: auto-delete after 24h)
  ⑦ Generates 10-min pre-signed GET URL
  ⑧ Returns { download_url, url_expires_at } to browser

  Portal UI shows:
  ┌──────────────────────────────────────────────────────┐
  │  Deploy Vulnerability Agent                          │
  │                                                      │
  │  Account:   [ aws-prod-account (123456789012) ▼ ]   │
  │  Platform:  [ Linux ]  [ Windows ]                   │
  │                                                      │
  │  [ ⬇ Download vul-agent-linux.zip ]  ← one click    │
  │                                                      │
  │  1. Unzip the file                                   │
  │  2. chmod +x vul-agent && ./vul-agent  (Linux)       │
  │     double-click vul-agent.exe         (Windows)     │
  │  3. Agent registers and starts scanning              │
  │                                                      │
  │  Download link valid for: 10 minutes                 │
  └──────────────────────────────────────────────────────┘


STEP 2 — User runs the agent on their server (first run only)
──────────────────────────────────────────────────────────────

  Agent startup — automatic, no user input:
  ① Reads agent_config.json
  ② Binary integrity check:
       actual_hash = sha256(this binary)
       if actual_hash != binary_sha256 → exit "Binary tampered. Re-download."
  ③ If agent_config has agent_id + agent_api_key → skip to STEP 3 (already registered)
  ④ Has registration_token → call vul engine to register:
       POST /api/v1/agents/register
       { registration_token, agent_id, hostname, resource_uid, platform, os_version, arch }
  ⑤ Vul engine register logic:
       a. Call onboarding API: GET /api/v1/agents/validate-token { token_hash=SHA256(token) }
          → confirms agent_id, account_id, tenant_id, token not expired
       b. Issues: agent_api_key = secrets.token_hex(32)
       c. Upserts vul_agent_sessions:
            INSERT (agent_id, account_id, tenant_id, api_key_hash, status='active', hostname)
       d. Returns { agent_api_key }
  ⑥ Agent saves to agent_config.json:
       {
         "agent_id":      "agnt-3f8a1b2c",   ← kept
         "agent_api_key": "hex-secret",       ← new, permanent scan credential
         "engine_url":    "...",
         "tenant_id":     "..."
       }
       (registration_token + binary_sha256 removed — no longer needed)
  ⑦ Prints: "Agent registered. Starting scan..."


STEP 3 — All subsequent scans
───────────────────────────────

  Agent: POST /api/v1/agents/scan
         Authorization: Bearer <agent_api_key>
         Body: { agent_id, tenant_id, hostname, resource_uid, findings... }
       │
       ▼
  Engine gate (local — no onboarding call):
    SELECT * FROM vul_agent_sessions
    WHERE agent_id      = $agent_id
      AND tenant_id     = $tenant_id
      AND api_key_hash  = SHA256($api_key)
      AND status        = 'active'
    → Not found → 403 "Invalid agent credentials"
    → Found → accept scan, UPDATE last_seen_at
```

---

## 7. Agent Lifecycle

```
[Portal: account onboarded as type='vulnerability']
        │
        │  issue_agent_token → agent_registrations row created
        ▼
     PENDING (30 min window)
        │
        │  agent runs → calls /register → api_key issued
        ▼
     ACTIVE (vul_agent_sessions status='active')
        │
        ├── sends scans (agent_id + api_key) ──► last_seen_at updated
        │
        ├── admin clicks Revoke ─────────────► REVOKED
        │     (vul_agent_sessions status='revoked'; all fleet scans rejected)
        │
        └── admin clicks Re-provision
              → portal calls issue_agent_token again
              → new agent_id + new registration_token issued
              → old vul_agent_sessions row stays revoked
              → new ZIP built + new api_key issued on first run
```

If registration token expires (30-min window missed), admin re-provisions — new download.

---

## 8. Why vul_agent_sessions (not reuse agent_registrations directly)

The scan validation gate runs on every scan — potentially hundreds of times per hour per agent.
It must be fast and must not depend on onboarding engine availability.

```
Option A: vul engine queries onboarding DB directly on every scan
  ✗ Cross-DB query on hot path
  ✗ Vul engine couples to onboarding DB schema
  ✗ Onboarding outage = no scans accepted

Option B: vul engine calls onboarding API on every scan
  ✗ HTTP call on hot scan path (latency)
  ✗ Onboarding outage = no scans accepted

Option C: vul_agent_sessions table in vul engine DB  ← CHOSEN
  ✓ Local lookup — fast
  ✓ Populated once at register time
  ✓ Onboarding outage does not affect scan acceptance
  ✓ Vul engine owns its own auth state
```

Onboarding is called **once** — at register time — to validate the registration token and
retrieve `agent_id + account_id + tenant_id`. After that, `vul_agent_sessions` is the
authority for scan authentication.

---

## 9. Binary Integrity — SHA256 Self-Check

```
Portal at download time:
  binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()
  → embed in agent_config.json

Agent at startup (before any network call):
  actual   = hashlib.sha256(open(sys.argv[0], 'rb').read()).hexdigest()
  expected = config["binary_sha256"]
  if actual != expected:
      exit("ERROR: Binary integrity check failed. Re-download from portal.")
```

---

## 10. Binary Distribution — S3

### S3 Bucket Layout

```
s3://cspm-agent-binaries/
├── vul-agent/                              ← permanent (dev team managed)
│   └── v1.0.0/
│       ├── vul-agent                       (Linux, ~50MB)
│       └── vul-agent.exe                   (Windows, ~50MB)
│
└── downloads/                              ← temporary per-provision ZIPs
    └── {uuid}/
        └── vul-agent-{platform}.zip
```

S3 lifecycle rule on `downloads/`: delete after 24 hours.

### Portal IAM permissions

```
s3:GetObject    on cspm-agent-binaries/vul-agent/*
s3:PutObject    on cspm-agent-binaries/downloads/*
s3:GeneratePresignedUrl
```

---

## 11. Required Changes by Layer

### 11.1 Onboarding Engine — No DB Changes

`agent_registrations` table already exists with the required columns.
`issue_agent_token` endpoint already exists.

**One optional addition** (not blocking v1):
Expose a token-validation endpoint for the vul engine to call at register time:

```
GET /api/v1/internal/agents/validate-token
Header: X-Token-Hash: <sha256>
Response: { agent_id, account_id, tenant_id, status, expires_at }

Alternatively: vul engine reads onboarding DB directly (same cluster, different schema).
Confirm with team which is preferred — API call vs direct DB read.
```

---

### 11.2 Vulnerability Engine — Database

> **Pre-migration discovery:** `scans.scan_id` is VARCHAR format `10052026_013`.
> Must be swapped for `scan_run_id UUID`. Same applies to `scan_vulnerabilities.scan_id`.
> Decision: **DROP both** (no production data exists).

**NEW table: `vul_agent_sessions`**

```sql
CREATE TABLE vul_agent_sessions (
  id              SERIAL PRIMARY KEY,
  agent_id        VARCHAR(20)  NOT NULL,          -- "agnt-xxxxxxxx" from onboarding
  account_id      UUID         NOT NULL,
  tenant_id       VARCHAR(255) NOT NULL,
  api_key_hash    VARCHAR(64)  NOT NULL,           -- SHA256(agent_api_key)
  status          VARCHAR(20)  NOT NULL DEFAULT 'active',  -- active / revoked
  hostname        VARCHAR(255),
  provisioned_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
  last_seen_at    TIMESTAMPTZ,

  UNIQUE (agent_id)
);

CREATE INDEX idx_vul_sessions_agent    ON vul_agent_sessions(agent_id);
CREATE INDEX idx_vul_sessions_account  ON vul_agent_sessions(account_id, tenant_id);
CREATE INDEX idx_vul_sessions_api_key  ON vul_agent_sessions(api_key_hash);
```

**Table: `scans`** — swap scan_id → scan_run_id

```sql
ALTER TABLE scans ADD COLUMN scan_run_id UUID;
ALTER TABLE scans ADD COLUMN tenant_id   UUID;
ALTER TABLE scans ADD COLUMN account_id  UUID;
ALTER TABLE scans DROP COLUMN scan_id;          -- clean break; no prod data
CREATE INDEX idx_scans_scan_run_id ON scans(scan_run_id);
```

**Table: `scan_vulnerabilities`** — same swap

```sql
ALTER TABLE scan_vulnerabilities ADD COLUMN scan_run_id  UUID;
ALTER TABLE scan_vulnerabilities ADD COLUMN tenant_id    UUID;
ALTER TABLE scan_vulnerabilities ADD COLUMN account_id   UUID;
ALTER TABLE scan_vulnerabilities ADD COLUMN resource_uid VARCHAR(255);
ALTER TABLE scan_vulnerabilities DROP COLUMN scan_id;   -- consistent with scans
CREATE INDEX idx_scan_vuln_scan_run_id ON scan_vulnerabilities(scan_run_id);
```

Both tables drop `scan_id` consistently — no legacy columns remain.

---

### 11.3 Vulnerability Engine — API

#### NEW: `POST /api/v1/agents/register`
Called by agent binary on first run only.

```
Request:  { registration_token, agent_id, hostname, resource_uid, platform, os_version, arch }
Response: { agent_api_key }

Logic:
① Call onboarding to validate token:
   GET /internal/agents/validate-token  { token_hash: SHA256(registration_token) }
   → returns: { agent_id, account_id, tenant_id, expires_at }
   → If not found or expired → 403 "Token invalid or expired"
   → If agent_id in response ≠ agent_id in request → 403 "Agent ID mismatch"

② Issue scan credential:
   agent_api_key = secrets.token_hex(32)

③ UPSERT vul_agent_sessions:
   INSERT (agent_id, account_id, tenant_id, api_key_hash=SHA256(key),
           status='active', hostname, provisioned_at=now())
   ON CONFLICT (agent_id) DO UPDATE SET
     api_key_hash=SHA256(key), status='active',
     hostname=$hostname, provisioned_at=now()

④ Return { agent_api_key }
   (plain key returned ONCE — agent must persist it in agent_config.json)
```

#### MODIFY: `POST /api/v1/agents/scan`
Replace current gate with local vul_agent_sessions lookup.

```
Request body:  { agent_id, tenant_id, hostname, resource_uid, findings... }
Header:        Authorization: Bearer <agent_api_key>

Gate:
  api_key = extract from Authorization header
  SELECT * FROM vul_agent_sessions
  WHERE agent_id     = $agent_id
    AND tenant_id    = $tenant_id
    AND api_key_hash = SHA256($api_key)
    AND status       = 'active'
  → Not found → 403 "Invalid agent credentials"
  → Found → accept scan
    UPDATE vul_agent_sessions SET last_seen_at = now()
    INSERT findings with scan_run_id, tenant_id, account_id, resource_uid
```

#### NEW: `POST /api/v1/agents/revoke`
Called by portal when admin clicks Revoke.

```
UPDATE vul_agent_sessions SET status = 'revoked'
WHERE agent_id = $1 AND tenant_id = $2
```

#### REMOVE: Hardcoded fallback in `vul_agent.py`

```python
# DELETE:
vul_agent_id = os.environ.get("VUL_AGENT_ID", "ajay4141")

# REPLACE WITH:
agent_id      = config.get("agent_id")
agent_api_key = config.get("agent_api_key")
if not agent_id or not agent_api_key:
    raise SystemExit("ERROR: Agent not configured. Re-download from portal.")
```

---

### 11.4 Portal Backend — Endpoint

#### MODIFY: Download provision flow

```
POST /api/vulnerability/agent/provision
Request:  { account_id, platform: "linux" | "windows" }

Logic:
1. Call onboarding: POST /api/v1/accounts/{account_id}/agent-token
   → receive { raw_token, agent_id }

2. Fetch binary from S3

3. binary_sha256 = sha256(binary_bytes)

4. Build agent_config.json:
   {
     "agent_id":           "agnt-3f8a1b2c",
     "registration_token": "<raw_token>",
     "binary_sha256":      "<hash>",
     "engine_url":         "<VUL_ENGINE_URL>",
     "tenant_id":          "<tenant_id>"
   }

5. ZIP in memory → upload to s3://cspm-agent-binaries/downloads/{uuid}/...

6. Generate 10-min pre-signed URL

7. Return { download_url, url_expires_at }
```

---

### 11.5 Portal UI — Changes

**Download Dialog:**

```
┌──────────────────────────────────────────────────────┐
│  Deploy Vulnerability Agent                          │
│                                                      │
│  Account:   [ aws-prod-account (123456789012) ▼ ]   │
│  Platform:  [ Linux ]  [ Windows ]                   │
│                                                      │
│  [ ⬇ Download vul-agent-linux.zip ]                  │
│                                                      │
│  1. Unzip   2. Run agent   3. Scans start auto       │
│                                                      │
│  Download link valid for: 10 minutes                 │
└──────────────────────────────────────────────────────┘
```

**Agent Management Table:**

| Agent ID | Account | Status | Last Seen | Provisioned | Actions |
|----------|---------|--------|-----------|-------------|---------|
| agnt-3f8a1b2c | aws-prod (123...) | ACTIVE | 2 hrs ago | 01 May 2026 | [Revoke] |
| agnt-7d2c9e01 | azure-dev | ACTIVE | 1 day ago | 15 Apr 2026 | [Revoke] |
| agnt-a1b2c3d4 | aws-staging | REVOKED | 10 days ago | — | [Re-provision] |

---

### 11.6 Agent Binary — `vul_agent.py` Changes

```python
def startup():
    config = load_config()

    # Step 1: Binary integrity check
    if config.get("binary_sha256"):
        actual = hashlib.sha256(open(sys.argv[0], 'rb').read()).hexdigest()
        if actual != config["binary_sha256"]:
            raise SystemExit("ERROR: Binary integrity check failed. Re-download.")

    # Step 2: Already registered
    if config.get("agent_id") and config.get("agent_api_key"):
        return config["agent_id"], config["agent_api_key"]

    # Step 3: First run — register with vul engine
    if config.get("registration_token") and config.get("agent_id"):
        response = call_register_endpoint(
            registration_token = config["registration_token"],
            agent_id           = config["agent_id"],
            hostname           = socket.gethostname(),
            resource_uid       = get_instance_id_from_imdsv2(),
            platform           = sys.platform,
            os_version         = platform.version(),
            arch               = platform.machine(),
        )
        config["agent_api_key"] = response["agent_api_key"]
        del config["registration_token"]
        del config["binary_sha256"]
        save_config(config)
        return config["agent_id"], config["agent_api_key"]

    raise SystemExit("ERROR: Agent not configured. Re-download from portal.")
```

---

## 12. Out of Scope for v1

| Feature | Deferred to |
|---------|-------------|
| Signed binaries / `.deb` / `.msi` installers | v2 |
| Agent auto-update mechanism | v2 |
| Agent heartbeat / health endpoint | v2 |
| Per-agent scan rate limiting | v2 |
| mTLS for agent ↔ engine communication | v2 |
| api_key rotation without re-provisioning | v2 |

---

## 13. Implementation Order

```
①  DB migration (vul engine)
     — CREATE vul_agent_sessions table
     — scans: DROP scan_id, ADD scan_run_id UUID
     — scan_vulnerabilities: DROP scan_id, ADD scan_run_id UUID + standard cols

②  Onboarding engine
     — Expose internal token-validation endpoint (or confirm direct DB access)
     — No schema changes needed

③  Vul Engine — POST /api/v1/agents/register (new)
     — Validate registration_token via onboarding
     — Issue agent_api_key, store hash in vul_agent_sessions

④  Vul Engine — MODIFY POST /api/v1/agents/scan
     — Replace old gate with vul_agent_sessions lookup

⑤  Vul Engine — POST /api/v1/agents/revoke (new)

⑥  Vul Agent (vul_agent.py)
     — Remove "ajay4141" fallback
     — Add integrity check + register flow

⑦  S3 bucket
     — Upload Linux + Windows binaries v1.0.0
     — Set lifecycle rule: delete downloads/* after 24h

⑧  Portal BFF
     — POST /api/vulnerability/agent/provision
       (call onboarding issue_agent_token → build ZIP → S3 upload → presigned URL)

⑨  Portal UI
     — Download dialog + Agent Management table

⑩  E2E test
     — Onboard vulnerability account → download ZIP → integrity-check
     → register → scan accepted → revoke → scan rejected → re-provision → scan accepted
```

---

## 14. Open Questions for Team

1. **Onboarding token validation**: Does vul engine call the onboarding API, or query onboarding DB directly? API call is cleaner (no cross-DB access); direct DB is faster. Confirm preferred approach.
2. **account_type gate**: Only `vulnerability`, `database`, `middleware` accounts can issue agent tokens (existing constraint). Is this correct for our use case?
3. **resource_uid**: Optional (NULL if not on AWS) — acceptable in scan payload?
4. **Re-provision behaviour**: New `agent_id` is issued on re-provision — old `agent_id` row stays revoked. Admin must redeploy config to all fleet servers. Acceptable?
5. **Revoke permission**: `tenant_admin` only, or `analyst` too?
6. **S3 bucket**: Create new `cspm-agent-binaries` or reuse existing bucket?
7. **Temp ZIP cleanup**: S3 lifecycle rule (delete after 24h) — sufficient?
8. ~~**scan_id history**~~ — **resolved**: drop both `scans.scan_id` and `scan_vulnerabilities.scan_id`. Clean break.

---

*Plan v1.7 — updated 2026-05-12 — added Section 3 end-to-end flow with value lifecycle.*  
*Shows every key value (tenant_id, account_id, agent_id, registration_token, api_key_hash, scan_run_id), exactly where each is created, reused, and removed across all 5 phases.*

*Plan v1.6 — updated 2026-05-12 — aligned with existing onboarding engine code.*  
*Key changes from v1.5: code inspection of onboarding engine revealed `agent_registrations` table and `issue_agent_token` endpoint already exist. Corrections: (1) `agent_id` is `agnt-xxxxxxxx` from `agent_registrations`, NOT `account_id`; (2) provision reuses onboarding's existing `issue_agent_token`; (3) register step is back — exchanges 30-min registration token for permanent `agent_api_key`; (4) `vul_agent_sessions` table replaces `vul_agent_credentials` — local to vul engine DB, populated once at register time, no onboarding call on scan path.*

*Plan v1.5 — identity from onboarding table.*  
*Plan v1.4 — scan_id → scan_run_id swap.*  
*Plan v1.3 — hybrid pre-signed URL delivery.*  
*Plan v1.2 — security hardening (token expiry, uuid4, api_key, binary SHA256).*
