# Vulnerability Agent Enrollment — Feature Plan
**Version:** 1.5  
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

Enforce a **provision → download → scan** lifecycle so that:
- Agent identity is sourced from the onboarding table (already exists when account is onboarded)
- Scan submissions are authenticated with a secret key — not just identity-checked
- The engine rejects scans from unknown or revoked agents
- User experience is completely frictionless — download a zip, run it, done
- **User never sees, copies, or types a token or key**

---

## 3. Core Design Principle

**The onboarding table is the identity source. We do not create a new agent identity.**

When a tenant onboards a cloud account, the onboarding engine already creates an `account_id`. That `account_id` IS the agent identity. The vulnerability agent is scoped to an account — not to an individual server.

```
Onboarding table (already exists):
  account_id  UUID  ← this becomes the agent's identity
  tenant_id   UUID
  status      active / inactive
  provider    aws / azure / gcp / ...
```

One agent config per account. All servers in that account use the same config.
Individual server identity (hostname, resource_uid) is captured per scan finding for audit — not used as a gate.

---

## 4. Design Decisions (Agreed)

| Decision | Choice | Reason |
|----------|--------|--------|
| Where does agent identity come from? | Onboarding table — `account_id` already exists | No new identity to create; account is the natural scoping unit |
| When is the agent credential issued? | Portal "Download Agent" click | Ties credential to tenant/account at download time |
| How does user activate the agent? | Pre-configured ZIP — `account_id` + `agent_api_key` silently in `agent_config.json` | Zero friction; user never touches a key |
| Any manual token/key option? | **No** — one flow only | Keep it simple |
| Is there a register step? | **No** — agent scans directly after download | Identity comes from onboarding; no separate registration needed |
| Scan authentication? | `account_id` (from onboarding) + `agent_api_key` (issued at download) | account_id alone is not a secret; api_key prevents fake submissions |
| What does engine validate against? | Onboarding table (account active?) + `vul_agent_credentials` (api_key hash match?) | Two checks — identity + auth |
| Binary integrity? | SHA256 hash embedded in `agent_config.json`; agent self-verifies at startup | Detects tampered binary before any network call |
| Binary hosting? | S3 bucket (managed by dev team) | Simple; portal fetches at download time |
| Download delivery? | Pre-signed S3 URL (10-min expiry) for per-provision ZIP | Portal assembles ZIP + config in memory, uploads to temp S3 path, returns time-limited URL — browser downloads from S3 directly |
| Multi-server / cloud fleet? | Same config deployed to all servers in the account | Cloud-native; no hostname binding; admin manages at account level |
| Revoke? | Set `vul_agent_credentials.status = 'revoked'` → entire account fleet stops immediately | One click; cryptographically enforced via api_key |

---

## 5. Complete User Journey

```
STEP 1 — Portal Admin clicks "Download Agent"
──────────────────────────────────────────────

  Portal UI: Admin selects account + platform (Linux / Windows) → clicks Download
       │
       ▼
  Portal BFF → POST /api/vulnerability/agent/provision
               { tenant_id, account_id, platform }
       │
       ▼
  Portal backend:
  ① Validates account_id exists in onboarding table AND status = 'active'
     If not → 400 "Account not onboarded or inactive"

  ② Generates scan credential:
       agent_api_key = secrets.token_hex(32)   ← 256-bit secret, issued once

  ③ Upserts vul_agent_credentials:
     INSERT INTO vul_agent_credentials
       (tenant_id, account_id, api_key_hash, status, provisioned_at)
     VALUES
       ($tenant_id, $account_id, SHA256($agent_api_key), 'active', now())
     ON CONFLICT (tenant_id, account_id)
       DO UPDATE SET api_key_hash = SHA256($agent_api_key),
                     status = 'active',
                     provisioned_at = now()
     (re-downloading replaces the old credential — previous ZIP stops working)

  ④ Fetches binary from S3 (permanent store):
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent        (Linux)
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent.exe    (Windows)

  ⑤ Computes binary SHA256 hash

  ⑥ Creates agent_config.json:
       {
         "account_id":    "<account_id>",     ← identity from onboarding
         "agent_api_key": "<hex-secret>",     ← scan auth credential
         "binary_sha256": "<sha256>",         ← integrity check
         "engine_url":    "https://vul-engine.internal",
         "tenant_id":     "<tenant_id>"
       }

  ⑦ Zips binary + config in memory
  ⑧ Uploads ZIP to temporary S3 path:
       s3://cspm-agent-binaries/downloads/{uuid}/vul-agent-{platform}.zip
       (S3 lifecycle rule: auto-delete after 24 hours)
  ⑨ Generates 10-min pre-signed GET URL for that ZIP
  ⑩ Returns JSON to browser: { download_url, url_expires_at }

  Portal UI shows:
  ┌──────────────────────────────────────────────────────┐
  │  Deploy Vulnerability Agent                          │
  │                                                      │
  │  Account:   [ aws-prod-account (123456789012) ]      │
  │  Platform:  [ Linux ]  [ Windows ]                   │
  │                                                      │
  │  [ ⬇ Download vul-agent-linux.zip ]  ← one click    │
  │                                                      │
  │  How to install:                                     │
  │  1. Unzip the downloaded file                        │
  │  2. Linux:   chmod +x vul-agent && ./vul-agent       │
  │     Windows: double-click vul-agent.exe              │
  │  3. Agent starts scanning automatically              │
  │                                                      │
  │  Download link valid for: 10 minutes                 │
  └──────────────────────────────────────────────────────┘


STEP 2 — User runs the agent on their server
──────────────────────────────────────────────

  Linux:   unzip vul-agent-linux.zip && chmod +x vul-agent && ./vul-agent
  Windows: unzip → double-click vul-agent.exe

  Agent startup — automatic, no user input:
  ① Reads agent_config.json
  ② Self-integrity check:
       actual_hash = sha256(this binary file)
       if actual_hash != binary_sha256 → exit "Binary tampered. Re-download."
  ③ Validates config has account_id + agent_api_key
     If missing → exit "Agent not configured. Re-download from portal."
  ④ Collects server identity for scan payload:
       hostname     = system hostname
       resource_uid = AWS IMDSv2 instance ID (if available, else NULL)
       platform     = linux / windows
       os_version, arch
  ⑤ Runs scan → submits findings


STEP 3 — All scans (first run and every subsequent run)
──────────────────────────────────────────────────────────

  Agent: POST /api/v1/agents/scan
         Authorization: Bearer <agent_api_key>
         Body: { account_id, tenant_id, hostname, resource_uid, findings... }
       │
       ▼
  Engine gate — two checks in sequence:

    ① Identity + active status:
         SELECT status FROM onboarding_accounts
         WHERE account_id = $account_id AND tenant_id = $tenant_id
         → Not found or status != 'active' → 403 "Account not active"

    ② Scan authentication:
         SELECT status FROM vul_agent_credentials
         WHERE account_id  = $account_id
           AND tenant_id   = $tenant_id
           AND api_key_hash = SHA256($api_key)
           AND status      = 'active'
         → Not found → 403 "Invalid agent credentials"

    Both pass → accept scan, UPDATE vul_agent_credentials SET last_seen_at = now()
```

---

## 6. Agent Lifecycle

```
[Account onboarded in platform]
        │
        │  identity exists in onboarding table
        ▼
[Admin clicks Download Agent]
        │
        │  agent_api_key generated, hash stored in vul_agent_credentials
        ▼
     ACTIVE ──── sends scans (account_id + api_key) ──► last_seen_at updated
        │
        ├── admin clicks Revoke ──────────────────────► REVOKED
        │     (api_key_hash stays in DB, status = 'revoked')
        │     (all servers in fleet stop being accepted immediately)
        │
        └── admin clicks Re-provision (Download again)
              → new api_key issued → old ZIP stops working
              → status back to ACTIVE
```

No PENDING state. No token expiry. Identity validation is delegated entirely to the onboarding table.

---

## 7. Why No Register Step

Previous designs had a `register` endpoint for the agent to call on first run. It is not needed because:

| What register was doing | What replaces it |
|-------------------------|-----------------|
| Create agent identity (uuid4) | Identity already exists: `account_id` from onboarding |
| Issue `agent_api_key` | Issued at download time; embedded in ZIP |
| Capture hostname | Captured in scan payload on every scan |
| Set status = 'active' | Credential row is 'active' from the moment it's provisioned |

The agent goes directly from download → scan. No intermediate call.

---

## 8. Binary Integrity — SHA256 Self-Check

```
Portal at download time:
  binary_bytes  = fetch from S3
  binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()
  → embed in agent_config.json

Agent at startup (before any network call):
  actual   = hashlib.sha256(open(sys.argv[0], 'rb').read()).hexdigest()
  expected = config["binary_sha256"]
  if actual != expected:
      exit("ERROR: Binary integrity check failed. Re-download from portal.")
```

Catches: S3 compromise, download corruption, manual tampering.

---

## 9. Binary Distribution — S3

### S3 Bucket Layout

```
s3://cspm-agent-binaries/
├── vul-agent/                              ← permanent binaries (dev team managed)
│   └── v1.0.0/
│       ├── vul-agent                       (Linux binary, ~50MB)
│       └── vul-agent.exe                   (Windows binary, ~50MB)
│
└── downloads/                              ← temporary per-provision ZIPs
    └── {uuid}/
        └── vul-agent-{platform}.zip        (binary + agent_config.json)
```

S3 lifecycle rule on `downloads/` prefix: delete objects older than 24 hours.

### Dev Team Release Flow

```
pyinstaller --onefile vul_agent.py --name vul-agent        (Linux)
pyinstaller --onefile vul_agent.py --name vul-agent.exe    (Windows)
aws s3 cp dist/vul-agent     s3://cspm-agent-binaries/vul-agent/v1.0.0/
aws s3 cp dist/vul-agent.exe s3://cspm-agent-binaries/vul-agent/v1.0.0/
```

### Portal env vars

```
S3_VUL_AGENT_BUCKET  = cspm-agent-binaries
VUL_AGENT_VERSION    = v1.0.0
```

### Required IAM permissions for portal service account

```
s3:GetObject    on arn:aws:s3:::cspm-agent-binaries/vul-agent/*
s3:PutObject    on arn:aws:s3:::cspm-agent-binaries/downloads/*
s3:GeneratePresignedUrl
```

---

## 10. Required Changes by Layer

### 10.1 Vulnerability Engine — Database

> **Pre-migration discovery:** The existing `scans` table has `scan_id VARCHAR`
> format `10052026_013` (DDMMYYYY + sequence). This must be swapped for `scan_run_id UUID`
> (the cross-engine correlation ID from the pipeline orchestrator).

**NEW table: `vul_agent_credentials`**

```sql
CREATE TABLE vul_agent_credentials (
  id              SERIAL PRIMARY KEY,
  tenant_id       UUID        NOT NULL,
  account_id      UUID        NOT NULL,
  api_key_hash    VARCHAR(64) NOT NULL,       -- SHA256 of agent_api_key
  status          VARCHAR(20) NOT NULL DEFAULT 'active',  -- active / revoked
  provisioned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at    TIMESTAMPTZ,

  UNIQUE (tenant_id, account_id)              -- one credential per account
);

CREATE INDEX idx_vul_creds_account ON vul_agent_credentials(tenant_id, account_id);
CREATE INDEX idx_vul_creds_key     ON vul_agent_credentials(api_key_hash);
```

No `agents` table. Identity validation goes to the onboarding table. Only credential
(api_key_hash) and status live here.

**Table: `scans`** — swap scan_id for scan_run_id

```sql
ALTER TABLE scans ADD COLUMN scan_run_id UUID;
ALTER TABLE scans ADD COLUMN tenant_id   UUID;
ALTER TABLE scans ADD COLUMN account_id  UUID;

-- Drop old string-format column.
-- Values like "10052026_013" are vul-engine-internal only; no other engine references
-- them and no production scans exist yet. Clean break chosen over rename.
ALTER TABLE scans DROP COLUMN scan_id;

CREATE INDEX idx_scans_scan_run_id ON scans(scan_run_id);
```

**Table: `scan_vulnerabilities`** — swap scan_id + add standard columns

> Same pattern as `scans`: `scan_id` is expected to be a VARCHAR referencing
> `scans.scan_id`. Both must be swapped together so the FK relationship stays consistent.

```sql
-- Step 1: add the correct UUID column
ALTER TABLE scan_vulnerabilities ADD COLUMN scan_run_id UUID;

-- Step 2: drop the old string FK (consistent with scans.scan_id — drop, not rename)
ALTER TABLE scan_vulnerabilities DROP COLUMN scan_id;

-- Step 3: add remaining standard columns
ALTER TABLE scan_vulnerabilities
  ADD COLUMN tenant_id    UUID,
  ADD COLUMN account_id   UUID,
  ADD COLUMN resource_uid VARCHAR(255);

CREATE INDEX idx_scan_vuln_scan_run_id ON scan_vulnerabilities(scan_run_id);
```

> Both tables drop `scan_id` consistently — no legacy columns remain.

---

### 10.2 Vulnerability Engine — API

#### NEW: `POST /api/v1/agents/provision`
Called by portal backend only (internal, not exposed to agents).

```
Request:  { tenant_id, account_id, platform }
Response: { agent_api_key }   ← plain key, returned once, never stored plain

Logic:
- Validate account_id in onboarding table, status = 'active'
- api_key   = secrets.token_hex(32)
- key_hash  = sha256(api_key)
- UPSERT vul_agent_credentials:
    ON CONFLICT (tenant_id, account_id)
    DO UPDATE SET api_key_hash = key_hash, status = 'active', provisioned_at = now()
- Return { agent_api_key: api_key }
```

#### REMOVE: `POST /api/v1/agents/register`
No longer needed. Identity is from onboarding; credential is issued at provision.

#### MODIFY: `POST /api/v1/agents/scan`
Two-check gate against onboarding + vul_agent_credentials.

```
Request body:  { account_id, tenant_id, hostname, resource_uid, findings... }
Header:        Authorization: Bearer <agent_api_key>

Gate logic:
① SELECT status FROM onboarding_accounts
  WHERE account_id = $account_id AND tenant_id = $tenant_id
  → not found or not 'active' → 403 "Account not active"

② api_key = extract from Authorization header
   SELECT id FROM vul_agent_credentials
   WHERE account_id  = $account_id
     AND tenant_id   = $tenant_id
     AND api_key_hash = sha256($api_key)
     AND status      = 'active'
   → not found → 403 "Invalid agent credentials"

Both pass → accept scan
  UPDATE vul_agent_credentials SET last_seen_at = now()
  INSERT into scans / scan_vulnerabilities with scan_run_id, tenant_id, account_id, hostname, resource_uid
```

#### NEW: `POST /api/v1/agents/revoke`
Called by portal when admin clicks Revoke.

```
Request:  { tenant_id, account_id }
Logic:    UPDATE vul_agent_credentials SET status = 'revoked'
          WHERE tenant_id = $1 AND account_id = $2
```

#### REMOVE: Hardcoded fallback in `vul_agent.py`

```python
# DELETE:
vul_agent_id = os.environ.get("VUL_AGENT_ID", "ajay4141")

# REPLACE WITH:
account_id    = config.get("account_id")
agent_api_key = config.get("agent_api_key")
if not account_id or not agent_api_key:
    raise SystemExit("ERROR: Agent not configured. Re-download from portal.")
```

---

### 10.3 Portal Backend — Endpoint

#### NEW: `POST /api/vulnerability/agent/provision`

```
Request:  { tenant_id, account_id, platform: "linux" | "windows" }
Response: { download_url, url_expires_at }

Logic:
1. Call vul engine POST /api/v1/agents/provision
   → receive { agent_api_key }

2. Fetch binary from S3 (permanent store):
   s3://{S3_VUL_AGENT_BUCKET}/vul-agent/{VUL_AGENT_VERSION}/vul-agent{.exe}

3. Compute binary integrity hash:
   binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()

4. Build agent_config.json:
   {
     "account_id":    "<account_id>",
     "agent_api_key": "<plain_api_key>",
     "binary_sha256": "<hash>",
     "engine_url":    "<VUL_ENGINE_URL>",
     "tenant_id":     "<tenant_id>"
   }

5. Create ZIP in memory

6. Upload ZIP to temp S3 path:
   s3://{S3_VUL_AGENT_BUCKET}/downloads/{uuid}/vul-agent-{platform}.zip

7. Generate 10-min pre-signed URL:
   presigned_url = s3.generate_presigned_url("get_object", ExpiresIn=600)

8. Return { download_url: presigned_url, url_expires_at: <iso8601> }
```

---

### 10.4 Portal UI — Changes

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
│  How to install:                                     │
│  1. Unzip the downloaded file                        │
│  2. Linux:   chmod +x vul-agent && ./vul-agent       │
│     Windows: double-click vul-agent.exe              │
│  3. Agent starts scanning automatically              │
│                                                      │
│  Download link valid for: 10 minutes                 │
└──────────────────────────────────────────────────────┘
```

**Agent Management Table:**

| Account | Status | Last Seen | Provisioned | Actions |
|---------|--------|-----------|-------------|---------|
| aws-prod (123456789012) | ACTIVE | 2 hrs ago | 01 May 2026 | [Revoke] [Re-provision] |
| azure-dev | ACTIVE | 1 day ago | 15 Apr 2026 | [Revoke] [Re-provision] |
| aws-staging | REVOKED | 10 days ago | — | [Re-provision] |

---

### 10.5 Agent Binary — `vul_agent.py` Changes

```python
def startup():
    config = load_config()   # reads agent_config.json

    # Step 1: Verify binary integrity before any network call
    if config.get("binary_sha256"):
        actual = hashlib.sha256(open(sys.argv[0], 'rb').read()).hexdigest()
        if actual != config["binary_sha256"]:
            raise SystemExit("ERROR: Binary integrity check failed. Re-download from portal.")

    # Step 2: Validate config has required fields
    account_id    = config.get("account_id")
    agent_api_key = config.get("agent_api_key")
    if not account_id or not agent_api_key:
        raise SystemExit("ERROR: Agent not configured. Re-download from portal.")

    # Step 3: Collect server identity for scan payload
    server_info = {
        "hostname":     socket.gethostname(),
        "resource_uid": get_instance_id_from_imdsv2(),  # None if not AWS
        "platform":     sys.platform,
        "os_version":   platform.version(),
        "arch":         platform.machine(),
    }

    return account_id, agent_api_key, server_info

def run_scan(account_id, agent_api_key, server_info):
    headers = {"Authorization": f"Bearer {agent_api_key}"}
    payload = {
        "account_id":   account_id,
        "tenant_id":    config["tenant_id"],
        "findings":     [...],
        **server_info   # hostname, resource_uid, etc.
    }
    post("/api/v1/agents/scan", json=payload, headers=headers)
```

---

## 11. Out of Scope for v1

| Feature | Deferred to |
|---------|-------------|
| Signed binaries / `.deb` / `.msi` installers | v2 |
| Agent auto-update mechanism | v2 |
| Agent heartbeat / health endpoint | v2 |
| Per-agent scan rate limiting | v2 |
| mTLS for agent ↔ engine communication | v2 |
| api_key rotation without re-provisioning | v2 |
| Per-server revocation (today: per-account) | v2 |

---

## 12. Implementation Order

```
①  DB migration    — CREATE vul_agent_credentials table
                      scans: swap scan_id (VARCHAR) → scan_run_id (UUID)  ⚠ not backfillable
                      scan_vulnerabilities: same swap — scan_id → scan_run_id + add standard cols
                      Both tables: drop/rename decision must match — confirm before running

②  Vul Engine      — POST /api/v1/agents/provision
                      (validate onboarding, generate api_key, upsert vul_agent_credentials)

③  Vul Engine      — MODIFY POST /api/v1/agents/scan
                      (two-check gate: onboarding active + api_key_hash match)

④  Vul Engine      — POST /api/v1/agents/revoke

⑤  Vul Engine      — REMOVE /api/v1/agents/register (no longer needed)

⑥  Vul Agent       — remove "ajay4141"; add integrity check; read account_id + api_key from config

⑦  S3 bucket       — create cspm-agent-binaries; upload Linux + Windows binaries v1.0.0
                      set lifecycle rule: delete downloads/* after 24h

⑧  Portal BFF      — POST /api/vulnerability/agent/provision
                      (onboarding lookup → api_key → ZIP → S3 upload → presigned URL)

⑨  Portal UI       — Download dialog (account selector + platform) + Agent Management table

⑩  E2E test        — onboard account → download ZIP → integrity-check → scan accepted
                      → revoke → scan rejected → re-provision → scan accepted again
```

---

## 13. Open Questions for Team

1. **Onboarding table name**: What is the exact table/column name for `account_id` in the onboarding engine DB? Plan assumes `onboarding_accounts.account_id` — confirm.
2. **Cross-DB query**: Vul engine scan gate needs to query the onboarding table. Are these in the same DB or different DBs? If different — vul engine calls the onboarding engine API instead of direct SQL.
3. **resource_uid**: Mandatory on AWS, optional elsewhere — acceptable in scan payload?
4. **Re-provision behaviour**: Re-downloading issues a new api_key — previous ZIP stops working. Admin must redeploy config to all fleet servers. Is this acceptable, or should old key stay valid for a grace period?
5. **Revoke permission**: `tenant_admin` only, or `analyst` too?
6. **S3 bucket**: Create new `cspm-agent-binaries` or reuse existing one?
7. **Temp ZIP cleanup**: S3 lifecycle rule (delete after 24h) — confirm this is sufficient vs event-driven cleanup.
8. ~~**scan_id history**~~ — **resolved**: drop both `scans.scan_id` and `scan_vulnerabilities.scan_id`. No production data exists (engine was in dev state); clean break chosen.

---

*Plan v1.5 — updated 2026-05-12 — agent identity sourced from onboarding table.*  
*Key changes from v1.4: removed agent_id generation entirely — identity is `account_id` from the onboarding table. Removed register step and enrollment token. `vul_agent_credentials` table replaces the `agents` table (stores only api_key_hash + status, keyed by tenant_id + account_id). Agent goes directly from download → scan. agent_config.json contains account_id + agent_api_key. Engine validates against two tables: onboarding (active?) + vul_agent_credentials (api_key match?).*

*Plan v1.4 — updated 2026-05-12 — scan_id → scan_run_id swap documented.*

*Plan v1.3 — updated 2026-05-12 — hybrid pre-signed URL delivery.*

*Plan v1.2 — updated 2026-05-11 after security review.*
