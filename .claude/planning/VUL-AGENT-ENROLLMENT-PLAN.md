# Vulnerability Agent Enrollment — Feature Plan
**Version:** 1.1  
**Author:** Ajay  
**Status:** Ready for Team Review  
**Date:** 2026-05-11

---

## 1. Problem Statement

Currently the vulnerability agent has a hardcoded `"ajay4141"` fallback for `vul_agent_id`. There is no formal enrollment process — any agent can submit scans to the engine with no identity verification. This means:

- No way to know which server a scan came from
- No tenant/account isolation at the agent level
- No ability to revoke or audit individual agents

---

## 2. Goal

Enforce a **provision → download → register → scan** lifecycle so that:
- Every agent is pre-registered by the portal before a scan is accepted
- The engine rejects scans from unknown or revoked agents
- User experience is completely frictionless — download a zip, run it, done
- **User never sees, copies, or types a token**

---

## 3. Design Decisions (Agreed)

| Decision | Choice | Reason |
|----------|--------|--------|
| Who creates the agent identity? | Engine (on provision call) | Agent cannot self-register |
| When is identity created? | Portal "Download Agent" click | Ties agent to tenant/account at provisioning time |
| How does user activate the agent? | Pre-configured ZIP — token silently embedded in `agent_config.json` | Zero friction; user never touches a token |
| Any manual token option? | **No** — one flow only | Keep it simple; no `--token` flag, no curl one-liner |
| What if user downloads but runs later? | Token tied to billing `current_period_end` | Valid as long as subscription is active |
| What triggers token expiry? | Billing subscription end OR admin revoke | Auto cleanup on subscription lapse |
| Token storage? | SHA-256 hash only; plain token never stored in DB | Token shown nowhere after download; not recoverable |
| Scan gate? | Engine validates `vul_agent_id` status = `active` on every scan | 403 if unregistered or revoked |
| Binary hosting? | S3 bucket (managed by dev team) | Simple; portal fetches at download time |

---

## 4. Complete User Journey

```
STEP 1 — Portal Admin clicks "Download Agent"
──────────────────────────────────────────────

  Portal UI: Admin selects platform (Linux / Windows) → clicks Download
       │
       ▼
  Portal BFF → POST /api/v1/agents/provision  {tenant_id, account_id, platform}
       │
       ▼
  Vul Engine creates agents row:
  ┌────────────────────────────────────────────────────┐
  │ vul_agent_id      = NULL  ← not yet known          │
  │ status            = PENDING                        │
  │ token_hash        = SHA256(vlt-xxxx) ← row key     │
  │ token_expires_at  = billing.current_period_end     │
  │ tenant_id         = from request                   │
  │ account_id        = from request                   │
  │ hostname          = NULL  (filled on first run)    │
  │ platform          = NULL  (filled on first run)    │
  └────────────────────────────────────────────────────┘
       │
       ▼
  Portal backend:
  ① Receives { plain_token, expires_at } from engine
  ② Fetches binary from S3:
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent          (Linux)
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent.exe      (Windows)
  ③ Creates agent_config.json (token silently embedded):
       {
         "enrollment_token": "vlt-xxxx",   ← user never sees this
         "engine_url":       "https://vul-engine.internal",
         "tenant_id":        "tenant-uuid"
       }
  ④ Zips binary + config in memory
  ⑤ Streams ZIP as download response

  Portal UI shows:
  ┌──────────────────────────────────────────────────────┐
  │  Deploy Vulnerability Agent                          │
  │                                                      │
  │  Platform:  [ Linux ]  [ Windows ]                   │
  │                                                      │
  │  [ ⬇ Download vul-agent-linux.zip ]                  │
  │                                                      │
  │  Instructions:                                       │
  │  1. Unzip the downloaded file                        │
  │  2. Linux:   chmod +x vul-agent && ./vul-agent       │
  │     Windows: double-click vul-agent.exe              │
  │  3. Agent will register and start scanning           │
  │                                                      │
  │  Valid until: 15 Jun 2026 (your billing cycle)       │
  └──────────────────────────────────────────────────────┘


STEP 2 — User runs the agent on their server
─────────────────────────────────────────────

  Linux:   unzip vul-agent-linux.zip
           chmod +x vul-agent
           ./vul-agent

  Windows: unzip → double-click vul-agent.exe

  Agent startup (automatic, no user input needed):
  ① Reads agent_config.json → finds enrollment_token
  ② Collects server identity:
       hostname     = system hostname
       resource_uid = AWS IMDSv2 instance ID (if available, else NULL)
       platform     = linux / windows
       os_version   = OS version string
       arch         = amd64 / arm64
  ③ Calls: POST /api/v1/agents/register
           { token, hostname, resource_uid, platform, os_version, arch }
  ④ Engine:
       a. Finds PENDING row by token_hash = SHA256(token)
       b. Checks token_expires_at > now()
          If invalid → 403, agent prints error and exits
       c. Computes vul_agent_id:
            seed = "{tenant_id}:{account_id}:{resource_uid or hostname}"
            vul_agent_id = uuid5(NAMESPACE_DNS, seed)
            → same server always gets same ID
       d. UPDATE agents SET
            vul_agent_id     = computed_uuid,   ← now assigned
            status           = 'active',
            hostname         = $hostname,
            resource_uid     = $resource_uid,
            platform         = $platform,
            os_version       = $os_version,
            arch             = $arch,
            token_hash       = NULL,            ← consumed
            token_expires_at = NULL             ← consumed
  ⑤ Engine returns { vul_agent_id, tenant_id, engine_url }
  ⑥ Agent updates agent_config.json:
       {
         "vul_agent_id": "computed-uuid",   ← permanent identity
         "tenant_id":    "uuid",
         "engine_url":   "..."
       }
       (enrollment_token removed — no longer needed)
  ⑦ Prints: "Agent registered. Starting scan..."


STEP 3 — All subsequent scans
───────────────────────────────

  Agent: POST /api/v1/agents/scan { vul_agent_id, findings... }
       │
       ▼
  Engine gate:
    SELECT status FROM agents
    WHERE vul_agent_id = $1 AND tenant_id = $2

    status = 'active'  → accept scan, update last_seen_at
    anything else      → 403 "Agent not enrolled"
```

---

## 5. Agent Lifecycle States

```
[Admin clicks Download]
        │
        ▼
     PENDING ────── billing period ends ──────────────► EXPIRED  (automatic)
        │
        │  user runs binary, token validates
        ▼
     ACTIVE  ────── admin clicks Revoke ──────────────► REVOKED  (manual)
        │
        └── sends scans ──► last_seen_at updated every scan
```

---

## 6. Two-Key Design — How the Engine Relates Provision to Register

The agent row uses two different keys across its lifetime:

```
Stage      Row identified by     vul_agent_id    What it means
─────────  ────────────────────  ──────────────  ───────────────────────────────
PENDING    token_hash            NULL            Token is the only identity
ACTIVE     vul_agent_id          computed uuid   Permanent identity, token gone
```

**At register time the engine bridges the two:**

```
Agent sends token
      │
      ▼
Engine: SELECT * FROM agents WHERE token_hash = sha256(token)
      → finds the PENDING row (vul_agent_id is still NULL)
      │
      ▼
Engine computes permanent identity:
  seed         = "{tenant_id}:{account_id}:{resource_uid or hostname}"
  vul_agent_id = uuid5(NAMESPACE_DNS, seed)
      │
      ▼
Engine: UPDATE agents SET vul_agent_id = computed, status = 'active',
                          token_hash = NULL, token_expires_at = NULL
      │
      ▼
From now on all scans use vul_agent_id — token no longer exists
```

**Why uuid5 (deterministic) not uuid4 (random):**

| Property | uuid4 random | uuid5 from tenant+account+host |
|----------|-------------|-------------------------------|
| Same server re-installs agent | Gets a new ID — looks like a new agent | Gets same ID — engine recognises it |
| Different servers | Different IDs ✓ | Different IDs ✓ |
| Different tenants, same server | Same ID — collision! ✗ | Different IDs ✓ (tenant in seed) |
| Enumerable / guessable | No ✓ | No ✓ (uuid5 is not reversible) |

---

## 7. Token Expiry — Billing-Tied Logic

```
token_expires_at = org_subscriptions.current_period_end
```

| Scenario | Behaviour |
|----------|-----------|
| User downloads and runs same day | Works |
| User downloads, runs 2 weeks later | Works — still within billing period |
| Subscription renews monthly | New period_end; re-download not needed (agent already ACTIVE) |
| Subscription cancelled | PENDING tokens expire naturally; ACTIVE agents still scan until admin revokes |
| Admin wants to block an agent early | Manual Revoke from Agent Management UI |

---

## 7. Binary Distribution — S3

Dev team builds binaries once per release and uploads to S3. Portal fetches silently at download time. No user-facing GitHub links.

```
Dev team (one-time per release):
  pyinstaller --onefile vul_agent.py --name vul-agent         (Linux)
  pyinstaller --onefile vul_agent.py --name vul-agent.exe     (Windows)
  aws s3 cp dist/vul-agent     s3://cspm-agent-binaries/vul-agent/v1.0.0/
  aws s3 cp dist/vul-agent.exe s3://cspm-agent-binaries/vul-agent/v1.0.0/
        │
        ▼
Portal env vars:
  S3_VUL_AGENT_BUCKET  = cspm-agent-binaries
  VUL_AGENT_VERSION    = v1.0.0

To release a new agent version:
  → upload new binary to S3
  → update VUL_AGENT_VERSION env var in portal deployment
  → existing ACTIVE agents are unaffected (they keep running)
  → new downloads get the updated binary automatically
```

---

## 8. Required Changes by Layer

### 8.1 Vulnerability Engine — Database

**Table: `agents`** — ALTER to add enrollment columns

```sql
ALTER TABLE agents
  ADD COLUMN tenant_id         UUID,
  ADD COLUMN account_id        UUID,
  ADD COLUMN resource_uid      VARCHAR(255),
  ADD COLUMN token_hash        VARCHAR(64),     -- SHA256; NULL after activation
  ADD COLUMN token_expires_at  TIMESTAMPTZ,    -- billing period_end; NULL after activation
  ADD COLUMN status            VARCHAR(20)  NOT NULL DEFAULT 'pending',
  ADD COLUMN platform          VARCHAR(50),
  ADD COLUMN arch              VARCHAR(20),
  ADD COLUMN os_version        VARCHAR(100);

CREATE INDEX idx_agents_token_hash ON agents(token_hash)
  WHERE token_hash IS NOT NULL;
```

**Table: `scans`** — add cross-engine linking columns

```sql
ALTER TABLE scans
  ADD COLUMN scan_run_id  UUID,
  ADD COLUMN tenant_id    UUID,
  ADD COLUMN account_id   UUID;
```

**Table: `scan_vulnerabilities`** — add standard columns

```sql
ALTER TABLE scan_vulnerabilities
  ADD COLUMN scan_run_id   UUID,
  ADD COLUMN tenant_id     UUID,
  ADD COLUMN account_id    UUID,
  ADD COLUMN resource_uid  VARCHAR(255);
```

---

### 8.2 Vulnerability Engine — API

#### NEW: `POST /api/v1/agents/provision`
Called by portal backend only (not the agent).

```
Request:  { tenant_id, account_id, platform }
Response: { plain_token, expires_at }

Logic:
- Generate plain_token  = "vlt-" + secrets.token_hex(24)
- token_hash            = sha256(plain_token)
- token_expires_at      = query billing DB for org_subscriptions.current_period_end
- INSERT agents row:
    vul_agent_id = NULL    ← not assigned yet
    token_hash   = hash
    status       = 'pending'
    tenant_id, account_id, platform = from request
- Return plain_token     ← only time it ever leaves the system
  Note: vul_agent_id is NOT returned — it doesn't exist yet
```

#### MODIFY: `POST /api/v1/agents/register`
Called by agent binary on first run only.

```
Request:  { token, hostname, resource_uid, platform, os_version, arch }
Response: { vul_agent_id, tenant_id, engine_url }

Logic:
- hash = sha256(token)
- SELECT * FROM agents WHERE token_hash = hash AND status = 'pending'
- If not found:                 403 "Token invalid"
- If token_expires_at < now(): 403 "Token expired — download a new package from portal"
- If valid:
    seed         = f"{tenant_id}:{account_id}:{resource_uid or hostname}"
    vul_agent_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))

    UPDATE agents SET
      vul_agent_id     = vul_agent_id,    ← assigned here for the first time
      status           = 'active',
      hostname         = $hostname,
      resource_uid     = $resource_uid,
      platform         = $platform,
      os_version       = $os_version,
      arch             = $arch,
      token_hash       = NULL,            ← consumed
      token_expires_at = NULL             ← consumed
- Return { vul_agent_id, tenant_id, engine_url }
```

#### MODIFY: `POST /api/v1/agents/scan`
Add enrollment gate at the top.

```
Added logic:
- SELECT status FROM agents
  WHERE vul_agent_id = $vul_agent_id AND tenant_id = $tenant_id
- Not found or status != 'active' → 403 "Agent not enrolled"
- Continue with existing scan logic
```

#### REMOVE: Hardcoded fallback in `vul_agent.py:137`

```python
# DELETE:
vul_agent_id = os.environ.get("VUL_AGENT_ID", "ajay4141")

# REPLACE WITH:
vul_agent_id = config.get("vul_agent_id")
if not vul_agent_id:
    raise SystemExit("ERROR: Agent not registered. Download a fresh package from the portal.")
```

---

### 8.3 Portal Backend — New Endpoint

#### NEW: `POST /api/vulnerability/agent/provision`

```
Request:  { tenant_id, account_id, platform: "linux" | "windows" }

Logic:
1. Call vul engine POST /api/v1/agents/provision
   → receive { plain_token, expires_at }
   Note: vul_agent_id does not exist yet at this stage

2. Fetch binary from S3:
   s3://{S3_VUL_AGENT_BUCKET}/vul-agent/{VUL_AGENT_VERSION}/vul-agent{.exe}

3. Build agent_config.json in memory:
   {
     "enrollment_token": "<plain_token>",
     "engine_url":       "<VUL_ENGINE_URL>",
     "tenant_id":        "<tenant_id>"
   }

4. Create ZIP in memory:
   vul-agent-linux.zip
     ├── vul-agent          ← binary from S3
     └── agent_config.json  ← token pre-embedded

5. Stream ZIP as response:
   Content-Type:        application/zip
   Content-Disposition: attachment; filename="vul-agent-linux.zip"
```

---

### 8.4 Portal UI — Changes

**Download Dialog** (triggered by "Download Agent" button):

```
┌──────────────────────────────────────────────────────┐
│  Deploy Vulnerability Agent                          │
│                                                      │
│  Platform:  [ Linux ]  [ Windows ]                   │
│                                                      │
│  [ ⬇ Download vul-agent-linux.zip ]                  │
│                                                      │
│  How to install:                                     │
│  1. Unzip the downloaded file                        │
│  2. Linux:   chmod +x vul-agent && ./vul-agent       │
│     Windows: double-click vul-agent.exe              │
│  3. Agent registers and starts scanning automatically│
│                                                      │
│  Package valid until: 15 Jun 2026 (billing cycle)    │
└──────────────────────────────────────────────────────┘
```

**Agent Management Table** (new section under Vulnerabilities menu):

| Agent Name | Status | Last Seen | Since | Actions |
|------------|--------|-----------|-------|---------|
| prod-server-1 | ACTIVE | 2 hrs ago | 01 May 2026 | [Revoke] |
| staging-vm | PENDING | Never | Expires 15 Jun 2026 | [Revoke] |
| old-agent | REVOKED | 10 days ago | — | — |

---

### 8.5 Agent Binary — `vul_agent.py` Changes

```python
def startup():
    config = load_config()   # reads agent_config.json

    if config.get("vul_agent_id"):
        # Already registered — proceed directly to scanning
        return config["vul_agent_id"]

    if config.get("enrollment_token"):
        # First run — register silently, engine computes vul_agent_id
        print("Registering agent with engine...")
        response = call_register_endpoint(
            token        = config["enrollment_token"],
            hostname     = socket.gethostname(),
            resource_uid = get_instance_id_from_imdsv2(),  # None if not AWS
            platform     = sys.platform,
            os_version   = platform.version(),
            arch         = platform.machine(),
        )
        # vul_agent_id computed by engine: uuid5(tenant+account+hostname)
        config["vul_agent_id"] = response["vul_agent_id"]
        config["tenant_id"]    = response["tenant_id"]
        del config["enrollment_token"]   # consumed, remove
        save_config(config)
        print(f"Agent registered: {config['vul_agent_id']}")
        return config["vul_agent_id"]

    # No token, no ID — package is stale or missing
    raise SystemExit(
        "ERROR: Agent not registered.\n"
        "Download a fresh package from the portal and run again."
    )

# No --token flag. No manual input. No fallback.
```

---

## 9. Out of Scope for v1

| Feature | Deferred to |
|---------|-------------|
| Signed binaries / `.deb` / `.msi` installers | v2 |
| Agent auto-update mechanism | v2 |
| Agent heartbeat / health endpoint | v2 |
| Per-agent scan rate limiting | v2 |

---

## 10. Implementation Order

```
①  DB migration  — agents, scans, scan_vulnerabilities tables
②  Vul Engine    — POST /api/v1/agents/provision  (new)
③  Vul Engine    — POST /api/v1/agents/register   (modify)
④  Vul Engine    — POST /api/v1/agents/scan       (add gate)
⑤  Vul Agent     — remove "ajay4141" fallback; add enrollment startup flow
⑥  S3 bucket     — upload Linux + Windows binaries for v1.0.0
⑦  Portal BFF    — POST /api/vulnerability/agent/provision (zip builder)
⑧  Portal UI     — Download dialog + Agent Management table
⑨  E2E test      — provision → download → register → scan → revoke
```

---

## 11. Open Questions for Team

1. **IMDSv2 / resource_uid**: Mandatory on AWS, optional elsewhere — confirm this is acceptable.
2. **Multi-agent per server**: Can the same server register more than once? (e.g., dev + prod tenants)
3. **Revoke permission**: `tenant_admin` only, or `analyst` too?
4. **S3 bucket**: Create new `cspm-agent-binaries` bucket or reuse an existing one?

---

*Plan authored from design sessions on 2026-05-11. All design decisions agreed before this document was written.*
