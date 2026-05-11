# Vulnerability Agent Enrollment — Feature Plan
**Version:** 1.2  
**Author:** Ajay  
**Status:** Ready for Team Review  
**Date:** 2026-05-11

---

## 1. Problem Statement

Currently the vulnerability agent has a hardcoded `"ajay4141"` fallback for `vul_agent_id`. There is no formal enrollment process — any agent can submit scans to the engine with no identity verification. This means:

- No way to know which server a scan came from
- No tenant/account isolation at the agent level
- No ability to revoke or audit individual agents
- Fake scan results can be submitted by anyone

---

## 2. Goal

Enforce a **provision → download → register → scan** lifecycle so that:
- Every agent is pre-registered by the portal before a scan is accepted
- The engine rejects scans from unknown or revoked agents
- Scan submissions are authenticated — not just identity-checked
- User experience is completely frictionless — download a zip, run it, done
- **User never sees, copies, or types a token**

---

## 3. Design Decisions (Agreed)

| Decision | Choice | Reason |
|----------|--------|--------|
| Who creates the agent identity? | Engine at register time | Agent cannot self-register; identity needs server info |
| When is enrollment triggered? | Portal "Download Agent" click | Ties enrollment to tenant/account at provisioning time |
| How does user activate the agent? | Pre-configured ZIP — token silently in `agent_config.json` | Zero friction; user never touches a token |
| Any manual token option? | **No** — one flow only | Keep it simple; no `--token` flag |
| Token expiry window? | `min(30 days, billing.current_period_end)` | 30-day cap limits exposure if ZIP leaks; billing floor ensures active subscribers aren't blocked |
| What triggers token expiry? | 30-day cap OR billing subscription end OR admin revoke | Automatic cleanup in all scenarios |
| Token storage? | SHA-256 hash only; plain token never stored in DB | Token never recoverable after download |
| vul_agent_id assignment? | `uuid4()` — random, assigned by engine at register time | Stable identity not tied to mutable hostname |
| Scan authentication? | `vul_agent_id` + `agent_api_key` (issued at register) | vul_agent_id alone is not a secret; api_key prevents fake submissions |
| Binary integrity? | SHA256 hash embedded in `agent_config.json`; agent self-verifies | Detects tampered binary before it runs |
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
  ┌────────────────────────────────────────────────────────┐
  │ vul_agent_id      = NULL  ← assigned at register time  │
  │ agent_api_key_hash= NULL  ← assigned at register time  │
  │ status            = PENDING                            │
  │ token_hash        = SHA256(vlt-xxxx)  ← row key        │
  │ token_expires_at  = min(now+30d, billing.period_end)   │
  │ tenant_id         = from request                       │
  │ account_id        = from request                       │
  │ hostname          = NULL  (filled at register)         │
  │ platform          = NULL  (filled at register)         │
  └────────────────────────────────────────────────────────┘
       │
       ▼
  Portal backend:
  ① Receives { plain_token, expires_at } from engine
  ② Fetches binary from S3:
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent        (Linux)
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent.exe    (Windows)
  ③ Computes binary SHA256 hash
  ④ Creates agent_config.json (token + hash silently embedded):
       {
         "enrollment_token":  "vlt-xxxx",       ← user never sees this
         "binary_sha256":     "abcdef1234...",   ← integrity check
         "engine_url":        "https://vul-engine.internal",
         "tenant_id":         "tenant-uuid"
       }
  ⑤ Zips binary + config in memory
  ⑥ Streams ZIP as download response

  Portal UI shows:
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
  │  Package valid until: 10 Jun 2026 (30 days)          │
  └──────────────────────────────────────────────────────┘


STEP 2 — User runs the agent on their server (first run only)
──────────────────────────────────────────────────────────────

  Linux:   unzip vul-agent-linux.zip && chmod +x vul-agent && ./vul-agent
  Windows: unzip → double-click vul-agent.exe

  Agent startup — automatic, no user input:
  ① Reads agent_config.json → finds enrollment_token + binary_sha256
  ② Self-integrity check:
       actual_hash = sha256(this binary file)
       if actual_hash != binary_sha256 → exit "Binary tampered. Re-download."
  ③ Collects server identity:
       hostname     = system hostname
       resource_uid = AWS IMDSv2 instance ID (if available, else NULL)
       platform     = linux / windows
       os_version, arch
  ④ Calls: POST /api/v1/agents/register
           { token, hostname, resource_uid, platform, os_version, arch }
  ⑤ Engine:
       a. Finds PENDING row: WHERE token_hash = SHA256(token)
       b. Checks token_expires_at > now()
          If invalid → 403, agent prints clear error and exits
       c. Assigns permanent identity:
            vul_agent_id   = uuid4()               ← random, stable
            agent_api_key  = secrets.token_hex(32) ← for scan auth
       d. UPDATE agents SET
            vul_agent_id        = uuid4,
            agent_api_key_hash  = SHA256(agent_api_key),
            status              = 'active',
            hostname            = $hostname,
            resource_uid        = $resource_uid,
            platform, os_version, arch,
            token_hash          = NULL,   ← consumed
            token_expires_at    = NULL    ← consumed
  ⑥ Engine returns { vul_agent_id, agent_api_key, tenant_id, engine_url }
  ⑦ Agent saves to agent_config.json:
       {
         "vul_agent_id":  "uuid",            ← permanent identity
         "agent_api_key": "hex-secret",      ← for scan authentication
         "tenant_id":     "uuid",
         "engine_url":    "..."
       }
       (enrollment_token + binary_sha256 removed — no longer needed)
  ⑧ Prints: "Agent registered successfully. Starting scan..."


STEP 3 — All subsequent scans
───────────────────────────────

  Agent: POST /api/v1/agents/scan
         { vul_agent_id, agent_api_key, findings... }
         Authorization: Bearer <agent_api_key>
       │
       ▼
  Engine gate (two checks):
    ① Identity:  SELECT * FROM agents
                 WHERE vul_agent_id = $1 AND tenant_id = $2 AND status = 'active'
                 → Not found or not active → 403 "Agent not enrolled"

    ② Auth:      WHERE agent_api_key_hash = SHA256($agent_api_key)
                 → Hash mismatch → 403 "Invalid agent credentials"

    Both pass → accept scan, update last_seen_at
```

---

## 5. Agent Lifecycle States

```
[Admin clicks Download]
        │
        ▼
     PENDING ─── 30 days OR billing end ──────────────► EXPIRED  (automatic)
        │
        │  user runs binary → integrity check → register
        ▼
     ACTIVE  ─── admin clicks Revoke ────────────────► REVOKED  (manual)
        │
        └── sends scans (vul_agent_id + api_key) ──► last_seen_at updated
```

---

## 6. Two-Key Design — Provision → Register Bridge

The agent row uses different keys at different stages:

```
Stage      Row identified by       vul_agent_id   agent_api_key
─────────  ──────────────────────  ─────────────  ──────────────────────
PENDING    token_hash              NULL           NULL
ACTIVE     vul_agent_id            uuid4          issued + stored hashed
```

**How the bridge works:**
```
Agent sends enrollment_token (one-time)
      │
      ▼
Engine finds PENDING row via token_hash
      │
      ▼
Engine assigns:
  vul_agent_id  = uuid4()               ← random, never changes
  agent_api_key = secrets.token_hex(32) ← secret for scan auth
      │
      ▼
token_hash cleared → vul_agent_id + api_key_hash take over permanently
```

**Why uuid4 (random) not uuid5 (derived from hostname):**

| Property | uuid5 from hostname | uuid4 random |
|----------|--------------------|--------------| 
| Server renamed / VM replaced | New hostname = new ID — breaks history ✗ | Same ID always ✓ |
| Re-install on same server | Gets same ID ✓ | Gets new ID — provision again |
| Identity tied to mutable data | Yes — fragile ✗ | No — stable ✓ |
| Cross-tenant collision risk | Needs tenant in seed | None ✓ |

Re-installation gets a new uuid4 — intentional. Admin provisions a new download, old agent row is revoked. Clean slate.

---

## 7. Token Expiry — 30-Day Cap + Billing Floor

```
token_expires_at = MIN(now() + INTERVAL '30 days',
                       org_subscriptions.current_period_end)
```

| Scenario | Behaviour |
|----------|-----------|
| User downloads and runs same day | Works |
| User downloads, runs 2 weeks later | Works — within 30-day window |
| User downloads, forgets for 35 days | Token expired — download again from portal |
| Subscription cancelled mid-window | Token expires at period_end (earlier than 30 days) |
| Admin wants to block early | Manual Revoke from Agent Management UI |
| ZIP leaks or is shared | Max 30-day exposure window — not a year |

---

## 8. Binary Integrity — SHA256 Self-Check

Dev team publishes SHA256 of each binary alongside the S3 upload:

```
Portal at download time:
  binary_bytes = fetch from S3
  binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()
  → embed in agent_config.json

Agent at startup (before any network call):
  actual = hashlib.sha256(open(sys.argv[0], 'rb').read()).hexdigest()
  expected = config["binary_sha256"]
  if actual != expected:
      exit("ERROR: Binary integrity check failed. Re-download from portal.")
```

This catches: S3 compromise, download corruption, manual tampering.

---

## 9. Binary Distribution — S3

```
Dev team (one-time per release):
  pyinstaller --onefile vul_agent.py --name vul-agent        (Linux)
  pyinstaller --onefile vul_agent.py --name vul-agent.exe    (Windows)
  aws s3 cp dist/vul-agent     s3://cspm-agent-binaries/vul-agent/v1.0.0/
  aws s3 cp dist/vul-agent.exe s3://cspm-agent-binaries/vul-agent/v1.0.0/

Portal env vars:
  S3_VUL_AGENT_BUCKET  = cspm-agent-binaries
  VUL_AGENT_VERSION    = v1.0.0

To release a new agent version:
  → upload new binary to S3
  → update VUL_AGENT_VERSION env var in portal deployment
  → existing ACTIVE agents keep running (unaffected)
  → new downloads automatically get the updated binary
```

---

## 10. Required Changes by Layer

### 10.1 Vulnerability Engine — Database

**Table: `agents`** — ALTER to add enrollment + auth columns

```sql
ALTER TABLE agents
  ADD COLUMN tenant_id            UUID,
  ADD COLUMN account_id           UUID,
  ADD COLUMN resource_uid         VARCHAR(255),
  ADD COLUMN token_hash           VARCHAR(64),    -- SHA256; NULL after activation
  ADD COLUMN token_expires_at     TIMESTAMPTZ,   -- cleared after activation
  ADD COLUMN agent_api_key_hash   VARCHAR(64),    -- SHA256; permanent scan credential
  ADD COLUMN status               VARCHAR(20)  NOT NULL DEFAULT 'pending',
  ADD COLUMN platform             VARCHAR(50),
  ADD COLUMN arch                 VARCHAR(20),
  ADD COLUMN os_version           VARCHAR(100);

CREATE INDEX idx_agents_token_hash   ON agents(token_hash)        WHERE token_hash IS NOT NULL;
CREATE INDEX idx_agents_api_key_hash ON agents(agent_api_key_hash) WHERE agent_api_key_hash IS NOT NULL;
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

### 10.2 Vulnerability Engine — API

#### NEW: `POST /api/v1/agents/provision`
Called by portal backend only.

```
Request:  { tenant_id, account_id, platform }
Response: { plain_token, expires_at }

Logic:
- plain_token       = "vlt-" + secrets.token_hex(24)
- token_hash        = sha256(plain_token)
- token_expires_at  = MIN(now + 30 days, billing.current_period_end)
- INSERT agents row: vul_agent_id=NULL, agent_api_key_hash=NULL,
                     token_hash, token_expires_at, status='pending',
                     tenant_id, account_id, platform
- Return plain_token  ← only time it ever leaves the system
```

#### MODIFY: `POST /api/v1/agents/register`
Called by agent binary on first run only.

```
Request:  { token, hostname, resource_uid, platform, os_version, arch }
Response: { vul_agent_id, agent_api_key, tenant_id, engine_url }

Logic:
- hash = sha256(token)
- SELECT * FROM agents WHERE token_hash = hash AND status = 'pending'
- If not found:                 403 "Token invalid"
- If token_expires_at < now(): 403 "Token expired — re-download from portal"
- If valid:
    vul_agent_id  = str(uuid.uuid4())
    agent_api_key = secrets.token_hex(32)

    UPDATE agents SET
      vul_agent_id       = vul_agent_id,
      agent_api_key_hash = sha256(agent_api_key),
      status             = 'active',
      hostname, resource_uid, platform, os_version, arch,
      token_hash         = NULL,   ← consumed
      token_expires_at   = NULL    ← consumed
- Return { vul_agent_id, agent_api_key, tenant_id, engine_url }
  Note: agent_api_key returned in plain once — agent must store it
```

#### MODIFY: `POST /api/v1/agents/scan`
Replace single-check gate with two-factor gate.

```
Request must include: { vul_agent_id, findings... }
Header:               Authorization: Bearer <agent_api_key>

Gate logic:
- api_key = extract from Authorization header
- SELECT * FROM agents
  WHERE vul_agent_id       = $vul_agent_id
    AND tenant_id          = $tenant_id
    AND status             = 'active'
    AND agent_api_key_hash = sha256($api_key)
- Any mismatch → 403 "Invalid agent credentials"
- Pass → accept scan, UPDATE agents SET last_seen_at = now()
```

#### REMOVE: Hardcoded fallback in `vul_agent.py:137`

```python
# DELETE:
vul_agent_id = os.environ.get("VUL_AGENT_ID", "ajay4141")

# REPLACE WITH:
vul_agent_id  = config.get("vul_agent_id")
agent_api_key = config.get("agent_api_key")
if not vul_agent_id or not agent_api_key:
    raise SystemExit("ERROR: Agent not registered. Re-download from portal.")
```

---

### 10.3 Portal Backend — New Endpoint

#### NEW: `POST /api/vulnerability/agent/provision`

```
Request:  { tenant_id, account_id, platform: "linux" | "windows" }

Logic:
1. Call vul engine POST /api/v1/agents/provision
   → receive { plain_token, expires_at }

2. Fetch binary from S3:
   s3://{S3_VUL_AGENT_BUCKET}/vul-agent/{VUL_AGENT_VERSION}/vul-agent{.exe}

3. Compute binary integrity hash:
   binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()

4. Build agent_config.json:
   {
     "enrollment_token": "<plain_token>",
     "binary_sha256":    "<hash>",
     "engine_url":       "<VUL_ENGINE_URL>",
     "tenant_id":        "<tenant_id>"
   }

5. Create ZIP in memory → stream as download response
   Content-Disposition: attachment; filename="vul-agent-{platform}.zip"
```

---

### 10.4 Portal UI — Changes

**Download Dialog:**

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
│  Package valid until: 10 Jun 2026 (30 days)          │
└──────────────────────────────────────────────────────┘
```

**Agent Management Table:**

| Agent Name | Status | Last Seen | Since | Actions |
|------------|--------|-----------|-------|---------|
| prod-server-1 | ACTIVE | 2 hrs ago | 01 May 2026 | [Revoke] |
| staging-vm | PENDING | Never | Expires 10 Jun 2026 | [Revoke] |
| old-agent | REVOKED | 10 days ago | — | — |

---

### 10.5 Agent Binary — `vul_agent.py` Changes

```python
def startup():
    config = load_config()   # reads agent_config.json

    # Step 1: Always verify binary integrity first
    if config.get("binary_sha256"):
        actual = hashlib.sha256(open(sys.argv[0], 'rb').read()).hexdigest()
        if actual != config["binary_sha256"]:
            raise SystemExit("ERROR: Binary integrity check failed. Re-download from portal.")

    # Step 2: Already registered — just scan
    if config.get("vul_agent_id") and config.get("agent_api_key"):
        return config["vul_agent_id"], config["agent_api_key"]

    # Step 3: First run — register with engine
    if config.get("enrollment_token"):
        print("Registering agent with engine...")
        response = call_register_endpoint(
            token        = config["enrollment_token"],
            hostname     = socket.gethostname(),
            resource_uid = get_instance_id_from_imdsv2(),  # None if not AWS
            platform     = sys.platform,
            os_version   = platform.version(),
            arch         = platform.machine(),
        )
        config["vul_agent_id"]  = response["vul_agent_id"]
        config["agent_api_key"] = response["agent_api_key"]
        config["tenant_id"]     = response["tenant_id"]
        del config["enrollment_token"]  # consumed
        del config["binary_sha256"]     # no longer needed post-registration
        save_config(config)
        print(f"Agent registered: {config['vul_agent_id']}")
        return config["vul_agent_id"], config["agent_api_key"]

    raise SystemExit("ERROR: Agent not registered. Re-download from portal.")

def run_scan(vul_agent_id, agent_api_key):
    # All scan requests include both identity + auth credential
    headers = {"Authorization": f"Bearer {agent_api_key}"}
    payload = {"vul_agent_id": vul_agent_id, "findings": [...]}
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

---

## 12. Implementation Order

```
①  DB migration    — agents (+ api_key_hash col), scans, scan_vulnerabilities
②  Vul Engine      — POST /api/v1/agents/provision  (new)
③  Vul Engine      — POST /api/v1/agents/register   (assign uuid4 + api_key)
④  Vul Engine      — POST /api/v1/agents/scan       (two-factor gate)
⑤  Vul Agent       — remove "ajay4141"; add integrity check + registration flow
⑥  S3 bucket       — upload Linux + Windows binaries for v1.0.0
⑦  Portal BFF      — POST /api/vulnerability/agent/provision (zip builder + sha256)
⑧  Portal UI       — Download dialog + Agent Management table
⑨  E2E test        — provision → download → integrity-check → register → scan → revoke
```

---

## 13. Open Questions for Team

1. **resource_uid**: Mandatory on AWS, optional elsewhere — acceptable?
2. **Multi-agent per server**: Same server in two tenants = two provisions, two rows — confirm this is the intent.
3. **Revoke permission**: `tenant_admin` only, or `analyst` too?
4. **S3 bucket**: Create new `cspm-agent-binaries` or reuse existing one?
5. **api_key loss**: If user loses `agent_config.json`, the `agent_api_key` is unrecoverable (hashed in DB). Recovery path = revoke + re-provision. Confirm this is acceptable.

---

*Plan v1.2 — updated 2026-05-11 after security review.*  
*Key changes from v1.1: token expiry capped at 30 days, vul_agent_id changed to uuid4, scan auth requires agent_api_key, binary SHA256 self-check added.*
