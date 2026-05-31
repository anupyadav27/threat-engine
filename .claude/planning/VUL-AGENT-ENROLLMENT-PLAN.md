# Vulnerability Agent Enrollment -- Feature Plan
**Version:** 1.11  
**Author:** Ajay  
**Status:** Ready for Team Review  
**Date:** 2026-05-12

---

## 1. Problem Statement

Currently the vulnerability agent has a hardcoded `"ajay4141"` fallback for `vul_agent_id`. There is no formal enrollment process -- any agent can submit scans to the engine with no identity verification. This means:

- No tenant/account isolation at the agent level
- No ability to revoke or audit individual agents
- Fake scan results can be submitted by anyone

---

## 2. Goal

Enforce a **provision -> download -> register -> scan** lifecycle so that:
- Agent identity comes from the onboarding engine (already exists -- `agent_registrations` table)
- Scan submissions are authenticated with a permanent secret key issued at register time
- The engine rejects scans from unknown or revoked agents
- User experience is completely frictionless -- download a ZIP, run it, done
- **User never sees, copies, or types a token or key**

---

## 3. Actors in This Flow

Three distinct humans touch this feature. "Admin" is never used alone in this document --
every step names the specific actor below.

```
+---------------------+------------------------------+-----------------------------------------+
| Actor               | Portal Role / Permission      | What they do in this flow               |
+---------------------+------------------------------+-----------------------------------------+
| CSPM Admin          | tenant_admin                  | Logs into CSPM portal.                  |
|                     | cloud_accounts:write          | Creates the vulnerability account.      |
|                     |                              | Clicks "Download Agent" -> gets ZIP.     |
|                     |                              | Sends ZIP to Server Admin.              |
|                     |                              | Monitors agent status in portal.        |
|                     |                              | Revokes or re-provisions agents.        |
+---------------------+------------------------------+-----------------------------------------+
| Server Admin        | None (no portal login)        | Receives the ZIP from CSPM Admin.       |
| (IT / DevOps /      |                              | Deploys to one or many servers.         |
|  Infrastructure)    |                              | Unzips, runs binary. Done.              |
|                     |                              | No token to manage, no portal access.   |
+---------------------+------------------------------+-----------------------------------------+
| Analyst / Viewer    | analyst / viewer              | Views scan results in portal only.      |
|                     | cloud_accounts:read           | Zero role in enrollment or provisioning.|
+---------------------+------------------------------+-----------------------------------------+
```

> **Handoff point:** The CSPM Admin downloads the ZIP from the portal and hands it to the
> Server Admin via any channel (Slack, email, shared drive, Ansible/Chef). The ZIP is
> self-contained -- Server Admin needs no portal access, no credentials, no instructions
> beyond "unzip and run."

---

## 4. End-to-End Flow -- Block Diagram

```
  KEY:  + value CREATED   ~ value REUSED from earlier   - value REMOVED (consumed)
        +==+ database write    +--+ file / payload    [  ] service / actor
```

```
+-------------------------------------------------------------------------+
|  1. ONBOARDING   (CSPM Admin adds cloud account -- done once)                 |
|                                                                         |
|  [Admin] --onboard AWS/Azure/GCP---> [Onboarding Engine]                |
|                                            |                            |
|                                     +======v============+              |
|                                     |  cloud_accounts    |              |
|                                     |  + tenant_id       |              |
|                                     |  + account_id      |              |
|                                     |  + account_type    |              |
|                                     +===================+              |
+-------------------------------------------------------------------------+
                              | tenant_id + account_id
                              v
+-------------------------------------------------------------------------+
|  2. PROVISION   (CSPM Admin clicks "Download Agent")                         |
|                                                                         |
|  [Portal] -issue_agent_token(account_id)---> [Onboarding Engine]        |
|                                                      |                  |
|                                      +===============v==============+  |
|                                      |  agent_registrations          |  |
|                                      |  ~ tenant_id  ~ account_id   |  |
|                                      |  + agent_id  "agnt-3f8a1b"  |  |
|                                      |  + token_hash  SHA256(token) |  |
|                                      |    status=pending  ttl=30min |  |
|                                      +==============================+  |
|           <--- { raw_token, agent_id } --------------------------        |
|                                                                         |
|  [Portal] --fetch binary---> [S3]  compute binary_sha256                 |
|                                                                         |
|           +-- agent_config.json ------------------------+              |
|           |   ~ tenant_id      ~ agent_id "agnt-3f8a1b" |              |
|           |   + registration_token  (30-min, one-time)  |              |
|           |   + binary_sha256  (integrity check)         |--->[S3 temp]|
|           +---------------------------------------------+   10-min    |
|                                               pre-signed URL ---> [Browser downloads ZIP] |
+-------------------------------------------------------------------------+
                              | ZIP on server
                              v
+-------------------------------------------------------------------------+
|  3. REGISTER   (agent first run on server)                              |
|                                                                         |
|  [Agent]  sha256(binary) == binary_sha256 ?  [x] integrity OK             |
|     |                                                                   |
|     +--{ reg_token, agent_id, hostname }---> [Vul Engine /register]     |
|                                                      |                  |
|                           --SHA256(token)---> [Onboarding validate]     |
|                           <--- { agent_id, account_id, tenant_id } --   |
|                                                      |                  |
|                                      +===============v==============+  |
|                                      |  vul_agent_sessions  (vul DB) |  |
|                                      |  ~ agent_id  ~ account_id    |  |
|                                      |  ~ tenant_id                 |  |
|                                      |  + api_key_hash  SHA256(key) |  |
|                                      |    status=active             |  |
|                                      +==============================+  |
|     <--- { agent_api_key } ------------------------------------------   |
|                                                                         |
|           +-- agent_config.json (updated on disk) ------------+        |
|           |   ~ tenant_id      ~ agent_id                      |        |
|           |   + agent_api_key  (permanent scan credential)     |        |
|           |   - registration_token  (consumed, deleted)        |        |
|           |   - binary_sha256  (no longer needed)              |        |
|           +----------------------------------------------------+        |
+-------------------------------------------------------------------------+
                              | agent_id + api_key on disk
                              v
+-------------------------------------------------------------------------+
|  4. SCAN   (every run -- no onboarding call on this path)                |
|                                                                         |
|  [Agent] --{ agent_id + Bearer api_key + findings }---> [Vul Engine]   |
|                                                              |          |
|                              local gate (fast, no network)   |          |
|                              vul_agent_sessions:             |          |
|                              agent_id + api_key_hash         |          |
|                              + status=active  ->  PASS -------+          |
|                                                                         |
|                              +=======================================+  |
|                              |  scans                                |  |
|                              |  ~ account_id  ~ tenant_id            |  |
|                              |  ~ scan_run_id  (from orchestrator)   |  |
|                              +=======================================+  |
|                              |  scan_vulnerabilities                 |  |
|                              |  ~ account_id  ~ tenant_id            |  |
|                              |  ~ scan_run_id                        |  |
|                              |  + finding_id  + CVE  + severity      |  |
|                              +=======================================+  |
+-------------------------------------------------------------------------+
                              | findings stored (account_id is the FK)
                              v
+-------------------------------------------------------------------------+
|  5. PORTAL READS RESULTS                                                |
|                                                                         |
|  [Portal/BFF] --{ account_id, tenant_id }---> [Vul Engine]              |
|               <--- scan_vulnerabilities rows (CVE, severity, resource)   |
|                                                                         |
|  account_id and tenant_id are NEVER created by vul engine --             |
|  they flow from onboarding through every phase unchanged.               |
+-------------------------------------------------------------------------+
```

---

## 5. Core Design Principle

**The onboarding engine already creates agent identity. We do not create a new one.**

When a tenant onboards a `vulnerability` (or `database` / `middleware`) account, they call the
onboarding engine's `issue_agent_token` endpoint. This creates a row in `agent_registrations`
with a short readable `agent_id` (format: `agnt-xxxxxxxx`) linked to `account_id`.

```
agent_registrations (already exists in onboarding DB):
  registration_id  UUID PK
  agent_id         VARCHAR  -- e.g. "agnt-3f8a1b2c"  <- the agent's stable identity
  account_id       UUID FK -> cloud_accounts.account_id
  tenant_id        VARCHAR
  token_hash       VARCHAR(64)  -- SHA256 of registration token (30-min window)
  status           'pending' -> 'connected' -> 'disconnected'
  agent_hostname   VARCHAR
  agent_version    VARCHAR
  issued_at, activated_at, last_heartbeat_at, expires_at
```

The `agent_id` is NOT the `account_id` -- it is a separate short identifier generated per
registration. Multiple re-provisions of the same account create new `agent_id` values.

---

## 6. Design Decisions (Agreed)

| Decision | Choice | Reason |
|----------|--------|--------|
| Where does agent identity come from? | `agent_registrations.agent_id` -- created by onboarding's `issue_agent_token` | Already exists; purpose-built for agent identity |
| When is identity created? | Portal "Download Agent" click -> calls onboarding `issue_agent_token` | Ties enrollment to tenant/account at download time |
| How does user activate the agent? | Pre-configured ZIP -- `agent_id` + `registration_token` silently in `agent_config.json` | Zero friction; user never touches a token or key |
| Any manual token/key option? | **No** -- one flow only | Keep it simple |
| Is there a register step? | **Yes** -- needed to exchange `registration_token` -> `agent_api_key` | Registration token is one-time/30-min; api_key is the permanent scan credential |
| Registration token window? | 30 minutes (existing `expires_at = NOW()+30min` in onboarding) | Short window for initial handshake only; permanent key issued on registration |
| Scan authentication? | `agent_id` + `agent_api_key` (issued at register, stored in vul engine DB) | api_key is a secret; agent_id alone is not |
| Where is scan auth stored? | `vul_agent_sessions` table in vul engine DB | Vul engine must not write to onboarding DB; local table enables fast scan gate |
| Does vul engine call onboarding on every scan? | **No** -- only once at register time | Avoid coupling on hot scan path; vul_agent_sessions is the local authority |
| Binary integrity? | SHA256 hash embedded in `agent_config.json`; agent self-verifies at startup | Detects tampered binary before any network call |
| Binary hosting? | S3 bucket (managed by dev team) | Simple; portal fetches at download time |
| Download delivery? | Pre-signed S3 URL (10-min expiry) for per-provision ZIP | Portal assembles ZIP + config in memory, uploads to temp S3 path, returns time-limited URL |
| Multi-server / cloud fleet? | Same config deployed to all servers for the account | Cloud-native; no hostname binding; admin manages at account level |
| Revoke? | Set `vul_agent_sessions.status = 'revoked'` -> entire fleet stops immediately | One click; api_key cryptographically enforced |

---

## 7. Complete User Journey

```
STEP 1 -- CSPM Admin clicks "Download Agent"  [Actor: CSPM Admin -- tenant_admin, cloud_accounts:write]
----------------------------------------------

  Portal UI: CSPM Admin selects onboarded account + platform -> clicks Download
       |
       v
  Portal BFF -> calls onboarding engine:
               POST /api/v1/accounts/{account_id}/agent-token
               (existing endpoint: issue_agent_token)
       |
       v
  Onboarding engine:
  (1) Validates account exists (any account_type -- no restriction)
  (2) Generates: raw_token = uuid4()
  (3) Creates agent_registrations row:
       agent_id        = "agnt-" + uuid4()[:8]      <- stable readable identity
       token_hash      = SHA256(raw_token)
       status          = 'pending'
       expires_at      = NOW() + 30 minutes          <- short registration window
       account_id, tenant_id
  (4) Returns { raw_token, agent_id } to portal

  Portal backend:
  (1) Receives { raw_token, agent_id }
  (2) Fetches binary from S3 (permanent store):
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent        (Linux)
       s3://cspm-agent-binaries/vul-agent/{VERSION}/vul-agent.exe    (Windows)
  (3) Computes binary SHA256 hash
  (4) Creates agent_config.json:
       {
         "agent_id":            "agnt-3f8a1b2c",   <- identity from onboarding
         "registration_token":  "uuid4-raw",        <- one-time, 30-min window
         "binary_sha256":       "abcdef...",        <- integrity check
         "engine_url":          "https://vul-engine.internal",
         "tenant_id":           "tenant-uuid"
       }
  (5) Zips binary + config in memory
  (6) Uploads ZIP to temp S3 path:
       s3://cspm-agent-binaries/downloads/{uuid}/vul-agent-v{VERSION}-{platform}.zip
       (S3 lifecycle: auto-delete after 24h)
  (7) Generates 10-min pre-signed GET URL
  (8) Returns { download_url, url_expires_at, version } to browser

  Portal UI shows:
  +------------------------------------------------------+
  |  Deploy Vulnerability Agent                          |
  |                                                      |
  |  Account:   [ aws-prod-account (123456789012) v ]   |
  |  Platform:  [ Linux ]  [ Windows ]                   |
  |                                                      |
  |  [ v Download vul-agent-v1.0.0-linux.zip ]  <- one click  |
  |                                                      |
  |  1. Unzip the file                                   |
  |  2. chmod +x vul-agent && ./vul-agent  (Linux)       |
  |     double-click vul-agent.exe         (Windows)     |
  |  3. Agent registers and starts scanning              |
  |                                                      |
  |  Download link valid for: 10 minutes                 |
  +------------------------------------------------------+


STEP 2 -- Server Admin runs agent on target server  [Actor: Server Admin -- no portal login required]
--------------------------------------------------------------

  Agent startup -- automatic, no user input:
  (1) Reads agent_config.json
  (2) Binary integrity check:
       actual_hash = sha256(this binary)
       if actual_hash != binary_sha256 -> exit "Binary tampered. Re-download."
  (3) If agent_config has agent_id + agent_api_key -> skip to STEP 3 (already registered)
  (4) Has registration_token -> call vul engine to register:
       POST /api/v1/agents/register
       { registration_token, agent_id, hostname, resource_uid, platform, os_version, arch }
  (5) Vul engine register logic:
       a. Call onboarding API: GET /api/v1/agents/validate-token { token_hash=SHA256(token) }
          -> confirms agent_id, account_id, tenant_id, token not expired
       b. Issues: agent_api_key = secrets.token_hex(32)
       c. Upserts vul_agent_sessions:
            INSERT (agent_id, account_id, tenant_id, api_key_hash, status='active', hostname)
       d. Returns { agent_api_key }
  (6) Agent saves to agent_config.json:
       {
         "agent_id":      "agnt-3f8a1b2c",   <- kept
         "agent_api_key": "hex-secret",       <- new, permanent scan credential
         "engine_url":    "...",
         "tenant_id":     "..."
       }
       (registration_token + binary_sha256 removed -- no longer needed)
  (7) Prints: "Agent registered. Starting scan..."


STEP 3 -- All subsequent scans  [Actor: Agent binary -- fully automated, no human]
-------------------------------

  Agent: POST /api/v1/agents/scan
         Authorization: Bearer <agent_api_key>
         Body: { agent_id, tenant_id, hostname, resource_uid, findings... }
       |
       v
  Engine gate (local -- no onboarding call):
    SELECT * FROM vul_agent_sessions
    WHERE agent_id      = $agent_id
      AND tenant_id     = $tenant_id
      AND api_key_hash  = SHA256($api_key)
      AND status        = 'active'
    -> Not found -> 403 "Invalid agent credentials"
    -> Found -> accept scan, UPDATE last_seen_at
```

---

## 8. Agent Lifecycle

```
[Portal: account onboarded as type='vulnerability']
        |
        |  issue_agent_token -> agent_registrations row created
        v
     PENDING (30 min window)
        |
        |  agent runs -> calls /register -> api_key issued
        v
     ACTIVE (vul_agent_sessions status='active')
        |
        +-- sends scans (agent_id + api_key) ---> last_seen_at updated
        |
        +-- CSPM Admin clicks Revoke --------------> REVOKED
        |     (vul_agent_sessions status='revoked'; all fleet scans rejected)
        |
        +-- CSPM Admin clicks Re-provision
              -> portal calls issue_agent_token
              -> same agent_id reused + new registration_token issued
                (onboarding looks up existing agent_id for account_id;
                 updates token_hash + expires_at, resets status='pending')
              -> vul_agent_sessions UPSERT on /register restores status='active'
              -> new ZIP built (same agent_id, fresh token) + new api_key on first run
```

If registration token expires (30-min window missed), admin re-provisions -- new download.

---

## 9. Why vul_agent_sessions (not reuse agent_registrations directly)

The scan validation gate runs on every scan -- potentially hundreds of times per hour per agent.
It must be fast and must not depend on onboarding engine availability.

```
Option A: vul engine queries onboarding DB directly on every scan
  [!] Cross-DB query on hot path
  [!] Vul engine couples to onboarding DB schema
  [!] Onboarding outage = no scans accepted

Option B: vul engine calls onboarding API on every scan
  [!] HTTP call on hot scan path (latency)
  [!] Onboarding outage = no scans accepted

Option C: vul_agent_sessions table in vul engine DB  <- CHOSEN
  [x] Local lookup -- fast
  [x] Populated once at register time
  [x] Onboarding outage does not affect scan acceptance
  [x] Vul engine owns its own auth state
```

Onboarding is called **once** -- at register time -- to validate the registration token and
retrieve `agent_id + account_id + tenant_id`. After that, `vul_agent_sessions` is the
authority for scan authentication.

---

## 10. Binary Integrity -- SHA256 Self-Check

```
Portal at download time:
  binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()
  -> embed in agent_config.json

Agent at startup (before any network call):
  actual   = hashlib.sha256(open(sys.argv[0], 'rb').read()).hexdigest()
  expected = config["binary_sha256"]
  if actual != expected:
      exit("ERROR: Binary integrity check failed. Re-download from portal.")
```

---

## 11. Binary Distribution -- S3

### S3 Bucket Layout

```
s3://cspm-agent-binaries/
+-- vul-agent/                              <- permanent (dev team managed)
|   +-- v1.0.0/
|       +-- vul-agent                       (Linux, ~50MB)
|       +-- vul-agent.exe                   (Windows, ~50MB)
|
+-- downloads/                              <- temporary per-provision ZIPs
    +-- {uuid}/
        +-- vul-agent-v{VERSION}-{platform}.zip
```

S3 lifecycle rule on `downloads/`: delete after 24 hours.

### Portal IAM permissions

```
s3:GetObject    on cspm-agent-binaries/vul-agent/*
s3:PutObject    on cspm-agent-binaries/downloads/*
```

> Note: Pre-signed URLs require no additional IAM permission. The SDK generates
> them client-side using the caller's existing `s3:GetObject` credential.
> `s3:GeneratePresignedUrl` does not exist as an AWS IAM permission.

---

## 12. Required Changes by Layer

### 12.1 Onboarding Engine -- One New Endpoint Required

`agent_registrations` table already exists with the required columns.
`issue_agent_token` endpoint already exists.

> **Code observation:** The existing `issue_agent_token` raises HTTP 409 when an active
> registration already exists ("Revoke it first" ? `UniqueViolation` handler at line 831).
> The re-provision behaviour agreed in Q4 (reuse same agent_id) requires changing this to
> an UPDATE instead of INSERT+reject. The modify block below captures that change.
>
> **Token TTL inconsistency in current code:** `_BOOTSTRAP_TOKEN_TTL_MINUTES = 15` is
> defined at line 77 of `cloud_accounts.py` but the SQL hardcodes `INTERVAL '30 minutes'`
> at line 351 of `cloud_accounts_operations.py`. The constant is unused. Align both to
> 30 minutes (the DB value) and use the constant in SQL via application layer.
>
> **PKCE bootstrap (existing flow):** The current onboarding engine already implements PKCE
> (`POST /api/v1/agents/bootstrap`): agent sends `{ registration_id, code_verifier }`,
> server verifies `SHA256(code_verifier) == token_hash`, issues a 30-day JWT. Our plan's
> `/register` endpoint is a NEW endpoint in the vul engine ? it calls onboarding's
> `/validate-token` internally. The PKCE flow in onboarding remains untouched; the new
> endpoint sits in the vul engine and uses a simpler pre-configured ZIP delivery.

**Modify `issue_agent_token` behavior for re-provision** (reuse existing agent_id):

```
Current behavior:  always INSERT a new row -> new agent_id every call
Required behavior: look up existing agent_registrations row for account_id
  -> If found:  UPDATE token_hash=SHA256(new_raw_token),
                       status='pending',
                       expires_at=NOW()+30min
               RETURN existing agent_id  <- same identity preserved
  -> If not found: INSERT new row as before -> new agent_id (first provision)
```

This means re-provision produces a new download ZIP with the same `agent_id` already
in `vul_agent_sessions`. The `/register` UPSERT (ON CONFLICT agent_id DO UPDATE)
will update `api_key_hash` and restore `status='active'` -- no duplicate row, no
orphaned identity in portal Agent Management table.

**NEW endpoint -- REQUIRED for v1** (blocking: vul engine `/register` calls this):

```
POST /api/v1/internal/agents/validate-token
Body: { "token_hash": "<sha256>" }
Response 200: { agent_id, account_id, tenant_id, status, expires_at }
Response 404: token not found or expired
Response 409: token already consumed (status != 'pending')

Side effect:
  UPDATE agent_registrations
  SET    status = 'connected', activated_at = NOW()
  WHERE  token_hash = $token_hash
    AND  status     = 'pending'
    AND  expires_at > NOW()

This marks the token single-use -- a second call with the same hash returns 409.
```

> **Why POST, not GET:** The token_hash is a secret value. GET requests appear in
> server access logs, load balancer logs, and CloudWatch. POST with a JSON body
> keeps the secret out of logs.
>
> **Why API call, not direct DB read:** Vul engine must not know the onboarding DB
> host, credentials, or schema. API call preserves service boundary -- onboarding
> owns its own data. This is the chosen approach; direct DB read is ruled out.

---

### 12.2 Vulnerability Engine -- Database

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

**Table: `scans`** -- swap scan_id -> scan_run_id, drop vul_agent_id

```sql
ALTER TABLE scans ADD COLUMN scan_run_id UUID;
ALTER TABLE scans ADD COLUMN tenant_id   UUID;
ALTER TABLE scans ADD COLUMN account_id  UUID;
ALTER TABLE scans DROP COLUMN scan_id;          -- clean break; no prod data
ALTER TABLE scans DROP COLUMN vul_agent_id;     -- computed non-validated string; replaced by agent_id
CREATE INDEX idx_scans_scan_run_id ON scans(scan_run_id);
```

**Table: `scan_vulnerabilities`** -- same swap, drop vul_agent_id

```sql
ALTER TABLE scan_vulnerabilities ADD COLUMN scan_run_id  UUID;
ALTER TABLE scan_vulnerabilities ADD COLUMN tenant_id    UUID;
ALTER TABLE scan_vulnerabilities ADD COLUMN account_id   UUID;
ALTER TABLE scan_vulnerabilities ADD COLUMN resource_uid VARCHAR(255);
ALTER TABLE scan_vulnerabilities DROP COLUMN scan_id;        -- consistent with scans
ALTER TABLE scan_vulnerabilities DROP COLUMN vul_agent_id;   -- same: replaced by agent_id
CREATE INDEX idx_scan_vuln_scan_run_id ON scan_vulnerabilities(scan_run_id);
```

Both tables drop `scan_id` and `vul_agent_id` -- no legacy columns remain.

---

### 12.3 Vulnerability Engine -- API

#### NEW: `POST /api/v1/agents/register`
Called by agent binary on first run only.

> **Auth note:** This endpoint has NO session auth (no cookie, no JWT).
> The `registration_token` in the request body IS the authentication.
> Do NOT apply `require_permission()` here -- the agent has no session at this point.
> Apply IP-based rate limiting instead (max 10 req/min per IP).

```
Request:  { registration_token, agent_id, hostname, resource_uid, platform, os_version, arch }
Response: { agent_api_key }

Logic:
(1) Call onboarding to validate and consume token:
   POST /internal/agents/validate-token  { token_hash: SHA256(registration_token) }
   -> returns: { agent_id, account_id, tenant_id, expires_at }
   -> If 404 (not found or expired) -> 403 "Token invalid or expired.
                                         Please re-download from portal."
   -> If 409 (already consumed)     -> 403 "Token already used.
                                         Please re-provision from portal."
   -> If agent_id in response != agent_id in request -> 403 "Agent ID mismatch"
   Note: onboarding sets agent_registrations.status = 'connected' as a side effect --
         this makes the token single-use regardless of what happens next.

(2) Issue scan credential:
   agent_api_key = secrets.token_hex(32)

(3) UPSERT vul_agent_sessions:
   INSERT (agent_id, account_id, tenant_id, api_key_hash=SHA256(key),
           status='active', hostname, provisioned_at=now())
   ON CONFLICT (agent_id) DO UPDATE SET
     api_key_hash=SHA256(key), status='active',
     hostname=$hostname, provisioned_at=now()

(4) Return { agent_api_key }
   (plain key returned ONCE -- agent must persist it in agent_config.json)
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
  -> Not found -> 403 "Invalid agent credentials"
  -> Found -> session row returned
    UPDATE vul_agent_sessions SET last_seen_at = now()
    INSERT findings using:
      tenant_id  = session.tenant_id   <- from DB row, NOT request body
      account_id = session.account_id  <- from DB row, NOT request body
      scan_run_id, resource_uid from request body (audit fields only)
```

#### NEW: `POST /api/v1/agents/revoke`
Called by portal when CSPM Admin clicks Revoke.

```
Auth:   require_permission('agents:revoke')   <- tenant_admin and above
        tenant_id scoped from AuthContext (NOT request body)

Request body: { agent_id }

Logic:
  UPDATE vul_agent_sessions
  SET    status = 'revoked'
  WHERE  agent_id  = $agent_id
    AND  tenant_id = $auth_context.tenant_id   <- account-level scope enforced
```

> Revoke is account-level: a `tenant_admin` can only revoke agents that belong to
> their own tenant. `tenant_id` comes from `AuthContext`, never from the request body.
> `analyst` role does NOT have `agents:revoke` permission.

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

#### REMOVE: `vul_agent_id` from scan route model and engine internals

`vul_agent_id` is a computed non-validated string (`{tenant_id}-{hostname}-on-cloud`).
It is not a registered identity and carries no security enforcement value.
`agent_id` (from `vul_agent_sessions`) replaces it as the authoritative agent identity.

```
REMOVE from agents.py:34
  vul_agent_id: Optional[str] = None   <- ScanData model field

REMOVE from database.py (~15 locations)
  vul_agent_id TEXT column in CREATE TABLE
  vul_agent_id in INSERT / UPDATE / SELECT statements

REMOVE from scanner.py (4 locations)
  vul_agent_id: str = None             <- parameter (line 1281)
  vul_agent_id references at lines 1312, 1331, 1406, 1427
```

---

### 12.4 Portal Backend -- Endpoint

#### MODIFY: Download provision flow

```
POST /api/vulnerability/agent/provision
Request:  { account_id, platform: "linux" | "windows" }

Logic:
1. Call onboarding: POST /api/v1/accounts/{account_id}/agent-token
   -> receive { raw_token, agent_id }

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

5. ZIP in memory -> upload to s3://cspm-agent-binaries/downloads/{uuid}/...

6. Generate 10-min pre-signed URL

7. Return { download_url, url_expires_at }
```

---

### 12.5 Portal UI -- Changes

**Download Dialog:**

```
+------------------------------------------------------+
|  Deploy Vulnerability Agent                          |
|                                                      |
|  Account:   [ aws-prod-account (123456789012) v ]   |
|  Platform:  [ Linux ]  [ Windows ]                   |
|                                                      |
|  [ v Download vul-agent-linux.zip ]                  |
|                                                      |
|  1. Unzip   2. Run agent   3. Scans start auto       |
|                                                      |
|  Download link valid for: 10 minutes                 |
+------------------------------------------------------+
```

**Agent Management Table:**

| Agent ID | Account | Status | Last Seen | Provisioned | Actions |
|----------|---------|--------|-----------|-------------|---------|
| agnt-3f8a1b2c | aws-prod (123...) | ACTIVE | 2 hrs ago | 01 May 2026 | [Revoke] |
| agnt-7d2c9e01 | azure-dev | ACTIVE | 1 day ago | 15 Apr 2026 | [Revoke] |
| agnt-a1b2c3d4 | aws-staging | REVOKED | 10 days ago | -- | [Re-provision] |

---

### 12.6 Agent Binary -- `vul_agent.py` Changes

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

    # Step 3: First run -- register with vul engine
    if config.get("registration_token") and config.get("agent_id"):
        response = call_register_endpoint(
            registration_token = config["registration_token"],
            agent_id           = config["agent_id"],
            hostname           = socket.gethostname(),
            resource_uid       = get_resource_uid(),   # cloud-agnostic -- see table below
            platform           = sys.platform,
            os_version         = platform.version(),
            arch               = platform.machine(),
        )
        # Distinguish user-actionable errors from generic failures
        if response.status_code == 403:
            body = response.json()
            if "expired" in body.get("detail", "").lower():
                raise SystemExit(
                    "ERROR: Registration token expired (30-min window missed).\n"
                    "Please re-download from portal."
                )
            if "already used" in body.get("detail", "").lower():
                raise SystemExit(
                    "ERROR: Registration token already used.\n"
                    "Please re-provision from portal."
                )
            raise SystemExit(f"ERROR: Registration failed: {body.get('detail')}")

        config["agent_api_key"] = response.json()["agent_api_key"]
        del config["registration_token"]
        del config["binary_sha256"]
        save_config(config)

        # Protect config file -- api_key is a plaintext secret on disk
        if sys.platform != "win32":
            os.chmod(config_path, 0o600)   # owner read/write only

        return config["agent_id"], config["agent_api_key"]

    raise SystemExit("ERROR: Agent not configured. Re-download from portal.")
```

#### `get_resource_uid()` -- cross-cloud translation

`resource_uid` identifies the server running the agent. Each cloud exposes a metadata
endpoint; the agent probes them in order and prefixes the result so portal can display
the source. Falls back to hostname if no metadata endpoint responds.

```
Cloud     Metadata URL                                            Prefix + Value
-------   --------------------------------------------------------------------------
AWS EC2   http://169.254.169.254/latest/meta-data/instance-id    aws:<instance-id>
          (IMDSv2: PUT token first, then GET with token header)  e.g. aws:i-0abc1234ef567890

Azure VM  http://169.254.169.254/metadata/instance/compute/vmId  azure:<uuid>
          Header: Metadata: true                                  e.g. azure:3e68d9b7-...

GCP       http://metadata.google.internal/computeMetadata/v1/    gcp:<numeric-id>
            instance/id                                           e.g. gcp:1234567890123
          Header: Metadata-Flavor: Google

OCI       http://169.254.169.254/opc/v2/instance/id              oci:<uuid>

On-prem   (no metadata endpoint responds within 2s timeout)      onprem:<hostname>
          -> fall back to socket.gethostname()
```

```python
def get_resource_uid() -> str:
    """Detect cloud provider and return prefixed instance identifier."""
    probes = [
        ("aws",   "http://169.254.169.254/latest/meta-data/instance-id",  None),
        ("azure", "http://169.254.169.254/metadata/instance/compute/vmId", {"Metadata": "true"}),
        ("gcp",   "http://metadata.google.internal/computeMetadata/v1/instance/id",
                  {"Metadata-Flavor": "Google"}),
        ("oci",   "http://169.254.169.254/opc/v2/instance/id", None),
    ]
    for prefix, url, headers in probes:
        try:
            r = requests.get(url, headers=headers or {}, timeout=2)
            if r.ok:
                return f"{prefix}:{r.text.strip()}"
        except requests.RequestException:
            continue
    return f"onprem:{socket.gethostname()}"
```

> `resource_uid` is an audit field -- it is stored in `vul_agent_sessions.hostname`
> and surfaced in the portal Agent Management table. It is never used for
> authentication or tenant scoping.

#### REMOVE: `construct_vul_agent_id()` method and all call sites

```python
# DELETE entirely from vul_agent.py:
def construct_vul_agent_id(self) -> str:          # lines 202-251 approx
    tenant_id = self.config.get("tenant_id", "ajay4141")
    hostname = self.system_info.get("hostname", "unknown_host")
    if hostname.startswith("EC2"):
        return f"{tenant_id}-{hostname}-on-cloud"
    ...

# REMOVE call sites in vul_agent.py:
#   line 1430 -- vul_agent_id added to scan payload
#   line 1565 -- vul_agent_id added to scan payload
```

`hostname` is retained as an audit field in `vul_agent_sessions` and scan payloads.
The `"ajay4141"` hardcoded fallback lives only inside this method -- deleting the method
removes the last hardcoded tenant reference from the agent binary.

---

## 13. Out of Scope for v1

| Feature | Deferred to |
|---------|-------------|
| Signed binaries / `.deb` / `.msi` installers | v2 |
| Agent auto-update mechanism | v2 |
| Agent heartbeat / health endpoint | v2 |
| Per-agent scan rate limiting | v2 |
| mTLS for agent <-> engine communication | v2 |
| api_key rotation without re-provisioning | v2 |
| Systemd unit file (Linux daemon) / Windows service wrapper | v2 |
| DPAPI-encrypted config on Windows (api_key at rest) | v2 |

---

## 14. Implementation Order

```
(1)  DB migration (vul engine)
     -- CREATE vul_agent_sessions table
     -- scans: DROP scan_id, ADD scan_run_id UUID
     -- scans: DROP vul_agent_id              <- v1.8 removal
     -- scan_vulnerabilities: DROP scan_id, ADD scan_run_id UUID + standard cols
     -- scan_vulnerabilities: DROP vul_agent_id  <- v1.8 removal

(2)  Onboarding engine -- NEW endpoint (blocking, required for v1)
     -- POST /api/v1/internal/agents/validate-token
       (validate + consume token; sets agent_registrations.status = 'connected')
     -- No DB schema changes needed (status column already exists)

(3)  Vul Engine -- POST /api/v1/agents/register (new)
     -- Validate registration_token via onboarding
     -- Issue agent_api_key, store hash in vul_agent_sessions

(4)  Vul Engine -- MODIFY POST /api/v1/agents/scan
     -- Replace old gate with vul_agent_sessions lookup
     -- Remove vul_agent_id from ScanData model (agents.py:34)  <- v1.8 removal
     -- Remove vul_agent_id from database.py (~15 locations)    <- v1.8 removal
     -- Remove vul_agent_id from scanner.py (4 locations)       <- v1.8 removal

(5)  Vul Engine -- POST /api/v1/agents/revoke (new)

(6)  Vul Agent (vul_agent.py)
     -- Remove "ajay4141" fallback
     -- Add integrity check + register flow
     -- Delete construct_vul_agent_id() method (lines 202-251)  <- v1.8 removal
     -- Remove vul_agent_id from scan payload builds (lines 1430, 1565)  <- v1.8 removal

(7)  S3 bucket
     -- Upload Linux + Windows binaries v1.0.0
     -- Set lifecycle rule: delete downloads/* after 24h

(8)  Portal BFF
     -- POST /api/vulnerability/agent/provision
       (call onboarding issue_agent_token -> build ZIP -> S3 upload -> presigned URL)

(9)  Portal UI
     -- Download dialog + Agent Management table

(10)  E2E test
     -- Onboard vulnerability account -> download ZIP -> integrity-check
     -> register -> scan accepted -> revoke -> scan rejected -> re-provision -> scan accepted
```

---

## 15. Open Questions for Team

1. ~~**Onboarding token validation**~~ -- **resolved**: vul engine calls onboarding API (`POST /internal/agents/validate-token`). Direct DB read ruled out -- vul engine must not own onboarding DB credentials or schema.
2. ~~**account_type gate**~~ -- **resolved**: No constraint. Any account_type can issue an agent token. Remove the `account_type  in  (...)` validation from `issue_agent_token`.
3. ~~**resource_uid**~~ -- **resolved**: Translated across all clouds. Agent probes cloud metadata endpoints in order (AWS IMDSv2 -> Azure IMDS -> GCP metadata -> OCI), prefixes the result (`aws:i-...`, `azure:<uuid>`, `gcp:<id>`, `oci:<uuid>`), falls back to `onprem:<hostname>`. Never NULL. See `get_resource_uid()` in Section 11.6.
4. ~~**Re-provision behaviour**~~ -- **resolved**: Same `agent_id` is reused on re-provision. `issue_agent_token` looks up existing `agent_registrations` row for `account_id` and updates `token_hash` + `expires_at` rather than inserting a new row. The `/register` UPSERT (ON CONFLICT agent_id DO UPDATE) restores `status='active'` -- single identity per account, clean portal table.
5. ~~**Revoke permission**~~ -- **resolved**: Account-level. `require_permission('agents:revoke')` granted to `tenant_admin` and above. `tenant_id` scoped from AuthContext -- admin can only revoke agents within their own tenant. `analyst` cannot revoke.
6. **S3 bucket**: Create new `cspm-agent-binaries` or reuse existing bucket?
7. **Temp ZIP cleanup**: S3 lifecycle rule (delete after 24h) -- sufficient?
8. ~~**scan_id history**~~ -- **resolved**: drop both `scans.scan_id` and `scan_vulnerabilities.scan_id`. Clean break.

---

*Plan v1.11 -- updated 2026-05-12 -- actor roles clarified; code observations documented.
*Section 3 added: CSPM Admin (tenant_admin, cloud_accounts:write), Server Admin (no portal), Analyst/Viewer (read only). All 'Admin' labels replaced with specific actor names throughout Sections 4 and 7. Section 12.1 adds three code observations: 409 UniqueViolation must become UPDATE for re-provision; unused TTL constant vs hardcoded SQL; PKCE bootstrap already exists in onboarding -- our /register is a separate new endpoint in vul engine.

*Plan v1.10 -- updated 2026-05-12 -- team Q&A: 4 open questions resolved.*  
*Q2: account_type constraint removed -- any account type can provision an agent. Q3: resource_uid is never NULL -- cross-cloud detection table added (AWS/Azure/GCP/OCI/on-prem). Q4: re-provision reuses same agent_id -- `issue_agent_token` updates existing row instead of inserting; UPSERT in /register restores active status. Q5: revoke scoped to tenant_admin by AuthContext.tenant_id -- account-level, analyst excluded.*

*Plan v1.9 -- updated 2026-05-12 -- production readiness review: 10 gaps closed.*  
*Critical: validate-token endpoint marked required (not optional); token consumed after use (single-use guarantee); INSERT uses session row for tenant_id/account_id (multi-tenant isolation); removed fake `s3:GeneratePresignedUrl` IAM permission; added `chmod 600` on agent_config.json.*  
*Important: `/register` unauthenticated intent made explicit; expired token gives user-actionable error message; validate-token changed GET->POST (secret out of logs); version added to ZIP filename; systemd/Windows service added to Out of Scope.*

*Plan v1.8 -- updated 2026-05-12 -- added vul_agent_id removal.*  
*Removes `vul_agent_id` entirely: DROP COLUMN from `scans` + `scan_vulnerabilities`; remove from ScanData model, database.py, scanner.py; delete `construct_vul_agent_id()` and payload call sites. Eliminates the last hardcoded `"ajay4141"` tenant reference from the agent binary. `agent_id` from `vul_agent_sessions` is the authoritative identity.*

*Plan v1.7 -- updated 2026-05-12 -- added Section 3 end-to-end flow with value lifecycle.*  
*Shows every key value (tenant_id, account_id, agent_id, registration_token, api_key_hash, scan_run_id), exactly where each is created, reused, and removed across all 5 phases.*

*Plan v1.6 -- updated 2026-05-12 -- aligned with existing onboarding engine code.*  
*Key changes from v1.5: code inspection of onboarding engine revealed `agent_registrations` table and `issue_agent_token` endpoint already exist. Corrections: (1) `agent_id` is `agnt-xxxxxxxx` from `agent_registrations`, NOT `account_id`; (2) provision reuses onboarding's existing `issue_agent_token`; (3) register step is back -- exchanges 30-min registration token for permanent `agent_api_key`; (4) `vul_agent_sessions` table replaces `vul_agent_credentials` -- local to vul engine DB, populated once at register time, no onboarding call on scan path.*

*Plan v1.5 -- identity from onboarding table.*  
*Plan v1.4 -- scan_id -> scan_run_id swap.*  
*Plan v1.3 -- hybrid pre-signed URL delivery.*  
*Plan v1.2 -- security hardening (token expiry, uuid4, api_key, binary SHA256).*
