# Story: SECOPS-02 — Fix 6 Security Blockers in SecOps Engine

## Status: done

## Context

A security audit of the existing SecOps engine identified 6 blockers that must be resolved before code-repo accounts can be onboarded at scale. These are all hardening changes to existing code — no new features. The blockers span credential leakage, SSRF, git hook injection, missing tenant isolation in DB queries, and missing input validation.

All 6 fixes are in the same deployable unit (one PR, one image push). No DB schema changes — SECOPS-01 must ship first to add the `account_id` column to `secops_report` and `secops_findings`, but the code in this story does not need that column yet (SECOPS-04 writes it).

**Prerequisite**: SECOPS-01 applied.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [ ] GV Govern  [ ] ID Identify  [x] PR Protect  [x] DE Detect  [x] RS Respond  [ ] RC Recover
PR.DS-1, PR.DS-2, PR.AC-3, PR.AC-4, DE.CM-1, RS.AN-1

**CSA CCM v4 Domain(s)**
- CCM: IAM-02 (Identity Inventories), DSP-07 (Credential Handling), IVS-04 (Network Security — SSRF), SEF-02 (Incident Reporting)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | `_clone_repo()` | PAT embedded in git clone URL leaks via `ps aux` and application logs when git process spawns | B-1: GIT_ASKPASS env var; URL never contains PAT |
| Tampering | `_clone_repo()` | Attacker supplies a repo with a malicious `.git/hooks/pre-receive` that executes arbitrary commands on the scanner | B-3: `--config core.hooksPath=/dev/null` added to git clone cmd |
| Info Disclosure | `get_scan_findings()` | Endpoint returns findings for any `secops_scan_id` regardless of tenant — cross-tenant data exposure | B-4: Add `AND tenant_id = %s` using `auth.engine_tenant_id` |
| Spoofing | `get_scan_status()` | No `require_permission()` on status endpoint — unauthenticated callers can poll any scan ID | B-4: Add `Depends(require_permission("secops:read"))` |
| Spoofing | `update_cloud_account` | `credential_ref` field can be set to any string, pointing scan engine at wrong Secrets Manager path | B-5: Validate `credential_ref == f"threat-engine/account/{account_id}"` |
| Tampering | `scan_repo` POST | `repo_url` accepts `http://169.254.169.254/` (IMDS) or RFC1918 addresses — SSRF to internal AWS metadata | B-2: Pydantic validator: HTTPS only, allowlisted hostnames, block RFC1918 |

### PASTA (credentials/IAM/network)
| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Credential exfiltration | Steal PAT from logs | Submit scan with PAT in URL; grep pod logs or CloudWatch | GIT_ASKPASS: PAT passed via env, not URL |
| SSRF via repo_url | Read EC2 metadata (169.254.169.254) | POST /scan with `repo_url=http://169.254.169.254/latest/meta-data/` | URL validator: HTTPS only + allowlist + RFC1918 block |
| Code execution via git hook | RCE on scanner pod | Commit `.git/hooks/post-checkout` to repo, trigger scan | `--config core.hooksPath=/dev/null` in git clone |
| Cross-tenant read | Read another tenant's findings | Call GET /scan/{id}/findings with a scan_id from another tenant | `AND tenant_id = %s` using authenticated tenant from AuthContext |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1552.001 | Credentials in Files | D3-CH (Credential Hardening) | B-1: PAT never embedded in URL; passed via GIT_ASKPASS env var only |
| T1059.004 | Unix Shell (via Git Hooks) | D3-EAL (Execution Isolation) | B-3: `core.hooksPath=/dev/null` disables all git hooks before clone executes |
| T1190 | Exploit Public-Facing Application (SSRF) | D3-NTF (Network Traffic Filtering) | B-2: Pydantic validator blocks non-HTTPS, non-allowlisted, and RFC1918 repo URLs |
| T1078.004 | Valid Accounts: Cloud Accounts | D3-UAP (User Account Provisioning) | B-5: credential_ref validated to canonical Secrets Manager path format |

## Acceptance Criteria (Functional)
- [ ] B-1: `_clone_repo()` no longer embeds PAT in the git URL. PAT is passed via a `GIT_ASKPASS` helper script written to a temp file, executed, and deleted in `finally` block. Log line `Cloning {url}` uses sanitized URL (no credentials). `ps aux` during clone shows no PAT in argv.
- [ ] B-2: `ScanRequest.repo_url` has a Pydantic `@validator` that raises `ValueError` if: (a) scheme is not `https`, (b) hostname is not in `{github.com, gitlab.com, bitbucket.org}`, (c) hostname resolves to RFC1918 range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). Validator is called before any network I/O.
- [ ] B-3: `git clone` command includes `--config core.hooksPath=/dev/null`. Test: a repo with a `.git/hooks/pre-clone` file does not execute it.
- [ ] B-4a: `get_scan_findings()` query includes `AND tenant_id = %s` using `auth.engine_tenant_id`. Returns 404 (not 200 with empty list) when scan belongs to a different tenant.
- [ ] B-4b: `get_scan_status()` endpoint has `Depends(require_permission("secops:read"))`. Returns 403 for unauthenticated callers.
- [ ] B-5: `update_cloud_account()` in `cloud_accounts_operations.py`: if `credential_ref` is in the `updates` dict, validate it matches the regex `^threat-engine/account/[0-9a-f-]{36}$` (UUID format). Raise `ValueError` if it does not.
- [ ] B-6: SQL confirmed via `\d cloud_accounts` — partial unique index exists (created in SECOPS-01; this story verifies it before proceeding).

## Acceptance Criteria (Security — must pass bmad-security-reviewer)
- [ ] No PAT appears in any log line at any level (verify with `grep -r "ghp_\|glpat-\|BBDC-" /app/scan_output/` after test scan)
- [ ] URL validator unit test: `http://169.254.169.254/`, `https://internal.corp/repo`, `https://evil.github.com.attacker.com/` all rejected
- [ ] URL validator unit test: `https://github.com/org/repo` accepted
- [ ] `get_scan_findings` returns HTTP 403 when auth header omitted (not 200 or 500)
- [ ] `get_scan_status` returns HTTP 403 when auth header omitted
- [ ] `update_cloud_account` with `credential_ref="../../etc/passwd"` raises ValueError before any DB call
- [ ] GIT_ASKPASS helper script created with mode `0700` and deleted in `finally` regardless of clone outcome
- [ ] All new DB queries have `tenant_id` filter from `auth.engine_tenant_id` (not from request body)
- [ ] No plaintext credentials in logs
- [ ] Base image pinned (no `latest`) — SLSA Level 1

## Technical Notes

### B-1: GIT_ASKPASS implementation (sast.py `_clone_repo`)

Replace the current `_clone_repo` signature to accept `pat: Optional[str]` separately from a clean `repo_url`. Write a shell helper to a `tempfile.mktemp(suffix=".sh")`, `chmod 0700`, set `GIT_ASKPASS` env var, pass env to `subprocess.run`:

```python
import stat, tempfile, os, subprocess, shutil

def _clone_repo(repo_url: str, branch: str, dest: str, pat: Optional[str] = None) -> None:
    """Clone repo; PAT passed via GIT_ASKPASS, never embedded in URL."""
    if os.path.exists(dest):
        shutil.rmtree(dest)

    askpass_path: Optional[str] = None
    env = os.environ.copy()

    if pat:
        # Write a minimal GIT_ASKPASS script that echoes the PAT
        fd, askpass_path = tempfile.mkstemp(suffix=".sh")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("#!/bin/sh\necho '{}'\n".format(pat.replace("'", "'\\''")))
            os.chmod(askpass_path, stat.S_IRWXU)  # 0700 — owner only
            env["GIT_ASKPASS"] = askpass_path
            env["GIT_TERMINAL_PROMPT"] = "0"
        except Exception:
            if askpass_path and os.path.exists(askpass_path):
                os.unlink(askpass_path)
            raise

    cmd = [
        "git", "clone", "--depth", "1",
        "--branch", branch, "--single-branch",
        "--config", "core.hooksPath=/dev/null",   # B-3: disable git hooks
        repo_url, dest,
    ]
    # Log sanitized URL only — never log pat
    logger.info(f"Cloning {repo_url} branch={branch} -> {dest}")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, env=env
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
    finally:
        if askpass_path and os.path.exists(askpass_path):
            os.unlink(askpass_path)   # always delete

    logger.info(f"Clone complete: {dest}")
```

### B-2: URL validator (sast.py ScanRequest model)

```python
import ipaddress, socket
from pydantic import validator

ALLOWED_GIT_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / IMDS
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
]

class ScanRequest(BaseModel):
    tenant_id: str
    repo_url: str
    branch: str = "main"
    account_id: str              # added in SECOPS-04; validator declared here
    ...

    @validator("repo_url")
    def validate_repo_url(cls, v: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(v)
        if parsed.scheme != "https":
            raise ValueError("repo_url must use https scheme")
        host = (parsed.hostname or "").lower().rstrip(".")
        if host not in ALLOWED_GIT_HOSTS:
            raise ValueError(f"repo_url host '{host}' is not in the allowed list: {sorted(ALLOWED_GIT_HOSTS)}")
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
            if any(ip in net for net in _RFC1918):
                raise ValueError(f"repo_url resolves to a private/reserved IP: {ip}")
        except socket.gaierror:
            pass  # DNS failure — allow, will fail at clone time
        return v
```

### B-4: tenant_id filter on get_scan_findings

Change the WHERE clause in `get_scan_findings`:
```python
# OLD
"WHERE secops_scan_id = %s"

# NEW — always scope to auth tenant
"WHERE secops_scan_id = %s AND tenant_id = %s"
params = [secops_scan_id, auth.engine_tenant_id]
```

Add `Depends(require_permission("secops:read"))` to `get_scan_status` endpoint signature.

### B-5: credential_ref validation (cloud_accounts_operations.py)

In `update_cloud_account()`, after the `allowed` set filter, add:
```python
import re
_CRED_REF_PATTERN = re.compile(r'^threat-engine/account/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

if "credential_ref" in fields:
    if not _CRED_REF_PATTERN.match(fields["credential_ref"]):
        raise ValueError(
            f"credential_ref must match 'threat-engine/account/<uuid>'; got: {fields['credential_ref']}"
        )
```

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/secops/sast_engine/routers/sast.py` — B-1, B-2, B-3, B-4
- `/Users/apple/Desktop/threat-engine/engines/onboarding/database/cloud_accounts_operations.py` — B-5
- `/Users/apple/Desktop/threat-engine/shared/database/migrations/SECOPS-01A_cloud_accounts_repo_unique_idx.sql` — B-6 (verify exists from SECOPS-01)

## Definition of Done
- [ ] Code implemented and builds locally
- [ ] Docker image built and pushed: `yadavanup84/secops-scanner:v-secops-repoacct1`
- [ ] K8s manifest updated with new image tag
- [ ] kubectl apply and rollout status clean
- [ ] bmad-security-reviewer: no BLOCKERS on all 6 items
- [ ] bmad-qa: all 6 functional acceptance criteria verified
- [ ] Post-deploy: health check `/api/v1/health/live` returns 200; BFF smoke test returns non-500
- [ ] Memory updated at `/Users/apple/.claude/projects/-Users-apple-Desktop-threat-engine/memory/`
