# Story: SECOPS-03 — Onboarding Engine: code_security Account Type + Git Validator

## Status: done

## Context

The onboarding engine currently treats GitHub/GitLab/Bitbucket as a generic `secops` account type via a single `git` provider entry. This story formalises them as a distinct `code_security` account type with three concrete providers (`github`, `gitlab`, `bitbucket`), adds a `GitValidator` that verifies credentials by running `git ls-remote` before the account is accepted, and shapes the `auth_config` JSONB so downstream engines have a canonical location to find `repo_url`, `default_branch`, `project_name`, `vcs_platform`, and `scan_types`.

This mirrors how cloud CSP accounts use `cloud_csp` account_type and a provider-specific credential shape — consumers (SecOps engine, BFF) identify a code repo account by `account_type = 'code_security'`.

**Prerequisites**: SECOPS-01 applied (partial unique index exists on cloud_accounts).

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [x] Design  [x] Implementation  [ ] Verification  [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [ ] GV Govern  [x] ID Identify  [x] PR Protect  [ ] DE Detect  [ ] RS Respond  [ ] RC Recover
PR.DS-1, PR.DS-2, PR.AC-3, PR.AC-4

**CSA CCM v4 Domain(s)**
- CCM: IAM-02 (Identity Inventories), IAM-05 (Least-Privilege Access), DSP-07 (Data Classification — credential type tagging)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | GitValidator | Attacker supplies a repo URL for a repo they do not own — credentials pass validation for a different repo | `git ls-remote` uses the authenticated URL; it will fail 403 if the PAT has no read access to the specific repo |
| Tampering | `auth_config` JSONB | Attacker injects a `repo_url` pointing to an internal host by setting `auth_config` directly via PATCH | `auth_config` is populated by the onboarding router, not accepted verbatim from untrusted input; `repo_url` must pass the same SSRF validator as SECOPS-02 B-2 |
| Info Disclosure | GitValidator subprocess | `git ls-remote` output may echo PAT in error messages | Subprocess stderr captured and sanitized before logging; PAT passed via GIT_ASKPASS (same pattern as SECOPS-02 B-1) |
| DoS | GitValidator | Attacker triggers many concurrent validation requests to large repos | 10-second timeout on `git ls-remote`; process killed on timeout |

### PASTA (credentials/IAM/network)
| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Credential exfiltration | Capture PAT during validation | GitValidator logs stderr containing `ghp_…` | GIT_ASKPASS pattern; stderr sanitized before log |
| Cross-tenant read | Onboard another tenant's repo | Create `code_security` account with repo_url matching another tenant's repo | Partial UNIQUE index `(tenant_id, repo_url)` prevents duplicate per-tenant; different tenants may share public repos |
| DoS via git ls-remote | Hang validation thread | Point to a slow/large repo and trigger many validation requests | 10s timeout; subprocess.run with `timeout=10` |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | D3-UAP (User Account Provisioning) | `code_security` account type requires credential validation via `git ls-remote` before account reaches `active` status |
| T1552.001 | Credentials in Files | D3-CH (Credential Hardening) | PAT passed via GIT_ASKPASS in GitValidator; never logged or stored in auth_config JSONB |

## Acceptance Criteria (Functional)
- [ ] `PROVIDER_TO_ACCOUNT_TYPE` in `constants.py` maps `github`, `gitlab`, `bitbucket` to `"code_security"`
- [ ] `VALID_ACCOUNT_TYPES["cloud"]` includes `"code_security"` in its frozenset
- [ ] New file `engines/onboarding/validators/git_validator.py` exists with `GitValidator` class
- [ ] `GitValidator.validate(repo_url, credential_type, credentials)` calls `git ls-remote <url> HEAD` with a 10-second timeout; returns `{"valid": True, "message": "..."}` on success, `{"valid": False, "message": "<sanitized error>"}` on failure
- [ ] PAT is passed to `git ls-remote` via GIT_ASKPASS (not embedded in URL)
- [ ] `GitValidator` is wired into `_get_validator()` in `cloud_accounts.py` for providers `github`, `gitlab`, `bitbucket`
- [ ] `auth_config` JSONB for `code_security` accounts is populated with keys: `repo_url`, `default_branch`, `project_name`, `vcs_platform`, `scan_types` (see Technical Notes for shape)
- [ ] Credential stored in Secrets Manager as `{credential_type: "pat_token"|"ssh_key", credentials: {pat_token: "...", repo_url: "..."}}` using the existing `SecretsManagerStorage.store()` pattern
- [ ] Validation failure returns HTTP 422 with `{"valid": false, "message": "<reason>"}` to the caller (not 500)
- [ ] An account with `account_type = 'code_security'` appears in `list_cloud_accounts` results when filtered by `account_type=code_security`

## Acceptance Criteria (Security — must pass bmad-security-reviewer)
- [ ] GitValidator subprocess stderr is sanitized: any substring matching `ghp_[A-Za-z0-9]+`, `glpat-[A-Za-z0-9_-]+`, or `BBDC-[A-Za-z0-9]+` is replaced with `***` before logging
- [ ] GitValidator never logs the PAT; it logs repo_url only (sanitized of credentials)
- [ ] GIT_ASKPASS helper created at mode `0700`, deleted in `finally`
- [ ] `repo_url` in `auth_config` passes the same SSRF allowlist validator from SECOPS-02 B-2 before being written to DB
- [ ] No plaintext credentials in DB — only `credential_ref` pointing to Secrets Manager path
- [ ] `account_type = 'code_security'` accepted in `VALID_ACCOUNT_TYPES["cloud"]` frozenset — no other tenant type allows it without explicit update
- [ ] New `code_security` accounts have `credential_validation_status = 'pending'` on creation; set to `'valid'` only after GitValidator returns `{"valid": true}`
- [ ] Timeout enforced: GitValidator raises `TimeoutError` (not hangs) if `git ls-remote` takes > 10s
- [ ] Base image pinned (no `latest`) — SLSA Level 1

## Technical Notes

### constants.py changes

```python
# Add to PROVIDER_TO_ACCOUNT_TYPE
"github":    "code_security",
"gitlab":    "code_security",
"bitbucket": "code_security",

# Add to VALID_ACCOUNT_TYPES["cloud"]
VALID_ACCOUNT_TYPES: Dict[str, FrozenSet[str]] = {
    "cloud":    frozenset({"cloud_csp", "vulnerability", "secops", "code_security",
                           "database", "middleware"}),
    ...
}
```

### auth_config JSONB shape for code_security accounts

```json
{
  "repo_url":       "https://github.com/org/repo",
  "default_branch": "main",
  "project_name":   "repo",
  "vcs_platform":   "github",
  "scan_types":     ["sast"]
}
```

`scan_types` defaults to `["sast"]`. DAST is added by user in the wizard (SECOPS-06).
`project_name` is derived from `repo_url.rstrip("/").split("/")[-1].removesuffix(".git")` at account creation time; stored in `auth_config` so downstream engines do not re-derive it.

### GitValidator location and signature

New file: `/Users/apple/Desktop/threat-engine/engines/onboarding/validators/git_validator.py`

```python
class GitValidator:
    """Validates git repository credentials by attempting git ls-remote HEAD."""

    ALLOWED_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})
    PAT_REDACT_PATTERN = re.compile(
        r'(ghp_[A-Za-z0-9]+|glpat-[A-Za-z0-9_-]+|BBDC-[A-Za-z0-9]+)'
    )

    def validate(
        self,
        repo_url: str,
        credential_type: str,
        credentials: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run git ls-remote HEAD to verify credentials.

        Args:
            repo_url: HTTPS git URL (must already pass SSRF validation).
            credential_type: 'pat_token' or 'ssh_key'.
            credentials: Dict with 'pat_token' or 'private_key' key.

        Returns:
            {'valid': bool, 'message': str}
        """
        ...
```

### Wiring into _get_validator() (cloud_accounts.py)

The onboarding router already calls `_get_validator(provider)` to select a validator class. Extend that mapping:

```python
from validators.git_validator import GitValidator

_VALIDATORS = {
    ...
    "github":    GitValidator,
    "gitlab":    GitValidator,
    "bitbucket": GitValidator,
}
```

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/onboarding/constants.py` — extend PROVIDER_TO_ACCOUNT_TYPE and VALID_ACCOUNT_TYPES
- `/Users/apple/Desktop/threat-engine/engines/onboarding/validators/git_validator.py` — create new
- `/Users/apple/Desktop/threat-engine/engines/onboarding/cloud_accounts.py` — wire GitValidator into `_get_validator()`

## Definition of Done
- [ ] Code implemented and builds locally
- [ ] Docker image built and pushed: `yadavanup84/threat-engine-onboarding-api:v-onboard-repoacct1`
- [ ] K8s manifest updated with new image tag
- [ ] kubectl apply and rollout status clean
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-qa: all functional acceptance criteria verified — including a live GitHub repo validation with a real PAT
- [ ] Post-deploy: `POST /api/v1/cloud-accounts` with `provider=github`, `account_type=code_security` creates account; `GET /api/v1/cloud-accounts?account_type=code_security` returns it
- [ ] Memory updated at `/Users/apple/.claude/projects/-Users-apple-Desktop-threat-engine/memory/`