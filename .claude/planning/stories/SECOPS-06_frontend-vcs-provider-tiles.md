# Story: SECOPS-06 — Frontend Wizard: GitHub / GitLab / Bitbucket Provider Tiles

## Status: done

## Context

The onboarding wizard currently shows a single generic `git` provider tile for all code repos. With SECOPS-03 shipping three distinct providers (`github`, `gitlab`, `bitbucket`) under the new `code_security` account type, the wizard must show three separate tiles so users see recognisable branding and so the `provider` field in the API call carries the correct value.

The wizard also needs to pass `account_id` (returned from `POST /cloud-accounts`) into the scan trigger call, and expose a `default_branch` input in the Repository step (defaulting to `main`). These are minor wiring changes on top of the existing step flow.

The `secops` account type entry in `ACCOUNT_TYPE_OPTIONS` is updated to reference `code_security` internally; the label remains "SecOps / Code" for the user.

**Prerequisites**: SECOPS-03 deployed (onboarding engine accepts `provider=github/gitlab/bitbucket` with `account_type=code_security`).

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [ ] Verification  [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [ ] GV Govern  [ ] ID Identify  [x] PR Protect  [ ] DE Detect  [ ] RS Respond  [ ] RC Recover
PR.DS-1, PR.AC-3, PR.AC-4

**CSA CCM v4 Domain(s)**
- CCM: IAM-02 (Identity Inventories — user-facing account creation), DSP-07

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | Provider tile selection | User selects `github` tile but submits `provider=bitbucket` in API call via devtools | Provider value is set from the tile key constant in the JS map, not from user free-text input |
| Info Disclosure | `account_id` in scan trigger | `account_id` returned from `POST /cloud-accounts` is passed into scan trigger; it could leak to unintended logs | `account_id` is an opaque UUID — not a secret; acceptable to include in API calls |
| Tampering | `default_branch` field | Attacker injects a branch name containing shell metacharacters | `default_branch` passed to API as a JSON string field; the onboarding engine stores it in `auth_config` JSONB — no shell execution on this path |
| DoS | Rapid wizard resubmission | User clicks Submit multiple times; multiple accounts created | Submit button disabled after first click; spinner shown during API call |

### PASTA (credentials/IAM/network — N/A for frontend-only change)
N/A — this story makes no backend auth or network path changes.

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | D3-UAP (User Account Provisioning) | Wizard enforces distinct provider selection; `account_type=code_security` is set in the POST body from the UI constant — not user-editable free text |

## Acceptance Criteria (Functional)
- [ ] When `account_type = 'code_security'` is selected in Step 1, the provider grid in Step 1 (or the provider selection sub-step) shows three tiles: `github` (black/#24292e), `gitlab` (#FC6D26 GitLab orange), `bitbucket` (#0052CC Atlassian blue) instead of the generic `git` tile
- [ ] Selecting a VCS tile sets `provider` to the tile key (`github`, `gitlab`, `bitbucket`) in the wizard state
- [ ] The `PROVIDERS` map in `OnboardingWizard.jsx` gains three entries: `github`, `gitlab`, `bitbucket` (the generic `git` entry may be retained for backwards compat or removed)
- [ ] `CREDENTIAL_FIELDS` map gains keys `github_pat_token`, `github_ssh_key`, `gitlab_pat_token`, `gitlab_ssh_key`, `bitbucket_pat_token`, `bitbucket_ssh_key` — same field shapes as existing `git_pat_token` / `git_ssh_key` but keyed per-provider (allows placeholder text customisation per platform)
- [ ] Repository step (Step 2 for `code_security`) has a `default_branch` input field. It defaults to `main`. It is optional.
- [ ] `POST /api/v1/cloud-accounts` body includes `provider` (github|gitlab|bitbucket), `account_type: "code_security"`, `auth_config.default_branch` from the wizard input
- [ ] `account_id` returned from `POST /cloud-accounts` is stored in wizard state and passed in the scan trigger call as `account_id`
- [ ] After successful account creation, the scan trigger call does NOT pass `repo_url` in the body (it is resolved from `auth_config` by the engine — SECOPS-04)
- [ ] Account type label displayed to user remains "SecOps / Code" (or similar) — internal `code_security` key is not shown
- [ ] Submit button is disabled during the API call; re-enabled on error to allow retry

## Acceptance Criteria (Security — must pass bmad-security-reviewer)
- [ ] PAT / SSH key fields have `type="password"` (`secret: true`) — not visible in plaintext in the form
- [ ] PAT / SSH key values are not stored in component state beyond the wizard session (cleared on wizard close/unmount)
- [ ] `provider` value in the POST body comes from the constant map key (not from user text input)
- [ ] `account_type` value hardcoded to `"code_security"` in the wizard POST body for VCS providers — not user-editable
- [ ] No `console.log` or debug output that could expose PAT values
- [ ] `default_branch` field accepts printable characters only; validated client-side with regex `^[a-zA-Z0-9._/-]{1,128}$` before POST
- [ ] `X-Auth-Context` header forwarded correctly by `postToEngine` (existing pattern — verify not broken)

## Technical Notes

### Provider tile additions (OnboardingWizard.jsx)

In the `PROVIDERS` map, add after the `k8s` entry:

```js
// VCS providers — used when account_type = 'code_security'
github:    { name: 'GitHub',    full: 'GitHub Repository',    color: '#24292E' },
gitlab:    { name: 'GitLab',    full: 'GitLab Repository',    color: '#FC6D26' },
bitbucket: { name: 'Bitbucket', full: 'Bitbucket Repository', color: '#0052CC' },
```

The existing `git` entry can be kept as a fallback for any legacy state but should not be shown in the UI tile grid.

### VCS provider set

Add a constant:

```js
const VCS_PROVIDERS = {
  github:    PROVIDERS.github,
  gitlab:    PROVIDERS.gitlab,
  bitbucket: PROVIDERS.bitbucket,
};
const VCS_PROVIDER_SET = new Set(Object.keys(VCS_PROVIDERS));
```

### Provider grid conditional rendering

In the provider tile grid (Step 1), detect when `accountType === 'code_security'` (or when the selected account type maps to `code_security`) and render the VCS grid instead of the full cloud provider grid:

```jsx
const providerMap = accountType === 'code_security'
  ? VCS_PROVIDERS
  : accountType === 'database'
    ? DB_PROVIDERS
    : CLOUD_PROVIDERS;
```

### CREDENTIAL_FIELDS additions

```js
github_pat_token: [
  { key: 'repo_url',  label: 'Repository URL',          placeholder: 'https://github.com/org/repo', secret: false },
  { key: 'pat_token', label: 'Personal Access Token',   placeholder: 'ghp_…',                       secret: true  },
],
github_ssh_key: [
  { key: 'repo_url',    label: 'Repository URL',        placeholder: 'git@github.com:org/repo.git', secret: false },
  { key: 'private_key', label: 'SSH Private Key',       placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----…', secret: true, textarea: true },
],
// gitlab_pat_token / gitlab_ssh_key / bitbucket_pat_token / bitbucket_ssh_key — same shape
// placeholder text should reference the correct platform
```

### default_branch field addition to Step 2 (Repository step)

In the Repository step for `code_security`, add a `default_branch` field after `repo_url`:

```jsx
<Field
  def={{ key: 'default_branch', label: 'Default Branch', placeholder: 'main', optional: true, secret: false }}
  value={creds.default_branch || 'main'}
  onChange={v => setCreds(c => ({ ...c, default_branch: v || 'main' }))}
/>
```

### account_id flow in wizard submit

After `POST /cloud-accounts` succeeds, extract `account_id` from the response and store it in wizard state. Pass it in the scan trigger payload:

```js
// After account creation
const { account_id } = createdAccount;
setWizardState(s => ({ ...s, account_id }));

// In scan trigger call
const scanPayload = {
  account_id,           // required (SECOPS-04)
  tenant_id,
  scan_run_id: ...,
  branch: creds.default_branch || 'main',
  // repo_url is intentionally omitted — engine resolves from auth_config
};
```

### auth_config in POST /cloud-accounts payload

```js
const accountPayload = {
  provider,            // 'github' | 'gitlab' | 'bitbucket'
  account_type: 'code_security',
  account_name: projectName,
  auth_config: {
    repo_url:       creds.repo_url,
    default_branch: creds.default_branch || 'main',
    project_name:   projectName,
    vcs_platform:   provider,
    scan_types:     ['sast'],
  },
  credential_type: authMethod,   // 'pat_token' | 'ssh_key'
  // credentials go into Secrets Manager via onboarding engine
};
```

## Key Files
- `/Users/apple/Desktop/threat-engine/frontend/src/components/domain/OnboardingWizard.jsx` — primary change

## Definition of Done
- [ ] Code implemented and builds locally (`npm run build` succeeds with no TypeScript/lint errors)
- [ ] Docker image built and pushed: `yadavanup84/cspm-frontend:v-secops-repoacct1`
- [ ] K8s manifest updated with new image tag
- [ ] kubectl apply and rollout status clean
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-qa: manual wizard walkthrough — create a GitHub account with a real PAT; verify `account_type=code_security` in DB; verify scan triggers with `account_id`; verify `secops_latest_scan` row upserted
- [ ] Post-deploy: CSPM portal onboarding wizard shows GitHub/GitLab/Bitbucket tiles when "SecOps / Code" is selected
- [ ] Memory updated at `/Users/apple/.claude/projects/-Users-apple-Desktop-threat-engine/memory/`