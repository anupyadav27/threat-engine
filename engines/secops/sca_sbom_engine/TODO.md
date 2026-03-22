# SBOM Engine — Pending Work

This document tracks all open integration items and future enhancements for the
SBOM Engine. Each item includes owner, context, and enough detail for the
responsible team to implement without needing to read the engine source code.

---

## 1. SecOps Orchestrator — Private Git Repository Integration

**Owner:** SecOps Orchestrator team
**Priority:** High
**Status:** SBOM engine side complete — orchestrator side pending

### Background

The SBOM engine already supports private repos via a `git_token` field in the
scan request. The token is used only during the git clone and is never logged,
stored, or returned. The engine side requires no further changes.

The SecOps Orchestrator must act as the single credential owner — it fetches
the token from AWS Secrets Manager and injects it into the SBOM engine API call.

### Architecture

```
AWS Secrets Manager
      │
      │  GetSecretValue("sbom-engine/git/<credential_name>")
      ▼
SecOps Orchestrator  ──── POST /api/v1/sbom/scan-repo ────▶  SBOM Engine
  (fetches token)            { git_url, git_token }            (clone + scan)
                              internal EKS VPC only
```

### Implementation steps

**Step 1 — Store the git credential in AWS Secrets Manager (one-time per org)**

Naming convention: `sbom-engine/git/<credential_name>`

```bash
aws secretsmanager create-secret \
  --name "sbom-engine/git/github-myorg" \
  --description "GitHub PAT for MyOrg private repos" \
  --secret-string '{
    "token":    "ghp_xxxxxxxxxxxxxxxxxxxx",
    "username": "",
    "provider": "github"
  }'
```

Valid `provider` values: `github` | `gitlab` | `bitbucket` | `azure` | `generic`

`username` is only required for Bitbucket App Passwords and self-hosted servers
that need `username:token` format.

**Step 2 — Add IAM permission to the orchestrator's role**

The orchestrator's IAM role needs read access to SBOM engine git secrets:

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret"
  ],
  "Resource": "arn:aws:secretsmanager:ap-south-1:588989875114:secret:sbom-engine/git/*"
}
```

**Step 3 — Orchestrator call pattern (Python example)**

```python
import boto3
import json
import httpx

SBOM_ENGINE_URL = "http://sbom-engine:8002"   # internal K8s service name
SBOM_API_KEY    = "sbom-api-key-2024"          # use a dedicated orchestrator key in prod

def trigger_sbom_scan(git_url: str, credential_name: str, application_name: str, host_id: str):
    # 1. Fetch token from Secrets Manager
    sm = boto3.client("secretsmanager", region_name="ap-south-1")
    response = sm.get_secret_value(SecretId=f"sbom-engine/git/{credential_name}")
    cred = json.loads(response["SecretString"])

    # 2. Call SBOM engine — token stays on internal VPC network
    payload = {
        "git_url":          git_url,
        "application_name": application_name,
        "host_id":          host_id,
        "git_token":        cred["token"],
        "git_username":     cred.get("username", ""),
    }
    resp = httpx.post(
        f"{SBOM_ENGINE_URL}/api/v1/sbom/scan-repo",
        headers={"X-API-Key": SBOM_API_KEY},
        json=payload,
        timeout=180,
    )
    resp.raise_for_status()
    return resp.json()   # contains sbom_id, components, vulnerabilities, cyclonedx
```

**Step 4 — Production API key (recommended)**

For production, add a dedicated orchestrator API key so calls can be audited
per-caller. Update the `API_KEY` env var in `sbom_engine/deployment.yaml`:

```yaml
- name: API_KEY
  value: '["sbom-api-key-2024","orchestrator-key-prod"]'
```

The orchestrator uses `orchestrator-key-prod`; human testers keep using
`sbom-api-key-2024`.

### Provider-specific token formats (handled automatically by the engine)

| Provider | Token type | Notes |
|---|---|---|
| GitHub | Personal Access Token (classic or fine-grained) | Needs `repo` read scope |
| GitLab | Personal Access Token or Project Access Token | Needs `read_repository` scope |
| Bitbucket | App Password | Set `username` field to your Bitbucket username |
| Azure DevOps | Personal Access Token | Set `username` to any non-empty string |
| Self-hosted (Gitea, Forgejo, GitHub Enterprise) | PAT | Set `username` if server requires it |

---

## 2. CI/CD Pipeline Integration

**Owner:** Individual development teams
**Priority:** Medium
**Status:** Not implemented — API is ready, workflow files not created

### Background

Development teams can trigger an SBOM scan automatically on every git push
by calling the SBOM engine from their CI/CD pipeline. No orchestrator needed
for this path — the dev team manages their own token.

### GitHub Actions example

Create `.github/workflows/sbom-scan.yml` in any repository:

```yaml
name: SBOM Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  sbom-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan repository for vulnerabilities
        run: |
          RESULT=$(curl -s -X POST \
            http://a51f0ee45336749ada26775a04a1eed6-1195814996.ap-south-1.elb.amazonaws.com:8002/api/v1/sbom/scan-repo \
            -H "X-API-Key: ${{ secrets.SBOM_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d "{
              \"git_url\": \"${{ github.server_url }}/${{ github.repository }}.git\",
              \"application_name\": \"${{ github.repository }}\",
              \"host_id\": \"github-ci\",
              \"git_token\": \"${{ secrets.GITHUB_TOKEN }}\"
            }")
          echo "$RESULT" | python3 -c "
          import sys, json
          r = json.load(sys.stdin)
          print(f'SBOM ID: {r[\"sbom_id\"]}')
          print(f'Components: {r[\"components\"]}')
          print(f'Vulnerable: {r[\"vulnerable_components\"]}')
          if r['vulnerable_components'] > 0:
              print('WARNING: Vulnerable components found — review SBOM')
          "
```

Add `SBOM_API_KEY` as a GitHub Actions secret in the repository settings.

### GitLab CI example

Add to `.gitlab-ci.yml`:

```yaml
sbom-scan:
  stage: security
  script:
    - |
      curl -s -X POST \
        http://a51f0ee45336749ada26775a04a1eed6-1195814996.ap-south-1.elb.amazonaws.com:8002/api/v1/sbom/scan-repo \
        -H "X-API-Key: $SBOM_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"git_url\":\"$CI_REPOSITORY_URL\",\"application_name\":\"$CI_PROJECT_NAME\",\"host_id\":\"gitlab-ci\",\"git_token\":\"$CI_JOB_TOKEN\"}"
  only:
    - main
    - merge_requests
```

---

## 3. vul_agent — Automatic SBOM Scan on Agent Registration

**Owner:** vul_agent team
**Priority:** Medium
**Status:** Not implemented

### Background

The `vul_agent` already runs on every host and reports OS/package vulnerabilities
to `vul_engine`. An extension can make it also report the git remote URL of the
deployed application, which triggers an automatic SBOM scan without any manual step.

### Proposed flow

```
Host (vul_agent running)
  │
  │  1. Detect git remote of deployed app:
  │     git -C /opt/myapp remote get-url origin
  │     → https://github.com/myorg/myapp.git
  │
  │  2. POST to SBOM engine:
  │     { git_url, host_id, application_name, git_token (from agent config) }
  ▼
SBOM Engine  →  full SBOM + vulnerability enrichment stored
```

### Implementation notes for vul_agent team

- Agent config should include an optional `git_token` or `sbom_credential_name`
- Agent detects git remote by running `git remote get-url origin` in the
  application directory (configurable path)
- SBOM scan should be triggered alongside the existing OS/package scan
- If no git remote found, skip SBOM scan silently
- SBOM engine URL: `http://sbom-engine:8002` (internal) or the LoadBalancer URL

---

## 4. Dedicated API Keys per Caller

**Owner:** Platform / DevOps team
**Priority:** Low
**Status:** Not implemented — single shared key in use

### Background

Currently all callers share `sbom-api-key-2024`. For production, each caller
(orchestrator, CI/CD pipelines, vul_agent, human testers) should have its own
key so API access can be audited and revoked independently.

### Implementation

Update `API_KEY` env var in `sbom_engine/deployment.yaml`:

```yaml
- name: API_KEY
  value: '["sbom-api-key-2024","orchestrator-key-prod","cicd-key-prod","agent-key-sbom"]'
```

Move these keys to `vulnerability-db-secret` (or a dedicated K8s secret)
rather than plain env var for production security.
