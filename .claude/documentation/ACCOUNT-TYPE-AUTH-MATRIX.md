# Account Type — Auth Method Matrix

**Source of truth:** `catalog/account_types/auth_requirements.yaml`  
**Date:** 2026-05-03

This document is the human-readable view of the YAML catalog.
The frontend wizard reads the YAML directly to render the correct credential form.

---

## Quick Reference Matrix

| Technology | Tenant Type | Auth Model | Creds Stored? | Rotation Needed | What Admin Must Prepare |
|-----------|------------|-----------|--------------|-----------------|------------------------|
| **AWS (access key)** | cloud | API Secret | ✅ Secrets Manager | Yes | IAM user + SecurityAudit policy + access keys |
| **AWS (assume-role)** | cloud | IAM Role | ❌ No secret stored | No | Cross-account IAM role ARN + external ID |
| **Azure** | cloud | API Secret | ✅ Secrets Manager | Yes | App registration + client secret + Reader role |
| **GCP** | cloud | File Upload | ✅ Secrets Manager | Yes | Service account + JSON key file download |
| **OCI** | cloud | File Upload | ✅ Secrets Manager | Yes | API signing key pair + config file |
| **AliCloud** | cloud | API Secret | ✅ Secrets Manager | Yes | RAM user + ReadOnlyAccess + access key |
| **IBM Cloud** | cloud | API Secret | ✅ Secrets Manager | Yes | Service ID + Viewer role + API key |
| **K8s (kubeconfig)** | cloud | File Upload | ✅ Secrets Manager | Yes | ServiceAccount + cluster-reader + kubeconfig |
| **K8s (in-cluster)** | cloud | IAM Role | ❌ Pod service account | No | ClusterRoleBinding for scanner pod |
| **GitHub (PAT)** | secops | Git Token | ✅ Secrets Manager | Yes | PAT with repo:read scope |
| **GitHub (App)** | secops | Git Token | ❌ App token auto-renews | No | Install CSPM GitHub App on org |
| **GitHub (SSH)** | secops | Git Token | ✅ Secrets Manager | Yes | Deploy key with read access on repo |
| **GitLab (PAT)** | secops | Git Token | ✅ Secrets Manager | Yes | PAT with read_repository scope |
| **GitLab (Deploy Token)** | secops | Git Token | ✅ Secrets Manager | Yes | Deploy token on project |
| **Bitbucket** | secops | Git Token | ✅ Secrets Manager | Yes | App password with Repositories: Read |
| **Azure DevOps** | secops | Git Token | ✅ Secrets Manager | Yes | PAT with Code: Read scope |
| **Vulnerability Agent** | vulnerability | Agent (PKCE) | ❌ No cloud creds | No | sudo access on target + outbound HTTPS 443 |
| **Database Agent** | database | Agent (PKCE) | ❌ No cloud creds | No | Read-only DB user + outbound HTTPS 443 |
| **Middleware Agent** | middleware | Agent (PKCE) | ❌ No cloud creds | No | Config file read access + outbound HTTPS 443 |
| **K8s Technology** | technology | File Upload | ✅ Secrets Manager | Yes | cluster-reader + kubeconfig |

---

## Auth Model Definitions

### API Secret
Static credentials stored encrypted in AWS Secrets Manager after validation.
- **Path:** `threat-engine/account/{account_id}`
- **Validation:** Real CSP API call at onboarding time
- **Credential health-check:** Weekly Celery task re-validates stored creds
- **On expiry:** Schedule paused + email alert + `credential_validation_status='expired'`

### IAM Role (No Secret)
Cross-account assume-role or in-cluster pod identity. No long-lived secret stored on the platform.
- **AWS assume-role:** Platform's AWS account (588989875114) assumes the customer's role
- **K8s in-cluster:** Pod uses its own service account — zero external credentials
- **No rotation needed** — tokens are short-lived and auto-renewed

### File Upload
Credential file (JSON, PEM, kubeconfig) uploaded once and stored encrypted in Secrets Manager.
- Same encryption as API secrets
- User must manually rotate when the file credential expires

### Git Token
Repository access token stored encrypted in Secrets Manager.
- Validated by attempting to list refs on the repository
- GitHub App is the recommended method for orgs — tokens auto-renew
- PATs and deploy tokens require manual rotation

### Agent (PKCE Bootstrap)
No cloud credentials stored on the platform. Zero credential attack surface on the CSPM side.
- Admin generates a one-time bootstrap token in the wizard
- Bootstrap token uses PKCE: only `code_challenge` stored, never the raw token
- Agent installs on target system, exchanges `registration_id + code_verifier` once
- Ongoing: agent uses its own `agent_token` (separate from bootstrap) for heartbeats
- **What gets scanned:** The agent scans locally (DB config, package list, middleware config)
  and sends only the findings — never raw credentials or config file contents

---

## Per-Technology Admin Preparation Checklist

### AWS — Access Key Method
```
☐ 1. Create IAM user with programmatic access only
       IAM → Users → Add user → Programmatic access
☐ 2. Attach SecurityAudit managed policy
       Policy ARN: arn:aws:iam::aws:policy/SecurityAudit
☐ 3. (Optional) Attach ReadOnlyAccess for broader discovery
       Policy ARN: arn:aws:iam::aws:policy/ReadOnlyAccess
☐ 4. Generate access keys → copy Access Key ID + Secret Access Key
☐ 5. Paste both values in the CSPM onboarding wizard
```

### AWS — IAM Role Method (Recommended for Production)
```
☐ 1. Go to IAM → Roles → Create role → Another AWS account
       Trusted account ID: 588989875114 (CSPM platform)
       ☐ Check "Require external ID" → enter the ID shown in the CSPM wizard
☐ 2. Attach SecurityAudit managed policy to the role
☐ 3. Copy the Role ARN from the role Overview page
       Format: arn:aws:iam::YOUR_ACCOUNT_ID:role/YOUR_ROLE_NAME
☐ 4. Paste Role ARN (and External ID) in the CSPM wizard
```

### Azure — Service Principal
```
☐ 1. Azure AD → App registrations → New registration
       Name: CSPM-Audit, Account type: Single tenant
☐ 2. Note: Application (client) ID, Directory (tenant) ID
☐ 3. Certificates & secrets → New client secret
       Set expiry → Copy secret VALUE (shown once only)
☐ 4. Subscriptions → your subscription → Access control (IAM)
       Add role assignment → Reader → Assign to your app registration
☐ 5. Note: Subscription ID
☐ 6. Enter all four values in the CSPM wizard
```

### GCP — Service Account
```
☐ 1. IAM & Admin → Service Accounts → Create
       Name: cspm-audit-sa
☐ 2. IAM & Admin → IAM → Add principal → service account email
       Role: Viewer (or Security Reviewer)
☐ 3. Service Accounts → select account → Keys → Add Key → JSON
       Download the .json file
☐ 4. Upload the JSON file in the CSPM wizard
```

### OCI
```
☐ 1. Profile → API Keys → Add API Key → Generate API key pair
       Download both public and private key files
☐ 2. After uploading public key: copy the shown config file snippet
       Save as a file named 'config'
☐ 3. Upload both 'config' file and private key .pem in the CSPM wizard
☐ 4. Ensure OCI user has read policy on tenancy:
       Allow group Auditors to read all-resources in tenancy
```

### AliCloud
```
☐ 1. RAM console → Users → Create User → Programmatic access
☐ 2. RAM console → Users → select user → Add Permissions → ReadOnlyAccess
☐ 3. Users → select user → Authentication → Create AccessKey
       Copy AccessKey ID and AccessKey Secret
☐ 4. Enter both in the CSPM wizard
```

### GitHub (PAT)
```
☐ 1. GitHub → Settings → Developer settings → Personal access tokens (classic)
☐ 2. Generate new token → Scopes: repo (if private), read:org (if org repos)
☐ 3. Copy token (shown once)
☐ 4. Enter token + repo URL in CSPM wizard
```

### GitHub (App — Recommended for Orgs)
```
☐ 1. In CSPM wizard click "Install GitHub App"
☐ 2. Authorize the CSPM GitHub App on your GitHub organization
☐ 3. Select which repositories to grant access to (or "All repositories")
☐ 4. Wizard auto-populates Installation ID — no manual token needed
```

### GitLab (Deploy Token — Recommended)
```
☐ 1. GitLab project → Settings → Repository → Deploy tokens
☐ 2. Create token: Name: cspm-scanner, Scope: read_repository
☐ 3. Copy username and token value (shown once)
☐ 4. Enter both + repo URL in CSPM wizard
```

### Bitbucket (App Password)
```
☐ 1. Bitbucket → Personal settings → App passwords → Create
☐ 2. Permission: Repositories: Read
☐ 3. Copy password (shown once)
☐ 4. Enter username + app password + repo URL in CSPM wizard
```

### Kubernetes (Kubeconfig)
```
☐ 1. Create ClusterRole with read access:
       kubectl create clusterrole cspm-reader --verb=get,list,watch --resource='*'
☐ 2. Create ServiceAccount:
       kubectl create serviceaccount cspm-scanner -n kube-system
☐ 3. Bind ClusterRole to ServiceAccount:
       kubectl create clusterrolebinding cspm-reader-binding \
         --clusterrole=cspm-reader \
         --serviceaccount=kube-system:cspm-scanner
☐ 4. Generate kubeconfig:
       TOKEN=$(kubectl -n kube-system create token cspm-scanner --duration=87600h)
       # Build kubeconfig file with this token and cluster endpoint
☐ 5. Upload the kubeconfig file in CSPM wizard
```

### Vulnerability / Database / Middleware Agents
```
☐ 1. Ensure target system has outbound HTTPS (port 443) to CSPM platform
☐ 2. For Database agent: create read-only DB user on the target database
       (credentials configured locally on agent — NOT sent to CSPM platform)
☐ 3. Ensure sudo/root access on the target system for agent installation
☐ 4. In CSPM wizard: click "Generate Install Command"
       → A time-limited install command is shown (valid 15 minutes)
☐ 5. Run the install command on the target system
☐ 6. Wizard shows "Waiting for agent to register..." → green once connected
```

---

## Frontend Wizard Logic

The wizard reads `catalog/account_types/auth_requirements.yaml` at load time.
Based on the selected `tenant_type` + `provider` + `auth_model_id`:

```
1. Filter account_types by tenant_type
2. Show provider grid (AWS / Azure / GCP / etc.)
3. On provider select: show available auth_models for that provider
4. On auth_model select:
     IF auth_model = 'agent':
       → Show "Prerequisites checklist"
       → Show "Generate Install Command" button (calls POST /agent-token)
       → Show install command + waiting spinner
     ELSE:
       → Show admin_prerequisites steps (numbered checklist)
       → Then show credential_fields form
       → On submit: POST /cloud-accounts/{id}/credentials
5. On validation success:
     → Show green check + detected account_id
     → Show missing_permissions warnings (if any)
     → Proceed to schedule creation step
```

---

## Engines by Account Type

| Account Type | Engines That Run |
|-------------|-----------------|
| cloud (AWS/Azure/GCP/OCI/AliCloud/IBM) | discovery, inventory, check, threat, compliance, iam, datasec, network, risk |
| cloud (K8s) | discovery, inventory, check, threat, compliance, container_security, risk |
| secops (GitHub/GitLab/Bitbucket/ADO) | secops |
| vulnerability (agent) | vulnerability |
| database (agent) | dbsec |
| middleware (agent) | check (middleware rules) |
| technology (K8s) | technology |

Engines in `engines_requested` are stored on the `schedules` row — the admin can customize
which engines run on each schedule (e.g. daily compliance-only vs weekly full scan).
