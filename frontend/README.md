# Threat Engine UI — CSPM Portal

Enterprise Cloud Security Posture Management (CSPM) platform frontend built with **Next.js 15** and **React 19**, deployed on **AWS EKS**.

---

## Documentation

| Document | Audience | Description |
|----------|----------|-------------|
| [📘 User Guide](docs/USER_GUIDE.md) | Security analysts, compliance officers, executives | Feature walkthrough, onboarding, roles & permissions |
| [🛠 Developer Guide](docs/DEVELOPER_GUIDE.md) | Frontend engineers | Architecture, component library, API patterns, local setup |
| [🚀 DevOps Guide](docs/DEVOPS_GUIDE.md) | DevOps / platform engineers | Docker build, EKS deploy, CI/CD pipeline, runbooks |

---

## What is this?

Threat Engine UI is the web frontend for the CSPM platform. It connects to the **Django backend** (`cspm-backend`) and the suite of security engines running on EKS.

**Key capabilities:**
- 🔍 **Threat Detection** — MITRE ATT&CK mapped findings with risk scoring 0–100
- ✅ **Compliance** — 13+ frameworks (CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2)
- ☁️ **Multi-Cloud** — AWS, Azure, GCP, OCI, AliCloud, IBM Cloud
- 📦 **Inventory** — 40+ cloud services, asset relationships, drift detection
- 🔐 **IAM Security** — 57 IAM rules, identity posture scoring
- 🗄 **Data Security** — 62 data classification rules, sensitivity mapping
- 💻 **Code Security** — IaC scanning across 14 languages

---

## Live Environment

| Resource | URL |
|----------|-----|
| **UI** | `http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/ui` |
| **API** | `http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/cspm` |
| **EKS Cluster** | `vulnerability-eks-cluster` (ap-south-1 / Mumbai) |
| **Namespace** | `threat-engine-engines` |

---

## Local Development

```bash
# Install dependencies
npm install

# Create local env file
cp .env.local.example .env.local
# Edit .env.local — set NEXT_PUBLIC_API_BASE and NEXT_PUBLIC_AUTH_URL

# Start dev server
npm run dev
# → http://localhost:3000/ui
```

See the [Developer Guide](docs/DEVELOPER_GUIDE.md) for full local setup instructions, component docs, and coding conventions.

---

## Deploy to Production

```bash
# Build and push Docker image
docker build \
  --build-arg NEXT_PUBLIC_API_BASE=http://<ELB>/cspm \
  --build-arg NEXT_PUBLIC_AUTH_URL=http://<ELB>/cspm \
  --build-arg NEXT_PUBLIC_TENANT_ID=<tenant-id> \
  -t yadavanup84/threat-engine-ui:latest .

docker push yadavanup84/threat-engine-ui:latest

# Rolling deploy to EKS (zero-downtime)
kubectl rollout restart deployment/cspm-frontend -n threat-engine-engines
kubectl rollout status  deployment/cspm-frontend -n threat-engine-engines
```

For the full deployment guide including CI/CD pipeline setup, secrets management, and rollback procedures — see the [DevOps Guide](docs/DEVOPS_GUIDE.md).

---

## CI/CD

The GitHub Actions pipeline at [`.github/workflows/deploy-ui.yml`](../.github/workflows/deploy-ui.yml) automatically:

1. **Builds** the Docker image with production env vars baked in
2. **Pushes** `:latest` and `:<sha>` tags to DockerHub
3. **Applies** Kubernetes manifests to EKS
4. **Rolling restarts** both frontend and backend deployments
5. **Smoke tests** both health endpoints

**Triggers automatically** on push to `main` when `ui_samples/**` or Kubernetes manifests change.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | Next.js 15 (App Router, `output: 'standalone'`, `basePath: '/ui'`) |
| UI Library | React 19 |
| Styling | Tailwind CSS + CSS custom properties (design tokens) |
| Tables | TanStack React Table v8 |
| Charts | Recharts |
| Icons | Lucide React |
| Auth | Cookie sessions via Django backend (CSRF-protected) |
| State | React Context (Auth, Theme, GlobalFilter, Toast, SavedFilters) |

---

## Project Structure

```
src/
├── app/                    # Next.js App Router pages
│   ├── auth/login/        # Login page (email/password + SSO/SAML)
│   ├── dashboard/         # Executive security dashboard
│   ├── threats/           # Threat detection + analytics + threat hunting
│   ├── misconfig/         # Misconfigurations & check findings
│   ├── compliance/        # Compliance frameworks (7 supported)
│   ├── inventory/         # Asset inventory + drift detection
│   ├── iam/               # IAM security posture
│   ├── datasec/           # Data security & classification
│   ├── secops/            # Code & IaC security scanning
│   ├── vulnerabilities/   # CVE & vulnerability management
│   ├── risk/              # Risk quantification
│   └── scans/             # Scan history & management
│
├── components/
│   ├── layout/            # AppShell, Sidebar, GlobalFilterBar, TopBar
│   └── shared/            # DataTable, MetricStrip, Charts, Toast, EmptyState, Can, ...
│
└── lib/                   # API client, auth context, filter context, constants, utils
```

---

## Key Files

| File | Purpose |
|------|---------|
| `src/lib/api.js` | `getFromEngine(engine, path, params)` — routes to ELB |
| `src/lib/auth-context.js` | Authentication state, login/logout, session management |
| `src/lib/global-filter-context.jsx` | Provider/Account/Region/TimeRange scope filter |
| `src/lib/saved-filters-context.jsx` | Pinned named filter presets (localStorage) |
| `src/lib/constants.js` | Navigation, engine endpoints, mock data |
| `src/app/globals.css` | CSS custom properties (design tokens) |
| `Dockerfile` | Multi-stage production build |
| `next.config.mjs` | `basePath: '/ui'`, standalone output |

---

*Threat Engine UI — v1.0 | Last updated: 2026-03-07*
