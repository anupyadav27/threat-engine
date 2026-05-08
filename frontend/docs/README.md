# Threat Engine UI Documentation

Enterprise Cloud Security Posture Management (CSPM) portal — frontend documentation hub.

---

## Choose your guide

<div style="display:flex;gap:24px;flex-wrap:wrap;margin-top:24px">

<div style="flex:1;min-width:200px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;padding:24px">

### 📘 User Guide

For **security analysts**, compliance officers, and executives.

- Platform overview & onboarding
- All 13+ security pages walkthrough
- Compliance frameworks explained
- Roles & permissions
- Glossary of terms

[→ Open User Guide](USER_GUIDE.md)

</div>

<div style="flex:1;min-width:200px;background:#f5f3ff;border:1px solid #ddd6fe;border-radius:12px;padding:24px">

### 🛠 Developer Guide

For **frontend engineers** building and extending the UI.

- Architecture & tech stack
- Local setup in 5 minutes
- Full component library reference
- API integration patterns
- Adding new pages & components

[→ Open Developer Guide](DEVELOPER_GUIDE.md)

</div>

<div style="flex:1;min-width:200px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;padding:24px">

### 🚀 DevOps Guide

For **DevOps & platform engineers** operating the stack on EKS.

- Docker build & push
- Kubernetes deploy & rollback
- GitHub Actions CI/CD pipeline
- Secrets management
- Monitoring & runbooks

[→ Open DevOps Guide](DEVOPS_GUIDE.md)

</div>

</div>

---

## Quick facts

| Property | Value |
|----------|-------|
| Framework | Next.js 15 (App Router) |
| UI | React 19 + Tailwind CSS |
| Auth | Django backend (cookie sessions) |
| Deployment | AWS EKS, ap-south-1 |
| CI/CD | GitHub Actions → DockerHub → EKS |
| Supported clouds | AWS, Azure, GCP, OCI, AliCloud, IBM |
| Compliance frameworks | 13+ (CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2…) |

---

## Live URL

```
http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/ui
```
