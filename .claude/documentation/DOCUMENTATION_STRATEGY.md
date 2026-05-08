# CSPM Platform — Documentation Strategy

> **Purpose**: Defines every document type the platform should publish, audience, access tier, ownership, and how to keep it current. Benchmarked against Wiz, Orca Security, and Prisma Cloud.
> **Status**: Draft v1 — 2026-05-08
> **Decision point**: Which docs move to public portal in V1 launch

---

## 1. Documentation Ecosystem Map

The full set of docs organized by who produces them and who consumes them.

```mermaid
graph TD
    subgraph PRODUCERS["📝 Who Creates"]
        ENG[Engineering Team]
        SEC[Security Team]
        PM[Product / PM]
        DEVREL[DevRel / Tech Writer]
    end

    subgraph INTERNAL["🔒 Internal Only"]
        I1[CSPM Constitution]
        I2[Agent Binding Rules]
        I3[Database Schema]
        I4[Infrastructure Guide]
        I5[Secrets & Credentials]
        I6[Operations Runbook]
        I7[Incident Runbook]
        I8[RBAC Matrix]
        I9[Engine Prerequisite Data]
        I10[Testing & Quality Gates]
        I11[Architecture Decisions ADRs]
    end

    subgraph GATED["🔐 Login-Gated Customer Docs"]
        G1[Getting Started per CSP]
        G2[Cloud Account Onboarding]
        G3[RBAC & SSO Setup Guide]
        G4[Alert Rules & Notifications]
        G5[Compliance Report Generation]
        G6[Integration Setup Guides]
        G7[Vulnerability Management Guide]
        G8[Container & K8s Security Guide]
        G9[DSPM / Data Security Guide]
        G10[CIEM / Identity Guide]
        G11[Network Security Guide]
        G12[IaC Scanning & CI/CD Guide]
        G13[Custom Rule Authoring]
        G14[MSSP / Multi-Tenant Guide]
        G15[Release Notes Archive]
    end

    subgraph PUBLIC["🌐 Fully Public"]
        P1[Trust Center]
        P2[Public API Reference]
        P3[Rule / Policy Library]
        P4[Compliance Framework Coverage]
        P5[Architecture Overview]
        P6[Multi-CSP Onboarding Overview]
        P7[Monthly Release Notes]
        P8[Security Posture Blog / Academy]
        P9[SLA & SLO Reference]
        P10[Data Retention Policy]
        P11[Integration Catalog]
        P12[CLI Reference]
    end

    ENG --> I1 & I3 & I4 & I5 & I6 & I7 & I11
    SEC --> I2 & I8 & I10
    PM --> I9 & P9 & P10
    DEVREL --> G1 & G2 & G3 & G4 & G5 & G6 & G7 & G8 & G9 & G10 & G11 & G12 & G13 & G14
    DEVREL --> P2 & P3 & P4 & P5 & P6 & P7 & P8 & P11 & P12
    SEC --> P1

    style PUBLIC fill:#d4edda,stroke:#28a745,color:#000
    style GATED fill:#d1ecf1,stroke:#17a2b8,color:#000
    style INTERNAL fill:#f8d7da,stroke:#dc3545,color:#000
    style PRODUCERS fill:#fff3cd,stroke:#ffc107,color:#000
```

---

## 2. Publication Tier Model

Three tiers define access control. Decision rule: **if a prospect can't see it, it can't help win the deal.**

```mermaid
flowchart LR
    subgraph T1["🌐 Tier 1 — Fully Public\n(No login, indexed by Google)"]
        direction TB
        T1A["Trust Center\n(SOC2, ISO, Pentest, CAIQ)"]
        T1B["Public API Reference\n(OpenAPI/pan.dev style)"]
        T1C["Rule / Policy Library\n(1918+ rules, per CSP)"]
        T1D["Monthly Release Notes"]
        T1E["Architecture Overview"]
        T1F["Compliance Framework Matrix"]
        T1G["SLA & SLO Reference"]
        T1H["Data Retention Policy"]
        T1I["Integration Catalog"]
        T1J["CLI Reference"]
    end

    subgraph T2["🔐 Tier 2 — Customer Portal\n(Login required, active subscription)"]
        direction TB
        T2A["Per-CSP Onboarding Guides"]
        T2B["RBAC & SSO Setup"]
        T2C["Alert & Notification Config"]
        T2D["Compliance Report Generation"]
        T2E["Integration Setup Guides\n(Jira, Splunk, ServiceNow...)"]
        T2F["Vulnerability Management"]
        T2G["Container & K8s Security"]
        T2H["DSPM / Data Security"]
        T2I["CIEM / Identity Entitlement"]
        T2J["Network Security Guide"]
        T2K["IaC / CI-CD Scanning"]
        T2L["Custom Rule Authoring"]
        T2M["MSSP / Multi-Tenant"]
    end

    subgraph T3["🔒 Tier 3 — Internal Only\n(Engineering & Ops teams)"]
        direction TB
        T3A["CSPM Constitution"]
        T3B["Database Schema"]
        T3C["Infrastructure / EKS"]
        T3D["Secrets & Credentials"]
        T3E["Operations & Incident Runbooks"]
        T3F["Agent Binding Rules"]
        T3G["Testing Quality Gates"]
        T3H["Architecture Decision Records"]
    end

    T1 -->|"Converts prospects\nSEO + trust signals"| T2
    T2 -->|"Supports customers\nReduces support load"| T3

    style T1 fill:#d4edda,stroke:#28a745,color:#000
    style T2 fill:#d1ecf1,stroke:#17a2b8,color:#000
    style T3 fill:#f8d7da,stroke:#dc3545,color:#000
```

---

## 3. Competitor Benchmark — What They Publish

### 3.1 Access Model Comparison

```mermaid
quadrantChart
    title Doc Openness vs Doc Depth (Competitor Benchmark)
    x-axis "Login-Gated" --> "Fully Public"
    y-axis "Shallow / Marketing" --> "Deep / Technical"
    quadrant-1 "Best for Developer Adoption"
    quadrant-2 "Open but Thin"
    quadrant-3 "Hidden and Thin"
    quadrant-4 "Deep but Closed"
    Prisma Cloud: [0.85, 0.90]
    Wiz: [0.15, 0.85]
    Orca: [0.10, 0.80]
    Our Platform Today: [0.05, 0.40]
    Our Platform Target: [0.75, 0.85]
```

### 3.2 Doc Type Coverage Matrix

| Doc Type | Wiz | Orca | Prisma | **Us Today** | **Gap** |
|---|:---:|:---:|:---:|:---:|---|
| Cloud onboarding per CSP | 🔐 | 🔐 | 🌐 | ❌ | Build + publish |
| Rule / policy library | 🔐 | 🔐 | 🌐 | ❌ | **High priority** |
| API reference | 🔐 | 🔐 | 🌐 | 🔒 | Make public |
| Compliance framework coverage | 🔐 | 🔐 | 🌐 | 🔒 | Make public |
| RBAC & SSO guide | 🔐 | 🔐 | 🌐 | 🔒 | Move to portal |
| Vulnerability management guide | 🔐 | 🔐 | 🌐 | ❌ | Build |
| Container & K8s security | 🔐 | 🔐 | 🌐 | ❌ | Build |
| CIEM / identity guide | 🔐 | 🔐 | 🌐 | ❌ | Build |
| DSPM / data security guide | 🔐 | 🔐 | 🌐 | ❌ | Build |
| Network security guide | 🔐 | 🔐 | 🌐 | ❌ | Build |
| IaC / CI-CD scanning guide | 🔐 | 🔐 | 🌐 | ❌ | Build |
| Custom rule authoring | 🔐 | 🔐 | 🌐 | 🔒 | Move to portal |
| Integration setup guides | 🔐 | 🔐 | 🌐 | ❌ | Build per integration |
| SIEM integration docs | 🔐 | 🔐 | 🌐 | ❌ | Build |
| Alert & notification config | 🔐 | 🔐 | 🌐 | ❌ | Build |
| **Trust Center** | **🌐** | **🌐** | partial | **❌** | **Critical gap** |
| SOC 2 Type II report | 🌐 | 🌐 | ❌ | ❌ | **Critical** |
| Pentest report (public PDF) | 🌐 | 🌐 | ❌ | ❌ | **Critical** |
| CAIQ / SIG Lite self-assessment | 🌐 | 🌐 | ❌ | ❌ | **Critical** |
| Subprocessor list | 🌐 | 🌐 | ❌ | ❌ | Required for GDPR |
| Data flow diagram | 🌐 | ❌ | ❌ | ❌ | Build |
| **Release notes (public)** | partial | 🔐 | **🌐** | **❌** | **Critical gap** |
| SLA & SLO reference | 🔐 | 🔐 | ❌ | ❌ | Build |
| Data retention policy | 🔐 | 🔐 | ❌ | ❌ | GDPR/SOC2 required |
| CLI reference | 🌐 | ❌ | 🌐 | ❌ | Build (product gap too) |
| Query language reference | ❌ | 🔐 (Sonar) | 🌐 (RQL) | ❌ | Depends on product |
| Terraform provider | ❌ | ❌ | 🌐 | ❌ | Future |
| Education / Academy content | 🌐 | partial | ❌ | ❌ | Future |
| MSSP / multi-tenant guide | 🔐 | 🔐 | 🌐 | ❌ | Build |
| Architecture overview (public) | 🔐 | 🔐 | 🌐 | 🔒 | Make public version |

**Legend**: 🌐 Public · 🔐 Login-gated · 🔒 Internal only · ❌ Does not exist

---

## 4. Priority Roadmap

```mermaid
gantt
    title Documentation Publication Roadmap
    dateFormat  YYYY-MM-DD
    axisFormat  %b %Y

    section P0 — Unblocks Sales (Now)
    Trust Center (SOC2 + ISO + Pentest + CAIQ)   :crit, p0a, 2026-05-08, 21d
    Monthly Release Notes (public)                :crit, p0b, 2026-05-08, 14d
    Subprocessor List + Data Retention Policy     :crit, p0c, 2026-05-08, 7d

    section P1 — Customer Portal V1
    Per-CSP Onboarding Guides (6 CSPs)            :p1a, after p0b, 30d
    Public API Reference (OpenAPI publish)         :p1b, after p0b, 14d
    Public Rule Library (1918+ rules rendered)    :p1c, after p0b, 30d
    Compliance Framework Coverage Matrix          :p1d, after p0b, 14d
    RBAC & SSO Setup Guide                        :p1e, after p0a, 14d
    Architecture Overview (public version)        :p1f, after p0b, 7d

    section P2 — Feature Guides (Sprint-paired)
    Vulnerability Management Guide               :p2a, after p1a, 21d
    Container & K8s Security Guide               :p2b, after p1a, 21d
    CIEM / Identity Entitlement Guide            :p2c, after p1a, 21d
    DSPM / Data Security Guide                   :p2d, after p1a, 21d
    Network Security Guide                       :p2e, after p1a, 21d
    IaC / CI-CD Scanning Guide                   :p2f, after p1a, 14d
    Alert Rules & Notifications Guide            :p2g, after p1e, 14d
    Integration Setup Guides (Jira/Splunk/SIEM)  :p2h, after p1b, 30d

    section P3 — Depth & Differentiation
    SLA & SLO Reference                          :p3a, after p2a, 14d
    CLI Reference                                :p3b, after p2f, 21d
    MSSP / Multi-Tenant Guide                    :p3c, after p2a, 21d
    Custom Rule Authoring (public)               :p3d, after p3b, 14d
    Education / Academy Content                  :p3e, after p3a, 60d
    Query Language Reference                     :p3f, after p3b, 30d
```

---

## 5. Doc Type Taxonomy

Every document we publish belongs to one of these seven types. Knowing the type tells you who writes it, how often it changes, and who reviews it.

```mermaid
mindmap
  root((CSPM Docs))
    Trust & Compliance
      Trust Center
      SOC2 / ISO Certs
      Pentest Report
      CAIQ Self-Assessment
      Subprocessors
      Data Retention Policy
      SLA & SLO
    Conceptual
      Architecture Overview
      Security Graph Concepts
      Data Flow Diagrams
      Multi-Cloud Strategy
    Onboarding & Setup
      Per-CSP Connector Guides
      RBAC & SSO Setup
      Scanner Agent Install
      First Scan Walkthrough
    Reference
      API Reference
      Rule / Policy Library
      CLI Reference
      Compliance Framework Matrix
      Query Language Reference
      Integration Catalog
    How-To Guides
      Per-Feature Guides
        Vulnerability Management
        Container Security
        CIEM / Identity
        DSPM / Data Security
        Network Security
        IaC Scanning
      Per-Integration Guides
        Jira
        Slack
        Splunk
        ServiceNow
        PagerDuty
        AWS Security Hub
    Operational
      Alert Rules & Notifications
      Report Generation
      Custom Rule Authoring
      MSSP Multi-Tenant
      Audit Logs
    Release & Change
      Monthly Release Notes
      Changelog per Engine
      Deprecation Registry
      Migration Guides
```

---

## 6. Keep-Current Model

The biggest risk for any doc program is drift between code and docs. These rules prevent it.

```mermaid
flowchart TD
    A[Engineer writes code change] --> B{Does it change any of:}
    B -->|API endpoint| C[Update API Reference]
    B -->|DB schema| D[Update DATABASE-SCHEMA.md]
    B -->|New rule / check| E[Update Rule Library page]
    B -->|New integration| F[Update Integration Catalog]
    B -->|New feature| G[Update relevant How-To guide]
    B -->|Image tag push| H[Write CHANGELOG entry]
    B -->|Breaking change| I[Add to Deprecation Registry]

    C & D & E & F & G & H & I --> J[Doc PR checklist gate at Code Review]
    J --> K{Checklist complete?}
    K -->|No| L[PR blocked — return to dev]
    K -->|Yes| M[Merge approved]

    M --> N[Monthly: compile CHANGELOG into Release Notes]
    N --> O[Quarterly: stale doc audit\nflag any doc untouched > 90 days]
    O --> P[Annual: full doc review\nagainst new competitor benchmark]

    style J fill:#fff3cd,stroke:#ffc107,color:#000
    style L fill:#f8d7da,stroke:#dc3545,color:#000
    style M fill:#d4edda,stroke:#28a745,color:#000
```

### Doc Ownership Table

| Doc Category | Primary Owner | Reviewer | Trigger to Update |
|---|---|---|---|
| Trust Center | Security Lead | Legal | New cert, new pentest, new policy |
| API Reference | Backend Eng | DevRel | Any endpoint change |
| Rule Library | Check Engine team | PM | Any rule add/modify/deprecate |
| Release Notes | Tech Writer / PM | Eng Lead | Every sprint / image push |
| Onboarding Guides | DevRel | Customer Success | CSP connector change |
| Feature Guides | DevRel + Engine owner | PM | Feature change |
| Integration Guides | Integrations Eng | DevRel | Integration API change |
| Architecture Overview | Architect | Eng Lead | Major design change |
| Compliance Matrix | Compliance Eng | PM | New framework, new rule |
| SLA & SLO | PM | Eng Lead | Quarterly review |
| Data Retention | Legal / PM | Security | Regulatory change |
| CHANGELOG | All engineers | — | Every image push |

---

## 7. Trust Center — Minimum Viable Contents

This is the single highest-impact doc to publish. Enterprise buyers check it before POC.

```mermaid
graph LR
    TC[Trust Center\ntrust.yourplatform.com]

    TC --> CERT[Certifications]
    TC --> REPORTS[Reports]
    TC --> POLICIES[Policies]
    TC --> LEGAL[Legal]
    TC --> ASSESS[Self-Assessments]

    CERT --> C1[SOC 2 Type II + HIPAA]
    CERT --> C2[ISO 27001]
    CERT --> C3[ISO 27017 Cloud Security]
    CERT --> C4[PCI DSS v4]
    CERT --> C5[FedRAMP — target Moderate]
    CERT --> C6[GDPR Compliant]

    REPORTS --> R1[Penetration Test Report PDF]
    REPORTS --> R2[SOC 2 Report]
    REPORTS --> R3[DR Test Report]
    REPORTS --> R4[Data Flow Diagram]

    POLICIES --> PO1[Security Policy]
    POLICIES --> PO2[Privacy Policy]
    POLICIES --> PO3[Access Management Policy]
    POLICIES --> PO4[Incident Response Policy]
    POLICIES --> PO5[AI Governance Policy]

    LEGAL --> L1[Subprocessor List]
    LEGAL --> L2[Data Processing Agreement]
    LEGAL --> L3[Business Continuity Plan]

    ASSESS --> A1[CAIQ Self-Assessment]
    ASSESS --> A2[SIG Lite]
    ASSESS --> A3[CSA STAR Level 1]

    style TC fill:#343a40,color:#fff,stroke:#000
    style CERT fill:#d4edda,stroke:#28a745,color:#000
    style REPORTS fill:#d1ecf1,stroke:#17a2b8,color:#000
    style POLICIES fill:#fff3cd,stroke:#ffc107,color:#000
    style LEGAL fill:#f8d7da,stroke:#dc3545,color:#000
    style ASSESS fill:#e2d9f3,stroke:#6f42c1,color:#000
```

---

## 8. What We Publish in V1 (Final Decision Checklist)

Use this to make the final call on what goes live at launch.

### Tier 1 — Must publish publicly at V1 launch

- [ ] **Trust Center** — SOC2 report, pentest report, CAIQ, subprocessors, data flow diagram
- [ ] **Data Retention Policy** — required for GDPR, asked by every enterprise
- [ ] **SLA & SLO Reference** — scan frequency, findings-to-UI SLA, uptime target
- [ ] **Monthly Release Notes** — V1 format, public, starting from first GA release
- [ ] **Architecture Overview** — high-level, how data flows from cloud to findings to UI
- [ ] **Public API Reference** — expose the FastAPI OpenAPI JSON or publish to developer portal
- [ ] **Compliance Framework Coverage** — table of all 13+ frameworks with rule counts per CSP
- [ ] **Rule / Policy Library** — every check rule as a browsable public page (1918+ rules)

### Tier 2 — Customer portal at V1 launch

- [ ] **Per-CSP Onboarding Guide** — AWS, Azure, GCP, OCI, AliCloud, IBM
- [ ] **RBAC & SSO Setup Guide**
- [ ] **Alert Rules & Notifications Guide**
- [ ] **Vulnerability Management Guide**
- [ ] **Container & K8s Security Guide**
- [ ] **CIEM / Identity Entitlement Guide**
- [ ] **DSPM / Data Security Guide**
- [ ] **Network Security Guide**
- [ ] **IaC Scanning & CI-CD Integration Guide**
- [ ] **Integration Guides** — Jira, Slack, Splunk, PagerDuty (at minimum)

### Tier 3 — Post-V1 (Depth & Differentiation)

- [ ] CLI Reference (requires CLI product to exist first)
- [ ] Query Language Reference (requires investigation query feature)
- [ ] Custom Rule Authoring Guide (public version)
- [ ] MSSP / Multi-Tenant Guide
- [ ] Terraform Provider Reference
- [ ] Education / Academy Content
- [ ] CHANGELOG.md (internal first, surface publicly later)

---

## 9. Key Competitive Insight

```mermaid
graph TD
    A["🎯 Strategic Observation"] --> B["Prisma Cloud is the only one\nwith fully public docs"]
    B --> C["This wins:\n• Google SEO for security queries\n• Developer self-evaluation\n• Prospect self-qualification\n• Partner integrations"]
    A --> D["Wiz & Orca hide everything behind login"]
    D --> E["This forces a sales call\nbefore any technical evaluation"]
    E --> F["Friction = lost deals for challengers"]
    B --> G["Our recommendation:\nGo Prisma-model — fully public\nfor Tier 1 docs"]
    G --> H["We win on transparency\nwhat we can't yet win on brand"]

    style A fill:#343a40,color:#fff
    style G fill:#d4edda,stroke:#28a745,color:#000
    style H fill:#d4edda,stroke:#28a745,color:#000
    style F fill:#f8d7da,stroke:#dc3545,color:#000
```

---

*Last updated: 2026-05-08 | Status: Draft v1 — pending final V1 launch decision*
*Benchmarked against: Wiz (docs.wiz.io), Orca (docs.orcasecurity.io), Prisma Cloud (docs.prismacloud.io, pan.dev)*
