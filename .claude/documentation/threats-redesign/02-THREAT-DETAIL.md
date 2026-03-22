# Page 2: Threat Detail (`/threats/[threatId]`)

> Enterprise benchmark: Wiz Issue Detail, Orca Alert Detail, Prisma Cloud Alert Detail

---

## Page Purpose
Full context for a single threat. Answers: "Why does this matter? What's the attack path? What's impacted? How do I fix it?"

This is NOT a finding detail. It shows the **threat scenario** with supporting evidence, blast radius, and remediation priority.

---

## Block-Level UI Design

```
┌─────────────────────────────────────────────────────────────────────┐
│ BREADCRUMB: Threats > [Threat Title]                                │
├─────────────────────────────────────────────────────────────────────┤
│ THREAT HEADER                                                       │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ ●CRITICAL  T1530 · Collection                                  │ │
│ │                                                                 │ │
│ │ Public S3 bucket with PII data exposure                        │ │
│ │ ─────────────────────────────────────────                      │ │
│ │ An S3 bucket containing personally identifiable information    │ │
│ │ is publicly accessible, enabling data exfiltration.            │ │
│ │                                                                 │ │
│ │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────┐│ │
│ │ │Risk: 95  │ │Provider  │ │Account   │ │Region    │ │Status ││ │
│ │ │██████████│ │AWS       │ │58898..14 │ │ap-south-1│ │Active ││ │
│ │ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └───────┘│ │
│ │                                                                 │ │
│ │ [Assign ▼]  [Change Status ▼]  [Suppress]  [Export]           │ │
│ └─────────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│ TAB BAR: [Overview] [Attack Path] [Blast Radius] [Evidence]        │
│          [Remediation] [Timeline]                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ ═══ TAB: OVERVIEW (default) ═══════════════════════════════════════ │
│                                                                     │
│ SECTION 1: EXPOSURE CONTEXT (prominent, always visible)             │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Exposure Analysis                                               │ │
│ │                                                                 │ │
│ │ ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐ │ │
│ │ │🌐 Internet │  │🔓 Public   │  │🔑 Trust    │  │📊 Sensitiv│ │ │
│ │ │  Exposed   │  │  Access    │  │  Exposure  │  │  Data     │ │ │
│ │ │    YES     │  │   YES      │  │   NO       │  │   YES     │ │ │
│ │ │ Direct via │  │ Bucket ACL │  │            │  │ PII found │ │ │
│ │ │ 0.0.0.0/0 │  │ allows *   │  │            │  │ 1,240 rec │ │ │
│ │ └────────────┘  └────────────┘  └────────────┘  └───────────┘ │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│ SECTION 2: AFFECTED RESOURCES                                       │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Affected Resources (3)                                          │ │
│ │                                                                 │ │
│ │ Resource          │ Type       │ Account    │ Region    │ Risk  │ │
│ │ ──────────────────┼────────────┼────────────┼───────────┼─────  │ │
│ │ my-data-bucket    │ s3.bucket  │ 58898..14  │ ap-south-1│  95   │ │
│ │ data-backup-2026  │ s3.bucket  │ 58898..14  │ us-east-1 │  88   │ │
│ │ log-archive       │ s3.bucket  │ 58898..14  │ eu-west-1 │  72   │ │
│ │                                                                 │ │
│ │ [View in Inventory →]                                           │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│ SECTION 3: SUPPORTING FINDINGS (evidence, collapsed by default)     │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Supporting Findings (5)                              [Expand ▼] │ │
│ │                                                                 │ │
│ │ ● FAIL  s3-bucket-public-read   "S3 bucket allows public read" │ │
│ │ ● FAIL  s3-bucket-no-encryption "S3 bucket not encrypted"      │ │
│ │ ● FAIL  s3-bucket-no-logging    "S3 bucket logging disabled"   │ │
│ │ ● FAIL  s3-bucket-no-versioning "S3 bucket versioning off"     │ │
│ │ ● WARN  s3-bucket-lifecycle     "No lifecycle policy"          │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│ SECTION 4: MITRE ATT&CK CONTEXT                                    │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ MITRE ATT&CK Mapping                                           │ │
│ │                                                                 │ │
│ │ Technique: T1530 — Data from Cloud Storage Object              │ │
│ │ Tactic: Collection                                              │ │
│ │                                                                 │ │
│ │ Description: Adversaries may access data from improperly        │ │
│ │ secured cloud storage. Public S3 buckets are a common target.   │ │
│ │                                                                 │ │
│ │ Platforms: AWS, Azure, GCP                                      │ │
│ │ Detection: Monitor CloudTrail for GetObject on public buckets   │ │
│ │                                                                 │ │
│ │ [View on MITRE →]                                               │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│ ═══ TAB: ATTACK PATH ═════════════════════════════════════════════ │
│                                                                     │
│ SECTION: ATTACK PATH VISUALIZATION                                  │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │                                                                 │ │
│ │  🌐 Internet                                                    │ │
│ │     │                                                           │ │
│ │     ▼                                                           │ │
│ │  ┌──────────┐    ┌──────────┐    ┌──────────┐                  │ │
│ │  │ ALB      │───→│ EC2      │───→│ IAM Role │                  │ │
│ │  │ public   │    │ instance │    │ admin    │                  │ │
│ │  │ T1190    │    │ T1078    │    │ T1098    │                  │ │
│ │  │ Risk: 80 │    │ Risk: 75 │    │ Risk: 90 │                  │ │
│ │  └──────────┘    └──────────┘    └──────────┘                  │ │
│ │                                       │                         │ │
│ │                                       ▼                         │ │
│ │                                  ┌──────────┐                   │ │
│ │                                  │ S3 Bucket│                   │ │
│ │                                  │ PII Data │                   │ │
│ │                                  │ T1530    │                   │ │
│ │                                  │ Risk: 95 │                   │ │
│ │                                  └──────────┘                   │ │
│ │                                  🎯 TARGET                      │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│ ═══ TAB: BLAST RADIUS ════════════════════════════════════════════ │
│                                                                     │
│ SECTION: BLAST RADIUS MINI-GRAPH                                    │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Blast Radius: 12 resources reachable                            │ │
│ │                                                                 │ │
│ │ [Force-directed mini-graph centered on threat resource]         │ │
│ │                                                                 │ │
│ │ Depth 0: 1 resource (source)                                    │ │
│ │ Depth 1: 4 resources (IAM roles, security groups)               │ │
│ │ Depth 2: 5 resources (EC2, Lambda)                              │ │
│ │ Depth 3: 2 resources (DynamoDB, S3)                             │ │
│ │                                                                 │ │
│ │ [Open Full Blast Radius →]                                      │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│ ═══ TAB: REMEDIATION ═════════════════════════════════════════════ │
│                                                                     │
│ SECTION: REMEDIATION STEPS                                          │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Recommended Actions (Priority Order)                            │ │
│ │                                                                 │ │
│ │ ① Disable public access on S3 bucket                           │ │
│ │   Impact: Immediately blocks external access                    │ │
│ │   Effort: Low   Risk: Minimal                                   │ │
│ │   [Auto-Remediate ▶]                                            │ │
│ │                                                                 │ │
│ │ ② Enable server-side encryption (SSE-S3 or SSE-KMS)            │ │
│ │   Impact: Protects data at rest                                 │ │
│ │   Effort: Low   Risk: None                                      │ │
│ │                                                                 │ │
│ │ ③ Enable bucket versioning and logging                          │ │
│ │   Impact: Audit trail for forensics                             │ │
│ │   Effort: Low   Risk: Cost increase                              │ │
│ │                                                                 │ │
│ │ SLA Status: ⚠ At Risk (5 of 7 days remaining)                  │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│ ═══ TAB: TIMELINE ════════════════════════════════════════════════ │
│                                                                     │
│ SECTION: ACTIVITY TIMELINE                                          │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Timeline                                                        │ │
│ │                                                                 │ │
│ │ ● Mar 15, 10:30  Threat detected by scan bfed9ebc...           │ │
│ │ │                 Severity: Critical, Risk: 95                  │ │
│ │ │                                                               │ │
│ │ ● Mar 15, 10:32  MITRE technique T1530 mapped                  │ │
│ │ │                 Tactic: Collection                             │ │
│ │ │                                                               │ │
│ │ ● Mar 15, 10:35  Attack path identified (3 hops)               │ │
│ │ │                 Source: ALB → Target: S3                       │ │
│ │ │                                                               │ │
│ │ ○ (pending)      Awaiting assignment                            │ │
│ └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## JSON Data Contract (BFF → UI)

```jsonc
// GET /api/v1/views/threats/{threatId}?tenant_id=X
{
  // ── Threat Header ──
  "threat": {
    "id": "tf_abc123",
    "title": "Public S3 bucket with PII data exposure",
    "description": "An S3 bucket containing personally identifiable information is publicly accessible via bucket ACL, enabling potential data exfiltration by adversaries.",
    "severity": "critical",
    "riskScore": 95,
    "status": "active",
    "assignee": "",
    "provider": "AWS",
    "account": "588989875114",
    "region": "ap-south-1",
    "resourceType": "s3.bucket",
    "resourceUid": "arn:aws:s3:::my-data-bucket",
    "detected": "2026-03-15T10:30:00Z",
    "lastSeen": "2026-03-17T06:00:00Z",
    "environment": "production",
    "threatCategory": "data_exposure",
    "ruleId": "s3-bucket-public-read"
  },

  // ── Exposure Context ──
  "exposure": {
    "internetExposed": true,
    "internetExposedReason": "Bucket ACL allows public read (0.0.0.0/0)",
    "publicAccess": true,
    "publicAccessReason": "Bucket policy allows s3:GetObject for *",
    "trustExposure": false,
    "trustExposureReason": "",
    "sensitiveData": true,
    "sensitiveDataReason": "PII detected: 1,240 records (SSN, email, phone)",
    "sensitiveDataCount": 1240
  },

  // ── MITRE ATT&CK Context ──
  "mitre": {
    "techniqueId": "T1530",
    "techniqueName": "Data from Cloud Storage Object",
    "tacticName": "Collection",
    "description": "Adversaries may access data from improperly secured cloud storage.",
    "platforms": ["AWS", "Azure", "GCP"],
    "detectionGuidance": "Monitor CloudTrail for GetObject on public buckets",
    "remediationGuidance": "Block public access, enable encryption, enable logging",
    "url": "https://attack.mitre.org/techniques/T1530/"
  },

  // ── Affected Resources ──
  "affectedResources": [
    {
      "resourceUid": "arn:aws:s3:::my-data-bucket",
      "resourceName": "my-data-bucket",
      "resourceType": "s3.bucket",
      "account": "588989875114",
      "region": "ap-south-1",
      "riskScore": 95
    }
  ],

  // ── Supporting Findings (from check engine) ──
  "supportingFindings": [
    {
      "findingId": "cf_001",
      "ruleId": "s3-bucket-public-read",
      "title": "S3 bucket allows public read access",
      "severity": "critical",
      "status": "FAIL",
      "resourceArn": "arn:aws:s3:::my-data-bucket",
      "framework": "CIS AWS 1.5",
      "remediation": "Set BlockPublicAccess to true"
    }
  ],

  // ── Attack Path (if exists) ──
  "attackPath": {
    "exists": true,
    "pathId": "ap_001",
    "title": "Internet → ALB → EC2 → IAM Role → S3 PII Bucket",
    "severity": "critical",
    "hops": 4,
    "steps": [
      {
        "order": 0,
        "resourceType": "internet",
        "resourceName": "Internet",
        "technique": "T1190",
        "tacticName": "Initial Access",
        "riskScore": 0
      },
      {
        "order": 1,
        "resourceType": "elasticloadbalancing.loadbalancer",
        "resourceName": "prod-alb",
        "resourceArn": "arn:aws:elasticloadbalancing:...",
        "technique": "T1190",
        "tacticName": "Initial Access",
        "riskScore": 80
      },
      {
        "order": 2,
        "resourceType": "ec2.instance",
        "resourceName": "web-server-01",
        "resourceArn": "arn:aws:ec2:...",
        "technique": "T1078",
        "tacticName": "Credential Access",
        "riskScore": 75
      },
      {
        "order": 3,
        "resourceType": "iam.role",
        "resourceName": "web-server-role",
        "resourceArn": "arn:aws:iam::...",
        "technique": "T1098",
        "tacticName": "Privilege Escalation",
        "riskScore": 90
      },
      {
        "order": 4,
        "resourceType": "s3.bucket",
        "resourceName": "my-data-bucket",
        "resourceArn": "arn:aws:s3:::my-data-bucket",
        "technique": "T1530",
        "tacticName": "Collection",
        "riskScore": 95,
        "isTarget": true
      }
    ]
  },

  // ── Blast Radius (mini) ──
  "blastRadius": {
    "reachableCount": 12,
    "resourcesWithThreats": 4,
    "depthDistribution": { "0": 1, "1": 4, "2": 5, "3": 2 },
    "maxDepth": 3
  },

  // ── Remediation ──
  "remediation": {
    "steps": [
      {
        "order": 1,
        "action": "Disable public access on S3 bucket",
        "impact": "Immediately blocks external access to bucket contents",
        "effort": "low",
        "risk": "minimal",
        "autoRemediable": true
      },
      {
        "order": 2,
        "action": "Enable server-side encryption (SSE-S3 or SSE-KMS)",
        "impact": "Protects data at rest from unauthorized access",
        "effort": "low",
        "risk": "none",
        "autoRemediable": true
      },
      {
        "order": 3,
        "action": "Enable bucket versioning and access logging",
        "impact": "Creates audit trail for forensic investigation",
        "effort": "low",
        "risk": "minor cost increase",
        "autoRemediable": false
      }
    ],
    "sla": {
      "targetDays": 7,
      "daysElapsed": 2,
      "daysRemaining": 5,
      "status": "at_risk"
    },
    "totalSteps": 3,
    "completedSteps": 0
  },

  // ── Timeline ──
  "timeline": [
    {
      "timestamp": "2026-03-15T10:30:00Z",
      "event": "Threat detected",
      "detail": "Severity: Critical, Risk Score: 95",
      "actor": "system",
      "type": "detection"
    },
    {
      "timestamp": "2026-03-15T10:32:00Z",
      "event": "MITRE technique mapped",
      "detail": "T1530 — Collection",
      "actor": "system",
      "type": "enrichment"
    },
    {
      "timestamp": "2026-03-15T10:35:00Z",
      "event": "Attack path identified",
      "detail": "4 hops: Internet → ALB → EC2 → IAM → S3",
      "actor": "system",
      "type": "analysis"
    }
  ]
}
```

---

## Data Flow: What Engine Provides vs What's Needed

| Section | Source | Engine Endpoint | Status |
|---------|--------|----------------|--------|
| threat header | threat_findings | `GET /api/v1/threat/{id}` | ✅ EXISTS — returns full finding |
| exposure.internetExposed | Neo4j | `GET /api/v1/graph/internet-exposed` | 🟡 Exists but returns list, need per-resource check |
| exposure.sensitiveData | datasec engine | Cross-engine call | 🔴 NEW — need datasec connector |
| mitre details | mitre_technique_reference | Join in engine or BFF | 🟡 Table exists, not exposed as standalone endpoint |
| affectedResources | threat_findings | `GET /api/v1/threat/{id}/assets` | ✅ EXISTS |
| supportingFindings | check_findings | `GET /api/v1/threat/{id}/misconfig-findings` | ✅ EXISTS |
| attackPath | Neo4j | `GET /api/v1/graph/attack-paths` | 🟡 Exists but returns all paths, need filter by resource |
| blastRadius | Neo4j | `GET /api/v1/graph/blast-radius/{uid}` | ✅ EXISTS |
| remediation | threat_findings.finding_data | `GET /api/v1/threat/{id}/remediation` | ✅ EXISTS |
| timeline | ❌ Not stored | Need to derive from scan timestamps | 🔴 NEW — build in BFF from audit trail |

### New BFF: `bff/threat_detail.py`

Replaces the current client-side hack of fetching 1000 threats and filtering by ID.

```python
# Pseudocode
async def view_threat_detail(threat_id, tenant_id):
    threat, assets, findings, remediation, mitre_ref = await fetch_many([
        ("threat", f"/api/v1/threat/{threat_id}", {"tenant_id": tenant_id}),
        ("threat", f"/api/v1/threat/{threat_id}/assets", {"tenant_id": tenant_id}),
        ("threat", f"/api/v1/threat/{threat_id}/misconfig-findings", {"tenant_id": tenant_id}),
        ("threat", f"/api/v1/threat/{threat_id}/remediation", {"tenant_id": tenant_id}),
        # MITRE reference — new endpoint needed or join in engine
    ])
    # Also fetch blast radius and attack path for this resource
    blast = await fetch("threat", f"/api/v1/graph/blast-radius/{resource_uid}", ...)
    paths = await fetch("threat", "/api/v1/graph/attack-paths", {"resource_uid": resource_uid, ...})

    return { "threat": ..., "exposure": ..., "mitre": ..., ... }
```
