# Page 3: Threat Analytics (`/threats/analytics`)

> Enterprise benchmark: Wiz Security Graph Analytics, Orca CIEM Analytics, Prisma Cloud Investigate

---

## Page Purpose
Security leadership view. Shows threat distribution, trends over time, top affected services, and attack pattern analysis.

---

## Block-Level UI Design

```
┌─────────────────────────────────────────────────────────────────────┐
│ BREADCRUMB: Threats > Analytics                                     │
├─────────────────────────────────────────────────────────────────────┤
│ METRIC STRIP — THREAT VOLUME                                        │
│ ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│ │ Total   │ │Crit+High │ │New (7d)  │ │Resolved  │ │ Mean Time │  │
│ │ Threats │ │ Threats  │ │ Threats  │ │ /Week    │ │ to Detect │  │
│ │  847    │ │   179    │ │   34     │ │   12     │ │  4.2 hrs  │  │
│ └─────────┘ └──────────┘ └──────────┘ └──────────┘ └───────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│ ROW 1: CHARTS (3-column)                                            │
│ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────┐ │
│ │ SEVERITY DONUT   │ │ BY CATEGORY      │ │ BY PROVIDER          │ │
│ │                  │ │                  │ │                      │ │
│ │   ┌───┐          │ │ ─── Data Exp(45) │ │ ─── AWS  (680)      │ │
│ │   │   │  Crit 23 │ │ ─── Identity(38) │ │ ─── Azure(120)     │ │
│ │   │   │  High156 │ │ ─── Network (29) │ │ ─── GCP  ( 47)     │ │
│ │   └───┘  Med 412 │ │ ─── Config  (17) │ │                      │ │
│ │          Low 256 │ │ ─── Crypto  (12) │ │                      │ │
│ └──────────────────┘ └──────────────────┘ └──────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│ ROW 2: 30-DAY TREND (full width, stacked area)                      │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Threat Trend (30 Days)                      [7d] [14d] [30d]  │ │
│ │                                                                 │ │
│ │   ╱\    /\                                                      │ │
│ │  /  \__/  \___/\    ←── critical (red area)                    │ │
│ │ /              \___  ←── high (orange area)                    │ │
│ │                      ←── medium (yellow area)                  │ │
│ │                      ←── low (blue area)                       │ │
│ │                                                                 │ │
│ │ Feb 15        Feb 22        Mar 01        Mar 08        Mar 15 │ │
│ └─────────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│ ROW 3: TWO-COLUMN                                                   │
│ ┌────────────────────────────────┐ ┌──────────────────────────────┐ │
│ │ TOP AFFECTED SERVICES          │ │ TOP MITRE TECHNIQUES         │ │
│ │ (Horizontal stacked bar)       │ │ (Horizontal bar)             │ │
│ │                                │ │                              │ │
│ │ EC2    ████████░░░░  45       │ │ T1078  ████████  45          │ │
│ │ S3     ███████░░░   38       │ │ T1530  ██████    38          │ │
│ │ IAM    ██████░░     29       │ │ T1190  █████     29          │ │
│ │ RDS    ████░        17       │ │ T1098  ████      17          │ │
│ │ Lambda ███          12       │ │ T1562  ███       12          │ │
│ └────────────────────────────────┘ └──────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│ ROW 4: ACCOUNT HEATMAP (full width)                                 │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Threat Distribution by Account                                  │ │
│ │                                                                 │ │
│ │ Account      │ Critical │ High │ Medium │ Low │ Total          │ │
│ │ ─────────────┼──────────┼──────┼────────┼─────┼──────          │ │
│ │ 58898..14    │    18    │ 120  │  340   │ 200 │  678           │ │
│ │ 12345..89    │     3    │  25  │   52   │  40 │  120           │ │
│ │ 99887..65    │     2    │  11  │   20   │  16 │   49           │ │
│ │                                                                 │ │
│ │ (cells colored by severity concentration — heatmap style)       │ │
│ └─────────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│ ROW 5: PATTERN ANALYSIS (full width)                                │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Common Threat Patterns                                          │ │
│ │                                                                 │ │
│ │ Pattern                  │ Occurrences │ Severity │ Services    │ │
│ │ ─────────────────────────┼─────────────┼──────────┼──────────── │ │
│ │ Public storage + no enc  │     23      │ Critical │ S3, GCS     │ │
│ │ Overprivileged identity  │     18      │ High     │ IAM         │ │
│ │ Open security group + DB │     12      │ Critical │ EC2, RDS    │ │
│ │ Unused creds + admin     │      8      │ High     │ IAM         │ │
│ └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## JSON Data Contract (BFF → UI)

```jsonc
// GET /api/v1/views/threats/analytics?tenant_id=X&days=30
{
  "kpi": {
    "total": 847,
    "criticalAndHigh": 179,
    "newLast7Days": 34,
    "resolvedPerWeek": 12,
    "meanTimeToDetectHours": 4.2,
    "meanTimeToRemediateHours": 72.5,
    "slaCompliancePct": 85.2,
    "topTactic": "Initial Access"
  },

  "severityDistribution": [
    { "name": "Critical", "value": 23, "color": "#ef4444" },
    { "name": "High", "value": 156, "color": "#f97316" },
    { "name": "Medium", "value": 412, "color": "#eab308" },
    { "name": "Low", "value": 256, "color": "#3b82f6" }
  ],

  "byCategory": [
    { "name": "Data Exposure", "count": 45, "color": "#ef4444" },
    { "name": "Identity Risk", "count": 38, "color": "#f97316" },
    { "name": "Network Exposure", "count": 29, "color": "#eab308" },
    { "name": "Misconfiguration", "count": 17, "color": "#3b82f6" },
    { "name": "Cryptographic", "count": 12, "color": "#8b5cf6" }
  ],

  "byProvider": [
    { "name": "AWS", "count": 680, "color": "#f97316" },
    { "name": "Azure", "count": 120, "color": "#3b82f6" },
    { "name": "GCP", "count": 47, "color": "#22c55e" }
  ],

  "trendData": [
    {
      "date": "2026-02-15",
      "critical": 5, "high": 42, "medium": 120, "low": 80, "total": 247
    }
    // ... 30 days
  ],

  "topServices": [
    { "name": "EC2", "critical": 8, "high": 22, "medium": 15, "low": 0, "total": 45 },
    { "name": "S3", "critical": 5, "high": 18, "medium": 15, "low": 0, "total": 38 },
    { "name": "IAM", "critical": 4, "high": 12, "medium": 13, "low": 0, "total": 29 },
    { "name": "RDS", "critical": 3, "high": 8, "medium": 6, "low": 0, "total": 17 },
    { "name": "Lambda", "critical": 2, "high": 5, "medium": 5, "low": 0, "total": 12 }
  ],

  "topMitreTechniques": [
    { "id": "T1078", "name": "Valid Accounts", "count": 45, "severity": "high" },
    { "id": "T1530", "name": "Data from Cloud Storage", "count": 38, "severity": "critical" },
    { "id": "T1190", "name": "Exploit Public-Facing App", "count": 29, "severity": "critical" },
    { "id": "T1098", "name": "Account Manipulation", "count": 17, "severity": "high" },
    { "id": "T1562", "name": "Impair Defenses", "count": 12, "severity": "high" }
  ],

  "accountHeatmap": [
    {
      "account": "588989875114",
      "accountName": "Production",
      "critical": 18, "high": 120, "medium": 340, "low": 200, "total": 678
    },
    {
      "account": "123456789012",
      "accountName": "Staging",
      "critical": 3, "high": 25, "medium": 52, "low": 40, "total": 120
    }
  ],

  "patterns": [
    {
      "name": "Public storage without encryption",
      "occurrences": 23,
      "severity": "critical",
      "services": ["S3", "GCS"],
      "ruleIds": ["s3-bucket-public-read", "s3-bucket-no-encryption"]
    }
  ]
}
```

---

## Data Flow: Engine → BFF → UI

| Section | Engine Endpoint | Exists? | Notes |
|---------|----------------|---------|-------|
| kpi.total/critical/high | `/api/v1/threat/ui-data` → summary | ✅ | |
| kpi.newLast7Days | derived | 🟡 | BFF counts threats with first_seen_at in last 7d |
| kpi.resolvedPerWeek | `/api/v1/threat/analytics/trend` → summary | 🟡 | Need resolved_count from summary |
| kpi.meanTimeToDetect | `/api/v1/threat/ui-data` → summary.mean_time_to_remediate_hours | ✅ | |
| severityDistribution | `/api/v1/threat/analytics/distribution` | ✅ | Returns by_severity |
| byCategory | `/api/v1/threat/analytics/distribution` → by_category | ✅ | |
| byProvider | BFF aggregation | ✅ | From onboarding + threat data |
| trendData | `/api/v1/threat/analytics/trend` | ✅ | Returns trend_data[] |
| topServices | `/api/v1/threat/ui-data` → summary.by_service | ✅ | |
| topMitreTechniques | `/api/v1/threat/ui-data` → mitre_matrix | ✅ | Flatten + sort by count |
| accountHeatmap | `/api/v1/threat/ui-data` → summary.by_account | ✅ | |
| patterns | `/api/v1/threat/analytics/patterns` | ✅ | |

### BFF: `bff/threat_analytics.py` (NEW)
All data available from existing endpoints. This BFF just aggregates + normalizes.
No new engine work needed. No DB changes needed.
