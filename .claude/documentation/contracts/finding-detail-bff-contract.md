# Finding Detail BFF Contract

**Endpoint:** `GET /api/v1/views/finding/{engine}/{id}`
**Auth:** `X-Auth-Context` header (resolved from access_token cookie by gateway)
**Tenant:** derived from auth context only — never from query params

## Request

| Parameter | Location | Validation |
|-----------|----------|-----------|
| `engine` | path | must be in ENGINE_MAP: `check`, `threat`, `iam`, `network-security`, `datasec`, `encryption`, `container-security`, `dbsec`, `ai-security`, `cdr`, `secops` |
| `id` | path | `[A-Za-z0-9._:/-]`, 1–128 chars |

## Response Shape

```json
{
  "engine": "iam",
  "finding": {
    "findingId": "abc123",
    "engine": "iam",
    "ruleId": "AWS-IAM-001",
    "severity": "high",
    "status": "open",
    "title": "Root account active",
    "description": "Root account has active API keys",
    "resourceUid": "arn:aws:iam::123456789:root",
    "resourceType": "AWS::IAM::Root",
    "resourceName": null,
    "provider": "aws",
    "accountId": "123456789",
    "region": "us-east-1",
    "firstSeenAt": "2026-05-01T00:00:00Z",
    "lastSeenAt": "2026-05-18T00:00:00Z",
    "riskScore": 95,
    "findingData": { }
  },
  "header": { /* same as finding */ },
  "resourceContext": null,
  "relatedFindings": {
    "available": true,
    "perEngineAvailability": { "iam": true, "check": true },
    "restrictedEngines": [],
    "items": [
      {
        "engine": "check",
        "findingId": "def456",
        "severity": "medium",
        "ruleId": "AWS-CFG-012",
        "status": "open",
        "title": null
      }
    ]
  },
  "related": [ /* flat list of relatedFindings.items as dicts */ ],
  "compliance": {
    "available": true,
    "controlMappings": [
      {
        "framework": "CIS AWS 1.4",
        "controlId": "1.7",
        "controlName": "Eliminate use of root account",
        "status": "FAIL"
      }
    ]
  },
  "remediation": {
    "available": true,
    "steps": [
      { "order": 1, "action": "Navigate to IAM console", "detail": null }
    ],
    "references": ["https://docs.aws.amazon.com/..."],
    "estimatedEffort": "15 minutes",
    "slaPriority": "72h",
    "guidance": "Remediation guidance text",
    "markdown": "Remediation guidance text",
    "runbook_url": ""
  },
  "engineExtensions": {},
  "tabPermissions": {
    "overview": true,
    "resource": true,
    "related": true,
    "compliance": true,
    "remediation": true
  },
  "degradedEngines": [],
  "restrictedEngines": [],
  "evidence": {},
  "supporting": [],
  "partial": false,
  "allTabs": [
    { "tabId": "overview",    "label": "Overview" },
    { "tabId": "resource",    "label": "Resource" },
    { "tabId": "related",     "label": "Related" },
    { "tabId": "compliance",  "label": "Compliance" },
    { "tabId": "remediation", "label": "Remediation" }
  ]
}
```

## Error cases

| Condition | HTTP Status | Body |
|-----------|-------------|------|
| Invalid engine slug | 400 | `{"detail": "engine must be one of [...] "}` |
| Engine not yet supported (secops) | 501 | `{"detail": "engine 'secops' not yet supported"}` |
| Finding not found OR cross-tenant probe | 404 | `{"detail": "finding not found"}` |
| No active tenant in session | 400 | `{"detail": "No active tenant in session..."}` |
| Caller lacks `<engine>:read` | 403 | auth middleware response |
| Engine DB unavailable | 503 | `{"detail": "database unavailable", "engine": "<table>"}` |

## Resource Context (Tab 2)

`resourceContext` is always `null` in this response. The frontend calls
`/api/v1/views/inventory/asset/{uid}` separately for the Resource Context tab.
This avoids a synchronous dependency on the inventory engine for all finding lookups.

## Related Findings (Tab 3)

- Fan-out to all permitted engines with `supported: true`
- Per-engine timeout: 800ms; failures surface as `perEngineAvailability[engine] = false`
- Sorted by severity DESC (critical→high→medium→low), capped at 100 total
- Engines the caller lacks permission for appear in `restrictedEngines`

## Compliance (Tab 4)

- Source: `rule_control_mapping` table in check DB, keyed by `rule_id`
- TTL cache: 5 minutes; empty on cache miss
- `available: false` only on DB failure, never when the rule has no mappings

## Remediation (Tab 5)

- Source: `rule_metadata.remediation_guidance` JSONB in check DB
- TTL cache: 5 minutes
- `slaPriority`: critical=24h, high=72h, medium=30d, low=90d
- `available: false` only on DB failure

## Status PATCH

`PATCH /api/v1/views/finding/{engine}/{id}/status`

Request body:
```json
{ "status": "resolved", "note": "Fixed in PR #123" }
```

Valid status values: `open`, `resolved`, `suppressed`, `in_progress`

Response: `FindingHeader` (same shape as `finding` above)

Requires caller to have the engine-specific write permission (currently same as read perm).