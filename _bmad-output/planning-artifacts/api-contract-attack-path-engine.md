---
title: "API Contract — Attack Path Engine"
type: api-contract
status: draft
version: "1.0"
date: "2026-05-15"
author: "Anup Yadave"
engine: "engine-attack-path"
port: 8025
base_url_internal: "http://engine-attack-path.threat-engine-engines.svc.cluster.local:80"
base_url_gateway: "/api/v1/attack-paths"
permission_prefix: "attack_path"
---

# API Contract: Attack Path Engine

## Overview

All engine endpoints require an `Authorization: Bearer <token>` cookie-based token forwarded
by the gateway as an `X-Auth-Context` header. The gateway's `AuthMiddleware` validates the
token, resolves `tenant_id` from the token's claims, and injects the `AuthContext` as the
`X-Auth-Context` header before forwarding to the engine.

Every engine endpoint calls `Depends(require_permission("attack_path:read"))` or
`Depends(require_permission("attack_path:write"))` via the `engine_auth` shared library.

**Base URL (internal, K8s cluster):**
`http://engine-attack-path.threat-engine-engines.svc.cluster.local:80`

**External path (via gateway):**
`/api/v1/attack-paths/...` → proxied by gateway to engine internal URL

**Internal-only endpoints** (not gateway-exposed, Argo use only):
`POST /api/v1/internal/scan`

---

## Endpoint Index

| # | Method | Path | Permission | Auth |
|---|---|---|---|---|
| 1 | GET | /api/v1/health/live | None | None |
| 2 | GET | /api/v1/health/ready | None | None |
| 3 | GET | /api/v1/attack-paths | attack_path:read | Bearer + X-Auth-Context |
| 4 | GET | /api/v1/attack-paths/{path_id} | attack_path:read | Bearer + X-Auth-Context |
| 5 | GET | /api/v1/crown-jewels | attack_path:read | Bearer + X-Auth-Context |
| 6 | PATCH | /api/v1/crown-jewels/{resource_uid} | attack_path:write | Bearer + X-Auth-Context |
| 7 | GET | /api/v1/choke-points | attack_path:read | Bearer + X-Auth-Context |
| 8 | GET | /api/v1/attack-paths/trends | attack_path:read | Bearer + X-Auth-Context |
| 9 | POST | /api/v1/internal/scan | X-Internal-Secret | Internal only — not gateway-exposed |

BFF endpoints (in gateway, not engine):

| # | Method | Path | Notes |
|---|---|---|---|
| 10 | GET | /api/v1/views/attack-paths | Merged view for UI dashboard |
| 11 | GET | /api/v1/views/attack-paths/{path_id} | Full per-hop story for UI drilldown |

---

## 1. GET /api/v1/health/live

Liveness probe. Returns 200 immediately as long as the FastAPI process is running.
No DB or Neo4j check is performed (liveness ≠ readiness).

### Auth
None required. This endpoint is on the PUBLIC_PREFIXES list in the gateway middleware.

### Response 200
```json
{
  "status": "ok",
  "engine": "attack-path",
  "timestamp": "2026-05-15T14:30:00Z"
}
```

### Error Responses
None. If the process is not running, Kubernetes will not receive a response and will restart the pod.

---

## 2. GET /api/v1/health/ready

Readiness probe. Verifies that the engine can reach both PostgreSQL and Neo4j Aura.
Returns 200 only when both dependencies are reachable. K8s will not route traffic to the pod
until this returns 200.

### Auth
None required.

### Response 200
```json
{
  "status": "ready",
  "engine": "attack-path",
  "checks": {
    "postgres": "ok",
    "neo4j": "ok"
  },
  "timestamp": "2026-05-15T14:30:00Z"
}
```

### Response 503 — Dependency Unavailable
```json
{
  "status": "not_ready",
  "engine": "attack-path",
  "checks": {
    "postgres": "ok",
    "neo4j": "error: connection timeout after 5s"
  },
  "timestamp": "2026-05-15T14:30:00Z"
}
```

---

## 3. GET /api/v1/attack-paths

Returns a paginated list of attack paths for the authenticated tenant, with KPI summary counts.

Default behaviour: returns only `is_representative=true` paths (one per convergence group).
The full group is retrievable by filtering `group_id`.

For the `viewer` role, the `paths[]` array is omitted from the response — only `total` and
`kpis` are returned.

### Auth
Bearer token + X-Auth-Context header. Permission: `attack_path:read`.

### Query Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| scan_run_id | UUID | No | Filter to a specific scan run. If omitted, returns most recent scan. |
| severity | string | No | One of: `critical`, `high`, `medium`, `low`. Comma-separated for multiple. |
| chain_type | string | No | Filter by path chain type (e.g., `internet_to_data`, `internet_to_secrets`). |
| entry_point_type | string | No | Filter by origin type: `internet`, `onprem`, `vpn`, `peer_account`, `vendor`, `k8s_external`. |
| crown_jewel_type | string | No | Filter by crown jewel category: `data`, `secrets`, `identity`, `infra_control`, `ai_model`, `code`. |
| representative_only | boolean | No | Default `true`. Set `false` to include all paths including non-representative group members. |
| has_active_cdr | boolean | No | If `true`, return only paths where `has_active_cdr_actor=true`. |
| account_id | string | No | Filter to a specific cloud account. |
| provider | string | No | Filter by CSP: `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`. |
| page | integer | No | Default `1`. Page number (1-indexed). |
| page_size | integer | No | Default `50`. Max `200`. Number of paths per page. |

### Response 200 — Full (analyst, tenant_admin, org_admin, platform_admin)
```json
{
  "paths": [
    {
      "path_id": "a3f9c2b1d4e8f072a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
      "severity": "critical",
      "path_score": 87,
      "probability_score": 0.7200,
      "impact_score": 0.9500,
      "chain_type": "internet_to_data",
      "entry_point_type": "internet",
      "depth": 3,
      "title": "Internet → EC2 → IAMRole → S3 (PII)",
      "crown_jewel_uid": "arn:aws:s3:::prod-customer-data",
      "crown_jewel_type": "data",
      "data_classification": "pii",
      "account_id": "588989875114",
      "provider": "aws",
      "node_uids": [
        "arn:aws:ec2:ap-south-1:588989875114:instance/i-0abc123def456",
        "arn:aws:iam::588989875114:role/web-prod-role",
        "arn:aws:s3:::prod-customer-data"
      ],
      "node_types": [
        "ec2.instance",
        "iam.role",
        "s3.bucket"
      ],
      "edge_types": ["ASSUMES", "CAN_ACCESS"],
      "hop_categories": ["privilege_escalation", "data_access"],
      "group_id": "c4f91200a3b4",
      "group_size": 3,
      "is_representative": true,
      "absorbed_count": 1,
      "choke_node_uid": "arn:aws:iam::588989875114:role/web-prod-role",
      "has_active_cdr_actor": true,
      "max_epss": 0.9400,
      "misconfig_count": 4,
      "threat_count": 1,
      "first_seen_at": "2026-04-28T10:00:00Z",
      "last_seen_at": "2026-05-15T14:00:00Z",
      "open_days": 17,
      "status": "active"
    }
  ],
  "total": 142,
  "page": 1,
  "page_size": 50,
  "pages": 3,
  "kpis": {
    "critical": 12,
    "high": 38,
    "medium": 54,
    "low": 38,
    "total": 142,
    "choke_points": 5,
    "longest_open_days": 47,
    "paths_with_active_cdr": 3,
    "crown_jewels_at_risk": 23
  }
}
```

### Response 200 — Summary Only (viewer role)
```json
{
  "paths": null,
  "total": 142,
  "page": 1,
  "page_size": 50,
  "pages": null,
  "kpis": {
    "critical": 12,
    "high": 38,
    "medium": 54,
    "low": 38,
    "total": 142,
    "choke_points": 5,
    "longest_open_days": 47,
    "paths_with_active_cdr": 3,
    "crown_jewels_at_risk": 23
  }
}
```

### Error Responses

**400 Bad Request** — Invalid query parameter value
```json
{
  "detail": "Invalid severity value 'urgent'. Must be one of: critical, high, medium, low"
}
```

**401 Unauthorized** — Missing or invalid token
```json
{
  "detail": "Authentication required"
}
```

**403 Forbidden** — Valid token but missing permission
```json
{
  "detail": "Permission denied: attack_path:read required"
}
```

**500 Internal Server Error**
```json
{
  "detail": "Internal server error",
  "request_id": "req_abc123"
}
```

---

## 4. GET /api/v1/attack-paths/{path_id}

Returns the full path story for a single attack path, including per-hop node evidence stored
in `attack_path_nodes`.

The viewer role receives 403 for this endpoint (path story detail is restricted).

### Auth
Bearer token + X-Auth-Context. Permission: `attack_path:read`.
Viewer role returns 403.

### Path Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| path_id | string | Yes | SHA256 path identifier from the list endpoint. |

### Response 200
```json
{
  "path_id": "a3f9c2b1d4e8f072a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
  "path_score": 87,
  "severity": "critical",
  "probability_score": 0.7200,
  "impact_score": 0.9500,
  "chain_type": "internet_to_data",
  "entry_point_type": "internet",
  "depth": 3,
  "title": "Internet → EC2 → IAMRole → S3 (PII)",
  "crown_jewel_uid": "arn:aws:s3:::prod-customer-data",
  "crown_jewel_type": "data",
  "data_classification": "pii",
  "account_id": "588989875114",
  "provider": "aws",
  "group_id": "c4f91200a3b4",
  "group_size": 3,
  "absorbed_count": 1,
  "has_active_cdr_actor": true,
  "max_epss": 0.9400,
  "misconfig_count": 4,
  "threat_count": 1,
  "first_seen_at": "2026-04-28T10:00:00Z",
  "last_seen_at": "2026-05-15T14:00:00Z",
  "open_days": 17,
  "status": "active",
  "steps": [
    {
      "hop_index": 0,
      "node_uid": "arn:aws:ec2:ap-south-1:588989875114:instance/i-0abc123def456",
      "node_name": "web-server-prod",
      "node_type": "ec2.instance",
      "edge_to_next": "ASSUMES",
      "edge_category": "privilege_escalation",
      "traversal_reason": "EC2 has IamInstanceProfile with role web-prod-role attached",
      "policy_statement": null,
      "sg_rule": {
        "port": 22,
        "protocol": "tcp",
        "cidr": "0.0.0.0/0",
        "direction": "inbound"
      },
      "misconfigs": [
        {
          "rule_id": "aws-ec2-imds-v1",
          "severity": "high",
          "title": "IMDSv1 enabled — token hijack risk",
          "remediation": "Enforce IMDSv2 by setting HttpTokens=required on the instance metadata options"
        },
        {
          "rule_id": "aws-sg-ssh-open",
          "severity": "critical",
          "title": "SSH port 22 open to 0.0.0.0/0",
          "remediation": "Restrict SSH ingress to known CIDR ranges or use AWS Systems Manager Session Manager"
        }
      ],
      "cves": [
        {
          "cve_id": "CVE-2023-44487",
          "epss": 0.9400,
          "cvss": 7.5,
          "in_kev": true,
          "description": "HTTP/2 Rapid Reset Attack"
        }
      ],
      "threat_detections": [
        {
          "detection_type": "T1078.004",
          "technique": "Valid Accounts: Cloud Accounts",
          "severity": "high"
        }
      ],
      "cdr_actor_active": true,
      "cdr_actor_uid": "i-0abc123def456/root",
      "risk_score": 84,
      "is_crown_jewel": false,
      "data_classification": null,
      "encrypted_by": null,
      "cert_expiry": null
    },
    {
      "hop_index": 1,
      "node_uid": "arn:aws:iam::588989875114:role/web-prod-role",
      "node_name": "web-prod-role",
      "node_type": "iam.role",
      "edge_to_next": "CAN_ACCESS",
      "edge_category": "data_access",
      "traversal_reason": "Policy allows s3:GetObject and s3:ListBucket on Resource:* without a permission boundary",
      "policy_statement": {
        "actions": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
        "resource": "*",
        "effect": "Allow",
        "policy_arn": "arn:aws:iam::588989875114:policy/web-prod-s3-policy"
      },
      "sg_rule": null,
      "misconfigs": [
        {
          "rule_id": "aws-iam-no-boundary",
          "severity": "critical",
          "title": "IAM role has no permission boundary",
          "remediation": "Attach a permission boundary policy that restricts the role to required services only"
        },
        {
          "rule_id": "aws-iam-wildcard-resource",
          "severity": "high",
          "title": "Policy grants wildcard Resource access",
          "remediation": "Scope s3:GetObject to specific bucket ARNs rather than Resource:*"
        }
      ],
      "cves": [],
      "threat_detections": [],
      "cdr_actor_active": false,
      "cdr_actor_uid": null,
      "risk_score": 71,
      "is_crown_jewel": false,
      "data_classification": null,
      "encrypted_by": null,
      "cert_expiry": null
    },
    {
      "hop_index": 2,
      "node_uid": "arn:aws:s3:::prod-customer-data",
      "node_name": "prod-customer-data",
      "node_type": "s3.bucket",
      "edge_to_next": null,
      "edge_category": null,
      "traversal_reason": "Crown jewel destination — PII data store",
      "policy_statement": null,
      "sg_rule": null,
      "misconfigs": [
        {
          "rule_id": "aws-s3-no-kms",
          "severity": "high",
          "title": "S3 bucket not encrypted with customer-managed KMS key",
          "remediation": "Enable SSE-KMS with a customer-managed key for this bucket"
        }
      ],
      "cves": [],
      "threat_detections": [],
      "cdr_actor_active": false,
      "cdr_actor_uid": null,
      "risk_score": 78,
      "is_crown_jewel": true,
      "crown_jewel_type": "data",
      "data_classification": "pii",
      "encrypted_by": null,
      "encryption_gap": "SSE-S3 only — not customer-managed KMS",
      "cert_expiry": null
    }
  ]
}
```

### Error Responses

**403 Forbidden** — Viewer role attempting path story
```json
{
  "detail": "Permission denied: path story requires analyst role or above"
}
```

**404 Not Found** — path_id does not exist for this tenant
```json
{
  "detail": "Attack path not found"
}
```

**500 Internal Server Error**
```json
{
  "detail": "Internal server error",
  "request_id": "req_def456"
}
```

---

## 5. GET /api/v1/crown-jewels

Returns the list of crown jewels for the authenticated tenant with path count per jewel.
Combines auto-classified crown jewels with manual overrides. Override status is indicated
by the `is_manual_override` field.

### Auth
Bearer token + X-Auth-Context. Permission: `attack_path:read`.

### Query Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| scan_run_id | UUID | No | If omitted, returns most recent scan. |
| crown_jewel_type | string | No | Filter by type: `data`, `secrets`, `identity`, `infra_control`, `ai_model`, `code`. |
| data_classification | string | No | Filter by data classification: `pii`, `financial`, `credentials`. |
| account_id | string | No | Filter to a specific cloud account. |
| provider | string | No | Filter by CSP. |
| page | integer | No | Default `1`. |
| page_size | integer | No | Default `50`. Max `200`. |

### Response 200
```json
{
  "crown_jewels": [
    {
      "resource_uid": "arn:aws:s3:::prod-customer-data",
      "resource_name": "prod-customer-data",
      "resource_type": "s3.bucket",
      "account_id": "588989875114",
      "provider": "aws",
      "region": "ap-south-1",
      "crown_jewel_type": "data",
      "data_classification": "pii",
      "is_manual_override": false,
      "override_reason": null,
      "set_by": null,
      "attack_path_count": 7,
      "is_choke_point": false,
      "is_on_attack_path": true,
      "blast_radius_count": 0,
      "encryption_type": "sse",
      "encryption_gap": "SSE-S3 only — not customer-managed KMS",
      "risk_score": 78,
      "scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "last_seen_at": "2026-05-15T14:00:00Z"
    },
    {
      "resource_uid": "arn:aws:rds:ap-south-1:588989875114:db:prod-postgres-01",
      "resource_name": "prod-postgres-01",
      "resource_type": "rds.instance",
      "account_id": "588989875114",
      "provider": "aws",
      "region": "ap-south-1",
      "crown_jewel_type": "data",
      "data_classification": null,
      "is_manual_override": true,
      "override_reason": "Primary customer database — classified as crown jewel by tenant admin",
      "set_by": "alice@example.com",
      "attack_path_count": 3,
      "is_choke_point": false,
      "is_on_attack_path": true,
      "blast_radius_count": 0,
      "encryption_type": "kms",
      "encryption_gap": null,
      "risk_score": 65,
      "scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "last_seen_at": "2026-05-15T14:00:00Z"
    }
  ],
  "total": 23,
  "page": 1,
  "page_size": 50,
  "pages": 1
}
```

### Error Responses

**400 Bad Request**
```json
{
  "detail": "Invalid crown_jewel_type 'critical'. Must be one of: data, secrets, identity, infra_control, ai_model, code"
}
```

**403 Forbidden**
```json
{
  "detail": "Permission denied: attack_path:read required"
}
```

---

## 6. PATCH /api/v1/crown-jewels/{resource_uid}

Manually tag or untag a resource as a crown jewel. Requires `attack_path:write` permission
(tenant_admin, org_admin, platform_admin). Analyst and viewer roles receive 403.

Overrides are stored in `crown_jewel_overrides`. A manual override always supersedes
auto-classification. Setting `is_crown_jewel: false` suppresses auto-classification for that
resource until the override is removed (by setting `is_crown_jewel: true` again or deleting
the override via a future DELETE endpoint).

The `set_by` field is populated from `AuthContext.user_email` — it is not provided by the
caller. The engine reads the email from the auth context injected by the gateway.

Override changes take effect on the next scan run.

### Auth
Bearer token + X-Auth-Context. Permission: `attack_path:write`.

### Path Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| resource_uid | string | Yes | URL-encoded resource UID (ARN, Azure resource ID, etc.) |

### Request Body

```json
{
  "is_crown_jewel": true,
  "crown_jewel_type": "data",
  "reason": "This bucket contains PII data for EU customers — must track attack paths"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| is_crown_jewel | boolean | Yes | True to tag, false to untag. |
| crown_jewel_type | string | No | One of: `data`, `secrets`, `identity`, `infra_control`, `ai_model`, `code`. Required when is_crown_jewel=true. |
| reason | string | No | Human-readable justification. Stored in audit record. |

### Response 200

```json
{
  "resource_uid": "arn:aws:s3:::build-artifacts-prod",
  "tenant_id": "my-tenant",
  "is_crown_jewel": true,
  "crown_jewel_type": "data",
  "reason": "This bucket contains PII data for EU customers — must track attack paths",
  "set_by": "alice@example.com",
  "created_at": "2026-05-15T14:35:00Z",
  "updated_at": "2026-05-15T14:35:00Z",
  "note": "Override will take effect on the next scan run"
}
```

### Error Responses

**400 Bad Request** — Missing crown_jewel_type when tagging
```json
{
  "detail": "crown_jewel_type is required when is_crown_jewel is true"
}
```

**403 Forbidden** — Analyst or viewer attempting to write
```json
{
  "detail": "Permission denied: attack_path:write required (tenant_admin or above)"
}
```

**404 Not Found** — Resource UID not found in posture table for this tenant
```json
{
  "detail": "Resource not found: arn:aws:s3:::build-artifacts-prod"
}
```

---

## 7. GET /api/v1/choke-points

Returns the top N choke point nodes — resources whose remediation would break the most attack
paths. Sorted by `paths_blocked_if_fixed` descending.

Only nodes that appear as `choke_node_uid` in at least one convergence group are returned.
Maximum 10 nodes per query (hard limit — the engine only computes the top 10).

Viewer role returns 403 for this endpoint.

### Auth
Bearer token + X-Auth-Context. Permission: `attack_path:read`.
Viewer role returns 403.

### Query Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| scan_run_id | UUID | No | Filter to a specific scan run. Defaults to most recent. |
| limit | integer | No | Default `10`. Max `10`. Number of choke points to return. |
| account_id | string | No | Filter to a specific cloud account. |

### Response 200

```json
{
  "choke_points": [
    {
      "node_uid": "arn:aws:iam::588989875114:role/web-prod-role",
      "node_name": "web-prod-role",
      "node_type": "iam.role",
      "account_id": "588989875114",
      "provider": "aws",
      "region": "us-east-1",
      "paths_blocked_if_fixed": 14,
      "avg_path_score": 76.3,
      "max_path_score": 87,
      "severity_breakdown": {
        "critical": 5,
        "high": 7,
        "medium": 2,
        "low": 0
      },
      "crown_jewels_protected": [
        "arn:aws:s3:::prod-customer-data",
        "arn:aws:rds:ap-south-1:588989875114:db:prod-postgres-01"
      ],
      "recommended_fix": "Attach a permission boundary to this role limiting it to s3:GetObject on specific bucket ARNs",
      "risk_score": 84,
      "is_on_attack_path": true,
      "scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
    },
    {
      "node_uid": "arn:aws:eks:ap-south-1:588989875114:cluster/prod-eks",
      "node_name": "prod-eks",
      "node_type": "eks.cluster",
      "account_id": "588989875114",
      "provider": "aws",
      "region": "ap-south-1",
      "paths_blocked_if_fixed": 9,
      "avg_path_score": 68.1,
      "max_path_score": 81,
      "severity_breakdown": {
        "critical": 3,
        "high": 4,
        "medium": 2,
        "low": 0
      },
      "crown_jewels_protected": [
        "arn:aws:secretsmanager:ap-south-1:588989875114:secret/db-creds"
      ],
      "recommended_fix": "Enable RBAC audit logging and restrict cluster admin ClusterRoleBindings",
      "risk_score": 79,
      "is_on_attack_path": true,
      "scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
    }
  ],
  "total": 5,
  "scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
}
```

### Error Responses

**403 Forbidden** — Viewer role
```json
{
  "detail": "Permission denied: choke points require analyst role or above"
}
```

---

## 8. GET /api/v1/attack-paths/trends

Returns path history data for trend analysis. Supports two modes:

- **Tenant-level trends:** overall path count and score trajectory over the last N days
- **Single-path trend:** score and composition history for one specific path

### Auth
Bearer token + X-Auth-Context. Permission: `attack_path:read`.

### Query Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| days | integer | No | Default `30`. Number of days of history to return. Max `90`. |
| path_id | string | No | If provided, returns history for a single path. If omitted, returns tenant-level trends. |
| account_id | string | No | Filter to a specific account (tenant-level mode only). |

### Response 200 — Tenant-Level Trends (path_id omitted)

```json
{
  "mode": "tenant",
  "tenant_id": "my-tenant",
  "period_days": 30,
  "summary": {
    "current_critical": 12,
    "current_high": 38,
    "total_current": 142,
    "new_paths_this_period": 8,
    "resolved_paths_this_period": 3,
    "longest_open_days": 47,
    "longest_open_path_id": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
  },
  "score_history": [
    {
      "date": "2026-04-15",
      "total_paths": 138,
      "critical": 10,
      "high": 36,
      "medium": 52,
      "low": 40,
      "avg_score": 58.2
    },
    {
      "date": "2026-04-22",
      "total_paths": 141,
      "critical": 11,
      "high": 37,
      "medium": 53,
      "low": 40,
      "avg_score": 59.1
    },
    {
      "date": "2026-04-29",
      "total_paths": 139,
      "critical": 11,
      "high": 37,
      "medium": 52,
      "low": 39,
      "avg_score": 58.8
    },
    {
      "date": "2026-05-06",
      "total_paths": 145,
      "critical": 13,
      "high": 39,
      "medium": 55,
      "low": 38,
      "avg_score": 61.4
    },
    {
      "date": "2026-05-13",
      "total_paths": 142,
      "critical": 12,
      "high": 38,
      "medium": 54,
      "low": 38,
      "avg_score": 60.7
    }
  ],
  "new_critical_paths": [
    {
      "path_id": "a3f9c2b1d4e8f072a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
      "title": "Internet → EC2 → IAMRole → S3 (PII)",
      "path_score": 87,
      "first_seen_at": "2026-05-06T08:00:00Z"
    }
  ],
  "resolved_paths": [
    {
      "path_id": "f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9",
      "title": "VPN → Jump Server → RDS (credentials)",
      "last_path_score": 74,
      "resolved_at": "2026-05-08T14:00:00Z"
    }
  ]
}
```

### Response 200 — Single-Path Trend (path_id provided)

```json
{
  "mode": "single_path",
  "path_id": "a3f9c2b1d4e8f072a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
  "title": "Internet → EC2 → IAMRole → S3 (PII)",
  "period_days": 30,
  "first_seen_at": "2026-04-28T10:00:00Z",
  "open_days": 17,
  "history": [
    {
      "scan_run_id": "2a3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d",
      "recorded_at": "2026-04-28T10:00:00Z",
      "score": 82,
      "severity": "critical",
      "node_count": 3,
      "node_uids": [
        "arn:aws:ec2:ap-south-1:588989875114:instance/i-0abc123def456",
        "arn:aws:iam::588989875114:role/web-prod-role",
        "arn:aws:s3:::prod-customer-data"
      ],
      "node_changes": null
    },
    {
      "scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "recorded_at": "2026-05-15T14:00:00Z",
      "score": 87,
      "severity": "critical",
      "node_count": 3,
      "node_uids": [
        "arn:aws:ec2:ap-south-1:588989875114:instance/i-0abc123def456",
        "arn:aws:iam::588989875114:role/web-prod-role",
        "arn:aws:s3:::prod-customer-data"
      ],
      "node_changes": {
        "added": [],
        "removed": [],
        "score_delta": 5,
        "score_delta_reason": "CDR actor became active on node i-0abc123def456"
      }
    }
  ]
}
```

### Error Responses

**400 Bad Request** — days value out of range
```json
{
  "detail": "days must be between 1 and 90"
}
```

**404 Not Found** — path_id not found (single-path mode)
```json
{
  "detail": "Attack path not found or no history available"
}
```

---

## 9. POST /api/v1/internal/scan

Argo Workflows trigger endpoint. Initiates a full attack path scan for the given tenant and
scan run. This endpoint is internal-only and must NOT be exposed via the gateway.

The endpoint is excluded from gateway routing by not registering its prefix in the service
route table. The gateway only proxies `/api/v1/attack-paths/...` paths — the `/internal/`
prefix is unreachable from outside the cluster.

### Auth
`X-Internal-Secret` header — value from `threat-engine-secrets` Kubernetes secret.
No `Authorization` header or `X-Auth-Context` required.

### Request Body

```json
{
  "scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tenant_id": "my-tenant",
  "account_id": "588989875114",
  "provider": "aws"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| scan_run_id | UUID | Yes | Pipeline scan run identifier — same UUID across all engines in the run. |
| tenant_id | string | Yes | Tenant identifier. |
| account_id | string | Yes | Cloud account identifier (AWS account ID, Azure subscription, etc.) |
| provider | string | No | CSP: `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`. If omitted, engine infers from resource_uid prefixes. |

### Response 202 — Accepted

```json
{
  "job_id": "ap-scan-3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tenant_id": "my-tenant",
  "status": "queued",
  "message": "Attack path scan queued successfully"
}
```

### Error Responses

**401 Unauthorized** — Missing or invalid X-Internal-Secret
```json
{
  "detail": "Unauthorized: invalid internal secret"
}
```

**400 Bad Request** — Missing required field
```json
{
  "detail": "scan_run_id is required"
}
```

**409 Conflict** — Scan already in progress for this scan_run_id
```json
{
  "detail": "Scan already in progress for scan_run_id 3fa85f64-5717-4562-b3fc-2c963f66afa6"
}
```

---

## 10. BFF: GET /api/v1/views/attack-paths

Gateway BFF handler (`shared/api_gateway/bff/attack_paths.py`). Returns a merged view for the
Attack Paths UI dashboard. Calls the engine `GET /api/v1/attack-paths` and enriches with
display-ready fields.

This endpoint uses the standard `fetchView("attack-paths")` pattern from `frontend/src/lib/api.js`.

### Auth
Bearer token cookie → Gateway `AuthMiddleware` builds `AuthContext`. BFF reads
`AuthContext.engine_tenant_id` and `AuthContext.permissions` before proxying to engine.

### Query Parameters

Passes through all query parameters from `GET /api/v1/attack-paths` plus:

| Name | Type | Required | Description |
|---|---|---|---|
| view | string | No | `dashboard` (default) or `full`. Dashboard returns top-severity paths only. |

### Response 200

Adds display-ready fields on top of the engine response:

```json
{
  "view": "attack-paths",
  "scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "last_scan_at": "2026-05-15T14:00:00Z",
  "paths": [
    {
      "path_id": "a3f9c2b1d4e8f072a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
      "severity": "critical",
      "path_score": 87,
      "probability_score": 0.7200,
      "impact_score": 0.9500,
      "chain_type": "internet_to_data",
      "entry_point_type": "internet",
      "depth": 3,
      "title": "Internet → EC2 → IAMRole → S3 (PII)",
      "crown_jewel_uid": "arn:aws:s3:::prod-customer-data",
      "crown_jewel_type": "data",
      "data_classification": "pii",
      "group_size": 3,
      "is_representative": true,
      "choke_node_uid": "arn:aws:iam::588989875114:role/web-prod-role",
      "has_active_cdr_actor": true,
      "max_epss": 0.9400,
      "misconfig_count": 4,
      "open_days": 17,
      "status": "active",
      "display": {
        "severity_color": "#DC2626",
        "entry_icon": "globe",
        "crown_icon": "database",
        "cdr_badge": true,
        "age_label": "17 days open",
        "group_label": "3 similar paths"
      }
    }
  ],
  "total": 142,
  "page": 1,
  "page_size": 50,
  "pages": 3,
  "kpis": {
    "critical": 12,
    "high": 38,
    "medium": 54,
    "low": 38,
    "total": 142,
    "choke_points": 5,
    "longest_open_days": 47,
    "paths_with_active_cdr": 3,
    "crown_jewels_at_risk": 23
  },
  "choke_points_preview": [
    {
      "node_uid": "arn:aws:iam::588989875114:role/web-prod-role",
      "node_name": "web-prod-role",
      "node_type": "iam.role",
      "paths_blocked_if_fixed": 14,
      "avg_path_score": 76.3
    }
  ]
}
```

**BFF contract rules:**
- The BFF must NOT add fallback or mock data. If the engine returns an error, propagate the
  error to the UI — do not substitute synthetic data.
- `display.*` fields are computed by the BFF from engine response fields. They are never
  stored in the engine DB.
- `choke_points_preview` is populated by a parallel call to `GET /api/v1/choke-points?limit=3`.
  If that call fails, `choke_points_preview` is omitted (not an empty array — omit the key
  entirely so the UI falls back to "See Choke Points" link).

---

## 11. BFF: GET /api/v1/views/attack-paths/{path_id}

Gateway BFF handler for the Attack Path drilldown panel (side-panel or full-page path story).
Calls `GET /api/v1/attack-paths/{path_id}` and adds display-ready enrichments per hop.

### Auth
Bearer token cookie → AuthMiddleware → AuthContext. Viewer role returns 403 (same as engine).

### Path Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| path_id | string | Yes | SHA256 path identifier. |

### Response 200

Wraps the engine `path_id` response with BFF display fields per hop:

```json
{
  "view": "attack-path-detail",
  "path_id": "a3f9c2b1d4e8f072a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
  "path_score": 87,
  "severity": "critical",
  "probability_score": 0.7200,
  "impact_score": 0.9500,
  "chain_type": "internet_to_data",
  "title": "Internet → EC2 → IAMRole → S3 (PII)",
  "open_days": 17,
  "has_active_cdr_actor": true,
  "group_size": 3,
  "steps": [
    {
      "hop_index": 0,
      "node_uid": "arn:aws:ec2:ap-south-1:588989875114:instance/i-0abc123def456",
      "node_name": "web-server-prod",
      "node_type": "ec2.instance",
      "edge_to_next": "ASSUMES",
      "edge_category": "privilege_escalation",
      "traversal_reason": "EC2 has IamInstanceProfile with role web-prod-role attached",
      "misconfigs": [
        {
          "rule_id": "aws-ec2-imds-v1",
          "severity": "high",
          "title": "IMDSv1 enabled — token hijack risk",
          "remediation": "Enforce IMDSv2 by setting HttpTokens=required on the instance metadata options"
        },
        {
          "rule_id": "aws-sg-ssh-open",
          "severity": "critical",
          "title": "SSH port 22 open to 0.0.0.0/0",
          "remediation": "Restrict SSH ingress to known CIDR ranges or use Systems Manager Session Manager"
        }
      ],
      "cves": [
        {
          "cve_id": "CVE-2023-44487",
          "epss": 0.9400,
          "cvss": 7.5,
          "in_kev": true,
          "description": "HTTP/2 Rapid Reset Attack"
        }
      ],
      "cdr_actor_active": true,
      "cdr_actor_uid": "i-0abc123def456/root",
      "risk_score": 84,
      "is_crown_jewel": false,
      "display": {
        "node_icon": "server",
        "edge_label": "Assumes IAM Role",
        "edge_color": "#F59E0B",
        "cdr_badge": true,
        "kev_badge": true,
        "severity_indicator": "critical"
      }
    },
    {
      "hop_index": 1,
      "node_uid": "arn:aws:iam::588989875114:role/web-prod-role",
      "node_name": "web-prod-role",
      "node_type": "iam.role",
      "edge_to_next": "CAN_ACCESS",
      "edge_category": "data_access",
      "traversal_reason": "Policy allows s3:GetObject and s3:ListBucket on Resource:* without a permission boundary",
      "policy_statement": {
        "actions": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
        "resource": "*",
        "effect": "Allow",
        "policy_arn": "arn:aws:iam::588989875114:policy/web-prod-s3-policy"
      },
      "misconfigs": [
        {
          "rule_id": "aws-iam-no-boundary",
          "severity": "critical",
          "title": "IAM role has no permission boundary",
          "remediation": "Attach a permission boundary policy restricting the role to required services"
        }
      ],
      "cves": [],
      "cdr_actor_active": false,
      "risk_score": 71,
      "is_crown_jewel": false,
      "display": {
        "node_icon": "shield",
        "edge_label": "Can Access S3",
        "edge_color": "#EF4444",
        "cdr_badge": false,
        "kev_badge": false,
        "severity_indicator": "critical"
      }
    },
    {
      "hop_index": 2,
      "node_uid": "arn:aws:s3:::prod-customer-data",
      "node_name": "prod-customer-data",
      "node_type": "s3.bucket",
      "edge_to_next": null,
      "edge_category": null,
      "traversal_reason": "Crown jewel destination — PII data store",
      "misconfigs": [
        {
          "rule_id": "aws-s3-no-kms",
          "severity": "high",
          "title": "S3 bucket not encrypted with customer-managed KMS key",
          "remediation": "Enable SSE-KMS with a customer-managed key for this bucket"
        }
      ],
      "cves": [],
      "cdr_actor_active": false,
      "risk_score": 78,
      "is_crown_jewel": true,
      "crown_jewel_type": "data",
      "data_classification": "pii",
      "encryption_gap": "SSE-S3 only — not customer-managed KMS",
      "display": {
        "node_icon": "database",
        "edge_label": null,
        "edge_color": null,
        "cdr_badge": false,
        "kev_badge": false,
        "severity_indicator": "crown_jewel",
        "crown_jewel_badge": true,
        "pii_badge": true
      }
    }
  ]
}
```

**BFF contract rules:**
- `display.*` fields on each step are computed by the BFF. They are not stored in the engine.
- `node_icon` maps from `node_type` using a static lookup table in the BFF.
- `edge_label` maps from `edge_to_next` + `edge_category` using a static lookup table.
- If the engine returns 404, the BFF returns 404 to the UI — no fallback synthetic path.

---

## Appendix A — Permission Summary

| Permission | Roles | Endpoints |
|---|---|---|
| `attack_path:read` | platform_admin, org_admin, tenant_admin, analyst, viewer (summary only) | All GET endpoints |
| `attack_path:write` | platform_admin, org_admin, tenant_admin | PATCH /crown-jewels/{uid} |

Viewer role restrictions:
- `GET /attack-paths` → `paths[]` array is null; only `kpis{}` and `total` are returned
- `GET /attack-paths/{path_id}` → 403
- `GET /choke-points` → 403

---

## Appendix B — Error Code Reference

| HTTP Status | Meaning | When Used |
|---|---|---|
| 200 | OK | Successful GET or PATCH |
| 202 | Accepted | Scan job queued (POST /internal/scan) |
| 400 | Bad Request | Invalid query param, missing required field |
| 401 | Unauthorized | Missing or invalid Bearer token |
| 403 | Forbidden | Valid token but insufficient permission |
| 404 | Not Found | path_id, resource_uid not found for this tenant |
| 409 | Conflict | Duplicate scan_run_id in progress |
| 500 | Internal Server Error | DB error, Neo4j error, unhandled exception |
| 503 | Service Unavailable | Readiness probe failure (DB or Neo4j unreachable) |

All error responses follow the format:
```json
{
  "detail": "Human-readable error message"
}
```

500 errors include an additional `request_id` field for log correlation:
```json
{
  "detail": "Internal server error",
  "request_id": "req_abc123"
}
```

---

## Appendix C — Gateway Configuration

Add to `shared/api_gateway/main.py` SERVICE_ROUTES:
```python
"attack-path": "http://engine-attack-path.threat-engine-engines.svc.cluster.local:80",
```

Add to `frontend/src/lib/constants.js` ENGINE_ENDPOINTS:
```javascript
ATTACK_PATH: '/api/v1/attack-paths',
CROWN_JEWELS: '/api/v1/crown-jewels',
CHOKE_POINTS: '/api/v1/choke-points',
```

BFF file to create:
`shared/api_gateway/bff/attack_paths.py`

BFF handler registration in `shared/api_gateway/main.py`:
```python
from bff.attack_paths import router as attack_paths_bff_router
app.include_router(attack_paths_bff_router, prefix="/api/v1/views")
```
