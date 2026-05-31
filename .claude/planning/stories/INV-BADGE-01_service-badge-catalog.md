# INV-BADGE-01 — Service Badge Catalog (Data-Driven, Multi-CSP)

## Problem

Service badges in the inventory table are hardcoded in `frontend/src/app/inventory/page.jsx`
(`SERVICE_BADGE` map, ~35 entries). This cannot scale:

- AWS alone has 200+ services
- Azure/GCP/OCI/AliCloud/IBM each have 50–300 services
- Any new service requires a code change + image rebuild + deploy
- Badges are missing for most non-AWS services

## Goal

Drive service badges from a **data catalog** that maps `(csp, service)` → `(label, color, icon_key)`.
The catalog is seeded from `di_resource_catalog` which already has every `(csp, service, resource_type)`
combination discovered during scans.

---

## Architecture

### 1. DB: New table `service_badge_catalog`

Location: `threat_engine_di` DB (alongside `di_resource_catalog`)

```sql
CREATE TABLE IF NOT EXISTS service_badge_catalog (
    id           SERIAL PRIMARY KEY,
    csp          VARCHAR(50)   NOT NULL,   -- aws / azure / gcp / oci / ibm / alicloud / k8s
    service      VARCHAR(100)  NOT NULL,   -- ec2, s3, Microsoft.Compute/virtualMachines, etc.
    label        VARCHAR(20)   NOT NULL,   -- short display label: "EC2", "VM", "GCS"
    color        VARCHAR(7)    NOT NULL,   -- hex color: "#f97316"
    icon_key     VARCHAR(50),             -- optional: maps to a Lucide icon or CSP icon slug
    UNIQUE (csp, service)
);
```

Seeded by a Python script that:
1. Reads all distinct `(csp, service)` from `di_resource_catalog`
2. For known services, applies curated label/color from `catalog/badge_seed.json`
3. For unknown services: auto-generates label (first 6 chars uppercased) + assigns a color
   from a deterministic hash of the service name

### 2. DI engine: New endpoint

```
GET /api/v1/di/badge-catalog?csp=aws,azure,gcp
```

Returns:
```json
{
  "badges": {
    "aws:ec2":   { "label": "EC2",   "color": "#f97316", "icon_key": "server" },
    "aws:s3":    { "label": "S3",    "color": "#3b82f6", "icon_key": "database" },
    "azure:Microsoft.Compute": { "label": "VM", "color": "#0078d4" },
    ...
  }
}
```

### 3. BFF: Include badge catalog in inventory response

In `view_inventory`, add one call to DI `/api/v1/di/badge-catalog` (runs in parallel with
existing calls), then include result in BFF response under key `"badgeCatalog"`.

The BFF already knows which CSPs are present (`by_provider`), so it only fetches the
relevant CSPs.

### 4. Frontend: Load once, use everywhere

In `inventory/page.jsx`:
- Read `data.badgeCatalog` from BFF response
- Replace hardcoded `SERVICE_BADGE` map with `badgeCatalog` lookup
- Key format: `"${provider}:${service}"` then fallback to `"*:${service}"`

In `InventoryQueryBuilder.jsx`:
- The `Service` field dropdown now populates from `badgeCatalog` keys rather than
  a static list

---

## Files to create / change

| File | Change |
|------|--------|
| `shared/database/migrations/di_009_service_badge_catalog.sql` | CREATE TABLE + seed known badges |
| `catalog/badge_seed.json` | Curated label+color for ~80 well-known services across all CSPs |
| `engines/di/di_engine/api/api_server.py` | Add `GET /api/v1/di/badge-catalog` |
| `shared/api_gateway/bff/inventory.py` | Call badge-catalog in `view_inventory` parallel fetch; add to response |
| `frontend/src/app/inventory/page.jsx` | Replace `SERVICE_BADGE` with `data.badgeCatalog` lookup |
| `frontend/src/components/shared/InventoryQueryBuilder.jsx` | Service dropdown from catalog |

---

## Seed data (catalog/badge_seed.json)

Curated entries covering all CSPs. Structure:
```json
{
  "aws": {
    "ec2":                    { "label": "EC2",    "color": "#f97316" },
    "s3":                     { "label": "S3",     "color": "#3b82f6" },
    "rds":                    { "label": "RDS",    "color": "#06b6d4" },
    "lambda":                 { "label": "λ",      "color": "#f59e0b" },
    "eks":                    { "label": "EKS",    "color": "#0ea5e9" },
    "ecs":                    { "label": "ECS",    "color": "#22c55e" },
    "iam":                    { "label": "IAM",    "color": "#a855f7" },
    "kms":                    { "label": "KMS",    "color": "#6366f1" },
    "vpc":                    { "label": "VPC",    "color": "#84cc16" },
    "dynamodb":               { "label": "DDB",    "color": "#16a34a" },
    "elasticloadbalancing":   { "label": "ELB",    "color": "#f43f5e" },
    "cloudtrail":             { "label": "Trail",  "color": "#64748b" },
    "secretsmanager":         { "label": "Sec",    "color": "#dc2626" },
    "apigateway":             { "label": "APIGW",  "color": "#0891b2" },
    "sagemaker":              { "label": "ML",     "color": "#7c3aed" },
    "bedrock":                { "label": "AI",     "color": "#7c3aed" },
    "redshift":               { "label": "RS",     "color": "#7c3aed" },
    "ecr":                    { "label": "ECR",    "color": "#8b5cf6" },
    "cloudwatch":             { "label": "CW",     "color": "#9333ea" },
    "cloudfront":             { "label": "CDN",    "color": "#f43f5e" },
    "route53":                { "label": "DNS",    "color": "#10b981" },
    "waf":                    { "label": "WAF",    "color": "#dc2626" },
    "sns":                    { "label": "SNS",    "color": "#f59e0b" },
    "sqs":                    { "label": "SQS",    "color": "#f97316" },
    "guardduty":              { "label": "GD",     "color": "#7c3aed" },
    "config":                 { "label": "Cfg",    "color": "#64748b" }
  },
  "azure": {
    "Microsoft.Compute":           { "label": "VM",     "color": "#0078d4" },
    "Microsoft.Storage":           { "label": "Blob",   "color": "#3b82f6" },
    "Microsoft.Sql":               { "label": "SQL",    "color": "#06b6d4" },
    "Microsoft.Network":           { "label": "Net",    "color": "#0ea5e9" },
    "Microsoft.KeyVault":          { "label": "Vault",  "color": "#6366f1" },
    "Microsoft.ContainerService":  { "label": "AKS",    "color": "#326CE5" },
    "Microsoft.Web":               { "label": "App",    "color": "#22c55e" },
    "Microsoft.Authorization":     { "label": "IAM",    "color": "#a855f7" }
  },
  "gcp": {
    "compute":     { "label": "GCE",   "color": "#4285f4" },
    "storage":     { "label": "GCS",   "color": "#fbbc04" },
    "container":   { "label": "GKE",   "color": "#0f9d58" },
    "cloudsql":    { "label": "SQL",   "color": "#06b6d4" },
    "iam":         { "label": "IAM",   "color": "#a855f7" },
    "kms":         { "label": "KMS",   "color": "#6366f1" },
    "bigquery":    { "label": "BQ",    "color": "#4285f4" },
    "pubsub":      { "label": "PubSub","color": "#f59e0b" }
  },
  "oci": {
    "core":        { "label": "Core",  "color": "#c74634" },
    "objectstorage":{ "label": "OBS",  "color": "#3b82f6" },
    "database":    { "label": "DB",    "color": "#06b6d4" },
    "identity":    { "label": "IAM",   "color": "#a855f7" },
    "loadbalancer":{ "label": "LB",    "color": "#f43f5e" }
  },
  "k8s": {
    "core":        { "label": "K8S",   "color": "#326CE5" },
    "apps":        { "label": "App",   "color": "#0ea5e9" },
    "rbac":        { "label": "RBAC",  "color": "#a855f7" },
    "networking":  { "label": "Net",   "color": "#22c55e" }
  }
}
```

---

## Acceptance Criteria

1. `service_badge_catalog` table exists in `threat_engine_di` DB with rows for all discovered services
2. `GET /api/v1/di/badge-catalog` returns the full badge map in < 100ms (single DB read, no joins)
3. BFF `view_inventory` includes `badgeCatalog` in response
4. Inventory table shows correct label + color for every service across all CSPs — no hardcoded fallbacks remain in `page.jsx`
5. For services not in the catalog, frontend auto-generates label (first 6 chars) + uses `#6b7280` neutral grey
6. Adding a new service requires only inserting a row into `service_badge_catalog` — no code deploy

---

## Definition of Done

- [ ] Migration `di_009_service_badge_catalog.sql` applied to prod
- [ ] `catalog/badge_seed.json` committed with ~80 known services
- [ ] DI engine `/api/v1/di/badge-catalog` endpoint live and returning data
- [ ] BFF response includes `badgeCatalog` key
- [ ] Frontend reads from `data.badgeCatalog`, zero hardcoded service colors remain
- [ ] DI engine + api-gateway + cspm-portal images rebuilt and deployed

## Estimated effort: 1 sprint day (small)