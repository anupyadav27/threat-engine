# Blast Radius Redesign Plan

## Problem Statement

Current blast radius is a **raw graph dump** — shows all neighbors bidirectionally without security semantics. A security group shows 28 other SGs and subnets, which is meaningless from a CSPM perspective.

**Blast radius in CSPM answers**: "If this resource is compromised/misconfigured/goes down, what else is impacted?" — specifically:
- What **compute** (EC2, Lambda, EKS, ECS) is affected?
- What **data** (S3, RDS, DynamoDB, Redshift) is at risk?
- What **identity** (IAM roles, policies) is exposed?
- Through what **dependency chain** does impact flow?

## Design Decisions

### 1. Traversal Direction: BACKWARD (Dependents)

Current code traverses bidirectionally (both `from→to` and `to→from`). This is wrong for blast radius.

**For blast radius, we need REVERSE traversal** — find what DEPENDS ON the origin resource:

- If **VPC** is compromised → find everything `contained_by` this VPC (instances, RDS, Lambda, subnets, SGs)
- If **Security Group** is compromised → find everything `attached_to` this SG (instances, RDS, Lambda, ELB)
- If **IAM Role** is compromised → find everything that `uses` this role (Lambda, EC2, ECS, CodeBuild)
- If **KMS Key** is compromised → find everything `encrypted_by` this key (S3, RDS, DynamoDB, Lambda)
- If **S3 Bucket** is compromised → find what `stores_data_in` / `logging_enabled_to` / `replicates_to` this bucket

**Implementation**: Query `WHERE to_uid = origin` and traverse `to_uid → from_uid` (reverse direction). This finds "who points at me" = "who depends on me".

### 2. Resource Categorization

Add a `RESOURCE_CATEGORIES` map to classify `resource_type` into security-meaningful groups:

```python
RESOURCE_CATEGORIES = {
    # COMPUTE — can execute code
    "compute": ["ec2.instance", "lambda.function", "ecs.task", "ecs.service",
                "eks.cluster", "batch.compute-environment", "lightsail.instance",
                "ec2.image", "ecs.definition"],
    # DATA STORAGE — holds data
    "storage": ["s3.bucket", "efs.file-system", "ebs.volume", "ec2.volume",
                "glacier.vault", "backup.backup-vault", "ec2.snapshot"],
    # DATABASE — structured data
    "database": ["rds.db-instance", "rds.db-cluster", "dynamodb.table",
                 "elasticache.cluster", "elasticache.replication-group",
                 "es.domain", "redshift.cluster", "docdb.cluster"],
    # IDENTITY — permissions & access
    "identity": ["iam.role", "iam.user", "iam.group", "iam.policy",
                 "iam.instance-profile"],
    # NETWORK — connectivity & boundaries
    "network": ["ec2.vpc", "ec2.subnet", "ec2.security-group", "ec2.network-acl",
                "ec2.route-table", "ec2.internet-gateway", "ec2.nat-gateway",
                "ec2.transit-gateway", "ec2.vpc-peering-connection",
                "ec2.network-interface"],
    # LOAD BALANCING — traffic routing
    "load_balancer": ["elbv2.balancer", "elbv2.target-group", "elbv2.listener",
                      "elasticloadbalancing.load-balancer"],
    # ENCRYPTION — key management
    "encryption": ["kms.key", "kms.alias", "kms.custom-key-store",
                   "acm.certificate", "secretsmanager.secret"],
    # SERVERLESS / EVENT — orchestration
    "serverless": ["events.rule", "events.event-bus", "states.state-machine",
                   "sqs.queue", "sns.topic", "kinesis.stream"],
    # LOGGING — audit trail
    "logging": ["logs.log-group", "cloudtrail.trail", "cloudwatch.alarm"],
    # CDN / API — external surface
    "external": ["cloudfront.distribution", "apigateway.rest-api",
                 "waf.web-acl"],
}
```

### 3. Response Shape

Replace the flat `nodes[]` + `edges[]` with a security-meaningful structure:

```json
{
  "origin": {
    "uid": "arn:aws:ec2:...:security-group/sg-xxx",
    "name": "web-sg",
    "type": "ec2.security-group",
    "category": "network"
  },
  "max_depth": 3,
  "impact_summary": {
    "total_impacted": 15,
    "compute": 4,
    "database": 2,
    "storage": 1,
    "identity": 3,
    "network": 5,
    "encryption": 0,
    "load_balancer": 0,
    "serverless": 0,
    "logging": 0,
    "external": 0
  },
  "layers": [
    {
      "hop": 1,
      "resources": [
        {
          "uid": "arn:aws:ec2:...:instance/i-xxx",
          "name": "web-server-01",
          "type": "ec2.instance",
          "category": "compute",
          "relation_type": "attached_to",
          "relation_label": "uses this security group",
          "hop": 1
        }
      ]
    },
    {
      "hop": 2,
      "resources": [...]
    }
  ],
  "nodes": [...],  // Keep flat list for tree rendering
  "edges": [...],  // Keep edges with relation_type labels
  "depth_distribution": {"1": 8, "2": 5, "3": 2}
}
```

### 4. Frontend: Layered Tree Layout

Replace the radial SVG graph with a **top-down tree** that groups resources by category within each hop layer:

```
┌─────────────────────────────────────────┐
│  IMPACT SUMMARY                         │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐      │
│  │ 4   │ │ 2   │ │ 1   │ │ 3   │      │
│  │Comp.│ │ DB  │ │Store│ │Ident│      │
│  └─────┘ └─────┘ └─────┘ └─────┘      │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  DEPENDENCY TREE                        │
│                                         │
│  ◉ sg-xxx (Origin - Security Group)     │
│  ├── 🖥 i-abc (EC2 Instance) ──attached │
│  │   ├── 🔑 role-xxx (IAM Role) ──uses │
│  │   └── 💾 vol-xxx (EBS Vol) ──attach  │
│  ├── 🖥 i-def (EC2 Instance) ──attached │
│  │   └── 🗄 rds-xxx (RDS) ──contained  │
│  ├── ⚡ fn-xxx (Lambda) ──attached      │
│  │   └── 🪣 s3-xxx (S3 Bucket) ──uses  │
│  └── ⚖ elb-xxx (Load Balancer) ──att.  │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  IMPACTED RESOURCES TABLE               │
│  Resource | Category | Hop | Relation   │
│  i-abc    | Compute  |  1  | attached_to│
│  role-xxx | Identity |  2  | uses       │
│  ...                                    │
└─────────────────────────────────────────┘
```

## Implementation Steps

### Step 1: Backend — Update `get_blast_radius()` in `inventory_db_loader.py`

**File**: `engines/inventory/inventory_engine/api/inventory_db_loader.py`

Changes:
1. Add `RESOURCE_CATEGORIES` dict at module level
2. Add `categorize_resource(resource_type)` helper function
3. Rewrite the CTE query to traverse **REVERSE direction** (find dependents, not dependencies):
   - `edges` CTE: only reverse direction (`to_uid AS source, from_uid AS target`)
   - This finds: "who depends on origin?" by following backward edges
4. Add `category` field to each node during enrichment
5. Build `impact_summary` dict with counts per category
6. Build `layers` grouping for frontend tree rendering
7. Keep flat `nodes[]` and `edges[]` for backward compatibility

### Step 2: Frontend — Redesign Blast Radius tab in asset detail page

**File**: `ui_samples/src/app/inventory/[assetId]/page.jsx`

Changes:
1. Replace the 4 KPI cards with **Impact Summary** cards that show counts by category (Compute, Database, Storage, Identity) — only show categories that have > 0 count, using category-specific icons and colors
2. Replace `<BlastRadiusGraph>` radial SVG with a **tree component**:
   - Origin at top, collapsible tree below
   - Each node shows: icon (by category), name, type, relation_type badge
   - Color-coded by category (blue=compute, orange=storage, red=database, purple=identity, gray=network)
   - Lines connect parent→child with relation label
3. Keep the **Impacted Resources Table** but add Category column with colored badges
4. Replace the `BlastRadiusGraph` function component with `BlastRadiusTree`

### Step 3: Build, Deploy, Verify

1. Build Docker image `yadavanup84/inventory-engine:v12-blast-radius`
2. Push and deploy to EKS
3. Build frontend `yadavanup84/cspm-frontend:v6-blast-tree`
4. Push and deploy to EKS
5. Verify via preview dev server
