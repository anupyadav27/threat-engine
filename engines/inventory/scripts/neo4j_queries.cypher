// ============================================================
// Neo4j Query Library — Inventory Graph
// ============================================================
// Node labels:  Asset, Account, Tenant, Region
// Key props on Asset:
//   asset_id, resource_uid, resource_type, resource_name,
//   provider, account_id, tenant_id, region, service,
//   tags (map), emitted_fields (map)
//
// Usage:  substitute $account_id, $provider, $tenant_id, etc.
// ============================================================


// ────────────────────────────────────────────────────────────
// 1. SCHEMA INSPECTION
// ────────────────────────────────────────────────────────────

// 1.1  What accounts are loaded?
MATCH (a:Account)
RETURN a.provider AS provider, a.account_id AS account_id, a.name AS name
ORDER BY a.provider, a.account_id;

// 1.2  Asset counts per account + provider
MATCH (a:Asset)-[:BELONGS_TO]->(acc:Account)
RETURN acc.provider AS provider, acc.account_id AS account_id,
       count(a) AS asset_count
ORDER BY provider, account_id;

// 1.3  Asset counts per resource_type (one account)
MATCH (a:Asset)-[:BELONGS_TO]->(acc:Account {account_id: $account_id, provider: $provider})
RETURN a.resource_type AS resource_type, count(a) AS cnt
ORDER BY cnt DESC;

// 1.4  All distinct relationship types in the graph
MATCH ()-[r]->()
RETURN type(r) AS rel_type, count(r) AS cnt
ORDER BY cnt DESC;

// 1.5  Relationship type distribution per provider
MATCH (from:Asset)-[r]->(to:Asset)
WHERE from.provider = $provider
RETURN type(r) AS rel_type, count(r) AS cnt
ORDER BY cnt DESC;


// ────────────────────────────────────────────────────────────
// 2. PER-ACCOUNT SUBGRAPH (core UI pattern)
// ────────────────────────────────────────────────────────────

// 2.1  All assets for one account (paginated)
//      Suitable for asset list / table view in UI
MATCH (a:Asset)-[:BELONGS_TO]->(acc:Account {account_id: $account_id, provider: $provider})
RETURN a.asset_id       AS asset_id,
       a.resource_uid   AS resource_uid,
       a.resource_type  AS resource_type,
       a.resource_name  AS resource_name,
       a.service        AS service,
       a.region         AS region,
       a.tags           AS tags
ORDER BY a.service, a.resource_type, a.resource_name
SKIP $skip LIMIT $limit;

// 2.2  All assets + their direct relationships in one account
//      Returns edge list suitable for graph visualisation
MATCH (a:Asset)-[:BELONGS_TO]->(acc:Account {account_id: $account_id, provider: $provider})
OPTIONAL MATCH (a)-[r]->(b:Asset)-[:BELONGS_TO]->(acc)
RETURN a.resource_uid  AS from_uid,
       a.resource_type AS from_type,
       a.resource_name AS from_name,
       type(r)         AS rel_type,
       b.resource_uid  AS to_uid,
       b.resource_type AS to_type,
       b.resource_name AS to_name
ORDER BY from_type, from_name;

// 2.3  Cross-account edges (where account A uses a resource in account B)
MATCH (a:Asset)-[:BELONGS_TO]->(accA:Account {account_id: $account_id})
MATCH (a)-[r]->(b:Asset)-[:BELONGS_TO]->(accB:Account)
WHERE accB.account_id <> $account_id
RETURN a.resource_uid  AS from_uid,
       a.resource_type AS from_type,
       accA.account_id AS from_account,
       type(r)         AS rel_type,
       b.resource_uid  AS to_uid,
       b.resource_type AS to_type,
       accB.account_id AS to_account;


// ────────────────────────────────────────────────────────────
// 3. SINGLE ASSET DETAIL (click-through in UI)
// ────────────────────────────────────────────────────────────

// 3.1  Full detail for one asset
MATCH (a:Asset {asset_id: $asset_id})
RETURN a;

// 3.2  Immediate neighbours of one asset (1 hop, any direction)
MATCH (a:Asset {asset_id: $asset_id})-[r]-(b:Asset)
RETURN a.resource_uid  AS center_uid,
       type(r)         AS rel_type,
       b.asset_id      AS neighbour_asset_id,
       b.resource_uid  AS neighbour_uid,
       b.resource_type AS neighbour_type,
       b.resource_name AS neighbour_name,
       b.account_id    AS neighbour_account,
       CASE WHEN startNode(r) = a THEN 'outbound' ELSE 'inbound' END AS direction;

// 3.3  N-hop neighbourhood (graph context panel in UI)
//      depth 1–3 recommended for readability
MATCH path = (a:Asset {asset_id: $asset_id})-[*1..2]-(b:Asset)
RETURN path;

// 3.4  Ancestors — what does this asset belong to / depend on?
MATCH (a:Asset {asset_id: $asset_id})-[r:CONTAINED_BY|ATTACHED_TO|USES*1..4]->(parent:Asset)
RETURN parent.resource_uid  AS parent_uid,
       parent.resource_type AS parent_type,
       parent.resource_name AS parent_name,
       length(()-[r*]-()) + 1 AS depth;

// 3.5  Descendants — what resources are under this asset?
MATCH (child:Asset)-[r:CONTAINED_BY|ATTACHED_TO*1..4]->(a:Asset {asset_id: $asset_id})
RETURN child.resource_uid  AS child_uid,
       child.resource_type AS child_type,
       child.resource_name AS child_name;


// ────────────────────────────────────────────────────────────
// 4. SERVICE-LEVEL TOPOLOGY (zoom-out view)
// ────────────────────────────────────────────────────────────

// 4.1  Service → service relationship map for one account
MATCH (a:Asset)-[:BELONGS_TO]->(acc:Account {account_id: $account_id, provider: $provider})
MATCH (a)-[r]->(b:Asset)-[:BELONGS_TO]->(acc)
WHERE a.service <> b.service
RETURN a.service AS from_service, type(r) AS rel_type,
       b.service AS to_service, count(r) AS edge_count
ORDER BY edge_count DESC;

// 4.2  Resource type to resource type relationship map
MATCH (a:Asset {provider: $provider, account_id: $account_id})-[r]->(b:Asset)
WHERE b.account_id = $account_id
RETURN a.resource_type AS from_type, type(r) AS rel_type,
       b.resource_type AS to_type, count(r) AS cnt
ORDER BY cnt DESC;


// ────────────────────────────────────────────────────────────
// 5. SECURITY ANALYSIS QUERIES
// ────────────────────────────────────────────────────────────

// 5.1  Encryption coverage — assets with and without a KMS key relationship
MATCH (a:Asset {provider: $provider, account_id: $account_id})
WHERE a.resource_type IN [
    'aws.s3.bucket', 'aws.rds.db_instance', 'aws.ec2.volume',
    'aws.sqs.queue', 'aws.sns.topic', 'aws.secretsmanager.secret',
    'aws.dynamodb.table', 'aws.kinesis.stream'
]
OPTIONAL MATCH (a)-[:ENCRYPTED_BY]->(k:Asset)
RETURN a.resource_type AS resource_type, a.resource_name AS name,
       a.resource_uid  AS uid,
       CASE WHEN k IS NOT NULL THEN 'encrypted' ELSE 'NOT_ENCRYPTED' END AS encryption_status,
       k.resource_uid  AS kms_key_uid
ORDER BY encryption_status DESC, resource_type;

// 5.2  S3 bucket public access chain
//      Find buckets not blocked by a public-access-block config
MATCH (bucket:Asset {resource_type: 'aws.s3.bucket', account_id: $account_id})
WHERE NOT (bucket)-[:CONTAINED_BY]->(:Asset {resource_type: 'aws.s3.bucket_public_access_block'})
  AND NOT (:Asset {resource_type: 'aws.s3.bucket_public_access_block'})-[:CONTAINED_BY]->(bucket)
RETURN bucket.resource_name AS bucket_name, bucket.resource_uid AS uid, bucket.region AS region;

// 5.3  IAM roles attached to compute resources (blast radius)
MATCH (compute:Asset {account_id: $account_id})
WHERE compute.resource_type IN [
    'aws.ec2.instance', 'aws.lambda.function',
    'aws.ecs.task_definition', 'aws.eks.nodegroup'
]
MATCH (compute)-[:USES]->(role:Asset {resource_type: 'aws.iam.role'})
RETURN compute.resource_type AS compute_type,
       compute.resource_name AS compute_name,
       role.resource_name    AS role_name,
       role.resource_uid     AS role_arn;

// 5.4  Security groups with broad scope — find SGs attached to many resources
MATCH (sg:Asset {resource_type: 'aws.ec2.security_group', account_id: $account_id})
MATCH (r:Asset)-[:USES]->(sg)
WITH sg, count(r) AS attached_count
WHERE attached_count > 5
RETURN sg.resource_name AS sg_name, sg.resource_uid AS sg_id,
       attached_count
ORDER BY attached_count DESC;

// 5.5  Network attack surface — resources with internet-facing security groups
MATCH (sg:Asset {resource_type: 'aws.ec2.security_group', account_id: $account_id})
WHERE sg.emitted_fields.has_open_ingress = true
   OR sg.emitted_fields.internet_accessible = true
MATCH (resource:Asset)-[:USES]->(sg)
RETURN resource.resource_type AS resource_type,
       resource.resource_name AS resource_name,
       resource.resource_uid  AS resource_uid,
       sg.resource_name       AS sg_name;

// 5.6  Lambda functions without VPC (potential data exfil path)
MATCH (fn:Asset {resource_type: 'aws.lambda.function', account_id: $account_id})
WHERE NOT (fn)-[:DEPLOYED_IN]->(:Asset {resource_type: 'aws.ec2.vpc'})
  AND NOT (fn)-[:USES]->(:Asset {resource_type: 'aws.ec2.vpc'})
RETURN fn.resource_name AS function_name, fn.resource_uid AS arn, fn.region AS region;

// 5.7  RDS instances without Multi-AZ or encryption
MATCH (db:Asset {resource_type: 'aws.rds.db_instance', account_id: $account_id})
WHERE db.emitted_fields.MultiAZ = false OR db.emitted_fields.StorageEncrypted = false
RETURN db.resource_name AS db_id,
       db.emitted_fields.MultiAZ          AS multi_az,
       db.emitted_fields.StorageEncrypted AS encrypted,
       db.region AS region;

// 5.8  ECS tasks with host networking (privilege escalation risk)
MATCH (td:Asset {resource_type: 'aws.ecs.task_definition', account_id: $account_id})
WHERE td.emitted_fields.NetworkMode = 'host'
RETURN td.resource_name AS task_family, td.resource_uid AS arn;

// 5.9  Secrets in environment variables (Lambda / ECS)
MATCH (fn:Asset {account_id: $account_id})
WHERE fn.resource_type IN ['aws.lambda.function', 'aws.ecs.task_definition']
  AND any(k IN keys(fn.emitted_fields) WHERE
    toLower(k) CONTAINS 'password' OR
    toLower(k) CONTAINS 'secret'   OR
    toLower(k) CONTAINS 'api_key'  OR
    toLower(k) CONTAINS 'token'
  )
RETURN fn.resource_type AS type, fn.resource_name AS name,
       fn.resource_uid AS uid, fn.region AS region;


// ────────────────────────────────────────────────────────────
// 6. BLAST RADIUS / IMPACT ANALYSIS
// ────────────────────────────────────────────────────────────

// 6.1  If a KMS key is compromised, what data is exposed?
MATCH (k:Asset {resource_uid: $kms_key_uid})
MATCH (resource:Asset)-[:ENCRYPTED_BY]->(k)
RETURN resource.resource_type AS resource_type,
       resource.resource_name AS resource_name,
       resource.account_id    AS account_id,
       resource.region        AS region
ORDER BY resource.resource_type;

// 6.2  If a VPC is deleted, what resources lose network access?
MATCH (vpc:Asset {resource_uid: $vpc_uid})
MATCH (resource:Asset)-[:DEPLOYED_IN|USES]->(vpc)
RETURN resource.resource_type AS resource_type,
       resource.resource_name AS resource_name,
       resource.resource_uid  AS uid
ORDER BY resource.resource_type;

// 6.3  If an IAM role is removed, which compute resources lose access?
MATCH (role:Asset {resource_uid: $role_arn})
MATCH (compute:Asset)-[:USES]->(role)
RETURN compute.resource_type AS type,
       compute.resource_name AS name,
       compute.resource_uid  AS uid,
       compute.account_id    AS account_id;

// 6.4  Full dependency chain (up to 5 hops) from a critical asset
MATCH path = (a:Asset {resource_uid: $start_uid})-[*1..5]->(dep:Asset)
WITH dep, min(length(path)) AS shortest_path
RETURN dep.resource_type AS dep_type, dep.resource_name AS dep_name,
       dep.resource_uid  AS dep_uid, shortest_path
ORDER BY shortest_path, dep_type;

// 6.5  Most connected assets (potential single points of failure)
MATCH (a:Asset {account_id: $account_id})
WITH a, size([(a)-[]-() | 1]) AS degree
WHERE degree > 10
RETURN a.resource_type AS type, a.resource_name AS name,
       a.resource_uid  AS uid, a.region AS region,
       degree
ORDER BY degree DESC
LIMIT 20;


// ────────────────────────────────────────────────────────────
// 7. TENANT-LEVEL AGGREGATIONS (multi-account dashboard)
// ────────────────────────────────────────────────────────────

// 7.1  Asset count per account within a tenant
MATCH (t:Tenant {tenant_id: $tenant_id})<-[:MEMBER_OF]-(acc:Account)<-[:BELONGS_TO]-(a:Asset)
RETURN acc.provider AS provider, acc.account_id AS account_id,
       count(a) AS assets
ORDER BY provider, account_id;

// 7.2  Resource type distribution across all tenant accounts
MATCH (t:Tenant {tenant_id: $tenant_id})<-[:MEMBER_OF]-(acc:Account)<-[:BELONGS_TO]-(a:Asset)
RETURN a.resource_type AS resource_type, acc.provider AS provider,
       count(a) AS cnt
ORDER BY cnt DESC
LIMIT 30;

// 7.3  Cross-account relationship count (shared services)
MATCH (t:Tenant {tenant_id: $tenant_id})<-[:MEMBER_OF]-(acc:Account)
MATCH (a:Asset)-[:BELONGS_TO]->(acc)
MATCH (a)-[r]->(b:Asset)-[:BELONGS_TO]->(acc2:Account)-[:MEMBER_OF]->(t)
WHERE acc <> acc2
RETURN acc.account_id AS from_account, type(r) AS rel_type,
       acc2.account_id AS to_account, count(r) AS cnt
ORDER BY cnt DESC;

// 7.4  Region distribution for one tenant
MATCH (t:Tenant {tenant_id: $tenant_id})<-[:MEMBER_OF]-(acc:Account)<-[:BELONGS_TO]-(a:Asset)
  -[:IN_REGION]->(r:Region)
RETURN r.region AS region, r.provider AS provider,
       count(a) AS asset_count
ORDER BY asset_count DESC;


// ────────────────────────────────────────────────────────────
// 8. GRAPH TRAVERSAL PATTERNS
// ────────────────────────────────────────────────────────────

// 8.1  Shortest path between two assets
MATCH (a:Asset {resource_uid: $source_uid}),
      (b:Asset {resource_uid: $target_uid}),
      path = shortestPath((a)-[*..10]-(b))
RETURN path;

// 8.2  All paths (up to length 6) between two assets
MATCH (a:Asset {resource_uid: $source_uid}),
      (b:Asset {resource_uid: $target_uid}),
      path = (a)-[*1..6]-(b)
RETURN path
LIMIT 25;

// 8.3  Find assets reachable via a specific relationship type
MATCH (a:Asset {resource_uid: $start_uid})-[:USES*1..4]->(target:Asset)
RETURN DISTINCT target.resource_type AS type, target.resource_name AS name,
       target.resource_uid AS uid
ORDER BY type, name;

// 8.4  Find all assets connected to a specific subnet
MATCH (subnet:Asset {resource_type: 'aws.ec2.subnet', resource_uid: $subnet_uid})
MATCH (resource:Asset)-[:DEPLOYED_IN|CONTAINED_BY]->(subnet)
RETURN resource.resource_type AS type, resource.resource_name AS name,
       resource.resource_uid  AS uid;

// 8.5  Load balancer → target group → instance chain
MATCH (lb:Asset {resource_type: 'aws.elasticloadbalancingv2.load_balancer', account_id: $account_id})
MATCH (lb)-[:USES]->(tg:Asset {resource_type: 'aws.elasticloadbalancingv2.target_group'})
MATCH (tg)-[:USES]->(instance:Asset {resource_type: 'aws.ec2.instance'})
RETURN lb.resource_name  AS load_balancer,
       tg.resource_name  AS target_group,
       instance.resource_name AS instance,
       instance.region   AS region;


// ────────────────────────────────────────────────────────────
// 9. COMPLIANCE / DRIFT DETECTION
// ────────────────────────────────────────────────────────────

// 9.1  Untagged critical resources
MATCH (a:Asset {account_id: $account_id})
WHERE a.resource_type IN [
    'aws.ec2.instance', 'aws.rds.db_instance',
    'aws.s3.bucket', 'aws.lambda.function'
]
  AND (a.tags IS NULL OR size(keys(a.tags)) = 0)
RETURN a.resource_type AS type, a.resource_name AS name,
       a.resource_uid  AS uid, a.region AS region;

// 9.2  Resources missing environment tag
MATCH (a:Asset {account_id: $account_id})
WHERE NOT exists(a.tags.Environment) AND NOT exists(a.tags.environment) AND NOT exists(a.tags.env)
RETURN a.resource_type AS type, a.resource_name AS name,
       a.resource_uid  AS uid
ORDER BY type, name
LIMIT 50;

// 9.3  Resources without encryption relationship (by service)
MATCH (a:Asset {account_id: $account_id, service: $service})
WHERE NOT (a)-[:ENCRYPTED_BY]->()
RETURN a.resource_type AS type, a.resource_name AS name,
       a.resource_uid  AS uid, a.region AS region;

// 9.4  EC2 instances not in an Auto Scaling Group
MATCH (i:Asset {resource_type: 'aws.ec2.instance', account_id: $account_id})
WHERE NOT (:Asset {resource_type: 'aws.autoscaling.auto_scaling_group'})-[:MANAGES]->(i)
  AND NOT (i)-[:CONTAINED_BY]->(:Asset {resource_type: 'aws.autoscaling.auto_scaling_group'})
RETURN i.resource_name AS instance_id, i.region AS region,
       i.emitted_fields.InstanceType AS instance_type;

// 9.5  Orphaned EBS volumes (not attached to any instance)
MATCH (v:Asset {resource_type: 'aws.ec2.volume', account_id: $account_id})
WHERE NOT (v)-[:ATTACHED_TO]->(:Asset {resource_type: 'aws.ec2.instance'})
  AND NOT (:Asset {resource_type: 'aws.ec2.instance'})-[:USES]->(v)
RETURN v.resource_name AS volume_id, v.region AS region,
       v.emitted_fields.Size AS size_gb,
       v.emitted_fields.State AS state;


// ────────────────────────────────────────────────────────────
// 10. UI HELPER PATTERNS
// ────────────────────────────────────────────────────────────

// 10.1  Type-ahead search by name prefix (asset search bar)
MATCH (a:Asset {account_id: $account_id})
WHERE a.resource_name STARTS WITH $name_prefix
   OR a.resource_uid  CONTAINS $name_prefix
RETURN a.asset_id, a.resource_type, a.resource_name, a.resource_uid
LIMIT 20;

// 10.2  Filter assets by tag key=value
MATCH (a:Asset {account_id: $account_id})
WHERE a.tags[$tag_key] = $tag_value
RETURN a.resource_type AS type, a.resource_name AS name,
       a.resource_uid  AS uid, a.region AS region
ORDER BY type, name;

// 10.3  Breadcrumb trail for a sub-resource (e.g. subnet → vpc → account)
MATCH (a:Asset {asset_id: $asset_id})
OPTIONAL MATCH path = (a)-[:CONTAINED_BY*1..5]->(top:Asset)
WHERE NOT (top)-[:CONTAINED_BY]->(:Asset)
WITH a, path,
     CASE WHEN path IS NULL THEN [a]
          ELSE nodes(path) END AS chain
UNWIND range(0, size(chain)-1) AS idx
RETURN idx AS depth,
       chain[idx].resource_type AS resource_type,
       chain[idx].resource_name AS resource_name,
       chain[idx].resource_uid  AS resource_uid;

// 10.4  Count relationship types for a given asset (summary card)
MATCH (a:Asset {asset_id: $asset_id})-[r]->(b)
RETURN type(r) AS rel_type, count(b) AS target_count
UNION ALL
MATCH (a:Asset {asset_id: $asset_id})<-[r]-(b)
RETURN type(r) AS rel_type, count(b) AS source_count;

// 10.5  Export full account subgraph as edge list (for D3.js / Sigma)
MATCH (a:Asset)-[:BELONGS_TO]->(acc:Account {account_id: $account_id, provider: $provider})
WITH collect(a) AS nodes
UNWIND nodes AS n
OPTIONAL MATCH (n)-[r]->(m:Asset)-[:BELONGS_TO]->(acc)
RETURN
  n.asset_id      AS source_id,
  n.resource_type AS source_type,
  n.resource_name AS source_name,
  type(r)         AS rel_type,
  m.asset_id      AS target_id,
  m.resource_type AS target_type,
  m.resource_name AS target_name;


// ────────────────────────────────────────────────────────────
// 11. AZURE-SPECIFIC QUERIES
// ────────────────────────────────────────────────────────────

// 11.1  Azure resource group containment
MATCH (rg:Asset {resource_type: 'microsoft.resources/resourcegroups', account_id: $subscription_id})
MATCH (r:Asset)-[:CONTAINED_BY]->(rg)
RETURN rg.resource_name AS resource_group,
       r.resource_type  AS resource_type,
       r.resource_name  AS resource_name
ORDER BY rg.resource_name, r.resource_type;

// 11.2  Azure VNet topology
MATCH (vnet:Asset {resource_type: 'microsoft.network/virtualnetworks', account_id: $subscription_id})
OPTIONAL MATCH (subnet:Asset)-[:CONTAINED_BY]->(vnet)
WHERE subnet.resource_type = 'microsoft.network/virtualnetworks/subnets'
OPTIONAL MATCH (nsg:Asset)-[:ATTACHED_TO]->(subnet)
WHERE nsg.resource_type = 'microsoft.network/networksecuritygroups'
RETURN vnet.resource_name AS vnet_name,
       subnet.resource_name AS subnet_name,
       nsg.resource_name AS nsg_name;

// 11.3  Azure managed identity usage
MATCH (id:Asset {resource_type: 'microsoft.managedidentity/userassignedidentities',
                 account_id: $subscription_id})
MATCH (r:Asset)-[:USES]->(id)
RETURN id.resource_name AS identity_name,
       r.resource_type  AS used_by_type,
       r.resource_name  AS used_by_name
ORDER BY id.resource_name;

// 11.4  Azure Key Vault usage across services
MATCH (kv:Asset {resource_type: 'microsoft.keyvault/vaults', account_id: $subscription_id})
MATCH (r:Asset)-[:USES|ENCRYPTED_BY]->(kv)
RETURN kv.resource_name AS key_vault, r.resource_type AS consumer_type,
       r.resource_name  AS consumer_name
ORDER BY kv.resource_name, r.resource_type;


// ────────────────────────────────────────────────────────────
// 12. GCP-SPECIFIC QUERIES
// ────────────────────────────────────────────────────────────

// 12.1  GCP project asset map
MATCH (a:Asset {provider: 'gcp', account_id: $project_id})
RETURN a.service AS service, a.resource_type AS resource_type, count(a) AS cnt
ORDER BY service, resource_type;

// 12.2  GCP service account usage
MATCH (sa:Asset {resource_type: 'iam.service_account', provider: 'gcp', account_id: $project_id})
MATCH (r:Asset)-[:USES]->(sa)
RETURN sa.resource_name AS service_account,
       r.resource_type  AS used_by_type,
       r.resource_name  AS used_by_name
ORDER BY sa.resource_name;

// 12.3  GCP KMS key usage
MATCH (key:Asset {resource_type: 'cloudkms.crypto_key', provider: 'gcp', account_id: $project_id})
MATCH (r:Asset)-[:ENCRYPTED_BY]->(key)
RETURN key.resource_name AS kms_key, r.resource_type AS encrypted_resource_type,
       count(r) AS cnt
ORDER BY cnt DESC;

// 12.4  GCP Pub/Sub topic → subscription → push endpoint chain
MATCH (topic:Asset {resource_type: 'pubsub.topic', account_id: $project_id})
MATCH (sub:Asset {resource_type: 'pubsub.subscription'})-[:USES]->(topic)
RETURN topic.resource_name AS topic_name,
       sub.resource_name   AS subscription_name,
       sub.emitted_fields.PushConfig AS push_config;


// ────────────────────────────────────────────────────────────
// 13. KUBERNETES-SPECIFIC QUERIES
// ────────────────────────────────────────────────────────────

// 13.1  Namespace overview
MATCH (ns:Asset {resource_type: 'core.namespace', provider: 'k8s'})
OPTIONAL MATCH (r:Asset)-[:CONTAINED_BY]->(ns)
RETURN ns.resource_name AS namespace, count(r) AS resource_count
ORDER BY resource_count DESC;

// 13.2  Workload → pod chain for one namespace
MATCH (ns:Asset {resource_type: 'core.namespace', resource_name: $namespace})
MATCH (workload:Asset)-[:CONTAINED_BY]->(ns)
WHERE workload.resource_type IN [
    'apps.deployment', 'apps.statefulset', 'apps.daemonset', 'batch.job'
]
OPTIONAL MATCH (workload)-[:MANAGES]->(pod:Asset {resource_type: 'core.pod'})
RETURN workload.resource_type AS workload_type,
       workload.resource_name AS workload_name,
       collect(pod.resource_name) AS managed_pods;

// 13.3  HPA → deployment scaling relationships
MATCH (hpa:Asset {resource_type: 'autoscaling.horizontalpodautoscaler', provider: 'k8s'})
MATCH (hpa)-[:SCALES]->(target:Asset)
RETURN hpa.resource_name AS hpa_name, hpa.resource_name AS namespace,
       target.resource_type AS target_type, target.resource_name AS target_name,
       hpa.emitted_fields.minReplicas AS min_replicas,
       hpa.emitted_fields.maxReplicas AS max_replicas;

// 13.4  Services without a matching workload (stale services)
MATCH (svc:Asset {resource_type: 'core.service', provider: 'k8s'})
WHERE svc.resource_name <> 'kubernetes'
  AND NOT (svc)-[:ROUTES_TO]->(:Asset)
  AND NOT (:Asset)-[:USES]->(svc)
RETURN svc.resource_name AS service_name,
       svc.emitted_fields.namespace AS namespace,
       svc.emitted_fields.selector AS selector;

// 13.5  RBAC: ClusterRole → ServiceAccount → workload (privilege audit)
MATCH (rb:Asset {resource_type: 'rbac.clusterrolebinding', provider: 'k8s'})
MATCH (rb)-[:GRANTS]->(role:Asset {resource_type: 'rbac.clusterrole'})
MATCH (rb)-[:BINDS]->(sa:Asset {resource_type: 'core.serviceaccount'})
OPTIONAL MATCH (workload:Asset)-[:USES]->(sa)
RETURN role.resource_name AS cluster_role, sa.resource_name AS service_account,
       sa.emitted_fields.namespace AS namespace,
       collect(DISTINCT workload.resource_name) AS used_by_workloads;


// ────────────────────────────────────────────────────────────
// 14. QUICK DIAGNOSTICS
// ────────────────────────────────────────────────────────────

// 14.1  Graph health check
MATCH (a:Asset) RETURN count(a) AS total_assets;
MATCH ()-[r:BELONGS_TO]->(acc:Account) RETURN count(r) AS assets_linked_to_accounts;
MATCH ()-[r]->() WHERE type(r) NOT IN ['BELONGS_TO','MEMBER_OF','IN_REGION']
  RETURN count(r) AS inventory_relationship_count;

// 14.2  Assets with no outbound or inbound inventory relationships
//       (isolated nodes — may indicate missing rules)
MATCH (a:Asset {account_id: $account_id})
WHERE NOT (a)-[:CONTAINED_BY|USES|ENCRYPTED_BY|ATTACHED_TO|DEPLOYED_IN|MANAGES|ROUTES_TO|SCALES|GRANTS|BINDS]->()
  AND NOT ()<-[:CONTAINED_BY|USES|ENCRYPTED_BY|ATTACHED_TO|DEPLOYED_IN|MANAGES|ROUTES_TO|SCALES|GRANTS|BINDS]-(a)
RETURN a.resource_type AS resource_type, count(a) AS isolated_count
ORDER BY isolated_count DESC;

// 14.3  Rule hit-rate summary (which relationship types have most edges)
MATCH (a:Asset)-[r]->(b:Asset)
RETURN type(r) AS rel_type,
       r.provider AS provider,
       count(r) AS edge_count
ORDER BY edge_count DESC
LIMIT 30;
