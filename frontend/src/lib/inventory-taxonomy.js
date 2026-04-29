/**
 * Inventory Taxonomy — client-side lookup tables.
 *
 * Maps the 35 canonical relation_types and 14 resource domains
 * to colors, labels, and icons so the UI can render taxonomy-aware
 * views without extra API calls.
 *
 * Source of truth: engines/inventory/inventory_engine/config/relation_types.json
 */

// ── 7 Relation Families ─────────────────────────────────────────────────────
// Grouped from the 11 backend categories into 7 UI-friendly families.
export const RELATION_FAMILIES = {
  structural: {
    label: 'Structural',
    color: '#6366f1',
    iconName: 'Layers',
    description: 'Containment, grouping, attachment',
  },
  network: {
    label: 'Network',
    color: '#3b82f6',
    iconName: 'Network',
    description: 'Connectivity, routing, DNS',
  },
  security: {
    label: 'Security',
    color: '#ef4444',
    iconName: 'Shield',
    description: 'Firewall, exposure, protection',
  },
  identity: {
    label: 'Identity & Access',
    color: '#f59e0b',
    iconName: 'Key',
    description: 'IAM roles, policies, authentication',
  },
  data: {
    label: 'Data Protection',
    color: '#10b981',
    iconName: 'Lock',
    description: 'Encryption, backup, replication',
  },
  execution: {
    label: 'Execution',
    color: '#8b5cf6',
    iconName: 'Zap',
    description: 'Invocation, triggers, dependencies',
  },
  governance: {
    label: 'Governance',
    color: '#64748b',
    iconName: 'ClipboardCheck',
    description: 'Logging, monitoring, compliance',
  },
};

// ── 35+ Relation Types → Family mapping ──────────────────────────────────────
// Keys match the `relation_type` values stored in `inventory_relationships`.
// Backend `_RELATION_FAMILY_MAP` mirrors this 1:1 (api_server.py:1257).
export const RELATION_TYPE_MAP = {
  // Structural
  contained_by:       { family: 'structural', sub: 'containment' },
  contains:           { family: 'structural', sub: 'containment' },
  member_of:          { family: 'structural', sub: 'grouping' },
  attached_to:        { family: 'structural', sub: 'attachment' },
  associated_with:    { family: 'structural', sub: 'association' },
  references:         { family: 'structural', sub: 'reference' },
  // Network
  peers_with:         { family: 'network', sub: 'peering' },
  connected_to:       { family: 'network', sub: 'connectivity' },
  routes_to:          { family: 'network', sub: 'routing' },
  forwards_to:        { family: 'network', sub: 'forwarding' },
  serves_traffic_for: { family: 'network', sub: 'load_balancing' },
  resolves_to:        { family: 'network', sub: 'dns' },
  // Security
  allows_traffic_from:{ family: 'security', sub: 'firewall_ingress' },
  allows_traffic_to:  { family: 'security', sub: 'firewall_egress' },
  restricted_to:      { family: 'security', sub: 'restriction' },
  exposed_through:    { family: 'security', sub: 'exposure' },
  internet_connected: { family: 'security', sub: 'internet' },
  protected_by:       { family: 'security', sub: 'protection' },
  scanned_by:         { family: 'security', sub: 'scanning' },
  // Identity & Access
  uses:               { family: 'identity', sub: 'role_usage' },
  assumes:            { family: 'identity', sub: 'role_assumption' },
  has_policy:         { family: 'identity', sub: 'policy_attachment' },
  grants_access_to:   { family: 'identity', sub: 'permission_grant' },
  controlled_by:      { family: 'identity', sub: 'ownership' },
  authenticated_by:   { family: 'identity', sub: 'authentication' },
  // Data Protection
  encrypted_by:       { family: 'data', sub: 'encryption' },
  stores_data_in:     { family: 'data', sub: 'storage' },
  backs_up_to:        { family: 'data', sub: 'backup' },
  replicates_to:      { family: 'data', sub: 'replication' },
  // Execution & Dependency
  runs_on:            { family: 'execution', sub: 'hosting' },
  invokes:            { family: 'execution', sub: 'invocation' },
  triggers:           { family: 'execution', sub: 'event_trigger' },
  triggered_by:       { family: 'execution', sub: 'event_trigger' },
  publishes_to:       { family: 'execution', sub: 'pub_sub' },
  subscribes_to:      { family: 'execution', sub: 'subscription' },
  scales_with:        { family: 'execution', sub: 'scaling' },
  cached_by:          { family: 'execution', sub: 'caching' },
  depends_on:         { family: 'execution', sub: 'dependency' },
  // Governance
  manages:            { family: 'governance', sub: 'management' },
  deployed_by:        { family: 'governance', sub: 'deployment' },
  applies_to:         { family: 'governance', sub: 'policy_application' },
  complies_with:      { family: 'governance', sub: 'compliance' },
  logging_enabled_to: { family: 'governance', sub: 'logging' },
  monitored_by:       { family: 'governance', sub: 'monitoring' },
};

// ── 14 Resource Domains ──────────────────────────────────────────────────────
// Maps service names/resource_types to semantic domains for UI categorization.
export const RESOURCE_DOMAINS = {
  IDENTITY:         { label: 'Identity',         color: '#f59e0b', iconName: 'KeyRound',        services: ['iam', 'cognito', 'sso', 'sts', 'identity', 'directory-service'] },
  NETWORK:          { label: 'Network',          color: '#6366f1', iconName: 'Network',         services: ['vpc', 'subnet', 'route-table', 'route53', 'transit-gateway', 'internet-gateway', 'nat-gateway', 'direct-connect', 'vpn', 'endpoint'] },
  NETWORK_SECURITY: { label: 'Net Security',     color: '#ef4444', iconName: 'Shield',          services: ['security-group', 'network-acl', 'waf', 'firewall', 'shield', 'guardduty', 'macie'] },
  COMPUTE:          { label: 'Compute',          color: '#3b82f6', iconName: 'Server',          services: ['ec2', 'lightsail', 'batch', 'outposts', 'auto-scaling', 'autoscaling'] },
  CONTAINER_K8S:    { label: 'Containers',       color: '#06b6d4', iconName: 'Box',             services: ['ecs', 'eks', 'ecr', 'fargate'] },
  SERVERLESS:       { label: 'Serverless',       color: '#d946ef', iconName: 'Zap',             services: ['lambda', 'step-functions', 'apprunner'] },
  STORAGE:          { label: 'Storage',          color: '#10b981', iconName: 'HardDrive',       services: ['s3', 'ebs', 'efs', 'fsx', 'glacier', 'storage-gateway'] },
  DATABASE:         { label: 'Database',         color: '#f97316', iconName: 'Database',        services: ['rds', 'dynamodb', 'elasticache', 'redshift', 'neptune', 'documentdb', 'keyspaces', 'timestream'] },
  SECRET_CRYPTO:    { label: 'Secrets & Keys',   color: '#ec4899', iconName: 'Lock',            services: ['kms', 'secretsmanager', 'acm', 'cloudhsm'] },
  APPLICATION:      { label: 'Application',      color: '#8b5cf6', iconName: 'Globe',           services: ['apigateway', 'cloudfront', 'appsync', 'amplify', 'elastic-beanstalk', 'app-mesh'] },
  MESSAGING:        { label: 'Messaging',        color: '#14b8a6', iconName: 'MessageSquare',   services: ['sqs', 'sns', 'kinesis', 'msk', 'eventbridge', 'mq'] },
  MONITORING:       { label: 'Monitoring',       color: '#64748b', iconName: 'Activity',        services: ['cloudwatch', 'cloudtrail', 'logs', 'x-ray', 'inspector'] },
  GOVERNANCE:       { label: 'Governance',       color: '#a855f7', iconName: 'ClipboardCheck',  services: ['config', 'organizations', 'ssm', 'backup', 'control-tower', 'service-catalog'] },
  AI_ML:            { label: 'AI / ML',          color: '#d946ef', iconName: 'Brain',           services: ['sagemaker', 'bedrock', 'comprehend', 'rekognition', 'textract', 'polly', 'lex'] },
};

// Build a reverse index: service-keyword → domain key
const _SERVICE_DOMAIN_INDEX = {};
Object.entries(RESOURCE_DOMAINS).forEach(([domainKey, meta]) => {
  meta.services.forEach((svc) => {
    _SERVICE_DOMAIN_INDEX[svc] = domainKey;
  });
});

// ── Helper: resolve a relation_type string to its family metadata ────────────
export function resolveRelationType(relType) {
  if (!relType) return null;
  const entry = RELATION_TYPE_MAP[relType];
  if (!entry) return { family: 'governance', color: '#64748b', label: relType.replace(/_/g, ' '), sub: 'unknown' };
  const familyMeta = RELATION_FAMILIES[entry.family];
  return {
    family: entry.family,
    sub: entry.sub,
    color: familyMeta?.color || '#64748b',
    label: familyMeta?.label || entry.family,
    iconName: familyMeta?.iconName || 'Circle',
  };
}

// ── Helper: classify a resource_type or service string into a domain ─────────
export function classifyResourceDomain(resourceTypeOrService) {
  if (!resourceTypeOrService) return { key: 'GOVERNANCE', ...RESOURCE_DOMAINS.GOVERNANCE };
  const raw = resourceTypeOrService.toLowerCase().replace(/[.:]/g, '-');

  // Direct match on known service keywords
  for (const svc of Object.keys(_SERVICE_DOMAIN_INDEX)) {
    if (raw.includes(svc)) {
      const key = _SERVICE_DOMAIN_INDEX[svc];
      return { key, ...RESOURCE_DOMAINS[key] };
    }
  }

  // Fallback heuristics
  if (raw.includes('instance') || raw.includes('server') || raw.includes('vm'))
    return { key: 'COMPUTE', ...RESOURCE_DOMAINS.COMPUTE };
  if (raw.includes('bucket') || raw.includes('volume') || raw.includes('disk'))
    return { key: 'STORAGE', ...RESOURCE_DOMAINS.STORAGE };
  if (raw.includes('database') || raw.includes('cluster') || raw.includes('table'))
    return { key: 'DATABASE', ...RESOURCE_DOMAINS.DATABASE };
  if (raw.includes('function'))
    return { key: 'SERVERLESS', ...RESOURCE_DOMAINS.SERVERLESS };
  if (raw.includes('role') || raw.includes('user') || raw.includes('group') || raw.includes('policy'))
    return { key: 'IDENTITY', ...RESOURCE_DOMAINS.IDENTITY };
  if (raw.includes('key') || raw.includes('secret') || raw.includes('certificate'))
    return { key: 'SECRET_CRYPTO', ...RESOURCE_DOMAINS.SECRET_CRYPTO };
  if (raw.includes('queue') || raw.includes('topic') || raw.includes('stream'))
    return { key: 'MESSAGING', ...RESOURCE_DOMAINS.MESSAGING };
  if (raw.includes('log') || raw.includes('alarm') || raw.includes('trail'))
    return { key: 'MONITORING', ...RESOURCE_DOMAINS.MONITORING };

  return { key: 'GOVERNANCE', ...RESOURCE_DOMAINS.GOVERNANCE };
}

// ── Helper: classify a link's family for graph coloring ──────────────────────
// Input: relation_type string OR the backend `type` field (which is already a family key)
export function classifyLinkFamily(relTypeOrFamily) {
  if (!relTypeOrFamily) return 'governance';
  // If it's already a family key (from backend _classify_link_type), return it
  if (RELATION_FAMILIES[relTypeOrFamily]) return relTypeOrFamily;
  // Otherwise resolve from relation_type
  const entry = RELATION_TYPE_MAP[relTypeOrFamily];
  return entry?.family || 'governance';
}

// ── Lucide Icon Mapping (service/type → icon name) ───────────────────────────
export const SERVICE_ICONS = {
  // AWS resource types
  'ec2.instance': 'Server', 'ec2.vpc': 'Network', 'ec2.subnet': 'Layers',
  'ec2.security-group': 'Shield', 'ec2.internet-gateway': 'Globe',
  'ec2.nat-gateway': 'ArrowLeftRight', 'ec2.load-balancer': 'Scale',
  'ec2.network-interface': 'Cable', 'ec2.network-acl': 'ShieldCheck',
  'ec2.route-table': 'Route', 'ec2.eip': 'MapPin',
  // Service-level fallbacks (if exact type not matched)
  'elbv2': 'Scale', 'rds': 'Database', 'dynamodb': 'Table',
  'elasticache': 'Zap', 'redshift': 'BarChart3',
  's3': 'HardDrive', 'ebs': 'Disc', 'efs': 'FolderOpen', 'fsx': 'FolderOpen',
  'lambda': 'Cpu', 'ecs': 'Container', 'eks': 'Ship', 'fargate': 'Container',
  'iam': 'KeyRound', 'kms': 'Lock', 'secretsmanager': 'KeySquare', 'acm': 'Award',
  'cloudwatch': 'Activity', 'cloudtrail': 'FileSearch', 'logs': 'ScrollText',
  'config': 'Settings', 'route53': 'Globe2', 'cloudfront': 'Gauge',
  'apigateway': 'Webhook', 'sqs': 'Inbox', 'sns': 'Bell',
  'kinesis': 'Workflow', 'waf': 'ShieldAlert', 'guardduty': 'Eye',
  'cognito': 'Users', 'sso': 'Users', 'sagemaker': 'Brain',
  'step-functions': 'GitBranch', 'batch': 'Layers',
  // Azure equivalents
  'network.virtual-network': 'Network', 'network.subnet': 'Layers',
  'network.network-security-group': 'Shield', 'compute.virtual-machine': 'Server',
  'sql.server': 'Database', 'storage.storage-account': 'HardDrive',
  // GCP equivalents
  'vpc.vpc': 'Network', 'vpc.subnet': 'Layers', 'compute.instance': 'Server',
  // OCI equivalents
  'core.vcn': 'Network', 'core.subnet': 'Layers', 'core.instance': 'Server',
  'core.internet-gateway': 'Globe',
};

export function getServiceIcon(resourceType) {
  if (!resourceType) return 'Box';
  const exact = SERVICE_ICONS[resourceType];
  if (exact) return exact;
  const svc = resourceType.split('.')[0];
  return SERVICE_ICONS[svc] || 'Box';
}

// ── Multi-CSP Virtual Network Type Detection ─────────────────────────────────
export const VNET_TYPES = new Set([
  'ec2.vpc', 'vpc.vpc',                           // AWS, GCP
  'network.virtual-network', 'vnet.vnet',          // Azure
  'vcn.vcn', 'core.vcn',                           // OCI
]);

export const SUBNET_TYPES = new Set([
  'ec2.subnet', 'vpc.subnet',                      // AWS, GCP
  'network.subnet',                                 // Azure
  'core.subnet',                                     // OCI
]);

export const IGW_TYPES = new Set([
  'ec2.internet-gateway',                           // AWS
  'core.internet-gateway',                           // OCI
]);

// ── Global Services (not VPC-bound — fallback only) ──────────────────────────
// If a resource has a contained_by VPC relationship, it overrides this set.
export const GLOBAL_SERVICES = new Set([
  'iam', 's3', 'cloudwatch', 'cloudtrail', 'kms', 'secretsmanager',
  'route53', 'cloudfront', 'acm', 'organizations', 'config', 'sso',
  'sts', 'cognito', 'waf', 'shield', 'inspector', 'guardduty',
  'dynamodb', 'sns', 'sqs', 'kinesis', 'eventbridge',
  'apigateway', 'ecr', 'ssm', 'backup', 'sagemaker', 'bedrock',
]);

export function isGlobalService(resourceType) {
  const svc = (resourceType || '').split('.')[0].toLowerCase();
  return GLOBAL_SERVICES.has(svc);
}

// ── CSP-specific label helpers ───────────────────────────────────────────────
const VNET_LABELS = { aws: 'VPC', azure: 'VNet', gcp: 'VPC', oci: 'VCN' };
export function getVNetLabel(provider) {
  return VNET_LABELS[(provider || '').toLowerCase()] || 'VPC';
}

// ── 6 Resource Tiers (layered architecture within containment boxes) ─────────
// Defines the top-to-bottom rendering order within each VPC/Subnet box.
export const RESOURCE_TIERS = {
  EDGE: {
    order: 0,
    label: 'Edge / Gateway',
    iconName: 'Network',
    color: '#10b981',
    types: new Set([
      'ec2.internet-gateway', 'ec2.nat-gateway', 'ec2.vpn-gateway', 'ec2.eip',
      'ec2.transit-gateway', 'ec2.transit-gateway-attachment',
      'core.internet-gateway', 'core.nat-gateway',
      'cloudfront.distribution', 'apigateway.rest-api', 'apigateway.http-api',
      'waf.web-acl', 'route53.hosted-zone', 'route53.record-set',
      'network.application-gateway', 'network.frontdoor',
      'compute.global-address', 'compute.forwarding-rule',
    ]),
  },
  LOAD_BALANCER: {
    order: 1,
    label: 'Load Balancer',
    iconName: 'Scale',
    color: '#6366f1',
    types: new Set([
      'elbv2.balancer', 'elbv2.target-group', 'elbv2.listener',
      'ec2.load-balancer', 'elasticloadbalancingv2.loadbalancer',
      'network.load-balancer',
    ]),
  },
  COMPUTE: {
    order: 2,
    label: 'Compute',
    iconName: 'Server',
    color: '#3b82f6',
    types: new Set([
      'ec2.instance', 'ec2.auto-scaling-group', 'ec2.launch_template',
      'lambda.function', 'lambda.layer-version',
      'ecs.task', 'ecs.service', 'ecs.cluster',
      'eks.cluster', 'eks.nodegroup',
      'batch.job', 'batch.compute-environment',
      'apprunner.service', 'lightsail.instance',
      'compute.virtual-machine', 'compute.virtual-machine-scale-set',
      'compute.instance',
      'core.instance',
    ]),
  },
  DATA: {
    order: 3,
    label: 'Data & Storage',
    iconName: 'Database',
    color: '#f97316',
    types: new Set([
      'rds.db-instance', 'rds.db-cluster', 'rds.db-proxy',
      'dynamodb.table', 'elasticache.cluster', 'elasticache.replication-group',
      's3.bucket', 'efs.file-system', 'fsx.file-system', 'ebs.volume', 'ec2.volume',
      'redshift.cluster', 'neptune.db-cluster', 'documentdb.db-cluster',
      'keyspaces.keyspace', 'timestream.database',
      'kinesis.stream', 'sqs.queue', 'sns.topic',
      'msk.cluster', 'mq.broker', 'eventbridge.rule',
      'sql.server', 'sql.database', 'storage.storage-account',
      'cosmosdb.database-account',
      'sql.instance', 'storage.bucket',
    ]),
  },
  SECURITY: {
    order: 4,
    label: 'Security & Identity',
    iconName: 'Shield',
    color: '#f59e0b',
    types: new Set([
      'iam.role', 'iam.user', 'iam.group', 'iam.policy', 'iam.instance-profile',
      'ec2.instance-profile',
      'kms.key', 'secretsmanager.secret', 'acm.certificate',
      'cognito.user-pool', 'cognito.identity-pool',
      'sso.instance', 'sts.assumed-role',
      'guardduty.detector', 'inspector.assessment-target', 'macie.session',
      'keyvault.vault',
    ]),
  },
  MONITORING: {
    order: 5,
    label: 'Monitoring & Governance',
    iconName: 'Activity',
    color: '#64748b',
    types: new Set([
      'cloudwatch.alarm', 'cloudwatch.log-group',
      'cloudtrail.trail', 'config.rule', 'config.recorder',
      'ssm.parameter', 'ssm.document',
      'organizations.account', 'backup.vault', 'backup.plan',
      'x-ray.group',
    ]),
  },
};

// Tier rendering order
export const TIER_ORDER = ['EDGE', 'LOAD_BALANCER', 'COMPUTE', 'DATA', 'SECURITY', 'MONITORING'];

// Build reverse index: resource_type → tier key
const _TYPE_TIER_INDEX = {};
Object.entries(RESOURCE_TIERS).forEach(([tierKey, meta]) => {
  meta.types.forEach((type) => {
    _TYPE_TIER_INDEX[type] = tierKey;
  });
});

/**
 * Returns true if this resource type is a generic fallback (quota/metadata junk).
 * Catches normalizer artifacts like:
 *   ec2.resource                                   → dot-resource suffix
 *   ec2.vpc_block_public_access_exclusion_resource  → underscore-resource suffix
 *   ec2.local_gateway_route_table_vpc_association_local_gateway_route_table → >40 chars
 *   ec2.subnet_subnet                              → doubled word
 */
export function isJunkResourceType(resourceType) {
  if (!resourceType) return true;
  if (resourceType.endsWith('.resource')) return true;
  const JUNK_SUFFIXES = ['.quota', '.limit', '.account-setting', '.attribute'];
  if (JUNK_SUFFIXES.some(s => resourceType.endsWith(s))) return true;

  // Check sub-type part (after the dot) for normalizer artifacts
  const dotIdx = resourceType.indexOf('.');
  if (dotIdx >= 0) {
    const subType = resourceType.slice(dotIdx + 1);
    // Sub-type ending with _resource (underscore variant of .resource)
    if (subType.endsWith('_resource')) return true;
    // Very long sub-type (>40 chars) = normalizer compound artifact
    if (subType.length > 40) return true;
    // Doubled word patterns like subnet_subnet, table_table
    const parts = subType.split(/[-_]/);
    if (parts.length >= 2 && parts[parts.length - 1] === parts[parts.length - 2]) return true;
  }

  return false;
}

/**
 * Classify a resource type into an architecture tier.
 * Returns { key, ...tierMeta } or null if unmapped.
 */
export function classifyResourceTier(resourceType) {
  if (!resourceType || isJunkResourceType(resourceType)) return null;

  // Direct match on full resource_type
  const directKey = _TYPE_TIER_INDEX[resourceType];
  if (directKey) return { key: directKey, ...RESOURCE_TIERS[directKey] };

  // Fallback: match by service prefix ONLY if the service belongs to a single tier
  // (ec2.* spans multiple tiers, so we skip ambiguous services)
  const svc = resourceType.split('.')[0];
  let matchedTier = null;
  let ambiguous = false;
  for (const [tierKey, meta] of Object.entries(RESOURCE_TIERS)) {
    for (const t of meta.types) {
      if (t.startsWith(svc + '.')) {
        if (matchedTier && matchedTier !== tierKey) {
          ambiguous = true;
          break;
        }
        matchedTier = tierKey;
        break; // found match in this tier, check next tier
      }
    }
    if (ambiguous) break;
  }
  if (matchedTier && !ambiguous) {
    return { key: matchedTier, ...RESOURCE_TIERS[matchedTier] };
  }

  return null; // unmapped or ambiguous → uncategorized
}

// ── Nesting layer colors (monochromatic, same family) ────────────────────────
// Progressive opacity from dark (outermost) to light (innermost).
// Base color: slate/blue-gray (#64748b).
export const NESTING_COLORS = {
  account:  { bg: 'rgba(100,116,139,0.03)', border: 'rgba(100,116,139,0.25)' },
  region:   { bg: 'rgba(100,116,139,0.04)', border: 'rgba(100,116,139,0.18)' },
  vpc:      { bg: 'rgba(100,116,139,0.06)', border: 'rgba(100,116,139,0.30)' },
  az:       { bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.15)' },
  subnet:   { bg: 'rgba(100,116,139,0.10)', border: 'rgba(100,116,139,0.22)' },
  tier:     { bg: 'rgba(100,116,139,0.03)', border: 'transparent' },
};

// ── Helper: group relationships by family ────────────────────────────────────
// Returns: [{ family, familyMeta, relationships: [...] }, ...]
export function groupRelationshipsByFamily(relationships) {
  const groups = {};
  (relationships || []).forEach((rel) => {
    const relType = rel.relationship_type || rel.relation_type || 'associated_with';
    const resolved = resolveRelationType(relType);
    const familyKey = resolved?.family || 'governance';
    if (!groups[familyKey]) {
      groups[familyKey] = {
        family: familyKey,
        familyMeta: RELATION_FAMILIES[familyKey] || RELATION_FAMILIES.governance,
        relationships: [],
      };
    }
    groups[familyKey].relationships.push({ ...rel, _resolved: resolved });
  });

  // Sort families by a fixed display order
  const ORDER = ['structural', 'network', 'security', 'identity', 'data', 'execution', 'governance'];
  return ORDER
    .filter((f) => groups[f])
    .map((f) => groups[f]);
}
