// Per-engine module definitions — single source of truth for the whole UI.
// Each engine's findings carry a module field (see moduleField below).
// The UI reads this field and maps it to { label, color } for rendering.

export const ENGINE_MODULES = {

  iam: {
    moduleField: 'iam_module',
    modules: {
      // canonical keys (backend)
      root_account:           { label: 'Root Account',          color: '#ef4444' },
      mfa_enforcement:        { label: 'MFA Enforcement',       color: '#f97316' },
      password_policy:        { label: 'Password Policy',       color: '#eab308' },
      excessive_permissions:  { label: 'Excessive Permissions', color: '#8b5cf6' },
      key_management:         { label: 'Key Management',        color: '#3b82f6' },
      service_accounts:       { label: 'Service Accounts',      color: '#14b8a6' },
      // aliases used by some rules / frontend filters
      role_management:        { label: 'Roles & Policies',      color: '#6366f1' },
      access_keys:            { label: 'Access Keys',           color: '#3b82f6' },
      mfa:                    { label: 'MFA',                   color: '#f97316' },
      least_privilege:        { label: 'Least Privilege',       color: '#8b5cf6' },
      access_control:         { label: 'Access Control',        color: '#14b8a6' },
    },
  },

  datasec: {
    moduleField: null, // resolved via resolveDataSecModule()
    modules: {
      data_protection_encryption: { label: 'Data Protection',    color: '#3b82f6' },
      data_access_governance:     { label: 'Access Governance',  color: '#14b8a6' },
      data_activity_monitoring:   { label: 'Activity Monitoring',color: '#8b5cf6' },
      data_residency:             { label: 'Data Residency',     color: '#6366f1' },
      data_compliance:            { label: 'Data Compliance',    color: '#f97316' },
      data_classification:        { label: 'Classification',     color: '#ec4899' },
      // aliases
      encryption:                 { label: 'Data Protection',    color: '#3b82f6' },
      encryption_at_rest:         { label: 'Data Protection',    color: '#3b82f6' },
      sensitive_data_protection:  { label: 'Data Protection',    color: '#3b82f6' },
      access_control:             { label: 'Access Governance',  color: '#14b8a6' },
      public_access_prevention:   { label: 'Access Governance',  color: '#14b8a6' },
      audit_logging:              { label: 'Activity Monitoring',color: '#8b5cf6' },
      data_protection:            { label: 'Data Compliance',    color: '#f97316' },
      dlp:                        { label: 'Data Compliance',    color: '#f97316' },
    },
  },

  'network-security': {
    moduleField: 'security_domain',
    modules: {
      security_groups:   { label: 'Security Groups',   color: '#6366f1' },
      internet_exposure: { label: 'Internet Exposure', color: '#ef4444' },
      waf_protection:    { label: 'WAF / DDoS',        color: '#0ea5e9' },
      vpc_topology:      { label: 'VPC Topology',      color: '#8b5cf6' },
      dns_security:      { label: 'DNS Security',      color: '#14b8a6' },
      load_balancer:     { label: 'Load Balancer',     color: '#10b981' },
    },
  },

  encryption: {
    moduleField: 'encryption_domain',
    modules: {
      kms_keys:       { label: 'KMS Keys',      color: '#8b5cf6' },
      s3_encryption:  { label: 'S3 Buckets',    color: '#ef4444' },
      rds_encryption: { label: 'RDS Instances', color: '#3b82f6' },
      ebs_encryption: { label: 'EBS Volumes',   color: '#f97316' },
      tls_https:      { label: 'TLS / HTTPS',   color: '#06b6d4' },
      certificates:   { label: 'Certificates',  color: '#10b981' },
    },
  },

  'container-security': {
    moduleField: 'security_domain',
    modules: {
      cluster_security:  { label: 'Cluster Security',  color: '#8b5cf6' },
      workload_security: { label: 'Workload Security', color: '#3b82f6' },
      image_security:    { label: 'Image Security',    color: '#06b6d4' },
      network_exposure:  { label: 'Network Exposure',  color: '#f97316' },
      rbac_access:       { label: 'RBAC Access',       color: '#22c55e' },
      runtime_audit:     { label: 'Runtime Audit',     color: '#eab308' },
    },
  },

  'database-security': {
    moduleField: 'security_domain',
    modules: {
      access_control:   { label: 'Access Control',    color: '#8b5cf6' },
      encryption:       { label: 'Encryption',        color: '#3b82f6' },
      audit_logging:    { label: 'Audit Logging',     color: '#06b6d4' },
      backup_recovery:  { label: 'Backup & Recovery', color: '#22c55e' },
      network_security: { label: 'Network Security',  color: '#f97316' },
      configuration:    { label: 'Configuration',     color: '#eab308' },
    },
  },

  'ai-security': {
    moduleField: 'ai_module',
    modules: {
      model_security:    { label: 'Model Security',    color: '#8b5cf6' },
      endpoint_security: { label: 'Endpoint Security', color: '#3b82f6' },
      prompt_security:   { label: 'Prompt Security',   color: '#ef4444' },
      data_pipeline:     { label: 'Data Pipeline',     color: '#06b6d4' },
      ai_governance:     { label: 'AI Governance',     color: '#10b981' },
      access_control:    { label: 'Access Control',    color: '#f59e0b' },
    },
  },

  misconfig: {
    moduleField: 'posture_category',
    modules: {
      iam:              { label: 'IAM',              color: '#6366f1' },
      network:          { label: 'Network',          color: '#ef4444' },
      storage:          { label: 'Storage',          color: '#3b82f6' },
      encryption:       { label: 'Encryption',       color: '#8b5cf6' },
      logging:          { label: 'Logging',          color: '#14b8a6' },
      compute:          { label: 'Compute',          color: '#f97316' },
      database:         { label: 'Database',         color: '#22c55e' },
      serverless:       { label: 'Serverless',       color: '#ec4899' },
    },
  },

  // CDR uses behavioral detections, not config modules — map to detection types
  cdr: {
    moduleField: 'detection_type',
    modules: {
      credential_access:   { label: 'Credential Access',  color: '#ef4444' },
      privilege_escalation:{ label: 'Privilege Escalation',color: '#f97316' },
      data_exfiltration:   { label: 'Data Exfiltration',  color: '#8b5cf6' },
      lateral_movement:    { label: 'Lateral Movement',   color: '#eab308' },
      persistence:         { label: 'Persistence',        color: '#14b8a6' },
      discovery:           { label: 'Discovery',          color: '#3b82f6' },
    },
  },
};

// Resolve the module key for a finding row
export function resolveModule(finding, engine) {
  const cfg = ENGINE_MODULES[engine];
  if (!cfg) return null;

  let raw = null;

  if (engine === 'datasec') {
    const mods = finding.datasec_modules || finding.data_security_modules || [];
    raw = mods[0] || finding.posture_category || finding.domain || finding.security_domain || '';
  } else {
    raw = finding[cfg.moduleField] || finding.security_domain || finding.posture_category || '';
  }

  const key = (raw || '').toLowerCase().trim();
  const meta = cfg.modules[key];
  return meta ? { key, ...meta } : (key ? { key, label: key.replace(/_/g, ' '), color: '#64748b' } : null);
}

export function getEngineModules(engine) {
  return ENGINE_MODULES[engine]?.modules || {};
}
