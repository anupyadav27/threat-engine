'use client';

/**
 * PostureTabs — AP-P4-04
 *
 * 5-dimension security posture tabs for the inventory asset detail page.
 * Lazy-loads posture data on first tab click.
 *
 * Props:
 *   resourceUid    {string}   — resource_uid of the asset
 *   resourceType   {string}   — resource_type used to determine relevant tabs
 *
 * Data: GET /gateway/api/v1/views/inventory/asset/{uid}/posture
 * Security: field stripping applied server-side in BFF (AP-P4-04 AC-4).
 *   viewer role receives empty IAM tab and minimal attack_path.
 */

import { useState, useCallback, useEffect } from 'react';
import { Network, Key, Lock, Database, HardDrive, Shield, AlertTriangle, Check, Search, Webhook } from 'lucide-react';

// ── Tab configuration ─────────────────────────────────────────────────────────

const COMPUTE_TYPES = new Set([
  'ec2.instance', 'lambda.function', 'ecs.task-definition', 'eks.cluster',
  'vm', 'gce.instance', 'oci.compute', 'oci.container_instance',
  'azure.function', 'cloud_run.service',
]);

const DATA_TYPES = new Set([
  's3.bucket', 'blob.container', 'gcs.bucket', 'oci.object_storage',
]);

const DB_TYPES = new Set([
  'rds.instance', 'aurora.cluster', 'cloud_sql.instance', 'oci.autonomous_db', 'redshift.cluster',
]);

const IAM_TYPES = new Set(['iam.role', 'iam.user']);

const ENCRYPTION_TYPES = new Set([
  'kms.key', 'key_vault.key', 'secretsmanager.secret',
]);

const NETWORK_TYPES = new Set([
  'elasticloadbalancing.loadbalancer', 'alb', 'nlb', 'azure.load_balancer',
]);

const API_TYPES = new Set([
  'aws.apigateway.rest_api', 'aws.apigateway.stage',
  'aws.apigatewayv2.api', 'aws.apigatewayv2.stage',
  'azure.apimanagement.service', 'azure.apimanagement.api',
  'gcp.apigee.environment', 'gcp.apigee.api_proxy',
  'gcp.apigateway.api', 'gcp.apigateway.api_config',
  'oci.apigateway.gateway', 'oci.apigateway.deployment',
  'alicloud.apigateway.api_group', 'alicloud.apigateway.api',
  'k8s.networking.ingress', 'k8s.gateway.gateway', 'k8s.gateway.httproute',
  'aws.appsync.graphql_api',
]);

function resolveTabs(resourceType) {
  const t = (resourceType || '').toLowerCase();
  if (API_TYPES.has(t))        return ['api_security', 'network', 'findings'];
  if (COMPUTE_TYPES.has(t))    return ['network', 'iam', 'encryption', 'data', 'database', 'findings'];
  if (DATA_TYPES.has(t))       return ['data', 'findings'];
  if (DB_TYPES.has(t))         return ['database', 'findings'];
  if (IAM_TYPES.has(t))        return ['iam', 'findings'];
  if (ENCRYPTION_TYPES.has(t)) return ['encryption', 'findings'];
  if (NETWORK_TYPES.has(t))    return ['network', 'findings'];
  // Default: show all + findings
  return ['network', 'iam', 'encryption', 'data', 'database', 'findings'];
}

const TAB_META = {
  api_security: { label: 'API Security', Icon: Webhook,   color: '#f59e0b' },
  network:      { label: 'Network',      Icon: Network,   color: '#0ea5e9' },
  iam:          { label: 'IAM',          Icon: Key,       color: '#a855f7' },
  encryption:   { label: 'Encryption',   Icon: Lock,      color: '#6d28d9' },
  data:         { label: 'Data',         Icon: HardDrive, color: '#22c55e' },
  database:     { label: 'Database',     Icon: Database,  color: '#3b82f6' },
  findings:     { label: 'Findings',     Icon: Search,    color: '#f97316' },
};

// ── Helper components ─────────────────────────────────────────────────────────

function BoolBadge({ value, trueLabel, falseLabel }) {
  if (value === null || value === undefined) return (
    <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.3)' }}>—</span>
  );
  const ok    = Boolean(value);
  const label = ok ? (trueLabel || 'Yes') : (falseLabel || 'No');
  const color = ok ? '#22c55e' : '#ef4444';
  return (
    <span
      className="flex items-center gap-1 text-[10px] font-semibold"
      style={{ color }}
    >
      {ok ? <Check style={{ width: 10, height: 10 }} /> : <AlertTriangle style={{ width: 10, height: 10 }} />}
      {label}
    </span>
  );
}

function PostureField({ label, value, danger }) {
  if (value === null || value === undefined) return null;
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 border-b" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
      <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.45)' }}>{label}</span>
      <span
        className="text-[10px] font-semibold text-right"
        style={{ color: danger ? '#ef4444' : 'rgba(255,255,255,0.8)' }}
      >
        {String(value)}
      </span>
    </div>
  );
}

function EmptyDimension({ tab }) {
  return (
    <div
      className="rounded-xl border px-4 py-6 text-center text-[11px]"
      style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.35)' }}
    >
      No {tab} posture signals collected yet. Ensure the relevant engine has run for this account.
    </div>
  );
}

// ── Dimension panels ──────────────────────────────────────────────────────────

function NetworkPanel({ d }) {
  if (!d || Object.values(d).every(v => v === null || v === undefined)) {
    return <EmptyDimension tab="network" />;
  }
  return (
    <div className="space-y-0.5">
      <PostureField label="Internet Exposed" value={<BoolBadge value={d.is_internet_exposed} trueLabel="Exposed" falseLabel="Not Exposed" />} />
      <PostureField label="Entry Point Type" value={d.entry_point_type} />
      <PostureField label="WAF Protected"    value={<BoolBadge value={d.waf_protected} trueLabel="Protected" falseLabel="Unprotected" />} />
      <PostureField label="On-Prem Reachable" value={d.is_onprem_reachable !== undefined ? <BoolBadge value={d.is_onprem_reachable} /> : null} />
    </div>
  );
}

function IamPanel({ d }) {
  if (!d || Object.keys(d).length === 0) {
    return (
      <div className="text-[11px] text-center py-6" style={{ color: 'rgba(255,255,255,0.35)' }}>
        IAM details restricted for your role.
      </div>
    );
  }
  return (
    <div className="space-y-0.5">
      {d.attached_role_arn && (
        <PostureField label="Attached Role ARN" value={d.attached_role_arn} />
      )}
      <PostureField label="Admin Role"     value={<BoolBadge value={d.is_admin_role} trueLabel="Admin" falseLabel="Non-Admin" />} />
      <PostureField label="Wildcard Policy" value={<BoolBadge value={d.has_wildcard_policy} trueLabel="YES" falseLabel="No" />} danger={d.has_wildcard_policy} />
      <PostureField label="MFA Required"   value={<BoolBadge value={d.mfa_required} trueLabel="Required" falseLabel="Not Required" />} />
      <PostureField label="Permission Boundary" value={<BoolBadge value={d.has_permission_boundary} trueLabel="Set" falseLabel="Missing" />} />
      {d.iam_reachable_count != null && (
        <PostureField label="IAM Reachable Count" value={d.iam_reachable_count} />
      )}
    </div>
  );
}

function EncryptionPanel({ d }) {
  if (!d || Object.values(d).every(v => v === null || v === undefined)) {
    return <EmptyDimension tab="encryption" />;
  }

  const days    = d.cert_days_to_expiry;
  const daysStr = days != null
    ? days <= 0    ? 'EXPIRED'
    : days < 30    ? `Expires in ${days}d`
    : `${days}d remaining`
    : null;
  const daysColor = days != null
    ? days <= 0    ? '#ef4444'
    : days < 30    ? '#f97316'
    : '#22c55e'
    : null;

  return (
    <div className="space-y-0.5">
      <PostureField label="Volume Encrypted" value={<BoolBadge value={d.volume_encrypted} trueLabel="Encrypted" falseLabel="Unencrypted" />} danger={d.volume_encrypted === false} />
      <PostureField label="Encryption Type" value={d.encryption_type} />
      {daysStr && (
        <PostureField
          label="Certificate Expiry"
          value={<span className="text-[10px] font-bold" style={{ color: daysColor }}>{daysStr}</span>}
        />
      )}
      <PostureField label="In-Transit TLS" value={<BoolBadge value={d.in_transit_tls} trueLabel="TLS" falseLabel="No TLS" />} danger={d.in_transit_tls === false} />
    </div>
  );
}

function DataPanel({ d }) {
  if (!d || Object.values(d).every(v => v === null || v === undefined)) {
    return <EmptyDimension tab="data" />;
  }
  return (
    <div className="space-y-0.5">
      {d.data_classification && (
        <div className="py-1.5 border-b flex items-center justify-between" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.45)' }}>Classification</span>
          <span
            className="text-[10px] font-bold px-2 py-0.5 rounded-full"
            style={{ backgroundColor: 'rgba(168,85,247,0.15)', color: '#a855f7' }}
          >
            {d.data_classification}
          </span>
        </div>
      )}
      <PostureField label="Can Access PII"  value={<BoolBadge value={d.can_access_pii} trueLabel="Yes" falseLabel="No" />} danger={d.can_access_pii} />
      <PostureField label="Can Write Data"  value={<BoolBadge value={d.can_write_data} />} />
      <PostureField label="Exfil Path Exists" value={<BoolBadge value={d.exfil_path_exists} trueLabel="Yes" falseLabel="No" />} danger={d.exfil_path_exists} />
    </div>
  );
}

function DatabasePanel({ d }) {
  if (!d || Object.values(d).every(v => v === null || v === undefined)) {
    return <EmptyDimension tab="database" />;
  }
  const dbCount = Array.isArray(d.connected_db_uids) ? d.connected_db_uids.length : d.connected_db_uids;
  return (
    <div className="space-y-0.5">
      {dbCount != null && <PostureField label="Connected DBs" value={dbCount} />}
      <PostureField label="DB Auth Type" value={d.db_auth_type} />
      <PostureField label="Same VPC"     value={<BoolBadge value={d.db_same_vpc} trueLabel="Same VPC" falseLabel="Cross-VPC" />} />
    </div>
  );
}

function APISecurityPanel({ d }) {
  if (!d || Object.values(d).every(v => v === null || v === undefined)) {
    return <EmptyDimension tab="api_security" />;
  }

  const score = d.api_security_score;
  const scoreColor = score == null ? '#6b7280'
    : score >= 80  ? '#22c55e'
    : score >= 50  ? '#eab308'
    : '#ef4444';

  const authType = d.api_auth_type || 'none';
  const authColor = authType === 'none' ? '#ef4444'
    : authType === 'unknown' ? '#eab308'
    : '#22c55e';

  return (
    <div className="space-y-0.5">
      {score != null && (
        <div className="py-1.5 border-b flex items-center justify-between" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.45)' }}>API Security Score</span>
          <span className="text-[11px] font-bold" style={{ color: scoreColor }}>{score}/100</span>
        </div>
      )}
      <div className="py-1.5 border-b flex items-center justify-between" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
        <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.45)' }}>Auth Type</span>
        <span className="text-[10px] font-bold" style={{ color: authColor }}>{authType.toUpperCase()}</span>
      </div>
      <PostureField
        label="WAF Protected"
        value={<BoolBadge value={d.api_has_waf} trueLabel="Protected" falseLabel="No WAF" />}
        danger={d.api_has_waf === false}
      />
      <PostureField
        label="Rate Limited"
        value={<BoolBadge value={d.api_has_rate_limit} trueLabel="Enabled" falseLabel="No Limit" />}
        danger={d.api_has_rate_limit === false}
      />
      <PostureField
        label="Publicly Accessible"
        value={<BoolBadge value={d.api_publicly_accessible} trueLabel="Public" falseLabel="Private" />}
        danger={d.api_publicly_accessible === true}
      />
      {d.api_deprecated_version_active != null && (
        <PostureField
          label="Deprecated Version"
          value={<BoolBadge value={d.api_deprecated_version_active} trueLabel="Active" falseLabel="None" />}
          danger={d.api_deprecated_version_active}
        />
      )}
      {d.api_detail && (
        <div className="mt-2 pt-2 border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          {d.api_detail.owasp_categories_hit?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1">
              {d.api_detail.owasp_categories_hit.map(cat => (
                <span
                  key={cat}
                  className="text-[9px] px-1.5 py-0.5 rounded font-semibold"
                  style={{ backgroundColor: 'rgba(245,158,11,0.15)', color: '#f59e0b' }}
                >
                  {cat}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const SEV_COLOR_F = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#6b7280' };
const SEV_BG_F    = { critical: 'rgba(239,68,68,0.12)', high: 'rgba(249,115,22,0.12)', medium: 'rgba(234,179,8,0.12)', low: 'rgba(107,114,128,0.12)' };
const ENGINE_COLOR = {
  check: '#0ea5e9', iam: '#a855f7', network: '#22c55e',
  datasec: '#f97316', vuln: '#ef4444', cdr: '#eab308', container: '#6d28d9',
};

function FindingsPanel({ resourceUid }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);
  const [loaded, setLoaded]   = useState(false);

  useEffect(() => {
    if (!resourceUid || loaded || loading) return;
    setLoading(true);
    fetch(
      `/gateway/api/v1/views/inventory/asset/${encodeURIComponent(resourceUid)}/findings`,
      { credentials: 'include' },
    )
      .then(r => r.ok ? r.json() : Promise.reject(`HTTP ${r.status}`))
      .then(d => { setData(d); setLoading(false); setLoaded(true); })
      .catch(err => { setError(String(err)); setLoading(false); setLoaded(true); });
  }, [resourceUid, loaded, loading]);

  if (loading) {
    return (
      <div className="space-y-2">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-8 rounded animate-pulse" style={{ backgroundColor: 'rgba(255,255,255,0.04)' }} />
        ))}
      </div>
    );
  }
  if (error) {
    return (
      <div className="text-[11px] text-center py-4" style={{ color: '#f97316' }}>
        Could not load findings: {error}
      </div>
    );
  }
  if (!data || (data.findings || []).length === 0) {
    return <EmptyDimension tab="findings" />;
  }

  const findings = data.findings || [];
  return (
    <div className="space-y-1.5">
      {/* Summary chips */}
      {data.by_severity && (
        <div className="flex items-center gap-1.5 flex-wrap mb-2">
          {['critical', 'high', 'medium', 'low'].map(s =>
            data.by_severity[s] > 0 ? (
              <span
                key={s}
                className="text-[9px] font-bold px-2 py-0.5 rounded-full uppercase"
                style={{ backgroundColor: SEV_BG_F[s], color: SEV_COLOR_F[s] }}
              >
                {data.by_severity[s]} {s}
              </span>
            ) : null
          )}
          <span className="text-[9px] ml-auto" style={{ color: 'rgba(255,255,255,0.35)' }}>
            {data.total ?? findings.length} total
          </span>
        </div>
      )}
      {/* Finding rows */}
      {findings.slice(0, 20).map((f, i) => (
        <div
          key={i}
          className="rounded-lg border px-3 py-2 space-y-0.5"
          style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}
        >
          <div className="flex items-center gap-2">
            <span
              className="text-[9px] font-bold px-1.5 py-0.5 rounded-full uppercase flex-shrink-0"
              style={{ backgroundColor: SEV_BG_F[f.severity], color: SEV_COLOR_F[f.severity] || '#6b7280' }}
            >
              {f.severity}
            </span>
            <span
              className="text-[9px] font-bold px-1.5 py-0.5 rounded flex-shrink-0"
              style={{ backgroundColor: 'rgba(255,255,255,0.06)', color: ENGINE_COLOR[f.source_engine] || 'rgba(255,255,255,0.5)' }}
            >
              {f.source_engine}
            </span>
            <span className="text-[10px] truncate" style={{ color: 'rgba(255,255,255,0.8)' }}>
              {f.title}
            </span>
          </div>
          {f.rule_id && (
            <p className="text-[9px] font-mono" style={{ color: 'rgba(255,255,255,0.35)' }}>{f.rule_id}</p>
          )}
        </div>
      ))}
      {findings.length > 20 && (
        <p className="text-[10px] text-center pt-1" style={{ color: 'rgba(255,255,255,0.35)' }}>
          Showing 20 of {findings.length} findings
        </p>
      )}
    </div>
  );
}

const PANEL_MAP = {
  api_security: APISecurityPanel,
  network:      NetworkPanel,
  iam:          IamPanel,
  encryption:   EncryptionPanel,
  data:         DataPanel,
  database:     DatabasePanel,
  findings:     FindingsPanel,
};

// ── PostureTabs ───────────────────────────────────────────────────────────────

export default function PostureTabs({ resourceUid, resourceType }) {
  const tabs         = resolveTabs(resourceType);
  const [activeTab, setActiveTab] = useState(tabs[0]);
  const [posture, setPosture]     = useState(null);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState(null);
  const [loaded, setLoaded]       = useState(false);

  // Lazy load — only on first activation (AC-131 / story AC-132)
  const loadPosture = useCallback(async () => {
    if (loaded || loading || !resourceUid) return;
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(
        `/gateway/api/v1/views/inventory/asset/${encodeURIComponent(resourceUid)}/posture`,
        { credentials: 'include' },
      );
      if (resp.status === 404) {
        setPosture(null);
      } else if (!resp.ok) {
        setError(`HTTP ${resp.status}`);
      } else {
        const d = await resp.json();
        setPosture(d);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
      setLoaded(true);
    }
  }, [resourceUid, loaded, loading]);

  const handleTabClick = useCallback(tab => {
    setActiveTab(tab);
    loadPosture();
  }, [loadPosture]);

  const meta       = TAB_META[activeTab] || {};
  const Panel      = PANEL_MAP[activeTab];
  const dimension  = posture?.[activeTab];

  return (
    <div
      className="rounded-xl border overflow-hidden mt-4"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'rgba(255,255,255,0.07)' }}
    >
      {/* Tab header */}
      <div
        className="flex border-b overflow-x-auto"
        style={{ borderColor: 'rgba(255,255,255,0.07)' }}
      >
        {tabs.map(tab => {
          const m = TAB_META[tab];
          const active = activeTab === tab;
          return (
            <button
              key={tab}
              onClick={() => handleTabClick(tab)}
              className="flex items-center gap-1.5 px-4 py-3 text-xs font-semibold border-b-2 transition-all whitespace-nowrap flex-shrink-0"
              style={{
                color: active ? m.color : 'var(--text-secondary)',
                borderColor: active ? m.color : 'transparent',
                backgroundColor: active ? `${m.color}08` : 'transparent',
              }}
            >
              <m.Icon style={{ width: 12, height: 12 }} />
              {m.label}
            </button>
          );
        })}
      </div>

      {/* Tab body */}
      <div className="px-4 py-4">
        {activeTab !== 'findings' && loading && (
          <div className="space-y-2">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className="h-8 rounded animate-pulse"
                style={{ backgroundColor: 'rgba(255,255,255,0.04)' }}
              />
            ))}
          </div>
        )}
        {activeTab !== 'findings' && !loading && error && (
          <div className="text-[11px] text-center py-4" style={{ color: '#f97316' }}>
            Could not load posture data: {error}
          </div>
        )}
        {activeTab !== 'findings' && !loading && !error && loaded && !posture && (
          <EmptyDimension tab={activeTab} />
        )}
        {/* Findings tab manages its own fetch lifecycle */}
        {activeTab === 'findings' && <FindingsPanel resourceUid={resourceUid} />}

        {/* Posture tabs share one fetch */}
        {activeTab !== 'findings' && (
          <>
            {!loaded ? (
              <div className="text-center text-[11px] py-6" style={{ color: 'rgba(255,255,255,0.3)' }}>
                Loading posture data…
              </div>
            ) : (
              posture && Panel && <Panel d={dimension} />
            )}
          </>
        )}
      </div>
    </div>
  );
}
