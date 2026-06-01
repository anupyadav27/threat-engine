'use client';

import { useEffect, useState } from 'react';
import { ArrowRight, ExternalLink, Layers } from 'lucide-react';
import EmptyState from '@/components/shared/EmptyState';
import { fetchView } from '@/lib/api';

function Skeleton() {
  return (
    <div className="space-y-3 animate-pulse">
      {[80, 65, 72, 55, 68].map((w, i) => (
        <div key={i} className="h-3 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', width: `${w}%` }} />
      ))}
    </div>
  );
}

function ScoreBar({ label, score }) {
  if (score == null) return null;
  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs w-28 shrink-0" style={{ color: 'var(--text-muted)' }}>{label}</span>
      <div className="flex-1 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
        <div className="h-full rounded-full" style={{ width: `${Math.min(score, 100)}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-bold w-8 text-right" style={{ color }}>{score}</span>
    </div>
  );
}

const ENGINE_LABELS = {
  check: 'Config Check', 'network-security': 'Network', network: 'Network', iam: 'IAM',
  datasec: 'Data Security', encryption: 'Encryption', 'container-security': 'Container',
  'ai-security': 'AI Security', dbsec: 'Database', vulnerability: 'Vulnerability',
  secops: 'SecOps', cdr: 'CDR',
};
const ENGINE_ROUTES = {
  check: '/misconfig', 'network-security': '/network-security', network: '/network-security',
  iam: '/iam', datasec: '/datasec', encryption: '/encryption',
  'container-security': '/container-security', 'ai-security': '/ai-security',
  dbsec: '/database-security', vulnerability: '/vulnerabilities', secops: '/secops', cdr: '/cdr',
};
const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

const rtype = (t = '') => t.replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ');
const suid  = (uid = '') => uid.split(/[/:?]/).filter(Boolean).pop() || uid;
const fmt   = d => d ? new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : null;

export default function ResourceContextTab({ finding, data }) {
  const header      = finding?.header || data?.header;
  const resourceUid = header?.resourceUid;
  const curEngine   = header?.engine;

  const [ctx, setCtx]         = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!resourceUid) return;
    setLoading(true);
    fetchView(`resource/${encodeURIComponent(resourceUid)}`)
      .then(d => { setCtx(d || null); setLoading(false); })
      .catch(() => { setCtx(null); setLoading(false); });
  }, [resourceUid]);

  if (!resourceUid) {
    return (
      <EmptyState
        title="No resource context"
        description="This finding is not associated with a specific cloud resource."
      />
    );
  }

  const asset    = ctx?.resource      || null;
  const posture  = ctx?.posture        || null;
  const rels     = ctx?.relationships  || [];
  const fSummary = ctx?.findings_summary || null;
  const outbound = rels.filter(r => r.direction === 'outbound');
  const inbound  = rels.filter(r => r.direction === 'inbound');

  return (
    <div className="flex flex-col gap-6">

      {loading && <Skeleton />}

      {/* Unavailable state */}
      {!loading && !ctx && (
        <div className="rounded-lg border p-8 text-center" style={{ borderColor: 'var(--border-primary)' }}>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
            Resource context unavailable — asset may not be in DI inventory yet.
          </p>
          <a href={`/inventory/${encodeURIComponent(resourceUid)}`}
            className="inline-flex items-center gap-1.5 mt-3 text-sm font-medium hover:opacity-75 transition-opacity"
            style={{ color: 'var(--accent-primary)' }}>
            <ExternalLink className="w-3.5 h-3.5" /> Open Inventory page
          </a>
        </div>
      )}

      {/* Asset Details */}
      {!loading && asset && (
        <div className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
          <div className="flex items-start justify-between mb-3">
            <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Asset Details</h3>
            <a href={`/inventory/${encodeURIComponent(resourceUid)}`}
              className="inline-flex items-center gap-1 text-xs font-medium hover:opacity-75 transition-opacity"
              style={{ color: 'var(--accent-primary)' }}>
              <Layers className="w-3 h-3" /> Full Inventory
            </a>
          </div>
          <div className="space-y-2">
            {[
              { label: 'Name',         value: asset.resource_name,              mono: false },
              { label: 'Resource UID', value: asset.resource_uid,               mono: true  },
              { label: 'Type',         value: rtype(asset.resource_type),       mono: false },
              { label: 'Service',      value: asset.service,                    mono: false },
              { label: 'Provider',     value: asset.provider?.toUpperCase(),    mono: false },
              { label: 'Account',      value: asset.account_id,                 mono: true  },
              { label: 'Region',       value: asset.region,                     mono: false },
              { label: 'First Seen',   value: fmt(asset.first_seen_at),         mono: false },
              { label: 'Last Seen',    value: fmt(asset.last_seen_at),          mono: false },
            ].filter(f => f.value).map(f => (
              <div key={f.label} className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-28" style={{ color: 'var(--text-muted)' }}>{f.label}</span>
                {f.mono
                  ? <code className="text-xs break-all flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>{f.value}</code>
                  : <span className="text-xs break-all flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>{f.value}</span>
                }
              </div>
            ))}
          </div>
          {asset.tags && Object.keys(asset.tags).length > 0 && (
            <div className="mt-3 pt-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-muted)' }}>Tags</p>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(asset.tags).map(([k, v]) => (
                  <span key={k} className="text-xs px-2 py-0.5 rounded border"
                    style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
                    {k}: {String(v)}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Security Posture */}
      {!loading && posture && (
        <div className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Security Posture</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between pb-2 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Overall Score</span>
              <span className="text-lg font-bold"
                style={{ color: posture.overall_posture_score >= 80 ? '#22c55e' : posture.overall_posture_score >= 60 ? '#eab308' : '#ef4444' }}>
                {posture.overall_posture_score ?? '—'}
              </span>
            </div>
            <ScoreBar label="IAM"          score={posture.iam_score} />
            <ScoreBar label="Network"      score={posture.network_score} />
            <ScoreBar label="Encryption"   score={posture.encryption_score} />
            <ScoreBar label="Container"    score={posture.container_security_score} />
            <ScoreBar label="Database"     score={posture.dbsec_score} />
            <ScoreBar label="API Security" score={posture.api_security_score} />
            <ScoreBar label="AI Security"  score={posture.ai_security_score} />
            <div className="flex flex-wrap gap-3 pt-1 text-xs">
              {posture.is_internet_exposed     && <span style={{ color: '#ef4444' }}>Internet Exposed</span>}
              {posture.is_encrypted_at_rest    && <span style={{ color: '#22c55e' }}>Encrypted at Rest</span>}
              {posture.is_encrypted_in_transit && <span style={{ color: '#22c55e' }}>Encrypted in Transit</span>}
              {posture.has_kms_managed_key     && <span style={{ color: '#22c55e' }}>KMS Managed</span>}
            </div>
          </div>
        </div>
      )}

      {/* Findings Across Engines */}
      {!loading && fSummary && fSummary.total > 0 && (
        <div className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
            Findings Across Engines — {fSummary.total} total
          </h3>
          <div className="space-y-1.5">
            {Object.entries(fSummary.by_engine || {}).map(([eng, count]) => {
              const route    = ENGINE_ROUTES[eng];
              const label    = ENGINE_LABELS[eng] || eng;
              const isCurrent = eng === curEngine;
              const inner = (
                <div className="flex items-center justify-between px-3 py-2 rounded border"
                  style={{
                    backgroundColor: isCurrent ? 'rgba(99,102,241,0.08)' : 'var(--bg-tertiary)',
                    borderColor:     isCurrent ? 'rgba(99,102,241,0.3)'  : 'var(--border-primary)',
                    opacity: isCurrent ? 0.7 : 1,
                  }}>
                  <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{label}</span>
                  <span className="text-xs font-bold px-2 py-0.5 rounded"
                    style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>{count}</span>
                </div>
              );
              if (route && !isCurrent) return (
                <a key={eng} href={`${route}?resource_uid=${encodeURIComponent(resourceUid)}`}
                  className="block hover:opacity-80 transition-opacity">{inner}</a>
              );
              return <div key={eng}>{inner}</div>;
            })}
          </div>
          <div className="flex gap-3 pt-2 text-xs">
            {Object.entries(fSummary.by_severity || {}).filter(([, n]) => n > 0).map(([s, n]) => (
              <span key={s} className="font-bold" style={{ color: SEV_COLOR[s] || 'var(--text-muted)' }}>
                {n} {s}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Relationships */}
      {!loading && (outbound.length > 0 || inbound.length > 0) && (
        <div className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
            Relationships ({rels.length})
          </h3>

          {outbound.length > 0 && (
            <>
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>
                Outbound — {outbound.length}
              </p>
              <div className="space-y-1.5 mb-3">
                {outbound.slice(0, 6).map((r, i) => (
                  <div key={i} className="flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs"
                    style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}>
                    <span className="text-[10px] font-medium px-1.5 py-0.5 rounded shrink-0"
                      style={{ backgroundColor: 'rgba(99,102,241,0.12)', color: '#818cf8' }}>
                      {rtype(r.source_resource_type || r.resource_type || '')}
                    </span>
                    <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-muted)' }} />
                    <span className="text-[10px] shrink-0" style={{ color: 'var(--text-muted)' }}>
                      {(r.relationship_type || r.relation_type || '').replace(/_/g, ' ')}
                    </span>
                    <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-muted)' }} />
                    <span className="truncate flex-1" style={{ color: 'var(--text-secondary)' }}
                      title={r.related_resource_uid || r.target_resource_uid || r.peer_uid}>
                      {r.related_resource_name || suid(r.related_resource_uid || r.target_resource_uid || r.peer_uid || '')}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}

          {inbound.length > 0 && (
            <>
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>
                Inbound — {inbound.length}
              </p>
              <div className="space-y-1.5">
                {inbound.slice(0, 6).map((r, i) => (
                  <div key={i} className="flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs"
                    style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}>
                    <span className="truncate flex-1" style={{ color: 'var(--text-secondary)' }}
                      title={r.related_resource_uid || r.source_resource_uid || r.peer_uid}>
                      {r.related_resource_name || suid(r.related_resource_uid || r.source_resource_uid || r.peer_uid || '')}
                    </span>
                    <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-muted)' }} />
                    <span className="text-[10px] shrink-0" style={{ color: 'var(--text-muted)' }}>
                      {(r.relationship_type || r.relation_type || '').replace(/_/g, ' ')}
                    </span>
                    <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-muted)' }} />
                    <span className="text-[10px] font-medium px-1.5 py-0.5 rounded shrink-0"
                      style={{ backgroundColor: 'rgba(99,102,241,0.12)', color: '#818cf8' }}>
                      {rtype(r.target_resource_type || r.resource_type || '')}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
