'use client';

import { useState, useEffect, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft, ArrowRight, Copy, Check, Shield, Database, Network,
  AlertTriangle, CheckCircle, Crosshair, Zap, ChevronDown, ChevronRight,
  Plus, Minus, RefreshCw, Box, ClipboardCheck, Globe, ExternalLink,
  KeyRound, Server, HardDrive, MessageSquare, Activity, Brain, MapPin, Tag,
  Lock,
} from 'lucide-react';
import { getFromEngine, fetchView } from '@/lib/api';
import { RESOURCE_DOMAINS } from '@/lib/inventory-taxonomy';
import DataTable from '@/components/shared/DataTable';
import StatusIndicator from '@/components/shared/StatusIndicator';
import DriftTimeline from '@/components/shared/DriftTimeline';
import ComplianceFindingDetail from '@/components/shared/ComplianceFindingDetail';
import PostureTabs from './PostureTabs';
import CspIcon from '@/components/shared/CspIcon';
import {
  SeverityBadge, FindingsBar, AttackPathBadge, CrownJewelBadge,
  ChokepointBadge, ExposureBadge, RiskScore,
} from '@/components/shared/SecurityBadges';

const DOMAIN_ICON_MAP = {
  KeyRound, Network, Shield, Server, Box, Zap, HardDrive, Database,
  Lock, Globe, MessageSquare, Activity, ClipboardCheck, Brain,
};


/**
 * Normalize blast-radius response — handles both the old BFF format
 * (center / total_nodes) and the new format (origin / total_impacted).
 * Also computes impact_summary from nodes when BFF doesn't provide it.
 */
function normalizeBlastData(raw, fallbackOrigin) {
  if (!raw || typeof raw !== 'object') {
    return { nodes: [], edges: [], total_impacted: 0, impact_summary: {}, origin: fallbackOrigin, toxic_combos: [] };
  }
  const nodes = raw.nodes || [];
  const edges = raw.edges || [];
  const origin = raw.origin || raw.center || fallbackOrigin;
  const total_impacted = raw.total_impacted ?? raw.total_nodes ?? nodes.length;
  const toxic_combos = raw.toxic_combos || [];

  // Compute impact_summary from nodes when BFF doesn't provide it
  let impact_summary = raw.impact_summary || null;
  if (!impact_summary || Object.keys(impact_summary).length === 0) {
    impact_summary = {};
    nodes.forEach((n) => {
      const cat = n.category || 'other';
      impact_summary[cat] = (impact_summary[cat] || 0) + 1;
    });
  }

  return { nodes, edges, origin, total_impacted, impact_summary, toxic_combos };
}

export default function AssetDetailPage() {
  const params = useParams();
  const router = useRouter();
  const assetId = decodeURIComponent(params.assetId);

  const [asset, setAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [copiedId, setCopiedId] = useState(false);

  // Fetch asset details via BFF (parallel cross-engine enrichment), with
  // blast-radius as a separate call since it's a heavier graph query.
  useEffect(() => {
    const loadAsset = async () => {
      setLoading(true);
      setError(null);
      try {
        const encoded = encodeURIComponent(assetId);

        // BFF assembles: inventory + check + threat + compliance + drift
        // Blast radius is separate (graph + per-node posture enrichment)
        const [bffRes, blastRes] = await Promise.allSettled([
          fetchView(`inventory/asset/${encoded}`),
          fetchView(`inventory/asset/${encoded}/blast-radius`),
        ]);

        const bffData = bffRes.status === 'fulfilled' ? bffRes.value : null;

        // Fallback: call DI engine via gateway when BFF fails
        if (!bffData || bffData.error) {
          const assetRes = await Promise.allSettled([
            getFromEngine('gateway', `/api/v1/di/assets/${encoded}`),
          ]);

          const assetData = assetRes[0].status === 'fulfilled' ? assetRes[0].value : null;
          if (!assetData || assetData.error) {
            setError(assetData?.error || 'Asset not found');
            setLoading(false);
            return;
          }
          const base = assetData.asset || assetData;
          const blastRaw = blastRes.status === 'fulfilled' ? blastRes.value : null;

          setAsset({
            ...base,
            resource_id: base.resource_uid || base.resource_id || assetId,
            resource_name: base.resource_name || base.resource_uid?.split('/').pop() || assetId,
            resource_type: base.resource_type || '',
            service: base.service || '',
            provider: (base.provider || 'aws').toLowerCase(),
            tags: base.tags || {},
            posture: {},
            blast_radius: normalizeBlastData(blastRaw, assetId),
          });
          setLoading(false);
          return;
        }

        // ── BFF response: pre-assembled cross-engine data ────────────
        const base = bffData.asset || {};
        const blastRaw = blastRes.status === 'fulfilled' ? blastRes.value : null;

        setAsset({
          ...base,
          resource_id: base.resource_uid || base.resource_id || assetId,
          resource_name: base.metadata?.name || base.resource_uid?.split('/').pop() || base.resource_id || assetId,
          resource_type: base.resource_type || '',
          service: base.service || (base.resource_type ? base.resource_type.split('::')[1]?.toLowerCase() : '') || '',
          provider: (base.provider || 'aws').toLowerCase(),
          tags: base.tags || {},
          config: (base.config && Object.keys(base.config).length > 0) ? base.config : {},
          // Cross-engine enrichment from BFF
          findings: bffData.check_severity || {},
          findings_detail: bffData.check_findings || [],
          check_posture: bffData.check_posture || {},
          threats: bffData.threat_findings || [],
          threat_severity: bffData.threat_severity || {},
          compliance: bffData.compliance_findings || [],
          drift_info: bffData.drift || base.drift_info || null,
          blast_radius: normalizeBlastData(blastRaw, assetId),
          posture: bffData.posture || {},
        });
      } catch (err) {
        setError(err?.message || 'Failed to load asset details');
      } finally {
        setLoading(false);
      }
    };

    loadAsset();
  }, [assetId]);

  // Copy to clipboard helper
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  // Table columns for findings (matches API findings_detail: rule_id, title, severity, status, service)
  const findingsColumns = [
    {
      accessorKey: 'rule_id',
      header: 'Rule ID',
      cell: (info) => (
        <code
          className="text-xs px-2 py-1 rounded"
          style={{ color: 'var(--text-tertiary)', backgroundColor: 'var(--bg-tertiary)', wordBreak: 'break-word', whiteSpace: 'normal' }}
        >
          {info.getValue() || ''}
        </code>
      ),
    },
    {
      accessorKey: 'title',
      header: 'Title',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue() || '-'}
        </span>
      ),
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'service',
      header: 'Service',
      cell: (info) => (
        <span className="text-xs font-medium px-2 py-1 rounded" style={{ color: 'var(--text-tertiary)', backgroundColor: 'var(--bg-tertiary)' }}>
          {(info.getValue() || '').toUpperCase()}
        </span>
      ),
    },
    {
      accessorKey: 'posture_category',
      header: 'Security Posture',
      cell: (info) => {
        const val = info.getValue() || 'configuration';
        const label = val.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
        const colorMap = {
          encryption: '#8b5cf6',
          public_access: '#ef4444',
          logging: '#3b82f6',
          backup: '#06b6d4',
          access_control: '#f59e0b',
          network: '#6366f1',
          key_management: '#ec4899',
          configuration: '#64748b',
          data_protection: '#14b8a6',
          threat_detection: '#f97316',
        };
        const bg = colorMap[val] || '#64748b';
        return (
          <span
            className="text-xs font-medium px-2 py-1 rounded"
            style={{ backgroundColor: bg + '20', color: bg }}
          >
            {label}
          </span>
        );
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const val = (info.getValue() || '').toUpperCase();
        const isFail = val === 'FAIL';
        return (
          <span
            className="text-xs font-medium px-2 py-1 rounded"
            style={{
              backgroundColor: isFail ? 'var(--accent-danger)' : 'var(--accent-success)',
              color: 'white',
            }}
          >
            {val}
          </span>
        );
      },
    },
  ];

  // Table columns for compliance (matches API: framework, control_id, control_name, status, severity)
  // ── Compliance expandable rows ──────────────────────────────────────
  const [expandedCompliance, setExpandedCompliance] = useState(new Set());
  const [selectedComplianceFinding, setSelectedComplianceFinding] = useState(null);

  const toggleCompliance = useCallback((idx) => {
    setExpandedCompliance((prev) => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  }, []);

  const complianceColumns = [
    {
      id: 'expand',
      header: '',
      size: 36,
      cell: (info) => {
        const idx = info.row.index;
        return (
          <button
            onClick={(e) => { e.stopPropagation(); toggleCompliance(idx); }}
            style={{ color: 'var(--text-muted)' }}
          >
            {expandedCompliance.has(idx)
              ? <ChevronDown className="w-4 h-4" />
              : <ChevronRight className="w-4 h-4" />}
          </button>
        );
      },
    },
    {
      accessorKey: 'framework',
      header: 'Framework',
      cell: (info) => (
        <span className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>
          {info.getValue() || '-'}
        </span>
      ),
    },
    {
      accessorKey: 'control_id',
      header: 'Control',
      cell: (info) => (
        <code className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
          {info.getValue() || '-'}
        </code>
      ),
    },
    {
      accessorKey: 'control_name',
      header: 'Description',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue() || '-'}
        </span>
      ),
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = (info.getValue() || '').toLowerCase();
        const isPass = status === 'pass';
        return (
          <div className="flex items-center gap-2">
            {isPass ? (
              <>
                <CheckCircle className="w-4 h-4" style={{ color: 'var(--accent-success)' }} />
                <span style={{ color: 'var(--accent-success)' }}>Pass</span>
              </>
            ) : (
              <>
                <AlertTriangle className="w-4 h-4" style={{ color: 'var(--accent-danger)' }} />
                <span style={{ color: 'var(--accent-danger)' }}>Fail</span>
              </>
            )}
          </div>
        );
      },
    },
  ];

  const renderComplianceExpanded = useCallback((row) => {
    const idx = (asset.compliance || []).indexOf(row);
    if (!expandedCompliance.has(idx)) return null;
    const fmt = (d) => d ? new Date(d).toLocaleDateString() : '—';
    return (
      <div
        className="px-6 py-4 border-t space-y-3"
        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
      >
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-tertiary)' }}>Rule ID</div>
            <code className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>
              {row.rule_id || '—'}
            </code>
          </div>
          <div>
            <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-tertiary)' }}>Category</div>
            <span className="text-xs px-2 py-1 rounded font-medium"
              style={{ backgroundColor: 'var(--bg-badge)', color: 'var(--text-secondary)' }}>
              {row.category || '—'}
            </span>
          </div>
          <div>
            <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-tertiary)' }}>Framework</div>
            <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
              {row.framework || '—'} — {row.control_id || ''}
            </span>
          </div>
          <div>
            <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-tertiary)' }}>Last Seen</div>
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              {fmt(row.last_seen)}
            </span>
          </div>
        </div>
        {(row.description || row.control_name) && (
          <div>
            <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-tertiary)' }}>Description</div>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              {row.description || row.control_name}
            </p>
          </div>
        )}
        {row.rationale && (
          <div>
            <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-tertiary)' }}>Rationale</div>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              {row.rationale}
            </p>
          </div>
        )}
        {row.remediation && (
          <div>
            <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-tertiary)' }}>Remediation</div>
            <div
              className="text-sm p-3 rounded border"
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-secondary)',
              }}
            >
              {row.remediation}
            </div>
          </div>
        )}
        {row.resource && typeof row.resource === 'object' && (
          <div>
            <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-tertiary)' }}>Resource Details</div>
            <div className="font-mono text-xs p-3 rounded border overflow-x-auto"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
              {JSON.stringify(row.resource, null, 2)}
            </div>
          </div>
        )}
      </div>
    );
  }, [expandedCompliance, asset]);

  // Table columns for threats (MITRE ATT&CK enriched from threat engine)
  const threatColumns = [
    {
      accessorKey: 'threat_category',
      header: 'Category',
      cell: (info) => (
        <span
          className="text-xs font-medium px-2 py-1 rounded"
          style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-tertiary)' }}
        >
          {(info.getValue() || '').replace(/_/g, ' ')}
        </span>
      ),
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'mitre_tactics',
      header: 'MITRE Tactics',
      cell: (info) => {
        const tactics = info.getValue() || [];
        return (
          <div className="flex flex-wrap gap-1">
            {tactics.slice(0, 3).map((t, i) => (
              <span
                key={i}
                className="text-xs px-2 py-0.5 rounded"
                style={{ backgroundColor: 'var(--accent-primary)', color: 'white', opacity: 0.85 }}
              >
                {t}
              </span>
            ))}
            {tactics.length > 3 && (
              <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                +{tactics.length - 3}
              </span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: 'mitre_techniques',
      header: 'Techniques',
      cell: (info) => {
        const techs = info.getValue() || [];
        return (
          <div className="flex flex-wrap gap-1">
            {techs.slice(0, 2).map((t, i) => (
              <code
                key={i}
                className="text-xs px-1.5 py-0.5 rounded"
                style={{ color: 'var(--text-tertiary)', backgroundColor: 'var(--bg-tertiary)' }}
              >
                {t}
              </code>
            ))}
            {techs.length > 2 && (
              <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                +{techs.length - 2}
              </span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const val = (info.getValue() || 'open').toLowerCase();
        return (
          <span
            className="text-xs font-medium px-2 py-1 rounded"
            style={{
              backgroundColor: val === 'open' ? 'var(--accent-danger)' : 'var(--accent-success)',
              color: 'white',
            }}
          >
            {val.toUpperCase()}
          </span>
        );
      },
    },
    {
      accessorKey: 'last_seen_at',
      header: 'Last Seen',
      cell: (info) => (
        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
          {info.getValue() ? new Date(info.getValue()).toLocaleDateString() : '-'}
        </span>
      ),
    },
  ];

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-24 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        <div className="h-48 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--accent-danger)' }}>
        <p className="text-sm font-medium" style={{ color: 'var(--accent-danger)' }}>Error: {error}</p>
      </div>
    );
  }

  if (!asset) {
    return (
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No data available</p>
      </div>
    );
  }

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical':
        return 'var(--accent-danger)';
      case 'high':
        return 'var(--accent-warning)';
      case 'medium':
        return '#f59e0b';
      case 'low':
        return 'var(--accent-success)';
      default:
        return 'var(--text-tertiary)';
    }
  };

  const posture = asset.posture || {};
  const sidebarCardStyle = { backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' };

  return (
    <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start' }}>
      {/* ── LEFT SIDEBAR ── sticky identity + signals panel */}
      <aside style={{ width: 220, flexShrink: 0, position: 'sticky', top: 72, display: 'flex', flexDirection: 'column', gap: 10 }}>
        {/* Identity card */}
        <div className="rounded-xl border p-4" style={sidebarCardStyle}>
          <div className="flex items-center gap-2 mb-3">
            <CspIcon provider={asset.provider} size={20} />
            <div style={{ minWidth: 0 }}>
              <p className="font-semibold text-sm truncate" style={{ color: 'var(--text-primary)' }} title={asset.resource_name}>
                {asset.resource_name}
              </p>
              <p className="text-[10px] truncate" style={{ color: 'var(--text-muted)' }}>{asset.resource_type}</p>
            </div>
          </div>
          <div className="space-y-1.5 text-xs" style={{ color: 'var(--text-secondary)' }}>
            <div className="flex items-center gap-1.5">
              <MapPin className="w-3 h-3 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
              <span className="truncate">{asset.region || '—'}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Tag className="w-3 h-3 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
              <span className="truncate">{(asset.service || '').toUpperCase() || '—'}</span>
            </div>
            {asset.account_id && (
              <p className="font-mono text-[10px] pt-0.5" style={{ color: 'var(--text-muted)' }}>
                ···{String(asset.account_id).slice(-6)}
              </p>
            )}
          </div>
        </div>

        {/* Risk Score */}
        <div className="rounded-xl border p-4" style={sidebarCardStyle}>
          <p className="text-[10px] uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Risk Score</p>
          <div className="flex items-center gap-2">
            <span
              className="text-3xl font-bold tabular-nums"
              style={{ color: getSeverityColor(posture.overall_posture_score >= 70 ? 'critical' : posture.overall_posture_score >= 50 ? 'high' : posture.overall_posture_score >= 30 ? 'medium' : 'low') }}
            >
              {posture.overall_posture_score ?? asset.risk_score ?? '—'}
            </span>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>/100</span>
          </div>
          {posture.posture_vector && (
            <p className="text-[10px] font-mono mt-1 truncate" style={{ color: 'var(--text-muted)' }} title={posture.posture_vector}>
              {posture.posture_vector}
            </p>
          )}
        </div>

        {/* Signals */}
        <div className="rounded-xl border p-4" style={sidebarCardStyle}>
          <p className="text-[10px] uppercase tracking-wide mb-3" style={{ color: 'var(--text-muted)' }}>Signals</p>
          <div className="space-y-2">
            {[
              { label: 'Internet Exposed',   value: posture.is_internet_exposed,   danger: true  },
              { label: 'On Attack Path',      value: posture.is_on_attack_path,     danger: true  },
              { label: 'Crown Jewel',         value: posture.is_crown_jewel,        danger: false },
              { label: 'Choke Point',         value: posture.is_choke_point,        danger: false },
              { label: 'Admin Role',          value: posture.is_admin_role,         danger: true  },
              { label: 'Wildcard Policy',     value: posture.role_has_wildcard_policy, danger: true },
              { label: 'Active CDR Actor',    value: posture.has_active_cdr_actor,  danger: true  },
              { label: 'Encrypted at Rest',   value: posture.is_encrypted_at_rest,  danger: false, invert: true },
              { label: 'MFA Enforced',        value: posture.mfa_enforced,          danger: false, invert: true },
            ].filter(({ value }) => value !== null && value !== undefined).map(({ label, value, danger, invert }) => {
              const isActive = Boolean(value);
              const isRed = invert ? !isActive : (isActive && danger);
              const isGreen = invert ? isActive : (!danger && isActive);
              const dotColor = isRed ? 'var(--accent-danger)' : isGreen ? 'var(--accent-success)' : isActive ? '#60a5fa' : 'var(--text-muted)';
              return (
                <div key={label} className="flex items-center justify-between gap-2">
                  <span className="text-[11px] truncate" style={{ color: 'var(--text-secondary)' }}>{label}</span>
                  <span
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ backgroundColor: isActive ? dotColor : 'var(--bg-tertiary)', border: `1px solid ${isActive ? dotColor : 'var(--border-primary)'}` }}
                  />
                </div>
              );
            })}
            {posture.blast_radius_count > 0 && (
              <div className="flex items-center justify-between gap-2 pt-1 mt-1 border-t" style={{ borderColor: 'var(--border-primary)' }}>
                <span className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>Blast Radius</span>
                <span className="text-[11px] font-semibold tabular-nums" style={{ color: 'var(--accent-warning)' }}>
                  {posture.blast_radius_count}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Findings summary */}
        {(asset.findings?.critical > 0 || asset.findings?.high > 0 || asset.findings?.medium > 0 || asset.findings?.low > 0) && (
          <div className="rounded-xl border p-4" style={sidebarCardStyle}>
            <p className="text-[10px] uppercase tracking-wide mb-3" style={{ color: 'var(--text-muted)' }}>Findings</p>
            <FindingsBar findings={asset.findings} />
          </div>
        )}

        {/* Timeline */}
        <div className="rounded-xl border p-4" style={sidebarCardStyle}>
          <p className="text-[10px] uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Timeline</p>
          <div className="space-y-2 text-[11px]">
            {[
              { label: 'First Seen',    value: asset.created_at || asset.first_seen_at },
              { label: 'Last Scanned',  value: asset.last_scanned || asset.last_seen_at },
              { label: 'Last Modified', value: asset.last_modified },
            ].map(({ label, value }) => value && (
              <div key={label}>
                <span style={{ color: 'var(--text-muted)' }}>{label}</span>
                <p style={{ color: 'var(--text-secondary)' }}>{new Date(value).toLocaleDateString()}</p>
              </div>
            ))}
          </div>
        </div>
      </aside>

      {/* ── RIGHT MAIN CONTENT ─────────────────────────────────── */}
      <div style={{ flex: 1, minWidth: 0 }} className="space-y-4">

      {/* Header */}
      <div className="flex items-start gap-3">
        <button
            onClick={() => router.push('/inventory')}
            className="mt-1 p-1 rounded-lg transition-colors"
            style={{ backgroundColor: 'transparent' }}
            onMouseEnter={(e) => (e.target.style.backgroundColor = 'var(--bg-tertiary)')}
            onMouseLeave={(e) => (e.target.style.backgroundColor = 'transparent')}
          >
            <ArrowLeft className="w-5 h-5" style={{ color: 'var(--text-tertiary)' }} />
          </button>
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
                {asset.resource_name}
              </h1>
              <StatusIndicator status={asset.status} />
            </div>
            <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
              {asset.resource_type} • {(asset.service || '').toUpperCase()} • {asset.region}
            </p>
            <div className="mt-3 space-y-2">
              <div>
                <p className="text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>
                  Resource ARN/ID
                </p>
                <div
                  className="flex items-center gap-2 rounded-lg px-3 py-2"
                  style={{ backgroundColor: 'var(--bg-tertiary)' }}
                >
                  <code className="text-sm flex-1 overflow-hidden text-ellipsis" style={{ color: 'var(--text-secondary)' }}>
                    {assetId}
                  </code>
                  <button
                    onClick={() => copyToClipboard(assetId)}
                    className="p-1 rounded transition-colors"
                    onMouseEnter={(e) => (e.target.style.backgroundColor = 'var(--bg-secondary)')}
                    onMouseLeave={(e) => (e.target.style.backgroundColor = 'transparent')}
                  >
                    {copiedId ? (
                      <Check className="w-4 h-4" style={{ color: 'var(--accent-success)' }} />
                    ) : (
                      <Copy className="w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

      {/* Tabs */}
      <div style={{ borderBottomColor: 'var(--border-primary)' }} className="border-b">
        <div className="flex gap-1 overflow-x-auto" style={{ scrollbarWidth: 'none' }}>
          {[
            { id: 'overview',      label: 'Overview'     },
            { id: 'blast-radius',  label: 'Blast Radius' },
            { id: 'compliance',    label: 'Compliance'   },
            { id: 'drift',         label: 'Drift'        },
            { id: 'configuration', label: 'Config'       },
            { id: 'posture',       label: 'Posture'      },
          ].map(({ id, label }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`px-4 py-3 text-sm font-medium transition-colors border-b-2 whitespace-nowrap ${
                activeTab === id ? 'border-blue-500' : 'border-transparent'
              }`}
              style={{ color: activeTab === id ? 'var(--accent-primary)' : 'var(--text-tertiary)' }}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-4">
          {/* Internet Exposure Banner */}
          {(asset.internet_exposed || asset.public || asset.internet_exposure?.exposed) && (
            <div className="flex items-center gap-3 rounded-xl p-4 border"
              style={{ backgroundColor: '#ef444410', borderColor: '#ef4444' }}>
              <div className="p-2 rounded-lg" style={{ backgroundColor: '#ef444420' }}>
                <Globe className="w-5 h-5" style={{ color: '#ef4444' }} />
              </div>
              <div className="flex-1">
                <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>
                  Internet Exposed
                </p>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
                  {asset.internet_exposure?.reason || 'This resource is reachable from the public internet.'}
                  {asset.internet_exposure?.port && ` Port ${asset.internet_exposure.port}.`}
                  {asset.internet_exposure?.protocol && ` Protocol: ${asset.internet_exposure.protocol}.`}
                </p>
              </div>
              {asset.internet_exposure?.type && (
                <span className="text-[10px] font-bold px-2.5 py-1 rounded-full whitespace-nowrap"
                  style={{ backgroundColor: '#ef444425', color: '#ef4444' }}>
                  {asset.internet_exposure.type.replace(/_/g, ' ').toUpperCase()}
                </span>
              )}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Misconfigurations Summary */}
          <div
            className="lg:col-span-2 rounded-lg p-6 border"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Misconfigurations Summary
            </h3>
            <div className="grid grid-cols-4 gap-4">
              {[
                {
                  label: 'Critical',
                  value: asset.findings?.critical || 0,
                  color: 'var(--accent-danger)',
                },
                { label: 'High', value: asset.findings?.high || 0, color: 'var(--accent-warning)' },
                {
                  label: 'Medium',
                  value: asset.findings?.medium || 0,
                  color: '#f59e0b',
                },
                { label: 'Low', value: asset.findings?.low || 0, color: 'var(--accent-success)' },
              ].map((item) => (
                <div
                  key={item.label}
                  className="rounded-lg p-4 border"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    borderColor: 'var(--border-primary)',
                  }}
                >
                  <div
                    className="text-2xl font-bold mb-1"
                    style={{ color: item.color }}
                  >
                    {item.value}
                  </div>
                  <p
                    className="text-xs"
                    style={{ color: 'var(--text-tertiary)' }}
                  >
                    {item.label}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Security Posture by Domain */}
          <div
            className="lg:col-span-2 rounded-lg p-6 border"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Security Posture
            </h3>
            {Object.keys(asset.check_posture || {}).length > 0 ? (
              <div className="space-y-2">
                {Object.entries(asset.check_posture)
                  .sort((a, b) => b[1].fail - a[1].fail)
                  .map(([domain, counts]) => {
                    const total = counts.total || 1;
                    const passRate = Math.round((counts.pass / total) * 100);
                    const label = domain.replace(/_/g, ' ').replace(/\band\b/g, '&').replace(/\b\w/g, c => c.toUpperCase());
                    return (
                      <div key={domain} className="flex items-center gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs truncate" style={{ color: 'var(--text-secondary)' }}>{label}</span>
                            <span className="text-xs whitespace-nowrap ml-2" style={{ color: 'var(--text-tertiary)' }}>
                              <span style={{ color: 'var(--accent-success)' }}>{counts.pass}</span>
                              {' / '}
                              <span style={{ color: counts.fail > 0 ? 'var(--accent-danger)' : 'var(--text-tertiary)' }}>{counts.fail}</span>
                            </span>
                          </div>
                          <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                            <div
                              className="h-1.5 rounded-full transition-all"
                              style={{
                                width: `${passRate}%`,
                                backgroundColor: passRate === 100 ? 'var(--accent-success)' : passRate >= 70 ? '#f59e0b' : 'var(--accent-danger)',
                              }}
                            />
                          </div>
                        </div>
                      </div>
                    );
                  })}
              </div>
            ) : (
              <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No check findings available for this resource.</p>
            )}
          </div>

        </div>
      </div>
      )}

      {activeTab === 'configuration' && (() => {
        // Only show emitted_fields from metadata — clean, deduplicated
        const skipKeys = new Set(['_raw_response', '_dependent_data', '_enriched_from',
          'resource_uid', 'resource_arn', 'resource_type', 'resource_id']);
        const isSkip = (k) => skipKeys.has(k) || k.startsWith('_');

        const fmtVal = (v) => {
          if (v === null || v === undefined) return '—';
          if (typeof v === 'boolean') return v ? 'true' : 'false';
          if (typeof v === 'object') return JSON.stringify(v, null, 2);
          return String(v);
        };

        const emitted = asset.emitted_fields || {};
        const entries = Object.entries(emitted).filter(([k]) => !isSkip(k));

        return (
          <div
            className="rounded-lg p-6 border"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Configuration
            </h2>
            {entries.length > 0 ? (
              <div className="rounded-lg border overflow-auto max-h-[600px]" style={{ borderColor: 'var(--border-primary)' }}>
                <table className="w-full text-sm">
                  <thead className="sticky top-0">
                    <tr style={{ backgroundColor: 'var(--bg-tertiary)', borderBottomColor: 'var(--border-primary)' }} className="border-b">
                      <th className="text-left px-4 py-2 font-medium text-xs" style={{ color: 'var(--text-tertiary)', width: '35%' }}>Property</th>
                      <th className="text-left px-4 py-2 font-medium text-xs" style={{ color: 'var(--text-tertiary)' }}>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.map(([key, value], idx) => (
                      <tr key={key} style={{ backgroundColor: idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)', borderBottomColor: 'var(--border-primary)' }} className="border-b last:border-b-0">
                        <td className="px-4 py-2 font-mono text-xs break-all" style={{ color: 'var(--accent-primary)' }}>{key}</td>
                        <td className="px-4 py-2 text-xs break-all whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>
                          {fmtVal(value)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No configuration data available.</p>
            )}
          </div>
        );
      })()}


      {activeTab === 'compliance' && (
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
              Compliance Status
            </h2>
            <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">
              {asset.compliance?.length || 0} frameworks
            </span>
          </div>
          {asset.compliance && asset.compliance.length > 0 ? (
            <DataTable
              data={asset.compliance}
              columns={complianceColumns}
              pageSize={10}
              loading={loading}
              emptyMessage="No compliance data found"
              renderExpandedRow={renderComplianceExpanded}
              onRowClick={(row) => setSelectedComplianceFinding(row)}
            />
          ) : (
            <div className="text-center py-8" style={{ color: 'var(--text-tertiary)' }}>
              No compliance data found
            </div>
          )}
          {selectedComplianceFinding && (
            <ComplianceFindingDetail
              controlId={selectedComplianceFinding.control_id}
              framework={selectedComplianceFinding.framework}
              inlineData={selectedComplianceFinding}
              onClose={() => setSelectedComplianceFinding(null)}
            />
          )}
        </div>
      )}

      {activeTab === 'drift' && (
        <DriftTimeline drift={asset.drift_info} service={asset.service} />
      )}

      {activeTab === 'blast-radius' && (
        <BlastRadiusView
          blastData={asset.blast_radius}
          originName={asset.name || assetId}
          originType={asset.resource_type || ''}
        />
      )}

      {activeTab === 'posture' && (
        <PostureTabs
          resourceUid={asset.resource_id || assetId}
          resourceType={asset.resource_type || ''}
        />
      )}
      </div>
    </div>
  );
}


/* ─── Category colors & icons for blast radius (taxonomy-based) ─── */
// Map backend category strings to RESOURCE_DOMAINS for rendering
function getBlastCategoryMeta(category) {
  const domainMap = {
    compute: 'COMPUTE', database: 'DATABASE', storage: 'STORAGE',
    identity: 'IDENTITY', network: 'NETWORK', load_balancer: 'APPLICATION',
    encryption: 'SECRET_CRYPTO', serverless: 'SERVERLESS', logging: 'MONITORING',
    external: 'APPLICATION', container: 'CONTAINER_K8S', messaging: 'MESSAGING',
  };
  const domainKey = domainMap[category];
  if (domainKey && RESOURCE_DOMAINS[domainKey]) {
    const d = RESOURCE_DOMAINS[domainKey];
    return { label: d.label, color: d.color, icon: DOMAIN_ICON_MAP[d.iconName] || Server };
  }
  return { label: category ? category.charAt(0).toUpperCase() + category.slice(1) : 'Other', color: '#9ca3af', icon: Box };
}

// Categories that represent high-value targets (security impact)
const HIGH_VALUE_CATEGORIES = ['compute', 'database', 'storage', 'identity'];

/* ─── Blast Radius View ─── */
function BlastRadiusView({ blastData, originName, originType }) {
  const nodes = blastData?.nodes || [];
  const edges = blastData?.edges || [];
  const impact = blastData?.impact_summary || {};
  const total = blastData?.total_impacted || 0;

  // toxic_combos: nodes in the blast radius that ALSO have co-existing dangerous misconfigs.
  // These are the highest-priority attacker targets: reachable + already weakened.
  const toxicCombos = blastData?.toxic_combos || [];
  const toxicUidMap = new Map(toxicCombos.map((t) => [t.resource_uid, t]));

  const [showOnlyToxic, setShowOnlyToxic] = useState(false);

  // Impact KPI cards
  const impactCards = Object.entries(impact)
    .filter(([, count]) => count > 0)
    .sort((a, b) => {
      const ai = HIGH_VALUE_CATEGORIES.indexOf(a[0]);
      const bi = HIGH_VALUE_CATEGORIES.indexOf(b[0]);
      if (ai !== -1 && bi === -1) return -1;
      if (ai === -1 && bi !== -1) return 1;
      if (ai !== -1 && bi !== -1) return ai - bi;
      return b[1] - a[1];
    });

  // Build tree: edges map parent → children
  const childrenMap = {};
  edges.forEach((e) => {
    if (!childrenMap[e.source]) childrenMap[e.source] = [];
    if (!childrenMap[e.source].find((c) => c.id === e.target)) {
      const node = nodes.find((n) => n.id === e.target);
      childrenMap[e.source].push({ ...node, relation_type: e.relation_type || '' });
    }
  });

  // Sorted table: toxic first, then high-value, then by hop
  const sortedNodes = [...nodes].sort((a, b) => {
    const at = toxicUidMap.has(a.id) ? 0 : 1;
    const bt = toxicUidMap.has(b.id) ? 0 : 1;
    if (at !== bt) return at - bt;
    const ai = HIGH_VALUE_CATEGORIES.indexOf(a.category);
    const bi = HIGH_VALUE_CATEGORIES.indexOf(b.category);
    if (ai !== -1 && bi === -1) return -1;
    if (ai === -1 && bi !== -1) return 1;
    return (a.hop || 0) - (b.hop || 0);
  });

  const displayNodes = showOnlyToxic ? sortedNodes.filter((n) => toxicUidMap.has(n.id)) : sortedNodes;

  return (
    <div className="space-y-6">

      {/* ════════════════════════════════════════════
          SECTION 1 — BLAST RADIUS
          ════════════════════════════════════════════ */}
      <div>
        {/* Section heading */}
        <div className="flex items-center gap-3 mb-4">
          <div className="flex items-center gap-2">
            <Crosshair className="w-5 h-5" style={{ color: 'var(--accent-danger)' }} />
            <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
              Blast Radius
            </h2>
          </div>
          <span
            className="text-xs px-2.5 py-1 rounded-full font-bold"
            style={{ backgroundColor: total > 0 ? 'rgba(239,68,68,0.15)' : 'var(--bg-tertiary)', color: total > 0 ? '#f87171' : 'var(--text-muted)' }}
          >
            {total} reachable resource{total !== 1 ? 's' : ''}
          </span>
          {toxicCombos.length > 0 && (
            <span
              className="text-xs px-2.5 py-1 rounded-full font-bold"
              style={{ backgroundColor: 'rgba(124,58,237,0.15)', color: '#a78bfa' }}
            >
              ☠ {toxicCombos.length} toxic
            </span>
          )}
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            — resources reachable if this asset is compromised
          </span>
        </div>

        {total === 0 ? (
          <div
            className="rounded-lg border p-10 text-center"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <Crosshair className="w-10 h-10 mx-auto mb-3 opacity-30" style={{ color: 'var(--text-tertiary)' }} />
            <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>No reachable resources</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              No resources are reachable from this asset via attack-path edges
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Impact category KPIs */}
            {impactCards.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {impactCards.map(([cat, count]) => {
                  const meta = getBlastCategoryMeta(cat);
                  const isHighValue = HIGH_VALUE_CATEGORIES.includes(cat);
                  return (
                    <div
                      key={cat}
                      className="flex items-center gap-2 rounded-lg px-3 py-2 border"
                      style={{
                        borderColor: isHighValue ? meta.color : 'var(--border-primary)',
                        backgroundColor: isHighValue ? `${meta.color}10` : 'var(--bg-tertiary)',
                      }}
                    >
                      {meta.icon && <meta.icon className="w-4 h-4" style={{ color: meta.color }} />}
                      <div>
                        <div className="text-base font-bold tabular-nums" style={{ color: meta.color }}>{count}</div>
                        <div className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{meta.label}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Dependency tree */}
            <div
              className="rounded-lg border overflow-hidden"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
            >
              <div className="px-4 py-3 border-b flex items-center gap-2" style={{ borderColor: 'var(--border-primary)' }}>
                <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-tertiary)' }}>
                  Dependency Tree
                </span>
                {toxicCombos.length > 0 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ backgroundColor: 'rgba(124,58,237,0.12)', color: '#a78bfa' }}>
                    ☠ = toxic combo
                  </span>
                )}
              </div>
              <div className="p-4 font-mono text-xs overflow-x-auto" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className="inline-flex items-center justify-center w-5 h-5 rounded-full text-white text-[10px] font-bold flex-shrink-0"
                    style={{ backgroundColor: '#3b82f6' }}
                  >◉</span>
                  <span className="font-bold" style={{ color: 'var(--text-primary)' }}>{originName}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
                    {originType || 'origin'}
                  </span>
                </div>
                <TreeBranch
                  parentId={blastData?.origin}
                  childrenMap={childrenMap}
                  depth={0}
                  maxDepth={4}
                  visited={new Set()}
                  toxicUidMap={toxicUidMap}
                />
              </div>
            </div>

            {/* Impacted resources table */}
            <div
              className="rounded-lg border overflow-hidden"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
            >
              <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-primary)' }}>
                <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-tertiary)' }}>
                  All Reachable Resources
                </span>
                {toxicCombos.length > 0 && (
                  <button
                    onClick={() => setShowOnlyToxic((v) => !v)}
                    className="text-xs px-2.5 py-1 rounded-full font-medium"
                    style={{
                      backgroundColor: showOnlyToxic ? '#7c3aed' : 'rgba(124,58,237,0.12)',
                      color: showOnlyToxic ? 'white' : '#a78bfa',
                      border: '1px solid rgba(124,58,237,0.3)',
                    }}
                  >
                    {showOnlyToxic ? 'Show all' : `☠ Toxic only (${toxicCombos.length})`}
                  </button>
                )}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-primary)' }}>
                      <th className="text-left py-2 px-4 font-medium" style={{ color: 'var(--text-tertiary)' }}>Resource</th>
                      <th className="text-left py-2 pr-3 font-medium" style={{ color: 'var(--text-tertiary)' }}>Category</th>
                      <th className="text-left py-2 pr-3 font-medium" style={{ color: 'var(--text-tertiary)' }}>Type</th>
                      <th className="text-left py-2 pr-3 font-medium" style={{ color: 'var(--text-tertiary)' }}>Hop</th>
                      <th className="text-left py-2 pr-3 font-medium" style={{ color: 'var(--text-tertiary)' }}>Via</th>
                      <th className="text-left py-2 pr-4 font-medium" style={{ color: 'var(--text-tertiary)' }}>Toxic Combo</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayNodes.map((node, idx) => {
                      const meta = getBlastCategoryMeta(node.category);
                      const isHighValue = HIGH_VALUE_CATEGORIES.includes(node.category);
                      const toxic = toxicUidMap.get(node.id);
                      return (
                        <tr
                          key={idx}
                          style={{
                            borderBottom: '1px solid var(--border-primary)',
                            backgroundColor: toxic ? 'rgba(124,58,237,0.05)' : 'transparent',
                          }}
                        >
                          <td className="py-2 px-4">
                            <div className="flex items-center gap-1.5">
                              {toxic && <span title={`Toxic: ${(toxic.conditions || []).join(', ')}`} className="text-[11px]">☠</span>}
                              <code style={{ color: toxic ? '#c4b5fd' : isHighValue ? meta.color : 'var(--text-secondary)' }}>
                                {(node.name || node.id || '').length > 48
                                  ? (node.name || node.id).substring(0, 48) + '…'
                                  : node.name || node.id}
                              </code>
                            </div>
                          </td>
                          <td className="py-2 pr-3">
                            <span
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold"
                              style={{ backgroundColor: `${meta.color}20`, color: meta.color }}
                            >
                              {meta.icon && <meta.icon className="w-3 h-3" />} {meta.label}
                            </span>
                          </td>
                          <td className="py-2 pr-3" style={{ color: 'var(--text-tertiary)' }}>{node.type || '—'}</td>
                          <td className="py-2 pr-3">
                            <span
                              className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                              style={{
                                backgroundColor: node.hop === 1 ? 'rgba(239,68,68,0.2)' : node.hop === 2 ? 'rgba(249,115,22,0.2)' : 'rgba(245,158,11,0.2)',
                                color: node.hop === 1 ? '#f87171' : node.hop === 2 ? '#fb923c' : '#fbbf24',
                              }}
                            >
                              hop {node.hop}
                            </span>
                          </td>
                          <td className="py-2 pr-3">
                            <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
                              {node.relation_type || '—'}
                            </span>
                          </td>
                          <td className="py-2 pr-4">
                            {toxic ? (
                              <span className="text-[10px] px-1.5 py-0.5 rounded font-bold" style={{ backgroundColor: 'rgba(124,58,237,0.25)', color: '#c4b5fd' }}>
                                Yes
                              </span>
                            ) : (
                              <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                                No
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ════════════════════════════════════════════
          SECTION 2 — TOXIC COMBINATIONS (only shown when combos exist)
          ════════════════════════════════════════════ */}
      {toxicCombos.length > 0 && <div>
        {/* Section heading */}
        <div className="flex items-center gap-3 mb-4">
          <div className="flex items-center gap-2">
            <span className="text-lg">☠</span>
            <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
              Toxic Combinations
            </h2>
          </div>
          <span
            className="text-xs px-2.5 py-1 rounded-full font-bold"
            style={{
              backgroundColor: toxicCombos.length > 0 ? 'rgba(124,58,237,0.15)' : 'var(--bg-tertiary)',
              color: toxicCombos.length > 0 ? '#a78bfa' : 'var(--text-muted)',
            }}
          >
            {toxicCombos.length} found
          </span>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            — reachable resources with co-existing dangerous misconfigurations
          </span>
        </div>

        {toxicCombos.length === 0 ? (
          <div
            className="rounded-lg border p-8 text-center"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <span className="text-3xl opacity-20">☠</span>
            <p className="text-sm font-medium mt-2" style={{ color: 'var(--text-secondary)' }}>No toxic combinations found</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              No resources in the blast radius have co-existing critical misconfigurations
            </p>
          </div>
        ) : (
          <div
            className="rounded-lg border"
            style={{ backgroundColor: 'rgba(124,58,237,0.05)', borderColor: 'rgba(124,58,237,0.3)' }}
          >
            <div className="px-4 py-3 border-b" style={{ borderColor: 'rgba(124,58,237,0.2)' }}>
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                These resources are <strong style={{ color: 'var(--text-primary)' }}>both reachable from this asset AND have multiple dangerous misconfigurations</strong>.
                An attacker moving laterally can reach and exploit them immediately.
              </p>
            </div>
            <div className="divide-y" style={{ borderColor: 'rgba(124,58,237,0.15)' }}>
              {toxicCombos.map((t, i) => (
                <div key={i} className="flex items-start gap-3 px-4 py-3">
                  <span className="text-base flex-shrink-0 mt-0.5">☠</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <a
                        href={`/inventory/${encodeURIComponent(t.resource_uid)}`}
                        className="font-mono text-xs hover:underline truncate"
                        style={{ color: '#c4b5fd' }}
                        title={t.resource_uid}
                      >
                        {t.resource_uid.length > 72 ? t.resource_uid.substring(0, 72) + '…' : t.resource_uid}
                      </a>
                      {t.severity && (
                        <span
                          className="text-[10px] px-1.5 py-0.5 rounded font-bold flex-shrink-0"
                          style={{
                            backgroundColor: t.severity === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(249,115,22,0.2)',
                            color: t.severity === 'CRITICAL' ? '#f87171' : '#fb923c',
                          }}
                        >
                          {t.severity}
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {(t.conditions || []).map((cond, ci) => (
                        <span
                          key={ci}
                          className="text-[10px] px-1.5 py-0.5 rounded"
                          style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#fca5a5' }}
                        >
                          {cond}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>}

    </div>
  );
}


/* ─── Recursive Tree Branch ─── */
function TreeBranch({ parentId, childrenMap, depth, maxDepth, visited, toxicUidMap = new Map() }) {
  if (!parentId || depth >= maxDepth) return null;
  const children = childrenMap[parentId] || [];
  if (children.length === 0) return null;

  return (
    <div style={{ marginLeft: depth === 0 ? 12 : 20 }}>
      {children.map((child, idx) => {
        if (visited.has(child.id)) return null;
        const newVisited = new Set(visited);
        newVisited.add(child.id);

        const meta = getBlastCategoryMeta(child.category);
        const isLast = idx === children.length - 1;
        const hasChildren = (childrenMap[child.id] || []).length > 0;
        const isHighValue = HIGH_VALUE_CATEGORIES.includes(child.category);
        const isToxic = toxicUidMap.has(child.id);

        return (
          <div key={child.id || idx}>
            <div
              className="flex items-center gap-1.5 py-0.5 rounded"
              style={isToxic ? { backgroundColor: 'rgba(124,58,237,0.12)', paddingLeft: 4, paddingRight: 4 } : {}}
            >
              {/* Tree connector */}
              <span style={{ color: 'var(--border-primary)', userSelect: 'none' }}>
                {isLast ? '└─' : '├─'}
              </span>
              {/* Toxic skull */}
              {isToxic && <span title="Toxic combination" className="text-[11px]">☠</span>}
              {/* Category icon */}
              {meta.icon && <meta.icon className="w-3.5 h-3.5" style={{ color: isToxic ? '#a78bfa' : meta.color }} />}
              {/* Name */}
              <span
                className={isHighValue || isToxic ? 'font-semibold' : ''}
                style={{ color: isToxic ? '#c4b5fd' : isHighValue ? meta.color : 'var(--text-secondary)' }}
              >
                {(child.name || child.id || '').length > 40
                  ? (child.name || child.id).substring(0, 40) + '...'
                  : child.name || child.id}
              </span>
              {/* Type badge */}
              <span
                className="text-[9px] px-1 py-0.5 rounded"
                style={{
                  backgroundColor: isToxic ? 'rgba(124,58,237,0.2)' : `${meta.color}15`,
                  color: isToxic ? '#a78bfa' : meta.color,
                }}
              >
                {child.type || child.category}
              </span>
              {/* Relation */}
              <span className="text-[9px]" style={{ color: 'var(--text-tertiary)' }}>
                ← {child.relation_type}
              </span>
            </div>
            {/* Recurse */}
            {hasChildren && (
              <TreeBranch
                parentId={child.id}
                childrenMap={childrenMap}
                depth={depth + 1}
                maxDepth={maxDepth}
                visited={newVisited}
                toxicUidMap={toxicUidMap}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
