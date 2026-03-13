'use client';

import { useState, useEffect, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft,
  Copy,
  Check,
  Shield,
  Lock,
  Database,
  Network,
  AlertTriangle,
  CheckCircle,
  Crosshair,
  Zap,
  ChevronDown,
  ChevronRight,
  Plus,
  Minus,
  RefreshCw,
  Box,
} from 'lucide-react';
import { getFromEngine, fetchView } from '@/lib/api';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';
import CloudServiceIcon from '@/components/shared/CloudServiceIcon';
import DriftTimeline from '@/components/shared/DriftTimeline';


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

        // Fallback to direct engine calls if BFF fails
        if (!bffData || bffData.error) {
          const [assetRes, relsRes, driftRes] = await Promise.allSettled([
            getFromEngine('inventory', `/api/v1/inventory/assets/${encoded}`),
            getFromEngine('inventory', `/api/v1/inventory/assets/${encoded}/relationships`, { depth: 2 }),
            getFromEngine('inventory', `/api/v1/inventory/assets/${encoded}/drift`, { limit: 20 }),
          ]);

          const assetData = assetRes.status === 'fulfilled' ? assetRes.value : null;
          if (!assetData || assetData.error) {
            setError(assetData?.error || 'Asset not found');
            setLoading(false);
            return;
          }
          const base = assetData.asset || assetData;
          const relsData = relsRes.status === 'fulfilled' ? relsRes.value : null;
          const rawRels = relsData?.relationships || [];
          const normalizedRels = rawRels.length > 0
            ? rawRels.map((r) => ({
                relationship_type: r.relation_type || r.relationship_type || 'related_to',
                related_resource: r.source === assetId ? r.target : (r.source || r.target || ''),
                related_type: r.resource_type || r.label || 'Resource',
                direction: r.source === assetId ? 'outbound' : 'inbound',
              }))
            : base.relationships || [];
          const driftData = driftRes.status === 'fulfilled' ? driftRes.value : null;
          const blastData = blastRes.status === 'fulfilled' ? blastRes.value : null;

          setAsset({
            ...base,
            resource_id: base.resource_uid || base.resource_id || assetId,
            resource_name: base.metadata?.name || base.resource_uid?.split('/').pop() || base.resource_id || assetId,
            resource_type: base.resource_type || '',
            service: base.service || (base.resource_type ? base.resource_type.split('::')[1]?.toLowerCase() : '') || '',
            provider: (base.provider || 'aws').toLowerCase(),
            tags: base.tags || {},
            config: (base.config && Object.keys(base.config).length > 0) ? base.config : {},
            relationships: normalizedRels,
            drift_info: driftData?.drift_info || base.drift_info || null,
            blast_radius: blastData || { nodes: [], edges: [], total_impacted: 0, impact_summary: {}, origin: assetId },
          });
          setLoading(false);
          return;
        }

        // ── BFF response: pre-assembled cross-engine data ────────────
        const base = bffData.asset || {};
        const blastData = blastRes.status === 'fulfilled' ? blastRes.value : null;

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
          findings: bffData.check_severity || base.findings || {},
          findings_detail: bffData.check_findings || [],
          check_posture: bffData.check_posture || {},
          threats: bffData.threat_findings || [],
          threat_severity: bffData.threat_severity || {},
          compliance: bffData.compliance_findings || [],
          relationships: bffData.relationships || base.relationships || [],
          drift_info: bffData.drift || base.drift_info || null,
          blast_radius: blastData || { nodes: [], edges: [], total_impacted: 0, impact_summary: {}, origin: assetId },
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

  // Table columns for relationships
  const relationshipColumns = [
    {
      accessorKey: 'relationship_type',
      header: 'Relationship Type',
      cell: (info) => (
        <span
          className="text-xs font-medium px-2 py-1 rounded"
          style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-tertiary)' }}
        >
          {info.getValue().replace(/_/g, ' ')}
        </span>
      ),
    },
    {
      accessorKey: 'related_resource',
      header: 'Related Resource',
      cell: (info) => (
        <code
          className="text-xs"
          style={{ color: 'var(--text-tertiary)' }}
        >
          {info.getValue().substring(0, 40)}...
        </code>
      ),
    },
    {
      accessorKey: 'related_type',
      header: 'Type',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'direction',
      header: 'Direction',
      cell: (info) => {
        const direction = info.getValue();
        return (
          <span
            className="text-xs font-medium px-2 py-1 rounded"
            style={{
              backgroundColor:
                direction === 'inbound'
                  ? 'var(--accent-success)'
                  : 'var(--accent-primary)',
              color: 'white',
            }}
          >
            {direction === 'inbound' ? '← Inbound' : '→ Outbound'}
          </span>
        );
      },
    },
  ];

  // Table columns for findings (matches API findings_detail: rule_id, title, severity, status, service)
  const findingsColumns = [
    {
      accessorKey: 'rule_id',
      header: 'Rule ID',
      cell: (info) => (
        <code
          className="text-xs px-2 py-1 rounded"
          style={{ color: 'var(--text-tertiary)', backgroundColor: 'var(--bg-tertiary)' }}
        >
          {(info.getValue() || '').substring(0, 20)}
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
  const complianceColumns = [
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4 flex-1">
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

        {/* Quick Info Cards */}
        <div className="grid grid-cols-2 gap-3 min-w-max">
          <div
            className="rounded-lg p-3 border"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
              Risk Score
            </p>
            <p
              className="text-2xl font-bold"
              style={{ color: getSeverityColor(asset.risk_score >= 70 ? 'critical' : asset.risk_score >= 50 ? 'high' : asset.risk_score >= 30 ? 'medium' : 'low') }}
            >
              {asset.risk_score}%
            </p>
          </div>
          <div
            className="rounded-lg p-3 border"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
              Findings
            </p>
            <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
              {(asset.findings?.critical || 0) + (asset.findings?.high || 0) + (asset.findings?.medium || 0)}
            </p>
          </div>
          <div
            className="rounded-lg p-3 border"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
              Owner
            </p>
            <p className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
              {asset.owner || '—'}
            </p>
          </div>
          <div
            className="rounded-lg p-3 border"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
              Account
            </p>
            <p className="text-sm font-semibold font-mono" style={{ color: 'var(--text-secondary)' }}>
              {asset.account_id}
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ borderBottomColor: 'var(--border-primary)' }} className="border-b">
        <div className="flex gap-1">
          {['overview', 'configuration', 'findings', 'threats', 'relationships', 'blast-radius', 'compliance', 'drift'].map(
            (tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-3 text-sm font-medium transition-colors border-b-2 ${
                  activeTab === tab ? 'border-blue-500' : 'border-transparent'
                }`}
                style={{
                  color:
                    activeTab === tab ? 'var(--accent-primary)' : 'var(--text-tertiary)',
                }}
              >
                {tab === 'blast-radius' ? 'Blast Radius' : tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            )
          )}
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Findings Summary */}
          <div
            className="lg:col-span-2 rounded-lg p-6 border"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Findings Summary
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

          {/* Metadata */}
          <div
            className="rounded-lg p-6 border"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Timeline
            </h3>
            <div className="space-y-3 text-sm">
              <div>
                <p style={{ color: 'var(--text-tertiary)' }}>Created</p>
                <p style={{ color: 'var(--text-secondary)' }}>
                  {asset.created_at ? new Date(asset.created_at).toLocaleDateString() : 'N/A'}
                </p>
              </div>
              <div>
                <p style={{ color: 'var(--text-tertiary)' }}>Last Modified</p>
                <p style={{ color: 'var(--text-secondary)' }}>
                  {asset.last_modified ? new Date(asset.last_modified).toLocaleDateString() : 'N/A'}
                </p>
              </div>
              <div>
                <p style={{ color: 'var(--text-tertiary)' }}>Last Scanned</p>
                <p style={{ color: 'var(--text-secondary)' }}>
                  {asset.last_scanned ? new Date(asset.last_scanned).toLocaleDateString() : 'N/A'}
                </p>
              </div>
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

        const emitted = asset.metadata?.emitted_fields || {};
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

      {activeTab === 'findings' && (
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
              Findings
            </h2>
            <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">
              {asset.findings_detail?.length || 0} findings
            </span>
          </div>
          {asset.findings_detail && asset.findings_detail.length > 0 ? (
            <DataTable
              data={asset.findings_detail}
              columns={findingsColumns}
              pageSize={10}
              loading={loading}
              emptyMessage="No findings found"
            />
          ) : (
            <div className="text-center py-8" style={{ color: 'var(--text-tertiary)' }}>
              No findings found
            </div>
          )}
        </div>
      )}

      {activeTab === 'relationships' && (
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
              Related Resources
            </h2>
            <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">
              {asset.relationships?.length || 0} relationships
            </span>
          </div>
          {asset.relationships && asset.relationships.length > 0 ? (
            <DataTable
              data={asset.relationships}
              columns={relationshipColumns}
              pageSize={10}
              loading={loading}
              emptyMessage="No relationships found"
            />
          ) : (
            <div className="text-center py-8" style={{ color: 'var(--text-tertiary)' }}>
              No related resources found
            </div>
          )}
        </div>
      )}

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
            />
          ) : (
            <div className="text-center py-8" style={{ color: 'var(--text-tertiary)' }}>
              No compliance data found
            </div>
          )}
        </div>
      )}

      {activeTab === 'drift' && (
        <DriftTimeline drift={asset.drift_info} service={asset.service} />
      )}

      {activeTab === 'threats' && (
        <div className="space-y-4">
          {/* Threat Severity Summary */}
          {asset.threat_severity && (
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: 'Critical', key: 'critical', color: 'var(--accent-danger)' },
                { label: 'High', key: 'high', color: 'var(--accent-warning)' },
                { label: 'Medium', key: 'medium', color: '#f59e0b' },
                { label: 'Low', key: 'low', color: 'var(--accent-success)' },
              ].map((item) => (
                <div
                  key={item.key}
                  className="rounded-lg p-4 border"
                  style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
                >
                  <div className="text-2xl font-bold mb-1" style={{ color: item.color }}>
                    {asset.threat_severity[item.key] || 0}
                  </div>
                  <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                    {item.label} Threats
                  </p>
                </div>
              ))}
            </div>
          )}
          <div
            className="rounded-lg p-6 border"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5" style={{ color: 'var(--accent-warning)' }} />
                <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                  Threat Findings
                </h2>
              </div>
              <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">
                {asset.threats?.length || 0} threats
              </span>
            </div>
            {asset.threats && asset.threats.length > 0 ? (
              <DataTable
                data={asset.threats}
                columns={threatColumns}
                pageSize={10}
                loading={loading}
                emptyMessage="No threats found"
              />
            ) : (
              <div className="text-center py-8" style={{ color: 'var(--text-tertiary)' }}>
                No threat findings for this resource
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'blast-radius' && (
        <BlastRadiusView
          blastData={asset.blast_radius}
          originName={asset.name || assetId}
          originType={asset.resource_type || ''}
        />
      )}
    </div>
  );
}


/* ─── Category colors & icons for blast radius ─── */
const CATEGORY_META = {
  compute:       { label: 'Compute',       color: '#3b82f6', icon: '🖥' },
  database:      { label: 'Database',      color: '#ef4444', icon: '🗄' },
  storage:       { label: 'Storage',       color: '#f59e0b', icon: '💾' },
  identity:      { label: 'Identity',      color: '#a855f7', icon: '🔑' },
  network:       { label: 'Network',       color: '#6b7280', icon: '🌐' },
  load_balancer: { label: 'Load Balancer', color: '#06b6d4', icon: '⚖' },
  encryption:    { label: 'Encryption',    color: '#10b981', icon: '🔒' },
  serverless:    { label: 'Serverless',    color: '#8b5cf6', icon: '⚡' },
  logging:       { label: 'Logging',       color: '#64748b', icon: '📋' },
  external:      { label: 'External',      color: '#ec4899', icon: '🌍' },
  other:         { label: 'Other',         color: '#9ca3af', icon: '◦' },
};

// Categories that represent high-value targets (security impact)
const HIGH_VALUE_CATEGORIES = ['compute', 'database', 'storage', 'identity'];

/* ─── Blast Radius View ─── */
function BlastRadiusView({ blastData, originName, originType }) {
  const nodes = blastData?.nodes || [];
  const edges = blastData?.edges || [];
  const impact = blastData?.impact_summary || {};
  const total = blastData?.total_impacted || 0;

  if (total === 0) {
    return (
      <div className="text-center py-16" style={{ color: 'var(--text-tertiary)' }}>
        <Crosshair className="w-10 h-10 mx-auto mb-3 opacity-30" />
        <p className="text-sm">No resources depend on this resource</p>
        <p className="text-xs mt-1 opacity-60">Blast radius is zero — compromising this resource has no downstream impact</p>
      </div>
    );
  }

  // Impact KPI cards — only show categories that have > 0 count
  const impactCards = Object.entries(impact)
    .filter(([, count]) => count > 0)
    .sort((a, b) => {
      const ai = HIGH_VALUE_CATEGORIES.indexOf(a[0]);
      const bi = HIGH_VALUE_CATEGORIES.indexOf(b[0]);
      // High-value categories first, then by count
      if (ai !== -1 && bi === -1) return -1;
      if (ai === -1 && bi !== -1) return 1;
      if (ai !== -1 && bi !== -1) return ai - bi;
      return b[1] - a[1];
    });

  // Build tree structure: edges map parent→children
  const childrenMap = {};
  edges.forEach((e) => {
    if (!childrenMap[e.source]) childrenMap[e.source] = [];
    // Avoid duplicate children
    if (!childrenMap[e.source].find((c) => c.id === e.target)) {
      const node = nodes.find((n) => n.id === e.target);
      childrenMap[e.source].push({
        ...node,
        relation_type: e.relation_type || '',
      });
    }
  });

  return (
    <div className="space-y-4">
      {/* Impact Summary */}
      <div
        className="rounded-lg p-4 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex items-center gap-2 mb-3">
          <Crosshair className="w-4 h-4" style={{ color: 'var(--accent-danger)' }} />
          <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            Impact Summary
          </h3>
          <span
            className="text-xs px-2 py-0.5 rounded-full font-bold"
            style={{ backgroundColor: 'var(--accent-danger)', color: 'white' }}
          >
            {total} total
          </span>
        </div>
        <p className="text-xs mb-3" style={{ color: 'var(--text-tertiary)' }}>
          If this resource is compromised, the following resources are impacted:
        </p>
        <div className="flex flex-wrap gap-2">
          {impactCards.map(([cat, count]) => {
            const meta = CATEGORY_META[cat] || CATEGORY_META.other;
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
                <span className="text-base">{meta.icon}</span>
                <div>
                  <div className="text-lg font-bold" style={{ color: meta.color }}>{count}</div>
                  <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{meta.label}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Dependency Tree */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="p-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <Crosshair className="w-5 h-5" style={{ color: 'var(--accent-danger)' }} />
            <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
              Dependency Tree
            </h2>
            <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
              — resources that depend on this resource
            </span>
          </div>
        </div>
        <div className="p-4 font-mono text-xs" style={{ backgroundColor: 'var(--bg-secondary)' }}>
          {/* Origin */}
          <div className="flex items-center gap-2 mb-1">
            <span
              className="inline-flex items-center justify-center w-5 h-5 rounded-full text-white text-[10px] font-bold"
              style={{ backgroundColor: '#3b82f6' }}
            >
              ◉
            </span>
            <span className="font-bold" style={{ color: 'var(--text-primary)' }}>
              {originName}
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
              {originType || 'origin'}
            </span>
          </div>
          {/* Children tree */}
          <TreeBranch
            parentId={blastData?.origin}
            childrenMap={childrenMap}
            depth={0}
            maxDepth={4}
            visited={new Set()}
          />
        </div>
      </div>

      {/* Impacted Resources Table */}
      <div
        className="rounded-lg p-5 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
          Impacted Resources
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-primary)' }}>
                <th className="text-left py-2 pr-3 font-medium" style={{ color: 'var(--text-tertiary)' }}>Resource</th>
                <th className="text-left py-2 pr-3 font-medium" style={{ color: 'var(--text-tertiary)' }}>Category</th>
                <th className="text-left py-2 pr-3 font-medium" style={{ color: 'var(--text-tertiary)' }}>Type</th>
                <th className="text-left py-2 pr-3 font-medium" style={{ color: 'var(--text-tertiary)' }}>Hop</th>
                <th className="text-left py-2 font-medium" style={{ color: 'var(--text-tertiary)' }}>Relationship</th>
              </tr>
            </thead>
            <tbody>
              {[...nodes]
                .sort((a, b) => {
                  // High-value categories first, then by hop
                  const ai = HIGH_VALUE_CATEGORIES.indexOf(a.category);
                  const bi = HIGH_VALUE_CATEGORIES.indexOf(b.category);
                  if (ai !== -1 && bi === -1) return -1;
                  if (ai === -1 && bi !== -1) return 1;
                  return a.hop - b.hop;
                })
                .map((node, idx) => {
                  const meta = CATEGORY_META[node.category] || CATEGORY_META.other;
                  const isHighValue = HIGH_VALUE_CATEGORIES.includes(node.category);
                  return (
                    <tr
                      key={idx}
                      style={{ borderBottom: '1px solid var(--border-primary)' }}
                      className={isHighValue ? 'font-medium' : ''}
                    >
                      <td className="py-2 pr-3">
                        <code style={{ color: isHighValue ? meta.color : 'var(--text-secondary)' }}>
                          {(node.name || node.id || '').length > 50
                            ? (node.name || node.id).substring(0, 50) + '...'
                            : node.name || node.id}
                        </code>
                      </td>
                      <td className="py-2 pr-3">
                        <span
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold"
                          style={{
                            backgroundColor: `${meta.color}20`,
                            color: meta.color,
                          }}
                        >
                          {meta.icon} {meta.label}
                        </span>
                      </td>
                      <td className="py-2 pr-3" style={{ color: 'var(--text-tertiary)' }}>
                        {node.type || '-'}
                      </td>
                      <td className="py-2 pr-3">
                        <span
                          className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                          style={{
                            backgroundColor: node.hop === 1 ? 'var(--accent-danger)' : node.hop === 2 ? 'var(--accent-warning)' : '#f59e0b',
                            color: 'white',
                          }}
                        >
                          {node.hop}
                        </span>
                      </td>
                      <td className="py-2">
                        <span
                          className="text-[10px] px-1.5 py-0.5 rounded"
                          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}
                        >
                          {node.relation_type || '-'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}


/* ─── Recursive Tree Branch ─── */
function TreeBranch({ parentId, childrenMap, depth, maxDepth, visited }) {
  if (!parentId || depth >= maxDepth) return null;
  const children = childrenMap[parentId] || [];
  if (children.length === 0) return null;

  return (
    <div style={{ marginLeft: depth === 0 ? 12 : 20 }}>
      {children.map((child, idx) => {
        if (visited.has(child.id)) return null;
        const newVisited = new Set(visited);
        newVisited.add(child.id);

        const meta = CATEGORY_META[child.category] || CATEGORY_META.other;
        const isLast = idx === children.length - 1;
        const hasChildren = (childrenMap[child.id] || []).length > 0;
        const isHighValue = HIGH_VALUE_CATEGORIES.includes(child.category);

        return (
          <div key={child.id || idx}>
            <div className="flex items-center gap-1.5 py-0.5">
              {/* Tree connector */}
              <span style={{ color: 'var(--border-primary)', userSelect: 'none' }}>
                {isLast ? '└─' : '├─'}
              </span>
              {/* Category icon */}
              <span className="text-sm">{meta.icon}</span>
              {/* Name */}
              <span
                className={isHighValue ? 'font-semibold' : ''}
                style={{ color: isHighValue ? meta.color : 'var(--text-secondary)' }}
              >
                {(child.name || child.id || '').length > 40
                  ? (child.name || child.id).substring(0, 40) + '...'
                  : child.name || child.id}
              </span>
              {/* Type badge */}
              <span
                className="text-[9px] px-1 py-0.5 rounded"
                style={{ backgroundColor: `${meta.color}15`, color: meta.color }}
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
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
