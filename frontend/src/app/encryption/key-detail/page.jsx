'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { Key, Shield, AlertTriangle, ArrowLeft, AlertCircle } from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import { TENANT_ID } from '@/lib/constants';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import Link from 'next/link';

export default function KeyDetailPage() {
  const searchParams = useSearchParams();
  const keyId = searchParams.get('keyId');

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dependencies, setDependencies] = useState(null);
  const [blastRadius, setBlastRadius] = useState(null);

  useEffect(() => {
    if (!keyId) return;

    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const [depResult, brResult] = await Promise.all([
          getFromEngine('gateway', `/api/v1/encryption/keys/${keyId}/dependencies`, {
            tenant_id: TENANT_ID,
          }),
          getFromEngine('gateway', `/api/v1/encryption/keys/${keyId}/blast-radius`, {
            tenant_id: TENANT_ID,
          }),
        ]);

        if (depResult.error) { setError(depResult.error); return; }
        if (brResult.error) { setError(brResult.error); return; }

        setDependencies(depResult);
        setBlastRadius(brResult);
      } catch (err) {
        setError(err?.message || 'Failed to load key details');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [keyId]);

  // ── Blast radius score color ──
  const scoreColor = (score) => {
    if (score >= 80) return '#ef4444';
    if (score >= 60) return '#f97316';
    if (score >= 40) return '#eab308';
    if (score >= 20) return '#3b82f6';
    return '#22c55e';
  };

  const scoreSeverity = (score) => {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'info';
  };

  // ── Column definitions for dependency table ──
  const dependencyColumns = [
    {
      accessorKey: 'resource_uid', header: 'Resource UID',
      cell: (info) => (
        <span className="text-xs font-mono break-all" style={{ color: 'var(--text-primary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'resource_type', header: 'Type',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  if (!keyId) {
    return (
      <div className="p-6 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
        <div className="flex items-center gap-2 text-yellow-400">
          <AlertTriangle className="w-5 h-5" />
          <span>No key ID provided. Go back and select a key.</span>
        </div>
        <Link href="/encryption" className="inline-flex items-center gap-1 mt-3 text-sm hover:underline" style={{ color: 'var(--accent-primary)' }}>
          <ArrowLeft className="w-4 h-4" /> Back to Keys
        </Link>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2" style={{ borderColor: 'var(--accent-primary)' }} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
        <div className="flex items-center gap-2 text-red-400">
          <AlertCircle className="w-5 h-5" /><span>{error}</span>
        </div>
        <Link href="/encryption" className="inline-flex items-center gap-1 mt-3 text-sm hover:underline" style={{ color: 'var(--accent-primary)' }}>
          <ArrowLeft className="w-4 h-4" /> Back to Keys
        </Link>
      </div>
    );
  }

  const keyMeta = dependencies?.key_metadata || {};
  const depList = dependencies?.resources || [];
  const br = blastRadius || {};
  const brScore = br.score ?? 0;
  const brAffected = br.affected_resources || [];
  const brBySeverity = br.by_severity || {};
  const brByType = br.by_type || {};

  return (
    <div className="space-y-5">
      {/* ── Back link ── */}
      <Link href="/encryption" className="inline-flex items-center gap-1 text-sm hover:underline" style={{ color: 'var(--accent-primary)' }}>
        <ArrowLeft className="w-4 h-4" /> Back to Keys
      </Link>

      {/* ── Page Heading ── */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <Key className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Key Detail</h1>
        </div>
        <p className="text-sm font-mono break-all" style={{ color: 'var(--text-secondary)' }}>
          {keyMeta.arn || keyMeta.key_id || keyId}
        </p>
      </div>

      {/* ── Key Metadata Cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'State', value: keyMeta.state || keyMeta.status || '-' },
          { label: 'Manager', value: keyMeta.key_manager || keyMeta.manager || '-' },
          { label: 'Spec', value: keyMeta.key_spec || keyMeta.algorithm || '-' },
          { label: 'Rotation', value: keyMeta.rotation_enabled ? 'Enabled' : 'Disabled' },
          { label: 'Created', value: keyMeta.created_at || '-' },
          { label: 'Origin', value: keyMeta.origin || '-' },
        ].map((item, i) => (
          <div key={i} className="rounded-lg p-4" style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
            <div className="text-[10px] uppercase tracking-wide font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
              {item.label}
            </div>
            <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
              {item.value}
            </div>
          </div>
        ))}
      </div>

      {/* ── Two-column layout: Dependencies + Blast Radius ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* ── Dependencies Table (2/3 width) ── */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5" style={{ color: 'var(--accent-primary)' }} />
            <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
              Dependent Resources
            </h2>
            <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
              {depList.length}
            </span>
          </div>
          <DataTable data={depList} columns={dependencyColumns} pageSize={10} hideToolbar />
        </div>

        {/* ── Blast Radius Panel (1/3 width) ── */}
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" style={{ color: scoreColor(brScore) }} />
            <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
              Blast Radius
            </h2>
          </div>

          {/* Score Gauge */}
          <div className="rounded-lg p-5 text-center" style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
            <div className="relative inline-flex items-center justify-center w-32 h-32 mb-3">
              <svg className="w-32 h-32 -rotate-90" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="50" fill="none" stroke="var(--border-primary)" strokeWidth="10" />
                <circle
                  cx="60" cy="60" r="50"
                  fill="none"
                  stroke={scoreColor(brScore)}
                  strokeWidth="10"
                  strokeLinecap="round"
                  strokeDasharray={`${(brScore / 100) * 314} 314`}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-bold" style={{ color: scoreColor(brScore) }}>{brScore}</span>
                <span className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>/ 100</span>
              </div>
            </div>
            <div className="mb-1">
              <SeverityBadge severity={scoreSeverity(brScore)} />
            </div>
            <p className="text-xs mt-2" style={{ color: 'var(--text-tertiary)' }}>
              {brAffected.length || br.total_affected || 0} resources affected
            </p>
          </div>

          {/* Breakdown by Severity */}
          {Object.keys(brBySeverity).length > 0 && (
            <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
              <h3 className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                By Severity
              </h3>
              <div className="space-y-2">
                {Object.entries(brBySeverity).map(([sev, count]) => (
                  <div key={sev} className="flex items-center justify-between">
                    <SeverityBadge severity={sev} />
                    <span className="text-sm font-semibold tabular-nums" style={{ color: 'var(--text-primary)' }}>{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Breakdown by Type */}
          {Object.keys(brByType).length > 0 && (
            <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
              <h3 className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                By Resource Type
              </h3>
              <div className="space-y-2">
                {Object.entries(brByType)
                  .sort(([, a], [, b]) => b - a)
                  .map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between">
                      <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                        {type}
                      </span>
                      <span className="text-sm font-semibold tabular-nums" style={{ color: 'var(--text-primary)' }}>{count}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
