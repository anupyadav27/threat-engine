'use client';

import { useState, useEffect, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ChevronLeft, Package, AlertTriangle, Shield,
  FileText, Loader2, ExternalLink, Tag,
} from 'lucide-react';
import { fetchApi } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import FilterBar from '@/components/shared/FilterBar';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const SCA_API_KEY = 'sbom-api-key-2024';
const SCA_BASE = '/secops/api/v1/secops/sca/api/v1/sbom';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
    hour12: true,
  });
}

function getRiskLevel(vulnCount) {
  if (vulnCount >= 5) return 'high';
  if (vulnCount >= 2) return 'medium';
  if (vulnCount >= 1) return 'low';
  return 'none';
}

function getRiskColor(level) {
  if (level === 'high')   return { bg: 'bg-red-500/15',    text: 'text-red-400',    border: 'border-red-500/30' };
  if (level === 'medium') return { bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/30' };
  if (level === 'low')    return { bg: 'bg-yellow-500/15', text: 'text-yellow-400', border: 'border-yellow-500/30' };
  return { bg: 'bg-slate-500/15', text: 'text-slate-400', border: 'border-slate-500/30' };
}

// ---------------------------------------------------------------------------
// SeverityBar (inline)
// ---------------------------------------------------------------------------
function SeverityBar({ counts }) {
  const SEG = [
    { key: 'high',   label: 'High',   bg: 'bg-red-500',    text: 'text-red-400' },
    { key: 'medium', label: 'Medium', bg: 'bg-orange-500', text: 'text-orange-400' },
    { key: 'low',    label: 'Low',    bg: 'bg-yellow-500', text: 'text-yellow-400' },
  ];
  const total = SEG.reduce((a, s) => a + (counts[s.key] || 0), 0);
  if (total === 0) {
    return (
      <div className="text-sm text-center py-4" style={{ color: 'var(--text-tertiary)' }}>
        No vulnerable packages
      </div>
    );
  }
  return (
    <div>
      <div className="flex rounded-full overflow-hidden h-3 gap-px">
        {SEG.map(s => {
          const v = counts[s.key] || 0;
          if (!v) return null;
          return (
            <div key={s.key} className={`${s.bg} transition-all`}
              style={{ width: `${(v / total) * 100}%` }}
              title={`${s.label}: ${v}`} />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 mt-3">
        {SEG.map(s => {
          const v = counts[s.key] || 0;
          return (
            <div key={s.key} className="flex items-center gap-1.5">
              <span className={`inline-block w-2 h-2 rounded-full ${s.bg}`} />
              <span className={`text-xs font-semibold ${s.text}`}>{v}</span>
              <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{s.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Expandable row for a vulnerable package
// ---------------------------------------------------------------------------
function ExpandedPackageRow({ comp }) {
  const vulnIds = comp.vulnerability_ids || [];
  return (
    <div className="px-5 py-4 space-y-4 border-t" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
      <div className="grid grid-cols-2 gap-x-4 gap-y-3">
        {/* PURL */}
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
            Package URL (PURL)
          </div>
          <code className="text-xs font-mono break-all" style={{ color: 'var(--text-secondary)' }}>
            {comp.purl || '—'}
          </code>
        </div>

        {/* Recommendation */}
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
            Recommendation
          </div>
          <div className="text-xs p-2 rounded-lg border border-green-500/20 bg-green-500/5 text-green-300">
            Upgrade to latest stable version. Check the package changelog for security patches.
          </div>
        </div>
      </div>

      {/* CVE list */}
      {vulnIds.length > 0 && (
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>
            All CVEs ({vulnIds.length})
          </div>
          <div className="flex flex-wrap gap-2">
            {vulnIds.map(cve => (
              <a
                key={cve}
                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded-md border bg-red-500/10 text-red-400 border-red-500/30 hover:bg-red-500/20 transition-colors">
                {cve}
                <ExternalLink className="w-2.5 h-2.5" />
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
export default function ScaSbomDetailPage() {
  const params = useParams();
  const router = useRouter();
  const sbomId = params.sbomId;

  const [sbom,    setSbom]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [activeTab, setActiveTab] = useState('vulnerable');
  const [sortBy,  setSortBy]  = useState('risk');

  // ---------------------------------------------------------------------------
  // Fetch SBOM detail
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!sbomId) return;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchApi(`${SCA_BASE}/${sbomId}`, {
          headers: { 'X-API-Key': SCA_API_KEY },
        });
        if (data && !data.error) setSbom(data);
        else setError(data?.error || data?.detail || 'Failed to load SBOM');
      } catch (err) {
        setError(err?.message || 'Failed to load SBOM data');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [sbomId]);

  // ---------------------------------------------------------------------------
  // Derived data
  // ---------------------------------------------------------------------------
  const vulnComponents = useMemo(() => {
    if (!sbom) return [];
    return (sbom.vulnerable_components || []).map(comp => {
      const count = (comp.vulnerability_ids || []).length;
      const risk  = getRiskLevel(count);
      return { ...comp, _vulnCount: count, _risk: risk };
    });
  }, [sbom]);

  // Severity counts from vulnerability counts (proxy)
  const severityCounts = useMemo(() => {
    const counts = { high: 0, medium: 0, low: 0 };
    vulnComponents.forEach(c => {
      if (c._risk === 'high')   counts.high++;
      else if (c._risk === 'medium') counts.medium++;
      else if (c._risk === 'low')    counts.low++;
    });
    return counts;
  }, [vulnComponents]);

  const totalCves = useMemo(() => {
    return vulnComponents.reduce((a, c) => a + c._vulnCount, 0);
  }, [vulnComponents]);

  // License analysis
  const licenseSummary = useMemo(() => {
    if (!sbom?.components) return { types: {}, top: [] };
    const types = {};
    (sbom.components || []).forEach(c => {
      const lic = c.license || c.licenses?.[0] || 'Unknown';
      types[lic] = (types[lic] || 0) + 1;
    });
    const top = Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 10);
    return { types, top };
  }, [sbom]);

  const licenseTypeCount = Object.keys(licenseSummary.types).length;

  // Sorted vulnerable components
  const sortedComponents = useMemo(() => {
    const arr = [...vulnComponents];
    if (sortBy === 'risk') {
      const riskOrder = { high: 0, medium: 1, low: 2, none: 3 };
      arr.sort((a, b) => (riskOrder[a._risk] ?? 9) - (riskOrder[b._risk] ?? 9) || b._vulnCount - a._vulnCount);
    } else if (sortBy === 'name') {
      arr.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    }
    return arr;
  }, [vulnComponents, sortBy]);

  // ---------------------------------------------------------------------------
  // Column definitions — Vulnerable Packages
  // ---------------------------------------------------------------------------
  const vulnColumns = useMemo(() => [
    {
      id: 'package',
      header: 'Package',
      cell: info => {
        const row = info.row.original;
        return (
          <div className="min-w-0">
            <div className="text-sm font-semibold truncate max-w-[180px]" title={row.name || '—'} style={{ color: 'var(--text-primary)' }}>{row.name || '—'}</div>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-md mt-0.5 inline-block"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
              {row.version || 'unknown'}
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: 'purl',
      header: 'PURL',
      cell: info => {
        const v = info.getValue() || '—';
        return (
          <span className="text-xs font-mono truncate block max-w-[220px]" title={v} style={{ color: 'var(--text-secondary)' }}>
            {v}
          </span>
        );
      },
    },
    {
      id: 'cve_count',
      header: 'CVE Count',
      size: 100,
      cell: info => {
        const n = info.row.original._vulnCount;
        const cls = n >= 5 ? 'text-red-400' : n >= 2 ? 'text-orange-400' : 'text-yellow-400';
        return <span className={`text-sm font-bold ${cls}`}>{n}</span>;
      },
    },
    {
      id: 'risk',
      header: 'Risk Level',
      size: 100,
      cell: info => {
        const level = info.row.original._risk;
        const c = getRiskColor(level);
        return (
          <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border capitalize ${c.bg} ${c.text} ${c.border}`}>
            {level}
          </span>
        );
      },
    },
    {
      id: 'cve_ids',
      header: 'CVE IDs',
      cell: info => {
        const ids = info.row.original.vulnerability_ids || [];
        if (ids.length === 0) return <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
        const shown = ids.slice(0, 2);
        const remaining = ids.length - shown.length;
        return (
          <div className="flex flex-wrap items-center gap-1">
            {shown.map(id => (
              <span key={id} className="text-[10px] font-mono px-1.5 py-0.5 rounded border bg-red-500/10 text-red-400 border-red-500/20">
                {id}
              </span>
            ))}
            {remaining > 0 && (
              <span className="text-[10px] font-medium" style={{ color: 'var(--text-tertiary)' }}>
                +{remaining} more
              </span>
            )}
          </div>
        );
      },
    },
  ], []);

  // License table columns
  const licenseColumns = useMemo(() => [
    {
      id: 'license',
      header: 'License',
      cell: info => {
        const v = info.row.original[0];
        return (
          <span className="text-sm font-semibold truncate block max-w-[200px]" title={v} style={{ color: 'var(--text-primary)' }}>
            {v}
          </span>
        );
      },
    },
    {
      id: 'count',
      header: 'Packages',
      size: 100,
      cell: info => (
        <span className="text-sm font-semibold text-blue-400">{info.row.original[1]}</span>
      ),
    },
    {
      id: 'pct',
      header: '% of Total',
      size: 120,
      cell: info => {
        const total = sbom?.component_count || 1;
        const pct = ((info.row.original[1] / total) * 100).toFixed(1);
        return (
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <div className="h-full bg-blue-500 rounded-full" style={{ width: `${pct}%` }} />
            </div>
            <span className="text-xs w-12 text-right" style={{ color: 'var(--text-secondary)' }}>{pct}%</span>
          </div>
        );
      },
    },
  ], [sbom]);

  // Filter bar config
  const sortOptions = [
    { key: 'sortBy', label: 'Sort By', options: ['risk', 'name'] },
  ];

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]" style={{ color: 'var(--text-tertiary)' }}>
        <div className="flex items-center gap-2">
          <Loader2 className="w-5 h-5 animate-spin" />
          Loading SBOM data...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-6 py-8 space-y-4">
        <button onClick={() => router.push('/secops')}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Code Security
        </button>
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-red-400">Failed to load SBOM</div>
            <div className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{error}</div>
          </div>
        </div>
      </div>
    );
  }

  const appName    = sbom?.application_name || sbomId;
  const sbomFormat = sbom?.sbom_format || 'SPDX';
  const compCount  = sbom?.component_count ?? 0;

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="px-6 pt-6 pb-0">

        {/* Back button */}
        <button onClick={() => router.push('/secops')}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity mb-4"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Code Security
        </button>

        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>{appName}</h1>
              <span className="text-xs px-2.5 py-1 rounded-full border bg-green-500/10 text-green-400 border-green-500/30 font-semibold">
                {sbomFormat}
              </span>
              <span className="text-xs px-2.5 py-1 rounded-full border font-semibold"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
                {compCount} components
              </span>
            </div>
            {sbom?.created_at && (
              <div className="text-xs mt-2" style={{ color: 'var(--text-tertiary)' }}>
                Generated {fmtDate(sbom.created_at)}
              </div>
            )}
          </div>
        </div>

        {/* KPI cards */}
        <div className="grid grid-cols-4 gap-x-4 gap-y-4 mb-6">
          <KpiCard
            title="Total Components"
            value={compCount}
            subtitle={`${sbomFormat} format`}
            icon={<Package className="w-5 h-5" />}
            color="blue"
          />
          <KpiCard
            title="Vulnerable Packages"
            value={vulnComponents.length}
            subtitle={`${((vulnComponents.length / Math.max(compCount, 1)) * 100).toFixed(1)}% of total`}
            icon={<AlertTriangle className="w-5 h-5" />}
            color={vulnComponents.length > 0 ? 'red' : 'green'}
          />
          <KpiCard
            title="Total CVEs"
            value={totalCves}
            subtitle={`Across ${vulnComponents.length} packages`}
            icon={<Shield className="w-5 h-5" />}
            color={totalCves > 0 ? 'orange' : 'green'}
          />
          <KpiCard
            title="License Types"
            value={licenseTypeCount || '—'}
            subtitle="Unique licenses detected"
            icon={<Tag className="w-5 h-5" />}
            color="purple"
          />
        </div>

        {/* Severity distribution bar */}
        <div className="rounded-2xl border overflow-hidden mb-6"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
            <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Risk Distribution</div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Vulnerable packages by risk level (proxy based on CVE count)
            </div>
          </div>
          <div className="px-5 py-4">
            <SeverityBar counts={severityCounts} />
          </div>
        </div>

        {/* Tab strip */}
        <div className="flex items-center gap-1 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          {[
            { id: 'vulnerable', label: `Vulnerable Packages (${vulnComponents.length})` },
            { id: 'licenses',   label: 'License Analysis' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === tab.id ? 'border-blue-500 text-blue-400' : 'border-transparent hover:opacity-75'
              }`}
              style={activeTab !== tab.id ? { color: 'var(--text-secondary)' } : {}}>
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="px-6 pt-5 pb-8 space-y-4">

        {/* Vulnerable Packages tab */}
        {activeTab === 'vulnerable' && (
          <>
            <FilterBar
              filters={sortOptions}
              activeFilters={{ sortBy }}
              onFilterChange={(key, val) => { if (key === 'sortBy') setSortBy(val); }}
            />
            <DataTable
              data={sortedComponents}
              columns={vulnColumns}
              pageSize={20}
              emptyMessage="No vulnerable packages detected. All dependencies appear secure."
              renderExpandedRow={(row) => <ExpandedPackageRow comp={row} />}
            />
          </>
        )}

        {/* License Analysis tab */}
        {activeTab === 'licenses' && (
          <div className="space-y-5">
            {/* Summary cards row */}
            {licenseSummary.top.length > 0 && (
              <div className="grid grid-cols-4 gap-x-4 gap-y-3">
                {licenseSummary.top.slice(0, 4).map(([lic, count]) => (
                  <div key={lic} className="rounded-xl border p-4"
                    style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                    <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
                      {lic}
                    </div>
                    <div className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>{count}</div>
                    <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                      {((count / Math.max(compCount, 1)) * 100).toFixed(1)}% of packages
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* License table */}
            {licenseSummary.top.length > 0 ? (
              <DataTable
                data={licenseSummary.top}
                columns={licenseColumns}
                pageSize={20}
                emptyMessage="No license data available."
              />
            ) : (
              <div className="rounded-2xl border p-8 text-center"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <FileText className="w-10 h-10 mx-auto mb-3" style={{ color: 'var(--text-tertiary)' }} />
                <div className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
                  No license information available in this SBOM
                </div>
                <div className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
                  License data depends on the SBOM generator and package registry metadata
                </div>
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  );
}
