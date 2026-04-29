'use client';

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Shield, ChevronRight, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import DataTable from '@/components/shared/DataTable';
import GaugeChart from '@/components/charts/GaugeChart';

const FRAMEWORK_NAMES = {
  'cis': 'CIS AWS Foundations Benchmark v1.4',
  'nist': 'NIST CSF v1.1',
  'pci-dss': 'PCI DSS v3.2.1',
  'soc2': 'SOC 2 Type II',
  'iso27001': 'ISO 27001:2013',
  'hipaa': 'HIPAA Security Rule',
  'gdpr': 'GDPR Technical Controls',
};

export default function FrameworkDetailPage() {
  const router = useRouter();
  const params = useParams();
  const frameworkId = params?.framework;
  const [loading, setLoading] = useState(true);
  const [framework, setFramework] = useState(null);
  const [error, setError] = useState(null);
  const [activeCategory, setActiveCategory] = useState('All');

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await getFromEngine('compliance', `/api/v1/compliance/report/${frameworkId}`);
        if (res && !res.error && res.controls) {
          setFramework(res);
        } else {
          setError(res?.error || 'Framework not found');
        }
      } catch (err) {
        setError(err?.message || 'Failed to load framework data');
      } finally {
        setLoading(false);
      }
    };
    if (frameworkId) fetchData();
  }, [frameworkId]);

  const categories = framework ? ['All', ...new Set((framework.controls || []).map((c) => c.category))] : ['All'];
  const filteredControls = framework
    ? (activeCategory === 'All' ? framework.controls : (framework.controls || []).filter((c) => c.category === activeCategory))
    : [];

  const columns = [
    {
      accessorKey: 'control_id',
      header: 'Control ID',
      cell: (info) => <code className="text-xs font-mono" style={{ color: 'var(--accent-primary)' }}>{info.getValue()}</code>,
    },
    {
      accessorKey: 'title',
      header: 'Control',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'category',
      header: 'Category',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
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
        const val = info.getValue();
        return (
          <div className="flex items-center gap-1">
            {val === 'pass'
              ? <CheckCircle className="w-4 h-4" style={{ color: 'var(--accent-success)' }} />
              : <XCircle className="w-4 h-4" style={{ color: 'var(--accent-danger)' }} />}
            <span className="text-xs font-medium capitalize" style={{ color: val === 'pass' ? 'var(--accent-success)' : 'var(--accent-danger)' }}>
              {val}
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: 'findings',
      header: 'Findings',
      cell: (info) => (
        <span className="text-sm font-bold" style={{ color: info.getValue() > 0 ? 'var(--accent-warning)' : 'var(--text-muted)' }}>
          {info.getValue() > 0 ? info.getValue() : '—'}
        </span>
      ),
    },
  ];

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-24 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        <div className="h-48 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        <div className="h-96 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
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

  if (!framework) return <div className="p-6" style={{ color: 'var(--text-secondary)' }}>No data available.</div>;

  const passRate = framework.total_controls > 0 ? Math.round((framework.passed / framework.total_controls) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2">
        <button onClick={() => router.push('/compliance')} className="text-sm" style={{ color: 'var(--text-muted)' }}>Compliance</button>
        <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>{framework.name}</h1>
      </div>

      {/* Header Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Compliance Score" value={`${framework.score ?? passRate}%`} subtitle="Overall score" icon={<Shield className="w-5 h-5" />} color="blue" />
        <KpiCard title="Controls Passed" value={framework.passed} subtitle="Compliant controls" icon={<CheckCircle className="w-5 h-5" />} color="green" />
        <KpiCard title="Controls Failed" value={framework.failed} subtitle="Non-compliant" icon={<XCircle className="w-5 h-5" />} color="red" />
        <KpiCard title="Total Controls" value={framework.total_controls} subtitle="In this framework" icon={<AlertTriangle className="w-5 h-5" />} color="blue" />
      </div>

      {/* Score Gauge */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="rounded-xl p-6 border flex flex-col items-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4 self-start" style={{ color: 'var(--text-primary)' }}>Compliance Score</h2>
          <GaugeChart value={framework.score ?? passRate} max={100} label="Score" />
          <div className="mt-4 w-full space-y-2">
            <div className="flex justify-between text-sm">
              <span style={{ color: 'var(--text-muted)' }}>Passed</span>
              <span style={{ color: 'var(--accent-success)' }}>{framework.passed} controls</span>
            </div>
            <div className="flex justify-between text-sm">
              <span style={{ color: 'var(--text-muted)' }}>Failed</span>
              <span style={{ color: 'var(--accent-danger)' }}>{framework.failed} controls</span>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Controls by Category</h2>
          <div className="grid grid-cols-2 gap-3">
            {categories.filter((c) => c !== 'All').map((cat) => {
              const catControls = (framework.controls || []).filter((c) => c.category === cat);
              const catPassed = catControls.filter((c) => c.status === 'pass').length;
              const catTotal = catControls.length;
              const catPct = catTotal > 0 ? Math.round((catPassed / catTotal) * 100) : 0;
              return (
                <div key={cat} className="rounded-lg p-3 border" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{cat}</span>
                    <span className="text-xs font-bold" style={{ color: catPct === 100 ? 'var(--accent-success)' : catPct >= 50 ? 'var(--accent-warning)' : 'var(--accent-danger)' }}>
                      {catPct}%
                    </span>
                  </div>
                  <div className="h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${catPct}%`,
                        backgroundColor: catPct === 100 ? 'var(--accent-success)' : catPct >= 50 ? 'var(--accent-warning)' : 'var(--accent-danger)',
                      }}
                    />
                  </div>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{catPassed}/{catTotal} passed</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Controls Table */}
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Controls Detail</h2>
          <div className="flex gap-2 flex-wrap">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className="text-xs px-3 py-1 rounded-full border"
                style={{
                  backgroundColor: activeCategory === cat ? 'var(--accent-primary)' : 'transparent',
                  color: activeCategory === cat ? 'white' : 'var(--text-secondary)',
                  borderColor: activeCategory === cat ? 'var(--accent-primary)' : 'var(--border-primary)',
                }}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
        <DataTable columns={columns} data={filteredControls} />
      </div>
    </div>
  );
}
