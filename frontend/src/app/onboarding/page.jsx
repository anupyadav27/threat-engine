'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Plus, Cloud, Globe, HardDrive, CheckCircle, AlertTriangle, Play, Loader2 } from 'lucide-react';
import { getFromEngine, postToEngine } from '@/lib/api';
import { useTenant } from '@/lib/tenant-context';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import ScanRunDetailModal from '@/components/domain/ScanRunDetailModal';


export default function OnboardingPage() {
  const { customerId, activeTenant } = useTenant();
  const [loading, setLoading] = useState(true);
  const [accounts, setAccounts] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [expandedGroup, setExpandedGroup] = useState(null);
  const [runningFor, setRunningFor] = useState({});    // accountId → true while triggering
  const [selectedRunId, setSelectedRunId] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const tenantId = activeTenant?.tenant_id;
        const qp = tenantId ? `?tenant_id=${tenantId}` : '';
        const [accountsData, schedsData] = await Promise.all([
          getFromEngine('onboarding', `/api/v1/cloud-accounts${qp}`),
          getFromEngine('onboarding', `/api/v1/schedules${qp}&limit=200`),
        ]);
        const raw = accountsData?.accounts || (Array.isArray(accountsData) ? accountsData : []);
        const normalized = raw.map(a => ({
          id: a.account_id,
          name: a.account_name || a.account_id,
          accountId: a.account_id,
          provider: (a.provider || 'AWS').toUpperCase(),
          type: a.scan_type || 'Standard',
          regions: a.regions_count || 1,
          resources: a.total_resources || 0,
          findings: a.total_findings || 0,
          lastScan: a.last_scan_at,
          credStatus: a.credential_validation_status === 'valid' ? 'Valid'
            : a.credential_validation_status === 'expired' ? 'Expired' : 'Expiring Soon',
          health: a.credential_validation_status === 'valid' ? 'Healthy' : 'Warning',
        }));
        setAccounts(normalized);
        setSchedules(schedsData?.schedules || []);
      } catch (error) {
        console.warn('Error fetching accounts:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [activeTenant]);

  async function handleRunNow(accountId) {
    const sched = schedules.find(s => s.account_id === accountId);
    if (!sched) { alert('No schedule found for this account. Add a schedule first.'); return; }
    setRunningFor(p => ({ ...p, [accountId]: true }));
    try {
      const result = await postToEngine('onboarding', `/api/v1/schedules/${sched.schedule_id}/run-now`, {});
      if (result.scan_run_id) setSelectedRunId(result.scan_run_id);
    } catch (e) {
      console.error('run-now failed:', e);
    } finally {
      setRunningFor(p => ({ ...p, [accountId]: false }));
    }
  }

  const accountColumns = [
    {
      accessorKey: 'name',
      header: 'Account Name',
      cell: (info) => (
        <Link
          href={`/onboarding/accounts/${info.row.original.id}`}
          style={{ color: 'var(--accent-primary)' }}
          className="font-medium hover:underline"
        >
          {info.getValue()}
        </Link>
      ),
    },
    {
      accessorKey: 'accountId',
      header: 'Account ID',
      cell: (info) => <code style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }} className="px-2 py-1 rounded text-xs">{info.getValue()}</code>,
    },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: (info) => {
        const provider = info.getValue();
        const providerColors = { AWS: '#FF9900', Azure: '#0078D4', GCP: '#4285F4', OCI: '#F80000' };
        const color = providerColors[provider] || '#666';
        return <span style={{ backgroundColor: color + '20', color }} className="px-2 py-1 rounded text-xs font-semibold">{provider}</span>;
      },
    },
    {
      accessorKey: 'type',
      header: 'Type',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }} className="text-sm">{info.getValue()}</span>,
    },
    {
      accessorKey: 'regions',
      header: 'Regions',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'resources',
      header: 'Resources',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }} className="font-medium">{info.getValue()}</span>,
    },
    {
      accessorKey: 'findings',
      header: 'Findings',
      cell: (info) => {
        const findings = info.getValue();
        const color = findings > 10 ? '#ef4444' : findings > 5 ? '#f97316' : '#10b981';
        return <span style={{ color }} className="font-semibold">{findings}</span>;
      },
    },
    {
      accessorKey: 'lastScan',
      header: 'Last Scan',
      cell: (info) => {
        const v = info.getValue();
        if (!v) return <span style={{ color: 'var(--text-muted)' }} className="text-xs">Never</span>;
        const diff = Date.now() - new Date(v);
        const m = Math.floor(diff / 60000);
        const label = m < 60 ? `${m}m ago` : m < 1440 ? `${Math.floor(m/60)}h ago` : new Date(v).toLocaleDateString();
        return <span style={{ color: 'var(--text-tertiary)' }} className="text-xs">{label}</span>;
      },
    },
    {
      accessorKey: 'credStatus',
      header: 'Credential Status',
      cell: (info) => {
        const status = info.getValue();
        const colors = { Valid: '#10b981', 'Expiring Soon': '#f97316', Expired: '#ef4444' };
        const color = colors[status] || '#666';
        return <span style={{ backgroundColor: color + '20', color }} className="px-2 py-1 rounded text-xs font-semibold">{status}</span>;
      },
    },
    {
      accessorKey: 'health',
      header: 'Health',
      cell: (info) => {
        const health = info.getValue();
        const icon = health === 'Healthy' ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />;
        const color = health === 'Healthy' ? '#10b981' : '#f97316';
        return <span style={{ color }} className="flex items-center gap-1 text-xs font-medium">{icon} {health}</span>;
      },
    },
    {
      id: 'actions',
      header: '',
      cell: (info) => {
        const accountId = info.row.original.id;
        const busy = runningFor[accountId];
        return (
          <button
            onClick={e => { e.stopPropagation(); handleRunNow(accountId); }}
            disabled={busy}
            title="Run scan now"
            className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium hover:opacity-80 disabled:opacity-40"
            style={{ backgroundColor: 'rgba(59,130,246,0.1)', color: 'var(--accent-primary)', border: '1px solid rgba(59,130,246,0.25)' }}>
            {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
            {busy ? 'Launching…' : 'Run'}
          </button>
        );
      },
    },
  ];


  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>Cloud Account Management</h1>
          <p style={{ color: 'var(--text-tertiary)' }} className="mt-1">Manage onboarded cloud accounts and multi-cloud security posture</p>
        </div>
        <Link
          href="/onboarding/wizard"
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium transition-colors"
          style={{ backgroundColor: 'var(--accent-primary)' }}
        >
          <Plus className="w-4 h-4" /> Add Account
        </Link>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <KpiCard title="Total Accounts" value={accounts.length} subtitle="All clouds" icon={<Cloud className="w-5 h-5" />} color="blue" />
        <KpiCard title="Active" value={accounts.filter(a => a.health === 'Healthy').length} subtitle="Healthy" icon={<CheckCircle className="w-5 h-5" />} color="green" />
        <KpiCard title="Issues" value={accounts.filter(a => a.health !== 'Healthy').length} subtitle="Needs attention" icon={<AlertTriangle className="w-5 h-5" />} color="orange" />
        <KpiCard title="Total Resources" value={accounts.reduce((sum, a) => sum + (a.resources || 0), 0)} subtitle="Across all accounts" icon={<HardDrive className="w-5 h-5" />} color="blue" />
      </div>

      {/* Cloud Accounts Table */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Cloud Accounts</h2>
        <DataTable data={accounts} columns={accountColumns} pageSize={10} loading={loading} emptyMessage="No accounts found" />
      </div>

      {/* Account Groups (by Provider) */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Account Groups</h2>
        <div className="space-y-2">
          {(() => {
            const grouped = accounts.reduce((acc, a) => {
              const p = a.provider || 'Unknown';
              if (!acc[p]) acc[p] = [];
              acc[p].push(a.name);
              return acc;
            }, {});
            return Object.entries(grouped).map(([providerName, acctNames]) => (
              <div key={providerName} className="rounded-lg border p-4 cursor-pointer hover:border-blue-500 transition-colors" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} onClick={() => setExpandedGroup(expandedGroup === providerName ? null : providerName)}>
                <div className="flex items-center justify-between">
                  <div>
                    <h3 style={{ color: 'var(--text-primary)' }} className="font-semibold">{providerName}</h3>
                    <p style={{ color: 'var(--text-tertiary)' }} className="text-sm mt-1">{acctNames.length} account{acctNames.length !== 1 ? 's' : ''}</p>
                  </div>
                  <Globe className="w-5 h-5" style={{ color: 'var(--text-secondary)' }} />
                </div>
                {expandedGroup === providerName && (
                  <div className="mt-3 pt-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
                    <ul className="space-y-1">
                      {acctNames.map((acc) => (
                        <li key={acc} style={{ color: 'var(--text-secondary)' }} className="text-sm flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-blue-500" /> {acc}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ));
          })()}
          {accounts.length === 0 && !loading && (
            <p className="text-sm py-4 text-center" style={{ color: 'var(--text-tertiary)' }}>No account groups available</p>
          )}
        </div>
      </div>

      {/* Integration Health Dashboard */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Integration Health</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {accounts.slice(0, 3).map((acc) => (
            <div key={acc.id} className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="flex items-center justify-between mb-3">
                <h3 style={{ color: 'var(--text-primary)' }} className="font-semibold">{acc.name}</h3>
                <span style={{ backgroundColor: (acc.health === 'Healthy' ? '#10b981' : acc.health === 'Warning' ? '#f97316' : '#ef4444') + '20', color: (acc.health === 'Healthy' ? '#10b981' : acc.health === 'Warning' ? '#f97316' : '#ef4444') }} className="px-2 py-1 rounded text-xs font-semibold">{acc.health}</span>
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span style={{ color: 'var(--text-tertiary)' }}>Last Sync</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{acc.lastScan ? new Date(acc.lastScan).toLocaleString() : 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span style={{ color: 'var(--text-tertiary)' }}>Credential Status</span>
                  <span style={{ color: acc.credStatus === 'Valid' ? '#10b981' : acc.credStatus === 'Expired' ? '#ef4444' : '#f97316' }} className="font-semibold">{acc.credStatus}</span>
                </div>
                <div className="flex justify-between">
                  <span style={{ color: 'var(--text-tertiary)' }}>Errors (24h)</span>
                  <span style={{ color: 'var(--text-secondary)' }}>0</span>
                </div>
                <div className="flex justify-between">
                  <span style={{ color: 'var(--text-tertiary)' }}>Webhook Status</span>
                  <span style={{ color: '#10b981' }} className="text-xs font-semibold">Active</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Scan run detail modal */}
      {selectedRunId && (
        <ScanRunDetailModal scanRunId={selectedRunId} onClose={() => setSelectedRunId(null)} />
      )}

      {/* Credential Management */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Credential Management</h2>
        <div className="rounded-lg border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderColor: 'var(--border-primary)', borderBottomWidth: '1px' }}>
                <th style={{ color: 'var(--text-secondary)', textAlign: 'left', paddingBottom: '12px', fontWeight: 600 }}>Account</th>
                <th style={{ color: 'var(--text-secondary)', textAlign: 'left', paddingBottom: '12px', fontWeight: 600 }}>Provider</th>
                <th style={{ color: 'var(--text-secondary)', textAlign: 'left', paddingBottom: '12px', fontWeight: 600 }}>Credential Status</th>
                <th style={{ color: 'var(--text-secondary)', textAlign: 'left', paddingBottom: '12px', fontWeight: 600 }}>Last Scan</th>
              </tr>
            </thead>
            <tbody>
              {accounts.length === 0 ? (
                <tr><td colSpan={4} className="py-6 text-center" style={{ color: 'var(--text-tertiary)' }}>No credential data available</td></tr>
              ) : accounts.map((acc, idx) => (
                <tr key={idx} style={{ borderColor: 'var(--border-primary)', borderBottomWidth: idx < accounts.length - 1 ? '1px' : '0' }}>
                  <td style={{ color: 'var(--text-secondary)', padding: '12px 0' }}>{acc.name}</td>
                  <td style={{ padding: '12px 0' }}>
                    <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>{acc.provider}</span>
                  </td>
                  <td style={{ padding: '12px 0' }}>
                    <span style={{ backgroundColor: (acc.credStatus === 'Valid' ? '#10b981' : acc.credStatus === 'Expired' ? '#ef4444' : '#f97316') + '20', color: (acc.credStatus === 'Valid' ? '#10b981' : acc.credStatus === 'Expired' ? '#ef4444' : '#f97316') }} className="px-2 py-1 rounded text-xs font-semibold">{acc.credStatus}</span>
                  </td>
                  <td style={{ color: 'var(--text-tertiary)', padding: '12px 0' }}>{acc.lastScan ? new Date(acc.lastScan).toLocaleDateString() : 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
