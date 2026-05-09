'use client';

import { useState, useCallback } from 'react';
import {
  DollarSign, ChevronDown, ChevronRight, Download, RefreshCw,
  Building2, Cloud, Filter,
} from 'lucide-react';
import { useViewFetch } from '@/lib/use-view-fetch';
import { useAuth } from '@/lib/auth-context';

const PROVIDER_COLORS = {
  aws:   'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  gcp:   'bg-blue-500/15 text-blue-300 border border-blue-500/30',
  azure: 'bg-sky-500/15 text-sky-300 border border-sky-500/30',
  k8s:   'bg-purple-500/15 text-purple-300 border border-purple-500/30',
  oci:   'bg-red-500/15 text-red-300 border border-red-500/30',
};

const STATUS_COLORS = {
  active:   'bg-emerald-500/15 text-emerald-300',
  trialing: 'bg-blue-500/15 text-blue-300',
  past_due: 'bg-yellow-500/15 text-yellow-300',
  suspended:'bg-red-500/15 text-red-300',
};

function ProviderBadge({ provider }) {
  const cls = PROVIDER_COLORS[provider] || 'bg-zinc-700 text-zinc-300';
  return (
    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase ${cls}`}>
      {provider}
    </span>
  );
}

function AmountCell({ amount }) {
  return (
    <span className="font-mono font-semibold text-emerald-400">
      ${amount.toLocaleString()}
    </span>
  );
}

function OrgRow({ org }) {
  const [expanded, setExpanded] = useState(false);
  const statusCls = STATUS_COLORS[org.status] || 'bg-zinc-700 text-zinc-400';

  return (
    <>
      <tr
        className="border-b border-zinc-800 hover:bg-zinc-800/40 cursor-pointer transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <td className="px-4 py-3 w-6 text-zinc-500">
          {expanded
            ? <ChevronDown size={14} />
            : <ChevronRight size={14} />
          }
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <Building2 size={14} className="text-zinc-500 flex-shrink-0" />
            <span className="font-mono text-xs text-zinc-200 truncate max-w-[200px]" title={org.org_id}>
              {org.org_id}
            </span>
          </div>
        </td>
        <td className="px-4 py-3">
          <span className={`text-xs px-2 py-0.5 rounded-full ${statusCls}`}>
            {org.status}
          </span>
        </td>
        <td className="px-4 py-3 text-xs text-zinc-300 capitalize">
          {org.plan_name}
        </td>
        <td className="px-4 py-3">
          <div className="flex flex-wrap gap-1">
            {[...new Set(org.accounts.map(a => a.provider))].map(p => (
              <ProviderBadge key={p} provider={p} />
            ))}
          </div>
        </td>
        <td className="px-4 py-3 text-right text-xs text-zinc-300 font-mono">
          {org.total_billable.toLocaleString()}
        </td>
        <td className="px-4 py-3 text-right">
          <AmountCell amount={org.monthly_amount_usd} />
        </td>
        <td className="px-4 py-3 text-right">
          <button
            onClick={e => {
              e.stopPropagation();
              navigator.clipboard.writeText(String(org.monthly_amount_usd));
            }}
            className="text-[10px] text-zinc-500 hover:text-zinc-200 px-2 py-1 rounded border border-zinc-700 hover:border-zinc-500 transition-colors"
            title="Copy amount for Stripe Invoice"
          >
            Copy $
          </button>
        </td>
      </tr>

      {expanded && org.accounts.map(acct => (
        <tr key={`${acct.account_id}-${acct.provider}`} className="bg-zinc-900/60 border-b border-zinc-800/50">
          <td />
          <td className="px-4 py-2 pl-10">
            <span className="font-mono text-[11px] text-zinc-400 truncate block max-w-[200px]" title={acct.account_id}>
              {acct.account_id}
            </span>
          </td>
          <td />
          <td />
          <td className="px-4 py-2">
            <ProviderBadge provider={acct.provider} />
          </td>
          <td className="px-4 py-2 text-right text-xs text-zinc-400 font-mono">
            {acct.avg_billable_30d.toLocaleString()}
          </td>
          <td />
          <td />
        </tr>
      ))}
    </>
  );
}

export default function AdminBillingPage() {
  const { user } = useAuth();
  const [providerFilter, setProviderFilter] = useState('');
  const [orgFilter, setOrgFilter] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  const params = {};
  if (providerFilter) params.provider = providerFilter;
  if (orgFilter) params.org_id = orgFilter;

  const { data, loading, error } = useViewFetch('admin-billing', params, [refreshKey]);

  const orgs = data?.orgs || [];
  const pricing = data?.pricing || {};
  const csvRows = data?.csv_rows || [];

  const totalBillable = orgs.reduce((s, o) => s + o.total_billable, 0);
  const totalRevenue = orgs.reduce((s, o) => s + o.monthly_amount_usd, 0);

  const downloadCsv = useCallback(() => {
    if (!csvRows.length) return;
    const headers = Object.keys(csvRows[0]).join(',');
    const rows = csvRows.map(r => Object.values(r).join(','));
    const csv = [headers, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `billing-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [csvRows]);

  if (user?.role_level > 1) {
    return (
      <div className="flex items-center justify-center h-64 text-zinc-500">
        Platform admin access required.
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <DollarSign size={20} className="text-emerald-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Billing Overview</h1>
          <span className="text-xs text-zinc-500 bg-zinc-800 px-2 py-0.5 rounded">30-day avg</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={downloadCsv}
            className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 px-3 py-1.5 rounded border border-zinc-700 hover:border-zinc-500 transition-colors"
          >
            <Download size={13} /> Export CSV
          </button>
          <button
            onClick={() => setRefreshKey(k => k + 1)}
            className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 px-3 py-1.5 rounded border border-zinc-700 hover:border-zinc-500 transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Orgs', value: orgs.length, suffix: '' },
          { label: 'Billable Resources', value: totalBillable.toLocaleString(), suffix: '' },
          { label: 'Monthly Revenue', value: `$${totalRevenue.toLocaleString()}`, suffix: '' },
          { label: 'Pricing', value: `$${pricing.flat_fee_usd || 1000} / ${pricing.flat_cap_resources || 50}`, suffix: `then $${pricing.per_resource_usd || 20}/resource` },
        ].map(({ label, value, suffix }) => (
          <div key={label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <div className="text-xs text-zinc-500 mb-1">{label}</div>
            <div className="text-xl font-semibold text-zinc-100">{value}</div>
            {suffix && <div className="text-[10px] text-zinc-600 mt-0.5">{suffix}</div>}
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Filter size={13} className="text-zinc-500" />
        <input
          type="text"
          placeholder="Filter by org ID..."
          value={orgFilter}
          onChange={e => setOrgFilter(e.target.value)}
          className="bg-zinc-900 border border-zinc-700 text-xs text-zinc-200 rounded px-3 py-1.5 w-56 focus:outline-none focus:border-zinc-500"
        />
        <select
          value={providerFilter}
          onChange={e => setProviderFilter(e.target.value)}
          className="bg-zinc-900 border border-zinc-700 text-xs text-zinc-200 rounded px-3 py-1.5 focus:outline-none focus:border-zinc-500"
        >
          <option value="">All providers</option>
          {['aws', 'gcp', 'azure', 'k8s', 'oci'].map(p => (
            <option key={p} value={p}>{p.toUpperCase()}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      {error && (
        <div className="text-red-400 text-xs bg-red-950/30 border border-red-800/30 rounded p-3">
          Failed to load billing data: {error}
        </div>
      )}

      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900/80">
              <th className="w-6" />
              <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400">Org</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400">Plan</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400">Providers</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-zinc-400">Billable (30d avg)</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-zinc-400">Monthly $</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-zinc-400"></th>
            </tr>
          </thead>
          <tbody>
            {loading && !orgs.length ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b border-zinc-800">
                  {Array.from({ length: 8 }).map((_, j) => (
                    <td key={j} className="px-4 py-3">
                      <div className="h-3 bg-zinc-800 rounded animate-pulse w-3/4" />
                    </td>
                  ))}
                </tr>
              ))
            ) : orgs.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-zinc-500 text-xs">
                  No billing data. Run a resource scan first.
                </td>
              </tr>
            ) : (
              orgs.map(org => <OrgRow key={org.org_id} org={org} />)
            )}
          </tbody>
        </table>
      </div>

      <div className="text-[10px] text-zinc-600 text-center">
        Counts are 30-day averages updated daily at 01:00 UTC. Use &ldquo;Copy $&rdquo; to copy the amount for a Stripe Invoice.
      </div>
    </div>
  );
}
