'use client';

import { useState, useCallback } from 'react';
import {
  Building2, Plus, RefreshCw, CheckCircle, XCircle, Clock,
  Copy, Check, ChevronDown, ChevronRight,
} from 'lucide-react';
import { getFromEngine, fetchFromCspm } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';

const STATUS_COLORS = {
  active:    'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
  trialing:  'bg-blue-500/15 text-blue-300 border border-blue-500/30',
  past_due:  'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
  suspended: 'bg-red-500/15 text-red-300 border border-red-500/30',
  free:      'bg-zinc-600/40 text-zinc-300 border border-zinc-500/30',
};

function StatusBadge({ status: s }) {
  const cls = STATUS_COLORS[s] || 'bg-zinc-700 text-zinc-300';
  return (
    <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase tracking-wide ${cls}`}>
      {s}
    </span>
  );
}

function TrialDays({ trialEndAt }) {
  if (!trialEndAt) return <span className="text-zinc-500 text-sm">—</span>;
  const days = Math.ceil((new Date(trialEndAt) - Date.now()) / 86400000);
  const color = days < 3 ? 'text-red-400' : days < 7 ? 'text-yellow-400' : 'text-zinc-300';
  return <span className={`text-sm font-mono ${color}`}>{days > 0 ? `${days}d` : 'expired'}</span>;
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={copy} className="ml-2 text-zinc-400 hover:text-zinc-200 transition-colors">
      {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
    </button>
  );
}

function OrgRow({ org }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <>
      <tr
        className="border-b border-zinc-800 hover:bg-zinc-800/40 cursor-pointer transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            {expanded ? <ChevronDown size={14} className="text-zinc-500" /> : <ChevronRight size={14} className="text-zinc-500" />}
            <span className="font-medium text-zinc-100">{org.org_name}</span>
          </div>
        </td>
        <td className="px-4 py-3 font-mono text-xs text-zinc-400">{org.org_id}</td>
        <td className="px-4 py-3"><StatusBadge status={org.status} /></td>
        <td className="px-4 py-3 text-sm text-zinc-300">{org.plan_name}</td>
        <td className="px-4 py-3 text-sm text-zinc-300 text-center">{org.accounts_connected ?? 0}</td>
        <td className="px-4 py-3 text-sm text-zinc-300 text-center">{org.users_count ?? 0}</td>
        <td className="px-4 py-3"><TrialDays trialEndAt={org.trial_end_at} /></td>
      </tr>
      {expanded && (
        <tr className="border-b border-zinc-800 bg-zinc-900/60">
          <td colSpan={7} className="px-8 py-3">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-zinc-500">Created:</span>{' '}
                <span className="text-zinc-300">{org.created_at ? new Date(org.created_at).toLocaleString() : '—'}</span>
              </div>
              <div>
                <span className="text-zinc-500">Trial ends:</span>{' '}
                <span className="text-zinc-300">{org.trial_end_at ? new Date(org.trial_end_at).toLocaleDateString() : '—'}</span>
              </div>
              {org.payment_failed_at && (
                <div className="text-red-400">
                  Payment failed: {new Date(org.payment_failed_at).toLocaleDateString()}
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function CreateOrgModal({ onClose, onCreated }) {
  const [orgName, setOrgName] = useState('');
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const submit = async () => {
    if (!orgName.trim() || !email.trim()) { setError('Both fields are required'); return; }
    setLoading(true);
    setError('');
    const res = await fetchFromCspm('/api/admin/provision-org/', {
      method: 'POST',
      body: JSON.stringify({ org_name: orgName.trim(), contact_email: email.trim().toLowerCase() }),
    });
    setLoading(false);
    if (res?.error) { setError(res.error); return; }
    setResult(res);
    onCreated();
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="rounded-xl border p-6 w-full max-w-md max-h-[90vh] overflow-y-auto"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        onClick={e => e.stopPropagation()}
      >
        {!result ? (
          <>
            <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Provision New Customer Org
            </h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>
                  Org Name
                </label>
                <input
                  className="w-full px-3 py-2 rounded-lg text-sm border outline-none"
                  style={{
                    backgroundColor: 'var(--bg-input)',
                    borderColor: error && !orgName ? 'rgb(239 68 68)' : 'var(--border-primary)',
                    color: 'var(--text-primary)',
                  }}
                  placeholder="Acme Corp"
                  value={orgName}
                  onChange={e => setOrgName(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>
                  Org Admin Email
                </label>
                <input
                  type="email"
                  className="w-full px-3 py-2 rounded-lg text-sm border outline-none"
                  style={{
                    backgroundColor: 'var(--bg-input)',
                    borderColor: error && !email ? 'rgb(239 68 68)' : 'var(--border-primary)',
                    color: 'var(--text-primary)',
                  }}
                  placeholder="admin@acmecorp.com"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && submit()}
                />
              </div>
              {error && <p className="text-red-400 text-sm">{error}</p>}
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={onClose}
                className="flex-1 px-4 py-2 rounded-lg text-sm border transition-colors"
                style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              >
                Cancel
              </button>
              <button
                onClick={submit}
                disabled={loading}
                className="flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
              >
                {loading ? 'Provisioning...' : 'Create Org'}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="flex items-center gap-2 mb-4">
              <CheckCircle size={20} className="text-emerald-400" />
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                Org Provisioned
              </h2>
            </div>
            <div className="space-y-3 text-sm">
              <div>
                <span style={{ color: 'var(--text-secondary)' }}>Org:</span>{' '}
                <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{result.org_name}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)' }}>Customer ID:</span>{' '}
                <span className="font-mono text-xs" style={{ color: 'var(--text-primary)' }}>{result.customer_id}</span>
                <CopyButton text={result.customer_id} />
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)' }}>Admin email:</span>{' '}
                <span style={{ color: 'var(--text-primary)' }}>{result.contact_email}</span>
              </div>
              <div className="rounded-lg p-3 border" style={{ backgroundColor: 'var(--bg-input)', borderColor: 'var(--border-secondary)' }}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-yellow-400">Invite Token (expires 72h)</span>
                  <CopyButton text={result.invite_token} />
                </div>
                <p className="font-mono text-xs break-all" style={{ color: 'var(--text-secondary)' }}>
                  {result.invite_token}
                </p>
                <p className="text-xs mt-2 text-zinc-500">
                  Share this token with the org admin. They use it at the accept-invite endpoint to activate their account.
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="w-full mt-6 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
              style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
            >
              Done
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export default function AdminOrgsPage() {
  const { isPlatformAdmin } = useAuth();
  const [orgs, setOrgs] = useState(null);
  const [summary, setSummary] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [statusFilter, setStatusFilter] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    const params = {};
    if (statusFilter) params.status = statusFilter;
    const res = await getFromEngine('platformAdmin', '/api/v1/padmin/orgs', params);
    setLoading(false);
    if (res?.error) { setError(res.error); return; }
    setOrgs(res.orgs || []);
    setSummary(res.summary || {});
  }, [statusFilter]);

  // Load on first render
  useState(() => { load(); }, []);

  if (!isPlatformAdmin) {
    return (
      <div className="flex items-center justify-center h-64">
        <p style={{ color: 'var(--text-tertiary)' }}>Platform admin access required.</p>
      </div>
    );
  }

  const statuses = ['active', 'trialing', 'past_due', 'suspended', 'free'];

  return (
    <div className="space-y-6">
      {showModal && (
        <CreateOrgModal
          onClose={() => setShowModal(false)}
          onCreated={() => { setShowModal(false); load(); }}
        />
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Customer Orgs
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Provision and manage customer organisations
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm border transition-colors disabled:opacity-50"
            style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
          >
            <Plus size={14} />
            New Org
          </button>
        </div>
      </div>

      {/* Summary KPIs */}
      <div className="grid grid-cols-5 gap-3">
        {statuses.map(s => (
          <button
            key={s}
            onClick={() => setStatusFilter(statusFilter === s ? '' : s)}
            className={`rounded-lg border p-3 text-left transition-colors ${statusFilter === s ? 'ring-1 ring-blue-500' : ''}`}
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <div className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
              {summary[s] ?? 0}
            </div>
            <div className="text-xs mt-1 capitalize" style={{ color: 'var(--text-tertiary)' }}>{s}</div>
          </button>
        ))}
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left" style={{ borderColor: 'var(--border-primary)' }}>
              {['Org Name', 'Customer ID', 'Status', 'Plan', 'Accounts', 'Users', 'Trial'].map(h => (
                <th key={h} className="px-4 py-3 font-medium text-xs uppercase tracking-wide"
                  style={{ color: 'var(--text-tertiary)' }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && !orgs && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-sm" style={{ color: 'var(--text-tertiary)' }}>Loading...</td></tr>
            )}
            {!loading && orgs?.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center">
                  <Building2 size={32} className="mx-auto mb-2 text-zinc-600" />
                  <p style={{ color: 'var(--text-tertiary)' }}>No orgs yet. Click <strong>New Org</strong> to provision the first customer.</p>
                </td>
              </tr>
            )}
            {orgs?.map(org => <OrgRow key={org.org_id} org={org} />)}
          </tbody>
        </table>
      </div>

      {orgs && (
        <p className="text-xs text-right" style={{ color: 'var(--text-tertiary)' }}>
          {orgs.length} org{orgs.length !== 1 ? 's' : ''} {statusFilter ? `(filtered: ${statusFilter})` : ''}
        </p>
      )}
    </div>
  );
}
