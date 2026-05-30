'use client';
import { useState, useEffect, useCallback } from 'react';
import { Building2, Plus, RefreshCw, X } from 'lucide-react';
import DataTable from '@/components/shared/DataTable';
import { getFromEngine, postToEngine } from '@/lib/api';
import { useTenant } from '@/lib/tenant-context';
import { TenantTypeSelector } from '@/components/onboarding/TenantTypeSelector';

// ── Create Tenant Modal ───────────────────────────────────────────────────────

function CreateTenantModal({ onClose, onCreated }) {
  const { customerId } = useTenant();
  const [form, setForm] = useState({ tenant_name: '', tenant_description: '', tenant_type: 'cloud' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!form.tenant_name.trim()) return;
    setSaving(true);
    setError(null);

    // AC3 — tenant_type included in POST body
    const res = await postToEngine('gateway', '/api/v1/tenants', {
      customer_id: customerId,
      tenant_name: form.tenant_name.trim(),
      tenant_description: form.tenant_description.trim() || undefined,
      tenant_type: form.tenant_type,
    });

    setSaving(false);
    if (res.error) {
      setError(res.error);
    } else {
      onCreated(res);
      onClose();
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="rounded-xl w-full max-w-md shadow-2xl flex flex-col max-h-[90vh]" style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
        <div className="flex items-center justify-between p-6 pb-5 flex-shrink-0">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Create Workspace</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/10">
            <X className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col flex-1 min-h-0">
        <div className="flex-1 overflow-y-auto px-6 space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Workspace Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={form.tenant_name}
              onChange={e => setForm(f => ({ ...f, tenant_name: e.target.value }))}
              placeholder="e.g. Production, Dev, APAC"
              className="w-full px-3 py-2 rounded-lg text-sm outline-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }}
              required
            />
          </div>

          {/* AC1, AC2 — TenantTypeSelector with 3 options + descriptions */}
          <TenantTypeSelector
            value={form.tenant_type}
            onChange={v => setForm(f => ({ ...f, tenant_type: v }))}
          />

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Description <span className="text-xs font-normal" style={{ color: 'var(--text-tertiary)' }}>(optional)</span>
            </label>
            <textarea
              rows={3}
              value={form.tenant_description}
              onChange={e => setForm(f => ({ ...f, tenant_description: e.target.value }))}
              placeholder="Describe the purpose of this workspace"
              className="w-full px-3 py-2 rounded-lg text-sm outline-none resize-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>

          {error && (
            <p className="text-sm text-red-400 bg-red-500/10 px-3 py-2 rounded-lg">{error}</p>
          )}
        </div>

        <div className="flex justify-end gap-3 px-6 py-4 border-t flex-shrink-0" style={{ borderColor: 'var(--border-primary)' }}>
            <button type="button" onClick={onClose} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !form.tenant_name.trim()}
              className="px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50"
              style={{ backgroundColor: 'var(--accent-primary)' }}
            >
              {saving ? 'Creating…' : 'Create Workspace'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ value }) {
  const active = value === 'active';
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${active ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
      {value}
    </span>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function TenantsPage() {
  const { customerId } = useTenant();
  const [tenants, setTenants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    if (!customerId) return;
    setLoading(true);
    setError(null);
    const res = await getFromEngine('gateway', '/api/v1/tenants', { customer_id: customerId });
    setLoading(false);
    if (res.error) {
      setError(res.error);
    } else {
      setTenants(res.tenants ?? []);
    }
  }, [customerId]);

  useEffect(() => { load(); }, [load]);

  const TYPE_BADGE = {
    cloud:         { bg: 'rgba(59,130,246,0.15)', color: '#60a5fa' },
    vulnerability: { bg: 'rgba(245,158,11,0.15)', color: '#fbbf24' },
    secops:        { bg: 'rgba(139,92,246,0.15)', color: '#a78bfa' },
  };

  const columns = [
    {
      accessorKey: 'tenant_name',
      header: 'Workspace Name',
      cell: i => <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{i.getValue()}</span>,
    },
    {
      accessorKey: 'tenant_type',
      header: 'Type',
      cell: i => {
        const t = i.getValue();
        if (!t) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
        const style = TYPE_BADGE[t] || { bg: 'rgba(100,116,139,0.15)', color: '#94a3b8' };
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold uppercase"
            style={{ backgroundColor: style.bg, color: style.color }}>
            {t}
          </span>
        );
      },
    },
    {
      accessorKey: 'tenant_id',
      header: 'Tenant ID',
      cell: i => <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>{i.getValue()}</span>,
    },
    {
      accessorKey: 'account_count',
      header: 'Accounts',
      cell: i => <span className="text-sm font-medium">{i.getValue() ?? 0}</span>,
    },
    {
      accessorKey: 'tenant_description',
      header: 'Description',
      cell: i => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{i.getValue() || '—'}</span>,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: i => <StatusBadge value={i.getValue()} />,
    },
    {
      accessorKey: 'created_at',
      header: 'Created',
      cell: i => {
        const v = i.getValue();
        return <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{v ? new Date(v).toLocaleDateString() : '—'}</span>;
      },
    },
  ];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Building2 className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
          <div>
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Tenant Management</h1>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>Workspaces that group your cloud accounts.</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={load}
            disabled={loading}
            className="p-2 rounded-lg hover:bg-white/5 disabled:opacity-50"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} style={{ color: 'var(--text-secondary)' }} />
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--accent-primary)' }}
          >
            <Plus className="w-4 h-4" /> New Workspace
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="px-4 py-3 rounded-lg text-sm text-red-400 bg-red-500/10 border border-red-500/20">
          {error}
        </div>
      )}

      {/* Table */}
      <DataTable
        data={tenants}
        columns={columns}
        pageSize={25}
        hideToolbar
        isLoading={loading}
        emptyMessage="No workspaces yet. Create one to start onboarding cloud accounts."
      />

      {/* Create modal */}
      {showCreate && (
        <CreateTenantModal
          onClose={() => setShowCreate(false)}
          onCreated={newTenant => setTenants(prev => [newTenant, ...prev])}
        />
      )}
    </div>
  );
}
