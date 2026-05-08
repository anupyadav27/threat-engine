'use client';

import { useState, useEffect, useCallback } from 'react';
import { Shield, Plus, Trash2 } from 'lucide-react';
import GroupAccessModal from '@/components/settings/GroupAccessModal';

const ROLE_STYLES = {
  tenant_admin: { bg: 'rgba(59,130,246,0.15)',  color: '#60a5fa' },
  analyst:      { bg: 'rgba(139,92,246,0.15)',  color: '#a78bfa' },
  viewer:       { bg: 'rgba(100,116,139,0.15)', color: '#94a3b8' },
};

function RoleBadge({ role }) {
  const s = ROLE_STYLES[role] || ROLE_STYLES.viewer;
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded font-semibold uppercase"
      style={{ backgroundColor: s.bg, color: s.color }}>
      {role?.replace('_', ' ')}
    </span>
  );
}

function TenantAccessCard({ tenant, onRefresh }) {
  const [accesses, setAccesses] = useState([]);
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    const tid = tenant.id || tenant.tenant_id;
    fetch(`/gateway/api/v1/tenants/${tid}/group-access/`, { credentials: 'include' })
      .then(r => r.ok ? r.json() : [])
      .then(d => setAccesses(d.results || d || []))
      .catch(() => {});
  }, [tenant]);

  const handleRemove = async (accessId) => {
    const tid = tenant.id || tenant.tenant_id;
    try {
      await fetch(`/gateway/api/v1/tenants/${tid}/group-access/${accessId}/`, {
        method: 'DELETE', credentials: 'include',
      });
      setAccesses(a => a.filter(x => x.id !== accessId));
    } catch (_) {}
  };

  return (
    <div className="rounded-xl border p-4 space-y-3"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            {tenant.name || tenant.tenant_name}
          </div>
          <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
            {accesses.length} group{accesses.length !== 1 ? 's' : ''} with access
          </div>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-1 px-2 py-1 text-xs rounded-lg border hover:opacity-80"
          style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
        >
          <Plus size={11} /> Assign Group
        </button>
      </div>

      {accesses.length > 0 && (
        <div className="space-y-1.5">
          {accesses.map(a => (
            <div key={a.id} className="flex items-center justify-between px-3 py-2 rounded-lg"
              style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
                  {a.group_name || a.group}
                </span>
                <RoleBadge role={a.role_name || a.role} />
              </div>
              <button onClick={() => handleRemove(a.id)} className="hover:opacity-60" style={{ color: 'var(--text-muted)' }}>
                <Trash2 size={11} />
              </button>
            </div>
          ))}
        </div>
      )}

      {showModal && (
        <GroupAccessModal
          tenant={tenant}
          onClose={() => setShowModal(false)}
          onSaved={() => { setShowModal(false); onRefresh?.(); }}
        />
      )}
    </div>
  );
}

export default function AccessPage() {
  const [tenants, setTenants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  const fetchTenants = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await fetch('/gateway/api/v1/tenants/', { credentials: 'include' });
      if (!resp.ok) throw new Error(`Error ${resp.status}`);
      const data = await resp.json();
      setTenants(data.results || data || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchTenants(); }, [fetchTenants, refreshKey]);

  return (
    <div className="p-6 space-y-5 max-w-4xl">
      <div>
        <h1 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>Access Control</h1>
        <div className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Assign groups to tenants with specific roles
        </div>
      </div>

      {error && (
        <div className="text-sm p-3 rounded-xl border" style={{ borderColor: 'rgba(239,68,68,0.3)', backgroundColor: 'rgba(239,68,68,0.08)', color: '#f87171' }}>
          {error}
        </div>
      )}

      {loading ? (
        <div className="space-y-3">
          {[1,2].map(i => <div key={i} className="h-28 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />)}
        </div>
      ) : tenants.length === 0 ? (
        <div className="text-center py-16" style={{ color: 'var(--text-muted)' }}>
          <Shield size={40} className="mx-auto mb-3" />
          <div className="text-sm">No tenants found</div>
        </div>
      ) : (
        <div className="space-y-3">
          {tenants.map(t => (
            <TenantAccessCard key={t.id || t.tenant_id} tenant={t} onRefresh={() => setRefreshKey(k => k + 1)} />
          ))}
        </div>
      )}
    </div>
  );
}
