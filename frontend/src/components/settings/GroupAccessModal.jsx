'use client';

import { useState, useEffect } from 'react';
import { X, Shield } from 'lucide-react';

const ROLE_OPTIONS = [
  { value: 'viewer',       label: 'Viewer' },
  { value: 'analyst',      label: 'Analyst' },
  { value: 'tenant_admin', label: 'Tenant Admin' },
];

export default function GroupAccessModal({ tenant, onClose, onSaved }) {
  const [groups, setGroups]     = useState([]);
  const [form, setForm]         = useState({ group: '', role: 'viewer' });
  const [saving, setSaving]     = useState(false);
  const [error, setError]       = useState('');

  useEffect(() => {
    fetch('/gateway/api/v1/groups/', { credentials: 'include' })
      .then(r => r.ok ? r.json() : [])
      .then(d => setGroups(d.results || d || []))
      .catch(() => {});
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.group || !form.role) return;
    setSaving(true);
    setError('');
    try {
      const resp = await fetch(`/gateway/api/v1/tenants/${tenant.id || tenant.tenant_id}/group-access/`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group: form.group, role: form.role }),
      });
      if (!resp.ok) {
        const d = await resp.json().catch(() => ({}));
        throw new Error(d.detail || `Error ${resp.status}`);
      }
      if (onSaved) onSaved();
      onClose();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}>
      <div className="w-full max-w-sm rounded-2xl border shadow-2xl" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <Shield size={15} style={{ color: 'var(--accent-primary)' }} />
            <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Assign Group Access</span>
          </div>
          <button onClick={onClose} className="hover:opacity-60" style={{ color: 'var(--text-muted)' }}><X size={15} /></button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div className="text-xs p-2.5 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
            Granting access to tenant: <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>{tenant?.name || tenant?.tenant_name}</span>
          </div>

          {/* Group selector */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Group <span className="text-red-400">*</span>
            </label>
            <select
              value={form.group}
              onChange={e => setForm(f => ({ ...f, group: e.target.value }))}
              required
              className="w-full px-3 py-2 text-sm rounded-lg border outline-none appearance-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            >
              <option value="">Select a group…</option>
              {groups.map(g => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
          </div>

          {/* Role selector */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Role</label>
            <div className="flex gap-1.5">
              {ROLE_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setForm(f => ({ ...f, role: opt.value }))}
                  className="flex-1 py-1.5 text-xs rounded-lg border transition-colors"
                  style={{
                    borderColor: form.role === opt.value ? 'rgba(59,130,246,0.4)' : 'var(--border-primary)',
                    backgroundColor: form.role === opt.value ? 'rgba(59,130,246,0.12)' : 'var(--bg-tertiary)',
                    color: form.role === opt.value ? 'var(--accent-primary)' : 'var(--text-secondary)',
                  }}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {error && (
            <div className="text-xs p-2.5 rounded-lg border" style={{ borderColor: 'rgba(239,68,68,0.3)', backgroundColor: 'rgba(239,68,68,0.08)', color: '#f87171' }}>
              {error}
            </div>
          )}

          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose}
              className="flex-1 py-2 text-sm rounded-lg border hover:opacity-80"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
              Cancel
            </button>
            <button type="submit" disabled={saving || !form.group}
              className="flex-1 py-2 text-sm font-medium rounded-lg disabled:opacity-40 hover:opacity-90"
              style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}>
              {saving ? 'Assigning…' : 'Assign Access'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
