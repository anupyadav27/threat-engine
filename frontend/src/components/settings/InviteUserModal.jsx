'use client';

import { useState, useEffect } from 'react';
import { X, Mail, Send } from 'lucide-react';

const ROLE_OPTIONS = [
  { value: 'viewer',       label: 'Viewer',       desc: 'Read-only access' },
  { value: 'analyst',      label: 'Analyst',      desc: 'Read + export findings' },
  { value: 'tenant_admin', label: 'Tenant Admin', desc: 'Full tenant management' },
];

export default function InviteUserModal({ onClose, onInvited }) {
  const [tenants, setTenants] = useState([]);
  const [form, setForm] = useState({ email: '', tenant_id: '', role: 'viewer' });
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    fetch('/gateway/api/v1/tenants/', { credentials: 'include' })
      .then(r => r.ok ? r.json() : [])
      .then(d => setTenants(d.results || d || []))
      .catch(() => {});
  }, []);

  const setField = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.email) return;
    setSending(true);
    setError('');
    try {
      const resp = await fetch('/gateway/api/v1/invites/', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      if (!resp.ok) {
        const d = await resp.json().catch(() => ({}));
        throw new Error(d.detail || `Error ${resp.status}`);
      }
      setSuccess(true);
      if (onInvited) onInvited(form.email);
      setTimeout(onClose, 1500);
    } catch (e) {
      setError(e.message);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}>
      <div className="w-full max-w-md rounded-2xl border shadow-2xl" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <Mail size={15} style={{ color: 'var(--accent-primary)' }} />
            <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Invite Team Member</span>
          </div>
          <button onClick={onClose} className="hover:opacity-60" style={{ color: 'var(--text-muted)' }}><X size={15} /></button>
        </div>

        {success ? (
          <div className="p-8 text-center space-y-2">
            <div className="text-3xl">✉️</div>
            <div className="text-sm font-semibold" style={{ color: '#22c55e' }}>Invite sent to {form.email}</div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="p-5 space-y-4">
            {/* Email */}
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Email address <span className="text-red-400">*</span>
              </label>
              <input
                type="email"
                value={form.email}
                onChange={e => setField('email', e.target.value)}
                placeholder="user@example.com"
                required
                className="w-full px-3 py-2 text-sm rounded-lg border outline-none"
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              />
            </div>

            {/* Tenant */}
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Tenant <span className="text-xs" style={{ color: 'var(--text-muted)' }}>(optional)</span>
              </label>
              <select
                value={form.tenant_id}
                onChange={e => setField('tenant_id', e.target.value)}
                className="w-full px-3 py-2 text-sm rounded-lg border outline-none appearance-none"
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              >
                <option value="">No specific tenant</option>
                {tenants.map(t => (
                  <option key={t.id || t.tenant_id} value={t.id || t.tenant_id}>{t.name || t.tenant_name}</option>
                ))}
              </select>
            </div>

            {/* Role */}
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>Role</label>
              <div className="space-y-1.5">
                {ROLE_OPTIONS.map(opt => (
                  <label key={opt.value} className="flex items-start gap-2 p-2.5 rounded-lg border cursor-pointer transition-colors"
                    style={{
                      borderColor: form.role === opt.value ? 'rgba(59,130,246,0.4)' : 'var(--border-primary)',
                      backgroundColor: form.role === opt.value ? 'rgba(59,130,246,0.08)' : 'var(--bg-tertiary)',
                    }}>
                    <input
                      type="radio"
                      name="role"
                      value={opt.value}
                      checked={form.role === opt.value}
                      onChange={() => setField('role', opt.value)}
                      className="mt-0.5"
                    />
                    <div>
                      <div className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{opt.label}</div>
                      <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>{opt.desc}</div>
                    </div>
                  </label>
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
              <button type="submit" disabled={sending || !form.email}
                className="flex-1 flex items-center justify-center gap-1.5 py-2 text-sm font-medium rounded-lg disabled:opacity-40 hover:opacity-90"
                style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}>
                <Send size={13} />
                {sending ? 'Sending…' : 'Send Invite'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
