'use client';
import { useState, useEffect, useCallback } from 'react';
import { Users, Plus, X, Mail, ShieldCheck, Building2, ChevronDown } from 'lucide-react';
import DataTable from '@/components/shared/DataTable';
import { useAuth } from '@/lib/auth-context';
import { useTenant } from '@/lib/tenant-context';
import { fetchFromCspm, postToEngine, getFromEngine } from '@/lib/api';
import { useToast } from '@/lib/toast-context';
import OnboardingStepFlow from '@/components/onboarding/OnboardingStepFlow';

// ── RBAC: which roles a given role can assign ─────────────────────────────────
// platform_admin → all roles
// org_admin      → org_admin and below
// tenant_admin   → analyst, viewer only
const ASSIGNABLE_ROLES = {
  platform_admin: ['platform_admin', 'org_admin', 'tenant_admin', 'analyst', 'viewer'],
  org_admin:      ['org_admin', 'tenant_admin', 'analyst', 'viewer'],
  tenant_admin:   ['analyst', 'viewer'],
  analyst:        [],
  viewer:         [],
};

const ROLE_LABELS = {
  platform_admin: 'Platform Admin',
  org_admin:      'Org Admin',
  tenant_admin:   'Tenant Admin',
  analyst:        'Analyst',
  viewer:         'Viewer',
};

const ROLE_COLORS = {
  platform_admin: { bg: 'rgba(239,68,68,0.12)',   color: '#f87171' },
  org_admin:      { bg: 'rgba(59,130,246,0.12)',   color: '#60a5fa' },
  tenant_admin:   { bg: 'rgba(139,92,246,0.12)',   color: '#a78bfa' },
  analyst:        { bg: 'rgba(34,197,94,0.12)',    color: '#4ade80' },
  viewer:         { bg: 'rgba(100,116,139,0.12)',  color: '#94a3b8' },
};

// ── Invite User Modal ─────────────────────────────────────────────────────────
function InviteUserModal({ myRole, tenants, onClose, onInvited }) {
  const { customerId } = useTenant();
  const [form, setForm] = useState({ email: '', role: '', tenant_id: '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const assignable = ASSIGNABLE_ROLES[myRole] || [];

  async function handleSubmit(e) {
    e.preventDefault();
    if (!form.email || !form.role) return;
    setSaving(true); setError(null);
    const res = await fetchFromCspm('/api/auth/users/invite/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email:     form.email.trim(),
        role:      form.role,
        tenant_id: form.tenant_id || undefined,
        customer_id: customerId,
      }),
    });
    setSaving(false);
    if (res?.error || res?.detail) { setError(res.error || res.detail); return; }
    onInvited?.(res);
    onClose();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="rounded-xl p-6 w-full max-w-md shadow-2xl"
        style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Invite User</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/10">
            <X className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Email */}
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Email address <span className="text-red-400">*</span>
            </label>
            <input type="email" required autoFocus
              value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              placeholder="user@company.com"
              className="w-full px-3 py-2 rounded-lg text-sm outline-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }} />
          </div>

          {/* Role — only show roles this actor can assign */}
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Role <span className="text-red-400">*</span>
            </label>
            <div className="relative">
              <select required value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
                className="w-full px-3 py-2 rounded-lg text-sm outline-none appearance-none"
                style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: form.role ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                <option value="" disabled>Select a role…</option>
                {assignable.map(r => (
                  <option key={r} value={r}>{ROLE_LABELS[r]}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-3 top-2.5 w-4 h-4 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
            </div>
            {form.role && (
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                {form.role === 'platform_admin' && 'Full platform access across all organizations.'}
                {form.role === 'org_admin'      && 'Manages org-level settings, tenants, and billing.'}
                {form.role === 'tenant_admin'   && 'Manages accounts, users, and scans in a workspace.'}
                {form.role === 'analyst'        && 'Reads all findings; cannot manage accounts or users.'}
                {form.role === 'viewer'         && 'Read-only access to posture and reports.'}
              </p>
            )}
          </div>

          {/* Workspace assignment (optional) */}
          {tenants.length > 0 && (
            <div>
              <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Assign to Workspace <span className="text-xs font-normal" style={{ color: 'var(--text-muted)' }}>(optional)</span>
              </label>
              <div className="relative">
                <select value={form.tenant_id} onChange={e => setForm(f => ({ ...f, tenant_id: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg text-sm outline-none appearance-none"
                  style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }}>
                  <option value="">All workspaces</option>
                  {tenants.map(t => <option key={t.tenant_id} value={t.tenant_id}>{t.tenant_name}</option>)}
                </select>
                <ChevronDown className="absolute right-3 top-2.5 w-4 h-4 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
              </div>
            </div>
          )}

          {error && <p className="text-sm text-red-400 bg-red-500/10 px-3 py-2 rounded-lg">{error}</p>}

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 rounded-lg text-sm"
              style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>Cancel</button>
            <button type="submit" disabled={saving || !form.email || !form.role}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50"
              style={{ backgroundColor: 'var(--accent-primary)' }}>
              <Mail className="w-4 h-4" />
              {saving ? 'Sending…' : 'Send Invite'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Change Role Modal ─────────────────────────────────────────────────────────
function ChangeRoleModal({ user, myRole, onClose, onSaved }) {
  const [selectedRole, setSelectedRole] = useState(user.role || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const assignable = ASSIGNABLE_ROLES[myRole] || [];

  async function handleSave() {
    if (!selectedRole || selectedRole === user.role) { onClose(); return; }
    setSaving(true); setError(null);
    const res = await fetchFromCspm(`/api/auth/users/${user.id}/`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: selectedRole }),
    });
    setSaving(false);
    if (res?.error || res?.detail) { setError(res.error || res.detail); return; }
    onSaved?.({ ...user, role: selectedRole });
    onClose();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="rounded-xl p-6 w-full max-w-sm shadow-2xl"
        style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Change Role — {user.name || user.email}</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/10">
            <X className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          </button>
        </div>
        <div className="space-y-2 mb-4">
          {assignable.map(r => {
            const s = ROLE_COLORS[r] || {};
            const active = selectedRole === r;
            return (
              <button key={r} onClick={() => setSelectedRole(r)}
                className="w-full flex items-center justify-between px-3 py-2.5 rounded-lg border text-sm transition-colors"
                style={{
                  backgroundColor: active ? (s.bg || 'transparent') : 'transparent',
                  borderColor: active ? (s.color || 'var(--border-primary)') : 'var(--border-primary)',
                  color: active ? (s.color || 'var(--text-primary)') : 'var(--text-secondary)',
                }}>
                <span className="font-medium">{ROLE_LABELS[r]}</span>
                {active && <ShieldCheck className="w-4 h-4" />}
              </button>
            );
          })}
        </div>
        {error && <p className="text-sm text-red-400 mb-3">{error}</p>}
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm"
            style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>Cancel</button>
          <button onClick={handleSave} disabled={saving || !selectedRole}
            className="px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50"
            style={{ backgroundColor: 'var(--accent-primary)' }}>
            {saving ? 'Saving…' : 'Save Role'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function UserOnboardingPage() {
  const { role: myRole } = useAuth();
  const { customerId, activeTenant } = useTenant();
  const toast = useToast();

  const [users, setUsers]     = useState([]);
  const [tenants, setTenants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showInvite, setShowInvite]         = useState(false);
  const [changeRoleUser, setChangeRoleUser] = useState(null);

  const canInvite = (ASSIGNABLE_ROLES[myRole] || []).length > 0;

  const loadData = useCallback(async () => {
    setLoading(true);
    const tenantParam = activeTenant?.tenant_id ? `?tenant_id=${encodeURIComponent(activeTenant.tenant_id)}` : '';
    try {
      const [usersRes, tenantsRes] = await Promise.all([
        fetchFromCspm(`/api/auth/users/${tenantParam}`),
        customerId ? getFromEngine('onboarding', '/api/v1/tenants', { customer_id: customerId }) : Promise.resolve({}),
      ]);
      setUsers(Array.isArray(usersRes) ? usersRes : (usersRes?.users || []));
      setTenants(tenantsRes?.tenants || []);
    } catch { /* silently fail */ }
    finally { setLoading(false); }
  }, [activeTenant, customerId]);

  useEffect(() => { loadData(); }, [loadData]);

  // ── Step-flow computation ───────────────────────────────────────────────────
  const totalUsers  = users.length;
  const activeUsers = users.filter(u => u.status === 'active').length;
  const hasInvited  = totalUsers > 0;
  const hasWorkspaceAssigned = users.some(u => u.tenant_id);
  const hasRoleAssigned      = users.some(u => u.role && u.role !== 'pending');
  const hasActive            = activeUsers > 0;

  const steps = [
    {
      id: 'invite',
      label: 'Invite',
      sublabel: hasInvited ? `${totalUsers} invited` : 'No users yet',
      status: hasInvited ? 'complete' : 'current',
      action: !hasInvited && canInvite ? { label: 'Invite User', onClick: () => setShowInvite(true) } : null,
    },
    {
      id: 'workspace',
      label: 'Workspace',
      sublabel: hasWorkspaceAssigned ? 'Assigned' : 'Not assigned',
      status: hasWorkspaceAssigned ? 'complete' : hasInvited ? 'current' : 'pending',
    },
    {
      id: 'role',
      label: 'Role',
      sublabel: hasRoleAssigned ? 'Roles set' : 'Pending',
      status: hasRoleAssigned ? 'complete' : hasWorkspaceAssigned ? 'current' : 'pending',
    },
    {
      id: 'active',
      label: 'Active',
      sublabel: hasActive ? `${activeUsers} active` : 'Awaiting acceptance',
      status: hasActive ? 'complete' : hasRoleAssigned ? 'current' : 'pending',
    },
  ];

  // ── Columns ────────────────────────────────────────────────────────────────
  const columns = [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: info => (
        <div>
          <p className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue() || '—'}</p>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{info.row.original.email}</p>
        </div>
      ),
    },
    {
      accessorKey: 'role',
      header: 'Role',
      cell: info => {
        const r = info.getValue();
        const s = ROLE_COLORS[r] || { bg: 'rgba(100,116,139,0.12)', color: '#94a3b8' };
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold"
            style={{ backgroundColor: s.bg, color: s.color }}>
            {ROLE_LABELS[r] || r || '—'}
          </span>
        );
      },
    },
    {
      accessorKey: 'tenant_name',
      header: 'Workspace',
      cell: info => {
        const v = info.getValue() || info.row.original.tenant_id;
        return v
          ? <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
              <Building2 className="w-3 h-3" />{v}
            </span>
          : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>All workspaces</span>;
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: info => {
        const s = info.getValue();
        const isActive = s === 'active';
        return (
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${isActive ? 'bg-green-500/20 text-green-400' : 'bg-amber-500/20 text-amber-400'}`}>
            {s || 'pending'}
          </span>
        );
      },
    },
    {
      accessorKey: 'last_login',
      header: 'Last Login',
      cell: info => {
        const v = info.getValue();
        if (!v) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Never</span>;
        const m = Math.floor((Date.now() - new Date(v)) / 60000);
        return <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
          {m < 60 ? `${m}m ago` : m < 1440 ? `${Math.floor(m / 60)}h ago` : new Date(v).toLocaleDateString()}
        </span>;
      },
    },
    {
      id: 'actions',
      header: '',
      cell: info => {
        const user = info.row.original;
        const canChangeRole = (ASSIGNABLE_ROLES[myRole] || []).includes(user.role) ||
          (ASSIGNABLE_ROLES[myRole] || []).length > 0;
        if (!canChangeRole) return null;
        return (
          <button onClick={() => setChangeRoleUser(user)}
            className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium hover:opacity-80"
            style={{ backgroundColor: 'rgba(139,92,246,0.1)', color: '#a78bfa', border: '1px solid rgba(139,92,246,0.25)' }}>
            <ShieldCheck className="w-3 h-3" /> Change Role
          </button>
        );
      },
    },
  ];

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Users className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>User Onboarding</h1>
            <p className="text-sm mt-0.5" style={{ color: 'var(--text-tertiary)' }}>Invite users and assign workspace roles</p>
          </div>
        </div>
        {canInvite && (
          <button onClick={() => setShowInvite(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--accent-primary)' }}>
            <Plus className="w-4 h-4" /> Invite User
          </button>
        )}
      </div>

      {/* Step flow */}
      <OnboardingStepFlow steps={steps} />

      {/* Role legend */}
      <div className="rounded-xl border p-4"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-secondary)' }}>ROLE PERMISSIONS</p>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
          {Object.entries(ROLE_LABELS).map(([key, label]) => {
            const s = ROLE_COLORS[key] || {};
            const canAssign = (ASSIGNABLE_ROLES[myRole] || []).includes(key);
            return (
              <div key={key} className="rounded-lg border p-2.5 text-center"
                style={{
                  backgroundColor: s.bg,
                  borderColor: canAssign ? (s.color || 'transparent') : 'transparent',
                  opacity: canAssign ? 1 : 0.5,
                }}>
                <p className="text-xs font-semibold" style={{ color: s.color }}>{label}</p>
                {canAssign && <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>You can assign</p>}
              </div>
            );
          })}
        </div>
      </div>

      {/* Users table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Users</h2>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {activeUsers} active / {totalUsers} total
          </span>
        </div>
        {!loading && users.length === 0
          ? (
            <div className="rounded-xl border border-dashed p-10 flex flex-col items-center gap-3"
              style={{ borderColor: 'var(--border-primary)' }}>
              <Users className="w-10 h-10" style={{ color: 'var(--text-muted)' }} />
              <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No users yet</p>
              {canInvite && (
                <button onClick={() => setShowInvite(true)}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
                  style={{ backgroundColor: 'var(--accent-primary)' }}>
                  <Plus className="w-4 h-4" /> Invite First User
                </button>
              )}
            </div>
          )
          : <DataTable data={users} columns={columns} pageSize={25} loading={loading} emptyMessage="No users found" />
        }
      </div>

      {/* Modals */}
      {showInvite && (
        <InviteUserModal
          myRole={myRole}
          tenants={tenants}
          onClose={() => setShowInvite(false)}
          onInvited={user => {
            setUsers(prev => [user, ...prev]);
            toast.success(`Invite sent to ${user.email || 'user'}`);
          }}
        />
      )}
      {changeRoleUser && (
        <ChangeRoleModal
          user={changeRoleUser}
          myRole={myRole}
          onClose={() => setChangeRoleUser(null)}
          onSaved={updated => {
            setUsers(prev => prev.map(u => u.id === updated.id ? updated : u));
            toast.success('Role updated');
          }}
        />
      )}
    </div>
  );
}
