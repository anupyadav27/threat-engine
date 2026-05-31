'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { fetchView } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';
import { Users, UserPlus, ShieldCheck, Clock, CheckCircle2, AlertCircle } from 'lucide-react';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import SearchBar from '@/components/shared/SearchBar';
import FilterBar from '@/components/shared/FilterBar';
import InviteUserModal from '@/components/settings/InviteUserModal';

// AC4: only org_admin and platform_admin may access this page
const ALLOWED_ROLES = ['org_admin', 'platform_admin'];

const ROLE_COLORS = {
  platform_admin: { bg: 'bg-purple-500/20', text: 'text-purple-400', label: 'Platform Admin' },
  org_admin:      { bg: 'bg-blue-500/20',   text: 'text-blue-400',   label: 'Org Admin' },
  tenant_admin:   { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'Tenant Admin' },
  analyst:        { bg: 'bg-cyan-500/20',   text: 'text-cyan-400',   label: 'Analyst' },
  viewer:         { bg: 'bg-slate-500/20',  text: 'text-slate-400',  label: 'Viewer' },
  // legacy label compat
  super_admin:    { bg: 'bg-purple-500/20', text: 'text-purple-400', label: 'Super Admin' },
  admin:          { bg: 'bg-blue-500/20',   text: 'text-blue-400',   label: 'Admin' },
  user:           { bg: 'bg-slate-500/20',  text: 'text-slate-400',  label: 'User' },
};

const STATUS_COLORS = {
  active:   { bg: 'bg-green-500/20',  text: 'text-green-400',  label: 'Active',   icon: CheckCircle2 },
  inactive: { bg: 'bg-slate-500/20',  text: 'text-slate-400',  label: 'Inactive', icon: AlertCircle },
  pending:  { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Pending',  icon: Clock },
};

const FILTERS = [
  {
    key: 'role',
    label: 'Role',
    options: [
      { value: '', label: 'All Roles' },
      { value: 'platform_admin', label: 'Platform Admin' },
      { value: 'org_admin', label: 'Org Admin' },
      { value: 'tenant_admin', label: 'Tenant Admin' },
      { value: 'analyst', label: 'Analyst' },
      { value: 'viewer', label: 'Viewer' },
    ],
  },
  {
    key: 'status',
    label: 'Status',
    options: [
      { value: '', label: 'All Statuses' },
      { value: 'active', label: 'Active' },
      { value: 'inactive', label: 'Inactive' },
      { value: 'pending', label: 'Pending' },
    ],
  },
];

// Loading skeleton for AC11
function UsersSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <div className="h-8 w-48 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="h-4 w-72 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        </div>
        <div className="h-10 w-32 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="h-24 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        ))}
      </div>
      <div className="rounded-xl border p-6 space-y-3" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        {[1, 2, 3, 4, 5].map(i => (
          <div key={i} className="h-12 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        ))}
      </div>
    </div>
  );
}

export default function UsersPage() {
  const router = useRouter();
  const { role, isInitialized } = useAuth();
  const [search, setSearch] = useState('');
  const [activeFilters, setActiveFilters] = useState({ role: '', status: '' });
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showInviteModal, setShowInviteModal] = useState(false);

  // AC4: role guard — redirect tenant_admin, analyst, viewer to 403
  useEffect(() => {
    if (!isInitialized) return;
    if (role && !ALLOWED_ROLES.includes(role)) {
      router.replace('/403');
    }
  }, [role, isInitialized, router]);

  // AC1: fetch user list via BFF view
  const loadUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchView('users');
      if (data && !data.error) {
        const rawList = data.users || [];
        setUsers(
          rawList.map(u => ({
            id: u.user_id,
            name: u.name || u.email || '',
            email: u.email || '',
            role: u.role || 'viewer',
            status: u.status || 'active',
            date_joined: u.date_joined
              ? new Date(u.date_joined).toLocaleDateString()
              : '—',
            last_login: u.last_login
              ? new Date(u.last_login).toLocaleDateString()
              : 'Never',
          }))
        );
      } else {
        setError(data?.error || 'Failed to load users.');
      }
    } catch (err) {
      console.error('Failed to fetch users:', err);
      setError('Failed to load users.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!isInitialized) return;
    if (!role || !ALLOWED_ROLES.includes(role)) return;
    loadUsers();
  }, [isInitialized, role]);

  // AC11: show skeleton while loading
  if (!isInitialized || loading) return <UsersSkeleton />;

  // AC4: blank while redirect resolves
  if (!ALLOWED_ROLES.includes(role)) return null;

  const totalUsers = users.length;
  const adminCount = users.filter(u => ['platform_admin', 'org_admin'].includes(u.role)).length;
  const activeCount = users.filter(u => u.status === 'active').length;
  const pendingCount = users.filter(u => u.status === 'pending').length;

  const filtered = users.filter(u => {
    const q = search.toLowerCase();
    const matchSearch = !search || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q);
    const matchRole = !activeFilters.role || u.role === activeFilters.role;
    const matchStatus = !activeFilters.status || u.status === activeFilters.status;
    return matchSearch && matchRole && matchStatus;
  });

  const columns = [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: (info) => (
        <div>
          <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</p>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{info.row.original.email}</p>
        </div>
      ),
    },
    {
      accessorKey: 'role',
      header: 'Role',
      cell: (info) => {
        const c = ROLE_COLORS[info.getValue()] || ROLE_COLORS.viewer;
        return (
          <span className={`text-xs px-2.5 py-1 rounded font-medium ${c.bg} ${c.text}`}>
            {c.label}
          </span>
        );
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const c = STATUS_COLORS[info.getValue()] || STATUS_COLORS.inactive;
        const Icon = c.icon;
        return (
          <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded font-medium ${c.bg} ${c.text}`}>
            <Icon size={11} />
            {c.label}
          </span>
        );
      },
    },
    {
      accessorKey: 'date_joined',
      header: 'Joined At',
      cell: (info) => (
        <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'last_login',
      header: 'Last Login',
      cell: (info) => (
        <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">{info.getValue()}</span>
      ),
    },
    // AC2: Re-invite action per row (visible only to allowed roles — already gated at page level)
    {
      id: 'actions',
      header: 'Actions',
      cell: (info) => (
        <div className="flex items-center gap-2">
          <button
            onClick={() => router.push(`/settings/users/${info.row.original.id}/accounts`)}
            className="p-1.5 rounded-lg transition-colors hover:opacity-75 text-xs"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}
            title="Manage account access"
          >
            <ShieldCheck size={13} />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            User Management
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Manage org users, roles, and access permissions
          </p>
        </div>
        {/* AC2: Invite button — visible because page is already role-gated */}
        <button
          onClick={() => setShowInviteModal(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors text-white text-sm"
          style={{ backgroundColor: 'var(--accent-primary)' }}
        >
          <UserPlus size={16} />
          Invite User
        </button>
      </div>

      {/* Error state */}
      {error && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: 'rgba(220,38,38,0.1)', borderColor: 'rgba(239,68,68,0.4)' }}>
          <p className="text-sm" style={{ color: '#f87171' }}>{error}</p>
        </div>
      )}

      {/* KPI Cards — AC1 data counts */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Users"
          value={totalUsers}
          subtitle="All accounts"
          icon={<Users className="w-5 h-5" />}
          color="blue"
        />
        <KpiCard
          title="Admins"
          value={adminCount}
          subtitle="Org + Platform admins"
          icon={<ShieldCheck className="w-5 h-5" />}
          color="purple"
        />
        <KpiCard
          title="Active Users"
          value={activeCount}
          subtitle="Currently active"
          icon={<CheckCircle2 className="w-5 h-5" />}
          color="green"
        />
        <KpiCard
          title="Pending Invites"
          value={pendingCount}
          subtitle="Awaiting acceptance"
          icon={<Clock className="w-5 h-5" />}
          color="orange"
        />
      </div>

      {/* Users Table */}
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
            All Users
            <span className="ml-2 text-sm font-normal" style={{ color: 'var(--text-muted)' }}>
              ({filtered.length}/{totalUsers})
            </span>
          </h2>
          <div className="flex items-center gap-3 flex-wrap">
            <SearchBar
              value={search}
              onChange={setSearch}
              placeholder="Search by name or email..."
            />
            <FilterBar
              filters={FILTERS}
              activeFilters={activeFilters}
              onFilterChange={(key, value) => setActiveFilters(prev => ({ ...prev, [key]: value }))}
            />
          </div>
        </div>
        <DataTable
          data={filtered}
          columns={columns}
          pageSize={15}
          emptyMessage="No users match your search"
        />
      </div>

      {/* AC2: Invite User Modal */}
      {showInviteModal && (
        <InviteUserModal
          onClose={() => setShowInviteModal(false)}
          onInvited={() => {
            setShowInviteModal(false);
            // Refresh the list after a successful invite
            loadUsers();
          }}
        />
      )}
    </div>
  );
}
