'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getFromEngine, fetchFromCspm } from '@/lib/api';
import { Users, UserPlus, Edit2, Trash2, ShieldCheck } from 'lucide-react';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import SearchBar from '@/components/shared/SearchBar';
import FilterBar from '@/components/shared/FilterBar';
import { useToast } from '@/lib/toast-context';


const ROLE_COLORS = {
  super_admin: { bg: 'bg-purple-500/20', text: 'text-purple-400', label: 'Super Admin' },
  admin:       { bg: 'bg-blue-500/20',   text: 'text-blue-400',   label: 'Admin' },
  tenant_admin:{ bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'Tenant Admin' },
  user:        { bg: 'bg-slate-500/20',  text: 'text-slate-400',  label: 'User' },
};

const STATUS_COLORS = {
  active:   { bg: 'bg-green-500/20',  text: 'text-green-400',  label: 'Active' },
  inactive: { bg: 'bg-slate-500/20',  text: 'text-slate-400',  label: 'Inactive' },
  pending:  { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Pending' },
};

const FILTERS = [
  {
    key: 'role',
    label: 'Role',
    options: [
      { value: '', label: 'All Roles' },
      { value: 'super_admin', label: 'Super Admin' },
      { value: 'admin', label: 'Admin' },
      { value: 'tenant_admin', label: 'Tenant Admin' },
      { value: 'user', label: 'User' },
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

export default function UsersPage() {
  const router = useRouter();
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [activeFilters, setActiveFilters] = useState({ role: '', status: '' });
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchUsers = async () => {
      setLoading(true);
      setError(null);
      try {
        // Try Django CSPM backend first (has real users with roles and auth)
        const cspmRes = await fetchFromCspm('/api/users/');
        if (cspmRes && !cspmRes.error) {
          const rawList = cspmRes.results || (Array.isArray(cspmRes) ? cspmRes : []);
          if (rawList.length > 0) {
            setUsers(rawList.map(u => ({
              id: u.id || u.pk,
              name: u.full_name || u.get_full_name || `${u.first_name || ''} ${u.last_name || ''}`.trim() || u.username || u.email,
              email: u.email || '',
              role: u.role || (u.is_superuser ? 'super_admin' : u.is_staff ? 'admin' : 'user'),
              status: u.is_active ? 'active' : 'inactive',
              last_login: u.last_login ? new Date(u.last_login).toLocaleDateString() : 'Never',
            })));
            return;
          }
        }
        // Fallback: onboarding engine users (derived from cloud accounts)
        const res = await getFromEngine('onboarding', '/api/v1/users');
        if (res && !res.error) {
          const raw = Array.isArray(res) ? res : (res.users || res.results || res.data || []);
          setUsers(raw);
        } else {
          setError('Failed to load users.');
        }
      } catch (err) {
        console.warn('Failed to fetch users:', err);
        setError('Failed to load users.');
      } finally {
        setLoading(false);
      }
    };
    fetchUsers();
  }, []);

  const totalUsers = users.length;
  const adminUsers = users.filter((u) => u.role === 'admin' || u.role === 'super_admin').length;
  const activeCount = users.filter((u) => u.status === 'active').length;
  const pendingInvites = users.filter((u) => u.status === 'pending').length;

  const filtered = users.filter((u) => {
    const matchesSearch = !search ||
      u.name.toLowerCase().includes(search.toLowerCase()) ||
      u.email.toLowerCase().includes(search.toLowerCase());
    const matchesRole = !activeFilters.role || u.role === activeFilters.role;
    const matchesStatus = !activeFilters.status || u.status === activeFilters.status;
    return matchesSearch && matchesRole && matchesStatus;
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
        const c = ROLE_COLORS[info.getValue()] || ROLE_COLORS.user;
        return <span className={`text-xs px-3 py-1 rounded font-medium ${c.bg} ${c.text}`}>{c.label}</span>;
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const c = STATUS_COLORS[info.getValue()] || STATUS_COLORS.inactive;
        return <span className={`text-xs px-3 py-1 rounded font-medium ${c.bg} ${c.text}`}>{c.label}</span>;
      },
    },
    {
      accessorKey: 'last_login',
      header: 'Last Login',
      cell: (info) => (
        <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">{info.getValue()}</span>
      ),
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: (info) => (
        <div className="flex items-center gap-2">
          <button
            onClick={() => toast.info(`Edit user: ${info.row.original.name}`)}
            className="p-2 rounded-lg transition-colors hover:opacity-75"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}
            title="Edit user"
          >
            <Edit2 size={14} />
          </button>
          <button
            onClick={() => toast.warning(`Delete is a restricted action — perform this from the admin panel.`)}
            className="p-2 rounded-lg transition-colors hover:opacity-75"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}
            title="Delete user"
          >
            <Trash2 size={14} />
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
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
            User Management
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Manage platform users, roles, and access permissions
          </p>
        </div>
        <button
          onClick={() => router.push('/settings/users/add')}
          className="flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors text-white"
          style={{ backgroundColor: 'var(--accent-primary)' }}
        >
          <UserPlus size={18} />
          Invite User
        </button>
      </div>

      {/* Error state */}
      {error && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: '#ef4444' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Users" value={totalUsers} subtitle="All accounts" icon={<Users className="w-5 h-5" />} color="blue" />
        <KpiCard title="Admins" value={adminUsers} subtitle="Super + Tenant admins" icon={<ShieldCheck className="w-5 h-5" />} color="purple" />
        <KpiCard title="Active Users" value={activeCount} subtitle="Currently active" icon={<Users className="w-5 h-5" />} color="green" />
        <KpiCard title="Pending Invites" value={pendingInvites} subtitle="Awaiting acceptance" icon={<UserPlus className="w-5 h-5" />} color="orange" />
      </div>

      {/* Users Table */}
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        {/* Table toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
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
              onFilterChange={(key, value) => setActiveFilters((prev) => ({ ...prev, [key]: value }))}
            />
          </div>
        </div>
        <DataTable
          data={filtered}
          columns={columns}
          pageSize={10}
          emptyMessage="No users match your search"
        />
      </div>
    </div>
  );
}
