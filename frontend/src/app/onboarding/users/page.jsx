'use client';
import { useState, useEffect } from 'react';
import { Users, Plus } from 'lucide-react';
import DataTable from '@/components/shared/DataTable';

export default function UsersPage() {
  const [users, setUsers] = useState([]);

  useEffect(() => {
    fetch('/gateway/api/v1/platform/users', { headers: { 'X-Tenant-ID': process.env.NEXT_PUBLIC_TENANT_ID || 'default-tenant' } })
      .then(r => r.ok ? r.json() : [])
      .then(d => setUsers(Array.isArray(d) ? d : (d.users || [])))
      .catch(() => {});
  }, []);

  const columns = [
    { accessorKey: 'name', header: 'Name' },
    { accessorKey: 'email', header: 'Email' },
    { accessorKey: 'role', header: 'Role', cell: (i) => <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: i.getValue()==='Admin' ? 'rgba(59,130,246,0.15)' : 'var(--bg-tertiary)', color: i.getValue()==='Admin' ? '#60a5fa' : 'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey: 'status', header: 'Status', cell: (i) => <span className={`text-xs px-2 py-0.5 rounded ${i.getValue()==='active'?'bg-green-500/20 text-green-400':'bg-gray-500/20 text-gray-400'}`}>{i.getValue()}</span> },
    { accessorKey: 'last_login', header: 'Last Login' },
  ];

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Users className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>User Management</h1>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white" style={{ backgroundColor: 'var(--accent-primary)' }}>
          <Plus className="w-4 h-4" /> Add User
        </button>
      </div>
      <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>Manage platform users, roles, and access permissions.</p>
      {users.length > 0
        ? <DataTable data={users} columns={columns} pageSize={25} hideToolbar />
        : <p className="text-sm text-center py-10" style={{ color: 'var(--text-muted)' }}>No users found.</p>
      }
    </div>
  );
}
