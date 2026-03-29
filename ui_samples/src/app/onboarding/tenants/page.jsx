'use client';
import { useState } from 'react';
import { Building2, Plus } from 'lucide-react';
import DataTable from '@/components/shared/DataTable';

const MOCK_TENANTS = [
  { id: 'default-tenant', name: 'Default', accounts: 1, provider: 'AWS', status: 'active', created: '2026-03-22' },
  { id: 'test-tenant-002', name: 'Production Tenant', accounts: 1, provider: 'AWS', status: 'active', created: '2026-02-17' },
];

export default function TenantsPage() {
  const columns = [
    { accessorKey: 'name', header: 'Tenant Name' },
    { accessorKey: 'id', header: 'Tenant ID', cell: (i) => <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>{i.getValue()}</span> },
    { accessorKey: 'accounts', header: 'Accounts' },
    { accessorKey: 'provider', header: 'Provider', cell: (i) => <span className="text-xs uppercase font-medium">{i.getValue()}</span> },
    { accessorKey: 'status', header: 'Status', cell: (i) => <span className={`text-xs px-2 py-0.5 rounded ${i.getValue()==='active'?'bg-green-500/20 text-green-400':'bg-gray-500/20 text-gray-400'}`}>{i.getValue()}</span> },
    { accessorKey: 'created', header: 'Created' },
  ];

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Building2 className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Tenant Management</h1>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white" style={{ backgroundColor: 'var(--accent-primary)' }}>
          <Plus className="w-4 h-4" /> Add Tenant
        </button>
      </div>
      <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>Manage tenants and their cloud account associations.</p>
      <DataTable data={MOCK_TENANTS} columns={columns} pageSize={25} hideToolbar />
    </div>
  );
}
