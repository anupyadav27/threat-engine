'use client';

import { useEffect, useState } from 'react';
import {
  Building2,
  Plus,
  Cloud,
  Users,
} from 'lucide-react';
import { getFromEngine, fetchFromCspm } from '@/lib/api';
import { useToast } from '@/lib/toast-context';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import StatusIndicator from '@/components/shared/StatusIndicator';


/**
 * Tenant Management Page
 * Manage multiple cloud accounts and users across tenants
 */
export default function TenantsPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [tenants, setTenants] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchTenants = async () => {
      setLoading(true);
      setError(null);
      try {
        // Try Django CSPM backend first (has real tenant/org data)
        const cspmRes = await fetchFromCspm('/api/tenants/');
        if (cspmRes && !cspmRes.error) {
          const raw = cspmRes.results || (Array.isArray(cspmRes) ? cspmRes : []);
          if (raw.length > 0) {
            setTenants(raw.map(t => ({
              id: t.id || t.pk,
              name: t.name || t.tenant_name || t.organization || '',
              plan: t.plan || t.subscription || 'Enterprise',
              accounts_count: t.accounts_count || t.cloud_accounts_count || 0,
              users_count: t.users_count || t.user_count || 0,
              status: t.status || (t.is_active ? 'active' : 'inactive'),
              created_at: t.created_at || t.date_joined || new Date().toISOString(),
            })));
            return;
          }
        }
        // Fallback: derive single tenant from cloud accounts in onboarding engine
        const accountsRes = await getFromEngine('onboarding', '/api/v1/cloud-accounts');
        if (accountsRes && !accountsRes.error) {
          const accounts = Array.isArray(accountsRes) ? accountsRes : (accountsRes.accounts || accountsRes.results || accountsRes.data || []);
          setTenants([{
            id: 'default',
            name: 'Default Organization',
            plan: 'Enterprise',
            accounts_count: accounts.length,
            users_count: 0,
            status: 'active',
            created_at: new Date().toISOString(),
          }]);
        } else {
          setError('Failed to load tenants.');
        }
      } catch (err) {
        console.warn('Error fetching tenants:', err);
        setError('Failed to load tenants.');
      } finally {
        setLoading(false);
      }
    };

    fetchTenants();
  }, []);

  // Calculate tenant statistics
  const tenantStats = {
    total: tenants.length,
    active: tenants.filter((t) => t.status === 'active').length,
    accounts: tenants.reduce((sum, t) => sum + t.accounts_count, 0),
    users: tenants.reduce((sum, t) => sum + t.users_count, 0),
  };

  // Table columns
  const columns = [
    {
      accessorKey: 'name',
      header: 'Tenant Name',
      cell: (info) => (
        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'plan',
      header: 'Plan',
      cell: (info) => {
        const plan = info.getValue();
        const planColors = {
          Enterprise: '#8b5cf6',
          Pro: '#3b82f6',
          Starter: '#6b7280',
        };
        const color = planColors[plan] || '#6b7280';
        return (
          <span
            className="text-xs px-2 py-1 rounded font-semibold"
            style={{ backgroundColor: color + '20', color }}
          >
            {plan}
          </span>
        );
      },
    },
    {
      accessorKey: 'accounts_count',
      header: 'Cloud Accounts',
      cell: (info) => (
        <div className="flex items-center gap-2">
          <Cloud className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <span className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
            {info.getValue()}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'users_count',
      header: 'Users',
      cell: (info) => (
        <div className="flex items-center gap-2">
          <Users className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <span className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
            {info.getValue()}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        const statusMap = {
          active: 'completed',
          inactive: 'running',
          suspended: 'failed',
        };
        return <StatusIndicator status={statusMap[status] || 'running'} />;
      },
    },
    {
      accessorKey: 'created_at',
      header: 'Created',
      cell: (info) => {
        const date = new Date(info.getValue());
        return (
          <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            {date.toLocaleDateString()}
          </span>
        );
      },
    },
    {
      accessorKey: 'id',
      header: 'Actions',
      cell: (info) => (
        <div className="flex gap-2">
          <button
            className="p-1 rounded hover:opacity-70 transition-colors"
            style={{ color: 'var(--text-secondary)' }}
            title="View tenant details"
          >
            👁️
          </button>
          <button
            className="p-1 rounded hover:opacity-70 transition-colors"
            style={{ color: 'var(--text-secondary)' }}
            title="Edit tenant"
          >
            ✎
          </button>
        </div>
      ),
    },
  ];

  const handleAddTenant = () => {
    toast.info('Tenant creation is managed via the admin portal.');
  };

  const handleRowClick = (tenant) => {
    console.log('Viewing tenant:', tenant.id);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Tenant Management
          </h1>
          <p className="mt-1" style={{ color: 'var(--text-tertiary)' }}>
            Manage multi-tenant organizations and cloud account associations
          </p>
        </div>
        <button
          onClick={handleAddTenant}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Tenant
        </button>
      </div>

      {/* Error state */}
      {error && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: '#ef4444' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Tenants"
          value={tenantStats.total}
          subtitle="Managed organizations"
          icon={<Building2 className="w-5 h-5" />}
          color="blue"
        />
        <KpiCard
          title="Active"
          value={tenantStats.active}
          subtitle="Active tenants"
          icon={<Building2 className="w-5 h-5" />}
          color="green"
        />
        <KpiCard
          title="Cloud Accounts"
          value={tenantStats.accounts}
          subtitle="Across all tenants"
          icon={<Cloud className="w-5 h-5" />}
          color="purple"
        />
        <KpiCard
          title="Total Users"
          value={tenantStats.users}
          subtitle="Across all tenants"
          icon={<Users className="w-5 h-5" />}
          color="orange"
        />
      </div>

      {/* Tenants Table */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Tenants
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            {tenants.length} organizations configured
          </p>
        </div>

        <DataTable
          data={tenants}
          columns={columns}
          pageSize={10}
          onRowClick={handleRowClick}
          loading={loading}
          emptyMessage="No tenants found"
        />
      </div>

      {/* Tenant Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {tenants.map((tenant) => (
          <div
            key={tenant.id}
            className="rounded-xl p-6 border hover:shadow-lg transition-all duration-200 cursor-pointer"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                  {tenant.name}
                </h3>
                <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
                  Created {tenant.created_at ? new Date(tenant.created_at).toLocaleDateString() : 'N/A'}
                </p>
              </div>
              <span
                className="text-xs px-3 py-1 rounded font-semibold"
                style={{
                  backgroundColor: tenant.plan === 'Enterprise'
                    ? '#8b5cf620'
                    : tenant.plan === 'Pro'
                      ? '#3b82f620'
                      : '#6b728020',
                  color: tenant.plan === 'Enterprise'
                    ? '#8b5cf6'
                    : tenant.plan === 'Pro'
                      ? '#3b82f6'
                      : '#6b7280',
                }}
              >
                {tenant.plan}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4 pt-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
              <div>
                <p className="text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>
                  Cloud Accounts
                </p>
                <p className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                  {tenant.accounts_count}
                </p>
              </div>
              <div>
                <p className="text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>
                  Users
                </p>
                <p className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                  {tenant.users_count}
                </p>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
              <p className="text-xs mb-2" style={{ color: 'var(--text-tertiary)' }}>
                Status
              </p>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-500" />
                <span className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
                  {(tenant.status || '').charAt(0).toUpperCase() + (tenant.status || '').slice(1)}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Tenant Configuration Info */}
      <div
        className="rounded-xl p-6 border transition-colors duration-200"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
          Tenant Configuration
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <p className="text-xs mb-2" style={{ color: 'var(--text-tertiary)' }}>
              Organization Structure
            </p>
            <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              Multi-tenant isolated architecture
            </p>
            <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>
              Each tenant maintains isolated data and configurations
            </p>
          </div>

          <div>
            <p className="text-xs mb-2" style={{ color: 'var(--text-tertiary)' }}>
              Authentication
            </p>
            <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              SSO / OIDC Integration
            </p>
            <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>
              Supports enterprise identity providers
            </p>
          </div>

          <div>
            <p className="text-xs mb-2" style={{ color: 'var(--text-tertiary)' }}>
              Compliance
            </p>
            <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              Data Residency & Isolation
            </p>
            <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>
              Complies with GDPR, HIPAA, and other regulations
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
