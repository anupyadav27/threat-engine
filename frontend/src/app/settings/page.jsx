'use client';

import { useEffect, useState } from 'react';
import {
  Shield,
  Server,
  Database,
  Cloud,
  Lock,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
  Zap,
  RefreshCw,
  ChevronDown,
  Copy,
  Plus,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';

/**
 * Enterprise Settings & Configuration
 * Multi-tab interface for platform administration
 */
export default function SettingsPage() {
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('platform-health');
  const [engines, setEngines] = useState([]);
  const [apiKeys, setApiKeys] = useState([]);
  const [integrations, setIntegrations] = useState([]);
  const [auditLog, setAuditLog] = useState([]);
  const [notifications, setNotifications] = useState([]);

  // Fetch real engine health status
  useEffect(() => {
    const fetchHealth = async () => {
      const engineList = [
        { id: 'discoveries', name: 'Discovery' },
        { id: 'check', name: 'Check' },
        { id: 'inventory', name: 'Inventory' },
        { id: 'threat', name: 'Threat' },
        { id: 'compliance', name: 'Compliance' },
        { id: 'iam', name: 'IAM' },
        { id: 'datasec', name: 'DataSec' },
        { id: 'secops', name: 'SecOps' },
        { id: 'rule', name: 'Rule Engine' },
        { id: 'onboarding', name: 'Onboarding' },
      ];

      const healthChecks = await Promise.allSettled(
        engineList.map(async (eng) => {
          const prefix = eng.id === 'discoveries' ? 'discoveries' : eng.id;
          const res = await getFromEngine(prefix, '/api/v1/health');
          return {
            id: eng.id,
            name: eng.name,
            status: res && !res.error ? 'Healthy' : 'Unhealthy',
            uptime: res?.uptime || '—',
            heartbeat: res && !res.error ? 'just now' : 'unreachable',
            cpu: res?.cpu || '—',
            memory: res?.memory || '—',
            queue: res?.queue_depth || '—',
            version: res?.version || '—',
          };
        })
      );

      setEngines(healthChecks.map(r => r.status === 'fulfilled' ? r.value : {
        ...engineList[healthChecks.indexOf(r)],
        status: 'Unhealthy', uptime: '—', heartbeat: 'unreachable', cpu: '—', memory: '—', queue: '—', version: '—',
      }));
      setLoading(false);
    };

    fetchHealth();
  }, []);

  // Table columns
  const engineColumns = [
    {
      accessorKey: 'name',
      header: 'Engine',
      cell: (info) => <span style={{ color: 'var(--text-primary)' }} className="font-medium">{info.getValue()}</span>,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        const color = status === 'Healthy' ? '#10b981' : '#f97316';
        return <span style={{ backgroundColor: color + '20', color }} className="px-2 py-1 rounded text-xs font-semibold">{status}</span>;
      },
    },
    {
      accessorKey: 'uptime',
      header: 'Uptime',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }}>{info.getValue()}%</span>,
    },
    {
      accessorKey: 'heartbeat',
      header: 'Last Heartbeat',
      cell: (info) => <span style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'cpu',
      header: 'CPU %',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }}>{info.getValue()}%</span>,
    },
    {
      accessorKey: 'memory',
      header: 'Memory %',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }}>{info.getValue()}%</span>,
    },
    {
      accessorKey: 'queue',
      header: 'Queue Depth',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'version',
      header: 'Version',
      cell: (info) => <code style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }} className="px-2 py-1 rounded text-xs">v{info.getValue()}</code>,
    },
  ];

  const apiKeyColumns = [
    {
      accessorKey: 'name',
      header: 'Key Name',
      cell: (info) => <span style={{ color: 'var(--text-primary)' }} className="font-medium">{info.getValue()}</span>,
    },
    {
      accessorKey: 'keyId',
      header: 'Key ID (Masked)',
      cell: (info) => <code style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }} className="px-2 py-1 rounded text-xs">{info.getValue()}</code>,
    },
    {
      accessorKey: 'scopes',
      header: 'Scopes',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }} className="text-sm">{info.getValue()}</span>,
    },
    {
      accessorKey: 'created',
      header: 'Created',
      cell: (info) => <span style={{ color: 'var(--text-tertiary)' }}>{new Date(info.getValue()).toLocaleDateString()}</span>,
    },
    {
      accessorKey: 'lastUsed',
      header: 'Last Used',
      cell: (info) => <span style={{ color: 'var(--text-tertiary)' }}>{new Date(info.getValue()).toLocaleDateString()}</span>,
    },
    {
      accessorKey: 'expires',
      header: 'Expires',
      cell: (info) => <span style={{ color: 'var(--text-tertiary)' }}>{new Date(info.getValue()).toLocaleDateString()}</span>,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        const color = status === 'Active' ? '#10b981' : '#f97316';
        return <span style={{ backgroundColor: color + '20', color }} className="px-2 py-1 rounded text-xs font-semibold">{status}</span>;
      },
    },
    {
      accessorKey: 'createdBy',
      header: 'Created By',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }} className="text-sm">{info.getValue()}</span>,
    },
  ];

  const auditColumns = [
    {
      accessorKey: 'timestamp',
      header: 'Timestamp',
      cell: (info) => <span style={{ color: 'var(--text-tertiary)' }}>{new Date(info.getValue()).toLocaleString()}</span>,
    },
    {
      accessorKey: 'user',
      header: 'User',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }} className="text-sm">{info.getValue()}</span>,
    },
    {
      accessorKey: 'action',
      header: 'Action',
      cell: (info) => <span style={{ color: 'var(--text-primary)' }} className="font-medium">{info.getValue()}</span>,
    },
    {
      accessorKey: 'resource',
      header: 'Resource',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'details',
      header: 'Details',
      cell: (info) => <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">{info.getValue()}</span>,
    },
    {
      accessorKey: 'ip',
      header: 'IP Address',
      cell: (info) => <code style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }} className="px-2 py-1 rounded text-xs">{info.getValue()}</code>,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => (
        <span style={{ color: '#10b981' }} className="text-xs font-semibold flex items-center gap-1">
          <CheckCircle className="w-4 h-4" /> {info.getValue()}
        </span>
      ),
    },
  ];

  const integrationColumns = [
    {
      accessorKey: 'name',
      header: 'Integration',
      cell: (info) => <span style={{ color: 'var(--text-primary)' }} className="font-medium">{info.getValue()}</span>,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        const color = status === 'Connected' ? '#10b981' : status === 'Error' ? '#ef4444' : '#9ca3af';
        return <span style={{ backgroundColor: color + '20', color }} className="px-2 py-1 rounded text-xs font-semibold">{status}</span>;
      },
    },
    {
      accessorKey: 'lastSync',
      header: 'Last Sync',
      cell: (info) => <span style={{ color: 'var(--text-tertiary)' }}>{info.getValue() ? new Date(info.getValue()).toLocaleString() : '—'}</span>,
    },
    {
      accessorKey: 'eventsSent',
      header: 'Events Sent',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
  ];

  const notificationColumns = [
    {
      accessorKey: 'name',
      header: 'Rule Name',
      cell: (info) => <span style={{ color: 'var(--text-primary)' }} className="font-medium">{info.getValue()}</span>,
    },
    {
      accessorKey: 'trigger',
      header: 'Trigger',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => {
        const severity = info.getValue();
        const severityColors = { Critical: '#ef4444', High: '#f97316', Info: '#3b82f6' };
        const color = severityColors[severity] || '#6b7280';
        return <span style={{ backgroundColor: color + '20', color }} className="px-2 py-1 rounded text-xs font-semibold">{severity}</span>;
      },
    },
    {
      accessorKey: 'channels',
      header: 'Channels',
      cell: (info) => <span style={{ color: 'var(--text-secondary)' }} className="text-sm">{info.getValue()}</span>,
    },
    {
      accessorKey: 'recipients',
      header: 'Recipients',
      cell: (info) => <span style={{ color: 'var(--text-tertiary)' }} className="text-sm truncate">{info.getValue()}</span>,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        const color = status === 'Active' ? '#10b981' : '#9ca3af';
        return <span style={{ backgroundColor: color + '20', color }} className="px-2 py-1 rounded text-xs font-semibold">{status}</span>;
      },
    },
  ];

  const tabs = [
    { id: 'platform-health', label: 'Platform Health', icon: Shield },
    { id: 'integrations', label: 'Integrations', icon: Cloud },
    { id: 'api-keys', label: 'API Keys', icon: Lock },
    { id: 'audit-log', label: 'Audit Log', icon: Activity },
    { id: 'notifications', label: 'Notifications', icon: AlertTriangle },
    { id: 'general', label: 'General', icon: Zap },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>Settings</h1>
        <p style={{ color: 'var(--text-tertiary)' }} className="mt-1">Manage platform configuration, integrations, and security settings</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b" style={{ borderColor: 'var(--border-primary)' }}>
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors"
              style={{
                borderColor: isActive ? 'var(--accent-primary)' : 'transparent',
                color: isActive ? 'var(--accent-primary)' : 'var(--text-secondary)',
              }}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      <div>
        {/* Platform Health Tab */}
        {activeTab === 'platform-health' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <KpiCard title="Engines Online" value={`${engines.filter(e => e.status === 'Healthy').length}/${engines.length}`} subtitle="Healthy" icon={<Server className="w-5 h-5" />} color="green" />
              <KpiCard title="Engines Total" value={engines.length} subtitle="Registered" icon={<Activity className="w-5 h-5" />} color="green" />
              <KpiCard title="Healthy" value={engines.filter(e => e.status === 'Healthy').length} subtitle="Engines responding" icon={<Zap className="w-5 h-5" />} color="blue" />
              <KpiCard title="Unhealthy" value={engines.filter(e => e.status !== 'Healthy').length} subtitle="Needs attention" icon={<RefreshCw className="w-5 h-5" />} color={engines.filter(e => e.status !== 'Healthy').length > 0 ? 'orange' : 'green'} />
            </div>
            <div className="space-y-4">
              <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Engine Status</h3>
              <DataTable data={engines} columns={engineColumns} pageSize={10} loading={loading} emptyMessage="No engines found" />
            </div>
          </div>
        )}

        {/* Integrations Tab */}
        {activeTab === 'integrations' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Connected Integrations</h3>
              <button className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium transition-colors" style={{ backgroundColor: 'var(--accent-primary)' }}>
                <Plus className="w-4 h-4" /> Add Integration
              </button>
            </div>
            <DataTable data={integrations} columns={integrationColumns} pageSize={10} loading={loading} emptyMessage="No integrations configured" />
          </div>
        )}

        {/* API Keys Tab */}
        {activeTab === 'api-keys' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>API Keys</h3>
                <p style={{ color: 'var(--text-tertiary)' }} className="text-sm mt-1">Rotate keys every 90 days. Expiring keys highlighted in orange.</p>
              </div>
              <button className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium transition-colors" style={{ backgroundColor: 'var(--accent-primary)' }}>
                <Plus className="w-4 h-4" /> Generate New Key
              </button>
            </div>
            <DataTable data={apiKeys} columns={apiKeyColumns} pageSize={10} loading={loading} emptyMessage="No API keys found" />
          </div>
        )}

        {/* Audit Log Tab */}
        {activeTab === 'audit-log' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Audit Log</h3>
              <p style={{ color: 'var(--text-tertiary)' }} className="text-sm mt-1">Complete record of all platform activities and user actions</p>
            </div>
            <DataTable data={auditLog} columns={auditColumns} pageSize={10} loading={loading} emptyMessage="No audit entries found" />
          </div>
        )}

        {/* Notifications Tab */}
        {activeTab === 'notifications' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Notification Rules</h3>
              <button className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium transition-colors" style={{ backgroundColor: 'var(--accent-primary)' }}>
                <Plus className="w-4 h-4" /> Add Rule
              </button>
            </div>
            <DataTable data={notifications} columns={notificationColumns} pageSize={10} loading={loading} emptyMessage="No notification rules found" />
          </div>
        )}

        {/* General Tab */}
        {activeTab === 'general' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Tenant Settings */}
              <div className="rounded-lg border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Tenant Settings</h3>
                <div className="space-y-4">
                  <div>
                    <label style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium">Tenant Name</label>
                    <input type="text" defaultValue="Acme Corporation" className="w-full mt-2 px-3 py-2 rounded-lg border" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }} />
                  </div>
                  <div>
                    <label style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium">Default Timezone</label>
                    <select className="w-full mt-2 px-3 py-2 rounded-lg border" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
                      <option>US/Eastern</option>
                      <option>US/Central</option>
                      <option>US/Pacific</option>
                      <option>Europe/London</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium">Data Retention (Days)</label>
                    <input type="number" defaultValue={90} className="w-full mt-2 px-3 py-2 rounded-lg border" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }} />
                  </div>
                </div>
              </div>

              {/* Security Settings */}
              <div className="rounded-lg border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Security Settings</h3>
                <div className="space-y-4">
                  <div>
                    <label style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium">Session Timeout (Minutes)</label>
                    <input type="number" defaultValue={30} className="w-full mt-2 px-3 py-2 rounded-lg border" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }} />
                  </div>
                  <div>
                    <label style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium">Require MFA</label>
                    <select className="w-full mt-2 px-3 py-2 rounded-lg border" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
                      <option>Enforced</option>
                      <option>Optional</option>
                      <option>Disabled</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium">IP Whitelist (comma-separated)</label>
                    <input type="text" defaultValue="10.0.0.0/8, 192.168.0.0/16" className="w-full mt-2 px-3 py-2 rounded-lg border" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }} />
                  </div>
                </div>
              </div>

              {/* Scan Defaults */}
              <div className="rounded-lg border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Scan Defaults</h3>
                <div className="space-y-4">
                  <div>
                    <label style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium">Default Scan Frequency</label>
                    <select className="w-full mt-2 px-3 py-2 rounded-lg border" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
                      <option>Every 6 hours</option>
                      <option>Every 12 hours</option>
                      <option>Daily</option>
                      <option>Weekly</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium">Auto-Remediation</label>
                    <select className="w-full mt-2 px-3 py-2 rounded-lg border" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
                      <option>Disabled</option>
                      <option>Enabled (Low severity only)</option>
                      <option>Enabled (All)</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Framework Defaults */}
              <div className="rounded-lg border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Framework Defaults</h3>
                <div className="space-y-3">
                  {['CIS Benchmarks', 'NIST 800-53', 'PCI-DSS', 'ISO 27001', 'SOC 2'].map((fw) => (
                    <label key={fw} className="flex items-center gap-3">
                      <input type="checkbox" defaultChecked className="w-4 h-4 rounded" />
                      <span style={{ color: 'var(--text-secondary)' }} className="text-sm">{fw}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
            <button className="px-6 py-2 rounded-lg text-white font-medium transition-colors" style={{ backgroundColor: 'var(--accent-primary)' }}>Save Changes</button>
          </div>
        )}
      </div>
    </div>
  );
}
