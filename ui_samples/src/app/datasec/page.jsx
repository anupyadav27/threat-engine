'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Database,
  Lock,
  AlertTriangle,
  Globe,
  Activity,
  Shield,
  HardDrive,
  MapPin,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import FilterBar from '@/components/shared/FilterBar';
import MetricStrip from '@/components/shared/MetricStrip';
import DataTable from '@/components/shared/DataTable';
import SearchBar from '@/components/shared/SearchBar';
import SeverityBadge from '@/components/shared/SeverityBadge';
import SeverityDonut from '@/components/charts/SeverityDonut';

/**
 * Enterprise Data Security and Classification Page
 * Comprehensive data catalog, classification, encryption, residency, and access monitoring
 */
export default function DataSecurityPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [realCatalog, setRealCatalog] = useState([]);
  const [realClassification, setRealClassification] = useState([]);
  const [dlpViolations, setDlpViolations] = useState([]);
  const [encryptionData, setEncryptionData] = useState([]);
  const [dataResidency, setDataResidency] = useState([]);
  const [accessMonitoring, setAccessMonitoring] = useState([]);
  const [catalogSearch, setCatalogSearch] = useState('');
  const [activeFilters, setActiveFilters] = useState({ classification: '', data_type: '' });

  const { provider, account, region, filterSummary } = useGlobalFilter();

  const handleFilterChange = (key, value) => {
    setActiveFilters(prev => ({ ...prev, [key]: value }));
  };

  // BFF already scope-filters catalog
  const activeCatalog = realCatalog;
  const activeClassification = realClassification;
  const scopeFiltered = realCatalog;

  // Local filter options (provider and region now handled by global filter)
  const dsFilterDefs = [
    { key: 'classification', label: 'Classification',   options: ['PII', 'PHI', 'PCI', 'Confidential', 'Internal'] },
    { key: 'data_type',      label: 'Store Type',       options: ['RDS', 'S3', 'DynamoDB', 'Redshift', 'BigQuery', 'CosmosDB'] },
  ];

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchView('datasec', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.catalog)          setRealCatalog(data.catalog);
        if (data.classifications)  setRealClassification(data.classifications);
        if (data.dlp)              setDlpViolations(data.dlp);
        if (data.encryption)       setEncryptionData(data.encryption);
        if (data.residency)        setDataResidency(data.residency);
        if (data.accessMonitoring) setAccessMonitoring(data.accessMonitoring);
      } catch (err) {
        console.warn('Error fetching data security data:', err);
        setError(err?.message || 'Failed to load data security data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  // Calculate KPI stats from scopeFiltered
  const dataStoresMonitored = scopeFiltered.length;
  const sensitiveDataStores = scopeFiltered.filter(d => ['PII', 'PHI', 'PCI', 'Confidential'].includes(d.classification)).length;
  const unencryptedStores = scopeFiltered.filter(d => !d.encryption || d.encryption === 'None' || d.encryption === 'Unknown').length;
  const publicAccessStores = scopeFiltered.filter(d => d.public_access).length;
  const crossRegionData = [...new Set(scopeFiltered.map(d => d.region))].length;
  const dlpViolationCount = dlpViolations.length;
  const encryptionKeyIssues = encryptionData.filter(e => !e.rotation).length;
  const retentionPolicyViolations = 0;
  const dataRiskScore = Math.min(100, Math.round(
    (unencryptedStores + publicAccessStores * 2) / Math.max(dataStoresMonitored, 1) * 100
  )) || 0;

  // MetricStrip computed values
  const sensitiveExposed = scopeFiltered.filter(d =>
    ['PII', 'PHI', 'Sensitive'].includes(d.classification) &&
    (d.public_access === true || d.encryption === 'None' || d.encryption === false)
  ).length;
  const unencryptedCount = scopeFiltered.filter(d =>
    d.encrypted === false || d.encryption === 'None' || d.encryption_status === 'unencrypted'
  ).length;
  const classifiedPct = Math.round(
    scopeFiltered.filter(d => d.classification && d.classification !== 'Unknown').length /
    Math.max(scopeFiltered.length, 1) * 100
  );
  const encryptedPct = Math.round(
    scopeFiltered.filter(d =>
      d.encrypted === true || (d.encryption && d.encryption !== 'None' && d.encryption !== 'Unknown')
    ).length / Math.max(scopeFiltered.length, 1) * 100
  );

  // Classification summary — real data only
  const classificationColorMap = { PII: '#ef4444', PHI: '#f97316', PCI: '#eab308', Confidential: '#8b5cf6', Secrets: '#ec4899', Internal: '#3b82f6', Public: '#6b7280' };
  const classificationData = Object.entries(
    activeClassification.reduce((acc, c) => { acc[c.type] = (acc[c.type] || 0) + (c.count || 1); return acc; }, {})
  ).map(([name, value]) => ({ name, value, color: classificationColorMap[name] || '#6b7280' }));

  // Tab definitions
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'catalog', label: 'Data Catalog' },
    { id: 'classification', label: 'Classification' },
    { id: 'encryption', label: 'Encryption' },
    { id: 'residency', label: 'Data Residency' },
    { id: 'access', label: 'Access Monitoring' },
    { id: 'dlp', label: 'DLP' },
  ];

  // Data Catalog columns
  const catalogColumns = [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'type',
      header: 'Type',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'region',
      header: 'Region',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'classification',
      header: 'Classification',
      cell: (info) => {
        const classType = info.getValue();
        const colorMap = {
          PII: 'bg-red-500/20 text-red-300',
          PHI: 'bg-orange-500/20 text-orange-300',
          PCI: 'bg-yellow-500/20 text-yellow-300',
          Confidential: 'bg-purple-500/20 text-purple-300',
          Internal: 'bg-blue-500/20 text-blue-300',
          Public: 'bg-slate-500/20 text-slate-300',
        };
        return (
          <span className={`text-xs px-2 py-1 rounded ${colorMap[classType] || 'bg-slate-700 text-slate-300'}`}>
            {classType}
          </span>
        );
      },
    },
    {
      accessorKey: 'encryption',
      header: 'Encryption',
      cell: (info) => (
        <div className="flex items-center gap-2">
          {info.getValue() !== 'None' ? (
            <Lock className="w-4 h-4 text-green-400" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-red-400" />
          )}
          <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
            {info.getValue()}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'owner',
      header: 'Owner',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
  ];

  // Classification columns
  const classificationColumns = [
    {
      accessorKey: 'name',
      header: 'Pattern',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'type',
      header: 'Type',
      cell: (info) => {
        const typeMap = {
          PII: 'bg-red-500/20 text-red-300',
          PHI: 'bg-orange-500/20 text-orange-300',
          PCI: 'bg-yellow-500/20 text-yellow-300',
          Secrets: 'bg-pink-500/20 text-pink-300',
          Public: 'bg-blue-500/20 text-blue-300',
        };
        return (
          <span className={`text-xs px-2 py-1 rounded ${typeMap[info.getValue()]}`}>
            {info.getValue()}
          </span>
        );
      },
    },
    {
      accessorKey: 'count',
      header: 'Records Found',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
          {info.getValue().toLocaleString()}
        </span>
      ),
    },
    {
      accessorKey: 'locations',
      header: 'Locations',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()} stores</span>
      ),
    },
    {
      accessorKey: 'confidence',
      header: 'Confidence',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
          {info.getValue()}%
        </span>
      ),
    },
  ];

  // Encryption columns
  const encryptionColumns = [
    {
      accessorKey: 'resource',
      header: 'Resource',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'type',
      header: 'Encryption Type',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'rotation',
      header: 'Key Rotation',
      cell: (info) => (
        <span className="text-sm">{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        return status === 'encrypted' ? (
          <span className="text-xs px-2 py-1 rounded bg-green-500/20 text-green-400">Encrypted</span>
        ) : (
          <span className="text-xs px-2 py-1 rounded bg-red-500/20 text-red-400">Unencrypted</span>
        );
      },
    },
  ];

  // Data Residency columns
  const residencyColumns = [
    {
      accessorKey: 'region',
      header: 'Region',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'assets',
      header: 'Data Stores',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'compliance',
      header: 'Compliance Frameworks',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        return status === 'compliant' ? (
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500" />
            <span className="text-sm text-green-400">Compliant</span>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-red-500" />
            <span className="text-sm text-red-400">Non-compliant</span>
          </div>
        );
      },
    },
  ];

  // Access Monitoring columns
  const accessColumns = [
    {
      accessorKey: 'timestamp',
      header: 'Timestamp',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
          {new Date(info.getValue()).toLocaleString()}
        </span>
      ),
    },
    {
      accessorKey: 'resource',
      header: 'Resource',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'user',
      header: 'User/Service',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'action',
      header: 'Action',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'location',
      header: 'Location',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'anomaly',
      header: 'Anomaly',
      cell: (info) => (
        info.getValue() ? (
          <span className="text-xs px-2 py-1 rounded bg-orange-500/20 text-orange-400">Detected</span>
        ) : (
          <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>Normal</span>
        )
      ),
    },
  ];

  // DLP columns
  const dlpColumns = [
    {
      accessorKey: 'type',
      header: 'Violation Type',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'resource',
      header: 'Resource',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'data_type',
      header: 'Data Type',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'action',
      header: 'Action Taken',
      cell: (info) => (
        <span className="text-sm">{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'timestamp',
      header: 'Timestamp',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
          {new Date(info.getValue()).toLocaleDateString()}
        </span>
      ),
    },
  ];

  if (error) {
    return (
      <div className="rounded-xl p-8 border text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <AlertTriangle className="w-10 h-10 mx-auto mb-3" style={{ color: '#ef4444' }} />
        <p className="text-base font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Failed to load data security data</p>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>Data Security</h1>
        {filterSummary && (
          <p className="text-xs mt-0.5 mb-2" style={{ color: 'var(--text-tertiary)' }}>
            <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
            <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{filterSummary}</span>
          </p>
        )}
        <p className="mt-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
          Data catalog, classification, encryption, residency, and access monitoring
        </p>
      </div>

      {/* Hierarchical Filter Bar */}
      <FilterBar
        filters={dsFilterDefs}
        activeFilters={activeFilters}
        onFilterChange={handleFilterChange}
      />

      {/* Tab Navigation */}
      <div className="border-b transition-colors duration-200" style={{ borderColor: 'var(--border-primary)' }}>
        <div className="flex gap-1 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors border-b-2 ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent transition-colors duration-200 hover:opacity-80'
              }`}
              style={activeTab !== tab.id ? { color: 'var(--text-tertiary)' } : {}}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* MetricStrip KPIs */}
          <MetricStrip groups={[
            {
              label: '🔴 DATA RISK',
              color: 'var(--accent-danger)',
              cells: [
                { label: 'SENSITIVE EXPOSED', value: sensitiveExposed, valueColor: 'var(--severity-critical)', noTrend: true, context: 'PII/PHI + public' },
                { label: 'UNENCRYPTED STORES', value: unencryptedCount, valueColor: 'var(--severity-high)', delta: -3, deltaGoodDown: true, context: 'vs last 7d' },
                { label: 'DLP VIOLATIONS', value: dlpViolationCount, valueColor: 'var(--severity-critical)', noTrend: true, context: 'policy breaches' },
              ],
            },
            {
              label: '🔵 COVERAGE',
              color: 'var(--accent-primary)',
              cells: [
                { label: 'STORES MONITORED', value: scopeFiltered.length },
                { label: 'CLASSIFIED', value: classifiedPct + '%', valueColor: 'var(--accent-success)', delta: +4, context: 'vs last month' },
                { label: 'ENCRYPTED', value: encryptedPct + '%', valueColor: 'var(--accent-success)', context: 'at-rest encryption' },
              ],
            },
          ]} />

          {/* Data Risk Score & Classification */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Risk Gauge */}
            <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                Data Risk Score
              </h3>
              <div className="flex justify-center items-center h-40">
                <div className="text-center">
                  <div className="text-4xl font-bold" style={{ color: '#f97316' }}>
                    {dataRiskScore}/100
                  </div>
                  <p className="text-sm mt-2 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
                    Moderate risk
                  </p>
                </div>
              </div>
            </div>

            {/* Classification Distribution */}
            <div className="lg:col-span-2 rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                Classification Distribution
              </h3>
              <div className="flex justify-center">
                {classificationData.length > 0 ? (
                  <SeverityDonut data={classificationData} title="Records" />
                ) : (
                  <p className="text-sm py-10" style={{ color: 'var(--text-muted)' }}>No classification data available</p>
                )}
              </div>
            </div>
          </div>

          {/* Recent DLP Violations */}
          <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
            <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              Recent DLP Violations
            </h3>
            {dlpViolations.length === 0 ? (
              <p className="text-sm text-center py-6" style={{ color: 'var(--text-muted)' }}>No DLP violations detected</p>
            ) : (
              <div className="space-y-3">
                {dlpViolations.slice(0, 5).map((violation, idx) => (
                  <div
                    key={violation.id || idx}
                    className="p-4 border rounded-lg transition-colors duration-200"
                    style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                          {violation.type || violation.violation_type || violation.title || 'DLP Violation'}
                        </p>
                        <p className="text-xs mt-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
                          {violation.resource && `Resource: ${violation.resource}`}{violation.data_type && ` | Data: ${violation.data_type}`}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={violation.severity} />
                        {violation.action && (
                          <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                            {violation.action}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Data Catalog Tab */}
      {activeTab === 'catalog' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                Data Stores
              </h2>
              <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
                Complete inventory of data repositories and classifications
              </p>
            </div>
            <SearchBar
              value={catalogSearch}
              onChange={setCatalogSearch}
              placeholder="Search by name, type, or classification..."
            />
          </div>
          <DataTable
            data={activeCatalog.filter(d => !catalogSearch || (d.name + ' ' + d.type + ' ' + d.classification + ' ' + d.provider).toLowerCase().includes(catalogSearch.toLowerCase()))}
            columns={catalogColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No data stores found"
          />
        </div>
      )}

      {/* Classification Tab */}
      {activeTab === 'classification' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              Sensitive Data Patterns
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Detected PII, PHI, PCI, and other sensitive data patterns with confidence scores
            </p>
          </div>
          <DataTable
            data={activeClassification}
            columns={classificationColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No classified patterns found"
          />
        </div>
      )}

      {/* Encryption Tab */}
      {activeTab === 'encryption' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              Encryption Status
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Encryption type and key rotation status for all data stores
            </p>
          </div>
          <DataTable
            data={encryptionData}
            columns={encryptionColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No encryption records found"
          />
        </div>
      )}

      {/* Data Residency Tab */}
      {activeTab === 'residency' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              Regional Compliance
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Data residency and compliance framework coverage by region
            </p>
          </div>
          <DataTable
            data={dataResidency}
            columns={residencyColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No regions found"
          />
        </div>
      )}

      {/* Access Monitoring Tab */}
      {activeTab === 'access' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              Recent Access Events
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Data access events with anomaly detection and location tracking
            </p>
          </div>
          <DataTable
            data={accessMonitoring}
            columns={accessColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No access events found"
          />
        </div>
      )}

      {/* DLP Tab */}
      {activeTab === 'dlp' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              DLP Violations
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Data loss prevention violations with action taken and severity assessment
            </p>
          </div>
          <DataTable
            data={dlpViolations}
            columns={dlpColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No violations found"
          />
        </div>
      )}
    </div>
  );
}
