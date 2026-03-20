'use client';

import { useEffect, useMemo, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Globe,
  ChevronRight,
  AlertTriangle,
  Shield,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Lock,
  Search,
  Database,
  HardDrive,
  Network,
  Server,
  Clock,
  MapPin,
  User,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CATEGORY_TABS = [
  { key: 'all', label: 'All' },
  { key: 'direct_public', label: 'Direct Public' },
  { key: 'databases', label: 'Databases' },
  { key: 'storage', label: 'Storage' },
  { key: 'load_balancers', label: 'Load Balancers' },
];

const CATEGORY_META = {
  direct_public: {
    label: 'Direct Internet Access',
    color: '#ef4444',
    bg: 'rgba(239,68,68,0.08)',
    border: 'rgba(239,68,68,0.25)',
    icon: Globe,
  },
  databases: {
    label: 'Publicly Accessible Databases',
    color: '#f97316',
    bg: 'rgba(249,115,22,0.08)',
    border: 'rgba(249,115,22,0.25)',
    icon: Database,
  },
  storage: {
    label: 'Public Storage',
    color: '#eab308',
    bg: 'rgba(234,179,8,0.08)',
    border: 'rgba(234,179,8,0.25)',
    icon: HardDrive,
  },
  load_balancers: {
    label: 'Load Balancers',
    color: '#3b82f6',
    bg: 'rgba(59,130,246,0.08)',
    border: 'rgba(59,130,246,0.25)',
    icon: Network,
  },
};

const CATEGORY_ORDER = ['direct_public', 'databases', 'storage', 'load_balancers'];

const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low'];

const SEV_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
};

/**
 * Map a resource to its exposure category key based on resource_type / exposure_type.
 */
function categoriseResource(r) {
  const type = (r.resourceType || r.resource_type || '').toLowerCase();
  const exposure = (r.exposureType || r.exposure_type || '').toLowerCase();

  if (type.includes('rds') || type.includes('database') || type.includes('dynamodb') || type.includes('redshift') || type.includes('aurora')) {
    return 'databases';
  }
  if (type.includes('s3') || type.includes('storage') || type.includes('bucket') || exposure.includes('acl') || exposure.includes('public bucket')) {
    return 'storage';
  }
  if (type.includes('alb') || type.includes('elb') || type.includes('nlb') || type.includes('loadbalancer') || type.includes('load_balancer')) {
    return 'load_balancers';
  }
  return 'direct_public';
}

/**
 * Remediation advice keyed by category.
 */
const REMEDIATION_BY_CATEGORY = {
  direct_public: [
    'Restrict Security Group inbound rules to specific CIDR ranges',
    'Remove 0.0.0.0/0 rules for management ports (22, 3389)',
    'Use AWS Systems Manager Session Manager instead of direct SSH',
    'Consider placing the resource behind a load balancer or bastion host',
  ],
  databases: [
    'Set "Publicly Accessible" to No in the database configuration',
    'Restrict Security Group to VPC CIDR or specific application subnets',
    'Place the database in a private subnet with no internet gateway route',
    'Enable encryption in transit and rotate credentials',
  ],
  storage: [
    'Enable S3 Block Public Access on the bucket and account level',
    'Remove public ACL grants for All Users / Authenticated Users',
    'Audit bucket policy for overly permissive Allow statements',
    'Enable server-side encryption and access logging',
  ],
  load_balancers: [
    'Redirect HTTP (port 80) to HTTPS with a permanent 301 redirect',
    'Enforce minimum TLS 1.2 in the HTTPS listener security policy',
    'Enable WAF WebACL on the load balancer',
    'Review target group health checks and listener rules',
  ],
};

// ---------------------------------------------------------------------------
// Exposure Path SVG
// ---------------------------------------------------------------------------

function ExposurePathDiagram({ resource, category }) {
  const sevColor = SEV_COLOR[resource.severity] || '#6b7280';
  const ports = parsePortList(resource);
  const portLabel = ports.length > 0 ? ports[0] : '443';
  const resourceLabel = resource.resourceName || resource.resource_name || 'Resource';
  const resourceType = resource.resourceType || resource.resource_type || '';

  return (
    <svg
      viewBox="0 0 520 70"
      className="w-full"
      style={{ maxWidth: 520, height: 70 }}
      aria-label={`Exposure path: Internet to ${resourceLabel}`}
    >
      {/* Internet node */}
      <circle cx="40" cy="30" r="18" fill="rgba(239,68,68,0.12)" stroke="#ef4444" strokeWidth="1.5" />
      <text x="40" y="34" textAnchor="middle" fill="#ef4444" fontSize="11" fontWeight="700">
        WWW
      </text>
      <text x="40" y="62" textAnchor="middle" fill="var(--text-muted)" fontSize="9">
        Internet
      </text>

      {/* Arrow 1: Internet to Security Group */}
      <line x1="60" y1="30" x2="175" y2="30" stroke={sevColor} strokeWidth="1.5" strokeDasharray="4 2" opacity="0.6" />
      <polygon points="175,25 185,30 175,35" fill={sevColor} opacity="0.7" />
      {/* Port label on arrow */}
      <rect x="98" y="16" width="48" height="16" rx="4" fill="var(--bg-secondary)" stroke="var(--border-primary)" strokeWidth="0.5" />
      <text x="122" y="28" textAnchor="middle" fill={sevColor} fontSize="9" fontWeight="600" fontFamily="monospace">
        :{portLabel}
      </text>

      {/* Security Group node */}
      <rect x="190" y="14" width="80" height="32" rx="6" fill="var(--bg-secondary)" stroke="var(--border-primary)" strokeWidth="1" />
      <text x="230" y="34" textAnchor="middle" fill="var(--text-secondary)" fontSize="9" fontWeight="600">
        SG / NaCL
      </text>
      <text x="230" y="62" textAnchor="middle" fill="var(--text-muted)" fontSize="9">
        Firewall
      </text>

      {/* Arrow 2: SG to Resource */}
      <line x1="272" y1="30" x2="370" y2="30" stroke={sevColor} strokeWidth="1.5" opacity="0.5" />
      <polygon points="370,25 380,30 370,35" fill={sevColor} opacity="0.7" />

      {/* Resource node */}
      <rect x="385" y="12" width="120" height="36" rx="8" fill={`${sevColor}10`} stroke={sevColor} strokeWidth="1.5" />
      <text x="445" y="28" textAnchor="middle" fill="var(--text-primary)" fontSize="10" fontWeight="700">
        {resourceLabel.length > 16 ? resourceLabel.slice(0, 14) + '..' : resourceLabel}
      </text>
      <text x="445" y="42" textAnchor="middle" fill="var(--text-muted)" fontSize="8">
        {resourceType.length > 20 ? resourceType.slice(0, 18) + '..' : resourceType}
      </text>
      <text x="445" y="62" textAnchor="middle" fill="var(--text-muted)" fontSize="9">
        Resource
      </text>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parsePortList(resource) {
  const raw = resource.openPorts || resource.open_ports || '';
  if (Array.isArray(raw)) return raw.map(String).filter(Boolean);
  return String(raw)
    .split(/[,;\s]+/)
    .map(p => p.replace(/^:/, '').trim())
    .filter(p => p && p !== 'N/A');
}

function formatDetectedTime(ts) {
  if (!ts) return 'Unknown';
  try {
    const date = new Date(ts);
    const now = new Date();
    const diffMs = now - date;
    const diffH = Math.floor(diffMs / (1000 * 60 * 60));
    if (diffH < 1) return 'Just now';
    if (diffH < 24) return `${diffH}h ago`;
    const diffD = Math.floor(diffH / 24);
    if (diffD < 30) return `${diffD}d ago`;
    return date.toLocaleDateString();
  } catch {
    return String(ts);
  }
}

// ---------------------------------------------------------------------------
// ExposureCard
// ---------------------------------------------------------------------------

function ExposureCard({ resource, category }) {
  const [expanded, setExpanded] = useState(false);
  const severity = resource.severity || 'medium';
  const sevColor = SEV_COLOR[severity] || '#6b7280';
  const ports = parsePortList(resource);
  const remediations = REMEDIATION_BY_CATEGORY[category] || REMEDIATION_BY_CATEGORY.direct_public;

  const resourceName = resource.resourceName || resource.resource_name || 'Unknown Resource';
  const resourceType = resource.resourceType || resource.resource_type || '';
  const account = resource.account || resource.accountId || '';
  const region = resource.region || '';
  const detectedAt = resource.detectedAt || resource.detected_at || resource.created_at || '';
  const resourceArn = resource.resourceArn || resource.resource_arn || '';
  const riskScore = resource.riskScore ?? resource.risk_score ?? '-';

  return (
    <div
      className="rounded-xl border overflow-hidden transition-all duration-200 hover:border-opacity-60"
      style={{
        backgroundColor: 'var(--bg-card)',
        borderColor: 'var(--border-primary)',
        borderLeft: `4px solid ${sevColor}`,
      }}
    >
      {/* Main content */}
      <div className="p-5">
        {/* Top row: severity + resource name + type + risk */}
        <div className="flex items-start justify-between gap-4 mb-3">
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <SeverityBadge severity={severity} />
            <div className="min-w-0">
              <p
                className="text-sm font-bold leading-tight truncate"
                style={{ color: 'var(--text-primary)' }}
                title={resourceName}
              >
                {resourceName}
              </p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
                {resourceType}
              </p>
            </div>
          </div>
          <div className="text-right flex-shrink-0">
            <p className="text-[10px] uppercase tracking-wider font-medium" style={{ color: 'var(--text-muted)' }}>
              Risk
            </p>
            <p className="text-xl font-black leading-none" style={{ color: sevColor }}>
              {riskScore}
            </p>
          </div>
        </div>

        {/* Exposure path diagram */}
        <div
          className="rounded-lg p-3 mb-3"
          style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}
        >
          <ExposurePathDiagram resource={resource} category={category} />
        </div>

        {/* Port badges + metadata row */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center flex-wrap gap-1.5">
            {ports.length > 0 ? (
              ports.map((port) => (
                <span
                  key={port}
                  className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    color: 'var(--text-secondary)',
                    border: '1px solid var(--border-primary)',
                  }}
                >
                  :{port}
                </span>
              ))
            ) : (
              <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>No ports listed</span>
            )}
          </div>

          <div className="flex items-center gap-3 text-[11px]" style={{ color: 'var(--text-muted)' }}>
            {account && (
              <span className="flex items-center gap-1">
                <User className="w-3 h-3" />
                {account}
              </span>
            )}
            {region && (
              <span className="flex items-center gap-1">
                <MapPin className="w-3 h-3" />
                {region}
              </span>
            )}
            {detectedAt && (
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {formatDetectedTime(detectedAt)}
              </span>
            )}
          </div>
        </div>

        {/* Expand / action row */}
        <div className="flex items-center justify-between mt-3 pt-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-4">
            <a
              href={`/threats`}
              className="inline-flex items-center gap-1 text-xs font-medium hover:opacity-75 transition-opacity"
              style={{ color: '#ef4444' }}
            >
              <ExternalLink className="w-3.5 h-3.5" />
              View Threat
            </a>
            <a
              href={`/inventory`}
              className="inline-flex items-center gap-1 text-xs font-medium hover:opacity-75 transition-opacity"
              style={{ color: 'var(--accent-primary, #3b82f6)' }}
            >
              <ExternalLink className="w-3.5 h-3.5" />
              View in Inventory
            </a>
          </div>
          <button
            onClick={() => setExpanded((p) => !p)}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg transition-colors hover:opacity-75"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
          >
            {expanded ? (
              <>
                Hide Remediation <ChevronUp className="w-3.5 h-3.5" />
              </>
            ) : (
              <>
                Show Remediation <ChevronDown className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>
      </div>

      {/* Expanded remediation panel */}
      {expanded && (
        <div
          className="border-t px-5 py-4 space-y-4"
          style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}
        >
          {/* ARN */}
          {resourceArn && (
            <div>
              <p
                className="text-[10px] font-bold uppercase tracking-wider mb-1"
                style={{ color: 'var(--text-muted)' }}
              >
                Resource ARN
              </p>
              <p className="text-xs font-mono break-all" style={{ color: 'var(--text-secondary)' }}>
                {resourceArn}
              </p>
            </div>
          )}

          {/* Remediation */}
          <div>
            <p
              className="text-[10px] font-bold uppercase tracking-wider mb-2 flex items-center gap-1.5"
              style={{ color: 'var(--text-muted)' }}
            >
              <Lock className="w-3 h-3" />
              Recommended Remediation
            </p>
            <div className="space-y-2">
              {remediations.map((step, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span
                    className="flex-shrink-0 w-5 h-5 rounded-full text-[10px] font-bold flex items-center justify-center mt-0.5"
                    style={{ backgroundColor: `${sevColor}20`, color: sevColor }}
                  >
                    {i + 1}
                  </span>
                  <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                    {step}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

export default function InternetExposedPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  // Fetch data from BFF
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetchView('threats/internet-exposed');
        if (cancelled) return;
        if (res?.error) {
          setError(res.error);
        } else {
          setData(res);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err?.message || 'Failed to load internet-exposed resources');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, []);

  // Normalize resources array from various possible response shapes
  const resources = useMemo(() => {
    if (!data) return [];
    // BFF shape: { resources: [...] } or { exposed_resources: [...] } or top-level array
    const raw = data.resources || data.exposedResources || data.exposed_resources || (Array.isArray(data) ? data : []);
    return raw;
  }, [data]);

  // KPI values -- prefer BFF-provided kpi object, fall back to counting
  const kpi = useMemo(() => {
    if (data?.kpi) return data.kpi;
    const total = resources.length;
    const critical = resources.filter((r) => r.severity === 'critical').length;
    const high = resources.filter((r) => r.severity === 'high').length;
    const medium = resources.filter((r) => r.severity === 'medium').length;
    return { total, critical, high, medium };
  }, [data, resources]);

  // Categorise each resource
  const categorisedResources = useMemo(() => {
    return resources.map((r) => ({
      ...r,
      _category: r.category || categoriseResource(r),
    }));
  }, [resources]);

  // Apply filters: tab, search, severity
  const filteredResources = useMemo(() => {
    let list = categorisedResources;

    // Category tab
    if (activeTab !== 'all') {
      list = list.filter((r) => r._category === activeTab);
    }

    // Severity
    if (severityFilter !== 'all') {
      list = list.filter((r) => r.severity === severityFilter);
    }

    // Search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((r) => {
        const name = (r.resourceName || r.resource_name || '').toLowerCase();
        const arn = (r.resourceArn || r.resource_arn || '').toLowerCase();
        const type = (r.resourceType || r.resource_type || '').toLowerCase();
        return name.includes(q) || arn.includes(q) || type.includes(q);
      });
    }

    return list;
  }, [categorisedResources, activeTab, severityFilter, searchQuery]);

  // Group filtered resources by category for display
  const groupedResources = useMemo(() => {
    const acc = {};
    filteredResources.forEach((r) => {
      const cat = r._category;
      if (!acc[cat]) acc[cat] = [];
      acc[cat].push(r);
    });
    return CATEGORY_ORDER.filter((c) => acc[c]?.length).map((c) => ({
      category: c,
      items: acc[c],
    }));
  }, [filteredResources]);

  // Tab counts
  const tabCounts = useMemo(() => {
    const counts = { all: categorisedResources.length };
    CATEGORY_ORDER.forEach((c) => {
      counts[c] = categorisedResources.filter((r) => r._category === c).length;
    });
    return counts;
  }, [categorisedResources]);

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  return (
    <div className="space-y-6">
      {/* Header + Breadcrumb */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <button
            onClick={() => router.push('/threats')}
            className="text-sm hover:opacity-80 transition-opacity"
            style={{ color: 'var(--text-muted)' }}
          >
            Threats
          </button>
          <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            Internet Exposed
          </span>
        </div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Internet Exposed Resources
        </h1>
      </div>

      {/* Threats Sub-Navigation */}
      <ThreatsSubNav />

      {/* KPI Strip */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-32 rounded-xl animate-pulse"
              style={{ backgroundColor: 'var(--bg-card)' }}
            />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            title="Total Exposed"
            value={kpi.total ?? 0}
            subtitle="Resources reachable from internet"
            icon={<Globe className="w-5 h-5" />}
            color="red"
          />
          <KpiCard
            title="Critical"
            value={kpi.critical ?? 0}
            subtitle="Immediate remediation required"
            icon={<AlertTriangle className="w-5 h-5" />}
            color="red"
          />
          <KpiCard
            title="High"
            value={kpi.high ?? 0}
            subtitle="High exposure risk"
            icon={<AlertTriangle className="w-5 h-5" />}
            color="orange"
          />
          <KpiCard
            title="Medium"
            value={kpi.medium ?? 0}
            subtitle="Moderate exposure"
            icon={<Shield className="w-5 h-5" />}
            color="yellow"
          />
        </div>
      )}

      {/* Category Tabs */}
      <div
        className="flex items-center gap-1 p-1 rounded-lg overflow-x-auto"
        style={{ backgroundColor: 'var(--bg-secondary)' }}
      >
        {CATEGORY_TABS.map((tab) => {
          const isActive = activeTab === tab.key;
          const count = tabCounts[tab.key] ?? 0;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium whitespace-nowrap transition-all duration-200"
              style={{
                backgroundColor: isActive ? 'var(--bg-card)' : 'transparent',
                color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
                boxShadow: isActive ? '0 1px 3px rgba(0,0,0,0.2)' : 'none',
              }}
            >
              {tab.label}
              <span
                className="text-xs px-1.5 py-0.5 rounded-full font-semibold"
                style={{
                  backgroundColor: isActive ? 'rgba(59,130,246,0.15)' : 'var(--bg-tertiary)',
                  color: isActive ? '#3b82f6' : 'var(--text-muted)',
                }}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Filters: Search + Severity */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
            style={{ color: 'var(--text-muted)' }}
          />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by resource name, ARN, or type..."
            className="w-full pl-10 pr-4 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-primary)',
              borderColor: 'var(--border-primary)',
            }}
          />
        </div>

        {/* Severity dropdown */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-2 rounded-lg border text-sm font-medium focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors"
          style={{
            backgroundColor: 'var(--bg-tertiary)',
            color: 'var(--text-primary)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {/* Result count */}
        <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>
          {filteredResources.length} resource{filteredResources.length !== 1 ? 's' : ''} found
        </span>
      </div>

      {/* Error State */}
      {error && !loading && (
        <div
          className="rounded-lg p-4 border"
          style={{ backgroundColor: 'rgba(220,38,38,0.08)', borderColor: '#ef4444' }}
        >
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" style={{ color: '#ef4444' }} />
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              {error}
            </p>
          </div>
        </div>
      )}

      {/* Loading state */}
      {loading && <LoadingSkeleton rows={6} cols={3} />}

      {/* Empty state */}
      {!loading && !error && resources.length === 0 && (
        <EmptyState
          icon={<Globe className="w-12 h-12" />}
          title="No Internet-Exposed Resources"
          description="No resources with public internet exposure were detected. This is a positive security posture indicator."
        />
      )}

      {/* No results from filters */}
      {!loading && resources.length > 0 && filteredResources.length === 0 && (
        <EmptyState
          icon={<Search className="w-12 h-12" />}
          title="No Matching Resources"
          description="No resources match the current filter criteria. Try adjusting the category, severity, or search query."
          action={{
            label: 'Clear Filters',
            onClick: () => {
              setActiveTab('all');
              setSeverityFilter('all');
              setSearchQuery('');
            },
          }}
        />
      )}

      {/* Grouped resource cards */}
      {!loading && filteredResources.length > 0 && (
        <div className="space-y-8">
          {groupedResources.map(({ category, items }) => {
            const meta = CATEGORY_META[category];
            const CatIcon = meta?.icon || Server;
            return (
              <div key={category}>
                {/* Category section header */}
                <div className="flex items-center gap-3 mb-4">
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: meta?.bg || 'var(--bg-tertiary)' }}
                  >
                    <CatIcon className="w-4 h-4" style={{ color: meta?.color || 'var(--text-muted)' }} />
                  </div>
                  <h2 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
                    {meta?.label || category}
                  </h2>
                  <span
                    className="text-xs px-2.5 py-0.5 rounded-full font-semibold"
                    style={{
                      backgroundColor: meta?.bg || 'var(--bg-tertiary)',
                      color: meta?.color || 'var(--text-muted)',
                      border: `1px solid ${meta?.border || 'var(--border-primary)'}`,
                    }}
                  >
                    {items.length} resource{items.length !== 1 ? 's' : ''}
                  </span>
                </div>

                {/* Cards */}
                <div className="space-y-3">
                  {items.map((resource, i) => (
                    <ExposureCard
                      key={resource.uid || resource.resource_arn || resource.resourceArn || `${category}-${i}`}
                      resource={resource}
                      category={category}
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
