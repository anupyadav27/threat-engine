'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Globe, ChevronRight, AlertTriangle, Shield,
  ExternalLink, ChevronDown, ChevronUp, Lock, Wifi,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import CloudServiceIcon, { getServiceColor } from '@/components/shared/CloudServiceIcon';

// ── Exposure categories ───────────────────────────────────────────────────────
const EXPOSURE_CATEGORIES = {
  'Direct Internet Access': {
    color: '#ef4444',
    bg:    'rgba(239,68,68,0.1)',
    border:'rgba(239,68,68,0.25)',
    match: r => r.resource_type === 'EC2 Instance' || (r.exposure_type.toLowerCase().includes('public ip')),
  },
  'Publicly Accessible Database': {
    color: '#f97316',
    bg:    'rgba(249,115,22,0.1)',
    border:'rgba(249,115,22,0.25)',
    match: r => r.resource_type === 'RDS Database' || r.resource_type.toLowerCase().includes('database'),
  },
  'Public Storage': {
    color: '#eab308',
    bg:    'rgba(234,179,8,0.1)',
    border:'rgba(234,179,8,0.25)',
    match: r => r.resource_type === 'S3 Bucket' || r.exposure_type.toLowerCase().includes('acl'),
  },
  'Load Balancer Exposed': {
    color: '#3b82f6',
    bg:    'rgba(59,130,246,0.1)',
    border:'rgba(59,130,246,0.25)',
    match: r => r.resource_type === 'ALB' || r.resource_type.toLowerCase().includes('loadbalancer') || r.resource_type.toLowerCase().includes('alb'),
  },
};

const CATEGORY_ORDER = [
  'Direct Internet Access',
  'Publicly Accessible Database',
  'Public Storage',
  'Load Balancer Exposed',
];

const categorise = (resource) => {
  for (const cat of CATEGORY_ORDER) {
    if (EXPOSURE_CATEGORIES[cat].match(resource)) return cat;
  }
  return 'Direct Internet Access';
};

// Remediation advice per resource type
const REMEDIATION = {
  'EC2 Instance': [
    'Restrict Security Group inbound rules to specific CIDR ranges',
    'Remove 0.0.0.0/0 rules for management ports (22, 3389)',
    'Use AWS Systems Manager Session Manager instead of direct SSH',
  ],
  'S3 Bucket': [
    'Enable S3 Block Public Access on the bucket and account level',
    'Remove public ACL grants for All Users / Authenticated Users',
    'Audit bucket policy for overly permissive Allow statements',
  ],
  'RDS Database': [
    'Set "Publicly Accessible" to No in the RDS configuration',
    'Restrict Security Group to VPC CIDR or specific application subnets',
    'Consider placing the database in a private subnet',
  ],
  'ALB': [
    'Redirect HTTP (port 80) to HTTPS with a permanent 301 redirect',
    'Enforce minimum TLS 1.2 in the HTTPS listener security policy',
    'Review target group health check and listener rules',
  ],
  'default': [
    'Review Security Group rules and remove overly permissive rules',
    'Apply least-privilege network access controls',
  ],
};


// ── Exposure path card ────────────────────────────────────────────────────────
function ExposureCard({ resource }) {
  const [expanded, setExpanded] = useState(false);
  const color = getServiceColor(resource.resource_type);
  const sevColor = {
    critical: '#ef4444',
    high:     '#f97316',
    medium:   '#eab308',
    low:      '#22c55e',
  }[resource.severity] || '#95B8D1';

  const ports = resource.open_ports
    .split(/,\s*/)
    .filter(p => p && p !== 'N/A');

  const remediations = REMEDIATION[resource.resource_type] || REMEDIATION.default;

  return (
    <div className="rounded-xl border overflow-hidden transition-all duration-200"
      style={{
        backgroundColor: 'var(--bg-card)',
        borderColor: 'var(--border-primary)',
        borderLeft: `4px solid ${sevColor}`,
      }}>

      <div className="p-4">
        <div className="flex items-start gap-4">
          {/* ── Visual exposure path ── */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-3 flex-wrap">
              {/* Internet node */}
              <div className="flex flex-col items-center gap-1 flex-shrink-0">
                <div className="w-10 h-10 rounded-full flex items-center justify-center border-2"
                  style={{ backgroundColor: 'rgba(239,68,68,0.12)', borderColor: '#ef4444' }}>
                  <Globe className="w-5 h-5" style={{ color: '#ef4444' }} />
                </div>
                <span className="text-[9px] font-bold uppercase tracking-wide" style={{ color: '#ef4444' }}>
                  Internet
                </span>
              </div>

              {/* Animated arrow */}
              <div className="flex flex-col items-center flex-1 min-w-[80px]">
                <span className="text-[9px] px-2 py-0.5 rounded mb-1 font-semibold"
                  style={{ backgroundColor: `${sevColor}15`, color: sevColor }}>
                  0.0.0.0/0
                </span>
                <div className="flex items-center w-full">
                  <div className="flex-1 h-0.5 rounded" style={{ backgroundColor: sevColor, opacity: 0.4 }} />
                  <div className="flex-shrink-0 w-0 h-0"
                    style={{
                      borderTop: '5px solid transparent',
                      borderBottom: '5px solid transparent',
                      borderLeft: `7px solid ${sevColor}`,
                      opacity: 0.7,
                    }}
                  />
                </div>
              </div>

              {/* Resource node */}
              <div className="flex flex-col items-center gap-1 flex-shrink-0">
                <div className="w-10 h-10 rounded-full flex items-center justify-center border-2"
                  style={{ backgroundColor: color + '20', borderColor: color }}>
                  <CloudServiceIcon service={resource.resource_type} size={20} />
                </div>
                <span className="text-[9px] font-bold uppercase tracking-wide" style={{ color }}>
                  {resource.resource_type.replace(/\s+/g, '').slice(0, 3).toUpperCase()}
                </span>
              </div>

              {/* Resource info */}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-bold leading-tight" style={{ color: 'var(--text-primary)' }}>
                  {resource.resource_name}
                </p>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
                  {resource.resource_type} · {resource.region}
                </p>
              </div>
            </div>

            {/* Exposure type + port badges */}
            <div className="flex items-center flex-wrap gap-2">
              <span className="text-[11px] px-2 py-0.5 rounded font-medium"
                style={{
                  backgroundColor: `${sevColor}12`,
                  color: sevColor,
                  border: `1px solid ${sevColor}35`,
                }}>
                {resource.exposure_type}
              </span>
              {ports.map(port => (
                <span key={port}
                  className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    color: 'var(--text-secondary)',
                    border: '1px solid var(--border-primary)',
                  }}>
                  :{port}
                </span>
              ))}
            </div>
          </div>

          {/* Right column: severity + risk + expand */}
          <div className="flex flex-col items-end gap-2 flex-shrink-0">
            <SeverityBadge severity={resource.severity} />
            <div className="text-right">
              <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>Risk Score</p>
              <p className="text-xl font-black leading-none" style={{ color: sevColor }}>
                {resource.risk_score}
              </p>
            </div>
            <button
              onClick={() => setExpanded(p => !p)}
              className="p-1.5 rounded-lg transition-opacity hover:opacity-70"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
              {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </div>

      {/* ── Expanded: ARN + remediation ── */}
      {expanded && (
        <div className="border-t p-4 space-y-4"
          style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>

          {/* ARN */}
          <div>
            <p className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>
              Resource ARN
            </p>
            <p className="text-xs font-mono break-all" style={{ color: 'var(--text-secondary)' }}>
              {resource.resource_arn}
            </p>
          </div>

          {/* Account */}
          <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--text-muted)' }}>
            <span>Account: <strong style={{ color: 'var(--text-secondary)' }}>{resource.account}</strong></span>
            <span>Region: <strong style={{ color: 'var(--text-secondary)' }}>{resource.region}</strong></span>
          </div>

          {/* Remediation steps */}
          <div>
            <p className="text-[10px] font-bold uppercase tracking-wider mb-2 flex items-center gap-1.5"
              style={{ color: 'var(--text-muted)' }}>
              <Lock className="w-3 h-3" />
              Recommended Remediation
            </p>
            <div className="space-y-1.5">
              {remediations.map((step, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span className="flex-shrink-0 w-4 h-4 rounded-full text-[9px] font-bold flex items-center justify-center mt-0.5"
                    style={{ backgroundColor: `${sevColor}20`, color: sevColor }}>
                    {i + 1}
                  </span>
                  <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{step}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Quick action links */}
          <div className="flex items-center gap-4 pt-2 border-t" style={{ borderColor: 'var(--border-primary)' }}>
            <a href="/misconfig"
              className="inline-flex items-center gap-1.5 text-xs font-medium hover:opacity-75 transition-opacity"
              style={{ color: 'var(--accent-primary)' }}>
              <ExternalLink className="w-3.5 h-3.5" />
              View Misconfigurations →
            </a>
            <a href="/threats"
              className="inline-flex items-center gap-1.5 text-xs font-medium hover:opacity-75 transition-opacity"
              style={{ color: '#ef4444' }}>
              <ExternalLink className="w-3.5 h-3.5" />
              View Threats →
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function InternetExposedPage() {
  const router = useRouter();
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [resources, setResources] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const res = await getFromEngine('threat', '/api/v1/graph/internet-exposed', { scan_run_id: 'latest' });
        if (res && !res.error && res.exposed_resources) {
          setResources(res.exposed_resources);
        }
      } catch (err) {
        setError('Failed to load internet-exposed resources. Please check that the Threat engine is running.');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const critical = resources.filter(r => r.severity === 'critical').length;
  const high     = resources.filter(r => r.severity === 'high').length;
  const medium   = resources.filter(r => r.severity === 'medium').length;

  // Group by exposure category
  const groups = useMemo(() => {
    const acc = {};
    resources.forEach(r => {
      const cat = categorise(r);
      if (!acc[cat]) acc[cat] = [];
      acc[cat].push(r);
    });
    return CATEGORY_ORDER.filter(c => acc[c]?.length).map(c => ({ category: c, items: acc[c] }));
  }, [resources]);

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2">
        <button onClick={() => router.push('/threats')} className="text-sm hover:opacity-80 transition-opacity"
          style={{ color: 'var(--text-muted)' }}>
          Threats
        </button>
        <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Internet Exposed Resources</h1>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Exposed" value={resources.length} subtitle="Direct internet exposure" icon={<Globe className="w-5 h-5" />}        color="red"    />
        <KpiCard title="Critical"      value={critical}          subtitle="Immediate risk"           icon={<AlertTriangle className="w-5 h-5" />} color="red"    />
        <KpiCard title="High"          value={high}              subtitle="High exposure risk"       icon={<AlertTriangle className="w-5 h-5" />} color="orange" />
        <KpiCard title="Medium"        value={medium}            subtitle="Moderate exposure"        icon={<Shield className="w-5 h-5" />}        color="yellow" />
      </div>

      {/* Error state */}
      {error && resources.length === 0 && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: '#ef4444' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      {/* Internet → Resource exposure banner */}
      <div className="rounded-xl border p-4 flex items-center gap-4"
        style={{ backgroundColor: 'rgba(239,68,68,0.06)', borderColor: 'rgba(239,68,68,0.2)' }}>
        <Wifi className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Resources below are directly reachable from the public internet. Each card shows the exposure path,
          open ports, and recommended remediation steps.
        </p>
      </div>

      {/* Grouped exposure cards */}
      {loading ? (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-24 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
          ))}
        </div>
      ) : resources.length === 0 ? (
        <div className="rounded-lg p-8 border text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No internet-exposed resources found</p>
        </div>
      ) : (
        <div className="space-y-8">
          {groups.map(({ category, items }) => {
            const catCfg = EXPOSURE_CATEGORIES[category];
            return (
              <div key={category}>
                {/* Category header */}
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                    style={{ backgroundColor: catCfg.color }} />
                  <h2 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
                    {category}
                  </h2>
                  <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold"
                    style={{ backgroundColor: catCfg.bg, color: catCfg.color, border: `1px solid ${catCfg.border}` }}>
                    {items.length} resource{items.length !== 1 ? 's' : ''}
                  </span>
                </div>

                {/* Cards */}
                <div className="space-y-3">
                  {items.map((resource, i) => (
                    <ExposureCard key={i} resource={resource} />
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
