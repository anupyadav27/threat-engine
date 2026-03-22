'use client';

/**
 * Architecture Diagram v2 — Two-column layout with horizontal subnets.
 *
 * Layout:
 *   ┌──────────────────────────────────────────────┬──────────────────┐
 *   │  REGIONS (70%)                               │ GLOBAL (30%)     │
 *   │  ┌─ Region: us-east-1 ────────────────────┐  │ ┌─ Global ────┐ │
 *   │  │ ┌─ VPC: vpc-abc ────────────────────┐  │  │ │ S3 buckets  │ │
 *   │  │ │ [IGW] [RT:3] [NACL:2] [VPCe:1]   │  │  │ │ CloudFront  │ │
 *   │  │ │ ┌Public┐ ┌Private┐ ┌Database┐     │  │  │ │ Route53     │ │
 *   │  │ │ │ ALB  │ │ EC2   │ │ RDS    │     │  │  │ │ Lambda      │ │
 *   │  │ │ │ IGW  │ │ EKS   │ │ Aurora │     │  │  │ └─────────────┘ │
 *   │  │ │ └──────┘ └───────┘ └────────┘     │  │  │                 │
 *   │  │ └───────────────────────────────────┘  │  │                 │
 *   │  │ Regional: Bedrock, SQS, SNS            │  │                 │
 *   │  └────────────────────────────────────────┘  │                 │
 *   └──────────────────────────────────────────────┴──────────────────┘
 *   ┌─ Supporting Services Reference ────────────────────────────────┐
 *   │ Identity: IAM-R1 ThreatEngineRole, IAM-R2 eks-cluster-role    │
 *   │ Security: SG-1 default, SG-2 launch-wizard-1                  │
 *   │ Network:  RT-1 main, NACL-1 default                           │
 *   └────────────────────────────────────────────────────────────────┘
 */

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import * as LucideIcons from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import {
  classifyLinkFamily,
  getServiceIcon,
  NESTING_COLORS,
  getVNetLabel,
} from '@/lib/inventory-taxonomy';
import { CLOUD_PROVIDERS } from '@/lib/constants';
import { useGlobalFilter } from '@/lib/global-filter-context';

// ── Helpers ─────────────────────────────────────────────────────────────────

function LucideIcon({ name, size = 16, color, className = '' }) {
  const Icon = LucideIcons[name] || LucideIcons.Box;
  return <Icon size={size} color={color} className={className} />;
}

const CATEGORY_CONFIG = {
  compute:           { icon: 'Server',       color: '#3b82f6', label: 'Compute' },
  compute_eks:       { icon: 'Server',       color: '#2563eb', label: 'Compute · EKS' },
  compute_ecs:       { icon: 'Server',       color: '#1d4ed8', label: 'Compute · ECS' },
  compute_rds:       { icon: 'Server',       color: '#7c3aed', label: 'Compute · RDS' },
  compute_redshift:  { icon: 'Server',       color: '#6d28d9', label: 'Compute · Redshift' },
  compute_sagemaker: { icon: 'Server',       color: '#c026d3', label: 'Compute · SageMaker' },
  compute_emr:       { icon: 'Server',       color: '#0891b2', label: 'Compute · EMR' },
  compute_elasticache:{ icon: 'Server',      color: '#059669', label: 'Compute · ElastiCache' },
  compute_opensearch:{ icon: 'Server',       color: '#e11d48', label: 'Compute · OpenSearch' },
  compute_lambda:    { icon: 'Server',       color: '#d97706', label: 'Compute · Lambda' },
  lambda:      { icon: 'Zap',          color: '#d97706', label: 'Lambda' },
  file_storage:{ icon: 'FolderOpen',   color: '#f59e0b', label: 'File Storage (EFS)' },
  container:   { icon: 'Container',    color: '#06b6d4', label: 'Containers' },
  database:    { icon: 'Database',     color: '#8b5cf6', label: 'Database' },
  storage:     { icon: 'HardDrive',    color: '#f59e0b', label: 'Storage' },
  network:     { icon: 'Network',      color: '#64748b', label: 'Network' },
  edge:        { icon: 'Globe',        color: '#10b981', label: 'Edge / CDN' },
  security:    { icon: 'Shield',       color: '#ef4444', label: 'Security' },
  identity:    { icon: 'KeyRound',     color: '#f97316', label: 'Identity' },
  encryption:  { icon: 'Lock',         color: '#a855f7', label: 'Encryption' },
  monitoring:  { icon: 'Activity',     color: '#14b8a6', label: 'Monitoring' },
  logging:     { icon: 'FileText',    color: '#0d9488', label: 'Logging & Audit' },
  management:  { icon: 'Settings',     color: '#6b7280', label: 'Management' },
  messaging:   { icon: 'MessageSquare',color: '#ec4899', label: 'Messaging' },
  analytics:   { icon: 'BarChart3',    color: '#0ea5e9', label: 'Analytics' },
  ai_ml:       { icon: 'Brain',        color: '#d946ef', label: 'AI / ML' },
  iot:         { icon: 'Wifi',         color: '#84cc16', label: 'IoT' },
  other:       { icon: 'Box',          color: '#94a3b8', label: 'Other' },
};

const MODEL_BADGE = {
  IaaS: { bg: '#dbeafe', color: '#2563eb', label: 'IaaS' },
  PaaS: { bg: '#dcfce7', color: '#16a34a', label: 'PaaS' },
  FaaS: { bg: '#fef3c7', color: '#d97706', label: 'FaaS' },
  SaaS: { bg: '#fce7f3', color: '#db2777', label: 'SaaS' },
};

const SUBNET_TYPE_COLORS = {
  public:    { border: '#10b981', bg: '#10b98108', icon: 'Globe',    label: 'Public' },
  private:   { border: '#3b82f6', bg: '#3b82f608', icon: 'Lock',     label: 'Private' },
  database:  { border: '#8b5cf6', bg: '#8b5cf608', icon: 'Database', label: 'Database' },
  analytics: { border: '#0ea5e9', bg: '#0ea5e908', icon: 'BarChart3',label: 'Analytics' },
  storage:   { border: '#f59e0b', bg: '#f59e0b08', icon: 'HardDrive',label: 'Storage' },
  unknown:   { border: '#64748b', bg: '#64748b08', icon: 'Layers',   label: 'Subnet' },
};

const CATEGORY_ORDER = [
  'edge', 'compute', 'container', 'database', 'file_storage', 'storage',
  'lambda', 'network', 'messaging', 'analytics', 'ai_ml', 'iot', 'other',
];

function sortCategories(entries) {
  return entries.sort(([a], [b]) => {
    const ai = CATEGORY_ORDER.indexOf(a);
    const bi = CATEGORY_ORDER.indexOf(b);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });
}

// ── ResourceChip ────────────────────────────────────────────────────────────

/**
 * Scroll to a supporting-service ref in the Supporting Services Reference
 * section and flash-highlight it.
 */
function scrollToRef(refId) {
  const el = document.getElementById(`supporting-ref-${refId}`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.add('ring-2', 'ring-indigo-400');
    setTimeout(() => el.classList.remove('ring-2', 'ring-indigo-400'), 2000);
  }
}

function ResourceChip({ resource, onClick, compact = false }) {
  const [hovered, setHovered] = useState(false);
  const catConfig = CATEGORY_CONFIG[resource.category] || CATEGORY_CONFIG.other;
  const iconName = getServiceIcon(resource.resource_type) || catConfig.icon;
  const _garbage = /^(iip-assoc-|List[A-Z]|Describe[A-Z]|Get[A-Z])/;
  const _pick = (v) => v && !_garbage.test(v) ? v : null;
  const displayName = _pick(resource.name) || _pick(resource.resource_id)
    || resource.resource_uid?.split('/').pop() || '?';
  const modelBadge = resource.service_model ? MODEL_BADGE[resource.service_model] : null;
  const refIds = resource.ref_ids || [];
  const hasRefs = refIds.length > 0;

  return (
    <div
      id={`resource-${resource.resource_uid}`}
      className="inline-flex flex-col rounded-lg cursor-pointer transition-all"
      style={{
        backgroundColor: hovered ? catConfig.color + '12' : 'rgba(100,116,139,0.05)',
        border: `1px solid ${hovered ? catConfig.color + '40' : 'rgba(100,116,139,0.12)'}`,
        minWidth: hasRefs && !compact ? 160 : undefined,
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      title={[displayName, resource.resource_type, resource.subcategory].filter(Boolean).join('\n')}
    >
      {/* Top row: icon + name + badges — clicking goes to asset page */}
      <div
        className="flex items-center gap-1.5 px-2 py-1.5 text-xs"
        onClick={() => onClick?.(resource)}
      >
        <LucideIcon name={iconName} size={compact ? 12 : 14} color={catConfig.color} />
        <span style={{ color: 'var(--text-primary)', maxWidth: compact ? 120 : 180 }} className="truncate font-medium">
          {displayName}
        </span>
        {!compact && modelBadge && (
          <span className="text-[8px] px-1 rounded font-medium"
            style={{ backgroundColor: modelBadge.bg, color: modelBadge.color }}>
            {modelBadge.label}
          </span>
        )}
        {resource.access_pattern === 'public' && (
          <LucideIcon name="Globe" size={10} color="#10b981" />
        )}
        {resource.posture?.total_critical > 0 && (
          <span className="text-[8px] px-1 rounded font-bold"
            style={{ backgroundColor: '#fef2f2', color: '#dc2626' }}>
            {resource.posture.total_critical}C
          </span>
        )}
      </div>

      {/* Bottom row: ref-id badges — each is an isolated clickable box */}
      {hasRefs && (
        <div className="flex flex-wrap gap-1 px-1.5 pb-1.5"
          style={{ borderTop: '1px solid rgba(100,116,139,0.08)' }}>
          {refIds.map(r => (
            <button
              key={r}
              className="text-[8px] px-1.5 py-0.5 rounded font-mono transition-colors cursor-pointer"
              style={{
                backgroundColor: 'rgba(99,102,241,0.08)',
                color: '#818cf8',
                border: '1px solid rgba(99,102,241,0.18)',
              }}
              title={`Scroll to ${r} in Supporting Services`}
              onClick={(e) => { e.stopPropagation(); scrollToRef(r); }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(99,102,241,0.20)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'rgba(99,102,241,0.08)'; }}
            >
              {r}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── CategoryGroup ───────────────────────────────────────────────────────────

function CategoryGroup({ category, resources, onResourceClick, compact = false }) {
  const [collapsed, setCollapsed] = useState(false);
  const config = CATEGORY_CONFIG[category] || CATEGORY_CONFIG.other;
  if (!resources || resources.length === 0) return null;

  return (
    <div className="mb-1">
      <div
        className="flex items-center gap-1.5 cursor-pointer py-0.5 px-1.5 rounded"
        style={{ borderLeft: `2px solid ${config.color}` }}
        onClick={() => setCollapsed(!collapsed)}
      >
        <LucideIcon name={collapsed ? 'ChevronRight' : 'ChevronDown'} size={10} color="var(--text-tertiary)" />
        <LucideIcon name={config.icon} size={11} color={config.color} />
        <span className="text-[10px] font-medium" style={{ color: config.color }}>
          {config.label}
        </span>
        <span className="text-[9px]" style={{ color: 'var(--text-tertiary)' }}>
          ({resources.length})
        </span>
      </div>
      {!collapsed && (
        <div className="flex flex-wrap gap-1 mt-0.5 pb-1 px-1.5 pl-4">
          {resources.map(r => (
            <ResourceChip key={r.resource_uid} resource={r} onClick={onResourceClick} compact={compact} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── CategoryGroupedResources ────────────────────────────────────────────────

function CategoryGroupedResources({ resourcesByCategory, onResourceClick, compact = false }) {
  const entries = sortCategories(Object.entries(resourcesByCategory || {}));
  if (entries.length === 0) return null;

  return (
    <div className="space-y-0.5">
      {entries.map(([cat, resources]) => (
        <CategoryGroup
          key={cat} category={cat} resources={resources}
          onResourceClick={onResourceClick} compact={compact}
        />
      ))}
    </div>
  );
}

// ── VPC Infrastructure Bar ──────────────────────────────────────────────────

function VPCInfraBar({ items }) {
  if (!items || items.length === 0) return null;

  // Group by subcategory for compact badges
  const groups = {};
  items.forEach(item => {
    const key = item.subcategory || item.category || 'infra';
    if (!groups[key]) groups[key] = [];
    groups[key].push(item);
  });

  return (
    <div className="flex flex-wrap gap-1.5 mb-2">
      {Object.entries(groups).map(([key, grp]) => {
        const catConfig = CATEGORY_CONFIG[grp[0]?.category] || CATEGORY_CONFIG.network;
        return (
          <div key={key}
            className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px]"
            style={{ backgroundColor: catConfig.color + '12', color: catConfig.color, border: `1px solid ${catConfig.color}20` }}
            title={grp.map(i => i.name || i.ref_id || i.resource_uid?.split('/').pop()).join(', ')}
          >
            <LucideIcon name={catConfig.icon} size={10} color={catConfig.color} />
            <span className="font-medium capitalize">{key.replace(/_/g, ' ')}</span>
            <span className="font-bold">({grp.length})</span>
          </div>
        );
      })}
    </div>
  );
}

// ── SubnetColumn ────────────────────────────────────────────────────────────

function SubnetColumn({ subnet, onResourceClick }) {
  const cats = subnet.resources_by_category || subnet.categories || {};
  const totalResources = Object.values(cats).reduce((sum, arr) => sum + arr.length, 0);
  const subnetType = subnet.subnet_type || 'unknown';
  const typeConfig = SUBNET_TYPE_COLORS[subnetType] || SUBNET_TYPE_COLORS.unknown;
  // Use subnet name; fall back to subnet ID from UID
  const rawName = subnet.name || subnet.subnet_uid?.split('/').pop() || 'Subnet';
  const subnetName = rawName === 'ip-name' ? subnet.subnet_uid?.split('/').pop() : rawName;
  // AZ: show just the AZ suffix (e.g. "1a" from "ap-south-1a")
  const azFull = subnet.az || '';
  const azShort = azFull.replace(/^.*?(\d+[a-z])$/, '$1');

  return (
    <div
      className="rounded-lg border p-2 min-w-[220px] flex-1"
      style={{
        backgroundColor: typeConfig.bg,
        borderColor: typeConfig.border + '40',
        borderTopWidth: 3,
        borderTopColor: typeConfig.border,
      }}
    >
      {/* Subnet header */}
      <div className="flex items-center gap-1.5 mb-1">
        <LucideIcon name={typeConfig.icon} size={12} color={typeConfig.border} />
        <span className="text-[10px] font-semibold" style={{ color: typeConfig.border }}>
          {typeConfig.label}
        </span>
        {azFull && (
          <span className="text-[8px] px-1.5 py-0.5 rounded font-bold"
            style={{ backgroundColor: '#6366f118', color: '#818cf8', border: '1px solid #6366f125' }}>
            AZ: {azShort || azFull}
          </span>
        )}
        <span className="text-[9px] ml-auto" style={{ color: 'var(--text-tertiary)' }}>
          ({totalResources})
        </span>
      </div>
      <div className="text-[9px] mb-1.5 truncate font-mono" style={{ color: 'var(--text-tertiary)' }} title={subnetName}>
        {subnetName}
      </div>

      {/* Resources stacked vertically by category */}
      <CategoryGroupedResources
        resourcesByCategory={cats}
        onResourceClick={onResourceClick}
        compact
      />
      {totalResources === 0 && (
        <div className="text-[9px] py-2 text-center" style={{ color: 'var(--text-tertiary)' }}>Empty</div>
      )}
    </div>
  );
}

// ── VPCBox ───────────────────────────────────────────────────────────────────

function VPCBox({ vpc, provider, onResourceClick }) {
  const vnetLabel = getVNetLabel(provider);
  const vpcName = vpc.name || vpc.vpc_uid?.split('/').pop();
  const subnets = vpc.subnets || [];
  const edgeServices = vpc.edge_services || [];
  const totalSubnetResources = subnets.reduce((sum, s) =>
    sum + Object.values(s.resources_by_category || s.categories || {}).reduce((s2, arr) => s2 + arr.length, 0), 0
  );
  const totalResources = totalSubnetResources + edgeServices.length;

  return (
    <div
      className="rounded-xl border p-3 mb-3"
      style={{ backgroundColor: NESTING_COLORS.vpc.bg, borderColor: NESTING_COLORS.vpc.border, borderWidth: 2 }}
    >
      {/* VPC header + infra bar */}
      <div className="flex items-center gap-2 mb-2">
        <LucideIcon name="Network" size={16} color="rgba(100,116,139,0.8)" />
        <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
          {vnetLabel}: {vpcName}
        </span>
        <span className="text-[10px] px-1.5 py-0.5 rounded"
          style={{ backgroundColor: 'rgba(100,116,139,0.10)', color: 'var(--text-secondary)' }}>
          {totalResources} resources · {subnets.length} subnets
        </span>
      </div>

      {/* VPC infrastructure badges (RT, NACL, VPCe, etc.) */}
      <VPCInfraBar items={vpc.vpc_infrastructure} />

      {/* Horizontal layout: Edge (left) | Subnets (center) */}
      <div className="flex gap-2">
        {/* LEFT: Edge vertical column */}
        {edgeServices.length > 0 && (
          <div className="w-[150px] shrink-0 rounded-lg border p-2 flex flex-col"
            style={{ backgroundColor: '#10b98106', borderColor: '#10b98130',
                     borderTopWidth: 3, borderTopColor: '#10b981' }}>
            <div className="flex items-center gap-1.5 mb-2">
              <LucideIcon name="Globe" size={12} color="#10b981" />
              <span className="text-[10px] font-bold" style={{ color: '#10b981' }}>Edge</span>
              <span className="text-[9px] ml-auto px-1 py-0.5 rounded-full font-semibold"
                style={{ backgroundColor: '#10b98115', color: '#10b981' }}>
                {edgeServices.length}
              </span>
            </div>
            <div className="flex flex-col gap-1">
              {edgeServices.map(r => (
                <ResourceChip key={r.resource_uid} resource={r} onClick={onResourceClick} compact />
              ))}
            </div>
          </div>
        )}

        {/* CENTER: Subnets (horizontal scroll) */}
        <div className="flex-1 min-w-0">
          {subnets.length > 0 ? (
            <div className="flex gap-2 overflow-x-auto pb-1">
              {subnets.map(subnet => (
                <SubnetColumn
                  key={subnet.subnet_uid}
                  subnet={subnet}
                  onResourceClick={onResourceClick}
                />
              ))}
            </div>
          ) : (
            <div className="text-xs py-3 text-center" style={{ color: 'var(--text-tertiary)' }}>
              No subnets detected
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── GlobalPrimaryPanel (right column) ───────────────────────────────────────

function GlobalPrimaryPanel({ globalPrimary, onResourceClick }) {
  const totalResources = Object.values(globalPrimary || {})
    .reduce((sum, arr) => sum + arr.length, 0);
  if (totalResources === 0) return null;

  return (
    <div className="rounded-lg border p-3"
      style={{ backgroundColor: NESTING_COLORS.az?.bg || '#f8fafc08', borderColor: NESTING_COLORS.az?.border || '#64748b20' }}>
      <div className="flex items-center gap-2 mb-2">
        <LucideIcon name="Cloud" size={14} color="var(--text-tertiary)" />
        <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
          GLOBAL PRIMARY
        </span>
        <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
          ({totalResources})
        </span>
      </div>
      <CategoryGroupedResources
        resourcesByCategory={globalPrimary}
        onResourceClick={onResourceClick}
      />
    </div>
  );
}

// ── PublicServicesPanel (vertical column parallel to regions) ────────────────

function PublicServicesPanel({ publicServices, onResourceClick }) {
  const entries = sortCategories(Object.entries(publicServices || {}));
  const totalResources = entries.reduce((sum, [, arr]) => sum + arr.length, 0);
  if (totalResources === 0) return null;

  return (
    <div className="rounded-lg border p-3"
      style={{ backgroundColor: '#f59e0b06', borderColor: '#f59e0b25',
               borderTopWidth: 3, borderTopColor: '#f59e0b' }}>
      <div className="flex items-center gap-2 mb-3">
        <LucideIcon name="Cloud" size={14} color="#f59e0b" />
        <span className="text-xs font-bold" style={{ color: '#f59e0b' }}>
          PUBLIC SERVICES
        </span>
        <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold"
          style={{ backgroundColor: '#f59e0b15', color: '#f59e0b' }}>
          {totalResources}
        </span>
      </div>

      {/* Group by category, each as a bordered sub-section */}
      <div className="flex flex-col gap-2">
        {entries.map(([cat, resources]) => {
          const config = CATEGORY_CONFIG[cat] || CATEGORY_CONFIG.other;
          // Sub-group by resource_type for better organisation
          const byType = {};
          resources.forEach(r => {
            const rt = r.resource_type || 'unknown';
            if (!byType[rt]) byType[rt] = [];
            byType[rt].push(r);
          });
          const sortedTypes = Object.entries(byType).sort((a, b) => b[1].length - a[1].length);

          return (
            <div key={cat} className="rounded border px-2 py-2"
              style={{ borderColor: config.color + '25', backgroundColor: config.color + '05' }}>
              <div className="flex items-center gap-1.5 mb-1.5">
                <LucideIcon name={config.icon} size={12} color={config.color} />
                <span className="text-[10px] font-bold" style={{ color: config.color }}>
                  {config.label}
                </span>
                <span className="text-[9px] ml-auto" style={{ color: 'var(--text-tertiary)' }}>
                  ({resources.length})
                </span>
              </div>
              {sortedTypes.map(([rt, items]) => {
                const shortType = rt.split('.').pop().replace(/-/g, ' ');
                return (
                  <div key={rt} className="mb-1">
                    {sortedTypes.length > 1 && (
                      <div className="text-[8px] font-semibold capitalize mb-0.5 pl-1"
                        style={{ color: 'var(--text-tertiary)' }}>
                        {shortType} ({items.length})
                      </div>
                    )}
                    <div className="flex flex-col gap-0.5">
                      {items.map(r => (
                        <div key={r.resource_uid}
                          className="flex items-center gap-1.5 px-1.5 py-1 rounded cursor-pointer transition-all text-[10px]"
                          style={{ backgroundColor: 'rgba(100,116,139,0.04)', border: '1px solid rgba(100,116,139,0.08)' }}
                          onClick={() => onResourceClick?.(r)}
                          onMouseEnter={(e) => { e.currentTarget.style.borderColor = config.color + '40'; }}
                          onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(100,116,139,0.08)'; }}
                          title={`${r.name || r.resource_id} · ${r.region || ''}`}
                        >
                          <LucideIcon name={config.icon} size={10} color={config.color} />
                          <span className="truncate" style={{ color: 'var(--text-primary)', maxWidth: 130 }}>
                            {r.name || r.resource_id || r.resource_uid?.split('/').pop() || '?'}
                          </span>
                          {r.region && (
                            <span className="text-[7px] ml-auto shrink-0 px-1 rounded font-mono"
                              style={{ color: 'var(--text-tertiary)', backgroundColor: 'rgba(100,116,139,0.08)' }}>
                              {r.region.replace(/^[a-z]+-[a-z]+-/, '')}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── RegionalPrimaryBox ──────────────────────────────────────────────────────

function RegionalPrimaryBox({ regionalPrimary, onResourceClick }) {
  const totalResources = Object.values(regionalPrimary || {})
    .reduce((sum, arr) => sum + arr.length, 0);
  if (totalResources === 0) return null;

  return (
    <div className="rounded-lg border p-2 mb-2"
      style={{ backgroundColor: 'rgba(100,116,139,0.04)', borderColor: 'rgba(100,116,139,0.12)' }}>
      <div className="flex items-center gap-2 mb-1.5">
        <LucideIcon name="Layers" size={12} color="var(--text-tertiary)" />
        <span className="text-[10px] font-semibold" style={{ color: 'var(--text-secondary)' }}>
          REGIONAL SERVICES
        </span>
        <span className="text-[9px]" style={{ color: 'var(--text-tertiary)' }}>({totalResources})</span>
      </div>
      <CategoryGroupedResources
        resourcesByCategory={regionalPrimary}
        onResourceClick={onResourceClick}
        compact
      />
    </div>
  );
}

// ── Supporting Services Reference — Vertical Boxes ──────────────────────────

function SupportingServicesTable({ supportingServices, groupsMeta, onResourceClick }) {
  const [expandedTypes, setExpandedTypes] = useState({});

  const groups = Object.entries(supportingServices || {});
  if (groups.length === 0) return null;

  const totalCount = groups.reduce((sum, [, grp]) => {
    const globalCount = (grp.global || []).length;
    const regionalCount = Object.values(grp.regional || {}).reduce((s, arr) => s + arr.length, 0);
    return sum + globalCount + regionalCount;
  }, 0);

  // Toggle expand for a resource_type within a group
  const toggleType = (groupKey, rtKey) => {
    const key = `${groupKey}::${rtKey}`;
    setExpandedTypes(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="rounded-lg border p-3"
      style={{ backgroundColor: 'rgba(100,116,139,0.03)', borderColor: 'rgba(100,116,139,0.15)' }}>
      <div className="flex items-center gap-2 mb-3">
        <LucideIcon name="Table2" size={14} color="var(--text-tertiary)" />
        <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
          SUPPORTING SERVICES REFERENCE
        </span>
        <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
          ({totalCount} resources)
        </span>
      </div>

      {/* Horizontal grid of vertical boxes — one per group */}
      <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${Math.min(groups.length, 4)}, 1fr)` }}>
        {groups.map(([groupKey, grp]) => {
          const meta = (groupsMeta || {})[groupKey] || {};
          const catConfig = CATEGORY_CONFIG[groupKey] || CATEGORY_CONFIG.other;
          const allItems = [
            ...(grp.global || []),
            ...Object.values(grp.regional || {}).flat(),
          ];
          const groupTotal = allItems.length;

          // Group items by resource_type for subcategory breakdown
          const byType = {};
          allItems.forEach(item => {
            const rt = item.resource_type || 'unknown';
            if (!byType[rt]) byType[rt] = [];
            byType[rt].push(item);
          });
          const sortedTypes = Object.entries(byType).sort((a, b) => b[1].length - a[1].length);

          return (
            <div key={groupKey}
              className="rounded-lg border p-2.5 flex flex-col"
              style={{
                borderColor: catConfig.color + '30',
                backgroundColor: catConfig.color + '06',
                borderTopWidth: 3,
                borderTopColor: catConfig.color,
              }}
            >
              {/* Group header */}
              <div className="flex items-center gap-1.5 mb-2">
                <LucideIcon name={meta.icon || catConfig.icon} size={14} color={catConfig.color} />
                <span className="text-[11px] font-bold" style={{ color: catConfig.color }}>
                  {meta.label || catConfig.label}
                </span>
                <span className="text-[9px] ml-auto px-1.5 py-0.5 rounded-full font-semibold"
                  style={{ backgroundColor: catConfig.color + '15', color: catConfig.color }}>
                  {groupTotal}
                </span>
              </div>

              {/* Subcategory rows (grouped by resource_type) */}
              <div className="flex flex-col gap-1 flex-1">
                {sortedTypes.map(([rt, items]) => {
                  const shortType = rt.split('.').pop().replace(/-/g, ' ');
                  const typeKey = `${groupKey}::${rt}`;
                  const isExpanded = expandedTypes[typeKey];
                  const MAX_COLLAPSED = 3;
                  const showExpand = items.length > MAX_COLLAPSED;
                  const displayItems = isExpanded ? items : items.slice(0, MAX_COLLAPSED);

                  return (
                    <div key={rt} className="rounded border px-2 py-1.5"
                      style={{ borderColor: 'rgba(100,116,139,0.10)', backgroundColor: 'rgba(100,116,139,0.03)' }}>
                      {/* Subcategory header */}
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className="text-[9px] font-semibold capitalize" style={{ color: 'var(--text-secondary)' }}>
                          {shortType}
                        </span>
                        <span className="text-[8px]" style={{ color: 'var(--text-tertiary)' }}>
                          ({items.length})
                        </span>
                      </div>
                      {/* Resource items with ref_id */}
                      <div className="flex flex-wrap gap-1">
                        {displayItems.map(r => {
                          const refId = r.ref_id;
                          const itemName = r.name || r.resource_id || r.resource_uid?.split('/').pop() || '?';
                          return (
                            <div
                              key={r.resource_uid}
                              id={refId ? `supporting-ref-${refId}` : undefined}
                              className="inline-flex items-center gap-1 px-1.5 py-1 rounded cursor-pointer transition-all text-[10px]"
                              style={{
                                backgroundColor: 'rgba(100,116,139,0.05)',
                                border: '1px solid rgba(100,116,139,0.10)',
                              }}
                              onClick={() => onResourceClick?.(r)}
                              onMouseEnter={(e) => { e.currentTarget.style.borderColor = catConfig.color + '50'; e.currentTarget.style.backgroundColor = catConfig.color + '10'; }}
                              onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(100,116,139,0.10)'; e.currentTarget.style.backgroundColor = 'rgba(100,116,139,0.05)'; }}
                              title={`Click to view ${itemName} asset details`}
                            >
                              {refId && (
                                <span className="text-[8px] font-mono font-bold px-1 py-0.5 rounded"
                                  style={{ backgroundColor: catConfig.color + '15', color: catConfig.color }}>
                                  {refId}
                                </span>
                              )}
                              <span className="truncate" style={{ color: 'var(--text-primary)', maxWidth: 140 }}>
                                {itemName}
                              </span>
                            </div>
                          );
                        })}
                        {showExpand && (
                          <button
                            className="text-[9px] px-1.5 py-0.5 rounded transition-colors"
                            style={{ color: catConfig.color, backgroundColor: catConfig.color + '10' }}
                            onClick={() => toggleType(groupKey, rt)}
                          >
                            {isExpanded ? '▲ less' : `+${items.length - MAX_COLLAPSED} more`}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── AccountCard ─────────────────────────────────────────────────────────────

function AccountCard({ account, onResourceClick }) {
  const provider = (account.provider || 'aws').toLowerCase();
  const cspInfo = CLOUD_PROVIDERS[provider] || CLOUD_PROVIDERS.aws;
  const regions = account.regions || [];

  // v2: global_primary / supporting_services
  // v1 compat: global_services (treat as global_primary if v2 missing)
  const globalPrimary = Object.keys(account.global_primary || {}).length > 0
    ? account.global_primary
    : (account.global_services || {});
  const publicServices = account.public_services || {};
  const supportingServices = account.supporting_services || {};

  const hasGlobal = Object.values(globalPrimary).some(arr => arr?.length > 0);
  const hasPublic = Object.values(publicServices).some(arr => arr?.length > 0);
  const hasRegions = regions.length > 0;
  const rightColumnsCount = (hasPublic ? 1 : 0) + (hasGlobal ? 1 : 0);

  return (
    <div
      className="rounded-xl border p-4 mb-4"
      style={{
        backgroundColor: NESTING_COLORS.account.bg,
        borderColor: NESTING_COLORS.account.border,
        borderWidth: 2,
      }}
    >
      {/* Account Header */}
      <div className="flex items-center gap-3 mb-4">
        <span className="text-xs font-bold px-2.5 py-1 rounded-md"
          style={{ backgroundColor: cspInfo.color + '20', color: cspInfo.color }}>
          {cspInfo.name}
        </span>
        <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
          Account: {account.account_id}
        </span>
      </div>

      {/* Multi-column layout: Regions (left) | Public Services | Global (right) */}
      <div className="flex gap-4">
        {/* LEFT: Regions (wider) */}
        <div className={rightColumnsCount > 0 ? 'flex-[6] min-w-0' : 'flex-1 min-w-0'}>
          {regions.map(region => {
            // v2: regional_primary / v1 compat: regional_services
            const regPrimary = Object.keys(region.regional_primary || {}).length > 0
              ? region.regional_primary
              : (region.regional_services || {});
            const regPrimaryCount = Object.values(regPrimary).reduce((s, arr) => s + (arr?.length || 0), 0);
            const hasVpcs = (region.vpcs || []).some(vpc =>
              (vpc.subnets || []).length > 0 || (vpc.edge_services || []).length > 0
            );

            // Skip empty regions — no VPCs with resources and no regional services
            if (!hasVpcs && regPrimaryCount === 0) return null;

            return (
              <div key={region.region} className="mb-3 rounded-lg border p-3"
                style={{ backgroundColor: NESTING_COLORS.region.bg, borderColor: NESTING_COLORS.region.border }}>
                <div className="flex items-center gap-2 mb-2">
                  <LucideIcon name="MapPin" size={14} color="var(--text-tertiary)" />
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
                    Region: {region.region}
                  </span>
                </div>

                {/* VPCs FIRST — with edge + subnets inside */}
                {(region.vpcs || []).map(vpc => (
                  <VPCBox
                    key={vpc.vpc_uid}
                    vpc={vpc}
                    provider={provider}
                    onResourceClick={onResourceClick}
                  />
                ))}

                {/* Regional services AFTER VPC (Lambda, etc.) */}
                {regPrimaryCount > 0 && (
                  <RegionalPrimaryBox
                    regionalPrimary={regPrimary}
                    onResourceClick={onResourceClick}
                  />
                )}
              </div>
            );
          })}

          {!hasRegions && (
            <div className="text-xs p-4 text-center rounded-lg border"
              style={{ color: 'var(--text-tertiary)', borderColor: 'var(--border-primary)' }}>
              No regional resources
            </div>
          )}
        </div>

        {/* MIDDLE: Public Services (S3, DynamoDB, SQS, etc.) */}
        {hasPublic && (
          <div className="flex-[2] min-w-[200px] max-w-[280px]">
            <PublicServicesPanel
              publicServices={publicServices}
              onResourceClick={onResourceClick}
            />
          </div>
        )}

        {/* RIGHT: Global Primary (IAM, etc.) */}
        {hasGlobal && (
          <div className="flex-[2] min-w-[200px] max-w-[280px]">
            <GlobalPrimaryPanel
              globalPrimary={globalPrimary}
              onResourceClick={onResourceClick}
            />
          </div>
        )}
      </div>

      {/* Bottom: Supporting Services Reference */}
      <div className="mt-4">
        <SupportingServicesTable
          supportingServices={supportingServices}
          groupsMeta={null}
          onResourceClick={onResourceClick}
        />
      </div>
    </div>
  );
}

// ── FilterPanel ─────────────────────────────────────────────────────────────

/**
 * Extracts all unique filter options from architecture data.
 */
function extractFilterOptions(data) {
  const accounts = new Set();
  const regions = new Set();
  const primaryCategories = new Set();
  const supportingGroups = new Set();

  (data?.accounts || []).forEach(acct => {
    accounts.add(acct.account_id);
    // Supporting groups
    Object.keys(acct.supporting_services || {}).forEach(g => supportingGroups.add(g));
    // Public services categories
    Object.keys(acct.public_services || {}).forEach(c => primaryCategories.add(c));
    // Global primary categories
    Object.keys(acct.global_primary || {}).forEach(c => primaryCategories.add(c));

    (acct.regions || []).forEach(reg => {
      regions.add(reg.region);
      // Regional primary categories
      Object.keys(reg.regional_primary || {}).forEach(c => primaryCategories.add(c));
      // Subnet categories
      (reg.vpcs || []).forEach(vpc => {
        (vpc.subnets || []).forEach(sn => {
          Object.keys(sn.resources_by_category || {}).forEach(c => primaryCategories.add(c));
        });
      });
    });
  });

  return {
    accounts: [...accounts].sort(),
    regions: [...regions].sort(),
    primaryCategories: [...primaryCategories].sort(),
    supportingGroups: [...supportingGroups].sort(),
  };
}

/**
 * Applies filters to the architecture data, returning a filtered copy.
 */
function applyFilters(data, filters) {
  if (!data?.accounts) return data;
  const { selectedAccounts, selectedRegions, selectedCategories, selectedSupporting, searchText } = filters;
  const searchLower = (searchText || '').toLowerCase().trim();

  // Helper: does a resource match the search text?
  const matchesSearch = (item) => {
    if (!searchLower) return true;
    const name = (item.name || item.resource_id || item.resource_uid || '').toLowerCase();
    const rt = (item.resource_type || '').toLowerCase();
    return name.includes(searchLower) || rt.includes(searchLower);
  };

  // Helper: filter a dict of category → items[]
  const filterCatDict = (dict, allowedCats) => {
    if (!dict) return {};
    const result = {};
    for (const [cat, items] of Object.entries(dict)) {
      if (allowedCats && !allowedCats.has(cat)) continue;
      const filtered = searchLower ? items.filter(matchesSearch) : items;
      if (filtered.length > 0) result[cat] = filtered;
    }
    return result;
  };

  // Helper: filter supporting services
  const filterSupporting = (ss) => {
    if (!ss) return {};
    const result = {};
    for (const [groupKey, grp] of Object.entries(ss)) {
      if (selectedSupporting && !selectedSupporting.has(groupKey)) continue;
      const filteredGrp = { ...grp };
      if (searchLower) {
        if (grp.global) {
          filteredGrp.global = grp.global.filter(matchesSearch);
        }
        if (grp.regional) {
          const filteredRegional = {};
          for (const [rk, items] of Object.entries(grp.regional)) {
            if (selectedRegions && !selectedRegions.has(rk)) continue;
            const f = items.filter(matchesSearch);
            if (f.length > 0) filteredRegional[rk] = f;
          }
          filteredGrp.regional = filteredRegional;
        }
      } else if (selectedRegions && grp.regional) {
        const filteredRegional = {};
        for (const [rk, items] of Object.entries(grp.regional)) {
          if (selectedRegions.has(rk)) filteredRegional[rk] = items;
        }
        filteredGrp.regional = filteredRegional;
      }
      // Check if group has any items left
      const hasItems = (filteredGrp.global || []).length > 0 ||
        Object.values(filteredGrp.regional || {}).some(a => a.length > 0);
      if (hasItems) result[groupKey] = filteredGrp;
    }
    return result;
  };

  const catSet = selectedCategories ? new Set(selectedCategories) : null;

  const filteredAccounts = data.accounts
    .filter(acct => !selectedAccounts || selectedAccounts.has(acct.account_id))
    .map(acct => {
      const filteredRegions = (acct.regions || [])
        .filter(reg => !selectedRegions || selectedRegions.has(reg.region))
        .map(reg => {
          const filteredVpcs = (reg.vpcs || []).map(vpc => {
            const filteredSubnets = (vpc.subnets || []).map(sn => ({
              ...sn,
              resources_by_category: filterCatDict(sn.resources_by_category, catSet),
            })).filter(sn => Object.keys(sn.resources_by_category || {}).length > 0);

            return {
              ...vpc,
              subnets: filteredSubnets,
              edge_services: searchLower
                ? (vpc.edge_services || []).filter(matchesSearch)
                : vpc.edge_services,
            };
          });

          return {
            ...reg,
            vpcs: filteredVpcs,
            regional_primary: filterCatDict(reg.regional_primary, catSet),
          };
        });

      return {
        ...acct,
        regions: filteredRegions,
        global_primary: filterCatDict(acct.global_primary, catSet),
        public_services: filterCatDict(acct.public_services, catSet),
        supporting_services: filterSupporting(acct.supporting_services),
      };
    });

  return { ...data, accounts: filteredAccounts };
}

/**
 * Multi-select dropdown for filtering.
 */
function FilterDropdown({ label, icon, options, selected, onToggle, onClear, colorMap }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const allSelected = !selected || selected.size === options.length;
  const count = selected ? selected.size : options.length;

  useEffect(() => {
    const handleClick = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[11px] transition-all"
        style={{
          borderColor: allSelected ? 'var(--border-primary)' : '#3b82f6',
          backgroundColor: allSelected ? 'var(--bg-card)' : 'rgba(59,130,246,0.08)',
          color: 'var(--text-secondary)',
        }}
      >
        <LucideIcon name={icon} size={12} color={allSelected ? 'var(--text-tertiary)' : '#3b82f6'} />
        <span className="font-medium">{label}</span>
        <span className="px-1.5 py-0.5 rounded-full text-[9px] font-bold"
          style={{
            backgroundColor: allSelected ? 'var(--bg-tertiary)' : 'rgba(59,130,246,0.15)',
            color: allSelected ? 'var(--text-tertiary)' : '#3b82f6',
          }}>
          {allSelected ? 'All' : count}
        </span>
        <LucideIcon name={open ? 'ChevronUp' : 'ChevronDown'} size={10} color="var(--text-tertiary)" />
      </button>

      {open && (
        <div className="absolute top-full mt-1 left-0 z-50 min-w-[200px] max-h-[300px] overflow-y-auto rounded-lg border shadow-lg p-1.5"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {/* Select All / Clear */}
          <div className="flex items-center justify-between px-2 py-1 mb-1 border-b"
            style={{ borderColor: 'var(--border-primary)' }}>
            <button onClick={onClear}
              className="text-[10px] font-medium transition-colors hover:underline"
              style={{ color: '#3b82f6' }}>
              {allSelected ? 'Clear all' : 'Select all'}
            </button>
          </div>
          {options.map(opt => {
            const isSelected = !selected || selected.has(opt);
            const optColor = colorMap?.[opt];
            return (
              <button
                key={opt}
                onClick={() => onToggle(opt)}
                className="flex items-center gap-2 w-full px-2 py-1.5 rounded text-left text-[11px] transition-colors"
                style={{
                  backgroundColor: isSelected ? 'rgba(59,130,246,0.06)' : 'transparent',
                  color: 'var(--text-primary)',
                }}
              >
                <div className="w-3.5 h-3.5 rounded border flex items-center justify-center"
                  style={{
                    borderColor: isSelected ? '#3b82f6' : 'var(--border-primary)',
                    backgroundColor: isSelected ? '#3b82f6' : 'transparent',
                  }}>
                  {isSelected && <LucideIcon name="Check" size={8} color="white" />}
                </div>
                {optColor && (
                  <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: optColor }} />
                )}
                <span className="truncate">{opt}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function FilterPanel({ data, filters, onFiltersChange }) {
  const options = useMemo(() => extractFilterOptions(data), [data]);
  const { selectedAccounts, selectedRegions, selectedCategories, selectedSupporting, searchText } = filters;

  // Color maps for visual hints
  const catColors = useMemo(() => {
    const m = {};
    options.primaryCategories.forEach(c => { m[c] = CATEGORY_CONFIG[c]?.color || '#94a3b8'; });
    return m;
  }, [options.primaryCategories]);

  const supColors = useMemo(() => {
    const m = {};
    options.supportingGroups.forEach(g => { m[g] = CATEGORY_CONFIG[g]?.color || '#64748b'; });
    return m;
  }, [options.supportingGroups]);

  // Toggle helpers
  const toggleSet = (currentSet, allOptions, value) => {
    // If null (all selected), create set without the value
    if (!currentSet) {
      const s = new Set(allOptions);
      s.delete(value);
      return s.size === 0 ? null : s;
    }
    const next = new Set(currentSet);
    if (next.has(value)) {
      next.delete(value);
      if (next.size === 0) return null; // empty → select all
    } else {
      next.add(value);
      if (next.size === allOptions.length) return null; // all selected
    }
    return next;
  };

  const clearSet = (currentSet, allOptions) => {
    // Toggle: if all selected → clear all; if some → select all
    if (!currentSet || currentSet.size === allOptions.length) {
      return new Set(); // clear all — will show nothing
    }
    return null; // select all
  };

  const hasActiveFilters = selectedAccounts || selectedRegions || selectedCategories || selectedSupporting || searchText;

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <LucideIcon name="SlidersHorizontal" size={14} color="var(--text-tertiary)" />
      <span className="text-[10px] font-semibold" style={{ color: 'var(--text-tertiary)' }}>FILTERS:</span>

      {/* Search */}
      <div className="relative">
        <LucideIcon name="Search" size={12} color="var(--text-tertiary)"
          className="absolute left-2 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          placeholder="Search resources..."
          value={searchText || ''}
          onChange={e => onFiltersChange({ ...filters, searchText: e.target.value || '' })}
          className="pl-6 pr-2 py-1.5 rounded-lg border text-[11px] w-[160px] outline-none transition-colors"
          style={{
            borderColor: searchText ? '#3b82f6' : 'var(--border-primary)',
            backgroundColor: 'var(--bg-card)',
            color: 'var(--text-primary)',
          }}
        />
      </div>

      {/* Account filter (only show if > 1 account) */}
      {options.accounts.length > 1 && (
        <FilterDropdown
          label="Account"
          icon="Building2"
          options={options.accounts}
          selected={selectedAccounts}
          onToggle={v => onFiltersChange({ ...filters, selectedAccounts: toggleSet(selectedAccounts, options.accounts, v) })}
          onClear={() => onFiltersChange({ ...filters, selectedAccounts: clearSet(selectedAccounts, options.accounts) })}
        />
      )}

      {/* Region filter */}
      <FilterDropdown
        label="Region"
        icon="MapPin"
        options={options.regions}
        selected={selectedRegions}
        onToggle={v => onFiltersChange({ ...filters, selectedRegions: toggleSet(selectedRegions, options.regions, v) })}
        onClear={() => onFiltersChange({ ...filters, selectedRegions: clearSet(selectedRegions, options.regions) })}
      />

      {/* Primary service categories */}
      <FilterDropdown
        label="Services"
        icon="Server"
        options={options.primaryCategories}
        selected={selectedCategories}
        onToggle={v => onFiltersChange({ ...filters, selectedCategories: toggleSet(selectedCategories, options.primaryCategories, v) })}
        onClear={() => onFiltersChange({ ...filters, selectedCategories: clearSet(selectedCategories, options.primaryCategories) })}
        colorMap={catColors}
      />

      {/* Supporting service groups */}
      <FilterDropdown
        label="Supporting"
        icon="Link"
        options={options.supportingGroups}
        selected={selectedSupporting}
        onToggle={v => onFiltersChange({ ...filters, selectedSupporting: toggleSet(selectedSupporting, options.supportingGroups, v) })}
        onClear={() => onFiltersChange({ ...filters, selectedSupporting: clearSet(selectedSupporting, options.supportingGroups) })}
        colorMap={supColors}
      />

      {/* Reset all */}
      {hasActiveFilters && (
        <button
          onClick={() => onFiltersChange({ selectedAccounts: null, selectedRegions: null, selectedCategories: null, selectedSupporting: null, searchText: '' })}
          className="flex items-center gap-1 px-2 py-1.5 rounded-lg text-[10px] font-medium transition-colors"
          style={{ color: '#ef4444', backgroundColor: 'rgba(239,68,68,0.08)' }}
        >
          <LucideIcon name="X" size={10} color="#ef4444" />
          Reset
        </button>
      )}
    </div>
  );
}

// ── StatsStrip ──────────────────────────────────────────────────────────────

function StatsStrip({ data }) {
  const stats = data?.stats || {};
  const accounts = data?.accounts || [];

  let vpcCount = 0, subnetCount = 0, primaryCount = 0, supportingCount = 0;
  accounts.forEach(acct => {
    (acct.regions || []).forEach(reg => {
      (reg.vpcs || []).forEach(vpc => {
        vpcCount++;
        subnetCount += (vpc.subnets || []).length;
      });
    });
    // Count supporting
    Object.values(acct.supporting_services || {}).forEach(grp => {
      supportingCount += (grp.global || []).length;
      Object.values(grp.regional || {}).forEach(arr => { supportingCount += arr.length; });
    });
  });
  primaryCount = (stats.total_assets || 0) - supportingCount;

  const items = [
    { label: 'Accounts', value: accounts.length, icon: 'Building2' },
    { label: 'VPCs', value: vpcCount, icon: 'Network' },
    { label: 'Subnets', value: subnetCount, icon: 'Layers' },
    { label: 'Primary', value: primaryCount, icon: 'Server', color: '#3b82f6' },
    { label: 'Supporting', value: supportingCount, icon: 'Link', color: '#64748b' },
    { label: 'Total Assets', value: stats.total_assets || 0, icon: 'Package' },
  ];

  return (
    <div className="flex flex-wrap gap-3">
      {items.map(s => (
        <div key={s.label} className="flex items-center gap-2 px-3 py-2 rounded-lg border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <LucideIcon name={s.icon} size={14} color={s.color || 'var(--text-tertiary)'} />
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{s.label}</span>
          <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{s.value}</span>
        </div>
      ))}
    </div>
  );
}

// ── PrioritySelector ────────────────────────────────────────────────────────

function PrioritySelector({ value, onChange }) {
  const options = [
    { val: 1, label: 'Core only', desc: 'VPC, compute, database, storage, serverless' },
    { val: 2, label: 'Important', desc: '+ load balancers, containers, messaging, KMS' },
    { val: 3, label: 'Expanded', desc: '+ security groups, route tables, ENIs' },
    { val: 4, label: 'Detailed', desc: '+ monitoring, config, SSM' },
    { val: 5, label: 'Everything', desc: 'All discovered resources' },
  ];

  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] font-semibold" style={{ color: 'var(--text-tertiary)' }}>Detail:</span>
      {options.map(opt => (
        <button
          key={opt.val}
          onClick={() => onChange(opt.val)}
          className="px-2 py-1 rounded text-[10px] transition-colors"
          style={{
            backgroundColor: value === opt.val ? 'var(--text-primary)' : 'var(--bg-tertiary)',
            color: value === opt.val ? 'var(--bg-primary)' : 'var(--text-secondary)',
          }}
          title={opt.desc}
        >
          P{opt.val}
        </button>
      ))}
    </div>
  );
}

// ── InterfaceConnections (lightweight indicator) ────────────────────────────

function InterfaceIndicators({ connections }) {
  if (!connections || connections.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-2 mt-2 px-1">
      <span className="text-[9px] font-semibold" style={{ color: 'var(--text-tertiary)' }}>FLOWS:</span>
      {connections.slice(0, 20).map((conn, i) => (
        <div key={i} className="flex items-center gap-1 text-[9px]"
          style={{ color: 'var(--text-tertiary)' }}>
          <span className="px-1 rounded" style={{ backgroundColor: 'rgba(59,130,246,0.1)' }}>
            {conn.from_subnet_type || '?'}
          </span>
          <LucideIcon name="ArrowRight" size={8} color="var(--text-tertiary)" />
          <span className="px-1 rounded" style={{ backgroundColor: 'rgba(139,92,246,0.1)' }}>
            {conn.to_subnet_type || '?'}
          </span>
          <span style={{ color: 'var(--text-tertiary)', opacity: 0.6 }}>
            ({conn.count || 1})
          </span>
        </div>
      ))}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN PAGE
// ═════════════════════════════════════════════════════════════════════════════

export default function ArchitectureDiagramV2Page() {
  const router = useRouter();
  const { provider } = useGlobalFilter();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [maxPriority, setMaxPriority] = useState(2);
  const [filters, setFilters] = useState({
    selectedAccounts: null,  // null = all selected
    selectedRegions: null,
    selectedCategories: null,
    selectedSupporting: null,
    searchText: '',
  });

  useEffect(() => {
    const loadArchitecture = async () => {
      setLoading(true);
      setError(null);
      try {
        const params = {
          max_priority: maxPriority,
          include_relationships: true,
        };
        if (provider) params.csp = provider;

        let result;
        try {
          result = await getFromEngine(
            'gateway',
            '/api/v1/views/inventory/architecture',
            params
          );
        } catch {
          result = await getFromEngine(
            'inventory',
            '/api/v1/inventory/architecture',
            params
          );
        }

        if (result?.error) {
          setError(result.error);
          return;
        }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load architecture data');
      } finally {
        setLoading(false);
      }
    };
    loadArchitecture();
  }, [provider, maxPriority]);

  const handleResourceClick = useCallback((resource) => {
    const uid = resource?.resource_uid || resource?.id;
    if (uid) router.push(`/inventory/${encodeURIComponent(uid)}`);
  }, [router]);

  const zoomIn = () => setZoom(z => Math.min(z * 1.2, 3));
  const zoomOut = () => setZoom(z => Math.max(z / 1.2, 0.3));
  const zoomFit = () => setZoom(1);

  // Apply client-side filters to the loaded data
  const filteredData = useMemo(() => {
    if (!data) return data;
    return applyFilters(data, filters);
  }, [data, filters]);

  const accounts = filteredData?.accounts || [];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={() => router.push('/inventory')}
            className="p-1.5 rounded-lg transition-colors hover:bg-[var(--bg-tertiary)]"
          >
            <LucideIcon name="ArrowLeft" size={20} color="var(--text-tertiary)" />
          </button>
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
              Infrastructure Architecture
            </h1>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Live topology — Regions (left) &middot; Global (right) &middot; Supporting (reference)
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <PrioritySelector value={maxPriority} onChange={setMaxPriority} />
          <div className="flex items-center gap-2">
            <button onClick={zoomOut} className="p-2 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <LucideIcon name="ZoomOut" size={16} color="var(--text-secondary)" />
            </button>
            <span className="text-xs min-w-[3rem] text-center" style={{ color: 'var(--text-tertiary)' }}>
              {Math.round(zoom * 100)}%
            </span>
            <button onClick={zoomIn} className="p-2 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <LucideIcon name="ZoomIn" size={16} color="var(--text-secondary)" />
            </button>
            <button onClick={zoomFit} className="p-2 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <LucideIcon name="Maximize2" size={16} color="var(--text-secondary)" />
            </button>
          </div>
        </div>
      </div>

      {/* Stats (from raw unfiltered data) */}
      {!loading && !error && data && <StatsStrip data={data} />}

      {/* Filters */}
      {!loading && !error && data && (
        <FilterPanel data={data} filters={filters} onFiltersChange={setFilters} />
      )}

      {/* Error */}
      {error && (
        <div className="rounded-lg p-4 border flex items-center gap-3"
          style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: '#ef4444' }}>
          <LucideIcon name="AlertTriangle" size={20} color="#ef4444" />
          <div>
            <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>Failed to load architecture</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center p-20">
          <div className="text-center">
            <LucideIcon name="Loader2" size={24} color="var(--text-tertiary)" className="animate-spin mx-auto mb-2" />
            <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>Loading infrastructure topology...</p>
          </div>
        </div>
      )}

      {/* Empty state — no data or empty accounts */}
      {!loading && !error && (!data || data.accounts?.length === 0) && (
        <div className="flex items-center justify-center p-20">
          <div className="text-center">
            <LucideIcon name="LayoutGrid" size={40} color="var(--text-tertiary)" className="mx-auto mb-3" />
            <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              No infrastructure data available
            </p>
            <p className="text-xs mt-1.5 max-w-xs mx-auto" style={{ color: 'var(--text-tertiary)' }}>
              Run a discovery scan to populate the architecture diagram, or check that your cloud accounts are onboarded.
            </p>
            <button
              onClick={() => router.push('/inventory')}
              className="mt-4 px-4 py-2 rounded-lg text-xs font-medium transition-colors"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
            >
              Back to Inventory
            </button>
          </div>
        </div>
      )}

      {/* Architecture Diagram */}
      {!loading && !error && data && data.accounts?.length > 0 && (
        <div
          className="rounded-xl border overflow-auto"
          style={{
            backgroundColor: 'var(--bg-primary)',
            borderColor: 'var(--border-primary)',
            maxHeight: 'calc(100vh - 260px)',
          }}
        >
          <div style={{
            transform: `scale(${zoom})`,
            transformOrigin: 'top left',
            padding: 16,
            minWidth: zoom < 1 ? `${100 / zoom}%` : '100%',
          }}>
            {accounts.length === 0 ? (
              <div className="flex items-center justify-center p-20">
                <div className="text-center">
                  <LucideIcon name="LayoutGrid" size={32} color="var(--text-tertiary)" className="mx-auto mb-3" />
                  <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No resources to display</p>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
                    Run a discovery scan to populate the architecture diagram
                  </p>
                </div>
              </div>
            ) : (
              accounts.map(account => (
                <AccountCard
                  key={account.account_id}
                  account={account}
                  onResourceClick={handleResourceClick}
                />
              ))
            )}
          </div>
        </div>
      )}

      {/* Interface connections */}
      {!loading && !error && data?.interface_connections?.length > 0 && (
        <InterfaceIndicators connections={data.interface_connections} />
      )}

      {/* Legend */}
      {!loading && !error && accounts.length > 0 && (
        <div className="flex flex-wrap gap-4 px-1">
          {/* Subnet types */}
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-semibold" style={{ color: 'var(--text-tertiary)' }}>SUBNETS:</span>
            {Object.entries(SUBNET_TYPE_COLORS).filter(([k]) => k !== 'unknown').map(([key, cfg]) => (
              <div key={key} className="flex items-center gap-1">
                <div className="w-3 h-1 rounded" style={{ backgroundColor: cfg.border }} />
                <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{cfg.label}</span>
              </div>
            ))}
          </div>
          {/* Categories */}
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-[10px] font-semibold" style={{ color: 'var(--text-tertiary)' }}>CATEGORIES:</span>
            {Object.entries(CATEGORY_CONFIG)
              .filter(([k]) => !['other', 'security', 'identity', 'encryption', 'monitoring', 'management'].includes(k))
              .map(([key, cfg]) => (
              <div key={key} className="flex items-center gap-1">
                <LucideIcon name={cfg.icon} size={10} color={cfg.color} />
                <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{cfg.label}</span>
              </div>
            ))}
          </div>
          {/* Nesting */}
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-semibold" style={{ color: 'var(--text-tertiary)' }}>NESTING:</span>
            {['account', 'region', 'vpc', 'subnet'].map(level => (
              <div key={level} className="flex items-center gap-1">
                <div className="w-3 h-3 rounded border" style={{
                  backgroundColor: NESTING_COLORS[level]?.bg,
                  borderColor: NESTING_COLORS[level]?.border,
                }} />
                <span className="text-[10px] capitalize" style={{ color: 'var(--text-tertiary)' }}>{level}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
