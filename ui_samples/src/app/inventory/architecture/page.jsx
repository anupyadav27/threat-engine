'use client';

/**
 * Architecture Diagram — Landscape Layout
 *
 * Per-account view. TGW strip on the far left spans full account height.
 * Regions scroll horizontally. Inside each VPC:
 *   ALB/Edge tier (leftmost) | Public subnets | Private subnets (main area)
 * Compute inside subnets is grouped by PaaS type (eks-compute, rds-compute, …).
 * Public services (S3, CloudFront, Route53…) in a fixed right column.
 * Supporting services (IAM, KMS, SGs…) in a collapsible bottom bar.
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import * as LucideIcons from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';

// ── Icons ─────────────────────────────────────────────────────────────────────

function Icon({ name, size = 14, className = '' }) {
  const C = LucideIcons[name] || LucideIcons.Box;
  return <C size={size} className={className} />;
}

// ── PaaS compute group config ─────────────────────────────────────────────────

const PAAS_CFG = {
  'compute':              { label: 'Compute',      icon: 'Server',    border: 'border-slate-500',   bg: 'bg-slate-600/20',    text: 'text-slate-300' },
  'eks-compute':          { label: 'EKS',          icon: 'Layers',    border: 'border-blue-500',    bg: 'bg-blue-900/20',     text: 'text-blue-300'  },
  'ecs-compute':          { label: 'ECS',          icon: 'Box',       border: 'border-teal-500',    bg: 'bg-teal-900/20',     text: 'text-teal-300'  },
  'rds-compute':          { label: 'RDS',          icon: 'Database',  border: 'border-indigo-500',  bg: 'bg-indigo-900/20',   text: 'text-indigo-300'},
  'elasticache-compute':  { label: 'ElastiCache',  icon: 'Zap',       border: 'border-cyan-500',    bg: 'bg-cyan-900/20',     text: 'text-cyan-300'  },
  'redshift-compute':     { label: 'Redshift',     icon: 'BarChart3', border: 'border-purple-500',  bg: 'bg-purple-900/20',   text: 'text-purple-300'},
  'docdb-compute':        { label: 'DocDB',        icon: 'Database',  border: 'border-green-500',   bg: 'bg-green-900/20',    text: 'text-green-300' },
  'neptune-compute':      { label: 'Neptune',      icon: 'GitBranch', border: 'border-violet-500',  bg: 'bg-violet-900/20',   text: 'text-violet-300'},
  'sagemaker-compute':    { label: 'SageMaker',    icon: 'Brain',     border: 'border-orange-500',  bg: 'bg-orange-900/20',   text: 'text-orange-300'},
  'emr-compute':          { label: 'EMR',          icon: 'Cpu',       border: 'border-yellow-500',  bg: 'bg-yellow-900/20',   text: 'text-yellow-300'},
};

// Regional service categories shown below VPCs
const REGIONAL_CATS = [
  'compute-serverless', 'compute-database', 'compute-analytics',
  'messaging', 'network-dns', 'services',
];

// Supporting service categories rendered in bottom bar
const SUPPORTING_CFG = {
  identity:        { icon: 'KeyRound',    label: 'IAM',           color: 'text-orange-400' },
  encryption:      { icon: 'Lock',        label: 'KMS / Certs',   color: 'text-purple-400' },
  monitoring:      { icon: 'Activity',    label: 'Monitoring',    color: 'text-teal-400'   },
  logging:         { icon: 'FileText',    label: 'Logs',          color: 'text-cyan-400'   },
  management:      { icon: 'Settings',    label: 'Management',    color: 'text-slate-400'  },
  security:        { icon: 'Shield',      label: 'Security',      color: 'text-red-400'    },
  'storage-block': { icon: 'HardDrive',   label: 'EBS / Volumes', color: 'text-amber-400'  },
  'storage-file':  { icon: 'FolderOpen',  label: 'EFS',           color: 'text-amber-300'  },
};

// Public-facing service categories shown in right column
const PUBLIC_CATS = [
  'storage-object', 'internet_edge', 'public', 'network-dns',
];

// Gateway types → icon + colour (VPC-internal, shown in gateway strip)
const GW_CFG = {
  'ec2.internet-gateway':       { icon: 'Globe',      label: 'IGW',  color: 'text-green-400'  },
  'ec2.nat-gateway':            { icon: 'ArrowRight', label: 'NAT',  color: 'text-yellow-400' },
  'ec2.vpn-gateway':            { icon: 'Lock',       label: 'VGW',  color: 'text-orange-400' },
  'ec2.vpc-peering-connection': { icon: 'GitMerge',   label: 'Peer', color: 'text-blue-400'   },
};

// Subnet / VPC badge icons (attached resources shown as icon badges)
const BADGE_ICONS = {
  'ec2.network-acl':       { icon: 'TableProperties', label: 'NACL', color: 'text-red-400'    },
  'ec2.route-table':       { icon: 'Route',            label: 'RT',   color: 'text-blue-400'   },
  'ec2.network-interface': { icon: 'Network',           label: 'ENI',  color: 'text-slate-400'  },
  'ec2.security-group':    { icon: 'ShieldCheck',       label: 'SG',   color: 'text-orange-400' },
  'ec2.vpc-endpoint':      { icon: 'PlugZap',           label: 'VPCE', color: 'text-purple-400' },
  'ec2.address':           { icon: 'Globe',             label: 'EIP',  color: 'text-cyan-400'   },
};

// Per-resource-type config used inside supporting service sub-boxes
const RESOURCE_TYPE_CFG = {
  'iam.role':              { icon: 'UserCog',        label: 'Roles',            color: 'text-orange-400' },
  'iam.policy':            { icon: 'ScrollText',     label: 'Policies',         color: 'text-orange-300' },
  'iam.instance-profile':  { icon: 'ServerCog',      label: 'Instance Profiles',color: 'text-orange-200' },
  'iam.user':              { icon: 'User',            label: 'Users',            color: 'text-orange-400' },
  'iam.group':             { icon: 'Users',           label: 'Groups',           color: 'text-orange-300' },
  'kms.key':               { icon: 'KeyRound',        label: 'KMS Keys',         color: 'text-purple-400' },
  'kms.alias':             { icon: 'Tag',             label: 'KMS Aliases',      color: 'text-purple-300' },
  'acm.certificate':       { icon: 'BadgeCheck',      label: 'Certificates',     color: 'text-purple-300' },
  'ec2.security-group':    { icon: 'ShieldCheck',     label: 'Security Groups',  color: 'text-red-400'    },
  'ec2.network-acl':       { icon: 'TableProperties', label: 'NACLs',            color: 'text-red-300'    },
  'ec2.route-table':       { icon: 'Route',           label: 'Route Tables',     color: 'text-blue-300'   },
  'ecr.repository':        { icon: 'Container',       label: 'ECR Repos',        color: 'text-teal-400'   },
  'cloudtrail.trail':      { icon: 'Activity',        label: 'CloudTrail',       color: 'text-teal-400'   },
  'logs.resource':         { icon: 'FileText',        label: 'Log Groups',       color: 'text-cyan-400'   },
  'backup.resource':       { icon: 'Archive',         label: 'Backup Plans',     color: 'text-green-400'  },
  'ram.permission':        { icon: 'Share2',          label: 'RAM Permissions',  color: 'text-amber-400'  },
  'elasticbeanstalk.platform': { icon: 'Cpu',         label: 'EB Platforms',     color: 'text-slate-400'  },
  'bedrock.foundation-model': { icon: 'Brain',        label: 'Bedrock Models',   color: 'text-violet-400' },
};

// External connectivity types — shown OUTSIDE the account box, only if resources exist
const EXTERNAL_CFG = {
  'ec2.vpn-gateway': {
    group: 'vpn',      label: 'VPN Gateway',     icon: 'Lock',       color: 'text-orange-400', border: 'border-orange-700', bg: 'bg-orange-950/40',
  },
  'ec2.vpn-connection': {
    group: 'vpn',      label: 'VPN Connection',  icon: 'Lock',       color: 'text-orange-300', border: 'border-orange-700', bg: 'bg-orange-950/40',
  },
  'ec2.customer-gateway': {
    group: 'vpn',      label: 'Customer GW',     icon: 'Building2',  color: 'text-yellow-400', border: 'border-yellow-700', bg: 'bg-yellow-950/40',
  },
  'ec2.transit-gateway': {
    group: 'tgw',      label: 'Transit GW',      icon: 'Share2',     color: 'text-orange-400', border: 'border-orange-700', bg: 'bg-orange-950/40',
  },
  'ec2.vpc-peering-connection': {
    group: 'peering',  label: 'VPC Peering',     icon: 'GitMerge',   color: 'text-blue-400',   border: 'border-blue-700',   bg: 'bg-blue-950/40',
  },
  'directconnect.connection': {
    group: 'dx',       label: 'Direct Connect',  icon: 'Cable',      color: 'text-purple-400', border: 'border-purple-700', bg: 'bg-purple-950/40',
  },
  'directconnect.virtual-interface': {
    group: 'dx',       label: 'DX Interface',    icon: 'Plug',       color: 'text-purple-300', border: 'border-purple-600', bg: 'bg-purple-900/30',
  },
  'directconnect.direct-connect-gateway': {
    group: 'dx',       label: 'DX Gateway',      icon: 'Router',     color: 'text-violet-400', border: 'border-violet-700', bg: 'bg-violet-950/40',
  },
};

// Group display order + labels for the external panel
const EXTERNAL_GROUPS = {
  dx:      { label: 'Direct Connect',   icon: 'Cable',    color: 'text-purple-400', border: 'border-purple-700', bg: 'bg-purple-950/30' },
  vpn:     { label: 'VPN / On-Prem',    icon: 'Lock',     color: 'text-orange-400', border: 'border-orange-700', bg: 'bg-orange-950/30' },
  tgw:     { label: 'Transit Gateway',  icon: 'Share2',   color: 'text-orange-300', border: 'border-orange-600', bg: 'bg-orange-900/20' },
  peering: { label: 'VPC Peering',      icon: 'GitMerge', color: 'text-blue-400',   border: 'border-blue-700',   bg: 'bg-blue-950/30'   },
};

/** Scan account data and return only the external connection groups that have resources. */
function collectExternalConnections(account) {
  const found = {}; // group → { cfg, items[] }

  const addItem = (type, resource, region) => {
    const cfg = EXTERNAL_CFG[type];
    if (!cfg) return;
    const g = cfg.group;
    if (!found[g]) found[g] = { cfg: EXTERNAL_GROUPS[g], items: [] };
    found[g].items.push({ ...resource, _type: type, _region: region });
  };

  for (const region of account.regions || []) {
    // VPC gateways (vpn-gateway, peering, etc.)
    for (const vpc of region.vpcs || []) {
      for (const gw of vpc.gateways || []) {
        addItem(gw.type || gw.resource_type, gw, region.region);
      }
    }
    // Regional primary — network-gateway bucket (TGW) + anything else
    for (const [, items] of Object.entries(region.regional_primary || {})) {
      for (const item of items) {
        addItem(item.type || item.resource_type, item, region.region);
      }
    }
    // Supporting services (DX resources may land here)
    for (const [, data] of Object.entries(account.supporting_services || {})) {
      for (const item of (Array.isArray(data) ? data : data?.items || [])) {
        addItem(item.type || item.resource_type, item, region.region);
      }
    }
  }

  // Return ordered by EXTERNAL_GROUPS key order
  return Object.keys(EXTERNAL_GROUPS)
    .filter(g => found[g])
    .map(g => ({ group: g, ...found[g] }));
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function shortName(r) {
  const n = r?.name || r?.display_name || r?.resource_id || '';
  return n.length > 18 ? n.slice(0, 16) + '…' : (n || r?.uid?.split('/').pop()?.slice(-12) || '?');
}

function riskRing(score) {
  if (score >= 70) return 'ring-1 ring-red-500';
  if (score >= 40) return 'ring-1 ring-yellow-500';
  return '';
}

// ── Resource chip ─────────────────────────────────────────────────────────────

function ResourceChip({ resource, onClick }) {
  const risk = resource?.risk_score;
  return (
    <button
      onClick={() => onClick?.(resource)}
      title={`${resource.type || resource.resource_type}\n${resource.uid || resource.resource_uid}`}
      className={`inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded
        bg-slate-700 border border-slate-600 text-slate-300
        hover:bg-slate-600 hover:border-slate-400 transition-colors cursor-pointer
        ${riskRing(risk)}`}
    >
      <span className="max-w-[120px] truncate">{shortName(resource)}</span>
      {risk >= 70 && <span className="text-red-400 text-[8px]">●</span>}
    </button>
  );
}

// ── Compute group (PaaS grouping inside subnet) ───────────────────────────────

function ComputeGroup({ groupKey, resources, onClick }) {
  const [exp, setExp] = useState(true);
  const cfg = PAAS_CFG[groupKey] || PAAS_CFG.compute;
  if (!resources?.length) return null;

  return (
    <div className={`rounded border ${cfg.border} ${cfg.bg} p-1.5 mb-1`}>
      <button
        className={`flex items-center gap-1 w-full text-left ${cfg.text} mb-1`}
        onClick={() => setExp(v => !v)}
      >
        <Icon name={cfg.icon} size={10} className={cfg.text} />
        <span className="text-[9px] font-semibold">{cfg.label}</span>
        <span className="text-[9px] text-slate-500 ml-1">×{resources.length}</span>
        <span className="ml-auto text-[8px] text-slate-600">{exp ? '▾' : '▸'}</span>
      </button>
      {exp && (
        <div className="flex flex-wrap gap-1">
          {resources.map(r => (
            <ResourceChip key={r.uid || r.resource_uid} resource={r} onClick={onClick} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Subnet column ─────────────────────────────────────────────────────────────

function SubnetColumn({ subnet, onClick }) {
  const isPublic = subnet.subnet_type === 'public';
  const rbc = subnet.resources_by_category || {};
  const total = Object.values(rbc).reduce((s, a) => s + a.length, 0);
  const az = subnet.az?.split('-').pop() || '';

  return (
    <div className={`rounded border p-2 min-w-[170px] max-w-[260px] flex-shrink-0
      ${isPublic
        ? 'border-amber-700 bg-amber-950/30'
        : 'border-slate-500 bg-slate-700/20'}`}
    >
      {/* Header */}
      <div className="flex items-center gap-1 mb-2">
        <span className={`text-[8px] font-bold px-1 rounded
          ${isPublic ? 'bg-amber-800 text-amber-200' : 'bg-slate-700 text-slate-400'}`}>
          {isPublic ? 'PUB' : 'PRIV'}
        </span>
        <span className="text-[10px] text-slate-400 truncate flex-1" title={subnet.name}>
          {subnet.name}
        </span>
        <span className="text-[9px] text-slate-600">{az}</span>
      </div>

      {/* Badges (NACL, RT, ENI) with Lucide icons */}
      {subnet.badges?.length > 0 && (
        <div className="flex gap-1 mb-1 flex-wrap">
          {subnet.badges.map((b, i) => {
            const bc = BADGE_ICONS[b.type] || {};
            return (
              <span key={i}
                title={b.type}
                className={`flex items-center gap-0.5 text-[8px] px-1 py-0.5 rounded
                  bg-slate-700 border border-slate-600/70 ${bc.color || 'text-slate-400'}`}
              >
                <Icon name={bc.icon || 'Box'} size={8} />
                {bc.label || b.type?.split('.').pop()?.toUpperCase()}
              </span>
            );
          })}
        </div>
      )}

      {total === 0 && (
        <div className="text-[9px] text-slate-600 italic mt-1">empty</div>
      )}

      {/* Compute groups */}
      {Object.entries(rbc).map(([key, items]) =>
        items.length > 0 ? (
          <ComputeGroup key={key} groupKey={key} resources={items} onClick={onClick} />
        ) : null
      )}
    </div>
  );
}

// ── ALB / edge tier — leftmost inside VPC (internet entry point) ─────────────

function ALBEdgeTier({ edgeServices }) {
  if (!edgeServices?.length) return null;
  return (
    <div className="flex flex-col items-center gap-1.5 px-2 border-x border-slate-600 mx-1">
      <span className="text-[8px] text-slate-600 font-semibold tracking-widest"
        style={{ writingMode: 'vertical-lr', transform: 'rotate(180deg)' }}>
        EDGE
      </span>
      {edgeServices.map(svc => {
        const label = svc.name?.split('-').slice(-2).join('-') ||
          svc.type?.split('.').pop()?.toUpperCase() || 'SVC';
        const isAlb = (svc.type || '').includes('load-balancer');
        const isEndpoint = (svc.type || '').includes('endpoint');
        return (
          <div
            key={svc.uid || svc.resource_uid}
            title={`${svc.type}\n${svc.name}`}
            className={`text-[9px] px-1.5 py-1 rounded border text-center w-full cursor-default
              ${isAlb
                ? 'border-green-600 bg-green-900/30 text-green-300'
                : isEndpoint
                  ? 'border-blue-600 bg-blue-900/30 text-blue-300'
                  : 'border-slate-500 bg-slate-700/30 text-slate-400'}`}
          >
            {isAlb ? '⚖' : isEndpoint ? '⬡' : '⊕'} {label}
          </div>
        );
      })}
    </div>
  );
}

// ── VPC box ───────────────────────────────────────────────────────────────────

function VPCBox({ vpc, onClick }) {
  const [collapsed, setCollapsed] = useState(false);
  const publicSubnets  = (vpc.subnets || []).filter(s => s.subnet_type === 'public');
  const privateSubnets = (vpc.subnets || []).filter(s => s.subnet_type !== 'public');
  const gateways    = vpc.gateways    || [];
  const edgeServices = vpc.edge_services || [];
  const totalSubnets = (vpc.subnets || []).length;

  // Unique gateway types as icon badges
  const gwTypes = [...new Set(gateways.map(g => g.type || g.resource_type).filter(Boolean))];
  const edgeTypes = [...new Set(edgeServices.map(e => e.type || e.resource_type).filter(Boolean))];

  return (
    <div className="rounded-lg border border-slate-500 bg-slate-800/40 mb-3">
      {/* VPC header */}
      <button
        className="w-full flex items-center gap-2 px-3 py-1.5 border-b border-slate-600 hover:bg-slate-700/30"
        onClick={() => setCollapsed(v => !v)}
      >
        <Icon name="Network" size={12} className="text-slate-400" />
        <span className="text-[11px] font-semibold text-slate-200">{vpc.name}</span>
        {vpc.cidr && (
          <span className="text-[9px] text-slate-500 bg-slate-700 px-1 rounded">{vpc.cidr}</span>
        )}
        {/* Gateway + edge badges with Lucide icons */}
        {gwTypes.map(t => {
          const gc = GW_CFG[t] || BADGE_ICONS[t] || {};
          return (
            <span key={t} title={t}
              className={`flex items-center gap-0.5 text-[8px] px-1.5 py-0.5 rounded
                bg-slate-700/80 border border-slate-600/60 ${gc.color || 'text-slate-400'}`}>
              <Icon name={gc.icon || 'Router'} size={8} />
              {gc.label || t.split('.').pop().toUpperCase()}
            </span>
          );
        })}
        {edgeTypes.map(t => (
          <span key={`edge-${t}`} title={t}
            className="flex items-center gap-0.5 text-[8px] px-1.5 py-0.5 rounded
              bg-green-900/40 border border-green-800/60 text-green-400">
            <Icon name="PlugZap" size={8} />
            {t.split('.').pop().toUpperCase().slice(0, 6)}
          </span>
        ))}
        <span className="text-[9px] text-slate-600 ml-1">{totalSubnets} subnets</span>
        <span className="ml-auto text-slate-500 text-[10px]">{collapsed ? '▸' : '▾'}</span>
      </button>

      {!collapsed && (
        <div className="p-2">
          {/* Gateway strip */}
          {gateways.length > 0 && (
            <div className="flex flex-wrap gap-1 mb-2 pb-2 border-b border-slate-600/50">
              {gateways.map(gw => {
                const gwCfg = GW_CFG[gw.type] || { icon: 'Router', label: gw.type?.split('.').pop(), color: 'text-slate-400' };
                return (
                  <div
                    key={gw.uid || gw.resource_uid}
                    title={`${gw.type}\n${gw.name}`}
                    className="flex items-center gap-1 text-[9px] px-2 py-0.5 rounded
                      border border-slate-600 bg-slate-700/40 cursor-default"
                  >
                    <Icon name={gwCfg.icon} size={10} className={gwCfg.color} />
                    <span className={gwCfg.color}>{gwCfg.label}</span>
                  </div>
                );
              })}
            </div>
          )}

          {/* Edge → Public → Private layout (left to right, internet flows left→right) */}
          <div className="flex gap-0 items-start overflow-x-auto">

            {/* ALB / NLB / VPC endpoints — leftmost, internet entry point */}
            <ALBEdgeTier edgeServices={edgeServices} />

            {/* Public subnets — after edge, before private */}
            {publicSubnets.length > 0 && (
              <div className="flex flex-col gap-1 pl-1 pr-2 border-r border-amber-800/60 mr-2 flex-shrink-0">
                {publicSubnets.map(s => (
                  <SubnetColumn key={s.uid || s.subnet_uid} subnet={s} onClick={onClick} />
                ))}
              </div>
            )}

            {/* Private subnets — main area */}
            <div className="flex flex-row flex-wrap gap-1 flex-1 min-w-0">
              {privateSubnets.length > 0 ? (
                privateSubnets.map(s => (
                  <SubnetColumn key={s.uid || s.subnet_uid} subnet={s} onClick={onClick} />
                ))
              ) : (
                !publicSubnets.length && (
                  <div className="text-[10px] text-slate-600 italic p-2">No subnets</div>
                )
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Regional services row (below VPCs inside region) ─────────────────────────

function RegionalServicesRow({ regionalPrimary }) {
  if (!regionalPrimary) return null;
  const items = Object.entries(regionalPrimary)
    .filter(([, arr]) => arr?.length > 0)
    .flatMap(([cat, arr]) => arr.map(r => ({ ...r, _cat: cat })));
  if (!items.length) return null;

  return (
    <div className="mt-2 pt-2 border-t border-slate-600/50">
      <div className="flex items-center gap-1 mb-1">
        <Icon name="Zap" size={10} className="text-violet-400" />
        <span className="text-[9px] font-semibold text-slate-500">REGIONAL SERVICES</span>
        <span className="text-[9px] text-slate-600">×{items.length}</span>
      </div>
      <div className="flex flex-wrap gap-1">
        {items.slice(0, 24).map(r => (
          <div
            key={r.uid || r.resource_uid}
            title={`${r.type || r.resource_type}\n${r.region}`}
            className="text-[10px] px-1.5 py-0.5 rounded border border-violet-700
              bg-violet-900/20 text-violet-300 cursor-default"
          >
            {shortName(r)}
          </div>
        ))}
        {items.length > 24 && (
          <span className="text-[10px] text-slate-600">+{items.length - 24}</span>
        )}
      </div>
    </div>
  );
}

// ── Region card ───────────────────────────────────────────────────────────────

function RegionCard({ regionData, onClick }) {
  const [collapsed, setCollapsed] = useState(false);
  const vpcs = regionData.vpcs || [];
  // Exclude TGW from regional_primary (handled by TGW strip)
  const regionalPrimary = useMemo(() => {
    const rp = { ...(regionData.regional_primary || {}) };
    delete rp['network-gateway'];
    return rp;
  }, [regionData]);

  return (
    <div className="rounded-lg border border-slate-600 bg-slate-800/60 flex-shrink-0"
      style={{ minWidth: '380px', maxWidth: '700px' }}>
      {/* Header */}
      <button
        className="w-full flex items-center gap-2 px-3 py-2 border-b border-slate-600 hover:bg-slate-700/20"
        onClick={() => setCollapsed(v => !v)}
      >
        <span className="w-2 h-2 rounded-full bg-blue-400 flex-shrink-0" />
        <span className="text-[12px] font-semibold text-slate-200">{regionData.region}</span>
        <span className="text-[10px] text-slate-500">{vpcs.length} VPC{vpcs.length !== 1 ? 's' : ''}</span>
        {regionData.availability_zones?.length > 0 && (
          <div className="flex gap-1 ml-1">
            {regionData.availability_zones.map(az => (
              <span key={az} className="text-[8px] px-1 rounded bg-slate-700 text-slate-500">{az.split('-').pop()}</span>
            ))}
          </div>
        )}
        <span className="ml-auto text-slate-500 text-[11px]">{collapsed ? '▸' : '▾'}</span>
      </button>

      {!collapsed && (
        <div className="p-3">
          {vpcs.length === 0 && !Object.values(regionalPrimary).some(a => a?.length > 0) && (
            <div className="text-[10px] text-slate-600 italic mb-2">No resources</div>
          )}
          {vpcs.map(vpc => (
            <VPCBox key={vpc.uid || vpc.vpc_uid} vpc={vpc} onClick={onClick} />
          ))}
          <RegionalServicesRow regionalPrimary={regionalPrimary} />
        </div>
      )}
    </div>
  );
}

// ── External connections panel — above account, only populated groups shown ───

function ExternalConnectionsPanel({ groups }) {
  if (!groups?.length) return null;
  return (
    <div className="mb-2 rounded-lg border border-slate-600 bg-slate-900/80 px-4 py-3">
      <div className="flex items-center gap-2 mb-3">
        <Icon name="Globe2" size={12} className="text-slate-500" />
        <span className="text-[9px] font-bold text-slate-500 tracking-widest">EXTERNAL CONNECTIVITY</span>
        <span className="text-[8px] text-slate-600">(resources discovered in scan)</span>
      </div>
      <div className="flex flex-wrap gap-3">
        {groups.map(({ group, cfg, items }) => (
          <div key={group}
            className={`rounded-lg border ${cfg.border} ${cfg.bg} px-3 py-2 min-w-[140px]`}>
            {/* Group header */}
            <div className={`flex items-center gap-1.5 mb-2 ${cfg.color}`}>
              <Icon name={cfg.icon} size={12} className={cfg.color} />
              <span className="text-[10px] font-semibold">{cfg.label}</span>
              <span className="text-[9px] text-slate-600 ml-auto">×{items.length}</span>
            </div>
            {/* Individual resources */}
            <div className="flex flex-col gap-1">
              {items.slice(0, 5).map((item, idx) => (
                <div key={item.uid || item.resource_uid || idx}
                  className="flex items-center gap-1 text-[9px] text-slate-400"
                  title={`${item._type}\n${item._region}`}>
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-600 flex-shrink-0" />
                  <span className="truncate">{shortName(item)}</span>
                  <span className="text-slate-600 ml-auto flex-shrink-0">{item._region?.split('-').pop()}</span>
                </div>
              ))}
              {items.length > 5 && (
                <span className="text-[9px] text-slate-600">+{items.length - 5} more</span>
              )}
            </div>
            {/* Arrow pointing down into account */}
            <div className="flex justify-center mt-2">
              <span className="text-slate-700 text-[14px]">↓</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── TGW strip — full account height, far left ─────────────────────────────────

function TGWStrip({ tgwEntries }) {
  if (!tgwEntries?.length) return null;
  return (
    <div className="flex-shrink-0 flex flex-col items-center
      border-r border-orange-900 bg-orange-950/20 px-2 py-3 mr-3"
      style={{ minWidth: '80px' }}>
      <span className="text-[8px] font-bold text-orange-500 tracking-widest mb-3"
        style={{ writingMode: 'vertical-lr', transform: 'rotate(180deg)', letterSpacing: '0.15em' }}>
        TRANSIT GW
      </span>
      {tgwEntries.map(tgw => (
        <div key={tgw.uid || tgw.resource_uid}
          className="w-full mb-3 rounded border border-orange-700 bg-orange-950/50 p-2 text-center"
          title={`${tgw.type || 'ec2.transit-gateway'}\n${tgw.region}`}>
          <div className="text-xl mb-1">⇆</div>
          <div className="text-[9px] text-orange-300 truncate" title={tgw.name}>
            {shortName(tgw)}
          </div>
          <div className="text-[8px] text-orange-600 mt-0.5">{tgw.region}</div>
          <div className="mt-2 border-l-2 border-dashed border-orange-800 h-4 mx-auto w-0" />
        </div>
      ))}
    </div>
  );
}

// Public service type → icon config
const PUBLIC_TYPE_CFG = {
  's3.bucket':          { icon: 'HardDrive',   label: 'S3',          color: 'text-green-400'  },
  'cloudfront.distribution': { icon: 'Globe2', label: 'CloudFront',  color: 'text-blue-400'   },
  'route53.hosted-zone': { icon: 'Navigation', label: 'Route53',     color: 'text-teal-400'   },
  'elasticbeanstalk.application': { icon: 'Cpu', label: 'EB App',    color: 'text-slate-400'  },
  'elasticbeanstalk.platform': { icon: 'Cpu',   label: 'EB Platform',color: 'text-slate-400'  },
};

// ── Public services column — far right, account-wide ─────────────────────────

function PublicServicesColumn({ publicServices }) {
  // Gather all items from all categories, group by resource_type
  const allItems = useMemo(() => {
    const items = Object.values(publicServices || {}).flat();
    const byType = {};
    for (const item of items) {
      const rt = item.resource_type || item.type || 'other';
      if (!byType[rt]) byType[rt] = [];
      byType[rt].push(item);
    }
    return Object.entries(byType).sort(([, a], [, b]) => b.length - a.length);
  }, [publicServices]);

  if (!allItems.length) return null;

  return (
    <div className="flex-shrink-0 flex flex-col ml-3 pl-3 border-l border-blue-900"
      style={{ minWidth: '130px', maxWidth: '160px' }}>
      <div className="flex items-center gap-1 mb-3">
        <Icon name="Globe2" size={10} className="text-blue-400" />
        <span className="text-[8px] font-bold text-blue-400 tracking-widest">PUBLIC</span>
      </div>
      {allItems.map(([rt, items]) => {
        const cfg = PUBLIC_TYPE_CFG[rt] || RESOURCE_TYPE_CFG[rt];
        return (
          <div key={rt} className="mb-2 rounded border border-blue-900/60 bg-blue-950/30 p-1.5">
            {/* Type header with icon badge */}
            <div className={`flex items-center gap-1 mb-1 ${cfg?.color || 'text-blue-300'}`}>
              <Icon name={cfg?.icon || 'Box'} size={10} />
              <span className="text-[9px] font-semibold flex-1 truncate">
                {cfg?.label || rt.split('.').pop()}
              </span>
              <span className="text-[8px] text-blue-700">×{items.length}</span>
            </div>
            {/* Individual items */}
            {items.slice(0, 5).map(r => (
              <div
                key={r.uid || r.resource_uid}
                title={`${r.type || r.resource_type}\n${r.name}`}
                className="text-[9px] text-blue-300/80 truncate py-0.5 pl-1
                  border-l border-blue-800/50 ml-1 cursor-default hover:text-blue-200"
              >
                {shortName(r)}
              </div>
            ))}
            {items.length > 5 && (
              <div className="text-[8px] text-blue-700 pl-1">+{items.length - 5}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Supporting services bar — full width, account bottom ──────────────────────
// Renders category cards (IAM, Security, Encryption…). Within each card,
// items are grouped by resource_type as collapsible sub-boxes with Lucide icons.

function SupportingTypeBox({ groupKey, rt, items }) {
  const [exp, setExp] = useState(false);
  const rtCfg = RESOURCE_TYPE_CFG[rt];
  const label = rtCfg?.label || rt.split('.').pop();
  const color = rtCfg?.color || 'text-slate-400';
  const iconName = rtCfg?.icon || 'Box';

  return (
    <div className="rounded border border-slate-700/70 bg-slate-900/50">
      <button
        onClick={() => setExp(v => !v)}
        className="w-full flex items-center gap-1.5 px-2 py-1 hover:bg-slate-700/30 transition-colors"
      >
        <Icon name={iconName} size={10} className={color} />
        <span className={`text-[9px] flex-1 text-left truncate ${color}`}>{label}</span>
        <span className="text-[9px] text-slate-600">×{items.length}</span>
        <span className="text-[8px] text-slate-700 ml-0.5">{exp ? '▾' : '▸'}</span>
      </button>
      {exp && (
        <div className="px-2 pb-2 pt-0.5 flex flex-wrap gap-1 max-h-28 overflow-y-auto">
          {items.slice(0, 30).map((item, idx) => (
            <span
              key={item.uid || item.resource_uid || idx}
              title={item.uid || item.resource_uid}
              className="text-[8px] px-1.5 py-0.5 rounded bg-slate-700 border border-slate-600
                text-slate-300 max-w-[120px] truncate cursor-default"
            >
              {item.ref_id && <span className="text-slate-500 mr-0.5">{item.ref_id}</span>}
              {shortName(item)}
            </span>
          ))}
          {items.length > 30 && (
            <span className="text-[8px] text-slate-600 self-end">+{items.length - 30}</span>
          )}
        </div>
      )}
    </div>
  );
}

function SupportingBar({ supportingServices }) {
  const [collapsedGroups, setCollapsedGroups] = useState({});
  if (!supportingServices || !Object.keys(supportingServices).length) return null;

  const toggleGroup = (group) =>
    setCollapsedGroups(prev => ({ ...prev, [group]: !prev[group] }));

  return (
    <div className="mt-4 pt-3 border-t-2 border-slate-700">
      <div className="flex items-center gap-1 mb-3">
        <Icon name="Shield" size={11} className="text-slate-500" />
        <span className="text-[9px] font-bold text-slate-500 tracking-widest">SUPPORTING SERVICES</span>
      </div>
      <div className="flex flex-wrap gap-3">
        {Object.entries(supportingServices).map(([group, data]) => {
          const cfg = SUPPORTING_CFG[group];
          const items = Array.isArray(data) ? data : (data?.items || []);
          if (!items.length) return null;

          // Group items by resource_type for sub-boxes
          const byType = {};
          for (const item of items) {
            const rt = item.resource_type || item.type || 'unknown';
            if (!byType[rt]) byType[rt] = [];
            byType[rt].push(item);
          }
          // Sort sub-types by count descending
          const sortedTypes = Object.entries(byType).sort(([, a], [, b]) => b.length - a.length);
          const isCollapsed = collapsedGroups[group];

          return (
            <div key={group}
              className="rounded-lg border border-slate-700 bg-slate-800/60 overflow-hidden"
              style={{ minWidth: '160px', maxWidth: '220px' }}
            >
              {/* Category header */}
              <button
                onClick={() => toggleGroup(group)}
                className="w-full flex items-center gap-1.5 px-3 py-2
                  border-b border-slate-700 hover:bg-slate-700/30 transition-colors"
              >
                {cfg && <Icon name={cfg.icon} size={11} className={cfg.color} />}
                <span className={`text-[10px] font-semibold flex-1 text-left ${cfg?.color || 'text-slate-300'}`}>
                  {cfg?.label || group}
                </span>
                <span className="text-[9px] text-slate-600">×{items.length}</span>
                <span className="text-[9px] text-slate-700 ml-1">{isCollapsed ? '▸' : '▾'}</span>
              </button>

              {/* Sub-boxes per resource type */}
              {!isCollapsed && (
                <div className="p-1.5 flex flex-col gap-1">
                  {sortedTypes.map(([rt, typeItems]) => (
                    <SupportingTypeBox
                      key={rt}
                      groupKey={group}
                      rt={rt}
                      items={typeItems}
                    />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Account view ──────────────────────────────────────────────────────────────

function AccountView({ account, onResourceClick }) {
  // Collect TGW entries (for the internal strip) — only TGW type
  const tgwEntries = useMemo(() =>
    (account.regions || []).flatMap(r =>
      (r.regional_primary?.['network-gateway'] || [])
        .filter(t => (t.type || t.resource_type) === 'ec2.transit-gateway')
        .map(t => ({ ...t, region: r.region }))
    ),
  [account]);

  // Collect all external connection groups (only populated ones)
  const externalGroups = useMemo(() => collectExternalConnections(account), [account]);

  return (
    <div className="mb-6">
      {/* External connectivity panel — outside + above account box */}
      <ExternalConnectionsPanel groups={externalGroups} />

      <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
      {/* Account header */}
      <div className="flex items-center gap-3 mb-4 pb-2 border-b border-slate-700">
        <span className="px-2 py-0.5 rounded text-xs font-bold bg-orange-900 text-orange-300 border border-orange-700">
          {(account.provider || 'aws').toUpperCase()}
        </span>
        <span className="text-sm font-semibold text-slate-200">{account.account_id}</span>
        <span className="text-xs text-slate-500">
          {account.regions?.length || 0} region{account.regions?.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Main content: TGW | Regions (scrollable) | Public Services */}
      <div className="flex" style={{ minHeight: '200px' }}>

        {/* TGW strip — leftmost, spans full account height */}
        <TGWStrip tgwEntries={tgwEntries} />

        {/* Regions — horizontal scroll */}
        <div className="flex-1 flex flex-row gap-3 overflow-x-auto pb-2 min-w-0">
          {(account.regions || []).map(r => (
            <RegionCard key={r.region} regionData={r} onClick={onResourceClick} />
          ))}
        </div>

        {/* Public services column — rightmost */}
        <PublicServicesColumn publicServices={account.public_services} />
      </div>

      {/* Supporting services — full width bottom */}
      <SupportingBar supportingServices={account.supporting_services} />
      </div>
    </div>
  );
}

// ── Resource detail drawer ────────────────────────────────────────────────────

function ResourceDrawer({ resource, onClose }) {
  if (!resource) return null;
  const fields = [
    ['Type',       resource.type || resource.resource_type],
    ['Region',     resource.region],
    ['Account',    resource.account_id],
    ['UID',        resource.uid || resource.resource_uid],
    ['Risk Score', resource.risk_score],
    ['Criticality',resource.criticality],
    ['Status',     resource.compliance_status],
  ].filter(([, v]) => v != null && v !== '');

  return (
    <div className="fixed right-0 top-0 h-full w-80 bg-slate-900 border-l border-slate-700 shadow-2xl z-50 overflow-y-auto p-4">
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-sm font-semibold text-slate-200">{shortName(resource)}</h3>
        <button onClick={onClose} className="text-slate-500 hover:text-slate-300 text-lg leading-none">✕</button>
      </div>
      <dl className="space-y-2">
        {fields.map(([k, v]) => (
          <div key={k}>
            <dt className="text-[10px] text-slate-500">{k}</dt>
            <dd className="text-[11px] text-slate-300 break-all">{String(v)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

// ── Account selector ──────────────────────────────────────────────────────────

function AccountSelector({ accounts, selectedId, onChange }) {
  return (
    <select
      value={selectedId || ''}
      onChange={e => onChange(e.target.value)}
      className="text-xs bg-slate-800 border border-slate-600 rounded px-3 py-1.5
        text-slate-200 focus:outline-none focus:border-blue-500"
    >
      {accounts.map(a => (
        <option key={a.account_id} value={a.account_id}>
          {(a.provider || 'aws').toUpperCase()} · {a.account_id}
          {' '}({a.regions?.length || 0} regions)
        </option>
      ))}
    </select>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ArchitecturePage() {
  const router = useRouter();
  const { provider } = useGlobalFilter();

  const [data,             setData]            = useState(null);
  const [loading,          setLoading]         = useState(true);
  const [error,            setError]           = useState(null);
  const [maxPriority,      setMaxPriority]     = useState(3);
  const [selectedAccountId, setSelectedAccountId] = useState(null);
  const [selectedResource, setSelectedResource] = useState(null);

  // Load data
  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const params = { max_priority: maxPriority, include_relationships: true };
        if (provider) params.csp = provider;

        let result;
        try {
          result = await getFromEngine('gateway', '/api/v1/views/inventory/architecture', params);
        } catch {
          result = await getFromEngine('inventory', '/api/v1/inventory/architecture', params);
        }
        if (result?.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load architecture data');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [provider, maxPriority]);

  // Auto-select first account
  useEffect(() => {
    if (data?.accounts?.length && !selectedAccountId) {
      setSelectedAccountId(data.accounts[0].account_id);
    }
  }, [data, selectedAccountId]);

  const accounts = data?.accounts || [];
  const selectedAccount = useMemo(
    () => accounts.find(a => a.account_id === selectedAccountId) || accounts[0],
    [accounts, selectedAccountId],
  );

  const handleResourceClick = useCallback(resource => {
    setSelectedResource(resource);
  }, []);

  const stats = data?.stats || {};

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">

      {/* ── Toolbar ── */}
      <div className="sticky top-0 z-40 bg-slate-900/95 border-b border-slate-700
        px-4 py-2 flex items-center gap-3 flex-wrap backdrop-blur">
        <h1 className="text-sm font-bold text-slate-200">Architecture</h1>
        <div className="h-4 w-px bg-slate-700" />

        {accounts.length > 1 && (
          <AccountSelector
            accounts={accounts}
            selectedId={selectedAccountId}
            onChange={id => { setSelectedAccountId(id); setSelectedResource(null); }}
          />
        )}

        {/* Priority slider */}
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-slate-500">Detail</span>
          {[1, 2, 3, 4, 5].map(p => (
            <button
              key={p}
              onClick={() => setMaxPriority(p)}
              className={`text-[10px] w-6 h-6 rounded-full font-bold transition-colors
                ${maxPriority >= p
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-700 text-slate-500 hover:bg-slate-600'}`}
            >
              P{p}
            </button>
          ))}
        </div>

        <div className="ml-auto flex items-center gap-3">
          {stats.total_assets > 0 && (
            <span className="text-[10px] text-slate-500">
              {stats.total_assets} assets · {stats.total_vpcs} VPCs · {stats.total_relationships} edges
            </span>
          )}
          <button
            onClick={() => { setData(null); setLoading(true); }}
            className="text-xs px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-300"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* ── Body ── */}
      <div className="p-4">
        {loading && (
          <div className="flex items-center justify-center h-72 text-slate-500">
            <span className="animate-pulse text-sm">Loading architecture…</span>
          </div>
        )}
        {error && (
          <div className="flex items-center justify-center h-72 text-red-400 text-sm">
            Failed to load: {error}
          </div>
        )}
        {!loading && !error && !accounts.length && (
          <div className="flex flex-col items-center justify-center h-72 gap-2 text-slate-500">
            <Icon name="Network" size={32} className="text-slate-700" />
            <span className="text-sm">No architecture data — run a scan first.</span>
          </div>
        )}
        {!loading && !error && selectedAccount && (
          <AccountView account={selectedAccount} onResourceClick={handleResourceClick} />
        )}
      </div>

      {/* ── Resource detail drawer ── */}
      {selectedResource && (
        <ResourceDrawer resource={selectedResource} onClose={() => setSelectedResource(null)} />
      )}
    </div>
  );
}
