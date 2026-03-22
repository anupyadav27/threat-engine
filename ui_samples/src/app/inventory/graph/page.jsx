'use client';

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import * as LucideIcons from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import {
  RESOURCE_DOMAINS,
  classifyResourceDomain,
  classifyLinkFamily,
  getServiceIcon,
  VNET_TYPES,
  SUBNET_TYPES,
  IGW_TYPES,
  getVNetLabel,
  RESOURCE_TIERS,
  TIER_ORDER,
  classifyResourceTier,
  isJunkResourceType,
  NESTING_COLORS,
} from '@/lib/inventory-taxonomy';
import { CLOUD_PROVIDERS } from '@/lib/constants';
import { useGlobalFilter } from '@/lib/global-filter-context';

// ── Dynamic Lucide icon renderer ─────────────────────────────────────────────
function LucideIcon({ name, size = 16, color, className = '' }) {
  const Icon = LucideIcons[name] || LucideIcons.Box;
  return <Icon size={size} color={color} className={className} />;
}

// ── Structural relationship types (used for nesting, not drawn as arrows) ────
const STRUCTURAL_RELATIONS = new Set([
  'contained_by', 'contains', 'member_of', 'attached_to',
  'associated_with', 'references',
]);

// ── Arrow color by relation family ───────────────────────────────────────────
const ARROW_COLORS = {
  network: '#3b82f6',
  security: '#ef4444',
  data: '#10b981',
  execution: '#8b5cf6',
  identity: '#f59e0b',
  governance: '#64748b',
  structural: '#6366f1',
};

function getArrowColor(relType) {
  const family = classifyLinkFamily(relType);
  return ARROW_COLORS[family] || '#64748b';
}

// ── Helper: count resources across all tiers ─────────────────────────────────
function countTierResources(tiers) {
  if (!tiers) return 0;
  return TIER_ORDER.reduce((sum, k) => sum + (tiers[k]?.length || 0), 0);
}

// ── Build containment tree from graph data with tier grouping ────────────────
function buildContainmentTree(nodes, links) {
  const nodeMap = {};
  nodes.forEach(n => { nodeMap[n.id] = n; });

  // Build parent map from contained_by links
  const parentMap = {};
  const childrenMap = {};
  links.forEach(l => {
    if (l.label === 'contained_by') {
      const childId = typeof l.source === 'object' ? l.source.id : l.source;
      const parentId = typeof l.target === 'object' ? l.target.id : l.target;
      parentMap[childId] = parentId;
      if (!childrenMap[parentId]) childrenMap[parentId] = [];
      childrenMap[parentId].push(childId);
    }
  });

  // Build SG attachment map
  const sgMap = {};
  links.forEach(l => {
    if (l.label === 'attached_to') {
      const srcId = typeof l.source === 'object' ? l.source.id : l.source;
      const tgtId = typeof l.target === 'object' ? l.target.id : l.target;
      const tgtNode = nodeMap[tgtId];
      if (tgtNode && (tgtNode.type === 'ec2.security-group' || tgtNode.type === 'network.network-security-group')) {
        if (!sgMap[srcId]) sgMap[srcId] = [];
        sgMap[srcId].push({ id: tgtId, name: tgtNode.name || tgtId.split('/').pop() });
      }
    }
  });

  // Find ancestor of specific type set
  function findAncestor(nodeId, typeSet) {
    let current = nodeId;
    const visited = new Set();
    while (parentMap[current] && !visited.has(current)) {
      visited.add(current);
      current = parentMap[current];
      const n = nodeMap[current];
      if (n && typeSet.has(n.type)) return n;
    }
    return null;
  }

  // Classify subnet as public/private
  function classifySubnet(subnetId) {
    const routeLinks = links.filter(l => {
      const src = typeof l.source === 'object' ? l.source.id : l.source;
      return src === subnetId && l.label === 'routes_to';
    });
    for (const rtLink of routeLinks) {
      const rtId = typeof rtLink.target === 'object' ? rtLink.target.id : rtLink.target;
      const igwConnected = links.some(l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        return (s === rtId || t === rtId) && (IGW_TYPES.has(nodeMap[s]?.type) || IGW_TYPES.has(nodeMap[t]?.type));
      });
      if (igwConnected) return 'public';
    }
    const children = childrenMap[subnetId] || [];
    const hasInternet = children.some(childId =>
      links.some(l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        return s === childId && l.label === 'internet_connected';
      })
    );
    if (hasInternet) return 'public';
    const subnetNode = nodeMap[subnetId];
    if (subnetNode?.name?.toLowerCase().includes('public')) return 'public';
    return 'private';
  }

  // Derive AZ from subnet
  function deriveAZ(subnetNode) {
    if (!subnetNode) return 'default';
    const name = (subnetNode.name || '').toLowerCase();
    const azMatch = name.match(/([a-z]+-[a-z]+-\d+[a-f])/);
    if (azMatch) return azMatch[1];
    const shortMatch = name.match(/\b(\d[a-f])\b/);
    if (shortMatch && subnetNode.region) return `${subnetNode.region}${shortMatch[1]}`;
    return 'default';
  }

  // Helper: create empty tiers object
  function emptyTiers() {
    const t = {};
    TIER_ORDER.forEach(k => { t[k] = []; });
    return t;
  }

  // Helper: place a resource into the right tier
  function placeInTier(tiersObj, enrichedResource) {
    const tier = classifyResourceTier(enrichedResource.type || enrichedResource.service);
    const key = tier?.key || 'MONITORING'; // fallback to monitoring/governance
    if (!tiersObj[key]) tiersObj[key] = [];
    tiersObj[key].push(enrichedResource);
  }

  // Build the tree: accounts → regions → vnets → azs → subnets → tiers → resources
  const tree = {};
  const processedAsStructural = new Set();
  let filteredCount = 0;

  // Structural types rendered as boxes, not as leaf resources
  const STRUCTURAL_TYPES = new Set([
    ...VNET_TYPES, ...SUBNET_TYPES, ...IGW_TYPES,
    'ec2.security-group', 'ec2.network-acl', 'ec2.route-table',
    'ec2.network-interface', 'ec2.security-group-rule',
    'ec2.group',                      // AZ zone groups + SG normalizer fallback
    'network.network-security-group',
  ]);

  nodes.forEach(node => {
    if (STRUCTURAL_TYPES.has(node.type)) {
      processedAsStructural.add(node.id);
      return; // structural nodes become boxes, not leaf chips
    }
    if (node.synthetic) return;

    // Filter junk resource types (quota, metadata, generic fallbacks)
    if (isJunkResourceType(node.type)) {
      filteredCount++;
      return;
    }

    const acct = node.account_id || 'unknown';
    const region = node.region || 'global';
    const provider = node.provider || 'aws';

    const vnet = findAncestor(node.id, VNET_TYPES);
    const subnet = findAncestor(node.id, SUBNET_TYPES);

    if (!tree[acct]) tree[acct] = { provider, regions: {} };
    if (!tree[acct].regions[region]) tree[acct].regions[region] = { vnets: {}, globalTiers: emptyTiers() };

    const domain = classifyResourceDomain(node.type || node.service);
    const tierInfo = classifyResourceTier(node.type || node.service);
    const enriched = {
      ...node,
      domainKey: domain.key,
      domainColor: tierInfo?.color || domain.color,
      domainLabel: tierInfo?.label || domain.label,
      tierKey: tierInfo?.key || null,
      iconName: getServiceIcon(node.type || node.service),
      securityGroups: sgMap[node.id] || [],
    };

    if (vnet) {
      const vnetId = vnet.id;
      if (!tree[acct].regions[region].vnets[vnetId]) {
        tree[acct].regions[region].vnets[vnetId] = {
          node: vnet,
          azs: {},
          vpcTiers: emptyTiers(),
          hasIGW: false,
        };
      }
      const vnetData = tree[acct].regions[region].vnets[vnetId];
      if (!vnetData.hasIGW) {
        vnetData.hasIGW = links.some(l => {
          const s = typeof l.source === 'object' ? l.source.id : l.source;
          const t = typeof l.target === 'object' ? l.target.id : l.target;
          return (s === vnetId || t === vnetId) &&
            (l.label === 'attached_to' || l.label === 'connected_to') &&
            (IGW_TYPES.has(nodeMap[s]?.type) || IGW_TYPES.has(nodeMap[t]?.type));
        });
      }

      if (subnet) {
        const subnetId = subnet.id;
        const az = deriveAZ(subnet);
        const subnetClass = classifySubnet(subnetId);

        if (!vnetData.azs[az]) vnetData.azs[az] = { subnets: {} };
        if (!vnetData.azs[az].subnets[subnetId]) {
          vnetData.azs[az].subnets[subnetId] = {
            node: subnet,
            type: subnetClass,
            tiers: emptyTiers(),
          };
        }
        placeInTier(vnetData.azs[az].subnets[subnetId].tiers, enriched);
      } else {
        // In VPC but not in a subnet
        placeInTier(vnetData.vpcTiers, enriched);
      }
    } else {
      // Global / regional service (no VPC containment)
      placeInTier(tree[acct].regions[region].globalTiers, enriched);
    }
  });

  return { tree, filteredCount };
}

// ── Extract flow edges (non-structural) ──────────────────────────────────────
function extractFlowEdges(links) {
  return links.filter(l => !STRUCTURAL_RELATIONS.has(l.label));
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════════

function ResourceChip({ resource, onClick }) {
  const [hovered, setHovered] = useState(false);
  return (
    <div
      id={`resource-${resource.id}`}
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md cursor-pointer transition-all text-xs"
      style={{
        backgroundColor: hovered ? resource.domainColor + '20' : 'rgba(100,116,139,0.06)',
        border: `1px solid ${hovered ? resource.domainColor + '40' : 'rgba(100,116,139,0.10)'}`,
      }}
      onClick={() => onClick(resource)}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      title={`${resource.name || resource.id}\n${resource.type}\n${resource.domainLabel}`}
    >
      <LucideIcon name={resource.iconName} size={14} color={resource.domainColor} />
      <span style={{ color: 'var(--text-primary)', maxWidth: 140 }} className="truncate">
        {resource.name || resource.id?.split('/').pop() || resource.id}
      </span>
      {resource.securityGroups?.length > 0 && (
        <span className="text-[9px] px-1 rounded" style={{ backgroundColor: '#6366f120', color: '#6366f1' }}>
          {resource.securityGroups.length} SG
        </span>
      )}
    </div>
  );
}

// ── TierRow: renders one tier's resources with left-border color ─────────────
function TierRow({ tierKey, resources, onResourceClick }) {
  const [collapsed, setCollapsed] = useState(false);
  const tier = RESOURCE_TIERS[tierKey];
  if (!tier || !resources || resources.length === 0) return null;

  return (
    <div className="mb-1" style={{ backgroundColor: NESTING_COLORS.tier.bg, borderRadius: 4 }}>
      <div
        className="flex items-center gap-1.5 cursor-pointer py-1 px-2 rounded"
        style={{ borderLeft: `3px solid ${tier.color}` }}
        onClick={() => setCollapsed(!collapsed)}
      >
        <LucideIcon name={collapsed ? 'ChevronRight' : 'ChevronDown'} size={10} color="var(--text-tertiary)" />
        <LucideIcon name={tier.iconName} size={12} color={tier.color} />
        <span className="text-[10px] font-medium" style={{ color: tier.color }}>
          {tier.label}
        </span>
        <span className="text-[9px]" style={{ color: 'var(--text-tertiary)' }}>
          ({resources.length})
        </span>
      </div>
      {!collapsed && (
        <div className="flex flex-wrap gap-1 mt-0.5 pb-1.5 px-2 pl-5">
          {resources.map(r => (
            <ResourceChip key={r.id} resource={r} onClick={onResourceClick} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── SubnetBox: containment box with tier-grouped resources ───────────────────
function SubnetBox({ subnetData, onResourceClick }) {
  const isPublic = subnetData.type === 'public';
  const subnetName = subnetData.node?.name || subnetData.node?.id?.split('/').pop() || 'Subnet';
  const totalResources = countTierResources(subnetData.tiers);

  return (
    <div
      className="rounded-lg border p-2 mb-2"
      style={{
        backgroundColor: NESTING_COLORS.subnet.bg,
        borderColor: isPublic ? '#10b98140' : NESTING_COLORS.subnet.border,
        borderLeftWidth: 3,
        borderLeftColor: isPublic ? '#10b981' : 'rgba(100,116,139,0.35)',
      }}
    >
      <div className="flex items-center gap-1.5 mb-1.5">
        {isPublic && <LucideIcon name="Globe" size={12} color="#10b981" />}
        <LucideIcon name="Layers" size={12} color={isPublic ? '#10b981' : 'var(--text-tertiary)'} />
        <span className="text-[10px] font-semibold" style={{ color: isPublic ? '#10b981' : 'var(--text-secondary)' }}>
          {isPublic ? 'Public' : 'Private'} Subnet — {subnetName}
        </span>
        <span className="text-[9px]" style={{ color: 'var(--text-tertiary)' }}>
          ({totalResources})
        </span>
      </div>
      <div className="space-y-0.5">
        {TIER_ORDER.map(tierKey => (
          <TierRow
            key={tierKey}
            tierKey={tierKey}
            resources={subnetData.tiers?.[tierKey]}
            onResourceClick={onResourceClick}
          />
        ))}
      </div>
    </div>
  );
}

// ── AZColumn: availability zone containment box ──────────────────────────────
function AZColumn({ azName, azData, onResourceClick }) {
  const subnets = Object.values(azData.subnets);
  const publicSubnets = subnets.filter(s => s.type === 'public');
  const privateSubnets = subnets.filter(s => s.type === 'private');
  const totalResources = subnets.reduce((sum, s) => sum + countTierResources(s.tiers), 0);

  return (
    <div
      className="flex-1 min-w-[240px] rounded-lg border p-2"
      style={{
        backgroundColor: NESTING_COLORS.az.bg,
        borderColor: NESTING_COLORS.az.border,
        borderStyle: 'dashed',
      }}
    >
      <div className="flex items-center gap-1.5 mb-2 px-1">
        <LucideIcon name="MapPin" size={12} color="var(--text-tertiary)" />
        <span className="text-[10px] font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {azName === 'default' ? 'Default Zone' : azName}
        </span>
        <span className="text-[9px]" style={{ color: 'var(--text-tertiary)' }}>
          ({totalResources} resources)
        </span>
      </div>
      {publicSubnets.map(s => (
        <SubnetBox key={s.node?.id || Math.random()} subnetData={s} onResourceClick={onResourceClick} />
      ))}
      {privateSubnets.map(s => (
        <SubnetBox key={s.node?.id || Math.random()} subnetData={s} onResourceClick={onResourceClick} />
      ))}
    </div>
  );
}

// ── VNetBox: VPC/VNet/VCN containment box ────────────────────────────────────
function VNetBox({ vnetId, vnetData, provider, onResourceClick }) {
  const vnetLabel = getVNetLabel(provider);
  const vnetName = vnetData.node?.name || vnetId.split('/').pop() || vnetId;
  const azEntries = Object.entries(vnetData.azs);
  const totalInSubnets = azEntries.reduce((sum, [, az]) =>
    sum + Object.values(az.subnets).reduce((s, sub) => s + countTierResources(sub.tiers), 0), 0
  );
  const totalVpcLevel = countTierResources(vnetData.vpcTiers);
  const totalResources = totalInSubnets + totalVpcLevel;

  return (
    <div
      className="rounded-xl border p-3 mb-3"
      style={{
        backgroundColor: NESTING_COLORS.vpc.bg,
        borderColor: NESTING_COLORS.vpc.border,
        borderWidth: 2,
      }}
    >
      {/* VNet Header */}
      <div className="flex items-center gap-2 mb-3">
        <LucideIcon name="Network" size={16} color="rgba(100,116,139,0.8)" />
        <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
          {vnetLabel}: {vnetName}
        </span>
        <span className="text-[10px] px-1.5 py-0.5 rounded"
          style={{ backgroundColor: 'rgba(100,116,139,0.10)', color: 'var(--text-secondary)' }}>
          {totalResources} resources
        </span>
        {vnetData.hasIGW && (
          <span className="text-[10px] px-1.5 py-0.5 rounded flex items-center gap-1"
            style={{ backgroundColor: '#10b98115', color: '#10b981' }}>
            <LucideIcon name="Globe" size={10} color="#10b981" />
            Internet Gateway
          </span>
        )}
      </div>

      {/* AZ Columns */}
      {azEntries.length > 0 && (
        <div className="flex gap-2 flex-wrap">
          {azEntries.map(([azName, azData]) => (
            <AZColumn key={azName} azName={azName} azData={azData} onResourceClick={onResourceClick} />
          ))}
        </div>
      )}

      {/* VPC-level resources (not in any subnet) — tier grouped */}
      {totalVpcLevel > 0 && (
        <div className="mt-2 p-2 rounded-lg border"
          style={{ borderColor: NESTING_COLORS.az.border, backgroundColor: NESTING_COLORS.az.bg }}>
          <span className="text-[10px] font-semibold mb-1.5 block" style={{ color: 'var(--text-secondary)' }}>
            {vnetLabel}-level Resources ({totalVpcLevel})
          </span>
          <div className="space-y-0.5">
            {TIER_ORDER.map(tierKey => (
              <TierRow
                key={tierKey}
                tierKey={tierKey}
                resources={vnetData.vpcTiers?.[tierKey]}
                onResourceClick={onResourceClick}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── GlobalServicesBox: tier-grouped global/regional resources ─────────────────
function GlobalServicesBox({ globalTiers, onResourceClick }) {
  const totalResources = countTierResources(globalTiers);
  if (totalResources === 0) return null;

  return (
    <div className="rounded-lg border p-3 mb-3"
      style={{ backgroundColor: NESTING_COLORS.az.bg, borderColor: NESTING_COLORS.az.border }}>
      <div className="flex items-center gap-2 mb-2">
        <LucideIcon name="Cloud" size={14} color="var(--text-tertiary)" />
        <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
          GLOBAL / REGIONAL SERVICES
        </span>
        <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
          ({totalResources})
        </span>
      </div>
      <div className="space-y-0.5">
        {TIER_ORDER.map(tierKey => (
          <TierRow
            key={tierKey}
            tierKey={tierKey}
            resources={globalTiers?.[tierKey]}
            onResourceClick={onResourceClick}
          />
        ))}
      </div>
    </div>
  );
}

// ── AccountCard: outermost containment box ───────────────────────────────────
function AccountCard({ accountId, accountData, onResourceClick }) {
  const provider = accountData.provider || 'aws';
  const cspInfo = CLOUD_PROVIDERS[provider] || CLOUD_PROVIDERS.aws;
  const regions = Object.entries(accountData.regions || {});

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
        <span
          className="text-xs font-bold px-2.5 py-1 rounded-md"
          style={{ backgroundColor: cspInfo.color + '20', color: cspInfo.color }}
        >
          {cspInfo.name}
        </span>
        <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
          Account: {accountId}
        </span>
      </div>

      {/* Regions */}
      {regions.map(([regionName, regionData]) => (
        <div key={regionName} className="mb-3 rounded-lg border p-3"
          style={{ backgroundColor: NESTING_COLORS.region.bg, borderColor: NESTING_COLORS.region.border }}>
          {/* Region Header */}
          <div className="flex items-center gap-2 mb-2">
            <LucideIcon name="MapPin" size={14} color="var(--text-tertiary)" />
            <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
              Region: {regionName}
            </span>
          </div>

          {/* Global Services Box (tier-grouped) */}
          <GlobalServicesBox globalTiers={regionData.globalTiers} onResourceClick={onResourceClick} />

          {/* VNets */}
          {Object.entries(regionData.vnets || {}).map(([vnetId, vnetData]) => (
            <VNetBox
              key={vnetId}
              vnetId={vnetId}
              vnetData={vnetData}
              provider={provider}
              onResourceClick={onResourceClick}
            />
          ))}

          {/* No resources in region */}
          {Object.keys(regionData.vnets || {}).length === 0 && countTierResources(regionData.globalTiers) === 0 && (
            <div className="text-xs p-3 text-center" style={{ color: 'var(--text-tertiary)' }}>
              No resources in this region
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Connection Arrows SVG Overlay ────────────────────────────────────────────
function ConnectionArrows({ flowEdges, containerRef }) {
  const [arrows, setArrows] = useState([]);

  useEffect(() => {
    if (!containerRef.current || flowEdges.length === 0) return;

    const timer = setTimeout(() => {
      const containerRect = containerRef.current.getBoundingClientRect();
      const newArrows = [];

      flowEdges.forEach(edge => {
        const srcId = typeof edge.source === 'object' ? edge.source.id : edge.source;
        const tgtId = typeof edge.target === 'object' ? edge.target.id : edge.target;
        const sourceEl = document.getElementById(`resource-${srcId}`);
        const targetEl = document.getElementById(`resource-${tgtId}`);

        if (sourceEl && targetEl) {
          const srcRect = sourceEl.getBoundingClientRect();
          const tgtRect = targetEl.getBoundingClientRect();

          newArrows.push({
            x1: srcRect.left + srcRect.width / 2 - containerRect.left,
            y1: srcRect.bottom - containerRect.top,
            x2: tgtRect.left + tgtRect.width / 2 - containerRect.left,
            y2: tgtRect.top - containerRect.top,
            label: edge.label,
            color: getArrowColor(edge.label),
          });
        }
      });

      setArrows(newArrows);
    }, 500);

    return () => clearTimeout(timer);
  }, [flowEdges, containerRef]);

  if (arrows.length === 0) return null;

  return (
    <svg
      className="absolute inset-0 pointer-events-none"
      style={{ width: '100%', height: '100%', overflow: 'visible' }}
    >
      <defs>
        {Object.entries(ARROW_COLORS).map(([family, color]) => (
          <marker
            key={family}
            id={`arrow-${family}`}
            markerWidth="6"
            markerHeight="4"
            refX="5"
            refY="2"
            orient="auto"
          >
            <path d="M0,0 L6,2 L0,4 Z" fill={color} opacity="0.6" />
          </marker>
        ))}
      </defs>
      {arrows.map((arrow, i) => {
        const family = classifyLinkFamily(arrow.label);
        const dx = arrow.x2 - arrow.x1;
        const dy = arrow.y2 - arrow.y1;
        const cx = arrow.x1 + dx / 2 + (dy > 0 ? 30 : -30);
        const cy = arrow.y1 + dy / 2;

        return (
          <g key={i}>
            <path
              d={`M ${arrow.x1} ${arrow.y1} Q ${cx} ${cy} ${arrow.x2} ${arrow.y2}`}
              fill="none"
              stroke={arrow.color}
              strokeWidth="1.5"
              strokeDasharray={family === 'execution' ? '4,3' : family === 'data' ? '2,2' : 'none'}
              opacity="0.4"
              markerEnd={`url(#arrow-${family})`}
            />
          </g>
        );
      })}
    </svg>
  );
}

// ── Stats Strip ──────────────────────────────────────────────────────────────
function StatsStrip({ tree, totalNodes, totalLinks, flowEdgeCount, filteredCount }) {
  const accounts = Object.keys(tree);
  let vnetCount = 0;
  let subnetCount = 0;
  let resourceCount = 0;
  accounts.forEach(acct => {
    Object.values(tree[acct].regions).forEach(region => {
      resourceCount += countTierResources(region.globalTiers);
      Object.values(region.vnets).forEach(vnet => {
        vnetCount++;
        resourceCount += countTierResources(vnet.vpcTiers);
        Object.values(vnet.azs).forEach(az => {
          Object.values(az.subnets).forEach(sub => {
            subnetCount++;
            resourceCount += countTierResources(sub.tiers);
          });
        });
      });
    });
  });

  const stats = [
    { label: 'Accounts', value: accounts.length, icon: 'Building2' },
    { label: 'VPCs/VNets', value: vnetCount, icon: 'Network' },
    { label: 'Subnets', value: subnetCount, icon: 'Layers' },
    { label: 'Resources', value: resourceCount, icon: 'Server' },
    { label: 'Connections', value: flowEdgeCount, icon: 'ArrowRightLeft' },
  ];
  if (filteredCount > 0) {
    stats.push({ label: 'Filtered', value: filteredCount, icon: 'EyeOff', dimmed: true });
  }

  return (
    <div className="flex flex-wrap gap-3">
      {stats.map(s => (
        <div key={s.label} className="flex items-center gap-2 px-3 py-2 rounded-lg border"
          style={{
            backgroundColor: s.dimmed ? 'transparent' : 'var(--bg-card)',
            borderColor: s.dimmed ? 'rgba(100,116,139,0.15)' : 'var(--border-primary)',
            opacity: s.dimmed ? 0.6 : 1,
          }}>
          <LucideIcon name={s.icon} size={14} color="var(--text-tertiary)" />
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{s.label}</span>
          <span className="text-sm font-semibold" style={{ color: s.dimmed ? 'var(--text-tertiary)' : 'var(--text-primary)' }}>
            {s.value}
          </span>
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════════════

export default function ArchitectureDiagramPage() {
  const router = useRouter();
  const containerRef = useRef(null);
  const { provider, account, region } = useGlobalFilter();

  const [rawData, setRawData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [zoom, setZoom] = useState(1);

  // Fetch graph data
  useEffect(() => {
    const loadGraph = async () => {
      setLoading(true);
      setError(null);
      try {
        const params = { depth: 3, limit: 500 };
        if (provider) params.provider = provider;
        const data = await getFromEngine(
          'inventory',
          '/api/v1/inventory/runs/latest/graph',
          params
        );
        if (data.error) { setError(data.error); return; }
        setRawData({ nodes: data.nodes || [], links: data.links || [] });
      } catch (err) {
        setError(err?.message || 'Failed to load architecture data');
      } finally {
        setLoading(false);
      }
    };
    loadGraph();
  }, [provider, account, region]);

  // Build containment tree with tier grouping
  const { tree, filteredCount } = useMemo(() => {
    if (rawData.nodes.length === 0) return { tree: {}, filteredCount: 0 };
    return buildContainmentTree(rawData.nodes, rawData.links);
  }, [rawData]);

  // Extract flow edges
  const flowEdges = useMemo(() => extractFlowEdges(rawData.links), [rawData.links]);

  // Resource click → navigate to asset detail
  const handleResourceClick = useCallback((resource) => {
    if (resource?.id) {
      router.push(`/inventory/${encodeURIComponent(resource.id)}`);
    }
  }, [router]);

  // Zoom controls
  const zoomIn = () => setZoom(z => Math.min(z * 1.2, 3));
  const zoomOut = () => setZoom(z => Math.max(z / 1.2, 0.3));
  const zoomFit = () => setZoom(1);

  const accountEntries = Object.entries(tree);

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
              Live topology — Account → Region → VPC → AZ → Subnet → Tier → Resources
            </p>
          </div>
        </div>
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

      {/* Stats Strip */}
      {!loading && !error && (
        <StatsStrip
          tree={tree}
          totalNodes={rawData.nodes.length}
          totalLinks={rawData.links.length}
          flowEdgeCount={flowEdges.length}
          filteredCount={filteredCount}
        />
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

      {/* Architecture Diagram */}
      {!loading && !error && (
        <div
          className="rounded-xl border overflow-auto relative"
          style={{
            backgroundColor: 'var(--bg-primary)',
            borderColor: 'var(--border-primary)',
            maxHeight: 'calc(100vh - 240px)',
          }}
          ref={containerRef}
        >
          <div
            style={{
              transform: `scale(${zoom})`,
              transformOrigin: 'top left',
              padding: 16,
              minWidth: zoom < 1 ? `${100 / zoom}%` : '100%',
            }}
          >
            {accountEntries.length === 0 ? (
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
              accountEntries.map(([accountId, accountData]) => (
                <AccountCard
                  key={accountId}
                  accountId={accountId}
                  accountData={accountData}
                  onResourceClick={handleResourceClick}
                />
              ))
            )}
          </div>

          {/* SVG Connection Arrows */}
          <ConnectionArrows flowEdges={flowEdges} containerRef={containerRef} />
        </div>
      )}

      {/* Legend */}
      {!loading && !error && accountEntries.length > 0 && (
        <div className="flex flex-wrap gap-4 px-1">
          {/* Tier colors */}
          <div className="flex items-center gap-4">
            <span className="text-[10px] font-semibold" style={{ color: 'var(--text-tertiary)' }}>TIERS:</span>
            {TIER_ORDER.map(tierKey => {
              const tier = RESOURCE_TIERS[tierKey];
              return (
                <div key={tierKey} className="flex items-center gap-1">
                  <div className="w-2.5 h-0.5 rounded" style={{ backgroundColor: tier.color }} />
                  <LucideIcon name={tier.iconName} size={10} color={tier.color} />
                  <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{tier.label}</span>
                </div>
              );
            })}
          </div>
          {/* Arrow types */}
          <div className="flex items-center gap-4">
            <span className="text-[10px] font-semibold" style={{ color: 'var(--text-tertiary)' }}>ARROWS:</span>
            {[
              { label: 'Traffic', color: ARROW_COLORS.network, dash: false },
              { label: 'Data', color: ARROW_COLORS.data, dash: false },
              { label: 'Execution', color: ARROW_COLORS.execution, dash: true },
              { label: 'Security', color: ARROW_COLORS.security, dash: false },
              { label: 'Identity', color: ARROW_COLORS.identity, dash: false },
            ].map(a => (
              <div key={a.label} className="flex items-center gap-1">
                <div style={{ width: 16, height: 2, backgroundColor: a.color, borderRadius: 1,
                  ...(a.dash ? { backgroundImage: `repeating-linear-gradient(90deg, ${a.color} 0 4px, transparent 4px 7px)`, backgroundColor: 'transparent' } : {})
                }} />
                <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{a.label}</span>
              </div>
            ))}
          </div>
          {/* Nesting depth visual */}
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-semibold" style={{ color: 'var(--text-tertiary)' }}>NESTING:</span>
            {[
              { label: 'Account', colors: NESTING_COLORS.account },
              { label: 'Region', colors: NESTING_COLORS.region },
              { label: 'VPC', colors: NESTING_COLORS.vpc },
              { label: 'AZ', colors: NESTING_COLORS.az },
              { label: 'Subnet', colors: NESTING_COLORS.subnet },
            ].map(item => (
              <div key={item.label} className="flex items-center gap-1">
                <div className="w-3 h-3 rounded border" style={{
                  backgroundColor: item.colors.bg,
                  borderColor: item.colors.border,
                }} />
                <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{item.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
