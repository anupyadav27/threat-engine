'use client';

import React, {
  useState,
  useEffect,
  useRef,
  useMemo,
  useCallback,
} from 'react';
import { fetchView, getFromEngine } from '@/lib/api';
import { getServiceIcon } from '@/lib/inventory-taxonomy';
import * as LucideIcons from 'lucide-react';
import {
  Network,
  ChevronRight,
  Search,
  X,
  ZoomIn,
  ZoomOut,
  Maximize2,
  ShieldAlert,
  Globe,
  ExternalLink,
  GitBranch,
  AlertTriangle,
  Eye,
  Filter,
  RotateCcw,
  Server,
  HardDrive,
  Database,
  Cpu,
  KeyRound,
  Lock,
  Shield,
  Layers,
  Scale,
  Box,
} from 'lucide-react';
import { TENANT_ID } from '@/lib/constants';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityBadge from '@/components/shared/SeverityBadge';
import EmptyState from '@/components/shared/EmptyState';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

// ---------------------------------------------------------------------------
// Lucide icon resolver — maps icon name string to React component
// ---------------------------------------------------------------------------
function getLucideIcon(name) {
  if (!name) return Box;
  return LucideIcons[name] || Box;
}

// ---------------------------------------------------------------------------
// Node type configuration
// ---------------------------------------------------------------------------
const NODE_TYPE_CONFIG = {
  Internet:        { color: '#ef4444', label: 'Internet',       iconName: 'Globe' },
  EC2:             { color: '#3b82f6', label: 'EC2',            iconName: 'Server' },
  S3:              { color: '#22c55e', label: 'S3',             iconName: 'HardDrive' },
  IAM:             { color: '#a855f7', label: 'IAM',            iconName: 'KeyRound' },
  RDS:             { color: '#f97316', label: 'RDS',            iconName: 'Database' },
  Lambda:          { color: '#06b6d4', label: 'Lambda',         iconName: 'Cpu' },
  VPC:             { color: '#8b5cf6', label: 'VPC',            iconName: 'Network' },
  SecurityGroup:   { color: '#ef4444', label: 'Security Group', iconName: 'Shield' },
  LoadBalancer:    { color: '#eab308', label: 'Load Balancer',  iconName: 'Scale' },
  CloudFront:      { color: '#f59e0b', label: 'CloudFront',     iconName: 'Gauge' },
  DynamoDB:        { color: '#527fff', label: 'DynamoDB',       iconName: 'Table' },
  SNS:             { color: '#ec4899', label: 'SNS',            iconName: 'Bell' },
  SQS:             { color: '#ec4899', label: 'SQS',            iconName: 'Inbox' },
  KMS:             { color: '#dc2626', label: 'KMS',            iconName: 'Lock' },
  Subnet:          { color: '#7c3aed', label: 'Subnet',         iconName: 'Layers' },
  NATGateway:      { color: '#f97316', label: 'NAT Gateway',    iconName: 'ArrowLeftRight' },
  ElastiCache:     { color: '#c7131f', label: 'ElastiCache',    iconName: 'Zap' },
  EKS:             { color: '#326ce5', label: 'EKS',            iconName: 'Ship' },
  ECS:             { color: '#ff9900', label: 'ECS',            iconName: 'Container' },
  threat:          { color: '#dc2626', label: 'Threat',         iconName: 'ShieldAlert' },
  Account:         { color: '#0ea5e9', label: 'Account',        iconName: 'Building2' },
  Org:             { color: '#0284c7', label: 'Organization',   iconName: 'Building' },
  Finding:         { color: '#f97316', label: 'Finding',        iconName: 'AlertTriangle' },
};

const DEFAULT_NODE_COLOR = '#6b7280';

// ---------------------------------------------------------------------------
// Edge type configuration
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Edge type configuration — kind: 'path' | 'association'
// 'path' edges are drawn solid (attacker traversal route)
// 'association' edges are drawn dashed (context: findings, encryption, etc.)
// ---------------------------------------------------------------------------
const EDGE_TYPE_CONFIG = {
  // ── PATH edges (attack traversal) ──���───────────────────────────────────
  EXPOSES:         { color: '#ef4444', label: 'Exposes',        kind: 'path' },
  ASSUMES:         { color: '#c084fc', label: 'Assumes',        kind: 'path' },
  CAN_ASSUME:      { color: '#c084fc', label: 'Can Assume',     kind: 'path' },
  CAN_ACCESS:      { color: '#a855f7', label: 'Can Access',     kind: 'path' },
  ACCESSES:        { color: '#a855f7', label: 'Accesses',       kind: 'path' },
  STORES:          { color: '#22c55e', label: 'Stores Data',    kind: 'path' },
  ROUTES_TO:       { color: '#eab308', label: 'Routes To',      kind: 'path' },
  CONNECTS_TO:     { color: '#60a5fa', label: 'Connects To',    kind: 'path' },
  ATTACHED_TO:     { color: '#3b82f6', label: 'Attached To',    kind: 'path' },
  HOSTED_IN:       { color: '#6366f1', label: 'Hosted In',      kind: 'path' },
  IN_VPC:          { color: '#8b5cf6', label: 'In VPC',         kind: 'path' },
  RUNS_ON:         { color: '#06b6d4', label: 'Runs On',        kind: 'path' },
  ALLOWS_TRAFFIC:  { color: '#22c55e', label: 'Allows Traffic', kind: 'path' },
  // ── ASSOCIATION edges (context only, dashed) ───────────────────────────
  HAS_THREAT:      { color: '#ef4444', label: 'Has Threat',     kind: 'association' },
  HAS_FINDING:     { color: '#f97316', label: 'Has Finding',    kind: 'association' },
  AFFECTED_BY:     { color: '#f87171', label: 'Affected By',    kind: 'association' },
  ENCRYPTED_BY:    { color: '#64748b', label: 'Encrypted By',   kind: 'association' },
  PROTECTED_BY:    { color: '#06b6d4', label: 'Protected By',   kind: 'association' },
  DEPENDS_ON:      { color: '#64748b', label: 'Depends On',     kind: 'association' },
  PROTECTS:        { color: '#06b6d4', label: 'Protects',       kind: 'association' },
  OWNS:            { color: '#fbbf24', label: 'Owns',           kind: 'association' },
  MEMBER_OF:       { color: '#94a3b8', label: 'Member Of',      kind: 'association' },
  LOGS_TO:         { color: '#475569', label: 'Logs To',        kind: 'association' },
  AFFECTS:         { color: '#f87171', label: 'Affects',        kind: 'association' },
  CONTAINS:        { color: '#06b6d4', label: 'Contains',       kind: 'association' },
  HAS_ACCESS:      { color: '#a855f7', label: 'Has Access',     kind: 'association' },
  REFERENCES:      { color: '#3b82f6', label: 'References',     kind: 'association' },
  RELATES_TO:      { color: '#94a3b8', label: 'Relates To',     kind: 'association' },
};

const DEFAULT_EDGE_COLOR = '#525252';

// ---------------------------------------------------------------------------
// Force simulation helpers
// ---------------------------------------------------------------------------
function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

function forceSimulation(nodes, edges, width, height, iterations = 200) {
  const CHARGE = -500;
  const LINK_DIST = 140;
  const COLLISION_PAD = 14;
  const ALPHA_DECAY = 0.02;

  // Initialize positions from center with jitter
  const cx = width / 2;
  const cy = height / 2;
  nodes.forEach((n) => {
    if (n.x == null) n.x = cx + (Math.random() - 0.5) * width * 0.6;
    if (n.y == null) n.y = cy + (Math.random() - 0.5) * height * 0.6;
    n.vx = 0;
    n.vy = 0;
  });

  // Build adjacency for quick lookup
  const nodeMap = {};
  nodes.forEach((n) => { nodeMap[n.id] = n; });

  let alpha = 1;

  for (let tick = 0; tick < iterations; tick++) {
    alpha *= (1 - ALPHA_DECAY);
    if (alpha < 0.001) break;

    // Charge repulsion (n^2 but acceptable for < 2000 nodes)
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (CHARGE * alpha) / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx -= fx;
        a.vy -= fy;
        b.vx += fx;
        b.vy += fy;
      }
    }

    // Link attraction
    edges.forEach((e) => {
      const src = nodeMap[e.source];
      const tgt = nodeMap[e.target];
      if (!src || !tgt) return;
      let dx = tgt.x - src.x;
      let dy = tgt.y - src.y;
      let dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - LINK_DIST) * 0.05 * alpha;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      src.vx += fx;
      src.vy += fy;
      tgt.vx -= fx;
      tgt.vy -= fy;
    });

    // Center gravity
    nodes.forEach((n) => {
      n.vx += (cx - n.x) * 0.01 * alpha;
      n.vy += (cy - n.y) * 0.01 * alpha;
    });

    // Collision
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        const rA = (a._radius || 8) + COLLISION_PAD;
        const rB = (b._radius || 8) + COLLISION_PAD;
        const minDist = rA + rB;
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < minDist) {
          const overlap = (minDist - dist) / 2;
          const ox = (dx / dist) * overlap;
          const oy = (dy / dist) * overlap;
          a.x -= ox;
          a.y -= oy;
          b.x += ox;
          b.y += oy;
        }
      }
    }

    // Velocity decay + position update
    nodes.forEach((n) => {
      n.vx *= 0.6;
      n.vy *= 0.6;
      n.x += n.vx;
      n.y += n.vy;
      // Keep within bounds with padding
      n.x = clamp(n.x, 40, width - 40);
      n.y = clamp(n.y, 40, height - 40);
    });
  }
}

// ---------------------------------------------------------------------------
// SecurityGraph SVG component
// ---------------------------------------------------------------------------
function SecurityGraph({
  nodes,
  edges,
  selectedNodeId,
  onNodeClick,
  searchQuery,
  visibleNodeTypes,
  visibleEdgeTypes,
  viewPreset,
  highlightedNodeIds,
  containerWidth,
  containerHeight,
}) {
  const svgRef = useRef(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 });
  const [dragNode, setDragNode] = useState(null);
  const [isPanning, setIsPanning] = useState(false);
  const panStart = useRef({ x: 0, y: 0, tx: 0, ty: 0 });
  const [nodePositions, setNodePositions] = useState({});
  const rafRef = useRef(null);

  const width = containerWidth || 1200;
  const height = containerHeight || 600;

  // Filter nodes and edges
  const filteredNodes = useMemo(() => {
    return nodes.filter((n) => {
      const nType = normalizeType(n.type || n.resourceType || '');
      if (visibleNodeTypes && !visibleNodeTypes.has(nType)) return false;
      // Threat hunting presets
      if (viewPreset === 'threats') {
        return n.has_threat || (n.threats ?? n.threatCount ?? 0) > 0;
      }
      if (viewPreset === 'internet') {
        return n.internet_exposed ?? n.internetExposed ?? false;
      }
      return true;
    });
  }, [nodes, visibleNodeTypes, viewPreset]);

  const filteredNodeIds = useMemo(
    () => new Set(filteredNodes.map((n) => n.id)),
    [filteredNodes]
  );

  const filteredEdges = useMemo(() => {
    return edges.filter((e) => {
      const eType = (e.type || e.relationship || '').toUpperCase().replace(/\s+/g, '_');
      return (
        (!visibleEdgeTypes || visibleEdgeTypes.has(eType)) &&
        filteredNodeIds.has(e.source) &&
        filteredNodeIds.has(e.target)
      );
    });
  }, [edges, visibleEdgeTypes, filteredNodeIds]);

  // Compute connection counts for sizing
  const connectionCounts = useMemo(() => {
    const counts = {};
    filteredEdges.forEach((e) => {
      counts[e.source] = (counts[e.source] || 0) + 1;
      counts[e.target] = (counts[e.target] || 0) + 1;
    });
    return counts;
  }, [filteredEdges]);

  // Run simulation
  useEffect(() => {
    if (filteredNodes.length === 0) return;

    const simNodes = filteredNodes.map((n) => {
      const conns = connectionCounts[n.id] || 0;
      const radius = Math.max(16, Math.min(24, 16 + Math.min(conns, 10) * 0.8));
      return {
        ...n,
        x: nodePositions[n.id]?.x ?? null,
        y: nodePositions[n.id]?.y ?? null,
        _radius: radius,
      };
    });

    forceSimulation(simNodes, filteredEdges, width, height, 200);

    const pos = {};
    simNodes.forEach((n) => {
      pos[n.id] = { x: n.x, y: n.y, _radius: n._radius };
    });
    setNodePositions(pos);
  }, [filteredNodes.length, filteredEdges.length, width, height]); // eslint-disable-line react-hooks/exhaustive-deps

  // Search highlight
  const searchMatch = useMemo(() => {
    if (!searchQuery.trim()) return null;
    const q = searchQuery.toLowerCase();
    return new Set(
      filteredNodes
        .filter(
          (n) =>
            (n.label || '').toLowerCase().includes(q) ||
            (n.id || '').toLowerCase().includes(q) ||
            (n.resourceName || '').toLowerCase().includes(q)
        )
        .map((n) => n.id)
    );
  }, [filteredNodes, searchQuery]);

  // Connected nodes to selected
  const connectedToSelected = useMemo(() => {
    if (!selectedNodeId) return new Set();
    const connected = new Set([selectedNodeId]);
    filteredEdges.forEach((e) => {
      if (e.source === selectedNodeId) connected.add(e.target);
      if (e.target === selectedNodeId) connected.add(e.source);
    });
    return connected;
  }, [selectedNodeId, filteredEdges]);

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    setTransform((t) => ({ ...t, k: Math.min(t.k * 1.3, 5) }));
  }, []);

  const handleZoomOut = useCallback(() => {
    setTransform((t) => ({ ...t, k: Math.max(t.k / 1.3, 0.2) }));
  }, []);

  const handleZoomReset = useCallback(() => {
    setTransform({ x: 0, y: 0, k: 1 });
  }, []);

  // Wheel zoom
  const handleWheel = useCallback((e) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setTransform((t) => ({
      ...t,
      k: clamp(t.k * delta, 0.2, 5),
    }));
  }, []);

  // Pan handlers
  const handleMouseDown = useCallback(
    (e) => {
      if (e.target === svgRef.current || e.target.tagName === 'rect') {
        setIsPanning(true);
        panStart.current = {
          x: e.clientX,
          y: e.clientY,
          tx: transform.x,
          ty: transform.y,
        };
      }
    },
    [transform]
  );

  const handleMouseMove = useCallback(
    (e) => {
      if (dragNode) {
        // Dragging a node
        const dx = (e.clientX - panStart.current.x) / transform.k;
        const dy = (e.clientY - panStart.current.y) / transform.k;
        setNodePositions((prev) => ({
          ...prev,
          [dragNode]: {
            ...prev[dragNode],
            x: (prev[dragNode]?.x || 0) + dx,
            y: (prev[dragNode]?.y || 0) + dy,
          },
        }));
        panStart.current.x = e.clientX;
        panStart.current.y = e.clientY;
        return;
      }
      if (isPanning) {
        const dx = e.clientX - panStart.current.x;
        const dy = e.clientY - panStart.current.y;
        setTransform((t) => ({
          ...t,
          x: panStart.current.tx + dx,
          y: panStart.current.ty + dy,
        }));
      }
    },
    [isPanning, dragNode, transform.k]
  );

  const handleMouseUp = useCallback(() => {
    setIsPanning(false);
    setDragNode(null);
  }, []);

  // Node drag start
  const handleNodeMouseDown = useCallback(
    (e, nodeId) => {
      e.stopPropagation();
      setDragNode(nodeId);
      panStart.current = { x: e.clientX, y: e.clientY };
    },
    []
  );

  // Keyboard
  useEffect(() => {
    const handler = (e) => {
      if (e.key === 'Escape') onNodeClick(null);
      if (e.key === '+' || e.key === '=') handleZoomIn();
      if (e.key === '-') handleZoomOut();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onNodeClick, handleZoomIn, handleZoomOut]);

  const getNodeColor = (type) => {
    const nType = normalizeType(type);
    return NODE_TYPE_CONFIG[nType]?.color || DEFAULT_NODE_COLOR;
  };

  const getEdgeColor = (type) => {
    const eType = (type || '').toUpperCase().replace(/\s+/g, '_');
    return EDGE_TYPE_CONFIG[eType]?.color || DEFAULT_EDGE_COLOR;
  };

  return (
    <div className="relative w-full" style={{ height: `${height}px` }}>
      {/* Zoom controls */}
      <div className="absolute top-3 right-3 z-10 flex flex-col gap-1.5">
        <button
          onClick={handleZoomIn}
          className="p-2 rounded-lg border transition-colors hover:opacity-80"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
          title="Zoom in (+)"
        >
          <ZoomIn className="w-4 h-4" style={{ color: 'var(--text-primary)' }} />
        </button>
        <button
          onClick={handleZoomOut}
          className="p-2 rounded-lg border transition-colors hover:opacity-80"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
          title="Zoom out (-)"
        >
          <ZoomOut className="w-4 h-4" style={{ color: 'var(--text-primary)' }} />
        </button>
        <button
          onClick={handleZoomReset}
          className="p-2 rounded-lg border transition-colors hover:opacity-80"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
          title="Reset zoom"
        >
          <Maximize2 className="w-4 h-4" style={{ color: 'var(--text-primary)' }} />
        </button>
      </div>

      {/* Legend bar */}
      <div className="absolute bottom-3 left-3 z-10 flex items-center gap-4 px-3 py-2 rounded-lg border"
        style={{ backgroundColor: 'rgba(10,10,10,0.85)', borderColor: 'var(--border-primary)' }}
      >
        <span className="text-[10px] font-medium" style={{ color: 'var(--text-secondary)' }}>
          Click node to inspect | Scroll to zoom | Drag to pan
        </span>
      </div>

      <svg
        ref={svgRef}
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-full"
        style={{ backgroundColor: '#0a0e17', cursor: isPanning ? 'grabbing' : 'grab' }}
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <defs>
          {/* Arrow marker */}
          <marker
            id="arrowhead"
            viewBox="0 0 10 7"
            refX="10"
            refY="3.5"
            markerWidth="8"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <polygon points="0 0, 10 3.5, 0 7" fill="currentColor" opacity="0.6" />
          </marker>
          {/* Glow filter for selected node */}
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Background for click-to-deselect */}
        <rect
          width={width}
          height={height}
          fill="transparent"
          onClick={() => onNodeClick(null)}
        />

        <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.k})`}>
          {/* Two-layer edge rendering:
              Pass 1 — ASSOCIATION edges (dashed, behind nodes, subtle)
              Pass 2 — PATH edges (solid, in front, colored by attack category)
              This matches Orca's visual model: route is prominent, context is subtle. */}
          {(() => {
            // Sort: association edges first (drawn under path edges)
            const sortedEdges = [
              ...filteredEdges.filter(e => {
                const eType = (e.type || e.relationship || '').toUpperCase().replace(/\s+/g, '_');
                return (e.edge_kind || EDGE_TYPE_CONFIG[eType]?.kind) === 'association';
              }),
              ...filteredEdges.filter(e => {
                const eType = (e.type || e.relationship || '').toUpperCase().replace(/\s+/g, '_');
                return (e.edge_kind || EDGE_TYPE_CONFIG[eType]?.kind) !== 'association';
              }),
            ];

            return sortedEdges.map((edge, idx) => {
              const srcPos = nodePositions[edge.source];
              const tgtPos = nodePositions[edge.target];
              if (!srcPos || !tgtPos) return null;

              const eType = (edge.type || edge.relationship || '').toUpperCase().replace(/\s+/g, '_');
              const edgeCfg = EDGE_TYPE_CONFIG[eType];
              const isAssociation = (edge.edge_kind || edgeCfg?.kind) === 'association';

              const isConnected =
                selectedNodeId &&
                (edge.source === selectedNodeId || edge.target === selectedNodeId);

              // Path edges: visible and colored; Association: muted and dashed
              const opacity = isAssociation
                ? (selectedNodeId ? (isConnected ? 0.5 : 0.08) : 0.25)
                : (selectedNodeId ? (isConnected ? 1 : 0.06) : 0.6);
              const strokeWidth = isAssociation ? 1 : (isConnected ? 2.5 : 1.5);
              const edgeColor = getEdgeColor(edge.type || edge.relationship);

              // Shorten line so it doesn't overlap the node circle
              const dx = tgtPos.x - srcPos.x;
              const dy = tgtPos.y - srcPos.y;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              const srcR = srcPos._radius || 16;
              const tgtR = tgtPos._radius || 16;
              const x1 = srcPos.x + (dx / dist) * (srcR + 2);
              const y1 = srcPos.y + (dy / dist) * (srcR + 2);
              const x2 = tgtPos.x - (dx / dist) * (tgtR + 6);
              const y2 = tgtPos.y - (dy / dist) * (tgtR + 6);
              const mx = (x1 + x2) / 2;
              const my = (y1 + y2) / 2;

              return (
                <g key={`edge-${idx}`}>
                  <line
                    x1={x1} y1={y1} x2={x2} y2={y2}
                    stroke={edgeColor}
                    strokeWidth={strokeWidth}
                    strokeOpacity={opacity}
                    strokeDasharray={isAssociation ? '5 3' : 'none'}
                    markerEnd={isAssociation ? undefined : 'url(#arrowhead)'}
                  />
                  {/* Edge label shown when connected to selection */}
                  {isConnected && (
                    <text
                      x={mx} y={my - 5}
                      textAnchor="middle"
                      fill={edgeColor}
                      fontSize={8}
                      fontFamily="system-ui, sans-serif"
                      fontWeight="600"
                      style={{ pointerEvents: 'none' }}
                    >
                      {(edge.type || edge.relationship || '').replace(/_/g, ' ')}
                    </text>
                  )}
                </g>
              );
            });
          })()}

          {/* Nodes — Wiz-style: circle with Lucide icon + label below */}
          {filteredNodes.map((node) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;

            const conns = connectionCounts[node.id] || 0;
            const radius = Math.max(16, Math.min(24, 16 + Math.min(conns, 10) * 0.8));
            const color = getNodeColor(node.type || node.resourceType);
            const NodeIcon = getNodeIcon(node.type || node.resourceType || '');
            const isSelected = selectedNodeId === node.id;
            const isConnectedToSel =
              selectedNodeId && connectedToSelected.has(node.id);
            const isSearchHit = searchMatch && searchMatch.has(node.id);
            // Dim when: selection active + not connected; OR search active + no match;
            // OR a path is highlighted + this node is not in that path
            const isDimmed =
              (highlightedNodeIds && !highlightedNodeIds.has(node.id)) ||
              (!highlightedNodeIds && selectedNodeId && !isConnectedToSel) ||
              (!highlightedNodeIds && searchMatch && searchMatch.size > 0 && !isSearchHit);
            const hasThreat = node.threatCount > 0 || node.has_threat;
            const name =
              node.label ||
              node.resourceName ||
              node.id?.split('/')?.pop()?.split(':')?.pop() ||
              '';
            const truncName = name.length > 18 ? name.slice(0, 16) + '..' : name;

            return (
              <g
                key={node.id}
                style={{
                  cursor: dragNode === node.id ? 'grabbing' : 'pointer',
                  opacity: isDimmed ? 0.12 : 1,
                  transition: 'opacity 0.25s ease',
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  onNodeClick(node.id);
                }}
                onMouseDown={(e) => handleNodeMouseDown(e, node.id)}
              >
                {/* Threat pulse ring */}
                {hasThreat && (
                  <circle
                    cx={pos.x} cy={pos.y} r={radius + 6}
                    fill="none" stroke="#ef4444" strokeWidth={1.5}
                    strokeOpacity={0.5} strokeDasharray="4 3"
                  />
                )}

                {/* Selection ring */}
                {isSelected && (
                  <circle
                    cx={pos.x} cy={pos.y} r={radius + 5}
                    fill="none" stroke="#fbbf24" strokeWidth={2.5}
                    filter="url(#glow)"
                  />
                )}

                {/* Search match ring */}
                {isSearchHit && !isSelected && (
                  <circle
                    cx={pos.x} cy={pos.y} r={radius + 4}
                    fill="none" stroke="#22d3ee" strokeWidth={1.5}
                    strokeDasharray="5 3"
                  />
                )}

                {/* Outer border ring (Wiz style) */}
                <circle
                  cx={pos.x} cy={pos.y} r={radius + 1}
                  fill="none" stroke={color} strokeWidth={2}
                  strokeOpacity={0.4}
                />

                {/* Main circle — dark fill with colored border */}
                <circle
                  cx={pos.x} cy={pos.y} r={radius}
                  fill="#131a2b"
                  stroke={color} strokeWidth={2}
                />

                {/* Lucide icon */}
                <foreignObject
                  x={pos.x - radius * 0.5}
                  y={pos.y - radius * 0.5}
                  width={radius}
                  height={radius}
                  style={{ pointerEvents: 'none', overflow: 'visible' }}
                >
                  <div style={{
                    width: '100%', height: '100%',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <NodeIcon
                      style={{
                        width: Math.max(12, radius * 0.6),
                        height: Math.max(12, radius * 0.6),
                        color: color,
                      }}
                    />
                  </div>
                </foreignObject>

                {/* Risk badge (top-right corner) */}
                {(node.riskScore || 0) > 0 && (
                  <g>
                    <circle
                      cx={pos.x + radius * 0.7} cy={pos.y - radius * 0.7}
                      r={7}
                      fill={node.riskScore >= 70 ? '#ef4444' : node.riskScore >= 40 ? '#f97316' : '#22c55e'}
                    />
                    <text
                      x={pos.x + radius * 0.7} y={pos.y - radius * 0.7}
                      textAnchor="middle" dominantBaseline="central"
                      fill="white" fontSize={7} fontWeight="bold"
                      fontFamily="system-ui, sans-serif"
                      style={{ pointerEvents: 'none' }}
                    >
                      {node.riskScore}
                    </text>
                  </g>
                )}

                {/* Label below node */}
                <text
                  x={pos.x}
                  y={pos.y + radius + 14}
                  textAnchor="middle"
                  fill="rgba(255,255,255,0.75)"
                  fontSize={10}
                  fontWeight="500"
                  fontFamily="system-ui, sans-serif"
                  style={{ pointerEvents: 'none' }}
                >
                  {truncName}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Normalize resource type string to config key
// ---------------------------------------------------------------------------
function normalizeType(raw) {
  if (!raw) return 'Unknown';
  // Exact match first (e.g., "Internet", "threat")
  if (NODE_TYPE_CONFIG[raw]) return raw;
  const s = raw.replace(/[._\-\s]+/g, '').toLowerCase();
  for (const key of Object.keys(NODE_TYPE_CONFIG)) {
    if (key.toLowerCase() === s) return key;
  }
  // Service prefix from resource_type format "service.subtype"
  const svc = raw.split('.')[0].toLowerCase();
  // Partial matches
  if (svc === 'ec2' || s.includes('instance')) return 'EC2';
  if (svc === 's3' || s.includes('bucket')) return 'S3';
  if (svc === 'iam' || s.includes('role') || s.includes('policy')) return 'IAM';
  if (svc === 'rds' || s.includes('dbinstance')) return 'RDS';
  if (svc === 'lambda') return 'Lambda';
  if (s.includes('vpc') && !s.includes('endpoint')) return 'VPC';
  if (s.includes('securitygroup') || s.includes('security-group')) return 'SecurityGroup';
  if (s.includes('loadbalancer') || svc === 'elbv2' || svc === 'elb') return 'LoadBalancer';
  if (svc === 'cloudfront' || s.includes('distribution')) return 'CloudFront';
  if (svc === 'dynamodb') return 'DynamoDB';
  if (svc === 'sns') return 'SNS';
  if (svc === 'sqs') return 'SQS';
  if (svc === 'kms') return 'KMS';
  if (s.includes('subnet')) return 'Subnet';
  if (s.includes('nat')) return 'NATGateway';
  if (svc === 'elasticache') return 'ElastiCache';
  if (svc === 'eks') return 'EKS';
  if (svc === 'ecs') return 'ECS';
  if (raw === 'threat') return 'threat';
  return raw;
}

/**
 * Get Lucide icon component for a resource type.
 * Uses inventory-taxonomy SERVICE_ICONS for exact type, NODE_TYPE_CONFIG for normalized.
 */
function getNodeIcon(resourceType) {
  // Try inventory-taxonomy lookup first (handles "ec2.instance", "lambda", etc.)
  const iconName = getServiceIcon(resourceType);
  const Icon = getLucideIcon(iconName);
  if (Icon && Icon !== Box) return Icon;
  // Fall back to NODE_TYPE_CONFIG
  const nType = normalizeType(resourceType);
  const cfgIconName = NODE_TYPE_CONFIG[nType]?.iconName;
  return cfgIconName ? getLucideIcon(cfgIconName) : Box;
}

// ---------------------------------------------------------------------------
// Detail Panel
// ---------------------------------------------------------------------------
function DetailPanel({ node, edges, allNodes, onNodeClick, onClose }) {
  if (!node) return null;

  const connectedEdges = edges.filter(
    (e) => e.source === node.id || e.target === node.id
  );

  const connectedNodes = connectedEdges.map((e) => {
    const targetId = e.source === node.id ? e.target : e.source;
    const targetNode = allNodes.find((n) => n.id === targetId);
    return { edge: e, node: targetNode };
  }).filter((c) => c.node);

  const riskScore = node.risk_score ?? node.riskScore ?? 0;
  const threatCount = node.threats ?? node.threatCount ?? 0;
  const findingCount = node.findings?.length ?? node.findingCount ?? 0;
  const nType = normalizeType(node.type || node.resourceType || '');
  const color = NODE_TYPE_CONFIG[nType]?.color || DEFAULT_NODE_COLOR;

  const riskColor =
    riskScore >= 75
      ? '#ef4444'
      : riskScore >= 50
      ? '#f97316'
      : riskScore >= 25
      ? '#eab308'
      : '#22c55e';

  return (
    <div
      className="absolute top-0 right-0 h-full w-[320px] border-l overflow-y-auto z-20
                 transition-transform duration-300 ease-out"
      style={{
        backgroundColor: 'var(--bg-card)',
        borderColor: 'var(--border-primary)',
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3 border-b sticky top-0 z-10"
        style={{
          borderColor: 'var(--border-primary)',
          backgroundColor: 'var(--bg-card)',
        }}
      >
        <h3
          className="text-sm font-semibold"
          style={{ color: 'var(--text-primary)' }}
        >
          Node Details
        </h3>
        <button
          onClick={onClose}
          className="p-1 rounded hover:opacity-70 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}
          title="Close (Esc)"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-5">
        {/* Resource type + name */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            {(() => {
              const PanelIcon = getNodeIcon(node.type || node.resourceType || '');
              return (
                <span className="w-5 h-5 rounded flex-shrink-0 flex items-center justify-center"
                  style={{ backgroundColor: color }}>
                  <PanelIcon style={{ width: 12, height: 12, color: 'white' }} />
                </span>
              );
            })()}
            <span
              className="text-xs font-semibold uppercase tracking-wider"
              style={{ color: 'var(--text-secondary)' }}
            >
              {NODE_TYPE_CONFIG[nType]?.label || node.type || 'Resource'}
            </span>
            {node.has_threat && (
              <span
                className="ml-auto text-[10px] px-2 py-0.5 rounded-full font-semibold"
                style={{
                  backgroundColor: 'rgba(239,68,68,0.15)',
                  color: '#ef4444',
                }}
              >
                Threat
              </span>
            )}
          </div>
          <p
            className="text-base font-bold leading-tight"
            style={{ color: 'var(--text-primary)' }}
          >
            {node.label || node.resourceName || node.id}
          </p>
          <p
            className="text-[11px] mt-1 break-all font-mono"
            style={{ color: 'var(--text-secondary)' }}
          >
            {node.arn || node.id}
          </p>
        </div>

        {/* Risk Score Gauge */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <span
              className="text-xs font-medium"
              style={{ color: 'var(--text-secondary)' }}
            >
              Risk Score
            </span>
            <span className="text-lg font-bold" style={{ color: riskColor }}>
              {riskScore}
            </span>
          </div>
          <div
            className="w-full h-2 rounded-full overflow-hidden"
            style={{ backgroundColor: 'var(--bg-secondary)' }}
          >
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${riskScore}%`,
                backgroundColor: riskColor,
              }}
            />
          </div>
        </div>

        {/* Counts */}
        <div className="grid grid-cols-2 gap-2">
          <div
            className="rounded-lg p-3 border text-center"
            style={{
              backgroundColor: 'var(--bg-secondary)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <p className="text-xl font-bold" style={{ color: '#ef4444' }}>
              {threatCount}
            </p>
            <p
              className="text-[10px] font-medium mt-0.5"
              style={{ color: 'var(--text-secondary)' }}
            >
              Threats
            </p>
          </div>
          <div
            className="rounded-lg p-3 border text-center"
            style={{
              backgroundColor: 'var(--bg-secondary)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <p className="text-xl font-bold" style={{ color: '#f97316' }}>
              {findingCount}
            </p>
            <p
              className="text-[10px] font-medium mt-0.5"
              style={{ color: 'var(--text-secondary)' }}
            >
              Findings
            </p>
          </div>
        </div>

        {/* Meta */}
        <div className="flex flex-wrap gap-1.5">
          {[
            { k: 'Provider', v: node.provider },
            { k: 'Account', v: node.account },
            { k: 'Region', v: node.region },
          ]
            .filter((m) => m.v)
            .map((m) => (
              <span
                key={m.k}
                className="text-[10px] px-2 py-0.5 rounded border"
                style={{
                  borderColor: 'var(--border-primary)',
                  color: 'var(--text-secondary)',
                  backgroundColor: 'var(--bg-secondary)',
                }}
              >
                <span style={{ color: 'var(--text-secondary)', opacity: 0.6 }}>
                  {m.k}:{' '}
                </span>
                {m.v}
              </span>
            ))}
        </div>

        {/* Connected Resources */}
        <div>
          <p
            className="text-xs font-semibold uppercase tracking-wider mb-2"
            style={{ color: 'var(--text-secondary)' }}
          >
            Connected Resources ({connectedNodes.length})
          </p>
          <div className="space-y-1.5 max-h-[200px] overflow-y-auto">
            {connectedNodes.length === 0 && (
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                No connected resources
              </p>
            )}
            {connectedNodes.map(({ edge, node: cn }) => {
              const cnType = normalizeType(cn.type || cn.resourceType || '');
              const cnColor = NODE_TYPE_CONFIG[cnType]?.color || DEFAULT_NODE_COLOR;
              const CnIcon = getNodeIcon(cn.type || cn.resourceType || '');
              return (
                <button
                  key={cn.id}
                  onClick={() => onNodeClick(cn.id)}
                  className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg border text-left
                             hover:opacity-80 transition-opacity"
                  style={{
                    backgroundColor: 'var(--bg-secondary)',
                    borderColor: 'var(--border-primary)',
                  }}
                >
                  <span className="w-4 h-4 rounded flex-shrink-0 flex items-center justify-center"
                    style={{ backgroundColor: cnColor }}>
                    <CnIcon style={{ width: 10, height: 10, color: 'white' }} />
                  </span>
                  <div className="flex-1 min-w-0">
                    <p
                      className="text-xs font-medium truncate"
                      style={{ color: 'var(--text-primary)' }}
                    >
                      {cn.label || cn.resourceName || cn.id}
                    </p>
                    <p
                      className="text-[10px] truncate"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      {edge.type || edge.relationship || 'related'}
                    </p>
                  </div>
                  <ChevronRight
                    className="w-3 h-3 flex-shrink-0"
                    style={{ color: 'var(--text-secondary)' }}
                  />
                </button>
              );
            })}
          </div>
        </div>

        {/* Quick Links */}
        <div
          className="flex flex-col gap-2 pt-3 border-t"
          style={{ borderColor: 'var(--border-primary)' }}
        >
          <a
            href={`/ui/inventory/architecture?resource_uid=${encodeURIComponent(node.id)}`}
            className="flex items-center justify-center gap-2 text-xs py-2 rounded-lg border
                       hover:opacity-75 transition-opacity"
            style={{
              borderColor: 'var(--border-primary)',
              color: 'var(--text-secondary)',
            }}
          >
            <Eye className="w-3 h-3" />
            View in Inventory
          </a>
          <a
            href={`/ui/threats?search=${encodeURIComponent(node.id)}`}
            className="flex items-center justify-center gap-2 text-xs py-2 rounded-lg
                       hover:opacity-90 transition-opacity text-white"
            style={{ backgroundColor: 'rgba(239,68,68,0.7)' }}
          >
            <ShieldAlert className="w-3 h-3" />
            View Threats
          </a>
          <a
            href={`/ui/threats/blast-radius?resource_uid=${encodeURIComponent(node.id)}`}
            className="flex items-center justify-center gap-2 text-xs py-2 rounded-lg
                       hover:opacity-90 transition-opacity text-white"
            style={{ backgroundColor: 'rgba(139,92,246,0.7)' }}
          >
            <GitBranch className="w-3 h-3" />
            Blast Radius
          </a>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Multi-select filter dropdown
// ---------------------------------------------------------------------------
function MultiSelectFilter({ label, icon, items, selected, onToggle }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const sel = selected || new Set(items.map((i) => i.key));
  const allSelected = items.every((i) => sel.has(i.key));
  const noneSelected = items.every((i) => !sel.has(i.key));

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium
                   transition-colors hover:opacity-80"
        style={{
          backgroundColor: 'var(--bg-secondary)',
          borderColor: 'var(--border-primary)',
          color: 'var(--text-primary)',
        }}
      >
        {icon}
        {label}
        <span
          className="ml-1 text-[10px] px-1.5 py-0.5 rounded-full"
          style={{
            backgroundColor: 'rgba(59,130,246,0.2)',
            color: '#60a5fa',
          }}
        >
          {[...sel].filter((k) => items.some((i) => i.key === k)).length}
        </span>
      </button>

      {open && (
        <div
          className="absolute top-full mt-1 left-0 z-30 rounded-lg border shadow-xl
                     py-2 min-w-[200px] max-h-[300px] overflow-y-auto"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          {/* Select All / None */}
          <div className="flex items-center justify-between px-3 pb-2 mb-1 border-b"
            style={{ borderColor: 'var(--border-primary)' }}
          >
            <button
              onClick={() => {
                items.forEach((i) => {
                  if (!sel.has(i.key)) onToggle(i.key);
                });
              }}
              className="text-[10px] hover:underline"
              style={{ color: '#60a5fa' }}
            >
              All
            </button>
            <button
              onClick={() => {
                items.forEach((i) => {
                  if (sel.has(i.key)) onToggle(i.key);
                });
              }}
              className="text-[10px] hover:underline"
              style={{ color: '#60a5fa' }}
            >
              None
            </button>
          </div>

          {items.map((item) => (
            <label
              key={item.key}
              className="flex items-center gap-2.5 px-3 py-1.5 cursor-pointer
                         hover:bg-white/5 transition-colors"
            >
              <input
                type="checkbox"
                checked={sel.has(item.key)}
                onChange={() => onToggle(item.key)}
                className="rounded border-gray-500 bg-transparent text-blue-500
                           focus:ring-blue-500 focus:ring-offset-0 w-3.5 h-3.5"
              />
              {item.color && (
                <span
                  className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                  style={{ backgroundColor: item.color }}
                />
              )}
              <span className="text-xs" style={{ color: 'var(--text-primary)' }}>
                {item.label}
              </span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Visual Query Builder
// Structured filter UI that generates Cypher internally — never exposed to user.
// ---------------------------------------------------------------------------

const RESOURCE_TYPE_OPTIONS = [
  { value: '', label: 'Any Resource Type' },
  { value: 'EC2', label: 'EC2 Instance' },
  { value: 'S3', label: 'S3 Bucket' },
  { value: 'IAM', label: 'IAM Role / User / Policy' },
  { value: 'Lambda', label: 'Lambda Function' },
  { value: 'RDS', label: 'RDS Database' },
  { value: 'EKS', label: 'EKS Cluster' },
  { value: 'SecurityGroup', label: 'Security Group' },
  { value: 'KMS', label: 'KMS Key' },
  { value: 'VPC', label: 'VPC' },
  { value: 'Subnet', label: 'Subnet' },
  { value: 'LoadBalancer', label: 'Load Balancer' },
  { value: 'DynamoDB', label: 'DynamoDB Table' },
];

const SECURITY_STATUS_OPTIONS = [
  { value: '', label: 'Any Status' },
  { value: 'has_threat', label: 'Has Active Threats' },
  { value: 'internet_exposed', label: 'Internet Exposed' },
  { value: 'high_risk', label: 'High Risk Score (≥70)' },
  { value: 'critical_findings', label: 'Has Critical Findings' },
];

const CONNECTED_TO_OPTIONS = [
  { value: '', label: 'Any Resource' },
  { value: 'Internet', label: 'Internet (directly exposed)' },
  { value: 'IAM', label: 'IAM Role / Identity' },
  { value: 'S3', label: 'S3 Bucket' },
  { value: 'KMS', label: 'KMS Key' },
  { value: 'RDS', label: 'Database' },
  { value: 'EC2', label: 'EC2 Instance' },
  { value: 'SecurityGroup', label: 'Security Group' },
];


function SelectField({ label, value, onChange, options }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-[10px] font-semibold uppercase tracking-wider"
        style={{ color: 'var(--text-secondary)' }}>
        {label}
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="px-2.5 py-2 rounded-lg border text-xs outline-none cursor-pointer"
        style={{
          backgroundColor: 'var(--bg-primary)',
          borderColor: 'var(--border-primary)',
          color: value ? 'var(--text-primary)' : 'var(--text-secondary)',
          minWidth: '180px',
        }}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} style={{ backgroundColor: 'var(--bg-card)' }}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

/**
 * Call backend explore endpoint — structured params → Cypher → graph data.
 * Uses BFF proxy for gateway consistency.
 */
async function runExploreQuery(tenantId, qstate) {
  const { resourceType, securityStatus, connectedTo, viaEdge, edgeKind, withinHops } = qstate;
  const params = { tenant_id: tenantId };
  if (resourceType)   params.resource_type    = resourceType;
  if (securityStatus) params.security_status  = securityStatus;
  if (connectedTo)    params.connected_to     = connectedTo;
  if (viaEdge)        params.via_edge         = viaEdge;
  if (edgeKind)       params.edge_kind        = edgeKind;
  if (withinHops > 1) params.within_hops      = withinHops;

  // Use BFF proxy (gateway consistency) with fallback to direct engine call
  const result = await getFromEngine('threat', '/api/v1/graph/explore', params);
  if (result?.error) throw new Error(result.error);
  return result;
}

const VIA_EDGE_OPTIONS_EXTENDED = [
  { value: '', label: 'Any Relationship' },
  // Path edges
  { value: 'ASSUMES',     label: 'ASSUMES (role assumption)' },
  { value: 'CAN_ACCESS',  label: 'CAN_ACCESS (access grant)' },
  { value: 'EXPOSES',     label: 'EXPOSES (internet path)' },
  { value: 'ROUTES_TO',   label: 'ROUTES_TO (network)' },
  { value: 'STORES',      label: 'STORES (data access)' },
  { value: 'CONNECTS_TO', label: 'CONNECTS_TO (network)' },
  { value: 'ATTACHED_TO', label: 'ATTACHED_TO (volume)' },
  { value: 'IN_VPC',      label: 'IN_VPC (containment)' },
  // Association edges
  { value: 'ENCRYPTED_BY', label: 'ENCRYPTED_BY (encryption)' },
  { value: 'DEPENDS_ON',   label: 'DEPENDS_ON (dependency)' },
  { value: 'HAS_FINDING',  label: 'HAS_FINDING (misconfig)' },
  { value: 'AFFECTED_BY',  label: 'AFFECTED_BY (finding)' },
];

const EDGE_KIND_OPTIONS = [
  { value: '',            label: 'All Edges' },
  { value: 'path',        label: 'Path Only (attack traversal)' },
  { value: 'association', label: 'Association Only (context)' },
];

function VisualQueryBuilder({ tenantId, onResultChange, activeResult }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [qstate, setQstate] = useState({
    resourceType: '',
    securityStatus: '',
    connectedTo: '',
    viaEdge: '',
    edgeKind: '',
    withinHops: 2,
  });

  const hasActiveQuery = qstate.resourceType || qstate.securityStatus || qstate.connectedTo || qstate.viaEdge || qstate.edgeKind;

  // ── Real-time filter: auto-run on every state change (300ms debounce) ──
  useEffect(() => {
    if (!hasActiveQuery) {
      onResultChange(null);
      return;
    }
    const timer = setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await runExploreQuery(tenantId, qstate);
        onResultChange(result);
      } catch (err) {
        setError(err.message || 'Query failed');
      } finally {
        setLoading(false);
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [qstate, hasActiveQuery, tenantId]); // eslint-disable-line react-hooks/exhaustive-deps

  function handleClear() {
    setQstate({ resourceType: '', securityStatus: '', connectedTo: '', viaEdge: '', edgeKind: '', withinHops: 2 });
    onResultChange(null);
    setError(null);
  }

  return (
    <div
      className="rounded-xl border overflow-hidden"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      {/* Toggle header */}
      <div
        role="button"
        tabIndex={0}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => e.key === 'Enter' && setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 hover:opacity-80 transition-opacity cursor-pointer"
      >
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4" style={{ color: activeResult ? '#3b82f6' : 'var(--text-secondary)' }} />
          <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            Graph Explorer
          </span>
          {/* Live indicator */}
          {loading && (
            <span className="animate-pulse text-[10px] font-medium" style={{ color: '#60a5fa' }}>
              ● Live
            </span>
          )}
          {activeResult && !loading && (
            <span
              className="text-[10px] px-2 py-0.5 rounded-full font-medium"
              style={{ backgroundColor: 'rgba(59,130,246,0.15)', color: '#60a5fa' }}
            >
              {activeResult.cypher_summary} — {activeResult.matched_nodes} matched / {activeResult.total_nodes} nodes
            </span>
          )}
          {!activeResult && !loading && (
            <span className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>
              Filters update the graph in real-time
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {activeResult && (
            <button
              onClick={(e) => { e.stopPropagation(); handleClear(); }}
              className="text-[11px] px-2 py-0.5 rounded hover:opacity-70 transition-opacity"
              style={{ color: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)' }}
            >
              Clear
            </button>
          )}
          <ChevronRight
            className="w-4 h-4 transition-transform duration-200"
            style={{ color: 'var(--text-secondary)', transform: open ? 'rotate(90deg)' : 'none' }}
          />
        </div>
      </div>

      {/* Builder body */}
      {open && (
        <div className="px-4 pb-4 pt-0 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex flex-wrap gap-4 mt-4 items-end">
            <SelectField
              label="Resource Type"
              value={qstate.resourceType}
              onChange={(v) => setQstate((s) => ({ ...s, resourceType: v }))}
              options={RESOURCE_TYPE_OPTIONS}
            />
            <SelectField
              label="Security Status"
              value={qstate.securityStatus}
              onChange={(v) => setQstate((s) => ({ ...s, securityStatus: v }))}
              options={SECURITY_STATUS_OPTIONS}
            />
            <SelectField
              label="Connected To"
              value={qstate.connectedTo}
              onChange={(v) => setQstate((s) => ({ ...s, connectedTo: v }))}
              options={CONNECTED_TO_OPTIONS}
            />
            <SelectField
              label="Via Edge Type"
              value={qstate.viaEdge}
              onChange={(v) => setQstate((s) => ({ ...s, viaEdge: v }))}
              options={VIA_EDGE_OPTIONS_EXTENDED}
            />
            <SelectField
              label="Edge Layer"
              value={qstate.edgeKind}
              onChange={(v) => setQstate((s) => ({ ...s, edgeKind: v }))}
              options={EDGE_KIND_OPTIONS}
            />

            {/* Within hops */}
            <div className="flex flex-col gap-1">
              <label className="text-[10px] font-semibold uppercase tracking-wider"
                style={{ color: 'var(--text-secondary)' }}>
                Within Hops
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="range" min={0} max={5} value={qstate.withinHops}
                  onChange={(e) => setQstate((s) => ({ ...s, withinHops: Number(e.target.value) }))}
                  className="w-24 accent-blue-500"
                />
                <span className="text-xs font-bold w-12 text-center" style={{ color: 'var(--text-primary)' }}>
                  {qstate.withinHops === 0 ? 'exact' : qstate.withinHops}
                </span>
              </div>
            </div>

            <div className="flex-1" />

            {/* Result count */}
            {activeResult && !loading && (
              <div className="text-xs px-3 py-2 rounded-lg border"
                style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
                <span className="font-bold" style={{ color: '#22c55e' }}>{activeResult.matched_nodes}</span>
                <span> matched · </span>
                <span className="font-bold" style={{ color: 'var(--text-primary)' }}>{activeResult.total_nodes}</span>
                <span> nodes</span>
              </div>
            )}

            {(hasActiveQuery || activeResult) && (
              <button
                onClick={handleClear}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium hover:opacity-80 transition-opacity border"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              >
                <RotateCcw className="w-3 h-3" />
                Clear
              </button>
            )}
          </div>

          {/* Error */}
          {error && (
            <div className="mt-3 px-3 py-2 rounded-lg text-xs" style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444' }}>
              {error}
            </div>
          )}

          {/* Query preview (natural language) */}
          {hasActiveQuery && !error && (
            <div className="mt-3 px-3 py-2 rounded-lg text-xs"
              style={{ backgroundColor: 'rgba(59,130,246,0.08)', color: 'var(--text-secondary)' }}>
              <span className="font-semibold" style={{ color: '#60a5fa' }}>Live filter: </span>
              Find {qstate.resourceType || 'all resources'}
              {qstate.securityStatus ? ` where ${qstate.securityStatus.replace(/_/g, ' ')}` : ''}
              {qstate.connectedTo ? ` connected to ${qstate.connectedTo}` : ''}
              {qstate.viaEdge ? ` via ${qstate.viaEdge}` : ''}
              {qstate.edgeKind ? ` (${qstate.edgeKind} edges only)` : ''}
              {qstate.connectedTo ? (qstate.withinHops === 0 ? ' (exact match, no traversal)' : ` within ${qstate.withinHops} hop${qstate.withinHops > 1 ? 's' : ''}`) : ''}
              {!qstate.connectedTo && qstate.withinHops === 0 ? ' (isolated — no neighbors)' : ''}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Orca-style Attack Path Cards
// Horizontal chip row: Internet → EC2 [risk:72, findings:3] → IAM → S3
// ---------------------------------------------------------------------------
const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#64748b',
};

// ---------------------------------------------------------------------------
// Orca-style Attack Path Components
// ---------------------------------------------------------------------------

function NodeDetailTooltip({ node, anchorRect }) {
  const riskSev =
    node.risk_score >= 80 ? 'critical'
    : node.risk_score >= 60 ? 'high'
    : node.risk_score >= 40 ? 'medium'
    : node.risk_score > 0 ? 'low'
    : null;
  const sevColor = riskSev ? SEVERITY_COLORS[riskSev] : '#64748b';
  const nType = normalizeType(node.type || '');
  const typeLabel = NODE_TYPE_CONFIG[nType]?.label || (node.type || '').split('.').pop();

  // Compute findings / threats detail arrays from node data if present
  const findingDetails = Array.isArray(node.findings) ? node.findings : [];
  const threatDetails  = Array.isArray(node.threats)  ? node.threats  : [];

  // Position: centred above the chip, clamped to viewport
  const tooltipW = 248;
  const rawLeft = anchorRect.left + anchorRect.width / 2 - tooltipW / 2;
  const left = Math.max(8, Math.min(rawLeft, window.innerWidth - tooltipW - 8));
  const top  = anchorRect.top - 8; // translate(-100%) moves it above

  return (
    <div
      style={{
        position: 'fixed',
        left,
        top,
        transform: 'translateY(-100%)',
        width: tooltipW,
        zIndex: 9999,
        pointerEvents: 'none',
      }}
    >
      {/* Arrow */}
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <div style={{
          width: 0, height: 0,
          borderLeft: '6px solid transparent',
          borderRight: '6px solid transparent',
          borderTop: '6px solid #1e293b',
          marginBottom: -1,
        }} />
      </div>

      <div
        className="rounded-lg border text-[11px] overflow-hidden"
        style={{
          backgroundColor: '#0f172a',
          borderColor: sevColor + '50',
          boxShadow: `0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px ${sevColor}20`,
        }}
      >
        {/* Header */}
        <div
          className="px-3 py-2 border-b flex items-center gap-2"
          style={{ borderColor: 'rgba(255,255,255,0.08)', backgroundColor: `${sevColor}0d` }}
        >
          <span
            className="font-bold text-[10px] px-1.5 py-0.5 rounded uppercase tracking-wide"
            style={{ backgroundColor: `${sevColor}20`, color: sevColor }}
          >
            {typeLabel}
          </span>
          {riskSev && (
            <span className="font-semibold" style={{ color: sevColor }}>
              Risk {node.risk_score}
            </span>
          )}
        </div>

        <div className="px-3 py-2 flex flex-col gap-2">
          {/* Full resource name */}
          <div>
            <span className="text-[9px] uppercase tracking-wide" style={{ color: 'rgba(255,255,255,0.35)' }}>
              Resource
            </span>
            <p className="font-medium mt-0.5 break-all leading-snug" style={{ color: 'rgba(255,255,255,0.9)', fontSize: 10 }}>
              {node.name || node.uid || '—'}
            </p>
            {node.name && node.uid && node.uid !== node.name && (
              <p className="text-[8px] mt-0.5 break-all" style={{ color: 'rgba(255,255,255,0.35)' }}>
                {node.uid}
              </p>
            )}
          </div>

          {/* Findings section */}
          {node.finding_count > 0 && (
            <div>
              <div className="flex items-center gap-1 mb-1">
                <AlertTriangle style={{ width: 9, height: 9, color: '#f97316' }} />
                <span className="font-semibold text-[10px]" style={{ color: '#f97316' }}>
                  {node.finding_count} Finding{node.finding_count !== 1 ? 's' : ''}
                  <span className="font-normal text-[9px] ml-1" style={{ color: 'rgba(255,255,255,0.4)' }}>
                    (critical / high)
                  </span>
                </span>
              </div>
              {findingDetails.length > 0 ? (
                <div className="flex flex-col gap-0.5">
                  {findingDetails.slice(0, 4).map((f, i) => (
                    <div key={i} className="flex items-start gap-1.5">
                      <div
                        className="w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0"
                        style={{ backgroundColor: SEVERITY_COLORS[f.severity] || '#f97316' }}
                      />
                      <span className="text-[9px] leading-snug" style={{ color: 'rgba(255,255,255,0.7)' }}>
                        {(f.rule_name || f.title || f.finding_id || '').slice(0, 52)}
                      </span>
                    </div>
                  ))}
                  {findingDetails.length > 4 && (
                    <span className="text-[9px] pl-3" style={{ color: 'rgba(255,255,255,0.3)' }}>
                      +{findingDetails.length - 4} more
                    </span>
                  )}
                </div>
              ) : (
                <div className="flex flex-col gap-1">
                  {node.finding_severity_breakdown && Object.entries(node.finding_severity_breakdown).map(([sev, cnt]) => (
                    <div key={sev} className="flex items-center gap-1.5">
                      <div className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                        style={{ backgroundColor: SEVERITY_COLORS[sev] || '#64748b' }} />
                      <span className="text-[9px] capitalize" style={{ color: 'rgba(255,255,255,0.55)' }}>
                        {sev}: {cnt}
                      </span>
                    </div>
                  ))}
                  {!node.finding_severity_breakdown && (
                    <span className="text-[9px] pl-0.5" style={{ color: 'rgba(255,255,255,0.35)' }}>
                      Click resource in graph for details
                    </span>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Threats section */}
          {node.threat_count > 0 && (
            <div>
              <div className="flex items-center gap-1 mb-1">
                <Zap style={{ width: 9, height: 9, color: '#ef4444' }} />
                <span className="font-semibold text-[10px]" style={{ color: '#ef4444' }}>
                  {node.threat_count} Active Threat{node.threat_count !== 1 ? 's' : ''}
                  {node.threat_severity && (
                    <span
                      className="ml-1 font-medium capitalize text-[9px] px-1 py-0.5 rounded"
                      style={{
                        backgroundColor: `${SEVERITY_COLORS[node.threat_severity] || '#ef4444'}20`,
                        color: SEVERITY_COLORS[node.threat_severity] || '#ef4444',
                      }}
                    >
                      {node.threat_severity}
                    </span>
                  )}
                </span>
              </div>
              {threatDetails.length > 0 ? (
                <div className="flex flex-col gap-0.5">
                  {threatDetails.slice(0, 3).map((t, i) => (
                    <div key={i} className="flex items-start gap-1.5">
                      <div
                        className="w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0"
                        style={{ backgroundColor: SEVERITY_COLORS[t.severity] || '#ef4444' }}
                      />
                      <span className="text-[9px] leading-snug" style={{ color: 'rgba(255,255,255,0.7)' }}>
                        {(t.rule_name || t.technique || t.threat_id || '').slice(0, 52)}
                      </span>
                    </div>
                  ))}
                  {threatDetails.length > 3 && (
                    <span className="text-[9px] pl-3" style={{ color: 'rgba(255,255,255,0.3)' }}>
                      +{threatDetails.length - 3} more
                    </span>
                  )}
                </div>
              ) : (
                <span className="text-[9px]" style={{ color: 'rgba(255,255,255,0.35)' }}>
                  Click resource in graph for details
                </span>
              )}
            </div>
          )}

          {/* Clean node — no findings/threats */}
          {!node.finding_count && !node.threat_count && (
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: '#22c55e' }} />
              <span className="text-[10px]" style={{ color: '#4ade80' }}>No findings detected</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function NodeChip({ node, isActive }) {
  const [hovered, setHovered]       = useState(false);
  const [pinned, setPinned]         = useState(false);
  const [anchorRect, setAnchorRect] = useState(null);
  const chipRef = useRef(null);

  const showTooltip = () => {
    if (chipRef.current) setAnchorRect(chipRef.current.getBoundingClientRect());
    setHovered(true);
  };
  const hideTooltip = () => { if (!pinned) setHovered(false); };
  const togglePin   = (e) => {
    e.stopPropagation();
    if (chipRef.current) setAnchorRect(chipRef.current.getBoundingClientRect());
    setPinned(v => !v);
    setHovered(true);
  };

  const tooltipVisible = hovered || pinned;

  const riskSev =
    node.risk_score >= 80 ? 'critical'
    : node.risk_score >= 60 ? 'high'
    : node.risk_score >= 40 ? 'medium'
    : node.risk_score > 0 ? 'low'
    : null;

  const sevColor = riskSev ? SEVERITY_COLORS[riskSev] : null;
  const NodeIcon = getNodeIcon(node.type || '');
  const nType = normalizeType(node.type || '');
  const typeColor = NODE_TYPE_CONFIG[nType]?.color || DEFAULT_NODE_COLOR;
  const typeLabel = NODE_TYPE_CONFIG[nType]?.label || (node.type || '').split('.').pop().toUpperCase();
  const displayName = (node.name || node.uid || 'Unknown').split('/').pop().split(':').pop();
  const isInternet = node.type === 'Internet' || node.uid === 'Internet';

  return (
    <>
      <div
        ref={chipRef}
        onClick={togglePin}
        onMouseEnter={showTooltip}
        onMouseLeave={hideTooltip}
        className="flex flex-col rounded-lg border overflow-hidden flex-shrink-0 cursor-pointer"
        style={{
          width: 112,
          backgroundColor: isInternet ? 'rgba(239,68,68,0.06)' : sevColor ? `${sevColor}08` : 'rgba(255,255,255,0.04)',
          borderColor: pinned ? '#60a5fa' : isActive ? '#3b82f6' : sevColor || 'rgba(255,255,255,0.1)',
          borderWidth: pinned || isActive ? 1.5 : 1,
          boxShadow: pinned ? '0 0 0 2px #3b82f640' : isActive ? `0 0 0 1px #3b82f640` : 'none',
          transition: 'border-color 0.15s, box-shadow 0.15s',
        }}
      >
        {/* Severity accent bar */}
        {sevColor && <div className="h-0.5 w-full" style={{ backgroundColor: sevColor }} />}

        <div className="flex flex-col items-center gap-1.5 px-2 pt-2.5 pb-2">
          <div className="relative">
            {/* Threat pulse ring */}
            {node.threat_count > 0 && (
              <div
                className="absolute inset-0 rounded-full animate-ping"
                style={{ backgroundColor: SEVERITY_COLORS[node.threat_severity] || '#ef4444', opacity: 0.3, margin: -3 }}
              />
            )}
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center"
              style={{ backgroundColor: `${typeColor}18`, border: `1.5px solid ${typeColor}60` }}
            >
              <NodeIcon style={{ width: 15, height: 15, color: typeColor }} />
            </div>
            {/* Risk badge */}
            {node.risk_score > 0 && (
              <div
                className="absolute -top-1.5 -right-1.5 rounded-full text-white flex items-center justify-center font-bold"
                style={{ width: 18, height: 18, backgroundColor: sevColor, fontSize: 8, lineHeight: 1 }}
              >
                {node.risk_score}
              </div>
            )}
          </div>

          {/* Type pill */}
          <span
            className="text-[8px] font-semibold px-1.5 py-0.5 rounded-full tracking-wide"
            style={{ backgroundColor: `${typeColor}18`, color: typeColor }}
          >
            {typeLabel.slice(0, 10)}
          </span>

          {/* Resource name */}
          <span
            className="text-[9px] font-medium text-center leading-tight w-full"
            style={{ color: 'rgba(255,255,255,0.85)', wordBreak: 'break-all' }}
          >
            {displayName.slice(0, 18)}
          </span>

          {/* Findings + threats badges */}
          {(node.finding_count > 0 || node.threat_count > 0) && (
            <div className="flex items-center gap-1 mt-0.5">
              {node.finding_count > 0 && (
                <span
                  className="flex items-center gap-0.5 text-[8px] font-semibold px-1 py-0.5 rounded"
                  style={{ backgroundColor: 'rgba(249,115,22,0.18)', color: '#f97316', border: '1px solid rgba(249,115,22,0.3)' }}
                >
                  <AlertTriangle style={{ width: 8, height: 8 }} />
                  {node.finding_count}
                </span>
              )}
              {node.threat_count > 0 && (
                <span
                  className="flex items-center gap-0.5 text-[8px] font-semibold px-1 py-0.5 rounded"
                  style={{ backgroundColor: 'rgba(239,68,68,0.18)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}
                >
                  <Zap style={{ width: 8, height: 8 }} />
                  {node.threat_count}
                </span>
              )}
            </div>
          )}

          {/* Pin hint */}
          <span className="text-[7px] mt-0.5" style={{ color: 'rgba(255,255,255,0.2)' }}>
            {pinned ? 'click to close' : 'hover / click'}
          </span>
        </div>
      </div>

      {/* Detail tooltip — fixed position, breaks out of overflow */}
      {tooltipVisible && anchorRect && (
        <NodeDetailTooltip node={node} anchorRect={anchorRect} />
      )}
    </>
  );
}

function EdgeArrow({ edge }) {
  const cfg = EDGE_TYPE_CONFIG[edge.type?.toUpperCase()] || {};
  const color = cfg.color || '#475569';
  const label = (edge.type || '').replace(/_/g, ' ');
  const isPath = cfg.kind !== 'association';

  return (
    <div className="flex flex-col items-center justify-center gap-1 flex-shrink-0" style={{ width: 52 }}>
      <span
        className="text-[8px] font-semibold text-center leading-tight"
        style={{ color, maxWidth: 50, wordBreak: 'break-word' }}
      >
        {label}
      </span>
      <div className="flex items-center w-full">
        <div
          className="flex-1 h-px"
          style={{
            backgroundColor: color,
            opacity: isPath ? 0.8 : 0.4,
            backgroundImage: isPath ? 'none' : `repeating-linear-gradient(90deg, ${color} 0, ${color} 4px, transparent 4px, transparent 8px)`,
            backgroundSize: isPath ? 'none' : '8px 1px',
            backgroundRepeat: 'repeat-x',
            height: 1.5,
          }}
        />
        <svg width="7" height="7" viewBox="0 0 7 7" style={{ flexShrink: 0 }}>
          <polygon points="0,0 7,3.5 0,7" fill={color} opacity={isPath ? 0.9 : 0.5} />
        </svg>
      </div>
    </div>
  );
}

function OrcaPathCard({ path, highlighted, onHighlight }) {
  const isActive = highlighted === path.path_id;
  const entryIsInternet = path.entry_type === 'Internet' || path.entry_point === 'Internet';

  const maxSev = (() => {
    const node = path.nodes?.find(n => n.threat_severity);
    if (node) return node.threat_severity;
    const maxRisk = Math.max(...(path.nodes || []).map(n => n.risk_score || 0));
    if (maxRisk >= 80) return 'critical';
    if (maxRisk >= 60) return 'high';
    if (maxRisk >= 40) return 'medium';
    return null;
  })();
  const sevColor = maxSev ? SEVERITY_COLORS[maxSev] : '#475569';

  // Target is the last node
  const target = path.nodes?.[path.nodes.length - 1];
  const targetName = target ? (target.name || target.uid || '').split('/').pop().split(':').pop() : '';

  return (
    <div
      onClick={() => onHighlight(isActive ? null : path.path_id)}
      className="rounded-lg border cursor-pointer transition-all duration-150"
      style={{
        backgroundColor: isActive ? 'rgba(59,130,246,0.07)' : 'rgba(255,255,255,0.02)',
        borderColor: isActive ? '#3b82f6' : 'rgba(255,255,255,0.08)',
        borderLeftWidth: 3,
        borderLeftColor: sevColor,
        padding: '10px 12px',
      }}
    >
      {/* Header row */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {entryIsInternet && (
            <span
              className="flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded-full uppercase tracking-wide"
              style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#ef4444' }}
            >
              <Globe style={{ width: 9, height: 9 }} /> Internet
            </span>
          )}
          <span className="text-[9px] font-medium" style={{ color: 'rgba(255,255,255,0.4)' }}>
            {path.hops} hop{path.hops !== 1 ? 's' : ''}
          </span>
          {targetName && (
            <span className="text-[9px]" style={{ color: 'rgba(255,255,255,0.35)' }}>
              → {targetName.slice(0, 22)}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          {maxSev && (
            <span
              className="text-[9px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wide"
              style={{ backgroundColor: `${sevColor}18`, color: sevColor }}
            >
              {maxSev}
            </span>
          )}
          {path.total_risk > 0 && (
            <span
              className="text-[9px] font-bold px-2 py-0.5 rounded-full"
              style={{ backgroundColor: `${sevColor}18`, color: sevColor }}
            >
              Risk {path.total_risk}
            </span>
          )}
          <span className="text-[8px] font-mono" style={{ color: 'rgba(255,255,255,0.2)' }}>
            #{(path.path_id || '').slice(0, 8)}
          </span>
        </div>
      </div>

      {/* Node + edge flow */}
      <div className="flex items-center overflow-x-auto pb-1" style={{ gap: 0 }}>
        {(path.nodes || []).map((node, i) => (
          <React.Fragment key={node.uid || i}>
            <NodeChip node={node} isActive={isActive} />
            {i < (path.edges || []).length && (
              <EdgeArrow edge={path.edges[i]} />
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

function OrcaPathPanel({ paths, highlightedPath, onHighlight }) {
  const [showAll, setShowAll] = useState(false);
  if (!paths || paths.length === 0) return null;

  const displayed = showAll ? paths : paths.slice(0, 6);
  const criticalCount = paths.filter(p => {
    const maxRisk = Math.max(...(p.nodes || []).map(n => n.risk_score || 0));
    return maxRisk >= 80;
  }).length;
  const internetCount = paths.filter(p => p.entry_point === 'Internet' || p.entry_type === 'Internet').length;

  return (
    <div
      className="rounded-xl border overflow-hidden"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3 border-b"
        style={{ borderColor: 'var(--border-primary)', backgroundColor: 'rgba(239,68,68,0.04)' }}
      >
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4" style={{ color: '#ef4444' }} />
            <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
              Attack Paths
            </span>
          </div>
          <span
            className="text-[10px] font-bold px-2 py-0.5 rounded-full"
            style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#ef4444' }}
          >
            {paths.length}
          </span>
          {criticalCount > 0 && (
            <span
              className="text-[10px] font-medium px-2 py-0.5 rounded-full"
              style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#fca5a5' }}
            >
              {criticalCount} critical
            </span>
          )}
          {internetCount > 0 && (
            <span
              className="flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full"
              style={{ backgroundColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.5)' }}
            >
              <Globe style={{ width: 9, height: 9 }} />
              {internetCount} internet-exposed
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.3)' }}>
            Click path to highlight in graph
          </span>
          {paths.length > 6 && (
            <button
              onClick={() => setShowAll(v => !v)}
              className="text-[11px] font-medium hover:underline"
              style={{ color: '#60a5fa' }}
            >
              {showAll ? 'Show less' : `Show all ${paths.length}`}
            </button>
          )}
        </div>
      </div>

      {/* Legend */}
      <div
        className="flex items-center gap-5 px-4 py-2 border-b"
        style={{ borderColor: 'var(--border-primary)' }}
      >
        {[
          { color: '#ef4444', label: 'Critical ≥80' },
          { color: '#f97316', label: 'High ≥60' },
          { color: '#eab308', label: 'Medium ≥40' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color, opacity: 0.8 }} />
            <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</span>
          </div>
        ))}
        <div className="flex items-center gap-1.5 ml-2">
          <AlertTriangle style={{ width: 9, height: 9, color: '#f97316' }} />
          <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.4)' }}>Findings</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Zap style={{ width: 9, height: 9, color: '#ef4444' }} />
          <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.4)' }}>Active threats</span>
        </div>
      </div>

      {/* Path list */}
      <div className="p-4 flex flex-col gap-2.5 max-h-[480px] overflow-y-auto">
        {displayed.map((path) => (
          <OrcaPathCard
            key={path.path_id}
            path={path}
            highlighted={highlightedPath}
            onHighlight={onHighlight}
          />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------
export default function SecurityGraphExplorer() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [visibleNodeTypes, setVisibleNodeTypes] = useState(null); // null = show all
  const [visibleEdgeTypes, setVisibleEdgeTypes] = useState(null); // null = show all
  // Threat hunting: quick-filter presets
  const [viewPreset, setViewPreset] = useState('all'); // 'all' | 'threats' | 'internet'
  const [exploreResult, setExploreResult] = useState(null); // result from Graph Explorer query
  const [orcaPaths, setOrcaPaths] = useState([]);           // Orca-style attack path cards
  const [highlightedPath, setHighlightedPath] = useState(null); // path_id of highlighted path
  const containerRef = useRef(null);
  const [containerDims, setContainerDims] = useState({ w: 1200, h: 600 });

  // Fetch data
  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchView('threats/graph');
        if (cancelled) return;
        if (result?.error) {
          setError(result.error);
        } else {
          setData(result);
          // Orca paths are included in the graph view response
          if (Array.isArray(result?.orca_paths)) {
            setOrcaPaths(result.orca_paths);
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err?.message || 'Failed to load graph data');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  // Measure container
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver((entries) => {
      const rect = entries[0].contentRect;
      setContainerDims({
        w: Math.max(400, rect.width),
        h: Math.max(400, rect.height),
      });
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // Derive nodes and edges from data
  const allNodes = useMemo(() => {
    if (!data) return [];
    return Array.isArray(data.nodes) ? data.nodes : [];
  }, [data]);

  const allEdges = useMemo(() => {
    if (!data) return [];
    return Array.isArray(data.edges)
      ? data.edges
      : Array.isArray(data.links)
      ? data.links
      : Array.isArray(data.relationships)
      ? data.relationships
      : [];
  }, [data]);

  // When explore query returns results, use those; otherwise use full graph data
  const nodes = useMemo(() => exploreResult ? exploreResult.nodes : allNodes, [exploreResult, allNodes]);
  const edges = useMemo(() => exploreResult ? exploreResult.edges : allEdges, [exploreResult, allEdges]);

  // KPIs — computed from allNodes/allEdges (pre-filter baseline)
  const kpi = useMemo(() => {
    if (data?.kpi) return data.kpi;
    const totalConns = allEdges.length * 2; // each edge touches 2 nodes
    const avgConns = allNodes.length > 0 ? (totalConns / allNodes.length).toFixed(1) : '0';
    const highRisk = allNodes.filter(
      (n) => (n.risk_score ?? n.riskScore ?? 0) >= 70
    ).length;
    const internetExposed = allNodes.filter(
      (n) => n.internet_exposed ?? n.internetExposed ?? false
    ).length;
    const techniques = new Set();
    allNodes.forEach((n) => {
      (n.mitre_techniques ?? n.techniques ?? []).forEach((t) => techniques.add(t));
    });
    return {
      totalNodes: allNodes.length,
      totalEdges: allEdges.length,
      avgConnections: avgConns,
      highRisk,
      internetExposed,
      techniques: techniques.size,
    };
  }, [data, allNodes, allEdges]);

  // Selected node object
  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) || null,
    [nodes, selectedNodeId]
  );

  // Discover unique node/edge types in data
  const discoveredNodeTypes = useMemo(() => {
    const types = new Set();
    nodes.forEach((n) => types.add(normalizeType(n.type || n.resourceType || '')));
    return types;
  }, [nodes]);

  const discoveredEdgeTypes = useMemo(() => {
    const types = new Set();
    edges.forEach((e) =>
      types.add((e.type || e.relationship || 'UNKNOWN').toUpperCase().replace(/\s+/g, '_'))
    );
    return types;
  }, [edges]);

  // Auto-initialize visible sets to include ALL types (config + discovered)
  const allNodeTypes = useMemo(() => {
    return new Set([...Object.keys(NODE_TYPE_CONFIG), ...discoveredNodeTypes]);
  }, [discoveredNodeTypes]);

  const allEdgeTypes = useMemo(() => {
    return new Set([...Object.keys(EDGE_TYPE_CONFIG), ...discoveredEdgeTypes]);
  }, [discoveredEdgeTypes]);

  // Initialize once data arrives
  useEffect(() => {
    if (visibleNodeTypes === null && allNodeTypes.size > 0) {
      setVisibleNodeTypes(new Set(allNodeTypes));
    }
  }, [allNodeTypes]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (visibleEdgeTypes === null && allEdgeTypes.size > 0) {
      setVisibleEdgeTypes(new Set(allEdgeTypes));
    }
  }, [allEdgeTypes]); // eslint-disable-line react-hooks/exhaustive-deps

  // Node type filter items
  const nodeTypeItems = useMemo(() => {
    const all = new Set([
      ...Object.keys(NODE_TYPE_CONFIG),
      ...discoveredNodeTypes,
    ]);
    return [...all].map((key) => ({
      key,
      label: NODE_TYPE_CONFIG[key]?.label || key,
      color: NODE_TYPE_CONFIG[key]?.color || DEFAULT_NODE_COLOR,
    }));
  }, [discoveredNodeTypes]);

  // Edge type filter items
  const edgeTypeItems = useMemo(() => {
    const all = new Set([
      ...Object.keys(EDGE_TYPE_CONFIG),
      ...discoveredEdgeTypes,
    ]);
    return [...all].map((key) => ({
      key,
      label: EDGE_TYPE_CONFIG[key]?.label || key.replace(/_/g, ' '),
      color: EDGE_TYPE_CONFIG[key]?.color || DEFAULT_EDGE_COLOR,
    }));
  }, [discoveredEdgeTypes]);

  const toggleNodeType = useCallback((key) => {
    setVisibleNodeTypes((prev) => {
      const next = new Set(prev || allNodeTypes);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }, [allNodeTypes]);

  const toggleEdgeType = useCallback((key) => {
    setVisibleEdgeTypes((prev) => {
      const next = new Set(prev || allEdgeTypes);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }, [allEdgeTypes]);

  const handleNodeClick = useCallback((nodeId) => {
    setSelectedNodeId((prev) => (prev === nodeId ? null : nodeId));
  }, []);

  // Highlighted node IDs from Orca path selection
  const highlightedNodeIds = useMemo(() => {
    if (!highlightedPath) return null;
    const p = orcaPaths.find((op) => op.path_id === highlightedPath);
    return p ? new Set(p.nodes.map((n) => n.uid)) : null;
  }, [highlightedPath, orcaPaths]);

  // Graph height: fill viewport minus header space
  const graphHeight = typeof window !== 'undefined' ? Math.max(500, window.innerHeight - 340) : 600;

  // ----- Render -----

  if (loading) {
    return (
      <div className="space-y-4 p-6" style={{ backgroundColor: 'var(--bg-primary)', minHeight: '100vh' }}>
        {/* Header skeleton */}
        <div>
          <div className="h-8 w-64 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          <div className="h-4 w-40 mt-2 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        </div>
        {/* MetricStrip skeleton */}
        <div
          className="rounded-xl border overflow-hidden"
          style={{ display: 'flex', backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          {[1, 2].map((g) => (
            <div key={g} style={{ flex: 1, padding: '14px 20px', borderLeft: g > 1 ? '1px solid var(--border-primary)' : 'none', borderTop: '3px solid var(--bg-secondary)' }}>
              <div className="h-3 w-24 rounded animate-pulse mb-4" style={{ backgroundColor: 'var(--bg-secondary)' }} />
              <div style={{ display: 'flex', gap: 28 }}>
                {[1, 2, 3].map((c) => (
                  <div key={c}>
                    <div className="h-2.5 w-14 rounded animate-pulse mb-2" style={{ backgroundColor: 'var(--bg-secondary)' }} />
                    <div className="h-6 w-10 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        {/* Graph skeleton */}
        <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: '#0a0e17', borderColor: 'var(--border-primary)', height: graphHeight }}>
          <div className="flex items-center justify-center h-full">
            <div className="flex flex-col items-center gap-3">
              <Network className="w-12 h-12 animate-pulse" style={{ color: 'var(--text-secondary)', opacity: 0.3 }} />
              <p className="text-sm animate-pulse" style={{ color: 'var(--text-secondary)' }}>Loading security graph...</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4 p-6" style={{ backgroundColor: 'var(--bg-primary)', minHeight: '100vh' }}>
        <Header />
        <div
          className="rounded-xl border p-8"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <EmptyState
            icon={<AlertTriangle className="w-12 h-12" />}
            title="Failed to Load Graph"
            description={error}
            action={{
              label: 'Retry',
              onClick: () => window.location.reload(),
            }}
          />
        </div>
      </div>
    );
  }

  if (nodes.length === 0) {
    return (
      <div className="space-y-4 p-6" style={{ backgroundColor: 'var(--bg-primary)', minHeight: '100vh' }}>
        <Header />
        <div
          className="rounded-xl border p-8"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <EmptyState
            icon={<Network className="w-12 h-12" />}
            title="No Graph Data"
            description="No security graph data is available. Run an inventory scan to build the resource graph."
          />
        </div>
      </div>
    );
  }

  return (
    <div
      className="space-y-4 p-6"
      style={{ backgroundColor: 'var(--bg-primary)', minHeight: '100vh' }}
    >
      {/* Header + Breadcrumb */}
      <Header />

      {/* Threats Sub-Navigation */}
      <ThreatsSubNav />

      {/* KPI MetricStrip */}
      <MetricStrip
        groups={[
          {
            label: '\u{1F535} GRAPH TOPOLOGY',
            color: 'var(--accent-primary)',
            cells: [
              { label: 'NODES', value: kpi.nodes ?? kpi.totalNodes ?? nodes.length, noTrend: true, context: 'cloud resources' },
              { label: 'EDGES', value: kpi.edges ?? kpi.totalEdges ?? edges.length, noTrend: true, context: 'relationships' },
              { label: 'AVG RISK', value: kpi.avgRisk ?? kpi.avgConnections ?? '0', noTrend: true, context: 'risk score' },
            ],
          },
          {
            label: '\u{1F534} RISK',
            color: 'var(--accent-danger)',
            cells: [
              { label: 'INTERNET EXPOSED', value: kpi.internetExposed ?? 0, valueColor: '#f97316', noTrend: true, context: 'publicly reachable' },
              { label: 'GRAPH NODES', value: nodes.length, noTrend: true, context: 'in view' },
              { label: 'GRAPH EDGES', value: edges.length, noTrend: true, context: 'in view' },
            ],
          },
        ]}
      />

      {/* Toolbar: Search + Filters */}
      <div
        className="flex flex-wrap items-center gap-3 rounded-xl border px-4 py-3"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        {/* Search */}
        <div
          className="flex items-center gap-2 px-3 rounded-lg border flex-1 min-w-[220px]"
          style={{
            backgroundColor: 'var(--bg-secondary)',
            borderColor: 'var(--border-primary)',
            height: '38px',
          }}
        >
          <Search
            className="w-4 h-4 flex-shrink-0"
            style={{ color: 'var(--text-secondary)' }}
          />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search resource name or ID..."
            className="flex-1 bg-transparent outline-none text-sm"
            style={{ color: 'var(--text-primary)' }}
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="hover:opacity-70 transition-opacity"
              style={{ color: 'var(--text-secondary)' }}
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Node type filter */}
        <MultiSelectFilter
          label="Node Types"
          icon={<Filter className="w-3.5 h-3.5" />}
          items={nodeTypeItems}
          selected={visibleNodeTypes}
          onToggle={toggleNodeType}
        />

        {/* Edge type filter */}
        <MultiSelectFilter
          label="Edge Types"
          icon={<GitBranch className="w-3.5 h-3.5" />}
          items={edgeTypeItems}
          selected={visibleEdgeTypes}
          onToggle={toggleEdgeType}
        />

        {/* Separator */}
        <div className="w-px h-6" style={{ backgroundColor: 'var(--border-primary)' }} />

        {/* Threat hunting quick filters */}
        {[
          { key: 'all', label: 'All', icon: null },
          { key: 'threats', label: 'With Threats', icon: <ShieldAlert className="w-3 h-3" /> },
          { key: 'internet', label: 'Internet Exposed', icon: <Globe className="w-3 h-3" /> },
        ].map((preset) => (
          <button
            key={preset.key}
            onClick={() => setViewPreset(preset.key)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg border text-xs font-medium transition-colors"
            style={{
              backgroundColor: viewPreset === preset.key ? 'rgba(59,130,246,0.15)' : 'var(--bg-secondary)',
              borderColor: viewPreset === preset.key ? '#3b82f6' : 'var(--border-primary)',
              color: viewPreset === preset.key ? '#60a5fa' : 'var(--text-secondary)',
            }}
          >
            {preset.icon}
            {preset.label}
          </button>
        ))}

        {/* Reset filters */}
        <button
          onClick={() => {
            setVisibleNodeTypes(new Set(allNodeTypes));
            setVisibleEdgeTypes(new Set(allEdgeTypes));
            setViewPreset('all');
            setSearchQuery('');
            setSelectedNodeId(null);
            setExploreResult(null);
          }}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg border text-xs font-medium
                     hover:opacity-80 transition-opacity"
          style={{
            backgroundColor: 'var(--bg-secondary)',
            borderColor: 'var(--border-primary)',
            color: 'var(--text-secondary)',
          }}
          title="Reset all filters"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Reset
        </button>
      </div>

      {/* Graph Explorer — structured filters → Neo4j Cypher */}
      <VisualQueryBuilder
        tenantId={TENANT_ID}
        onResultChange={setExploreResult}
        activeResult={exploreResult}
      />

      {/* Graph + Detail Panel */}
      <div
        ref={containerRef}
        className="relative rounded-xl border overflow-hidden"
        style={{
          borderColor: 'var(--border-primary)',
          height: `${graphHeight}px`,
        }}
      >
        <SecurityGraph
          nodes={nodes}
          edges={edges}
          selectedNodeId={selectedNodeId}
          onNodeClick={handleNodeClick}
          searchQuery={searchQuery}
          visibleNodeTypes={visibleNodeTypes}
          visibleEdgeTypes={visibleEdgeTypes}
          viewPreset={viewPreset}
          highlightedNodeIds={highlightedNodeIds}
          containerWidth={containerDims.w}
          containerHeight={graphHeight}
        />

        {/* Empty state overlay when filter returns no nodes */}
        {exploreResult && nodes.length === 0 && (
          <div
            className="absolute inset-0 flex flex-col items-center justify-center gap-4 z-20"
            style={{ backgroundColor: 'rgba(10,14,23,0.92)', backdropFilter: 'blur(2px)' }}
          >
            <div className="flex flex-col items-center gap-3 text-center">
              <div
                className="w-14 h-14 rounded-full flex items-center justify-center"
                style={{ backgroundColor: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.3)' }}
              >
                <Filter className="w-6 h-6" style={{ color: '#60a5fa' }} />
              </div>
              <div>
                <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                  No nodes match these filters
                </p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
                  {exploreResult.cypher_summary
                    ? `Query: ${exploreResult.cypher_summary}`
                    : 'Try broadening the filter criteria'}
                </p>
              </div>
              <button
                onClick={() => setExploreResult(null)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-opacity hover:opacity-80"
                style={{ backgroundColor: '#3b82f6', color: '#fff' }}
              >
                <RotateCcw className="w-4 h-4" />
                Clear Filters — Show Full Graph
              </button>
            </div>
          </div>
        )}

        {/* Detail Panel (slides in from right) */}
        {selectedNode && (
          <DetailPanel
            node={selectedNode}
            edges={edges}
            allNodes={nodes}
            onNodeClick={handleNodeClick}
            onClose={() => setSelectedNodeId(null)}
          />
        )}
      </div>

      {/* Orca-style Attack Path Cards */}
      <OrcaPathPanel
        paths={orcaPaths}
        highlightedPath={highlightedPath}
        onHighlight={setHighlightedPath}
        onNodeClick={handleNodeClick}
      />

      {/* Graph Legend */}
      <div
        className="rounded-xl border p-5"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <div className="flex flex-wrap gap-x-6 gap-y-2">
          <span
            className="text-xs font-semibold uppercase tracking-wider"
            style={{ color: 'var(--text-secondary)' }}
          >
            Nodes:
          </span>
          {Object.entries(NODE_TYPE_CONFIG).map(([key, cfg]) => (
            <div key={key} className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5 rounded-full"
                style={{ backgroundColor: cfg.color }}
              />
              <span className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                {cfg.label}
              </span>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap gap-x-6 gap-y-2 mt-3 pt-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <span
            className="text-xs font-semibold uppercase tracking-wider"
            style={{ color: 'var(--text-secondary)' }}
          >
            Edges:
          </span>
          {/* Kind legend */}
          <div className="flex items-center gap-1.5">
            <span className="w-5 h-[2px] rounded" style={{ backgroundColor: '#60a5fa' }} />
            <span className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>Path (attack route)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <svg width="20" height="4">
              <line x1="0" y1="2" x2="20" y2="2" stroke="#475569" strokeWidth="1.5" strokeDasharray="4 2" />
            </svg>
            <span className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>Association (context)</span>
          </div>
          <div className="w-px h-4 self-center" style={{ backgroundColor: 'var(--border-primary)' }} />
          {Object.entries(EDGE_TYPE_CONFIG).map(([key, cfg]) => (
            <div key={key} className="flex items-center gap-1.5">
              {cfg.kind === 'association'
                ? <svg width="16" height="4"><line x1="0" y1="2" x2="16" y2="2" stroke={cfg.color} strokeWidth="1.5" strokeDasharray="4 2" /></svg>
                : <span className="w-4 h-[2px] rounded" style={{ backgroundColor: cfg.color }} />
              }
              <span className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                {cfg.label}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Header sub-component
// ---------------------------------------------------------------------------
function Header() {
  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <a
          href="/ui/threats"
          className="text-xs hover:underline"
          style={{ color: 'var(--text-secondary)' }}
        >
          Threats
        </a>
        <ChevronRight className="w-3 h-3" style={{ color: 'var(--text-secondary)' }} />
        <span className="text-xs" style={{ color: 'var(--text-primary)' }}>
          Graph Explorer
        </span>
      </div>
      <h1
        className="text-2xl font-bold flex items-center gap-2.5"
        style={{ color: 'var(--text-primary)' }}
      >
        <Network size={26} style={{ color: '#3b82f6' }} />
        Security Graph Explorer
      </h1>
      <p
        className="text-sm mt-1"
        style={{ color: 'var(--text-secondary)' }}
      >
        Interactive force-directed graph of all cloud resources, relationships, and security posture
      </p>
    </div>
  );
}
