'use client';

import React, {
  useState,
  useEffect,
  useRef,
  useMemo,
  useCallback,
} from 'react';
import { fetchView } from '@/lib/api';
import {
  Network,
  ChevronRight,
  Search,
  X,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Shield,
  ShieldAlert,
  ExternalLink,
  GitBranch,
  AlertTriangle,
  Eye,
  Filter,
  RotateCcw,
} from 'lucide-react';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

// ---------------------------------------------------------------------------
// Node type configuration
// ---------------------------------------------------------------------------
const NODE_TYPE_CONFIG = {
  EC2:             { color: '#3b82f6', abbr: 'EC2',  label: 'EC2' },
  S3:              { color: '#22c55e', abbr: 'S3',   label: 'S3' },
  IAM:             { color: '#a855f7', abbr: 'IAM',  label: 'IAM' },
  RDS:             { color: '#f97316', abbr: 'RDS',  label: 'RDS' },
  Lambda:          { color: '#06b6d4', abbr: 'Fn',   label: 'Lambda' },
  VPC:             { color: '#8b5cf6', abbr: 'VPC',  label: 'VPC' },
  SecurityGroup:   { color: '#ef4444', abbr: 'SG',   label: 'Security Group' },
  LoadBalancer:    { color: '#eab308', abbr: 'LB',   label: 'Load Balancer' },
  CloudFront:      { color: '#f59e0b', abbr: 'CF',   label: 'CloudFront' },
  DynamoDB:        { color: '#527fff', abbr: 'DDB',  label: 'DynamoDB' },
  SNS:             { color: '#ec4899', abbr: 'SNS',  label: 'SNS' },
  SQS:             { color: '#ec4899', abbr: 'SQS',  label: 'SQS' },
  KMS:             { color: '#dc2626', abbr: 'KMS',  label: 'KMS' },
  Subnet:          { color: '#7c3aed', abbr: 'SUB',  label: 'Subnet' },
  NATGateway:      { color: '#f97316', abbr: 'NAT',  label: 'NAT Gateway' },
  ElastiCache:     { color: '#c7131f', abbr: 'EC',   label: 'ElastiCache' },
  EKS:             { color: '#326ce5', abbr: 'EKS',  label: 'EKS' },
  ECS:             { color: '#ff9900', abbr: 'ECS',  label: 'ECS' },
};

const DEFAULT_NODE_COLOR = '#6b7280';

// ---------------------------------------------------------------------------
// Edge type configuration
// ---------------------------------------------------------------------------
const EDGE_TYPE_CONFIG = {
  ROUTES_TO:       { color: '#eab308', label: 'Routes To' },
  EXPOSES:         { color: '#ef4444', label: 'Exposes' },
  HAS_ACCESS:      { color: '#a855f7', label: 'Has Access' },
  ALLOWS_TRAFFIC:  { color: '#22c55e', label: 'Allows Traffic' },
  HAS_THREAT:      { color: '#ef4444', label: 'Has Threat' },
  HAS_FINDING:     { color: '#f97316', label: 'Has Finding' },
  REFERENCES:      { color: '#3b82f6', label: 'References' },
  CONTAINS:        { color: '#06b6d4', label: 'Contains' },
};

const DEFAULT_EDGE_COLOR = '#525252';

// ---------------------------------------------------------------------------
// Force simulation helpers
// ---------------------------------------------------------------------------
function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

function forceSimulation(nodes, edges, width, height, iterations = 200) {
  const CHARGE = -300;
  const LINK_DIST = 100;
  const COLLISION_PAD = 8;
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
      return visibleNodeTypes.has(nType);
    });
  }, [nodes, visibleNodeTypes]);

  const filteredNodeIds = useMemo(
    () => new Set(filteredNodes.map((n) => n.id)),
    [filteredNodes]
  );

  const filteredEdges = useMemo(() => {
    return edges.filter((e) => {
      const eType = (e.type || e.relationship || '').toUpperCase().replace(/\s+/g, '_');
      return (
        visibleEdgeTypes.has(eType) &&
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
      const radius = 6 + Math.min(conns, 15) * 1.2;
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

  const getNodeAbbr = (type) => {
    const nType = normalizeType(type);
    return NODE_TYPE_CONFIG[nType]?.abbr || type?.slice(0, 3)?.toUpperCase() || '?';
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
            <polygon points="0 0, 10 3.5, 0 7" fill="#525252" />
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
          {/* Edges */}
          {filteredEdges.map((edge, idx) => {
            const srcPos = nodePositions[edge.source];
            const tgtPos = nodePositions[edge.target];
            if (!srcPos || !tgtPos) return null;

            const isConnected =
              selectedNodeId &&
              (edge.source === selectedNodeId || edge.target === selectedNodeId);
            const opacity = selectedNodeId ? (isConnected ? 0.9 : 0.08) : 0.4;

            return (
              <line
                key={`edge-${idx}`}
                x1={srcPos.x}
                y1={srcPos.y}
                x2={tgtPos.x}
                y2={tgtPos.y}
                stroke={getEdgeColor(edge.type || edge.relationship)}
                strokeWidth={isConnected ? 2 : 1}
                strokeOpacity={opacity}
                markerEnd={isConnected ? 'url(#arrowhead)' : undefined}
              />
            );
          })}

          {/* Nodes */}
          {filteredNodes.map((node) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;

            const conns = connectionCounts[node.id] || 0;
            const radius = pos._radius || 6 + Math.min(conns, 15) * 1.2;
            const color = getNodeColor(node.type || node.resourceType);
            const abbr = getNodeAbbr(node.type || node.resourceType);
            const isSelected = selectedNodeId === node.id;
            const isConnectedToSel =
              selectedNodeId && connectedToSelected.has(node.id);
            const isSearchHit = searchMatch && searchMatch.has(node.id);
            const isDimmed =
              (selectedNodeId && !isConnectedToSel) ||
              (searchMatch && searchMatch.size > 0 && !isSearchHit);
            const name =
              node.label ||
              node.resourceName ||
              node.id?.split('/')?.pop()?.split(':')?.pop() ||
              '';
            const truncName = name.length > 16 ? name.slice(0, 14) + '..' : name;

            return (
              <g
                key={node.id}
                style={{
                  cursor: dragNode === node.id ? 'grabbing' : 'pointer',
                  opacity: isDimmed ? 0.15 : 1,
                  transition: 'opacity 0.2s',
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  onNodeClick(node.id);
                }}
                onMouseDown={(e) => handleNodeMouseDown(e, node.id)}
              >
                {/* Threat glow */}
                {node.has_threat && (
                  <circle
                    cx={pos.x}
                    cy={pos.y}
                    r={radius + 6}
                    fill="none"
                    stroke="#ef4444"
                    strokeWidth={1.5}
                    strokeOpacity={0.6}
                    strokeDasharray="3 2"
                  />
                )}

                {/* Selection ring */}
                {isSelected && (
                  <circle
                    cx={pos.x}
                    cy={pos.y}
                    r={radius + 4}
                    fill="none"
                    stroke="#fbbf24"
                    strokeWidth={2.5}
                    filter="url(#glow)"
                  />
                )}

                {/* Search match ring */}
                {isSearchHit && !isSelected && (
                  <circle
                    cx={pos.x}
                    cy={pos.y}
                    r={radius + 3}
                    fill="none"
                    stroke="#22d3ee"
                    strokeWidth={1.5}
                    strokeDasharray="4 2"
                  />
                )}

                {/* Main circle */}
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={radius}
                  fill={color}
                  stroke="rgba(255,255,255,0.2)"
                  strokeWidth={1}
                />

                {/* Abbreviation text */}
                <text
                  x={pos.x}
                  y={pos.y}
                  textAnchor="middle"
                  dominantBaseline="central"
                  fill="white"
                  fontSize={Math.max(7, Math.min(radius * 0.7, 11))}
                  fontWeight="bold"
                  fontFamily="system-ui, sans-serif"
                  style={{ pointerEvents: 'none' }}
                >
                  {abbr}
                </text>

                {/* Label */}
                <text
                  x={pos.x}
                  y={pos.y + radius + 12}
                  textAnchor="middle"
                  fill="rgba(255,255,255,0.7)"
                  fontSize={9}
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
  const s = raw.replace(/[._\-\s]+/g, '').toLowerCase();
  for (const key of Object.keys(NODE_TYPE_CONFIG)) {
    if (key.toLowerCase() === s) return key;
  }
  // Partial matches
  if (s.includes('ec2') || s.includes('instance')) return 'EC2';
  if (s.includes('s3') || s.includes('bucket')) return 'S3';
  if (s.includes('iam') || s.includes('role') || s.includes('user') || s.includes('policy')) return 'IAM';
  if (s.includes('rds') || s.includes('dbinstance')) return 'RDS';
  if (s.includes('lambda') || s.includes('function')) return 'Lambda';
  if (s.includes('vpc') && !s.includes('endpoint')) return 'VPC';
  if (s.includes('securitygroup') || s.includes('sg')) return 'SecurityGroup';
  if (s.includes('loadbalancer') || s.includes('alb') || s.includes('elb') || s.includes('nlb')) return 'LoadBalancer';
  if (s.includes('cloudfront') || s.includes('distribution')) return 'CloudFront';
  if (s.includes('dynamodb') || s.includes('ddb')) return 'DynamoDB';
  if (s.includes('sns')) return 'SNS';
  if (s.includes('sqs')) return 'SQS';
  if (s.includes('kms') || s.includes('key')) return 'KMS';
  if (s.includes('subnet')) return 'Subnet';
  if (s.includes('nat')) return 'NATGateway';
  if (s.includes('elasticache') || s.includes('cache')) return 'ElastiCache';
  if (s.includes('eks') || s.includes('cluster')) return 'EKS';
  if (s.includes('ecs') || s.includes('task') || s.includes('container')) return 'ECS';
  return raw;
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
            <span
              className="w-3 h-3 rounded-full flex-shrink-0"
              style={{ backgroundColor: color }}
            />
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
                  <span
                    className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                    style={{ backgroundColor: cnColor }}
                  />
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
            href={`/inventory?search=${encodeURIComponent(node.id)}`}
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
            href={`/threats?search=${encodeURIComponent(node.id)}`}
            className="flex items-center justify-center gap-2 text-xs py-2 rounded-lg
                       hover:opacity-90 transition-opacity text-white"
            style={{ backgroundColor: 'rgba(239,68,68,0.7)' }}
          >
            <ShieldAlert className="w-3 h-3" />
            View Threats
          </a>
          <a
            href={`/threats/blast-radius?uid=${encodeURIComponent(node.id)}`}
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

  const allSelected = items.every((i) => selected.has(i.key));
  const noneSelected = items.every((i) => !selected.has(i.key));

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
          {[...selected].filter((k) => items.some((i) => i.key === k)).length}
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
                const all = new Set(items.map((i) => i.key));
                items.forEach((i) => {
                  if (!selected.has(i.key)) onToggle(i.key);
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
                  if (selected.has(i.key)) onToggle(i.key);
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
                checked={selected.has(item.key)}
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
// Main Page
// ---------------------------------------------------------------------------
export default function SecurityGraphExplorer() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [visibleNodeTypes, setVisibleNodeTypes] = useState(
    new Set(Object.keys(NODE_TYPE_CONFIG))
  );
  const [visibleEdgeTypes, setVisibleEdgeTypes] = useState(
    new Set(Object.keys(EDGE_TYPE_CONFIG))
  );
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
  const nodes = useMemo(() => {
    if (!data) return [];
    return Array.isArray(data.nodes) ? data.nodes : [];
  }, [data]);

  const edges = useMemo(() => {
    if (!data) return [];
    return Array.isArray(data.edges)
      ? data.edges
      : Array.isArray(data.links)
      ? data.links
      : Array.isArray(data.relationships)
      ? data.relationships
      : [];
  }, [data]);

  // KPIs
  const kpi = useMemo(() => {
    if (data?.kpi) return data.kpi;
    const avgRisk =
      nodes.length > 0
        ? Math.round(
            nodes.reduce((sum, n) => sum + (n.risk_score ?? n.riskScore ?? 0), 0) /
              nodes.length
          )
        : 0;
    return {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      avgRiskScore: avgRisk,
    };
  }, [data, nodes, edges]);

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
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }, []);

  const toggleEdgeType = useCallback((key) => {
    setVisibleEdgeTypes((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }, []);

  const handleNodeClick = useCallback((nodeId) => {
    setSelectedNodeId((prev) => (prev === nodeId ? null : nodeId));
  }, []);

  // Graph height: fill viewport minus header space
  const graphHeight = typeof window !== 'undefined' ? Math.max(500, window.innerHeight - 340) : 600;

  // ----- Render -----

  if (loading) {
    return (
      <div className="space-y-6 p-6" style={{ backgroundColor: 'var(--bg-primary)', minHeight: '100vh' }}>
        {/* Header skeleton */}
        <div>
          <div className="h-8 w-64 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          <div className="h-4 w-40 mt-2 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        </div>
        {/* KPI skeleton */}
        <div className="grid grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="rounded-xl border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="h-4 w-20 rounded animate-pulse mb-3" style={{ backgroundColor: 'var(--bg-secondary)' }} />
              <div className="h-8 w-16 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
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
      <div className="space-y-6 p-6" style={{ backgroundColor: 'var(--bg-primary)', minHeight: '100vh' }}>
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
      <div className="space-y-6 p-6" style={{ backgroundColor: 'var(--bg-primary)', minHeight: '100vh' }}>
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

      {/* KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <KpiCard
          title="Total Nodes"
          value={kpi.totalNodes ?? nodes.length}
          icon={<Network size={20} />}
          color="blue"
          subtitle="Cloud resources in graph"
        />
        <KpiCard
          title="Total Edges"
          value={kpi.totalEdges ?? edges.length}
          icon={<GitBranch size={20} />}
          color="purple"
          subtitle="Relationships mapped"
        />
        <KpiCard
          title="Avg Risk Score"
          value={kpi.avgRiskScore ?? 0}
          icon={<Shield size={20} />}
          color={
            (kpi.avgRiskScore ?? 0) >= 70
              ? 'red'
              : (kpi.avgRiskScore ?? 0) >= 40
              ? 'orange'
              : 'green'
          }
          subtitle="Across all resources"
        />
      </div>

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

        {/* Reset filters */}
        <button
          onClick={() => {
            setVisibleNodeTypes(new Set(Object.keys(NODE_TYPE_CONFIG)));
            setVisibleEdgeTypes(new Set(Object.keys(EDGE_TYPE_CONFIG)));
            setSearchQuery('');
            setSelectedNodeId(null);
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
          containerWidth={containerDims.w}
          containerHeight={graphHeight}
        />

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
          {Object.entries(EDGE_TYPE_CONFIG).map(([key, cfg]) => (
            <div key={key} className="flex items-center gap-1.5">
              <span
                className="w-4 h-[2px] rounded"
                style={{ backgroundColor: cfg.color }}
              />
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
          href="/threats"
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
