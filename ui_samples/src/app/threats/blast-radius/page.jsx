'use client';

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useSearchParams } from 'next/navigation';
import {
  Search,
  ChevronRight,
  AlertTriangle,
  Shield,
  Zap,
  Network,
  ExternalLink,
  Globe,
  X,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ArrowRight,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

import { fetchView } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import SearchBar from '@/components/shared/SearchBar';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import DataTable from '@/components/shared/DataTable';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

// ---------------------------------------------------------------------------
// Force Simulation Engine
// ---------------------------------------------------------------------------
class ForceSimulation {
  constructor(nodes, edges, width, height) {
    this.nodes = nodes;
    this.edges = edges;
    this.width = width;
    this.height = height;
    this.alpha = 1.0;
    this.alphaDecay = 0.012;
    this.charge = -400;
    this.linkDistance = 120;
    this.centerStrength = 0.04;
    this.centerX = width / 2;
    this.centerY = height / 2;

    // Place nodes in a radial layout seeded by depth (hops)
    this.nodes.forEach((node, i) => {
      if (node.x == null) {
        const angle = (i / Math.max(this.nodes.length, 1)) * Math.PI * 2;
        const radius = 60 + (node.hops || 0) * 90 + Math.random() * 30;
        node.x = this.centerX + Math.cos(angle) * radius;
        node.y = this.centerY + Math.sin(angle) * radius;
      }
      node.vx = 0;
      node.vy = 0;
    });
  }

  /** Run a single tick of the simulation. Returns current alpha. */
  tick() {
    this._chargeForce();
    this._linkForce();
    this._centerForce();
    this._integrate();
    this.alpha *= 1 - this.alphaDecay;
    return this.alpha;
  }

  _chargeForce() {
    const nodes = this.nodes;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (this.charge / (dist * dist)) * this.alpha;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx -= fx;
        a.vy -= fy;
        b.vx += fx;
        b.vy += fy;
      }
    }
  }

  _linkForce() {
    this.edges.forEach((edge) => {
      const a = this.nodes[edge.source];
      const b = this.nodes[edge.target];
      if (!a || !b) return;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = ((dist - this.linkDistance) / dist) * 0.15 * this.alpha;
      const fx = dx * force;
      const fy = dy * force;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    });
  }

  _centerForce() {
    this.nodes.forEach((node) => {
      node.vx += (this.centerX - node.x) * this.centerStrength * this.alpha;
      node.vy += (this.centerY - node.y) * this.centerStrength * this.alpha;
    });
  }

  _integrate() {
    const pad = 30;
    this.nodes.forEach((node) => {
      node.vx *= 0.9;
      node.vy *= 0.9;
      node.x += node.vx;
      node.y += node.vy;
      node.x = Math.max(pad, Math.min(this.width - pad, node.x));
      node.y = Math.max(pad, Math.min(this.height - pad, node.y));
    });
  }
}

// ---------------------------------------------------------------------------
// ForceGraph — custom SVG force-directed graph
// ---------------------------------------------------------------------------
function ForceGraph({ nodes, edges, selectedId, onNodeClick }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const simRef = useRef(null);
  const rafRef = useRef(null);
  const [, forceRender] = useState(0);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const draggingRef = useRef(false);
  const panStartRef = useRef(null);

  const WIDTH = 960;
  const HEIGHT = 560;

  // Run simulation
  useEffect(() => {
    if (!nodes.length) return;
    // Deep-clone nodes so simulation can mutate positions
    const simNodes = nodes.map((n) => ({ ...n }));
    simRef.current = { nodes: simNodes };
    const sim = new ForceSimulation(simNodes, edges, WIDTH, HEIGHT);
    let ticks = 0;
    const maxTicks = 200;

    const animate = () => {
      const alpha = sim.tick();
      ticks++;
      forceRender((v) => v + 1);
      if (alpha > 0.002 && ticks < maxTicks) {
        rafRef.current = requestAnimationFrame(animate);
      }
    };
    rafRef.current = requestAnimationFrame(animate);

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [nodes, edges]);

  // Zoom via scroll
  const handleWheel = useCallback((e) => {
    e.preventDefault();
    setZoom((z) => Math.max(0.3, Math.min(4, z * (1 - e.deltaY * 0.001))));
  }, []);

  // Pan via drag on background
  const handlePointerDown = useCallback(
    (e) => {
      // Only left mouse for pan on background
      if (e.target !== svgRef.current && e.target.tagName !== 'rect') return;
      draggingRef.current = true;
      panStartRef.current = { x: e.clientX - pan.x * zoom, y: e.clientY - pan.y * zoom };
      svgRef.current?.setPointerCapture?.(e.pointerId);
    },
    [pan, zoom],
  );

  const handlePointerMove = useCallback(
    (e) => {
      if (!draggingRef.current || !panStartRef.current) return;
      setPan({
        x: (e.clientX - panStartRef.current.x) / zoom,
        y: (e.clientY - panStartRef.current.y) / zoom,
      });
    },
    [zoom],
  );

  const handlePointerUp = useCallback(() => {
    draggingRef.current = false;
    panStartRef.current = null;
  }, []);

  const resetView = useCallback(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, []);

  const simNodes = simRef.current?.nodes || [];

  // Determine node color
  const nodeColor = (node) => {
    if (node.isSource) return '#3b82f6'; // blue
    if ((node.threats || 0) > 0) return '#ef4444'; // red
    if ((node.findingCount || 0) > 0) return '#f97316'; // orange
    return '#22c55e'; // green
  };

  const nodeRadius = (node) => {
    if (node.isSource) return 24;
    return 14 + Math.min(Math.sqrt(node.findingCount || 0) * 2, 10);
  };

  // Truncate label
  const truncate = (s, len = 14) => (s && s.length > len ? s.slice(0, len - 1) + '\u2026' : s);

  return (
    <div ref={containerRef} className="relative w-full rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
      {/* Zoom controls */}
      <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
        <button
          onClick={() => setZoom((z) => Math.min(4, z * 1.3))}
          className="p-1.5 rounded-lg border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
          title="Zoom in"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(0.3, z / 1.3))}
          className="p-1.5 rounded-lg border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
          title="Zoom out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={resetView}
          className="p-1.5 rounded-lg border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
          title="Reset view"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* Legend */}
      <div
        className="absolute bottom-3 left-3 z-10 rounded-lg border p-3 text-xs space-y-1.5"
        style={{ backgroundColor: 'rgba(20,20,20,0.85)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
      >
        <div className="font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Legend</div>
        {[
          { color: '#3b82f6', label: 'Source' },
          { color: '#ef4444', label: 'Threats' },
          { color: '#f97316', label: 'Findings' },
          { color: '#22c55e', label: 'Clean' },
        ].map((item) => (
          <div key={item.label} className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ backgroundColor: item.color }} />
            <span>{item.label}</span>
          </div>
        ))}
      </div>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="w-full cursor-grab active:cursor-grabbing"
        style={{ minHeight: 400, maxHeight: 600, background: 'radial-gradient(ellipse at center, rgba(30,30,40,0.6) 0%, rgba(10,10,10,0.95) 100%)' }}
        onWheel={handleWheel}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onContextMenu={(e) => e.preventDefault()}
      >
        <defs>
          <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="rgba(148,163,184,0.4)" />
          </marker>
          <filter id="node-glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Invisible rect for pan drag target */}
        <rect x="0" y="0" width={WIDTH} height={HEIGHT} fill="transparent" />

        <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
          {/* Edges */}
          {edges.map((edge, i) => {
            const s = simNodes[edge.source];
            const t = simNodes[edge.target];
            if (!s || !t) return null;
            return (
              <line
                key={`e-${i}`}
                x1={s.x}
                y1={s.y}
                x2={t.x}
                y2={t.y}
                stroke="rgba(148,163,184,0.25)"
                strokeWidth={1.5}
                markerEnd="url(#arrowhead)"
              />
            );
          })}

          {/* Nodes */}
          {simNodes.map((node) => {
            const r = nodeRadius(node);
            const fill = nodeColor(node);
            const isSelected = node.uid === selectedId;

            return (
              <g
                key={node.id}
                onClick={(e) => {
                  e.stopPropagation();
                  onNodeClick(node);
                }}
                style={{ cursor: 'pointer' }}
              >
                {/* Selection ring */}
                {isSelected && (
                  <circle cx={node.x} cy={node.y} r={r + 5} fill="none" stroke="#93c5fd" strokeWidth={2.5} filter="url(#node-glow)" />
                )}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={r}
                  fill={fill}
                  opacity={0.9}
                  stroke="rgba(255,255,255,0.15)"
                  strokeWidth={1}
                />
                <text
                  x={node.x}
                  y={node.y + r + 14}
                  fontSize="10"
                  fill="rgba(245,245,245,0.8)"
                  textAnchor="middle"
                  pointerEvents="none"
                  fontWeight="500"
                >
                  {truncate(node.resourceName || node.resourceType)}
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
// Detail Panel (right column)
// ---------------------------------------------------------------------------
function DetailPanel({ node, allNodes, onClose }) {
  if (!node) return null;

  const riskScore = node.riskScore ?? 0;
  const riskColor = riskScore >= 80 ? '#ef4444' : riskScore >= 60 ? '#f97316' : riskScore >= 40 ? '#eab308' : '#22c55e';

  // Find connected nodes
  const connected = allNodes.filter((n) => n.uid !== node.uid && Math.abs((n.hops || 0) - (node.hops || 0)) <= 1);

  return (
    <div
      className="rounded-xl border overflow-y-auto"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
        <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Resource Details</h3>
        <button onClick={onClose} className="hover:opacity-70 transition-opacity" style={{ color: 'var(--text-secondary)' }}>
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-5">
        {/* Resource Info */}
        <div>
          <p className="text-xs font-medium uppercase tracking-wide mb-1" style={{ color: 'var(--text-secondary)' }}>Name</p>
          <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{node.resourceName || 'N/A'}</p>
        </div>
        <div>
          <p className="text-xs font-medium uppercase tracking-wide mb-1" style={{ color: 'var(--text-secondary)' }}>Type</p>
          <p className="text-sm" style={{ color: 'var(--text-primary)' }}>{node.resourceType || 'N/A'}</p>
        </div>
        <div>
          <p className="text-xs font-medium uppercase tracking-wide mb-1" style={{ color: 'var(--text-secondary)' }}>ARN / UID</p>
          <p className="text-xs font-mono break-all" style={{ color: 'var(--text-secondary)' }}>{node.uid || 'N/A'}</p>
        </div>

        {/* Risk Score */}
        <div>
          <div className="flex items-center justify-between mb-1">
            <p className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>Risk Score</p>
            <span className="text-sm font-bold" style={{ color: riskColor }}>{riskScore}</span>
          </div>
          <div className="w-full h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            <div className="h-full rounded-full transition-all duration-500" style={{ width: `${riskScore}%`, backgroundColor: riskColor }} />
          </div>
        </div>

        {/* Counts */}
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-lg p-3 border" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
            <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>Threats</p>
            <p className="text-lg font-bold text-red-400">{node.threats ?? 0}</p>
          </div>
          <div className="rounded-lg p-3 border" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
            <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>Findings</p>
            <p className="text-lg font-bold text-orange-400">{node.findingCount ?? 0}</p>
          </div>
        </div>

        {/* Hop distance */}
        <div>
          <p className="text-xs font-medium uppercase tracking-wide mb-1" style={{ color: 'var(--text-secondary)' }}>Hop Distance</p>
          <p className="text-sm" style={{ color: 'var(--text-primary)' }}>{node.hops ?? 0} hops from source</p>
        </div>

        {/* Connected resources */}
        {connected.length > 0 && (
          <div>
            <p className="text-xs font-medium uppercase tracking-wide mb-2" style={{ color: 'var(--text-secondary)' }}>
              Connected Resources ({connected.length})
            </p>
            <div className="space-y-1.5 max-h-40 overflow-y-auto">
              {connected.slice(0, 10).map((n) => (
                <div key={n.uid} className="flex items-center gap-2 text-xs px-2 py-1.5 rounded" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                  <span
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ backgroundColor: n.isSource ? '#3b82f6' : (n.threats || 0) > 0 ? '#ef4444' : (n.findingCount || 0) > 0 ? '#f97316' : '#22c55e' }}
                  />
                  <span className="truncate" style={{ color: 'var(--text-primary)' }}>{n.resourceName || n.resourceType}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="pt-2 space-y-2 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <a
            href={`/inventory?resource_uid=${encodeURIComponent(node.uid || '')}`}
            className="w-full flex items-center justify-center gap-2 py-2 px-4 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white transition-colors"
          >
            View in Inventory
            <ArrowRight className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Depth Distribution BarChart (Recharts)
// ---------------------------------------------------------------------------
function DepthDistributionChart({ distribution }) {
  const chartData = useMemo(() => {
    if (!distribution) return [];
    return Object.entries(distribution)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([depth, count]) => ({ depth: `Depth ${depth}`, count: Number(count) }));
  }, [distribution]);

  if (!chartData.length) return null;

  const barColors = ['#3b82f6', '#6366f1', '#8b5cf6', '#a855f7', '#c084fc', '#d8b4fe'];

  return (
    <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Depth Distribution</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
          <XAxis dataKey="depth" tick={{ fill: '#a3a3a3', fontSize: 12 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#a3a3a3', fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} />
          <RechartsTooltip
            contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, color: '#f5f5f5' }}
            cursor={{ fill: 'rgba(255,255,255,0.04)' }}
          />
          <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={48}>
            {chartData.map((_, idx) => (
              <Cell key={idx} fill={barColors[idx % barColors.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Internet-Exposed Table Columns
// ---------------------------------------------------------------------------
const internetExposedColumns = [
  {
    accessorKey: 'uid',
    header: 'Resource',
    cell: ({ getValue }) => {
      const uid = getValue();
      const name = uid ? uid.split(':').pop() || uid.split('/').pop() || uid : 'N/A';
      return (
        <span className="font-mono text-xs truncate block max-w-[200px]" title={uid} style={{ color: 'var(--text-primary)' }}>
          {name}
        </span>
      );
    },
  },
  {
    accessorKey: 'resourceType',
    header: 'Type',
    cell: ({ getValue }) => {
      const t = getValue() || '';
      const short = t.includes('.') ? t.split('.').pop() : t;
      return (
        <span className="px-2 py-0.5 rounded text-xs" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
          {short}
        </span>
      );
    },
  },
  {
    accessorKey: 'region',
    header: 'Region',
    cell: ({ getValue }) => <span style={{ color: 'var(--text-secondary)' }}>{getValue() || '-'}</span>,
  },
  {
    accessorKey: 'riskScore',
    header: 'Risk',
    cell: ({ getValue }) => {
      const score = Number(getValue()) || 0;
      const color = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e';
      return (
        <div className="flex items-center gap-2">
          <div className="w-14 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: color }} />
          </div>
          <span className="text-xs font-semibold" style={{ color }}>{score}</span>
        </div>
      );
    },
  },
  {
    accessorKey: 'threats',
    header: 'Threats',
    cell: ({ getValue }) => {
      const v = Number(getValue()) || 0;
      return v > 0 ? (
        <span className="flex items-center gap-1 text-red-400 font-semibold text-xs">
          <AlertTriangle className="w-3.5 h-3.5" />
          {v}
        </span>
      ) : (
        <span style={{ color: 'var(--text-secondary)' }}>&mdash;</span>
      );
    },
  },
  {
    accessorKey: 'findings',
    header: 'Findings',
    cell: ({ getValue }) => <span className="font-semibold text-xs" style={{ color: 'var(--text-primary)' }}>{getValue() ?? 0}</span>,
  },
];

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------
export default function BlastRadiusPage() {
  const searchParams = useSearchParams();
  const initialResourceUid = searchParams.get('resource_uid') || '';

  const [searchInput, setSearchInput] = useState(initialResourceUid);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [pageData, setPageData] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  // ---- Data Fetching ----

  const loadData = useCallback(async (resourceUid) => {
    try {
      setLoading(true);
      setError(null);
      setSelectedNode(null);

      const params = {};
      if (resourceUid) params.resource_uid = resourceUid;

      const data = await fetchView('threats/blast-radius', params);

      if (data?.error) {
        setError(data.error);
        setPageData(null);
      } else {
        setPageData(data);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load blast radius data.');
      setPageData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadData(initialResourceUid || undefined);
  }, [loadData, initialResourceUid]);

  // Search handler
  const handleSearch = useCallback(
    (e) => {
      if (e) e.preventDefault();
      if (searchInput.trim()) {
        loadData(searchInput.trim());
      } else {
        loadData(undefined);
      }
    },
    [searchInput, loadData],
  );

  // ---- Derive graph data structures from BFF response ----

  const { graphNodes, graphEdges, kpi, blastRadius, internetExposed } = useMemo(() => {
    if (!pageData) {
      return { graphNodes: [], graphEdges: [], kpi: null, blastRadius: null, internetExposed: [] };
    }

    const kpi = pageData.kpi || null;
    const blast = pageData.blastRadius || null;
    const exposed = pageData.internetExposed || [];

    if (!blast || !blast.sourceResource) {
      return { graphNodes: [], graphEdges: [], kpi, blastRadius: blast, internetExposed: exposed };
    }

    // Build nodes: source + reachable
    const src = blast.sourceResource;
    const reachable = blast.reachableResources || [];

    const nodes = [
      {
        id: 0,
        uid: src.uid,
        resourceType: src.resourceType,
        resourceName: src.resourceName || (src.uid ? src.uid.split(':').pop() : 'Source'),
        riskScore: src.riskScore ?? 0,
        hops: 0,
        threats: 0,
        findingCount: 0,
        isSource: true,
      },
      ...reachable.map((r, i) => ({
        id: i + 1,
        uid: r.uid,
        resourceType: r.resourceType || '',
        resourceName: r.resourceName || (r.uid ? r.uid.split(':').pop() : `Resource ${i + 1}`),
        riskScore: r.riskScore ?? 0,
        hops: r.hops ?? 1,
        threats: r.threats ?? 0,
        findingCount: r.findingCount ?? 0,
        region: r.region || '',
        isSource: false,
      })),
    ];

    // Build edges: source -> hop 1, hop N -> hop N+1 (deterministic, not random)
    const edgesArr = [];
    const uidToIdx = new Map(nodes.map((n, i) => [n.uid, i]));

    // Connect source to every hop-1 node
    nodes.forEach((n, i) => {
      if (n.hops === 1) {
        edgesArr.push({ source: 0, target: i });
      }
    });

    // Connect hop N to hop N+1 (pair by order)
    const byHop = {};
    nodes.forEach((n, i) => {
      if (i === 0) return;
      const h = n.hops || 1;
      if (!byHop[h]) byHop[h] = [];
      byHop[h].push(i);
    });

    const hopLevels = Object.keys(byHop).map(Number).sort((a, b) => a - b);
    for (let hi = 0; hi < hopLevels.length - 1; hi++) {
      const currentLevel = byHop[hopLevels[hi]];
      const nextLevel = byHop[hopLevels[hi + 1]];
      if (!currentLevel || !nextLevel) continue;
      // Distribute next-level nodes across current-level nodes
      nextLevel.forEach((targetIdx, j) => {
        const sourceIdx = currentLevel[j % currentLevel.length];
        edgesArr.push({ source: sourceIdx, target: targetIdx });
      });
    }

    return { graphNodes: nodes, graphEdges: edgesArr, kpi, blastRadius: blast, internetExposed: exposed };
  }, [pageData]);

  // ---- Render ----

  const kpiCards = useMemo(() => {
    const k = kpi || {};
    return [
      { title: 'Total Nodes', value: k.totalNodes ?? 0, icon: <Network className="w-5 h-5" />, color: 'blue', subtitle: 'Resources in graph' },
      { title: 'Internet Exposed', value: k.internetExposed ?? 0, icon: <Globe className="w-5 h-5" />, color: 'red', subtitle: 'Publicly accessible' },
      { title: 'High Risk', value: k.resourcesWithThreats ?? 0, icon: <AlertTriangle className="w-5 h-5" />, color: 'orange', subtitle: 'Active threats detected' },
      { title: 'Edges', value: graphEdges.length, icon: <Zap className="w-5 h-5" />, color: 'purple', subtitle: 'Resource relationships' },
    ];
  }, [kpi, graphEdges.length]);

  // Depth distribution chart data
  const depthDistribution = blastRadius?.depthDistribution || null;

  return (
    <div className="min-h-screen p-6 lg:p-8" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="max-w-[1600px] mx-auto space-y-6">
        {/* Header + Breadcrumb */}
        <div>
          <div className="flex items-center gap-2 text-xs mb-2" style={{ color: 'var(--text-secondary)' }}>
            <a href="/threats" className="hover:underline">Threats</a>
            <ChevronRight className="w-3 h-3" />
            <span style={{ color: 'var(--text-primary)' }}>Blast Radius</span>
          </div>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Blast Radius</h1>
              <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
                Visualize downstream impact from a compromised resource.
              </p>
            </div>
            <form onSubmit={handleSearch} className="flex gap-2 w-full sm:w-auto">
              <SearchBar
                value={searchInput}
                onChange={setSearchInput}
                placeholder="Enter resource ARN or UID..."
                style={{ minWidth: 280, flex: 1 }}
              />
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-2 rounded-lg text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 transition-colors flex items-center gap-1.5 flex-shrink-0"
              >
                <Search className="w-4 h-4" />
                Analyze
              </button>
            </form>
          </div>
        </div>

        {/* Threats Sub-Navigation */}
        <ThreatsSubNav />

        {/* Error banner */}
        {error && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg border border-red-500/30 bg-red-500/10">
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* Loading state */}
        {loading && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="h-28 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
              ))}
            </div>
            <LoadingSkeleton rows={6} cols={3} />
          </div>
        )}

        {/* Empty state */}
        {!loading && !error && !pageData && (
          <EmptyState
            icon={<Network className="w-12 h-12" />}
            title="No Blast Radius Data"
            description="Enter a resource ARN or UID above to analyze its blast radius, or wait for the BFF view to return summary data."
          />
        )}

        {/* Main content */}
        {!loading && pageData && (
          <>
            {/* KPI Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {kpiCards.map((card) => (
                <KpiCard
                  key={card.title}
                  title={card.title}
                  value={card.value}
                  subtitle={card.subtitle}
                  icon={card.icon}
                  color={card.color}
                />
              ))}
            </div>

            {/* Two-column layout: Graph + Detail */}
            {graphNodes.length > 0 ? (
              <div className="grid grid-cols-1 lg:grid-cols-[1fr_340px] gap-6">
                {/* Left: Force Graph */}
                <div>
                  <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
                    {blastRadius?.sourceResource?.resourceName
                      ? `Blast Radius: ${blastRadius.sourceResource.resourceName}`
                      : 'Blast Radius Graph'}
                    <span className="ml-2 text-xs font-normal" style={{ color: 'var(--text-secondary)' }}>
                      ({graphNodes.length} nodes, {graphEdges.length} edges)
                    </span>
                  </h2>
                  <ForceGraph
                    nodes={graphNodes}
                    edges={graphEdges}
                    selectedId={selectedNode?.uid}
                    onNodeClick={setSelectedNode}
                  />
                </div>

                {/* Right: Detail Panel */}
                <div className="lg:sticky lg:top-6 self-start">
                  {selectedNode ? (
                    <DetailPanel
                      node={selectedNode}
                      allNodes={graphNodes}
                      onClose={() => setSelectedNode(null)}
                    />
                  ) : (
                    <div
                      className="rounded-xl border p-8 flex flex-col items-center justify-center text-center"
                      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)', minHeight: 300 }}
                    >
                      <Shield className="w-10 h-10 mb-3" style={{ color: 'var(--text-secondary)' }} />
                      <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
                        Click a node in the graph to view details
                      </p>
                      <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
                        Resource type, risk score, threats, and connected resources will appear here.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <EmptyState
                icon={<Network className="w-12 h-12" />}
                title="No Graph Data"
                description="The blast radius response did not include graph nodes. Try searching for a specific resource ARN."
              />
            )}

            {/* Below graph: Depth distribution + Internet exposed table */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Depth Distribution Chart */}
              {depthDistribution && Object.keys(depthDistribution).length > 0 && (
                <DepthDistributionChart distribution={depthDistribution} />
              )}

              {/* Blast Radius Summary card */}
              {blastRadius && (
                <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                  <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Blast Radius Summary</h3>
                  <div className="space-y-4">
                    {[
                      { label: 'Total Reachable', value: blastRadius.reachableCount ?? 0, color: '#3b82f6' },
                      { label: 'Resources with Threats', value: blastRadius.resourcesWithThreats ?? 0, color: '#ef4444' },
                      {
                        label: 'Max Hop Distance',
                        value: depthDistribution
                          ? Math.max(...Object.keys(depthDistribution).map(Number), 0)
                          : 0,
                        color: '#f97316',
                      },
                      { label: 'Average Blast Radius', value: kpi?.avgBlastRadius != null ? Number(kpi.avgBlastRadius).toFixed(1) : '0', color: '#8b5cf6' },
                    ].map((item) => (
                      <div key={item.label} className="flex items-center justify-between">
                        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                        <span className="text-xl font-bold" style={{ color: item.color }}>{item.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Internet Exposed Table */}
            {internetExposed && internetExposed.length > 0 && (
              <div>
                <h2 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
                  <Globe className="w-4 h-4 text-red-400" />
                  Internet-Exposed Resources
                  <span className="text-xs font-normal px-2 py-0.5 rounded-full bg-red-500/15 text-red-400">
                    {internetExposed.length}
                  </span>
                </h2>
                <DataTable
                  data={internetExposed}
                  columns={internetExposedColumns}
                  pageSize={10}
                  emptyMessage="No internet-exposed resources found."
                />
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
