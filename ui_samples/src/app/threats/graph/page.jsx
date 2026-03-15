'use client';

import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { getFromEngine } from '@/lib/api';
import dynamic from 'next/dynamic';
import {
  Network,
  AlertTriangle,
  Info,
  RefreshCw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Minimize2,
  X,
  Shield,
  Server,
  Database,
  Search,
} from 'lucide-react';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { getServiceColor } from '@/components/shared/CloudServiceIcon';

// Dynamically import ForceGraph2D (requires window/canvas — SSR-safe)
const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false });

// ── Node type colors — sourced from CloudServiceIcon brand palette ─────────────
const NODE_COLORS = {
  S3Bucket:      getServiceColor('S3Bucket'),
  IAMRole:       getServiceColor('IAMRole'),
  EC2Instance:   getServiceColor('EC2Instance'),
  SecurityGroup: getServiceColor('SecurityGroup'),
  Lambda:        getServiceColor('Lambda'),
  RDS:           getServiceColor('RDS'),
  VPC:           getServiceColor('VPC'),
  Subnet:        getServiceColor('Subnet'),
  NATGateway:    getServiceColor('NATGateway'),
  VPCEndpoint:   getServiceColor('VPCEndpoint'),
  KMSKey:        getServiceColor('KMSKey'),
  SNSTopic:      getServiceColor('SNSTopic'),
  SQSQueue:      getServiceColor('SQSQueue'),
  DynamoDBTable: getServiceColor('DynamoDBTable'),
  CloudFront:    getServiceColor('CloudFront'),
  ElastiCache:   getServiceColor('ElastiCache'),
  default:       '#95B8D1',
};

// ── Node type abbreviations (shown inside circle) ─────────────────────────────
const NODE_ABBR = {
  S3Bucket:      'S3',
  IAMRole:       'IAM',
  EC2Instance:   'EC2',
  SecurityGroup: 'SG',
  Lambda:        'λ',
  RDS:           'RDS',
  VPC:           'VPC',
  Subnet:        'SUB',
  NATGateway:    'NAT',
  VPCEndpoint:   'VPE',
  KMSKey:        'KMS',
  SNSTopic:      'SNS',
  SQSQueue:      'SQS',
  DynamoDBTable: 'DDB',
  CloudFront:    'CF',
  ElastiCache:   'EC',
  default:       '?',
};

// ── Relationship colors (kept from original) ──────────────────────────────────
const RELATIONSHIP_COLORS = {
  HAS_THREAT:     '#FF4444',
  HAS_FINDING:    '#FF8800',
  REFERENCES:     '#4488FF',
  CONTAINS:       '#44FF44',
  EXPOSES:        '#FF44FF',
  ROUTES_TO:      '#FFFF44',
  ALLOWS_TRAFFIC: '#FF9999',
};


// ── Main page component ───────────────────────────────────────────────────────
export default function SecurityGraphExplorer() {
  const graphRef       = useRef(null);
  const containerRef   = useRef(null);
  const [graphWidth,   setGraphWidth]   = useState(800);
  const [graphHeight,  setGraphHeight]  = useState(480);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [searchQuery,  setSearchQuery]  = useState('');
  const [highlightNodes, setHighlightNodes] = useState(new Set());
  const [highlightLinks, setHighlightLinks] = useState(new Set());
  const [rebuilding,     setRebuilding]     = useState(false);
  const [rebuildProgress, setRebuildProgress] = useState(0);
  const [showRebuildConfirm, setShowRebuildConfirm] = useState(false);
  const [isClient, setIsClient] = useState(false);
  const [nodes, setNodes] = useState([]);
  const [links, setLinks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Layer visibility toggles
  const [visibleLinkTypes, setVisibleLinkTypes] = useState(new Set(Object.keys(RELATIONSHIP_COLORS)));
  const [visibleNodeTypes, setVisibleNodeTypes] = useState(new Set(Object.keys(NODE_COLORS)));

  useEffect(() => { setIsClient(true); }, []);

  // Fetch graph data from inventory engine
  useEffect(() => {
    const fetchGraph = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await getFromEngine('inventory', '/api/v1/inventory/runs/latest/graph');
        if (data && !data.error) {
          setNodes(Array.isArray(data.nodes) ? data.nodes : []);
          setLinks(Array.isArray(data.links || data.edges || data.relationships) ? (data.links || data.edges || data.relationships) : []);
        } else {
          setError('Failed to load security graph data.');
        }
      } catch (err) {
        console.warn('Graph fetch failed:', err);
        setError('Failed to load security graph data.');
      } finally {
        setLoading(false);
      }
    };
    fetchGraph();
  }, []);

  // Measure container width
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(entries => {
      const w = entries[0].contentRect.width;
      setGraphWidth(Math.max(400, w));
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // Full-screen graph height
  useEffect(() => {
    setGraphHeight(isFullscreen ? window.innerHeight - 120 : 480);
  }, [isFullscreen]);

  // Filtered graph data via useMemo
  const filteredGraphData = useMemo(() => ({
    nodes: nodes.filter(n => visibleNodeTypes.has(n.type)),
    links: links.filter(l =>
      visibleLinkTypes.has(l.type) &&
      visibleNodeTypes.has(nodes.find(n => n.id === l.source || n.id === (l.source?.id))?.type || 'default') &&
      visibleNodeTypes.has(nodes.find(n => n.id === l.target || n.id === (l.target?.id))?.type || 'default')
    ),
  }), [nodes, links, visibleLinkTypes, visibleNodeTypes]);

  // Node canvas rendering (enhanced: type abbr inside, backdrop label, rim glow)
  const drawNode = useCallback((node, ctx, globalScale) => {
    // Guard: skip if position not yet assigned by force simulation
    if (node.x == null || node.y == null || !isFinite(node.x) || !isFinite(node.y)) return;

    const score        = node.risk_score || 0;
    const radius       = 8 + (score / 100) * 8; // 8–16px
    const color        = NODE_COLORS[node.type] || NODE_COLORS.default;
    const abbr         = NODE_ABBR[node.type]   || NODE_ABBR.default;
    const isSelected   = selectedNode?.id === node.id;
    const isHighlighted = highlightNodes.size > 0 && highlightNodes.has(node.id);
    const isDimmed     = highlightNodes.size > 0 && !highlightNodes.has(node.id) && !isSelected;

    ctx.save();
    ctx.globalAlpha = isDimmed ? 0.22 : 1;

    // ── Outer glow for threat nodes ─────────────────────────────────────
    if (node.has_threat) {
      const glowRadius = radius + 7;
      const grd = ctx.createRadialGradient(node.x, node.y, radius, node.x, node.y, glowRadius);
      grd.addColorStop(0, isDimmed ? 'rgba(255,68,68,0.15)' : 'rgba(255,68,68,0.45)');
      grd.addColorStop(1, 'rgba(255,68,68,0)');
      ctx.beginPath();
      ctx.arc(node.x, node.y, glowRadius, 0, 2 * Math.PI);
      ctx.fillStyle = grd;
      ctx.fill();

      // Solid threat ring
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius + 4, 0, 2 * Math.PI);
      ctx.strokeStyle = isDimmed ? 'rgba(255,68,68,0.2)' : '#FF4444';
      ctx.lineWidth   = 1.5 / globalScale;
      ctx.stroke();
    }

    // ── Attack path / selection ring ────────────────────────────────────
    if (isHighlighted || isSelected) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius + (isSelected ? 5 : 3.5), 0, 2 * Math.PI);
      ctx.strokeStyle = isSelected ? '#FFD700' : '#FF8800';
      ctx.lineWidth   = 2.5 / globalScale;
      ctx.stroke();
    }

    // ── Main circle fill ────────────────────────────────────────────────
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
    // Radial gradient: lighter center, darker edge for depth
    const fillGrd = ctx.createRadialGradient(node.x - radius * 0.3, node.y - radius * 0.3, 0, node.x, node.y, radius);
    fillGrd.addColorStop(0, color + 'FF');
    fillGrd.addColorStop(1, color + 'BB');
    ctx.fillStyle = fillGrd;
    ctx.fill();

    // ── Rim highlight ───────────────────────────────────────────────────
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
    ctx.strokeStyle = 'rgba(255,255,255,0.35)';
    ctx.lineWidth   = 1.2 / globalScale;
    ctx.stroke();

    // ── Type abbreviation inside circle ─────────────────────────────────
    const abbrSize = Math.max(6, Math.min(radius * 0.65, 11 / globalScale));
    ctx.font        = `bold ${abbrSize}px sans-serif`;
    ctx.fillStyle   = 'rgba(0,0,0,0.75)';
    ctx.textAlign   = 'center';
    ctx.textBaseline = 'middle';
    // Shadow
    ctx.shadowColor  = 'rgba(0,0,0,0.6)';
    ctx.shadowBlur   = 2;
    ctx.fillText(abbr, node.x, node.y);
    ctx.shadowBlur = 0;

    // ── Label below node with opaque backdrop ────────────────────────────
    const label     = (node.label || node.id).substring(0, 18);
    const labelSize = Math.max(8, 10 / globalScale);
    ctx.font        = `${labelSize}px sans-serif`;
    ctx.textAlign   = 'center';
    ctx.textBaseline = 'top';

    const tw = ctx.measureText(label).width;
    const th = labelSize + 2;
    const lx = node.x - tw / 2 - 4;
    const ly = node.y + radius + 3;

    // Backdrop rectangle
    ctx.fillStyle = 'rgba(0,0,0,0.72)';
    ctx.beginPath();
    // Rounded rect via arc corners
    const bw = tw + 8;
    const bh = th + 3;
    const br = 3;
    ctx.moveTo(lx + br, ly);
    ctx.lineTo(lx + bw - br, ly);
    ctx.arcTo(lx + bw, ly, lx + bw, ly + br, br);
    ctx.lineTo(lx + bw, ly + bh - br);
    ctx.arcTo(lx + bw, ly + bh, lx + bw - br, ly + bh, br);
    ctx.lineTo(lx + br, ly + bh);
    ctx.arcTo(lx, ly + bh, lx, ly + bh - br, br);
    ctx.lineTo(lx, ly + br);
    ctx.arcTo(lx, ly, lx + br, ly, br);
    ctx.closePath();
    ctx.fill();

    // Label text
    ctx.fillStyle = '#ffffffee';
    ctx.fillText(label, node.x, ly + 1.5);

    ctx.restore();
  }, [selectedNode, highlightNodes]);

  // BFS attack path highlighting
  const computeAttackPath = useCallback((startNodeId) => {
    const hnodes = new Set([startNodeId]);
    const hlinks = new Set();
    const queue  = [startNodeId];
    const visited = new Set([startNodeId]);

    while (queue.length > 0) {
      const curr = queue.shift();
      links.forEach((link, idx) => {
        const src = typeof link.source === 'object' ? link.source.id : link.source;
        const tgt = typeof link.target === 'object' ? link.target.id : link.target;
        if (src === curr && link.type === 'HAS_THREAT' && !visited.has(tgt)) {
          hnodes.add(tgt);
          hlinks.add(idx);
          queue.push(tgt);
          visited.add(tgt);
        }
      });
    }
    return { hnodes, hlinks };
  }, [links]);

  const handleNodeClick = useCallback((node) => {
    if (selectedNode?.id === node.id) {
      // Deselect
      setSelectedNode(null);
      setHighlightNodes(new Set());
      setHighlightLinks(new Set());
    } else {
      setSelectedNode(node);
      if (node.has_threat) {
        const { hnodes, hlinks } = computeAttackPath(node.id);
        setHighlightNodes(hnodes);
        setHighlightLinks(hlinks);
      } else {
        setHighlightNodes(new Set([node.id]));
        setHighlightLinks(new Set());
      }
    }
  }, [selectedNode, computeAttackPath]);

  const handleBackgroundClick = useCallback(() => {
    setSelectedNode(null);
    setHighlightNodes(new Set());
    setHighlightLinks(new Set());
  }, []);

  const handleZoom = (delta) => {
    if (!graphRef.current) return;
    const currentZoom = graphRef.current.zoom();
    graphRef.current.zoom(Math.max(0.3, Math.min(4, currentZoom + delta)), 400);
  };

  const handleRefresh = () => {
    if (graphRef.current) {
      graphRef.current.d3ReheatSimulation();
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    const found = nodes.find(n =>
      (n.label || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (n.id || '').toLowerCase().includes(searchQuery.toLowerCase())
    );
    if (found && graphRef.current) {
      graphRef.current.centerAt(found.x, found.y, 600);
      graphRef.current.zoom(2, 600);
      handleNodeClick(found);
    }
  };

  const handleRebuild = async () => {
    setRebuilding(true);
    setShowRebuildConfirm(false);
    setRebuildProgress(0);
    try {
      for (let i = 0; i <= 100; i += 10) {
        await new Promise(r => setTimeout(r, 200));
        setRebuildProgress(i);
      }
    } catch (error) {
      console.warn('Rebuild failed:', error);
    } finally {
      setTimeout(() => setRebuilding(false), 500);
    }
  };

  // Link color based on type and highlight state
  const getLinkColor = useCallback((link) => {
    const baseColor = RELATIONSHIP_COLORS[link.type] || '#888888';
    if (highlightLinks.size === 0) return baseColor + 'CC'; // more visible by default
    const idx = links.indexOf(link);
    return highlightLinks.has(idx) ? baseColor : '#2a2a3a';
  }, [highlightLinks, links]);

  const getLinkWidth = useCallback((link) => {
    const idx = links.indexOf(link);
    return highlightLinks.has(idx) ? 2.5 : (link.type === 'HAS_THREAT' ? 2 : 1);
  }, [highlightLinks, links]);

  // Toggle helpers
  const toggleLinkType = (type) => {
    setVisibleLinkTypes(prev => {
      const next = new Set(prev);
      next.has(type) ? next.delete(type) : next.add(type);
      return next;
    });
  };

  const toggleNodeType = (type) => {
    setVisibleNodeTypes(prev => {
      const next = new Set(prev);
      next.has(type) ? next.delete(type) : next.add(type);
      return next;
    });
  };

  // Node findings — derived from node's actual threat data (no mock)
  const nodeFindings = selectedNode?.findings || [];

  return (
    <div className="space-y-4" style={{ backgroundColor: 'var(--bg-primary)' }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--text-primary)' }}>
            <Network size={32} style={{ color: 'var(--accent-primary)' }} />
            Security Graph Explorer
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
            Wiz-style graph-based cloud security visualization — risk-scored nodes, attack path tracing, layer filtering
          </p>
        </div>
        <button
          onClick={() => setShowRebuildConfirm(true)}
          disabled={rebuilding}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-white text-sm font-medium transition-colors disabled:opacity-50"
          style={{ backgroundColor: 'var(--accent-primary)' }}
        >
          <RefreshCw className={`w-4 h-4 ${rebuilding ? 'animate-spin' : ''}`} />
          Rebuild Graph
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Nodes"         value={nodes.length}                                   icon={<Network size={20} />}        color="blue"   subtitle="Cloud resources" />
        <KpiCard title="Relationships"        value={links.length}                                   icon={<Info size={20} />}           color="purple" subtitle="Edges in graph"  />
        <KpiCard title="Threatened Nodes"     value={nodes.filter(n => n.has_threat).length}         icon={<AlertTriangle size={20} />}  color="red"    subtitle="Active threats"  />
        <KpiCard title="High Risk (≥75)"      value={nodes.filter(n => n.risk_score >= 75).length}   icon={<Shield size={20} />}         color="orange" subtitle="Need attention"  />
      </div>

      {/* Error state */}
      {error && nodes.length === 0 && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: '#ef4444' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && nodes.length === 0 && (
        <div className="rounded-lg p-8 border text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <Network className="mx-auto mb-3 w-10 h-10" style={{ color: 'var(--text-muted)' }} />
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No graph data available. Run an inventory scan to build the security graph.</p>
        </div>
      )}

      {rebuilding && (
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Rebuilding security graph…</span>
            <span className="text-sm font-medium" style={{ color: 'var(--accent-primary)' }}>{rebuildProgress}%</span>
          </div>
          <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
            <div className="h-full rounded-full transition-all" style={{ width: `${rebuildProgress}%`, backgroundColor: 'var(--accent-primary)' }} />
          </div>
        </div>
      )}

      {/* Search bar */}
      <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <form onSubmit={handleSearch} className="flex gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search by resource name or ID (e.g., prod-data-bucket)…"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>
          <button type="submit" className="px-4 py-2 rounded-lg text-white text-sm font-medium" style={{ backgroundColor: 'var(--accent-primary)' }}>
            Search
          </button>
        </form>
      </div>

      {/* Layer Filter Toolbar */}
      <div className="rounded-xl p-4 border space-y-3" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>Relationship Types</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(RELATIONSHIP_COLORS).map(([type, color]) => (
              <button
                key={type}
                onClick={() => toggleLinkType(type)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border transition-all"
                style={{
                  backgroundColor: visibleLinkTypes.has(type) ? color + '22' : 'var(--bg-tertiary)',
                  borderColor:     visibleLinkTypes.has(type) ? color : 'var(--border-primary)',
                  color:           visibleLinkTypes.has(type) ? color : 'var(--text-muted)',
                  opacity:         visibleLinkTypes.has(type) ? 1 : 0.6,
                }}
              >
                <span className="inline-block w-2 h-0.5 rounded" style={{ backgroundColor: color }} />
                {type.replace(/_/g, ' ')}
              </button>
            ))}
          </div>
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>Resource Types</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(NODE_COLORS).filter(([k]) => k !== 'default').map(([type, color]) => (
              <button
                key={type}
                onClick={() => toggleNodeType(type)}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border transition-all"
                style={{
                  backgroundColor: visibleNodeTypes.has(type) ? color + '22' : 'var(--bg-tertiary)',
                  borderColor:     visibleNodeTypes.has(type) ? color : 'var(--border-primary)',
                  color:           visibleNodeTypes.has(type) ? color : 'var(--text-muted)',
                  opacity:         visibleNodeTypes.has(type) ? 1 : 0.5,
                }}
              >
                <span className="inline-block w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
                {type}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Graph + Side Panel */}
      <div className={`flex gap-4 ${isFullscreen ? 'fixed inset-0 z-50 p-4 flex-col' : ''}`}
        style={isFullscreen ? { backgroundColor: 'var(--bg-primary)' } : {}}>
        {/* Graph container */}
        <div
          ref={containerRef}
          className="relative rounded-xl border overflow-hidden flex-1"
          style={{ backgroundColor: '#0f1117', borderColor: 'var(--border-primary)', minHeight: `${graphHeight}px` }}
        >
          {/* Floating toolbar */}
          <div className="absolute top-3 right-3 z-10 flex flex-col gap-2">
            <button onClick={() => handleZoom(0.4)} title="Zoom in"
              className="p-2 rounded-lg border shadow hover:opacity-80 transition-opacity"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <ZoomIn className="w-4 h-4" style={{ color: 'var(--text-primary)' }} />
            </button>
            <button onClick={() => handleZoom(-0.4)} title="Zoom out"
              className="p-2 rounded-lg border shadow hover:opacity-80 transition-opacity"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <ZoomOut className="w-4 h-4" style={{ color: 'var(--text-primary)' }} />
            </button>
            <button onClick={handleRefresh} title="Re-run simulation"
              className="p-2 rounded-lg border shadow hover:opacity-80 transition-opacity"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <RefreshCw className="w-4 h-4" style={{ color: 'var(--text-primary)' }} />
            </button>
            <button onClick={() => setIsFullscreen(f => !f)} title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
              className="p-2 rounded-lg border shadow hover:opacity-80 transition-opacity"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              {isFullscreen
                ? <Minimize2 className="w-4 h-4" style={{ color: 'var(--text-primary)' }} />
                : <Maximize2 className="w-4 h-4" style={{ color: 'var(--text-primary)' }} />}
            </button>
          </div>

          {/* Attack path hint */}
          {selectedNode?.has_threat && highlightNodes.size > 1 && (
            <div className="absolute top-3 left-3 z-10 text-xs px-3 py-1.5 rounded-lg border"
              style={{ backgroundColor: 'rgba(239,68,68,0.15)', borderColor: '#ef4444', color: '#ef4444' }}>
              ⚡ Attack path: {highlightNodes.size} nodes traced
            </div>
          )}

          {/* Hint text */}
          <div className="absolute bottom-3 left-3 z-10 text-xs" style={{ color: '#ffffff60' }}>
            Click node to select · Threatened nodes show attack path · Drag to reposition
          </div>

          {/* ForceGraph2D */}
          {isClient && (
            <ForceGraph2D
              ref={graphRef}
              graphData={filteredGraphData}
              width={graphWidth - (selectedNode ? 340 : 0)}
              height={graphHeight}
              backgroundColor="#0d1117"
              nodeCanvasObject={drawNode}
              nodeCanvasObjectMode={() => 'replace'}
              linkColor={getLinkColor}
              linkWidth={getLinkWidth}
              linkDirectionalArrowLength={6}
              linkDirectionalArrowRelPos={0.95}
              linkDirectionalArrowColor={link => RELATIONSHIP_COLORS[link.type] || '#888888'}
              linkCurvature={0.1}
              onNodeClick={handleNodeClick}
              onBackgroundClick={handleBackgroundClick}
              enableNodeDrag={true}
              cooldownTicks={140}
              d3AlphaDecay={0.015}
              d3VelocityDecay={0.35}
              nodeLabel={node => `${node.type}: ${node.label} (risk: ${node.risk_score})`}
            />
          )}
        </div>

        {/* Node Detail Side Panel */}
        {selectedNode && (
          <div
            className="rounded-xl border overflow-y-auto flex-shrink-0"
            style={{ width: '320px', backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            {/* Panel header */}
            <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Resource Detail</h3>
              <button onClick={() => { setSelectedNode(null); setHighlightNodes(new Set()); setHighlightLinks(new Set()); }}
                className="hover:opacity-75 transition-opacity" style={{ color: 'var(--text-muted)' }}>
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 space-y-4">
              {/* Resource type badge */}
              <div className="flex items-center gap-2">
                <span
                  className="inline-block w-3 h-3 rounded-full flex-shrink-0"
                  style={{ backgroundColor: NODE_COLORS[selectedNode.type] || NODE_COLORS.default }}
                />
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                  {selectedNode.type}
                </span>
                {selectedNode.has_threat && (
                  <span className="ml-auto text-xs px-2 py-0.5 rounded-full font-semibold" style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#ef4444' }}>
                    Threatened
                  </span>
                )}
              </div>

              {/* Resource name */}
              <div>
                <p className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>{selectedNode.label}</p>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{selectedNode.id}</p>
              </div>

              {/* Risk score gauge */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>Risk Score</span>
                  <span className="text-lg font-bold" style={{ color: selectedNode.risk_score >= 75 ? '#ef4444' : selectedNode.risk_score >= 50 ? '#f97316' : '#22c55e' }}>
                    {selectedNode.risk_score}
                  </span>
                </div>
                <div className="w-full h-2 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                  <div className="h-full rounded-full transition-all"
                    style={{
                      width: `${selectedNode.risk_score}%`,
                      backgroundColor: selectedNode.risk_score >= 75 ? '#ef4444' : selectedNode.risk_score >= 50 ? '#f97316' : '#22c55e',
                    }}
                  />
                </div>
              </div>

              {/* Meta tags */}
              <div className="flex flex-wrap gap-1.5">
                {[
                  { label: 'Provider', value: selectedNode.provider },
                  { label: 'Account',  value: selectedNode.account  },
                  { label: 'Region',   value: selectedNode.region   },
                ].map(({ label, value }) => (
                  <div key={label} className="text-xs px-2 py-0.5 rounded border" style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)', backgroundColor: 'var(--bg-secondary)' }}>
                    <span style={{ color: 'var(--text-muted)' }}>{label}: </span>{value}
                  </div>
                ))}
              </div>

              {/* Connections count */}
              <div className="rounded-lg p-3 border" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                <p className="text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>CONNECTIONS</p>
                <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {links.filter(l => {
                    const src = typeof l.source === 'object' ? l.source.id : l.source;
                    const tgt = typeof l.target === 'object' ? l.target.id : l.target;
                    return src === selectedNode.id || tgt === selectedNode.id;
                  }).length} relationships
                </p>
              </div>

              {/* Findings */}
              {nodeFindings.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>FINDINGS</p>
                  <div className="space-y-2">
                    {nodeFindings.map(f => (
                      <div key={f.id} className="rounded-lg p-2.5 border" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                        <div className="flex items-center justify-between mb-0.5">
                          <code className="text-xs" style={{ color: 'var(--text-muted)' }}>{f.id}</code>
                          <SeverityBadge severity={f.severity} />
                        </div>
                        <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{f.title}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Quick actions */}
              <div className="flex flex-col gap-2 pt-2 border-t" style={{ borderColor: 'var(--border-primary)' }}>
                <a href="/misconfig" className="text-xs text-center py-2 rounded-lg border hover:opacity-75 transition-opacity"
                  style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
                  View in Misconfigurations →
                </a>
                <a href="/threats" className="text-xs text-center py-2 rounded-lg text-white"
                  style={{ backgroundColor: 'rgba(239,68,68,0.8)' }}>
                  View in Threats →
                </a>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Graph Legend */}
      <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Graph Legend</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
          {Object.entries(NODE_COLORS).filter(([k]) => k !== 'default').map(([type, color]) => (
            <div key={type} className="flex items-center gap-2">
              <div className="w-5 h-5 rounded-full flex-shrink-0 border-2 border-white/20" style={{ backgroundColor: color }} />
              <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{type}</span>
            </div>
          ))}
        </div>
        <div className="border-t pt-4" style={{ borderColor: 'var(--border-primary)' }}>
          <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>Relationship Types</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(RELATIONSHIP_COLORS).map(([type, color]) => (
              <div key={type} className="flex items-center gap-2">
                <div className="w-6 h-0.5 rounded flex-shrink-0" style={{ backgroundColor: color }} />
                <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{type.replace(/_/g, ' ')}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="border-t pt-4 mt-4 flex flex-wrap gap-6 text-xs" style={{ borderColor: 'var(--border-primary)', color: 'var(--text-muted)' }}>
          <span>⬤ Node size = risk score (higher = larger)</span>
          <span>🔴 Red ring = active threat</span>
          <span>🟡 Gold ring = selected node</span>
          <span>🟠 Orange ring = attack path</span>
        </div>
      </div>

      {/* Rebuild Confirmation Modal */}
      {showRebuildConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="rounded-xl border p-8 max-w-md w-full shadow-2xl"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
            <h3 className="text-xl font-bold mb-3" style={{ color: 'var(--text-primary)' }}>Rebuild Security Graph?</h3>
            <p className="text-sm mb-6" style={{ color: 'var(--text-secondary)' }}>
              This will re-scan all cloud resources and rebuild the knowledge graph. This process may take several minutes.
            </p>
            <div className="flex gap-3">
              <button onClick={() => setShowRebuildConfirm(false)}
                className="flex-1 px-4 py-2 rounded-lg border text-sm font-medium transition-colors"
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
                Cancel
              </button>
              <button onClick={handleRebuild}
                className="flex-1 px-4 py-2 rounded-lg text-white text-sm font-medium transition-colors"
                style={{ backgroundColor: 'var(--accent-primary)' }}>
                Rebuild
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
