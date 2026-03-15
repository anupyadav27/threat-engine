'use client';

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Search, ChevronRight, AlertTriangle, Shield, Zap } from 'lucide-react';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { getFromEngine } from '@/lib/api';


// Force-directed graph simulation
class ForceSimulation {
  constructor(nodes, links, width, height) {
    this.nodes = nodes;
    this.links = links;
    this.width = width;
    this.height = height;
    this.alpha = 1;
    this.alphaDecay = 0.01;
    this.charge = -300;
    this.linkDistance = 80;
    this.centerX = width / 2;
    this.centerY = height / 2;

    // Initialize node positions
    this.nodes.forEach((node, i) => {
      if (!node.x) {
        const angle = (i / this.nodes.length) * Math.PI * 2;
        const radius = 100 + Math.random() * 50;
        node.x = this.centerX + Math.cos(angle) * radius;
        node.y = this.centerY + Math.sin(angle) * radius;
      }
      node.vx = (Math.random() - 0.5) * 2;
      node.vy = (Math.random() - 0.5) * 2;
    });
  }

  tick() {
    // Apply forces
    this.applyChargeForce();
    this.applyLinkForce();
    this.applyCenterForce();
    this.updatePositions();
    this.alpha *= (1 - this.alphaDecay);
  }

  applyChargeForce() {
    for (let i = 0; i < this.nodes.length; i++) {
      for (let j = i + 1; j < this.nodes.length; j++) {
        const a = this.nodes[i];
        const b = this.nodes[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const distance = Math.sqrt(dx * dx + dy * dy) || 0.1;
        const force = (this.charge / (distance * distance)) * this.alpha;
        const fx = (dx / distance) * force;
        const fy = (dy / distance) * force;
        a.vx -= fx;
        a.vy -= fy;
        b.vx += fx;
        b.vy += fy;
      }
    }
  }

  applyLinkForce() {
    this.links.forEach((link) => {
      const a = this.nodes[link.source];
      const b = this.nodes[link.target];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const distance = Math.sqrt(dx * dx + dy * dy) || 0.1;
      const force = ((distance - this.linkDistance) / distance) * 0.1 * this.alpha;
      const fx = dx * force;
      const fy = dy * force;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    });
  }

  applyCenterForce() {
    this.nodes.forEach((node) => {
      const dx = this.centerX - node.x;
      const dy = this.centerY - node.y;
      const distance = Math.sqrt(dx * dx + dy * dy) || 0.1;
      const force = 0.02 * this.alpha;
      node.vx += (dx / distance) * force;
      node.vy += (dy / distance) * force;
    });
  }

  updatePositions() {
    this.nodes.forEach((node) => {
      node.vx *= 0.95;
      node.vy *= 0.95;
      node.x += node.vx;
      node.y += node.vy;

      // Boundary conditions
      if (node.x < 20) node.x = 20;
      if (node.x > this.width - 20) node.x = this.width - 20;
      if (node.y < 20) node.y = 20;
      if (node.y > this.height - 20) node.y = this.height - 20;
    });
  }
}

// SVG Graph Visualization Component
function BlastRadiusGraph({ data, onNodeClick, selectedNodeUid }) {
  const svgRef = useRef(null);
  const simulationRef = useRef(null);
  const animationRef = useRef(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [hoveredNode, setHoveredNode] = useState(null);
  const [tooltip, setTooltip] = useState(null);

  const WIDTH = 1000;
  const HEIGHT = 600;

  const nodes = useMemo(() => {
    const n = [
      {
        id: 0,
        uid: data.source_resource.uid,
        label: data.source_resource.resource_type.split('::')[1],
        type: data.source_resource.resource_type,
        hops: 0,
        threats: [],
        finding_count: 0,
        isSource: true,
      },
      ...data.reachable_resources.map((r, i) => ({
        id: i + 1,
        uid: r.uid,
        label: r.resource_type.split('::')[1],
        type: r.resource_type,
        hops: r.hops,
        threats: r.threats,
        finding_count: r.finding_count,
        isSource: false,
      })),
    ];
    return n;
  }, [data]);

  const links = useMemo(() => {
    return data.reachable_resources
      .map((resource, i) => ({
        source: 0,
        target: i + 1,
        distance: resource.hops,
      }))
      .concat(
        data.reachable_resources.slice(1).flatMap((resource, i) => {
          const connectedIndices = [];
          data.reachable_resources.forEach((other, j) => {
            if (other.hops === resource.hops + 1 && Math.random() > 0.6) {
              connectedIndices.push(j + 1);
            }
          });
          return connectedIndices.map((target) => ({
            source: i + 1,
            target,
            distance: 1,
          }));
        })
      );
  }, [data]);

  useEffect(() => {
    if (!svgRef.current) return;

    simulationRef.current = new ForceSimulation(nodes, links, WIDTH, HEIGHT);

    const animate = () => {
      simulationRef.current.tick();
      if (simulationRef.current.alpha > 0.001) {
        animationRef.current = requestAnimationFrame(animate);
      }
    };

    animationRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationRef.current);
  }, [nodes, links]);

  const handleMouseWheel = useCallback((e) => {
    e.preventDefault();
    const newZoom = zoom * (1 - e.deltaY * 0.001);
    setZoom(Math.max(0.5, Math.min(3, newZoom)));
  }, [zoom]);

  const handleMouseDown = useCallback((e) => {
    if (e.button !== 2) return; // Right-click
    const startX = e.clientX;
    const startY = e.clientY;
    const startPan = { ...pan };

    const handleMouseMove = (moveEvent) => {
      setPan({
        x: startPan.x + (moveEvent.clientX - startX) / zoom,
        y: startPan.y + (moveEvent.clientY - startY) / zoom,
      });
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [pan, zoom]);

  const getNodeColor = (node) => {
    if (node.isSource) return 'rgb(100, 116, 255)';
    if (node.threats.length > 0) return 'rgb(239, 68, 68)';
    if (node.finding_count > 0) return 'rgb(249, 115, 22)';
    return 'rgb(34, 197, 94)';
  };

  const handleNodeHover = (node, e) => {
    if (node.isSource || node.threats.length > 0) {
      setHoveredNode(node.id);
      setTooltip({
        x: e.clientX,
        y: e.clientY,
        content: node,
      });
    }
  };

  if (!nodes.length) return null;

  return (
    <div className="relative w-full bg-gradient-to-br from-[var(--bg-secondary)] to-[var(--bg-card)] rounded-lg border border-[var(--border-primary)] overflow-hidden">
      <svg
        ref={svgRef}
        width={WIDTH}
        height={HEIGHT}
        className="w-full cursor-grab active:cursor-grabbing"
        style={{ background: 'radial-gradient(circle at center, rgba(15,23,42,0.8) 0%, rgba(15,23,42,0.95) 100%)' }}
        onWheel={handleMouseWheel}
        onMouseDown={handleMouseDown}
        onContextMenu={(e) => e.preventDefault()}
      >
        <defs>
          <linearGradient id="grad-threat" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="rgb(239, 68, 68)" />
            <stop offset="100%" stopColor="rgb(220, 38, 38)" />
          </linearGradient>
          <linearGradient id="grad-warning" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="rgb(249, 115, 22)" />
            <stop offset="100%" stopColor="rgb(234, 88, 12)" />
          </linearGradient>
          <linearGradient id="grad-clean" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="rgb(34, 197, 94)" />
            <stop offset="100%" stopColor="rgb(22, 163, 74)" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
          {/* Draw links */}
          {links.map((link, i) => {
            const source = nodes[link.source];
            const target = nodes[link.target];
            return (
              <g key={`link-${i}`}>
                <path
                  d={`M ${source.x} ${source.y} Q ${(source.x + target.x) / 2} ${(source.y + target.y) / 2 - 20} ${target.x} ${target.y}`}
                  stroke="rgba(148, 163, 184, 0.3)"
                  strokeWidth="2"
                  fill="none"
                  strokeDasharray="5,5"
                />
                <text
                  x={(source.x + target.x) / 2}
                  y={(source.y + target.y) / 2 - 25}
                  fontSize="11"
                  fill="rgba(148, 163, 184, 0.6)"
                  textAnchor="middle"
                >
                  {link.distance}h
                </text>
              </g>
            );
          })}

          {/* Draw nodes */}
          {nodes.map((node) => {
            const radius = node.isSource ? 28 : 18 + Math.sqrt(node.finding_count) * 2;
            const isSelected = node.uid === selectedNodeUid;
            const isHovered = hoveredNode === node.id;

            return (
              <g
                key={node.id}
                onMouseEnter={(e) => handleNodeHover(node, e)}
                onMouseLeave={() => {
                  setHoveredNode(null);
                  setTooltip(null);
                }}
                onClick={() => onNodeClick(node)}
                style={{ cursor: 'pointer' }}
                filter={isHovered || isSelected ? 'url(#glow)' : undefined}
              >
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={radius}
                  fill={getNodeColor(node)}
                  opacity={0.85}
                  stroke={isSelected ? 'rgb(147, 197, 253)' : 'rgba(255,255,255,0.2)'}
                  strokeWidth={isSelected ? 3 : 1}
                  style={{
                    transition: 'all 0.2s ease',
                    filter: isHovered ? 'drop-shadow(0 0 8px rgba(100,116,255,0.6))' : 'drop-shadow(0 0 4px rgba(0,0,0,0.3))',
                  }}
                />
                <text
                  x={node.x}
                  y={node.y + 4}
                  fontSize="12"
                  fontWeight="600"
                  fill="white"
                  textAnchor="middle"
                  pointerEvents="none"
                >
                  {node.label}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="absolute bg-[var(--bg-card)] border border-[var(--border-primary)] rounded-lg p-3 text-xs z-50 pointer-events-none max-w-xs"
          style={{
            left: `${tooltip.x + 10}px`,
            top: `${tooltip.y + 10}px`,
          }}
        >
          <div className="font-semibold text-[var(--text-primary)] mb-1">
            {tooltip.content.label}
          </div>
          <div className="text-[var(--text-secondary)] text-xs mb-2">
            {tooltip.content.type}
          </div>
          <div className="flex gap-3">
            <div>Hops: <span className="font-semibold text-[var(--accent-primary)]">{tooltip.content.hops}</span></div>
            <div>Findings: <span className="font-semibold">{tooltip.content.finding_count}</span></div>
            {tooltip.content.threats.length > 0 && (
              <div>Threats: <span className="font-semibold text-[var(--accent-danger)]">{tooltip.content.threats.length}</span></div>
            )}
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-[var(--bg-card)]/80 backdrop-blur-sm border border-[var(--border-primary)] rounded-lg p-3 text-xs">
        <div className="font-semibold text-[var(--text-primary)] mb-2">Legend</div>
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ background: 'rgb(100, 116, 255)' }} />
            <span>Source Resource</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ background: 'rgb(239, 68, 68)' }} />
            <span>With Threats</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ background: 'rgb(249, 115, 22)' }} />
            <span>With Findings</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ background: 'rgb(34, 197, 94)' }} />
            <span>Clean</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// Depth Distribution Chart
function DepthChart({ distribution }) {
  const maxValue = Math.max(...Object.values(distribution));

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border-primary)] rounded-lg p-6">
      <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4">Depth Distribution</h3>
      <div className="flex items-end gap-4 h-40">
        {Object.entries(distribution).map(([depth, count]) => (
          <div key={depth} className="flex-1 flex flex-col items-center">
            <div className="w-full relative h-32 bg-[var(--bg-secondary)] rounded-t-lg overflow-hidden flex items-end">
              <div
                className="w-full bg-gradient-to-t from-[var(--accent-primary)] to-[var(--accent-primary)]/70 transition-all duration-300 hover:opacity-80"
                style={{ height: `${(count / maxValue) * 100}%` }}
              />
            </div>
            <div className="text-xs text-[var(--text-secondary)] mt-2">Hop {depth}</div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">{count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Internet Exposed Resources Table
function InternetExposedTable({ resources }) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border-primary)] rounded-lg p-6 overflow-x-auto">
      <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4">Internet-Exposed Resources</h3>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--border-primary)]">
            <th className="text-left py-3 px-4 text-[var(--text-secondary)] font-medium">Resource</th>
            <th className="text-left py-3 px-4 text-[var(--text-secondary)] font-medium">Type</th>
            <th className="text-left py-3 px-4 text-[var(--text-secondary)] font-medium">Region</th>
            <th className="text-left py-3 px-4 text-[var(--text-secondary)] font-medium">Risk Score</th>
            <th className="text-left py-3 px-4 text-[var(--text-secondary)] font-medium">Threats</th>
            <th className="text-left py-3 px-4 text-[var(--text-secondary)] font-medium">Findings</th>
          </tr>
        </thead>
        <tbody>
          {resources.map((resource) => (
            <tr key={resource.uid} className="border-b border-[var(--border-primary)] hover:bg-[var(--bg-secondary)] transition-colors">
              <td className="py-3 px-4 text-[var(--text-primary)] truncate font-mono text-xs">{resource.uid.split(':').pop()}</td>
              <td className="py-3 px-4">
                <span className="px-2 py-1 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-xs">
                  {resource.resource_type.split('::')[1]}
                </span>
              </td>
              <td className="py-3 px-4 text-[var(--text-secondary)]">{resource.region}</td>
              <td className="py-3 px-4">
                <div className="flex items-center gap-2">
                  <div className="w-16 h-2 bg-[var(--bg-secondary)] rounded-full overflow-hidden">
                    <div
                      className={`h-full ${resource.risk_score >= 80 ? 'bg-[var(--accent-danger)]' : resource.risk_score >= 60 ? 'bg-[var(--accent-warning)]' : 'bg-[var(--accent-success)]'}`}
                      style={{ width: `${resource.risk_score}%` }}
                    />
                  </div>
                  <span className="font-semibold text-xs">{resource.risk_score}</span>
                </div>
              </td>
              <td className="py-3 px-4">
                {resource.threats > 0 ? (
                  <span className="text-[var(--accent-danger)] font-semibold flex items-center gap-1">
                    <AlertTriangle size={14} />
                    {resource.threats}
                  </span>
                ) : (
                  <span className="text-[var(--text-secondary)]">—</span>
                )}
              </td>
              <td className="py-3 px-4 text-[var(--text-primary)] font-semibold">{resource.findings}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Resource Detail Panel
function ResourceDetailPanel({ resource, onClose }) {
  if (!resource) return null;

  return (
    <div className="absolute right-0 top-0 bottom-0 w-80 bg-[var(--bg-card)] border-l border-[var(--border-primary)] shadow-2xl overflow-y-auto z-40">
      <div className="sticky top-0 bg-[var(--bg-card)] border-b border-[var(--border-primary)] px-6 py-4 flex items-center justify-between">
        <h3 className="font-semibold text-[var(--text-primary)]">Resource Details</h3>
        <button
          onClick={onClose}
          className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
        >
          ×
        </button>
      </div>

      <div className="p-6 space-y-4">
        <div>
          <label className="text-xs font-semibold text-[var(--text-secondary)] uppercase">Type</label>
          <p className="text-sm text-[var(--text-primary)] mt-1">{resource.type}</p>
        </div>

        <div>
          <label className="text-xs font-semibold text-[var(--text-secondary)] uppercase">Resource ID</label>
          <p className="text-xs text-[var(--text-secondary)] mt-1 font-mono break-all">{resource.uid}</p>
        </div>

        <div>
          <label className="text-xs font-semibold text-[var(--text-secondary)] uppercase">Hop Distance</label>
          <p className="text-sm text-[var(--text-primary)] mt-1">{resource.hops} hops from source</p>
        </div>

        <div>
          <label className="text-xs font-semibold text-[var(--text-secondary)] uppercase">Findings</label>
          <div className="flex items-center gap-2 mt-2">
            <div className="flex-1 h-2 bg-[var(--bg-secondary)] rounded-full overflow-hidden">
              <div
                className="h-full bg-[var(--accent-warning)]"
                style={{ width: `${Math.min(resource.finding_count * 20, 100)}%` }}
              />
            </div>
            <span className="text-sm font-semibold">{resource.finding_count}</span>
          </div>
        </div>

        {resource.threats && resource.threats.length > 0 && (
          <div>
            <label className="text-xs font-semibold text-[var(--text-secondary)] uppercase">Active Threats</label>
            <div className="mt-2 space-y-1">
              {resource.threats.map((threat) => (
                <div key={threat} className="flex items-center gap-2 text-xs">
                  <AlertTriangle size={12} className="text-[var(--accent-danger)]" />
                  <span className="text-[var(--text-secondary)]">Threat ID: {threat}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="pt-4 border-t border-[var(--border-primary)]">
          <button className="w-full py-2 px-4 bg-[var(--accent-primary)] text-white rounded-lg text-sm font-medium hover:bg-[var(--accent-primary)]/90 transition-colors flex items-center justify-center gap-2">
            <Zap size={14} />
            Analyze Resource
          </button>
        </div>
      </div>
    </div>
  );
}

// Main Page Component
export default function BlastRadiusPage() {
  const [searchInput, setSearchInput] = useState('');
  const [blastRadiusData, setBlastRadiusData] = useState(null);
  const [graphSummary, setGraphSummary] = useState(null);
  const [internetExposed, setInternetExposed] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadInitialData = async () => {
      try {
        setLoading(true);
        const summary = await getFromEngine('threat', '/api/v1/graph/summary', {});
        if (summary && !summary.error) setGraphSummary(summary);

        const exposed = await getFromEngine('threat', '/api/v1/graph/internet-exposed', {});
        if (exposed && !exposed.error) {
          const list = Array.isArray(exposed) ? exposed : (exposed.exposed_resources || null);
          if (list) setInternetExposed(list);
        }

        const blastData = await getFromEngine(
          'threat',
          '/api/v1/graph/blast-radius/latest',
          {}
        );
        if (blastData && !blastData.error) setBlastRadiusData(blastData);
      } catch (err) {
        console.warn('Error loading data:', err);
        setError('Failed to load blast radius data. Please check that the Threat engine is running.');
      } finally {
        setLoading(false);
      }
    };

    loadInitialData();
  }, []);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchInput.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const data = await getFromEngine('threat', `/api/v1/graph/blast-radius/${encodeURIComponent(searchInput)}`, {});
      if (data && !data.error) {
        setBlastRadiusData(data);
        setSelectedNode(null);
      } else {
        setError(`No blast radius data found for: ${searchInput}`);
      }
    } catch (err) {
      setError(`Failed to load blast radius for: ${searchInput}`);
    } finally {
      setLoading(false);
    }
  };

  const stats = graphSummary || {
    total_nodes: 0,
    internet_exposed_count: 0,
    avg_blast_radius: 0,
    resources_with_threats: 0,
  };

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-[var(--text-primary)] mb-2">Blast Radius Analysis</h1>
          <p className="text-[var(--text-secondary)]">
            Visualize the impact radius of resources and identify cascading security risks across your cloud infrastructure.
          </p>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <KpiCard
            title="Total Nodes"
            value={stats.total_nodes}
            description="Resources in graph"
            icon={Shield}
            trend="stable"
          />
          <KpiCard
            title="Internet-Exposed"
            value={stats.internet_exposed_count}
            description="Publicly accessible"
            icon={AlertTriangle}
            trend="down"
            trendValue="-2"
          />
          <KpiCard
            title="Avg Blast Radius"
            value={stats.avg_blast_radius.toFixed(1)}
            description="Reachable resources"
            icon={Zap}
            trend="up"
            trendValue="+5"
          />
          <KpiCard
            title="With Threats"
            value={stats.resources_with_threats}
            description="Active threats detected"
            icon={AlertTriangle}
            trend="up"
            trendValue="+1"
          />
        </div>

        {/* Search Bar */}
        <form onSubmit={handleSearch} className="mb-8">
          <div className="relative flex gap-3">
            <div className="flex-1 relative">
              <input
                type="text"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Enter resource ARN or UID to analyze blast radius..."
                className="w-full px-4 py-3 bg-[var(--bg-card)] border border-[var(--border-primary)] rounded-lg text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-primary)]"
              />
              <Search className="absolute right-4 top-3.5 text-[var(--text-secondary)] pointer-events-none" size={20} />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-3 bg-[var(--accent-primary)] text-white rounded-lg font-medium hover:bg-[var(--accent-primary)]/90 disabled:opacity-50 transition-colors flex items-center gap-2"
            >
              <ChevronRight size={18} />
              Analyze
            </button>
          </div>
          {error && <p className="text-[var(--accent-danger)] text-sm mt-2">{error}</p>}
        </form>

        {/* Main Content */}
        {blastRadiusData ? (
          <div className="grid grid-cols-1 gap-8">
            {/* Graph Visualization */}
            <div className="relative">
              <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-4">
                Blast Radius: {blastRadiusData.source_resource.resource_type.split('::')[1]}
              </h2>
              <BlastRadiusGraph
                data={blastRadiusData}
                onNodeClick={setSelectedNode}
                selectedNodeUid={selectedNode?.uid}
              />
              {selectedNode && (
                <ResourceDetailPanel resource={selectedNode} onClose={() => setSelectedNode(null)} />
              )}
            </div>

            {/* Bottom Row - Charts and Tables */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <DepthChart distribution={blastRadiusData.depth_distribution} />
              <div className="bg-[var(--bg-card)] border border-[var(--border-primary)] rounded-lg p-6">
                <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4">Blast Radius Summary</h3>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--text-secondary)]">Total Reachable Resources</span>
                    <span className="text-2xl font-bold text-[var(--accent-primary)]">
                      {blastRadiusData.reachable_count}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--text-secondary)]">Resources with Threats</span>
                    <span className="text-2xl font-bold text-[var(--accent-danger)]">
                      {blastRadiusData.resources_with_threats}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--text-secondary)]">Max Hop Distance</span>
                    <span className="text-2xl font-bold text-[var(--accent-warning)]">
                      {Math.max(...Object.keys(blastRadiusData.depth_distribution).map(Number))}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Internet Exposed Table */}
            {internetExposed && internetExposed.length > 0 && (
              <InternetExposedTable resources={internetExposed} />
            )}
          </div>
        ) : loading ? (
          <div className="flex items-center justify-center h-96 text-[var(--text-secondary)]">
            Loading blast radius data...
          </div>
        ) : null}
      </div>
    </div>
  );
}
