'use client';

/**
 * AttackPathCanvas — React Flow canvas for a single selected attack path.
 *
 * Props:
 *   detail          {object|null}  — full path detail (steps[], from BFF detail endpoint)
 *   loading         {boolean}      — show skeleton while fetching
 *   selectedNodeUid {string|null}  — node_uid of currently selected node (highlighted)
 *   onNodeClick     {function}     — called with step data when node is clicked
 */

import { useEffect, useCallback } from 'react';
import ReactFlow, {
  Background, Controls, MiniMap,
  useNodesState, useEdgesState, useReactFlow,
  ReactFlowProvider, Handle, Position, MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  Globe, Database, Server, Key, Lock, Shield,
  Network, Box, Cpu, HardDrive, Cloud, Activity, Wifi,
} from 'lucide-react';

// ── Type → icon + color ───────────────────────────────────────────────────────

const TYPE_MAP = {
  internet:       { Icon: Globe,     color: '#ef4444', label: 'Internet' },
  ec2:            { Icon: Server,    color: '#f97316', label: 'EC2' },
  s3:             { Icon: Database,  color: '#22c55e', label: 'S3' },
  rds:            { Icon: Database,  color: '#3b82f6', label: 'RDS' },
  lambda:         { Icon: Cpu,       color: '#f59e0b', label: 'Lambda' },
  iam:            { Icon: Key,       color: '#a855f7', label: 'IAM' },
  role:           { Icon: Key,       color: '#a855f7', label: 'IAM Role' },
  secretsmanager: { Icon: Lock,      color: '#8b5cf6', label: 'Secrets' },
  kms:            { Icon: Shield,    color: '#6d28d9', label: 'KMS' },
  eks:            { Icon: Box,       color: '#3b82f6', label: 'EKS' },
  vpc:            { Icon: Network,   color: '#0ea5e9', label: 'VPC' },
  compute:        { Icon: Server,    color: '#f97316', label: 'Compute' },
  storage:        { Icon: HardDrive, color: '#22c55e', label: 'Storage' },
  secrets:        { Icon: Lock,      color: '#a855f7', label: 'Secrets' },
  identity:       { Icon: Key,       color: '#a855f7', label: 'Identity' },
  network:        { Icon: Network,   color: '#3b82f6', label: 'Network' },
  data:           { Icon: Database,  color: '#22c55e', label: 'Data' },
};

function resolveType(typeStr) {
  const t = (typeStr || '').toLowerCase();
  for (const [key, cfg] of Object.entries(TYPE_MAP)) {
    if (t.includes(key)) return cfg;
  }
  return { Icon: Cloud, color: '#64748b', label: (typeStr || '').split('.').pop() || 'Resource' };
}

// ── Edge color by vector type ─────────────────────────────────────────────────

const EDGE_COLORS = {
  NETWORK:   '#0ea5e9',
  LATERAL:   '#f97316',
  EXPLOIT:   '#ef4444',
  PRIVILEGE: '#a855f7',
  ASSUME:    '#a855f7',
  DATA:      '#22c55e',
  COMPROMISE:'#ef4444',
};

export function resolveEdgeColor(edgeType) {
  const t = (edgeType || '').toUpperCase();
  for (const [key, color] of Object.entries(EDGE_COLORS)) {
    if (t.includes(key)) return color;
  }
  return '#475569';
}

// ── Severity ──────────────────────────────────────────────────────────────────

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#6b7280' };

function deriveSeverityColor(step, fallback) {
  const sevs = [
    ...(step.misconfigs || []).map(m => m.severity),
    ...(step.cves || []).map(c => c.severity),
  ].filter(Boolean).sort((a, b) => (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9));
  return sevs[0] ? SEV_COLOR[sevs[0]] : fallback;
}

// ── Custom Attack Node ────────────────────────────────────────────────────────

const HANDLE_STYLE = { background: 'transparent', border: 'none', width: 8, height: 8 };

function AttackNode({ data }) {
  const cfg = resolveType(data.node_type);
  const misconfigCount = data.misconfigs?.length ?? data.misconfig_count ?? 0;
  const cveCount = data.cves?.length ?? 0;
  const severityColor = deriveSeverityColor(data, cfg.color);
  const label = (data.node_name || data.node_uid || '').split('/').pop().split(':').pop();

  const borderColor = data.isSelected ? cfg.color : data.is_choke_point ? '#a855f7' : `${cfg.color}55`;
  const borderWidth = data.isSelected || data.is_choke_point ? 2 : 1.5;
  const boxShadow = data.isSelected
    ? `0 0 0 3px ${cfg.color}30, 0 4px 20px rgba(0,0,0,0.5)`
    : data.cdr_actor_active
    ? '0 0 0 2px rgba(239,68,68,0.3)'
    : '0 2px 8px rgba(0,0,0,0.4)';

  return (
    <div style={{ position: 'relative', width: 110 }}>
      {!data.isFirst && (
        <Handle type="target" position={Position.Left} style={HANDLE_STYLE} />
      )}

      <div
        style={{
          width: 110,
          backgroundColor: data.isSelected ? `${cfg.color}18` : `${cfg.color}08`,
          border: `${borderWidth}px solid ${borderColor}`,
          borderRadius: 12,
          boxShadow,
          overflow: 'hidden',
          cursor: 'pointer',
          transition: 'all 0.15s',
        }}
      >
        {/* Severity accent bar */}
        <div style={{ height: 3, backgroundColor: severityColor }} />

        <div style={{ padding: '10px 8px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
          {/* Icon */}
          <div style={{ position: 'relative' }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 8,
                backgroundColor: `${cfg.color}18`,
                border: `1.5px solid ${cfg.color}40`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <cfg.Icon style={{ width: 16, height: 16, color: cfg.color }} />
            </div>

            {/* Crown Jewel badge */}
            {(data.is_choke_point || data.isLast) && (
              <div
                style={{
                  position: 'absolute',
                  top: -6,
                  right: -6,
                  width: 16,
                  height: 16,
                  borderRadius: '50%',
                  backgroundColor: '#a855f7',
                  border: '2px solid #080d17',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 7,
                  fontWeight: 700,
                  color: '#fff',
                }}
              >
                CJ
              </div>
            )}
          </div>

          {/* Type chip */}
          <span
            style={{
              fontSize: 8,
              fontWeight: 700,
              padding: '2px 6px',
              borderRadius: 20,
              backgroundColor: `${cfg.color}18`,
              color: cfg.color,
              letterSpacing: '0.04em',
              maxWidth: '100%',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {cfg.label}
          </span>

          {/* Short name */}
          <span
            style={{
              fontSize: 8,
              fontWeight: 500,
              color: 'rgba(255,255,255,0.85)',
              textAlign: 'center',
              wordBreak: 'break-all',
              lineHeight: 1.3,
              maxWidth: '100%',
            }}
          >
            {label.slice(0, 14)}
          </span>

          {/* Badges */}
          <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', justifyContent: 'center' }}>
            {misconfigCount > 0 && (
              <span
                style={{
                  fontSize: 7,
                  fontWeight: 600,
                  padding: '1px 4px',
                  borderRadius: 4,
                  backgroundColor: 'rgba(249,115,22,0.15)',
                  color: '#f97316',
                  border: '1px solid rgba(249,115,22,0.3)',
                }}
              >
                {misconfigCount}M
              </span>
            )}
            {cveCount > 0 && (
              <span
                style={{
                  fontSize: 7,
                  fontWeight: 600,
                  padding: '1px 4px',
                  borderRadius: 4,
                  backgroundColor: 'rgba(239,68,68,0.15)',
                  color: '#ef4444',
                  border: '1px solid rgba(239,68,68,0.3)',
                }}
              >
                {cveCount}C
              </span>
            )}
            {data.cdr_actor_active && (
              <span
                style={{
                  fontSize: 7,
                  fontWeight: 700,
                  padding: '1px 4px',
                  borderRadius: 4,
                  backgroundColor: '#ef4444',
                  color: '#fff',
                }}
              >
                LIVE
              </span>
            )}
          </div>
        </div>
      </div>

      {!data.isLast && (
        <Handle type="source" position={Position.Right} style={HANDLE_STYLE} />
      )}
    </div>
  );
}

// ── Source Node (Internet / VPN / Peer Account) ───────────────────────────────

const SOURCE_CONFIGS = {
  internet:     { Icon: Globe,    color: '#ef4444', label: 'Internet',     subtitle: 'External Threat Source' },
  vpn:          { Icon: Network,  color: '#f97316', label: 'VPN',          subtitle: 'VPN Connection' },
  onprem:       { Icon: Server,   color: '#f97316', label: 'On-Premises',  subtitle: 'On-Premises Network' },
  peer_account: { Icon: Cloud,    color: '#a855f7', label: 'Peer Account', subtitle: 'Cross-Account Access' },
};

function SourceNode({ data }) {
  const entryType = (data.node_type || 'internet').toLowerCase();
  const cfg = SOURCE_CONFIGS[entryType] || SOURCE_CONFIGS.internet;

  return (
    <>
      <style>{`
        @keyframes src-pulse {
          0%   { transform: scale(1);   opacity: 0.6; }
          50%  { transform: scale(1.08); opacity: 0.25; }
          100% { transform: scale(1);   opacity: 0.6; }
        }
        @keyframes src-pulse2 {
          0%   { transform: scale(1);   opacity: 0.35; }
          50%  { transform: scale(1.15); opacity: 0.1; }
          100% { transform: scale(1);   opacity: 0.35; }
        }
      `}</style>

      <div
        style={{
          width: 108,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 8,
          position: 'relative',
        }}
      >
        {/* Outer pulse ring 2 */}
        <div
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: 108,
            height: 108,
            borderRadius: '50%',
            border: `1px dashed ${cfg.color}`,
            animation: 'src-pulse2 3s ease-in-out infinite',
            marginTop: -14,
            pointerEvents: 'none',
          }}
        />
        {/* Outer pulse ring 1 */}
        <div
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: 92,
            height: 92,
            borderRadius: '50%',
            border: `1.5px dashed ${cfg.color}60`,
            animation: 'src-pulse 2.4s ease-in-out infinite',
            marginTop: -14,
            pointerEvents: 'none',
          }}
        />

        {/* Core oval */}
        <div
          style={{
            width: 78,
            height: 78,
            borderRadius: '50%',
            border: `2px dashed ${cfg.color}`,
            backgroundColor: `${cfg.color}12`,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 5,
            boxShadow: `0 0 24px ${cfg.color}30, inset 0 0 20px ${cfg.color}08`,
            position: 'relative',
            zIndex: 1,
          }}
        >
          <cfg.Icon style={{ width: 26, height: 26, color: cfg.color }} />
          <span
            style={{
              fontSize: 8,
              fontWeight: 800,
              color: cfg.color,
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
            }}
          >
            {cfg.label}
          </span>
        </div>

        {/* Subtitle */}
        <span
          style={{
            fontSize: 9,
            color: 'rgba(255,255,255,0.45)',
            textAlign: 'center',
            lineHeight: 1.3,
            maxWidth: 100,
            position: 'relative',
            zIndex: 1,
          }}
        >
          {cfg.subtitle}
        </span>

        {/* Source handle — right side, vertically centered on the oval */}
        <Handle
          type="source"
          position={Position.Right}
          style={{
            ...HANDLE_STYLE,
            right: -4,
            top: 39,
          }}
        />
      </div>
    </>
  );
}

const nodeTypes = { attackNode: AttackNode, sourceNode: SourceNode };

// ── Steps → RF nodes + edges ──────────────────────────────────────────────────

const NODE_WIDTH = 110;
const NODE_GAP   = 130;

function stepsToGraph(steps, selectedNodeUid) {
  // Filter topology scaffolding nodes — these are not real cloud resources
  const visibleSteps = steps.filter(s => s.node_type !== 'VirtualNode');
  steps = visibleSteps;
  const nodes = steps.map((step, i) => {
    const id = step.node_uid || `node-${i}`;
    const isSource = id.startsWith('__source__');
    return {
      id,
      type: isSource ? 'sourceNode' : 'attackNode',
      position: { x: i * (NODE_WIDTH + NODE_GAP), y: isSource ? 10 : 20 },
      data: {
        ...step,
        isFirst:    i === 0,
        isLast:     i === steps.length - 1,
        isSelected: id === selectedNodeUid,
      },
      draggable: false,
    };
  });

  const edges = steps.slice(0, -1).map((step, i) => {
    const color   = resolveEdgeColor(step.edge_to_next);
    const srcId   = step.node_uid || `node-${i}`;
    const tgtId   = steps[i + 1].node_uid || `node-${i + 1}`;
    const rawEdge = (step.edge_to_next || '').replace(/_/g, ' ');
    const edgeLabel = rawEdge.length > 0
      ? rawEdge.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ')
      : null;

    return {
      id: `e-${i}`,
      source: srcId,
      target: tgtId,
      animated: !!step.cdr_actor_active,
      style: { stroke: color, strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color, width: 18, height: 18 },
      label: edgeLabel,
      labelStyle: {
        fill: color,
        fontSize: 8,
        fontWeight: 700,
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
      },
      labelBgStyle: {
        fill: '#0c111d',
        fillOpacity: 0.85,
        stroke: `${color}40`,
        strokeWidth: 1,
        rx: 4,
      },
      labelBgPadding: [4, 6],
    };
  });

  return { nodes, edges };
}

// ── Empty + loading states ────────────────────────────────────────────────────

function EmptyCanvas() {
  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 12,
        color: 'rgba(255,255,255,0.25)',
      }}
    >
      <Activity style={{ width: 44, height: 44, opacity: 0.25 }} />
      <p style={{ fontSize: 14, fontWeight: 500, color: 'rgba(255,255,255,0.3)' }}>
        Select a path to investigate
      </p>
      <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.18)', maxWidth: 220, textAlign: 'center', lineHeight: 1.5 }}>
        Click any path in the list to visualize its attack chain on the canvas
      </p>
    </div>
  );
}

function LoadingCanvas() {
  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
      {[0, 1, 2].map(i => (
        <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              width: 110,
              height: 150,
              borderRadius: 12,
              backgroundColor: 'rgba(255,255,255,0.06)',
              opacity: 1 - i * 0.2,
            }}
          />
          {i < 2 && (
            <div style={{ width: 60, height: 2, backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: 1 }} />
          )}
        </span>
      ))}
    </div>
  );
}

// ── Inner canvas — must live inside ReactFlowProvider ─────────────────────────

function CanvasInner({ detail, loading, selectedNodeUid, onNodeClick }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const { fitView } = useReactFlow();

  useEffect(() => {
    if (!detail?.steps?.length) {
      setNodes([]);
      setEdges([]);
      return;
    }
    const { nodes: n, edges: e } = stepsToGraph(detail.steps, selectedNodeUid);
    setNodes(n);
    setEdges(e);
    setTimeout(() => fitView({ padding: 0.25, duration: 450 }), 60);
  }, [detail, selectedNodeUid, fitView, setNodes, setEdges]);

  const handleNodeClick = useCallback((_, node) => {
    onNodeClick?.(node.data);
  }, [onNodeClick]);

  if (loading) return <LoadingCanvas />;
  if (!detail)  return <EmptyCanvas />;

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={handleNodeClick}
      fitView
      fitViewOptions={{ padding: 0.25 }}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
      proOptions={{ hideAttribution: true }}
      style={{ backgroundColor: '#080d17' }}
    >
      <Background color="#1e2d40" gap={24} size={1} />
      <Controls
        showInteractive={false}
        style={{
          backgroundColor: '#0c111d',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 8,
        }}
      />
      <MiniMap
        nodeColor={node => {
          const uid = node.data?.node_uid || '';
          if (uid.startsWith('__source__')) {
            return (SOURCE_CONFIGS[node.data?.node_type] || SOURCE_CONFIGS.internet).color;
          }
          return resolveType(node.data?.node_type).color;
        }}
        style={{
          backgroundColor: '#0c111d',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 8,
        }}
        maskColor="rgba(8,13,23,0.8)"
      />
    </ReactFlow>
  );
}

// ── Public export ─────────────────────────────────────────────────────────────

export default function AttackPathCanvas(props) {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} />
    </ReactFlowProvider>
  );
}
