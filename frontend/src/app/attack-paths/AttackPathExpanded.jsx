'use client';

/**
 * AttackPathExpanded — inline expansion section below an AttackPathRow.
 *
 * Fetches steps[] lazily on first expand. Caches via detailCache ref Map
 * passed from parent (no re-fetch on same path re-open).
 *
 * Renders:
 *   - Canvas strip: NodeBox chain + EdgeArrow between hops
 *   - AttackStory: per-step narrative
 *   - AssetDetailMini: when a node is clicked (selectedNodeStep state)
 *   - "View Full Details →" button → opens PathDetailPanel slide-over
 *
 * Security:
 *   - policy_statement NEVER rendered in this component
 *   - credential_ref NEVER rendered anywhere
 *   - Viewer role: canvas renders but node click is a no-op; no PathDetailPanel button
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Activity, X } from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';
import AssetDetailMini from '@/components/shared/AssetDetailMini';
import NodeBox from './NodeBox';
import EdgeArrow from './EdgeArrow';
import AttackStory from './AttackStory';
import styles from './attack-paths.module.css';

// PathDetailPanel removed — was in threats/attack-paths (deleted). Future: AP-P4-03.
const PathDetailPanel = null;

// ── Skeleton canvas ───────────────────────────────────────────────────────────

function SkeletonCanvas() {
  return (
    <div className="flex items-center gap-0 py-2" style={{ minWidth: 'max-content' }}>
      {[0, 1, 2].map(i => (
        <span key={i} className="flex items-center">
          <div className={styles.skeletonNode} style={{ opacity: 1 - i * 0.18 }} />
          {i < 2 && (
            <div
              style={{
                width: 52,
                height: 2,
                borderRadius: 1,
                backgroundColor: 'rgba(255,255,255,0.08)',
              }}
            />
          )}
        </span>
      ))}
    </div>
  );
}

// ── Edge tooltip ──────────────────────────────────────────────────────────────

function EdgeTooltip({ step, x, y }) {
  if (!step) return null;
  const edgeLabel = (step.edge_to_next || step.edge_category || '').replace(/_/g, ' ').toUpperCase();
  const reason = step.traversal_reason?.slice(0, 80);
  const sg = step.sg_rule;

  return (
    <div
      className={styles.edgeTooltip}
      style={{ top: y + 16, left: Math.min(x, (typeof window !== 'undefined' ? window.innerWidth : 1200) - 270) }}
    >
      {edgeLabel && (
        <p className="font-bold text-[10px]" style={{ color: '#0ea5e9', marginBottom: 4 }}>
          {edgeLabel}
        </p>
      )}
      {reason && (
        <p className="text-[10px] italic" style={{ color: 'rgba(255,255,255,0.6)' }}>
          {reason}
        </p>
      )}
      {sg && (
        <div className="flex items-center gap-2 mt-2 text-[9px] font-mono" style={{ color: 'rgba(255,255,255,0.5)' }}>
          <span>Port {sg.port ?? '—'}</span>
          <span>{sg.protocol ?? '—'}</span>
          {sg.cidr && (
            <span style={{ color: sg.cidr === '0.0.0.0/0' ? '#ef4444' : 'inherit' }}>
              {sg.cidr}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ── AttackPathExpanded ────────────────────────────────────────────────────────

export default function AttackPathExpanded({ pathId, detailCache, onClose }) {
  const { role } = useAuth();
  const isViewer = role === 'viewer';
  const router = useRouter();

  const [loading, setLoading]               = useState(false);
  const [error, setError]                   = useState(null);
  const [detail, setDetail]                 = useState(null);
  const [selectedNodeStep, setSelectedNode] = useState(null);
  const [edgeTooltip, setEdgeTooltip]       = useState(null); // { x, y, step }
  const [panelOpen, setPanelOpen]           = useState(false);

  // Fetch detail (lazy, cached)
  useEffect(() => {
    if (!pathId) return;

    if (detailCache.current.has(pathId)) {
      setDetail(detailCache.current.get(pathId));
      return;
    }

    setLoading(true);
    setError(null);
    fetchView(`attack-paths/${pathId}`).then(result => {
      if (result?.error || result?.detail) {
        setError(result.error || result.detail || 'Failed to load path details');
        setLoading(false);
        return;
      }
      detailCache.current.set(pathId, result);
      setDetail(result);
      setLoading(false);
    }).catch(err => {
      setError(err?.message || 'Failed to load path details');
      setLoading(false);
    });
  }, [pathId, detailCache]);

  const steps = detail?.steps || [];

  // Node click handler — viewer: no-op
  const handleNodeClick = useCallback((step) => {
    if (isViewer) return;
    setSelectedNode(prev =>
      prev?.node_uid === step.node_uid ? null : step
    );
  }, [isViewer]);

  // Edge tooltip handlers
  const handleEdgeHoverStart = useCallback((step) => (e) => {
    setEdgeTooltip({ x: e.clientX, y: e.clientY, step });
  }, []);

  const handleEdgeHoverEnd = useCallback(() => {
    setEdgeTooltip(null);
  }, []);

  // Navigate to inventory
  const handleViewFull = useCallback(() => {
    if (!selectedNodeStep?.node_uid) return;
    router.push(`/inventory/${encodeURIComponent(selectedNodeStep.node_uid)}`);
  }, [router, selectedNodeStep]);

  return (
    <div
      className={styles.accordionExpand}
      style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid rgba(255,255,255,0.07)',
        borderTop: 'none',
        borderRadius: '0 0 10px 10px',
        padding: '14px 16px 16px',
      }}
    >
      {/* Loading skeleton */}
      {loading && (
        <div className={styles.canvasStrip}>
          <SkeletonCanvas />
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <div
          className="py-4 text-center text-xs rounded-lg border"
          style={{
            backgroundColor: 'rgba(239,68,68,0.07)',
            borderColor: 'rgba(239,68,68,0.25)',
            color: '#f87171',
          }}
        >
          {error}
        </div>
      )}

      {/* Main content */}
      {!loading && !error && (
        <>
          {/* Canvas strip */}
          {steps.length > 0 && (
            <div className={styles.canvasStrip}>
              <div className="flex items-center gap-0 py-2" style={{ minWidth: 'max-content' }}>
                {steps.map((step, i) => (
                  <span key={`${step.node_uid || i}-${i}`} className="flex items-center">
                    <NodeBox
                      node={step}
                      isFirst={i === 0}
                      isLast={i === steps.length - 1}
                      onClick={handleNodeClick}
                      selected={selectedNodeStep?.node_uid === step.node_uid}
                    />
                    {i < steps.length - 1 && (
                      <EdgeArrow
                        edge={step}
                        onHoverStart={handleEdgeHoverStart(step)}
                        onHoverEnd={handleEdgeHoverEnd}
                      />
                    )}
                  </span>
                ))}
              </div>
            </div>
          )}

          {steps.length === 0 && detail && (
            <p className="text-[11px] text-center py-4" style={{ color: 'var(--text-secondary)' }}>
              No step data returned from engine.
            </p>
          )}

          {/* Edge tooltip */}
          {edgeTooltip && (
            <EdgeTooltip step={edgeTooltip.step} x={edgeTooltip.x} y={edgeTooltip.y} />
          )}

          {/* AssetDetailMini — shown when a node is selected */}
          {selectedNodeStep && !isViewer && (
            <div className={styles.nodeDetailSection}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[9px] font-bold uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>
                  Node Detail
                </span>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="p-1 rounded hover:bg-white/10 transition-colors"
                  style={{ color: 'var(--text-secondary)' }}
                  aria-label="Close node detail"
                >
                  <X style={{ width: 12, height: 12 }} />
                </button>
              </div>
              <AssetDetailMini
                uid={selectedNodeStep.node_uid}
                displayName={selectedNodeStep.node_name || selectedNodeStep.node_uid}
                resourceType={selectedNodeStep.node_type}
                prefetchedMisconfigs={selectedNodeStep.misconfigs}
                prefetchedCves={selectedNodeStep.cves}
                prefetchedThreats={selectedNodeStep.threat_detections}
                onViewFull={handleViewFull}
              />
            </div>
          )}

          {/* Attack Story */}
          {steps.length > 0 && (
            <div className="mt-4 border-t pt-4" style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
              <AttackStory steps={steps} />
            </div>
          )}

          {/* Footer: "View Full Details" */}
          {!isViewer && PathDetailPanel && (
            <div className="flex justify-end mt-4 pt-3 border-t" style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
              <button
                onClick={() => setPanelOpen(true)}
                className="flex items-center gap-1.5 text-[11px] font-semibold hover:opacity-80 transition-opacity"
                style={{ color: 'var(--accent-primary)' }}
              >
                <Activity style={{ width: 12, height: 12 }} />
                View Full Details →
              </button>
            </div>
          )}
        </>
      )}

      {/* PathDetailPanel slide-over */}
      {panelOpen && PathDetailPanel && (
        <PathDetailPanel
          pathId={pathId}
          onClose={() => setPanelOpen(false)}
        />
      )}
    </div>
  );
}
