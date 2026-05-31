'use client';

/**
 * AssetDetailMini — compact 4-tab asset detail panel.
 *
 * Used in two contexts:
 *   1. Attack path node click — prefetched* props are provided, no BFF call for those tabs.
 *   2. Inventory row expand  — no prefetched props, all tabs lazy-fetch from BFF.
 *
 * Tabs: Misconfigs | CVEs | CDR | Posture
 *
 * Security constraints (CONSTITUTION):
 *   - credential_ref never rendered
 *   - policy_statement never rendered
 *   - CDR tab hidden for viewer role (BFF returns null detail for CDR)
 *   - EPSS shows "—" when null (viewer role field-stripping)
 *   - No fallback/mock data — error state only
 */

import { useState, useEffect, useRef } from 'react';
import { Copy, Check, ExternalLink } from 'lucide-react';
import { fetchView } from '@/lib/api';
import SeverityBadge from './SeverityBadge';

// ── Severity sort order ──────────────────────────────────────────────────────

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function sortBySeverity(findings) {
  return [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
  );
}

// ── Skeleton loading rows ────────────────────────────────────────────────────

function SkeletonRows() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          style={{
            height: 36,
            borderRadius: 6,
            background: 'linear-gradient(90deg, var(--bg-tertiary, #1e293b) 25%, var(--bg-secondary, #283548) 50%, var(--bg-tertiary, #1e293b) 75%)',
            backgroundSize: '200% 100%',
            animation: 'adm-shimmer 1.4s ease infinite',
            opacity: 1 - i * 0.15,
          }}
        />
      ))}
      <style>{`
        @keyframes adm-shimmer {
          0%   { background-position: 200% 0; }
          100% { background-position: -200% 0; }
        }
      `}</style>
    </div>
  );
}

// ── Error state ──────────────────────────────────────────────────────────────

function ErrorState({ message }) {
  return (
    <div
      style={{
        padding: '16px',
        color: 'var(--accent-danger, #ef4444)',
        fontSize: 13,
        textAlign: 'center',
      }}
    >
      {message}
    </div>
  );
}

// ── Empty state ──────────────────────────────────────────────────────────────

function EmptyState({ message }) {
  return (
    <div
      style={{
        padding: '16px',
        color: 'var(--text-muted, #64748b)',
        fontSize: 13,
        textAlign: 'center',
      }}
    >
      {message}
    </div>
  );
}

// ── MITRE technique badge ────────────────────────────────────────────────────

function MitreBadge({ techniqueId }) {
  if (!techniqueId) return null;
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '1px 7px',
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 600,
        fontFamily: 'monospace',
        backgroundColor: 'rgba(139,92,246,0.18)',
        color: '#a78bfa',
        flexShrink: 0,
      }}
    >
      {techniqueId}
    </span>
  );
}

// ── Misconfigs tab content ───────────────────────────────────────────────────

function MisconfigsTab({ findings, loading, error }) {
  const [showAll, setShowAll] = useState(false);

  if (loading) return <SkeletonRows />;
  if (error) return <ErrorState message={error} />;
  if (!findings || findings.length === 0)
    return <EmptyState message="No misconfigurations found for this asset" />;

  const sorted = sortBySeverity(findings);
  const visible = showAll ? sorted : sorted.slice(0, 10);
  const hasMore = sorted.length > 10;

  return (
    <div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {visible.map((f, idx) => (
          <div
            key={f.finding_id || f.rule_id || idx}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '7px 8px',
              borderRadius: 6,
              backgroundColor: 'var(--bg-secondary, #1e293b)',
              flexWrap: 'wrap',
            }}
          >
            <SeverityBadge severity={f.severity} />
            <span
              style={{
                flex: 1,
                fontSize: 13,
                color: 'var(--text-primary, #e2e8f0)',
                minWidth: 0,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={f.title}
            >
              {f.title || f.rule_id || 'Unnamed finding'}
            </span>
            {f.rule_id && (
              <code
                style={{
                  fontSize: 10,
                  padding: '1px 5px',
                  borderRadius: 3,
                  backgroundColor: 'var(--bg-tertiary, #283548)',
                  color: 'var(--text-tertiary, #94a3b8)',
                  flexShrink: 0,
                  maxWidth: 160,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
                title={f.rule_id}
              >
                {f.rule_id}
              </code>
            )}
            {f.status && (
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  padding: '1px 6px',
                  borderRadius: 4,
                  backgroundColor:
                    f.status.toLowerCase() === 'open'
                      ? 'rgba(239,68,68,0.15)'
                      : 'rgba(34,197,94,0.15)',
                  color:
                    f.status.toLowerCase() === 'open' ? '#f87171' : '#4ade80',
                  textTransform: 'uppercase',
                  flexShrink: 0,
                }}
              >
                {f.status}
              </span>
            )}
          </div>
        ))}
      </div>
      {hasMore && !showAll && (
        <button
          onClick={() => setShowAll(true)}
          style={{
            marginTop: 8,
            fontSize: 12,
            color: 'var(--accent-primary, #3b82f6)',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            padding: 0,
          }}
        >
          Show all {sorted.length} misconfigurations
        </button>
      )}
    </div>
  );
}

// ── CVEs tab content ─────────────────────────────────────────────────────────

function CvesTab({ findings, loading, error }) {
  if (loading) return <SkeletonRows />;
  if (error) return <ErrorState message={error} />;
  if (!findings || findings.length === 0)
    return <EmptyState message="No CVEs found for this asset" />;

  // Sort by epss_score desc (null treated as -1 so it sinks to bottom)
  const sorted = [...findings].sort(
    (a, b) => (b.epss_score ?? -1) - (a.epss_score ?? -1)
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {sorted.map((f, idx) => {
        const epssRed = f.epss_score !== null && f.epss_score >= 0.5;
        const epssDisplay =
          f.epss_score !== null
            ? `${(f.epss_score * 100).toFixed(1)}%`
            : '—';

        return (
          <div
            key={f.finding_id || f.rule_id || idx}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '7px 8px',
              borderRadius: 6,
              backgroundColor: 'var(--bg-secondary, #1e293b)',
              flexWrap: 'wrap',
            }}
          >
            {/* CVE ID */}
            <code
              style={{
                fontSize: 11,
                fontWeight: 600,
                padding: '1px 5px',
                borderRadius: 3,
                backgroundColor: 'var(--bg-tertiary, #283548)',
                color: 'var(--text-secondary, #94a3b8)',
                flexShrink: 0,
              }}
            >
              {f.rule_id || 'CVE-UNKNOWN'}
            </code>

            {/* KEV badge */}
            {f.in_kev && (
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  padding: '1px 5px',
                  borderRadius: 4,
                  backgroundColor: 'rgba(239,68,68,0.2)',
                  color: '#f87171',
                  flexShrink: 0,
                }}
              >
                KEV
              </span>
            )}

            {/* EPSS */}
            <span
              style={{
                fontSize: 12,
                fontWeight: 600,
                color: epssRed
                  ? '#f87171'
                  : 'var(--text-tertiary, #64748b)',
                flexShrink: 0,
              }}
              title="EPSS score"
            >
              EPSS {epssDisplay}
            </span>

            {/* CVSS */}
            {f.cvss_score !== null && f.cvss_score !== undefined && (
              <span
                style={{
                  fontSize: 12,
                  color: 'var(--text-muted, #64748b)',
                  flexShrink: 0,
                }}
                title="CVSS score"
              >
                CVSS {f.cvss_score}
              </span>
            )}

            {/* Severity badge — pushes to right */}
            <span style={{ marginLeft: 'auto', flexShrink: 0 }}>
              <SeverityBadge severity={f.severity} />
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── CDR tab content ──────────────────────────────────────────────────────────

function CdrTab({ findings, loading, error }) {
  if (loading) return <SkeletonRows />;
  if (error) return <ErrorState message={error} />;
  if (!findings || findings.length === 0)
    return <EmptyState message="No CDR detections for this asset" />;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {findings.map((f, idx) => (
        <div
          key={f.finding_id || idx}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '7px 8px',
            borderRadius: 6,
            backgroundColor: 'var(--bg-secondary, #1e293b)',
            flexWrap: 'wrap',
          }}
        >
          <MitreBadge techniqueId={f.mitre_technique_id} />
          {f.mitre_tactic && (
            <span
              style={{
                fontSize: 11,
                color: 'var(--text-muted, #64748b)',
                flexShrink: 0,
              }}
            >
              {f.mitre_tactic}
            </span>
          )}
          <span
            style={{
              flex: 1,
              fontSize: 13,
              color: 'var(--text-primary, #e2e8f0)',
              minWidth: 0,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
            title={f.title}
          >
            {f.title || 'CDR Detection'}
          </span>
          <span style={{ marginLeft: 'auto', flexShrink: 0 }}>
            <SeverityBadge severity={f.severity} />
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Posture signal row ───────────────────────────────────────────────────────

function PostureSignalRow({ label, value, color }) {
  if (value === null || value === undefined) return null;
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '6px 8px',
        borderRadius: 6,
        backgroundColor: 'var(--bg-secondary, #1e293b)',
      }}
    >
      <span style={{ fontSize: 13, color: 'var(--text-secondary, #94a3b8)' }}>
        {label}
      </span>
      <span
        style={{
          fontSize: 12,
          fontWeight: 600,
          color: color || 'var(--text-primary, #e2e8f0)',
        }}
      >
        {value}
      </span>
    </div>
  );
}

// ── Posture tab content ──────────────────────────────────────────────────────

function PostureTab({ posture, loading, error }) {
  if (loading) return <SkeletonRows />;
  if (error) return <ErrorState message={error} />;
  if (!posture)
    return <EmptyState message="Posture data not yet scanned" />;

  const net = posture.network || {};
  const enc = posture.encryption || {};
  const ap = posture.attack_path || {};
  const iam = posture.iam || {};
  const container = posture.container || {};

  // Cert days — stored as cert_days_to_expiry in BFF response
  const certDays =
    enc.cert_days_remaining ?? enc.cert_days_to_expiry ?? null;

  const rows = [
    // Network
    {
      label: 'Internet Exposure',
      value:
        net.is_internet_exposed === true
          ? 'Internet Exposed'
          : net.is_internet_exposed === false
          ? 'Private'
          : null,
      color:
        net.is_internet_exposed === true
          ? '#f87171'
          : net.is_internet_exposed === false
          ? '#4ade80'
          : undefined,
    },
    {
      label: 'Subnet',
      value:
        net.is_in_private_subnet === true
          ? 'Private Subnet'
          : net.is_in_private_subnet === false
          ? 'Public Subnet'
          : null,
      color:
        net.is_in_private_subnet === true
          ? '#4ade80'
          : net.is_in_private_subnet === false
          ? '#fbbf24'
          : undefined,
    },
    // Encryption
    {
      label: 'Encryption at Rest',
      value:
        enc.volume_encrypted === true
          ? 'Encrypted at Rest'
          : enc.volume_encrypted === false
          ? 'Unencrypted'
          : null,
      color:
        enc.volume_encrypted === true
          ? '#4ade80'
          : enc.volume_encrypted === false
          ? '#f87171'
          : undefined,
    },
    // Attack path
    {
      label: 'Attack Path',
      value:
        ap.is_on_attack_path === true
          ? 'On Attack Path'
          : ap.is_on_attack_path === false
          ? 'Not on path'
          : null,
      color:
        ap.is_on_attack_path === true
          ? '#f87171'
          : '#64748b',
    },
    // Choke point — only show if true
    ap.is_choke_point === true
      ? {
          label: 'Choke Point',
          value:
            ap.attack_path_count != null
              ? `Choke Point — breaks ${ap.attack_path_count} path${ap.attack_path_count !== 1 ? 's' : ''}`
              : 'Choke Point',
          color: '#f87171',
        }
      : null,
    // IAM admin — only show if true
    iam.is_admin_role === true
      ? { label: 'IAM Role', value: 'Admin Role', color: '#f87171' }
      : null,
    // Privileged container — only show if true
    container.has_privileged_container === true
      ? {
          label: 'Container',
          value: 'Privileged Container',
          color: '#f87171',
        }
      : null,
    // Cert expiry — only show when a value is present
    certDays !== null && certDays !== undefined
      ? {
          label: 'Certificate',
          value: `Cert expires in ${certDays} days`,
          color: certDays < 30 ? '#fbbf24' : 'var(--text-primary, #e2e8f0)',
        }
      : null,
  ].filter(Boolean);

  if (rows.every((r) => r.value === null)) {
    return <EmptyState message="Posture data not yet scanned" />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {rows.map((row, idx) =>
        row.value !== null ? (
          <PostureSignalRow
            key={idx}
            label={row.label}
            value={row.value}
            color={row.color}
          />
        ) : null
      )}
    </div>
  );
}

// ── Main component ───────────────────────────────────────────────────────────

const TABS = [
  { id: 'misconfigs', label: 'Misconfigs' },
  { id: 'cves',       label: 'CVEs' },
  { id: 'cdr',        label: 'CDR' },
  { id: 'posture',    label: 'Posture' },
];

export default function AssetDetailMini({
  uid,
  displayName,
  resourceType,
  onViewFull,
  prefetchedMisconfigs,
  prefetchedCves,
  prefetchedThreats,
}) {
  const [activeTab, setActiveTab]       = useState('misconfigs');
  const [copiedUid, setCopiedUid]       = useState(false);

  // Findings state (lazy-fetched when prefetched* absent)
  const [findingsData, setFindingsData] = useState(null);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError]     = useState(null);
  const findingsFetched = useRef(false);

  // Posture state (always lazy-fetched on first Posture tab activation)
  const [postureData, setPostureData]   = useState(null);
  const [postureLoading, setPostureLoading] = useState(false);
  const [postureError, setPostureError]     = useState(null);
  const postureFetched = useRef(false);

  // Determine whether we need a BFF call for the findings tabs.
  // We need it when any of the three prefetched* props is absent.
  const needsFindingsFetch =
    prefetchedMisconfigs === undefined ||
    prefetchedCves        === undefined ||
    prefetchedThreats     === undefined;

  // Determine viewer role: CDR tab is hidden for viewers.
  // We detect viewer status from the absence of CDR findings when the BFF
  // returns (CDR detail is null for analyst/tenant_admin, and CDR tab BFF
  // returns 403 for viewer — we hide if we get an error on that engine).
  // Since we cannot read AuthContext here (pure component), we infer from
  // the BFF's by_engine response: if cdr count is 0 AND we got a BFF
  // response, we assume the role is at least analyst-level (tab still shown).
  // Viewer detection: fetchView returns error.detail containing '403' or
  // the by_engine.cdr count is absent AND findingsError contains 403.
  const [isCdrHidden, setIsCdrHidden] = useState(false);

  // Lazy-fetch findings from BFF on first non-posture tab activation when
  // prefetched* props are not provided.
  useEffect(() => {
    if (!uid) return;
    if (!needsFindingsFetch) return;
    if (findingsFetched.current) return;
    if (activeTab === 'posture') return; // posture has its own fetch

    findingsFetched.current = true;
    setFindingsLoading(true);
    setFindingsError(null);

    const encoded = encodeURIComponent(uid);
    fetchView(`inventory/asset/${encoded}/findings`, { status: 'open' })
      .then((data) => {
        if (data?.error) {
          // Check for 403 — viewer cannot see CDR data
          if (
            String(data.error).includes('403') ||
            String(data.error).includes('Forbidden')
          ) {
            setIsCdrHidden(true);
          }
          setFindingsError(`Unable to load findings — ${data.error}`);
          setFindingsLoading(false);
          return;
        }
        setFindingsData(data);
        setFindingsLoading(false);
      })
      .catch((err) => {
        setFindingsError(`Unable to load findings — ${err?.message || 'error'}`);
        setFindingsLoading(false);
      });
  }, [uid, activeTab, needsFindingsFetch]);

  // Lazy-fetch posture on first Posture tab activation.
  useEffect(() => {
    if (!uid) return;
    if (activeTab !== 'posture') return;
    if (postureFetched.current) return;

    postureFetched.current = true;
    setPostureLoading(true);
    setPostureError(null);

    const encoded = encodeURIComponent(uid);
    fetchView(`inventory/asset/${encoded}/posture`)
      .then((data) => {
        if (data?.error) {
          // 404 = not yet scanned — show empty state, not error
          if (
            String(data.error).includes('404') ||
            String(data.error).includes('No posture data')
          ) {
            setPostureData(null);
            setPostureLoading(false);
            return;
          }
          setPostureError(`Unable to load posture — ${data.error}`);
          setPostureLoading(false);
          return;
        }
        setPostureData(data);
        setPostureLoading(false);
      })
      .catch((err) => {
        setPostureError(`Unable to load posture — ${err?.message || 'error'}`);
        setPostureLoading(false);
      });
  }, [uid, activeTab]);

  // ── Derive per-tab findings ──────────────────────────────────────────────

  const allFindings = findingsData?.findings || [];

  const misconfigs =
    prefetchedMisconfigs !== undefined
      ? prefetchedMisconfigs
      : allFindings.filter((f) => f.source_engine === 'check');

  const cves =
    prefetchedCves !== undefined
      ? prefetchedCves
      : allFindings.filter((f) => f.finding_type === 'cve');

  const cdrFindings =
    prefetchedThreats !== undefined
      ? prefetchedThreats
      : allFindings.filter((f) => f.source_engine === 'cdr');

  // ── Tab counts ──────────────────────────────────────────────────────────

  function tabCount(tabId) {
    if (tabId === 'misconfigs') {
      if (prefetchedMisconfigs !== undefined) return prefetchedMisconfigs.length;
      if (findingsData) return misconfigs.length;
      return null;
    }
    if (tabId === 'cves') {
      if (prefetchedCves !== undefined) return prefetchedCves.length;
      if (findingsData) return cves.length;
      return null;
    }
    if (tabId === 'cdr') {
      if (prefetchedThreats !== undefined) return prefetchedThreats.length;
      if (findingsData) return cdrFindings.length;
      return null;
    }
    return null; // posture has no count
  }

  // ── Copy UID to clipboard ────────────────────────────────────────────────

  const handleCopyUid = () => {
    if (!uid) return;
    try {
      navigator.clipboard.writeText(uid);
      setCopiedUid(true);
      setTimeout(() => setCopiedUid(false), 2000);
    } catch {}
  };

  // ── Visible tabs (CDR hidden for viewer) ────────────────────────────────

  const visibleTabs = TABS.filter((t) => !(t.id === 'cdr' && isCdrHidden));

  // Ensure activeTab is valid when CDR gets hidden
  const resolvedTab = visibleTabs.find((t) => t.id === activeTab)
    ? activeTab
    : visibleTabs[0]?.id || 'misconfigs';

  // ── Render ───────────────────────────────────────────────────────────────

  const truncatedName =
    displayName && displayName.length > 40
      ? displayName.slice(0, 37) + '…'
      : displayName || uid || 'Asset';

  return (
    <div
      style={{
        minWidth: 320,
        border: '1px solid var(--border-color, #1e293b)',
        borderRadius: 10,
        backgroundColor: 'var(--bg-primary, #0f172a)',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div
        style={{
          padding: '12px 14px 10px',
          borderBottom: '1px solid var(--border-color, #1e293b)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: 8,
        }}
      >
        <div style={{ minWidth: 0 }}>
          {/* Resource type badge */}
          {resourceType && (
            <span
              style={{
                display: 'inline-block',
                fontSize: 10,
                fontWeight: 600,
                padding: '1px 6px',
                borderRadius: 4,
                backgroundColor: 'rgba(99,102,241,0.18)',
                color: '#818cf8',
                marginBottom: 4,
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
              }}
            >
              {resourceType}
            </span>
          )}
          {/* Display name */}
          <div
            style={{
              fontSize: 14,
              fontWeight: 600,
              color: 'var(--text-primary, #e2e8f0)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
            title={displayName || uid}
          >
            {truncatedName}
          </div>
          {/* UID with copy button */}
          {uid && (
            <button
              onClick={handleCopyUid}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                marginTop: 2,
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                padding: 0,
                color: 'var(--text-muted, #64748b)',
              }}
              title="Copy resource UID"
            >
              <code
                style={{
                  fontSize: 10,
                  fontFamily: 'monospace',
                  maxWidth: 200,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  display: 'inline-block',
                }}
              >
                {uid}
              </code>
              {copiedUid ? (
                <Check style={{ width: 11, height: 11, color: '#4ade80' }} />
              ) : (
                <Copy style={{ width: 11, height: 11 }} />
              )}
            </button>
          )}
        </div>

        {/* View Full Asset button */}
        <button
          onClick={() => onViewFull && onViewFull()}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            padding: '5px 10px',
            borderRadius: 6,
            fontSize: 12,
            fontWeight: 600,
            backgroundColor: 'rgba(99,102,241,0.15)',
            color: '#818cf8',
            border: '1px solid rgba(99,102,241,0.3)',
            cursor: 'pointer',
            flexShrink: 0,
            whiteSpace: 'nowrap',
          }}
        >
          View Full Asset
          <ExternalLink style={{ width: 11, height: 11 }} />
        </button>
      </div>

      {/* ── Tab bar ────────────────────────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          gap: 0,
          borderBottom: '1px solid var(--border-color, #1e293b)',
          backgroundColor: 'var(--bg-primary, #0f172a)',
        }}
      >
        {visibleTabs.map((tab) => {
          const count = tabCount(tab.id);
          const isActive = resolvedTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                flex: 1,
                padding: '8px 4px',
                fontSize: 12,
                fontWeight: isActive ? 600 : 400,
                color: isActive
                  ? 'var(--accent-primary, #6366f1)'
                  : 'var(--text-muted, #64748b)',
                background: 'none',
                border: 'none',
                borderBottom: isActive
                  ? '2px solid var(--accent-primary, #6366f1)'
                  : '2px solid transparent',
                cursor: 'pointer',
                transition: 'color 0.15s, border-color 0.15s',
                whiteSpace: 'nowrap',
              }}
            >
              {tab.label}
              {count !== null && (
                <span
                  style={{
                    marginLeft: 4,
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '0 4px',
                    borderRadius: 8,
                    backgroundColor: isActive
                      ? 'rgba(99,102,241,0.2)'
                      : 'var(--bg-tertiary, #283548)',
                    color: isActive ? '#818cf8' : 'var(--text-muted, #64748b)',
                  }}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Tab content ────────────────────────────────────────────────── */}
      <div
        style={{
          padding: '12px 12px',
          maxHeight: 320,
          overflowY: 'auto',
          overflowX: 'hidden',
        }}
      >
        {resolvedTab === 'misconfigs' && (
          <MisconfigsTab
            findings={misconfigs}
            loading={needsFindingsFetch && findingsLoading && prefetchedMisconfigs === undefined}
            error={needsFindingsFetch && findingsError && prefetchedMisconfigs === undefined ? findingsError : null}
          />
        )}
        {resolvedTab === 'cves' && (
          <CvesTab
            findings={cves}
            loading={needsFindingsFetch && findingsLoading && prefetchedCves === undefined}
            error={needsFindingsFetch && findingsError && prefetchedCves === undefined ? findingsError : null}
          />
        )}
        {resolvedTab === 'cdr' && (
          <CdrTab
            findings={cdrFindings}
            loading={needsFindingsFetch && findingsLoading && prefetchedThreats === undefined}
            error={needsFindingsFetch && findingsError && prefetchedThreats === undefined ? findingsError : null}
          />
        )}
        {resolvedTab === 'posture' && (
          <PostureTab
            posture={postureData}
            loading={postureLoading}
            error={postureError}
          />
        )}
      </div>
    </div>
  );
}
