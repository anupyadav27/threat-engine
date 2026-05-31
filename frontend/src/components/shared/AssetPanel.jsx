'use client';

import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  X, ExternalLink, ChevronRight, Shield, Network, Lock,
  Eye, Radar, AlertTriangle, CheckCircle2,
  RefreshCw, Cloud, MapPin, Layers,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import CspIcon from './CspIcon';
import {
  SeverityBadge,
  FindingsBar,
  AttackPathBadge,
  CrownJewelBadge,
  ChokepointBadge,
  ExposureBadge,
  RiskScore,
  FindingTypeBadge,
  SourceEngineBadge,
} from './SecurityBadges';

// ── Design tokens ──────────────────────────────────────────────────────────────
const S = {
  panel: {
    position: 'fixed', top: 0, right: 0, bottom: 0, zIndex: 50,
    width: 820, maxWidth: '96vw',
    background: 'var(--bg-card)',
    borderLeft: '1px solid var(--border-primary)',
    boxShadow: '-8px 0 32px rgba(0,0,0,0.28)',
    display: 'flex', flexDirection: 'column',
    overflow: 'hidden',
  },
  overlay: {
    position: 'fixed', inset: 0, zIndex: 49,
    background: 'rgba(0,0,0,0.35)',
    backdropFilter: 'blur(1px)',
  },
  header: {
    display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
    padding: '14px 16px 12px',
    borderBottom: '1px solid var(--border-primary)',
    flexShrink: 0,
  },
  tabBar: {
    display: 'flex', gap: 0,
    borderBottom: '1px solid var(--border-primary)',
    flexShrink: 0, overflowX: 'auto',
    scrollbarWidth: 'none',
  },
  body: { flex: 1, overflowY: 'auto', padding: '14px 16px' },
  section: {
    marginBottom: 16,
    background: 'var(--bg-secondary)',
    borderRadius: 8,
    border: '1px solid var(--border-primary)',
    overflow: 'hidden',
  },
  sectionHead: {
    display: 'flex', alignItems: 'center', gap: 6,
    padding: '8px 12px',
    borderBottom: '1px solid var(--border-primary)',
    fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)',
    textTransform: 'uppercase', letterSpacing: '0.06em',
  },
  row: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '6px 12px',
    borderBottom: '1px solid var(--border-primary)',
    fontSize: 12,
  },
  label: { color: 'var(--text-secondary)', flexShrink: 0 },
  value: { color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: 11, textAlign: 'right', wordBreak: 'break-all', maxWidth: '60%' },
  pill: (color, bg) => ({
    display: 'inline-flex', alignItems: 'center',
    fontSize: 10, fontWeight: 700,
    padding: '2px 7px', borderRadius: 4,
    color, background: bg,
  }),
};

// ── Tabs config ────────────────────────────────────────────────────────────────
const TABS = [
  { id: 'summary',    label: 'Summary',    icon: Layers },
  { id: 'alerts',     label: 'Alerts',     icon: AlertTriangle },
  { id: 'posture',    label: 'Posture',    icon: Shield },
  { id: 'compliance', label: 'Compliance', icon: CheckCircle2 },
];

// ── Bool signal row ────────────────────────────────────────────────────────────
function SignalRow({ label, value, trueColor = '#ef4444', falseColor = '#22c55e', invert = false }) {
  const isTrue = Boolean(value);
  const color = (invert ? !isTrue : isTrue) ? trueColor : falseColor;
  return (
    <div style={{ ...S.row, borderBottom: 'none' }}>
      <span style={S.label}>{label}</span>
      <span style={{ ...S.pill(color, `${color}18`), fontSize: 10 }}>
        {isTrue ? 'Yes' : 'No'}
      </span>
    </div>
  );
}

// ── Skeleton ──────────────────────────────────────────────────────────────────
function PanelSkeleton() {
  return (
    <div style={S.body}>
      {[200, 140, 180, 160].map((h, i) => (
        <div key={i} style={{ ...S.section, height: h, marginBottom: 12,
          background: 'var(--bg-secondary)', animation: 'pulse 1.5s infinite' }} />
      ))}
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function AssetPanel({ resourceUid, onClose }) {
  const [activeTab, setActiveTab] = useState('summary');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [findingsPage, setFindingsPage] = useState(1);
  const panelRef = useRef(null);

  const load = useCallback(async (page = 1) => {
    setLoading(true);
    setError(null);
    try {
      const result = await getFromEngine(
        'gateway',
        `/api/v1/views/inventory/asset/${encodeURIComponent(resourceUid)}/panel`,
        { findings_page: page, findings_page_size: 50 },
      );
      setData(result);
      setFindingsPage(page);
    } catch (e) {
      setError(e?.message || 'Failed to load asset details');
    } finally {
      setLoading(false);
    }
  }, [resourceUid]);

  useEffect(() => { load(); }, [load]);

  // Close on Escape
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const asset = data?.asset || {};
  const posture = data?.posture || {};
  const findings = data?.findings?.data || [];
  const findingsTotal = data?.findings?.total || 0;
  const checkSummary = data?.check_summary || {};
  const checkFindings = data?.check_findings || [];
  const complianceScore = data?.compliance_score;

  const providerKey = (asset.provider || '').toLowerCase();
  const accountDisplay = asset.account_id
    ? `···${String(asset.account_id).slice(-6)}`
    : '—';

  return (
    <>
      {/* Overlay */}
      <div style={S.overlay} onClick={onClose} />

      {/* Panel */}
      <div ref={panelRef} style={S.panel} role="dialog" aria-modal="true">

        {/* ── Header ── */}
        <div style={S.header}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
              <CspIcon provider={providerKey} size={16} />
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {asset.resource_name || asset.resource_uid || resourceUid}
              </span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, alignItems: 'center' }}>
              <span style={{ fontSize: 10, color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                {asset.resource_type || '—'}
              </span>
              {asset.region && (
                <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 10, color: 'var(--text-tertiary)' }}>
                  <MapPin size={10} /> {asset.region}
                </span>
              )}
              <span style={{ fontSize: 10, color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                {accountDisplay}
              </span>
            </div>
            {/* Attack-path signals */}
            {!loading && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 7 }}>
                {posture.is_on_attack_path && <AttackPathBadge size="sm" />}
                {posture.is_crown_jewel && <CrownJewelBadge size="sm" crownType={posture.crown_jewel_type} />}
                {posture.is_choke_point && <ChokepointBadge size="sm" />}
                {posture.is_internet_exposed && <ExposureBadge size="sm" />}
                {posture.overall_posture_score > 0 && (
                  <RiskScore score={posture.overall_posture_score} size="sm" />
                )}
              </div>
            )}
          </div>
          <div style={{ display: 'flex', gap: 6, flexShrink: 0, marginLeft: 10 }}>
            <button
              title="Close"
              onClick={onClose}
              style={{ padding: 6, borderRadius: 6, background: 'var(--bg-tertiary)',
                color: 'var(--text-secondary)', border: 'none', cursor: 'pointer',
                display: 'flex', alignItems: 'center' }}
            >
              <X size={14} />
            </button>
          </div>
        </div>

        {/* ── Tab bar ── */}
        <div style={S.tabBar}>
          {TABS.map(({ id, label, icon: Icon }) => {
            const active = activeTab === id;
            const totalAlerts = (checkSummary.critical || 0) + (checkSummary.high || 0)
              + (checkSummary.medium || 0) + (checkSummary.low || 0);
            const badge = id === 'alerts' && totalAlerts > 0 ? totalAlerts : null;
            return (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '9px 13px', fontSize: 11, fontWeight: active ? 700 : 500,
                  color: active ? 'var(--accent-primary)' : 'var(--text-secondary)',
                  background: 'none', border: 'none', cursor: 'pointer',
                  borderBottom: active ? '2px solid var(--accent-primary)' : '2px solid transparent',
                  whiteSpace: 'nowrap', transition: 'color 0.15s',
                }}
              >
                <Icon size={11} />
                {label}
                {badge && (
                  <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 8,
                    background: 'rgba(239,68,68,0.15)', color: '#ef4444', marginLeft: 2 }}>
                    {badge > 99 ? '99+' : badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* ── Body ── */}
        {loading ? (
          <PanelSkeleton />
        ) : error ? (
          <div style={{ ...S.body, display: 'flex', flexDirection: 'column', alignItems: 'center',
            justifyContent: 'center', gap: 10, color: 'var(--text-secondary)' }}>
            <AlertTriangle size={20} style={{ color: '#f97316' }} />
            <span style={{ fontSize: 12 }}>{error}</span>
            <button onClick={() => load()}
              style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11,
                color: 'var(--accent-primary)', background: 'none', border: 'none', cursor: 'pointer' }}>
              <RefreshCw size={12} /> Retry
            </button>
          </div>
        ) : (
          <div style={S.body}>
            {activeTab === 'summary' && (
              <SummaryTab asset={asset} posture={posture} checkSummary={checkSummary} complianceScore={complianceScore} />
            )}
            {activeTab === 'posture' && <PostureTab posture={posture} />}
            {activeTab === 'compliance' && <ComplianceTab score={complianceScore} asset={asset} />}
            {activeTab === 'alerts' && (
              <AlertsTab
                checkFindings={findings.length > 0 ? findings : checkFindings}
                checkSummary={checkSummary}
              />
            )}
          </div>
        )}

      </div>
    </>
  );
}

// ── Summary tab ────────────────────────────────────────────────────────────────
function SummaryTab({ asset, posture, checkSummary, complianceScore }) {
  const totalFindings = (checkSummary.critical || 0) + (checkSummary.high || 0)
    + (checkSummary.medium || 0) + (checkSummary.low || 0);

  return (
    <>
      {/* Identity */}
      <div style={S.section}>
        <div style={S.sectionHead}><Cloud size={11} /> Identity</div>
        {[
          ['Resource UID',  asset.resource_uid],
          ['Type',          asset.resource_type],
          ['Service',       asset.service],
          ['Provider',      (asset.provider || '').toUpperCase()],
          ['Account',       asset.account_id],
          ['Region',        asset.region],
        ].map(([k, v]) => v ? (
          <div key={k} style={{ ...S.row, borderBottom: '1px solid var(--border-primary)' }}>
            <span style={S.label}>{k}</span>
            <span style={S.value}>{v}</span>
          </div>
        ) : null)}
      </div>

      {/* Risk signals */}
      <div style={S.section}>
        <div style={S.sectionHead}><Shield size={11} /> Risk Signals</div>
        <div style={{ padding: '8px 12px', display: 'flex', flexWrap: 'wrap', gap: 5 }}>
          {posture.is_on_attack_path && <AttackPathBadge />}
          {posture.is_crown_jewel && <CrownJewelBadge crownType={posture.crown_jewel_type} />}
          {posture.is_choke_point && <ChokepointBadge />}
          {posture.is_internet_exposed && <ExposureBadge />}
          {posture.has_known_exploit && (
            <span style={{ ...S.pill('#ef4444', 'rgba(239,68,68,0.13)'), gap: 4 }}>
              <AlertTriangle size={10} /> Known Exploit
            </span>
          )}
          {posture.has_priv_escalation_path && (
            <span style={{ ...S.pill('#f97316', 'rgba(249,115,22,0.13)'), gap: 4 }}>
              <ChevronRight size={10} /> Priv Escalation
            </span>
          )}
          {!posture.is_on_attack_path && !posture.is_crown_jewel && !posture.is_internet_exposed && (
            <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>No critical signals</span>
          )}
        </div>
        {posture.overall_posture_score > 0 && (
          <div style={{ ...S.row, borderTop: '1px solid var(--border-primary)' }}>
            <span style={S.label}>Posture Score</span>
            <RiskScore score={posture.overall_posture_score} />
          </div>
        )}
        {posture.blast_radius_count > 0 && (
          <div style={{ ...S.row, borderTop: '1px solid var(--border-primary)' }}>
            <span style={S.label}>Blast Radius</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: '#f97316' }}>
              {posture.blast_radius_count} assets
            </span>
          </div>
        )}
      </div>

      {/* Findings summary */}
      {totalFindings > 0 && (
        <div style={S.section}>
          <div style={S.sectionHead}><AlertTriangle size={11} /> Findings</div>
          <div style={{ padding: '8px 12px' }}>
            <FindingsBar
              critical={checkSummary.critical || 0}
              high={checkSummary.high || 0}
              medium={checkSummary.medium || 0}
              low={checkSummary.low || 0}
            />
          </div>
        </div>
      )}

      {/* Drift */}
      <div style={S.section}>
        <div style={S.sectionHead}><RefreshCw size={11} /> Drift</div>
        {asset.drift_detected && (
          <div style={{ ...S.row, borderBottom: '1px solid var(--border-primary)', background: 'rgba(249,115,22,0.06)' }}>
            <span style={S.label}>Config Changed</span>
            <span style={{ ...S.pill('#f97316', 'rgba(249,115,22,0.15)') }}>Drift Detected</span>
          </div>
        )}
        {!asset.drift_detected && (
          <div style={{ ...S.row, borderBottom: '1px solid var(--border-primary)' }}>
            <span style={S.label}>Config Changed</span>
            <span style={{ ...S.pill('#22c55e', 'rgba(34,197,94,0.12)') }}>Stable</span>
          </div>
        )}
        {[
          ['First Seen', asset.first_seen_at || asset.created_at],
          ['Last Seen',  asset.last_seen_at  || asset.last_scanned],
        ].map(([k, v]) => v ? (
          <div key={k} style={{ ...S.row, borderBottom: '1px solid var(--border-primary)' }}>
            <span style={S.label}>{k}</span>
            <span style={S.value}>{new Date(v).toLocaleString()}</span>
          </div>
        ) : null)}
        {asset.config_hash && (
          <div style={{ ...S.row, borderBottom: 'none' }}>
            <span style={S.label}>Config Hash</span>
            <span style={{ ...S.value, fontSize: 10 }}>{asset.config_hash.slice(0, 16)}…</span>
          </div>
        )}
      </div>
    </>
  );
}

// ── Findings tab ───────────────────────────────────────────────────────────────
function FindingsTab({ findings, total, page, pageSize, onPage }) {
  if (!findings.length) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
        padding: 32, gap: 8, color: 'var(--text-secondary)' }}>
        <CheckCircle2 size={24} style={{ color: '#22c55e' }} />
        <span style={{ fontSize: 12 }}>No open findings</span>
      </div>
    );
  }

  const totalPages = Math.ceil(total / pageSize);

  return (
    <>
      <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 10 }}>
        {total} finding{total !== 1 ? 's' : ''} · showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {findings.map((f) => (
          <FindingRow key={f.finding_id || f.source_finding_id} finding={f} />
        ))}
      </div>
      {totalPages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 14 }}>
          <button
            disabled={page === 1}
            onClick={() => onPage(page - 1)}
            style={{ fontSize: 11, padding: '4px 10px', borderRadius: 5,
              background: 'var(--bg-tertiary)', color: 'var(--text-secondary)',
              border: 'none', cursor: page === 1 ? 'not-allowed' : 'pointer',
              opacity: page === 1 ? 0.4 : 1 }}
          >Prev</button>
          <span style={{ fontSize: 11, color: 'var(--text-tertiary)', alignSelf: 'center' }}>
            {page} / {totalPages}
          </span>
          <button
            disabled={page >= totalPages}
            onClick={() => onPage(page + 1)}
            style={{ fontSize: 11, padding: '4px 10px', borderRadius: 5,
              background: 'var(--bg-tertiary)', color: 'var(--text-secondary)',
              border: 'none', cursor: page >= totalPages ? 'not-allowed' : 'pointer',
              opacity: page >= totalPages ? 0.4 : 1 }}
          >Next</button>
        </div>
      )}
    </>
  );
}

function FindingRow({ finding }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      onClick={() => setExpanded(e => !e)}
      style={{ background: 'var(--bg-secondary)', borderRadius: 7,
        border: '1px solid var(--border-primary)', cursor: 'pointer',
        overflow: 'hidden', transition: 'border-color 0.15s' }}
    >
      <div style={{ padding: '8px 10px', display: 'flex', alignItems: 'flex-start', gap: 8 }}>
        <SeverityBadge severity={finding.severity} size="sm" />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: expanded ? 'normal' : 'nowrap' }}>
            {finding.title || finding.rule_id || 'Finding'}
          </div>
          <div style={{ display: 'flex', gap: 4, marginTop: 4, flexWrap: 'wrap' }}>
            <SourceEngineBadge engine={finding.source_engine} size="sm" />
            <FindingTypeBadge type={finding.finding_type} size="sm" />
            {finding.in_kev && (
              <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 4,
                background: 'rgba(239,68,68,0.15)', color: '#ef4444' }}>KEV</span>
            )}
            {finding.epss_score > 0 && (
              <span style={{ fontSize: 9, fontWeight: 600, padding: '1px 5px', borderRadius: 4,
                background: 'rgba(249,115,22,0.12)', color: '#f97316' }}>
                EPSS {(finding.epss_score * 100).toFixed(1)}%
              </span>
            )}
          </div>
        </div>
        <ChevronRight size={12} style={{ flexShrink: 0, color: 'var(--text-tertiary)',
          transform: expanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s' }} />
      </div>
      {expanded && finding.description && (
        <div style={{ padding: '0 10px 10px', fontSize: 11, color: 'var(--text-secondary)',
          lineHeight: 1.5, borderTop: '1px solid var(--border-primary)', paddingTop: 8 }}>
          {finding.description}
          {finding.mitre_technique_id && (
            <div style={{ marginTop: 6, fontSize: 10, color: 'var(--text-tertiary)' }}>
              MITRE: {finding.mitre_technique_id}
              {finding.mitre_tactic && ` · ${finding.mitre_tactic}`}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Posture tab ────────────────────────────────────────────────────────────────
function PostureTab({ posture }) {
  if (!posture || Object.keys(posture).length === 0) {
    return (
      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-secondary)', fontSize: 12 }}>
        No posture data available for this asset.
      </div>
    );
  }

  return (
    <>
      {/* Network */}
      <div style={S.section}>
        <div style={S.sectionHead}><Network size={11} /> Network</div>
        <SignalRow label="Internet Exposed"   value={posture.is_internet_exposed} />
        <SignalRow label="In Private Subnet"  value={posture.is_in_private_subnet} invert trueColor="#22c55e" falseColor="#64748b" />
        {posture.network_exposure_score > 0 && (
          <div style={{ ...S.row, borderTop: '1px solid var(--border-primary)' }}>
            <span style={S.label}>Exposure Score</span>
            <RiskScore score={posture.network_exposure_score} size="sm" />
          </div>
        )}
      </div>

      {/* IAM */}
      <div style={S.section}>
        <div style={S.sectionHead}><Shield size={11} /> IAM</div>
        <SignalRow label="Admin Role"              value={posture.is_admin_role} />
        <SignalRow label="Wildcard Policy"         value={posture.role_has_wildcard_policy} />
        <SignalRow label="MFA Enforced"            value={posture.mfa_enforced} invert trueColor="#22c55e" falseColor="#ef4444" />
        <SignalRow label="Priv Escalation Path"    value={posture.has_priv_escalation_path} />
        <SignalRow label="CDR-Confirmed Escalation" value={posture.priv_escalation_cdr_confirmed} />
      </div>

      {/* Encryption */}
      <div style={S.section}>
        <div style={S.sectionHead}><Lock size={11} /> Encryption</div>
        <SignalRow label="Encrypted at Rest"    value={posture.is_encrypted_at_rest}    invert trueColor="#22c55e" falseColor="#ef4444" />
        <SignalRow label="KMS-Managed Key"      value={posture.has_kms_managed_key}     invert trueColor="#22c55e" falseColor="#64748b" />
        {posture.cert_days_remaining > 0 && (
          <div style={{ ...S.row, borderTop: '1px solid var(--border-primary)' }}>
            <span style={S.label}>Cert Expiry</span>
            <span style={{ fontSize: 12, color: posture.cert_days_remaining < 30 ? '#ef4444' : '#22c55e', fontWeight: 600 }}>
              {posture.cert_days_remaining}d
            </span>
          </div>
        )}
      </div>

      {/* Data */}
      <div style={S.section}>
        <div style={S.sectionHead}><Eye size={11} /> Data</div>
        <SignalRow label="Exfil Path Detected"   value={posture.has_exfil_path} />
        <SignalRow label="Unencrypted PII Store"  value={posture.unencrypted_pii_store} />
        <SignalRow label="Internet-Exposed PII"   value={posture.internet_exposed_with_pii} />
        {posture.data_classification && posture.data_classification !== 'unknown' && (
          <div style={{ ...S.row, borderTop: '1px solid var(--border-primary)' }}>
            <span style={S.label}>Classification</span>
            <span style={S.value}>{posture.data_classification}</span>
          </div>
        )}
        {posture.reachable_pii_store_count > 0 && (
          <div style={{ ...S.row, borderTop: '1px solid var(--border-primary)' }}>
            <span style={S.label}>Reachable PII Stores</span>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#ec4899' }}>
              {posture.reachable_pii_store_count}
            </span>
          </div>
        )}
      </div>

      {/* CDR */}
      {(posture.has_active_cdr_actor || posture.cdr_actor_count > 0) && (
        <div style={S.section}>
          <div style={S.sectionHead}><Radar size={11} /> CDR Activity</div>
          <SignalRow label="Active Actor"  value={posture.has_active_cdr_actor} />
          {posture.cdr_actor_count > 0 && (
            <div style={{ ...S.row, borderTop: '1px solid var(--border-primary)' }}>
              <span style={S.label}>Actor Count</span>
              <span style={{ fontSize: 12, fontWeight: 600, color: '#eab308' }}>
                {posture.cdr_actor_count}
              </span>
            </div>
          )}
        </div>
      )}

      {/* Vulnerability */}
      {(posture.vuln_critical_count > 0 || posture.vuln_high_count > 0) && (
        <div style={S.section}>
          <div style={S.sectionHead}><AlertTriangle size={11} /> Vulnerabilities</div>
          {posture.vuln_critical_count > 0 && (
            <div style={S.row}>
              <span style={S.label}>Critical CVEs</span>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#ef4444' }}>{posture.vuln_critical_count}</span>
            </div>
          )}
          {posture.vuln_high_count > 0 && (
            <div style={S.row}>
              <span style={S.label}>High CVEs</span>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#f97316' }}>{posture.vuln_high_count}</span>
            </div>
          )}
          <SignalRow label="Known Exploit (KEV)" value={posture.has_known_exploit} />
        </div>
      )}
    </>
  );
}

// ── Compliance tab ─────────────────────────────────────────────────────────────
function ComplianceTab({ score, asset }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '28px 16px', gap: 16 }}>
      {score != null ? (
        <>
          <div style={{ fontSize: 48, fontWeight: 900, color: score >= 80 ? '#22c55e' : score >= 50 ? '#eab308' : '#ef4444' }}>
            {score}<span style={{ fontSize: 20, fontWeight: 500 }}>%</span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Overall Compliance Score</div>
        </>
      ) : (
        <>
          <CheckCircle2 size={28} style={{ color: 'var(--text-tertiary)' }} />
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>No compliance data for this asset</span>
        </>
      )}
      <button
        style={{ marginTop: 8, fontSize: 11, fontWeight: 600, color: 'var(--accent-primary)',
          background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}
        onClick={() => window.location.href = `/compliance?resource=${encodeURIComponent(asset.resource_uid || '')}`}
      >
        View full report <ExternalLink size={11} />
      </button>
    </div>
  );
}

// ── Alerts tab — failed checks only (Orca-style) ─────────────────────────────
const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#64748b' };
const SEV_ICON  = { critical: '◆', high: '▲', medium: '▲', low: '●' };

function AlertsTab({ checkFindings, checkSummary }) {
  // Only failed findings — filter out anything that explicitly passed
  const alerts = checkFindings.filter(f => {
    const st = (f.status || '').toLowerCase();
    return st !== 'pass' && st !== 'passed';
  });

  const totalFailed = alerts.length
    || ((checkSummary.critical || 0) + (checkSummary.high || 0)
        + (checkSummary.medium || 0) + (checkSummary.low || 0));

  if (!totalFailed) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
        padding: 40, gap: 10, color: 'var(--text-secondary)' }}>
        <CheckCircle2 size={28} style={{ color: '#22c55e' }} />
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>No alerts</span>
        <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>All checks passed for this asset</span>
      </div>
    );
  }

  return (
    <>
      {/* Severity summary bar — Orca style */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', marginRight: 4 }}>
          {totalFailed} Alert{totalFailed !== 1 ? 's' : ''}
        </span>
        {SEV_ORDER.map(s => {
          const count = checkSummary[s] || 0;
          if (!count) return null;
          return (
            <span key={s} style={{ ...S.pill(SEV_COLOR[s], `${SEV_COLOR[s]}18`),
              fontSize: 10, padding: '3px 8px', gap: 3 }}>
              {SEV_ICON[s]} {count} {s.charAt(0).toUpperCase() + s.slice(1)}
            </span>
          );
        })}
      </div>

      {/* Alert rows */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {alerts.length > 0
          ? alerts.map((f, i) => <AlertRow key={f.finding_id || f.source_finding_id || i} finding={f} />)
          : /* checkFindings empty but summary has counts — summary-only view */
            SEV_ORDER.map(s => {
              const count = checkSummary[s] || 0;
              if (!count) return null;
              return (
                <div key={s} style={{ ...S.row, borderBottom: '1px solid var(--border-primary)',
                  background: 'var(--bg-secondary)', borderRadius: 7, border: '1px solid var(--border-primary)' }}>
                  <span style={{ ...S.pill(SEV_COLOR[s], `${SEV_COLOR[s]}18`), fontSize: 10 }}>
                    {SEV_ICON[s]} {s.toUpperCase()}
                  </span>
                  <span style={{ fontSize: 12, fontWeight: 700, color: SEV_COLOR[s] }}>{count}</span>
                </div>
              );
            })
        }
      </div>
    </>
  );
}

function AlertRow({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const sev = (finding.severity || 'low').toLowerCase();
  const sevColor = SEV_COLOR[sev] || '#64748b';

  return (
    <div
      onClick={() => setExpanded(e => !e)}
      style={{ background: 'var(--bg-secondary)', borderRadius: 7,
        border: '1px solid rgba(239,68,68,0.18)', cursor: 'pointer', overflow: 'hidden' }}
    >
      {/* Row header */}
      <div style={{ padding: '9px 10px', display: 'flex', alignItems: 'flex-start', gap: 8 }}>
        {/* Severity dot */}
        <span style={{ marginTop: 3, fontSize: 10, color: sevColor, flexShrink: 0, fontWeight: 700 }}>
          {SEV_ICON[sev] || '●'}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: expanded ? 'normal' : 'nowrap' }}>
            {finding.title || finding.rule_id || 'Alert'}
          </div>
          <div style={{ display: 'flex', gap: 5, marginTop: 3, flexWrap: 'wrap', alignItems: 'center' }}>
            {/* FAIL badge — always shown */}
            <span style={{ ...S.pill('#ef4444', 'rgba(239,68,68,0.12)'), fontSize: 9, fontWeight: 800 }}>
              FAIL
            </span>
            {finding.severity && (
              <span style={{ ...S.pill(sevColor, `${sevColor}18`), fontSize: 9 }}>
                {finding.severity.toUpperCase()}
              </span>
            )}
            {finding.service && (
              <span style={{ fontSize: 10, color: 'var(--text-tertiary)' }}>{finding.service}</span>
            )}
          </div>
        </div>
        <ChevronRight size={12} style={{ flexShrink: 0, color: 'var(--text-tertiary)', marginTop: 2,
          transform: expanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s' }} />
      </div>

      {/* Expanded details */}
      {expanded && (
        <div style={{ borderTop: '1px solid var(--border-primary)', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {finding.description && (
            <p style={{ margin: 0, fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.55 }}>
              {finding.description}
            </p>
          )}
          {finding.recommendation && (
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5,
              padding: '7px 10px', background: 'rgba(34,197,94,0.07)', borderRadius: 5,
              borderLeft: '2px solid #22c55e' }}>
              <strong style={{ color: '#22c55e' }}>Fix: </strong>{finding.recommendation}
            </div>
          )}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, fontSize: 10, color: 'var(--text-tertiary)' }}>
            {finding.rule_id && (
              <span>Rule: <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{finding.rule_id}</span></span>
            )}
            {finding.control_id && <span>Control: {finding.control_id}</span>}
            {finding.framework && <span>Framework: {finding.framework}</span>}
          </div>
        </div>
      )}
    </div>
  );
}
