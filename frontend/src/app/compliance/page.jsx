'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import {
  Shield, ChevronRight, ChevronDown, CheckCircle, XCircle,
  AlertTriangle, ArrowLeft, Search, Download, X, FileText,
  Server, ExternalLink, Clock,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import { TENANT_ID } from '@/lib/constants';
import SeverityBadge from '@/components/shared/SeverityBadge';

/* ─── Colors ─────────────────────────────────────────────── */
const C = {
  pass: '#22c55e', fail: '#ef4444', partial: '#f59e0b', na: '#6b7280',
  blue: '#3b82f6', bg: 'var(--bg-card)', border: 'var(--border-primary)',
};

const statusIcon = (s) => {
  if (s === 'PASS') return <CheckCircle size={16} style={{ color: C.pass }} />;
  if (s === 'FAIL') return <XCircle size={16} style={{ color: C.fail }} />;
  if (s === 'PARTIAL') return <AlertTriangle size={16} style={{ color: C.partial }} />;
  return <span style={{ color: C.na, fontSize: 12 }}>--</span>;
};

const pct = (n, d) => d > 0 ? Math.round(100 * n / d) : 0;

/* ═══════════════════════════════════════════════════════════
   Main Compliance Page — Orca-style single page
   ═══════════════════════════════════════════════════════════ */
export default function CompliancePage() {
  // ── State ──
  const [loading, setLoading] = useState(true);
  const [frameworks, setFrameworks] = useState([]);
  const [selectedFw, setSelectedFw] = useState(null);    // framework row clicked
  const [fwDetail, setFwDetail] = useState(null);         // framework assessment detail
  const [fwLoading, setFwLoading] = useState(false);
  const [controlPanel, setControlPanel] = useState(null); // slide-out control
  const [panelFindings, setPanelFindings] = useState([]);
  const [panelLoading, setPanelLoading] = useState(false);
  const [panelTab, setPanelTab] = useState('info');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedSections, setExpandedSections] = useState(new Set());

  // ── Fetch frameworks list ──
  useEffect(() => {
    setLoading(true);
    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    fetch(`${origin}/gateway/api/v1/views/compliance?tenant_id=${TENANT_ID || 'default-tenant'}`)
      .then(r => r.json())
      .then(d => {
        setFrameworks(d.frameworks || []);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  // ── Fetch framework detail when selected ──
  useEffect(() => {
    if (!selectedFw) { setFwDetail(null); return; }
    setFwLoading(true);
    setExpandedSections(new Set());
    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    fetch(`${origin}/gateway/api/v1/views/compliance/framework/${selectedFw.id}?tenant_id=${TENANT_ID || 'default-tenant'}`)
      .then(r => r.json())
      .then(d => setFwDetail(d))
      .catch(() => setFwDetail(null))
      .finally(() => setFwLoading(false));
  }, [selectedFw]);

  // ── Fetch control findings when panel opened ──
  const [controlDetail, setControlDetail] = useState(null);

  const openControlPanel = useCallback((ctrl) => {
    setControlPanel(ctrl);
    setControlDetail(null);
    setPanelTab('info');
    setPanelFindings([]);
    setPanelLoading(true);
    // Extract short control_id: cis_aws_aws_5.10_0059 → 5.10
    const parts = (ctrl.control_id || '').split('_');
    const numParts = parts.filter(p => /^\d/.test(p));
    const shortId = numParts.length > 0 ? numParts[0] : ctrl.control_id;
    const fwName = selectedFw?.name || selectedFw?.id || '';
    // Fetch findings + full control detail in parallel
    Promise.all([
      getFromEngine('compliance', '/api/v1/compliance/findings/by-control', {
        control_id: shortId, framework: fwName, limit: 50,
      }).catch(() => ({ findings: [] })),
      getFromEngine('compliance', `/api/v1/compliance/control/${ctrl.control_id}`, {}).catch(() => null),
    ]).then(([findingsData, detailData]) => {
      setPanelFindings(findingsData?.findings || []);
      setControlDetail(detailData);
    }).finally(() => setPanelLoading(false));
  }, [selectedFw]);

  // ── Computed totals ──
  const totals = useMemo(() => {
    const pass = frameworks.reduce((s, f) => s + (f.passed || 0), 0);
    const fail = frameworks.reduce((s, f) => s + (f.failed || 0), 0);
    const total = pass + fail || 1;
    return { pass, fail, total, score: pct(pass, total), byAsset: 0 };
  }, [frameworks]);

  // ── Toggle section accordion ──
  const toggleSection = (family) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      next.has(family) ? next.delete(family) : next.add(family);
      return next;
    });
  };

  // ═══ RENDER ═══
  return (
    <div style={{ padding: '20px 24px', maxWidth: '100%', position: 'relative' }}>
      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
        {selectedFw && (
          <button onClick={() => setSelectedFw(null)}
            style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 12px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 13 }}>
            <ArrowLeft size={14} /> Back
          </button>
        )}
        <Shield size={22} style={{ color: 'var(--accent-primary)' }} />
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            {selectedFw ? (selectedFw.name || selectedFw.id) : 'Compliance'}
          </h1>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
            {selectedFw ? `${fwDetail?.total_controls || '...'} controls` : `${frameworks.length} frameworks`}
          </p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          {selectedFw && (
            <>
              <button onClick={() => {
                const origin = typeof window !== 'undefined' ? window.location.origin : '';
                window.open(`${origin}/gateway/api/v1/views/compliance/framework/${selectedFw.id}/report?tenant_id=${TENANT_ID || 'default-tenant'}&format=csv`, '_blank');
              }} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 }}>
                <Download size={14} /> CSV
              </button>
              <button onClick={() => {
                const origin = typeof window !== 'undefined' ? window.location.origin : '';
                window.open(`${origin}/gateway/api/v1/views/compliance/framework/${selectedFw.id}/report?tenant_id=${TENANT_ID || 'default-tenant'}&format=json`, '_blank');
              }} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 }}>
                <Download size={14} /> JSON
              </button>
            </>
          )}
          <button style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 13 }}>
            <Download size={14} /> Export
          </button>
        </div>
      </div>

      {/* ── Score Strip ── */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 20, flexWrap: 'wrap' }}>
        <ScoreCard label="Compliance Score" sublabel="By Control"
          value={selectedFw && fwDetail ? `${fwDetail.score}%` : `${totals.score}%`}
          color={totals.score >= 70 ? C.pass : totals.score >= 40 ? C.partial : C.fail} />
        {selectedFw && fwDetail && (
          <div style={{ display: 'flex', gap: 24, padding: '16px 24px', borderRadius: 12, border: `1px solid ${C.border}`, backgroundColor: C.bg, flex: 1 }}>
            <MiniStat label="Pass" value={fwDetail.summary?.PASS || 0} color={C.pass} />
            <MiniStat label="Fail" value={fwDetail.summary?.FAIL || 0} color={C.fail} />
            <MiniStat label="Partial" value={fwDetail.summary?.PARTIAL || 0} color={C.partial} />
            <MiniStat label="N/A" value={fwDetail.summary?.NOT_APPLICABLE || 0} color={C.na} />
          </div>
        )}
      </div>

      {/* ═══ FRAMEWORKS LIST VIEW — Clean table ═══ */}
      {!selectedFw && (
        <div style={{ borderRadius: 12, border: `1px solid ${C.border}`, overflow: 'hidden', backgroundColor: C.bg }}>
          <div style={{ padding: '12px 20px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{frameworks.length} Frameworks</span>
            <div style={{ position: 'relative', width: 220 }}>
              <Search size={14} style={{ position: 'absolute', left: 10, top: 9, color: 'var(--text-muted)' }} />
              <input value={searchTerm} onChange={e => setSearchTerm(e.target.value)} placeholder="Filter..."
                style={{ width: '100%', padding: '7px 12px 7px 30px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: 12, outline: 'none' }} />
            </div>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)' }}>
                {['Framework', 'Provider', 'Score', 'Controls', 'Findings', ''].map(h => (
                  <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading...</td></tr>
              ) : frameworks
                  .filter(fw => !searchTerm || (fw.name || fw.id || '').toLowerCase().includes(searchTerm.toLowerCase()))
                  .map((fw, i) => {
                const passed = fw.passed || 0;
                const failed = fw.failed || 0;
                const total = fw.controls || (passed + failed) || 0;
                const score = fw.score || pct(passed, total);
                const scoreCol = score >= 70 ? C.pass : score >= 40 ? C.partial : C.fail;
                const provider = (fw.provider || 'multi').toUpperCase();
                const providerColors = {
                  AWS: '#f59e0b', AZURE: '#3b82f6', GCP: '#ef4444', OCI: '#a855f7',
                  IBM: '#06b6d4', ALICLOUD: '#f97316', MULTI: '#6b7280',
                };
                return (
                  <tr key={fw.id || i} onClick={() => setSelectedFw(fw)}
                    style={{ borderBottom: `1px solid ${C.border}`, cursor: 'pointer', transition: 'background 0.1s' }}
                    onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'}
                    onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <Shield size={16} style={{ color: 'var(--accent-primary)', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{fw.name || fw.id}</div>
                          {fw.version && <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>v{fw.version}</div>}
                        </div>
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, fontWeight: 700, backgroundColor: `${providerColors[provider] || providerColors.MULTI}20`, color: providerColors[provider] || providerColors.MULTI }}>
                        {provider}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <svg width="28" height="28" viewBox="0 0 36 36">
                          <circle cx="18" cy="18" r="15" fill="none" stroke="var(--bg-tertiary)" strokeWidth="3" />
                          <circle cx="18" cy="18" r="15" fill="none" stroke={scoreCol} strokeWidth="3"
                            strokeDasharray={`${score * 0.942} 94.2`} strokeLinecap="round" transform="rotate(-90 18 18)" />
                        </svg>
                        <span style={{ fontSize: 15, fontWeight: 700, color: scoreCol }}>{score}%</span>
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>{total}</div>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <Dot color={C.pass} count={passed} />
                        <Dot color={C.fail} count={failed} />
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{ fontSize: 14, fontWeight: 600, color: (fw.findings || failed) > 0 ? C.fail : C.pass }}>{fw.findings || failed}</span>
                    </td>
                    <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                      <ChevronRight size={16} style={{ color: 'var(--text-muted)' }} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ═══ FRAMEWORK DETAIL VIEW (accordion) ═══ */}
      {selectedFw && (
        <div>
          {/* Search */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center' }}>
            <div style={{ position: 'relative', flex: 1, maxWidth: 300 }}>
              <Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--text-muted)' }} />
              <input value={searchTerm} onChange={e => setSearchTerm(e.target.value)} placeholder="Search controls..."
                style={{ width: '100%', padding: '8px 12px 8px 30px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: 13, outline: 'none' }} />
            </div>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {fwDetail?.total_controls || 0} Control Tests
            </span>
            <button onClick={() => setExpandedSections(prev => prev.size > 0 ? new Set() : new Set((fwDetail?.families || []).map(f => f.family)))}
              style={{ fontSize: 12, color: 'var(--accent-primary)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}>
              {expandedSections.size > 0 ? 'Collapse All' : 'Expand All'}
            </button>
          </div>

          {fwLoading ? (
            <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-muted)' }}>Loading framework...</div>
          ) : (
            <div style={{ borderRadius: 12, border: `1px solid ${C.border}`, overflow: 'hidden', backgroundColor: C.bg }}>
              {/* Section header */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 80px 120px', padding: '10px 16px', borderBottom: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)' }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Section Name</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'center' }}>Score</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'center' }}>Control Tests</span>
              </div>

              {(fwDetail?.families || []).map((fam) => {
                const isOpen = expandedSections.has(fam.family);
                const famScore = pct(fam.pass, fam.total);
                const filteredControls = searchTerm
                  ? fam.controls.filter(c => (c.control_name || '').toLowerCase().includes(searchTerm.toLowerCase()) || (c.control_id || '').toLowerCase().includes(searchTerm.toLowerCase()))
                  : fam.controls;
                if (searchTerm && filteredControls.length === 0) return null;

                return (
                  <div key={fam.family}>
                    {/* Section row */}
                    <div onClick={() => toggleSection(fam.family)}
                      style={{ display: 'grid', gridTemplateColumns: '1fr 80px 120px', padding: '14px 16px', borderBottom: `1px solid ${C.border}`, cursor: 'pointer', transition: 'background 0.1s' }}
                      onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'}
                      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {isOpen ? <ChevronDown size={16} style={{ color: 'var(--text-muted)' }} /> : <ChevronRight size={16} style={{ color: 'var(--text-muted)' }} />}
                        <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{fam.family}</span>
                      </div>
                      <span style={{ fontSize: 14, fontWeight: 700, textAlign: 'center', color: famScore >= 70 ? C.pass : famScore >= 40 ? C.partial : C.fail }}>{famScore}%</span>
                      <div style={{ display: 'flex', gap: 6, justifyContent: 'center' }}>
                        <Dot color={C.pass} count={fam.pass} />
                        <Dot color={C.fail} count={fam.fail} />
                        <Dot color={C.na} count={fam.total - fam.pass - fam.fail} />
                      </div>
                    </div>

                    {/* Expanded controls */}
                    {isOpen && (
                      <div style={{ backgroundColor: 'var(--bg-secondary)' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                              {['Status', 'ID', 'Control', 'Severity', 'Findings', 'Resources'].map(h => (
                                <th key={h} style={{ padding: '8px 14px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{h}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {filteredControls.map((ctrl) => (
                              <tr key={ctrl.control_id} onClick={() => openControlPanel(ctrl)}
                                style={{ borderBottom: `1px solid ${C.border}`, cursor: 'pointer', transition: 'background 0.1s' }}
                                onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)'}
                                onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}>
                                <td style={{ padding: '10px 14px', width: 50 }}>{statusIcon(ctrl.status)}</td>
                                <td style={{ padding: '10px 14px', width: 180 }}>
                                  <code style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{ctrl.control_id?.slice(-15)}</code>
                                </td>
                                <td style={{ padding: '10px 14px' }}>
                                  <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>{ctrl.control_name || ctrl.control_id}</span>
                                </td>
                                <td style={{ padding: '10px 14px', width: 90 }}>
                                  {ctrl.severity && <SeverityBadge severity={ctrl.severity} />}
                                </td>
                                <td style={{ padding: '10px 14px', width: 80 }}>
                                  {ctrl.fail_count > 0 ? (
                                    <span onClick={(e) => { e.stopPropagation(); window.open(`/misconfig?control=${ctrl.control_id}`, '_blank'); }}
                                      style={{ fontSize: 12, fontWeight: 600, color: C.fail, cursor: 'pointer', textDecoration: 'underline' }}>
                                      <AlertTriangle size={12} style={{ verticalAlign: -2, marginRight: 4 }} />{ctrl.fail_count}
                                    </span>
                                  ) : (
                                    <span style={{ fontSize: 11, color: C.na }}>0</span>
                                  )}
                                </td>
                                <td style={{ padding: '10px 14px', width: 80 }}>
                                  {ctrl.total_resources > 0 ? (
                                    <span onClick={(e) => { e.stopPropagation(); window.open(`/inventory?control=${ctrl.control_id}`, '_blank'); }}
                                      style={{ fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer', textDecoration: 'underline' }}>
                                      {ctrl.total_resources}
                                    </span>
                                  ) : (
                                    <span style={{ fontSize: 11, color: C.na }}>—</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ═══ CONTROL DETAIL SLIDE-OUT PANEL ═══ */}
      {controlPanel && (
        <>
          <div onClick={() => setControlPanel(null)}
            style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.45)', zIndex: 40, backdropFilter: 'blur(2px)' }} />
          <div style={{
            position: 'fixed', top: 0, right: 0, bottom: 0, width: 560, zIndex: 50,
            backgroundColor: 'var(--bg-card)', borderLeft: `1px solid ${C.border}`,
            overflowY: 'auto', display: 'flex', flexDirection: 'column',
            boxShadow: '-8px 0 32px rgba(0,0,0,0.3)',
          }}>
            {/* Panel Header */}
            <div style={{ padding: '20px 24px', borderBottom: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {statusIcon(controlPanel.status)}
                  <span style={{ fontSize: 12, fontWeight: 700, color: controlPanel.status === 'PASS' ? C.pass : controlPanel.status === 'FAIL' ? C.fail : C.na }}>
                    {controlPanel.status}
                  </span>
                </div>
                <button onClick={() => setControlPanel(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 18 }}>
                  <X size={18} />
                </button>
              </div>
              <h2 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', margin: 0, lineHeight: 1.4 }}>
                {controlPanel.control_name || controlPanel.control_id}
              </h2>
              <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, backgroundColor: 'var(--accent-primary)', color: 'white', fontWeight: 600 }}>
                  {selectedFw?.name || selectedFw?.id}
                </span>
                {controlPanel.severity && <SeverityBadge severity={controlPanel.severity} />}
              </div>
            </div>

            {/* Panel Tabs */}
            <div style={{ display: 'flex', borderBottom: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)' }}>
              {[
                { id: 'info', label: 'Info' },
                { id: 'findings', label: `Findings (${panelFindings.length})` },
                { id: 'remediation', label: 'Remediation' },
              ].map(t => (
                <button key={t.id} onClick={() => setPanelTab(t.id)}
                  style={{
                    padding: '10px 20px', fontSize: 13, fontWeight: panelTab === t.id ? 700 : 500, border: 'none', cursor: 'pointer',
                    color: panelTab === t.id ? 'var(--accent-primary)' : 'var(--text-muted)',
                    borderBottom: panelTab === t.id ? '2px solid var(--accent-primary)' : '2px solid transparent',
                    backgroundColor: 'transparent',
                  }}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Panel Content */}
            <div style={{ padding: 24, flex: 1, overflowY: 'auto' }}>
              {/* Info Tab */}
              {panelTab === 'info' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                  {(controlDetail?.control_description || controlPanel.control_description) && (
                    <Section title="Description">
                      <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
                        {controlDetail?.control_description || controlPanel.control_description}
                      </p>
                    </Section>
                  )}
                  {controlDetail?.rationale && (
                    <Section title="Rationale">
                      <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>{controlDetail.rationale}</p>
                    </Section>
                  )}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <InfoBox label="Control ID" value={controlPanel.control_id} />
                    <InfoBox label="Family" value={controlPanel.control_family || controlPanel.domain} />
                    <InfoBox label="Assessment" value={controlPanel.assessment_type || 'automated'} />
                    <InfoBox label="Severity" value={controlPanel.severity || 'medium'} />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                    <StatBox label="Pass" value={controlPanel.pass_count || 0} color={C.pass} />
                    <StatBox label="Fail" value={controlPanel.fail_count || 0} color={C.fail} />
                    <StatBox label="Total" value={controlPanel.total_resources || 0} color={C.blue} />
                  </div>
                </div>
              )}

              {/* Findings Tab */}
              {panelTab === 'findings' && (
                <div>
                  {panelLoading ? (
                    <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-muted)' }}>Loading findings...</div>
                  ) : panelFindings.length === 0 ? (
                    <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-muted)' }}>No findings for this control</div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>{panelFindings.length} findings</div>
                      {panelFindings.map((f, i) => (
                        <div key={f.finding_id || i} style={{ padding: '12px 14px', borderRadius: 8, backgroundColor: 'var(--bg-secondary)', border: `1px solid ${C.border}` }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)' }}>{f.resource_type} · {f.region || 'global'}</div>
                            <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, backgroundColor: f.status === 'open' ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)', color: f.status === 'open' ? C.fail : C.pass, fontWeight: 600 }}>
                              {(f.check_result || f.status || '').toUpperCase()}
                            </span>
                          </div>
                          <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {f.resource_uid || f.resource_arn || '—'}
                          </div>
                          {f.checked_fields?.length > 0 && (
                            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 6 }}>
                              {f.checked_fields.map((cf, ci) => (
                                <code key={ci} style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>{cf}</code>
                              ))}
                            </div>
                          )}
                          {f.actual_values && Object.keys(f.actual_values).length > 0 && (
                            <pre style={{ fontSize: 9, margin: '6px 0 0', padding: 6, borderRadius: 4, backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)', overflow: 'auto', maxHeight: 60 }}>
                              {JSON.stringify(f.actual_values, null, 2)}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Remediation Tab */}
              {/* Remediation Tab — How to fix, CLI/Console/Terraform */}
              {panelTab === 'remediation' && (
                <RemediationTab controlDetail={controlDetail} findings={panelFindings} />
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ─── Remediation Tab Component ─────────────────────────────── */

function RemediationTab({ controlDetail, findings }) {
  const [activeMode, setActiveMode] = useState('console');
  const guidance = controlDetail?.implementation_guidance || '';
  const testing = controlDetail?.testing_procedures || '';
  const findingRem = findings?.[0]?.remediation || '';

  // Extract CLI commands from testing_procedures or remediation
  const extractCli = (text) => {
    if (!text) return null;
    const lines = text.split('\n');
    const cliLines = lines.filter(l => {
      const t = l.trim();
      return t.startsWith('aws ') || t.startsWith('az ') || t.startsWith('gcloud ') ||
             t.startsWith('kubectl ') || t.startsWith('ibmcloud ') || t.startsWith('aliyun ') ||
             t.startsWith('oci ') || t.startsWith('$ ');
    });
    return cliLines.length > 0 ? cliLines.join('\n') : null;
  };

  const cliFromTesting = extractCli(testing);
  const cliFromGuidance = extractCli(guidance);
  const cliContent = cliFromTesting || cliFromGuidance;

  // Console steps = the main guidance/remediation text
  const consoleContent = guidance || findingRem || null;

  const modes = [
    { id: 'cli', label: 'CLI', hasContent: !!cliContent },
    { id: 'console', label: 'Console', hasContent: !!consoleContent },
    { id: 'terraform', label: 'Terraform', hasContent: false },
    { id: 'pulumi', label: 'Pulumi', hasContent: false },
    { id: 'cloudformation', label: 'CloudFormation', hasContent: false },
    { id: 'arm', label: 'ARM', hasContent: false },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Mode selector — Orca style */}
      <div>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>
          Remediation Steps For
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {modes.map(m => (
            <button key={m.id} onClick={() => setActiveMode(m.id)}
              style={{
                padding: '7px 16px', borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: 'pointer',
                border: activeMode === m.id ? '2px solid var(--accent-primary)' : `1px solid ${C.border}`,
                backgroundColor: activeMode === m.id ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                color: activeMode === m.id ? 'white' : 'var(--text-secondary)',
                opacity: m.hasContent || m.id === activeMode ? 1 : 0.5,
              }}>
              {m.label}
              {m.hasContent && <span style={{ marginLeft: 4, fontSize: 9, color: activeMode === m.id ? 'white' : 'var(--accent-success)' }}>●</span>}
            </button>
          ))}
        </div>
      </div>

      {/* Content based on active mode */}
      {activeMode === 'cli' && (
        <div style={{ borderRadius: 8, backgroundColor: 'var(--bg-tertiary)', border: `1px solid ${C.border}`, overflow: 'hidden' }}>
          <div style={{ padding: '8px 14px', borderBottom: `1px solid ${C.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>CLI Commands</span>
          </div>
          <pre style={{ margin: 0, padding: 14, fontSize: 12, fontFamily: 'monospace', color: 'var(--text-primary)', whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>
            {cliContent || 'CLI remediation commands not available for this control.\n\nUse the Console tab for step-by-step remediation.'}
          </pre>
        </div>
      )}

      {activeMode === 'console' && (
        <Section title="Console Steps">
          {consoleContent ? (
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, margin: 0, whiteSpace: 'pre-wrap' }}>
              {consoleContent}
            </p>
          ) : (
            <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0 }}>Console remediation steps not available for this control.</p>
          )}
        </Section>
      )}

      {['terraform', 'pulumi', 'cloudformation', 'arm'].includes(activeMode) && (
        <Section title={`${modes.find(m => m.id === activeMode)?.label} Remediation`}>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0 }}>
            {modes.find(m => m.id === activeMode)?.label} remediation will be available in a future update.
          </p>
        </Section>
      )}
    </div>
  );
}

/* ─── Small components ─────────────────────────────────────── */

function ScoreCard({ label, sublabel, value, color }) {
  return (
    <div style={{ padding: '16px 24px', borderRadius: 12, border: `1px solid ${C.border}`, backgroundColor: C.bg }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{label}</div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span style={{ fontSize: 28, fontWeight: 800, color }}>{value}</span>
        {sublabel && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{sublabel}</span>}
      </div>
    </div>
  );
}

function MiniStat({ label, value, color }) {
  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, justifyContent: 'center' }}>
        <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: color }} />
        <span style={{ fontSize: 18, fontWeight: 700, color }}>{value}</span>
      </div>
      <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{label}</div>
    </div>
  );
}

function Dot({ color, count }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
      <div style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: color, flexShrink: 0 }} />
      <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>{count}</span>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <h3 style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>{title}</h3>
      <div style={{ padding: '12px 14px', borderRadius: 8, backgroundColor: 'var(--bg-secondary)', border: `1px solid ${C.border}` }}>
        {children}
      </div>
    </div>
  );
}

function InfoBox({ label, value }) {
  return (
    <div style={{ padding: '10px 12px', borderRadius: 8, backgroundColor: 'var(--bg-secondary)', border: `1px solid ${C.border}` }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-all' }}>{value || '—'}</div>
    </div>
  );
}

function StatBox({ label, value, color }) {
  return (
    <div style={{ padding: '12px', borderRadius: 8, backgroundColor: 'var(--bg-secondary)', border: `1px solid ${C.border}`, textAlign: 'center' }}>
      <div style={{ fontSize: 20, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{label}</div>
    </div>
  );
}
