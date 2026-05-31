'use client';

import { Shield, AlertTriangle, CheckCircle, Search, ChevronLeft, ChevronRight, Download } from 'lucide-react';
import { useState, useMemo, useEffect } from 'react';
import { useViewFetch } from '@/lib/use-view-fetch';
import SeverityBadge from '@/components/shared/SeverityBadge';

/* ─── Colour palette (mirrors compliance/page.jsx) ─── */
const C = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  pass:     '#22c55e',
  bg:       'var(--bg-card)',
  border:   'var(--border-primary)',
};

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const PAGE_SIZE = 25;

const sevColor = (s) => C[(s || '').toLowerCase()] || C.low;

/* ─── Summary chip ─── */
function SevChip({ label, count }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      padding: '8px 16px', borderRadius: 8,
      border: `1px solid ${C.border}`, backgroundColor: C.bg,
    }}>
      <div style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: sevColor(label), flexShrink: 0 }} />
      <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</span>
      <span style={{ fontSize: 18, fontWeight: 800, color: sevColor(label) }}>{count}</span>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════
   Compliance Remediation Queue page
   ════════════════════════════════════════════════════════════ */
export default function ComplianceRemediationPage() {
  const { data, loading, error } = useViewFetch('compliance/remediation');
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);

  const { failingControls = [], totalFailing = 0, bySeverity = {} } = data ?? {};

  /* Client-side filter + search across the full loaded dataset */
  const filtered = useMemo(() => {
    let rows = failingControls;
    if (severityFilter !== 'ALL') {
      rows = rows.filter(c => (c.severity || '').toUpperCase() === severityFilter);
    }
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      rows = rows.filter(c =>
        (c.control_title || '').toLowerCase().includes(term) ||
        (c.control_id    || '').toLowerCase().includes(term) ||
        (c.framework     || '').toLowerCase().includes(term),
      );
    }
    return rows;
  }, [failingControls, severityFilter, searchTerm]);

  /* Reset to page 1 whenever the filter/search changes */
  useEffect(() => { setCurrentPage(1); }, [severityFilter, searchTerm]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageStart  = (currentPage - 1) * PAGE_SIZE;
  const pageEnd    = pageStart + PAGE_SIZE;
  const displayed  = filtered.slice(pageStart, pageEnd);

  /* ── Loading ── */
  if (loading) {
    return (
      <div style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
          <Shield size={22} style={{ color: 'var(--accent-primary)' }} />
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>Remediation Queue</h1>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>Loading failing controls...</p>
          </div>
        </div>
        <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-muted)', backgroundColor: C.bg, borderRadius: 12, border: `1px solid ${C.border}` }}>
          Loading...
        </div>
      </div>
    );
  }

  /* ── Error ── */
  if (error) {
    return (
      <div style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
          <Shield size={22} style={{ color: 'var(--accent-primary)' }} />
          <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>Remediation Queue</h1>
        </div>
        <div style={{ padding: 40, textAlign: 'center', borderRadius: 12, border: `1px solid ${C.border}`, backgroundColor: C.bg }}>
          <AlertTriangle size={32} style={{ color: C.critical, marginBottom: 12 }} />
          <p style={{ color: 'var(--text-muted)', fontSize: 14, margin: 0 }}>{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: '20px 24px', maxWidth: '100%' }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
        <Shield size={22} style={{ color: 'var(--accent-primary)' }} />
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            Remediation Queue
            {totalFailing > 0 && (
              <span style={{ fontSize: 14, fontWeight: 600, color: C.critical, marginLeft: 10 }}>
                ({totalFailing} failing {totalFailing === 1 ? 'control' : 'controls'})
              </span>
            )}
          </h1>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
            Failing compliance controls sorted by severity
          </p>
        </div>
        <button
          onClick={() => {
            const header = ['Control ID', 'Title', 'Framework', 'Severity', 'Status', 'Resources'];
            const rows = failingControls.map(c => [
              c.control_id, c.control_title || c.title, c.framework, c.severity, c.status, c.resources ?? 0,
            ]);
            const csv = [header, ...rows].map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
            const a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' }));
            a.download = 'remediation_queue.csv';
            a.click();
          }}
          style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 }}
        >
          <Download size={14} /> Export CSV
        </button>
      </div>

      {/* ── Severity summary strip ── */}
      {totalFailing > 0 && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <SevChip key={sev} label={sev} count={bySeverity[sev] ?? 0} />
          ))}
        </div>
      )}

      {/* ── Empty state ── */}
      {totalFailing === 0 && (
        <div style={{
          padding: '60px 20px', textAlign: 'center', borderRadius: 12,
          border: `1px solid ${C.border}`, backgroundColor: C.bg,
        }}>
          <CheckCircle size={48} style={{ color: C.pass, marginBottom: 16 }} />
          <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 8px' }}>
            No failing controls — great job!
          </h2>
          <p style={{ fontSize: 14, color: 'var(--text-muted)', margin: 0 }}>
            All compliance controls are passing. Run a new scan to refresh results.
          </p>
        </div>
      )}

      {/* ── Table ── */}
      {totalFailing > 0 && (
        <div style={{ borderRadius: 12, border: `1px solid ${C.border}`, overflow: 'hidden', backgroundColor: C.bg }}>

          {/* Toolbar */}
          <div style={{
            padding: '12px 20px', borderBottom: `1px solid ${C.border}`,
            display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap',
          }}>
            {/* Search */}
            <div style={{ position: 'relative', flex: '1 1 220px', maxWidth: 300 }}>
              <Search size={14} style={{ position: 'absolute', left: 10, top: 9, color: 'var(--text-muted)' }} />
              <input
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Filter controls..."
                style={{
                  width: '100%', padding: '7px 12px 7px 30px', borderRadius: 8,
                  border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)',
                  color: 'var(--text-primary)', fontSize: 12, outline: 'none',
                }}
              />
            </div>

            {/* Severity filter pills */}
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  style={{
                    padding: '5px 12px', borderRadius: 6, fontSize: 11, fontWeight: 700, cursor: 'pointer',
                    border: severityFilter === sev ? `2px solid var(--accent-primary)` : `1px solid ${C.border}`,
                    backgroundColor: severityFilter === sev ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                    color: severityFilter === sev ? 'white' : 'var(--text-secondary)',
                    textTransform: 'uppercase',
                  }}
                >
                  {sev}
                </button>
              ))}
            </div>

            <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
              {filtered.length < totalFailing
                ? `${filtered.length} matching · ${totalFailing} total`
                : `${totalFailing} control${totalFailing !== 1 ? 's' : ''}`}
            </span>
          </div>

          {/* Table */}
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <colgroup>
              <col style={{ width: '12%' }} />  {/* Framework */}
              <col style={{ width: '18%' }} />  {/* Control ID */}
              <col style={{ width: '28%' }} />  {/* Title */}
              <col style={{ width: '9%' }} />   {/* Severity */}
              <col style={{ width: '15%' }} />  {/* Account */}
              <col style={{ width: '9%' }} />   {/* Days Open */}
              <col style={{ width: '9%' }} />   {/* Last Checked */}
            </colgroup>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)' }}>
                {['Framework', 'Control ID', 'Title', 'Severity', 'Account', 'Days Open', 'Last Checked'].map(h => (
                  <th key={h} style={{
                    padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600,
                    color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5,
                    overflow: 'hidden',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {displayed.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                    No controls match your filter.
                  </td>
                </tr>
              ) : displayed.map((ctrl, i) => {
                const daysOpen = ctrl.days_open || 0;
                const daysColor = daysOpen > 90 ? '#ef4444' : daysOpen > 30 ? '#f59e0b' : 'var(--text-secondary)';
                const acctDisplay = ctrl.affected_account_names?.[0] || ctrl.affected_accounts?.[0] || '—';
                return (
                  <tr
                    key={`${ctrl.framework}-${ctrl.control_id}-${i}`}
                    style={{ borderBottom: `1px solid ${C.border}`, transition: 'background 0.1s' }}
                    onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'; }}
                    onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'transparent'; }}
                  >
                    {/* Framework */}
                    <td style={{ padding: '10px 16px', overflow: 'hidden' }}>
                      <span style={{
                        fontSize: 11, padding: '2px 8px', borderRadius: 4, fontWeight: 700,
                        backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)',
                        display: 'inline-block', maxWidth: '100%',
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }} title={ctrl.framework || ''}>
                        {ctrl.framework || '—'}
                      </span>
                    </td>

                    {/* Control ID */}
                    <td style={{ padding: '10px 16px', overflow: 'hidden' }}>
                      <code style={{
                        fontSize: 11, color: 'var(--text-tertiary)', fontFamily: 'monospace',
                        display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
                        overflow: 'hidden', wordBreak: 'break-all',
                      }} title={ctrl.control_id || ''}>
                        {ctrl.control_id || '—'}
                      </code>
                    </td>

                    {/* Title */}
                    <td style={{ padding: '10px 16px', overflow: 'hidden' }}>
                      <span style={{
                        fontSize: 13, color: 'var(--text-primary)',
                        display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
                        overflow: 'hidden', lineHeight: 1.4,
                      }} title={ctrl.control_title || ctrl.control_id || ''}>
                        {ctrl.control_title || ctrl.control_id || '—'}
                      </span>
                    </td>

                    {/* Severity */}
                    <td style={{ padding: '10px 16px' }}>
                      {ctrl.severity
                        ? <SeverityBadge severity={ctrl.severity.toLowerCase()} />
                        : <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>
                      }
                    </td>

                    {/* Account */}
                    <td style={{ padding: '10px 16px', overflow: 'hidden' }}>
                      <span style={{
                        fontSize: 12, color: 'var(--text-secondary)',
                        display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }} title={acctDisplay}>
                        {acctDisplay}
                      </span>
                    </td>

                    {/* Days Open */}
                    <td style={{ padding: '10px 16px' }}>
                      {daysOpen > 0 ? (
                        <span style={{ fontSize: 13, fontWeight: 700, color: daysColor }}>
                          {daysOpen}d
                        </span>
                      ) : (
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>

                    {/* Last Checked */}
                    <td style={{ padding: '10px 16px' }}>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {ctrl.last_checked
                          ? new Date(ctrl.last_checked).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
                          : '—'
                        }
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination footer */}
          {totalPages > 1 && (
            <div style={{
              padding: '12px 20px', borderTop: `1px solid ${C.border}`,
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              backgroundColor: 'var(--bg-secondary)',
            }}>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Showing {pageStart + 1}–{Math.min(pageEnd, filtered.length)} of {filtered.length}
                {filtered.length < totalFailing && ` (${totalFailing} total)`}
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    padding: '5px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                    cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                    border: `1px solid ${C.border}`,
                    backgroundColor: currentPage === 1 ? 'var(--bg-tertiary)' : 'var(--bg-card)',
                    color: currentPage === 1 ? 'var(--text-muted)' : 'var(--text-primary)',
                    opacity: currentPage === 1 ? 0.5 : 1,
                  }}
                >
                  <ChevronLeft size={13} /> Previous
                </button>
                <span style={{ fontSize: 12, color: 'var(--text-muted)', minWidth: 80, textAlign: 'center' }}>
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    padding: '5px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                    cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                    border: `1px solid ${C.border}`,
                    backgroundColor: currentPage === totalPages ? 'var(--bg-tertiary)' : 'var(--bg-card)',
                    color: currentPage === totalPages ? 'var(--text-muted)' : 'var(--text-primary)',
                    opacity: currentPage === totalPages ? 0.5 : 1,
                  }}
                >
                  Next <ChevronRight size={13} />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
