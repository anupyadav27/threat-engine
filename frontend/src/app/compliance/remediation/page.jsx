'use client';

import { Shield, AlertTriangle, CheckCircle, Search } from 'lucide-react';
import { useState, useMemo } from 'react';
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

  const { failingControls = [], totalFailing = 0, bySeverity = {} } = data ?? {};

  /* Client-side filter + search (data is already severity-sorted from BFF) */
  const displayed = useMemo(() => {
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
              {displayed.length} result{displayed.length !== 1 ? 's' : ''}
            </span>
          </div>

          {/* Table */}
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)' }}>
                {['Framework', 'Control ID', 'Title', 'Severity', 'Affected Accounts', 'Last Checked'].map(h => (
                  <th key={h} style={{
                    padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600,
                    color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5,
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {displayed.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                    No controls match your filter.
                  </td>
                </tr>
              ) : displayed.map((ctrl, i) => (
                <tr
                  key={`${ctrl.framework}-${ctrl.control_id}-${i}`}
                  style={{ borderBottom: `1px solid ${C.border}`, transition: 'background 0.1s' }}
                  onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'; }}
                  onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'transparent'; }}
                >
                  {/* Framework */}
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{
                      fontSize: 11, padding: '2px 8px', borderRadius: 4, fontWeight: 700,
                      backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)',
                    }}>
                      {ctrl.framework || '—'}
                    </span>
                  </td>

                  {/* Control ID */}
                  <td style={{ padding: '12px 16px' }}>
                    <code style={{ fontSize: 11, color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                      {ctrl.control_id || '—'}
                    </code>
                  </td>

                  {/* Title */}
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>
                      {ctrl.control_title || ctrl.control_id || '—'}
                    </span>
                  </td>

                  {/* Severity */}
                  <td style={{ padding: '12px 16px' }}>
                    {ctrl.severity
                      ? <SeverityBadge severity={ctrl.severity.toLowerCase()} />
                      : <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>
                    }
                  </td>

                  {/* Affected Accounts */}
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                      {ctrl.affected_account_count ?? (ctrl.affected_accounts?.length ?? 0)}
                    </span>
                  </td>

                  {/* Last Checked */}
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      {ctrl.last_checked
                        ? new Date(ctrl.last_checked).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
                        : '—'
                      }
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
