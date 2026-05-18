'use client';

import { useState, useEffect } from 'react';
import { Webhook, AlertTriangle, ShieldAlert, Shield, Globe, Lock } from 'lucide-react';
import { useViewFetch } from '@/lib/use-view-fetch';
import EngineShell from '@/components/shared/EngineShell';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';
import KpiSparkCard from '@/components/shared/KpiSparkCard';
import FindingDetailPanel from '@/components/shared/FindingDetailPanel';

// ── Colours ──────────────────────────────────────────────────────────────────
const C = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  purple:   '#8b5cf6',
  sky:      '#38bdf8',
  indigo:   '#6366f1',
};

// ── OWASP category labels ─────────────────────────────────────────────────────
const OWASP_LABELS = {
  API1: 'API1 · Broken Object Level Auth',
  API2: 'API2 · Broken Authentication',
  API4: 'API4 · Unrestricted Resource Consumption',
  API7: 'API7 · SSRF',
  API8: 'API8 · Security Misconfiguration',
  API9: 'API9 · Improper Inventory',
};

// ── Small stat pill ───────────────────────────────────────────────────────────
function StatPill({ label, value, color = '#6366f1' }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      background: 'rgba(255,255,255,0.04)', borderRadius: 8,
      padding: '4px 10px', fontSize: 13,
    }}>
      <span style={{ color: '#94a3b8' }}>{label}</span>
      <span style={{ color, fontWeight: 700 }}>{value ?? '—'}</span>
    </div>
  );
}

// ── OWASP category row ────────────────────────────────────────────────────────
function OWASPBar({ category, count, maxCount }) {
  const pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ color: '#94a3b8', fontSize: 12 }}>
          {OWASP_LABELS[category] || category}
        </span>
        <span style={{ color: '#f1f5f9', fontSize: 12, fontWeight: 600 }}>{count}</span>
      </div>
      <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.08)' }}>
        <div style={{
          height: '100%', borderRadius: 3,
          width: `${pct}%`,
          background: C.indigo,
          transition: 'width 0.4s ease',
        }} />
      </div>
    </div>
  );
}

// ── Finding row ───────────────────────────────────────────────────────────────
function FindingRow({ finding, onClick }) {
  return (
    <tr
      onClick={() => onClick(finding)}
      style={{ cursor: 'pointer' }}
      className="hover:bg-white/5 transition-colors"
    >
      <td style={{ padding: '10px 12px' }}>
        <SeverityBadge severity={finding.severity} />
      </td>
      <td style={{ padding: '10px 12px', color: '#f1f5f9', fontSize: 13 }}>
        {finding.title}
      </td>
      <td style={{ padding: '10px 12px' }}>
        <span style={{
          fontSize: 11, fontWeight: 600, color: C.purple,
          background: 'rgba(139,92,246,0.12)', borderRadius: 4, padding: '2px 6px',
        }}>
          {finding.owasp_api_category}
        </span>
      </td>
      <td style={{ padding: '10px 12px', color: '#94a3b8', fontSize: 12, maxWidth: 260 }}>
        <span style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {finding.resource_uid}
        </span>
      </td>
      <td style={{ padding: '10px 12px' }}>
        {finding.has_waf
          ? <span style={{ color: C.low, fontSize: 12 }}>✓ WAF</span>
          : <span style={{ color: C.critical, fontSize: 12 }}>✗ No WAF</span>}
      </td>
      <td style={{ padding: '10px 12px' }}>
        {finding.is_publicly_accessible
          ? <span style={{ color: C.high, fontSize: 12 }}>Public</span>
          : <span style={{ color: '#64748b', fontSize: 12 }}>Private</span>}
      </td>
      <td style={{ padding: '10px 12px', color: '#94a3b8', fontSize: 12 }}>
        {finding.auth_type || '—'}
      </td>
    </tr>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function APISecurityPage() {
  const { data, loading, error } = useViewFetch('api_security');
  const [selected, setSelected] = useState(null);
  const [owaspFilter, setOwaspFilter] = useState('all');
  const [sevFilter, setSevFilter] = useState('all');

  const report = data?.report || {};
  const findings = data?.findings || [];

  const filtered = findings.filter(f => {
    const owaspOk = owaspFilter === 'all' || f.owasp_api_category === owaspFilter;
    const sevOk = sevFilter === 'all' || f.severity === sevFilter;
    return owaspOk && sevOk;
  });

  const owaspCounts = {};
  findings.forEach(f => {
    if (f.owasp_api_category) {
      owaspCounts[f.owasp_api_category] = (owaspCounts[f.owasp_api_category] || 0) + 1;
    }
  });
  const maxOwasp = Math.max(...Object.values(owaspCounts), 1);

  const publicNoWaf = findings.filter(f => f.is_publicly_accessible && !f.has_waf).length;
  const noAuthPublic = findings.filter(f => f.is_publicly_accessible && f.auth_type === 'none').length;
  const staleKeys = findings.filter(f => f.rule_id?.includes('stale_key')).length;

  return (
    <PageLayout>
      <EngineShell
        title="API Security"
        subtitle="OWASP API Top 10 · Auth · WAF · Rate Limits · Key Lifecycle"
        icon={<Webhook size={20} color={C.purple} />}
        loading={loading}
        error={error}
      >
        {/* ── KPI strip ──────────────────────────────────────────────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 24 }}>
          <KpiSparkCard
            label="Total Findings"
            value={report.total_findings ?? findings.length}
            color={C.indigo}
            icon={<AlertTriangle size={16} />}
          />
          <KpiSparkCard
            label="Critical / High"
            value={(report.critical_count ?? 0) + (report.high_count ?? 0)}
            color={C.critical}
            icon={<ShieldAlert size={16} />}
          />
          <KpiSparkCard
            label="Public · No WAF"
            value={publicNoWaf}
            color={C.high}
            icon={<Globe size={16} />}
          />
          <KpiSparkCard
            label="No Auth (Public)"
            value={noAuthPublic}
            color={C.critical}
            icon={<Lock size={16} />}
          />
        </div>

        {/* ── Stat pills ─────────────────────────────────────────────────── */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 20 }}>
          <StatPill label="API2 (Auth)" value={report.owasp_api2_count} color={C.critical} />
          <StatPill label="API4 (Rate Limit)" value={report.owasp_api4_count} color={C.high} />
          <StatPill label="API8 (Config)" value={report.owasp_api8_count} color={C.high} />
          <StatPill label="API9 (Inventory)" value={report.owasp_api9_count} color={C.medium} />
          <StatPill label="Stale API Keys" value={staleKeys} color={C.purple} />
          <StatPill label="CDR Enriched" value={report.cdr_enriched_count} color={C.sky} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 16 }}>
          {/* ── OWASP distribution sidebar ──────────────────────────────── */}
          <div style={{
            background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 10, padding: 16,
          }}>
            <div style={{ color: '#f1f5f9', fontWeight: 600, marginBottom: 14, fontSize: 13 }}>
              OWASP API Top 10
            </div>
            {['API1','API2','API4','API7','API8','API9'].map(cat => (
              <OWASPBar
                key={cat}
                category={cat}
                count={owaspCounts[cat] || 0}
                maxCount={maxOwasp}
              />
            ))}
          </div>

          {/* ── Findings table ──────────────────────────────────────────── */}
          <div style={{
            background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 10, overflow: 'hidden',
          }}>
            {/* Filters */}
            <div style={{
              padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)',
              display: 'flex', gap: 8,
            }}>
              {['all','critical','high','medium','low'].map(s => (
                <button
                  key={s}
                  onClick={() => setSevFilter(s)}
                  style={{
                    padding: '3px 10px', borderRadius: 6, fontSize: 12, cursor: 'pointer',
                    border: '1px solid',
                    borderColor: sevFilter === s ? C.indigo : 'rgba(255,255,255,0.1)',
                    background: sevFilter === s ? 'rgba(99,102,241,0.15)' : 'transparent',
                    color: sevFilter === s ? C.indigo : '#94a3b8',
                  }}
                >
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                {['all','API2','API4','API8','API9'].map(cat => (
                  <button
                    key={cat}
                    onClick={() => setOwaspFilter(cat)}
                    style={{
                      padding: '3px 10px', borderRadius: 6, fontSize: 11, cursor: 'pointer',
                      border: '1px solid',
                      borderColor: owaspFilter === cat ? C.purple : 'rgba(255,255,255,0.1)',
                      background: owaspFilter === cat ? 'rgba(139,92,246,0.12)' : 'transparent',
                      color: owaspFilter === cat ? C.purple : '#94a3b8',
                    }}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Table */}
            <div style={{ overflowX: 'auto', maxHeight: 520, overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                    {['Severity', 'Finding', 'OWASP', 'Resource', 'WAF', 'Exposure', 'Auth'].map(h => (
                      <th key={h} style={{
                        padding: '8px 12px', textAlign: 'left',
                        color: '#64748b', fontSize: 11, fontWeight: 600,
                        textTransform: 'uppercase', letterSpacing: '0.04em',
                        position: 'sticky', top: 0,
                        background: 'rgba(15,23,42,0.95)',
                      }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ padding: 32, textAlign: 'center', color: '#475569', fontSize: 13 }}>
                        {findings.length === 0
                          ? 'No API security findings — run a scan to populate this view.'
                          : 'No findings match the current filters.'}
                      </td>
                    </tr>
                  ) : (
                    filtered.map((f, i) => (
                      <FindingRow key={f.finding_id || i} finding={f} onClick={setSelected} />
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div style={{
              padding: '8px 16px', borderTop: '1px solid rgba(255,255,255,0.06)',
              color: '#475569', fontSize: 12,
            }}>
              Showing {filtered.length} of {findings.length} findings
            </div>
          </div>
        </div>

        {/* ── Detail panel ────────────────────────────────────────────────── */}
        {selected && (
          <FindingDetailPanel
            finding={selected}
            onClose={() => setSelected(null)}
          />
        )}
      </EngineShell>
    </PageLayout>
  );
}
