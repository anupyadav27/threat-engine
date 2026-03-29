'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';
import Link from 'next/link';
import {
  AlertTriangle, ShieldAlert, ShieldCheck,
  X, ExternalLink, Copy, Check,
  Download, FileSpreadsheet, RefreshCw, ArrowRight,
} from 'lucide-react';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { SEVERITY_COLORS, CLOUD_PROVIDERS } from '@/lib/constants';
import { fetchView } from '@/lib/api';
import PageLayout from '@/components/shared/PageLayout';
import InsightRow from '@/components/shared/InsightRow';


// ── Posture category styling ────────────────────────────────────────────────
const POSTURE_COLORS = {
  encryption: '#8b5cf6',
  public_access: '#ef4444',
  logging: '#3b82f6',
  backup: '#06b6d4',
  access_control: '#f59e0b',
  network: '#6366f1',
  key_management: '#ec4899',
  configuration: '#64748b',
  data_protection: '#14b8a6',
  threat_detection: '#f97316',
};

function PostureBadge({ category }) {
  const label = (category || 'configuration').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  const bg = POSTURE_COLORS[category] || '#64748b';
  return (
    <span className="text-xs font-medium px-2 py-1 rounded whitespace-nowrap"
      style={{ backgroundColor: bg + '20', color: bg }}>
      {label}
    </span>
  );
}

function SeverityBadgeInline({ severity }) {
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
  return (
    <span className="text-xs font-bold px-2.5 py-1 rounded-full uppercase tracking-wider"
      style={{ backgroundColor: color + '1a', color, border: `1px solid ${color}4d` }}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  const isFail = (status || '').toUpperCase() === 'FAIL';
  return (
    <span className="text-xs font-semibold px-2 py-1 rounded-full"
      style={{
        backgroundColor: isFail ? 'rgba(239,68,68,0.12)' : 'rgba(34,197,94,0.12)',
        color: isFail ? '#ef4444' : '#22c55e',
      }}>
      {isFail ? 'FAIL' : 'PASS'}
    </span>
  );
}

function ProviderBadge({ provider }) {
  const p = CLOUD_PROVIDERS[(provider || '').toLowerCase()];
  if (!p) return <span className="text-xs uppercase" style={{ color: 'var(--text-tertiary)' }}>{provider}</span>;
  return (
    <span className="text-xs font-semibold px-2 py-0.5 rounded"
      style={{ backgroundColor: p.bgColor, color: p.textColor }}>
      {p.name}
    </span>
  );
}


// ── Detail slide-out panel ──────────────────────────────────────────────────
function FindingDetailPanel({ finding, onClose }) {
  const [copied, setCopied] = useState(null);
  if (!finding) return null;

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1500);
  };

  const frameworks = finding.compliance_frameworks;
  const frameworkList = Array.isArray(frameworks)
    ? frameworks
    : (frameworks && typeof frameworks === 'object')
      ? Object.keys(frameworks)
      : [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      {/* Panel */}
      <div className="relative w-full max-w-2xl h-full overflow-y-auto shadow-2xl"
        style={{ backgroundColor: 'var(--bg-primary)' }}>
        {/* Header */}
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 px-6 py-5 border-b"
          style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-primary)' }}>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <SeverityBadgeInline severity={finding.severity} />
              <StatusBadge status={finding.status} />
              {finding.provider && <ProviderBadge provider={finding.provider} />}
            </div>
            <h2 className="text-lg font-bold leading-tight" style={{ color: 'var(--text-primary)' }}>
              {finding.title}
            </h2>
            <code className="text-xs mt-1 block" style={{ color: 'var(--text-muted)' }}>
              {finding.rule_id}
            </code>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:opacity-70 transition-opacity"
            style={{ color: 'var(--text-muted)' }}>
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-6">
          {/* Resource Details */}
          <section>
            <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
              Resource
            </h3>
            <div className="rounded-lg border p-4 space-y-2" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
              {[
                { label: 'ARN', value: finding.resource_arn },
                { label: 'Resource ID', value: finding.resource_uid },
                { label: 'Type', value: finding.resource_type },
                { label: 'Service', value: finding.service?.toUpperCase() },
                { label: 'Region', value: finding.region },
                { label: 'Account', value: finding.account_id },
                { label: 'Provider', value: finding.provider?.toUpperCase() },
              ].filter(r => r.value).map(r => (
                <div key={r.label} className="flex items-start justify-between gap-4">
                  <span className="text-xs font-medium shrink-0 w-20" style={{ color: 'var(--text-muted)' }}>{r.label}</span>
                  <div className="flex items-center gap-1.5 min-w-0 flex-1">
                    <code className="text-xs break-all" style={{ color: 'var(--text-secondary)' }}>{r.value}</code>
                    {r.label === 'ARN' && (
                      <button onClick={() => copyToClipboard(r.value, 'arn')}
                        className="shrink-0 p-0.5 rounded hover:opacity-70" style={{ color: 'var(--text-muted)' }}>
                        {copied === 'arn' ? <Check className="w-3.5 h-3.5" style={{ color: '#22c55e' }} /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Description & Rationale */}
          {(finding.description || finding.rationale) && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                Description
              </h3>
              <div className="rounded-lg border p-4 text-sm leading-relaxed"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
                {finding.description || finding.rationale}
              </div>
            </section>
          )}

          {/* Evidence */}
          {(finding.checked_fields || finding.actual_values) && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                Evidence
              </h3>
              <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                {finding.checked_fields && (
                  <div className="p-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                    <span className="text-xs font-semibold block mb-2" style={{ color: 'var(--text-muted)' }}>Checked Fields</span>
                    <pre className="text-xs overflow-x-auto whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>
                      {typeof finding.checked_fields === 'string'
                        ? finding.checked_fields
                        : JSON.stringify(finding.checked_fields, null, 2)}
                    </pre>
                  </div>
                )}
                {finding.actual_values && (
                  <div className="p-4">
                    <span className="text-xs font-semibold block mb-2" style={{ color: 'var(--text-muted)' }}>Actual Values</span>
                    <pre className="text-xs overflow-x-auto whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>
                      {typeof finding.actual_values === 'string'
                        ? finding.actual_values
                        : JSON.stringify(finding.actual_values, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                Remediation
              </h3>
              <div className="rounded-lg border p-4 text-sm leading-relaxed"
                style={{ backgroundColor: 'rgba(59,130,246,0.06)', borderColor: 'rgba(59,130,246,0.2)', color: 'var(--text-secondary)' }}>
                <div className="flex items-start gap-2">
                  <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" style={{ color: '#3b82f6' }} />
                  <span style={{ whiteSpace: 'pre-wrap' }}>{finding.remediation}</span>
                </div>
              </div>
            </section>
          )}

          {/* Posture & Domain */}
          <section>
            <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
              Classification
            </h3>
            <div className="flex flex-wrap gap-2">
              <PostureBadge category={finding.posture_category} />
              {finding.domain && (
                <span className="text-xs font-medium px-2 py-1 rounded"
                  style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                  {finding.domain}
                </span>
              )}
              {finding.risk_score != null && (
                <span className="text-xs font-bold px-2 py-1 rounded"
                  style={{
                    backgroundColor: finding.risk_score >= 70 ? 'rgba(239,68,68,0.12)' : 'rgba(234,179,8,0.12)',
                    color: finding.risk_score >= 70 ? '#ef4444' : '#eab308',
                  }}>
                  Risk: {finding.risk_score}
                </span>
              )}
            </div>
          </section>

          {/* Compliance Frameworks */}
          {frameworkList.length > 0 && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                Compliance Mapping
              </h3>
              <div className="flex flex-wrap gap-2">
                {frameworkList.map((fw, i) => {
                  const label = typeof fw === 'object' ? (fw.name || fw.id || JSON.stringify(fw)) : fw;
                  return (
                    <span key={`fw-${i}`} className="text-xs font-medium px-2.5 py-1 rounded-full"
                      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                      {label}
                    </span>
                  );
                })}
              </div>
            </section>
          )}

          {/* MITRE ATT&CK */}
          {((finding.mitre_tactics && finding.mitre_tactics.length > 0) ||
            (finding.mitre_techniques && finding.mitre_techniques.length > 0)) && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                MITRE ATT&CK
              </h3>
              <div className="flex flex-wrap gap-2">
                {(finding.mitre_tactics || []).map((t, i) => {
                  const label = typeof t === 'object' ? (t.name || t.tactic || JSON.stringify(t)) : t;
                  return (
                    <span key={`tactic-${i}`} className="text-xs font-medium px-2 py-1 rounded"
                      style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444' }}>
                      {label}
                    </span>
                  );
                })}
                {(finding.mitre_techniques || []).map((t, i) => {
                  const tid = typeof t === 'object' ? t.technique_id : null;
                  const tname = typeof t === 'object' ? (t.technique_name || t.name) : t;
                  const label = tid && tname ? `${tid}: ${tname}` : (tname || tid || (typeof t === 'string' ? t : JSON.stringify(t)));
                  return (
                    <span key={`technique-${i}`} className="text-xs font-medium px-2 py-1 rounded"
                      style={{ backgroundColor: 'rgba(249,115,22,0.1)', color: '#f97316' }}>
                      {label}
                    </span>
                  );
                })}
              </div>
            </section>
          )}

          {/* Link to asset detail */}
          {finding.resource_uid && (
            <div className="pt-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
              <a href={`/ui/inventory/${encodeURIComponent(finding.resource_uid)}`}
                className="inline-flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-lg transition-opacity hover:opacity-80"
                style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
                <ExternalLink className="w-4 h-4" /> View Asset Detail
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


// ── Export helpers ──────────────────────────────────────────────────────────

function escapeCSV(val) {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

async function exportCSV() {
  const data = await fetchView('misconfig');
  if (data.error) { alert(`Export failed: ${data.error}`); return; }

  const allFindings = (data.findings || []).map(f => ({
    ...f,
    account_id: f.account_id || '',
    resource_uid: f.resource_id || f.resource_uid || '',
  }));

  const headers = ['Severity','Status','Finding','Rule ID','Resource','Resource ARN','Service','Security Posture','Provider','Account','Region','Domain','Risk Score','Detected'];
  const rows = allFindings.map(f => [
    f.severity, f.status, f.title || f.rule_id, f.rule_id, f.resource_uid,
    f.resource_arn || '', f.service, f.posture_category || '', f.provider,
    f.account_id, f.region, f.domain || '', f.risk_score ?? '', f.created_at ?? '',
  ]);
  const csv = [headers.map(escapeCSV).join(','), ...rows.map(r => r.map(escapeCSV).join(','))].join('\n');
  const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `misconfigurations-${new Date().toISOString().split('T')[0]}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportPDF(findings, summary) {
  const sevCounts = summary?.severity_counts || {};
  const total = summary?.total || 0;
  const now = new Date().toLocaleString();

  const rowsHtml = (findings || []).slice(0, 200).map(f => `
    <tr>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;">
        <span style="background:${(SEVERITY_COLORS[f.severity] || '#999')}22;color:${SEVERITY_COLORS[f.severity] || '#999'};padding:2px 8px;border-radius:9999px;font-weight:700;font-size:10px;text-transform:uppercase;">${f.severity}</span>
      </td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;color:${f.status === 'FAIL' ? '#ef4444' : '#22c55e'};font-weight:600;">${f.status}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${f.title || f.rule_id}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;text-transform:uppercase;">${f.service || ''}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;text-transform:uppercase;">${f.provider || ''}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;">${f.account_id || ''}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;">${f.region || ''}</td>
    </tr>
  `).join('');

  const html = `<!DOCTYPE html><html><head><title>Posture Security Report</title>
    <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1e293b;margin:0;padding:32px;}
    @media print{body{padding:16px;} .no-print{display:none;}}</style></head><body>
    <div style="display:flex;align-items:center;justify-content:between;margin-bottom:24px;">
      <div><h1 style="font-size:22px;font-weight:700;margin:0;">Posture Security Report</h1>
      <p style="font-size:12px;color:#64748b;margin:4px 0 0;">Generated: ${now}</p></div>
    </div>
    <div style="display:flex;gap:12px;margin-bottom:24px;">
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#fef2f2;border:1px solid #fecaca;">
        <div style="font-size:10px;color:#991b1b;font-weight:600;text-transform:uppercase;">Critical</div>
        <div style="font-size:24px;font-weight:700;color:#dc2626;">${(sevCounts.critical || 0).toLocaleString()}</div></div>
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#fff7ed;border:1px solid #fed7aa;">
        <div style="font-size:10px;color:#9a3412;font-weight:600;text-transform:uppercase;">High</div>
        <div style="font-size:24px;font-weight:700;color:#ea580c;">${(sevCounts.high || 0).toLocaleString()}</div></div>
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#fefce8;border:1px solid #fde68a;">
        <div style="font-size:10px;color:#854d0e;font-weight:600;text-transform:uppercase;">Medium</div>
        <div style="font-size:24px;font-weight:700;color:#ca8a04;">${(sevCounts.medium || 0).toLocaleString()}</div></div>
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#f0f9ff;border:1px solid #bae6fd;">
        <div style="font-size:10px;color:#075985;font-weight:600;text-transform:uppercase;">Low</div>
        <div style="font-size:24px;font-weight:700;color:#0284c7;">${(sevCounts.low || 0).toLocaleString()}</div></div>
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#f8fafc;border:1px solid #e2e8f0;">
        <div style="font-size:10px;color:#475569;font-weight:600;text-transform:uppercase;">Total</div>
        <div style="font-size:24px;font-weight:700;color:#1e293b;">${total.toLocaleString()}</div></div>
    </div>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;">
      <thead><tr style="background:#f1f5f9;">
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Severity</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Status</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Finding</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Service</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Provider</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Account</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Region</th>
      </tr></thead>
      <tbody>${rowsHtml}</tbody>
    </table>
    <p style="margin-top:16px;font-size:10px;color:#94a3b8;">Showing up to 200 findings. Export CSV for full data.</p>
    <script>window.onload=function(){window.print();}</script>
  </body></html>`;

  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); }
}


// ── Top Failing Rules Chart ──────────────────────────────────────────────────

function TopFailingRulesChart({ topRules }) {
  return (
    <div>
      <h3 className="text-sm font-semibold uppercase tracking-wider mb-4" style={{ color: 'var(--text-muted)' }}>
        Top Failing Rules
      </h3>
      <div className="space-y-2.5">
        {topRules.length === 0 && (
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No data</p>
        )}
        {topRules.slice(0, 8).map((rule) => {
          const maxCount = topRules[0]?.count || 1;
          const pct = Math.round((rule.count / maxCount) * 100);
          return (
            <div key={rule.rule_id}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium truncate flex-1 mr-3" style={{ color: 'var(--text-secondary)' }}>
                  {rule.title || rule.rule_id}
                </span>
                <div className="flex items-center gap-2 shrink-0">
                  <SeverityBadgeInline severity={rule.severity} />
                  <span className="text-xs font-bold w-8 text-right" style={{ color: 'var(--text-primary)' }}>
                    {rule.count}
                  </span>
                </div>
              </div>
              <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <div className="h-full rounded-full" style={{
                  width: `${pct}%`,
                  backgroundColor: SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.medium,
                }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


// ── Service Breakdown Chart ─────────────────────────────────────────────────

function ServiceBreakdownChart({ byService }) {
  return (
    <div>
      <h3 className="text-sm font-semibold uppercase tracking-wider mb-4" style={{ color: 'var(--text-muted)' }}>
        Findings by Service
      </h3>
      <div className="space-y-2.5">
        {byService.length === 0 && (
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No data</p>
        )}
        {byService.slice(0, 10).map((svc) => {
          const maxCount = byService[0]?.total || 1;
          const pct = Math.round((svc.total / maxCount) * 100);
          const failPct = svc.total > 0 ? Math.round((svc.fail / svc.total) * 100) : 0;
          return (
            <div key={svc.service}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium uppercase" style={{ color: 'var(--text-secondary)' }}>
                  {svc.service}
                </span>
                <div className="flex items-center gap-3 text-xs">
                  <span style={{ color: '#ef4444' }}>{svc.fail} fail</span>
                  <span style={{ color: 'var(--text-muted)' }}>{svc.total} total</span>
                </div>
              </div>
              <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <div className="h-full rounded-full" style={{
                  width: `${pct}%`,
                  backgroundColor: failPct > 50 ? '#ef4444' : failPct > 25 ? '#f97316' : '#3b82f6',
                }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


// ── Main Page ─────────────────────────────────────────────────────────────────
export default function MisconfigurationsPage() {
  const { provider: globalProvider, account: globalAccount, region: globalRegion } = useGlobalFilter();

  // Data state
  const [loading, setLoading] = useState(true);
  const [allFindings, setAllFindings] = useState([]);
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);
  const [exporting, setExporting] = useState(false);

  // Detail panel
  const [selectedFinding, setSelectedFinding] = useState(null);

  // ── Fetch ─────────────────────────────────────────────────────────────
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchView('misconfig', {
        provider: globalProvider ? globalProvider.toLowerCase() : undefined,
        account: globalAccount || undefined,
        region: globalRegion || undefined,
      });
      if (data.error) {
        setError(data.error);
        setLoading(false);
        return;
      }

      const kpi = data.kpi || {};

      // Process findings
      const processed = (data.findings || []).map(f => ({
        ...f,
        account_id: f.account_id || '',
        resource_uid: f.resource_id || f.resource_uid || '',
        title: f.title || f.rule_name || f.rule_id || '',
        created_at: f.detected_at || f.created_at || '',
      }));

      // Derive top_rules
      const ruleCounts = {};
      processed.forEach(f => {
        const key = f.rule_id || f.title;
        if (!ruleCounts[key]) ruleCounts[key] = { rule_id: f.rule_id, title: f.title, severity: f.severity, count: 0 };
        ruleCounts[key].count++;
      });
      const topRules = Object.values(ruleCounts).sort((a, b) => b.count - a.count).slice(0, 10);

      // Derive by_service
      const byServiceList = Object.entries(data.byService || {}).map(([service, count]) => ({
        service,
        total: count,
        fail: count,
      })).sort((a, b) => b.total - a.total);

      setSummary({
        total: kpi.total || 0,
        severity_counts: {
          critical: kpi.critical || 0,
          high: kpi.high || 0,
          medium: kpi.medium || 0,
          low: kpi.low || 0,
        },
        status_counts: {
          FAIL: kpi.failed || 0,
          PASS: kpi.passed || 0,
        },
        top_rules: topRules,
        by_service: byServiceList,
      });

      setAllFindings(processed);
    } catch (err) {
      console.warn('[misconfig] fetch error:', err);
      setError('Failed to load posture data');
    } finally {
      setLoading(false);
    }
  }, [globalProvider, globalAccount, globalRegion]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // ── Derived data ──────────────────────────────────────────────────────
  const sevCounts = summary?.severity_counts || { critical: 0, high: 0, medium: 0, low: 0 };
  const totalFindings = summary?.total || 0;
  const statusCounts = summary?.status_counts || {};
  const topRules = summary?.top_rules || [];
  const byService = summary?.by_service || [];

  // ── Unique values helper ──────────────────────────────────────────────
  const uniqueVals = useCallback((key) => {
    return [...new Set(allFindings.map(f => f[key]).filter(Boolean))].sort();
  }, [allFindings]);

  // ── By-service grouped data ───────────────────────────────────────────
  const byServiceData = useMemo(() => {
    const groups = {};
    allFindings.forEach(f => {
      const svc = f.service || 'unknown';
      if (!groups[svc]) groups[svc] = [];
      groups[svc].push(f);
    });
    return Object.entries(groups)
      .sort(([, a], [, b]) => b.length - a.length)
      .flatMap(([, items]) => items);
  }, [allFindings]);

  // ── By-category grouped data ──────────────────────────────────────────
  const byCategoryData = useMemo(() => {
    const groups = {};
    allFindings.forEach(f => {
      const cat = f.posture_category || 'configuration';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(f);
    });
    return Object.entries(groups)
      .sort(([, a], [, b]) => b.length - a.length)
      .flatMap(([, items]) => items);
  }, [allFindings]);

  // ── Table columns ─────────────────────────────────────────────────────
  const columns = useMemo(() => [
    {
      accessorKey: 'provider',
      header: 'Provider',
      size: 90,
      cell: (info) => <ProviderBadge provider={info.getValue()} />,
    },
    {
      accessorKey: 'account_id',
      header: 'Account',
      size: 130,
      cell: (info) => (
        <span className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue() || '\u2014'}
        </span>
      ),
    },
    {
      accessorKey: 'region',
      header: 'Region',
      size: 120,
      cell: (info) => (
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
          {info.getValue() || '\u2014'}
        </span>
      ),
    },
    {
      accessorKey: 'service',
      header: 'Service',
      size: 85,
      cell: (info) => (
        <span className="text-xs font-semibold uppercase" style={{ color: 'var(--text-tertiary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'title',
      header: 'Rule ID',
      size: 320,
      cell: (info) => (
        <div className="min-w-0">
          <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
            {info.getValue()}
          </p>
          <code className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
            {info.row.original.rule_id}
          </code>
        </div>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 80,
      cell: (info) => <StatusBadge status={info.getValue()} />,
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      size: 100,
      cell: (info) => <SeverityBadgeInline severity={info.getValue()} />,
    },
    {
      accessorKey: 'created_at',
      header: 'Last Seen',
      size: 95,
      cell: (info) => {
        const val = info.getValue();
        if (!val) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{'\u2014'}</span>;
        const d = new Date(val);
        const ago = Math.floor((Date.now() - d.getTime()) / 86400000);
        return (
          <span className="text-xs" style={{ color: ago > 30 ? '#ef4444' : 'var(--text-muted)' }}>
            {ago}d ago
          </span>
        );
      },
    },
    {
      id: 'threat_link',
      header: '',
      size: 100,
      enableSorting: false,
      cell: (info) => {
        const ruleId = info.row.original.rule_id;
        return (
          <Link
            href={`/threats?search=${encodeURIComponent(ruleId || '')}`}
            className="inline-flex items-center gap-1 text-xs font-medium hover:opacity-80 transition-opacity whitespace-nowrap"
            style={{ color: 'var(--accent-primary)' }}
            onClick={(e) => e.stopPropagation()}
          >
            View Threat <ArrowRight className="w-3 h-3" />
          </Link>
        );
      },
    },
  ], []);

  // ── Primary filters ───────────────────────────────────────────────────
  const primaryFilters = useMemo(() => {
    const f = [
      { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
      { key: 'status', label: 'Status', options: ['FAIL', 'PASS'] },
    ];
    const providerVals = uniqueVals('provider');
    if (providerVals.length > 0) f.push({ key: 'provider', label: 'Provider', options: providerVals });
    const accountVals = uniqueVals('account_id');
    if (accountVals.length > 0) f.push({ key: 'account_id', label: 'Account', options: accountVals });
    const regionVals = uniqueVals('region');
    if (regionVals.length > 0) f.push({ key: 'region', label: 'Region', options: regionVals });
    return f;
  }, [allFindings, uniqueVals]);

  // ── Extra filters ─────────────────────────────────────────────────────
  const extraFilters = useMemo(() => {
    const extras = [];
    const serviceVals = uniqueVals('service');
    if (serviceVals.length > 0) extras.push({ key: 'service', label: 'Service', options: serviceVals });
    const postureVals = uniqueVals('posture_category');
    if (postureVals.length > 0) extras.push({ key: 'posture_category', label: 'Posture', options: postureVals });
    const domainVals = uniqueVals('domain');
    if (domainVals.length > 0) extras.push({ key: 'domain', label: 'Domain', options: domainVals });
    return extras;
  }, [allFindings, uniqueVals]);

  // ── Group-by options ──────────────────────────────────────────────────
  const groupByOptions = useMemo(() => [
    { key: 'severity', label: 'Severity' },
    { key: 'status', label: 'Status' },
    { key: 'service', label: 'Service' },
    { key: 'posture_category', label: 'Posture' },
    { key: 'provider', label: 'Provider' },
    { key: 'account_id', label: 'Account' },
    { key: 'region', label: 'Region' },
  ], []);

  // ── Page context ──────────────────────────────────────────────────────
  const pageContext = useMemo(() => ({
    title: 'Posture Security',
    brief: 'Cloud resource misconfigurations across all connected providers and accounts',
    details: [
      'Focus on critical and high severity findings first',
      'Use "By Service" tab to see which services need the most attention',
      'Click any finding row to view remediation guidance',
    ],
    tabs: [
      { id: 'findings', label: 'All Findings', count: allFindings.length },
      { id: 'by_service', label: 'By Service', count: allFindings.length },
      { id: 'by_category', label: 'By Category', count: allFindings.length },
    ],
  }), [allFindings]);

  // ── KPI groups ────────────────────────────────────────────────────────
  const kpiGroups = useMemo(() => [
    {
      title: 'Severity Breakdown',
      items: [
        { label: 'Critical', value: sevCounts.critical },
        { label: 'High', value: sevCounts.high },
        { label: 'Medium', value: sevCounts.medium },
      ],
    },
    {
      title: 'Summary',
      items: [
        { label: 'Total Findings', value: totalFindings },
        { label: 'Failed', value: statusCounts.FAIL || 0 },
        { label: 'Passed', value: statusCounts.PASS || 0 },
      ],
    },
  ], [sevCounts, totalFindings, statusCounts]);

  // ── Insight Row: top rules (left) + service breakdown (right) ─────────
  const insightRowContent = useMemo(() => (
    <InsightRow
      left={<TopFailingRulesChart topRules={topRules} />}
      right={<ServiceBreakdownChart byService={byService} />}
    />
  ), [topRules, byService]);

  // ── Tab data ──────────────────────────────────────────────────────────
  const tabData = useMemo(() => {
    const shared = { columns, filters: primaryFilters, extraFilters, groupByOptions };
    return {
      findings: { ...shared, data: allFindings },
      by_service: { ...shared, data: byServiceData, groupByOptions: [{ key: 'service', label: 'Service' }, ...groupByOptions] },
      by_category: { ...shared, data: byCategoryData, groupByOptions: [{ key: 'posture_category', label: 'Posture' }, ...groupByOptions] },
    };
  }, [allFindings, byServiceData, byCategoryData, columns, primaryFilters, extraFilters, groupByOptions]);

  // ── Row click handler ─────────────────────────────────────────────────
  const handleRowClick = useCallback((row) => {
    const finding = row?.original || row;
    if (finding) setSelectedFinding(finding);
  }, []);

  // ── Export handlers ───────────────────────────────────────────────────
  const handleExportCSV = async () => {
    setExporting(true);
    try { await exportCSV(); } finally { setExporting(false); }
  };
  const handleExportPDF = () => {
    exportPDF(allFindings, summary);
  };

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">
      {/* Export buttons above PageLayout */}
      <div className="flex items-center justify-end gap-2">
        <button onClick={handleExportCSV} disabled={exporting}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium border transition-opacity hover:opacity-80 disabled:opacity-50"
          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
          <FileSpreadsheet className="w-3.5 h-3.5" /> {exporting ? 'Exporting...' : 'CSV'}
        </button>
        <button onClick={handleExportPDF}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium border transition-opacity hover:opacity-80"
          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
          <Download className="w-3.5 h-3.5" /> PDF
        </button>
        <button onClick={fetchData}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-opacity hover:opacity-80"
          style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      <PageLayout
        icon={ShieldAlert}
        pageContext={pageContext}
        kpiGroups={kpiGroups}
        insightRow={insightRowContent}
        tabData={tabData}
        loading={loading}
        error={error}
        defaultTab="findings"
        onRowClick={handleRowClick}
      />

      {/* Detail Slide-out */}
      <FindingDetailPanel
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
