'use client';

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  AlertTriangle, Shield, ShieldAlert, ShieldCheck, Search,
  RefreshCw, X, ChevronRight, ExternalLink, Copy, Check,
  Download, FileSpreadsheet, Filter, ArrowRight,
} from 'lucide-react';
import { useGlobalFilter } from '@/lib/global-filter-context';
import DataTable from '@/components/shared/DataTable';
import { SEVERITY_COLORS, CLOUD_PROVIDERS, TENANT_ID } from '@/lib/constants';
import { fetchView } from '@/lib/api';

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

// ── Severity summary card ───────────────────────────────────────────────────
function SeverityCard({ label, count, color, total }) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <div className="rounded-xl border p-5 flex flex-col transition-colors duration-200"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
          {label}
        </span>
        <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }} />
      </div>
      <span className="text-3xl font-bold" style={{ color }}>{count.toLocaleString()}</span>
      <div className="mt-2 w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}

// ── Styled filter select ────────────────────────────────────────────────────
function FilterSelect({ value, onChange, label, children }) {
  const isActive = value !== '';
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}
      className="text-xs px-3 py-2 rounded-lg border font-medium appearance-none cursor-pointer
        bg-[length:12px] bg-[right_8px_center] bg-no-repeat pr-7"
      style={{
        backgroundColor: isActive ? 'var(--accent-primary)' : 'var(--bg-secondary)',
        borderColor: isActive ? 'var(--accent-primary)' : 'var(--border-primary)',
        color: isActive ? '#fff' : 'var(--text-primary)',
        backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='none' stroke='${isActive ? '%23fff' : '%23999'}' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 5l3 3 3-3'/%3E%3C/svg%3E")`,
      }}>
      <option value="">{label}</option>
      {children}
    </select>
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

function exportPDF(findings, summary, filters) {
  const sevCounts = summary?.severity_counts || {};
  const total = summary?.total || 0;
  const filterDesc = Object.entries(filters).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`).join(', ') || 'None';
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

  const html = `<!DOCTYPE html><html><head><title>Misconfigurations Report</title>
    <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1e293b;margin:0;padding:32px;}
    @media print{body{padding:16px;} .no-print{display:none;}}</style></head><body>
    <div style="display:flex;align-items:center;justify-content:between;margin-bottom:24px;">
      <div><h1 style="font-size:22px;font-weight:700;margin:0;">Misconfigurations Report</h1>
      <p style="font-size:12px;color:#64748b;margin:4px 0 0;">Generated: ${now} | Filters: ${filterDesc}</p></div>
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


// ── Main Page ─────────────────────────────────────────────────────────────────
export default function MisconfigurationsPage() {
  const router = useRouter();
  const { provider: globalProvider, account: globalAccount, region: globalRegion, filterSummary } = useGlobalFilter();

  // Data state
  const [loading, setLoading] = useState(true);
  const [findings, setFindings] = useState([]);
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);
  const [exporting, setExporting] = useState(false);

  // Pagination (server-side)
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [totalRows, setTotalRows] = useState(0);

  // Sorting
  const [sortBy, setSortBy] = useState('severity');
  const [sortOrder, setSortOrder] = useState('asc');

  // Search
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  // Filters — includes scope (provider/account/region) + security filters
  const [filters, setFilters] = useState({
    provider: '',
    account_id: '',
    region: '',
    severity: '',
    status: '',
    service: '',
    posture_category: '',
  });

  // Detail panel
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Debounce search
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchTerm), 400);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  // Sync global filter → local filters on global change
  useEffect(() => {
    setFilters(prev => ({
      ...prev,
      provider: globalProvider ? globalProvider.toLowerCase() : '',
      account_id: globalAccount || '',
      region: globalRegion || '',
    }));
  }, [globalProvider, globalAccount, globalRegion]);

  // Fetch all data from BFF
  const fetchData = useCallback(async () => {
    setLoading(true);
    const data = await fetchView('misconfig', {
      provider: filters.provider || undefined,
      account: filters.account_id || undefined,
      region: filters.region || undefined,
    });
    if (data.error) {
      setError(data.error);
      setLoading(false);
      return;
    }

    // Map BFF kpi → summary shape expected by the page
    const kpi = data.kpi || {};

    // Process findings for the table — map BFF field names to what the table expects
    let allFindings = (data.findings || []).map(f => ({
      ...f,
      account_id: f.account_id || '',
      resource_uid: f.resource_id || f.resource_uid || '',
      title: f.title || f.rule_name || f.rule_id || '',
      created_at: f.detected_at || f.created_at || '',
    }));

    // Client-side filter by severity, status, service, posture_category, search
    if (filters.severity) {
      allFindings = allFindings.filter(f => f.severity === filters.severity);
    }
    if (filters.status) {
      allFindings = allFindings.filter(f => f.status === filters.status);
    }
    if (filters.service) {
      allFindings = allFindings.filter(f => f.service === filters.service);
    }
    if (filters.posture_category) {
      allFindings = allFindings.filter(f => f.posture_category === filters.posture_category);
    }
    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase();
      allFindings = allFindings.filter(f =>
        (f.title || '').toLowerCase().includes(q) ||
        (f.rule_id || '').toLowerCase().includes(q) ||
        (f.resource_uid || '').toLowerCase().includes(q)
      );
    }

    // Client-side sorting
    if (sortBy) {
      allFindings.sort((a, b) => {
        const aVal = (a[sortBy] || '');
        const bVal = (b[sortBy] || '');
        if (sortBy === 'severity') {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          const diff = (order[aVal] ?? 5) - (order[bVal] ?? 5);
          return sortOrder === 'desc' ? -diff : diff;
        }
        const cmp = String(aVal).localeCompare(String(bVal));
        return sortOrder === 'desc' ? -cmp : cmp;
      });
    }

    // Derive top_rules from findings
    const ruleCounts = {};
    allFindings.forEach(f => {
      const key = f.rule_id || f.title;
      if (!ruleCounts[key]) ruleCounts[key] = { rule_id: f.rule_id, title: f.title, severity: f.severity, count: 0 };
      ruleCounts[key].count++;
    });
    const topRules = Object.values(ruleCounts).sort((a, b) => b.count - a.count).slice(0, 10);

    // Derive by_service from byService dict
    const byServiceList = Object.entries(data.byService || {}).map(([service, count]) => ({
      service,
      total: count,
      fail: count,
    })).sort((a, b) => b.total - a.total);

    // Derive filter options from findings
    const providers = [...new Set(allFindings.map(f => f.provider).filter(Boolean))].sort();
    const accounts = [...new Set(allFindings.map(f => f.account_id).filter(Boolean))].sort();
    const regions = [...new Set(allFindings.map(f => f.region).filter(Boolean))].sort();
    const services = [...new Set(allFindings.map(f => f.service).filter(Boolean))].sort();
    const postures = [...new Set(allFindings.map(f => f.posture_category).filter(Boolean))].sort();

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
      by_provider: providers.map(p => ({ provider: p })),
      by_account: accounts.map(a => ({ account: a })),
      by_region: regions.map(r => ({ region: r })),
      by_posture: postures.map(p => ({ category: p })),
    });

    // Client-side pagination
    setTotalRows(allFindings.length);
    const start = (page - 1) * pageSize;
    setFindings(allFindings.slice(start, start + pageSize));
    setError(null);
    setLoading(false);
  }, [filters, debouncedSearch, page, pageSize, sortBy, sortOrder]);

  // Fetch on mount & filter/pagination/sort changes
  useEffect(() => { fetchData(); }, [fetchData]);

  // Reset page on filter change
  useEffect(() => { setPage(1); }, [filters, debouncedSearch]);

  // Refresh handler
  const handleRefresh = () => { fetchData(); };

  // Filter change
  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  // Clear all filters
  const clearFilters = () => {
    setFilters({ provider: '', account_id: '', region: '', severity: '', status: '', service: '', posture_category: '' });
    setSearchTerm('');
  };

  const activeFilterCount = Object.values(filters).filter(Boolean).length + (searchTerm ? 1 : 0);

  // Export handlers
  const handleExportCSV = async () => {
    setExporting(true);
    try { await exportCSV(); } finally { setExporting(false); }
  };
  const handleExportPDF = () => {
    exportPDF(findings, summary, filters);
  };

  // Derive filter options from summary
  const providerOptions = useMemo(() =>
    (summary?.by_provider || []).map(p => p.provider).filter(Boolean).sort(),
    [summary]);

  const accountOptions = useMemo(() =>
    (summary?.by_account || []).map(a => a.account).filter(Boolean).sort(),
    [summary]);

  const regionOptions = useMemo(() =>
    (summary?.by_region || []).map(r => r.region).filter(Boolean).sort(),
    [summary]);

  const serviceOptions = useMemo(() =>
    (summary?.by_service || []).map(s => s.service).filter(Boolean).sort(),
    [summary]);

  const postureOptions = useMemo(() =>
    (summary?.by_posture || []).map(p => p.category).filter(Boolean).sort(),
    [summary]);

  // Summary data
  const sevCounts = summary?.severity_counts || { critical: 0, high: 0, medium: 0, low: 0 };
  const totalFindings = summary?.total || 0;
  const statusCounts = summary?.status_counts || {};
  const topRules = summary?.top_rules || [];
  const byService = summary?.by_service || [];

  // ── Table columns: Provider → Account → Region → Service → Rule ID → Status → Severity → Last Seen ──
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

  // ── Server-side pagination handlers ────────────────────────────────────────
  const handlePageChange = (newPage) => setPage(newPage + 1); // DataTable uses 0-indexed
  const handlePageSizeChange = (newSize) => { setPageSize(newSize); setPage(1); };
  const handleSortChange = (columnId, direction) => {
    if (columnId) {
      setSortBy(columnId);
      setSortOrder(direction || 'asc');
    }
  };
  const handleSearchChange = (text) => setSearchTerm(text);

  return (
    <div className="space-y-6">
      {/* ── Page Header ────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Misconfigurations
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-tertiary)' }}>
            Cloud resource misconfigurations across all connected providers and accounts
          </p>
        </div>
        <div className="flex items-center gap-2">
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
          <button onClick={handleRefresh}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-opacity hover:opacity-80"
            style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* ── Severity Summary Cards ──────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <SeverityCard label="Critical" count={sevCounts.critical} color={SEVERITY_COLORS.critical} total={totalFindings} />
        <SeverityCard label="High" count={sevCounts.high} color={SEVERITY_COLORS.high} total={totalFindings} />
        <SeverityCard label="Medium" count={sevCounts.medium} color={SEVERITY_COLORS.medium} total={totalFindings} />
        <SeverityCard label="Low" count={sevCounts.low} color={SEVERITY_COLORS.low} total={totalFindings} />
        <div className="rounded-xl border p-5 flex flex-col transition-colors duration-200"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            Total Findings
          </span>
          <span className="text-3xl font-bold mt-2" style={{ color: 'var(--text-primary)' }}>
            {totalFindings.toLocaleString()}
          </span>
          <div className="flex gap-3 mt-2 text-xs" style={{ color: 'var(--text-tertiary)' }}>
            <span style={{ color: '#ef4444' }}>{statusCounts.FAIL || 0} fail</span>
            <span style={{ color: '#22c55e' }}>{statusCounts.PASS || 0} pass</span>
          </div>
        </div>
      </div>

      {/* ── Dashboard Charts Row ────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Failing Rules */}
        <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
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

        {/* Service Breakdown */}
        <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
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
      </div>

      {/* ── Filters Bar ──────────────────────────────────────────────────── */}
      <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex flex-wrap items-center gap-2">
          {/* Filter icon + label */}
          <div className="flex items-center gap-1.5 mr-1">
            <Filter className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
              Filters
            </span>
          </div>

          {/* Scope separator */}
          <div className="h-5 w-px mx-1" style={{ backgroundColor: 'var(--border-primary)' }} />

          {/* Provider */}
          <FilterSelect value={filters.provider} onChange={(v) => handleFilterChange('provider', v)} label="All Providers">
            {providerOptions.map(p => (
              <option key={p} value={p}>{p.toUpperCase()}</option>
            ))}
          </FilterSelect>

          {/* Account */}
          <FilterSelect value={filters.account_id} onChange={(v) => handleFilterChange('account_id', v)} label="All Accounts">
            {accountOptions.map(a => (
              <option key={a} value={a}>{a}</option>
            ))}
          </FilterSelect>

          {/* Region */}
          <FilterSelect value={filters.region} onChange={(v) => handleFilterChange('region', v)} label="All Regions">
            {regionOptions.map(r => (
              <option key={r} value={r}>{r}</option>
            ))}
          </FilterSelect>

          {/* Security separator */}
          <div className="h-5 w-px mx-1" style={{ backgroundColor: 'var(--border-primary)' }} />

          {/* Severity */}
          <FilterSelect value={filters.severity} onChange={(v) => handleFilterChange('severity', v)} label="All Severities">
            {['critical', 'high', 'medium', 'low'].map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </FilterSelect>

          {/* Status */}
          <FilterSelect value={filters.status} onChange={(v) => handleFilterChange('status', v)} label="All Statuses">
            <option value="FAIL">Fail</option>
            <option value="PASS">Pass</option>
          </FilterSelect>

          {/* Service */}
          <FilterSelect value={filters.service} onChange={(v) => handleFilterChange('service', v)} label="All Services">
            {serviceOptions.map(s => (
              <option key={s} value={s}>{s.toUpperCase()}</option>
            ))}
          </FilterSelect>

          {/* Posture */}
          <FilterSelect value={filters.posture_category} onChange={(v) => handleFilterChange('posture_category', v)} label="All Postures">
            {postureOptions.map(p => (
              <option key={p} value={p}>{p.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</option>
            ))}
          </FilterSelect>

          {/* Clear + Count */}
          {activeFilterCount > 0 && (
            <button onClick={clearFilters}
              className="flex items-center gap-1 text-xs font-medium px-2.5 py-1.5 rounded-lg transition-opacity hover:opacity-80"
              style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444' }}>
              <X className="w-3 h-3" /> Clear ({activeFilterCount})
            </button>
          )}

          {/* Results count */}
          <span className="ml-auto text-xs font-semibold" style={{ color: 'var(--text-tertiary)' }}>
            {totalRows.toLocaleString()} finding{totalRows !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      {/* ── Findings Table ───────────────────────────────────────────────── */}
      {error && (
        <div className="rounded-lg border p-4 text-sm" style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.2)', color: '#ef4444' }}>
          <AlertTriangle className="w-4 h-4 inline mr-2" />
          {error}
        </div>
      )}

      <DataTable
        data={findings}
        columns={columns}
        loading={loading}
        emptyMessage="No misconfigurations found matching the current filters"
        onRowClick={(row) => setSelectedFinding(row.original)}
        serverPagination
        totalRows={totalRows}
        currentPage={page - 1}
        onPageChange={handlePageChange}
        onPageSizeChange={handlePageSizeChange}
        onSearchChange={handleSearchChange}
        onSortChange={handleSortChange}
        pageSize={pageSize}
        onExportPdf={handleExportPDF}
        onExportExcel={handleExportCSV}
        showExport
      />

      {/* ── Detail Slide-out ──────────────────────────────────────────────── */}
      <FindingDetailPanel
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
