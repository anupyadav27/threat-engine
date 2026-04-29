'use client';

import { useState, useEffect, useMemo } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';
import {
  ChevronLeft, AlertTriangle, Shield, FileCode, Globe,
  Package, Loader2, ExternalLink, Info,
} from 'lucide-react';
import { getFromEngine, fetchApi } from '@/lib/api';
import SeverityBadge from '@/components/shared/SeverityBadge';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const TENANT_ID = 'test-tenant';
const SCA_API_KEY = 'sbom-api-key-2024';
const SCA_BASE = '/secops/api/v1/secops/sca/api/v1/sbom';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function normalizeSev(s) {
  if (!s) return 'info';
  const v = String(s).toLowerCase();
  if (v === 'blocker') return 'critical';
  if (v === 'major')   return 'high';
  if (v === 'minor')   return 'medium';
  return v;
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' +
    d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function toTitleCase(str) {
  if (!str) return '—';
  return str
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// SAST fix hint map
// ---------------------------------------------------------------------------
const SAST_FIX_HINTS = {
  sql_injection:     'Use parameterized queries / prepared statements. Never concatenate user input into SQL.',
  command_injection: 'Use subprocess with shell=False and a list of arguments. Never pass user input to os.system().',
  xss:               'Use a templating engine with auto-escaping (e.g. render_template). Never build HTML by string concatenation.',
  open_redirect:     'Validate redirect URLs against an allowlist. Only allow relative paths.',
  path_traversal:    'Use os.path.basename() to strip directory components. Validate against a safe base path.',
  pickle:            'Never deserialize untrusted data with pickle. Use JSON or a safe alternative.',
  ssrf:              'Validate and whitelist allowed URLs/hostnames before making outbound HTTP requests.',
  debug_mode:        'Set DEBUG=False in production. Use environment variables for configuration.',
  weak_hash:         'Use SHA-256 or stronger (hashlib.sha256). MD5/SHA1 are cryptographically broken.',
  random:            'Use the secrets module for cryptographic operations, not the random module.',
};

function getSastFix(ruleId) {
  if (!ruleId) return null;
  const r = ruleId.toLowerCase();
  for (const [key, hint] of Object.entries(SAST_FIX_HINTS)) {
    if (r.includes(key)) return hint;
  }
  return 'Review the finding and apply the principle of least privilege / input validation.';
}

// ---------------------------------------------------------------------------
// CVSS color helper
// ---------------------------------------------------------------------------
function cvssColor(score) {
  const s = parseFloat(score);
  if (isNaN(s)) return 'var(--text-secondary)';
  if (s >= 9)   return '#ef4444';
  if (s >= 7)   return '#f97316';
  if (s >= 4)   return '#eab308';
  return '#22c55e';
}

// ---------------------------------------------------------------------------
// HTTP method badge
// ---------------------------------------------------------------------------
function MethodBadge({ method }) {
  if (!method) return null;
  const m = method.toUpperCase();
  const cfg = {
    GET:    'bg-blue-500/15 text-blue-400 border-blue-500/30',
    POST:   'bg-orange-500/15 text-orange-400 border-orange-500/30',
    PUT:    'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    DELETE: 'bg-red-500/15 text-red-400 border-red-500/30',
    PATCH:  'bg-purple-500/15 text-purple-400 border-purple-500/30',
  };
  return (
    <span className={`inline-flex items-center text-xs font-bold px-2 py-0.5 rounded border ${cfg[m] || 'bg-slate-500/15 text-slate-400 border-slate-500/30'}`}>
      {m}
    </span>
  );
}

// ---------------------------------------------------------------------------
// SourceBadge
// ---------------------------------------------------------------------------
function SourceBadge({ source }) {
  const cfg = {
    sast: { label: 'SAST', cls: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
    dast: { label: 'DAST', cls: 'bg-purple-500/15 text-purple-400 border-purple-500/30' },
    sca:  { label: 'SCA',  cls: 'bg-green-500/15 text-green-400 border-green-500/30' },
  };
  const { label, cls } = cfg[source] || { label: (source || '').toUpperCase(), cls: 'bg-slate-500/15 text-slate-400 border-slate-500/30' };
  return (
    <span className={`inline-flex items-center text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border ${cls}`}>
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Mini info card (label + value)
// ---------------------------------------------------------------------------
function MiniCard({ label, children }) {
  return (
    <div className="rounded-lg border px-4 py-3" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
        {label}
      </div>
      <div>{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section card wrapper
// ---------------------------------------------------------------------------
function SectionCard({ title, subtitle, children }) {
  return (
    <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="px-5 py-4 border-b flex items-center gap-3" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
        <div>
          <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{title}</div>
          {subtitle && <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{subtitle}</div>}
        </div>
      </div>
      <div className="p-5">
        {children}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function VulnDetailPage() {
  const params       = useParams();
  const router       = useRouter();
  const searchParams = useSearchParams();

  const findingId = params.id;
  const source    = searchParams.get('source') || 'sast';
  const scanId    = searchParams.get('scan_id');
  const ruleId    = searchParams.get('rule_id');

  const [finding,      setFinding]      = useState(null);
  const [allFindings,  setAllFindings]  = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [error,        setError]        = useState(null);

  // ---------------------------------------------------------------------------
  // Data fetch
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!findingId) return;

    const load = async () => {
      setLoading(true);
      setError(null);

      try {
        if (source === 'sast' && scanId) {
          const raw = await getFromEngine('secops', `/api/v1/secops/sast/scan/${scanId}/findings?limit=500`);
          const list = Array.isArray(raw) ? raw : (raw?.findings || []);
          setAllFindings(list);
          const found = list.find(f =>
            String(f.id) === String(findingId) ||
            (f.rule_id === ruleId && String(f.id) === String(findingId))
          ) || list.find(f => String(f.id) === String(findingId))
            || list.find(f => f.rule_id === ruleId);
          setFinding(found || null);
          if (!found) setError('Finding not found in this scan.');

        } else if (source === 'dast' && scanId) {
          const raw = await getFromEngine('secops', `/api/v1/secops/dast/scan/${scanId}/findings?limit=500`);
          const list = Array.isArray(raw) ? raw : (raw?.findings || []);
          setAllFindings(list);
          const found = list.find(f => String(f.id) === String(findingId))
            || list.find(f => f.rule_id === ruleId);
          setFinding(found || null);
          if (!found) setError('Finding not found in this scan.');

        } else if (source === 'sca') {
          // SCA findings are passed via query params — reconstruct minimal shape from searchParams
          const name    = searchParams.get('name')    || '';
          const version = searchParams.get('version') || '';
          const purl    = searchParams.get('purl')    || '';
          const cves    = searchParams.get('cves')    || '';
          const synth = {
            id:               findingId,
            name,
            version,
            purl,
            vulnerability_ids: cves ? cves.split(',') : [],
            severity:         searchParams.get('severity') || 'medium',
            status:           searchParams.get('status')   || 'open',
          };
          setFinding(synth);
          setAllFindings([synth]);

        } else {
          setError('Missing scan_id or unsupported source. Cannot load finding.');
        }
      } catch (err) {
        setError(err?.message || 'Failed to load finding data.');
      } finally {
        setLoading(false);
      }
    };

    load();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId, source, scanId, ruleId]);

  // ---------------------------------------------------------------------------
  // Derived data
  // ---------------------------------------------------------------------------
  const normalizedSev = useMemo(() => normalizeSev(finding?.severity), [finding]);

  const meta = useMemo(() => finding?.metadata || {}, [finding]);

  // Other occurrences of same rule_id
  const otherOccurrences = useMemo(() => {
    if (!finding || !finding.rule_id) return [];
    return allFindings
      .filter(f => f.rule_id === finding.rule_id && String(f.id) !== String(findingId))
      .slice(0, 5);
  }, [allFindings, finding, findingId]);

  const vulnTitle = toTitleCase(finding?.rule_id || finding?.vulnerability_type || '—');

  // ---------------------------------------------------------------------------
  // Loading / error states
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]" style={{ color: 'var(--text-tertiary)' }}>
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          Loading vulnerability details...
        </div>
      </div>
    );
  }

  if (error && !finding) {
    return (
      <div className="px-6 py-8 space-y-4">
        <button
          onClick={() => router.back()}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-tertiary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Back
        </button>
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-red-400">Failed to load vulnerability</div>
            <div className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{error}</div>
          </div>
        </div>
      </div>
    );
  }

  const f = finding || {};
  const isSast = source === 'sast';
  const isDast = source === 'dast';
  const isSca  = source === 'sca';

  const cvssScore  = meta.cvss_score;
  const httpMethod = meta.http_method || f.http_method;
  const scanDate   = searchParams.get('scan_date') || '';

  const fixText = isDast
    ? (meta.remediation || `Review and address this ${f.vulnerability_type || 'vulnerability'} finding.`)
    : isSca
    ? 'Update the affected package to a version without known vulnerabilities. Check the CVE advisories for patched releases.'
    : getSastFix(f.rule_id);

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="px-6 pt-6 pb-8 space-y-6 max-w-7xl mx-auto">

        {/* Back button */}
        <button
          onClick={() => router.back()}
          className="flex items-center gap-2 text-sm mb-6 hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-tertiary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Back
        </button>

        {/* ----------------------------------------------------------------- */}
        {/* Header card                                                        */}
        {/* ----------------------------------------------------------------- */}
        <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <div className="px-6 py-5 border-b" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>

            {/* Title row */}
            <div className="flex items-center gap-3 flex-wrap mb-3">
              <SeverityBadge severity={normalizedSev} />
              <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
                {vulnTitle}
              </h1>
            </div>

            {/* Source badges row */}
            <div className="flex items-center gap-2 flex-wrap mb-3">
              <SourceBadge source={source} />
              {f.language && (
                <span className="inline-flex items-center text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-slate-500/15 text-slate-400 border-slate-500/30">
                  {f.language}
                </span>
              )}
            </div>

            {/* Meta row */}
            <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs" style={{ color: 'var(--text-tertiary)' }}>
              {meta.cwe && (
                <span>
                  CWE: <span className="font-mono text-orange-400">{meta.cwe}</span>
                </span>
              )}
              {meta.owasp && (
                <span>
                  OWASP: <span style={{ color: 'var(--text-secondary)' }}>{meta.owasp}</span>
                </span>
              )}
              {isSast && f.language && (
                <span>
                  Language: <span style={{ color: 'var(--text-secondary)' }}>{f.language}</span>
                </span>
              )}
              {scanDate && (
                <span>
                  Scan: <span style={{ color: 'var(--text-secondary)' }}>{fmtDate(scanDate)}</span>
                </span>
              )}
            </div>
          </div>

          {/* 4 mini-cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-5">
            <MiniCard label="Severity">
              <SeverityBadge severity={normalizedSev} />
            </MiniCard>

            <MiniCard label="Source Engine">
              <SourceBadge source={source} />
            </MiniCard>

            <MiniCard label={isSca ? 'Package' : isDast ? 'Endpoint' : 'File'}>
              {isSca ? (
                <span className="text-xs font-mono" style={{ color: 'var(--text-primary)' }}>
                  {f.name ? `${f.name}@${f.version || '?'}` : '—'}
                </span>
              ) : isDast ? (
                <span className="text-xs font-mono truncate block max-w-[180px]" title={f.endpoint_url || f.resource || '—'} style={{ color: 'var(--text-primary)' }}>
                  {f.endpoint_url || f.resource || '—'}
                </span>
              ) : (
                <span className="text-xs font-mono" style={{ color: 'var(--text-primary)' }}>
                  {f.file_path ? `${f.file_path}${f.line_number ? `:${f.line_number}` : ''}` : '—'}
                </span>
              )}
            </MiniCard>

            <MiniCard label="Status">
              <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                f.status === 'resolved'
                  ? 'bg-green-500/15 text-green-400'
                  : f.status === 'open' || !f.status
                  ? 'bg-orange-500/15 text-orange-400'
                  : 'bg-slate-500/15 text-slate-400'
              }`}>
                {f.status || 'open'}
              </span>
            </MiniCard>
          </div>
        </div>

        {/* ----------------------------------------------------------------- */}
        {/* Two-column layout                                                  */}
        {/* ----------------------------------------------------------------- */}
        <div className="grid grid-cols-3 gap-6">

          {/* ---------------------------------------------------------------- */}
          {/* LEFT COLUMN (2/3)                                                */}
          {/* ---------------------------------------------------------------- */}
          <div className="col-span-3 lg:col-span-2 space-y-5">

            {/* Description card */}
            <SectionCard title="What is this vulnerability?" subtitle="Full description of the detected issue">
              <div className="text-sm leading-relaxed mb-4" style={{ color: 'var(--text-secondary)' }}>
                {f.message || f.description || '—'}
              </div>

              {isSast && f.file_path && (
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>
                    Location
                  </div>
                  <pre className="font-mono text-xs p-3 rounded-lg overflow-x-auto" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                    {`// File: ${f.file_path}${f.line_number ? ` line ${f.line_number}` : ''}`}
                  </pre>
                </div>
              )}
            </SectionCard>

            {/* Evidence card */}
            {(isDast || isSca || (isSast && (f.file_path || meta.code_context))) && (
              <SectionCard
                title={isDast ? 'Evidence' : isSca ? 'Affected Package Details' : 'Code Context'}
                subtitle={
                  isDast
                    ? 'Request details and payload captured during scan'
                    : isSca
                    ? 'Package and vulnerability identifiers'
                    : 'Source file location and context'
                }
              >
                {isDast && (
                  <div className="space-y-4">
                    {meta.parameter_name && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
                          Parameter
                        </div>
                        <pre className="font-mono text-xs p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                          {meta.parameter_name}
                        </pre>
                      </div>
                    )}
                    {meta.payload && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
                          Payload Used
                        </div>
                        <pre className="font-mono text-xs p-3 rounded-lg overflow-x-auto" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                          {meta.payload}
                        </pre>
                      </div>
                    )}
                    {meta.evidence && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
                          Raw Evidence
                        </div>
                        <pre className="font-mono text-xs p-3 rounded-lg overflow-x-auto" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                          {meta.evidence}
                        </pre>
                      </div>
                    )}
                    {!meta.parameter_name && !meta.payload && !meta.evidence && (
                      <div className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
                        No additional evidence recorded for this finding.
                      </div>
                    )}
                  </div>
                )}

                {isSca && (
                  <div className="space-y-4">
                    <div className="flex flex-wrap gap-4">
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Package</div>
                        <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{f.name || '—'}</span>
                      </div>
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Version</div>
                        <span className="text-sm font-mono text-orange-400">{f.version || '—'}</span>
                      </div>
                    </div>
                    {f.purl && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>PURL</div>
                        <pre className="font-mono text-xs p-3 rounded-lg overflow-x-auto" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                          {f.purl}
                        </pre>
                      </div>
                    )}
                    {f.vulnerability_ids && f.vulnerability_ids.length > 0 && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>
                          CVE Identifiers ({f.vulnerability_ids.length})
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {f.vulnerability_ids.map(cve => (
                            <span key={cve} className="text-xs font-mono px-2 py-0.5 rounded-md bg-red-500/10 text-red-400 border border-red-500/20">
                              {cve}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {isSast && (
                  <div className="space-y-3">
                    {f.file_path && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
                          File Path
                        </div>
                        <pre className="font-mono text-xs p-3 rounded-lg overflow-x-auto" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                          {f.file_path}{f.line_number ? ` (line ${f.line_number})` : ''}
                        </pre>
                      </div>
                    )}
                    {meta.code_context && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
                          Code Context
                        </div>
                        <pre className="font-mono text-xs p-3 rounded-lg overflow-x-auto" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                          {meta.code_context}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </SectionCard>
            )}

            {/* Fix / Remediation card */}
            <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-5 py-4 border-b flex items-center gap-3" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>How to fix this</div>
              </div>
              <div className="p-5">
                <div className="border-l-4 border-blue-500 bg-blue-500/5 rounded-r-xl px-4 py-4">
                  <div className="flex items-start gap-3">
                    <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                    <div className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                      {fixText}
                    </div>
                  </div>
                </div>

                {isDast && meta.cvss_vector && (
                  <div className="mt-4">
                    <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>CVSS Vector</div>
                    <pre className="font-mono text-xs p-3 rounded-lg overflow-x-auto" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                      {meta.cvss_vector}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ---------------------------------------------------------------- */}
          {/* RIGHT COLUMN (1/3)                                               */}
          {/* ---------------------------------------------------------------- */}
          <div className="col-span-3 lg:col-span-1 space-y-5">

            {/* Affected Asset card */}
            <SectionCard title="Affected Asset" subtitle={
              isSast ? 'Source file location' : isDast ? 'Scanned endpoint' : 'Vulnerable package'
            }>
              {isSast && (
                <div className="space-y-3">
                  {f.file_path && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>File</div>
                      <span className="text-xs font-mono break-all" style={{ color: 'var(--text-primary)' }}>{f.file_path}</span>
                    </div>
                  )}
                  {f.line_number && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Line</div>
                      <span className="text-sm font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>{f.line_number}</span>
                    </div>
                  )}
                  {f.language && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Language</div>
                      <span className="text-xs px-2 py-0.5 rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20">
                        {f.language}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {isDast && (
                <div className="space-y-3">
                  {f.endpoint_url && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Endpoint</div>
                      <span className="text-xs font-mono break-all" style={{ color: 'var(--text-primary)' }}>{f.endpoint_url}</span>
                    </div>
                  )}
                  {httpMethod && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Method</div>
                      <MethodBadge method={httpMethod} />
                    </div>
                  )}
                  {f.resource && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Resource</div>
                      <span className="text-xs font-mono break-all" style={{ color: 'var(--text-secondary)' }}>{f.resource}</span>
                    </div>
                  )}
                </div>
              )}

              {isSca && (
                <div className="space-y-3">
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Package</div>
                    <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                      {f.name || '—'}{f.version ? `@${f.version}` : ''}
                    </span>
                  </div>
                  {f.purl && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>PURL</div>
                      <span className="text-xs font-mono break-all" style={{ color: 'var(--text-secondary)' }}>
                        {f.purl.length > 60 ? f.purl.slice(0, 60) + '...' : f.purl}
                      </span>
                    </div>
                  )}
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>CVEs</div>
                    <span className="text-xl font-bold tabular-nums text-red-400">
                      {(f.vulnerability_ids || []).length}
                    </span>
                  </div>
                </div>
              )}
            </SectionCard>

            {/* Vulnerability Info card */}
            <SectionCard title="Vulnerability Info" subtitle="Classification and scoring">
              <div className="space-y-3">
                {meta.cwe && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>CWE</div>
                    <span className="text-xs font-mono px-2 py-1 rounded-md bg-orange-500/10 text-orange-400 border border-orange-500/20">
                      {meta.cwe}
                    </span>
                  </div>
                )}

                {meta.owasp && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>OWASP Category</div>
                    <span className="text-xs px-2 py-1 rounded-md bg-red-500/10 text-red-400 border border-red-500/20">
                      {meta.owasp}
                    </span>
                  </div>
                )}

                {cvssScore != null && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>CVSS Score</div>
                    <span className="text-2xl font-bold tabular-nums" style={{ color: cvssColor(cvssScore) }}>
                      {cvssScore}
                    </span>
                    <span className="text-xs ml-1" style={{ color: 'var(--text-tertiary)' }}>/10</span>
                  </div>
                )}

                {meta.confidence && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Confidence</div>
                    <span className="text-sm capitalize" style={{ color: 'var(--text-secondary)' }}>{meta.confidence}</span>
                  </div>
                )}

                <div>
                  <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>Rule ID</div>
                  <span className="text-xs font-mono break-all" style={{ color: 'var(--text-secondary)' }}>
                    {f.rule_id || f.vulnerability_type || '—'}
                  </span>
                </div>
              </div>
            </SectionCard>

            {/* Related Findings card */}
            {otherOccurrences.length > 0 && (
              <SectionCard
                title="Other Occurrences"
                subtitle={`${otherOccurrences.length} more instance${otherOccurrences.length > 1 ? 's' : ''} of this rule`}
              >
                <div className="space-y-2">
                  {otherOccurrences.map((occ, i) => {
                    const label = isSast
                      ? `${occ.file_path || '—'}${occ.line_number ? `:${occ.line_number}` : ''}`
                      : isDast
                      ? (occ.endpoint_url || occ.resource || '—')
                      : `${occ.name || '—'}@${occ.version || '?'}`;

                    const detailUrl = `/secops/vuln/${occ.id || i}?source=${source}&scan_id=${scanId || ''}&rule_id=${occ.rule_id || ''}`;

                    return (
                      <div
                        key={occ.id || i}
                        className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg border"
                        style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}
                      >
                        <span className="text-xs font-mono truncate flex-1" style={{ color: 'var(--text-secondary)' }} title={label}>
                          {label}
                        </span>
                        <button
                          onClick={() => router.push(detailUrl)}
                          className="flex items-center gap-1 text-xs text-blue-400 hover:opacity-75 transition-opacity flex-shrink-0"
                        >
                          View
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      </div>
                    );
                  })}
                </div>

                {scanId && (
                  <div className="mt-3">
                    <button
                      onClick={() => router.push(
                        source === 'sast'
                          ? `/secops/${scanId}`
                          : source === 'dast'
                          ? `/secops/dast/${scanId}`
                          : `/secops/sca/${scanId}`
                      )}
                      className="text-xs text-blue-400 hover:opacity-75 transition-opacity">
                      View all in scan
                    </button>
                  </div>
                )}
              </SectionCard>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
