'use client';

import { useEffect, useState } from 'react';
import { X, ExternalLink, Copy, Check, ShieldCheck, ArrowRight, ArrowLeft, Search, AlertOctagon, GitBranch, Tag, Crown, Zap, Activity } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import { resolveModule } from '@/lib/engine-modules';

// ── Helpers ───────────────────────────────────────────────────────────────────

function Field({ label, value, mono = false, copy = false }) {
  const [copied, setCopied] = useState(false);
  if (!value && value !== 0) return null;
  const doCopy = () => {
    navigator.clipboard.writeText(String(value));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-xs font-medium shrink-0 w-28" style={{ color: 'var(--text-muted)' }}>{label}</span>
      <div className="flex items-center gap-1.5 min-w-0 flex-1 justify-end">
        {mono
          ? <code className="text-xs break-all" style={{ color: 'var(--text-secondary)' }}>{value}</code>
          : <span className="text-xs break-all" style={{ color: 'var(--text-secondary)' }}>{value}</span>}
        {copy && (
          <button onClick={doCopy} className="shrink-0 p-0.5 rounded hover:opacity-70" style={{ color: 'var(--text-muted)' }}>
            {copied ? <Check className="w-3.5 h-3.5" style={{ color: '#22c55e' }} /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <section className="space-y-3">
      <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{title}</h3>
      {children}
    </section>
  );
}

function Card({ children, blue = false }) {
  return (
    <div className="rounded-lg border p-4"
      style={{
        backgroundColor: blue ? 'rgba(59,130,246,0.06)' : 'var(--bg-secondary)',
        borderColor: blue ? 'rgba(59,130,246,0.2)' : 'var(--border-primary)',
      }}>
      {children}
    </div>
  );
}

function ScoreBar({ label, score }) {
  if (score == null) return null;
  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs w-32 shrink-0" style={{ color: 'var(--text-muted)' }}>{label}</span>
      <div className="flex-1 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(score, 100)}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-bold w-8 text-right" style={{ color }}>{score}</span>
    </div>
  );
}

function Skeleton({ lines = 3 }) {
  return (
    <div className="space-y-3 animate-pulse">
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="h-3 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', width: `${65 + (i % 3) * 12}%` }} />
      ))}
    </div>
  );
}

const ENGINE_LABELS = {
  check: 'Config Check', network: 'Network', iam: 'IAM',
  datasec: 'Data Security', encryption: 'Encryption',
  container_security: 'Container', ai_security: 'AI Security',
  database_security: 'Database', vulnerability: 'Vulnerability',
  secops: 'SecOps', cdr: 'CDR', api_security: 'API Security',
};

const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
const SEV_RANK  = { critical: 4, high: 3, medium: 2, low: 1 };
const SEV_CLR   = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

const PANEL_TABS = [
  { id: 'overview',    label: 'Overview' },
  { id: 'score',       label: 'Score Breakdown' },
  { id: 'remediation', label: 'Remediation' },
  { id: 'context',     label: 'Context' },
];

// ── IAM Identity Section ──────────────────────────────────────────────────────
function IamIdentitySection({ finding, context, rels = [] }) {
  const [issuesExpanded, setIssuesExpanded] = useState(false);
  const [relsExpanded, setRelsExpanded] = useState(false);
  const allFindings  = context.allFindings  || [];
  const moduleLabels = context.moduleLabels || {};
  const identityName = finding.identity_name || '';

  const otherIssues = allFindings.filter(f =>
    f.identity_name && f.identity_name === identityName &&
    (f.finding_id || f.rule_id) !== (finding.finding_id || finding.rule_id)
  ).sort((a, b) => (SEV_RANK[b.severity?.toLowerCase()] || 0) - (SEV_RANK[a.severity?.toLowerCase()] || 0));

  const outbound   = rels.filter(r => r.direction === 'outbound');
  const inbound    = rels.filter(r => r.direction === 'inbound');
  const issueShowN = issuesExpanded ? otherIssues.length : 4;
  const relShowN   = relsExpanded   ? rels.length        : 5;
  const rtype = (t = '') => t.replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ');
  const suid  = (uid = '') => uid.split(/[/:?]/).filter(Boolean).pop() || uid;

  return (
    <>
      {finding.identity_name && (
        <Section title="Identity">
          <Card>
            <div className="flex items-start justify-between gap-4">
              <span className="text-xs font-medium shrink-0 w-28" style={{ color: 'var(--text-muted)' }}>Name</span>
              <code className="text-xs break-all flex-1" style={{ color: 'var(--text-secondary)' }}>{finding.identity_name}</code>
            </div>
          </Card>
        </Section>
      )}

      {otherIssues.length > 0 && (
        <Section title={`Other issues for this identity (${otherIssues.length})`}>
          <div className="space-y-1.5">
            {otherIssues.slice(0, issueShowN).map((f, i) => (
              <div key={f.finding_id || i}
                className="flex items-center gap-2 px-3 py-2 rounded border"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded shrink-0"
                  style={{ backgroundColor: `${SEV_CLR[f.severity?.toLowerCase()] || '#888'}22`, color: SEV_CLR[f.severity?.toLowerCase()] || '#888' }}>
                  {f.severity?.slice(0, 4) || '—'}
                </span>
                <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-secondary)' }} title={f.title || f.rule_id}>
                  {f.title || f.rule_id || '—'}
                </span>
                {f.iam_module && (
                  <span className="text-[10px] shrink-0" style={{ color: 'var(--text-muted)' }}>
                    {moduleLabels[f.iam_module] || f.iam_module}
                  </span>
                )}
              </div>
            ))}
            {otherIssues.length > 4 && (
              <button onClick={() => setIssuesExpanded(e => !e)}
                className="text-xs w-full text-center py-1.5 rounded border transition-opacity hover:opacity-70"
                style={{ color: 'var(--accent-primary)', borderColor: 'var(--border-primary)' }}>
                {issuesExpanded ? 'Show less' : `Show ${otherIssues.length - 4} more`}
              </button>
            )}
          </div>
        </Section>
      )}

      {rels.length > 0 && (
        <Section title={`Connections (${rels.length})`}>
          <div className="space-y-1.5">
            {outbound.length > 0 && (
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>
                Outbound — {outbound.length}
              </p>
            )}
            {outbound.slice(0, relShowN).map((r, i) => (
              <div key={`out-${i}`} className="flex items-center gap-1.5 px-3 py-2 rounded border"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                <span className="text-[10px] font-medium px-1.5 py-0.5 rounded shrink-0"
                  style={{ backgroundColor: 'rgba(99,102,241,0.12)', color: '#818cf8' }}>
                  {rtype(r.source_resource_type || finding.resource_type) || 'this'}
                </span>
                <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-muted)' }} />
                <span className="text-[10px] shrink-0 font-medium" style={{ color: 'var(--text-muted)' }}>
                  {(r.relationship_type || '').replace(/_/g, ' ')}
                </span>
                <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-muted)' }} />
                <div className="flex flex-col min-w-0 flex-1">
                  <span className="text-xs truncate" style={{ color: 'var(--text-secondary)' }}
                    title={r.related_resource_uid || r.target_resource_uid}>
                    {r.related_resource_name || suid(r.related_resource_uid || r.target_resource_uid || '')}
                  </span>
                  {r.related_resource_type && (
                    <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{rtype(r.related_resource_type)}</span>
                  )}
                </div>
              </div>
            ))}
            {inbound.length > 0 && (
              <p className={`text-[10px] font-semibold uppercase tracking-wider mb-1${outbound.length > 0 ? ' mt-3' : ''}`}
                style={{ color: 'var(--text-muted)' }}>
                Inbound — {inbound.length}
              </p>
            )}
            {inbound.slice(0, relShowN).map((r, i) => (
              <div key={`in-${i}`} className="flex items-center gap-1.5 px-3 py-2 rounded border"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                <div className="flex flex-col min-w-0 flex-1">
                  <span className="text-xs truncate" style={{ color: 'var(--text-secondary)' }}
                    title={r.related_resource_uid || r.source_resource_uid}>
                    {r.related_resource_name || suid(r.related_resource_uid || r.source_resource_uid || '')}
                  </span>
                  {r.related_resource_type && (
                    <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{rtype(r.related_resource_type)}</span>
                  )}
                </div>
                <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-muted)' }} />
                <span className="text-[10px] shrink-0 font-medium" style={{ color: 'var(--text-muted)' }}>
                  {(r.relationship_type || '').replace(/_/g, ' ')}
                </span>
                <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-muted)' }} />
                <span className="text-[10px] font-medium px-1.5 py-0.5 rounded shrink-0"
                  style={{ backgroundColor: 'rgba(99,102,241,0.12)', color: '#818cf8' }}>
                  {rtype(r.target_resource_type || finding.resource_type) || 'this'}
                </span>
              </div>
            ))}
            {rels.length > 5 && (
              <button onClick={() => setRelsExpanded(e => !e)}
                className="text-xs w-full text-center py-1.5 rounded border transition-opacity hover:opacity-70"
                style={{ color: 'var(--accent-primary)', borderColor: 'var(--border-primary)' }}>
                {relsExpanded ? 'Show less' : `Show ${rels.length - 5} more`}
              </button>
            )}
          </div>
        </Section>
      )}
    </>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
/**
 * @param {object}   finding                 — finding row object from any engine table
 * @param {function} onClose                 — called when ✕ or backdrop clicked
 * @param {object}   [context]               — optional page-specific config
 * @param {string}   [context.engine]        — engine key (e.g. "network")
 * @param {Array}    [context.fields]        — extra { label, value, mono } rows
 * @param {function} [context.renderExtra]   — (finding) => ReactNode appended to Overview tab
 */
export default function FindingDetailPanel({ finding, onClose, context = {} }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [resourceCtx, setResourceCtx] = useState(null);
  const [ctxLoading, setCtxLoading] = useState(false);

  const resourceId = finding?.resource_uid || finding?.resource_arn || finding?.resource_id || '';

  // Reset tab & async data when a different finding opens
  useEffect(() => {
    setActiveTab('overview');
    setResourceCtx(null);
  }, [finding?.finding_id, finding?.rule_id]);

  useEffect(() => {
    if (!resourceId || !finding) return;
    let cancelled = false;
    setCtxLoading(true);

    fetch(`/gateway/api/v1/views/resource/${encodeURIComponent(resourceId)}`, { credentials: 'include' })
      .then(r => (r.ok ? r.json() : null))
      .then(data  => { if (!cancelled) setResourceCtx(data); })
      .catch(()   => { if (!cancelled) setResourceCtx(null); })
      .finally(() => { if (!cancelled) setCtxLoading(false); });

    return () => { cancelled = true; };
  }, [resourceId]);

  if (!finding) return null;

  // ── Normalise fields ─────────────────────────────────────────────────────
  const title       = finding.title         || finding.rule_id       || 'Finding';
  const sev         = (finding.severity || 'low').toLowerCase();
  const status      = finding.status        || 'FAIL';
  const isFail      = status === 'FAIL';
  const service     = finding.service       || finding.container_service || finding.db_service || finding.encryption_domain || finding.network_layer || '';
  const domain      = finding.domain        || finding.security_domain   || finding.posture_category || finding.encryption_domain || '';
  const riskScore   = finding.risk_score    ?? null;
  const description = finding.description   || finding.rationale     || '';
  const _r          = finding.remediation;
  const remediation = typeof _r === 'string' ? _r
    : _r?.summary || (Array.isArray(_r?.steps) ? _r.steps.join('\n') : '') || '';
  const accountId   = finding.account_id    || finding.account       || finding.hierarchy_id || '';
  const provider    = (finding.provider     || 'aws').toUpperCase();
  const createdAt   = finding.created_at    || finding.first_seen_at || '';
  const riskColor   = riskScore >= 75 ? '#ef4444' : riskScore >= 50 ? '#f97316' : riskScore >= 25 ? '#eab308' : '#22c55e';

  const frameworks    = Array.isArray(finding.compliance_frameworks)
    ? finding.compliance_frameworks
    : (finding.compliance_frameworks && typeof finding.compliance_frameworks === 'object')
      ? Object.keys(finding.compliance_frameworks)
      : [];
  const tactics       = Array.isArray(finding.mitre_tactics)    ? finding.mitre_tactics    : [];
  const techniques    = Array.isArray(finding.mitre_techniques) ? finding.mitre_techniques : [];
  const checkedFields = finding.checked_fields;
  const actualValues  = finding.actual_values;
  const extraFields   = context.fields || [];

  const asset        = resourceCtx?.resource          || null;
  const posture      = resourceCtx?.posture           || null;
  const fSummary     = resourceCtx?.findings_summary  || null;
  const rels         = resourceCtx?.relationships     || [];
  const openFindings = resourceCtx?.open_findings     || [];
  const attackPaths  = resourceCtx?.attack_paths      || [];
  const inbound  = rels.filter(r => r.direction === 'inbound');
  const outbound = rels.filter(r => r.direction === 'outbound');

  // ── IAM policies helper ───────────────────────────────────────────────────
  const renderIamPolicies = () => {
    const rawCf = finding.checked_fields;
    const rawAv = finding.actual_values;
    const cfIsArray  = Array.isArray(rawCf) && rawCf.length > 0;
    const cfIsObject = rawCf && typeof rawCf === 'object' && !Array.isArray(rawCf);
    const avIsObject = rawAv && typeof rawAv === 'object' && !Array.isArray(rawAv);
    const cfEntries  = cfIsObject ? Object.entries(rawCf) : [];
    const avEntries  = avIsObject ? Object.entries(rawAv) : [];
    const kvEvidence = Object.fromEntries([...cfEntries, ...avEntries]);
    const entries    = Object.entries(kvEvidence);
    if (!cfIsArray && entries.length === 0) return null;

    const isPolicyKey = k => /polic|permission|action|resource|effect|statement|access|privilege|role|group|princi|allow|deny|boundary|entitl/i.test(k);
    const policyEntries = entries.filter(([k]) => isPolicyKey(k));
    const checkEntries  = entries.filter(([k]) => !isPolicyKey(k));
    const humanLabel = k => k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    const renderVal = v => {
      if (v === null || v === undefined) return '—';
      if (typeof v === 'boolean') return v ? 'Yes' : 'No';
      if (Array.isArray(v)) { if (!v.length) return '(none)'; if (v.every(x => typeof x !== 'object')) return v.join(', '); return JSON.stringify(v, null, 2); }
      if (typeof v === 'object') return JSON.stringify(v, null, 2);
      return String(v);
    };
    const isBlock = v => (typeof v === 'object' && v !== null) || (typeof v === 'string' && v.length > 80);
    const isBool  = v => typeof v === 'boolean';
    const boolClr = v => v ? '#22c55e' : '#ef4444';
    const EvidenceRow = ({ label, value }) => {
      const rendered = renderVal(value);
      if (isBlock(value)) return (
        <div className="rounded border p-3" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
          <span className="text-[10px] font-semibold uppercase tracking-wider block mb-1.5" style={{ color: 'var(--text-muted)' }}>{label}</span>
          <pre className="text-[10px] overflow-x-auto whitespace-pre-wrap leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{rendered}</pre>
        </div>
      );
      return (
        <div className="flex items-start justify-between gap-4">
          <span className="text-xs font-medium shrink-0 w-44" style={{ color: 'var(--text-muted)' }}>{label}</span>
          <span className="text-xs flex-1 text-right" style={{ color: isBool(value) ? boolClr(value) : 'var(--text-secondary)', fontWeight: isBool(value) ? 600 : 400 }}>{rendered}</span>
        </div>
      );
    };
    return (
      <>
        {cfIsArray && (
          <Section title="Fields Evaluated">
            <Card>
              <div className="flex flex-wrap gap-2">
                {rawCf.map((f, i) => (
                  <span key={i} className="text-xs px-2.5 py-1 rounded border font-mono"
                    style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>{f}</span>
                ))}
              </div>
            </Card>
          </Section>
        )}
        {policyEntries.length > 0 && (
          <Section title="Policy & Access Details">
            <div className="space-y-2">
              {policyEntries.map(([k, v]) => <EvidenceRow key={k} label={humanLabel(k)} value={v} />)}
            </div>
          </Section>
        )}
        {checkEntries.length > 0 && (
          <Section title="Check Evidence">
            <Card><div className="space-y-2.5">
              {checkEntries.map(([k, v]) => <EvidenceRow key={k} label={humanLabel(k)} value={v} />)}
            </div></Card>
          </Section>
        )}
      </>
    );
  };

  // ── Encryption details helper ─────────────────────────────────────────────
  const renderEncDetails = () => {
    const fd = finding.finding_data || {};
    const encFields = [
      { label: 'Encryption Domain', value: finding.encryption_domain || finding.security_domain || fd.encryption_domain, plain: true },
      { label: 'Encryption Status', value: finding.encryption_status || fd.encryption_status },
      { label: 'Key Type',          value: finding.key_type   || fd.key_type   || fd.key_manager },
      { label: 'Algorithm',         value: finding.algorithm  || fd.algorithm  || fd.key_algorithm },
      { label: 'KMS Key ID',        value: finding.kms_key_id || fd.kms_key_id || fd.key_id, mono: true },
      { label: 'Key Status',        value: finding.key_status || fd.key_status },
      { label: 'Rotation',
        value: finding.rotation_compliant != null
          ? (finding.rotation_compliant ? 'Compliant' : 'Non-compliant')
          : (fd.rotation_enabled != null ? (fd.rotation_enabled ? 'Enabled' : 'Disabled') : null) },
      { label: 'Last Rotated',      value: finding.last_rotated || fd.last_rotated },
      { label: 'In-Transit (TLS)',  value: finding.transit_enforced != null ? (finding.transit_enforced ? 'Enforced' : 'Not enforced') : null },
      { label: 'TLS Version',       value: finding.tls_version || fd.tls_version },
      { label: 'Cert Domain',       value: finding.domain  || fd.domain || fd.cert_domain },
      { label: 'Issuer',            value: finding.issuer  || fd.issuer },
      { label: 'Expires',           value: finding.expires_at || fd.expires_at },
      { label: 'Days Until Expiry', value: finding.days_until_expiry ?? fd.days_until_expiry ?? fd.cert_days_remaining },
    ].filter(f => f.value != null && f.value !== '');

    const rawCf   = finding.checked_fields;
    const cfIsArr = Array.isArray(rawCf) && rawCf.length > 0;
    if (!encFields.length && !cfIsArr) return null;

    const encColor = (label, value) => {
      const v = String(value).toLowerCase();
      if (/non.compliant|disabled|not enforced|unencrypted|expired/.test(v)) return '#ef4444';
      if (/compliant|enabled|enforced|encrypted|active|issued/.test(v))      return '#22c55e';
      return 'var(--text-secondary)';
    };
    return (
      <>
        {encFields.length > 0 && (
          <Section title="Encryption Details">
            <Card>
              <div className="space-y-2.5">
                {encFields.map(f => (
                  <div key={f.label} className="flex items-start justify-between gap-4">
                    <span className="text-xs font-medium shrink-0 w-36" style={{ color: 'var(--text-muted)' }}>{f.label}</span>
                    {f.mono
                      ? <code className="text-xs break-all flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>{String(f.value)}</code>
                      : <span className="text-xs flex-1 text-right font-medium"
                          style={{ color: f.plain ? 'var(--text-secondary)' : encColor(f.label, f.value) }}>
                          {String(f.value).replace(/_/g, ' ')}
                        </span>
                    }
                  </div>
                ))}
              </div>
            </Card>
          </Section>
        )}
        {cfIsArr && (
          <Section title="Fields Evaluated">
            <Card>
              <div className="flex flex-wrap gap-2">
                {rawCf.map((f, i) => (
                  <span key={i} className="text-xs px-2.5 py-1 rounded border font-mono"
                    style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>{f}</span>
                ))}
              </div>
            </Card>
          </Section>
        )}
      </>
    );
  };

  // ── Network details ──────────────────────────────────────────────────────────
  const renderNetworkDetails = () => {
    const fd = finding.finding_data || {};
    const fields = [
      { label: 'Port',         value: finding.port      || fd.port      || finding.from_port },
      { label: 'Protocol',     value: finding.protocol  || fd.protocol  || finding.ip_protocol },
      { label: 'Source CIDR',  value: finding.source_cidr || fd.source_cidr || finding.cidr_ipv4 || finding.cidr },
      { label: 'Dest CIDR',    value: finding.dest_cidr   || fd.dest_cidr },
      { label: 'Direction',    value: finding.direction   || fd.direction },
      { label: 'SG Rule ID',   value: finding.sg_rule_id  || fd.sg_rule_id, mono: true },
      { label: 'Network Layer',value: finding.network_layer || finding.security_domain },
      { label: 'Exposed',      value: finding.is_internet_exposed != null ? (finding.is_internet_exposed ? 'Yes — internet reachable' : 'No') : null },
    ].filter(f => f.value != null && f.value !== '');
    if (!fields.length) return null;
    const danger = v => /^(0\.0\.0\.0|yes|internet)/i.test(String(v));
    return (
      <Section title="Network Details">
        <Card>
          <div className="space-y-2.5">
            {fields.map(f => (
              <div key={f.label} className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>{f.label}</span>
                {f.mono
                  ? <code className="text-xs break-all flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>{String(f.value)}</code>
                  : <span className="text-xs flex-1 text-right font-medium"
                      style={{ color: danger(f.value) ? '#ef4444' : 'var(--text-secondary)' }}>
                      {String(f.value)}
                    </span>
                }
              </div>
            ))}
          </div>
        </Card>
      </Section>
    );
  };

  // ── Container details ────────────────────────────────────────────────────────
  const renderContainerDetails = () => {
    const fd = finding.finding_data || {};
    const fields = [
      { label: 'Image',           value: finding.image_name   || fd.image_name   || fd.container_image },
      { label: 'Image Tag',       value: finding.image_tag    || fd.image_tag },
      { label: 'Runtime',         value: finding.runtime      || fd.container_runtime },
      { label: 'Privileged',      value: finding.privileged   != null ? (finding.privileged   ? 'Yes — root access' : 'No') : (fd.privileged != null ? (fd.privileged ? 'Yes' : 'No') : null) },
      { label: 'Root Access',     value: finding.root_access  != null ? (finding.root_access  ? 'Yes' : 'No') : null },
      { label: 'CVEs',            value: (finding.cve_count || fd.cve_count) != null ? `${finding.cve_count || fd.cve_count || 0} total (${finding.critical_cve || fd.cve_critical || 0} critical)` : null },
      { label: 'Node Kernel',     value: finding.kernel_version || fd.kernel_version },
      { label: 'Cluster',         value: finding.cluster_name   || fd.cluster_name },
      { label: 'Namespace',       value: finding.namespace       || fd.namespace },
    ].filter(f => f.value != null && f.value !== '');
    if (!fields.length) return null;
    const bad = v => /yes|root/i.test(String(v));
    return (
      <Section title="Container Details">
        <Card>
          <div className="space-y-2.5">
            {fields.map(f => (
              <div key={f.label} className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>{f.label}</span>
                <span className="text-xs flex-1 text-right font-medium"
                  style={{ color: bad(f.value) ? '#ef4444' : 'var(--text-secondary)' }}>
                  {String(f.value)}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </Section>
    );
  };

  // ── AI Security details ──────────────────────────────────────────────────────
  const renderAiDetails = () => {
    const fd = finding.finding_data || {};
    const fields = [
      { label: 'Model ID',       value: finding.model_id       || fd.model_id       || finding.ai_service },
      { label: 'Endpoint URL',   value: finding.endpoint_url   || fd.endpoint_url,  mono: true },
      { label: 'Guardrails',     value: finding.guardrails_enabled != null ? (finding.guardrails_enabled ? 'Enabled' : 'Disabled') : null },
      { label: 'Public Endpoint',value: finding.is_public != null ? (finding.is_public ? 'Yes — exposed' : 'No') : (finding.endpoint_public != null ? (finding.endpoint_public ? 'Yes' : 'No') : null) },
      { label: 'API Key Age',    value: finding.api_key_age_days != null ? `${finding.api_key_age_days} days` : null },
      { label: 'Logging',        value: finding.logging_enabled != null ? (finding.logging_enabled ? 'Enabled' : 'Disabled') : null },
      { label: 'VPC Isolated',   value: finding.vpc_isolated   != null ? (finding.vpc_isolated   ? 'Yes' : 'No — internet access') : null },
    ].filter(f => f.value != null && f.value !== '');
    if (!fields.length) return null;
    const bad = v => /disabled|yes.*expos|no.*internet/i.test(String(v));
    return (
      <Section title="AI Security Details">
        <Card>
          <div className="space-y-2.5">
            {fields.map(f => (
              <div key={f.label} className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>{f.label}</span>
                {f.mono
                  ? <code className="text-xs break-all flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>{String(f.value)}</code>
                  : <span className="text-xs flex-1 text-right font-medium"
                      style={{ color: bad(f.value) ? '#ef4444' : /enabled|yes|vpc/i.test(String(f.value)) ? '#22c55e' : 'var(--text-secondary)' }}>
                      {String(f.value)}
                    </span>
                }
              </div>
            ))}
          </div>
        </Card>
      </Section>
    );
  };

  // ── Database Security details ─────────────────────────────────────────────────
  const renderDbDetails = () => {
    const fd = finding.finding_data || {};
    const fields = [
      { label: 'DB Engine',        value: finding.db_engine    || fd.db_engine    || finding.db_service },
      { label: 'Engine Version',   value: finding.db_version   || fd.db_version   || fd.engine_version },
      { label: 'Public Access',    value: (finding.publicly_accessible ?? fd.publicly_accessible) != null
          ? ((finding.publicly_accessible ?? fd.publicly_accessible) ? 'Yes — public endpoint' : 'No') : null },
      { label: 'Multi-AZ',         value: finding.multi_az     != null ? (finding.multi_az   ? 'Enabled' : 'Disabled') : null },
      { label: 'Backup Retention', value: finding.backup_retention_days != null ? `${finding.backup_retention_days} days` : null },
      { label: 'Storage Encrypted',value: finding.storage_encrypted != null ? (finding.storage_encrypted ? 'Yes' : 'No') : null },
      { label: 'Deletion Protect', value: finding.deletion_protection != null ? (finding.deletion_protection ? 'Enabled' : 'Disabled') : null },
      { label: 'IAM Auth',         value: finding.iam_auth_enabled != null ? (finding.iam_auth_enabled ? 'Enabled' : 'Disabled') : null },
      { label: 'Query Logging',    value: finding.query_logging_enabled != null ? (finding.query_logging_enabled ? 'Enabled' : 'Disabled') : null },
    ].filter(f => f.value != null && f.value !== '');
    if (!fields.length) return null;
    const bad = v => /yes.*public|disabled|no(?! —|$)/i.test(String(v).trim());
    return (
      <Section title="Database Details">
        <Card>
          <div className="space-y-2.5">
            {fields.map(f => (
              <div key={f.label} className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-36" style={{ color: 'var(--text-muted)' }}>{f.label}</span>
                <span className="text-xs flex-1 text-right font-medium"
                  style={{ color: bad(f.value) ? '#ef4444' : /enabled|yes|multi|protected/i.test(String(f.value)) ? '#22c55e' : 'var(--text-secondary)' }}>
                  {String(f.value)}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </Section>
    );
  };

  // ── SLA helper ────────────────────────────────────────────────────────────────
  const renderSla = () => {
    const SLA = { critical: 1, high: 7, medium: 30, low: 90 };
    const sev = (finding.severity || '').toLowerCase();
    const days = SLA[sev];
    if (!days || !finding.first_seen_at) return null;
    const age = Math.floor((Date.now() - new Date(finding.first_seen_at).getTime()) / 86400000);
    const rem = days - age;
    const color = rem < 0 ? '#ef4444' : rem === 0 ? '#f97316' : rem <= 2 ? '#eab308' : 'var(--text-muted)';
    const label = rem < 0 ? `${Math.abs(rem)}d overdue` : rem === 0 ? 'Due today' : `${rem}d remaining`;
    return (
      <span className="text-[10px] font-semibold px-2 py-0.5 rounded border"
        style={{ color, borderColor: color, backgroundColor: `${color}15` }}
        title={`SLA: ${days} days for ${sev} severity`}>
        SLA: {label}
      </span>
    );
  };

  // ── Universal classification block — works for all engines ─────────────────
  const renderClassification = () => {
    const mod = context.engine ? resolveModule(finding, context.engine) : null;
    const cleanType = (finding.resource_type || '').replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ');

    const ENGINE_CATEGORY = {
      iam:                  'Identity & Access',
      datasec:              'Data Security',
      'network-security':   'Network Security',
      network:              'Network Security',
      encryption:           'Encryption',
      'container-security': 'Container Security',
      'database-security':  'Database Security',
      'ai-security':        'AI Security',
      misconfig:            'Cloud Posture',
      check:                'Cloud Posture',
      cdr:                  'Detection & Response',
    };

    const category = ENGINE_CATEGORY[context.engine] || (context.engine ? context.engine.replace(/-/g, ' ') : null);

    return (
      <Section title="Classification">
        <Card>
          <div className="space-y-2">
            {category && (
              <div className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>Engine</span>
                <span className="text-xs flex-1 text-right capitalize" style={{ color: 'var(--text-secondary)' }}>{category}</span>
              </div>
            )}
            {mod && (
              <div className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>Module</span>
                <span className="text-xs font-medium px-2 py-0.5 rounded" style={{ backgroundColor: `${mod.color}18`, color: mod.color }}>
                  {mod.label}
                </span>
              </div>
            )}
            {cleanType && (
              <div className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>Resource Type</span>
                <span className="text-xs flex-1 text-right capitalize" style={{ color: 'var(--text-secondary)' }}>{cleanType}</span>
              </div>
            )}
            {service && (
              <div className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>Service</span>
                <span className="text-xs flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>{service}</span>
              </div>
            )}
            {domain && domain !== service && (
              <div className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>Domain</span>
                <span className="text-xs flex-1 text-right capitalize" style={{ color: 'var(--text-secondary)' }}>{domain.replace(/_/g, ' ')}</span>
              </div>
            )}
            {finding.first_seen_at && (
              <div className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>First Seen</span>
                <span className="text-xs flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>
                  {new Date(finding.first_seen_at).toLocaleDateString()}
                </span>
              </div>
            )}
            {finding.last_seen_at && (
              <div className="flex items-start justify-between gap-4">
                <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>Last Seen</span>
                <span className="text-xs flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>
                  {new Date(finding.last_seen_at).toLocaleDateString()}
                </span>
              </div>
            )}
          </div>
        </Card>
      </Section>
    );
  };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />

      {/* Panel */}
      <div className="relative w-full max-w-2xl h-full flex flex-col shadow-2xl"
        style={{ backgroundColor: 'var(--bg-primary)' }}>

        {/* ── Header ── */}
        <div className="flex-shrink-0 flex items-start justify-between gap-4 px-6 pt-5 pb-4 border-b"
          style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-primary)' }}>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <SeverityBadge severity={finding.severity} />
              <span className={`text-xs font-bold px-2 py-0.5 rounded ${isFail ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                {status}
              </span>
              {renderSla()}
              {provider && (
                <span className="text-xs font-medium px-2 py-0.5 rounded"
                  style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                  {provider}
                </span>
              )}
              {service && (
                <span className="text-xs px-2 py-0.5 rounded"
                  style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                  {service}
                </span>
              )}
            </div>
            <h2 className="text-base font-bold leading-tight" style={{ color: 'var(--text-primary)' }}>
              {title}
            </h2>
            {finding.rule_id && (
              <code className="text-xs mt-1 block" style={{ color: 'var(--text-muted)' }}>
                {finding.rule_id}
              </code>
            )}
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:opacity-70 transition-opacity"
            style={{ color: 'var(--text-muted)' }}>
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* ── Tab Bar ── */}
        <div className="flex-shrink-0 flex border-b px-6"
          style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-primary)' }}>
          {PANEL_TABS.map(tab => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className="px-3 py-2.5 text-sm font-medium border-b-2 transition-colors mr-1"
                style={{
                  color: isActive ? 'var(--accent-primary)' : 'var(--text-muted)',
                  borderColor: isActive ? 'var(--accent-primary)' : 'transparent',
                  backgroundColor: 'transparent',
                }}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* ── Scrollable Tab Content ── */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

          {/* ═══════════════ OVERVIEW TAB ═══════════════ */}
          {activeTab === 'overview' && (
            <>
              {/* Alert Info / Description */}
              {description && (
                <Section title="Alert Info">
                  <Card>
                    <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{description}</p>
                  </Card>
                </Section>
              )}

              {/* Resource */}
              <Section title="Resource">
                <Card>
                  <div className="space-y-2">
                    <Field label="Resource ID"  value={resourceId}            mono copy />
                    <Field label="Type"          value={finding.resource_type} />
                    <Field label="Service"       value={service} />
                    <Field label="Region"        value={finding.region} />
                    <Field label="Account"       value={accountId}             mono />
                    <Field label="Provider"      value={provider} />
                    {createdAt && <Field label="First Seen" value={new Date(createdAt).toLocaleDateString()} />}
                    {extraFields.map(f => (
                      <Field key={f.label} label={f.label} value={f.value} mono={f.mono} />
                    ))}
                  </div>
                </Card>
              </Section>

              {/* Compliance Frameworks */}
              {frameworks.length > 0 && (
                <Section title="Compliance Frameworks">
                  <div className="flex flex-wrap gap-2">
                    {frameworks.map((fw, i) => {
                      const label = typeof fw === 'object' ? (fw.name || fw.id || JSON.stringify(fw)) : fw;
                      return (
                        <span key={i} className="text-xs font-medium px-2.5 py-1 rounded-full"
                          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                          {label}
                        </span>
                      );
                    })}
                  </div>
                </Section>
              )}

              {/* MITRE ATT&CK */}
              {(tactics.length > 0 || techniques.length > 0) && (
                <Section title="MITRE ATT&CK">
                  <div className="flex flex-wrap gap-2">
                    {tactics.map((t, i) => {
                      const label = typeof t === 'object' ? (t.name || t.tactic || JSON.stringify(t)) : t;
                      return (
                        <span key={i} className="text-xs font-medium px-2 py-1 rounded"
                          style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444' }}>
                          {label}
                        </span>
                      );
                    })}
                    {techniques.map((t, i) => {
                      const tid   = typeof t === 'object' ? t.technique_id : null;
                      const tname = typeof t === 'object' ? (t.technique_name || t.name) : t;
                      const label = tid && tname ? `${tid}: ${tname}` : (tname || tid || String(t));
                      return (
                        <span key={i} className="text-xs font-medium px-2 py-1 rounded"
                          style={{ backgroundColor: 'rgba(249,115,22,0.1)', color: '#f97316' }}>
                          {label}
                        </span>
                      );
                    })}
                  </div>
                </Section>
              )}

              {/* Async: Asset Details */}
              {ctxLoading && <Skeleton lines={4} />}
              {!ctxLoading && asset && (
                <Section title="Asset Details">
                  <Card>
                    <div className="space-y-2">
                      <Field label="Name"         value={asset.resource_name} />
                      <Field label="Resource UID" value={asset.resource_uid}  mono copy />
                      <Field label="Type"         value={asset.resource_type} />
                      <Field label="Service"      value={asset.service} />
                      <Field label="Provider"     value={asset.provider?.toUpperCase()} />
                      <Field label="Account"      value={asset.account_id} mono />
                      <Field label="Region"       value={asset.region} />
                      <Field label="First Seen"   value={asset.first_seen_at ? new Date(asset.first_seen_at).toLocaleDateString() : null} />
                      <Field label="Last Seen"    value={asset.last_seen_at  ? new Date(asset.last_seen_at).toLocaleDateString()  : null} />
                    </div>
                  </Card>
                </Section>
              )}

              {/* Async: Tags */}
              {!ctxLoading && asset?.tags && Object.keys(asset.tags).length > 0 && (
                <Section title="Tags">
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(asset.tags).map(([k, v]) => (
                      <span key={k} className="text-xs px-2 py-0.5 rounded border"
                        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
                        {k}: {String(v)}
                      </span>
                    ))}
                  </div>
                </Section>
              )}

              {/* Extra content injected by page (e.g. CorrelationTimeline for CDR) */}
              {context.renderExtra && context.renderExtra(finding)}

              {/* ── Navigation links ── */}
              <div className="flex flex-wrap gap-2 pt-2 border-t" style={{ borderColor: 'var(--border-primary)' }}>
                {resourceId && (
                  <a href={`/inventory/${encodeURIComponent(resourceId)}`}
                    onClick={e => e.stopPropagation()}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium hover:opacity-80 transition-opacity"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                    <ExternalLink className="w-3 h-3" /> View Asset
                  </a>
                )}
                {finding.finding_id && (
                  <a href={`/investigation?finding_id=${encodeURIComponent(finding.finding_id)}`}
                    onClick={e => e.stopPropagation()}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium hover:opacity-80 transition-opacity"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                    <Search className="w-3 h-3" /> Investigation
                  </a>
                )}
                {finding.rule_id && (
                  <a href={`/misconfig?rule=${encodeURIComponent(finding.rule_id)}`}
                    onClick={e => e.stopPropagation()}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium hover:opacity-80 transition-opacity"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                    <AlertOctagon className="w-3 h-3" /> Misconfig
                  </a>
                )}
                {resourceId && (
                  <a href={`/attack-paths?asset=${encodeURIComponent(resourceId)}`}
                    onClick={e => e.stopPropagation()}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium hover:opacity-80 transition-opacity"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                    <GitBranch className="w-3 h-3" style={{ color: '#ea580c' }} />
                    <span style={{ color: '#ea580c' }}>Attack Paths</span>
                  </a>
                )}
              </div>
            </>
          )}

          {/* ═══════════════ SCORE BREAKDOWN TAB ═══════════════ */}
          {activeTab === 'score' && (
            <>
              {/* Risk Score — large display */}
              {riskScore != null ? (
                <Section title="Risk Score">
                  <Card>
                    <div className="flex items-center gap-4 mb-3">
                      <div className="flex flex-col items-center justify-center w-16 h-16 rounded-full border-4 shrink-0"
                        style={{ borderColor: riskColor }}>
                        <span className="text-xl font-bold leading-none" style={{ color: riskColor }}>{riskScore}</span>
                        <span className="text-[9px] font-semibold mt-0.5" style={{ color: 'var(--text-muted)' }}>/ 100</span>
                      </div>
                      <div className="flex-1">
                        <div className="flex justify-between mb-1">
                          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Risk exposure</span>
                          <span className="text-xs font-bold" style={{ color: riskColor }}>
                            {riskScore >= 75 ? 'Critical' : riskScore >= 50 ? 'High' : riskScore >= 25 ? 'Medium' : 'Low'}
                          </span>
                        </div>
                        <div className="h-2 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                          <div className="h-full rounded-full transition-all" style={{ width: `${riskScore}%`, backgroundColor: riskColor }} />
                        </div>
                      </div>
                    </div>
                  </Card>
                </Section>
              ) : (
                <Section title="Risk Score">
                  <Card>
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Risk score not available for this finding.</p>
                  </Card>
                </Section>
              )}

              {/* Security Posture Scores (async) */}
              {ctxLoading && <Skeleton lines={6} />}
              {!ctxLoading && posture && (
                <Section title="Security Posture">
                  <Card>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between pb-2 border-b"
                        style={{ borderColor: 'var(--border-primary)' }}>
                        <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Overall Score</span>
                        <span className="text-lg font-bold"
                          style={{ color: posture.overall_posture_score >= 80 ? '#22c55e' : posture.overall_posture_score >= 60 ? '#eab308' : '#ef4444' }}>
                          {posture.overall_posture_score ?? '—'}
                        </span>
                      </div>
                      <ScoreBar label="IAM"          score={posture.iam_score} />
                      <ScoreBar label="Network"      score={posture.network_score} />
                      <ScoreBar label="Encryption"   score={posture.encryption_score} />
                      <ScoreBar label="API Security" score={posture.api_security_score} />
                      <ScoreBar label="Container"    score={posture.container_security_score} />
                      <ScoreBar label="AI Security"  score={posture.ai_security_score} />
                      <ScoreBar label="Database"     score={posture.dbsec_score} />
                      <div className="pt-2 flex flex-wrap gap-3 text-xs">
                        {posture.is_internet_exposed     && <span style={{ color: '#ef4444' }}>Internet Exposed</span>}
                        {posture.is_encrypted_at_rest    && <span style={{ color: '#22c55e' }}>Encrypted at Rest</span>}
                        {posture.is_encrypted_in_transit && <span style={{ color: '#22c55e' }}>Encrypted in Transit</span>}
                        {posture.has_kms_managed_key     && <span style={{ color: '#22c55e' }}>KMS Managed</span>}
                      </div>
                    </div>
                  </Card>
                </Section>
              )}

              {/* Findings across engines (async) */}
              {!ctxLoading && fSummary && fSummary.total > 0 && (
                <Section title="Findings Across Engines">
                  <div className="space-y-2">
                    {Object.entries(fSummary.by_engine).map(([eng, count]) => (
                      <div key={eng} className="flex items-center justify-between px-3 py-2 rounded border"
                        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                          {ENGINE_LABELS[eng] || eng}
                        </span>
                        <span className="text-xs font-bold px-2 py-0.5 rounded"
                          style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
                          {count}
                        </span>
                      </div>
                    ))}
                    <div className="flex gap-3 pt-1">
                      {Object.entries(fSummary.by_severity).filter(([, n]) => n > 0).map(([s, n]) => (
                        <span key={s} className="text-xs font-bold"
                          style={{ color: SEV_COLOR[s] || 'var(--text-muted)' }}>
                          {n} {s}
                        </span>
                      ))}
                    </div>
                  </div>
                </Section>
              )}

              {/* Classification */}
              {renderClassification()}

              {/* IAM-specific: identity section + policies */}
              {context.engine === 'iam' && <IamIdentitySection finding={finding} context={context} rels={rels} />}
              {context.engine === 'iam' && renderIamPolicies()}

              {/* Encryption-specific: key/cert/rotation config */}
              {context.engine === 'encryption' && renderEncDetails()}

              {/* Network-specific: port, protocol, CIDR, SG rule */}
              {context.engine === 'network-security' && renderNetworkDetails()}

              {/* Container-specific: image, CVEs, privileges, runtime */}
              {context.engine === 'container-security' && renderContainerDetails()}

              {/* AI Security-specific: model, endpoint, guardrails */}
              {context.engine === 'ai-security' && renderAiDetails()}

              {/* Database-specific: engine, backup, public access */}
              {context.engine === 'database-security' && renderDbDetails()}

              {/* Generic evidence (non-IAM, non-enc) */}
              {(checkedFields || actualValues) && context.engine !== 'iam' && context.engine !== 'encryption' && (
                <Section title="Evidence">
                  <div className="rounded-lg border overflow-hidden"
                    style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                    {checkedFields && (
                      <div className="p-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                        <span className="text-xs font-semibold block mb-2" style={{ color: 'var(--text-muted)' }}>Checked Fields</span>
                        <pre className="text-xs overflow-x-auto whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>
                          {typeof checkedFields === 'string' ? checkedFields : JSON.stringify(checkedFields, null, 2)}
                        </pre>
                      </div>
                    )}
                    {actualValues && (
                      <div className="p-4">
                        <span className="text-xs font-semibold block mb-2" style={{ color: 'var(--text-muted)' }}>Actual Values</span>
                        <pre className="text-xs overflow-x-auto whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>
                          {typeof actualValues === 'string' ? actualValues : JSON.stringify(actualValues, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </Section>
              )}
            </>
          )}

          {/* ═══════════════ REMEDIATION TAB ═══════════════ */}
          {activeTab === 'remediation' && (
            <>
              {/* Remediation guidance */}
              {remediation ? (
                <Section title="Remediation Steps">
                  <Card blue>
                    <div className="flex items-start gap-3">
                      <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" style={{ color: '#3b82f6' }} />
                      <span className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{remediation}</span>
                    </div>
                  </Card>
                </Section>
              ) : (
                <Section title="Remediation Steps">
                  <Card>
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                      No automated remediation available. Review the finding details and apply cloud provider best practices.
                    </p>
                  </Card>
                </Section>
              )}

              {/* Action buttons */}
              <div className="flex flex-wrap gap-2">
                {context.engine && finding.finding_id && (
                  <a href={`/finding/${context.engine}/${encodeURIComponent(finding.finding_id)}`}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium hover:opacity-80 transition-opacity"
                    style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
                    <ExternalLink className="w-3.5 h-3.5" /> Open Full Finding
                  </a>
                )}
                {resourceId && (
                  <a href={`/inventory/${encodeURIComponent(resourceId)}`}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium hover:opacity-80 transition-opacity"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                    <ExternalLink className="w-3.5 h-3.5" /> View Asset
                  </a>
                )}
              </div>

              {/* Outbound relationships */}
              {!ctxLoading && outbound.length > 0 && (
                <Section title={`Outbound (${outbound.length})`}>
                  <div className="space-y-2">
                    {outbound.map((rel, i) => (
                      <div key={i} className="flex items-start gap-3 px-3 py-2.5 rounded border"
                        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                        <ArrowRight className="w-3.5 h-3.5 mt-0.5 shrink-0" style={{ color: 'var(--accent-primary)' }} />
                        <div className="min-w-0 flex-1">
                          <span className="text-xs font-medium block" style={{ color: 'var(--text-secondary)' }}>
                            {rel.relation_type?.replace(/_/g, ' ')}
                          </span>
                          <code className="text-xs break-all block mt-0.5" style={{ color: 'var(--text-muted)' }}>
                            {rel.peer_uid}
                          </code>
                          {rel.peer_type && (
                            <span className="text-xs mt-0.5 inline-block" style={{ color: 'var(--text-muted)' }}>{rel.peer_type}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </Section>
              )}

              {/* Inbound relationships */}
              {!ctxLoading && inbound.length > 0 && (
                <Section title={`Inbound (${inbound.length})`}>
                  <div className="space-y-2">
                    {inbound.map((rel, i) => (
                      <div key={i} className="flex items-start gap-3 px-3 py-2.5 rounded border"
                        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                        <ArrowLeft className="w-3.5 h-3.5 mt-0.5 shrink-0" style={{ color: '#a78bfa' }} />
                        <div className="min-w-0 flex-1">
                          <span className="text-xs font-medium block" style={{ color: 'var(--text-secondary)' }}>
                            {rel.relation_type?.replace(/_/g, ' ')}
                          </span>
                          <code className="text-xs break-all block mt-0.5" style={{ color: 'var(--text-muted)' }}>
                            {rel.peer_uid}
                          </code>
                          {rel.peer_type && (
                            <span className="text-xs mt-0.5 inline-block" style={{ color: 'var(--text-muted)' }}>{rel.peer_type}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </Section>
              )}

              {/* Loading state for async rels */}
              {ctxLoading && <Skeleton lines={3} />}
            </>
          )}

          {/* ═══════════════ CONTEXT TAB ═══════════════ */}
          {activeTab === 'context' && (
            <>
              {/* Asset summary card */}
              <Section title="Asset">
                {ctxLoading ? <Skeleton lines={5} /> : asset ? (
                  <Card>
                    <div className="space-y-2">
                      <Field label="Name"         value={asset.resource_name} />
                      <Field label="Resource UID" value={asset.resource_uid}  mono copy />
                      <Field label="Type"         value={(asset.resource_type || '').replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ')} />
                      <Field label="Service"      value={asset.service} />
                      <Field label="Provider"     value={asset.provider?.toUpperCase()} />
                      <Field label="Account"      value={asset.account_id} mono />
                      <Field label="Region"       value={asset.region} />
                      <Field label="First Seen"   value={asset.first_seen_at ? new Date(asset.first_seen_at).toLocaleDateString() : null} />
                      <Field label="Last Seen"    value={asset.last_seen_at  ? new Date(asset.last_seen_at).toLocaleDateString()  : null} />
                    </div>
                    {resourceId && (
                      <div className="mt-3 pt-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
                        <a href={`/inventory/${encodeURIComponent(resourceId)}`}
                          onClick={e => e.stopPropagation()}
                          className="inline-flex items-center gap-1.5 text-xs font-medium hover:opacity-75"
                          style={{ color: 'var(--accent-primary)' }}>
                          <ExternalLink className="w-3 h-3" /> Open full asset page →
                        </a>
                      </div>
                    )}
                  </Card>
                ) : (
                  <Card>
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                      {resourceId ? 'Asset context not available.' : 'No resource ID on this finding.'}
                    </p>
                  </Card>
                )}
              </Section>

              {/* Tags */}
              {!ctxLoading && asset?.tags && Object.keys(asset.tags).length > 0 && (
                <Section title="Tags">
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(asset.tags).map(([k, v]) => (
                      <span key={k} className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border"
                        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
                        <Tag className="w-2.5 h-2.5 shrink-0" style={{ color: 'var(--text-muted)' }} />
                        <span style={{ color: 'var(--text-muted)' }}>{k}:</span> {String(v)}
                      </span>
                    ))}
                  </div>
                </Section>
              )}

              {/* Crown Jewel + Attack Path status banner */}
              {!ctxLoading && (posture?.is_crown_jewel || posture?.is_on_attack_path || posture?.is_choke_point) && (
                <Section title="Risk Signals">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 px-3 py-2 rounded border"
                      style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.3)' }}>
                      <Crown className="w-3.5 h-3.5 shrink-0" style={{ color: '#ef4444' }} />
                      <div className="flex-1 min-w-0">
                        <span className="text-xs font-semibold" style={{ color: '#ef4444' }}>Crown Jewel</span>
                        {posture.crown_jewel_type && (
                          <span className="text-xs ml-1.5" style={{ color: 'var(--text-muted)' }}>
                            · {posture.crown_jewel_type.replace(/_/g, ' ')}
                          </span>
                        )}
                      </div>
                      {posture.attack_path_count > 0 && (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                          style={{ backgroundColor: 'rgba(239,68,68,0.2)', color: '#ef4444' }}>
                          {posture.attack_path_count} path{posture.attack_path_count !== 1 ? 's' : ''}
                        </span>
                      )}
                    </div>
                    {posture.is_on_attack_path && !posture.is_crown_jewel && (
                      <div className="flex items-center gap-2 px-3 py-2 rounded border"
                        style={{ backgroundColor: 'rgba(249,115,22,0.08)', borderColor: 'rgba(249,115,22,0.3)' }}>
                        <GitBranch className="w-3.5 h-3.5 shrink-0" style={{ color: '#f97316' }} />
                        <span className="text-xs font-semibold" style={{ color: '#f97316' }}>
                          On Attack Path
                        </span>
                        {posture.attack_path_count > 0 && (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded ml-auto"
                            style={{ backgroundColor: 'rgba(249,115,22,0.2)', color: '#f97316' }}>
                            {posture.attack_path_count} path{posture.attack_path_count !== 1 ? 's' : ''}
                          </span>
                        )}
                      </div>
                    )}
                    {posture.is_choke_point && (
                      <div className="flex items-center gap-2 px-3 py-2 rounded border"
                        style={{ backgroundColor: 'rgba(139,92,246,0.08)', borderColor: 'rgba(139,92,246,0.3)' }}>
                        <Zap className="w-3.5 h-3.5 shrink-0" style={{ color: '#a78bfa' }} />
                        <span className="text-xs font-semibold" style={{ color: '#a78bfa' }}>Choke Point</span>
                        {posture.paths_blocked_if_fixed > 0 && (
                          <span className="text-xs ml-1.5" style={{ color: 'var(--text-muted)' }}>
                            · blocks {posture.paths_blocked_if_fixed} path{posture.paths_blocked_if_fixed !== 1 ? 's' : ''} if fixed
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </Section>
              )}

              {/* Security posture scores (compact) */}
              {!ctxLoading && posture && (
                <Section title="Posture Scores">
                  <Card>
                    <div className="space-y-2.5">
                      {[
                        ['IAM',          posture.iam_score],
                        ['Network',      posture.network_score],
                        ['Encryption',   posture.encryption_score],
                        ['Container',    posture.container_security_score],
                        ['Database',     posture.dbsec_score],
                        ['AI Security',  posture.ai_security_score],
                        ['API Security', posture.api_security_score],
                      ].filter(([, s]) => s != null).map(([label, score]) => (
                        <ScoreBar key={label} label={label} score={score} />
                      ))}
                    </div>
                    {/* Blast radius + posture metadata */}
                    {(posture.blast_radius_count > 0 || posture.posture_vector) && (
                      <div className="mt-3 pt-3 border-t space-y-1.5" style={{ borderColor: 'var(--border-primary)' }}>
                        {posture.blast_radius_count > 0 && (
                          <div className="flex justify-between text-xs">
                            <span style={{ color: 'var(--text-muted)' }}>Blast Radius</span>
                            <span style={{ fontWeight: 700, color: posture.blast_radius_count > 20 ? '#ef4444' : posture.blast_radius_count > 5 ? '#f97316' : 'var(--text-secondary)' }}>
                              {posture.blast_radius_count} resource{posture.blast_radius_count !== 1 ? 's' : ''}
                            </span>
                          </div>
                        )}
                        {posture.posture_vector && (
                          <div className="flex justify-between text-xs">
                            <span style={{ color: 'var(--text-muted)' }}>Vector</span>
                            <span className="font-mono text-[10px]" style={{ color: 'var(--text-secondary)' }}>{posture.posture_vector}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </Card>
                </Section>
              )}

              {/* Relationships graph */}
              {!ctxLoading && rels.length > 0 && (
                <Section title={`Relationships (${rels.length})`}>
                  <div className="space-y-1.5">
                    {rels.slice(0, 10).map((r, i) => {
                      const isOut = r.direction === 'outbound';
                      const uid = r.related_resource_uid || r.target_resource_uid || r.source_resource_uid || '';
                      const name = r.related_resource_name || (uid.split(/[/:?]/).filter(Boolean).pop() || uid);
                      const relType = (r.relationship_type || r.relation_type || '').replace(/_/g, ' ');
                      const rtype = (r.related_resource_type || '').replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ');
                      return (
                        <div key={i} className="flex items-center gap-2 px-3 py-2 rounded border"
                          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                          {isOut
                            ? <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--accent-primary)' }} />
                            : <ArrowLeft  className="w-3 h-3 shrink-0" style={{ color: '#a78bfa' }} />
                          }
                          <span className="text-[10px] font-medium shrink-0" style={{ color: 'var(--text-muted)' }}>{relType}</span>
                          <div className="flex flex-col min-w-0 flex-1">
                            <span className="text-xs truncate" style={{ color: 'var(--text-secondary)' }} title={uid}>{name}</span>
                            {rtype && <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{rtype}</span>}
                          </div>
                          {uid && (
                            <a href={`/inventory/${encodeURIComponent(uid)}`}
                              onClick={e => e.stopPropagation()}
                              className="shrink-0 hover:opacity-70"
                              style={{ color: 'var(--text-muted)' }}>
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          )}
                        </div>
                      );
                    })}
                    {rels.length > 10 && (
                      <p className="text-xs text-center py-1" style={{ color: 'var(--text-muted)' }}>
                        +{rels.length - 10} more — view in asset page
                      </p>
                    )}
                  </div>
                </Section>
              )}

              {/* CDR Activity */}
              {!ctxLoading && posture?.has_active_cdr_actor && (
                <Section title="Active Threat Activity">
                  <Card>
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2">
                        <Activity className="w-3.5 h-3.5 shrink-0" style={{ color: '#ef4444' }} />
                        <span className="text-xs font-semibold" style={{ color: '#ef4444' }}>
                          {posture.cdr_actor_count || 1} active threat actor{(posture.cdr_actor_count || 1) !== 1 ? 's' : ''} detected
                        </span>
                      </div>
                      {posture.cdr_last_seen_at && (
                        <div className="flex justify-between text-xs">
                          <span style={{ color: 'var(--text-muted)' }}>Last Activity</span>
                          <span style={{ color: 'var(--text-secondary)' }}>
                            {new Date(posture.cdr_last_seen_at).toLocaleString()}
                          </span>
                        </div>
                      )}
                      {Array.isArray(posture.cdr_ttps) && posture.cdr_ttps.length > 0 && (
                        <div className="pt-1.5">
                          <div className="text-[10px] font-semibold uppercase tracking-wide mb-1.5"
                            style={{ color: 'var(--text-muted)' }}>MITRE ATT&CK TTPs</div>
                          <div className="flex flex-wrap gap-1.5">
                            {posture.cdr_ttps.slice(0, 8).map(ttp => (
                              <span key={ttp} className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                                style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#f87171' }}>
                                {ttp}
                              </span>
                            ))}
                            {posture.cdr_ttps.length > 8 && (
                              <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                                +{posture.cdr_ttps.length - 8} more
                              </span>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </Card>
                </Section>
              )}

              {/* Attack Paths involving this asset */}
              {!ctxLoading && attackPaths.length > 0 && (
                <Section title={`Attack Paths (${attackPaths.length})`}>
                  <div className="space-y-1.5">
                    {attackPaths.map((ap, i) => {
                      const sev = (ap.severity || 'low').toLowerCase();
                      const roleLabel = { entry_point: 'Entry', crown_jewel: 'Target', choke_node: 'Choke', node: 'Node' };
                      const roleColor = { entry_point: '#f97316', crown_jewel: '#ef4444', choke_node: '#a78bfa', node: 'var(--text-muted)' };
                      return (
                        <div key={ap.path_id || i} className="px-3 py-2 rounded border"
                          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0"
                              style={{ backgroundColor: `${SEV_CLR[sev] || '#888'}22`, color: SEV_CLR[sev] || '#888' }}>
                              {sev.slice(0, 4).toUpperCase()}
                            </span>
                            <span className="text-[10px] font-semibold shrink-0"
                              style={{ color: roleColor[ap.resource_role] || 'var(--text-muted)' }}>
                              {roleLabel[ap.resource_role] || 'Node'}
                            </span>
                            <span className="text-xs flex-1 truncate font-medium"
                              style={{ color: 'var(--text-primary)' }} title={ap.attack_name || ap.chain_type}>
                              {ap.attack_name || ap.chain_type || 'Attack Path'}
                            </span>
                            <span className="text-[10px] font-bold shrink-0"
                              style={{ color: ap.path_score >= 70 ? '#ef4444' : ap.path_score >= 40 ? '#f97316' : '#eab308' }}>
                              {ap.path_score}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-[10px]" style={{ color: 'var(--text-muted)' }}>
                            {ap.confidence_level && <span>{ap.confidence_level}</span>}
                            {ap.misconfig_count > 0 && <span>{ap.misconfig_count} misconfig{ap.misconfig_count !== 1 ? 's' : ''}</span>}
                            {ap.has_active_cdr_actor && <span style={{ color: '#ef4444' }}>live actor</span>}
                            <a href={`/attack-paths?path=${ap.path_id}`}
                              onClick={e => e.stopPropagation()}
                              className="ml-auto hover:opacity-70" style={{ color: 'var(--accent-primary)' }}>
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Section>
              )}

              {/* All open findings on this asset (from security_findings) */}
              {!ctxLoading && openFindings.length > 0 && (
                <Section title={`Open Findings on This Asset (${openFindings.length})`}>
                  <div className="space-y-1.5">
                    {openFindings.map((f, i) => {
                      const sev = (f.severity || 'low').toLowerCase();
                      return (
                        <div key={f.finding_id || i} className="px-3 py-2 rounded border"
                          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0"
                              style={{ backgroundColor: `${SEV_CLR[sev] || '#888'}22`, color: SEV_CLR[sev] || '#888' }}>
                              {sev.slice(0, 4).toUpperCase()}
                            </span>
                            <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-secondary)' }}
                              title={f.title || f.rule_id}>
                              {f.title || f.rule_id || '—'}
                            </span>
                            {f.in_kev && (
                              <span className="text-[9px] font-bold px-1 py-0.5 rounded shrink-0"
                                style={{ backgroundColor: 'rgba(239,68,68,0.2)', color: '#ef4444' }}>
                                KEV
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-3 text-[10px]" style={{ color: 'var(--text-muted)' }}>
                            <span className="font-medium">{(f.source_engine || '').replace(/_/g, '-')}</span>
                            {f.mitre_technique_id && <span className="font-mono">{f.mitre_technique_id}</span>}
                            {f.epss_score != null && (
                              <span style={{ color: f.epss_score > 0.5 ? '#ef4444' : 'var(--text-muted)' }}>
                                EPSS {(f.epss_score * 100).toFixed(1)}%
                              </span>
                            )}
                            {f.cvss_score != null && <span>CVSS {f.cvss_score}</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Section>
              )}

              {/* Similar findings — same rule, different assets */}
              {(() => {
                const allFindings = context.allFindings || [];
                const ruleId = finding.rule_id;
                if (!ruleId || !allFindings.length) return null;
                const siblings = allFindings.filter(f =>
                  f.rule_id === ruleId &&
                  (f.finding_id || f.resource_uid) !== (finding.finding_id || finding.resource_uid)
                ).sort((a, b) => (SEV_RANK[b.severity?.toLowerCase()] || 0) - (SEV_RANK[a.severity?.toLowerCase()] || 0));
                if (!siblings.length) return null;
                return (
                  <Section title={`Same Rule on Other Assets (${siblings.length})`}>
                    <div className="space-y-1.5">
                      {siblings.slice(0, 6).map((f, i) => {
                        const uid  = f.resource_uid || f.resource_id || '';
                        const name = f.resource_name || (uid.split(/[/:?]/).filter(Boolean).pop() || uid);
                        const sev  = (f.severity || '').toLowerCase();
                        return (
                          <div key={f.finding_id || i} className="flex items-center gap-2 px-3 py-2 rounded border"
                            style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0"
                              style={{ backgroundColor: `${SEV_CLR[sev] || '#888'}22`, color: SEV_CLR[sev] || '#888' }}>
                              {(f.severity || '').slice(0, 4).toUpperCase()}
                            </span>
                            <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-secondary)' }} title={uid}>
                              {name}
                            </span>
                            {uid && (
                              <a href={`/inventory/${encodeURIComponent(uid)}`}
                                onClick={e => e.stopPropagation()}
                                className="shrink-0 hover:opacity-70" style={{ color: 'var(--text-muted)' }}>
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            )}
                          </div>
                        );
                      })}
                      {siblings.length > 6 && (
                        <a href={finding.rule_id ? `/misconfig?rule=${encodeURIComponent(finding.rule_id)}` : '#'}
                          className="text-xs block text-center py-1.5 rounded border hover:opacity-75"
                          style={{ color: 'var(--accent-primary)', borderColor: 'var(--border-primary)' }}>
                          +{siblings.length - 6} more — view all instances
                        </a>
                      )}
                    </div>
                  </Section>
                );
              })()}

              {ctxLoading && <Skeleton lines={4} />}
              {!ctxLoading && !asset && !rels.length && (
                <div className="text-center py-8">
                  <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Context data not available for this finding.</p>
                </div>
              )}
            </>
          )}

        </div>
      </div>
    </div>
  );
}
