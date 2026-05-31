'use client';

import { useEffect, useState } from 'react';
import { X, ExternalLink, Copy, Check, ShieldCheck, Layers, ArrowRight, ArrowLeft, Network } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

// ── Helper sub-components ─────────────────────────────────────────────────────
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
      <div className="flex items-center gap-1.5 min-w-0 flex-1">
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
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>{title}</h3>
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
        <div className="h-full rounded-full" style={{ width: `${Math.min(score, 100)}%`, backgroundColor: color }} />
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

// ── Main component ────────────────────────────────────────────────────────────
/**
 * @param {object}   finding           — finding row object from any engine table
 * @param {function} onClose           — called when ✕ or backdrop clicked
 * @param {object}   [context]              — optional page-specific config
 * @param {string}   [context.engine]       — engine key (e.g. "network")
 * @param {Array}    [context.fields]       — extra { label, value, mono } rows
 * @param {function} [context.renderExtra]  — (finding) => ReactNode appended to Finding tab
 */
export default function FindingDetailPanel({ finding, onClose, context = {} }) {
  const [activeTab, setActiveTab]     = useState('finding');
  const [resourceCtx, setResourceCtx] = useState(null);
  const [ctxLoading, setCtxLoading]   = useState(false);

  const resourceId = finding?.resource_uid || finding?.resource_arn || finding?.resource_id || '';

  useEffect(() => {
    if (!resourceId || !finding) return;
    let cancelled = false;
    setResourceCtx(null);
    setCtxLoading(true);

    fetch(`/gateway/api/v1/views/resource/${encodeURIComponent(resourceId)}`, {
      credentials: 'include',
    })
      .then(r => (r.ok ? r.json() : null))
      .then(data  => { if (!cancelled) setResourceCtx(data);  })
      .catch(()   => { if (!cancelled) setResourceCtx(null);  })
      .finally(() => { if (!cancelled) setCtxLoading(false); });

    return () => { cancelled = true; };
  }, [resourceId]);

  // Reset to Finding tab when a different finding opens
  useEffect(() => { setActiveTab('finding'); }, [finding?.finding_id || finding?.rule_id]);

  if (!finding) return null;

  // Normalise field names across engines
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

  const riskColor = riskScore >= 75 ? '#ef4444' : riskScore >= 50 ? '#f97316' : riskScore >= 25 ? '#eab308' : '#22c55e';

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

  // Resource / posture / relationships from BFF
  const asset    = resourceCtx?.resource      || null;
  const posture  = resourceCtx?.posture        || null;
  const fSummary = resourceCtx?.findings_summary || null;
  const rels     = resourceCtx?.relationships  || [];
  const inbound  = rels.filter(r => r.direction === 'inbound');
  const outbound = rels.filter(r => r.direction === 'outbound');

  const tabs = [
    { id: 'finding',       label: 'Finding' },
    { id: 'resource',      label: 'Resource' },
    { id: 'relationships', label: `Relationships${rels.length > 0 ? ` (${rels.length})` : ''}` },
  ];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />

      {/* Panel */}
      <div className="relative w-full max-w-2xl h-full flex flex-col shadow-2xl"
        style={{ backgroundColor: 'var(--bg-primary)' }}>

        {/* ── Header ── */}
        <div className="flex-shrink-0 flex items-start justify-between gap-4 px-6 py-5 border-b"
          style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-primary)' }}>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <SeverityBadge severity={finding.severity} />
              <span className={`text-xs font-bold px-2 py-0.5 rounded ${isFail ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                {status}
              </span>
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
            <code className="text-xs mt-1 block" style={{ color: 'var(--text-muted)' }}>
              {finding.rule_id}
            </code>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:opacity-70 transition-opacity"
            style={{ color: 'var(--text-muted)' }}>
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* ── Tab bar ── */}
        <div className="flex-shrink-0 flex border-b px-6" style={{ borderColor: 'var(--border-primary)' }}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="text-xs font-medium py-3 mr-6 border-b-2 transition-colors"
              style={{
                borderColor: activeTab === tab.id ? 'var(--accent-primary)' : 'transparent',
                color: activeTab === tab.id ? 'var(--accent-primary)' : 'var(--text-muted)',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── Tab content (scrollable) ── */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

          {/* ═══════════════════════════════════════════════════════════
              TAB 1 — FINDING
              ═══════════════════════════════════════════════════════════ */}
          {activeTab === 'finding' && (
            <>
              {/* Risk Score bar */}
              {riskScore != null && (
                <div className="rounded-lg p-3 border"
                  style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                  <div className="flex justify-between mb-1.5">
                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Risk Score</span>
                    <span className="text-xs font-bold" style={{ color: riskColor }}>{riskScore} / 100</span>
                  </div>
                  <div className="h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                    <div className="h-full rounded-full" style={{ width: `${riskScore}%`, backgroundColor: riskColor }} />
                  </div>
                </div>
              )}

              {/* Resource identity (from finding fields) */}
              <Section title="Resource">
                <Card>
                  <div className="space-y-2">
                    <Field label="Resource ID" value={resourceId}            mono copy />
                    <Field label="Type"        value={finding.resource_type} />
                    <Field label="Service"     value={service} />
                    <Field label="Region"      value={finding.region} />
                    <Field label="Account"     value={accountId}             mono />
                    <Field label="Provider"    value={provider} />
                    {extraFields.map(f => (
                      <Field key={f.label} label={f.label} value={f.value} mono={f.mono} />
                    ))}
                  </div>
                </Card>
              </Section>

              {/* Description */}
              {description && (
                <Section title="Description">
                  <Card>
                    <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{description}</p>
                  </Card>
                </Section>
              )}

              {/* Evidence */}
              {(checkedFields || actualValues) && (
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

              {/* Remediation */}
              {remediation && (
                <Section title="Remediation">
                  <Card blue>
                    <div className="flex items-start gap-2">
                      <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" style={{ color: '#3b82f6' }} />
                      <span className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{remediation}</span>
                    </div>
                  </Card>
                </Section>
              )}

              {/* Classification */}
              <Section title="Classification">
                <div className="flex flex-wrap gap-2">
                  {domain && (
                    <span className="text-xs font-medium px-2.5 py-1 rounded-full"
                      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                      {domain.replace(/_/g, ' ')}
                    </span>
                  )}
                  {riskScore != null && (
                    <span className="text-xs font-bold px-2 py-1 rounded"
                      style={{
                        backgroundColor: riskScore >= 70 ? 'rgba(239,68,68,0.12)' : 'rgba(234,179,8,0.12)',
                        color: riskScore >= 70 ? '#ef4444' : '#eab308',
                      }}>
                      Risk: {riskScore}
                    </span>
                  )}
                  {finding.iam_modules?.length > 0 && finding.iam_modules.map((m, i) => (
                    <span key={i} className="text-xs px-2 py-1 rounded"
                      style={{ backgroundColor: 'rgba(99,102,241,0.12)', color: '#818cf8' }}>
                      {m}
                    </span>
                  ))}
                  {finding.datasec_modules?.length > 0 && finding.datasec_modules.map((m, i) => (
                    <span key={i} className="text-xs px-2 py-1 rounded"
                      style={{ backgroundColor: 'rgba(20,184,166,0.12)', color: '#2dd4bf' }}>
                      {m}
                    </span>
                  ))}
                  {finding.data_classification?.length > 0 && finding.data_classification.map((c, i) => (
                    <span key={i} className="text-xs px-2 py-1 rounded"
                      style={{ backgroundColor: 'rgba(249,115,22,0.12)', color: '#f97316' }}>
                      {c}
                    </span>
                  ))}
                </div>
              </Section>

              {/* Compliance Frameworks */}
              {frameworks.length > 0 && (
                <Section title="Compliance Mapping">
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

              {/* Extra content injected by page (e.g. CorrelationTimeline for CDR L2 findings) */}
              {context.renderExtra && context.renderExtra(finding)}

              {/* CTAs */}
              {resourceId && (
                <div className="pt-2 border-t flex items-center gap-3 flex-wrap"
                  style={{ borderColor: 'var(--border-primary)' }}>
                  <a
                    href={`/inventory/${encodeURIComponent(resourceId)}`}
                    className="inline-flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-lg transition-opacity hover:opacity-80"
                    style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
                  >
                    <Layers className="w-4 h-4" /> View Full Asset
                  </a>
                  <a
                    href={`/inventory/${encodeURIComponent(resourceId)}`}
                    className="inline-flex items-center gap-2 text-xs px-3 py-2 rounded-lg transition-opacity hover:opacity-70"
                    style={{ color: 'var(--text-muted)', border: '1px solid var(--border-primary)' }}
                  >
                    <ExternalLink className="w-3.5 h-3.5" /> Inventory
                  </a>
                </div>
              )}
            </>
          )}

          {/* ═══════════════════════════════════════════════════════════
              TAB 2 — RESOURCE
              ═══════════════════════════════════════════════════════════ */}
          {activeTab === 'resource' && (
            <>
              {ctxLoading && <Skeleton lines={6} />}
              {!ctxLoading && !asset && (
                <div className="text-center py-12" style={{ color: 'var(--text-muted)' }}>
                  <p className="text-sm">Resource data unavailable</p>
                  <p className="text-xs mt-1 opacity-70">This resource may not yet be indexed in DI inventory.</p>
                </div>
              )}
              {!ctxLoading && asset && (
                <>
                  <Section title="Asset Identity">
                    <Card>
                      <div className="space-y-2">
                        <Field label="Name"        value={asset.resource_name} />
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

                  {asset.tags && Object.keys(asset.tags).length > 0 && (
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

                  {posture && (
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
                            {posture.is_internet_exposed        && <span style={{ color: '#ef4444' }}>Internet Exposed</span>}
                            {posture.is_encrypted_at_rest       && <span style={{ color: '#22c55e' }}>Encrypted at Rest</span>}
                            {posture.is_encrypted_in_transit    && <span style={{ color: '#22c55e' }}>Encrypted in Transit</span>}
                            {posture.has_kms_managed_key        && <span style={{ color: '#22c55e' }}>KMS Managed</span>}
                          </div>
                        </div>
                      </Card>
                    </Section>
                  )}

                  {fSummary && fSummary.total > 0 && (
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
                </>
              )}
            </>
          )}

          {/* ═══════════════════════════════════════════════════════════
              TAB 3 — RELATIONSHIPS
              ═══════════════════════════════════════════════════════════ */}
          {activeTab === 'relationships' && (
            <>
              {ctxLoading && <Skeleton lines={4} />}
              {!ctxLoading && rels.length === 0 && (
                <div className="text-center py-12" style={{ color: 'var(--text-muted)' }}>
                  <Network className="w-8 h-8 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">No relationships found</p>
                  <p className="text-xs mt-1 opacity-70">This resource has no recorded graph edges.</p>
                </div>
              )}
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
                            <span className="text-xs mt-0.5 inline-block" style={{ color: 'var(--text-muted)' }}>
                              {rel.peer_type}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </Section>
              )}
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
                            <span className="text-xs mt-0.5 inline-block" style={{ color: 'var(--text-muted)' }}>
                              {rel.peer_type}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </Section>
              )}
            </>
          )}

        </div>
      </div>
    </div>
  );
}
