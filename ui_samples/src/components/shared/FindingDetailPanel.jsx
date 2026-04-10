'use client';

import { useState } from 'react';
import { X, ExternalLink, Copy, Check, ShieldCheck } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

// ── Helper sub-components ────────────────────────────────────────────────────
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

// ── Main component ────────────────────────────────────────────────────────────
export default function FindingDetailPanel({ finding, onClose, context = {} }) {
  if (!finding) return null;

  // Normalise field names across engines
  const resourceId  = finding.resource_uid  || finding.resource_arn || finding.resource_id  || '';
  const title       = finding.title         || finding.rule_id       || 'Finding';
  const sev         = (finding.severity || 'low').toLowerCase();
  const status      = finding.status        || 'FAIL';
  const isFail      = status === 'FAIL';
  const service     = finding.service       || finding.container_service || finding.db_service || finding.encryption_domain || finding.network_layer || '';
  const domain      = finding.domain        || finding.security_domain   || finding.posture_category || finding.encryption_domain || '';
  const riskScore   = finding.risk_score    ?? null;
  const description = finding.description   || finding.rationale     || '';
  const remediation = finding.remediation   || '';
  const accountId   = finding.account_id    || finding.account       || finding.hierarchy_id || '';
  const provider    = (finding.provider     || 'aws').toUpperCase();

  const sevColor = sev === 'critical' ? '#ef4444' : sev === 'high' ? '#f97316' : sev === 'medium' ? '#eab308' : '#22c55e';
  const riskColor = riskScore >= 75 ? '#ef4444' : riskScore >= 50 ? '#f97316' : riskScore >= 25 ? '#eab308' : '#22c55e';

  // Compliance frameworks
  const frameworks = Array.isArray(finding.compliance_frameworks)
    ? finding.compliance_frameworks
    : (finding.compliance_frameworks && typeof finding.compliance_frameworks === 'object')
      ? Object.keys(finding.compliance_frameworks)
      : [];

  // MITRE
  const tactics    = Array.isArray(finding.mitre_tactics)    ? finding.mitre_tactics    : [];
  const techniques = Array.isArray(finding.mitre_techniques) ? finding.mitre_techniques : [];

  // Checked fields / evidence
  const checkedFields = finding.checked_fields;
  const actualValues  = finding.actual_values;

  // Extra page-specific context fields passed in
  const extraFields = context.fields || [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />

      {/* Panel */}
      <div className="relative w-full max-w-2xl h-full overflow-y-auto shadow-2xl"
        style={{ backgroundColor: 'var(--bg-primary)' }}>

        {/* ── Header ── */}
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 px-6 py-5 border-b"
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

        <div className="px-6 py-5 space-y-6">

          {/* ── Risk Score bar (if present) ── */}
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

          {/* ── Resource ── */}
          <Section title="Resource">
            <Card>
              <div className="space-y-2">
                <Field label="Resource ID"   value={resourceId}              mono copy />
                <Field label="Type"          value={finding.resource_type}   />
                <Field label="Service"       value={service}                 />
                <Field label="Region"        value={finding.region}          />
                <Field label="Account"       value={accountId}               mono />
                <Field label="Provider"      value={provider}                />
                {/* Page-specific extra fields */}
                {extraFields.map(f => (
                  <Field key={f.label} label={f.label} value={f.value} mono={f.mono} />
                ))}
              </div>
            </Card>
          </Section>

          {/* ── Description ── */}
          {description && (
            <Section title="Description">
              <Card>
                <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{description}</p>
              </Card>
            </Section>
          )}

          {/* ── Evidence ── */}
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

          {/* ── Remediation ── */}
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

          {/* ── Classification ── */}
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

          {/* ── Compliance Frameworks ── */}
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

          {/* ── MITRE ATT&CK ── */}
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

          {/* ── View in Inventory ── */}
          {resourceId && (
            <div className="pt-2 border-t" style={{ borderColor: 'var(--border-primary)' }}>
              <a href={`/ui/inventory/${encodeURIComponent(resourceId)}`}
                className="inline-flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-lg transition-opacity hover:opacity-80"
                style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
                <ExternalLink className="w-4 h-4" /> View in Inventory
              </a>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
