'use client';

import { emit } from '@/lib/telemetry';
import EmptyState from '@/components/shared/EmptyState';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { ShieldCheck, ExternalLink } from 'lucide-react';

function Field({ label, value, mono = false }) {
  if (!value && value !== 0) return null;
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-xs font-medium shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>{label}</span>
      {mono
        ? <code className="text-xs break-all flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>{String(value)}</code>
        : <span className="text-xs break-all flex-1 text-right" style={{ color: 'var(--text-secondary)' }}>{String(value)}</span>}
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div className="space-y-3">
      <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{title}</h3>
      {children}
    </div>
  );
}

function Card({ children, blue = false }) {
  return (
    <div className="rounded-lg border p-4" style={{
      backgroundColor: blue ? 'rgba(59,130,246,0.06)' : 'var(--bg-secondary)',
      borderColor:     blue ? 'rgba(59,130,246,0.2)'  : 'var(--border-primary)',
    }}>
      {children}
    </div>
  );
}

const SEV_CLR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

const FD_SKIP = new Set([
  'checked_fields', 'actual_values', 'description', 'rationale',
  'mitre_tactics', 'mitre_techniques', 'domain', 'security_domain', 'encryption_domain',
  'posture_category', 'service', 'container_service', 'db_service', 'network_layer',
  'iam_module', 'identity_name', 'identity_type', 'resource_type', 'region', 'account_id',
  'provider', 'title', 'severity', 'status', 'rule_id', 'finding_id',
]);

export default function OverviewTab({ finding, engine, id, data }) {
  const header = finding?.header || data?.header || finding;
  const compliance = data?.compliance || finding?.compliance;
  const evidence = data?.evidence || finding?.evidence;
  const supporting = data?.supporting || finding?.supporting || finding?.supportingFindings;
  const remediation = data?.remediation || finding?.remediation;
  const fd = header?.findingData || {};

  const riskScore    = header?.riskScore;
  const description  = header?.description || fd.description || fd.rationale || '';
  const resourceUid  = header?.resourceUid;
  const resourceType = header?.resourceType || fd.resource_type || '';
  const region       = header?.region   || fd.region    || '';
  const accountId    = header?.accountId || fd.account_id || '';
  const provider     = (header?.provider || fd.provider || '').toUpperCase();
  const firstSeen    = header?.firstSeenAt;
  const lastSeen     = header?.lastSeenAt;
  const ruleId       = header?.ruleId;

  const domain       = fd.domain || fd.security_domain || fd.encryption_domain || fd.posture_category || '';
  const service      = fd.service || fd.container_service || fd.db_service || fd.encryption_domain || fd.network_layer || '';
  const iamModule    = fd.iam_module || '';
  const identityName = fd.identity_name || '';

  const tactics    = Array.isArray(fd.mitre_tactics)    ? fd.mitre_tactics    : [];
  const techniques = Array.isArray(fd.mitre_techniques) ? fd.mitre_techniques : [];

  const controlMappings = compliance?.controlMappings || [];
  const checkedFields   = fd.checked_fields;
  const actualValues    = fd.actual_values;

  const riskColor = !riskScore ? '#22c55e'
    : riskScore >= 75 ? '#ef4444' : riskScore >= 50 ? '#f97316' : riskScore >= 25 ? '#eab308' : '#22c55e';

  const fmt = d => d ? new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : null;

  if (!header) {
    return <EmptyState title="No overview data" description="The BFF returned no header for this finding." />;
  }

  const extraFdEntries = Object.entries(fd).filter(([k, v]) =>
    !FD_SKIP.has(k) && v != null && v !== '' && k !== 'scan_run_id' && k !== 'tenant_id'
  );

  return (
    <div className="flex flex-col gap-6">

      {/* Risk Score */}
      {riskScore != null && (
        <div className="rounded-lg p-3 border" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
          <div className="flex justify-between mb-1.5">
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Risk Score</span>
            <span className="text-xs font-bold" style={{ color: riskColor }}>{riskScore} / 100</span>
          </div>
          <div className="h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
            <div className="h-full rounded-full" style={{ width: `${riskScore}%`, backgroundColor: riskColor }} />
          </div>
        </div>
      )}

      {/* Resource Identity */}
      <Section title="Resource">
        <Card>
          <div className="space-y-2">
            <Field label="Resource UID"  value={resourceUid}                                                        mono />
            {header?.resourceName && header.resourceName !== resourceUid && (
              <Field label="Name"        value={header.resourceName} />
            )}
            <Field label="Type"          value={resourceType.replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ')} />
            <Field label="Service"       value={service} />
            <Field label="Region"        value={region} />
            <Field label="Account"       value={accountId}                                                          mono />
            <Field label="Provider"      value={provider} />
            {identityName && <Field label="Identity" value={identityName} />}
            <Field label="First Seen"    value={fmt(firstSeen)} />
            <Field label="Last Seen"     value={fmt(lastSeen)} />
            {ruleId && <Field label="Rule ID"        value={ruleId}                                                mono />}
          </div>
          {resourceUid && (
            <div className="mt-3 pt-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
              <a href={`/inventory/${encodeURIComponent(resourceUid)}`}
                className="inline-flex items-center gap-1.5 text-xs font-medium hover:opacity-75 transition-opacity"
                style={{ color: 'var(--accent-primary)' }}>
                <ExternalLink className="w-3 h-3" /> View full asset in Inventory
              </a>
            </div>
          )}
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

      {/* Evidence — checked_fields + actual_values */}
      {(checkedFields || actualValues) && (
        <Section title="Evidence">
          <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
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

      {/* Engine-specific finding data (extra fields not covered above) */}
      {extraFdEntries.length > 0 && (
        <Section title="Finding Details">
          <Card>
            <div className="space-y-2">
              {extraFdEntries.map(([k, v]) => {
                const label    = k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                const isBool   = typeof v === 'boolean';
                const display  = isBool ? (v ? 'Yes' : 'No') : typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v);
                const isLong   = display.length > 80 || display.includes('\n');
                if (isLong) return (
                  <div key={k}>
                    <span className="text-[10px] font-semibold uppercase tracking-wide block mb-1" style={{ color: 'var(--text-muted)' }}>{label}</span>
                    <pre className="text-[10px] overflow-x-auto whitespace-pre-wrap p-2 rounded"
                      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{display}</pre>
                  </div>
                );
                return (
                  <div key={k} className="flex items-start justify-between gap-4">
                    <span className="text-xs font-medium shrink-0 w-40" style={{ color: 'var(--text-muted)' }}>{label}</span>
                    <span className="text-xs flex-1 text-right"
                      style={{ color: isBool ? (v ? '#22c55e' : '#ef4444') : 'var(--text-secondary)', fontWeight: isBool ? 600 : 400 }}>
                      {display}
                    </span>
                  </div>
                );
              })}
            </div>
          </Card>
        </Section>
      )}

      {/* Classification */}
      {(domain || service || iamModule) && (
        <Section title="Classification">
          <div className="flex flex-wrap gap-2">
            {domain && (
              <span className="text-xs font-medium px-2.5 py-1 rounded-full"
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                {domain.replace(/_/g, ' ')}
              </span>
            )}
            {service && service !== domain && (
              <span className="text-xs px-2.5 py-1 rounded-full"
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)', border: '1px solid var(--border-primary)' }}>
                {service.replace(/_/g, ' ')}
              </span>
            )}
            {iamModule && (
              <span className="text-xs px-2 py-1 rounded"
                style={{ backgroundColor: 'rgba(99,102,241,0.12)', color: '#818cf8' }}>
                {iamModule.replace(/_/g, ' ')}
              </span>
            )}
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

      {/* Compliance Frameworks */}
      {controlMappings.length > 0 && (
        <Section title="Compliance Mapping">
          <div className="space-y-1.5">
            {controlMappings.slice(0, 8).map((m, i) => (
              <div key={i} className="flex items-center gap-2 px-3 py-2 rounded border"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                <span className="text-xs font-medium shrink-0 w-28 truncate" style={{ color: 'var(--text-secondary)' }}>
                  {m.framework}
                </span>
                <code className="text-xs shrink-0" style={{ color: 'var(--text-muted)' }}>{m.controlId}</code>
                {m.controlName && (
                  <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-muted)' }}>{m.controlName}</span>
                )}
                {m.status && (
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0"
                    style={{
                      backgroundColor: m.status?.toLowerCase() === 'pass' ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
                      color:           m.status?.toLowerCase() === 'pass' ? '#22c55e'               : '#ef4444',
                    }}>
                    {m.status?.toUpperCase()}
                  </span>
                )}
              </div>
            ))}
            {controlMappings.length > 8 && (
              <p className="text-xs pl-1" style={{ color: 'var(--text-muted)' }}>
                +{controlMappings.length - 8} more — see Compliance tab
              </p>
            )}
          </div>
        </Section>
      )}

      {/* Remediation preview */}
      {(remediation?.guidance || remediation?.markdown) && (
        <Section title="Remediation">
          <Card blue>
            <div className="flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" style={{ color: '#3b82f6' }} />
              <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                {(remediation.guidance || remediation.markdown || '').slice(0, 320)}
                {(remediation.guidance || remediation.markdown || '').length > 320 && (
                  <span style={{ color: 'var(--text-muted)' }}>… see Remediation tab</span>
                )}
              </p>
            </div>
          </Card>
        </Section>
      )}

      {/* Additional evidence (array from BFF) */}
      {Array.isArray(evidence) && evidence.length > 0 && (
        <Section title="Additional Evidence">
          <div className="space-y-2">
            {evidence.map((ev, i) => (
              <div key={i} className="rounded border p-3" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                {typeof ev === 'string'
                  ? <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{ev}</p>
                  : <pre className="text-xs overflow-x-auto whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>
                      {JSON.stringify(ev, null, 2)}
                    </pre>
                }
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Supporting Findings */}
      {Array.isArray(supporting) && supporting.length > 0 && (
        <Section title="Supporting Findings">
          <div className="space-y-1.5">
            {supporting.map((s, i) => {
              const sEngine = s.engine || engine;
              return (
                <a key={s.findingId || i}
                  href={`/finding/${sEngine}/${encodeURIComponent(s.findingId)}`}
                  onClick={() => emit('finding.pivot_click', { engine, finding_id: id, pivot_type: 'finding', target_id: s.findingId })}
                  className="flex items-center gap-2 px-3 py-2 rounded border hover:opacity-80 transition-opacity"
                  style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
                  <SeverityBadge severity={s.severity || 'info'} />
                  <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-secondary)' }}>
                    {s.title || s.ruleId || s.findingId}
                  </span>
                </a>
              );
            })}
          </div>
        </Section>
      )}

    </div>
  );
}
