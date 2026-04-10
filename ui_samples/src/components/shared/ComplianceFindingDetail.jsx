'use client';

import { useState, useEffect } from 'react';
import {
  X, Shield, AlertTriangle, CheckCircle, Clock,
  FileText, Server, Eye, ChevronDown, ChevronRight,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import SeverityBadge from './SeverityBadge';

/**
 * ComplianceFindingDetail — modal popup showing full compliance finding details.
 *
 * Props:
 *   controlId  — control identifier (e.g. "1.18", "A.8.21")
 *   framework  — framework name (e.g. "CIS", "ISO27001")
 *   onClose    — callback to close the popup
 *   inlineData — optional pre-loaded finding data (from asset compliance tab)
 */
export default function ComplianceFindingDetail({ controlId, framework, onClose, inlineData }) {
  const [findings, setFindings] = useState(inlineData ? [inlineData] : []);
  const [loading, setLoading] = useState(!inlineData);
  const [error, setError] = useState(null);
  const [expandedIdx, setExpandedIdx] = useState(0);

  useEffect(() => {
    if (inlineData) return;
    const fetchDetail = async () => {
      setLoading(true);
      try {
        const data = await getFromEngine(
          'compliance',
          `/api/v1/compliance/findings/by-control`,
          { control_id: controlId, framework, limit: 20 }
        );
        if (data?.findings?.length > 0) {
          setFindings(data.findings);
        } else {
          setError('No findings found for this control');
        }
      } catch (e) {
        setError(e?.message || 'Failed to load finding details');
      } finally {
        setLoading(false);
      }
    };
    fetchDetail();
  }, [controlId, framework, inlineData]);

  const first = findings[0] || {};
  const fmt = (d) => d ? new Date(d).toLocaleDateString() : '—';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
      onClick={onClose}
    >
      <div
        className="rounded-xl border shadow-2xl w-full max-w-3xl max-h-[85vh] overflow-y-auto"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Shield size={18} style={{ color: 'var(--accent-primary)' }} />
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full"
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                {framework}
              </span>
              <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>
                Control {controlId}
              </span>
              {first.severity && <SeverityBadge severity={first.severity} />}
            </div>
            <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
              {first.control_name || controlId}
            </h2>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:opacity-70" style={{ color: 'var(--text-muted)' }}>
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        {loading ? (
          <div className="p-8 text-center" style={{ color: 'var(--text-muted)' }}>Loading...</div>
        ) : error ? (
          <div className="p-8 text-center" style={{ color: 'var(--accent-danger)' }}>{error}</div>
        ) : (
          <div className="p-5 space-y-4">

            {/* Finding Info Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <InfoCell label="Status" value={
                <span className="flex items-center gap-1.5">
                  {first.status === 'pass' || first.check_result === 'PASS'
                    ? <CheckCircle size={14} style={{ color: 'var(--accent-success)' }} />
                    : <AlertTriangle size={14} style={{ color: 'var(--accent-danger)' }} />}
                  <span className="uppercase text-xs font-bold"
                    style={{ color: first.status === 'pass' ? 'var(--accent-success)' : 'var(--accent-danger)' }}>
                    {first.check_result || first.status || 'OPEN'}
                  </span>
                </span>
              } />
              <InfoCell label="Confidence" value={first.confidence || '—'} />
              <InfoCell label="Category" value={first.category || '—'} />
              <InfoCell label="Region" value={first.region || 'global'} />
              <InfoCell label="First Seen" value={fmt(first.first_seen)} />
              <InfoCell label="Last Seen" value={fmt(first.last_seen)} />
              <InfoCell label="Rule ID" value={
                <code className="text-[10px] break-all" style={{ color: 'var(--text-secondary)' }}>
                  {first.rule_id || '—'}
                </code>
              } mono />
              <InfoCell label="Finding ID" value={
                <code className="text-[10px] break-all" style={{ color: 'var(--text-tertiary)' }}>
                  {first.finding_id?.slice(0, 18) || '—'}...
                </code>
              } mono />
            </div>

            {/* Affected Resources */}
            {findings.length > 0 && (
              <Section title={`Affected Resources (${findings.length})`} icon={Server}>
                <div className="space-y-1.5">
                  {findings.map((f, i) => (
                    <div key={f.finding_id || i}>
                      <button
                        className="w-full flex items-center gap-2 px-3 py-2 rounded text-left text-sm hover:brightness-95"
                        style={{ backgroundColor: 'var(--bg-tertiary)' }}
                        onClick={() => setExpandedIdx(expandedIdx === i ? -1 : i)}
                      >
                        {expandedIdx === i
                          ? <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} />
                          : <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />}
                        <code className="text-xs flex-1 truncate" style={{ color: 'var(--text-primary)' }}>
                          {f.resource_uid || f.resource_arn || '—'}
                        </code>
                        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                          {f.resource_type}
                        </span>
                        <SeverityBadge severity={f.severity} />
                      </button>
                      {expandedIdx === i && (
                        <div className="px-4 py-3 space-y-2 border-l-2 ml-5"
                          style={{ borderColor: 'var(--accent-primary)' }}>
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div>
                              <span style={{ color: 'var(--text-muted)' }}>Region: </span>
                              <span style={{ color: 'var(--text-secondary)' }}>{f.region || 'global'}</span>
                            </div>
                            <div>
                              <span style={{ color: 'var(--text-muted)' }}>Account: </span>
                              <span style={{ color: 'var(--text-secondary)' }}>{f.account_id || '—'}</span>
                            </div>
                          </div>

                          {/* Evidence — Checked Fields */}
                          {f.checked_fields?.length > 0 && (
                            <div>
                              <div className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>
                                Checked Fields
                              </div>
                              <div className="flex flex-wrap gap-1">
                                {f.checked_fields.map((cf, ci) => (
                                  <code key={ci} className="text-[10px] px-1.5 py-0.5 rounded"
                                    style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
                                    {cf}
                                  </code>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Evidence — Actual Values */}
                          {f.actual_values && Object.keys(f.actual_values).length > 0 && (
                            <div>
                              <div className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>
                                Actual Values
                              </div>
                              <pre className="text-[10px] p-2 rounded overflow-x-auto font-mono"
                                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                                {JSON.stringify(f.actual_values, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </Section>
            )}

            {/* Remediation */}
            {first.remediation && (
              <Section title="Remediation" icon={FileText}>
                <div className="text-sm p-3 rounded border"
                  style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
                  {first.remediation}
                </div>
              </Section>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function InfoCell({ label, value, mono }) {
  return (
    <div>
      <div className="text-[10px] font-semibold mb-0.5" style={{ color: 'var(--text-muted)' }}>{label}</div>
      <div className={`text-sm ${mono ? 'font-mono' : ''}`} style={{ color: 'var(--text-primary)' }}>
        {typeof value === 'string' ? value : value}
      </div>
    </div>
  );
}

function Section({ title, icon: Icon, children }) {
  return (
    <div className="rounded-lg border" style={{ borderColor: 'var(--border-primary)' }}>
      <div className="flex items-center gap-2 px-4 py-2.5 border-b"
        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
        {Icon && <Icon size={14} style={{ color: 'var(--text-tertiary)' }} />}
        <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{title}</span>
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}
