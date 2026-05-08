'use client';

import { emit } from '@/lib/telemetry';
import EmptyState from '@/components/shared/EmptyState';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { ENGINE_META } from './engine-meta';

function EvidenceList({ evidence }) {
  if (!Array.isArray(evidence) || evidence.length === 0) return null;
  return (
    <div className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
        Evidence
      </h3>
      <ul className="space-y-2">
        {evidence.map((ev, i) => (
          <li key={i} className="text-sm" style={{ color: 'var(--text-muted)' }}>
            {typeof ev === 'string' ? (
              ev
            ) : (
              <pre
                className="text-xs p-2 rounded overflow-x-auto"
                style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
              >
                {JSON.stringify(ev, null, 2)}
              </pre>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function SupportingFindings({ supporting, engine, id }) {
  if (!Array.isArray(supporting) || supporting.length === 0) return null;
  return (
    <div className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
        Supporting Findings
      </h3>
      <div className="flex flex-col divide-y" style={{ borderColor: 'var(--border-primary)' }}>
        {supporting.map((s, i) => {
          const sEngine = s.engine || engine;
          const meta = ENGINE_META[sEngine];
          return (
            <a
              key={s.findingId || i}
              href={`/finding/${sEngine}/${encodeURIComponent(s.findingId)}`}
              onClick={() =>
                emit('finding.pivot_click', {
                  engine,
                  finding_id: id,
                  pivot_type: 'finding',
                  target_id: s.findingId,
                })
              }
              className="flex items-center gap-2 py-2 hover:opacity-80"
              style={{ color: 'var(--text-primary)' }}
            >
              <SeverityBadge severity={s.severity || 'info'} />
              {meta && (
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  {meta.label}
                </span>
              )}
              <span className="text-sm flex-1 truncate">{s.title || s.ruleId || s.findingId}</span>
            </a>
          );
        })}
      </div>
    </div>
  );
}

export default function OverviewTab({ finding, engine, id, data }) {
  const header = finding?.header || data?.header;
  const evidence = finding?.evidence || data?.evidence;
  const supporting = finding?.supporting || data?.supporting || finding?.supportingFindings;

  if (!header && !evidence && !supporting) {
    return <EmptyState title="No overview data" description="The BFF returned no overview details." />;
  }

  return (
    <div className="flex flex-col gap-4">
      {header?.summary && (
        <div className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
            Summary
          </h3>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
            {header.summary}
          </p>
        </div>
      )}
      <EvidenceList evidence={evidence} />
      <SupportingFindings supporting={supporting} engine={engine} id={id} />
    </div>
  );
}
