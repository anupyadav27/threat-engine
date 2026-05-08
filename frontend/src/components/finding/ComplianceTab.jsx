'use client';

import EmptyState from '@/components/shared/EmptyState';
import { emit } from '@/lib/telemetry';

export default function ComplianceTab({ finding, engine, id, data }) {
  const mappings = finding?.compliance || data?.compliance || finding?.complianceMappings || [];

  if (!Array.isArray(mappings) || mappings.length === 0) {
    return (
      <EmptyState
        title="No compliance mappings"
        description="This finding's rule has no control mappings yet."
      />
    );
  }

  return (
    <div className="rounded-lg border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <table className="w-full text-sm">
        <thead style={{ backgroundColor: 'var(--bg-secondary)' }}>
          <tr>
            <th className="text-left px-3 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>Framework</th>
            <th className="text-left px-3 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>Control</th>
            <th className="text-left px-3 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>Title</th>
          </tr>
        </thead>
        <tbody>
          {mappings.map((m, i) => {
            const cid = m.controlId || m.control_id;
            const fw = m.framework;
            return (
              <tr key={`${fw}-${cid}-${i}`} className="border-t" style={{ borderColor: 'var(--border-primary)' }}>
                <td className="px-3 py-2" style={{ color: 'var(--text-primary)' }}>{fw}</td>
                <td className="px-3 py-2 font-mono text-xs">
                  <a
                    href={`/compliance/${encodeURIComponent(fw)}/control/${encodeURIComponent(cid)}`}
                    onClick={() =>
                      emit('finding.pivot_click', {
                        engine,
                        finding_id: id,
                        pivot_type: 'control',
                        target_id: cid,
                      })
                    }
                    style={{ color: 'var(--accent-primary)' }}
                  >
                    {cid}
                  </a>
                </td>
                <td className="px-3 py-2" style={{ color: 'var(--text-muted)' }}>
                  {m.title || m.controlTitle}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
