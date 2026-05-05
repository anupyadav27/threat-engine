'use client';

import { useMemo } from 'react';
import DataTable from '@/components/shared/DataTable';
import EmptyState from '@/components/shared/EmptyState';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { AlertTriangle } from 'lucide-react';
import { emit } from '@/lib/telemetry';
import { ENGINE_META } from './engine-meta';

export default function RelatedFindingsTab({ finding, engine, id, data }) {
  const related = finding?.related || data?.related || finding?.relatedFindings || [];
  const restrictedEngines = data?.restrictedEngines || finding?.restrictedEngines || [];
  const partial = data?.partial || finding?.partial || false;
  const degradedEngines = data?.degradedEngines || finding?.degradedEngines || [];

  const columns = useMemo(
    () => [
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => <SeverityBadge severity={row.original.severity || 'info'} />,
      },
      {
        accessorKey: 'engine',
        header: 'Engine',
        cell: ({ row }) => {
          const meta = ENGINE_META[row.original.engine];
          return <span className="text-xs">{meta?.label || row.original.engine}</span>;
        },
      },
      {
        accessorKey: 'title',
        header: 'Title',
        cell: ({ row }) => {
          const r = row.original;
          const targetEngine = r.engine || engine;
          const fid = r.findingId || r.finding_id;
          if (!fid) return <span>{r.title}</span>;
          return (
            <a
              href={`/finding/${targetEngine}/${encodeURIComponent(fid)}`}
              onClick={() =>
                emit('finding.pivot_click', {
                  engine,
                  finding_id: id,
                  pivot_type: 'finding',
                  target_id: fid,
                })
              }
              style={{ color: 'var(--accent-primary)' }}
            >
              {r.title || r.ruleId || fid}
            </a>
          );
        },
      },
      { accessorKey: 'resourceUid', header: 'Resource' },
      { accessorKey: 'lastSeenAt', header: 'Last seen' },
    ],
    [engine, id]
  );

  return (
    <div className="flex flex-col gap-3">
      {restrictedEngines.length > 0 && (
        <div
          className="flex items-start gap-2 rounded border p-3 text-sm"
          style={{
            backgroundColor: 'rgba(245,158,11,0.08)',
            borderColor: 'rgba(245,158,11,0.4)',
            color: 'var(--text-primary)',
          }}
        >
          <AlertTriangle className="w-4 h-4 mt-0.5" style={{ color: '#f59e0b' }} />
          <span>
            Some related findings are hidden because you don&apos;t have access to:{' '}
            <strong>{restrictedEngines.join(', ')}</strong>.
          </span>
        </div>
      )}
      {partial && degradedEngines.length > 0 && (
        <div
          className="flex items-start gap-2 rounded border p-3 text-sm"
          style={{
            backgroundColor: 'rgba(59,130,246,0.08)',
            borderColor: 'rgba(59,130,246,0.4)',
            color: 'var(--text-primary)',
          }}
        >
          <AlertTriangle className="w-4 h-4 mt-0.5" style={{ color: '#3b82f6' }} />
          <span>
            Partial results — these engines did not respond in time:{' '}
            <strong>{degradedEngines.join(', ')}</strong>.
          </span>
        </div>
      )}
      {related.length === 0 ? (
        <EmptyState
          title="No related findings"
          description="No other findings on this resource across other engines."
        />
      ) : (
        <DataTable data={related} columns={columns} emptyMessage="No related findings" />
      )}
    </div>
  );
}
