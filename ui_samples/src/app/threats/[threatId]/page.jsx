'use client';

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Shield, ChevronRight, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import SeverityBadge from '@/components/shared/SeverityBadge';
import DataTable from '@/components/shared/DataTable';

export default function ThreatDetailPage() {
  const router = useRouter();
  const params = useParams();
  const threatId = params?.threatId;
  const [loading, setLoading] = useState(true);
  const [threat, setThreat] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        // Fetch full threat list and find by ID
        const res = await getFromEngine('threat', '/api/v1/threat/list', { scan_run_id: 'latest', limit: 1000 });
        if (res && !res.error) {
          const list = res.findings || res.data || res;
          const found = Array.isArray(list) ? list.find((t) => t.id === threatId || t.finding_id === threatId) : null;
          if (found) {
            setThreat(found);
          } else {
            setError('Threat not found');
          }
        } else {
          setError(res?.error || 'Failed to load threat data');
        }
      } catch (err) {
        setError(err?.message || 'Failed to load threat data');
      } finally {
        setLoading(false);
      }
    };
    if (threatId) fetchData();
  }, [threatId]);

  const resourceColumns = [
    { accessorKey: 'arn', header: 'Resource ARN', cell: (info) => <code className="text-xs" style={{ color: 'var(--text-muted)' }}>{info.getValue()}</code> },
    { accessorKey: 'type', header: 'Type', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'action', header: 'Action', cell: (info) => <code className="text-xs" style={{ color: 'var(--accent-primary)' }}>{info.getValue()}</code> },
    { accessorKey: 'result', header: 'Result', cell: (info) => {
      const val = info.getValue();
      return <span className="text-xs" style={{ color: val === 'Success' ? 'var(--accent-danger)' : 'var(--accent-success)' }}>{val}</span>;
    }},
  ];

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-32 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        <div className="h-48 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--accent-danger)' }}>
        <p className="text-sm font-medium" style={{ color: 'var(--accent-danger)' }}>Error: {error}</p>
      </div>
    );
  }

  if (!threat) return <div className="p-6" style={{ color: 'var(--text-secondary)' }}>No data available.</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <button onClick={() => router.push('/threats')} className="text-sm" style={{ color: 'var(--text-muted)' }}>Threats</button>
        <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        <span className="text-sm" style={{ color: 'var(--text-muted)' }}>{threat.id}</span>
      </div>

      {/* Threat Header */}
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <SeverityBadge severity={threat.severity} />
              <code className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--accent-primary)' }}>{threat.mitre_technique}</code>
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{threat.mitre_tactic}</span>
            </div>
            <h1 className="text-xl font-bold mb-2" style={{ color: 'var(--text-primary)' }}>{threat.title}</h1>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{threat.description}</p>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold" style={{ color: threat.risk_score >= 80 ? 'var(--accent-danger)' : 'var(--accent-warning)' }}>
              {threat.risk_score}
            </div>
            <div className="text-xs" style={{ color: 'var(--text-muted)' }}>Risk Score</div>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4 pt-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <div><p className="text-xs" style={{ color: 'var(--text-muted)' }}>Provider</p><p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{threat.provider}</p></div>
          <div><p className="text-xs" style={{ color: 'var(--text-muted)' }}>Account</p><p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{threat.account}</p></div>
          <div><p className="text-xs" style={{ color: 'var(--text-muted)' }}>Status</p><p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{threat.status}</p></div>
          <div><p className="text-xs" style={{ color: 'var(--text-muted)' }}>Assignee</p><p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{threat.assignee || 'Unassigned'}</p></div>
        </div>
      </div>

      {/* Affected Resources */}
      {threat.affected_resource_details && (
        <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Affected Resources</h2>
          <DataTable columns={resourceColumns} data={threat.affected_resource_details} />
        </div>
      )}

      {/* Remediation Steps */}
      {threat.remediation_steps && (
        <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Remediation Steps</h2>
          <div className="space-y-3">
            {threat.remediation_steps.map((step, idx) => (
              <div key={idx} className="flex items-start gap-3">
                <div className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0" style={{ backgroundColor: 'var(--accent-success)', color: 'white' }}>
                  {idx + 1}
                </div>
                <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{step}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Timeline */}
      {threat.timeline && (
        <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Activity Timeline</h2>
          <div className="space-y-3">
            {threat.timeline.map((event, idx) => (
              <div key={idx} className="flex items-start gap-3">
                <Clock className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
                <div>
                  <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{new Date(event.time).toLocaleString()}</p>
                  <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{event.event} <span style={{ color: 'var(--text-muted)' }}>— {event.actor}</span></p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
