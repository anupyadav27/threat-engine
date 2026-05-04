'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowLeft, ExternalLink } from 'lucide-react';
import ScanPipelineProgress from '@/components/scans/ScanPipelineProgress';

export default function ScanProgressPage({ params }) {
  const { scanRunId } = params;
  const router = useRouter();
  const [progress, setProgress] = useState(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!scanRunId) return;

    // Try SSE stream from pipeline-monitor engine first
    const es = new EventSource(`/gateway/api/v1/pipeline-monitor/scans/${scanRunId}/stream`);
    es.onopen = () => setConnected(true);

    es.onmessage = (e) => {
      try { setProgress(JSON.parse(e.data)); } catch (_) {}
    };

    es.onerror = () => {
      es.close();
      setConnected(false);
      // Fall back to polling the scan-runs status endpoint
      const pollId = setInterval(async () => {
        try {
          const resp = await fetch(`/gateway/api/v1/scan-runs/${scanRunId}/status`, { credentials: 'include' });
          if (!resp.ok) return;
          const data = await resp.json();
          setProgress(data);
          if (data.overall_status === 'completed' || data.overall_status === 'failed') {
            clearInterval(pollId);
          }
        } catch (_) {}
      }, 5000);
      return () => clearInterval(pollId);
    };

    return () => es.close();
  }, [scanRunId]);

  const done = progress?.overall_status === 'completed' || progress?.overall_status === 'failed';

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Nav */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => router.back()}
          className="flex items-center gap-1.5 text-sm hover:opacity-70 transition-opacity"
          style={{ color: 'var(--text-muted)' }}
        >
          <ArrowLeft size={14} /> Back
        </button>
      </div>

      {/* Title */}
      <div>
        <h1 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
          Scan Progress
        </h1>
        <div className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Real-time pipeline status for scan run
          <span className="font-mono ml-1.5">{scanRunId}</span>
          {connected && (
            <span className="ml-2 text-[11px] px-1.5 py-0.5 rounded"
              style={{ backgroundColor: 'rgba(34,197,94,0.12)', color: '#22c55e' }}>
              LIVE
            </span>
          )}
        </div>
      </div>

      {/* Progress widget */}
      <div
        className="rounded-2xl border p-6"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <ScanPipelineProgress scanRunId={scanRunId} progress={progress} />
      </div>

      {/* Done actions */}
      {done && progress?.overall_status === 'completed' && (
        <div className="flex gap-3">
          <button
            onClick={() => router.push('/dashboard')}
            className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-xl hover:opacity-90 transition-opacity"
            style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
          >
            View Results <ExternalLink size={13} />
          </button>
          <button
            onClick={() => router.push('/onboarding/accounts')}
            className="px-4 py-2 text-sm rounded-xl border hover:opacity-80 transition-opacity"
            style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
          >
            Back to Accounts
          </button>
        </div>
      )}
    </div>
  );
}
