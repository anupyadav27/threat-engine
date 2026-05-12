'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowLeft, ExternalLink, Loader2 } from 'lucide-react';
import { fetchView } from '@/lib/api';
import ScanPipelineProgress from '@/components/scans/ScanPipelineProgress';

// Poll BFF view every 10 seconds per AC8
const POLL_INTERVAL_MS = 10_000;

export default function ScanProgressPage({ params }) {
  const { scanId } = params;
  const router = useRouter();
  const [progress, setProgress] = useState(null);
  const [connected, setConnected] = useState(false);
  const [loadingInitial, setLoadingInitial] = useState(true);
  const pollRef = useRef(null);

  // Fetch scan detail from BFF view (AC8)
  async function fetchScanDetail() {
    try {
      const data = await fetchView(`scan_detail?scan_run_id=${scanId}`);
      if (data && !data.error) {
        setProgress(data);
        return data;
      }
    } catch (_) {}
    return null;
  }

  useEffect(() => {
    if (!scanId) return;

    // Initial load
    fetchScanDetail().then(data => {
      setLoadingInitial(false);
      // Start polling unless already terminal
      if (data && (data.overall_status === 'completed' || data.overall_status === 'failed')) return;
      pollRef.current = setInterval(async () => {
        const d = await fetchScanDetail();
        if (d && (d.overall_status === 'completed' || d.overall_status === 'failed')) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
      }, POLL_INTERVAL_MS);
    });

    // Also try SSE stream from pipeline-monitor for live updates
    const es = new EventSource(`/gateway/api/v1/pipeline-monitor/scans/${scanId}/stream`);
    es.onopen = () => setConnected(true);
    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data);
        setProgress(parsed);
        // Stop BFF polling if SSE delivers terminal state
        if (parsed.overall_status === 'completed' || parsed.overall_status === 'failed') {
          if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
        }
      } catch (_) {}
    };
    es.onerror = () => {
      es.close();
      setConnected(false);
    };

    return () => {
      es.close();
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [scanId]);

  const done = progress?.overall_status === 'completed' || progress?.overall_status === 'failed';
  const isPolling = !done && !connected;

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-2">
        <button
          onClick={() => router.back()}
          className="flex items-center gap-1.5 text-sm hover:opacity-70 transition-opacity"
          style={{ color: 'var(--text-muted)' }}
        >
          <ArrowLeft size={14} /> Back
        </button>
      </div>

      <div>
        <h1 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
          Scan Progress
        </h1>
        <div className="flex items-center gap-2 text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
          <span>Pipeline status for scan</span>
          <code className="font-mono text-xs px-1.5 py-0.5 rounded"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
            {scanId}
          </code>
          {connected && (
            <span className="text-[11px] px-1.5 py-0.5 rounded"
              style={{ backgroundColor: 'rgba(34,197,94,0.12)', color: '#22c55e' }}>
              LIVE
            </span>
          )}
          {isPolling && !loadingInitial && (
            <span className="flex items-center gap-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>
              <Loader2 size={10} className="animate-spin" /> polling every 10s
            </span>
          )}
        </div>
      </div>

      <div
        className="rounded-2xl border p-6"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        {loadingInitial ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--text-muted)' }} />
          </div>
        ) : (
          <ScanPipelineProgress scanRunId={scanId} progress={progress} />
        )}
      </div>

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
            onClick={() => router.push('/onboarding')}
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
