'use client';

/**
 * ValidationStatus — Step 4 of the onboarding wizard.
 *
 * Polls GET /gateway/api/v1/cloud-accounts/{id}/validation-status every 5 s
 * until status is 'pass' or 'fail', or until 60 s elapsed (timeout → 'fail').
 *
 * Props:
 *   accountId       — ID of the cloud account to poll
 *   onPass(result)  — called when validation succeeds
 *   onFail(msg)     — called when validation fails
 *   onReEnter()     — called when user clicks "Re-enter Credentials"
 */

import { useEffect, useRef, useState } from 'react';
import { CheckCircle2, XCircle, Loader2, RefreshCw, AlertTriangle } from 'lucide-react';

const POLL_INTERVAL_MS = 5_000;
const MAX_WAIT_MS      = 60_000;

export default function ValidationStatus({ accountId, onPass, onFail, onReEnter }) {
  const [status, setStatus]   = useState('pending'); // pending | pass | fail | timeout
  const [message, setMessage] = useState('');
  const [elapsed, setElapsed] = useState(0);

  const pollRef    = useRef(null);
  const timeoutRef = useRef(null);
  const timerRef   = useRef(null);

  // Trigger validation then start polling
  useEffect(() => {
    if (!accountId) return;

    let cancelled = false;

    async function triggerAndPoll() {
      // Fire the validate call — ignore errors (engine may auto-validate on cred save)
      try {
        await fetch(`/gateway/api/v1/cloud-accounts/${accountId}/validate-credentials`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (_) {
        // Ignore trigger errors — poll will pick up status regardless
      }

      if (cancelled) return;

      // Elapsed counter (UI only)
      timerRef.current = setInterval(() => {
        setElapsed(e => e + 1);
      }, 1000);

      // Start polling
      pollRef.current = setInterval(async () => {
        try {
          const resp = await fetch(
            `/gateway/api/v1/cloud-accounts/${accountId}/validation-status`,
            { credentials: 'include' }
          );
          if (!resp.ok) return;
          const data = await resp.json();
          const s = data.status || data.validation_status;

          if (s === 'pass' || s === 'valid') {
            clearAll();
            if (!cancelled) {
              setStatus('pass');
              if (onPass) onPass(data);
            }
          } else if (s === 'fail' || s === 'invalid' || s === 'error') {
            clearAll();
            if (!cancelled) {
              const msg = data.error_message || data.detail || 'Validation failed.';
              setStatus('fail');
              setMessage(msg);
              if (onFail) onFail(msg);
            }
          }
        } catch (_) {
          // Ignore transient poll errors
        }
      }, POLL_INTERVAL_MS);

      // Hard timeout
      timeoutRef.current = setTimeout(() => {
        if (cancelled) return;
        clearAll();
        setStatus('timeout');
        const msg = 'Validation timed out after 60 seconds. Please check your credentials and try again.';
        setMessage(msg);
        if (onFail) onFail(msg);
      }, MAX_WAIT_MS);
    }

    triggerAndPoll();

    return () => {
      cancelled = true;
      clearAll();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accountId]);

  function clearAll() {
    if (pollRef.current)    clearInterval(pollRef.current);
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    if (timerRef.current)   clearInterval(timerRef.current);
  }

  // ── Pending ──────────────────────────────────────────────────────────────
  if (status === 'pending') {
    return (
      <div className="flex flex-col items-center gap-4 py-10">
        <Loader2
          className="w-10 h-10 animate-spin"
          style={{ color: 'var(--accent-primary)' }}
        />
        <div className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
          Validating credentials…
        </div>
        <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
          {elapsed}s elapsed — this may take up to 60 seconds
        </div>
      </div>
    );
  }

  // ── Pass ─────────────────────────────────────────────────────────────────
  if (status === 'pass') {
    return (
      <div className="space-y-4">
        <div
          className="flex items-center gap-3 p-4 rounded-xl border"
          style={{
            borderColor: 'rgba(34,197,94,0.35)',
            backgroundColor: 'rgba(34,197,94,0.08)',
          }}
        >
          <CheckCircle2 className="w-7 h-7 flex-shrink-0" style={{ color: '#22c55e' }} />
          <div>
            <div className="text-sm font-semibold" style={{ color: '#22c55e' }}>
              Credentials validated
            </div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Your credentials have been verified. Continue to set up a scan schedule.
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ── Fail / Timeout ────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">
      <div
        className="flex items-start gap-3 p-4 rounded-xl border"
        style={{
          borderColor: 'rgba(239,68,68,0.35)',
          backgroundColor: 'rgba(239,68,68,0.08)',
        }}
      >
        {status === 'timeout' ? (
          <AlertTriangle className="w-6 h-6 flex-shrink-0 mt-0.5" style={{ color: '#f97316' }} />
        ) : (
          <XCircle className="w-6 h-6 flex-shrink-0 mt-0.5" style={{ color: '#ef4444' }} />
        )}
        <div>
          <div
            className="text-sm font-semibold"
            style={{ color: status === 'timeout' ? '#f97316' : '#ef4444' }}
          >
            {status === 'timeout' ? 'Validation timed out' : 'Validation failed'}
          </div>
          {message && (
            <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              {message}
            </div>
          )}
        </div>
      </div>

      {onReEnter && (
        <button
          onClick={onReEnter}
          className="flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg border hover:opacity-80 transition-opacity"
          style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
        >
          <RefreshCw size={14} />
          Re-enter Credentials
        </button>
      )}
    </div>
  );
}
