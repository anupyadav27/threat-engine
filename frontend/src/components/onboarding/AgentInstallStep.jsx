'use client';

/**
 * AgentInstallStep — Onboarding-D9
 *
 * Renders after a vulnerability account is created. Workflow:
 *   1. User clicks "Generate Install Command"
 *   2. Client generates PKCE pair (Web Crypto API, verifier never leaves JS memory)
 *   3. POST /gateway/api/v1/cloud-accounts/{id}/agent-token
 *      with X-PKCE-Verifier header → receives install_command
 *   4. Install command displayed in code block (one-time; Refresh Token regenerates)
 *   5. AgentStatusPoller polls /gateway/api/v1/views/agent_status?account_id=…
 *      every 5 seconds until connected or 5-minute timeout
 *
 * Security:
 *   - Raw token is embedded in install_command — kept only in component state
 *   - verifier is NEVER stored outside this component's closure
 *   - No credentials written to console, localStorage, or sessionStorage
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Terminal, Copy, Check, AlertTriangle, Loader2,
  CheckCircle2, RefreshCw, ChevronDown, ChevronRight,
} from 'lucide-react';
import { generatePkce } from '@/lib/pkce';

// ── Constants ─────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS  = 5_000;   // 5 s between status checks
const TIMEOUT_MS        = 300_000; // 5 minutes total wait

// ── CopyableCode ──────────────────────────────────────────────────────────────

function CopyableCode({ code }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(code);
    } catch (_) {
      // Fallback: execCommand (deprecated but still broadly supported)
      const ta = document.createElement('textarea');
      ta.value = code;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [code]);

  return (
    <div
      className="relative rounded-xl overflow-hidden border"
      style={{ borderColor: 'var(--border-primary)' }}
    >
      {/* Toolbar */}
      <div
        className="flex items-center justify-between px-3 py-2 border-b"
        style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
          <Terminal size={12} /> Install command
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-xs px-2 py-0.5 rounded hover:opacity-70 transition-opacity"
          style={{ color: copied ? '#22c55e' : 'var(--text-muted)' }}
          aria-label="Copy install command"
        >
          {copied
            ? <><Check size={11} /> Copied!</>
            : <><Copy size={11} /> Copy</>}
        </button>
      </div>

      {/* Code */}
      <pre
        className="p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap"
        style={{ backgroundColor: '#0d1117', color: '#e6edf3', lineHeight: 1.7 }}
      >
        {code}
      </pre>
    </div>
  );
}

// ── AgentStatusPoller ────────────────────────────────────────────────────────

/**
 * Polls GET /gateway/api/v1/views/agent_status?account_id=… every 5 s.
 * Emits onConnected() after a 3-second display delay when status flips to
 * "connected". Shows timeout warning after 5 minutes.
 */
function AgentStatusPoller({ accountId, onConnected, onRetry }) {
  const [status, setStatus]     = useState('pending'); // pending | connected | timeout | error
  const [elapsed, setElapsed]   = useState(0);         // seconds elapsed
  const pollRef  = useRef(null);
  const timeoutRef = useRef(null);
  const connectedRef = useRef(false);

  useEffect(() => {
    if (!accountId) return;

    const poll = async () => {
      try {
        const resp = await fetch(
          `/gateway/api/v1/views/agent_status?account_id=${encodeURIComponent(accountId)}`,
          { credentials: 'include' },
        );
        if (!resp.ok) return; // transient network error — keep polling
        const data = await resp.json();

        if (data.status === 'connected' && !connectedRef.current) {
          connectedRef.current = true;
          setStatus('connected');
          clearInterval(pollRef.current);
          clearTimeout(timeoutRef.current);
          // AC7: auto-advance after 3 seconds
          setTimeout(() => onConnected?.(), 3000);
        }
      } catch (_) {
        // transient — keep polling
      }
      setElapsed(s => s + 5);
    };

    pollRef.current  = setInterval(poll, POLL_INTERVAL_MS);
    timeoutRef.current = setTimeout(() => {
      if (!connectedRef.current) {
        clearInterval(pollRef.current);
        setStatus('timeout');
      }
    }, TIMEOUT_MS);

    return () => {
      clearInterval(pollRef.current);
      clearTimeout(timeoutRef.current);
    };
  }, [accountId, onConnected]);

  // ── Render ──

  if (status === 'connected') {
    return (
      <div className="flex items-center gap-2.5 text-sm" style={{ color: '#22c55e' }}>
        <CheckCircle2 size={16} />
        <span className="font-medium">Agent connected! Ready to scan.</span>
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
          (Continuing in 3 s…)
        </span>
      </div>
    );
  }

  if (status === 'timeout') {
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-sm" style={{ color: '#fbbf24' }}>
          <AlertTriangle size={15} />
          <span>Agent not detected — check your installation.</span>
        </div>
        <button
          onClick={onRetry}
          className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border hover:opacity-80 transition-opacity"
          style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
        >
          <RefreshCw size={11} /> Retry
        </button>
      </div>
    );
  }

  // pending
  const minutesLeft = Math.max(0, Math.floor((TIMEOUT_MS / 1000 - elapsed) / 60));
  return (
    <div className="flex items-center gap-2.5 text-sm" style={{ color: 'var(--text-muted)' }}>
      <Loader2 className="w-4 h-4 animate-spin" style={{ color: 'var(--accent-primary)' }} />
      <span>
        Waiting for agent to connect…{' '}
        <span className="text-xs">({minutesLeft} min remaining)</span>
      </span>
    </div>
  );
}

// ── HelpAccordion ─────────────────────────────────────────────────────────────

const HELP_SECTIONS = [
  {
    title: 'Minimum requirements',
    content: (
      <ul className="list-disc list-inside space-y-1">
        <li>Linux x86_64 or arm64 (Ubuntu 18+, CentOS 7+, Amazon Linux 2+)</li>
        <li>Root or sudo access for installation</li>
        <li>64 MB free RAM; 200 MB free disk space</li>
        <li>Systemd or Docker runtime for service management</li>
        <li>curl or wget available</li>
      </ul>
    ),
  },
  {
    title: 'Firewall requirements',
    content: (
      <ul className="list-disc list-inside space-y-1">
        <li>Outbound HTTPS (port 443) to <code className="font-mono">agents.onam.cloud</code></li>
        <li>No inbound ports required — agent initiates all connections</li>
        <li>Heartbeat interval: every 60 seconds (minimal bandwidth)</li>
        <li>Proxy support: set <code className="font-mono">HTTPS_PROXY</code> env var before running the install script</li>
      </ul>
    ),
  },
  {
    title: 'Troubleshooting',
    content: (
      <ul className="list-disc list-inside space-y-1">
        <li>Check service status: <code className="font-mono">sudo systemctl status onam-agent</code></li>
        <li>View logs: <code className="font-mono">sudo journalctl -u onam-agent -f</code></li>
        <li>Verify outbound connectivity: <code className="font-mono">curl -I https://agents.onam.cloud/health</code></li>
        <li>Token validity: tokens expire after 30 minutes — click "Refresh Token" to regenerate</li>
        <li>Docker install: ensure the container has network access to <code className="font-mono">agents.onam.cloud</code></li>
      </ul>
    ),
  },
];

function HelpAccordion() {
  const [open, setOpen] = useState(null);

  return (
    <div className="space-y-1.5">
      <div className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
        Help
      </div>
      {HELP_SECTIONS.map((s, i) => {
        const isOpen = open === i;
        return (
          <div
            key={i}
            className="rounded-lg border overflow-hidden"
            style={{ borderColor: 'var(--border-primary)' }}
          >
            <button
              type="button"
              onClick={() => setOpen(isOpen ? null : i)}
              className="w-full flex items-center justify-between px-4 py-3 text-left hover:opacity-80 transition-opacity text-sm"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}
            >
              <span className="font-medium">{s.title}</span>
              {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
            {isOpen && (
              <div
                className="px-4 py-3 text-xs border-t"
                style={{
                  borderColor: 'var(--border-primary)',
                  backgroundColor: 'var(--bg-card)',
                  color: 'var(--text-secondary)',
                  lineHeight: 1.7,
                }}
              >
                {s.content}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── AgentInstallStep (main export) ────────────────────────────────────────────

/**
 * @param {object} props
 * @param {string} props.accountId   - Cloud account UUID (from wizard state after account creation)
 * @param {function} [props.onConnected] - Called when agent phones home (AC7)
 */
export default function AgentInstallStep({ accountId, onConnected }) {
  // AC9: installCommand lives only in component-local state — never in wizard state
  const [installCommand, setInstallCommand] = useState(null);
  const [genState, setGenState]             = useState('idle'); // idle | generating | waiting | done | error
  const [errorMsg, setErrorMsg]             = useState('');
  const [platform, setPlatform]             = useState('linux');

  // Reset polling when Refresh Token is clicked
  const [pollKey, setPollKey] = useState(0);

  // Clear install command on unmount (AC9)
  useEffect(() => {
    return () => setInstallCommand(null);
  }, []);

  // ── Generate install command ─────────────────────────────────────────────

  const handleGenerate = useCallback(async () => {
    setGenState('generating');
    setErrorMsg('');
    setInstallCommand(null);

    try {
      // AC2 (BLOCK-04): PKCE verifier sent as X-PKCE-Verifier header — never in body/URL
      const { codeVerifier } = await generatePkce();

      const resp = await fetch(
        `/gateway/api/v1/cloud-accounts/${accountId}/agent-token`,
        {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'X-PKCE-Verifier': codeVerifier,
          },
        },
      );

      if (!resp.ok) {
        const d = await resp.json().catch(() => ({}));
        throw new Error(d.detail || `Server error ${resp.status}`);
      }

      const data = await resp.json();
      const cmd = data.install_command;
      if (!cmd) throw new Error('No install_command in response');

      // AC9: store in component state only — never forwarded to wizard state
      setInstallCommand(cmd);
      setGenState('waiting');
    } catch (e) {
      setGenState('error');
      setErrorMsg(e.message || 'Failed to generate install command');
    }
    // codeVerifier goes out of scope here — not persisted anywhere
  }, [accountId]);

  // ── Refresh Token ──────────────────────────────────────────────────────────

  const handleRefresh = useCallback(() => {
    setInstallCommand(null);
    setGenState('idle');
    setErrorMsg('');
    setPollKey(k => k + 1); // restart poller
  }, []);

  // ── Platform-specific variants ────────────────────────────────────────────

  const dockerCommand = installCommand
    ? installCommand
        .replace('curl -sSL', 'curl -fsSL')
        .replace(
          '| bash -s --',
          '\n  # OR run as Docker container:\n  docker run --rm yadavanup84/onam-agent:latest',
        )
    : null;

  const displayedCommand = platform === 'docker' && dockerCommand
    ? dockerCommand
    : installCommand;

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">

      {/* One-time warning (AC4) */}
      {genState === 'waiting' && installCommand && (
        <div
          className="flex items-start gap-2 p-3 rounded-lg border text-xs"
          style={{
            borderColor: 'rgba(245,158,11,0.4)',
            backgroundColor: 'rgba(245,158,11,0.08)',
            color: '#fbbf24',
          }}
        >
          <AlertTriangle size={13} className="flex-shrink-0 mt-0.5" />
          <span>
            <strong>Save this command now.</strong> The install token is shown once only.
            If you navigate away, click "Refresh Token" to generate a new one.
          </span>
        </div>
      )}

      {/* Generate / Refresh button (idle or error state) */}
      {(genState === 'idle' || genState === 'error') && (
        <div className="space-y-3">
          {genState === 'error' && (
            <div
              className="flex items-center gap-2 text-xs p-3 rounded-lg border"
              style={{
                borderColor: 'rgba(239,68,68,0.3)',
                backgroundColor: 'rgba(239,68,68,0.08)',
                color: '#f87171',
              }}
            >
              <AlertTriangle size={13} /> {errorMsg}
            </div>
          )}
          <button
            onClick={handleGenerate}
            disabled={!accountId}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-opacity hover:opacity-90 disabled:opacity-40"
            style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
          >
            Generate Install Command
          </button>
          {!accountId && (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Complete the account creation step first.
            </p>
          )}
        </div>
      )}

      {/* Generating spinner */}
      {genState === 'generating' && (
        <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-muted)' }}>
          <Loader2 className="w-4 h-4 animate-spin" style={{ color: 'var(--accent-primary)' }} />
          Generating secure install command…
        </div>
      )}

      {/* Install command display (AC3, AC4) */}
      {(genState === 'waiting' || genState === 'done') && displayedCommand && (
        <div className="space-y-3">
          {/* Platform selector */}
          <div className="flex gap-1">
            {['linux', 'docker'].map(p => (
              <button
                key={p}
                type="button"
                onClick={() => setPlatform(p)}
                className="px-3 py-1 rounded-lg text-xs font-medium transition-colors"
                style={{
                  backgroundColor: platform === p ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                  color: platform === p ? 'white' : 'var(--text-secondary)',
                }}
              >
                {p === 'linux' ? 'Linux / macOS' : 'Docker'}
              </button>
            ))}
          </div>

          <CopyableCode code={displayedCommand} />

          {/* Refresh Token button (AC4) */}
          <button
            onClick={handleRefresh}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border hover:opacity-80 transition-opacity"
            style={{ borderColor: 'var(--border-primary)', color: 'var(--text-muted)' }}
          >
            <RefreshCw size={11} /> Refresh Token
          </button>
        </div>
      )}

      {/* Agent status poller (AC5, AC6, AC7, AC8) */}
      {genState === 'waiting' && accountId && (
        <AgentStatusPoller
          key={pollKey}
          accountId={accountId}
          onConnected={() => {
            setGenState('done');
            onConnected?.();
          }}
          onRetry={handleRefresh}
        />
      )}

      {/* Help accordion (AC10) */}
      <HelpAccordion />
    </div>
  );
}
