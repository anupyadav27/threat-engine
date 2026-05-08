'use client';

import { useState, useRef, useEffect } from 'react';
import { CheckCircle2, Copy, Check, Loader2, AlertTriangle, Terminal } from 'lucide-react';
import { generatePkce } from '@/lib/pkce';
import PrerequisitesChecklist from './PrerequisitesChecklist';

const POLL_INTERVAL_MS = 5000;

// Build platform-specific install command
function buildInstallCommand(platform, accountType, registrationId, codeVerifier) {
  const base = `--registration-id ${registrationId} --verifier ${codeVerifier}`;
  if (platform === 'docker') {
    const image = accountType === 'vulnerability' ? 'yadavanup84/cspm-vuln-agent:latest'
                : accountType === 'database'      ? 'yadavanup84/cspm-db-agent:latest'
                : 'yadavanup84/cspm-middleware-agent:latest';
    return `docker run -d --name cspm-agent \\\n  -e REGISTRATION_ID=${registrationId} \\\n  -e CODE_VERIFIER=${codeVerifier} \\\n  ${image}`;
  }
  return `curl -fsSL https://agent.cspm.io/install.sh | sudo bash -s -- \\\n  ${base}`;
}

function CopyableCode({ code }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative rounded-xl overflow-hidden border" style={{ borderColor: 'var(--border-primary)' }}>
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
        >
          {copied ? <><Check size={11} /> Copied!</> : <><Copy size={11} /> Copy</>}
        </button>
      </div>
      <pre
        className="p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap"
        style={{ backgroundColor: '#0d1117', color: '#e6edf3', lineHeight: 1.6 }}
      >
        {code}
      </pre>
    </div>
  );
}

export default function AgentInstallStep({ account, authModel, onComplete }) {
  const [state, setState] = useState('ready'); // ready | generating | waiting | complete | error
  const [installCmds, setInstallCmds] = useState(null);
  const [platform, setPlatform] = useState('linux');
  const [errorMsg, setErrorMsg] = useState('');
  const pollRef = useRef(null);

  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  async function handleGenerate() {
    setState('generating');
    setErrorMsg('');
    try {
      const { codeVerifier, codeChallenge } = await generatePkce();

      const resp = await fetch(`/gateway/api/v1/cloud-accounts/${account.account_id}/agent-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ code_challenge: codeChallenge, account_type: account.account_type }),
      });
      if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
      const { registration_id } = await resp.json();

      // Build commands for all platforms — verifier in JS memory only
      setInstallCmds({
        linux:  buildInstallCommand('linux',  account.account_type, registration_id, codeVerifier),
        docker: buildInstallCommand('docker', account.account_type, registration_id, codeVerifier),
      });
      setState('waiting');

      // Poll for agent heartbeat
      pollRef.current = setInterval(async () => {
        try {
          const statusResp = await fetch(`/gateway/api/v1/cloud-accounts/${account.account_id}`, {
            credentials: 'include',
          });
          if (!statusResp.ok) return;
          const data = await statusResp.json();
          if (data.account_status === 'active') {
            clearInterval(pollRef.current);
            setState('complete');
            if (onComplete) onComplete();
          }
        } catch (_) { /* ignore poll errors */ }
      }, POLL_INTERVAL_MS);
    } catch (e) {
      setState('error');
      setErrorMsg(e.message || 'Failed to generate install command');
    }
  }

  if (state === 'complete') {
    return (
      <div className="flex flex-col items-center gap-3 py-8">
        <CheckCircle2 className="w-10 h-10" style={{ color: '#22c55e' }} />
        <div className="text-sm font-semibold" style={{ color: '#22c55e' }}>Agent connected successfully!</div>
        <div className="text-xs" style={{ color: 'var(--text-muted)' }}>Your account is now active and will begin scanning.</div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Prerequisites */}
      <PrerequisitesChecklist authModel={authModel} />

      {/* Generate button */}
      {(state === 'ready' || state === 'error') && (
        <div className="space-y-3">
          {state === 'error' && (
            <div className="flex items-center gap-2 text-xs p-3 rounded-lg border" style={{ borderColor: 'rgba(239,68,68,0.3)', backgroundColor: 'rgba(239,68,68,0.08)', color: '#f87171' }}>
              <AlertTriangle size={13} /> {errorMsg}
            </div>
          )}
          <button
            onClick={handleGenerate}
            className="px-4 py-2.5 rounded-lg text-sm font-medium transition-opacity hover:opacity-90"
            style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
          >
            Generate Install Command
          </button>
        </div>
      )}

      {/* Install command */}
      {(state === 'waiting' || state === 'generating') && installCmds && (
        <div className="space-y-4">
          {/* One-time warning */}
          <div className="flex items-start gap-2 p-3 rounded-lg border text-xs"
            style={{ borderColor: 'rgba(245,158,11,0.4)', backgroundColor: 'rgba(245,158,11,0.08)', color: '#fbbf24' }}>
            <AlertTriangle size={13} className="flex-shrink-0 mt-0.5" />
            <span><strong>Save this command now.</strong> The install key is shown once only. If you navigate away, you will need to generate a new command.</span>
          </div>

          {/* Platform tabs */}
          <div className="flex gap-1">
            {['linux', 'docker'].map(p => (
              <button key={p} onClick={() => setPlatform(p)}
                className="px-3 py-1 rounded-lg text-xs font-medium transition-colors"
                style={{
                  backgroundColor: platform === p ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                  color: platform === p ? 'white' : 'var(--text-secondary)',
                }}>
                {p === 'linux' ? 'Linux / macOS' : 'Docker'}
              </button>
            ))}
          </div>

          <CopyableCode code={installCmds[platform]} />

          {/* Waiting indicator */}
          <div className="flex items-center gap-2.5 text-sm" style={{ color: 'var(--text-muted)' }}>
            <Loader2 className="w-4 h-4 animate-spin" style={{ color: 'var(--accent-primary)' }} />
            Waiting for agent to connect and send first heartbeat…
          </div>
        </div>
      )}
    </div>
  );
}
