'use client';

import EmptyState from '@/components/shared/EmptyState';
import { ExternalLink } from 'lucide-react';

/**
 * Minimal markdown-ish renderer — handles paragraphs, **bold**, `code`,
 * - lists, and ``` fenced blocks. Avoids pulling in a markdown dep.
 * For richer rendering a future story can swap in react-markdown.
 */
function renderMarkdown(md) {
  if (!md || typeof md !== 'string') return null;
  const lines = md.split('\n');
  const blocks = [];
  let buf = [];
  let inFence = false;
  let fenceBuf = [];

  function flushPara() {
    if (buf.length === 0) return;
    blocks.push({ type: 'p', text: buf.join(' ') });
    buf = [];
  }

  for (const ln of lines) {
    if (ln.trim().startsWith('```')) {
      if (inFence) {
        blocks.push({ type: 'code', text: fenceBuf.join('\n') });
        fenceBuf = [];
        inFence = false;
      } else {
        flushPara();
        inFence = true;
      }
      continue;
    }
    if (inFence) {
      fenceBuf.push(ln);
      continue;
    }
    if (ln.trim() === '') {
      flushPara();
      continue;
    }
    if (/^\s*[-*]\s+/.test(ln)) {
      flushPara();
      const last = blocks[blocks.length - 1];
      const item = ln.replace(/^\s*[-*]\s+/, '');
      if (last && last.type === 'ul') last.items.push(item);
      else blocks.push({ type: 'ul', items: [item] });
      continue;
    }
    buf.push(ln);
  }
  flushPara();
  if (inFence && fenceBuf.length) blocks.push({ type: 'code', text: fenceBuf.join('\n') });

  return blocks.map((b, i) => {
    if (b.type === 'p') return <p key={i} className="text-sm mb-2" style={{ color: 'var(--text-muted)' }}>{inline(b.text)}</p>;
    if (b.type === 'ul') return (
      <ul key={i} className="list-disc list-inside mb-2 text-sm" style={{ color: 'var(--text-muted)' }}>
        {b.items.map((it, j) => <li key={j}>{inline(it)}</li>)}
      </ul>
    );
    if (b.type === 'code') return (
      <pre key={i} className="text-xs p-3 rounded mb-2 overflow-x-auto"
        style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)' }}>
        {b.text}
      </pre>
    );
    return null;
  });
}

function inline(text) {
  // **bold** and `code` only
  const parts = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIdx = 0;
  let m;
  let key = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > lastIdx) parts.push(text.slice(lastIdx, m.index));
    const tok = m[0];
    if (tok.startsWith('**')) parts.push(<strong key={key++}>{tok.slice(2, -2)}</strong>);
    else parts.push(<code key={key++} className="px-1 rounded text-xs" style={{ backgroundColor: 'var(--bg-secondary)' }}>{tok.slice(1, -1)}</code>);
    lastIdx = m.index + tok.length;
  }
  if (lastIdx < text.length) parts.push(text.slice(lastIdx));
  return parts;
}

export default function RemediationTab({ finding, data }) {
  const remediation = finding?.remediation || data?.remediation || {};
  const guidance = remediation.guidance || remediation.markdown;
  const runbookUrl = remediation.runbookUrl || remediation.runbook_url;
  const references = remediation.references || [];

  if (!guidance && !runbookUrl && (!references || references.length === 0)) {
    return (
      <EmptyState
        title="No remediation guidance"
        description="This finding's rule has no remediation guidance configured."
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {guidance && (
        <div className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
            Remediation guidance
          </h3>
          {renderMarkdown(guidance)}
        </div>
      )}
      {runbookUrl && (
        <a
          href={runbookUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 px-3 py-2 rounded text-sm self-start"
          style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
        >
          <ExternalLink className="w-4 h-4" /> Open runbook
        </a>
      )}
      {Array.isArray(references) && references.length > 0 && (
        <div className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
            References
          </h3>
          <ul className="space-y-1 text-sm">
            {references.map((ref, i) => {
              const url = typeof ref === 'string' ? ref : ref.url;
              const label = typeof ref === 'string' ? ref : ref.label || ref.url;
              return (
                <li key={i}>
                  <a href={url} target="_blank" rel="noopener noreferrer"
                    style={{ color: 'var(--accent-primary)' }}
                    className="inline-flex items-center gap-1">
                    <ExternalLink className="w-3 h-3" /> {label}
                  </a>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
