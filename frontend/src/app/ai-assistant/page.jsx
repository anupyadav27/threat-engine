'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { API_BASE } from '@/lib/constants';

// ── Icons (inline SVG) ────────────────────────────────────────────────────────

const SendIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" />
  </svg>
);
const PlusIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);
const BotIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/>
    <path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/>
  </svg>
);
const SparkleIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2L14.4 9.6H22L16 14.4L18.4 22L12 17.2L5.6 22L8 14.4L2 9.6H9.6L12 2Z"/>
  </svg>
);

// ── Helpers ───────────────────────────────────────────────────────────────────

function activeTenantHeader() {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem('cspm_active_tenant');
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    const tid = parsed?.engine_tenant_id || parsed?.tenant_id;
    return tid ? { 'X-Active-Tenant-Id': String(tid) } : {};
  } catch { return {}; }
}

function apiHeaders(extra = {}) {
  return { 'Content-Type': 'application/json', ...activeTenantHeader(), ...extra };
}

function timeAgo(iso) {
  const d = new Date(iso);
  const diff = Math.floor((Date.now() - d) / 1000);
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString();
}

// ── Category colours ──────────────────────────────────────────────────────────

const CAT_STYLE = {
  'Security Posture': { bg: 'rgba(239,68,68,0.12)',   color: '#ef4444' },
  'Compliance':       { bg: 'rgba(59,130,246,0.12)',  color: '#3b82f6' },
  'Threats':          { bg: 'rgba(249,115,22,0.12)',  color: '#f97316' },
  'Inventory':        { bg: 'rgba(16,185,129,0.12)',  color: '#10b981' },
  'Access':           { bg: 'rgba(139,92,246,0.12)',  color: '#8b5cf6' },
  'Detections':       { bg: 'rgba(234,179,8,0.12)',   color: '#eab308' },
};

// ── Markdown renderer (simple) ────────────────────────────────────────────────

function renderMarkdown(text) {
  if (!text) return '';
  return text
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`(.+?)`/g, '<code style="background:rgba(255,255,255,0.08);padding:1px 5px;border-radius:3px;font-size:0.85em">$1</code>')
    .replace(/^### (.+)$/gm, '<h3 style="margin:12px 0 4px;font-size:1em;font-weight:600">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 style="margin:14px 0 4px;font-size:1.05em;font-weight:700">$1</h2>')
    .replace(/^- (.+)$/gm, '<li style="margin:2px 0;padding-left:4px">$1</li>')
    .replace(/(<li.*<\/li>\n?)+/g, m => `<ul style="padding-left:16px;margin:6px 0">${m}</ul>`)
    .replace(/\n\n/g, '<br/><br/>')
    .replace(/\n/g, '<br/>');
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Thinking() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{
        width: 28, height: 28, borderRadius: '50%',
        background: 'var(--accent-primary)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0,
      }}>
        <BotIcon />
      </div>
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border-primary)',
        borderRadius: 12, borderBottomLeftRadius: 4,
        padding: '10px 16px',
        display: 'flex', alignItems: 'center', gap: 6,
        color: 'var(--text-secondary)', fontSize: 13,
      }}>
        <span>Analysing</span>
        {[0, 1, 2].map(i => (
          <span key={i} style={{
            width: 5, height: 5, borderRadius: '50%',
            background: 'var(--accent-primary)',
            display: 'inline-block',
            animation: 'chatBounce 1.2s ease-in-out infinite',
            animationDelay: `${i * 0.2}s`,
          }} />
        ))}
      </div>
    </div>
  );
}

function MessageBubble({ msg }) {
  const isUser = msg.role === 'user';
  return (
    <div style={{
      display: 'flex',
      flexDirection: isUser ? 'row-reverse' : 'row',
      alignItems: 'flex-start',
      gap: 8,
    }}>
      {!isUser && (
        <div style={{
          width: 28, height: 28, borderRadius: '50%',
          background: 'var(--accent-primary)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0, marginTop: 2,
        }}>
          <BotIcon />
        </div>
      )}
      <div style={{
        maxWidth: '72%',
        background: isUser
          ? 'var(--accent-primary)'
          : 'var(--bg-secondary)',
        border: isUser ? 'none' : '1px solid var(--border-primary)',
        borderRadius: 12,
        borderBottomRightRadius: isUser ? 4 : 12,
        borderBottomLeftRadius: isUser ? 12 : 4,
        padding: '10px 14px',
        color: isUser ? '#fff' : 'var(--text-primary)',
        fontSize: 14,
        lineHeight: 1.6,
      }}>
        {isUser ? (
          <span>{msg.content}</span>
        ) : (
          <span dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }} />
        )}
      </div>
    </div>
  );
}

function QuickQuestions({ categories, onSelect }) {
  return (
    <div style={{ padding: '24px 0', maxWidth: 680, margin: '0 auto' }}>
      <div style={{ textAlign: 'center', marginBottom: 28 }}>
        <div style={{
          width: 52, height: 52, borderRadius: '50%',
          background: 'var(--accent-primary)', opacity: 0.9,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          margin: '0 auto 12px',
        }}>
          <BotIcon />
        </div>
        <h2 style={{ margin: '0 0 4px', fontSize: '1.2em', fontWeight: 700 }}>
          Ask your security data anything
        </h2>
        <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: 13 }}>
          Powered by Claude on AWS Bedrock · Data stays in your AWS account
        </p>
      </div>

      {Object.entries(categories).map(([cat, questions]) => {
        const style = CAT_STYLE[cat] || { bg: 'rgba(255,255,255,0.06)', color: 'var(--text-secondary)' };
        return (
          <div key={cat} style={{ marginBottom: 20 }}>
            <div style={{
              fontSize: 11, fontWeight: 700, letterSpacing: '0.08em',
              color: style.color, textTransform: 'uppercase', marginBottom: 8, paddingLeft: 2,
            }}>
              {cat}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {questions.map(q => (
                <button
                  key={q.id}
                  onClick={() => onSelect(q.question_text)}
                  style={{
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 10,
                    padding: '10px 14px',
                    textAlign: 'left',
                    cursor: 'pointer',
                    color: 'var(--text-primary)',
                    fontSize: 13,
                    lineHeight: 1.4,
                    transition: 'border-color 0.15s, background 0.15s',
                    display: 'flex', alignItems: 'flex-start', gap: 8,
                  }}
                  onMouseEnter={e => {
                    e.currentTarget.style.borderColor = style.color;
                    e.currentTarget.style.background = style.bg;
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.borderColor = 'var(--border-primary)';
                    e.currentTarget.style.background = 'var(--bg-secondary)';
                  }}
                >
                  <span style={{
                    marginTop: 1, color: style.color, flexShrink: 0,
                  }}>
                    <SparkleIcon />
                  </span>
                  <span>{q.question_text}</span>
                </button>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AiAssistantPage() {
  const [sessions, setSessions]         = useState([]);
  const [activeSession, setActiveSession] = useState(null);
  const [messages, setMessages]         = useState([]);
  const [quickQ, setQuickQ]             = useState({});
  const [input, setInput]               = useState('');
  const [streaming, setStreaming]       = useState(false);
  const [thinking, setThinking]         = useState(false);
  const [loadingMsgs, setLoadingMsgs]   = useState(false);

  const messagesEndRef = useRef(null);
  const textareaRef    = useRef(null);
  const abortRef       = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => { scrollToBottom(); }, [messages, thinking]);

  // Load sessions + quick questions on mount
  useEffect(() => {
    fetchSessions();
    fetchQuickQuestions();
  }, []);

  async function fetchSessions() {
    try {
      const r = await fetch(`${API_BASE}/gateway/api/v1/views/chat/sessions`, {
        headers: apiHeaders(),
        credentials: 'include',
      });
      if (r.ok) {
        const d = await r.json();
        setSessions(d.sessions || []);
      }
    } catch { /* silent */ }
  }

  async function fetchQuickQuestions() {
    try {
      const r = await fetch(`${API_BASE}/gateway/api/v1/views/chat/quick-questions`, {
        headers: apiHeaders(),
        credentials: 'include',
      });
      if (r.ok) {
        const d = await r.json();
        setQuickQ(d.categories || {});
      }
    } catch { /* silent */ }
  }

  async function loadSession(session) {
    setActiveSession(session);
    setMessages([]);
    setLoadingMsgs(true);
    try {
      const r = await fetch(
        `${API_BASE}/gateway/api/v1/views/chat/sessions/${session.session_id}/messages`,
        { headers: apiHeaders(), credentials: 'include' },
      );
      if (r.ok) {
        const d = await r.json();
        setMessages(d.messages || []);
      }
    } finally {
      setLoadingMsgs(false);
    }
  }

  async function createSession(firstMessage) {
    const r = await fetch(`${API_BASE}/gateway/api/v1/views/chat/sessions`, {
      method: 'POST',
      headers: apiHeaders(),
      credentials: 'include',
      body: JSON.stringify({
        title: firstMessage.slice(0, 60) + (firstMessage.length > 60 ? '…' : ''),
      }),
    });
    if (!r.ok) throw new Error('Failed to create session');
    const d = await r.json();
    const newSession = {
      session_id:    d.session_id,
      title:         d.title,
      message_count: 0,
      created_at:    new Date().toISOString(),
      updated_at:    new Date().toISOString(),
    };
    setSessions(prev => [newSession, ...prev]);
    setActiveSession(newSession);
    return newSession;
  }

  async function sendMessage(text) {
    const msgText = (text || input).trim();
    if (!msgText || streaming) return;

    setInput('');
    if (textareaRef.current) textareaRef.current.style.height = 'auto';

    // Add user message optimistically
    const userMsg = { role: 'user', content: msgText, message_id: `tmp-${Date.now()}` };
    setMessages(prev => [...prev, userMsg]);
    setThinking(true);
    setStreaming(true);

    let session = activeSession;
    if (!session) {
      try {
        session = await createSession(msgText);
      } catch {
        setThinking(false);
        setStreaming(false);
        return;
      }
    }

    // Add streaming assistant placeholder
    const streamId = `stream-${Date.now()}`;
    setMessages(prev => [...prev, { role: 'assistant', content: '', message_id: streamId, streaming: true }]);

    abortRef.current = new AbortController();

    try {
      const resp = await fetch(
        `${API_BASE}/gateway/api/v1/views/chat/sessions/${session.session_id}/messages`,
        {
          method: 'POST',
          headers: apiHeaders(),
          credentials: 'include',
          body: JSON.stringify({ message: msgText }),
          signal: abortRef.current.signal,
        },
      );

      if (!resp.ok) throw new Error('Request failed');

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.type === 'thinking') {
              setThinking(true);
            } else if (evt.type === 'token') {
              setThinking(false);
              setMessages(prev =>
                prev.map(m =>
                  m.message_id === streamId
                    ? { ...m, content: m.content + evt.content }
                    : m,
                ),
              );
            } else if (evt.type === 'done') {
              setMessages(prev =>
                prev.map(m =>
                  m.message_id === streamId
                    ? { ...m, message_id: evt.message_id, streaming: false }
                    : m,
                ),
              );
              fetchSessions();
            } else if (evt.type === 'error') {
              setMessages(prev =>
                prev.map(m =>
                  m.message_id === streamId
                    ? { ...m, content: `Error: ${evt.detail}`, streaming: false, error: true }
                    : m,
                ),
              );
            }
          } catch { /* malformed SSE line */ }
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setMessages(prev =>
          prev.map(m =>
            m.message_id === streamId
              ? { ...m, content: 'Something went wrong. Please try again.', streaming: false, error: true }
              : m,
          ),
        );
      }
    } finally {
      setThinking(false);
      setStreaming(false);
      abortRef.current = null;
    }
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  function handleTextareaChange(e) {
    setInput(e.target.value);
    e.target.style.height = 'auto';
    e.target.style.height = Math.min(e.target.scrollHeight, 160) + 'px';
  }

  function startNewChat() {
    if (abortRef.current) abortRef.current.abort();
    setActiveSession(null);
    setMessages([]);
    setInput('');
    setStreaming(false);
    setThinking(false);
  }

  const showEmptyState = !loadingMsgs && messages.length === 0;

  return (
    <>
      <style>{`
        @keyframes chatBounce {
          0%, 80%, 100% { transform: translateY(0); }
          40% { transform: translateY(-5px); }
        }
        .session-item:hover { background: var(--bg-secondary) !important; }
        .chat-input:focus { outline: none; border-color: var(--accent-primary) !important; }
        .send-btn:hover:not(:disabled) { opacity: 0.85; }
        .send-btn:disabled { opacity: 0.4; cursor: not-allowed; }
      `}</style>

      <div style={{
        display: 'flex',
        height: 'calc(100vh - 56px)',
        background: 'var(--bg-primary)',
        overflow: 'hidden',
      }}>

        {/* ── Left sidebar ──────────────────────────────────────────────────── */}
        <div style={{
          width: 240,
          borderRight: '1px solid var(--border-primary)',
          display: 'flex',
          flexDirection: 'column',
          flexShrink: 0,
          background: 'var(--bg-secondary)',
        }}>
          {/* Header */}
          <div style={{ padding: '16px 12px 12px', borderBottom: '1px solid var(--border-primary)' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              marginBottom: 10, color: 'var(--text-primary)', fontWeight: 700, fontSize: 13,
            }}>
              <span style={{ color: 'var(--accent-primary)' }}><BotIcon /></span>
              AI Assistant
            </div>
            <button
              onClick={startNewChat}
              style={{
                width: '100%', padding: '7px 10px',
                background: 'var(--accent-primary)', border: 'none',
                borderRadius: 8, cursor: 'pointer',
                color: '#fff', fontSize: 12, fontWeight: 600,
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              }}
            >
              <PlusIcon /> New Chat
            </button>
          </div>

          {/* Session list */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '8px 6px' }}>
            {sessions.length === 0 ? (
              <p style={{ color: 'var(--text-secondary)', fontSize: 12, padding: '12px 6px', margin: 0 }}>
                No conversations yet
              </p>
            ) : (
              sessions.map(s => (
                <div
                  key={s.session_id}
                  className="session-item"
                  onClick={() => loadSession(s)}
                  style={{
                    padding: '8px 10px', borderRadius: 8, cursor: 'pointer',
                    marginBottom: 2,
                    background: activeSession?.session_id === s.session_id
                      ? 'var(--bg-primary)' : 'transparent',
                    border: activeSession?.session_id === s.session_id
                      ? '1px solid var(--border-primary)' : '1px solid transparent',
                    transition: 'background 0.15s',
                  }}
                >
                  <div style={{
                    fontSize: 12, fontWeight: 500, color: 'var(--text-primary)',
                    whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                    marginBottom: 2,
                  }}>
                    {s.title}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>
                    {timeAgo(s.updated_at)} · {s.message_count} msgs
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Footer badge */}
          <div style={{
            padding: '10px 12px',
            borderTop: '1px solid var(--border-primary)',
            fontSize: 10, color: 'var(--text-secondary)',
            display: 'flex', alignItems: 'center', gap: 4,
          }}>
            <span style={{ color: 'var(--accent-primary)' }}><SparkleIcon /></span>
            Claude · AWS Bedrock · Data stays in AWS
          </div>
        </div>

        {/* ── Chat area ─────────────────────────────────────────────────────── */}
        <div style={{
          flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}>
          {/* Chat header */}
          <div style={{
            padding: '12px 20px',
            borderBottom: '1px solid var(--border-primary)',
            fontSize: 13, fontWeight: 600, color: 'var(--text-primary)',
            background: 'var(--bg-secondary)',
            flexShrink: 0,
          }}>
            {activeSession ? activeSession.title : 'New Conversation'}
          </div>

          {/* Messages */}
          <div style={{
            flex: 1, overflowY: 'auto',
            padding: '20px 24px',
            display: 'flex', flexDirection: 'column', gap: 16,
          }}>
            {loadingMsgs ? (
              <div style={{ textAlign: 'center', color: 'var(--text-secondary)', fontSize: 13, paddingTop: 40 }}>
                Loading conversation…
              </div>
            ) : showEmptyState ? (
              <QuickQuestions
                categories={quickQ}
                onSelect={q => { setInput(q); setTimeout(() => sendMessage(q), 50); }}
              />
            ) : (
              messages.map(msg => (
                <MessageBubble key={msg.message_id} msg={msg} />
              ))
            )}

            {thinking && <Thinking />}
            <div ref={messagesEndRef} />
          </div>

          {/* Input bar */}
          <div style={{
            padding: '12px 20px 16px',
            borderTop: '1px solid var(--border-primary)',
            background: 'var(--bg-secondary)',
            flexShrink: 0,
          }}>
            <div style={{
              display: 'flex', gap: 10, alignItems: 'flex-end',
              background: 'var(--bg-primary)',
              border: '1px solid var(--border-primary)',
              borderRadius: 12, padding: '8px 10px 8px 14px',
            }}>
              <textarea
                ref={textareaRef}
                className="chat-input"
                value={input}
                onChange={handleTextareaChange}
                onKeyDown={handleKeyDown}
                placeholder="Ask about findings, compliance, threats, or any cloud security question…"
                rows={1}
                disabled={streaming}
                style={{
                  flex: 1, background: 'none', border: 'none',
                  color: 'var(--text-primary)', fontSize: 14,
                  resize: 'none', lineHeight: 1.5,
                  maxHeight: 160, overflow: 'auto',
                  fontFamily: 'inherit',
                }}
              />
              <button
                className="send-btn"
                onClick={() => sendMessage()}
                disabled={!input.trim() || streaming}
                style={{
                  width: 36, height: 36, borderRadius: 8, flexShrink: 0,
                  background: 'var(--accent-primary)', border: 'none',
                  cursor: 'pointer', color: '#fff',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'opacity 0.15s',
                }}
              >
                <SendIcon />
              </button>
            </div>
            <p style={{
              margin: '6px 0 0', fontSize: 10, color: 'var(--text-secondary)', textAlign: 'center',
            }}>
              Press Enter to send · Shift+Enter for new line · Data is scoped to your tenant
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
