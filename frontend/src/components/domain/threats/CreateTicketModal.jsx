'use client';

/**
 * CreateTicketModal — slides up from bottom of the drawer as a sheet.
 *
 * Provides Jira / GitHub Issues / ServiceNow / PagerDuty integration selector
 * with pre-populated title, priority, assignee, labels, and full Markdown
 * description based on the 4-chapter scenario narrative.
 *
 * No external modal library — uses CSS transform: translateY animation.
 *
 * @param {Object}   props
 * @param {boolean}  props.isOpen          - Controls slide-in
 * @param {Function} props.onClose         - Close handler
 * @param {Object}   props.scenarioData    - Full scenario detail object from BFF
 */

import { useState, useEffect, useCallback } from 'react';
import { useToast } from '@/lib/toast-context';


const INTEGRATIONS = [
    { id: 'jira',        label: 'Jira' },
    { id: 'github',      label: 'GitHub Issues' },
    { id: 'servicenow',  label: 'ServiceNow' },
    { id: 'pagerduty',   label: 'PagerDuty' },
];

const PRIORITY_MAP = {
    critical: 'P1',
    high:     'P2',
    medium:   'P3',
    low:      'P4',
};

function buildDescription(data) {
    const {
        title = '',
        severity = '',
        risk_score = 0,
        resource_name = '',
        csp = '',
        region = '',
        first_seen_at = '',
        chain_of_consequence = '',
        remediation_actions = [],
        compliance_violations = [],
        scenario_id = '',
    } = data;

    const chainText = chain_of_consequence && chain_of_consequence.trim()
        ? chain_of_consequence
        : `This scenario involves ${resource_name} and requires immediate attention.`;

    const topActions = remediation_actions.slice(0, 3).map((a, i) => `${i + 1}. ${a.description}`).join('\n');
    const frameworks = compliance_violations.map((v) => `${v.framework} ${v.control_id}`.trim()).join(', ');

    const location = typeof window !== 'undefined' ? window.location.href : '';

    return `## Threat Scenario: ${title}

**Severity:** ${severity.toUpperCase()}  **Score:** ${risk_score}/100
**Resource:** ${resource_name} (${csp}/${region})
**Detected:** ${first_seen_at || '—'}

### What Happened
${chainText}

### Top Actions
${topActions || '(No remediation steps available)'}

### Compliance Violations
${frameworks || '(None identified)'}

**Deep Link:** ${location}${location.includes('?') ? '&' : '?'}scenario=${scenario_id}
`;
}

export default function CreateTicketModal({ isOpen, onClose, scenarioData = {} }) {
    const toast = useToast();

    const {
        title = '',
        severity = 'medium',
        remediation_actions = [],
        scenario_id = '',
    } = scenarioData;

    const priority = PRIORITY_MAP[severity] || 'P3';
    const firstOwner = remediation_actions[0]?.owner || 'Cloud Ops';
    const prefixedTitle = `[${severity.toUpperCase()}] ${title}`;
    const description = buildDescription(scenarioData);

    const [integration, setIntegration] = useState('jira');
    const [ticketTitle, setTicketTitle]  = useState(prefixedTitle);
    const [ticketDesc, setTicketDesc]   = useState(description);
    const [submitting, setSubmitting]    = useState(false);
    const [includeGraph, setIncludeGraph] = useState(false);

    // Sync title/desc when scenarioData changes
    useEffect(() => {
        setTicketTitle(`[${severity.toUpperCase()}] ${title}`);
        setTicketDesc(buildDescription(scenarioData));
    }, [scenario_id, title, severity]);

    const handleClose = useCallback(() => {
        if (!submitting) onClose();
    }, [submitting, onClose]);

    // Escape key closes modal
    useEffect(() => {
        if (!isOpen) return;
        const handler = (e) => { if (e.key === 'Escape') handleClose(); };
        document.addEventListener('keydown', handler);
        return () => document.removeEventListener('keydown', handler);
    }, [isOpen, handleClose]);

    async function handleCreate() {
        setSubmitting(true);
        try {
            const resp = await fetch('/api/v1/gateway/integrations/ticket', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    integration,
                    title: ticketTitle,
                    priority,
                    assignee: firstOwner,
                    labels: ['security', 'threat-engine', scenarioData.csp || ''].filter(Boolean),
                    description: ticketDesc,
                    scenario_id,
                    include_graph: includeGraph,
                }),
            });

            if (resp.ok) {
                const result = await resp.json().catch(() => ({}));
                const ticketUrl = result.url || result.ticket_url || '';
                toast.success(
                    ticketUrl ? `Ticket created: ${ticketUrl}` : 'Ticket created successfully.'
                );
                onClose();
            } else if (resp.status === 404 || resp.status === 501) {
                toast.warning('Ticket integration not configured. Contact your admin.');
                onClose();
            } else {
                const err = await resp.json().catch(() => ({}));
                toast.error(`Failed to create ticket: ${err.detail || err.message || resp.statusText}`);
            }
        } catch (e) {
            toast.error(`Failed to create ticket: ${e.message || 'Network error'}`);
        } finally {
            setSubmitting(false);
        }
    }

    return (
        <>
            {/* Backdrop */}
            {isOpen && (
                <div
                    onClick={handleClose}
                    style={{
                        position: 'absolute',
                        inset: 0,
                        backgroundColor: 'rgba(0,0,0,0.5)',
                        zIndex: 10,
                    }}
                    aria-hidden="true"
                />
            )}

            {/* Sheet */}
            <div
                role="dialog"
                aria-modal="true"
                aria-label="Create Ticket"
                style={{
                    position: 'absolute',
                    bottom: 0,
                    left: 0,
                    right: 0,
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderTopLeftRadius: 12,
                    borderTopRightRadius: 12,
                    padding: '20px 20px 24px',
                    zIndex: 11,
                    boxShadow: '0 -8px 32px rgba(0,0,0,0.4)',
                    transform: isOpen ? 'translateY(0)' : 'translateY(100%)',
                    transition: 'transform 300ms ease',
                    maxHeight: '85%',
                    overflowY: 'auto',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 14,
                }}
            >
                {/* Header */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                        Create Ticket
                    </h3>
                    <button
                        onClick={handleClose}
                        disabled={submitting}
                        aria-label="Close modal"
                        style={{
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: 18,
                            color: 'var(--text-muted)',
                            padding: '2px 6px',
                            borderRadius: 4,
                        }}
                    >
                        &times;
                    </button>
                </div>

                {/* Integration selector */}
                <div>
                    <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 6 }}>
                        Integration
                    </label>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {INTEGRATIONS.map((ig) => (
                            <button
                                key={ig.id}
                                onClick={() => setIntegration(ig.id)}
                                style={{
                                    fontSize: 12,
                                    fontWeight: integration === ig.id ? 700 : 500,
                                    padding: '5px 12px',
                                    borderRadius: 6,
                                    border: `1px solid ${integration === ig.id ? '#EA580C' : 'var(--border-primary)'}`,
                                    backgroundColor: integration === ig.id ? '#EA580C18' : 'var(--bg-tertiary)',
                                    color: integration === ig.id ? '#EA580C' : 'var(--text-secondary)',
                                    cursor: 'pointer',
                                }}
                            >
                                {ig.label}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Title */}
                <div>
                    <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 6 }}>
                        Title
                    </label>
                    <input
                        value={ticketTitle}
                        onChange={(e) => setTicketTitle(e.target.value)}
                        style={{
                            width: '100%',
                            fontSize: 13,
                            padding: '7px 10px',
                            borderRadius: 6,
                            border: '1px solid var(--border-primary)',
                            backgroundColor: 'var(--bg-tertiary)',
                            color: 'var(--text-primary)',
                            boxSizing: 'border-box',
                        }}
                    />
                </div>

                {/* Priority + Assignee row */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                    <div>
                        <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 6 }}>
                            Priority
                        </label>
                        <div
                            style={{
                                fontSize: 13,
                                padding: '7px 10px',
                                borderRadius: 6,
                                border: '1px solid var(--border-primary)',
                                backgroundColor: 'var(--bg-tertiary)',
                                color: priority === 'P1' ? '#DC2626' : priority === 'P2' ? '#EA580C' : 'var(--text-secondary)',
                                fontWeight: 700,
                            }}
                        >
                            {priority} — auto-mapped from {severity.toUpperCase()}
                        </div>
                    </div>
                    <div>
                        <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 6 }}>
                            Assignee
                        </label>
                        <div
                            style={{
                                fontSize: 13,
                                padding: '7px 10px',
                                borderRadius: 6,
                                border: '1px solid var(--border-primary)',
                                backgroundColor: 'var(--bg-tertiary)',
                                color: 'var(--text-secondary)',
                            }}
                        >
                            {firstOwner}
                        </div>
                    </div>
                </div>

                {/* Labels */}
                <div>
                    <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 6 }}>
                        Labels
                    </label>
                    <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                        {['security', 'threat-engine', scenarioData.csp || ''].filter(Boolean).map((lbl) => (
                            <span
                                key={lbl}
                                style={{
                                    fontSize: 10,
                                    fontWeight: 600,
                                    padding: '2px 8px',
                                    borderRadius: 9999,
                                    backgroundColor: 'var(--bg-tertiary)',
                                    border: '1px solid var(--border-primary)',
                                    color: 'var(--text-muted)',
                                }}
                            >
                                {lbl}
                            </span>
                        ))}
                    </div>
                </div>

                {/* Description */}
                <div>
                    <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 6 }}>
                        Description
                    </label>
                    <textarea
                        value={ticketDesc}
                        onChange={(e) => setTicketDesc(e.target.value)}
                        rows={8}
                        style={{
                            width: '100%',
                            fontSize: 11,
                            padding: '8px 10px',
                            borderRadius: 6,
                            border: '1px solid var(--border-primary)',
                            backgroundColor: '#0F172A',
                            color: '#94A3B8',
                            fontFamily: 'monospace',
                            lineHeight: 1.6,
                            resize: 'vertical',
                            boxSizing: 'border-box',
                        }}
                    />
                </div>

                {/* Include graph screenshot */}
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                    <input
                        type="checkbox"
                        checked={includeGraph}
                        onChange={(e) => setIncludeGraph(e.target.checked)}
                        style={{ width: 14, height: 14 }}
                    />
                    Include Graph Screenshot
                </label>

                {/* Footer: Cancel / Create */}
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginTop: 4 }}>
                    <button
                        onClick={handleClose}
                        disabled={submitting}
                        style={{
                            fontSize: 13,
                            fontWeight: 600,
                            padding: '8px 16px',
                            borderRadius: 6,
                            border: '1px solid var(--border-primary)',
                            backgroundColor: 'var(--bg-tertiary)',
                            color: 'var(--text-secondary)',
                            cursor: 'pointer',
                        }}
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleCreate}
                        disabled={submitting}
                        style={{
                            fontSize: 13,
                            fontWeight: 700,
                            padding: '8px 20px',
                            borderRadius: 6,
                            border: 'none',
                            backgroundColor: submitting ? '#374151' : '#EA580C',
                            color: '#fff',
                            cursor: submitting ? 'not-allowed' : 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                            opacity: submitting ? 0.7 : 1,
                            transition: 'opacity 150ms ease',
                        }}
                    >
                        {submitting ? (
                            <>
                                <span
                                    style={{
                                        width: 12,
                                        height: 12,
                                        border: '2px solid rgba(255,255,255,0.3)',
                                        borderTopColor: '#fff',
                                        borderRadius: '50%',
                                        display: 'inline-block',
                                        animation: 'spin 0.7s linear infinite',
                                    }}
                                />
                                Creating…
                            </>
                        ) : (
                            <>Create Ticket &#8594;</>
                        )}
                    </button>
                </div>
            </div>

            <style>{`
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            `}</style>
        </>
    );
}
