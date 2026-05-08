'use client';

/**
 * Chapter4Response — "The Response" chapter of the Scenario Detail Panel.
 *
 * Renders:
 *  1. "Break the Chain" section with grouped remediation_actions by urgency
 *  2. Persona Playbook tabs: Dev Team | Cloud Ops | IAM Admin | CISO Brief
 *
 * @param {Object}   props
 * @param {Object}   props.data                  - Full scenario detail object from BFF
 * @param {Function} props.onCreateTicket         - Open CreateTicketModal with action context
 */

import { useState } from 'react';

const URGENCY_CONFIG = {
    immediate:   { label: 'Immediate (today)',          color: '#DC2626' },
    short_term:  { label: 'Short-term (this week)',     color: '#EA580C' },
    medium_term: { label: 'Medium-term (this sprint)',  color: '#D97706' },
};

const PERSONA_TABS = [
    { id: 'dev',    label: 'Dev Team' },
    { id: 'ops',    label: 'Cloud Ops' },
    { id: 'iam',    label: 'IAM Admin' },
    { id: 'ciso',   label: 'CISO Brief' },
];

// ── Action item ───────────────────────────────────────────────────────────────

function ActionItem({ action, onCreateTicket }) {
    const [showAiTooltip, setShowAiTooltip] = useState(false);

    return (
        <div
            style={{
                backgroundColor: 'var(--bg-tertiary)',
                border: '1px solid var(--border-primary)',
                borderRadius: 8,
                padding: '12px 14px',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
            }}
        >
            {/* Step number + description */}
            <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                <span
                    style={{
                        flexShrink: 0,
                        width: 22,
                        height: 22,
                        borderRadius: '50%',
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: 10,
                        fontWeight: 700,
                        color: 'var(--text-muted)',
                        marginTop: 1,
                    }}
                >
                    {action.step}
                </span>
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.5 }}>
                    {action.description}
                </span>
            </div>

            {/* Owner + effort */}
            <div
                style={{
                    paddingLeft: 30,
                    fontSize: 11,
                    color: 'var(--text-muted)',
                    display: 'flex',
                    gap: 10,
                    flexWrap: 'wrap',
                }}
            >
                {action.owner && (
                    <span>Owner: <strong style={{ color: 'var(--text-secondary)' }}>{action.owner}</strong></span>
                )}
                {action.effort && (
                    <span>
                        Effort: <strong style={{ color: 'var(--text-secondary)' }}>
                            {action.effort}{action.effort_time && action.effort_time !== '—' ? ` (${action.effort_time})` : ''}
                        </strong>
                    </span>
                )}
            </div>

            {/* Impact arrow */}
            {action.impact && (
                <div style={{ paddingLeft: 30, fontSize: 11, color: '#0D9488' }}>
                    &#8594; {action.impact}
                </div>
            )}

            {/* Action links */}
            <div style={{ paddingLeft: 30, display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 2 }}>
                {/* AI Fix */}
                <div style={{ position: 'relative' }}>
                    <button
                        onMouseEnter={() => { if (!action.ai_fix_available) setShowAiTooltip(true); }}
                        onMouseLeave={() => setShowAiTooltip(false)}
                        onClick={() => {
                            if (action.ai_fix_available && action.finding_id) {
                                window.location.href = `/api/v1/fix/suggest?finding_id=${action.finding_id}&engine=secops`;
                            }
                        }}
                        style={{
                            fontSize: 11,
                            fontWeight: 600,
                            color: action.ai_fix_available ? '#EA580C' : '#475569',
                            background: 'none',
                            border: 'none',
                            cursor: action.ai_fix_available ? 'pointer' : 'default',
                            padding: 0,
                            textDecoration: action.ai_fix_available ? 'underline' : 'none',
                        }}
                    >
                        View AI Fix Suggestion &#8594;
                    </button>
                    {showAiTooltip && (
                        <div
                            style={{
                                position: 'absolute',
                                bottom: '120%',
                                left: 0,
                                backgroundColor: '#1E293B',
                                border: '1px solid #334155',
                                borderRadius: 6,
                                padding: '5px 8px',
                                fontSize: 10,
                                color: '#94A3B8',
                                whiteSpace: 'nowrap',
                                zIndex: 20,
                                pointerEvents: 'none',
                                boxShadow: '0 2px 8px rgba(0,0,0,0.4)',
                            }}
                        >
                            AI fix not available for this finding type.
                        </div>
                    )}
                </div>

                {/* Create ticket for this action */}
                <button
                    onClick={() => onCreateTicket && onCreateTicket(action)}
                    style={{
                        fontSize: 11,
                        fontWeight: 600,
                        color: '#3B82F6',
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        padding: 0,
                        textDecoration: 'underline',
                    }}
                >
                    Create Ticket &#8594;
                </button>
            </div>
        </div>
    );
}

// ── Urgency group ─────────────────────────────────────────────────────────────

function UrgencyGroup({ urgency, actions, onCreateTicket }) {
    const cfg = URGENCY_CONFIG[urgency] || URGENCY_CONFIG.medium_term;
    if (!actions.length) return null;

    return (
        <div style={{ marginBottom: 16 }}>
            <div
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    marginBottom: 10,
                }}
            >
                <span
                    style={{
                        width: 8,
                        height: 8,
                        borderRadius: '50%',
                        backgroundColor: cfg.color,
                        flexShrink: 0,
                        display: 'inline-block',
                    }}
                />
                <span
                    style={{
                        fontSize: 12,
                        fontWeight: 700,
                        color: cfg.color,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                    }}
                >
                    {cfg.label}
                </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {actions.map((action) => (
                    <ActionItem
                        key={action.step}
                        action={action}
                        onCreateTicket={onCreateTicket}
                    />
                ))}
            </div>
        </div>
    );
}

// ── Persona playbook tab content ──────────────────────────────────────────────

function PersonaContent({ persona, data }) {
    const {
        remediation_actions = [],
        contributing_findings = [],
        chain_of_consequence = '',
        compliance_violations = [],
        resource_type = '',
        resource_name = '',
    } = data;

    if (persona === 'ciso') {
        // 3-sentence executive summary
        const chainText = chain_of_consequence && chain_of_consequence.trim()
            ? chain_of_consequence
            : `This scenario affects ${resource_type || 'a resource'} (${resource_name}) and represents a multi-signal attack path.`;
        const topAction = remediation_actions[0]?.description || 'Review and remediate all contributing findings.';
        const frameworks = compliance_violations.map((v) => v.framework).filter(Boolean).join(', ') || 'applicable frameworks';

        return (
            <div
                style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 8,
                    padding: '14px 16px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 10,
                }}
            >
                <div
                    style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.07em',
                        marginBottom: 4,
                    }}
                >
                    Executive Summary
                </div>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, margin: 0 }}>
                    {chainText}
                </p>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, margin: 0 }}>
                    Immediate action required: {topAction}
                </p>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, margin: 0 }}>
                    Compliance frameworks at risk: <strong>{frameworks}</strong>
                </p>
            </div>
        );
    }

    // Filter actions by persona
    let filtered = remediation_actions;
    if (persona === 'dev') {
        filtered = remediation_actions.filter(
            (a) => (a.owner || '').toLowerCase().includes('dev')
                || contributing_findings.some(
                    (f) => f.signal_type === 'vulnerability' && f.step === a.step
                )
        );
        // If no dev-specific actions, show all vulnerability-related ones
        if (!filtered.length) {
            filtered = remediation_actions.filter(
                (a) => (a.owner || '').toLowerCase().includes('dev')
            );
        }
    } else if (persona === 'ops') {
        filtered = remediation_actions.filter((a) => {
            const sigTypes = contributing_findings.map((f) => f.signal_type);
            return (
                (a.owner || '').toLowerCase().includes('ops')
                || (a.owner || '').toLowerCase().includes('cloud')
                || sigTypes.includes('misconfig')
                || sigTypes.includes('network')
            );
        });
    } else if (persona === 'iam') {
        filtered = remediation_actions.filter((a) => {
            const sigTypes = contributing_findings.map((f) => f.signal_type);
            return (
                (a.owner || '').toLowerCase().includes('iam')
                || sigTypes.includes('identity')
            );
        });
    }

    if (!filtered.length) {
        return (
            <p style={{ fontSize: 13, color: 'var(--text-muted)', fontStyle: 'italic', padding: '10px 0' }}>
                No specific actions for this persona. See all actions in the main list.
            </p>
        );
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {filtered.map((action) => (
                <ActionItem key={action.step} action={action} />
            ))}
        </div>
    );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Chapter4Response({ data = {}, onCreateTicket }) {
    const [activePersona, setActivePersona] = useState('dev');

    const { remediation_actions = [] } = data;

    // Group by urgency
    const grouped = {
        immediate:   remediation_actions.filter((a) => a.urgency === 'immediate'),
        short_term:  remediation_actions.filter((a) => a.urgency === 'short_term'),
        medium_term: remediation_actions.filter((a) => a.urgency === 'medium_term'),
    };

    const hasActions = remediation_actions.length > 0;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, paddingBottom: 12 }}>
            {/* Break the Chain heading */}
            <div>
                <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 4 }}>
                    Break the Chain
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
                    Resolving any single action below disrupts the attack path.
                    Immediate actions eliminate the entry point entirely.
                </p>
            </div>

            {/* Grouped actions */}
            {hasActions ? (
                <div>
                    <UrgencyGroup urgency="immediate"   actions={grouped.immediate}   onCreateTicket={onCreateTicket} />
                    <UrgencyGroup urgency="short_term"  actions={grouped.short_term}  onCreateTicket={onCreateTicket} />
                    <UrgencyGroup urgency="medium_term" actions={grouped.medium_term} onCreateTicket={onCreateTicket} />
                </div>
            ) : (
                <p style={{ fontSize: 13, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    No remediation actions available. Run a full scan to generate recommendations.
                </p>
            )}

            {/* Persona Playbook tabs */}
            <div>
                <div
                    style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.07em',
                        marginBottom: 10,
                    }}
                >
                    Persona Playbook
                </div>

                {/* Tab bar */}
                <div
                    style={{
                        display: 'flex',
                        borderBottom: '1px solid var(--border-primary)',
                        marginBottom: 14,
                        gap: 0,
                    }}
                >
                    {PERSONA_TABS.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActivePersona(tab.id)}
                            style={{
                                fontSize: 12,
                                fontWeight: activePersona === tab.id ? 700 : 500,
                                padding: '8px 14px',
                                border: 'none',
                                borderBottom: activePersona === tab.id ? '2px solid #EA580C' : '2px solid transparent',
                                backgroundColor: 'transparent',
                                color: activePersona === tab.id ? '#EA580C' : 'var(--text-muted)',
                                cursor: 'pointer',
                                transition: 'color 150ms ease, border-color 150ms ease',
                                marginBottom: -1,
                            }}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>

                {/* Tab content */}
                <PersonaContent persona={activePersona} data={data} />
            </div>
        </div>
    );
}
