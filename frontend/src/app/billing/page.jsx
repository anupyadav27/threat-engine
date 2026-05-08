'use client';

import { useState, useEffect, useCallback } from 'react';
import {
    CreditCard, CheckCircle, XCircle, AlertTriangle, ExternalLink,
    TrendingUp, Users, Clock, X,
} from 'lucide-react';
import { useViewFetch } from '@/lib/use-view-fetch';
import { useAuth } from '@/lib/auth-context';
import { Suspense } from 'react';
import PaywallOverlay from '@/components/billing/PaywallOverlay';

// ── Colour helpers ────────────────────────────────────────────────────────────
const TIER_COLORS = {
    free:       { bg: 'rgba(107,114,128,0.12)', color: '#9ca3af', border: 'rgba(107,114,128,0.25)' },
    starter:    { bg: 'rgba(59,130,246,0.12)',  color: '#60a5fa', border: 'rgba(59,130,246,0.25)' },
    pro:        { bg: 'rgba(139,92,246,0.12)',  color: '#a78bfa', border: 'rgba(139,92,246,0.25)' },
    enterprise: { bg: 'rgba(245,158,11,0.12)',  color: '#fbbf24', border: 'rgba(245,158,11,0.25)' },
};

const STATUS_COLORS = {
    active:    { bg: 'rgba(16,185,129,0.12)',  color: '#34d399' },
    trialing:  { bg: 'rgba(59,130,246,0.12)',  color: '#60a5fa' },
    past_due:  { bg: 'rgba(245,158,11,0.12)',  color: '#fbbf24' },
    cancelled: { bg: 'rgba(239,68,68,0.12)',   color: '#f87171' },
    inactive:  { bg: 'rgba(107,114,128,0.12)', color: '#9ca3af' },
};

function tierStyle(tier) {
    return TIER_COLORS[(tier || '').toLowerCase()] || TIER_COLORS.free;
}

function statusStyle(status) {
    return STATUS_COLORS[(status || '').toLowerCase()] || STATUS_COLORS.inactive;
}

// ── Tier ordering for upgrade/downgrade logic ─────────────────────────────────
const TIER_RANK = { free: 0, starter: 1, pro: 2, enterprise: 3 };

function tierRank(t) {
    return TIER_RANK[(t || '').toLowerCase()] ?? 0;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Banner({ type, message, onClose }) {
    const styles = {
        success: { bg: 'rgba(16,185,129,0.12)',  border: 'rgba(16,185,129,0.3)',  color: '#34d399', Icon: CheckCircle },
        neutral: { bg: 'rgba(107,114,128,0.12)', border: 'rgba(107,114,128,0.3)', color: '#9ca3af', Icon: XCircle },
        warning: { bg: 'rgba(245,158,11,0.12)',  border: 'rgba(245,158,11,0.3)',  color: '#fbbf24', Icon: AlertTriangle },
        error:   { bg: 'rgba(239,68,68,0.12)',   border: 'rgba(239,68,68,0.3)',   color: '#f87171', Icon: XCircle },
    };
    const s = styles[type] || styles.neutral;
    const Icon = s.Icon;
    return (
        <div className="flex items-center gap-3 rounded-lg px-4 py-3 mb-4"
            style={{ backgroundColor: s.bg, border: `1px solid ${s.border}` }}>
            <Icon className="w-4 h-4 flex-shrink-0" style={{ color: s.color }} />
            <span className="text-sm flex-1" style={{ color: s.color }}>{message}</span>
            {onClose && (
                <button onClick={onClose} className="ml-auto">
                    <X className="w-4 h-4" style={{ color: s.color }} />
                </button>
            )}
        </div>
    );
}

function TierBadge({ tier }) {
    const ts = tierStyle(tier);
    return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wide"
            style={{ backgroundColor: ts.bg, color: ts.color, border: `1px solid ${ts.border}` }}>
            {tier || 'free'}
        </span>
    );
}

function StatusBadge({ status }) {
    const ss = statusStyle(status);
    return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium capitalize"
            style={{ backgroundColor: ss.bg, color: ss.color }}>
            {(status || '').replace('_', ' ') || 'unknown'}
        </span>
    );
}

function UsageMeter({ label, used, limit, upgradeHint }) {
    const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
    const isWarn = pct >= 75 && pct < 90;
    const isDanger = pct >= 90;
    const barColor = isDanger
        ? 'var(--accent-danger)'
        : isWarn
            ? 'var(--accent-warning)'
            : 'var(--accent-primary)';
    const labelColor = isDanger
        ? 'var(--accent-danger)'
        : isWarn
            ? 'var(--accent-warning)'
            : 'var(--text-secondary)';
    const showWarning = isWarn || isDanger;

    return (
        <div
            role="meter"
            aria-valuenow={pct}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={`${label}: ${used.toLocaleString()} of ${limit > 0 ? limit.toLocaleString() : 'unlimited'} (${pct}%)`}
            className="space-y-1.5">
            {/* Label row */}
            <div className="flex justify-between items-center gap-1">
                <span className="flex items-center gap-1 text-xs" style={{ color: labelColor }}>
                    {showWarning && (
                        <AlertTriangle className="w-3 h-3 flex-shrink-0" style={{ color: barColor }} />
                    )}
                    {label}
                </span>
                <span className="text-xs font-medium tabular-nums" style={{ color: isDanger ? 'var(--accent-danger)' : 'var(--text-primary)' }}>
                    {used.toLocaleString()} / {limit > 0 ? limit.toLocaleString() : 'unlimited'}
                </span>
            </div>
            {/* Progress bar */}
            <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <div className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${pct}%`, backgroundColor: barColor }} />
            </div>
            {/* Pct label */}
            <div className="text-right text-[10px]" style={{ color: 'var(--text-muted)' }}>{pct}% used</div>
            {/* Upgrade hint */}
            {(pct > 75) && upgradeHint && (
                <div className="flex items-start gap-1.5 text-[11px] px-1"
                    style={{ color: 'var(--text-muted)' }}>
                    <TrendingUp className="w-3 h-3 mt-0.5 flex-shrink-0" style={{ color: 'var(--accent-primary)' }} />
                    <span>{upgradeHint}</span>
                </div>
            )}
        </div>
    );
}

function TrialBanner({ subscription, onUpgradeClick }) {
    if (subscription?.status !== 'trialing' || !subscription.trial_end_at) return null;
    const trialEndMs = typeof subscription.trial_end_at === 'number'
        ? (subscription.trial_end_at > 1e10 ? subscription.trial_end_at : subscription.trial_end_at * 1000)
        : new Date(subscription.trial_end_at).getTime();
    const daysLeft = Math.max(0, Math.ceil((trialEndMs - Date.now()) / 86400000));
    const expired = daysLeft === 0;
    return (
        <div
            role="alert"
            aria-live="polite"
            className="flex items-center gap-3 rounded-lg px-4 py-3"
            style={{ backgroundColor: 'rgba(245,158,11,0.10)', border: '1px solid rgba(245,158,11,0.30)' }}>
            <Clock className="w-4 h-4 flex-shrink-0" style={{ color: '#fbbf24' }} />
            <span className="text-sm flex-1" style={{ color: '#fbbf24' }}>
                {expired
                    ? 'Your trial has ended — upgrade to restore full access'
                    : `Trial ends in ${daysLeft} day${daysLeft !== 1 ? 's' : ''} — upgrade to keep full access`}
            </span>
            <button
                onClick={onUpgradeClick}
                className="flex-shrink-0 px-3 py-1.5 rounded text-xs font-semibold"
                style={{ backgroundColor: '#fbbf24', color: '#020617' }}>
                {expired ? 'Upgrade Now to restore access' : 'Upgrade Now'}
            </button>
        </div>
    );
}

function RadioTierCard({ tier, price, isSelected, isCurrent, onSelect }) {
    const ts = tierStyle(tier);
    const priceLabel = price == null ? 'Custom' : price === 0 ? 'Free' : `$${price}/mo`;
    return (
        <div
            role="radio"
            aria-checked={isSelected}
            aria-label={`Select ${tier} plan${isCurrent ? ' (current)' : ''}`}
            tabIndex={0}
            onClick={() => onSelect(tier)}
            onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelect(tier);
                }
            }}
            className="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition-colors"
            style={{
                backgroundColor: isSelected ? 'var(--bg-tertiary)' : 'var(--bg-card)',
                border: isSelected ? '2px solid var(--accent-primary)' : '1px solid var(--border-primary)',
                outline: 'none',
            }}>
            {/* Radio dot */}
            <div
                className="flex-shrink-0 w-4 h-4 rounded-full flex items-center justify-center"
                style={{ border: `2px solid ${isSelected ? 'var(--accent-primary)' : 'var(--border-secondary)'}` }}>
                {isSelected && (
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--accent-primary)' }} />
                )}
            </div>
            {/* Tier badge */}
            <div className="flex-1 flex items-center gap-2">
                <span
                    className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide"
                    style={{ backgroundColor: ts.bg, color: ts.color, border: `1px solid ${ts.border}` }}>
                    {tier}
                </span>
            </div>
            {/* Price + current star */}
            <div
                className="text-sm font-bold tabular-nums flex items-center gap-1"
                style={{ color: isSelected ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                {priceLabel}
                {isCurrent && <span style={{ color: 'var(--accent-success)' }}>★</span>}
            </div>
        </div>
    );
}

function RadioPlanSelector({ plans, currentTier, selectedTier, onSelect, onUpgrade, upgradeLoading }) {
    const currentRank = tierRank(currentTier);
    const selectedRank = tierRank(selectedTier);
    const isCurrentSelected = selectedTier === currentTier;
    const isDowngrade = selectedRank < currentRank;

    return (
        <div
            id="plan-selector"
            className="rounded-lg p-4 space-y-3"
            style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
            <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Plan Options</h2>
            </div>
            <div role="radiogroup" aria-label="Subscription plan options" className="space-y-2">
                {plans.map(plan => (
                    <RadioTierCard
                        key={plan.plan_id || plan.tier}
                        tier={(plan.tier || '').toLowerCase()}
                        price={plan.price_monthly}
                        isSelected={selectedTier === (plan.tier || '').toLowerCase()}
                        isCurrent={currentTier === (plan.tier || '').toLowerCase()}
                        onSelect={onSelect}
                    />
                ))}
            </div>
            {/* CTA: show only when a non-current tier is selected */}
            {!isCurrentSelected && (
                <button
                    onClick={() => {
                        const selectedPlan = plans.find(p => (p.tier || '').toLowerCase() === selectedTier);
                        if (selectedPlan) onUpgrade(selectedPlan.plan_id, selectedTier);
                    }}
                    disabled={upgradeLoading}
                    className="w-full px-4 py-2.5 rounded text-sm font-semibold mt-1 transition-all"
                    style={{
                        backgroundColor: upgradeLoading
                            ? 'var(--bg-tertiary)'
                            : isDowngrade ? 'var(--bg-tertiary)' : 'var(--accent-primary)',
                        color: upgradeLoading
                            ? 'var(--text-muted)'
                            : isDowngrade ? 'var(--text-secondary)' : '#020617',
                        cursor: upgradeLoading ? 'not-allowed' : 'pointer',
                    }}>
                    {upgradeLoading
                        ? 'Processing…'
                        : isDowngrade
                            ? `Downgrade to ${selectedTier}`
                            : `Upgrade to ${selectedTier.charAt(0).toUpperCase() + selectedTier.slice(1)}`}
                </button>
            )}
        </div>
    );
}

function CurrentPlanCard({ subscription }) {
    if (!subscription || !Object.keys(subscription).length) {
        return (
            <div className="rounded-lg p-5" style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Subscription data unavailable.</p>
            </div>
        );
    }

    const { tier, status, current_period_end, amount, currency, billing_cycle } = subscription;
    const renewalDate = current_period_end
        ? new Date(current_period_end * 1000 || current_period_end).toLocaleDateString()
        : '—';
    const price = amount != null
        ? `${(currency || 'USD').toUpperCase()} ${(amount / 100).toFixed(2)} / ${billing_cycle || 'month'}`
        : 'Free';

    return (
        <div className="rounded-lg p-5 space-y-4"
            style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
            <div className="flex items-start justify-between gap-4">
                <div className="space-y-1">
                    <div className="flex items-center gap-2">
                        <CreditCard className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
                        <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Current Plan</h2>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                        <TierBadge tier={tier} />
                        <StatusBadge status={status} />
                    </div>
                </div>
                <div className="text-right">
                    <div className="text-lg font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>{price}</div>
                    <div className="text-xs" style={{ color: 'var(--text-muted)' }}>Renews {renewalDate}</div>
                </div>
            </div>
        </div>
    );
}

function UsageMeters({ usage, plans = [], currentTier = 'free' }) {
    if (!usage || !Object.keys(usage).length) {
        return null;
    }

    const accountsConnected = usage.accounts_connected ?? 0;
    const maxAccounts = usage.max_accounts ?? 0;
    const scansToday = usage.scans_today ?? 0;
    const scanLimit = usage.scan_freq_per_day ?? 0;
    // scans_per_month is a USAGE field (monthly consumption), not a plan limit field
    const scansMonth = usage.scans_this_month ?? 0;
    const scanMonthLimit = usage.scans_per_month ?? 0;

    // Derive next-tier plan for upgrade hints
    const TIER_ORDER = ['free', 'starter', 'pro', 'enterprise'];
    const currentRank = TIER_ORDER.indexOf((currentTier || 'free').toLowerCase());
    const nextTierKey = TIER_ORDER[currentRank + 1];
    const nextPlan = plans.find(p => (p.tier || '').toLowerCase() === nextTierKey);
    const nextTierName = nextTierKey
        ? nextTierKey.charAt(0).toUpperCase() + nextTierKey.slice(1)
        : null;

    const accountsHint = nextPlan?.max_accounts != null
        ? `Upgrading to ${nextTierName} gives ${nextPlan.max_accounts} accounts`
        : undefined;
    const scansDayHint = nextPlan?.scan_freq_per_day != null
        ? `Upgrading to ${nextTierName} gives ${nextPlan.scan_freq_per_day.toLocaleString()} scans/day`
        : undefined;
    // Monthly limit is derived from scan_freq_per_day * 30 — no separate monthly plan field
    const scansMonthHint = nextPlan?.scan_freq_per_day > 0
        ? `Upgrading to ${nextTierName} gives ~${(nextPlan.scan_freq_per_day * 30).toLocaleString()} scans/month`
        : undefined;

    return (
        <div className="rounded-lg p-5 space-y-4"
            style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
            <div className="flex items-center gap-2">
                <Users className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Usage vs Limits</h2>
            </div>
            <div className="space-y-5">
                <UsageMeter label="Cloud Accounts" used={accountsConnected} limit={maxAccounts} upgradeHint={accountsHint} />
                {scanLimit > 0 && (
                    <UsageMeter label="Scans Today" used={scansToday} limit={scanLimit} upgradeHint={scansDayHint} />
                )}
                {scanMonthLimit > 0 && (
                    <UsageMeter label="Scans This Month" used={scansMonth} limit={scanMonthLimit} upgradeHint={scansMonthHint} />
                )}
            </div>
        </div>
    );
}

function InvoiceTable({ invoices }) {
    if (!Array.isArray(invoices) || invoices.length === 0) {
        return (
            <div className="rounded-lg p-5"
                style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
                <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Invoice History</h2>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No invoices found.</p>
            </div>
        );
    }

    return (
        <div className="rounded-lg overflow-hidden"
            style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Invoice History</h2>
            </div>
            <div className="overflow-x-auto">
                <table className="w-full text-xs">
                    <thead>
                        <tr style={{ backgroundColor: 'var(--bg-secondary)' }}>
                            {['Date', 'Amount', 'Status', 'Invoice'].map(col => (
                                <th key={col} className="text-left px-4 py-2.5 font-medium"
                                    style={{ color: 'var(--text-muted)' }}>{col}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {invoices.map((inv, i) => {
                            const ss = statusStyle(inv.status);
                            const dateStr = inv.date
                                ? new Date(inv.date).toLocaleDateString()
                                : '—';
                            const amt = inv.amount != null
                                ? `${inv.currency || 'USD'} ${(inv.amount / 100).toFixed(2)}`
                                : '—';
                            return (
                                <tr key={inv.id || i} className="border-t"
                                    style={{ borderColor: 'var(--border-primary)' }}>
                                    <td className="px-4 py-2.5 tabular-nums" style={{ color: 'var(--text-secondary)' }}>{dateStr}</td>
                                    <td className="px-4 py-2.5 font-medium tabular-nums" style={{ color: 'var(--text-primary)' }}>{amt}</td>
                                    <td className="px-4 py-2.5">
                                        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium capitalize"
                                            style={{ backgroundColor: ss.bg, color: ss.color }}>
                                            {(inv.status || '').replace('_', ' ')}
                                        </span>
                                    </td>
                                    <td className="px-4 py-2.5">
                                        {inv.hosted_invoice_url ? (
                                            <a href={inv.hosted_invoice_url} target="_blank" rel="noopener noreferrer"
                                                className="inline-flex items-center gap-1 hover:underline"
                                                style={{ color: 'var(--accent-primary)' }}>
                                                View <ExternalLink className="w-3 h-3" />
                                            </a>
                                        ) : '—'}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function BillingPage() {
    const { user } = useAuth();
    const { data, loading, error } = useViewFetch('billing');

    const [banner, setBanner] = useState(null);
    const [upgradeLoading, setUpgradeLoading] = useState(false);
    const [selectedTier, setSelectedTier] = useState('free');

    // Sync selectedTier with loaded subscription tier
    useEffect(() => {
        if (data?.subscription?.tier) {
            setSelectedTier((data.subscription.tier || 'free').toLowerCase());
        }
    }, [data?.subscription?.tier]);

    // Handle Stripe redirect query params
    useEffect(() => {
        if (typeof window === 'undefined') return;
        const params = new URLSearchParams(window.location.search);
        if (params.get('success') === 'true') {
            const tier = data?.subscription?.tier || '';
            const max = data?.usage?.max_accounts ?? '';
            setBanner({
                type: 'success',
                message: `You're now on the ${tier || 'new'} plan.${max ? ` Connect up to ${max} accounts.` : ''}`,
            });
        } else if (params.get('cancelled') === 'true') {
            setBanner({ type: 'neutral', message: 'Upgrade cancelled.' });
        }
    }, [data]);

    const handleUpgrade = useCallback(async (planId, targetTier) => {
        setUpgradeLoading(true);
        try {
            const resp = await fetch('/gateway/api/v1/billing/checkout', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    plan_id: planId,
                    success_url: `${window.location.origin}/billing?success=true`,
                    cancel_url:  `${window.location.origin}/billing?cancelled=true`,
                }),
            });
            const result = await resp.json();
            if (result?.checkout_url) {
                window.location.href = result.checkout_url;
            } else {
                setBanner({ type: 'error', message: result?.detail || 'Failed to start checkout. Try again.' });
            }
        } catch {
            setBanner({ type: 'error', message: 'Network error. Please try again.' });
        } finally {
            setUpgradeLoading(false);
        }
    }, []);

    // Role gating: analyst/viewer get a restricted view
    const role = user?.role || user?.roles?.[0] || '';
    const isOrgAdmin = ['platform_admin', 'org_admin'].includes(role);
    const isTenantAdmin = role === 'tenant_admin';
    const canUpgrade = isOrgAdmin;

    if (!isOrgAdmin && !isTenantAdmin) {
        return (
            <div className="p-8 text-center space-y-3">
                <CreditCard className="w-10 h-10 mx-auto" style={{ color: 'var(--text-muted)' }} />
                <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Billing</h2>
                <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                    Contact your org admin to view billing and subscription details.
                </p>
            </div>
        );
    }

    if (loading) {
        return (
            <div className="space-y-4 p-6">
                {[...Array(3)].map((_, i) => (
                    <div key={i} className="h-32 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
                ))}
            </div>
        );
    }

    if (error) {
        return (
            <div className="p-6">
                <Banner type="error" message={error} />
            </div>
        );
    }

    const subscription = data?.subscription || {};
    const usage = data?.usage || {};
    const plans = data?.plans || [];
    const invoices = data?.invoices || [];
    const currentTier = (subscription?.tier || 'free').toLowerCase();

    const handleTrialUpgradeClick = () => {
        const TIER_ORDER = ['free', 'starter', 'pro', 'enterprise'];
        const currentIdx = TIER_ORDER.indexOf(currentTier);
        const nextTier = TIER_ORDER[currentIdx + 1];
        if (nextTier) setSelectedTier(nextTier);
        document.getElementById('plan-selector')?.scrollIntoView({ behavior: 'smooth' });
    };

    const trialBanner = (
        <TrialBanner subscription={subscription} onUpgradeClick={handleTrialUpgradeClick} />
    );

    const stripeBanner = banner && (
        <Banner type={banner.type} message={banner.message} onClose={() => setBanner(null)} />
    );

    return (
        <>
        <Suspense fallback={null}><PaywallOverlay /></Suspense>
        <div className="p-6 space-y-5 max-w-6xl">
            {/* Page heading */}
            <div className="flex items-center gap-3">
                <CreditCard className="w-5 h-5" style={{ color: 'var(--accent-primary)' }} />
                <h1 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>Billing & Subscription</h1>
            </div>

            {/* Full-width banners: trial sticky banner + Stripe redirect success/error */}
            {trialBanner}
            {stripeBanner}

            {/* Two-column grid */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-6 items-start">
                {/* Left column: plan identity + radio selector */}
                <div className="md:col-span-2 space-y-4">
                    <CurrentPlanCard subscription={subscription} />
                    {canUpgrade && plans.length > 0 && (
                        <RadioPlanSelector
                            plans={plans}
                            currentTier={currentTier}
                            selectedTier={selectedTier}
                            onSelect={setSelectedTier}
                            onUpgrade={handleUpgrade}
                            upgradeLoading={upgradeLoading}
                        />
                    )}
                </div>

                {/* Right column: usage meters + invoice history + downgrade link */}
                <div className="md:col-span-3 space-y-4">
                    <UsageMeters usage={usage} plans={plans} currentTier={currentTier} />
                    <InvoiceTable invoices={invoices} />
                    {canUpgrade && currentTier !== 'free' && (
                        <div className="text-center pt-2">
                            <button
                                onClick={() => setBanner({ type: 'neutral', message: 'To downgrade or cancel, contact support@cspm.local or use the Stripe portal.' })}
                                className="text-xs hover:underline"
                                style={{ color: 'var(--text-muted)' }}>
                                Downgrade or cancel subscription
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </div>
        </>
    );
}
