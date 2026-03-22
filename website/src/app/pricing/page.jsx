'use client';

import { useState, Fragment } from 'react';
import Link from 'next/link';
import {
  Check,
  X,
  ArrowRight,
  Shield,
  Zap,
  Building2,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  Star,
  Users,
  Globe,
  BarChart3,
  Lock,
  Clock,
  Headphones,
  Mail,
} from 'lucide-react';

/* ── Plan data ───────────────────────────────────────────────── */
const PLANS = [
  {
    id: 'starter',
    name: 'Starter',
    tagline: 'For teams getting started with cloud security',
    monthlyPrice: 599,
    annualPrice: 499,
    highlight: false,
    icon: Shield,
    iconColor: '#2563eb',
    features: [
      { text: 'Up to 5 cloud accounts',          included: true },
      { text: '1 cloud provider',                 included: true },
      { text: 'Core CSPM scanning',               included: true },
      { text: 'CIS + NIST frameworks',            included: true },
      { text: 'Email alerts',                     included: true },
      { text: '90-day data retention',            included: true },
      { text: '2 user seats',                     included: true },
      { text: 'Community support',                included: true },
      { text: 'IAM Security module',              included: false },
      { text: 'Data Security module',             included: false },
      { text: 'Custom compliance frameworks',     included: false },
      { text: 'Slack / PagerDuty / Jira',         included: false },
      { text: 'SSO / SAML',                       included: false },
      { text: 'Dedicated success manager',        included: false },
    ],
    cta: 'Start Free Trial',
    ctaHref: '/contact',
    note: '14-day free trial · No credit card required',
  },
  {
    id: 'professional',
    name: 'Professional',
    tagline: 'For security teams protecting growing cloud estates',
    monthlyPrice: 1799,
    annualPrice: 1499,
    highlight: true,
    icon: Zap,
    iconColor: '#7c3aed',
    features: [
      { text: 'Up to 25 cloud accounts',          included: true },
      { text: 'All 6 cloud providers',            included: true },
      { text: 'Full CSPM scanning',               included: true },
      { text: 'All 13 compliance frameworks',     included: true },
      { text: 'Slack / PagerDuty / Jira',         included: true },
      { text: 'Custom compliance frameworks',     included: true },
      { text: '1-year data retention',            included: true },
      { text: 'Unlimited users',                  included: true },
      { text: 'IAM Security module',              included: true },
      { text: 'Data Security module',             included: true },
      { text: 'Priority support + SLA',           included: true },
      { text: 'API access',                       included: true },
      { text: 'SSO / SAML',                       included: false },
      { text: 'Dedicated success manager',        included: false },
    ],
    cta: 'Start Free Trial',
    ctaHref: '/contact',
    note: '14-day free trial · No credit card required',
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    tagline: 'For large organizations with complex multi-cloud environments',
    monthlyPrice: null,
    annualPrice: null,
    highlight: false,
    icon: Building2,
    iconColor: '#059669',
    features: [
      { text: 'Unlimited cloud accounts',         included: true },
      { text: 'All providers + on-prem',          included: true },
      { text: 'Full platform access',             included: true },
      { text: 'All 13 + custom frameworks',       included: true },
      { text: 'All integrations',                 included: true },
      { text: 'Custom framework builder',         included: true },
      { text: 'Custom data retention',            included: true },
      { text: 'Unlimited users + RBAC',           included: true },
      { text: 'IAM + Data Security modules',      included: true },
      { text: 'SSO / SAML integration',           included: true },
      { text: 'Dedicated success manager',        included: true },
      { text: 'White-glove onboarding',           included: true },
      { text: 'SLA guarantees (99.9% uptime)',    included: true },
      { text: 'Custom contract & billing',        included: true },
    ],
    cta: 'Talk to Sales',
    ctaHref: '/contact',
    note: 'Custom pricing · Volume discounts available',
  },
];

/* ── Comparison table rows ───────────────────────────────────── */
const COMPARE_ROWS = [
  { category: 'Accounts & Providers', features: [
    { label: 'Cloud accounts',        starter: '5',             pro: '25',              ent: 'Unlimited' },
    { label: 'Cloud providers',       starter: '1',             pro: 'All 6',           ent: 'All 6 + on-prem' },
    { label: 'Scan frequency',        starter: 'Every 6 hrs',  pro: 'Every hour',      ent: 'Real-time / custom' },
  ]},
  { category: 'Security Modules', features: [
    { label: 'Core CSPM',             starter: true,  pro: true,  ent: true },
    { label: 'Threat Detection',      starter: true,  pro: true,  ent: true },
    { label: 'IAM Security',          starter: false, pro: true,  ent: true },
    { label: 'Data Security',         starter: false, pro: true,  ent: true },
    { label: 'Code Security',         starter: false, pro: true,  ent: true },
    { label: 'Asset Inventory',       starter: true,  pro: true,  ent: true },
  ]},
  { category: 'Compliance', features: [
    { label: 'Built-in frameworks',   starter: '2 (CIS, NIST)', pro: 'All 13',        ent: 'All 13' },
    { label: 'Custom frameworks',     starter: false,            pro: true,            ent: true },
    { label: 'Audit evidence export', starter: false,            pro: true,            ent: true },
    { label: 'Automated reports',     starter: 'Monthly',        pro: 'Weekly',        ent: 'Custom cadence' },
  ]},
  { category: 'Integrations', features: [
    { label: 'Email alerts',          starter: true,  pro: true,  ent: true },
    { label: 'Slack',                 starter: false, pro: true,  ent: true },
    { label: 'PagerDuty',             starter: false, pro: true,  ent: true },
    { label: 'Jira',                  starter: false, pro: true,  ent: true },
    { label: 'API access',            starter: false, pro: true,  ent: true },
    { label: 'SSO / SAML',           starter: false, pro: false, ent: true },
    { label: 'Webhook',               starter: false, pro: true,  ent: true },
  ]},
  { category: 'Data & Storage', features: [
    { label: 'Data retention',        starter: '90 days', pro: '1 year', ent: 'Custom' },
    { label: 'User seats',            starter: '2',       pro: 'Unlimited', ent: 'Unlimited' },
    { label: 'RBAC / fine-grained access', starter: false, pro: false, ent: true },
  ]},
  { category: 'Support', features: [
    { label: 'Support channel',       starter: 'Community', pro: 'Priority email', ent: 'Dedicated CSM' },
    { label: 'Response SLA',          starter: 'Best effort', pro: '< 4 hrs',     ent: '< 1 hr' },
    { label: 'Onboarding',            starter: 'Self-serve', pro: 'Guided setup',  ent: 'White-glove' },
    { label: 'Uptime SLA',            starter: '—',          pro: '99.5%',         ent: '99.9%' },
  ]},
];

/* ── FAQ data ────────────────────────────────────────────────── */
const FAQS = [
  {
    q: 'How do you count cloud accounts?',
    a: 'A cloud account is any unique billable entity in a cloud provider — an AWS account, an Azure subscription, a GCP project, an OCI tenancy compartment, etc. If you have 3 AWS accounts and 2 Azure subscriptions, that counts as 5 accounts toward your plan limit.',
  },
  {
    q: 'Can I change plans at any time?',
    a: "Yes. You can upgrade your plan at any time and the change takes effect immediately — you'll be billed the prorated difference. Downgrades take effect at the end of your current billing cycle. There's no lock-in on monthly plans.",
  },
  {
    q: 'Is there a free trial?',
    a: "Yes — Starter and Professional plans include a 14-day free trial with full feature access, no credit card required. Enterprise customers can request a proof-of-concept evaluation with Threat Engine scanning their real cloud environment.",
  },
  {
    q: 'Do you charge per resource or per finding?',
    a: 'No. Threat Engine charges only for the number of cloud accounts you connect — not for the number of resources discovered, findings generated, or rules evaluated. There are no overage fees or per-resource charges.',
  },
  {
    q: 'How does annual billing work?',
    a: "Annual plans are billed upfront for 12 months at a ~17% discount compared to month-to-month pricing. You can add accounts mid-year and we'll prorate the cost. Annual contracts can be paid by invoice with net-30 terms on request.",
  },
  {
    q: 'What data leaves my cloud environment?',
    a: 'Threat Engine uses read-only cloud provider credentials (AWS read-only IAM role, Azure Reader, GCP Viewer) to enumerate resource metadata and configuration. No actual data content (files, database rows, object contents) leaves your environment unless you explicitly enable the Data Security sampling module, which samples object metadata only.',
  },
];

/* ── Sub-components ──────────────────────────────────────────── */

function CellValue({ value }) {
  if (value === true)  return <Check size={17} style={{ color: '#059669' }} />;
  if (value === false) return <X     size={15} style={{ color: '#cbd5e1' }} />;
  return <span className="text-sm" style={{ color: '#475569' }}>{value}</span>;
}

function FaqItem({ q, a }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className="card-hover rounded-2xl overflow-hidden"
      style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 1px 6px rgba(15,23,42,0.04)' }}
    >
      <button
        className="w-full flex items-center justify-between p-6 text-left"
        onClick={() => setOpen(!open)}
      >
        <span className="font-semibold pr-4" style={{ color: '#0f172a' }}>{q}</span>
        {open
          ? <ChevronUp size={18} style={{ color: '#94a3b8', flexShrink: 0 }} />
          : <ChevronDown size={18} style={{ color: '#94a3b8', flexShrink: 0 }} />
        }
      </button>
      {open && (
        <div className="px-6 pb-6 -mt-2">
          <p className="text-sm leading-relaxed" style={{ color: '#475569' }}>{a}</p>
        </div>
      )}
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────── */
export default function PricingPage() {
  const [annual, setAnnual] = useState(true);

  return (
    <>
      {/* ─── HERO ─────────────────────────────────────────────── */}
      <section
        className="hero-bg grid-bg relative overflow-hidden"
        style={{ paddingTop: '140px', paddingBottom: '64px' }}
      >
        <div className="container relative text-center">
          <div className="badge badge-blue mb-6">Transparent Pricing</div>
          <h1 className="text-5xl font-black tracking-tight leading-[1.1] mb-5" style={{ color: '#0f172a' }}>
            Simple, <span className="gradient-text">Transparent</span> Pricing
          </h1>
          <p className="text-xl max-w-2xl mx-auto mb-10" style={{ color: '#475569' }}>
            No hidden fees. No per-resource charges. No surprise overages.
            Pay only for the cloud accounts you protect.
          </p>

          {/* Billing toggle */}
          <div className="inline-flex items-center gap-3 p-1 rounded-xl" style={{ background: '#f1f5f9', border: '1px solid #e2e8f0' }}>
            <button
              onClick={() => setAnnual(false)}
              className="px-5 py-2 rounded-lg text-sm font-semibold transition-all"
              style={{
                background: !annual ? '#ffffff' : 'transparent',
                color: !annual ? '#0f172a' : '#94a3b8',
                boxShadow: !annual ? '0 1px 4px rgba(15,23,42,0.08)' : 'none',
              }}
            >
              Monthly
            </button>
            <button
              onClick={() => setAnnual(true)}
              className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-semibold transition-all"
              style={{
                background: annual ? '#ffffff' : 'transparent',
                color: annual ? '#0f172a' : '#94a3b8',
                boxShadow: annual ? '0 1px 4px rgba(15,23,42,0.08)' : 'none',
              }}
            >
              Annual
              <span
                className="text-xs font-bold px-2 py-0.5 rounded-full"
                style={{ background: '#dcfce7', color: '#059669', border: '1px solid #a7f3d0' }}
              >
                Save 17%
              </span>
            </button>
          </div>
        </div>
      </section>

      {/* ─── PRICING CARDS ────────────────────────────────────── */}
      <section className="section" style={{ paddingTop: '48px', background: '#ffffff' }}>
        <div className="container">
          <div className="grid md:grid-cols-3 gap-6 items-stretch">
            {PLANS.map((plan) => {
              const price = annual ? plan.annualPrice : plan.monthlyPrice;
              const Icon = plan.icon;

              return (
                <div
                  key={plan.id}
                  className="relative rounded-2xl flex flex-col"
                  style={{
                    background: plan.highlight
                      ? 'linear-gradient(160deg, #eff6ff 0%, #f5f3ff 100%)'
                      : '#ffffff',
                    border: plan.highlight
                      ? '2px solid #7c3aed'
                      : '1px solid #e2e8f0',
                    boxShadow: plan.highlight
                      ? '0 8px 40px rgba(124,58,237,0.15), 0 2px 12px rgba(15,23,42,0.08)'
                      : '0 2px 8px rgba(15,23,42,0.05)',
                  }}
                >
                  {/* Most popular badge */}
                  {plan.highlight && (
                    <div className="absolute -top-3.5 left-1/2 -translate-x-1/2">
                      <div
                        className="flex items-center gap-1.5 px-4 py-1.5 rounded-full text-xs font-bold"
                        style={{ background: 'linear-gradient(135deg,#2563eb,#7c3aed)', color: '#fff' }}
                      >
                        <Star size={11} fill="currentColor" /> Most Popular
                      </div>
                    </div>
                  )}

                  <div className="p-8 flex-1 flex flex-col">
                    {/* Header */}
                    <div className="flex items-start gap-3 mb-5">
                      <div
                        className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                        style={{ background: `${plan.iconColor}12`, border: `1px solid ${plan.iconColor}25` }}
                      >
                        <Icon size={18} style={{ color: plan.iconColor }} />
                      </div>
                      <div>
                        <div className="font-bold text-lg" style={{ color: '#0f172a' }}>
                          {plan.name}
                        </div>
                        <div className="text-sm" style={{ color: '#64748b' }}>
                          {plan.tagline}
                        </div>
                      </div>
                    </div>

                    {/* Price */}
                    <div className="mb-6 pb-6" style={{ borderBottom: '1px solid #f1f5f9' }}>
                      {price !== null ? (
                        <>
                          <div className="flex items-end gap-1">
                            <span className="text-4xl font-black" style={{ color: '#0f172a' }}>
                              ${price.toLocaleString()}
                            </span>
                            <span className="mb-1 text-sm" style={{ color: '#94a3b8' }}>/mo</span>
                          </div>
                          {annual && (
                            <div className="text-xs mt-1" style={{ color: '#94a3b8' }}>
                              Billed annually (${(price * 12).toLocaleString()}/yr)
                            </div>
                          )}
                        </>
                      ) : (
                        <>
                          <div className="text-4xl font-black" style={{ color: '#0f172a' }}>
                            Custom
                          </div>
                          <div className="text-xs mt-1" style={{ color: '#94a3b8' }}>
                            Volume discounts · Flexible billing
                          </div>
                        </>
                      )}
                    </div>

                    {/* Features */}
                    <ul className="space-y-2.5 flex-1">
                      {plan.features.map((feat) => (
                        <li key={feat.text} className="flex items-center gap-2.5">
                          {feat.included
                            ? <Check size={15} style={{ color: '#059669', flexShrink: 0 }} />
                            : <X     size={14} style={{ color: '#e2e8f0', flexShrink: 0 }} />
                          }
                          <span
                            className="text-sm"
                            style={{ color: feat.included ? '#475569' : '#94a3b8' }}
                          >
                            {feat.text}
                          </span>
                        </li>
                      ))}
                    </ul>

                    {/* CTA */}
                    <div className="mt-8 space-y-3">
                      <Link
                        href={plan.ctaHref}
                        className={plan.highlight ? 'btn-primary w-full justify-center' : 'btn-secondary w-full justify-center'}
                      >
                        {plan.cta} <ArrowRight size={15} />
                      </Link>
                      <div className="text-center text-xs" style={{ color: '#94a3b8' }}>
                        {plan.note}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Trust row */}
          <div className="flex flex-wrap items-center justify-center gap-8 mt-12 pt-10" style={{ borderTop: '1px solid #f1f5f9' }}>
            {[
              { icon: Shield,    text: 'SOC 2 Type II Certified' },
              { icon: Lock,      text: 'Read-only cloud access' },
              { icon: Globe,     text: 'Data stays in your region' },
              { icon: Clock,     text: '99.9% uptime SLA' },
              { icon: Headphones, text: 'Priority support' },
            ].map((t) => (
              <div key={t.text} className="flex items-center gap-2">
                <t.icon size={14} style={{ color: '#2563eb' }} />
                <span className="text-sm" style={{ color: '#475569' }}>{t.text}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── COMPARISON TABLE ─────────────────────────────────── */}
      <section className="section" style={{ background: '#f8fafc', paddingTop: '80px' }}>
        <div className="container">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-black mb-3" style={{ color: '#0f172a' }}>
              Full <span className="gradient-text">Feature Comparison</span>
            </h2>
            <p style={{ color: '#475569' }}>Everything you need to make the right choice for your team</p>
          </div>

          <div className="overflow-x-auto rounded-2xl" style={{ border: '1px solid #e2e8f0', boxShadow: '0 2px 12px rgba(15,23,42,0.06)' }}>
            <table className="w-full" style={{ background: '#ffffff', borderCollapse: 'collapse', minWidth: 640 }}>
              {/* Sticky header */}
              <thead>
                <tr style={{ borderBottom: '2px solid #f1f5f9', background: '#f8fafc' }}>
                  <th className="text-left p-5 w-1/3" style={{ color: '#94a3b8', fontWeight: 500, fontSize: '13px' }}>
                    Feature
                  </th>
                  {['Starter', 'Professional', 'Enterprise'].map((name, i) => (
                    <th key={name} className="p-5 text-center" style={{ color: i === 1 ? '#7c3aed' : '#475569', fontWeight: 700, fontSize: '14px' }}>
                      {name}
                      {i === 1 && (
                        <div className="text-xs font-normal mt-0.5" style={{ color: '#7c3aed' }}>★ Most Popular</div>
                      )}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {COMPARE_ROWS.map((section) => (
                  <Fragment key={section.category}>
                    <tr
                      style={{ background: '#eff6ff', borderTop: '1px solid #e2e8f0', borderBottom: '1px solid #e2e8f0' }}
                    >
                      <td colSpan={4} className="px-5 py-2.5">
                        <span className="text-xs font-bold uppercase tracking-widest" style={{ color: '#2563eb' }}>
                          {section.category}
                        </span>
                      </td>
                    </tr>
                    {section.features.map((row) => (
                      <tr
                        key={row.label}
                        style={{ borderBottom: '1px solid #f8fafc' }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = '#f8fafc';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = 'transparent';
                        }}
                      >
                        <td className="p-5 text-sm" style={{ color: '#475569' }}>{row.label}</td>
                        <td className="p-5 text-center">
                          <div className="flex justify-center">
                            <CellValue value={row.starter} />
                          </div>
                        </td>
                        <td className="p-5 text-center" style={{ background: 'rgba(124,58,237,0.02)' }}>
                          <div className="flex justify-center">
                            <CellValue value={row.pro} />
                          </div>
                        </td>
                        <td className="p-5 text-center">
                          <div className="flex justify-center">
                            <CellValue value={row.ent} />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* ─── FAQ ──────────────────────────────────────────────── */}
      <section className="section" style={{ background: '#ffffff' }}>
        <div className="container max-w-3xl">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-black mb-3" style={{ color: '#0f172a' }}>
              Frequently Asked <span className="gradient-text">Questions</span>
            </h2>
            <p style={{ color: '#475569' }}>
              Still have questions?{' '}
              <Link href="/contact" className="no-underline" style={{ color: '#2563eb' }}>
                Talk to our team
              </Link>
            </p>
          </div>
          <div className="space-y-3">
            {FAQS.map((faq) => (
              <FaqItem key={faq.q} q={faq.q} a={faq.a} />
            ))}
          </div>
        </div>
      </section>

      {/* ─── ENTERPRISE CTA ───────────────────────────────────── */}
      <section
        className="section"
        style={{ background: '#f8fafc', paddingTop: '40px' }}
      >
        <div className="container">
          <div
            className="gradient-border rounded-3xl overflow-hidden"
            style={{ position: 'relative', background: '#ffffff', border: '1px solid #e2e8f0', boxShadow: '0 4px 24px rgba(15,23,42,0.08)' }}
          >
            <div
              className="absolute inset-0 pointer-events-none"
              style={{
                background: 'radial-gradient(ellipse 80% 60% at 50% 100%, rgba(5,150,105,0.04) 0%, transparent 100%)',
              }}
            />
            <div className="relative grid md:grid-cols-2 gap-0 items-center">
              {/* Left */}
              <div className="p-12 md:p-16">
                <div className="badge badge-green mb-6">Enterprise</div>
                <h2 className="text-3xl font-black mb-4" style={{ color: '#0f172a' }}>
                  Need a Custom Plan for Your{' '}
                  <span className="gradient-text">Organization?</span>
                </h2>
                <p className="mb-8" style={{ color: '#475569', lineHeight: '1.7' }}>
                  Large enterprises, MSSPs, and government organizations often need custom contract
                  structures, dedicated infrastructure, advanced RBAC, and hands-on onboarding
                  support. Our enterprise team will build a plan around your requirements.
                </p>
                <ul className="space-y-3 mb-8">
                  {[
                    'Unlimited accounts across all 6 providers',
                    'Dedicated cloud infrastructure in your region',
                    'White-glove onboarding with your security team',
                    'Custom SLA and contractual guarantees',
                    'MSSP multi-tenant portal available',
                    'Flexible multi-year contract and payment terms',
                  ].map((item) => (
                    <li key={item} className="flex items-center gap-2.5 text-sm" style={{ color: '#475569' }}>
                      <Check size={15} style={{ color: '#059669', flexShrink: 0 }} />
                      {item}
                    </li>
                  ))}
                </ul>
                <Link href="/contact" className="btn-primary">
                  Talk to Sales <ArrowRight size={16} />
                </Link>
              </div>

              {/* Right */}
              <div
                className="p-12 md:p-16"
                style={{ borderLeft: '1px solid #f1f5f9', background: '#f8fafc' }}
              >
                <div className="space-y-6">
                  <div>
                    <div className="text-sm font-semibold mb-1" style={{ color: '#94a3b8' }}>
                      Typical Enterprise Setup
                    </div>
                  </div>
                  {[
                    { icon: Globe,      label: 'Cloud Accounts',    value: '50–500+' },
                    { icon: Users,      label: 'Team Size',          value: 'Unlimited users' },
                    { icon: BarChart3,  label: 'Frameworks',         value: 'All 13 + custom' },
                    { icon: Lock,       label: 'Auth',               value: 'SSO / SAML / SCIM' },
                    { icon: Headphones, label: 'Support',            value: 'Dedicated CSM' },
                    { icon: Clock,      label: 'SLA',                value: '99.9% uptime' },
                    { icon: Shield,     label: 'Compliance',         value: 'SOC 2 + ISO 27001' },
                  ].map((row) => (
                    <div
                      key={row.label}
                      className="flex items-center gap-3 py-3"
                      style={{ borderBottom: '1px solid #e2e8f0' }}
                    >
                      <div
                        className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                        style={{ background: 'rgba(5,150,105,0.1)', border: '1px solid rgba(5,150,105,0.2)' }}
                      >
                        <row.icon size={14} style={{ color: '#059669' }} />
                      </div>
                      <span className="text-sm flex-1" style={{ color: '#475569' }}>{row.label}</span>
                      <span className="text-sm font-semibold" style={{ color: '#0f172a' }}>{row.value}</span>
                    </div>
                  ))}

                  <div className="flex items-center gap-2 pt-2">
                    <Mail size={14} style={{ color: '#94a3b8' }} />
                    <a
                      href="mailto:enterprise@threatengine.io"
                      className="text-sm no-underline"
                      style={{ color: '#2563eb' }}
                    >
                      enterprise@threatengine.io
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
