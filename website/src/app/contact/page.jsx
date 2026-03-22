'use client';

import { useState } from 'react';
import Link from 'next/link';
import {
  ArrowRight,
  Check,
  Shield,
  Search,
  BarChart3,
  Lock,
  Star,
  Building2,
  ChevronDown,
  Send,
  CheckCircle2,
  Award,
  Globe,
  ExternalLink,
} from 'lucide-react';

/* ── Demo bullet points ──────────────────────────────────────── */
const DEMO_HIGHLIGHTS = [
  {
    icon: Search,
    title: 'Live Scan of Your Cloud Environment',
    desc: 'We connect to your actual cloud account using read-only credentials and run a full discovery scan during the demo — so you see real findings, not a scripted presentation.',
  },
  {
    icon: BarChart3,
    title: 'Compliance Posture Report',
    desc: 'Receive a live compliance score against CIS Benchmarks, NIST CSF, and any other framework relevant to your organization, with a drill-down into control gaps.',
  },
  {
    icon: Shield,
    title: 'Threat Findings Walkthrough',
    desc: 'Walk through the highest-severity threat findings in your environment with MITRE ATT&CK context, risk scores, and step-by-step remediation guidance.',
  },
  {
    icon: Lock,
    title: 'IAM Posture Analysis',
    desc: 'See which IAM users, roles, and credentials in your accounts are over-permissioned, unused, or missing MFA — with least-privilege recommendations ready to apply.',
  },
];

/* ── Testimonials ────────────────────────────────────────────── */
const TESTIMONIALS = [
  {
    quote:
      "Threat Engine found 14 critical misconfigurations in our AWS environment in the first scan that our previous CSPM tool had missed entirely. The MITRE ATT&CK context made it trivially easy to prioritize remediation with our board.",
    name: 'Sarah Chen',
    title: 'VP of Security Engineering',
    company: 'Nexora Financial',
    initials: 'SC',
    color: '#2563eb',
  },
  {
    quote:
      "We went from a three-week manual compliance evidence collection cycle to a one-click export. The SOC 2 audit that used to take my team a month of prep now takes an afternoon. That alone justified the cost.",
    name: 'Marcus Okonkwo',
    title: 'CISO',
    company: 'Arclite Health',
    initials: 'MO',
    color: '#7c3aed',
  },
  {
    quote:
      "Managing security posture across our AWS, Azure, and GCP deployments used to mean three different tools and a spreadsheet. Threat Engine gave us a single pane of glass and an IAM posture score that we now present to the board monthly.",
    name: 'Priya Nair',
    title: 'Director of Cloud Security',
    company: 'Vantis Logistics',
    initials: 'PN',
    color: '#059669',
  },
];

/* ── Trust badges ────────────────────────────────────────────── */
const TRUST_BADGES = [
  { icon: Shield, label: 'SOC 2 Type II' },
  { icon: Award,  label: 'ISO 27001:2022' },
  { icon: Globe,  label: 'GDPR Compliant' },
  { icon: Lock,   label: 'Read-Only Access' },
];

/* ── Form options ────────────────────────────────────────────── */
const PROVIDERS = [
  { value: '',             label: 'Select primary provider…' },
  { value: 'aws',          label: 'Amazon Web Services (AWS)' },
  { value: 'azure',        label: 'Microsoft Azure' },
  { value: 'gcp',          label: 'Google Cloud Platform (GCP)' },
  { value: 'multi',        label: 'Multi-Cloud' },
  { value: 'oci',          label: 'Oracle Cloud (OCI)' },
  { value: 'alicloud',     label: 'Alibaba Cloud' },
  { value: 'ibm',          label: 'IBM Cloud' },
];

const ACCOUNT_RANGES = [
  { value: '',        label: 'Select a range…' },
  { value: '1-5',     label: '1–5 accounts' },
  { value: '6-25',    label: '6–25 accounts' },
  { value: '26-100',  label: '26–100 accounts' },
  { value: '101-500', label: '101–500 accounts' },
  { value: '500+',    label: '500+ accounts' },
];

/* ── Sub-components ──────────────────────────────────────────── */

function TestimonialCard({ quote, name, title, company, initials, color }) {
  return (
    <div
      className="rounded-2xl p-5"
      style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 1px 6px rgba(15,23,42,0.04)' }}
    >
      {/* Stars */}
      <div className="flex items-center gap-0.5 mb-3">
        {[...Array(5)].map((_, i) => (
          <Star key={i} size={12} fill="#f59e0b" style={{ color: '#f59e0b' }} />
        ))}
      </div>
      <p className="text-sm mb-4" style={{ color: '#475569', lineHeight: '1.6' }}>
        &ldquo;{quote}&rdquo;
      </p>
      <div className="flex items-center gap-3">
        <div
          className="w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0"
          style={{ background: `${color}15`, color, border: `1px solid ${color}25` }}
        >
          {initials}
        </div>
        <div>
          <div className="text-sm font-semibold" style={{ color: '#0f172a' }}>{name}</div>
          <div className="text-xs" style={{ color: '#64748b' }}>
            {title} · {company}
          </div>
        </div>
      </div>
    </div>
  );
}

const inputStyle = {
  width: '100%',
  padding: '12px 16px',
  background: '#f8fafc',
  border: '1px solid #e2e8f0',
  borderRadius: '10px',
  color: '#0f172a',
  fontSize: '14px',
  outline: 'none',
  transition: 'border-color 0.2s',
};

const labelStyle = {
  display: 'block',
  fontSize: '13px',
  fontWeight: 600,
  marginBottom: '6px',
  color: '#475569',
};

/* ── Page ─────────────────────────────────────────────────────── */
export default function ContactPage() {
  const [form, setForm] = useState({
    firstName: '',
    lastName: '',
    email: '',
    company: '',
    provider: '',
    accounts: '',
    message: '',
  });
  const [focused, setFocused] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});

  function validate() {
    const e = {};
    if (!form.firstName.trim()) e.firstName = 'Required';
    if (!form.lastName.trim())  e.lastName  = 'Required';
    if (!form.email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      e.email = 'Valid work email required';
    if (!form.company.trim()) e.company = 'Required';
    if (!form.provider)       e.provider = 'Please select a provider';
    if (!form.accounts)       e.accounts = 'Please select a range';
    return e;
  }

  function handleChange(e) {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    if (errors[name]) setErrors((prev) => ({ ...prev, [name]: undefined }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const errs = validate();
    if (Object.keys(errs).length > 0) {
      setErrors(errs);
      return;
    }
    setLoading(true);
    // Simulate network request
    await new Promise((r) => setTimeout(r, 1200));
    setLoading(false);
    setSubmitted(true);
  }

  function fieldStyle(name) {
    return {
      ...inputStyle,
      borderColor: errors[name]
        ? '#fca5a5'
        : focused === name
        ? '#93c5fd'
        : '#e2e8f0',
      background: errors[name] ? '#fef2f2' : focused === name ? '#ffffff' : '#f8fafc',
      boxShadow: focused === name ? '0 0 0 3px rgba(37,99,235,0.08)' : 'none',
    };
  }

  return (
    <>
      {/* ─── HERO STRIP ───────────────────────────────────────── */}
      <section
        className="hero-bg grid-bg"
        style={{ paddingTop: '100px', paddingBottom: '0' }}
      >
        <div className="container">
          <div className="text-center mb-12">
            <div className="badge badge-blue mb-5">Request Demo</div>
            <h1 className="text-5xl font-black tracking-tight leading-[1.1] mb-4" style={{ color: '#0f172a' }}>
              See Threat Engine{' '}
              <span className="gradient-text">in Action</span>
            </h1>
            <p className="text-lg max-w-xl mx-auto" style={{ color: '#475569' }}>
              Schedule a 45-minute personalized demo and we&apos;ll scan your actual cloud environment live.
            </p>
          </div>
        </div>
      </section>

      {/* ─── MAIN 2-COLUMN LAYOUT ─────────────────────────────── */}
      <section className="section" style={{ paddingTop: '40px', background: '#ffffff' }}>
        <div className="container">
          <div className="grid lg:grid-cols-5 gap-12 items-start">

            {/* ── LEFT COLUMN (40%) ─────────────────────────── */}
            <div className="lg:col-span-2 space-y-8">

              {/* What you'll see */}
              <div>
                <h2 className="text-2xl font-black mb-6" style={{ color: '#0f172a' }}>
                  What You&apos;ll See in the Demo
                </h2>
                <div className="space-y-4">
                  {DEMO_HIGHLIGHTS.map((item) => (
                    <div
                      key={item.title}
                      className="flex items-start gap-4"
                    >
                      <div
                        className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 mt-0.5"
                        style={{ background: '#eff6ff', border: '1px solid #bfdbfe' }}
                      >
                        <item.icon size={15} style={{ color: '#2563eb' }} />
                      </div>
                      <div>
                        <div className="text-sm font-semibold mb-1" style={{ color: '#0f172a' }}>
                          {item.title}
                        </div>
                        <div className="text-sm" style={{ color: '#475569', lineHeight: '1.6' }}>
                          {item.desc}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Testimonials */}
              <div>
                <h3 className="text-sm font-bold uppercase tracking-widest mb-4" style={{ color: '#94a3b8' }}>
                  What Customers Say
                </h3>
                <div className="space-y-3">
                  {TESTIMONIALS.map((t) => (
                    <TestimonialCard key={t.name} {...t} />
                  ))}
                </div>
              </div>

              {/* Trust badges */}
              <div>
                <h3 className="text-sm font-bold uppercase tracking-widest mb-4" style={{ color: '#94a3b8' }}>
                  Security &amp; Compliance
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  {TRUST_BADGES.map((b) => (
                    <div
                      key={b.label}
                      className="flex items-center gap-2.5 p-3 rounded-xl"
                      style={{
                        background: '#f0fdf4',
                        border: '1px solid #a7f3d0',
                      }}
                    >
                      <b.icon size={14} style={{ color: '#059669', flexShrink: 0 }} />
                      <span className="text-xs font-semibold" style={{ color: '#059669' }}>
                        {b.label}
                      </span>
                    </div>
                  ))}
                </div>
                <p className="text-xs mt-3" style={{ color: '#64748b' }}>
                  We use read-only cloud provider credentials. No write access, no data is
                  extracted from your environment without your explicit consent.
                </p>
              </div>
            </div>

            {/* ── RIGHT COLUMN (60%) ────────────────────────── */}
            <div className="lg:col-span-3">
              <div
                className="rounded-3xl p-8 md:p-10"
                style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 4px 24px rgba(15,23,42,0.08)', position: 'relative', overflow: 'hidden' }}
              >
                {/* Subtle accent */}
                <div
                  className="absolute top-0 right-0 w-64 h-64 pointer-events-none"
                  style={{
                    background: 'radial-gradient(circle, rgba(124,58,237,0.04) 0%, transparent 70%)',
                    transform: 'translate(30%, -30%)',
                  }}
                />

                {submitted ? (
                  /* ── SUCCESS STATE ─────────────────────── */
                  <div className="text-center py-12 px-4 relative">
                    <div
                      className="w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-6"
                      style={{ background: '#f0fdf4', border: '2px solid #a7f3d0' }}
                    >
                      <CheckCircle2 size={36} style={{ color: '#059669' }} />
                    </div>
                    <h2 className="text-3xl font-black mb-3">
                      <span className="gradient-text">Demo Requested!</span>
                    </h2>
                    <p className="text-lg mb-2" style={{ color: '#0f172a' }}>
                      Thanks, {form.firstName}. We&apos;ve got your request.
                    </p>
                    <p className="mb-8" style={{ color: '#475569' }}>
                      A member of our team will reach out to{' '}
                      <span style={{ color: '#2563eb' }}>{form.email}</span> within 24 hours
                      to schedule your personalized demo.
                    </p>
                    <div className="space-y-3">
                      <div className="flex items-center justify-center gap-4">
                        <Link href="/platform" className="btn-secondary" style={{ fontSize: '14px', padding: '10px 20px' }}>
                          Explore Platform
                        </Link>
                        <a
                          href="http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/ui/auth/login"
                          className="btn-primary"
                          style={{ fontSize: '14px', padding: '10px 20px' }}
                        >
                          Sign In to Portal <ExternalLink size={14} />
                        </a>
                      </div>
                    </div>
                  </div>
                ) : (
                  /* ── FORM STATE ────────────────────────── */
                  <div className="relative">
                    <h2 className="text-2xl font-black mb-1" style={{ color: '#0f172a' }}>
                      Request a Demo
                    </h2>
                    <p className="text-sm mb-8" style={{ color: '#64748b' }}>
                      Fill in your details and we&apos;ll reach out within 24 hours.
                    </p>

                    <form onSubmit={handleSubmit} noValidate>
                      {/* Row: First + Last */}
                      <div className="grid sm:grid-cols-2 gap-4 mb-4">
                        <div>
                          <label style={labelStyle}>First Name <span style={{ color: '#dc2626' }}>*</span></label>
                          <input
                            type="text"
                            name="firstName"
                            value={form.firstName}
                            onChange={handleChange}
                            onFocus={() => setFocused('firstName')}
                            onBlur={() => setFocused('')}
                            placeholder="Jane"
                            style={fieldStyle('firstName')}
                          />
                          {errors.firstName && (
                            <div className="text-xs mt-1" style={{ color: '#dc2626' }}>{errors.firstName}</div>
                          )}
                        </div>
                        <div>
                          <label style={labelStyle}>Last Name <span style={{ color: '#dc2626' }}>*</span></label>
                          <input
                            type="text"
                            name="lastName"
                            value={form.lastName}
                            onChange={handleChange}
                            onFocus={() => setFocused('lastName')}
                            onBlur={() => setFocused('')}
                            placeholder="Smith"
                            style={fieldStyle('lastName')}
                          />
                          {errors.lastName && (
                            <div className="text-xs mt-1" style={{ color: '#dc2626' }}>{errors.lastName}</div>
                          )}
                        </div>
                      </div>

                      {/* Work Email */}
                      <div className="mb-4">
                        <label style={labelStyle}>Work Email <span style={{ color: '#dc2626' }}>*</span></label>
                        <input
                          type="email"
                          name="email"
                          value={form.email}
                          onChange={handleChange}
                          onFocus={() => setFocused('email')}
                          onBlur={() => setFocused('')}
                          placeholder="jane@company.com"
                          style={fieldStyle('email')}
                        />
                        {errors.email && (
                          <div className="text-xs mt-1" style={{ color: '#dc2626' }}>{errors.email}</div>
                        )}
                      </div>

                      {/* Company */}
                      <div className="mb-4">
                        <label style={labelStyle}>Company <span style={{ color: '#dc2626' }}>*</span></label>
                        <input
                          type="text"
                          name="company"
                          value={form.company}
                          onChange={handleChange}
                          onFocus={() => setFocused('company')}
                          onBlur={() => setFocused('')}
                          placeholder="Acme Corp"
                          style={fieldStyle('company')}
                        />
                        {errors.company && (
                          <div className="text-xs mt-1" style={{ color: '#dc2626' }}>{errors.company}</div>
                        )}
                      </div>

                      {/* Row: Provider + Accounts */}
                      <div className="grid sm:grid-cols-2 gap-4 mb-4">
                        <div>
                          <label style={labelStyle}>
                            Primary Cloud Provider <span style={{ color: '#dc2626' }}>*</span>
                          </label>
                          <div style={{ position: 'relative' }}>
                            <select
                              name="provider"
                              value={form.provider}
                              onChange={handleChange}
                              onFocus={() => setFocused('provider')}
                              onBlur={() => setFocused('')}
                              style={{
                                ...fieldStyle('provider'),
                                appearance: 'none',
                                paddingRight: '36px',
                                cursor: 'pointer',
                              }}
                            >
                              {PROVIDERS.map((o) => (
                                <option key={o.value} value={o.value}>
                                  {o.label}
                                </option>
                              ))}
                            </select>
                            <ChevronDown
                              size={15}
                              style={{
                                position: 'absolute',
                                right: 12,
                                top: '50%',
                                transform: 'translateY(-50%)',
                                color: '#94a3b8',
                                pointerEvents: 'none',
                              }}
                            />
                          </div>
                          {errors.provider && (
                            <div className="text-xs mt-1" style={{ color: '#dc2626' }}>{errors.provider}</div>
                          )}
                        </div>
                        <div>
                          <label style={labelStyle}>
                            Number of Cloud Accounts <span style={{ color: '#dc2626' }}>*</span>
                          </label>
                          <div style={{ position: 'relative' }}>
                            <select
                              name="accounts"
                              value={form.accounts}
                              onChange={handleChange}
                              onFocus={() => setFocused('accounts')}
                              onBlur={() => setFocused('')}
                              style={{
                                ...fieldStyle('accounts'),
                                appearance: 'none',
                                paddingRight: '36px',
                                cursor: 'pointer',
                              }}
                            >
                              {ACCOUNT_RANGES.map((o) => (
                                <option key={o.value} value={o.value}>
                                  {o.label}
                                </option>
                              ))}
                            </select>
                            <ChevronDown
                              size={15}
                              style={{
                                position: 'absolute',
                                right: 12,
                                top: '50%',
                                transform: 'translateY(-50%)',
                                color: '#94a3b8',
                                pointerEvents: 'none',
                              }}
                            />
                          </div>
                          {errors.accounts && (
                            <div className="text-xs mt-1" style={{ color: '#dc2626' }}>{errors.accounts}</div>
                          )}
                        </div>
                      </div>

                      {/* Message */}
                      <div className="mb-6">
                        <label style={labelStyle}>
                          Message{' '}
                          <span style={{ color: '#94a3b8', fontWeight: 400 }}>(optional)</span>
                        </label>
                        <textarea
                          name="message"
                          value={form.message}
                          onChange={handleChange}
                          onFocus={() => setFocused('message')}
                          onBlur={() => setFocused('')}
                          rows={3}
                          placeholder="Tell us about your environment, use case, or any specific security concerns you'd like to cover in the demo…"
                          style={{
                            ...fieldStyle('message'),
                            resize: 'vertical',
                            minHeight: '88px',
                          }}
                        />
                      </div>

                      {/* Submit */}
                      <button
                        type="submit"
                        disabled={loading}
                        className="btn-primary w-full justify-center"
                        style={{
                          fontSize: '15px',
                          padding: '14px',
                          opacity: loading ? 0.7 : 1,
                          cursor: loading ? 'not-allowed' : 'pointer',
                        }}
                      >
                        {loading ? (
                          <>
                            <span
                              className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin"
                              style={{ display: 'inline-block' }}
                            />
                            Sending…
                          </>
                        ) : (
                          <>
                            <Send size={16} />
                            Request Demo
                          </>
                        )}
                      </button>

                      {/* Response note */}
                      <div className="flex items-center justify-center gap-2 mt-3">
                        <Check size={12} style={{ color: '#059669' }} />
                        <span className="text-xs" style={{ color: '#64748b' }}>
                          We&apos;ll respond within 24 hours · No spam, ever
                        </span>
                      </div>

                      {/* Divider */}
                      <div
                        className="flex items-center gap-3 my-5"
                        style={{ color: '#94a3b8' }}
                      >
                        <div className="flex-1 h-px" style={{ background: '#f1f5f9' }} />
                        <span className="text-xs">or</span>
                        <div className="flex-1 h-px" style={{ background: '#f1f5f9' }} />
                      </div>

                      {/* Sign In CTA */}
                      <a
                        href="http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/ui/auth/login"
                        className="btn-secondary w-full justify-center"
                        style={{ fontSize: '14px' }}
                      >
                        Sign In to CSPM Portal <ExternalLink size={14} />
                      </a>

                      <p className="text-center text-xs mt-3" style={{ color: '#94a3b8' }}>
                        Already have an account? Access your dashboard directly.
                      </p>
                    </form>
                  </div>
                )}
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* ─── BOTTOM STATS STRIP ───────────────────────────────── */}
      <section
        className="section"
        style={{ paddingTop: '64px', paddingBottom: '64px', borderTop: '1px solid #e2e8f0', background: '#f8fafc' }}
      >
        <div className="container">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
            {[
              { value: '500+',  label: 'Enterprise customers',   color: '#2563eb' },
              { value: '6',     label: 'Cloud providers covered', color: '#7c3aed' },
              { value: '<24 hr', label: 'Demo response time',    color: '#059669' },
              { value: '99.9%', label: 'Platform uptime SLA',    color: '#0891b2' },
            ].map((s) => (
              <div key={s.label}>
                <div className="text-3xl font-black mb-1" style={{ color: s.color }}>{s.value}</div>
                <div className="text-sm" style={{ color: '#475569' }}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}
