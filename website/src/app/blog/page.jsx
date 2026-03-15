import Link from 'next/link';
import { posts } from '@/lib/posts';
import { ArrowRight, Calendar, Clock, BookOpen, User, Rss, TrendingUp, Shield, AlertTriangle, FileSearch, GitBranch, Cpu, Server, BarChart3, Lock } from 'lucide-react';

// ── per-category editorial panels ─────────────────────────────────────────────

const CATEGORY_PANELS = {
  'Threat Intelligence': {
    icon: Shield,
    label: 'THREAT SCAN',
    bg: '#0f0a0a',
    borderColor: '#ef444440',
    glowColor: '#ef4444',
    stats: [
      { value: '3,900+', label: 'Findings' },
      { value: '82%', label: 'Misconfig rate' },
      { value: '500+', label: 'Accounts' },
    ],
    rows: [
      { id: 'TE-001', text: 'Public S3 bucket — sensitive data exposed', sev: 'CRITICAL', color: '#ef4444' },
      { id: 'TE-002', text: 'IAM wildcard (*:*) on Lambda execution role', sev: 'HIGH', color: '#f97316' },
      { id: 'TE-003', text: 'Security group open to 0.0.0.0/0 port 22', sev: 'HIGH', color: '#f97316' },
    ],
  },
  'MITRE ATT&CK': {
    icon: GitBranch,
    label: 'ATT&CK MATRIX',
    bg: '#080f1a',
    borderColor: '#2563eb40',
    glowColor: '#2563eb',
    stats: [
      { value: '14', label: 'Tactics' },
      { value: '193', label: 'Techniques' },
      { value: '411', label: 'Sub-techniques' },
    ],
    rows: [
      { id: 'TA0001', text: 'Initial Access — Phishing (T1566)', sev: 'HIGH', color: '#f97316' },
      { id: 'TA0003', text: 'Persistence — Create Account (T1136)', sev: 'MEDIUM', color: '#eab308' },
      { id: 'TA0005', text: 'Defense Evasion — Impair Logging (T1562)', sev: 'CRITICAL', color: '#ef4444' },
    ],
  },
  'Compliance': {
    icon: FileSearch,
    label: 'COMPLIANCE SCAN',
    bg: '#080f10',
    borderColor: '#059669 40',
    glowColor: '#059669',
    stats: [
      { value: '13', label: 'Frameworks' },
      { value: '500+', label: 'Controls' },
      { value: '89%', label: 'Avg score' },
    ],
    rows: [
      { id: 'CIS-1.1', text: 'MFA enabled on root account', sev: 'PASS', color: '#22c55e' },
      { id: 'CIS-2.1', text: 'S3 block public access — account level', sev: 'FAIL', color: '#ef4444' },
      { id: 'NIST-AC', text: 'Access control baseline — 4 gaps found', sev: 'WARN', color: '#f59e0b' },
    ],
  },
  'Architecture': {
    icon: Server,
    label: 'ARCHITECTURE SCAN',
    bg: '#09080f',
    borderColor: '#7c3aed40',
    glowColor: '#7c3aed',
    stats: [
      { value: '40+', label: 'Services mapped' },
      { value: '6', label: 'Cloud providers' },
      { value: '369', label: 'Relationship rules' },
    ],
    rows: [
      { id: 'INV-01', text: 'EC2 → SecurityGroup → allows 0.0.0.0/0', sev: 'HIGH', color: '#f97316' },
      { id: 'INV-02', text: 'S3 → CloudFront → exposed via public dist.', sev: 'MEDIUM', color: '#eab308' },
      { id: 'INV-03', text: 'RDS → IAMRole → wildcard assume role', sev: 'CRITICAL', color: '#ef4444' },
    ],
  },
  'DevSecOps': {
    icon: GitBranch,
    label: 'IAC SECURITY SCAN',
    bg: '#0f0a00',
    borderColor: '#f59e0b40',
    glowColor: '#f59e0b',
    stats: [
      { value: '14', label: 'IaC languages' },
      { value: '500+', label: 'Security rules' },
      { value: '<30s', label: 'Scan time' },
    ],
    rows: [
      { id: 'TE-S3-001', text: 'acl = "public-read" — Public ACL detected', sev: 'HIGH', color: '#f97316' },
      { id: 'TE-S3-019', text: 'force_destroy = true — Data loss risk', sev: 'MEDIUM', color: '#eab308' },
      { id: 'TE-EC2-008', text: 'User data script exposes secrets', sev: 'CRITICAL', color: '#ef4444' },
    ],
  },
  'AI Security': {
    icon: Cpu,
    label: 'AI THREAT DETECTION',
    bg: '#080f0f',
    borderColor: '#0891b240',
    glowColor: '#0891b2',
    stats: [
      { value: '97.3%', label: 'Detection rate' },
      { value: '0.4%', label: 'False positives' },
      { value: '<5ms', label: 'Inference time' },
    ],
    rows: [
      { id: 'AI-001', text: 'Anomalous API call pattern — exfil risk', sev: 'HIGH', color: '#f97316' },
      { id: 'AI-002', text: 'Credential stuffing detected — 3 accounts', sev: 'CRITICAL', color: '#ef4444' },
      { id: 'AI-003', text: 'ML model: confidence 94% — lateral move', sev: 'HIGH', color: '#f97316' },
    ],
  },
  'Kubernetes': {
    icon: Server,
    label: 'K8S POSTURE SCAN',
    bg: '#080f1a',
    borderColor: '#2563eb40',
    glowColor: '#326ce5',
    stats: [
      { value: '10', label: 'Control checks' },
      { value: '6', label: 'Node groups' },
      { value: '3', label: 'Critical findings' },
    ],
    rows: [
      { id: 'K8S-001', text: 'Pod running as root — privileged container', sev: 'CRITICAL', color: '#ef4444' },
      { id: 'K8S-002', text: 'No network policy — unrestricted pod comms', sev: 'HIGH', color: '#f97316' },
      { id: 'K8S-003', text: 'RBAC wildcard — ClusterRole with *:*', sev: 'HIGH', color: '#f97316' },
    ],
  },
  'Strategy': {
    icon: BarChart3,
    label: 'RISK POSTURE',
    bg: '#0a0f0a',
    borderColor: '#16a34a40',
    glowColor: '#16a34a',
    stats: [
      { value: '6', label: 'Cloud providers' },
      { value: '13+', label: 'Frameworks' },
      { value: '91%', label: 'Risk reduction' },
    ],
    rows: [
      { id: 'RSK-001', text: 'Multi-cloud identity sprawl — 3 providers', sev: 'HIGH', color: '#f97316' },
      { id: 'RSK-002', text: 'Shadow IT resources — 47 unmanaged', sev: 'MEDIUM', color: '#eab308' },
      { id: 'RSK-003', text: 'Compliance gap — HIPAA controls 12 failed', sev: 'HIGH', color: '#f97316' },
    ],
  },
};

function getPanel(category) {
  return CATEGORY_PANELS[category] || CATEGORY_PANELS['Threat Intelligence'];
}

// ── helpers ──────────────────────────────────────────────────────────────────

function CategoryBadge({ category, color, small = false }) {
  return (
    <span
      className={small ? 'badge' : 'badge'}
      style={{
        background: `${color}10`,
        color: color,
        border: `1px solid ${color}30`,
        fontSize: small ? '10px' : '11px',
        padding: small ? '3px 10px' : '4px 12px',
      }}
    >
      {category}
    </span>
  );
}

function AuthorChip({ author, date, readTime, small = false }) {
  return (
    <div className="flex items-center gap-3">
      {/* Avatar */}
      <div
        className="flex items-center justify-center rounded-full flex-shrink-0 font-bold"
        style={{
          width: small ? 28 : 36,
          height: small ? 28 : 36,
          background: 'linear-gradient(135deg,#2563eb,#7c3aed)',
          color: '#fff',
          fontSize: small ? '11px' : '13px',
        }}
      >
        AY
      </div>
      <div className="flex flex-col" style={{ gap: 1 }}>
        <span style={{ color: '#0f172a', fontSize: small ? '12px' : '13px', fontWeight: 600 }}>
          {author}
        </span>
        <div className="flex items-center gap-2" style={{ color: '#94a3b8', fontSize: '11px' }}>
          <span className="flex items-center gap-1">
            <Calendar size={10} />
            {date}
          </span>
          <span style={{ color: '#e2e8f0' }}>·</span>
          <span className="flex items-center gap-1">
            <Clock size={10} />
            {readTime}
          </span>
        </div>
      </div>
    </div>
  );
}

// ── featured post card ────────────────────────────────────────────────────────

function FeaturedPost({ post }) {
  const panel = getPanel(post.category);
  const PanelIcon = panel.icon;

  return (
    <div
      className="card-hover rounded-2xl overflow-hidden"
      style={{ border: `1px solid ${post.categoryColor}20`, background: '#ffffff', boxShadow: '0 4px 24px rgba(15,23,42,0.08)' }}
    >
      <div className="grid md:grid-cols-2 gap-0">
        {/* ── Rich dark editorial panel ── */}
        <div
          className="relative flex flex-col order-2 md:order-1"
          style={{ background: panel.bg, minHeight: 300 }}
        >
          {/* Header bar */}
          <div
            className="flex items-center gap-2 px-5 py-3"
            style={{ borderBottom: `1px solid ${panel.borderColor}`, background: `${panel.glowColor}08` }}
          >
            <span
              style={{
                width: 7, height: 7, borderRadius: '50%',
                background: panel.glowColor,
                boxShadow: `0 0 6px ${panel.glowColor}`,
                flexShrink: 0,
              }}
            />
            <span style={{ color: panel.glowColor, fontSize: '10px', fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace' }}>
              {panel.label}
            </span>
            <span
              style={{
                marginLeft: 'auto', fontSize: '10px', fontWeight: 700, padding: '2px 8px',
                borderRadius: 9999, background: `${post.categoryColor}20`,
                color: post.categoryColor, border: `1px solid ${post.categoryColor}40`, letterSpacing: '0.06em',
              }}
            >
              FEATURED
            </span>
          </div>

          {/* Stats row */}
          <div
            className="grid grid-cols-3"
            style={{ borderBottom: `1px solid ${panel.borderColor}` }}
          >
            {panel.stats.map((s) => (
              <div
                key={s.label}
                className="flex flex-col items-center justify-center py-4"
                style={{ borderRight: `1px solid ${panel.borderColor}` }}
              >
                <span style={{ color: panel.glowColor, fontSize: '1.25rem', fontWeight: 800, fontFamily: 'monospace', lineHeight: 1 }}>
                  {s.value}
                </span>
                <span style={{ color: '#64748b', fontSize: '10px', marginTop: 3, letterSpacing: '0.04em' }}>
                  {s.label}
                </span>
              </div>
            ))}
          </div>

          {/* Findings rows */}
          <div className="flex flex-col flex-1" style={{ padding: '12px 0' }}>
            {panel.rows.map((row) => (
              <div
                key={row.id}
                className="flex items-center gap-3 px-4 py-2"
                style={{ borderBottom: `1px solid ${panel.borderColor}`, borderLeft: `2px solid ${row.color}` }}
              >
                <span style={{ color: '#475569', fontSize: '10px', fontFamily: 'monospace', flexShrink: 0, minWidth: 64 }}>
                  {row.id}
                </span>
                <span style={{ color: '#94a3b8', fontSize: '11px', flex: 1, lineHeight: 1.4 }}>
                  {row.text}
                </span>
                <span
                  style={{
                    fontSize: '9px', fontWeight: 700, padding: '1px 7px', borderRadius: 9999,
                    color: row.color, background: `${row.color}15`, border: `1px solid ${row.color}40`,
                    letterSpacing: '0.06em', flexShrink: 0,
                  }}
                >
                  {row.sev}
                </span>
              </div>
            ))}
          </div>

          {/* Footer */}
          <div
            className="flex items-center gap-2 px-5 py-3"
            style={{ borderTop: `1px solid ${panel.borderColor}` }}
          >
            <PanelIcon size={12} style={{ color: '#475569' }} />
            <span style={{ color: '#475569', fontSize: '10px', fontFamily: 'monospace' }}>
              threat-engine · {post.date}
            </span>
          </div>
        </div>

        {/* Content panel */}
        <div className="flex flex-col justify-center p-8 md:p-10 order-1 md:order-2">
          <div className="mb-4">
            <CategoryBadge category={post.category} color={post.categoryColor} />
          </div>
          <h2
            className="font-bold leading-tight mb-3"
            style={{ color: '#0f172a', fontSize: 'clamp(1.4rem,2.5vw,1.9rem)' }}
          >
            {post.title}
          </h2>
          <p className="mb-6 leading-relaxed" style={{ color: '#475569', fontSize: '15px' }}>
            {post.excerpt}
          </p>
          <div className="mb-6">
            <AuthorChip author={post.author} date={post.date} readTime={post.readTime} />
          </div>
          <Link
            href={`/blog/${post.slug}`}
            className="btn-primary self-start"
            style={{ padding: '10px 24px', fontSize: '14px' }}
          >
            Read Article <ArrowRight size={14} />
          </Link>
        </div>
      </div>
    </div>
  );
}

// ── post card (grid) ──────────────────────────────────────────────────────────

function PostCard({ post }) {
  const panel = getPanel(post.category);
  const PanelIcon = panel.icon;

  return (
    <Link href={`/blog/${post.slug}`} className="no-underline block" style={{ color: 'inherit' }}>
      <article
        className="card-hover rounded-2xl overflow-hidden flex flex-col h-full"
        style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 2px 10px rgba(15,23,42,0.05)' }}
      >
        {/* ── Mini dark header visual ── */}
        <div
          className="relative flex items-center justify-between px-4 py-3"
          style={{
            background: panel.bg,
            borderBottom: `1px solid ${panel.borderColor}`,
          }}
        >
          {/* Scan label */}
          <div className="flex items-center gap-2">
            <span
              style={{
                width: 6, height: 6, borderRadius: '50%',
                background: panel.glowColor,
                boxShadow: `0 0 5px ${panel.glowColor}`,
              }}
            />
            <span style={{ color: panel.glowColor, fontSize: '9px', fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace' }}>
              {panel.label}
            </span>
          </div>
          {/* Stats chips */}
          <div className="flex items-center gap-2">
            <span style={{ color: '#475569', fontSize: '9px', fontFamily: 'monospace' }}>
              {panel.stats[0].value}
              <span style={{ color: '#334155', marginLeft: 3 }}>{panel.stats[0].label}</span>
            </span>
            <PanelIcon size={11} style={{ color: '#334155' }} />
          </div>
        </div>

        {/* Mini findings row */}
        <div
          style={{ background: panel.bg, borderBottom: `1px solid ${panel.borderColor}`, padding: '6px 16px' }}
        >
          <div className="flex items-center gap-2">
            <span style={{ color: '#334155', fontSize: '9px', fontFamily: 'monospace', flexShrink: 0 }}>
              {panel.rows[0].id}
            </span>
            <span
              style={{
                color: '#475569', fontSize: '10px', flex: 1, overflow: 'hidden',
                textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}
            >
              {panel.rows[0].text}
            </span>
            <span
              style={{
                fontSize: '8px', fontWeight: 700, padding: '1px 5px', borderRadius: 9999,
                color: panel.rows[0].color, background: `${panel.rows[0].color}15`,
                border: `1px solid ${panel.rows[0].color}40`, flexShrink: 0,
              }}
            >
              {panel.rows[0].sev}
            </span>
          </div>
        </div>

        <div className="flex flex-col flex-1 p-6">
          {/* Category */}
          <div className="mb-3">
            <CategoryBadge category={post.category} color={post.categoryColor} small />
          </div>

          {/* Title */}
          <h3
            className="font-bold leading-snug mb-3 transition-colors"
            style={{ color: '#0f172a', fontSize: '1rem', lineHeight: 1.4 }}
          >
            {post.title}
          </h3>

          {/* Excerpt */}
          <p
            className="leading-relaxed flex-1 mb-5"
            style={{ color: '#475569', fontSize: '13px', lineHeight: 1.65 }}
          >
            {post.excerpt}
          </p>

          {/* Footer */}
          <div
            className="flex items-center justify-between pt-4"
            style={{ borderTop: '1px solid #f1f5f9' }}
          >
            <AuthorChip author={post.author} date={post.date} readTime={post.readTime} small />
            <ArrowRight size={14} style={{ color: '#2563eb', flexShrink: 0 }} />
          </div>
        </div>
      </article>
    </Link>
  );
}

// ── page ─────────────────────────────────────────────────────────────────────

export default function BlogPage() {
  const featuredPost = posts.find((p) => p.featured);
  const allPosts = posts;

  // Unique categories derived from posts data (always objects with name + color)
  const uniqueCategories = [...new Map(posts.map((p) => [p.category, { name: p.category, color: p.categoryColor }])).values()];

  return (
    <div style={{ background: '#ffffff', minHeight: '100vh' }}>

      {/* ── Hero ──────────────────────────────────────────────────── */}
      <section
        className="relative hero-bg grid-bg overflow-hidden"
        style={{ paddingTop: 140, paddingBottom: 80 }}
      >
        <div className="container relative z-10">
          <div className="max-w-3xl mx-auto text-center">
            {/* Badge */}
            <div className="mb-6 flex justify-center">
              <span className="badge badge-blue flex items-center gap-2">
                <Rss size={11} />
                CSPM Research Blog
              </span>
            </div>

            {/* Heading */}
            <h1
              className="font-bold mb-5"
              style={{ fontSize: 'clamp(2rem,5vw,3.25rem)', lineHeight: 1.15, color: '#0f172a' }}
            >
              Security Insights from{' '}
              <span className="gradient-text">the Front Lines</span>
            </h1>

            {/* Subtext */}
            <p
              className="mb-8 mx-auto"
              style={{ color: '#475569', fontSize: '1.05rem', maxWidth: 560, lineHeight: 1.7 }}
            >
              In-depth research, practical guides, and threat intelligence from the Threat Engine
              security team.
            </p>

            {/* Author highlight */}
            <div
              className="inline-flex items-center gap-3 rounded-2xl px-5 py-3"
              style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 2px 10px rgba(15,23,42,0.06)' }}
            >
              <div
                className="rounded-full flex items-center justify-center font-bold text-white flex-shrink-0"
                style={{
                  width: 38,
                  height: 38,
                  background: 'linear-gradient(135deg,#2563eb,#7c3aed)',
                  fontSize: '13px',
                }}
              >
                AY
              </div>
              <div className="text-left">
                <div style={{ color: '#0f172a', fontSize: '13px', fontWeight: 600 }}>
                  Written by Anup Yadav
                </div>
                <div style={{ color: '#64748b', fontSize: '11px' }}>
                  Founder &amp; Head of Security Research
                </div>
              </div>
              <User size={14} style={{ color: '#2563eb', marginLeft: 4 }} />
            </div>
          </div>
        </div>
      </section>

      {/* ── Category pills ────────────────────────────────────────── */}
      <div className="container" style={{ paddingTop: 0, paddingBottom: 32 }}>
        <div className="flex flex-wrap items-center gap-2">
          <span style={{ color: '#94a3b8', fontSize: '12px', fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase', marginRight: 4 }}>
            Topics:
          </span>
          {uniqueCategories.map((cat) => (
            <span
              key={cat.name}
              className="badge"
              style={{
                background: `${cat.color}08`,
                color: cat.color,
                border: `1px solid ${cat.color}25`,
                fontSize: '11px',
                cursor: 'default',
              }}
            >
              {cat.name}
            </span>
          ))}
        </div>
      </div>

      {/* ── Featured post ─────────────────────────────────────────── */}
      {featuredPost && (
        <section className="container" style={{ paddingBottom: 48 }}>
          <div className="flex items-center gap-3 mb-6">
            <div
              style={{ width: 3, height: 20, borderRadius: 2, background: 'linear-gradient(#2563eb,#7c3aed)' }}
            />
            <span style={{ color: '#64748b', fontSize: '13px', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
              Featured Article
            </span>
          </div>
          <FeaturedPost post={featuredPost} />
        </section>
      )}

      {/* ── All posts grid ────────────────────────────────────────── */}
      <section className="container section" style={{ paddingTop: 16 }}>
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div
              style={{ width: 3, height: 20, borderRadius: 2, background: 'linear-gradient(#2563eb,#7c3aed)' }}
            />
            <span style={{ color: '#64748b', fontSize: '13px', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
              All Articles
            </span>
          </div>
          <span
            className="badge"
            style={{ background: '#eff6ff', color: '#2563eb', border: '1px solid #bfdbfe', fontSize: '11px' }}
          >
            <BookOpen size={10} />
            {allPosts.length} articles
          </span>
        </div>

        <div
          className="grid gap-6"
          style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))' }}
        >
          {allPosts.map((post) => (
            <PostCard key={post.slug} post={post} />
          ))}
        </div>
      </section>

      {/* ── Bottom CTA strip ──────────────────────────────────────── */}
      <section style={{ paddingBottom: 96 }}>
        <div className="container">
          <div
            className="rounded-2xl text-center"
            style={{
              padding: '56px 40px',
              border: '1px solid #e2e8f0',
              background: 'linear-gradient(135deg, #eff6ff 0%, #f5f3ff 100%)',
              boxShadow: '0 4px 24px rgba(15,23,42,0.06)',
            }}
          >
            <div className="mb-4 flex justify-center">
              <span className="badge badge-blue">
                <BookOpen size={11} />
                Never Miss an Article
              </span>
            </div>
            <h2
              className="font-bold mb-3"
              style={{ color: '#0f172a', fontSize: 'clamp(1.4rem,3vw,2rem)' }}
            >
              Stay ahead of cloud threats
            </h2>
            <p style={{ color: '#475569', fontSize: '15px', maxWidth: 480, margin: '0 auto 28px' }}>
              New research, threat intelligence, and practical guides published regularly by the
              Threat Engine security team.
            </p>
            <div className="flex items-center justify-center gap-3 flex-wrap">
              <Link href="/contact" className="btn-primary" style={{ padding: '10px 28px', fontSize: '14px' }}>
                Request a Demo <ArrowRight size={14} />
              </Link>
              <Link href="/platform" className="btn-secondary" style={{ padding: '10px 28px', fontSize: '14px' }}>
                Explore the Platform
              </Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
