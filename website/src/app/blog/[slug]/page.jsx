import { getPostBySlug, posts } from '@/lib/posts';
import CopyLinkButton from './CopyLinkButton';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft,
  Calendar,
  Clock,
  Tag,
  User,
  Twitter,
  Linkedin,
  BookOpen,
  ArrowRight,
  Mail,
  ChevronRight,
  Hash,
  CheckCircle2,
  Shield,
  Lightbulb,
} from 'lucide-react';

// ── Static generation ─────────────────────────────────────────────────────────

export function generateStaticParams() {
  return posts.map((p) => ({ slug: p.slug }));
}

export async function generateMetadata({ params }) {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) return {};
  return {
    title: `${post.title} — Threat Engine Blog`,
    description: post.excerpt,
    openGraph: {
      title: post.title,
      description: post.excerpt,
      type: 'article',
    },
  };
}

// ── Markdown → HTML transformer ───────────────────────────────────────────────

function markdownToHtml(md) {
  if (!md) return '';

  let html = md;

  // Fenced code blocks (``` ... ```) — process before inline code
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const escaped = code
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    return `<pre><code class="language-${lang || 'text'}">${escaped}</code></pre>`;
  });

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  // Bold + italic  ***text***
  html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');

  // Bold  **text**
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

  // Italic  *text*  (not preceded by another *)
  html = html.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, '<em>$1</em>');

  // ### h3 (before ##)
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');

  // ## h2
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');

  // # h1
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

  // Horizontal rules
  html = html.replace(/^---$/gm, '<hr />');

  // Blockquotes
  html = html.replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>');

  // Unordered lists — collect consecutive bullet lines into a single <ul>
  html = html.replace(/((?:^[-*] .+\n?)+)/gm, (block) => {
    const items = block
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((l) => `<li>${l.replace(/^[-*] /, '')}</li>`)
      .join('');
    return `<ul>${items}</ul>`;
  });

  // Ordered lists
  html = html.replace(/((?:^\d+\. .+\n?)+)/gm, (block) => {
    const items = block
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((l) => `<li>${l.replace(/^\d+\. /, '')}</li>`)
      .join('');
    return `<ol>${items}</ol>`;
  });

  // Paragraphs — blank-line separated runs of text not already wrapped in a block element
  const blockElements = ['<h1', '<h2', '<h3', '<ul', '<ol', '<li', '<pre', '<blockquote', '<hr'];
  html = html
    .split(/\n\n+/)
    .map((chunk) => {
      const trimmed = chunk.trim();
      if (!trimmed) return '';
      const isBlock = blockElements.some((tag) => trimmed.startsWith(tag));
      return isBlock ? trimmed : `<p>${trimmed.replace(/\n/g, ' ')}</p>`;
    })
    .join('\n');

  return html;
}

// ── Extract h2 headings for ToC ───────────────────────────────────────────────

function extractHeadings(content) {
  const matches = [...content.matchAll(/^## (.+)$/gm)];
  return matches.map((m) => ({
    text: m[1],
    id: m[1]
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)/g, ''),
  }));
}

// ── Small components ──────────────────────────────────────────────────────────

function CategoryBadge({ category, color }) {
  return (
    <span
      className="badge"
      style={{
        background: `${color}10`,
        color: color,
        border: `1px solid ${color}30`,
        fontSize: '11px',
      }}
    >
      {category}
    </span>
  );
}

function TagPill({ tag }) {
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        padding: '3px 10px',
        borderRadius: 999,
        fontSize: '11px',
        fontWeight: 500,
        background: '#eff6ff',
        color: '#2563eb',
        border: '1px solid #bfdbfe',
      }}
    >
      <Hash size={9} />
      {tag}
    </span>
  );
}

function SidebarArticleCard({ post }) {
  return (
    <Link href={`/blog/${post.slug}`} className="no-underline block group">
      <div
        className="rounded-xl p-3 transition-all hover:bg-slate-50"
        style={{ border: '1px solid transparent' }}
      >
        <span
          className="badge"
          style={{
            background: `${post.categoryColor}10`,
            color: post.categoryColor,
            border: `1px solid ${post.categoryColor}25`,
            fontSize: '9px',
            padding: '2px 8px',
            marginBottom: 6,
            display: 'inline-flex',
          }}
        >
          {post.category}
        </span>
        <p
          className="leading-snug"
          style={{ color: '#0f172a', fontSize: '13px', fontWeight: 500, marginTop: 4 }}
        >
          {post.title}
        </p>
        <div
          className="flex items-center gap-2 mt-2"
          style={{ color: '#94a3b8', fontSize: '11px' }}
        >
          <Clock size={10} />
          {post.readTime}
          <ChevronRight size={10} style={{ marginLeft: 'auto', color: '#2563eb' }} />
        </div>
      </div>
    </Link>
  );
}

function RelatedPostCard({ post }) {
  return (
    <Link href={`/blog/${post.slug}`} className="no-underline block" style={{ color: 'inherit' }}>
      <article
        className="card-hover rounded-2xl overflow-hidden"
        style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 2px 10px rgba(15,23,42,0.05)' }}
      >
        <div
          style={{
            height: 3,
            background: `linear-gradient(90deg,${post.categoryColor},${post.categoryColor}50)`,
          }}
        />
        <div className="p-5">
          <div className="mb-2">
            <CategoryBadge category={post.category} color={post.categoryColor} />
          </div>
          <h4
            className="font-semibold leading-snug mb-2"
            style={{ color: '#0f172a', fontSize: '15px' }}
          >
            {post.title}
          </h4>
          <p
            className="leading-relaxed mb-4"
            style={{ color: '#475569', fontSize: '13px', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}
          >
            {post.excerpt}
          </p>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2" style={{ color: '#94a3b8', fontSize: '11px' }}>
              <Calendar size={10} />
              {post.date}
              <span style={{ color: '#e2e8f0' }}>·</span>
              <Clock size={10} />
              {post.readTime}
            </div>
            <ArrowRight size={13} style={{ color: '#2563eb' }} />
          </div>
        </div>
      </article>
    </Link>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function BlogPostPage({ params }) {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) notFound();

  const htmlContent = markdownToHtml(post.content || '');
  const headings = extractHeadings(post.content || '');

  // Sidebar: up to 3 other posts
  const otherPosts = posts.filter((p) => p.slug !== post.slug).slice(0, 3);

  // Related: same category first, then fill from others
  const related = [
    ...posts.filter((p) => p.slug !== post.slug && p.category === post.category),
    ...posts.filter((p) => p.slug !== post.slug && p.category !== post.category),
  ].slice(0, 3);

  const twitterUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent(post.title)}&url=${encodeURIComponent(`https://threatengine.io/blog/${post.slug}`)}`;
  const linkedinUrl = `https://www.linkedin.com/shareArticle?mini=true&url=${encodeURIComponent(`https://threatengine.io/blog/${post.slug}`)}&title=${encodeURIComponent(post.title)}`;

  return (
    <div style={{ background: '#ffffff', minHeight: '100vh' }}>

      {/* ── Hero ────────────────────────────────────────────────────── */}
      <section
        className="relative hero-bg grid-bg overflow-hidden"
        style={{ paddingTop: 120, paddingBottom: 72 }}
      >
        {/* Ambient tint */}
        <div
          className="absolute pointer-events-none"
          style={{
            width: 700,
            height: 500,
            borderRadius: '50%',
            background: `radial-gradient(circle, ${post.categoryColor}08 0%, transparent 65%)`,
            top: -120,
            left: '50%',
            transform: 'translateX(-50%)',
          }}
        />
        {/* Decorative ring 1 */}
        <div
          className="absolute pointer-events-none"
          style={{
            width: 500,
            height: 500,
            borderRadius: '50%',
            border: `1px solid ${post.categoryColor}12`,
            top: '50%',
            right: -180,
            transform: 'translateY(-50%)',
          }}
        />
        {/* Decorative ring 2 */}
        <div
          className="absolute pointer-events-none"
          style={{
            width: 300,
            height: 300,
            borderRadius: '50%',
            border: `1px solid ${post.categoryColor}10`,
            top: '50%',
            right: -80,
            transform: 'translateY(-50%)',
          }}
        />

        <div className="container relative z-10" style={{ maxWidth: 900 }}>

          {/* Breadcrumb */}
          <div className="mb-8">
            <Link
              href="/blog"
              className="inline-flex items-center gap-2 no-underline transition-colors hover:text-blue-600"
              style={{ color: '#64748b', fontSize: '13px', fontWeight: 500 }}
            >
              <ArrowLeft size={14} />
              Back to Blog
            </Link>
          </div>

          {/* Category */}
          <div className="mb-5">
            <CategoryBadge category={post.category} color={post.categoryColor} />
          </div>

          {/* Title */}
          <h1
            className="font-bold leading-tight mb-5"
            style={{ color: '#0f172a', fontSize: 'clamp(1.75rem,4vw,3rem)', lineHeight: 1.15 }}
          >
            {post.title}
          </h1>

          {/* Excerpt */}
          <p
            className="mb-8 leading-relaxed"
            style={{ color: '#475569', fontSize: '1.1rem', maxWidth: 700 }}
          >
            {post.excerpt}
          </p>

          {/* Author row */}
          <div
            className="inline-flex flex-wrap items-center gap-5 rounded-2xl px-6 py-4 mb-6"
            style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 2px 10px rgba(15,23,42,0.06)' }}
          >
            {/* Avatar */}
            <div className="flex items-center gap-3">
              <div
                className="rounded-full flex items-center justify-center font-bold text-white flex-shrink-0"
                style={{
                  width: 44,
                  height: 44,
                  background: 'linear-gradient(135deg,#2563eb,#7c3aed)',
                  fontSize: '14px',
                }}
              >
                AY
              </div>
              <div>
                <div style={{ color: '#0f172a', fontSize: '14px', fontWeight: 600 }}>
                  Anup Yadav
                </div>
                <div style={{ color: '#64748b', fontSize: '12px' }}>
                  Founder &amp; Head of Security Research
                </div>
              </div>
            </div>

            <div style={{ width: 1, height: 36, background: '#e2e8f0' }} />

            <div className="flex items-center gap-4" style={{ color: '#64748b', fontSize: '13px' }}>
              <span className="flex items-center gap-1.5">
                <Calendar size={13} style={{ color: '#2563eb' }} />
                {post.date}
              </span>
              <span className="flex items-center gap-1.5">
                <Clock size={13} style={{ color: '#2563eb' }} />
                {post.readTime}
              </span>
            </div>
          </div>

          {/* Tags */}
          {post.tags && post.tags.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {post.tags.map((tag) => (
                <TagPill key={tag} tag={tag} />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* ── Body: 2-column layout ───────────────────────────────────── */}
      <div className="container" style={{ maxWidth: 1200, paddingTop: 48, paddingBottom: 80 }}>
        <div
          className="grid gap-12"
          style={{ gridTemplateColumns: 'minmax(0,1fr) 340px', alignItems: 'start' }}
        >

          {/* ── Main content ──────────────────────────────────────── */}
          <main>
            {/* Article body */}
            <article
              className="rounded-2xl mb-10 overflow-hidden"
              style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 2px 12px rgba(15,23,42,0.05)' }}
            >
              {/* Colored header bar */}
              <div
                style={{
                  padding: '20px 40px',
                  background: `linear-gradient(135deg, ${post.categoryColor}08 0%, ${post.categoryColor}04 100%)`,
                  borderBottom: `1px solid ${post.categoryColor}20`,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                }}
              >
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 8,
                    background: `${post.categoryColor}15`,
                    border: `1px solid ${post.categoryColor}30`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}
                >
                  <BookOpen size={15} color={post.categoryColor} />
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#0f172a' }}>Full Article</div>
                  <div style={{ fontSize: 11, color: '#64748b' }}>{post.readTime} · {post.category}</div>
                </div>
                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Clock size={11} color="#94a3b8" />
                  <span style={{ fontSize: 11, color: '#94a3b8' }}>{post.date}</span>
                </div>
              </div>

              {/* Key Takeaways */}
              {headings.length > 1 && (
                <div
                  style={{
                    margin: '32px 40px 8px',
                    padding: '20px 24px',
                    borderRadius: 12,
                    background: `linear-gradient(135deg, ${post.categoryColor}06, #f8fafc)`,
                    border: `1px solid ${post.categoryColor}20`,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                    <Lightbulb size={15} color={post.categoryColor} />
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#0f172a', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      What You&apos;ll Learn
                    </span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {headings.slice(0, 5).map((h) => (
                      <div key={h.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                        <CheckCircle2 size={14} color={post.categoryColor} style={{ flexShrink: 0, marginTop: 1 }} />
                        <a
                          href={`#${h.id}`}
                          style={{ fontSize: '13px', color: '#334155', textDecoration: 'none', lineHeight: 1.5 }}
                        >
                          {h.text}
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div
                className="prose"
                style={{ padding: '8px 40px 40px' }}
                dangerouslySetInnerHTML={{ __html: htmlContent }}
              />
            </article>

            {/* Inline platform CTA */}
            <div
              className="rounded-2xl mb-6 overflow-hidden"
              style={{ border: '1px solid #ddd6fe', boxShadow: '0 4px 20px rgba(124,58,237,0.08)' }}
            >
              <div
                style={{
                  padding: '28px 32px',
                  background: 'linear-gradient(135deg, #f5f3ff 0%, #eff6ff 100%)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 24,
                  flexWrap: 'wrap',
                }}
              >
                <div
                  style={{
                    width: 52,
                    height: 52,
                    borderRadius: 14,
                    background: 'linear-gradient(135deg, rgba(124,58,237,0.15), rgba(37,99,235,0.12))',
                    border: '1px solid rgba(124,58,237,0.25)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}
                >
                  <Shield size={24} color="#7c3aed" />
                </div>
                <div style={{ flex: 1, minWidth: 200 }}>
                  <div style={{ fontSize: 16, fontWeight: 700, color: '#0f172a', marginBottom: 4 }}>
                    Detect every misconfiguration in your cloud — automatically
                  </div>
                  <div style={{ fontSize: 13, color: '#475569', lineHeight: 1.6 }}>
                    Threat Engine scans 40+ cloud services against 200+ rules and maps findings to MITRE ATT&amp;CK. Connect your first account in 30 seconds.
                  </div>
                </div>
                <Link
                  href="/contact"
                  className="btn-primary"
                  style={{ padding: '10px 22px', fontSize: '13px', flexShrink: 0 }}
                >
                  Request Demo <ArrowRight size={13} />
                </Link>
              </div>
            </div>

            {/* Tags section */}
            {post.tags && post.tags.length > 0 && (
              <div
                className="rounded-2xl p-6 mb-6"
                style={{ border: '1px solid #e2e8f0', background: '#f8fafc' }}
              >
                <div className="flex items-center gap-2 mb-3">
                  <Tag size={14} style={{ color: '#2563eb' }} />
                  <span style={{ color: '#64748b', fontSize: '13px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Tags
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {post.tags.map((tag) => (
                    <TagPill key={tag} tag={tag} />
                  ))}
                </div>
              </div>
            )}

            {/* Share buttons */}
            <div
              className="rounded-2xl p-6 mb-6"
              style={{ border: '1px solid #e2e8f0', background: '#f8fafc' }}
            >
              <p style={{ color: '#64748b', fontSize: '13px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 14 }}>
                Share this article
              </p>
              <div className="flex flex-wrap gap-3">
                <a
                  href={twitterUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 no-underline transition-all rounded-xl px-4 py-2"
                  style={{
                    background: 'rgba(29,161,242,0.08)',
                    color: '#1d9bf0',
                    border: '1px solid rgba(29,161,242,0.2)',
                    fontSize: '13px',
                    fontWeight: 600,
                  }}
                >
                  <Twitter size={14} />
                  Share on X
                </a>
                <a
                  href={linkedinUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 no-underline transition-all rounded-xl px-4 py-2"
                  style={{
                    background: 'rgba(10,102,194,0.08)',
                    color: '#0a66c2',
                    border: '1px solid rgba(10,102,194,0.2)',
                    fontSize: '13px',
                    fontWeight: 600,
                  }}
                >
                  <Linkedin size={14} />
                  Share on LinkedIn
                </a>
                <CopyLinkButton slug={post.slug} />
              </div>
            </div>

            {/* About the author */}
            <div
              className="rounded-2xl overflow-hidden"
              style={{ border: '1px solid #e2e8f0', boxShadow: '0 2px 12px rgba(15,23,42,0.05)' }}
            >
              {/* Header bar */}
              <div
                style={{
                  padding: '12px 24px',
                  background: 'linear-gradient(135deg, #1e293b, #0f172a)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                }}
              >
                <User size={13} color="#94a3b8" />
                <span style={{ fontSize: '11px', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  About the Author
                </span>
              </div>
              {/* Content */}
              <div
                style={{
                  padding: '24px',
                  background: 'linear-gradient(135deg, #eff6ff 0%, #f5f3ff 100%)',
                }}
              >
                <div className="flex items-start gap-4">
                  <div
                    className="rounded-full flex items-center justify-center font-bold text-white flex-shrink-0"
                    style={{
                      width: 60,
                      height: 60,
                      background: 'linear-gradient(135deg,#2563eb,#7c3aed)',
                      fontSize: '17px',
                      boxShadow: '0 4px 16px rgba(37,99,235,0.3)',
                    }}
                  >
                    AY
                  </div>
                  <div style={{ flex: 1 }}>
                    <div className="flex items-center gap-2 mb-1">
                      <span style={{ color: '#0f172a', fontSize: '16px', fontWeight: 700 }}>
                        Anup Yadav
                      </span>
                      <span
                        className="badge"
                        style={{
                          background: '#eff6ff',
                          color: '#2563eb',
                          border: '1px solid #bfdbfe',
                          fontSize: '9px',
                          padding: '2px 8px',
                        }}
                      >
                        Founder
                      </span>
                    </div>
                    <div style={{ color: '#64748b', fontSize: '12px', marginBottom: 12 }}>
                      Founder &amp; Head of Security Research · Threat Engine
                    </div>
                    <p style={{ color: '#475569', fontSize: '13px', lineHeight: 1.75, marginBottom: 16 }}>
                      Anup leads security research at Threat Engine, focusing on cloud misconfiguration,
                      identity security, and MITRE ATT&amp;CK-mapped threat detection across AWS, Azure,
                      and GCP environments. He has analyzed thousands of cloud accounts and contributed
                      to Threat Engine&apos;s 13+ compliance framework integrations.
                    </p>
                    {/* Stats row */}
                    <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
                      {[
                        { value: '500+', label: 'Accounts audited' },
                        { value: '3,900+', label: 'Findings analyzed' },
                        { value: '13+', label: 'Frameworks covered' },
                      ].map(({ value, label }) => (
                        <div key={label}>
                          <div style={{ fontSize: 18, fontWeight: 800, color: '#2563eb', lineHeight: 1 }}>{value}</div>
                          <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{label}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </main>

          {/* ── Sidebar ─────────────────────────────────────────────── */}
          <aside className="flex flex-col gap-6" style={{ position: 'sticky', top: 96 }}>

            {/* Table of Contents */}
            {headings.length > 0 && (
              <div
                className="rounded-2xl p-5"
                style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 2px 10px rgba(15,23,42,0.05)' }}
              >
                <div className="flex items-center gap-2 mb-4">
                  <BookOpen size={14} style={{ color: '#2563eb' }} />
                  <span
                    style={{
                      color: '#64748b',
                      fontSize: '12px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.07em',
                    }}
                  >
                    Table of Contents
                  </span>
                </div>
                <nav className="flex flex-col gap-1">
                  {headings.map((h, i) => (
                    <a
                      key={h.id}
                      href={`#${h.id}`}
                      className="no-underline flex items-start gap-2 rounded-lg px-2 py-1.5 transition-all hover:text-blue-600 hover:bg-blue-50"
                      style={{ color: '#475569', fontSize: '13px' }}
                    >
                      <span
                        style={{
                          flexShrink: 0,
                          width: 18,
                          height: 18,
                          borderRadius: 4,
                          background: '#eff6ff',
                          color: '#2563eb',
                          fontSize: '9px',
                          fontWeight: 700,
                          display: 'inline-flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          marginTop: 1,
                        }}
                      >
                        {i + 1}
                      </span>
                      <span style={{ lineHeight: 1.4 }}>{h.text}</span>
                    </a>
                  ))}
                </nav>
              </div>
            )}

            {/* More Articles */}
            {otherPosts.length > 0 && (
              <div
                className="rounded-2xl p-5"
                style={{ border: '1px solid #e2e8f0', background: '#ffffff', boxShadow: '0 2px 10px rgba(15,23,42,0.05)' }}
              >
                <div className="flex items-center gap-2 mb-4">
                  <BookOpen size={14} style={{ color: '#2563eb' }} />
                  <span
                    style={{
                      color: '#64748b',
                      fontSize: '12px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.07em',
                    }}
                  >
                    More Articles
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  {otherPosts.map((p) => (
                    <SidebarArticleCard key={p.slug} post={p} />
                  ))}
                </div>
                <div className="mt-4 pt-3" style={{ borderTop: '1px solid #f1f5f9' }}>
                  <Link
                    href="/blog"
                    className="no-underline flex items-center gap-1 transition-colors"
                    style={{ color: '#2563eb', fontSize: '12px', fontWeight: 600 }}
                  >
                    View all articles <ArrowRight size={11} />
                  </Link>
                </div>
              </div>
            )}

            {/* Newsletter signup */}
            <div
              className="rounded-2xl p-5"
              style={{
                border: '1px solid #bfdbfe',
                background: 'linear-gradient(135deg, #eff6ff 0%, #ffffff 100%)',
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <Mail size={14} style={{ color: '#2563eb' }} />
                <span style={{ color: '#0f172a', fontSize: '13px', fontWeight: 700 }}>
                  Security Digest
                </span>
              </div>
              <p style={{ color: '#475569', fontSize: '12px', marginBottom: 14, lineHeight: 1.6 }}>
                New research and threat intelligence, delivered to your inbox.
              </p>
              <div className="flex flex-col gap-2">
                <input
                  type="email"
                  placeholder="you@company.com"
                  className="rounded-lg px-3 py-2"
                  style={{
                    background: '#ffffff',
                    border: '1px solid #e2e8f0',
                    color: '#0f172a',
                    fontSize: '13px',
                    outline: 'none',
                    width: '100%',
                  }}
                />
                <button
                  className="btn-primary justify-center"
                  style={{ padding: '9px 16px', fontSize: '13px', width: '100%' }}
                >
                  Subscribe <ArrowRight size={12} />
                </button>
              </div>
              <p style={{ color: '#94a3b8', fontSize: '11px', marginTop: 10, textAlign: 'center' }}>
                No spam. Unsubscribe any time.
              </p>
            </div>

            {/* CTA card */}
            <div
              className="rounded-2xl p-5 text-center"
              style={{
                border: '1px solid #ddd6fe',
                background: 'linear-gradient(135deg, #f5f3ff 0%, #ffffff 100%)',
              }}
            >
              <div
                className="rounded-full mx-auto flex items-center justify-center mb-3"
                style={{
                  width: 40,
                  height: 40,
                  background: 'rgba(124,58,237,0.1)',
                  border: '1px solid rgba(124,58,237,0.2)',
                }}
              >
                <User size={16} style={{ color: '#7c3aed' }} />
              </div>
              <p style={{ color: '#0f172a', fontSize: '13px', fontWeight: 700, marginBottom: 6 }}>
                See it in action
              </p>
              <p style={{ color: '#475569', fontSize: '12px', marginBottom: 14, lineHeight: 1.55 }}>
                Request a personalized demo of Threat Engine for your cloud environment.
              </p>
              <Link
                href="/contact"
                className="btn-primary justify-center"
                style={{ padding: '9px 16px', fontSize: '13px', width: '100%' }}
              >
                Request Demo <ArrowRight size={12} />
              </Link>
            </div>
          </aside>
        </div>
      </div>

      {/* ── Related posts ────────────────────────────────────────────── */}
      {related.length > 0 && (
        <section style={{ paddingBottom: 96 }}>
          <div className="container">
            <div
              className="pt-12"
              style={{ borderTop: '1px solid #e2e8f0' }}
            >
              <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-3">
                  <div
                    style={{
                      width: 3,
                      height: 20,
                      borderRadius: 2,
                      background: 'linear-gradient(#2563eb,#7c3aed)',
                    }}
                  />
                  <span
                    style={{
                      color: '#64748b',
                      fontSize: '13px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                    }}
                  >
                    Related Articles
                  </span>
                </div>
                <Link
                  href="/blog"
                  className="inline-flex items-center gap-1 no-underline"
                  style={{ color: '#2563eb', fontSize: '13px', fontWeight: 600 }}
                >
                  All articles <ArrowRight size={13} />
                </Link>
              </div>

              <div
                className="grid gap-6"
                style={{ gridTemplateColumns: 'repeat(auto-fill,minmax(300px,1fr))' }}
              >
                {related.map((p) => (
                  <RelatedPostCard key={p.slug} post={p} />
                ))}
              </div>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
