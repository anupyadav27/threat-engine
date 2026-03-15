'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Shield, ChevronDown, Menu, X, ArrowRight, Cloud, Lock, BarChart3, Code2, Search, Globe } from 'lucide-react';

const platformItems = [
  { icon: Search,   label: 'Threat Detection', desc: 'MITRE ATT&CK mapped findings',   href: '/platform#threat',    color: '#dc2626' },
  { icon: Lock,     label: 'IAM Security',     desc: '57 rules for identity posture',   href: '/platform#iam',       color: '#7c3aed' },
  { icon: BarChart3,label: 'Compliance',        desc: '13+ frameworks automated',         href: '/platform#compliance',color: '#059669' },
  { icon: Globe,    label: 'Asset Inventory',  desc: '40+ cloud services mapped',        href: '/platform#inventory', color: '#2563eb' },
  { icon: Code2,    label: 'Code Security',    desc: 'IaC scanning in 14 languages',     href: '/platform#secops',   color: '#ea580c' },
  { icon: Cloud,    label: 'Data Security',    desc: '62 data classification rules',     href: '/platform#datasec',  color: '#0891b2' },
];

export default function Navbar() {
  const [scrolled, setScrolled]       = useState(false);
  const [mobileOpen, setMobileOpen]   = useState(false);
  const [platformOpen, setPlatformOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll);
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <nav
      className="fixed top-0 left-0 right-0 z-50 transition-all duration-300"
      style={{
        background: scrolled ? 'rgba(255,255,255,0.97)' : 'transparent',
        backdropFilter: scrolled ? 'blur(20px)' : 'none',
        borderBottom: scrolled ? '1px solid #e2e8f0' : 'none',
        boxShadow: scrolled ? '0 1px 12px rgba(15,23,42,0.06)' : 'none',
      }}
    >
      <div className="container">
        <div className="flex items-center justify-between h-16">

          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5 no-underline">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center shadow-sm"
              style={{ background: 'linear-gradient(135deg,#2563eb,#7c3aed)' }}
            >
              <Shield size={16} className="text-white" />
            </div>
            <span className="font-bold text-lg tracking-tight" style={{ color: '#0f172a' }}>
              THREAT<span className="gradient-text">ENGINE</span>
            </span>
          </Link>

          {/* Desktop links */}
          <div className="hidden md:flex items-center gap-5">
            {/* Platform dropdown */}
            <div
              className="relative"
              onMouseEnter={() => setPlatformOpen(true)}
              onMouseLeave={() => setPlatformOpen(false)}
            >
              <button
                className="flex items-center gap-1 text-sm font-medium transition-colors bg-transparent border-none cursor-pointer"
                style={{ color: platformOpen ? '#2563eb' : '#475569' }}
              >
                Platform
                <ChevronDown size={14} className={`transition-transform ${platformOpen ? 'rotate-180' : ''}`} />
              </button>

              {platformOpen && (
                <div
                  className="absolute top-full left-1/2 -translate-x-1/2 mt-3 w-[480px] rounded-2xl p-3"
                  style={{
                    background: '#ffffff',
                    border: '1px solid #e2e8f0',
                    boxShadow: '0 20px 60px rgba(15,23,42,0.12)',
                  }}
                >
                  <div className="grid grid-cols-2 gap-1">
                    {platformItems.map((item) => (
                      <Link
                        key={item.label}
                        href={item.href}
                        className="flex items-start gap-3 p-3 rounded-xl transition-all no-underline group"
                        style={{ color: 'inherit' }}
                        onMouseEnter={e => e.currentTarget.style.background = '#f8fafc'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                      >
                        <div
                          className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
                          style={{ background: `${item.color}15` }}
                        >
                          <item.icon size={14} style={{ color: item.color }} />
                        </div>
                        <div>
                          <div className="text-sm font-semibold" style={{ color: '#0f172a' }}>{item.label}</div>
                          <div className="text-xs mt-0.5" style={{ color: '#94a3b8' }}>{item.desc}</div>
                        </div>
                      </Link>
                    ))}
                  </div>
                  <div
                    className="mt-2 pt-2 flex items-center justify-end px-2"
                    style={{ borderTop: '1px solid #f1f5f9' }}
                  >
                    <Link href="/platform" className="text-xs font-semibold no-underline" style={{ color: '#2563eb' }}>
                      View full platform →
                    </Link>
                  </div>
                </div>
              )}
            </div>

            {[
              { href: '/solutions', label: 'Solutions' },
              { href: '/pricing',   label: 'Pricing' },
              { href: '/blog',      label: 'Blog' },
              { href: '/contact',   label: 'Contact' },
            ].map(item => (
              <Link
                key={item.href}
                href={item.href}
                className="text-sm font-medium no-underline transition-colors"
                style={{ color: '#475569' }}
                onMouseEnter={e => e.target.style.color = '#0f172a'}
                onMouseLeave={e => e.target.style.color = '#475569'}
              >
                {item.label}
              </Link>
            ))}
          </div>

          {/* CTAs */}
          <div className="hidden md:flex items-center gap-3">
            <a
              href="http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/ui/auth/login"
              className="text-sm font-semibold no-underline transition-colors px-4 py-2 rounded-lg"
              style={{ color: '#475569' }}
              onMouseEnter={e => { e.currentTarget.style.color = '#0f172a'; e.currentTarget.style.background = '#f1f5f9'; }}
              onMouseLeave={e => { e.currentTarget.style.color = '#475569'; e.currentTarget.style.background = 'transparent'; }}
            >
              Sign In
            </a>
            <Link href="/contact" className="btn-primary" style={{ padding: '8px 20px', fontSize: '14px' }}>
              Request Demo <ArrowRight size={14} />
            </Link>
          </div>

          {/* Mobile hamburger */}
          <button
            className="md:hidden p-2 rounded-lg"
            style={{ color: '#475569' }}
            onClick={() => setMobileOpen(!mobileOpen)}
          >
            {mobileOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div
          className="md:hidden"
          style={{ background: '#ffffff', borderTop: '1px solid #e2e8f0', boxShadow: '0 8px 24px rgba(15,23,42,0.1)' }}
        >
          <div className="container py-5 flex flex-col gap-4">
            {[
              { href: '/platform',  label: 'Platform' },
              { href: '/solutions', label: 'Solutions' },
              { href: '/pricing',   label: 'Pricing' },
              { href: '/blog',      label: 'Blog' },
              { href: '/contact',   label: 'Contact' },
            ].map(item => (
              <Link
                key={item.href}
                href={item.href}
                className="text-sm font-medium no-underline"
                style={{ color: '#475569' }}
                onClick={() => setMobileOpen(false)}
              >
                {item.label}
              </Link>
            ))}
            <div className="flex items-center gap-3 pt-3" style={{ borderTop: '1px solid #e2e8f0' }}>
              <a
                href="http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/ui/auth/login"
                className="btn-secondary flex-1 justify-center text-sm no-underline"
              >
                Sign In
              </a>
              <Link href="/contact" className="btn-primary flex-1 justify-center text-sm" onClick={() => setMobileOpen(false)}>
                Request Demo
              </Link>
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
