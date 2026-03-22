'use client';
import Link from 'next/link';
import { Shield, Twitter, Linkedin, Github, Mail } from 'lucide-react';

const footerLinks = {
  Platform: [
    { label: 'Threat Detection', href: '/platform#threat' },
    { label: 'IAM Security',     href: '/platform#iam' },
    { label: 'Compliance',       href: '/platform#compliance' },
    { label: 'Asset Inventory',  href: '/platform#inventory' },
    { label: 'Code Security',    href: '/platform#secops' },
    { label: 'Data Security',    href: '/platform#datasec' },
  ],
  Solutions: [
    { label: 'For AWS',          href: '/solutions#aws' },
    { label: 'For Azure',        href: '/solutions#azure' },
    { label: 'For GCP',          href: '/solutions#gcp' },
    { label: 'For OCI',          href: '/solutions#oci' },
    { label: 'For Enterprises',  href: '/solutions#enterprise' },
    { label: 'For DevSecOps',    href: '/solutions#devsecops' },
  ],
  Resources: [
    { label: 'Blog',             href: '/blog' },
    { label: 'Documentation',    href: '#' },
    { label: 'CSPM Glossary',    href: '/blog' },
    { label: 'Security Research',href: '/blog' },
    { label: 'Release Notes',    href: '#' },
  ],
  Company: [
    { label: 'About',            href: '/contact' },
    { label: 'Contact',          href: '/contact' },
    { label: 'Request Demo',     href: '/contact' },
    { label: 'Pricing',          href: '/pricing' },
  ],
};

const frameworks = ['CIS', 'NIST', 'ISO 27001', 'PCI-DSS', 'HIPAA', 'GDPR', 'SOC 2'];

export default function Footer() {
  return (
    <footer style={{ background: '#f8fafc', borderTop: '1px solid #e2e8f0' }}>
      <div className="container" style={{ paddingTop: 64, paddingBottom: 48 }}>
        <div className="grid gap-12" style={{ gridTemplateColumns: '280px 1fr' }}>

          {/* Brand block */}
          <div>
            <Link href="/" className="flex items-center gap-2.5 no-underline mb-4">
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

            <p className="text-sm leading-relaxed mb-5" style={{ color: '#64748b' }}>
              The most comprehensive CSPM platform for multi-cloud environments.
              Protect AWS, Azure, GCP, OCI, AliCloud, and IBM Cloud with a single pane of glass.
            </p>

            {/* Framework badges */}
            <div className="flex flex-wrap gap-1.5 mb-5">
              {frameworks.map(f => (
                <span
                  key={f}
                  className="text-xs px-2.5 py-1 rounded-full font-medium"
                  style={{ background: '#eff6ff', color: '#2563eb', border: '1px solid #bfdbfe' }}
                >
                  {f}
                </span>
              ))}
            </div>

            {/* Social */}
            <div className="flex gap-2">
              {[
                { icon: Twitter,  href: '#',                              label: 'Twitter' },
                { icon: Linkedin, href: '#',                              label: 'LinkedIn' },
                { icon: Github,   href: '#',                              label: 'GitHub' },
                { icon: Mail,     href: 'mailto:hello@threatengine.io',   label: 'Email' },
              ].map(s => (
                <a
                  key={s.label}
                  href={s.href}
                  aria-label={s.label}
                  className="w-9 h-9 rounded-lg flex items-center justify-center transition-all no-underline"
                  style={{ background: '#ffffff', color: '#94a3b8', border: '1px solid #e2e8f0' }}
                  onMouseEnter={e => { e.currentTarget.style.background = '#eff6ff'; e.currentTarget.style.color = '#2563eb'; e.currentTarget.style.borderColor = '#bfdbfe'; }}
                  onMouseLeave={e => { e.currentTarget.style.background = '#ffffff'; e.currentTarget.style.color = '#94a3b8'; e.currentTarget.style.borderColor = '#e2e8f0'; }}
                >
                  <s.icon size={15} />
                </a>
              ))}
            </div>
          </div>

          {/* Link columns */}
          <div className="grid grid-cols-4 gap-8">
            {Object.entries(footerLinks).map(([section, links]) => (
              <div key={section}>
                <h4
                  className="text-xs font-bold uppercase tracking-widest mb-4"
                  style={{ color: '#94a3b8' }}
                >
                  {section}
                </h4>
                <ul style={{ listStyle: 'none', padding: 0, margin: 0 }} className="space-y-2.5">
                  {links.map(link => (
                    <li key={link.label}>
                      <Link
                        href={link.href}
                        className="text-sm no-underline transition-colors"
                        style={{ color: '#64748b' }}
                        onMouseEnter={e => e.target.style.color = '#2563eb'}
                        onMouseLeave={e => e.target.style.color = '#64748b'}
                      >
                        {link.label}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom bar */}
      <div style={{ borderTop: '1px solid #e2e8f0' }}>
        <div className="container" style={{ paddingTop: 20, paddingBottom: 20 }}>
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <p className="text-sm" style={{ color: '#94a3b8' }}>
              © 2026 Threat Engine, Inc. All rights reserved.
            </p>
            <div className="flex items-center gap-6">
              {['Privacy Policy', 'Terms of Service', 'Security', 'Cookie Policy'].map(item => (
                <a
                  key={item}
                  href="#"
                  className="text-xs no-underline transition-colors"
                  style={{ color: '#94a3b8' }}
                  onMouseEnter={e => e.target.style.color = '#475569'}
                  onMouseLeave={e => e.target.style.color = '#94a3b8'}
                >
                  {item}
                </a>
              ))}
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
