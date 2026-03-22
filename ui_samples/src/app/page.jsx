'use client';

import Link from 'next/link';
import {
  LayoutDashboard,
  UserPlus,
  Radar,
  Server,
  ShieldAlert,
  ClipboardCheck,
  KeyRound,
  Database,
  Code,
  TrendingUp,
  Settings,
  ArrowRight,
} from 'lucide-react';

const ICON_MAP = {
  LayoutDashboard,
  UserPlus,
  Radar,
  Server,
  ShieldAlert,
  ClipboardCheck,
  KeyRound,
  Database,
  Code,
  TrendingUp,
  Settings,
};

const sections = [
  {
    title: 'Dashboard',
    href: '/dashboard',
    icon: 'LayoutDashboard',
    description: 'KPI overview, threat severity distribution, compliance trends, and recent scan activity.',
    color: 'from-blue-500/20 to-blue-600/5',
    border: 'border-blue-500/30',
  },
  {
    title: 'Onboarding',
    href: '/onboarding',
    icon: 'UserPlus',
    description: 'Manage cloud accounts, add new providers via wizard, and validate credentials.',
    color: 'from-emerald-500/20 to-emerald-600/5',
    border: 'border-emerald-500/30',
  },
  {
    title: 'Scans',
    href: '/scans',
    icon: 'Radar',
    description: 'View scan history, trigger new scans, and monitor pipeline stage progress.',
    color: 'from-cyan-500/20 to-cyan-600/5',
    border: 'border-cyan-500/30',
  },
  {
    title: 'Inventory',
    href: '/inventory',
    icon: 'Server',
    description: 'Browse cloud assets, view configurations, relationships, and drift detection.',
    color: 'from-violet-500/20 to-violet-600/5',
    border: 'border-violet-500/30',
  },
  {
    title: 'Threats',
    href: '/threats',
    icon: 'ShieldAlert',
    description: 'Threat list with MITRE mapping, attack path visualization, and remediation queue.',
    color: 'from-red-500/20 to-red-600/5',
    border: 'border-red-500/30',
  },
  {
    title: 'Compliance',
    href: '/compliance',
    icon: 'ClipboardCheck',
    description: 'Framework compliance scores, control drill-downs, and downloadable reports.',
    color: 'from-amber-500/20 to-amber-600/5',
    border: 'border-amber-500/30',
  },
  {
    title: 'IAM Security',
    href: '/iam',
    icon: 'KeyRound',
    description: 'IAM findings across 6 modules with rule details and remediation guidance.',
    color: 'from-orange-500/20 to-orange-600/5',
    border: 'border-orange-500/30',
  },
  {
    title: 'Data Security',
    href: '/datasec',
    icon: 'Database',
    description: 'Data catalog, classification, lineage, residency compliance, and activity monitoring.',
    color: 'from-pink-500/20 to-pink-600/5',
    border: 'border-pink-500/30',
  },
  {
    title: 'Code Security',
    href: '/secops',
    icon: 'Code',
    description: 'IaC scan history, findings browser, and rule library across 14 languages.',
    color: 'from-teal-500/20 to-teal-600/5',
    border: 'border-teal-500/30',
  },
  {
    title: 'Risk Quantification',
    href: '/risk',
    icon: 'TrendingUp',
    description: 'FAIR-model financial risk exposure, scenario analysis, and risk trends.',
    color: 'from-indigo-500/20 to-indigo-600/5',
    border: 'border-indigo-500/30',
  },
  {
    title: 'Settings',
    href: '/settings',
    icon: 'Settings',
    description: 'Engine health status, platform configuration, and service versions.',
    color: 'from-slate-500/20 to-slate-600/5',
    border: 'border-slate-500/30',
  },
];

export default function HomePage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>Threat Engine CSPM</h1>
        <p className="mt-2" style={{ color: 'var(--text-tertiary)' }}>
          Cloud Security Posture Management — sample UI pages for all platform sections.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {sections.map((section) => {
          const Icon = ICON_MAP[section.icon];
          return (
            <Link
              key={section.href}
              href={section.href}
              className={`group relative rounded-xl border ${section.border} bg-gradient-to-br ${section.color} p-5 transition-all hover:scale-[1.02] hover:shadow-lg hover:shadow-black/20`}
            >
              <div className="flex items-start justify-between">
                <div className="rounded-lg p-2.5" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                  {Icon && <Icon className="h-5 w-5" style={{ color: 'var(--text-secondary)' }} />}
                </div>
                <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" style={{ color: 'var(--text-tertiary)', '--hover-color': 'var(--text-secondary)' }} />
              </div>
              <h2 className="mt-3 text-lg font-semibold text-white">{section.title}</h2>
              <p className="mt-1 text-sm text-slate-400 leading-relaxed">{section.description}</p>
            </Link>
          );
        })}
      </div>

      <div className="rounded-xl border p-5 transition-colors duration-200" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}>
        <h3 className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>API Configuration</h3>
        <div className="mt-2 flex flex-wrap gap-4 text-xs" style={{ color: 'var(--text-muted)' }}>
          <span>Base URL: <code style={{ color: 'var(--text-tertiary)' }}>{process.env.NEXT_PUBLIC_API_BASE || 'Not configured'}</code></span>
          <span>Tenant: <code style={{ color: 'var(--text-tertiary)' }}>{process.env.NEXT_PUBLIC_TENANT_ID?.slice(0, 8) || 'Not set'}...</code></span>
        </div>
      </div>
    </div>
  );
}
