'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const THREAT_NAV = [
    { label: 'Threat Center', href: '/threats-v1'     },
    { label: 'Graph',         href: '/threats/graph'  },
    { label: 'Trends',        href: '/threats/trends' },
];

export default function ThreatsSubNav({ criticalHighCount = 0 }) {
    const pathname = usePathname();
    const isActive = (href) => pathname === href || pathname.startsWith(href + '/');

    return (
        <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 0,
            borderBottom: '1px solid var(--border-primary)',
            marginBottom: 16,
            overflowX: 'auto',
        }}>
            {THREAT_NAV.map((tab) => {
                const active = isActive(tab.href);
                const showBadge = tab.href === '/threats-v1' && criticalHighCount > 0;
                return (
                    <Link
                        key={tab.href}
                        href={tab.href}
                        style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 6,
                            padding: '10px 18px',
                            fontSize: 13,
                            fontWeight: active ? 700 : 500,
                            color: active ? '#EA580C' : 'var(--text-muted)',
                            borderBottom: active ? '2px solid #EA580C' : '2px solid transparent',
                            marginBottom: -1,
                            textDecoration: 'none',
                            whiteSpace: 'nowrap',
                            transition: 'color 150ms ease',
                        }}
                        onMouseEnter={(e) => { if (!active) e.currentTarget.style.color = 'var(--text-secondary)'; }}
                        onMouseLeave={(e) => { if (!active) e.currentTarget.style.color = 'var(--text-muted)'; }}
                    >
                        {tab.label}
                        {showBadge && (
                            <span style={{
                                backgroundColor: '#DC2626', color: '#fff',
                                borderRadius: 9999, fontSize: 10, fontWeight: 700,
                                padding: '1px 6px', lineHeight: '16px',
                            }}>
                                {criticalHighCount > 99 ? '99+' : criticalHighCount}
                            </span>
                        )}
                    </Link>
                );
            })}
        </div>
    );
}
