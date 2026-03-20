'use client';

import { usePathname } from 'next/navigation';
import Link from 'next/link';

const THREAT_NAV = [
  { label: 'Overview', href: '/threats' },
  { label: 'Analytics', href: '/threats/analytics' },
  { label: 'Attack Paths', href: '/threats/attack-paths' },
  { label: 'Blast Radius', href: '/threats/blast-radius' },
  { label: 'Internet Exposed', href: '/threats/internet-exposed' },
  { label: 'Toxic Combos', href: '/threats/toxic-combinations' },
  { label: 'Graph', href: '/threats/graph' },
  { label: 'Hunting', href: '/threats/hunting' },
];

/**
 * Horizontal sub-navigation bar for Threats module pages.
 * Highlights the active item with an accent-colored underline.
 * Scrolls horizontally on mobile (overflow-x-auto).
 */
export default function ThreatsSubNav() {
  const pathname = usePathname();

  return (
    <nav
      className="flex items-center gap-1 overflow-x-auto rounded-lg px-1 py-1"
      style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}
    >
      {THREAT_NAV.map((item) => {
        const isActive = pathname === item.href;
        return (
          <Link
            key={item.href}
            href={item.href}
            className="relative whitespace-nowrap px-4 py-2 text-sm font-medium transition-colors duration-150 rounded-md"
            style={{
              color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
              backgroundColor: isActive ? 'var(--bg-secondary)' : 'transparent',
            }}
          >
            {item.label}
            {isActive && (
              <span
                className="absolute bottom-0 left-2 right-2 h-0.5 rounded-full"
                style={{ backgroundColor: 'var(--accent-primary)' }}
              />
            )}
          </Link>
        );
      })}
    </nav>
  );
}
