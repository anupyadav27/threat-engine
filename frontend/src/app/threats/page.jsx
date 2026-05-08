'use client';

/**
 * /threats — Threat Command Room (THREATS-UI-01)
 *
 * Wraps CommandRoom in a Suspense boundary so that useSearchParams()
 * inside CommandRoom satisfies the Next.js 15 static-generation requirement.
 *
 * All data is fetched from BFF GET /api/v1/views/threat-command-room.
 * RBAC: threats:read permission is required; viewer role can access this page.
 * Auth forwarded via X-Auth-Context header (no DEV_BYPASS_AUTH).
 */

import { Suspense } from 'react';
import CommandRoom from '@/components/domain/threats/CommandRoom';

function CommandRoomFallback() {
    return (
        <div
            style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 12,
            }}
        >
            {/* Minimal pulse bar skeleton */}
            <div
                style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 10,
                    height: 72,
                    animation: 'pulse 1.5s ease-in-out infinite',
                }}
            />
            {/* Filter bar skeleton */}
            <div
                style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 8,
                    height: 44,
                    animation: 'pulse 1.5s ease-in-out infinite',
                }}
            />
            {/* Card skeletons */}
            {[1, 2, 3, 4, 5].map((i) => (
                <div
                    key={i}
                    style={{
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 8,
                        height: 88,
                        animation: 'pulse 1.5s ease-in-out infinite',
                    }}
                />
            ))}
        </div>
    );
}

export default function ThreatsPage() {
    return (
        <Suspense fallback={<CommandRoomFallback />}>
            <CommandRoom />
        </Suspense>
    );
}
