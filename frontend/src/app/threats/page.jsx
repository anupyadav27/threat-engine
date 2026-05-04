'use client';

/**
 * /threats — Threat Command Room (THREAT-UI-01)
 *
 * Replaces the legacy flat detection table with the three-zone Command Room
 * layout: Pulse Bar (Zone A) + Scenario Cards (Zone B) + Preview Panel (Zone C).
 *
 * All data is fetched from BFF GET /api/v1/views/threat-command-room.
 * RBAC: threats:read permission is required; viewer role can access this page.
 * Auth forwarded via X-Auth-Context header (no DEV_BYPASS_AUTH).
 */

import CommandRoom from '@/components/domain/threats/CommandRoom';

export default function ThreatsPage() {
    return <CommandRoom />;
}
