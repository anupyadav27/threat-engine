'use client';

/**
 * ThreatBadgeContext — lightweight context for the live threat count badge
 * displayed next to the "Threats" nav item in the Sidebar.
 *
 * The Command Room page populates this after it fetches BFF data:
 *   const { setBadgeCount } = useThreatBadge();
 *   setBadgeCount('threatCriticalHighCount', critical + high);
 *
 * The Sidebar reads from badgeCounts:
 *   const { badgeCounts } = useThreatBadge();
 *   badgeCounts['threatCriticalHighCount']  // → number
 */

import { createContext, useContext, useState, useCallback } from 'react';

const ThreatBadgeContext = createContext({
    badgeCounts: {},
    setBadgeCount: () => {},
});

/**
 * ThreatBadgeProvider — wrap AppShell (or the root layout) with this provider.
 * @param {React.ReactNode} children
 */
export function ThreatBadgeProvider({ children }) {
    const [badgeCounts, setBadgeCounts] = useState({});

    const setBadgeCount = useCallback((key, count) => {
        setBadgeCounts((prev) => {
            if (prev[key] === count) return prev;
            return { ...prev, [key]: count };
        });
    }, []);

    return (
        <ThreatBadgeContext.Provider value={{ badgeCounts, setBadgeCount }}>
            {children}
        </ThreatBadgeContext.Provider>
    );
}

/**
 * useThreatBadge — access badge counts and setter.
 * @returns {{ badgeCounts: Record<string, number>, setBadgeCount: (key: string, count: number) => void }}
 */
export function useThreatBadge() {
    return useContext(ThreatBadgeContext);
}

export default ThreatBadgeContext;
