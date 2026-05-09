'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

/**
 * TrialCountdownChip — amber nav chip showing remaining trial days.
 *
 * Renders only when status === 'trialing' AND trial_days_remaining <= 7.
 * Polls /gateway/api/v1/billing/trial-status every 60 seconds.
 * Fail-open: renders nothing on fetch error or non-200 response.
 */
export default function TrialCountdownChip() {
  const [trialData, setTrialData] = useState(null);

  async function fetchStatus() {
    try {
      const resp = await fetch('/gateway/api/v1/billing/trial-status', {
        credentials: 'include',
      });
      if (resp.ok) {
        const data = await resp.json();
        setTrialData(data);
      }
      // Non-200: fail-open — leave trialData unchanged
    } catch {
      // Network error: fail-open — render nothing
    }
  }

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 60_000);
    return () => clearInterval(interval);
  }, []);

  if (
    !trialData ||
    !trialData.applicable ||
    trialData.status !== 'trialing' ||
    trialData.trial_days_remaining === null ||
    trialData.trial_days_remaining === undefined ||
    trialData.trial_days_remaining > 7
  ) {
    return null;
  }

  const days = trialData.trial_days_remaining;

  return (
    <Link href="/billing" style={{ textDecoration: 'none' }}>
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 4,
          background: '#f59e0b',
          color: '#1c1917',
          borderRadius: 12,
          padding: '3px 10px',
          fontSize: 12,
          fontWeight: 600,
          cursor: 'pointer',
          whiteSpace: 'nowrap',
        }}
        aria-label={`${days} day${days !== 1 ? 's' : ''} left in trial`}
      >
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <circle cx="12" cy="12" r="10" />
          <polyline points="12 6 12 12 16 14" />
        </svg>
        {days} day{days !== 1 ? 's' : ''} left in trial
      </span>
    </Link>
  );
}
