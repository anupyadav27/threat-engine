'use client';

/**
 * CloudProviderBadge — colored chip for cloud provider names.
 * Supports AWS / Azure / GCP / OCI / AliCloud / IBM.
 *
 * @param {{ provider: string, size?: 'sm' | 'md' }} props
 */

const PROVIDER_STYLES = {
  AWS:      { bg: 'rgba(255,153,0,0.15)',   text: '#FF9900',  label: 'AWS'      },
  Azure:    { bg: 'rgba(0,120,212,0.15)',   text: '#0078D4',  label: 'Azure'    },
  GCP:      { bg: 'rgba(66,133,244,0.15)', text: '#4285F4',  label: 'GCP'      },
  OCI:      { bg: 'rgba(248,0,0,0.15)',    text: '#F80000',  label: 'OCI'      },
  AliCloud: { bg: 'rgba(255,106,0,0.15)',  text: '#FF6A00',  label: 'AliCloud' },
  IBM:      { bg: 'rgba(31,112,193,0.15)', text: '#1F70C1',  label: 'IBM'      },
};

export default function CloudProviderBadge({ provider, size = 'sm' }) {
  const key = (provider || '').toUpperCase() === 'AWS' ? 'AWS'
    : (provider || '').charAt(0).toUpperCase() + (provider || '').slice(1).toLowerCase();
  const style = PROVIDER_STYLES[key] || PROVIDER_STYLES[provider] || { bg: 'rgba(100,100,100,0.15)', text: '#888', label: provider };

  const padding = size === 'md' ? 'px-3 py-1.5' : 'px-2 py-0.5';
  const fontSize = size === 'md' ? 'text-xs' : 'text-xs';

  return (
    <span
      className={`inline-flex items-center font-semibold rounded ${padding} ${fontSize} whitespace-nowrap`}
      style={{ backgroundColor: style.bg, color: style.text }}
    >
      {style.label}
    </span>
  );
}
