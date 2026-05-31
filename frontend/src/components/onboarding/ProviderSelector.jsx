'use client';

/**
 * ProviderSelector — CSP icon grid for Step 2 of the onboarding wizard.
 * Renders a clickable card for each provider. Selected provider gets a
 * highlight border and checkmark badge.
 */

import { Check } from 'lucide-react';

// Provider metadata: color + display name + SVG abbreviation
const PROVIDERS = [
  {
    key: 'aws',
    name: 'Amazon Web Services',
    short: 'AWS',
    color: '#FF9900',
    bgColor: 'rgba(255,153,0,0.12)',
    description: 'EC2, S3, IAM, RDS and 40+ services',
  },
  {
    key: 'azure',
    name: 'Microsoft Azure',
    short: 'Azure',
    color: '#0078D4',
    bgColor: 'rgba(0,120,212,0.12)',
    description: 'VMs, Blob Storage, AAD, AKS and more',
  },
  {
    key: 'gcp',
    name: 'Google Cloud Platform',
    short: 'GCP',
    color: '#4285F4',
    bgColor: 'rgba(66,133,244,0.12)',
    description: 'Compute Engine, GKE, IAM and more',
  },
  {
    key: 'oci',
    name: 'Oracle Cloud Infrastructure',
    short: 'OCI',
    color: '#F80000',
    bgColor: 'rgba(248,0,0,0.10)',
    description: 'Compute, Object Storage, VCN and more',
  },
  {
    key: 'alicloud',
    name: 'Alibaba Cloud',
    short: 'AliCloud',
    color: '#FF6A00',
    bgColor: 'rgba(255,106,0,0.12)',
    description: 'ECS, OSS, RAM, VPC and more',
  },
  {
    key: 'ibm',
    name: 'IBM Cloud',
    short: 'IBM',
    color: '#1F70C1',
    bgColor: 'rgba(31,112,193,0.12)',
    description: 'Virtual Servers, COS, IAM and more',
  },
  {
    key: 'k8s',
    name: 'Kubernetes',
    short: 'K8s',
    color: '#326CE5',
    bgColor: 'rgba(50,108,229,0.12)',
    description: 'Pods, RBAC, network policies and more',
  },
];

export default function ProviderSelector({ selected, onChange }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
      {PROVIDERS.map((p) => {
        const isSelected = selected === p.key;
        return (
          <button
            key={p.key}
            type="button"
            onClick={() => onChange(p.key)}
            className="relative text-left rounded-xl border p-4 transition-all hover:scale-[1.02] focus:outline-none focus:ring-2 focus:ring-blue-500"
            style={{
              backgroundColor: isSelected ? p.bgColor : 'var(--bg-card)',
              borderColor: isSelected ? p.color : 'var(--border-primary)',
              borderWidth: isSelected ? '2px' : '1px',
            }}
          >
            {/* Selected checkmark badge */}
            {isSelected && (
              <span
                className="absolute top-2 right-2 w-5 h-5 rounded-full flex items-center justify-center"
                style={{ backgroundColor: p.color }}
              >
                <Check size={11} color="white" />
              </span>
            )}

            {/* Provider logo abbreviation */}
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center mb-3 text-sm font-bold"
              style={{ backgroundColor: p.bgColor, color: p.color }}
            >
              {p.short}
            </div>

            <div className="text-sm font-semibold leading-tight" style={{ color: 'var(--text-primary)' }}>
              {p.name}
            </div>
            <div className="mt-1 text-[11px] leading-tight" style={{ color: 'var(--text-muted)' }}>
              {p.description}
            </div>
          </button>
        );
      })}
    </div>
  );
}
