'use client';

import { useRouter } from 'next/navigation';
import OnboardingWizard from '@/components/domain/OnboardingWizard';

export default function OnboardingWizardPage() {
  const router = useRouter();

  // The wizard handles account creation, credential storage, and schedule
  // creation internally. onComplete fires after all steps succeed.
  const handleWizardComplete = () => {
    router.push('/onboarding');
  };

  const handleWizardCancel = () => {
    router.push('/onboarding');
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>Add Account</h1>
        <p className="mt-1" style={{ color: 'var(--text-tertiary)' }}>
          Complete the wizard to onboard a cloud, agent, database, or code security account
        </p>
      </div>

      <div className="rounded-xl border p-8 transition-colors duration-200"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <OnboardingWizard
          onComplete={handleWizardComplete}
          onCancel={handleWizardCancel}
        />
      </div>
    </div>
  );
}
