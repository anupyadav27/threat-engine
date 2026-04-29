'use client';

import { useRouter } from 'next/navigation';
import { postToEngine } from '@/lib/api';
import OnboardingWizard from '@/components/domain/OnboardingWizard';

/**
 * Onboarding Wizard Page
 * Renders the 3-step wizard for adding new cloud accounts
 */
export default function OnboardingWizardPage() {
  const router = useRouter();

  const handleWizardComplete = async (accountData) => {
    console.log('Account onboarded:', accountData);
    try {
      // Create the account via backend API
      const result = await postToEngine('onboarding', '/api/v1/accounts', {
        provider: accountData.provider,
        auth_method: accountData.authMethod,
      });

      if (result && result.account_id) {
        // Store credentials for the created account
        try {
          await postToEngine('onboarding', `/api/v1/accounts/${result.account_id}/credentials`, accountData.credentials);

          // Validate credentials
          try {
            await postToEngine('onboarding', `/api/v1/accounts/${result.account_id}/validate-credentials`, {});
          } catch (validateError) {
            console.warn('Credential validation warning:', validateError);
          }
        } catch (credError) {
          console.warn('Credential storage warning:', credError);
        }

        setTimeout(() => {
          router.push('/onboarding');
        }, 2000);
      } else {
        // Fallback if no account_id returned - still redirect
        setTimeout(() => {
          router.push('/onboarding');
        }, 2000);
      }
    } catch (error) {
      console.warn('Error saving account:', error);
      // Still redirect on error with mock data handling
      setTimeout(() => {
        router.push('/onboarding');
      }, 2000);
    }
  };

  const handleWizardCancel = () => {
    router.push('/onboarding');
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>Add Cloud Account</h1>
        <p className="mt-1" style={{ color: 'var(--text-tertiary)' }}>
          Complete the wizard to onboard a new cloud provider account
        </p>
      </div>

      {/* Wizard Component */}
      <div className="rounded-xl border p-8 transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <OnboardingWizard
          onComplete={handleWizardComplete}
          onCancel={handleWizardCancel}
        />
      </div>
    </div>
  );
}
