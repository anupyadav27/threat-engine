/**
 * Onboarding wizard state — persisted to sessionStorage so browser refresh
 * does not lose wizard progress. Cleared when the wizard completes or the
 * user explicitly cancels.
 *
 * sessionStorage (not localStorage) — cleared automatically on tab close so
 * partially-entered credentials are not left on disk indefinitely.
 */

export type AccountType = 'cloud_csp' | 'vulnerability' | 'code_security' | 'database' | 'middleware';

export type WizardStep =
  | 'account-type'
  | 'provider'
  | 'credentials'
  | 'validate'
  | 'complete';

export interface WizardState {
  step: WizardStep;
  accountType: AccountType | null;
  provider: string | null;
  accountName: string;
  /** account_id returned by POST /cloud-accounts after creation */
  accountId: string | null;
  /** validation status: null = not run, 'pass' | 'fail' | 'pending' */
  validationStatus: 'pass' | 'fail' | 'pending' | null;
  validationError: string | null;
}

const WIZARD_KEY = 'onboarding_wizard_state';

export const INITIAL_WIZARD_STATE: WizardState = {
  step: 'account-type',
  accountType: null,
  provider: null,
  accountName: '',
  accountId: null,
  validationStatus: null,
  validationError: null,
};

export function saveWizardState(state: WizardState): void {
  if (typeof window === 'undefined') return;
  try {
    sessionStorage.setItem(WIZARD_KEY, JSON.stringify(state));
  } catch {
    // sessionStorage full or unavailable — silently ignore
  }
}

export function loadWizardState(): WizardState | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = sessionStorage.getItem(WIZARD_KEY);
    return raw ? (JSON.parse(raw) as WizardState) : null;
  } catch {
    return null;
  }
}

export function clearWizardState(): void {
  if (typeof window === 'undefined') return;
  sessionStorage.removeItem(WIZARD_KEY);
}
