---
id: onboarding-D8
title: "Frontend: onboarding wizard credential form (catalog-driven)"
sprint: D
points: 3
depends_on: [onboarding-C1, onboarding-D7]
blocks: [onboarding-D9, onboarding-D10]
security_blocks: []
nist_csf: PR.DS
owasp_samm: Implementation
csa_ccm: IAM-09
---

## Context

The onboarding wizard is the most important frontend story in the sprint. It walks an org admin or tenant admin through: (1) select account type, (2) enter provider (for cloud_csp accounts), (3) fill in credential fields, (4) save credentials to the onboarding engine (which stores in AWS SM), (5) trigger validation, (6) show PASS/FAIL result. The credential form is catalog-driven: a YAML configuration file (or JSON) defines what fields are shown for each `account_type` + `provider` combination. This avoids hardcoding provider-specific field names in the React component. The wizard lives at `/portal/onboarding/` (or an existing onboarding path — check the frontend structure). This is the highest-complexity frontend story — 3 points.

## Acceptance Criteria

- [ ] AC1: Wizard renders at `(portal)/onboarding/[step]/` with steps: `account-type → provider → credentials → validate → complete`.
- [ ] AC2: Step 1 — account type selection: `Cloud (CSP)`, `Vulnerability Agent`, `SecOps / Code`. Selection is persisted in local wizard state.
- [ ] AC3: Step 2 — for `cloud_csp` type: provider selector showing AWS, Azure, GCP, OCI, AliCloud with icons.
- [ ] AC4: Step 3 — credential form fields are rendered from a catalog JSON/YAML config (not hardcoded). Each provider's required fields are defined in the catalog.
- [ ] AC5: The catalog config is located at `frontend/src/config/credential-fields.json` and must include all 5 CSPs from architecture §6.2.1.
- [ ] AC6: Required fields (marked `required: true` in catalog) show a red asterisk and block form submission if empty.
- [ ] AC7: Credential fields of type `password` or `secret` use `<input type="password">` — never `type="text"`.
- [ ] AC8: On "Save Credentials", form POSTs to `POST /gateway/api/v1/cloud-accounts/{id}/credentials` (onboarding engine via gateway). On success, auto-advances to validation step.
- [ ] AC9: Step 4 — validation shows a spinner and polls `GET /gateway/api/v1/cloud-accounts/{id}/validation-status` every 5 seconds until status is `pass` or `fail` (max 60 seconds).
- [ ] AC10: On validation `pass` — show green checkmark, "Continue to Schedule Setup" button.
- [ ] AC11: On validation `fail` — show red error with the validation error message, "Re-enter Credentials" button to go back to step 3.
- [ ] AC12: Step 5 — completion screen with account summary and "Trigger First Scan" button (calls run-now from C7).
- [ ] AC13: Wizard state survives browser refresh (stored in sessionStorage, not URL params).

## Key Files

- `frontend/src/app/(portal)/onboarding/[step]/page.tsx` — Wizard step pages
- `frontend/src/components/onboarding/CredentialForm.tsx` — Catalog-driven credential form
- `frontend/src/components/onboarding/ProviderSelector.tsx` — CSP icon grid
- `frontend/src/components/onboarding/ValidationStatus.tsx` — Polling validation display
- `frontend/src/config/credential-fields.json` — Catalog: fields per provider
- `frontend/src/lib/wizard-state.ts` — Wizard state management (sessionStorage)

## Technical Notes

**Credential fields catalog format (`credential-fields.json`):**
```json
{
  "cloud_csp": {
    "aws": {
      "fields": [
        {"key": "access_key_id", "label": "Access Key ID", "type": "text", "required": true},
        {"key": "secret_access_key", "label": "Secret Access Key", "type": "password", "required": true},
        {"key": "assume_role_arn", "label": "Assume Role ARN (optional)", "type": "text", "required": false}
      ]
    },
    "azure": {
      "fields": [
        {"key": "client_id", "label": "Client ID", "type": "text", "required": true},
        {"key": "client_secret", "label": "Client Secret", "type": "password", "required": true},
        {"key": "tenant_id", "label": "Azure Tenant ID", "type": "text", "required": true},
        {"key": "subscription_id", "label": "Subscription ID", "type": "text", "required": true}
      ]
    },
    "gcp": {
      "fields": [
        {"key": "service_account_key_json", "label": "Service Account Key JSON (base64)", "type": "textarea", "required": true}
      ]
    },
    "oci": {
      "fields": [
        {"key": "user_ocid", "label": "User OCID", "type": "text", "required": true},
        {"key": "tenancy_ocid", "label": "Tenancy OCID", "type": "text", "required": true},
        {"key": "key_fingerprint", "label": "Key Fingerprint", "type": "text", "required": true},
        {"key": "private_key", "label": "Private Key (PEM)", "type": "textarea", "required": true}
      ]
    },
    "alicloud": {
      "fields": [
        {"key": "access_key_id", "label": "Access Key ID", "type": "text", "required": true},
        {"key": "access_key_secret", "label": "Access Key Secret", "type": "password", "required": true}
      ]
    }
  },
  "secops": {
    "github": { "fields": [{"key": "pat", "label": "Personal Access Token", "type": "password", "required": true}] },
    "gitlab": { "fields": [{"key": "pat", "label": "Personal Access Token", "type": "password", "required": true}] },
    "bitbucket": { "fields": [{"key": "pat", "label": "App Password", "type": "password", "required": true}] }
  }
}
```

**CredentialForm component (catalog-driven):**
```tsx
// components/onboarding/CredentialForm.tsx
import credentialFields from '@/config/credential-fields.json';

export function CredentialForm({ accountType, provider, onSubmit }) {
  const fields = credentialFields[accountType]?.[provider]?.fields ?? [];
  const [values, setValues] = useState({});

  return (
    <form onSubmit={() => onSubmit(values)}>
      {fields.map(field => (
        <div key={field.key}>
          <label>{field.label}{field.required && <span className="text-red-500">*</span>}</label>
          {field.type === 'textarea' ? (
            <Textarea required={field.required} onChange={e => setValues(v => ({...v, [field.key]: e.target.value}))} />
          ) : (
            <Input type={field.type} required={field.required} onChange={e => setValues(v => ({...v, [field.key]: e.target.value}))} />
          )}
        </div>
      ))}
      <Button type="submit">Save Credentials</Button>
    </form>
  );
}
```

**Validation polling:**
```tsx
// components/onboarding/ValidationStatus.tsx
useEffect(() => {
  const poll = setInterval(async () => {
    const status = await fetchValidationStatus(accountId);
    if (status === 'pass' || status === 'fail') {
      clearInterval(poll);
      setValidationResult(status);
    }
  }, 5000);
  const timeout = setTimeout(() => clearInterval(poll), 60000);
  return () => { clearInterval(poll); clearTimeout(timeout); };
}, [accountId]);
```

**Check existing onboarding pages:**
```bash
ls /Users/apple/Desktop/threat-engine/frontend/src/app/\(portal\)/ 2>/dev/null
ls /Users/apple/Desktop/threat-engine/frontend/src/app/\(portal\)/onboarding/ 2>/dev/null
```

**Wizard state in sessionStorage:**
```ts
// lib/wizard-state.ts
const WIZARD_KEY = 'onboarding_wizard_state';
export const saveWizardState = (state: WizardState) =>
  sessionStorage.setItem(WIZARD_KEY, JSON.stringify(state));
export const loadWizardState = (): WizardState | null => {
  const raw = sessionStorage.getItem(WIZARD_KEY);
  return raw ? JSON.parse(raw) : null;
};
```

## Security Checklist

- [ ] Credential fields of type `password`/`secret` use `<input type="password">`
- [ ] Wizard state stored in sessionStorage — not localStorage (cleared on tab close)
- [ ] No credentials logged to browser console
- [ ] Gateway API calls use the platform's cookie auth — no token in URL params
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] All 5 CSP credential forms render from catalog — no hardcoded field names in JSX
- [ ] Validation polling stops after `pass` or `fail` (does not poll forever)
- [ ] Password fields never show plaintext
- [ ] Frontend build succeeds
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] Visual QA: wizard steps 1-5 completable end-to-end for AWS account