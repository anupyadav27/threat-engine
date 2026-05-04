---
story_id: onboarding-D-8
title: Frontend — onboarding wizard credential form (catalog-driven)
status: ready
sprint: onboarding-revamp-D
depends_on: [onboarding-C-1, onboarding-D-7]
blocks: [onboarding-D-9, onboarding-D-10]
sme: React/Next.js 15 engineer
estimate: 3 days
---

# Story: Frontend — onboarding wizard credential form (catalog-driven)

## User Story
As an `org_admin`, I want to add a new cloud account by selecting a technology type and
following a step-by-step wizard that shows me exactly what to create in AWS/Azure/GCP etc.,
so that I can complete onboarding without reading external documentation.

## Context
`catalog/account_types/auth_requirements.yaml` is the single source of truth for all
account types. The wizard reads this YAML and renders:
1. Technology grid (AWS / Azure / GCP / OCI / AliCloud / IBM / K8s / GitHub / GitLab /
   Bitbucket / Azure DevOps / Agents)
2. Auth method selector (per provider — e.g. AWS has "Access Key" vs "IAM Role")
3. Admin prerequisites checklist (numbered steps for what the user must create first)
4. Credential form (fields from `credential_fields` in YAML)
5. Credential validation result (success + detected account_id, or missing_permissions list)

The wizard state machine has 6 steps:
```
SELECT_TECHNOLOGY → SELECT_AUTH_METHOD → SHOW_PREREQUISITES →
CREDENTIAL_FORM → VALIDATE → ATTACH_SCHEDULE
```

For agent types, after SELECT_AUTH_METHOD the flow forks to:
```
→ SHOW_AGENT_PREREQUISITES → GENERATE_TOKEN → SHOW_INSTALL_COMMAND → WAITING_FOR_AGENT
```

## Files to Create/Modify
- `frontend/src/app/onboarding/page.jsx` — main wizard page (or route)
- `frontend/src/components/onboarding/WizardStepper.jsx` — step progress indicator
- `frontend/src/components/onboarding/TechnologyGrid.jsx` — provider selection grid
- `frontend/src/components/onboarding/CredentialForm.jsx` — dynamic form from YAML
- `frontend/src/components/onboarding/PrerequisitesChecklist.jsx` — numbered steps
- `frontend/src/components/onboarding/ValidationResult.jsx` — pass/fail + warnings
- `frontend/src/lib/catalog.js` — YAML loader + form renderer helpers

## Implementation Notes

### YAML loading (`catalog.js`)

The YAML is read at build time and bundled:
```javascript
// frontend/src/lib/catalog.js
import yaml from 'js-yaml';
import fs from 'fs';
import path from 'path';

let _catalog = null;
export function getAccountTypeCatalog() {
  if (_catalog) return _catalog;
  // At build time (Next.js server component or getStaticProps):
  const raw = fs.readFileSync(
    path.join(process.cwd(), '../catalog/account_types/auth_requirements.yaml'),
    'utf8'
  );
  _catalog = yaml.load(raw);
  return _catalog;
}

export function getProvidersForTenantType(tenantType) {
  return _catalog.account_types.filter(a => a.tenant_type === tenantType);
}

export function getAuthModels(accountTypeId) {
  const at = _catalog.account_types.find(a => a.id === accountTypeId);
  return at?.auth_models || [];
}
```

### `CredentialForm` — renders fields from YAML

```jsx
export function CredentialForm({ authModel, onSubmit, loading }) {
  const { credential_fields } = authModel;
  const [values, setValues] = useState({});

  return (
    <form onSubmit={e => { e.preventDefault(); onSubmit(values); }}>
      {credential_fields.map(field => (
        <div key={field.name}>
          <label>{field.label}</label>
          {field.type === 'file' ? (
            <FileUpload name={field.name} onChange={f => setValues(v => ({...v, [field.name]: f}))} />
          ) : (
            <Input
              type={field.sensitive ? 'password' : 'text'}
              placeholder={field.placeholder}
              required={field.required}
              onChange={e => setValues(v => ({...v, [field.name]: e.target.value}))}
            />
          )}
          {field.help_text && <p className="text-sm text-gray-500">{field.help_text}</p>}
        </div>
      ))}
      <Button type="submit" loading={loading}>Validate Credentials</Button>
    </form>
  );
}
```

### Wizard state machine

```javascript
const WIZARD_STEPS = [
  'SELECT_TECHNOLOGY',
  'SELECT_AUTH_METHOD',
  'SHOW_PREREQUISITES',
  'CREDENTIAL_FORM',      // skipped for agent types
  'VALIDATE',
  'ATTACH_SCHEDULE',      // D10 story
];

// For agent:
const AGENT_STEPS = [
  'SELECT_TECHNOLOGY',
  'SELECT_AUTH_METHOD',
  'SHOW_PREREQUISITES',
  'GENERATE_TOKEN',       // C4: POST /cloud-accounts/{id}/agent-token
  'SHOW_INSTALL_COMMAND', // shows code_verifier-based install command
  'WAITING_FOR_AGENT',    // polls GET /cloud-accounts/{id} for status=active
];
```

### API calls

- Step: Create account stub: `POST /gateway/api/v1/cloud-accounts/` with `{tenant_id, provider, account_type}`
- Step: Submit credentials: `POST /gateway/api/v1/cloud-accounts/{id}/credentials` with form values
- Step: Get validation result: `GET /gateway/api/v1/cloud-accounts/{id}` → `credential_validation_status`

## Acceptance Criteria
- [ ] AC1: Technology grid shows all providers from YAML catalog (AWS, Azure, GCP, OCI, AliCloud, IBM, K8s, GitHub, GitLab, Bitbucket, ADO, Agents)
- [ ] AC2: Selecting AWS shows two auth methods: "Access Key" and "IAM Role"
- [ ] AC3: Prerequisites checklist renders the correct numbered steps for each auth_model
- [ ] AC4: `CredentialForm` renders fields defined in YAML (correct types: text/password/file)
- [ ] AC5: File upload (GCP JSON, OCI key) works and sends file to `POST /credentials`
- [ ] AC6: Validation success shows green check + detected account_id
- [ ] AC7: Validation failure shows missing_permissions list from API response
- [ ] AC8: Agent type skips credential form, goes to GENERATE_TOKEN → SHOW_INSTALL_COMMAND (D9)
- [ ] AC9: Wizard progress indicator shows current step

## Definition of Done
- [ ] Wizard renders all 12+ provider types from YAML
- [ ] CredentialForm dynamic field rendering works for text/password/file types
- [ ] API integration: create account stub, submit credentials, read validation result
- [ ] Agent flow forks correctly at SELECT_AUTH_METHOD
- [ ] No hardcoded provider list — reads from YAML catalog only
- [ ] Manual browser test: full AWS access-key onboarding end-to-end
- [ ] bmad-security-reviewer: no BLOCKERs
