---
story_id: onboarding-D-9
title: Frontend — agent install flow (PKCE) UI
status: ready
sprint: onboarding-revamp-D
depends_on: [onboarding-C-4, onboarding-D-8]
blocks: []
sme: React/Next.js 15 engineer + security engineer
estimate: 2 days
---

# Story: Frontend — agent install flow (PKCE) UI

## User Story
As an `org_admin`, I want to generate an agent install command in the wizard that I can
paste on the target server, and see a live "waiting for agent" spinner that turns green
once the agent connects, so that I can complete agent onboarding without reading docs.

## Context
Story C4 adds the backend PKCE bootstrap endpoint. This story builds the UI for the agent
flow within the onboarding wizard (D8):
1. User selects a vulnerability/database/middleware/K8s-technology account type.
2. Wizard shows prerequisites checklist.
3. User clicks "Generate Install Command" → browser generates `code_verifier` (never sent to server).
4. Browser calls `POST /cloud-accounts/{id}/agent-token` with `{code_challenge}`.
5. Server returns `{registration_id}`. Browser constructs install command with `code_verifier`.
6. Wizard shows install command in a copy-able code block. One-time display.
7. Wizard polls `GET /cloud-accounts/{id}` every 5 seconds.
8. When `account.status = 'active'` → spinner turns green, proceed to next step.

**Security: `code_verifier` is NEVER sent to the server. It is only displayed in the UI
install command. After the user navigates away, it is gone — agent must use the same
session to save the verifier.**

## Files to Create/Modify
- `frontend/src/components/onboarding/AgentInstallStep.jsx` — agent flow sub-wizard
- `frontend/src/lib/pkce.js` — PKCE helper (code_verifier generation + code_challenge derivation)

## Implementation Notes

### `pkce.js` — PKCE helpers

```javascript
// frontend/src/lib/pkce.js
export async function generatePkce() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const codeVerifier = Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');

  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const codeChallenge = Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0')).join('');

  return { codeVerifier, codeChallenge };
}
```

### `AgentInstallStep` component

```jsx
export function AgentInstallStep({ account, onComplete }) {
  const [state, setState] = useState('ready'); // ready | generating | waiting | complete
  const [installCommand, setInstallCommand] = useState('');
  const pollRef = useRef(null);

  async function handleGenerateCommand() {
    setState('generating');
    const { codeVerifier, codeChallenge } = await generatePkce();

    const resp = await fetch(`/gateway/api/v1/cloud-accounts/${account.id}/agent-token`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ code_challenge: codeChallenge, account_type: account.account_type }),
    });
    const { registration_id } = await resp.json();

    // Construct install command with code_verifier — SHOWN ONCE, never stored server-side
    const cmd = `curl -fsSL https://agent.cspm.io/install.sh | sudo bash -s -- \\
  --registration-id ${registration_id} \\
  --verifier ${codeVerifier} \\
  --api-url https://api.cspm.io`;

    setInstallCommand(cmd);
    setState('waiting');

    // Poll for agent registration
    pollRef.current = setInterval(async () => {
      const statusResp = await fetch(`/gateway/api/v1/cloud-accounts/${account.id}`);
      const data = await statusResp.json();
      if (data.account_status === 'active') {
        clearInterval(pollRef.current);
        setState('complete');
        onComplete();
      }
    }, 5000);
  }

  if (state === 'complete') {
    return <SuccessMessage message="Agent connected successfully!" />;
  }

  return (
    <div>
      <PrerequisitesChecklist steps={account.auth_model?.admin_prerequisites || []} />
      {state === 'ready' && (
        <Button onClick={handleGenerateCommand}>Generate Install Command</Button>
      )}
      {(state === 'waiting' || state === 'generating') && installCommand && (
        <>
          <Alert variant="warning">
            Save this command now — the install key is shown once only.
          </Alert>
          <CodeBlock code={installCommand} copyable />
          <WaitingSpinner message="Waiting for agent to connect..." />
        </>
      )}
    </div>
  );
}
```

### Security notes
- `code_verifier` exists only in component local state — cleared on unmount/navigate away
- If user navigates away before running the command, they must generate a new command
- `code_challenge` (SHA-256 of verifier) is the only value sent to server
- Install command shown once; user warned to copy it

## Acceptance Criteria
- [ ] AC1: "Generate Install Command" button appears for agent account types
- [ ] AC2: Clicking generates `code_verifier` client-side (never in network request to server)
- [ ] AC3: Install command shown in copy-able code block with warning "shown once"
- [ ] AC4: Polling starts immediately after command generated (5-second interval)
- [ ] AC5: When `account.account_status = 'active'` → spinner turns green, "Continue" button appears
- [ ] AC6: `code_verifier` is not in any network request tab (verify in browser DevTools)
- [ ] AC7: Navigating away and returning: user must generate a new command (old verifier gone)

## Definition of Done
- [ ] `generatePkce()` uses `crypto.subtle.digest` (Web Crypto API — no server involvement)
- [ ] Install command contains `--verifier {code_verifier}` and is shown once
- [ ] Polling implemented with cleanup on component unmount (`clearInterval`)
- [ ] Warning message shown: "Save this command — install key shown once only"
- [ ] Manual test: full agent install flow with mock agent bootstrap endpoint
- [ ] bmad-security-reviewer: no BLOCKERs — specifically verify code_verifier never in XHR
