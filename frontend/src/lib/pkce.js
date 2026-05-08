/**
 * PKCE helpers — Web Crypto API only. Nothing is ever sent to the server.
 *
 * code_verifier  — random 32-byte hex string, lives only in JS memory
 * code_challenge — SHA-256(code_verifier), safe to send to server
 *
 * Security contract: code_verifier is NEVER stored in localStorage, sessionStorage,
 * or any network request. It is only shown in the install command (one-time display).
 */

export async function generatePkce() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const codeVerifier = btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return { codeVerifier, codeChallenge };
}
