/**
 * Fallback permissions for authenticated users whose /me response returns
 * an empty permissions array (e.g. legacy sessions before RBAC-03 deploy).
 * Viewer-only — no write or admin capabilities.
 * Imported by both auth-context.js and permissions.js to avoid circular deps.
 */
export const FALLBACK_VIEWER_PERMISSIONS = [
  'discoveries:read',
  'check:read',
  'threat:read',
  'inventory:read',
  'compliance:read',
  'iam:read',
  'cdr:read',
  'network:read',
  'risk:read',
];
