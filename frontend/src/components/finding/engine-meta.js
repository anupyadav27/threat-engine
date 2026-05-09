/**
 * Engine metadata for the universal finding-detail page.
 * Keys are CP-2 long slugs (matches K8s service names).
 */
export const ENGINE_META = {
  iam:                   { label: 'IAM',                 route: '/iam' },
  'network-security':    { label: 'Network Security',    route: '/network-security' },
  datasec:               { label: 'Data Security',       route: '/datasec' },
  encryption:            { label: 'Encryption',          route: '/encryption' },
  'container-security':  { label: 'Container Security',  route: '/container-security' },
  dbsec:                 { label: 'Database Security',   route: '/database-security' },
  'ai-security':         { label: 'AI Security',         route: '/ai-security' },
  cdr:                   { label: 'CDR',                 route: '/cdr' },
  check:                 { label: 'Posture',             route: '/misconfig' },
  threat:                { label: 'Threats',             route: '/threats' },
  secops:                { label: 'SecOps',              route: '/secops' },
};

export default ENGINE_META;
