export const CRON_PRESETS = [
  { label: 'Daily at midnight UTC',   value: '0 0 * * *' },
  { label: 'Daily at 2 AM UTC',       value: '0 2 * * *' },
  { label: 'Daily at 6 AM UTC',       value: '0 6 * * *' },
  { label: 'Weekly (Sunday 2 AM)',     value: '0 2 * * 0' },
  { label: 'Weekly (Monday 2 AM)',     value: '0 2 * * 1' },
  { label: 'Monthly (1st at 2 AM)',    value: '0 2 1 * *' },
  { label: 'Custom',                   value: 'custom' },
];

const DAY_NAMES  = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

export function getNextRunTime(expr) {
  if (!expr || expr === 'custom') return 'Custom schedule';
  try {
    const parts = expr.trim().split(/\s+/);
    if (parts.length !== 5) return expr;
    const [min, hour, dom, , dow] = parts;

    const h  = hour === '*' ? 0 : parseInt(hour, 10);
    const m  = min  === '*' ? 0 : parseInt(min,  10);
    const now = new Date();
    const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), h, m, 0, 0));
    if (next <= now) next.setUTCDate(next.getUTCDate() + 1);

    // Advance to correct day-of-week if specified
    if (dow !== '*') {
      const target = parseInt(dow, 10);
      while (next.getUTCDay() !== target) next.setUTCDate(next.getUTCDate() + 1);
    }

    // Advance to correct day-of-month if specified
    if (dom !== '*') {
      const target = parseInt(dom, 10);
      while (next.getUTCDate() !== target) next.setUTCDate(next.getUTCDate() + 1);
    }

    return `${DAY_NAMES[next.getUTCDay()]} ${MONTH_NAMES[next.getUTCMonth()]} ${next.getUTCDate()} at ${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')} UTC`;
  } catch (_) {
    return expr;
  }
}

export function isCustomCron(value) {
  return !CRON_PRESETS.some(p => p.value === value && p.value !== 'custom');
}

// Service categories for scope selection
export const SERVICE_CATEGORIES = {
  compute:  { label: 'Compute',    services: ['ec2','vm','gce','oci_compute','ecs','eks','aks','gke'] },
  storage:  { label: 'Storage',    services: ['s3','azure_blob','gcs','oci_objectstorage'] },
  database: { label: 'Database',   services: ['rds','azure_sql','cloud_sql','oci_db','dynamodb','cosmos_db'] },
  iam:      { label: 'IAM',        services: ['iam','azure_ad','gcp_iam','oci_iam'] },
  network:  { label: 'Network',    services: ['vpc','vnet','gcp_vpc','oci_vcn','sg','nsg','elb','alb'] },
  security: { label: 'Security',   services: ['cloudtrail','azure_monitor','gcp_audit','guardduty','defender'] },
  serverless: { label: 'Serverless', services: ['lambda','azure_functions','cloud_functions'] },
};
