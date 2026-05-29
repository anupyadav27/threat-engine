'use client';

/**
 * SecurityBadges — reusable enterprise-grade badge & signal system.
 *
 * Design principles:
 *  - No emojis. All icons from lucide-react (consistent, professional).
 *  - Two sizes: sm (table rows, 18px height) and md (panel headers, 22px height).
 *  - Two variants: full (icon + label) and icon (icon only, tooltip shown).
 *  - All colors use low-opacity fills (12–18%) so they sit on dark AND light cards.
 *  - Tokens reference CSS vars from the app's design system where possible.
 *
 * Named exports (use individually — no default export):
 *
 *   Signal badges (security posture signals):
 *     AttackPathBadge, CrownJewelBadge, ChokepointBadge,
 *     ExposureBadge, PiiBadge, DriftBadge, CdrBadge, EncryptionBadge
 *
 *   Classification:
 *     SeverityBadge   — replaces old SeverityBadge.jsx (adds count + size props)
 *     DataClassBadge  — PII / PHI / PCI / Confidential / Internal / Public
 *     FindingTypeBadge — misconfig / cve / iam_violation / cdr_event / data_risk / network_exposure
 *     SourceEngineBadge — check / iam / network / datasec / vuln / cdr / container / dbsec
 *
 *   Scores:
 *     RiskScore  — colored filled pill with 0–100 number (no text label)
 *     FindingsBar — compact 4-dot severity row (C · H · M · L)
 *
 *   Primitives (for building new badges):
 *     BadgePill — base styled pill, accepts icon + label + color tokens
 */

import {
  Route,
  Star,
  Crosshair,
  Globe,
  ShieldAlert,
  GitBranch,
  Radar,
  Lock,
  Unlock,
  Eye,
  AlertOctagon,
  ShieldCheck,
  Activity,
  Database,
  Network,
  HardDrive,
  Key,
  Box,
} from 'lucide-react';

// ─── Design tokens ────────────────────────────────────────────────────────────

const T = {
  critical:     { color: '#ef4444', bg: 'rgba(239,68,68,0.13)'    },
  high:         { color: '#f97316', bg: 'rgba(249,115,22,0.13)'   },
  medium:       { color: '#eab308', bg: 'rgba(234,179,8,0.13)'    },
  low:          { color: '#3b82f6', bg: 'rgba(59,130,246,0.13)'   },
  info:         { color: '#6b7280', bg: 'rgba(107,114,128,0.13)'  },
  success:      { color: '#22c55e', bg: 'rgba(34,197,94,0.13)'    },
  purple:       { color: '#8b5cf6', bg: 'rgba(139,92,246,0.13)'   },
  amber:        { color: '#d97706', bg: 'rgba(217,119,6,0.13)'    },
  pink:         { color: '#db2777', bg: 'rgba(219,39,119,0.13)'   },
  sky:          { color: '#0ea5e9', bg: 'rgba(14,165,233,0.13)'   },
  neutral:      { color: '#94a3b8', bg: 'rgba(148,163,184,0.10)'  },
};

const SIZE = {
  sm: { fontSize: 10, iconSize: 10, px: 6, py: 2, gap: 4, borderRadius: 4,  height: 18 },
  md: { fontSize: 11, iconSize: 12, px: 8, py: 3, gap: 5, borderRadius: 5,  height: 22 },
  lg: { fontSize: 12, iconSize: 13, px: 10, py: 4, gap: 6, borderRadius: 6, height: 26 },
};

// ─── Primitive ────────────────────────────────────────────────────────────────

/**
 * BadgePill — base reusable pill.
 *
 * @param {object} props
 * @param {React.ComponentType} [props.Icon]  — lucide icon component
 * @param {string}  [props.label]             — text label
 * @param {string}  props.color               — foreground color (#hex)
 * @param {string}  props.bg                  — background color (rgba)
 * @param {'sm'|'md'|'lg'} [props.size]       — size variant (default 'sm')
 * @param {'full'|'icon'} [props.variant]     — full = icon+label, icon = icon only
 * @param {string}  [props.title]             — tooltip
 * @param {object}  [props.style]             — inline style overrides
 * @param {string}  [props.className]
 */
export function BadgePill({
  Icon,
  label,
  color,
  bg,
  size = 'sm',
  variant = 'full',
  title,
  style,
  className,
}) {
  const s = SIZE[size] || SIZE.sm;
  const showLabel = variant !== 'icon' && label;

  return (
    <span
      title={title || label}
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: showLabel ? s.gap : 0,
        paddingLeft: s.px,
        paddingRight: s.px,
        paddingTop: s.py,
        paddingBottom: s.py,
        borderRadius: s.borderRadius,
        background: bg,
        color,
        fontSize: s.fontSize,
        fontWeight: 600,
        letterSpacing: '0.02em',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
        lineHeight: 1,
        flexShrink: 0,
        userSelect: 'none',
        ...style,
      }}
    >
      {Icon && (
        <Icon
          style={{ width: s.iconSize, height: s.iconSize, flexShrink: 0 }}
          strokeWidth={2.2}
        />
      )}
      {showLabel && label}
    </span>
  );
}

// ─── Signal badges ────────────────────────────────────────────────────────────

/**
 * AttackPathBadge — shown when is_on_attack_path = true.
 * Uses Route icon (lateral movement / traversal path). Professional, not dramatic.
 */
export function AttackPathBadge({ size = 'sm', variant = 'full', label = 'Attack Path', style }) {
  return (
    <BadgePill
      Icon={Route}
      label={label}
      color={T.critical.color}
      bg={T.critical.bg}
      size={size}
      variant={variant}
      title="This resource is on an active attack path"
      style={style}
    />
  );
}

/**
 * CrownJewelBadge — shown when is_crown_jewel = true.
 * Uses Star (filled) — the enterprise standard (Wiz, Orca). Not a crown emoji.
 * crownJewelType: 'storage' | 'secrets' | 'admin_role' | 'k8s_api' | 'database' | etc.
 */
export function CrownJewelBadge({ size = 'sm', variant = 'full', crownJewelType, style }) {
  const label = crownJewelType
    ? crownJewelType.replace(/_/g, ' ')
    : 'Critical Asset';

  return (
    <BadgePill
      Icon={({ style: s, ...rest }) => (
        <Star {...rest} style={{ ...s, fill: 'currentColor' }} />
      )}
      label={label}
      color={T.amber.color}
      bg={T.amber.bg}
      size={size}
      variant={variant}
      title={`Crown jewel: ${label}`}
      style={style}
    />
  );
}

/**
 * ChokepointBadge — shown when is_choke_point = true.
 * Uses Crosshair — precision/targeting. Conveys "fixing this one breaks many paths".
 */
export function ChokepointBadge({ size = 'sm', variant = 'full', pathsBlocked, style }) {
  const label = pathsBlocked ? `Blocks ${pathsBlocked}` : 'Chokepoint';
  return (
    <BadgePill
      Icon={Crosshair}
      label={label}
      color={T.purple.color}
      bg={T.purple.bg}
      size={size}
      variant={variant}
      title={pathsBlocked ? `Remediating this blocks ${pathsBlocked} attack path(s)` : 'Attack path chokepoint'}
      style={style}
    />
  );
}

/**
 * ExposureBadge — shown when is_internet_exposed = true.
 * Uses Globe. exposureType: 'direct_ip' | 'public_bucket' | 'public_api' | 'function_url'.
 */
export function ExposureBadge({ size = 'sm', variant = 'full', exposureType, style }) {
  const labelMap = {
    direct_ip:     'Direct IP',
    public_bucket: 'Public Bucket',
    public_api:    'Public API',
    function_url:  'Function URL',
  };
  const label = labelMap[exposureType] || 'Internet Exposed';
  return (
    <BadgePill
      Icon={Globe}
      label={label}
      color={T.critical.color}
      bg={T.critical.bg}
      size={size}
      variant={variant}
      title="Internet exposed — reachable from public internet"
      style={style}
    />
  );
}

/**
 * PiiBadge — shown when can_access_pii = true or data_classification is sensitive.
 * Uses Eye — suggests "watched / sensitive visibility".
 */
export function PiiBadge({ size = 'sm', variant = 'full', style }) {
  return (
    <BadgePill
      Icon={Eye}
      label="PII Access"
      color={T.pink.color}
      bg={T.pink.bg}
      size={size}
      variant={variant}
      title="Can access PII data"
      style={style}
    />
  );
}

/**
 * DriftBadge — shown when drift_detected = true.
 * Uses GitBranch — conveys "config diverged from baseline".
 */
export function DriftBadge({ size = 'sm', variant = 'full', style }) {
  return (
    <BadgePill
      Icon={GitBranch}
      label="Drift"
      color={T.high.color}
      bg={T.high.bg}
      size={size}
      variant={variant}
      title="Configuration drift detected since last scan"
      style={style}
    />
  );
}

/**
 * CdrBadge — shown when has_active_cdr_actor = true.
 * Uses Radar — behavioral detection / active monitoring. Clean and technical.
 */
export function CdrBadge({ size = 'sm', variant = 'full', actorCount, style }) {
  const label = actorCount ? `${actorCount} Actor${actorCount > 1 ? 's' : ''}` : 'CDR Active';
  return (
    <BadgePill
      Icon={Radar}
      label={label}
      color={T.medium.color}
      bg={T.medium.bg}
      size={size}
      variant={variant}
      title="Active CDR behavioral detections on this resource"
      style={style}
    />
  );
}

/**
 * EncryptionBadge — shown for encryption posture.
 * variant 'pass' (encrypted) shows Lock in green; 'fail' (unencrypted) shows Unlock in red.
 */
export function EncryptionBadge({ encrypted = true, size = 'sm', variant = 'full', style }) {
  return (
    <BadgePill
      Icon={encrypted ? Lock : Unlock}
      label={encrypted ? 'Encrypted' : 'Unencrypted'}
      color={encrypted ? T.success.color : T.critical.color}
      bg={encrypted ? T.success.bg : T.critical.bg}
      size={size}
      variant={variant}
      title={encrypted ? 'Encrypted at rest' : 'Not encrypted at rest'}
      style={style}
    />
  );
}

// ─── Classification badges ────────────────────────────────────────────────────

const SEVERITY_TOKEN = {
  critical: T.critical,
  high:     T.high,
  medium:   T.medium,
  low:      T.low,
  info:     T.info,
  pass:     T.success,
  fail:     T.critical,
};

/**
 * SeverityBadge — replaces the old Tailwind-class version.
 * Adds: count prop (shows "3 Critical"), size prop, icon prop.
 *
 * @param {object} props
 * @param {'critical'|'high'|'medium'|'low'|'info'} props.severity
 * @param {number}  [props.count]   — if provided, shows "N Label"
 * @param {'sm'|'md'|'lg'} [props.size]
 * @param {'full'|'icon'} [props.variant]
 */
export function SeverityBadge({ severity = 'info', count, size = 'sm', variant = 'full', style }) {
  const tok = SEVERITY_TOKEN[(severity || 'info').toLowerCase()] || T.info;
  const LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', pass: 'Pass', fail: 'Fail' };
  const base = LABELS[(severity || 'info').toLowerCase()] || severity;
  const label = count !== undefined ? `${count} ${base}` : base;

  return (
    <BadgePill
      label={label}
      color={tok.color}
      bg={tok.bg}
      size={size}
      variant={variant}
      style={style}
    />
  );
}

const DATA_CLASS_TOKEN = {
  pii:          T.pink,
  phi:          T.critical,
  pci:          T.amber,
  restricted:   { color: '#dc2626', bg: 'rgba(220,38,38,0.18)' },
  confidential: T.sky,
  internal:     T.neutral,
  public:       T.success,
  unknown:      T.neutral,
};

/**
 * DataClassBadge — data classification label.
 * Uses ShieldAlert icon for sensitive classes (pii/phi/pci/restricted),
 * ShieldCheck for public, neutral for internal/unknown.
 */
export function DataClassBadge({ classification = 'unknown', size = 'sm', variant = 'full', style }) {
  const key = (classification || 'unknown').toLowerCase();
  const tok = DATA_CLASS_TOKEN[key] || T.neutral;
  const sensitive = ['pii', 'phi', 'pci', 'restricted', 'confidential'].includes(key);
  const label = key.toUpperCase();

  return (
    <BadgePill
      Icon={sensitive ? ShieldAlert : key === 'public' ? ShieldCheck : null}
      label={label}
      color={tok.color}
      bg={tok.bg}
      size={size}
      variant={variant}
      title={`Data classification: ${label}`}
      style={style}
    />
  );
}

const FINDING_TYPE_META = {
  misconfig:        { label: 'Alert',       color: T.high.color,     bg: T.high.bg    },
  cve:              { label: 'CVE',         color: T.critical.color, bg: T.critical.bg },
  iam_violation:    { label: 'IAM',         color: T.purple.color,   bg: T.purple.bg  },
  cdr_event:        { label: 'CDR',         color: T.medium.color,   bg: T.medium.bg  },
  data_risk:        { label: 'Data',        color: T.pink.color,     bg: T.pink.bg    },
  network_exposure: { label: 'Network',     color: T.sky.color,      bg: T.sky.bg     },
};

/** FindingTypeBadge — finding_type classifier pill (no icon, text only). */
export function FindingTypeBadge({ type, size = 'sm', style }) {
  const meta = FINDING_TYPE_META[(type || '').toLowerCase()] || {
    label: (type || 'Unknown').replace(/_/g, ' '),
    color: T.neutral.color, bg: T.neutral.bg,
  };
  return (
    <BadgePill
      label={meta.label}
      color={meta.color}
      bg={meta.bg}
      size={size}
      title={`Finding type: ${meta.label}`}
      style={style}
    />
  );
}

const ENGINE_META = {
  check:     { label: 'Config',   Icon: ShieldCheck, color: '#0ea5e9' },
  iam:       { label: 'IAM',      Icon: Key,         color: '#8b5cf6' },
  network:   { label: 'Network',  Icon: Network,     color: '#22c55e' },
  datasec:   { label: 'DataSec',  Icon: HardDrive,   color: '#f97316' },
  vuln:      { label: 'Vuln',     Icon: AlertOctagon,color: '#ef4444' },
  cdr:       { label: 'CDR',      Icon: Radar,       color: '#eab308' },
  container: { label: 'Container',Icon: Box,         color: '#6d28d9' },
  dbsec:     { label: 'DBSec',    Icon: Database,    color: '#3b82f6' },
  ai_security:{ label: 'AI Sec',  Icon: Activity,    color: '#06b6d4' },
  secops:    { label: 'SecOps',   Icon: ShieldAlert, color: '#f43f5e' },
  api_security:{ label: 'API',    Icon: Globe,       color: '#f59e0b' },
};

/**
 * SourceEngineBadge — identifies which security engine produced a finding.
 * variant='icon' useful in dense finding lists where space is tight.
 */
export function SourceEngineBadge({ engine, size = 'sm', variant = 'full', style }) {
  const key = (engine || '').toLowerCase();
  const meta = ENGINE_META[key] || {
    label: key || 'Unknown',
    Icon: ShieldCheck,
    color: T.neutral.color,
  };
  const bg = `${meta.color}18`;

  return (
    <BadgePill
      Icon={meta.Icon}
      label={meta.label}
      color={meta.color}
      bg={bg}
      size={size}
      variant={variant}
      title={`Source: ${meta.label} engine`}
      style={style}
    />
  );
}

// ─── Score components ─────────────────────────────────────────────────────────

/**
 * RiskScore — compact filled pill with numeric score.
 * No text label — the color and number communicate everything.
 *
 * ≥70 → red (critical)   40–69 → orange (high)
 * 20–39 → amber (medium) <20 → green (low)
 */
export function RiskScore({ score, size = 'sm', style }) {
  if (score === null || score === undefined) {
    return <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>;
  }
  const n = Number(score);
  const { color, bg } =
    n >= 70 ? { color: '#fff', bg: '#ef4444' } :
    n >= 40 ? { color: '#fff', bg: '#f97316' } :
    n >= 20 ? { color: '#111', bg: '#eab308' } :
              { color: '#fff', bg: '#22c55e' };

  const s = SIZE[size] || SIZE.sm;

  return (
    <span
      title={`Risk score: ${n}/100`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        minWidth: s.height + 6,
        height: s.height,
        paddingLeft: s.px,
        paddingRight: s.px,
        borderRadius: s.height / 2,
        background: bg,
        color,
        fontSize: s.fontSize + 1,
        fontWeight: 700,
        fontVariantNumeric: 'tabular-nums',
        letterSpacing: '-0.02em',
        flexShrink: 0,
        userSelect: 'none',
        ...style,
      }}
    >
      {n}
    </span>
  );
}

const SEV_DOTS = [
  { key: 'critical', color: '#ef4444' },
  { key: 'high',     color: '#f97316' },
  { key: 'medium',   color: '#eab308' },
  { key: 'low',      color: '#3b82f6' },
];

/**
 * FindingsBar — compact 4-dot severity row.
 *
 * Shows a colored dot + count for each non-zero severity.
 * Empty slots show a faint empty dot (not hidden — communicates "we checked").
 * Shows a green "Clean" label when all zero.
 *
 * findings = { critical: 0, high: 3, medium: 1, low: 0 }
 */
export function FindingsBar({ findings = {}, size = 'sm', style }) {
  const hasAny = SEV_DOTS.some(s => (findings[s.key] || 0) > 0);
  const dotSize = size === 'md' ? 7 : 6;
  const numSize = size === 'md' ? 12 : 11;

  if (!hasAny) {
    return (
      <span style={{
        fontSize: numSize, color: '#22c55e', fontWeight: 600,
        display: 'inline-flex', alignItems: 'center', gap: 4,
        ...style,
      }}>
        <ShieldCheck style={{ width: dotSize + 2, height: dotSize + 2, strokeWidth: 2.2 }} />
        Clean
      </span>
    );
  }

  return (
    <div style={{ display: 'inline-flex', gap: 6, alignItems: 'center', ...style }}>
      {SEV_DOTS.map(({ key, color }) => {
        const n = findings[key] || 0;
        return n > 0 ? (
          <span key={key} style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
            <span style={{
              width: dotSize, height: dotSize, borderRadius: '50%',
              background: color, flexShrink: 0,
            }} />
            <span style={{
              fontSize: numSize, fontWeight: 700, color,
              fontVariantNumeric: 'tabular-nums',
            }}>{n}</span>
          </span>
        ) : (
          <span key={key} style={{
            width: dotSize, height: dotSize, borderRadius: '50%',
            background: 'var(--border-primary, #1e293b)',
            flexShrink: 0, opacity: 0.5,
          }} />
        );
      })}
    </div>
  );
}
