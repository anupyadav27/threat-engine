'use client';

/**
 * <PivotLink> — entity-pivot primitive.
 *
 * Renders a real <a> (via next/link legacyBehavior) to a centrally-resolved
 * URL with a 400ms-delayed rich tooltip. Fires a `cspm:pivot-click`
 * CustomEvent on click. Never adds prefetch traffic.
 *
 * @see .claude/planning/stories/JNY-07_handoff_design.md §3
 */

import Link from 'next/link';
import { useState, useRef, useId, useMemo } from 'react';
import SeverityBadge from './SeverityBadge';
import CloudProviderBadge from './CloudProviderBadge';
import { resolvePivotUrl, ENTITY_REGISTRY } from '../../lib/pivot-routes';
import { emit } from '../../lib/telemetry';

const SIZE_CLASSES = {
  xs: { font: 'text-xs',   icon: 12 },
  sm: { font: 'text-sm',   icon: 14 },
  md: { font: 'text-base', icon: 16 },
};

function middleTruncate(str, max) {
  if (!str || str.length <= max) return str || '';
  const tail = 12;
  const head = Math.max(1, max - tail - 1);
  return `${str.slice(0, head)}…${str.slice(-tail)}`;
}

const TIP_STYLE = {
  backgroundColor: 'var(--bg-card, #0f172a)',
  borderColor: 'var(--border-primary, #334155)',
  color: 'var(--text-primary, #e2e8f0)',
  minWidth: 200, maxWidth: 320,
};
const TIP_HINT_STYLE = { borderColor: 'var(--border-primary, #334155)', color: 'var(--text-muted, #94a3b8)' };

function PivotTooltip({ id, entityLabel, EntityIcon, engine, provider, severity, x, y }) {
  return (
    <div role="tooltip" id={id}
      className="fixed z-50 pointer-events-none rounded-lg border px-3 py-2 text-xs shadow-xl"
      style={{ ...TIP_STYLE, top: y + 18, left: x }}>
      <div className="flex items-center gap-1.5 font-semibold mb-1">
        {EntityIcon && <EntityIcon size={14} aria-hidden />}<span>{entityLabel}</span>
      </div>
      {engine && <div className="mb-1"><span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-cyan-500/15 text-cyan-300">{engine}</span></div>}
      {provider && <div className="mb-1"><CloudProviderBadge provider={provider} /></div>}
      {severity && <div className="mb-1"><SeverityBadge severity={severity} /></div>}
      <div className="mt-1 pt-1 border-t text-[10px]" style={TIP_HINT_STYLE}>↗ Cmd/Ctrl-click to open in new tab</div>
    </div>
  );
}

/**
 * @param {Object} props
 * @param {'asset'|'threat'|'finding'|'technique'|'control'|'scenario'|'workload'|'scan'|'agent'|'identity'|'framework'} props.to
 * @param {string} props.id
 * @param {string} [props.engine]      Required when to='finding'.
 * @param {string} [props.framework]   Required when to='control'.
 * @param {'aws'|'azure'|'gcp'|'oci'|'alicloud'|'k8s'} [props.provider]
 * @param {string} [props.kind]        Sub-type for scan (sast|dast|sca|project).
 * @param {string} [props.label]       Display text; defaults to middle-truncated id.
 * @param {number} [props.truncate=40]
 * @param {boolean}[props.showIcon=true]
 * @param {'critical'|'high'|'medium'|'low'|'info'} [props.showSeverity]
 * @param {'xs'|'sm'|'md'} [props.size='sm']
 * @param {(e: MouseEvent) => void} [props.onClick] Runs before navigation.
 * @param {React.ReactNode} [props.children] Overrides label.
 * @returns {JSX.Element}
 */
export default function PivotLink({
  to,
  id,
  engine,
  framework,
  provider,
  kind,
  label,
  truncate = 40,
  showIcon = true,
  showSeverity,
  size = 'sm',
  onClick,
  children,
}) {
  const [tooltipPos, setTooltipPos] = useState(null);
  const timerRef = useRef(null);
  const tooltipId = useId();

  const entry = ENTITY_REGISTRY[to];
  const entityLabel = entry?.label || to;
  const EntityIcon = entry?.icon || null;
  const sizeCfg = SIZE_CLASSES[size] || SIZE_CLASSES.sm;

  const url = useMemo(
    () => resolvePivotUrl({ to, id, engine, framework, provider, kind }),
    [to, id, engine, framework, provider, kind]
  );

  // Edge cases per §7
  if (!id) {
    return (
      <span className={`text-gray-500 ${sizeCfg.font}`} title={`No ${entityLabel} id`}>
        {children || label || '—'}
      </span>
    );
  }
  if (!entry) {
    if (typeof console !== 'undefined') console.warn(`PivotLink: unknown to="${to}"`);
    return <span className={`text-gray-500 ${sizeCfg.font}`}>{children || label || id}</span>;
  }
  if (url === null) {
    if (typeof console !== 'undefined') {
      console.warn(`PivotLink: missing required prop for to="${to}" (engine? framework?)`);
    }
    return <span className={`text-gray-500 ${sizeCfg.font}`}>{children || label || id}</span>;
  }

  const display = children || label || middleTruncate(String(id), truncate);

  const showTip = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    setTooltipPos({ x: r.left, y: r.bottom });
  };
  const scheduleTip = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setTooltipPos({ x: r.left, y: r.bottom }), 400);
  };
  const cancelTip = () => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setTooltipPos(null);
  };

  const handleClick = (e) => {
    // Fire telemetry first — must be unblockable per §7
    emit('cspm:pivot-click', {
      to,
      id,
      engine,
      provider,
      sourceRoute: typeof window !== 'undefined' ? window.location.pathname : null,
      timestamp: Date.now(),
    });
    if (onClick) {
      try { onClick(e); } catch (_err) { /* swallow */ }
    }
  };

  const baseCls =
    'inline-flex items-center text-cyan-400 hover:text-cyan-300 hover:underline ' +
    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-500 rounded-sm ' +
    sizeCfg.font;

  return (
    <>
      <Link href={url} prefetch={false} legacyBehavior>
        <a
          className={baseCls}
          title={String(id)}
          aria-label={`Open ${entityLabel}: ${id}`}
          aria-describedby={tooltipPos ? tooltipId : undefined}
          onClick={handleClick}
          onFocus={showTip}
          onBlur={cancelTip}
          onMouseEnter={scheduleTip}
          onMouseLeave={cancelTip}
        >
          {showIcon && EntityIcon && (
            <EntityIcon size={sizeCfg.icon} className="inline mr-1 shrink-0" aria-hidden />
          )}
          <span className="truncate" dir="auto">{display}</span>
          {showSeverity && (
            <span className="ml-2"><SeverityBadge severity={showSeverity} /></span>
          )}
        </a>
      </Link>
      {tooltipPos && (
        <PivotTooltip
          id={tooltipId}
          entityLabel={entityLabel}
          EntityIcon={EntityIcon}
          engine={engine}
          provider={provider}
          severity={showSeverity}
          x={tooltipPos.x}
          y={tooltipPos.y}
        />
      )}
    </>
  );
}
