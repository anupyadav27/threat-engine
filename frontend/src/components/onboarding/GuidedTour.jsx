'use client';

import { useState, useEffect, useCallback, useRef, createContext, useContext } from 'react';
import { createPortal } from 'react-dom';
import { X, ChevronLeft, ChevronRight, Sparkles } from 'lucide-react';

/* ─── Tour context ─────────────────────────────────────────────────────────── */

const TourContext = createContext(null);

export function useTour() {
  return useContext(TourContext);
}

/* ─── Step definitions ─────────────────────────────────────────────────────── */

const TOUR_STEPS = [
  {
    target: 'tour-posture',
    title: 'Overall security posture',
    body: 'Your posture score is a weighted composite of findings, risk, and compliance across every connected cloud account.',
    placement: 'bottom',
  },
  {
    target: 'tour-kpi',
    title: 'KPI cards — your security pulse',
    body: 'Five live metrics: total assets, critical+high findings, active threats, internet-exposed resources, and compliance score. Click any card to drill in.',
    placement: 'bottom',
  },
  {
    target: 'tour-tab-switcher',
    title: 'Domain views',
    body: 'Switch between Overview, Security Posture, Threats, Compliance, IAM, Network and more. Each tab loads its own BFF data slice.',
    placement: 'bottom',
  },
  {
    target: 'tour-tab-compliance',
    title: 'Compliance tracking',
    body: 'Real-time scores across 13 frameworks — CIS, NIST, PCI-DSS, ISO 27001, HIPAA, SOC 2 and more. No manual mapping required.',
    placement: 'bottom',
  },
  {
    target: 'tour-tab-threats',
    title: 'Active threats',
    body: 'MITRE ATT&CK–mapped findings with attack-path chains. Each threat shows blast radius and the exact remediation step.',
    placement: 'bottom',
  },
];

/* ─── Tooltip placement ────────────────────────────────────────────────────── */

const GAP = 14; // px between spotlight edge and tooltip

function computeTooltipStyle(rect, placement, tooltipRef) {
  if (!rect) return {};
  const tw = tooltipRef.current?.offsetWidth  ?? 320;
  const th = tooltipRef.current?.offsetHeight ?? 120;

  switch (placement) {
    case 'bottom':
      return {
        top:  rect.bottom + GAP,
        left: Math.max(8, Math.min(rect.left + rect.width / 2 - tw / 2, window.innerWidth - tw - 8)),
      };
    case 'top':
      return {
        top:  rect.top - th - GAP,
        left: Math.max(8, Math.min(rect.left + rect.width / 2 - tw / 2, window.innerWidth - tw - 8)),
      };
    case 'left':
      return {
        top:  rect.top + rect.height / 2 - th / 2,
        left: Math.max(8, rect.left - tw - GAP),
      };
    case 'right':
    default:
      return {
        top:  rect.top + rect.height / 2 - th / 2,
        left: rect.right + GAP,
      };
  }
}

/* ─── Overlay + tooltip ────────────────────────────────────────────────────── */

function TourOverlay({ steps, stepIdx, onNext, onPrev, onClose }) {
  const step = steps[stepIdx];
  const [rect, setRect] = useState(null);
  const tooltipRef = useRef(null);
  const [tooltipStyle, setTooltipStyle] = useState({});

  // Find target element and measure
  useEffect(() => {
    const el = document.querySelector(`[data-tour="${step.target}"]`);
    if (!el) { setRect(null); return; }

    el.scrollIntoView({ behavior: 'smooth', block: 'center' });

    const update = () => {
      const r = el.getBoundingClientRect();
      setRect(r);
    };

    update();
    // re-measure after scroll settles
    const t = setTimeout(update, 350);
    window.addEventListener('resize', update);
    return () => { clearTimeout(t); window.removeEventListener('resize', update); };
  }, [step.target]);

  // Compute tooltip position whenever rect or step changes
  useEffect(() => {
    if (!rect) return;
    setTooltipStyle(computeTooltipStyle(rect, step.placement, tooltipRef));
  }, [rect, step.placement]);

  const PADDING = 8;

  return createPortal(
    <>
      {/* Dark backdrop with cutout */}
      <div className="fixed inset-0 z-[9998] pointer-events-none" aria-hidden>
        {rect ? (
          <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <mask id="tour-mask">
                <rect width="100%" height="100%" fill="white" />
                <rect
                  x={rect.left - PADDING}
                  y={rect.top - PADDING}
                  width={rect.width + PADDING * 2}
                  height={rect.height + PADDING * 2}
                  rx="8"
                  fill="black"
                />
              </mask>
            </defs>
            <rect width="100%" height="100%" fill="rgba(0,0,0,0.65)" mask="url(#tour-mask)" />
            {/* Highlight ring */}
            <rect
              x={rect.left - PADDING}
              y={rect.top - PADDING}
              width={rect.width + PADDING * 2}
              height={rect.height + PADDING * 2}
              rx="8"
              fill="none"
              stroke="#6366F1"
              strokeWidth="2"
              opacity="0.8"
            />
          </svg>
        ) : (
          <div className="absolute inset-0 bg-black/60" />
        )}
      </div>

      {/* Clickable close zone on backdrop */}
      <div className="fixed inset-0 z-[9998]" onClick={onClose} />

      {/* Tooltip card */}
      <div
        ref={tooltipRef}
        className="fixed z-[9999] w-80 rounded-2xl shadow-2xl pointer-events-auto"
        style={{
          ...tooltipStyle,
          background: 'var(--bg-secondary, #0D1530)',
          border: '1px solid var(--border-primary, #1E2D50)',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between p-4 pb-2">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-indigo-400 flex-shrink-0" />
            <span className="text-sm font-semibold text-white">{step.title}</span>
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-white transition-colors -mt-0.5 -mr-1"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="px-4 pb-4 text-xs text-slate-400 leading-relaxed">{step.body}</p>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 pb-4">
          {/* Step dots */}
          <div className="flex gap-1.5">
            {steps.map((_, i) => (
              <span
                key={i}
                className={`w-1.5 h-1.5 rounded-full transition-colors ${
                  i === stepIdx ? 'bg-indigo-400' : 'bg-slate-700'
                }`}
              />
            ))}
          </div>

          <div className="flex items-center gap-2">
            {stepIdx > 0 && (
              <button
                onClick={onPrev}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white transition-colors"
                style={{ background: 'var(--bg-tertiary, #162040)' }}
              >
                <ChevronLeft className="w-3.5 h-3.5" /> Back
              </button>
            )}
            <button
              onClick={stepIdx < steps.length - 1 ? onNext : onClose}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium text-white transition-colors"
              style={{ background: '#6366F1' }}
            >
              {stepIdx < steps.length - 1 ? (
                <><span>Next</span><ChevronRight className="w-3.5 h-3.5" /></>
              ) : (
                <span>Done</span>
              )}
            </button>
          </div>
        </div>
      </div>
    </>,
    document.body
  );
}

/* ─── Provider ─────────────────────────────────────────────────────────────── */

export function GuidedTourProvider({ children }) {
  const [active, setActive] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);

  const start = useCallback(() => {
    setStepIdx(0);
    setActive(true);
  }, []);

  const close = useCallback(() => setActive(false), []);

  const next = useCallback(() => {
    setStepIdx(i => (i < TOUR_STEPS.length - 1 ? i + 1 : i));
  }, []);

  const prev = useCallback(() => {
    setStepIdx(i => Math.max(0, i - 1));
  }, []);

  // Close on Escape
  useEffect(() => {
    if (!active) return;
    const handler = (e) => { if (e.key === 'Escape') close(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [active, close]);

  return (
    <TourContext.Provider value={{ start, close, active }}>
      {children}
      {active && (
        <TourOverlay
          steps={TOUR_STEPS}
          stepIdx={stepIdx}
          onNext={next}
          onPrev={prev}
          onClose={close}
        />
      )}
    </TourContext.Provider>
  );
}

/* ─── Trigger button ────────────────────────────────────────────────────────── */

export function TourButton({ className = '' }) {
  const tour = useTour();
  if (!tour) return null;

  return (
    <button
      onClick={tour.start}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${className}`}
      style={{
        background: 'rgba(99,102,241,0.1)',
        border: '1px solid rgba(99,102,241,0.3)',
        color: '#818CF8',
      }}
    >
      <Sparkles className="w-3.5 h-3.5" />
      Take a tour
    </button>
  );
}
