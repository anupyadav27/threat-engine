/**
 * Lightweight telemetry stub.
 *
 * Fire-and-forget CustomEvent dispatcher on `window`. Production sinks
 * (DataDog RUM / PostHog) can be wired by attaching a global listener
 * — this module never imports or awaits an external SDK.
 *
 * Per JNY-07 §5 + CP-2 C5: dev-mode console.debug mirror.
 *
 * @see .claude/planning/stories/JNY-07_handoff_design.md §5
 */

const IS_DEV =
  typeof process !== 'undefined' &&
  process.env &&
  process.env.NODE_ENV !== 'production';

/**
 * Emit a telemetry event. SSR-safe (no-op when window is absent).
 * Never throws; never awaits.
 *
 * @param {string} eventName - Custom event name, e.g. 'cspm:pivot-click'.
 * @param {Object} [payload] - Arbitrary detail object forwarded as event.detail.
 */
export function emit(eventName, payload = {}) {
  if (typeof window === 'undefined') return;
  try {
    window.dispatchEvent(new CustomEvent(eventName, { detail: payload }));
    if (IS_DEV) {
      // eslint-disable-next-line no-console
      console.debug('[telemetry]', eventName, payload);
    }
  } catch (_e) {
    /* never break UX */
  }
}

export default { emit };
