'use client';

/**
 * RefreshBus — lightweight pub/sub for page-wide refresh.
 *
 * Pages or tabs subscribe to a refresh event; the EngineShell's Refresh button
 * (or a global keypress) calls emitRefresh() to ask every subscriber to re-fetch.
 *
 * Usage:
 *   useEffect(() => subscribeRefresh(() => refetch()), [refetch]);
 *
 *   <EngineShell onRefresh={() => emitRefresh()}> ... </EngineShell>
 */

const listeners = new Set();

export function subscribeRefresh(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function emitRefresh(scope) {
  listeners.forEach(fn => {
    try {
      fn(scope);
    } catch (err) {
      // swallow — one listener should not break others
      // eslint-disable-next-line no-console
      console.error('[refreshBus] listener error', err);
    }
  });
}

export function clearRefreshSubscribers() {
  listeners.clear();
}
