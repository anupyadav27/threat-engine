'use client';

/**
 * ScanComparison — scan selector + day preset buttons.
 *
 * Two native <select> dropdowns populated from availableScans.
 * Preset buttons [7d][30d][90d] auto-select the two most recent
 * scans within each window.
 *
 * Validation: if scan_a is newer than scan_b, they are silently
 * swapped and a 2-second toast is shown.
 *
 * Props:
 *   availableScans  {Array}    - [{scan_run_id, completed_at, label}] newest-first
 *   activeScanA     {string}   - currently selected scan A run id
 *   activeScanB     {string}   - currently selected scan B run id
 *   activeDays      {number}   - currently active day preset
 *   loading         {boolean}  - show spinner when true
 *   onScanChange    {function(scan_a_id, scan_b_id)}
 *   onDaysChange    {function(days)}
 */

import { useState, useCallback } from 'react';

const DAY_PRESETS = [7, 30, 90];

function _scansWithinDays(scans, days) {
    if (!scans || !scans.length) return [];
    const cutoff = new Date(Date.now() - days * 86400 * 1000).toISOString();
    return scans.filter((s) => (s.completed_at || '') >= cutoff);
}

function _optionLabel(scan) {
    const short = scan.scan_run_id ? scan.scan_run_id.slice(0, 8) : '?';
    const label = scan.label || scan.completed_at?.slice(0, 10) || 'Unknown';
    return `${label} (${short}…)`;
}

export default function ScanComparison({
    availableScans = [],
    activeScanA = '',
    activeScanB = '',
    activeDays = 90,
    loading = false,
    onScanChange,
    onDaysChange,
}) {
    const [toast, setToast] = useState('');

    const showToast = useCallback((msg) => {
        setToast(msg);
        setTimeout(() => setToast(''), 2000);
    }, []);

    const _lookupTs = useCallback(
        (id) => {
            const s = availableScans.find((x) => x.scan_run_id === id);
            return s?.completed_at || '';
        },
        [availableScans],
    );

    const _emit = useCallback(
        (a, b) => {
            const tsA = _lookupTs(a);
            const tsB = _lookupTs(b);
            // Ensure scan_a is older than scan_b
            if (tsA && tsB && tsA > tsB) {
                showToast('Scans reordered for chronological comparison.');
                onScanChange?.(b, a);
            } else {
                onScanChange?.(a, b);
            }
        },
        [_lookupTs, onScanChange, showToast],
    );

    const handleDayPreset = useCallback(
        (days) => {
            onDaysChange?.(days);
            const inWindow = _scansWithinDays(availableScans, days);
            if (inWindow.length >= 2) {
                _emit(inWindow[1].scan_run_id, inWindow[0].scan_run_id);
            } else if (inWindow.length === 1) {
                onScanChange?.(inWindow[0].scan_run_id, inWindow[0].scan_run_id);
            }
        },
        [availableScans, onDaysChange, _emit, onScanChange],
    );

    const handleSelectA = useCallback(
        (e) => _emit(e.target.value, activeScanB),
        [_emit, activeScanB],
    );

    const handleSelectB = useCallback(
        (e) => _emit(activeScanA, e.target.value),
        [_emit, activeScanA],
    );

    const selectStyle = {
        backgroundColor: 'var(--bg-tertiary)',
        color: 'var(--text-primary)',
        border: '1px solid var(--border-primary)',
        borderRadius: 6,
        padding: '5px 10px',
        fontSize: 12,
        cursor: 'pointer',
        minWidth: 160,
    };

    return (
        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            {/* Day preset buttons */}
            <div style={{ display: 'flex', gap: 4 }}>
                {DAY_PRESETS.map((d) => {
                    const active = d === activeDays;
                    return (
                        <button
                            key={d}
                            onClick={() => handleDayPreset(d)}
                            style={{
                                padding: '4px 12px',
                                borderRadius: 6,
                                fontSize: 12,
                                fontWeight: active ? 700 : 500,
                                border: '1px solid',
                                borderColor: active ? '#EA580C' : 'var(--border-primary)',
                                backgroundColor: active ? 'rgba(234,88,12,0.12)' : 'transparent',
                                color: active ? '#EA580C' : 'var(--text-muted)',
                                cursor: 'pointer',
                            }}
                        >
                            {d}d
                        </button>
                    );
                })}
            </div>

            {/* Separator */}
            <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>Compare:</span>

            {/* Scan A selector */}
            <select
                value={activeScanA}
                onChange={handleSelectA}
                disabled={!availableScans.length}
                style={selectStyle}
            >
                <option value="">— Select scan A —</option>
                {availableScans.map((s) => (
                    <option key={s.scan_run_id} value={s.scan_run_id}>
                        {_optionLabel(s)}
                    </option>
                ))}
            </select>

            <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>vs</span>

            {/* Scan B selector */}
            <select
                value={activeScanB}
                onChange={handleSelectB}
                disabled={!availableScans.length}
                style={selectStyle}
            >
                <option value="">— Select scan B —</option>
                {availableScans.map((s) => (
                    <option key={s.scan_run_id} value={s.scan_run_id}>
                        {_optionLabel(s)}
                    </option>
                ))}
            </select>

            {/* Loading spinner */}
            {loading && (
                <div
                    style={{
                        width: 16,
                        height: 16,
                        borderRadius: '50%',
                        border: '2px solid var(--border-primary)',
                        borderTopColor: '#EA580C',
                        animation: 'spin 0.8s linear infinite',
                    }}
                />
            )}

            {/* Toast */}
            {toast && (
                <span
                    style={{
                        fontSize: 11,
                        color: '#D97706',
                        backgroundColor: 'rgba(217,119,6,0.1)',
                        border: '1px solid rgba(217,119,6,0.3)',
                        borderRadius: 6,
                        padding: '3px 10px',
                    }}
                >
                    {toast}
                </span>
            )}

            <style>{`
                @keyframes spin { to { transform: rotate(360deg); } }
            `}</style>
        </div>
    );
}
