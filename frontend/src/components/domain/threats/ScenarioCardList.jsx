'use client';

/**
 * ScenarioCardList — virtualised list of threat scenario cards.
 *
 * Rendering is handled by @tanstack/react-virtual to keep DOM size O(viewport)
 * regardless of how many scenarios the BFF returns.
 *
 * Filtering and sorting are performed by CommandRoom before this component
 * receives the final list — ScenarioCardList only renders what it receives.
 *
 * @param {Object}   props
 * @param {Array}    props.scenarios     - Already-filtered and sorted scenarios
 * @param {string}   props.selectedId   - Currently selected scenario id (from URL)
 * @param {Function} props.onCardClick  - Called with scenario when a card is clicked
 * @param {string}   [props.scanStatus] - 'running' | 'completed' | null
 * @param {number}   [props.totalCount] - Total unfiltered count (for footer)
 */

import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import ScenarioCard from './ScenarioCard';

const CARD_HEIGHT = 88; // px — fixed row height for virtualizer

export default function ScenarioCardList({
    scenarios = [],
    selectedId = null,
    onCardClick,
    scanStatus = null,
    totalCount = 0,
}) {
    const listRef = useRef(null);

    const virtualizer = useVirtualizer({
        count: scenarios.length,
        getScrollElement: () => listRef.current,
        estimateSize: () => CARD_HEIGHT,
        overscan: 5,
    });

    const displayTotal = totalCount || scenarios.length;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {/* Scan-in-progress amber banner */}
            {scanStatus === 'running' && (
                <div
                    style={{
                        backgroundColor: 'rgba(217,119,6,0.1)',
                        border: '1px solid rgba(217,119,6,0.3)',
                        borderRadius: 6,
                        padding: '8px 14px',
                        marginBottom: 10,
                        fontSize: 12,
                        color: '#D97706',
                        fontWeight: 600,
                    }}
                >
                    Scan in progress — results will update automatically.
                </div>
            )}

            {/* Empty state */}
            {scenarios.length === 0 && (
                <div
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'var(--text-muted)',
                        fontSize: 13,
                        padding: '40px 20px',
                        textAlign: 'center',
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 8,
                        minHeight: 120,
                    }}
                >
                    No threats match your filters.
                </div>
            )}

            {/* Virtualised scroll container */}
            {scenarios.length > 0 && (
                <div
                    ref={listRef}
                    style={{
                        flex: 1,
                        overflowY: 'auto',
                        position: 'relative',
                        maxHeight: 600,
                    }}
                >
                    <div
                        style={{
                            height: virtualizer.getTotalSize(),
                            position: 'relative',
                        }}
                    >
                        {virtualizer.getVirtualItems().map((vRow) => {
                            const scenario = scenarios[vRow.index];
                            return (
                                <div
                                    key={scenario.scenario_id}
                                    style={{
                                        position: 'absolute',
                                        top: vRow.start,
                                        left: 0,
                                        width: '100%',
                                        height: CARD_HEIGHT,
                                        paddingBottom: 6,
                                    }}
                                >
                                    <ScenarioCard
                                        scenario={scenario}
                                        isSelected={selectedId === scenario.scenario_id}
                                        onSelect={onCardClick}
                                    />
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* Count footer */}
            {scenarios.length > 0 && (
                <div
                    style={{
                        fontSize: 11,
                        color: 'var(--text-muted)',
                        paddingTop: 8,
                        borderTop: '1px solid var(--border-primary)',
                        marginTop: 6,
                        textAlign: 'right',
                    }}
                >
                    Showing {scenarios.length}
                    {displayTotal > scenarios.length ? ` of ${displayTotal}` : ''} scenarios
                </div>
            )}
        </div>
    );
}
