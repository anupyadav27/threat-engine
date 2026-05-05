/**
 * Engine-specific tab plugin registry for the universal finding-detail page.
 *
 * Phase B (JNY-05) ships with an EMPTY registry. Universal tabs (Overview,
 * Resource Context, Related Findings, Compliance, Remediation) are always
 * rendered first; entries here append after the universal tabs.
 *
 * Contract per entry:
 *   {
 *     tabId:    string,                 // unique per engine, used in ?tab=
 *     label:    string,                 // tab label
 *     component: () => Promise<{default: ReactComponent}>, // next/dynamic loader
 *     fetchPath?: (id) => string,       // optional secondary BFF path
 *     visible?: (finding) => boolean,   // optional visibility predicate
 *   }
 *
 * Components receive props: { finding, engine, id }
 *
 * Example registration (CIEM Activity Heatmap, kept commented for reference):
 *
 *   ciem: [
 *     {
 *       tabId: 'activity',
 *       label: 'Activity Heatmap',
 *       component: () => import('@/components/ciem/ActivityHeatmapTab'),
 *       fetchPath: (id) => `ciem/findings/${id}/activity`,
 *     },
 *   ],
 */
export const ENGINE_FINDING_TABS = {};

export default ENGINE_FINDING_TABS;
