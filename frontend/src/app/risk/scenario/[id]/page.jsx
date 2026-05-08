import RiskScenarioPageClient from './RiskScenarioPageClient';

/**
 * Risk scenario detail route: /risk/scenario/[id]
 *
 * Server shell — id validation runs in layout.jsx. Client component fetches
 * BFF (`/api/v1/views/risk/scenario/{id}`) and renders the 4-tab template:
 *   Overview · Driving Findings · Mitigations · Timeline.
 */
export default function RiskScenarioPage({ params }) {
  const { id } = params || {};
  return <RiskScenarioPageClient id={id} />;
}
