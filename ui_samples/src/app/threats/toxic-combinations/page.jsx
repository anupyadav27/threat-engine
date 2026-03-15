'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  AlertTriangle,
  Zap,
  Target,
  TrendingUp,
  ArrowRight,
  ChevronRight,
  Lock,
  Eye,
  Shield,
  Database,
  Cloud,
  Activity,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';

/**
 * Toxic Combinations Page - Compound Risk Analysis
 * Identifies resources with dangerous overlapping misconfigurations that create exponential risk
 * Backend API: GET /api/v1/graph/toxic-combinations, /api/v1/threat/resources/{resource_uid}/posture
 */
export default function ToxicCombinationsPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [toxicCombos, setToxicCombos] = useState([]);
  const [selectedMatrixCell, setSelectedMatrixCell] = useState(null);
  const [matrixDetail, setMatrixDetail] = useState(null);


  // Mock combination matrix data
  const misconfigCategories = [
    'Public Access',
    'Weak Encryption',
    'Excessive Permissions',
    'Logging Disabled',
    'Unpatched Systems',
  ];

  const [matrix, setMatrix] = useState({});
  const [error, setError] = useState(null);

  // Fetch toxic combinations on mount
  useEffect(() => {
    const fetchCombinations = async () => {
      setLoading(true);
      setError(null);
      try {
        const [combosRes, matrixRes] = await Promise.allSettled([
          getFromEngine('threat', '/api/v1/graph/toxic-combinations'),
          getFromEngine('threat', '/api/v1/graph/toxic-combinations/matrix'),
        ]);

        if (combosRes.status === 'fulfilled' && combosRes.value && !combosRes.value.error) {
          const raw = Array.isArray(combosRes.value) ? combosRes.value : (combosRes.value.combinations || combosRes.value.results || []);
          setToxicCombos(raw);
        } else {
          setError('Failed to load toxic combinations data.');
        }

        if (matrixRes.status === 'fulfilled' && matrixRes.value && !matrixRes.value.error) {
          setMatrix(matrixRes.value.matrix || matrixRes.value || {});
        }
      } catch (err) {
        console.warn('Error fetching toxic combinations:', err);
        setError('Failed to load toxic combinations data.');
      } finally {
        setLoading(false);
      }
    };

    fetchCombinations();
  }, []);

  // Calculate statistics
  const stats = {
    totalCombos: toxicCombos.length,
    criticalCombos: toxicCombos.filter((c) => c.toxicityScore >= 90).length,
    resourcesAtRisk: toxicCombos.length,
    avgMultiplier: (
      toxicCombos.reduce((sum, c) => sum + c.riskMultiplier, 0) /
      (toxicCombos.length || 1)
    ).toFixed(2),
  };

  // Render toxicity score with compound visualization
  const ToxicityMeter = ({ score, multiplier }) => {
    const segments = 10;
    const filledSegments = Math.ceil((score / 100) * segments);

    return (
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex gap-1">
            {Array.from({ length: segments }).map((_, idx) => (
              <div
                key={idx}
                className="h-2 rounded-sm transition-all"
                style={{
                  width: '8px',
                  backgroundColor:
                    idx < filledSegments
                      ? score >= 90
                        ? '#ef4444'
                        : score >= 75
                        ? '#f97316'
                        : '#eab308'
                      : 'var(--bg-tertiary)',
                }}
              />
            ))}
          </div>
          <span className="text-sm font-bold" style={{ color: score >= 90 ? '#ef4444' : '#f97316' }}>
            {score}
          </span>
        </div>
        <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Risk Multiplier: <span style={{ color: 'var(--accent-warning)' }}>×{multiplier}</span>
        </div>
      </div>
    );
  };

  // Render interconnected factor visualization
  const FactorConnector = ({ factors }) => {
    return (
      <div className="relative py-4">
        <div className="flex items-center justify-between gap-2">
          {factors.map((factor, idx) => (
            <div key={idx} className="flex-1 space-y-2">
              <div
                className="px-3 py-2 rounded-lg text-xs font-medium text-center transition-all cursor-pointer hover:scale-105"
                style={{
                  backgroundColor:
                    factor.severity === 'critical'
                      ? 'rgba(239, 68, 68, 0.15)'
                      : 'rgba(249, 115, 22, 0.15)',
                  borderLeft: `3px solid ${factor.severity === 'critical' ? '#ef4444' : '#f97316'}`,
                  color: factor.severity === 'critical' ? '#fecaca' : '#fed7aa',
                }}
              >
                {factor.name}
              </div>
              {idx < factors.length - 1 && (
                <div className="flex justify-center">
                  <ArrowRight
                    className="w-4 h-4"
                    style={{ color: 'var(--accent-warning)' }}
                  />
                </div>
              )}
            </div>
          ))}
        </div>
        <div className="mt-3 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
          <p className="text-xs font-semibold" style={{ color: 'var(--accent-danger)' }}>
            = {factors.length > 2 ? 'EXPONENTIAL RISK' : 'COMPOUND RISK'}
          </p>
        </div>
      </div>
    );
  };

  // Render combination matrix heatmap
  const CombinationMatrix = () => {
    const maxValue = 52;
    const getIntensity = (value) => {
      const intensity = (value / maxValue) * 100;
      return intensity;
    };

    return (
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
          Misconfig Co-occurrence Matrix
        </h3>
        <p className="text-sm mb-4" style={{ color: 'var(--text-secondary)' }}>
          Cell intensity shows how often misconfigurations appear together
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottomColor: 'var(--border-primary)' }} className="border-b">
                <th className="text-left py-3 px-3" style={{ color: 'var(--text-tertiary)' }}>
                  Config Type
                </th>
                {misconfigCategories.map((cat) => (
                  <th
                    key={cat}
                    className="text-center py-3 px-2"
                    style={{ color: 'var(--text-tertiary)' }}
                  >
                    <div className="transform -rotate-45 origin-center h-12 flex items-center justify-center">
                      <span className="whitespace-nowrap text-xs">{cat}</span>
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {misconfigCategories.map((rowCat, rowIdx) => (
                <tr
                  key={rowCat}
                  style={{ borderBottomColor: 'var(--border-primary)' }}
                  className="border-b"
                >
                  <td className="py-3 px-3 text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
                    {rowCat}
                  </td>
                  {misconfigCategories.map((colCat, colIdx) => {
                    const value = matrix[rowCat]?.[colIdx] || 0;
                    const intensity = getIntensity(value);

                    return (
                      <td
                        key={`${rowCat}-${colCat}`}
                        className="py-3 px-2 text-center cursor-pointer transition-all hover:scale-110"
                        onClick={() => {
                          setSelectedMatrixCell({ row: rowCat, col: colCat });
                          setMatrixDetail({
                            combinations: value,
                            resources: Math.floor(value / 2),
                          });
                        }}
                        style={{
                          backgroundColor: `rgba(239, 68, 68, ${intensity / 100})`,
                          color: intensity > 50 ? '#fff' : 'var(--text-secondary)',
                          cursor: 'pointer',
                        }}
                      >
                        <span className="font-semibold">{value}</span>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {selectedMatrixCell && matrixDetail && (
          <div
            className="mt-4 p-4 rounded-lg border"
            style={{
              backgroundColor: 'var(--bg-secondary)',
              borderColor: 'var(--accent-danger)',
            }}
          >
            <p className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
              {selectedMatrixCell.row} + {selectedMatrixCell.col}
            </p>
            <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
              <strong>{matrixDetail.combinations}</strong> co-occurrences affecting{' '}
              <strong>{matrixDetail.resources}</strong> resources
            </p>
          </div>
        )}
      </div>
    );
  };

  // Render priority remediation queue
  const RemediationQueue = () => {
    const sortedByPriority = [...toxicCombos].sort(
      (a, b) => b.toxicityScore - a.toxicityScore
    );

    return (
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
          Priority Remediation Queue
        </h3>
        <div className="space-y-3">
          {sortedByPriority.map((combo, idx) => (
            <div
              key={combo.id}
              className="flex items-center gap-4 p-4 rounded-lg border cursor-pointer transition-all hover:border-opacity-100"
              style={{
                backgroundColor: 'var(--bg-secondary)',
                borderColor: combo.toxicityScore >= 90 ? '#ef4444' : 'var(--border-primary)',
                borderLeftWidth: '4px',
              }}
              onClick={() => router.push(`/threats/toxic-combinations/${combo.id}`)}
            >
              <div className="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--accent-primary)' }}>
                {idx + 1}
              </div>

              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm truncate" style={{ color: 'var(--text-primary)' }}>
                  {combo.resourceName}
                </p>
                <p className="text-xs mt-1 truncate" style={{ color: 'var(--text-tertiary)' }}>
                  {combo.resourceType} • {combo.provider}
                </p>
              </div>

              <div className="flex items-center gap-3 flex-shrink-0">
                <div className="text-right">
                  <p className="text-sm font-bold" style={{ color: '#ef4444' }}>
                    {combo.toxicityScore}
                  </p>
                  <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    ×{combo.riskMultiplier}
                  </p>
                </div>
                <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Toxic Combinations
        </h1>
        <p className="mt-1" style={{ color: 'var(--text-secondary)' }}>
          Identify resources with dangerous overlapping misconfigurations that compound risk.
          A single misconfiguration is bad; multiple overlapping misconfigurations can be catastrophic.
        </p>
      </div>

      {/* Error state */}
      {error && toxicCombos.length === 0 && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: '#ef4444' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && toxicCombos.length === 0 && (
        <div className="rounded-lg p-8 border text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No toxic combinations detected. Run a threat scan to identify compound risks.</p>
        </div>
      )}

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Toxic Combinations"
          value={stats.totalCombos}
          subtitle="Identified"
          icon={<Zap className="w-5 h-5" />}
          color="red"
        />
        <KpiCard
          title="Critical Combos"
          value={stats.criticalCombos}
          subtitle="Score ≥90"
          icon={<AlertTriangle className="w-5 h-5" />}
          color="red"
        />
        <KpiCard
          title="Resources at Risk"
          value={stats.resourcesAtRisk}
          subtitle="Immediate action"
          icon={<Target className="w-5 h-5" />}
          color="orange"
        />
        <KpiCard
          title="Avg Risk Multiplier"
          value={`${stats.avgMultiplier}x`}
          subtitle="Compound effect"
          icon={<TrendingUp className="w-5 h-5" />}
          color="purple"
        />
      </div>

      {/* Toxic Combination Cards */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Toxic Combination Details
          </h2>
          <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
            Each resource below has multiple overlapping security issues. Click any card for detailed remediation steps.
          </p>
        </div>

        <div className="space-y-4">
          {toxicCombos.map((combo) => (
            <div
              key={combo.id}
              className="rounded-xl p-6 border transition-all hover:border-opacity-100 cursor-pointer"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: combo.toxicityScore >= 90 ? '#ef4444' : 'var(--border-primary)',
                borderLeftWidth: combo.toxicityScore >= 90 ? '4px' : '1px',
              }}
              onClick={() => router.push(`/threats/toxic-combinations/${combo.id}`)}
            >
              {/* Header: Resource Info */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                      {combo.resourceName}
                    </h3>
                    <span
                      className="text-xs px-3 py-1 rounded-full font-medium"
                      style={{
                        backgroundColor: 'var(--bg-secondary)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {combo.resourceType}
                    </span>
                    <span
                      className="text-xs px-3 py-1 rounded-full font-medium"
                      style={{
                        backgroundColor: combo.provider === 'AWS' ? 'rgba(255, 153, 0, 0.1)' : 'rgba(34, 136, 204, 0.1)',
                        color: combo.provider === 'AWS' ? '#ff9900' : '#2288cc',
                      }}
                    >
                      {combo.provider}
                    </span>
                  </div>
                  <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                    {combo.compoundRisk}
                  </p>
                </div>
              </div>

              {/* Toxicity Score Section */}
              <div className="mb-4 pb-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                <p className="text-xs font-semibold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                  Toxicity Score
                </p>
                <ToxicityMeter score={combo.toxicityScore} multiplier={combo.riskMultiplier} />
              </div>

              {/* Factor Connector */}
              <div className="mb-4 pb-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                <p className="text-xs font-semibold mb-3 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                  Overlapping Factors
                </p>
                <FactorConnector factors={combo.factors} />
              </div>

              {/* MITRE Techniques */}
              <div className="mb-4 pb-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                <p className="text-xs font-semibold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                  Attack Chain
                </p>
                <p className="text-sm mb-2" style={{ color: 'var(--text-secondary)' }}>
                  {combo.affectedTechniques}
                </p>
                <div className="flex flex-wrap gap-2">
                  {combo.techniquesMapped.map((tech) => (
                    <code
                      key={tech}
                      className="text-xs px-2 py-1 rounded font-mono"
                      style={{
                        backgroundColor: 'var(--bg-tertiary)',
                        color: 'var(--accent-primary)',
                      }}
                    >
                      {tech}
                    </code>
                  ))}
                </div>
              </div>

              {/* Priority Actions */}
              <div className="mb-4 pb-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                <p className="text-xs font-semibold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                  Recommended Actions
                </p>
                <ul className="space-y-2">
                  {combo.priorityActions.slice(0, 2).map((action, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
                      <span style={{ color: 'var(--accent-warning)' }} className="font-bold mt-0.5">
                        ✓
                      </span>
                      {action}
                    </li>
                  ))}
                  {combo.priorityActions.length > 2 && (
                    <li className="text-xs italic" style={{ color: 'var(--text-muted)' }}>
                      +{combo.priorityActions.length - 2} more actions
                    </li>
                  )}
                </ul>
              </div>

              {/* Data Impact */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>
                    Potential Records at Risk
                  </p>
                  <p className="text-lg font-bold" style={{ color: '#ef4444' }}>
                    {combo.estimatedExposure.toLocaleString()}
                  </p>
                </div>
                <ChevronRight className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Combination Matrix */}
      <CombinationMatrix />

      {/* Priority Remediation Queue */}
      <RemediationQueue />

      {/* Risk Compounding Explanation */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
          Understanding Toxic Combinations
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="p-4 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            <p className="font-semibold mb-2" style={{ color: 'var(--accent-warning)' }}>
              Single Issue
            </p>
            <p style={{ color: 'var(--text-secondary)' }}>
              One misconfiguration (e.g., public access) has limited impact if other controls exist.
            </p>
          </div>
          <div className="p-4 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            <p className="font-semibold mb-2" style={{ color: 'var(--accent-danger)' }}>
              Two Factors
            </p>
            <p style={{ color: 'var(--text-secondary)' }}>
              Multiple overlapping issues bypass defenses (e.g., public + no encryption = direct data exposure).
            </p>
          </div>
          <div className="p-4 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            <p className="font-semibold mb-2" style={{ color: '#ff4444' }}>
              Three+ Factors
            </p>
            <p style={{ color: 'var(--text-secondary)' }}>
              Exponential risk multiplier. Complete security failure enabling full compromise and data loss.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
