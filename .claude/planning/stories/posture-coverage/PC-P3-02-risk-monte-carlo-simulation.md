# Story PC-P3-02: Risk Engine — Monte Carlo Simulation for FAIR Loss Estimates

## Status: ready

## Metadata
- **Phase**: P3 — Tier C (mathematical modeling; requires statistical library + performance tuning)
- **Sprint**: Posture Coverage Enhancement — Planning Track
- **Points**: 8
- **Priority**: P3
- **Depends on**: PC-P1-01 (encryption signals), PC-P1-04 (vuln signals), PC-P2-01 (KEV)
- **RACI**: R=DEV A=DL C=SA I=PO
- **Security Gate**: bmad-security-reviewer

## Gap Being Closed

**Current state:** The risk engine computes FAIR risk as single-point estimates:
```
exposure = LEF × LM   (single value, no uncertainty range)
```

Real FAIR methodology requires probability distributions (PERT or log-normal) for each input variable and uses Monte Carlo simulation (10,000+ iterations) to produce a **range** of loss outcomes with confidence intervals. The current single-point estimate gives false precision — "this scenario costs $2.1M" when the honest answer is "$500K–$8M at 90% confidence."

**Why Tier C:** Requires `scipy` or `numpy` (not currently in the risk engine requirements), performance testing (10K iterations × N scenarios must complete in < 30s), and output format changes that affect the BFF and UI.

## FAIR Input Variable Distributions

Replace scalar values with PERT distributions (min, most_likely, max):

| Input Variable | Current | With Monte Carlo |
|---------------|---------|-----------------|
| EPSS (threat event frequency) | scalar from DB | PERT(epss*0.5, epss, min(epss*2,1)) |
| exposure_factor | scalar | PERT(0.1, computed_exposure, 0.95) |
| records_at_risk | scalar | PERT(count*0.3, count, count*3) |
| per_record_cost | $150 fixed | PERT($75, $150, $450) |
| regulatory_fine | scalar | PERT(fine*0.1, fine, fine*2.5) |

## New Output Shape

```python
# Current risk_scenario output:
{"total_exposure": 2100000, "severity": "critical"}

# New output with Monte Carlo:
{
    "exposure_p10": 450000,    # 10th percentile
    "exposure_p50": 1800000,   # median (most likely)
    "exposure_p90": 7200000,   # 90th percentile
    "exposure_mean": 2100000,  # mean (backward compat)
    "total_exposure": 2100000, # keep for backward compat
    "confidence_range": "$450K–$7.2M",
    "simulation_iterations": 10000
}
```

## BFF + UI Changes

- BFF `/views/risk` must pass through `exposure_p10`, `exposure_p50`, `exposure_p90`
- UI risk scenario card shows: `$450K – $7.2M` range with `~$1.8M most likely`
- Confidence band visualization (histogram or range bar)

## Performance Constraints

- 10,000 iterations per scenario
- Max 200 scenarios per scan (CRITICAL + HIGH only)
- Target: < 30 seconds total (use `numpy` vectorized Monte Carlo, not Python loops)
- Offload to background task if > 30s: return `status: computing` and poll

## Acceptance Criteria

- [ ] AC-1: Risk scenarios have `exposure_p10`, `exposure_p50`, `exposure_p90` fields populated
- [ ] AC-2: `exposure_p10 < exposure_p50 < exposure_p90` always true (sanity check)
- [ ] AC-3: 10,000 iterations for 100 scenarios completes in < 30 seconds (benchmark required)
- [ ] AC-4: `total_exposure` field preserved for backward compatibility (equals `exposure_p50`)
- [ ] AC-5: BFF passes through range fields to UI
- [ ] AC-6: UI shows confidence range — `$Xk – $Yk` on risk scenario cards
- [ ] AC-7: New risk engine image: `yadavanup84/engine-risk:v-risk-montecarlo1`

## Dependencies to Add
```
numpy>=1.24.0
scipy>=1.11.0  # for scipy.stats.triang (PERT distribution)
```

## Definition of Done
- [ ] Monte Carlo implemented with numpy vectorization
- [ ] Performance benchmark passes (30s limit)
- [ ] BFF + UI updated to show range
- [ ] Backward compat test: existing `total_exposure` field unchanged in API response
