# Story PC-P3-03: CDR Engine — ML-Based Behavioral Anomaly Detection (L3 Enhancement)

## Status: ready

## Metadata
- **Phase**: P3 — Tier C (requires 30+ days of historical data + ML model training pipeline)
- **Sprint**: Posture Coverage Enhancement — Planning Track
- **Points**: 13
- **Priority**: P3
- **Depends on**: CDR L1/L2 working (v-cdr-internal-auth1), `cdr_actor_daily_stats` table populated for 30+ days
- **RACI**: R=DEV A=DL C=SA,ML-engineer I=PO
- **Security Gate**: bmad-security-architect (new ML pipeline design) + bmad-security-reviewer

## Gap Being Closed

**Current state:** CDR L3 (behavioral baseline) uses simple threshold rules:
- action_count > mean + 2σ → anomaly
- This requires manually setting thresholds per actor type, produces high false positives for bursty workloads (deployments, batch jobs), and cannot detect "low and slow" attackers who stay within thresholds.

**What's needed:** Statistical/ML model that:
1. Learns normal behavior per actor (API call patterns, services, times, source IPs)
2. Detects deviations without requiring manual thresholds
3. Can detect "low and slow" credential abuse (attacker mimics normal traffic but slightly different services)

## Approach: Isolation Forest (recommended first step)

**Why Isolation Forest:**
- Unsupervised — no labeled attack data needed
- Works well on tabular CloudTrail features
- Fast inference (< 1ms per prediction at runtime)
- Explainable anomaly score (can surface "which features were anomalous")
- Already used by Wiz and Lacework for similar purposes

**Feature vector per actor per day:**
```python
features = [
    unique_services_count,     # how many AWS services called
    unique_ops_count,          # how many distinct API operations
    total_calls,               # total API call volume
    failed_calls_ratio,        # failed / total
    unique_source_ips,         # how many distinct source IPs
    calls_outside_business_hours,  # % of calls outside 08:00-20:00 local
    new_resource_access_count,     # resources accessed not seen in prior 7 days
    cross_region_calls,            # calls to non-home region
]
```

## Implementation Phases

### Phase 1: Data Pipeline (prerequisite)
- `cdr_actor_daily_stats` must be populated for 30+ days before training
- Add missing feature columns: `calls_outside_business_hours`, `new_resource_access_count`, `cross_region_calls`
- New migration: add these columns to `cdr_actor_daily_stats`

### Phase 2: Training Job
- CronJob runs weekly: trains Isolation Forest on last 90 days of `cdr_actor_daily_stats`
- Stores model as pickle to S3 or as serialized bytes in a `cdr_ml_models` table
- Model versioned with `trained_at` timestamp

### Phase 3: Inference (CDR scan)
- Load latest model at scan start
- Score each actor's feature vector → `anomaly_score` (−1 = anomaly, 1 = normal in sklearn convention)
- Actors with `anomaly_score < −0.1` → generate L3 CDR finding

### Phase 4: Posture Signal
- New column: `cdr_ml_anomaly_score NUMERIC(4,3)` in posture table
- Write per-resource: MAX anomaly score across all actors accessing the resource

## New Posture Column Needed

```sql
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS cdr_ml_anomaly_score NUMERIC(4,3) NOT NULL DEFAULT 0;
    -- 0 = normal, 1 = most anomalous; inverse of sklearn convention for readability
```

Risk engine integration: `cdr_ml_anomaly_score > 0.7` → additional +20 exposure boost

## Prerequisites (must be true before implementation starts)

- [ ] PRE-1: `cdr_actor_daily_stats` has 30+ days of data (check: `SELECT MIN(stat_date), MAX(stat_date) FROM cdr_actor_daily_stats`)
- [ ] PRE-2: `scikit-learn` added to CDR engine requirements.txt
- [ ] PRE-3: ML model storage location decided (S3 bucket or DB table)
- [ ] PRE-4: Training compute budget approved (weekly CronJob on spot scanner node)

## Acceptance Criteria

- [ ] AC-1: Isolation Forest model trains successfully on real `cdr_actor_daily_stats` data (≥30 days, ≥10 distinct actors)
- [ ] AC-2: Training job completes in < 5 minutes on a spot scanner node
- [ ] AC-3: Inference scores all actors for a scan in < 60 seconds
- [ ] AC-4: False positive rate < 5% on a "clean" scan (known-good baseline week)
- [ ] AC-5: At least 1 real anomaly detected in a 90-day historical replay (validate with a known incident if available)
- [ ] AC-6: `cdr_ml_anomaly_score` populated in posture table with values between 0–1
- [ ] AC-7: Model version is logged (`trained_at`, `n_samples`, `n_features`) for auditability

## Definition of Done
- [ ] PRE-1 through PRE-4 all satisfied
- [ ] Training CronJob deployed and runs successfully
- [ ] Inference integrated into CDR cron scan
- [ ] Posture column populated on next CDR run
- [ ] Documentation: feature vector definition + model retraining runbook