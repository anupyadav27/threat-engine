# Story PC-DEPTH-06: CDR — Multi-Event Exfiltration Sequence Detection

## Status: done

## Metadata
- **Phase**: Analysis Depth Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 5
- **Priority**: P2 — CDR currently flags individual CloudTrail events; chained sequences (recon → staging → exfil) are undetected
- **Depends on**: PC-P2-02 (CDR IAM cross-engine actor/role correlation wired)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-architect (graph traversal logic) + bmad-security-reviewer

## Gap Being Closed

The CDR engine's `correlation_evaluator.py` matches individual CloudTrail events against rule patterns (e.g. "GetObject from unusual IP"). It does NOT detect **multi-step attack sequences** where each individual event looks benign but the ordered sequence reveals an exfiltration campaign:

```
1. ListBuckets + GetBucketPolicy   ← recon (normal for developers)
2. GetObject × 500 in 5 minutes    ← staging/enumeration
3. CreateJob → S3 copy to external ← exfil (jobs can look like scheduled tasks)
```

No single step triggers an alert. The sequence does.

**Also undetected:**
- **Identity pivot sequence**: AssumeRole to prod-role → CreateUser → AttachUserPolicy=Admin → long-lived credentials issued
- **Compute hijack sequence**: CreateInstance (unknown AMI) → ModifyInstanceAttribute (disableApiTermination) → RunCommand (remote shell)
- **Secrets staging sequence**: GetSecretValue × 20 different secrets + CreateExternalConnection + PutObject to public bucket

---

## Data Required

### Source 1 — CDR Engine (`cdr_findings` table) — PRIMARY

All sequence detection runs **exclusively against `cdr_findings`** — CDR is the behavioral source.

```sql
SELECT
    actor_principal,
    service,
    operation,
    resource_uid,
    resource_type,
    actor_ip,
    event_time,
    account_id,
    region,
    action_category
FROM cdr_findings
WHERE tenant_id = %s
  AND account_id = %s
  AND event_time > NOW() - INTERVAL '24 hours'
ORDER BY actor_principal, event_time ASC
```

Loaded once per scan into memory as a **time-ordered event stream per actor**, then pattern-matched against sequence templates.

### Source 2 — CDR baseline (`cdr_actor_daily_stats`) — for anomaly context

```sql
SELECT actor_principal,
       avg_daily_get_object,
       avg_daily_assume_role,
       avg_daily_get_secret_value,
       p95_daily_get_object
FROM cdr_actor_daily_stats
WHERE tenant_id = %s
  AND account_id = %s
  AND stats_date >= CURRENT_DATE - INTERVAL '30 days'
```

Used to determine whether `GetObject × 500` is a spike vs. normal behavior for that actor.

### Source 3 — Discovery Engine — NOT needed

Sequence detection is purely behavioral (events). No config analysis required.

### Source 4 — Vulnerability Engine — NOT needed

---

## Sequence Detection Algorithm

### Architecture: `SequenceDetector`

**New file:** `engines/cdr/cdr_engine/detectors/sequence_detector.py`

```python
class SequenceDetector:
    """
    Detects multi-event attack sequences from ordered CDR event streams.
    Each sequence template specifies:
      - stages: ordered list of (service, operation_pattern, time_window_seconds, min_count)
      - severity: finding severity if full sequence matched
      - rule_id: CDR rule ID for the completed sequence
    """

    SEQUENCE_TEMPLATES = [
        ExfilSequenceTemplate,
        IdentityPivotTemplate,
        ComputeHijackTemplate,
        SecretsStagingTemplate,
    ]

    def detect(self, events_by_actor: Dict[str, List[Event]], baselines: Dict) -> List[Finding]:
        findings = []
        for actor, events in events_by_actor.items():
            for template in self.SEQUENCE_TEMPLATES:
                match = template.match(events, baselines.get(actor))
                if match:
                    findings.append(self._build_finding(match, actor, events))
        return findings
```

### Sequence Templates

#### Template 1: S3 Data Exfiltration Sequence

```python
class ExfilSequenceTemplate:
    rule_id = "aws.cdr.sequence.s3_exfil_pattern"
    severity = "critical"

    stages = [
        # Stage A: recon — list/get bucket config
        Stage(service="s3",
              operations=["ListBuckets", "GetBucketPolicy", "GetBucketAcl"],
              min_count=2,
              window_seconds=300),
        # Stage B: bulk read — spike above actor baseline p95
        Stage(service="s3",
              operations=["GetObject"],
              min_count_multiplier=5.0,    # 5× actor's p95 daily GetObject / 24h
              window_seconds=600),
        # Stage C: exfil path — copy/job to external or PutObject to external bucket
        Stage(service="s3",
              operations=["CreateJob", "PutObject"],
              cross_account_only=True,     # destination must be in different account
              window_seconds=3600),
    ]
    max_total_window_seconds = 7200   # all 3 stages within 2 hours
```

#### Template 2: Identity Pivot Sequence

```python
class IdentityPivotTemplate:
    rule_id = "aws.cdr.sequence.identity_pivot"
    severity = "critical"

    stages = [
        Stage(service="sts", operations=["AssumeRole"], min_count=1, window_seconds=60),
        Stage(service="iam", operations=["CreateUser", "CreateAccessKey"], min_count=1, window_seconds=300),
        Stage(service="iam",
              operations=["AttachUserPolicy", "PutUserPolicy"],
              policy_name_contains=["Admin", "Administrator", "Full"],
              window_seconds=300),
    ]
    max_total_window_seconds = 1800
```

#### Template 3: Secrets Staging Sequence

```python
class SecretsStagingTemplate:
    rule_id = "aws.cdr.sequence.secrets_staging"
    severity = "critical"

    stages = [
        Stage(service="secretsmanager",
              operations=["GetSecretValue"],
              min_count=10,           # ≥10 distinct secrets in window
              distinct_resources=True,
              window_seconds=900),
        Stage(service="s3",
              operations=["PutObject"],
              bucket_public_or_cross_account=True,
              window_seconds=1800),
    ]
    max_total_window_seconds = 3600
```

#### Template 4: Compute Hijack Sequence

```python
class ComputeHijackTemplate:
    rule_id = "aws.cdr.sequence.compute_hijack"
    severity = "high"

    stages = [
        Stage(service="ec2",
              operations=["RunInstances"],
              unknown_ami=True,        # AMI not in approved list
              window_seconds=300),
        Stage(service="ec2",
              operations=["ModifyInstanceAttribute"],
              attribute="disableApiTermination",
              window_seconds=600),
        Stage(service="ssm",
              operations=["SendCommand", "StartSession"],
              window_seconds=1800),
    ]
    max_total_window_seconds = 3600
```

### Stage Matching

```python
def _match_stage(self, events, stage, after_time):
    """
    Find events matching stage criteria in [after_time, after_time + window_seconds].
    Returns (matched: bool, last_event_time, matched_events).
    """
    window_end = after_time + timedelta(seconds=stage.window_seconds)
    candidates = [e for e in events
                  if after_time <= e.event_time <= window_end
                  and e.service == stage.service
                  and e.operation in stage.operations]

    if stage.distinct_resources:
        matched = len({e.resource_uid for e in candidates}) >= stage.min_count
    elif hasattr(stage, 'min_count_multiplier'):
        # spike detection — compare to baseline
        matched = len(candidates) >= (baseline_value * stage.min_count_multiplier)
    else:
        matched = len(candidates) >= stage.min_count

    return matched, max((e.event_time for e in candidates), default=after_time), candidates
```

---

## Findings Produced

| Rule ID | Severity | Notes |
|---------|---------|-------|
| `aws.cdr.sequence.s3_exfil_pattern` | CRITICAL | S3 recon → bulk read spike → cross-account write within 2h |
| `aws.cdr.sequence.identity_pivot` | CRITICAL | AssumeRole → CreateUser → admin policy within 30min |
| `aws.cdr.sequence.secrets_staging` | CRITICAL | ≥10 secrets read + PutObject to public/external bucket within 1h |
| `aws.cdr.sequence.compute_hijack` | HIGH | RunInstances (unknown AMI) → disable termination → SSM shell within 1h |

Each finding's `finding_data` includes:
```json
{
  "sequence_matched": "s3_exfil_pattern",
  "stage_1_events": [...],
  "stage_2_events": [...],
  "stage_3_events": [...],
  "total_duration_seconds": 4500,
  "baseline_comparison": {"actor_p95_get_object": 12, "observed_get_object": 847},
  "cdr_event_ids": ["uuid1", "uuid2", ...]
}
```

---

## Integration Point

**Called from** `engines/cdr/run_scan.py` after `CorrelationEvaluator.evaluate()`:

```python
# Load actor events for sequence detection (24h window)
actor_events = load_actor_event_stream(cdr_conn, scan_run_id, tenant_id, account_id)
baselines = load_actor_baselines(cdr_conn, tenant_id, account_id)

sequence_detector = SequenceDetector()
sequence_findings = sequence_detector.detect(actor_events, baselines)

# Write to cdr_findings (same table, new rule_ids)
writer.write_findings(cdr_conn, sequence_findings, scan_run_id, tenant_id)
```

---

## Posture Signals Written

Sequence detection findings write to the CDR dimension of `resource_security_posture`:
- `has_active_cdr_actor = True` — actor that completed the sequence
- `cdr_ttps` — append sequence rule_id to the TTP array
- `has_exfil_path = True` (written by CDR to DataSec posture column when S3 exfil sequence confirmed) — cross-engine signal

---

## Acceptance Criteria

- [ ] AC-1: `SequenceDetector` created at `engines/cdr/cdr_engine/detectors/sequence_detector.py` and called from `run_scan.py`
- [ ] AC-2: `aws.cdr.sequence.s3_exfil_pattern` fires when events contain: ≥2 s3:List*/GetBucketPolicy within 5min + ≥5× p95 GetObject within 10min + cross-account PutObject/CreateJob within 1h — all within 2h of each other
- [ ] AC-3: Sequence does NOT fire when GetObject volume is within actor's normal p95 baseline (no false positive for high-volume S3 users)
- [ ] AC-4: `aws.cdr.sequence.identity_pivot` fires when same `actor_principal` has: sts:AssumeRole + iam:CreateUser within 5min + iam:AttachUserPolicy to Admin policy within 5min of CreateUser
- [ ] AC-5: `aws.cdr.sequence.secrets_staging` fires when same actor reads ≥10 distinct secretsmanager secrets within 15min AND PutObject to cross-account or public bucket within 30min
- [ ] AC-6: `has_exfil_path=true` written to `resource_security_posture` for the actor's principal resource when S3 exfil sequence is confirmed
- [ ] AC-7: All CDR queries include `AND tenant_id = %s`
- [ ] AC-8: `finding_data` includes all 3 stage event lists + `baseline_comparison` dict for the actor

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1530 | Data from Cloud Storage — S3 exfil sequence |
| T1078.004 | Valid Cloud Accounts — identity pivot via AssumeRole + CreateUser |
| T1555.006 | Credentials from Password Stores: Cloud Secrets — secrets staging sequence |
| T1496 | Resource Hijacking — compute hijack sequence |
| T1020 | Automated Exfiltration — S3 cross-account copy job |

## Definition of Done
- [ ] `SequenceDetector` with all 4 templates implemented
- [ ] Baseline loading from `cdr_actor_daily_stats` wired (spike detection)
- [ ] Unit tests: `tests/unit/cdr/test_sequence_detector.py` — at least 2 test cases per template (positive + negative)
- [ ] CDR engine rebuilt and deployed
- [ ] After 24h of CloudTrail ingestion: `SELECT rule_id, COUNT(*) FROM cdr_findings WHERE rule_id LIKE '%sequence%' GROUP BY rule_id` — at least 1 row if any cross-account S3 activity exists
