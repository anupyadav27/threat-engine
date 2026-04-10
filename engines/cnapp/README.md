# CNAPP Engine (Placeholder)

Cloud-Native Application Protection Platform — combines all engines.

## Components (to be integrated)
- **CSPM**: Check engine (configuration scanning, compliance)
- **CIEM**: IAM engine + Log analysis (entitlement, least privilege)
- **CWPP**: Container/workload protection (future)
- **DSPM**: DataSec engine (data security posture)
- **Architecture**: Inventory + architecture builder

## Pipeline
```
Pipeline 1: CSPM Scan
  Discovery → Inventory → Check → Threat → Compliance/IAM/DataSec

Pipeline 2: Log Analysis (CIEM)
  Log Collection → CloudTrail Analysis → Anomaly Detection → Entitlement Analysis

Pipeline 3: Full Posture (CNAPP)
  CSPM Scan → Log Analysis → Combined Risk Scoring → Unified Dashboard
```
