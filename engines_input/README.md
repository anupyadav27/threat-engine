# Engines Input Directory

This directory contains input data for all engines, providing a centralized location for storing various input files needed by different engines.

## Structure

```
engines-input/
├── aws-configScan-engine/input/
├── azure-configScan-engine/input/
├── gcp-configScan-engine/input/
├── alicloud-configScan-engine/input/
├── oci-configScan-engine/input/
├── ibm-configScan-engine/input/
├── k8s-configScan-engine/input/
├── inventory-engine/input/
├── compliance-engine/input/
├── onboarding-engine/input/
└── rule-engine/input/
```

## Usage

### For Engines
Set `INPUT_DIR` environment variable:
```bash
export INPUT_DIR="/Users/apple/Desktop/threat-engine/engines-input/aws-configScan-engine/input"
```

### Engine-Specific Inputs
Each engine can store its specific input data in its respective `input/` folder:
- Configuration files
- Test data
- Reference files
- Templates
- Any other input data required by the engine

## Organization

You can organize input data by scan type, date, or purpose within each engine's `input/` folder as needed.


