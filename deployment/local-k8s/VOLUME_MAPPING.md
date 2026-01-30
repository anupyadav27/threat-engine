# Volume Mapping for Engine Input/Output

## Overview

Engines need access to:
- **engine-input**: Read-only input data (configs, templates, discovery results)
- **engine-output**: Write scan results, reports, findings

## Local Deployment (Docker Desktop K8s)

### Current Setup

**Onboarding Engine:**
- `engine-input` → `/app/engine_input` (read-only)
- `engine-output` → `/app/engine_output` (read-write)

**ConfigScan AWS Engine:**
- `engine-input` → `/app/engine_input` (read-only)
- `engine-output` → `/app/engine_output` (read-write)

### Volume Configuration

Uses `hostPath` volumes mapped to local directories:

```yaml
volumes:
- name: engine-input
  hostPath:
    path: /Users/apple/Desktop/threat-engine/engine_input
    type: DirectoryOrCreate
- name: engine-output
  hostPath:
    path: /Users/apple/Desktop/threat-engine/engine_output
    type: DirectoryOrCreate
```

### Directory Structure

```
/Users/apple/Desktop/threat-engine/
├── engine_input/
│   ├── engine_onboarding/input/
│   ├── engine_configscan_aws/input/
│   └── ...
└── engine_output/
    ├── engine_onboarding/output/
    ├── engine_configscan_aws/output/
    └── ...
```

## EKS Deployment

### S3-Based Storage

For EKS, volumes will be mapped to S3 buckets using one of these approaches:

#### Option 1: S3 Sidecar Pattern
- Use init container or sidecar to sync S3 → local volume
- Engines read/write to local volume
- Sidecar syncs local volume → S3

#### Option 2: Direct S3 Access
- Engines use S3 SDK directly
- No volume mounts needed
- Environment variables point to S3 paths

### EKS Volume Configuration (Example)

```yaml
volumes:
- name: engine-input
  persistentVolumeClaim:
    claimName: engine-input-pvc  # Backed by EBS or EFS
- name: engine-output
  persistentVolumeClaim:
    claimName: engine-output-pvc  # Backed by EBS or EFS
```

Or with S3 sync sidecar:

```yaml
volumes:
- name: engine-input
  emptyDir: {}
- name: engine-output
  emptyDir: {}
initContainers:
- name: s3-sync-input
  image: amazon/aws-cli
  command: ['sh', '-c', 'aws s3 sync s3://bucket/engine-input /app/engine_input']
  volumeMounts:
  - name: engine-input
    mountPath: /app/engine_input
```

## Environment Variables

Engines use these environment variables:

- `INPUT_DIR` or `ENGINE_INPUT_DIR` → Points to input directory
- `OUTPUT_DIR` or `ENGINE_OUTPUT_DIR` → Points to output directory
- `USE_S3` → Set to "true" for S3 mode in EKS

## Migration Path

**Local → EKS:**
1. Keep same volume mount paths (`/app/engine_input`, `/app/engine_output`)
2. Change volume type from `hostPath` to `PVC` or `emptyDir` with S3 sync
3. Add S3 sync init containers if using sidecar pattern
4. Update environment variables to point to S3 paths if using direct S3

## Testing

Verify volume mounts:

```bash
# Check volumes in pod
kubectl exec -n threat-engine-local <pod-name> -- ls -la /app/engine_input
kubectl exec -n threat-engine-local <pod-name> -- ls -la /app/engine_output

# Test write access
kubectl exec -n threat-engine-local <pod-name> -- touch /app/engine_output/test.txt
```
