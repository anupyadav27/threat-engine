# EKS: Getting RDS Secrets from AWS Secrets Manager

This doc explains how **consolidated_services** RDS config is used in EKS and how to source RDS credentials from **AWS Secrets Manager** instead of static K8s secrets.

---

## What EKS expects today

| Kubernetes secret                    | Keys (examples) | Used by |
|-------------------------------------|------------------|---------|
| **threat-engine-rds-credentials**   | RDS_HOST, RDS_PORT, RDS_SUPERUSER, RDS_SUPERUSER_PASSWORD | Init job (`init-threat-engine-databases`) |
| **threat-engine-db-passwords**       | CONFIGSCAN_DB_PASSWORD, COMPLIANCE_DB_PASSWORD, INVENTORY_DB_PASSWORD, THREAT_DB_PASSWORD, SHARED_DB_PASSWORD | All engine deployments (envFrom) |

Host/port/database name/user come from **ConfigMap** `threat-engine-db-config`; only **passwords** (and init superuser creds) come from secrets.

---

## Option 1: Store in Secrets Manager and sync with External Secrets Operator

### 1.1 Create the secret in AWS Secrets Manager (Mumbai)

Use one secret for **init + engine passwords** (or split if you prefer). Example single secret:

**Secret name (example):** `threat-engine/rds-credentials`  
**Region:** `ap-south-1`

**JSON structure** (keys must match what EKS expects or what you map in ExternalSecret):

```json
{
  "RDS_HOST": "postgres-vulnerability-db.xxxxx.ap-south-1.rds.amazonaws.com",
  "RDS_PORT": "5432",
  "RDS_SUPERUSER": "postgres",
  "RDS_SUPERUSER_PASSWORD": "<master-password>",
  "CONFIGSCAN_DB_PASSWORD": "<password>",
  "COMPLIANCE_DB_PASSWORD": "<password>",
  "INVENTORY_DB_PASSWORD": "<password>",
  "THREAT_DB_PASSWORD": "<password>",
  "SHARED_DB_PASSWORD": "<password>"
}
```

Create via CLI:

```bash
aws secretsmanager create-secret \
  --name "threat-engine/rds-credentials" \
  --region ap-south-1 \
  --description "RDS and engine DB passwords for threat-engine EKS" \
  --secret-string '{
    "RDS_HOST": "postgres-vulnerability-db.xxxxx.ap-south-1.rds.amazonaws.com",
    "RDS_PORT": "5432",
    "RDS_SUPERUSER": "postgres",
    "RDS_SUPERUSER_PASSWORD": "YOUR_MASTER_PASSWORD",
    "CONFIGSCAN_DB_PASSWORD": "YOUR_ENGINE_PASSWORD",
    "COMPLIANCE_DB_PASSWORD": "YOUR_ENGINE_PASSWORD",
    "INVENTORY_DB_PASSWORD": "YOUR_ENGINE_PASSWORD",
    "THREAT_DB_PASSWORD": "YOUR_ENGINE_PASSWORD",
    "SHARED_DB_PASSWORD": "YOUR_ENGINE_PASSWORD"
  }'
```

(Or create/update in AWS Console and paste the same JSON.)

### 1.2 Install External Secrets Operator (if not already)

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace
```

Configure the cluster to allow ESO to read from Secrets Manager (IRSA or node IAM). The ESO controller needs `secretsmanager:GetSecretValue` (and optionally `DescribeSecret`) on the secret ARN.

### 1.3 Create ExternalSecret → K8s Secret (init job)

Example: sync **threat-engine-rds-credentials** from Secrets Manager so the init job keeps working without manual `kubectl create secret`:

```yaml
# deployment/aws/eks/secrets/external-secret-rds-credentials.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: threat-engine-rds-credentials
  namespace: threat-engine-engines
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager-store   # ClusterSecretStore pointing at AWS
    kind: ClusterSecretStore
  target:
    name: threat-engine-rds-credentials
    creationPolicy: Owner
  data:
    - secretKey: RDS_HOST
      remoteRef:
        key: threat-engine/rds-credentials
        property: RDS_HOST
    - secretKey: RDS_PORT
      remoteRef:
        key: threat-engine/rds-credentials
        property: RDS_PORT
    - secretKey: RDS_SUPERUSER
      remoteRef:
        key: threat-engine/rds-credentials
        property: RDS_SUPERUSER
    - secretKey: RDS_SUPERUSER_PASSWORD
      remoteRef:
        key: threat-engine/rds-credentials
        property: RDS_SUPERUSER_PASSWORD
```

### 1.4 ClusterSecretStore for AWS Secrets Manager

ESO needs a **SecretStore** or **ClusterSecretStore** that points at AWS (and optionally the region). Example using IRSA:

```yaml
# deployment/aws/eks/secrets/cluster-secret-store-aws-example.yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-secrets-manager-store
spec:
  provider:
    aws:
      service: SecretsManager
      region: ap-south-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
            namespace: external-secrets
```

(You must create the service account and attach an IAM role that can `GetSecretValue` on `threat-engine/rds-credentials`.)

After applying the ClusterSecretStore and ExternalSecret, ESO will create/update the K8s secret **threat-engine-rds-credentials** from Secrets Manager. The init job already uses this secret name, so no change there.

### 1.5 Second ExternalSecret → engine passwords

Same idea for **threat-engine-db-passwords** (engine envFrom):

```yaml
# deployment/aws/eks/secrets/external-secret-db-passwords-example.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: threat-engine-db-passwords
  namespace: threat-engine-engines
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager-store
    kind: ClusterSecretStore
  target:
    name: threat-engine-db-passwords
    creationPolicy: Owner
  data:
    - secretKey: CONFIGSCAN_DB_PASSWORD
      remoteRef:
        key: threat-engine/rds-credentials
        property: CONFIGSCAN_DB_PASSWORD
    - secretKey: COMPLIANCE_DB_PASSWORD
      remoteRef:
        key: threat-engine/rds-credentials
        property: COMPLIANCE_DB_PASSWORD
    - secretKey: INVENTORY_DB_PASSWORD
      remoteRef:
        key: threat-engine/rds-credentials
        property: INVENTORY_DB_PASSWORD
    - secretKey: THREAT_DB_PASSWORD
      remoteRef:
        key: threat-engine/rds-credentials
        property: THREAT_DB_PASSWORD
    - secretKey: SHARED_DB_PASSWORD
      remoteRef:
        key: threat-engine/rds-credentials
        property: SHARED_DB_PASSWORD
```

Deployments already use `secretRef: threat-engine-db-passwords`, so once ESO creates this secret from Secrets Manager, engines get the passwords from Secrets Manager.

---

## Option 2: One-time sync (no External Secrets Operator)

If you don’t want ESO, you can create the K8s secrets **once** from Secrets Manager (e.g. in a CI job or runbook):

```bash
# Set variables
SECRET_ID="threat-engine/rds-credentials"
REGION="ap-south-1"
NS="threat-engine-engines"

# Get JSON from Secrets Manager
JSON=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ID" --region "$REGION" --query SecretString --output text)

# Create init-job secret (same keys as init-threat-engine-databases-job expects)
kubectl create secret generic threat-engine-rds-credentials -n "$NS" \
  --from-literal=RDS_HOST="$(echo "$JSON" | jq -r .RDS_HOST)" \
  --from-literal=RDS_PORT="$(echo "$JSON" | jq -r .RDS_PORT)" \
  --from-literal=RDS_SUPERUSER="$(echo "$JSON" | jq -r .RDS_SUPERUSER)" \
  --from-literal=RDS_SUPERUSER_PASSWORD="$(echo "$JSON" | jq -r .RDS_SUPERUSER_PASSWORD)" \
  --dry-run=client -o yaml | kubectl apply -f -

# Create engine-passwords secret (keys expected by threat-engine-db-passwords)
kubectl create secret generic threat-engine-db-passwords -n "$NS" \
  --from-literal=CONFIGSCAN_DB_PASSWORD="$(echo "$JSON" | jq -r .CONFIGSCAN_DB_PASSWORD)" \
  --from-literal=COMPLIANCE_DB_PASSWORD="$(echo "$JSON" | jq -r .COMPLIANCE_DB_PASSWORD)" \
  --from-literal=INVENTORY_DB_PASSWORD="$(echo "$JSON" | jq -r .INVENTORY_DB_PASSWORD)" \
  --from-literal=THREAT_DB_PASSWORD="$(echo "$JSON" | jq -r .THREAT_DB_PASSWORD)" \
  --from-literal=SHARED_DB_PASSWORD="$(echo "$JSON" | jq -r .SHARED_DB_PASSWORD)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

You’d need to re-run this (or a similar script) whenever you rotate the secret in Secrets Manager.

---

## Summary

- **consolidated_services** reads RDS from env vars; EKS supplies them via ConfigMap (host/port/db/user) + Secret (passwords). See **consolidated_services/database/RDS_AND_EKS_CONFIG.md**.
- To get RDS credentials from **Secrets Manager** in EKS:
  - **Option 1:** Store credentials in a secret (e.g. `threat-engine/rds-credentials`) and use **External Secrets Operator** to sync into **threat-engine-rds-credentials** and **threat-engine-db-passwords** (recommended).
  - **Option 2:** Use a one-off script that reads from Secrets Manager and runs `kubectl create secret` / `kubectl apply` to create or update those two K8s secrets.
