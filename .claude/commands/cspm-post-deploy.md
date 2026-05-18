# /cspm-post-deploy

Run the mandatory post-deployment verification checklist for a CSPM engine. Always run this after `/cspm-deploy` completes.

## Usage
```
/cspm-post-deploy <engine-name>
/cspm-post-deploy <engine-name> <expected-image-tag>
```

Examples:
```
/cspm-post-deploy engine-threat v-threat-v1-phase25
/cspm-post-deploy engine-gateway
```

## Steps (execute in order — no skipping)

### Step 1 — Pod image tag verification
```bash
kubectl get pods -n threat-engine-engines \
  -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[0].image,STATUS:.status.phase' \
  | grep <engine>
```
- Confirm running pod image matches the expected tag
- VSCode YAML linter silently reverts image tags — this step catches it
- If wrong: `kubectl set image deployment/<engine> <container>=yadavanup84/<engine>:<expected-tag> -n threat-engine-engines`

### Step 2 — Rollout health check
```bash
kubectl rollout status deployment/<engine> -n threat-engine-engines --timeout=120s
```
- Must show `successfully rolled out`
- If timeout: check pod events with `kubectl describe pod -l app=<engine> -n threat-engine-engines`

### Step 3 — Liveness + readiness probe check
```bash
kubectl get deployment <engine> -n threat-engine-engines -o jsonpath='{.spec.template.spec.containers[0].livenessProbe}'
kubectl get deployment <engine> -n threat-engine-engines -o jsonpath='{.spec.template.spec.containers[0].readinessProbe}'
```
- Both must be non-empty
- If missing: flag as constitution violation — do not proceed

### Step 4 — Log error scan (first 60 seconds)
```bash
kubectl logs -l app=<engine> -n threat-engine-engines --tail=100 --since=2m
```
- Look for: `ERROR`, `FATAL`, `Traceback`, `ImportError`, `Connection refused`, `Authentication failed`
- One startup `INFO` log per engine is expected — anything else warrants investigation
- If errors found → rollback immediately (Step 7)

### Step 5 — Health endpoint smoke test
Port-forward and hit the health endpoints:
```bash
kubectl port-forward svc/<engine> 9999:80 -n threat-engine-engines &
python3 -c "
import urllib.request, json
for path in ['/api/v1/health/live', '/api/v1/health/ready']:
    r = urllib.request.urlopen('http://localhost:9999' + path, timeout=5)
    print(path, r.status, json.loads(r.read()))
"
kill %1
```
- Both endpoints must return HTTP 200
- If either returns non-200 → rollback (Step 7)

### Step 6 — BFF smoke test (if engine has a BFF view)
Port-forward the gateway and call the relevant `/views/` endpoint:
```bash
kubectl port-forward svc/api-gateway 8888:80 -n threat-engine-engines &
python3 -c "
import urllib.request, json
req = urllib.request.Request('http://localhost:8888/api/v1/views/<view-name>',
  headers={'Cookie': 'access_token=<dev-token>', 'X-Tenant-ID': '<tenant-id>'})
r = urllib.request.urlopen(req, timeout=10)
print(r.status, list(json.loads(r.read()).keys()))
"
kill %1
```
- Must return 200 with expected top-level keys
- Skip this step only if the engine has no BFF view (document why)

### Step 7 — Rollback (only if Steps 1-6 fail)
```bash
kubectl rollout undo deployment/<engine> -n threat-engine-engines
kubectl rollout status deployment/<engine> -n threat-engine-engines
kubectl logs -l app=<engine> -n threat-engine-engines --tail=50
```
- After rollback: confirm previous image tag is running (Step 1 again)
- File a bug before re-attempting the deploy

## Pass criteria
All 6 steps green → deployment confirmed. Update MEMORY.md image tag table.

## Fail criteria
Any step fails → rollback immediately. Never leave a broken engine running.