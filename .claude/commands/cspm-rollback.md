# /cspm-rollback

Safely roll back a CSPM engine to its previous deployment. Confirms state before and after rollback.

## Usage
```
/cspm-rollback <engine-name>
/cspm-rollback <engine-name> --to <image-tag>
```

Examples:
```
/cspm-rollback engine-threat
/cspm-rollback engine-gateway --to v-bff-uibff1
/cspm-rollback engine-check-aws
```

## Steps

### Step 1 — Capture current state before rollback
```bash
kubectl get pods -n threat-engine-engines \
  -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[0].image,STATUS:.status.phase' \
  | grep <engine>

kubectl rollout history deployment/<engine> -n threat-engine-engines
```
Record the current image tag and revision number. You will need this to verify the rollback succeeded.

### Step 2 — Confirm rollback with user
Show the user:
- Current image: `<current-tag>`
- Will revert to: previous revision (or `--to <tag>` if specified)

**Pause here and ask for confirmation before proceeding.**

### Step 3a — Rollback to previous revision (default)
```bash
kubectl rollout undo deployment/<engine> -n threat-engine-engines
```

### Step 3b — Rollback to specific image tag (if `--to` specified)
```bash
kubectl set image deployment/<engine> <container>=yadavanup84/<engine>:<tag> -n threat-engine-engines
```
Get container name from: `kubectl get deployment <engine> -n threat-engine-engines -o jsonpath='{.spec.template.spec.containers[0].name}'`

### Step 4 — Wait for rollout
```bash
kubectl rollout status deployment/<engine> -n threat-engine-engines --timeout=120s
```

### Step 5 — Verify rolled-back pod image
```bash
kubectl get pods -n threat-engine-engines \
  -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[0].image,STATUS:.status.phase' \
  | grep <engine>
```
Confirm the running image matches the intended previous tag.

### Step 6 — Log check post-rollback
```bash
kubectl logs -l app=<engine> -n threat-engine-engines --tail=50 --since=2m
```
Look for clean startup — no `ERROR`, `Traceback`, or `Connection refused`.

### Step 7 — Health check post-rollback
```bash
kubectl port-forward svc/<engine> 9999:80 -n threat-engine-engines &
python3 -c "
import urllib.request
r = urllib.request.urlopen('http://localhost:9999/api/v1/health/live', timeout=5)
print('live:', r.status)
r = urllib.request.urlopen('http://localhost:9999/api/v1/health/ready', timeout=5)
print('ready:', r.status)
"
kill %1
```
Both must return 200.

## After rollback
- Update MEMORY.md image tag table to reflect the rolled-back tag
- File a bug describing what broke in the failed deployment
- Do not re-attempt the failed deploy until root cause is identified

## Notes
- For `engine-gateway` / `api-gateway`: VSCode YAML linter silently reverts image tags — always use `kubectl set image` (not manifest edit) when targeting the gateway
- If rollback itself fails: `kubectl describe pod -l app=<engine> -n threat-engine-engines` to check events
- Rollback history is limited to last 10 revisions by default