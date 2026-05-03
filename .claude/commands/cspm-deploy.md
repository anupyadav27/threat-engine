# /cspm-deploy

Deploy a CSPM engine to EKS. Runs the full 6-step deployment checklist.

## Usage
```
/cspm-deploy <engine-name> <image-tag>
```

Examples:
```
/cspm-deploy engine-threat v-multicsp4-auth
/cspm-deploy engine-network v-net-subtabs2
```

## Steps (always execute in order)

1. **Build** — `docker build -t yadavanup84/<engine>:<tag> -f engines/<engine>/Dockerfile .`
2. **Push** — `docker push yadavanup84/<engine>:<tag>` (requires user confirmation)
3. **Update manifest** — Edit `deployment/aws/eks/engines/<engine>.yaml` image tag
4. **Apply** — `kubectl apply -f deployment/aws/eks/engines/<engine>.yaml`
5. **Rollout status** — `kubectl rollout status deployment/<engine> -n threat-engine-engines`
6. **Log check** — `kubectl logs -f -l app=<engine> -n threat-engine-engines --tail=50`

## Rules
- Never use `latest` tag — always use a versioned tag
- Always confirm before `docker push` (step 2)
- Always run log check (step 6) — do not skip even if rollout succeeds
- If rollout fails → immediate rollback: `kubectl rollout undo deployment/<engine> -n threat-engine-engines`