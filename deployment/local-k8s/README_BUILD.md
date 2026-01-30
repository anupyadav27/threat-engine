# Build All Orchestration Engines

## Quick Commands

```bash
# Start build (background)
cd deployment/local-k8s
nohup ./build-all-engines.sh local > build.log 2>&1 &

# Monitor progress
tail -f build.log

# Check status
./build-status.sh

# After build completes, deploy
./deploy-orchestration.sh deploy
```

## Build Process

The build script will:
1. Build API Gateway image
2. Build Discovery Engine image
3. Build Check Engine image
4. Build Threat Engine image
5. Build Compliance Engine image
6. Build IAM Engine image
7. Build DataSec Engine image
8. Build Inventory Engine image

## Expected Output

After successful build, you should see:
```
✓ API Gateway built
✓ Discovery Engine built
✓ Check Engine built
✓ Threat Engine built
✓ Compliance Engine built
✓ IAM Engine built
✓ DataSec Engine built
✓ Inventory Engine built
```

## Next Steps

Once build completes:
1. Deploy to Kubernetes: `./deploy-orchestration.sh deploy`
2. Test orchestration: `python3 test_orchestration_k8s.py`
