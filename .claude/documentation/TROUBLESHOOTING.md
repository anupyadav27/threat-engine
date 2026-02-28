# Troubleshooting Guide

> Common issues and solutions for the CSPM platform.

---

## Database Issues

### Connection Refused
```
psycopg2.OperationalError: could not connect to server: Connection refused
```
**Solutions:**
1. Check PostgreSQL is running: `pg_isready -h localhost -p 5432`
2. Verify DB_HOST, DB_PORT environment variables
3. Check security group allows inbound on 5432 (for RDS)
4. Verify `pg_hba.conf` allows connections from your IP

### Column Does Not Exist
```
column cf.finding_id does not exist
```
**Solution:** Check the actual column name in the table. Some tables use `id` instead of `finding_id`. Run:
```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'check_findings';
```

### Database Does Not Exist
```
FATAL: database "threat_engine_threat" does not exist
```
**Solution:** Create the database:
```sql
CREATE DATABASE threat_engine_threat;
```
Then run schema migrations from `consolidated_services/database/schemas/`.

---

## FastAPI / API Issues

### Route Conflict (Wildcard Catching Specific Paths)
```
{"detail":"Threat not found: analysis"}
```
**Cause:** A wildcard route like `/{threat_id}` is registered before specific routes like `/analysis/prioritized`.

**Solution:** Move specific routes BEFORE wildcard routes in `api_server.py`:
```python
# MUST be before {threat_id} wildcard
@app.get("/api/v1/threat/analysis/prioritized")
async def get_prioritized(): ...

@app.get("/api/v1/threat/analysis/{detection_id}")
async def get_analysis(): ...

# Wildcard LAST
@app.get("/api/v1/threat/{threat_id}")
async def get_threat(): ...
```

### Single Body Parameter Validation Error
```
Input should be a valid string
```
**Cause:** FastAPI single `Body(...)` parameter without `embed=True`.

**Solution:** Add `embed=True`:
```python
@app.post("/api/v1/graph/build")
async def build_graph(tenant_id: str = Body(..., embed=True)):
```

### 422 Unprocessable Entity
**Cause:** Request body doesn't match expected Pydantic model.

**Solution:** Check the Swagger docs at `/docs` for the expected request format.

---

## Docker Issues

### Build Context - File Not Found
```
failed to calculate checksum of ref ... "/engine_threat/threat_engine": not found
```
**Solution:** Build from the repo root, not the engine directory:
```bash
# Correct
docker build -f engine_threat/Dockerfile -t threat-engine:latest .

# Wrong
cd engine_threat && docker build -t threat-engine:latest .
```

### Container Can't Connect to RDS
**Solutions:**
1. Check security group allows inbound from container's VPC/IP
2. Use host network mode for local dev: `--network host`
3. For Docker Compose, use service name as hostname: `postgres` not `localhost`

### Image Too Large
**Solution:** Use multi-stage builds and `.dockerignore`:
```
# .dockerignore
__pycache__
*.pyc
.git
tests/
docs/
*.md
```

---

## Neo4j Issues

### Can't See Graph in Neo4j Console
**Solutions:**
1. Verify data exists: `MATCH (n) RETURN count(n)`
2. In Neo4j Aura console, use the Query tab (not Overview)
3. Run visualization query: `MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 100`
4. Switch to Graph view (not Table view)

### Connection Timeout
```
neo4j.exceptions.ServiceUnavailable
```
**Solutions:**
1. Verify NEO4J_URI starts with `neo4j+s://` (for Aura)
2. Check credentials
3. Verify instance is running in Neo4j Aura console

---

## AWS / Cloud Scanning Issues

### Assume Role Failed
```
botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling the AssumeRole operation
```
**Solutions:**
1. Verify role ARN is correct
2. Check trust policy allows your account/role
3. Verify external ID if required
4. Check role permissions

### Rate Limiting
```
botocore.exceptions.ClientError: An error occurred (Throttling)
```
**Solutions:**
1. Reduce `MAX_DISCOVERY_WORKERS` (default 50 → try 10)
2. Increase `BOTO_READ_TIMEOUT`
3. Set `BOTO_RETRY_MODE=adaptive`

### No Resources Found
**Solutions:**
1. Verify correct AWS region: `export AWS_REGION=ap-south-1`
2. Check account has resources in the specified region
3. Verify IAM permissions include read access to target services

---

## Module / Import Issues

### ModuleNotFoundError
```
ModuleNotFoundError: No module named 'engine_common'
```
**Solutions:**
1. Set PYTHONPATH: `export PYTHONPATH=/path/to/threat-engine`
2. For Docker, ensure Dockerfile copies `engine_common/` and `consolidated_services/`
3. For local dev, install from repo root

### psycopg2 Build Failure
```
Error: pg_config executable not found
```
**Solutions:**
- Use binary package: `pip install psycopg2-binary`
- Or install PostgreSQL dev headers: `brew install postgresql` (Mac) / `apt install libpq-dev` (Linux)

---

## Git / Repository Issues

### YAML Files Accidentally Deleted
If cleanup scripts accidentally delete legitimate `.yaml` files:
```bash
# Restore from git
git checkout -- '*.yaml'
```
Note: Some AWS service YAML files have "backup" in the name (e.g., `aws.backup.backupplan.yaml`) — these are legitimate rules, not backup files.

### Worktree Merge Conflicts
```bash
# Stash desktop changes, merge, then drop stash
cd /path/to/desktop/repo
git stash save "before merge"
git merge branch-name
git stash drop
```

---

## Performance Issues

### Scan Taking Too Long
**Solutions:**
1. Reduce services scanned: specify `"services": ["s3", "iam"]` instead of all
2. Reduce regions: specify `"regions": ["ap-south-1"]` instead of all
3. Increase worker threads: `MAX_DISCOVERY_WORKERS=50`

### Graph Build Slow
**Solutions:**
1. Clear graph before rebuild: `MATCH (n) DETACH DELETE n`
2. Use batch operations for node creation
3. Check Neo4j instance memory (Aura free tier has limits)

### High Memory Usage
**Solutions:**
1. Reduce `DB_POOL_SIZE` (default 10)
2. Reduce `BOTO_MAX_POOL_CONNECTIONS` (default 100)
3. Set K8s resource limits appropriately

---

## Health Check Endpoints

Use these to diagnose service health:

| Engine | Health URL |
|--------|-----------|
| API Gateway | `GET /gateway/health` |
| Threat | `GET /health` |
| Check | `GET /api/v1/health` |
| Inventory | `GET /health` |
| Compliance | `GET /api/v1/health` |
| Discoveries | `GET /api/v1/health` |
| Onboarding | `GET /api/v1/health` |
| Rule | `GET /api/v1/health` |

---

## Log Locations

| Environment | Location |
|-------------|----------|
| Local (stdout) | Terminal output |
| Docker | `docker logs <container-name>` |
| EKS | `kubectl logs <pod-name> -n threat-engine-engines` |
| CloudWatch | Log group: `CLOUDWATCH_LOG_GROUP` env var |

### Enable Debug Logging
```bash
export LOG_LEVEL=DEBUG
```
