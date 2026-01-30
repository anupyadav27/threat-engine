# Docker Status Check

## Current Status

❌ **Docker daemon is not running**

## To Start Docker

### macOS (Docker Desktop)

1. **Open Docker Desktop**:
   - Click Docker icon in Applications
   - Or run: `open -a Docker`

2. **Wait for Docker to start**:
   - Look for whale icon in menu bar
   - Wait until it shows "Docker Desktop is running"

3. **Verify**:
   ```bash
   docker ps
   ```

### Linux

```bash
sudo systemctl start docker
sudo systemctl enable docker
```

## After Docker Starts

Run the build script:

```bash
cd deployment/local-k8s
./build-all-engines.sh local
```

## Quick Check Script

Use the helper script:

```bash
./check-and-start-docker.sh
```

This will:
- Check Docker status
- Attempt to start Docker Desktop (macOS)
- Wait and verify Docker is running
