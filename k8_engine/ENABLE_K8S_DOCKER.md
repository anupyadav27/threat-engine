# Enable Kubernetes in Docker Desktop (Quick Guide)

## 🎯 3-Minute Setup

### Step 1: Open Docker Desktop Settings
1. **Open Docker Desktop** application
2. Click the **⚙️ gear icon** (Settings) in the top-right corner

### Step 2: Enable Kubernetes
1. Click **Kubernetes** in the left sidebar
2. ✅ **Check the box**: "Enable Kubernetes"
3. ✅ **Check the box**: "Show system containers (advanced)"
4. Click **Apply & Restart**

### Step 3: Wait for Kubernetes to Start
- Docker Desktop will download and start Kubernetes
- This takes **2-3 minutes** the first time
- You'll see "Kubernetes is running ✅" in the bottom status bar

### Step 4: Verify It's Running
```bash
# Check Kubernetes is running
kubectl config current-context
# Should show: docker-desktop

# Check cluster
kubectl cluster-info
# Should show: Kubernetes control plane is running at https://kubernetes.docker.internal:6443

# Check nodes
kubectl get nodes
# Should show: docker-desktop   Ready   control-plane
```

---

## ✅ You're Ready!

Now run the test:

```bash
cd /Users/apple/Desktop/threat-engine/k8_engine
./test_docker_desktop.sh
```

Or manually:

```bash
cd /Users/apple/Desktop/threat-engine/k8_engine
source venv/bin/activate

# Test against Docker Desktop cluster
python3 run_yaml_scan.py --components pod rbac namespace --verbose
```

---

## Visual Checklist

```
Docker Desktop Settings:
┌─────────────────────────────────────┐
│ General                             │
│ Resources                           │
│ Docker Engine                       │
│ ►Kubernetes ◄ (click here)         │
│   └─ ✅ Enable Kubernetes           │
│   └─ ✅ Show system containers      │
│ Software Updates                    │
│ Extensions                          │
└─────────────────────────────────────┘
        ▼
   [Apply & Restart]
```

Status Bar Should Show:
```
🐳 Docker Desktop | 🎯 Kubernetes is running
```

---

## What Gets Installed

When you enable Kubernetes in Docker Desktop:
- ✅ Single-node Kubernetes cluster (v1.29+)
- ✅ kubectl configured automatically
- ✅ Local container registry
- ✅ CoreDNS for service discovery
- ✅ Full control plane access (API server, etcd, scheduler, controller-manager)

---

## Benefits for Testing

| Feature | Docker Desktop K8s |
|---------|-------------------|
| Setup | One checkbox ✅ |
| Speed | Native (fast) |
| Control Plane | Full access ✅ |
| Persistence | Survives restarts |
| Integration | Native macOS |
| Resource Usage | Shared with Docker |

---

## Alternative: Already Have Kubernetes?

If you already have a Kubernetes cluster (minikube, kind, remote), you can use it:

```bash
# List available contexts
kubectl config get-contexts

# Switch to your cluster
kubectl config use-context YOUR_CONTEXT

# Run engine
cd /Users/apple/Desktop/threat-engine/k8_engine
source venv/bin/activate
python3 run_yaml_scan.py --verbose
```

---

## Troubleshooting

### Docker Desktop shows "Kubernetes is starting..."
**Wait 2-3 minutes.** First-time setup downloads components.

### Error: "Unable to connect to server"
1. Check Docker Desktop status bar: "Kubernetes is running"
2. Restart Docker Desktop
3. Run: `kubectl config use-context docker-desktop`

### Already have minikube running?
No problem! You can have both:
```bash
# Use Docker Desktop
kubectl config use-context docker-desktop

# Use Minikube
kubectl config use-context minikube

# Check which is active
kubectl config current-context
```

---

## Next Steps

1. ✅ Enable Kubernetes in Docker Desktop (2-3 min)
2. ✅ Verify: `kubectl get nodes`
3. ✅ Run test: `./test_docker_desktop.sh`
4. ✅ Review results in `output/` directory
5. ✅ See full guide: `DOCKER_DESKTOP_TESTING.md`

Happy testing! 🚀

