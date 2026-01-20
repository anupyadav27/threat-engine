# EKS Service Inventory (Mumbai / ap-south-1)

## Cluster

- **EKS cluster name**: `vulnerability-eks-cluster`
- **Context ARN**: `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster`
- **Node(s)**:
  - `ip-172-31-20-169.ap-south-1.compute.internal` (internal `172.31.20.169`, external `3.110.134.85`)

## How to read this doc

- **ClusterIP** services are only reachable inside the cluster (or via port-forward).
- **LoadBalancer** services expose an AWS ELB hostname (public, unless configured internal).
- **In-cluster DNS** for a service is: `http://<service>.<namespace>.svc.cluster.local:<port>`
- **Port-forward pattern**:

```bash
kubectl -n <namespace> port-forward svc/<service> 8080:<servicePort>
curl -sS http://localhost:8080/health
```

## Services (all namespaces)

### `default` namespace

- **`cspm-ui-service`**
  - **Type**: LoadBalancer
  - **ClusterIP**: `10.100.58.82`
  - **External**: `aebe7a0b843404d2b8151cb953104948-2141152761.ap-south-1.elb.amazonaws.com`
  - **Ports**: `80 -> 3000/TCP`
  - **Endpoints (pods)**: `172.31.27.198:3000`, `172.31.28.91:3000`
  - **How to access**:
    - **LB**: `http://aebe7a0b843404d2b8151cb953104948-2141152761.ap-south-1.elb.amazonaws.com/`

- **`incremental-update-orchestrator-service`**
  - **Type**: LoadBalancer
  - **ClusterIP**: `10.100.152.74`
  - **External**: `a5a355c43b5e84a14973aea2036ba744-900543944.ap-south-1.elb.amazonaws.com`
  - **Ports**: `80 -> 80/TCP`
  - **Endpoints (pods)**: **none** (service has no ready backends right now)
  - **Note**: Deployment shows `0/0` pods, so this endpoint will not serve traffic until a workload is deployed.

- **`vulnerability-engine-service`**
  - **Type**: LoadBalancer
  - **ClusterIP**: `10.100.135.253`
  - **External**: `a0ecae1139d8e4afc8e7e72c8fcd35f2-336723212.ap-south-1.elb.amazonaws.com`
  - **Ports**: `80 -> 8000/TCP`
  - **Endpoints (pods)**: `172.31.25.245:8000`

### `secops-engine` namespace

- **`secops-scanner`**
  - **Type**: ClusterIP
  - **ClusterIP**: `10.100.221.4`
  - **Ports**: `8000 -> 8000/TCP`
  - **Endpoints (pods)**: `172.31.19.168:8000`, `172.31.31.243:8000`
  - **How to access**:
    - **In-cluster**: `http://secops-scanner.secops-engine.svc.cluster.local:8000/`
    - **Port-forward**:

```bash
kubectl -n secops-engine port-forward svc/secops-scanner 8000:8000
```

- **`secops-scanner-external`**
  - **Type**: LoadBalancer
  - **ClusterIP**: `10.100.98.161`
  - **External**: `a93124f3ae36243f2b87fd22eef0dfb2-205651023.ap-south-1.elb.amazonaws.com`
  - **Ports**: `80 -> 8000/TCP`
  - **Endpoints (pods)**: `172.31.19.168:8000`, `172.31.31.243:8000`
  - **How to access**:
    - **LB**: `http://a93124f3ae36243f2b87fd22eef0dfb2-205651023.ap-south-1.elb.amazonaws.com/`

### `threat-engine-engines` namespace

- **`aws-compliance-engine`**
  - **Type**: ClusterIP
  - **ClusterIP**: `10.100.211.21`
  - **Ports**: `80 -> 8000/TCP`
  - **Endpoints (pods)**: `172.31.16.42:8000`
  - **How to access**:
    - **In-cluster**: `http://aws-compliance-engine.threat-engine-engines.svc.cluster.local:80/`
    - **Swagger** (port-forward):

```bash
kubectl -n threat-engine-engines port-forward svc/aws-compliance-engine 8010:80
# then open:
# http://localhost:8010/docs
```

- **`onboarding-api`**
  - **Type**: ClusterIP
  - **ClusterIP**: `10.100.104.232`
  - **Ports**: `80 -> 8000/TCP`
  - **Endpoints (pods)**: `172.31.17.230:8000`, `172.31.20.56:8000`
  - **How to access** (port-forward):

```bash
kubectl -n threat-engine-engines port-forward svc/onboarding-api 8002:80
# http://localhost:8002/docs
```

- **`onboarding-api-lb`**
  - **Type**: LoadBalancer (**AWS LB type**: `nlb`)
  - **ClusterIP**: `10.100.121.185`
  - **External**: `a2d474d5fbb694ac5a295b05ba4ee566-8ce5ff8e72034235.elb.ap-south-1.amazonaws.com`
  - **Ports**: `80 -> 8000/TCP`
  - **Endpoints (pods)**: `172.31.17.230:8000`, `172.31.20.56:8000`
  - **How to access**:
    - **LB**: `http://a2d474d5fbb694ac5a295b05ba4ee566-8ce5ff8e72034235.elb.ap-south-1.amazonaws.com/docs`

- **`yaml-rule-builder`**
  - **Type**: ClusterIP
  - **ClusterIP**: `10.100.52.61`
  - **Ports**: `80 -> 8000/TCP`
  - **Endpoints (pods)**: `172.31.20.131:8000`
  - **How to access** (port-forward):

```bash
kubectl -n threat-engine-engines port-forward svc/yaml-rule-builder 8005:80
# http://localhost:8005/docs
```

- **`yaml-rule-builder-lb`**
  - **Type**: LoadBalancer (**AWS LB type**: `nlb`)
  - **ClusterIP**: `10.100.107.48`
  - **External**: `a91b0d018d6f04d81af8e0707381790c-3b0ceffd892abf34.elb.ap-south-1.amazonaws.com`
  - **Ports**: `80 -> 8000/TCP`
  - **Endpoints (pods)**: `172.31.20.131:8000`
  - **How to access**:
    - **LB**: `http://a91b0d018d6f04d81af8e0707381790c-3b0ceffd892abf34.elb.ap-south-1.amazonaws.com/docs`

## Ingresses

### `secops-engine/secops-scanner-ingress`

- **IngressClass**: `alb`
- **Hosts**:
  - `secops-scanner.example.com`
- **Backend**: service `secops-scanner` port `8000`
- **Status**: no ALB address recorded yet (`status.loadBalancer` empty)

## Notes / quick troubleshooting

- **Endpoints = `<none>`** means the Service has no ready backends (selector mismatch, pods not Ready, or no pods).
- For **LoadBalancer URL issues** (404/redirect), verify the LB is routing to the expected backend:
  - `kubectl -n <ns> describe svc <svc>`
  - `kubectl -n <ns> get endpoints <svc> -o wide`
  - `curl -I http://<elb-hostname>/docs` (if FastAPI)
