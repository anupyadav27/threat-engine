# EKS Cluster Setup - Handover Document

**Date**: December 29, 2024  
**Status**: ✅ Active  
**Region**: Mumbai (ap-south-1)

---

## 📋 Cluster Overview

### Basic Information
- **Cluster Name**: `vulnerability-eks-cluster`
- **Region**: `ap-south-1` (Mumbai, India)
- **Kubernetes Version**: 1.28
- **Status**: ACTIVE
- **Endpoint**: `https://C9DB16CCB487B3B9B30F073312A941BC.gr7.ap-south-1.eks.amazonaws.com`

### Node Group Details
- **Node Group Name**: `vulnerability-nodegroup`
- **Instance Type**: `t3.medium`
- **Node Count**: 1
- **AMI Type**: AL2_x86_64
- **Disk Size**: 20 GB
- **Capacity Type**: ON_DEMAND
- **Status**: ACTIVE

---

## 🔌 Accessing the Cluster

### Prerequisites
- AWS CLI installed and configured
- kubectl installed
- Appropriate IAM permissions

### Configure kubectl
```bash
aws eks update-kubeconfig --name vulnerability-eks-cluster --region ap-south-1
```

### Verify Cluster Access
```bash
kubectl get nodes
kubectl get pods --all-namespaces
```

### Expected Output
```
NAME                                          STATUS   ROLES    AGE   VERSION
ip-10-0-x-x.ap-south-1.compute.internal      Ready    <none>   Xm   v1.28.x-eks-xxxxxxx
```

---

## 🗄️ RDS Database Connection

### Connection Details
- **RDS Endpoint**: `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com`
- **Port**: `5432`
- **Database**: `vulnerability_db`
- **Username**: `postgres`
- **Password**: `[REDACTED - Store in AWS Secrets Manager]`

### Security Group Configuration
- EKS nodes can access RDS on port 5432
- Security group rule configured: `eks-vulnerability-sg` → `rds-postgres-sg`

### Connection String (for containers)
```
postgresql://postgres:[PASSWORD]@postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432/vulnerability_db
```

---

## 📦 Deploying Applications

### Example: Deploy a Pod with RDS Access

#### 1. Create a Secret for Database Credentials
```bash
kubectl create secret generic rds-credentials \
  --from-literal=DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
  --from-literal=DB_PORT=5432 \
  --from-literal=DB_NAME=vulnerability_db \
  --from-literal=DB_USER=postgres \
  --from-literal=DB_PASSWORD='apXuHV%2OSyRWK62'
```

#### 2. Example Deployment YAML
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerability-app
  labels:
    app: vulnerability
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerability
  template:
    metadata:
      labels:
        app: vulnerability
    spec:
      containers:
      - name: app
        image: your-image:latest
        env:
        - name: DB_HOST
          valueFrom:
            secretKeyRef:
              name: rds-credentials
              key: DB_HOST
        - name: DB_PORT
          valueFrom:
            secretKeyRef:
              name: rds-credentials
              key: DB_PORT
        - name: DB_NAME
          valueFrom:
            secretKeyRef:
              name: rds-credentials
              key: DB_NAME
        - name: DB_USER
          valueFrom:
            secretKeyRef:
              name: rds-credentials
              key: DB_USER
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: rds-credentials
              key: DB_PASSWORD
        ports:
        - containerPort: 8080
```

#### 3. Deploy
```bash
kubectl apply -f deployment.yaml
kubectl get pods
kubectl logs <pod-name>
```

---

## 🔧 IAM Roles

### Cluster Service Role
- **Role Name**: `vulnerability-eks-cluster-cluster-role`
- **ARN**: `arn:aws:iam::588989875114:role/vulnerability-eks-cluster-cluster-role`
- **Policies**:
  - `AmazonEKSClusterPolicy`

### Node Group Role
- **Role Name**: `vulnerability-eks-cluster-node-role`
- **ARN**: `arn:aws:iam::588989875114:role/vulnerability-eks-cluster-node-role`
- **Policies**:
  - `AmazonEKSWorkerNodePolicy`
  - `AmazonEKS_CNI_Policy`
  - `AmazonEC2ContainerRegistryReadOnly`
  - `AmazonSSMManagedInstanceCore`

---

## 🌐 Networking

### VPC Configuration
- **VPC ID**: `vpc-0f01f92b214c2db02` (Default VPC)
- **Subnets**: 4 subnets across availability zones
- **Security Group**: `eks-vulnerability-sg` (sg-032db21c2e103cf20)

### Security Group Rules
- **EKS Cluster**: Allows cluster communication
- **RDS Access**: EKS nodes can connect to RDS on port 5432

---

## 📊 Monitoring and Management

### View Cluster Status
```bash
aws eks describe-cluster --name vulnerability-eks-cluster --region ap-south-1
```

### View Node Group Status
```bash
aws eks describe-nodegroup \
  --cluster-name vulnerability-eks-cluster \
  --nodegroup-name vulnerability-nodegroup \
  --region ap-south-1
```

### View Logs
```bash
# Cluster logs are enabled and sent to CloudWatch
aws logs describe-log-groups --log-group-name-prefix /aws/eks/vulnerability-eks-cluster
```

### Scale Node Group
```bash
aws eks update-nodegroup-config \
  --cluster-name vulnerability-eks-cluster \
  --nodegroup-name vulnerability-nodegroup \
  --scaling-config minSize=1,maxSize=3,desiredSize=2 \
  --region ap-south-1
```

---

## 🔒 Security Best Practices

### Current Configuration
- ✅ Cluster logging enabled
- ✅ Public endpoint enabled (for kubectl access)
- ✅ Private endpoint disabled
- ✅ Security groups configured for RDS access
- ⚠️ Single node (no high availability)

### Recommendations
1. **Enable Private Endpoint**: For production, enable private endpoint
2. **Add More Nodes**: Scale to at least 2 nodes for high availability
3. **Use Secrets Manager**: Store RDS credentials in AWS Secrets Manager instead of Kubernetes secrets
4. **Enable Pod Security**: Configure Pod Security Standards
5. **Network Policies**: Implement network policies for pod-to-pod communication
6. **RBAC**: Configure Role-Based Access Control for Kubernetes

---

## 💰 Cost Estimate

### Current Setup
- **EKS Cluster**: $0.10/hour (~$73/month)
- **t3.medium Instance**: ~$0.0416/hour (~$30/month)
- **Total**: ~$103/month

### Cost Optimization
- Use Spot instances for non-production workloads
- Right-size instances based on actual usage
- Consider Fargate for serverless workloads

---

## 🛠️ Troubleshooting

### Common Issues

#### 1. Cannot Connect to Cluster
```bash
# Verify kubectl config
kubectl config current-context
# Should show: arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster

# Reconfigure if needed
aws eks update-kubeconfig --name vulnerability-eks-cluster --region ap-south-1
```

#### 2. Pods Cannot Connect to RDS
- Check security group rules
- Verify RDS endpoint is correct
- Check pod network policies
- Test connection from node:
```bash
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- psql -h postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com -U postgres -d vulnerability_db
```

#### 3. Node Not Ready
```bash
# Check node status
kubectl describe node <node-name>

# Check node logs
kubectl logs -n kube-system <cni-pod-name>
```

#### 4. Insufficient Resources
```bash
# Check node resources
kubectl top nodes
kubectl top pods --all-namespaces

# Scale node group if needed
aws eks update-nodegroup-config \
  --cluster-name vulnerability-eks-cluster \
  --nodegroup-name vulnerability-nodegroup \
  --scaling-config minSize=1,maxSize=3,desiredSize=2 \
  --region ap-south-1
```

---

## 📝 Useful Commands

### Cluster Management
```bash
# Get cluster info
kubectl cluster-info

# Get all resources
kubectl get all --all-namespaces

# Describe cluster
aws eks describe-cluster --name vulnerability-eks-cluster --region ap-south-1

# Update cluster version
aws eks update-cluster-version --name vulnerability-eks-cluster --region ap-south-1
```

### Node Management
```bash
# Get nodes
kubectl get nodes -o wide

# Describe node
kubectl describe node <node-name>

# Drain node (before maintenance)
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data
```

### Application Management
```bash
# Get pods
kubectl get pods -A

# Get services
kubectl get svc -A

# Get deployments
kubectl get deployments -A

# View logs
kubectl logs <pod-name> -n <namespace>

# Execute command in pod
kubectl exec -it <pod-name> -- /bin/bash
```

---

## 🔄 Next Steps

1. **Deploy Your Application**
   - Create deployment manifests
   - Configure RDS connection
   - Set up health checks

2. **Set Up CI/CD**
   - Configure GitHub Actions or GitLab CI
   - Set up image registry (ECR)
   - Automate deployments

3. **Monitoring**
   - Set up CloudWatch Container Insights
   - Configure Prometheus/Grafana
   - Set up alerting

4. **Scaling**
   - Configure Horizontal Pod Autoscaler
   - Set up Cluster Autoscaler
   - Plan for multi-node setup

---

## 📞 Support

### AWS Resources
- **EKS Documentation**: https://docs.aws.amazon.com/eks/
- **Kubernetes Documentation**: https://kubernetes.io/docs/
- **AWS Support**: Via AWS Console

### Internal Contacts
- **DevOps Team**: [Contact]
- **Database Admin**: [Contact]

---

## ✅ Verification Checklist

- [x] EKS cluster created and active
- [x] Node group created with t3.medium instance
- [x] kubectl configured
- [x] Security groups configured for RDS access
- [x] IAM roles created and attached
- [ ] Application deployed (pending)
- [ ] RDS connection tested from pods (pending)
- [ ] Monitoring configured (pending)

---

**Document Version**: 1.0  
**Last Updated**: December 29, 2024

---

*This document contains sensitive information. Store securely and limit access to authorized personnel only.*

