# Deployment Guide

Comprehensive deployment guide for the SMTP server across various environments and platforms.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Single Server Deployment](#single-server-deployment)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Cloud Platform Deployments](#cloud-platform-deployments)
6. [High Availability Setup](#high-availability-setup)
7. [TLS/SSL Configuration](#tlsssl-configuration)
8. [Database Setup](#database-setup)
9. [Monitoring Setup](#monitoring-setup)
10. [Backup and Recovery](#backup-and-recovery)
11. [Security Hardening](#security-hardening)
12. [Performance Tuning](#performance-tuning)

---

## Prerequisites

### System Requirements

**Minimum Requirements:**
- CPU: 2 cores
- RAM: 2GB
- Storage: 20GB SSD
- OS: Linux (Ubuntu 22.04+, Debian 11+, RHEL 8+), macOS 11+, Windows Server 2019+

**Recommended Requirements:**
- CPU: 4+ cores
- RAM: 8GB+
- Storage: 100GB+ SSD with IOPS > 3000
- OS: Linux (Ubuntu 24.04 LTS)

**Production Requirements:**
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 500GB+ NVMe SSD with IOPS > 10000
- Network: 1Gbps+
- OS: Linux (Ubuntu 24.04 LTS) with kernel 5.15+

### Software Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    sqlite3 \
    libsqlite3-dev \
    openssl \
    libssl-dev \
    ca-certificates \
    curl

# RHEL/CentOS/Rocky
sudo dnf install -y \
    gcc \
    make \
    sqlite \
    sqlite-devel \
    openssl \
    openssl-devel \
    ca-certificates \
    curl

# macOS
brew install sqlite openssl
```

### Network Requirements

**Required Ports:**
- 25/tcp - SMTP (inbound)
- 587/tcp - SMTP Submission (inbound)
- 465/tcp - SMTPS (inbound)
- 8080/tcp - HTTP API (optional, internal)
- 9090/tcp - Metrics (optional, internal)

**Firewall Configuration:**
```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 25/tcp
sudo ufw allow 587/tcp
sudo ufw allow 465/tcp
sudo ufw allow from 10.0.0.0/8 to any port 8080 proto tcp
sudo ufw allow from 10.0.0.0/8 to any port 9090 proto tcp
sudo ufw enable

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-port=25/tcp
sudo firewall-cmd --permanent --add-port=587/tcp
sudo firewall-cmd --permanent --add-port=465/tcp
sudo firewall-cmd --reload
```

---

## Single Server Deployment

### Step 1: Download and Build

```bash
# Clone repository
git clone https://github.com/yourusername/mail.git
cd mail

# Build for current platform
zig build -Doptimize=ReleaseSafe

# Verify build
./zig-out/bin/mail --version
```

### Step 2: Create System User

```bash
# Create dedicated user (no login shell)
sudo useradd -r -s /bin/false -d /var/lib/smtp -m smtp

# Create required directories
sudo mkdir -p /var/lib/smtp/{data,logs,queue}
sudo mkdir -p /etc/smtp
sudo chown -R smtp:smtp /var/lib/smtp
```

### Step 3: Configure Environment

```bash
# Create configuration file
sudo tee /etc/smtp/smtp.env << 'EOF'
# Server Configuration
SMTP_HOST=0.0.0.0
SMTP_PORT=25
SMTP_SUBMISSION_PORT=587
SMTP_SMTPS_PORT=465
SMTP_MAX_MESSAGE_SIZE=26214400

# TLS Configuration
TLS_CERT_PATH=/etc/smtp/certs/server.crt
TLS_KEY_PATH=/etc/smtp/certs/server.key
TLS_MODE=STARTTLS

# Storage Configuration
STORAGE_TYPE=maildir
STORAGE_PATH=/var/lib/smtp/data
QUEUE_PATH=/var/lib/smtp/queue

# Database Configuration
SMTP_DB_PATH=/var/lib/smtp/smtp.db

# Security Configuration
MAX_CONNECTIONS=1000
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60
SPAM_CHECK_ENABLED=true

# Logging
LOG_LEVEL=info
LOG_FILE=/var/lib/smtp/logs/smtp.log
EOF

sudo chown smtp:smtp /etc/smtp/smtp.env
sudo chmod 600 /etc/smtp/smtp.env
```

### Step 4: Generate TLS Certificates

```bash
# Generate self-signed certificate (development)
sudo mkdir -p /etc/smtp/certs
cd /etc/smtp/certs

sudo openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout server.key \
    -out server.crt \
    -days 365 \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=mail.example.com"

sudo chown smtp:smtp server.{key,crt}
sudo chmod 600 server.key
sudo chmod 644 server.crt

# For production, use Let's Encrypt (see TLS/SSL Configuration section)
```

### Step 5: Initialize Database

```bash
# Copy binary to system location
sudo cp zig-out/bin/mail /usr/local/bin/
sudo cp zig-out/bin/user-cli /usr/local/bin/
sudo cp zig-out/bin/gdpr-cli /usr/local/bin/

# Initialize database
sudo -u smtp /usr/local/bin/user-cli init

# Create admin user
sudo -u smtp /usr/local/bin/user-cli add admin@example.com --admin --password "SecurePassword123!"
```

### Step 6: Create Systemd Service

```bash
# Create service file
sudo tee /etc/systemd/system/mail.service << 'EOF'
[Unit]
Description=Mail Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=smtp
Group=smtp
WorkingDirectory=/var/lib/smtp
EnvironmentFile=/etc/smtp/smtp.env
ExecStart=/usr/local/bin/mail
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/smtp
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable mail
sudo systemctl start mail
sudo systemctl status mail
```

### Step 7: Verify Deployment

```bash
# Check service status
sudo systemctl status mail

# View logs
sudo journalctl -u mail -f

# Test SMTP connection
telnet localhost 25
# Expected: 220 mail.example.com ESMTP

# Test health endpoint
curl http://localhost:8080/health
# Expected: {"status":"healthy","uptime_seconds":123}
```

---

## Docker Deployment

### Dockerfile

Create `Dockerfile`:

```dockerfile
FROM alpine:3.19 AS builder

# Install build dependencies
RUN apk add --no-cache \
    curl \
    xz \
    gcc \
    musl-dev \
    sqlite-dev \
    openssl-dev

# Install Zig 0.15.1
RUN curl -L https://ziglang.org/download/0.15.1/zig-linux-x86_64-0.15.1.tar.xz | tar -xJ -C /opt
ENV PATH="/opt/zig-linux-x86_64-0.15.1:${PATH}"

# Copy source code
WORKDIR /app
COPY . .

# Build application
RUN zig build -Doptimize=ReleaseSafe

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    sqlite-libs \
    openssl \
    ca-certificates

# Create user and directories
RUN addgroup -S smtp && adduser -S smtp -G smtp
RUN mkdir -p /var/lib/smtp/{data,logs,queue} && \
    chown -R smtp:smtp /var/lib/smtp

# Copy binaries from builder
COPY --from=builder /app/zig-out/bin/mail /usr/local/bin/
COPY --from=builder /app/zig-out/bin/user-cli /usr/local/bin/
COPY --from=builder /app/zig-out/bin/gdpr-cli /usr/local/bin/

# Switch to non-root user
USER smtp
WORKDIR /var/lib/smtp

# Expose ports
EXPOSE 25 587 465 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Start server
CMD ["/usr/local/bin/mail"]
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  mail:
    build: .
    container_name: mail
    restart: unless-stopped
    ports:
      - "25:25"
      - "587:587"
      - "465:465"
      - "8080:8080"
      - "9090:9090"
    environment:
      - SMTP_HOST=0.0.0.0
      - SMTP_PORT=25
      - SMTP_SUBMISSION_PORT=587
      - SMTP_SMTPS_PORT=465
      - SMTP_MAX_MESSAGE_SIZE=26214400
      - TLS_CERT_PATH=/certs/server.crt
      - TLS_KEY_PATH=/certs/server.key
      - TLS_MODE=STARTTLS
      - STORAGE_TYPE=maildir
      - STORAGE_PATH=/var/lib/smtp/data
      - QUEUE_PATH=/var/lib/smtp/queue
      - SMTP_DB_PATH=/var/lib/smtp/smtp.db
      - MAX_CONNECTIONS=1000
      - RATE_LIMIT_ENABLED=true
      - RATE_LIMIT_PER_MINUTE=60
      - SPAM_CHECK_ENABLED=true
      - LOG_LEVEL=info
    volumes:
      - smtp-data:/var/lib/smtp/data
      - smtp-queue:/var/lib/smtp/queue
      - smtp-db:/var/lib/smtp
      - smtp-logs:/var/lib/smtp/logs
      - ./certs:/certs:ro
    networks:
      - smtp-network
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Optional: Prometheus for metrics
  prometheus:
    image: prom/prometheus:latest
    container_name: smtp-prometheus
    restart: unless-stopped
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    networks:
      - smtp-network

  # Optional: Grafana for visualization
  grafana:
    image: grafana/grafana:latest
    container_name: smtp-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
    networks:
      - smtp-network

volumes:
  smtp-data:
  smtp-queue:
  smtp-db:
  smtp-logs:
  prometheus-data:
  grafana-data:

networks:
  smtp-network:
    driver: bridge
```

### Prometheus Configuration

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'mail'
    static_configs:
      - targets: ['mail:9090']
        labels:
          service: 'smtp'
```

### Deploy with Docker

```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f mail

# Initialize database
docker exec mail user-cli init

# Create admin user
docker exec mail user-cli add admin@example.com --admin --password "SecurePassword123!"

# Check health
curl http://localhost:8080/health

# Access Grafana (if enabled)
open http://localhost:3000
```

---

## Kubernetes Deployment

### Namespace and ConfigMap

Create `k8s/namespace.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: smtp-system
  labels:
    app.kubernetes.io/name: mail
```

Create `k8s/configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: smtp-config
  namespace: smtp-system
data:
  SMTP_HOST: "0.0.0.0"
  SMTP_PORT: "25"
  SMTP_SUBMISSION_PORT: "587"
  SMTP_SMTPS_PORT: "465"
  SMTP_MAX_MESSAGE_SIZE: "26214400"
  TLS_MODE: "STARTTLS"
  STORAGE_TYPE: "maildir"
  STORAGE_PATH: "/var/lib/smtp/data"
  QUEUE_PATH: "/var/lib/smtp/queue"
  SMTP_DB_PATH: "/var/lib/smtp/smtp.db"
  MAX_CONNECTIONS: "1000"
  RATE_LIMIT_ENABLED: "true"
  RATE_LIMIT_PER_MINUTE: "60"
  SPAM_CHECK_ENABLED: "true"
  LOG_LEVEL: "info"
```

### Secret for TLS Certificates

```bash
# Create TLS secret from existing certificates
kubectl create secret tls smtp-tls \
  --cert=certs/server.crt \
  --key=certs/server.key \
  -n smtp-system
```

### PersistentVolumeClaim

Create `k8s/pvc.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: smtp-data-pvc
  namespace: smtp-system
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: fast-ssd
  resources:
    requests:
      storage: 100Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: smtp-queue-pvc
  namespace: smtp-system
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: fast-ssd
  resources:
    requests:
      storage: 50Gi
```

### Deployment

Create `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mail
  namespace: smtp-system
  labels:
    app: mail
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: mail
  template:
    metadata:
      labels:
        app: mail
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: mail
      securityContext:
        fsGroup: 1000
        runAsNonRoot: true
        runAsUser: 1000
      containers:
      - name: mail
        image: your-registry/mail:latest
        imagePullPolicy: Always
        ports:
        - name: smtp
          containerPort: 25
          protocol: TCP
        - name: submission
          containerPort: 587
          protocol: TCP
        - name: smtps
          containerPort: 465
          protocol: TCP
        - name: http
          containerPort: 8080
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP
        envFrom:
        - configMapRef:
            name: smtp-config
        env:
        - name: TLS_CERT_PATH
          value: "/certs/tls.crt"
        - name: TLS_KEY_PATH
          value: "/certs/tls.key"
        volumeMounts:
        - name: smtp-data
          mountPath: /var/lib/smtp/data
        - name: smtp-queue
          mountPath: /var/lib/smtp/queue
        - name: tls-certs
          mountPath: /certs
          readOnly: true
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 2000m
            memory: 2Gi
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
      volumes:
      - name: smtp-data
        persistentVolumeClaim:
          claimName: smtp-data-pvc
      - name: smtp-queue
        persistentVolumeClaim:
          claimName: smtp-queue-pvc
      - name: tls-certs
        secret:
          secretName: smtp-tls
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - mail
              topologyKey: kubernetes.io/hostname
```

### Service

Create `k8s/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: mail
  namespace: smtp-system
  labels:
    app: mail
spec:
  type: LoadBalancer
  selector:
    app: mail
  ports:
  - name: smtp
    port: 25
    targetPort: 25
    protocol: TCP
  - name: submission
    port: 587
    targetPort: 587
    protocol: TCP
  - name: smtps
    port: 465
    targetPort: 465
    protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: mail-internal
  namespace: smtp-system
  labels:
    app: mail
spec:
  type: ClusterIP
  selector:
    app: mail
  ports:
  - name: http
    port: 8080
    targetPort: 8080
    protocol: TCP
  - name: metrics
    port: 9090
    targetPort: 9090
    protocol: TCP
```

### ServiceAccount and RBAC

Create `k8s/rbac.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mail
  namespace: smtp-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mail-role
  namespace: smtp-system
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: mail-rolebinding
  namespace: smtp-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: mail-role
subjects:
- kind: ServiceAccount
  name: mail
  namespace: smtp-system
```

### HorizontalPodAutoscaler

Create `k8s/hpa.yaml`:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mail-hpa
  namespace: smtp-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mail
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 30
      - type: Pods
        value: 2
        periodSeconds: 30
      selectPolicy: Max
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Create TLS secret
kubectl create secret tls smtp-tls \
  --cert=certs/server.crt \
  --key=certs/server.key \
  -n smtp-system

# Apply all manifests
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml

# Wait for deployment
kubectl rollout status deployment/mail -n smtp-system

# Check pods
kubectl get pods -n smtp-system

# View logs
kubectl logs -f -l app=mail -n smtp-system

# Get service external IP
kubectl get svc mail -n smtp-system

# Initialize database (run once)
POD_NAME=$(kubectl get pods -n smtp-system -l app=mail -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n smtp-system $POD_NAME -- user-cli init

# Create admin user
kubectl exec -n smtp-system $POD_NAME -- user-cli add admin@example.com --admin --password "SecurePassword123!"
```

---

## Cloud Platform Deployments

### AWS EC2 Deployment

**Step 1: Launch EC2 Instance**

```bash
# Using AWS CLI
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.large \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxxx \
  --subnet-id subnet-xxxxxxxxx \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":100,"VolumeType":"gp3","Iops":3000}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=mail}]' \
  --iam-instance-profile Name=mail-profile
```

**Step 2: Security Group Configuration**

```bash
# Create security group
aws ec2 create-security-group \
  --group-name mail-sg \
  --description "Mail Server Security Group"

# Add inbound rules
aws ec2 authorize-security-group-ingress \
  --group-name mail-sg \
  --protocol tcp --port 25 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-name mail-sg \
  --protocol tcp --port 587 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-name mail-sg \
  --protocol tcp --port 465 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-name mail-sg \
  --protocol tcp --port 22 --cidr your-ip/32
```

**Step 3: Elastic IP and DNS**

```bash
# Allocate Elastic IP
aws ec2 allocate-address --domain vpc

# Associate with instance
aws ec2 associate-address \
  --instance-id i-xxxxxxxxx \
  --allocation-id eipalloc-xxxxxxxxx

# Update DNS (Route 53)
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch file://dns-change.json
```

### AWS ECS Deployment

Create `ecs-task-definition.json`:

```json
{
  "family": "mail",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/mail-task-role",
  "containerDefinitions": [
    {
      "name": "mail",
      "image": "ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/mail:latest",
      "essential": true,
      "portMappings": [
        {"containerPort": 25, "protocol": "tcp"},
        {"containerPort": 587, "protocol": "tcp"},
        {"containerPort": 465, "protocol": "tcp"},
        {"containerPort": 8080, "protocol": "tcp"},
        {"containerPort": 9090, "protocol": "tcp"}
      ],
      "environment": [
        {"name": "SMTP_HOST", "value": "0.0.0.0"},
        {"name": "SMTP_PORT", "value": "25"}
      ],
      "secrets": [
        {
          "name": "TLS_CERT",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:smtp/tls-cert"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "smtp-data",
          "containerPath": "/var/lib/smtp/data"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/mail",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "smtp"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -q -O- http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ],
  "volumes": [
    {
      "name": "smtp-data",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-xxxxxxxxx",
        "transitEncryption": "ENABLED"
      }
    }
  ]
}
```

Deploy ECS service:

```bash
# Register task definition
aws ecs register-task-definition --cli-input-json file://ecs-task-definition.json

# Create service
aws ecs create-service \
  --cluster smtp-cluster \
  --service-name mail \
  --task-definition mail:1 \
  --desired-count 3 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:us-east-1:ACCOUNT:targetgroup/smtp/xxx,containerName=mail,containerPort=587"
```

### GCP Compute Engine Deployment

```bash
# Create instance
gcloud compute instances create mail \
  --machine-type=n2-standard-4 \
  --zone=us-central1-a \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=100GB \
  --boot-disk-type=pd-ssd \
  --tags=mail \
  --metadata=startup-script='#!/bin/bash
    apt-get update
    apt-get install -y sqlite3 libsqlite3-dev
    # Install and configure SMTP server
    '

# Create firewall rules
gcloud compute firewall-rules create allow-smtp \
  --allow tcp:25,tcp:587,tcp:465 \
  --target-tags mail \
  --description "Allow SMTP traffic"

# Reserve static IP
gcloud compute addresses create mail-ip --region us-central1

# Attach static IP
gcloud compute instances add-access-config mail \
  --zone us-central1-a \
  --address $(gcloud compute addresses describe mail-ip --region us-central1 --format="value(address)")
```

### Azure VM Deployment

```bash
# Create resource group
az group create --name smtp-rg --location eastus

# Create virtual network
az network vnet create \
  --resource-group smtp-rg \
  --name smtp-vnet \
  --address-prefix 10.0.0.0/16 \
  --subnet-name smtp-subnet \
  --subnet-prefix 10.0.1.0/24

# Create public IP
az network public-ip create \
  --resource-group smtp-rg \
  --name smtp-public-ip \
  --sku Standard \
  --allocation-method Static

# Create NSG
az network nsg create \
  --resource-group smtp-rg \
  --name smtp-nsg

az network nsg rule create \
  --resource-group smtp-rg \
  --nsg-name smtp-nsg \
  --name allow-smtp \
  --priority 100 \
  --destination-port-ranges 25 587 465 \
  --protocol Tcp

# Create VM
az vm create \
  --resource-group smtp-rg \
  --name mail \
  --image Ubuntu2404 \
  --size Standard_D4s_v3 \
  --admin-username azureuser \
  --ssh-key-values ~/.ssh/id_rsa.pub \
  --public-ip-address smtp-public-ip \
  --nsg smtp-nsg \
  --vnet-name smtp-vnet \
  --subnet smtp-subnet \
  --os-disk-size-gb 100 \
  --storage-sku Premium_LRS
```

---

## High Availability Setup

### Load Balancer Configuration

**HAProxy Configuration** (`/etc/haproxy/haproxy.cfg`):

```
global
    log /dev/log local0
    log /dev/log local1 notice
    maxconn 4096
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000

frontend smtp_front
    bind *:25
    default_backend smtp_servers

frontend submission_front
    bind *:587
    default_backend smtp_servers

frontend smtps_front
    bind *:465
    default_backend smtp_servers

backend smtp_servers
    balance roundrobin
    option tcp-check
    server smtp1 10.0.1.10:25 check
    server smtp2 10.0.1.11:25 check
    server smtp3 10.0.1.12:25 check

listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 10s
    stats auth admin:password
```

### Keepalived for HA

**Master Node** (`/etc/keepalived/keepalived.conf`):

```
vrrp_script check_haproxy {
    script "/usr/bin/killall -0 haproxy"
    interval 2
    weight 2
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 101
    advert_int 1

    authentication {
        auth_type PASS
        auth_pass SecurePassword123
    }

    virtual_ipaddress {
        10.0.1.100/24
    }

    track_script {
        check_haproxy
    }
}
```

**Backup Node** (`/etc/keepalived/keepalived.conf`):

```
vrrp_instance VI_1 {
    state BACKUP
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1

    authentication {
        auth_type PASS
        auth_pass SecurePassword123
    }

    virtual_ipaddress {
        10.0.1.100/24
    }

    track_script {
        check_haproxy
    }
}
```

### Shared Storage with NFS

**NFS Server Setup:**

```bash
# Install NFS server
sudo apt-get install -y nfs-kernel-server

# Create shared directory
sudo mkdir -p /export/smtp/{data,queue}
sudo chown smtp:smtp /export/smtp

# Configure exports
sudo tee -a /etc/exports << 'EOF'
/export/smtp 10.0.1.0/24(rw,sync,no_subtree_check,no_root_squash)
EOF

# Apply configuration
sudo exportfs -ra
sudo systemctl restart nfs-server
```

**NFS Client Setup:**

```bash
# Install NFS client
sudo apt-get install -y nfs-common

# Mount NFS share
sudo mkdir -p /var/lib/smtp/{data,queue}
sudo mount 10.0.1.5:/export/smtp/data /var/lib/smtp/data
sudo mount 10.0.1.5:/export/smtp/queue /var/lib/smtp/queue

# Add to fstab for persistence
echo "10.0.1.5:/export/smtp/data /var/lib/smtp/data nfs defaults 0 0" | sudo tee -a /etc/fstab
echo "10.0.1.5:/export/smtp/queue /var/lib/smtp/queue nfs defaults 0 0" | sudo tee -a /etc/fstab
```

### Database Replication

For production HA, use PostgreSQL with replication instead of SQLite.

**Primary Server Configuration** (`/etc/postgresql/16/main/postgresql.conf`):

```
wal_level = replica
max_wal_senders = 3
wal_keep_size = 64
```

**Replica Server Setup:**

```bash
# Stop PostgreSQL on replica
sudo systemctl stop postgresql

# Remove data directory
sudo rm -rf /var/lib/postgresql/16/main/*

# Create base backup
sudo -u postgres pg_basebackup -h primary-host -D /var/lib/postgresql/16/main -U replication -P -v -R

# Start PostgreSQL
sudo systemctl start postgresql
```

---

## TLS/SSL Configuration

### Let's Encrypt (Recommended for Production)

```bash
# Install Certbot
sudo apt-get update
sudo apt-get install -y certbot

# Obtain certificate (HTTP-01 challenge)
sudo certbot certonly --standalone \
  -d mail.example.com \
  --email admin@example.com \
  --agree-tos \
  --no-eff-email

# Certificates will be at:
# /etc/letsencrypt/live/mail.example.com/fullchain.pem
# /etc/letsencrypt/live/mail.example.com/privkey.pem

# Update environment configuration
sudo tee -a /etc/smtp/smtp.env << 'EOF'
TLS_CERT_PATH=/etc/letsencrypt/live/mail.example.com/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/mail.example.com/privkey.pem
EOF

# Set up automatic renewal
sudo tee /etc/cron.daily/certbot-renew << 'EOF'
#!/bin/bash
certbot renew --quiet --post-hook "systemctl reload mail"
EOF
sudo chmod +x /etc/cron.daily/certbot-renew
```

### Custom CA Certificate

```bash
# Generate CA private key
openssl genrsa -aes256 -out ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key ca-key.pem -sha256 -out ca-cert.pem

# Generate server private key
openssl genrsa -out server-key.pem 4096

# Generate certificate signing request
openssl req -new -key server-key.pem -out server.csr

# Sign server certificate with CA
openssl x509 -req -days 365 -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -sha256

# Copy to SMTP server
sudo cp server-cert.pem /etc/smtp/certs/server.crt
sudo cp server-key.pem /etc/smtp/certs/server.key
sudo chown smtp:smtp /etc/smtp/certs/server.{crt,key}
sudo chmod 600 /etc/smtp/certs/server.key
```

### TLS Configuration Options

```bash
# STARTTLS mode (port 587)
TLS_MODE=STARTTLS
SMTP_SUBMISSION_PORT=587

# Implicit TLS mode (port 465)
TLS_MODE=IMPLICIT
SMTP_SMTPS_PORT=465

# Opportunistic TLS (both)
TLS_MODE=OPPORTUNISTIC
SMTP_PORT=25
SMTP_SUBMISSION_PORT=587
```

---

## Database Setup

### SQLite (Default)

```bash
# Initialize database
sudo -u smtp user-cli init

# Database location
SMTP_DB_PATH=/var/lib/smtp/smtp.db

# Backup database
sudo -u smtp sqlite3 /var/lib/smtp/smtp.db ".backup /var/lib/smtp/backup/smtp-$(date +%Y%m%d).db"

# Enable WAL mode for better concurrency
sudo -u smtp sqlite3 /var/lib/smtp/smtp.db "PRAGMA journal_mode=WAL;"
```

### PostgreSQL (Production)

**Install PostgreSQL:**

```bash
# Ubuntu/Debian
sudo apt-get install -y postgresql-16 postgresql-contrib

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE smtp;
CREATE USER smtp WITH ENCRYPTED PASSWORD 'SecurePassword123';
GRANT ALL PRIVILEGES ON DATABASE smtp TO smtp;
\c smtp
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EOF
```

**Schema Migration:**

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Messages table
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sender VARCHAR(255) NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    subject TEXT,
    body TEXT,
    headers JSONB,
    size_bytes INTEGER,
    received_at TIMESTAMP DEFAULT NOW(),
    delivered_at TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending'
);

-- Audit log table
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    ip_address INET,
    timestamp TIMESTAMP DEFAULT NOW(),
    details JSONB
);

-- Indexes
CREATE INDEX idx_messages_sender ON messages(sender);
CREATE INDEX idx_messages_recipient ON messages(recipient);
CREATE INDEX idx_messages_received_at ON messages(received_at DESC);
CREATE INDEX idx_audit_log_username ON audit_log(username);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);

-- Full-text search
CREATE INDEX idx_messages_subject_fts ON messages USING GIN(to_tsvector('english', subject));
CREATE INDEX idx_messages_body_fts ON messages USING GIN(to_tsvector('english', body));
```

**Configuration:**

```bash
# Update environment
DB_TYPE=postgresql
DB_HOST=localhost
DB_PORT=5432
DB_NAME=smtp
DB_USER=smtp
DB_PASSWORD=SecurePassword123
DB_POOL_SIZE=20
DB_TIMEOUT=30
```

---

## Monitoring Setup

### Prometheus Configuration

Create `/etc/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    region: 'us-east-1'

scrape_configs:
  - job_name: 'mail'
    static_configs:
      - targets:
        - 'mail1:9090'
        - 'mail2:9090'
        - 'mail3:9090'
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
      - source_labels: [instance]
        regex: '([^:]+):.*'
        replacement: '${1}'
        target_label: host

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - 'alertmanager:9093'

rule_files:
  - '/etc/prometheus/rules/*.yml'
```

### Prometheus Alert Rules

Create `/etc/prometheus/rules/smtp.yml`:

```yaml
groups:
  - name: smtp_alerts
    interval: 30s
    rules:
      - alert: SMTPServerDown
        expr: up{job="mail"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "SMTP server {{ $labels.instance }} is down"
          description: "SMTP server has been down for more than 1 minute"

      - alert: HighErrorRate
        expr: rate(smtp_errors_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate on {{ $labels.instance }}"
          description: "Error rate is {{ $value }} errors/sec"

      - alert: QueueBacklog
        expr: smtp_queue_size > 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Mail queue backlog on {{ $labels.instance }}"
          description: "Queue has {{ $value }} messages pending"

      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes{job="mail"} > 2e9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on {{ $labels.instance }}"
          description: "Memory usage is {{ $value | humanize }}B"

      - alert: HighCPUUsage
        expr: rate(process_cpu_seconds_total{job="mail"}[5m]) > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on {{ $labels.instance }}"
          description: "CPU usage is {{ $value | humanizePercentage }}"
```

### Grafana Dashboards

Import dashboard JSON or create manually with these panels:

1. **System Health:**
   - Uptime
   - CPU usage
   - Memory usage
   - Disk I/O

2. **SMTP Metrics:**
   - Messages received/sent per minute
   - Queue size
   - Error rate
   - Average processing time

3. **Connection Metrics:**
   - Active connections
   - Connection rate
   - Failed connections
   - Authentication failures

4. **Performance:**
   - P50/P95/P99 latency
   - Throughput (messages/sec)
   - Database query time

### Log Aggregation with Loki

**Promtail Configuration** (`/etc/promtail/config.yml`):

```yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: smtp-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: mail
          __path__: /var/lib/smtp/logs/*.log
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) \[(?P<level>\w+)\] (?P<message>.*)$'
      - labels:
          level:
      - timestamp:
          source: timestamp
          format: RFC3339
```

---

## Backup and Recovery

### Automated Backup Script

Create `/usr/local/bin/smtp-backup.sh`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/var/backups/smtp"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/$TIMESTAMP"

# Create backup directory
mkdir -p "$BACKUP_PATH"

# Backup database
echo "Backing up database..."
sqlite3 /var/lib/smtp/smtp.db ".backup $BACKUP_PATH/smtp.db"

# Backup mail data
echo "Backing up mail data..."
tar -czf "$BACKUP_PATH/data.tar.gz" -C /var/lib/smtp data/

# Backup queue
echo "Backing up queue..."
tar -czf "$BACKUP_PATH/queue.tar.gz" -C /var/lib/smtp queue/

# Backup configuration
echo "Backing up configuration..."
cp -r /etc/smtp "$BACKUP_PATH/config"

# Create manifest
echo "Creating manifest..."
cat > "$BACKUP_PATH/manifest.txt" << EOF
Backup created: $TIMESTAMP
Hostname: $(hostname)
Database size: $(stat -f%z "$BACKUP_PATH/smtp.db" 2>/dev/null || stat -c%s "$BACKUP_PATH/smtp.db")
Data archive size: $(stat -f%z "$BACKUP_PATH/data.tar.gz" 2>/dev/null || stat -c%s "$BACKUP_PATH/data.tar.gz")
Queue archive size: $(stat -f%z "$BACKUP_PATH/queue.tar.gz" 2>/dev/null || stat -c%s "$BACKUP_PATH/queue.tar.gz")
EOF

# Calculate checksums
echo "Calculating checksums..."
cd "$BACKUP_PATH"
sha256sum * > checksums.txt

# Compress entire backup
echo "Compressing backup..."
cd "$BACKUP_DIR"
tar -czf "${TIMESTAMP}.tar.gz" "$TIMESTAMP"
rm -rf "$TIMESTAMP"

# Upload to S3 (optional)
if command -v aws &> /dev/null; then
    echo "Uploading to S3..."
    aws s3 cp "${TIMESTAMP}.tar.gz" "s3://smtp-backups/$(hostname)/${TIMESTAMP}.tar.gz"
fi

# Clean old backups
echo "Cleaning old backups..."
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_PATH"
```

Make executable and schedule:

```bash
sudo chmod +x /usr/local/bin/smtp-backup.sh

# Add to crontab (daily at 2 AM)
sudo crontab -e
0 2 * * * /usr/local/bin/smtp-backup.sh >> /var/log/smtp-backup.log 2>&1
```

### Restore Procedure

Create `/usr/local/bin/smtp-restore.sh`:

```bash
#!/bin/bash
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_archive>"
    exit 1
fi

BACKUP_ARCHIVE="$1"
TEMP_DIR=$(mktemp -d)

echo "Restoring from: $BACKUP_ARCHIVE"

# Stop SMTP server
echo "Stopping SMTP server..."
systemctl stop mail

# Extract backup
echo "Extracting backup..."
tar -xzf "$BACKUP_ARCHIVE" -C "$TEMP_DIR"
BACKUP_DIR=$(ls -1 "$TEMP_DIR" | head -n 1)

# Verify checksums
echo "Verifying checksums..."
cd "$TEMP_DIR/$BACKUP_DIR"
sha256sum -c checksums.txt || {
    echo "Checksum verification failed!"
    exit 1
}

# Restore database
echo "Restoring database..."
cp smtp.db /var/lib/smtp/smtp.db
chown smtp:smtp /var/lib/smtp/smtp.db

# Restore data
echo "Restoring mail data..."
rm -rf /var/lib/smtp/data
tar -xzf data.tar.gz -C /var/lib/smtp/
chown -R smtp:smtp /var/lib/smtp/data

# Restore queue
echo "Restoring queue..."
rm -rf /var/lib/smtp/queue
tar -xzf queue.tar.gz -C /var/lib/smtp/
chown -R smtp:smtp /var/lib/smtp/queue

# Restore configuration
echo "Restoring configuration..."
cp -r config/* /etc/smtp/
chown -R root:root /etc/smtp
chmod 600 /etc/smtp/smtp.env

# Start SMTP server
echo "Starting SMTP server..."
systemctl start mail

# Cleanup
rm -rf "$TEMP_DIR"

echo "Restore completed successfully!"
```

---

## Security Hardening

### Firewall Configuration

```bash
# UFW (Ubuntu/Debian)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 25/tcp   # SMTP
sudo ufw allow 587/tcp  # Submission
sudo ufw allow 465/tcp  # SMTPS
sudo ufw limit 22/tcp   # Rate limit SSH
sudo ufw enable

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-service=smtp
sudo firewall-cmd --permanent --add-service=smtp-submission
sudo firewall-cmd --permanent --add-service=smtps
sudo firewall-cmd --reload
```

### Fail2Ban Configuration

Create `/etc/fail2ban/filter.d/smtp-auth.conf`:

```ini
[Definition]
failregex = ^.*Authentication failed for user.*from <HOST>$
            ^.*Invalid authentication attempt from <HOST>$
            ^.*Rejected connection from <HOST>.*$
ignoreregex =
```

Create `/etc/fail2ban/jail.d/smtp.conf`:

```ini
[smtp-auth]
enabled = true
port = smtp,submission,smtps
filter = smtp-auth
logpath = /var/lib/smtp/logs/smtp.log
maxretry = 5
findtime = 600
bantime = 3600
action = iptables-multiport[name=smtp, port="smtp,submission,smtps", protocol=tcp]
```

Restart Fail2Ban:

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status smtp-auth
```

### AppArmor Profile

Create `/etc/apparmor.d/usr.local.bin.mail`:

```
#include <tunables/global>

/usr/local/bin/mail {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>

  capability net_bind_service,
  capability setgid,
  capability setuid,

  network inet stream,
  network inet6 stream,

  /usr/local/bin/mail mr,
  /var/lib/smtp/** rw,
  /etc/smtp/** r,
  /tmp/** rw,

  deny /proc/sys/kernel/osrelease r,
  deny /sys/** r,
}
```

Load profile:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.mail
```

### SELinux Policy (RHEL/CentOS)

```bash
# Create SELinux module
cat > mail.te << EOF
module mail 1.0;

require {
    type smtp_port_t;
    type smtp_server_t;
    class tcp_socket { bind listen };
}

allow smtp_server_t smtp_port_t:tcp_socket { bind listen };
EOF

# Compile and install
checkmodule -M -m -o mail.mod mail.te
semodule_package -o mail.pp -m mail.mod
semodule -i mail.pp

# Set file contexts
semanage fcontext -a -t smtp_server_exec_t "/usr/local/bin/mail"
semanage fcontext -a -t smtp_server_var_lib_t "/var/lib/smtp(/.*)?"
restorecon -Rv /usr/local/bin/mail /var/lib/smtp
```

### System Hardening

```bash
# Disable unnecessary services
sudo systemctl disable --now avahi-daemon
sudo systemctl disable --now cups
sudo systemctl disable --now bluetooth

# Kernel hardening (sysctl)
sudo tee -a /etc/sysctl.d/99-smtp-hardening.conf << EOF
# Network security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1

# IPv6 security
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Increase connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.ipv4.tcp_max_syn_backlog = 8192

# File descriptor limits
fs.file-max = 65536
EOF

sudo sysctl -p /etc/sysctl.d/99-smtp-hardening.conf

# Set resource limits
sudo tee -a /etc/security/limits.conf << EOF
smtp soft nofile 65536
smtp hard nofile 65536
smtp soft nproc 4096
smtp hard nproc 4096
EOF
```

---

## Performance Tuning

### Kernel Tuning

```bash
# Network performance
sudo tee -a /etc/sysctl.d/99-smtp-performance.conf << EOF
# TCP tuning
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# Connection tracking
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
EOF

sudo sysctl -p /etc/sysctl.d/99-smtp-performance.conf
```

### Application Tuning

```bash
# Increase max connections
MAX_CONNECTIONS=10000

# Enable connection pooling
CONNECTION_POOL_SIZE=100

# Tune worker threads
WORKER_THREADS=8  # Number of CPU cores

# Enable async I/O
ASYNC_IO=true

# Cache configuration
CACHE_SIZE=1073741824  # 1GB
CACHE_TTL=300  # 5 minutes

# Queue tuning
QUEUE_BATCH_SIZE=100
QUEUE_WORKER_THREADS=4
```

### Database Optimization

**SQLite:**

```sql
-- Enable WAL mode
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -64000;  -- 64MB cache
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 30000000000;  -- 30GB mmap

-- Analyze tables
ANALYZE;

-- Rebuild indexes
REINDEX;

-- Vacuum database
VACUUM;
```

**PostgreSQL:**

```sql
-- Connection pooling (pgbouncer)
-- /etc/pgbouncer/pgbouncer.ini
[databases]
smtp = host=localhost port=5432 dbname=smtp

[pgbouncer]
listen_port = 6432
listen_addr = 127.0.0.1
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25

-- PostgreSQL tuning
-- /etc/postgresql/16/main/postgresql.conf
shared_buffers = 4GB
effective_cache_size = 12GB
maintenance_work_mem = 1GB
work_mem = 16MB
max_connections = 200
random_page_cost = 1.1
effective_io_concurrency = 200
```

---

## Validation Checklist

After deployment, verify the following:

### Service Health

- [ ] SMTP server is running: `systemctl status mail`
- [ ] Ports are listening: `ss -tlnp | grep -E '(25|587|465)'`
- [ ] Health endpoint responds: `curl http://localhost:8080/health`
- [ ] Metrics endpoint responds: `curl http://localhost:9090/metrics`

### Connectivity

- [ ] Can connect to SMTP: `telnet localhost 25`
- [ ] Can connect to Submission: `telnet localhost 587`
- [ ] STARTTLS works: `openssl s_client -starttls smtp -connect localhost:587`
- [ ] SMTPS works: `openssl s_client -connect localhost:465`

### Authentication

- [ ] User exists: `user-cli list`
- [ ] Can authenticate: Test with mail client
- [ ] Authentication failures are logged
- [ ] Rate limiting is active

### Email Flow

- [ ] Can send email via port 25
- [ ] Can send email via port 587 (authenticated)
- [ ] Messages are stored correctly
- [ ] Queue is processing
- [ ] Delivery is working

### Security

- [ ] TLS certificates are valid
- [ ] Firewall rules are active
- [ ] Fail2Ban is running
- [ ] AppArmor/SELinux is enforcing
- [ ] No unnecessary services running

### Monitoring

- [ ] Prometheus is scraping metrics
- [ ] Grafana dashboards are working
- [ ] Alerts are configured
- [ ] Logs are being collected
- [ ] Backup script is scheduled

### Performance

- [ ] Connection limits are appropriate
- [ ] Resource usage is normal
- [ ] No memory leaks detected
- [ ] Latency is acceptable
- [ ] Queue is not backing up

---

## Troubleshooting Common Issues

### Issue: Port 25 Permission Denied

**Solution:**
```bash
# Grant CAP_NET_BIND_SERVICE capability
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/mail

# Or run as root (not recommended)
# Or use systemd socket activation
```

### Issue: TLS Certificate Errors

**Solution:**
```bash
# Verify certificate
openssl x509 -in /etc/smtp/certs/server.crt -text -noout

# Check permissions
ls -l /etc/smtp/certs/

# Test TLS connection
openssl s_client -connect localhost:587 -starttls smtp
```

### Issue: Database Locked

**Solution:**
```bash
# Enable WAL mode
sqlite3 /var/lib/smtp/smtp.db "PRAGMA journal_mode=WAL;"

# Check for stale locks
lsof /var/lib/smtp/smtp.db

# Or migrate to PostgreSQL
```

### Issue: High Memory Usage

**Solution:**
```bash
# Check for memory leaks
valgrind --leak-check=full /usr/local/bin/mail

# Reduce cache size
CACHE_SIZE=536870912  # 512MB

# Enable memory limits in systemd
MemoryMax=2G
```

### Issue: Messages Not Delivering

**Solution:**
```bash
# Check queue
ls -l /var/lib/smtp/queue/

# View queue status
# (if queue management CLI is implemented)

# Check logs
journalctl -u mail -n 100 | grep delivery

# Verify DNS records
dig MX example.com
```

---

## Next Steps

After successful deployment:

1. **Configure DNS Records:**
   - MX records for inbound mail
   - SPF record for sender validation
   - DKIM keys for email signing
   - DMARC policy for authentication

2. **Set Up Monitoring:**
   - Configure alert rules
   - Create dashboards
   - Set up log aggregation
   - Configure on-call rotations

3. **Implement Backup Strategy:**
   - Schedule automated backups
   - Test restore procedures
   - Configure off-site storage
   - Document recovery processes

4. **Security Hardening:**
   - Perform security audit
   - Enable intrusion detection
   - Configure security scanning
   - Review access controls

5. **Performance Testing:**
   - Run load tests
   - Measure throughput
   - Identify bottlenecks
   - Optimize configuration

6. **Documentation:**
   - Document custom configurations
   - Create runbooks
   - Train operations team
   - Establish change management

---

For additional help, see:
- [Architecture Documentation](./ARCHITECTURE.md)
- [API Documentation](./API.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)
- [Performance Tuning Guide](./PERFORMANCE.md)
