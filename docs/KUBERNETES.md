# Kubernetes Deployment Guide

Comprehensive guide for deploying the SMTP server on Kubernetes with resource limits, network policies, and production best practices.

## Table of Contents

1. [Resource Requirements](#resource-requirements)
2. [Resource Limits](#resource-limits)
3. [Network Policies](#network-policies)
4. [Deployment Manifests](#deployment-manifests)
5. [ConfigMaps and Secrets](#configmaps-and-secrets)
6. [Service Configuration](#service-configuration)
7. [Horizontal Pod Autoscaling](#horizontal-pod-autoscaling)
8. [Pod Disruption Budgets](#pod-disruption-budgets)
9. [Health Checks](#health-checks)
10. [Monitoring](#monitoring)
11. [Security Best Practices](#security-best-practices)
12. [Troubleshooting](#troubleshooting)

---

## Resource Requirements

### Minimum Requirements (Development)

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|------------|-----------|----------------|--------------|
| Mail Server | 100m | 500m | 128Mi | 512Mi |
| Database (SQLite) | 50m | 200m | 64Mi | 256Mi |

### Recommended (Production - Small)

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|------------|-----------|----------------|--------------|
| Mail Server | 500m | 2000m | 512Mi | 2Gi |
| Database | 200m | 1000m | 256Mi | 1Gi |

### Recommended (Production - Large)

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|------------|-----------|----------------|--------------|
| Mail Server | 2000m | 4000m | 2Gi | 8Gi |
| Database | 1000m | 2000m | 1Gi | 4Gi |

### Resource Calculation Guidelines

```
CPU Request = (Expected connections per second) * 0.01 cores
Memory Request = (Max concurrent connections) * 64KB + 256MB base

Example: 1000 connections/sec, 10000 concurrent
- CPU: 1000 * 0.01 = 10 cores (request), 20 cores (limit)
- Memory: 10000 * 64KB + 256MB = 896MB (request), 1.8GB (limit)
```

---

## Resource Limits

### Deployment with Resource Limits

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mail
  namespace: mail
  labels:
    app: mail
    tier: backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mail
  template:
    metadata:
      labels:
        app: mail
        tier: backend
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: mail
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
      - name: mail
        image: mail:latest
        imagePullPolicy: Always
        ports:
        - name: smtp
          containerPort: 2525
          protocol: TCP
        - name: smtps
          containerPort: 4650
          protocol: TCP
        - name: submission
          containerPort: 5870
          protocol: TCP
        - name: http
          containerPort: 8080
          protocol: TCP
        resources:
          requests:
            cpu: "500m"
            memory: "512Mi"
            ephemeral-storage: "1Gi"
          limits:
            cpu: "2000m"
            memory: "2Gi"
            ephemeral-storage: "5Gi"
        env:
        - name: SMTP_PROFILE
          value: "production"
        - name: SMTP_PORT
          value: "2525"
        - name: SMTP_HOST
          value: "0.0.0.0"
        - name: SMTP_DB_PATH
          value: "/data/smtp.db"
        - name: SMTP_LOG_LEVEL
          value: "info"
        - name: SMTP_LOG_FORMAT
          value: "json"
        envFrom:
        - secretRef:
            name: smtp-secrets
        volumeMounts:
        - name: data
          mountPath: /data
        - name: config
          mountPath: /etc/mail
          readOnly: true
        - name: tls
          mountPath: /etc/tls
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health/live
            port: http
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        startupProbe:
          httpGet:
            path: /health/live
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 30
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: smtp-data
      - name: config
        configMap:
          name: smtp-config
      - name: tls
        secret:
          secretName: smtp-tls
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: mail
              topologyKey: kubernetes.io/hostname
      topologySpreadConstraints:
      - maxSkew: 1
        topologyKey: topology.kubernetes.io/zone
        whenUnsatisfiable: ScheduleAnyway
        labelSelector:
          matchLabels:
            app: mail
```

### LimitRange for Namespace

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: smtp-limits
  namespace: mail
spec:
  limits:
  - default:
      cpu: "1000m"
      memory: "1Gi"
    defaultRequest:
      cpu: "200m"
      memory: "256Mi"
    max:
      cpu: "4000m"
      memory: "8Gi"
    min:
      cpu: "50m"
      memory: "64Mi"
    type: Container
  - max:
      cpu: "8000m"
      memory: "16Gi"
    type: Pod
```

### ResourceQuota for Namespace

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: smtp-quota
  namespace: mail
spec:
  hard:
    requests.cpu: "10"
    requests.memory: "20Gi"
    limits.cpu: "20"
    limits.memory: "40Gi"
    persistentvolumeclaims: "10"
    pods: "20"
    services: "10"
    secrets: "20"
    configmaps: "10"
```

---

## Network Policies

### Default Deny All

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: mail
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### Allow SMTP Traffic

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-smtp-ingress
  namespace: mail
spec:
  podSelector:
    matchLabels:
      app: mail
  policyTypes:
  - Ingress
  ingress:
  # SMTP from external (via LoadBalancer/Ingress)
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 2525
    - protocol: TCP
      port: 4650
    - protocol: TCP
      port: 5870
  # Health checks from anywhere in cluster
  - from:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 8080
  # Inter-pod communication for clustering
  - from:
    - podSelector:
        matchLabels:
          app: mail
    ports:
    - protocol: TCP
      port: 7946  # Cluster gossip
    - protocol: UDP
      port: 7946
```

### Allow SMTP Egress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-smtp-egress
  namespace: mail
spec:
  podSelector:
    matchLabels:
      app: mail
  policyTypes:
  - Egress
  egress:
  # DNS resolution
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Outbound SMTP relay
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
    ports:
    - protocol: TCP
      port: 25
    - protocol: TCP
      port: 465
    - protocol: TCP
      port: 587
  # External services (SpamAssassin, ClamAV)
  - to:
    - podSelector:
        matchLabels:
          app: spamassassin
    - podSelector:
        matchLabels:
          app: clamav
    ports:
    - protocol: TCP
      port: 783   # SpamAssassin
    - protocol: TCP
      port: 3310  # ClamAV
  # Monitoring (Prometheus)
  - to:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9090
```

### Allow Database Access

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-database
  namespace: mail
spec:
  podSelector:
    matchLabels:
      app: mail
  policyTypes:
  - Egress
  egress:
  # PostgreSQL (if using external DB)
  - to:
    - podSelector:
        matchLabels:
          app: postgresql
    ports:
    - protocol: TCP
      port: 5432
  # Redis (if using for caching)
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
```

---

## ConfigMaps and Secrets

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: smtp-config
  namespace: mail
data:
  config.toml: |
    [server]
    hostname = "mail.example.com"
    banner = "ESMTP Server Ready"
    max_connections = 10000
    connection_timeout = 300

    [tls]
    enabled = true
    cert_file = "/etc/tls/tls.crt"
    key_file = "/etc/tls/tls.key"
    min_version = "1.2"

    [limits]
    max_message_size = 26214400
    max_recipients = 100
    max_line_length = 998

    [rate_limiting]
    enabled = true
    requests_per_minute = 100
    burst_size = 20

    [logging]
    level = "info"
    format = "json"

    [metrics]
    enabled = true
    port = 8080
    path = "/metrics"
```

### Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: smtp-secrets
  namespace: mail
type: Opaque
stringData:
  SMTP_ADMIN_PASSWORD: "your-secure-password"
  SMTP_DKIM_PRIVATE_KEY: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
  SMTP_DATABASE_URL: "postgresql://user:pass@db:5432/smtp"
---
apiVersion: v1
kind: Secret
metadata:
  name: smtp-tls
  namespace: mail
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
```

---

## Service Configuration

### ClusterIP Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: mail
  namespace: mail
  labels:
    app: mail
spec:
  type: ClusterIP
  ports:
  - name: smtp
    port: 25
    targetPort: 2525
    protocol: TCP
  - name: smtps
    port: 465
    targetPort: 4650
    protocol: TCP
  - name: submission
    port: 587
    targetPort: 5870
    protocol: TCP
  - name: http
    port: 8080
    targetPort: 8080
    protocol: TCP
  selector:
    app: mail
```

### LoadBalancer Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: mail-lb
  namespace: mail
  annotations:
    # AWS NLB
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled: "true"
    # GCP
    # cloud.google.com/load-balancer-type: "External"
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
  ports:
  - name: smtp
    port: 25
    targetPort: 2525
    protocol: TCP
  - name: smtps
    port: 465
    targetPort: 4650
    protocol: TCP
  - name: submission
    port: 587
    targetPort: 5870
    protocol: TCP
  selector:
    app: mail
```

---

## Horizontal Pod Autoscaling

### CPU-based HPA

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mail-hpa
  namespace: mail
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mail
  minReplicas: 3
  maxReplicas: 20
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
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

### Custom Metrics HPA

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mail-hpa-custom
  namespace: mail
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mail
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Pods
    pods:
      metric:
        name: smtp_active_connections
      target:
        type: AverageValue
        averageValue: "1000"
  - type: Pods
    pods:
      metric:
        name: smtp_queue_depth
      target:
        type: AverageValue
        averageValue: "500"
```

---

## Pod Disruption Budgets

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: mail-pdb
  namespace: mail
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: mail
---
# Alternative: maxUnavailable
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: mail-pdb-percent
  namespace: mail
spec:
  maxUnavailable: 33%
  selector:
    matchLabels:
      app: mail
```

---

## Health Checks

### Liveness Probe Details

The liveness probe checks if the SMTP server process is running and responsive:

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 10   # Wait for startup
  periodSeconds: 10         # Check every 10s
  timeoutSeconds: 5         # Timeout after 5s
  failureThreshold: 3       # Restart after 3 failures
  successThreshold: 1       # 1 success to be healthy
```

### Readiness Probe Details

The readiness probe checks if the server can accept new connections:

```yaml
readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
  successThreshold: 1
```

### Startup Probe Details

The startup probe allows for slow starts without affecting liveness:

```yaml
startupProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 30      # Allow up to 150s for startup
```

---

## Monitoring

### ServiceMonitor (Prometheus Operator)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mail
  namespace: mail
  labels:
    app: mail
spec:
  selector:
    matchLabels:
      app: mail
  endpoints:
  - port: http
    path: /metrics
    interval: 15s
    scrapeTimeout: 10s
  namespaceSelector:
    matchNames:
    - mail
```

### PrometheusRule for Alerts

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: mail-alerts
  namespace: mail
spec:
  groups:
  - name: mail
    rules:
    - alert: SMTPServerDown
      expr: up{job="mail"} == 0
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "SMTP server is down"
        description: "SMTP server {{ $labels.instance }} has been down for more than 5 minutes."

    - alert: SMTPHighErrorRate
      expr: rate(smtp_errors_total[5m]) > 10
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High SMTP error rate"
        description: "SMTP error rate is {{ $value }} errors/sec"

    - alert: SMTPQueueBacklog
      expr: smtp_queue_depth > 10000
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "SMTP queue backlog"
        description: "SMTP queue has {{ $value }} messages pending"

    - alert: SMTPHighMemory
      expr: container_memory_usage_bytes{container="mail"} / container_spec_memory_limit_bytes > 0.9
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High memory usage"
        description: "SMTP server memory usage is above 90%"
```

---

## Security Best Practices

### Security Checklist

- [ ] Run as non-root user (runAsNonRoot: true)
- [ ] Read-only root filesystem (readOnlyRootFilesystem: true)
- [ ] Drop all capabilities (capabilities.drop: ALL)
- [ ] No privilege escalation (allowPrivilegeEscalation: false)
- [ ] Use network policies to restrict traffic
- [ ] Store secrets in Kubernetes Secrets or external vault
- [ ] Enable TLS for all external connections
- [ ] Use service mesh for mTLS between pods
- [ ] Regularly scan images for vulnerabilities
- [ ] Enable audit logging
- [ ] Use PodSecurityPolicy or PodSecurity admission

### PodSecurity Standards

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: mail
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mail
  namespace: mail
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mail
  namespace: mail
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["smtp-secrets", "smtp-tls"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: mail
  namespace: mail
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: mail
subjects:
- kind: ServiceAccount
  name: mail
  namespace: mail
```

---

## Troubleshooting

### Common Issues

#### Pod Not Starting

```bash
# Check pod status
kubectl get pods -n mail -l app=mail

# Check pod events
kubectl describe pod -n mail <pod-name>

# Check logs
kubectl logs -n mail <pod-name> --previous
```

#### Network Connectivity Issues

```bash
# Test DNS resolution
kubectl run -it --rm debug --image=busybox -n mail -- nslookup mail

# Test SMTP connectivity
kubectl run -it --rm debug --image=busybox -n mail -- telnet mail 2525

# Check network policies
kubectl get networkpolicies -n mail
kubectl describe networkpolicy -n mail <policy-name>
```

#### Resource Issues

```bash
# Check resource usage
kubectl top pods -n mail

# Check resource quotas
kubectl describe resourcequota -n mail

# Check limit ranges
kubectl describe limitrange -n mail
```

#### TLS Issues

```bash
# Check certificate expiry
kubectl get secret smtp-tls -n mail -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -dates

# Verify TLS configuration
openssl s_client -connect mail.mail.svc:465 -servername mail.example.com
```

### Debug Container

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: smtp-debug
  namespace: mail
spec:
  containers:
  - name: debug
    image: nicolaka/netshoot
    command: ["sleep", "infinity"]
  restartPolicy: Never
```

```bash
# Access debug container
kubectl exec -it smtp-debug -n mail -- bash

# Test SMTP
telnet mail 2525

# Test DNS
dig mail.mail.svc.cluster.local

# Check network
traceroute mail
```

---

## Quick Start

```bash
# Create namespace
kubectl create namespace mail

# Apply configurations
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/network-policies.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/pdb.yaml

# Verify deployment
kubectl get all -n mail
kubectl rollout status deployment/mail -n mail

# Check logs
kubectl logs -f -l app=mail -n mail
```

---

*Last updated: 2025-11-26*
