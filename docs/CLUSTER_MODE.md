# Cluster Mode Guide

This guide explains how to configure and use cluster mode for high availability SMTP deployments.

## Overview

Cluster mode enables multiple SMTP server instances to work together, providing:

- **High Availability**: Automatic failover if a node goes down
- **Load Distribution**: Distribute connections across multiple nodes
- **Shared State**: Synchronized state across all nodes
- **Leader Election**: Automatic leader election for coordination
- **Health Monitoring**: Real-time health checks and status tracking

## Architecture

### Node Roles

#### Leader
- Coordinates cluster activities
- Manages shared state
- Handles leader election
- One leader per cluster

#### Follower
- Regular worker nodes
- Process SMTP connections
- Replicate state from leader
- Can become leader if needed

#### Candidate
- Temporary role during leader election
- Node attempting to become leader
- Transitions to leader or follower

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                        Cluster                               │
│                                                               │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐          │
│  │  Leader  │──────│ Follower │──────│ Follower │          │
│  │  Node 1  │      │  Node 2  │      │  Node 3  │          │
│  └──────────┘      └──────────┘      └──────────┘          │
│       │                  │                  │                │
│       └──────────────────┴──────────────────┘                │
│                 Shared State Store                           │
│         (Distributed Rate Limits, Metrics)                   │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

```bash
# Enable cluster mode
export SMTP_CLUSTER_ENABLED=true

# Node identification
export SMTP_CLUSTER_NODE_ID="node1"

# Cluster network
export SMTP_CLUSTER_BIND_ADDRESS="0.0.0.0"
export SMTP_CLUSTER_BIND_PORT=9000

# Peer nodes (comma-separated)
export SMTP_CLUSTER_PEERS="node2:9000,node3:9000"

# Timing configuration
export SMTP_CLUSTER_HEARTBEAT_INTERVAL=5000      # milliseconds
export SMTP_CLUSTER_HEARTBEAT_TIMEOUT=15000      # milliseconds
export SMTP_CLUSTER_ELECTION_TIMEOUT=10000       # milliseconds

# Optional: Auto-discovery
export SMTP_CLUSTER_AUTO_DISCOVERY=false
```

### Configuration File (config.toml)

```toml
[cluster]
enabled = true
node_id = "node1"
bind_address = "0.0.0.0"
bind_port = 9000

# Peer nodes
peers = [
  "192.168.1.101:9000",
  "192.168.1.102:9000",
  "192.168.1.103:9000"
]

# Timing
heartbeat_interval_ms = 5000
heartbeat_timeout_ms = 15000
leader_election_timeout_ms = 10000

# Features
enable_auto_discovery = false
```

## Deployment

### 3-Node Cluster Setup

#### Node 1 (192.168.1.101)

```bash
#!/bin/bash
export SMTP_CLUSTER_ENABLED=true
export SMTP_CLUSTER_NODE_ID="node1"
export SMTP_CLUSTER_BIND_ADDRESS="0.0.0.0"
export SMTP_CLUSTER_BIND_PORT=9000
export SMTP_CLUSTER_PEERS="192.168.1.102:9000,192.168.1.103:9000"

./zig-out/bin/mail --port 2525
```

#### Node 2 (192.168.1.102)

```bash
#!/bin/bash
export SMTP_CLUSTER_ENABLED=true
export SMTP_CLUSTER_NODE_ID="node2"
export SMTP_CLUSTER_BIND_ADDRESS="0.0.0.0"
export SMTP_CLUSTER_BIND_PORT=9000
export SMTP_CLUSTER_PEERS="192.168.1.101:9000,192.168.1.103:9000"

./zig-out/bin/mail --port 2525
```

#### Node 3 (192.168.1.103)

```bash
#!/bin/bash
export SMTP_CLUSTER_ENABLED=true
export SMTP_CLUSTER_NODE_ID="node3"
export SMTP_CLUSTER_BIND_ADDRESS="0.0.0.0"
export SMTP_CLUSTER_BIND_PORT=9000
export SMTP_CLUSTER_PEERS="192.168.1.101:9000,192.168.1.102:9000"

./zig-out/bin/mail --port 2525
```

### Docker Compose

```yaml
version: '3.8'

services:
  smtp-node1:
    image: mail:latest
    environment:
      - SMTP_CLUSTER_ENABLED=true
      - SMTP_CLUSTER_NODE_ID=node1
      - SMTP_CLUSTER_BIND_ADDRESS=0.0.0.0
      - SMTP_CLUSTER_BIND_PORT=9000
      - SMTP_CLUSTER_PEERS=smtp-node2:9000,smtp-node3:9000
    ports:
      - "2525:2525"
      - "9000:9000"
    networks:
      - smtp-cluster

  smtp-node2:
    image: mail:latest
    environment:
      - SMTP_CLUSTER_ENABLED=true
      - SMTP_CLUSTER_NODE_ID=node2
      - SMTP_CLUSTER_BIND_ADDRESS=0.0.0.0
      - SMTP_CLUSTER_BIND_PORT=9000
      - SMTP_CLUSTER_PEERS=smtp-node1:9000,smtp-node3:9000
    ports:
      - "2526:2525"
      - "9001:9000"
    networks:
      - smtp-cluster

  smtp-node3:
    image: mail:latest
    environment:
      - SMTP_CLUSTER_ENABLED=true
      - SMTP_CLUSTER_NODE_ID=node3
      - SMTP_CLUSTER_BIND_ADDRESS=0.0.0.0
      - SMTP_CLUSTER_BIND_PORT=9000
      - SMTP_CLUSTER_PEERS=smtp-node1:9000,smtp-node2:9000
    ports:
      - "2527:2525"
      - "9002:9000"
    networks:
      - smtp-cluster

networks:
  smtp-cluster:
    driver: bridge
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: smtp-cluster
spec:
  serviceName: smtp-cluster
  replicas: 3
  selector:
    matchLabels:
      app: mail
  template:
    metadata:
      labels:
        app: mail
    spec:
      containers:
      - name: mail
        image: mail:latest
        ports:
        - containerPort: 2525
          name: smtp
        - containerPort: 9000
          name: cluster
        env:
        - name: SMTP_CLUSTER_ENABLED
          value: "true"
        - name: SMTP_CLUSTER_NODE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: SMTP_CLUSTER_BIND_ADDRESS
          value: "0.0.0.0"
        - name: SMTP_CLUSTER_BIND_PORT
          value: "9000"
        - name: SMTP_CLUSTER_PEERS
          value: "smtp-cluster-0.smtp-cluster:9000,smtp-cluster-1.smtp-cluster:9000,smtp-cluster-2.smtp-cluster:9000"
---
apiVersion: v1
kind: Service
metadata:
  name: smtp-cluster
spec:
  clusterIP: None
  selector:
    app: mail
  ports:
  - port: 9000
    name: cluster
---
apiVersion: v1
kind: Service
metadata:
  name: smtp-service
spec:
  type: LoadBalancer
  selector:
    app: mail
  ports:
  - port: 2525
    targetPort: 2525
    name: smtp
```

## Usage in Code

### Initialize Cluster Manager

```zig
const cluster = @import("infrastructure/cluster.zig");

// Configure cluster
const config = cluster.ClusterConfig{
    .node_id = "node1",
    .bind_address = "0.0.0.0",
    .bind_port = 9000,
    .peers = &[_][]const u8{
        "192.168.1.102:9000",
        "192.168.1.103:9000",
    },
    .heartbeat_interval_ms = 5000,
    .heartbeat_timeout_ms = 15000,
    .leader_election_timeout_ms = 10000,
    .enable_auto_discovery = false,
};

// Initialize manager
const cluster_manager = try cluster.ClusterManager.init(allocator, config);
defer cluster_manager.deinit();

// Start cluster operations
try cluster_manager.start();
```

### Shared State Management

```zig
// Set shared state
try cluster_manager.state_store.set("rate_limit_192.168.1.100", "45");

// Get shared state
const value = try cluster_manager.state_store.get("rate_limit_192.168.1.100");

// Delete shared state
try cluster_manager.state_store.delete("rate_limit_192.168.1.100");
```

### Check Node Health

```zig
const stats = try cluster_manager.getClusterStats();

std.log.info("Cluster status:", .{});
std.log.info("  Total nodes: {}", .{stats.total_nodes});
std.log.info("  Healthy nodes: {}", .{stats.healthy_nodes});
std.log.info("  Leader: {s}", .{stats.leader_id});
```

### Leader Election

```zig
// Check if current node is leader
if (cluster_manager.local_node.role == .leader) {
    // Perform leader-only operations
    try performCoordination();
}

// Trigger election manually (for testing)
try cluster_manager.startLeaderElection();
```

## Network Protocol

### Message Format

```
┌─────────────┬─────────────┬──────────────────┐
│ Type (1B)   │ Length (4B) │ Body (variable)  │
└─────────────┴─────────────┴──────────────────┘
```

### Message Types

| Type | Value | Description |
|------|-------|-------------|
| Heartbeat | 1 | Node health status |
| State Update | 2 | Replicate state change |
| Election | 3 | Leader election request |
| Vote | 4 | Election vote response |
| Leader Announce | 5 | New leader announcement |

### Heartbeat Message

```json
{
  "node_id": "node1",
  "role": "leader",
  "timestamp": 1234567890,
  "metadata": {
    "version": "v0.26.0",
    "uptime_seconds": 3600,
    "active_connections": 42,
    "messages_processed": 1500,
    "cpu_usage": 45.2,
    "memory_usage_mb": 128
  }
}
```

### State Update Message

```json
{
  "key": "rate_limit_192.168.1.100",
  "value": "45",
  "timestamp": 1234567890
}
```

## Load Balancing

### HAProxy Configuration

```haproxy
global
    log /dev/log local0
    maxconn 4096

defaults
    log global
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend smtp_frontend
    bind *:2525
    default_backend smtp_backend

backend smtp_backend
    balance roundrobin
    option tcp-check
    tcp-check connect port 2525

    server node1 192.168.1.101:2525 check
    server node2 192.168.1.102:2525 check
    server node3 192.168.1.103:2525 check
```

### nginx TCP Load Balancing

```nginx
stream {
    upstream smtp_cluster {
        least_conn;
        server 192.168.1.101:2525 max_fails=3 fail_timeout=30s;
        server 192.168.1.102:2525 max_fails=3 fail_timeout=30s;
        server 192.168.1.103:2525 max_fails=3 fail_timeout=30s;
    }

    server {
        listen 2525;
        proxy_pass smtp_cluster;
        proxy_timeout 300s;
        proxy_connect_timeout 5s;
    }
}
```

## Monitoring

### Cluster Health Check

```bash
# Check cluster status via API
curl http://localhost:8080/api/cluster/status

# Expected response:
{
  "total_nodes": 3,
  "healthy_nodes": 3,
  "unhealthy_nodes": 0,
  "leader_id": "node1",
  "local_node": {
    "id": "node1",
    "role": "leader",
    "status": "healthy",
    "uptime_seconds": 3600
  }
}
```

### Node Metrics

```bash
# Get node metrics
curl http://localhost:8080/api/cluster/nodes/node1

# Response:
{
  "id": "node1",
  "address": "192.168.1.101",
  "port": 9000,
  "role": "leader",
  "status": "healthy",
  "last_heartbeat": 1234567890,
  "metadata": {
    "version": "v0.26.0",
    "uptime_seconds": 3600,
    "active_connections": 42,
    "messages_processed": 1500,
    "cpu_usage": 45.2,
    "memory_usage_mb": 128
  }
}
```

### Prometheus Metrics

```prometheus
# HELP smtp_cluster_nodes_total Total number of nodes in cluster
# TYPE smtp_cluster_nodes_total gauge
smtp_cluster_nodes_total 3

# HELP smtp_cluster_healthy_nodes Number of healthy nodes
# TYPE smtp_cluster_healthy_nodes gauge
smtp_cluster_healthy_nodes 3

# HELP smtp_cluster_leader_elections_total Total leader elections
# TYPE smtp_cluster_leader_elections_total counter
smtp_cluster_leader_elections_total 2

# HELP smtp_cluster_state_replications_total State replication operations
# TYPE smtp_cluster_state_replications_total counter
smtp_cluster_state_replications_total 1523
```

## Failure Scenarios

### Node Failure

**Scenario**: One node crashes or becomes unreachable

**Behavior**:
1. Other nodes detect missing heartbeats
2. Node marked as `disconnected` after timeout
3. Connections redistributed to healthy nodes
4. If leader fails, new election triggered

**Recovery**:
```bash
# Restart failed node
./zig-out/bin/mail --port 2525

# Node automatically rejoins cluster
# Syncs state from leader
# Begins processing connections
```

### Network Partition

**Scenario**: Network split isolates some nodes

**Behavior**:
1. Each partition may elect its own leader (split-brain)
2. Connections handled by available nodes
3. State may diverge between partitions

**Recovery**:
```bash
# Once network heals:
# - Nodes detect each other
# - New leader election
# - State reconciliation
# - Normal operation resumes
```

### Leader Failure

**Scenario**: Leader node crashes

**Behavior**:
1. Followers detect missing leader heartbeats
2. Election timeout triggers
3. Candidates propose themselves
4. Voting occurs among followers
5. New leader elected
6. Leader announces itself
7. Normal operation resumes

**Timeline**:
```
T+0s:  Leader crashes
T+15s: Heartbeat timeout detected
T+16s: Election initiated
T+17s: Voting completes
T+18s: New leader elected and announced
T+19s: Cluster operational
```

## Troubleshooting

### Issue: Split-Brain

**Symptoms**: Multiple leaders in cluster

**Diagnosis**:
```bash
# Check cluster status on each node
curl http://node1:8080/api/cluster/status
curl http://node2:8080/api/cluster/status
curl http://node3:8080/api/cluster/status

# If leader_id differs, split-brain detected
```

**Solution**:
```bash
# Restart minority partition nodes
# They will rejoin majority partition
```

### Issue: High Election Frequency

**Symptoms**: Frequent leader elections

**Causes**:
- Network instability
- Heartbeat timeout too low
- Node resource exhaustion

**Solution**:
```bash
# Increase timeouts
export SMTP_CLUSTER_HEARTBEAT_TIMEOUT=30000
export SMTP_CLUSTER_ELECTION_TIMEOUT=20000

# Check node health
htop
netstat -an | grep 9000
```

### Issue: State Replication Lag

**Symptoms**: Inconsistent state across nodes

**Diagnosis**:
```bash
# Check replication metrics
curl http://localhost:8080/api/cluster/replication/stats

# Expected:
{
  "pending_updates": 0,
  "failed_replications": 0,
  "avg_latency_ms": 5
}
```

**Solution**:
```bash
# Check network latency between nodes
ping node2
ping node3

# Increase replication buffer if needed
export SMTP_CLUSTER_REPLICATION_BUFFER_SIZE=10000
```

## Best Practices

### 1. Odd Number of Nodes

Always use an odd number of nodes (3, 5, 7) to prevent split-brain situations during elections.

### 2. Geographic Distribution

```
Region A         Region B         Region C
┌────────┐      ┌────────┐      ┌────────┐
│ Node 1 │      │ Node 2 │      │ Node 3 │
└────────┘      └────────┘      └────────┘
```

Distribute nodes across availability zones or data centers for better resilience.

### 3. Monitoring

- Monitor heartbeat status
- Track leader election frequency
- Watch state replication lag
- Alert on node failures

### 4. Capacity Planning

- Each node should handle full load during failures
- Plan for N-1 capacity (handle loss of any single node)
- Monitor resource usage per node

### 5. Network Requirements

- Low latency between nodes (<50ms)
- Stable connections (avoid packet loss)
- Dedicated cluster network if possible

## Performance Considerations

### Heartbeat Overhead

- Default: 5s interval = 0.2 msgs/sec per node
- 3-node cluster = 0.6 msgs/sec total
- Minimal CPU/network impact

### State Replication

- Async replication to minimize latency
- Batching for efficiency
- Configurable batch size and interval

### Election Performance

- Election completes in <3 seconds typically
- No downtime during election
- Followers continue processing

## Security

### Cluster Authentication

```bash
# Enable cluster authentication
export SMTP_CLUSTER_AUTH_ENABLED=true
export SMTP_CLUSTER_AUTH_TOKEN="your-secret-token"
```

### TLS for Cluster Communication

```bash
# Enable TLS for cluster traffic
export SMTP_CLUSTER_TLS_ENABLED=true
export SMTP_CLUSTER_TLS_CERT=/path/to/cluster-cert.pem
export SMTP_CLUSTER_TLS_KEY=/path/to/cluster-key.pem
```

### Firewall Rules

```bash
# Allow cluster traffic (port 9000) only from cluster nodes
sudo ufw allow from 192.168.1.101 to any port 9000
sudo ufw allow from 192.168.1.102 to any port 9000
sudo ufw allow from 192.168.1.103 to any port 9000
```

## Related Documentation

- [Multi-Tenancy](MULTI_TENANCY.md) - Tenant isolation and management
- [Load Balancing](LOAD_BALANCING.md) - Load balancer configuration
- [Monitoring](MONITORING.md) - Cluster monitoring and metrics
