# Performance Tuning Guide

Comprehensive guide for optimizing SMTP server performance across various workloads and deployment scenarios.

## Table of Contents

1. [Performance Metrics](#performance-metrics)
2. [Baseline Performance](#baseline-performance)
3. [System-Level Tuning](#system-level-tuning)
4. [Application-Level Tuning](#application-level-tuning)
5. [Database Optimization](#database-optimization)
6. [Storage Optimization](#storage-optimization)
7. [Network Tuning](#network-tuning)
8. [Memory Optimization](#memory-optimization)
9. [CPU Optimization](#cpu-optimization)
10. [I/O Optimization](#io-optimization)
11. [Caching Strategies](#caching-strategies)
12. [Load Balancing](#load-balancing)
13. [Monitoring and Profiling](#monitoring-and-profiling)
14. [Benchmarking](#benchmarking)
15. [Workload-Specific Tuning](#workload-specific-tuning)

---

## Performance Metrics

### Key Performance Indicators (KPIs)

**Throughput Metrics:**
- Messages per second (MPS)
- Concurrent connections
- Data transfer rate (MB/s)
- Queue processing rate

**Latency Metrics:**
- P50 (median) latency
- P95 latency
- P99 latency
- Max latency

**Resource Utilization:**
- CPU usage (%)
- Memory usage (MB/GB)
- Disk I/O (IOPS, MB/s)
- Network bandwidth (Mbps)

**Availability Metrics:**
- Uptime (%)
- Error rate (%)
- Queue depth
- Connection rejection rate

### Monitoring Commands

```bash
# Real-time metrics
curl http://localhost:9090/metrics

# Connection statistics
curl http://localhost:8080/stats | jq

# System resources
top -b -n 1 | grep mail
ps aux | grep mail | awk '{print "CPU: "$3"% MEM: "$4"%"}'

# Network connections
ss -s
ss -tan | grep :25 | wc -l

# Disk I/O
iostat -x 1 5

# Queue status
ls /var/lib/smtp/queue/ | wc -l
```

---

## Baseline Performance

### Expected Performance Targets

**Small Deployment (< 1000 users):**
- Throughput: 100-500 MPS
- Concurrent connections: 50-200
- P95 latency: < 100ms
- CPU: < 25%
- Memory: < 500MB

**Medium Deployment (1000-10000 users):**
- Throughput: 500-2000 MPS
- Concurrent connections: 200-1000
- P95 latency: < 150ms
- CPU: 25-50%
- Memory: 500MB-2GB

**Large Deployment (> 10000 users):**
- Throughput: 2000-10000 MPS
- Concurrent connections: 1000-5000
- P95 latency: < 200ms
- CPU: 50-75%
- Memory: 2-8GB

### Hardware Requirements by Workload

**Light Load (< 100 MPS):**
- CPU: 2 cores @ 2.5 GHz
- RAM: 2GB
- Storage: 50GB SSD
- Network: 100 Mbps

**Medium Load (100-1000 MPS):**
- CPU: 4 cores @ 3.0 GHz
- RAM: 8GB
- Storage: 200GB NVMe SSD
- Network: 1 Gbps

**Heavy Load (1000+ MPS):**
- CPU: 8+ cores @ 3.5 GHz
- RAM: 16GB+
- Storage: 500GB+ NVMe SSD (RAID 10)
- Network: 10 Gbps

---

## System-Level Tuning

### Kernel Parameters

Create `/etc/sysctl.d/99-smtp-performance.conf`:

```conf
# File System
fs.file-max = 200000
fs.nr_open = 200000

# Memory Management
vm.swappiness = 10
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1

# Network Core
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 40960

# TCP Performance
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# TCP Congestion Control
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Connection Tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15

# IPv6 (if used)
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
```

Apply settings:

```bash
sudo sysctl -p /etc/sysctl.d/99-smtp-performance.conf

# Verify
sudo sysctl -a | grep -E "file-max|somaxconn|tcp_rmem"
```

### System Limits

Edit `/etc/security/limits.conf`:

```conf
# User limits for smtp
smtp soft nofile 65536
smtp hard nofile 65536
smtp soft nproc 32768
smtp hard nproc 32768
smtp soft memlock unlimited
smtp hard memlock unlimited

# Root limits
root soft nofile 65536
root hard nofile 65536
```

### Systemd Service Limits

Create `/etc/systemd/system/mail.service.d/limits.conf`:

```ini
[Service]
# File descriptors
LimitNOFILE=65536

# Processes
LimitNPROC=32768

# Memory
MemoryHigh=8G
MemoryMax=12G
MemorySwapMax=0

# CPU
CPUQuota=400%
CPUAffinity=0-7

# I/O
IOWeight=1000
BlockIOWeight=1000
```

Apply:

```bash
sudo systemctl daemon-reload
sudo systemctl restart mail
```

### Huge Pages

Enable for better memory performance with large deployments:

```bash
# Calculate required huge pages (for 8GB allocation)
# Huge page size: 2MB
# Required: 8GB / 2MB = 4096 pages

# Enable huge pages
sudo tee -a /etc/sysctl.d/99-hugepages.conf << 'EOF'
vm.nr_hugepages = 4096
vm.hugetlb_shm_group = 1000  # smtp group ID
EOF

sudo sysctl -p /etc/sysctl.d/99-hugepages.conf

# Verify
cat /proc/meminfo | grep Huge
```

---

## Application-Level Tuning

### Connection Management

Edit `/etc/smtp/smtp.env`:

```bash
# Maximum concurrent connections
MAX_CONNECTIONS=5000

# Connection timeout (seconds)
CONNECTION_TIMEOUT=300

# Idle timeout for inactive connections
IDLE_TIMEOUT=120

# Enable TCP_NODELAY (disable Nagle's algorithm)
TCP_NODELAY=true

# Enable TCP keepalive
TCP_KEEPALIVE=true
TCP_KEEPALIVE_IDLE=60
TCP_KEEPALIVE_INTERVAL=10
TCP_KEEPALIVE_COUNT=5

# Connection backlog
LISTEN_BACKLOG=1024
```

### Worker Thread Configuration

```bash
# Number of worker threads (match CPU cores)
WORKER_THREADS=8

# Queue worker threads (dedicated for queue processing)
QUEUE_WORKER_THREADS=4

# I/O threads (for async operations)
IO_THREADS=4

# Thread stack size (KB)
THREAD_STACK_SIZE=8192
```

### Message Processing

```bash
# Maximum message size (bytes)
SMTP_MAX_MESSAGE_SIZE=52428800  # 50MB

# Maximum recipients per message
SMTP_MAX_RECIPIENTS=100

# Pipeline depth (for PIPELINING extension)
PIPELINE_MAX_COMMANDS=50

# Chunk size for BDAT (bytes)
BDAT_CHUNK_SIZE=65536  # 64KB
```

### Rate Limiting

```bash
# Enable rate limiting
RATE_LIMIT_ENABLED=true

# Messages per minute per IP
RATE_LIMIT_PER_MINUTE=120

# Burst allowance
RATE_LIMIT_BURST=20

# Rate limit cleanup interval (seconds)
RATE_LIMIT_CLEANUP_INTERVAL=300

# Whitelist trusted IPs
RATE_LIMIT_WHITELIST=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

### Queue Configuration

```bash
# Enable queue processing
QUEUE_ENABLED=true

# Queue batch size (messages processed per iteration)
QUEUE_BATCH_SIZE=100

# Queue processing interval (milliseconds)
QUEUE_INTERVAL=1000

# Maximum retry attempts
QUEUE_MAX_RETRIES=5

# Retry backoff multiplier
QUEUE_RETRY_BACKOFF=2

# Initial retry delay (seconds)
QUEUE_INITIAL_RETRY_DELAY=60

# Maximum delivery time (seconds)
QUEUE_MAX_AGE=86400  # 24 hours
```

---

## Database Optimization

### SQLite Tuning

Run these pragmas on database initialization:

```sql
-- Write-Ahead Logging for better concurrency
PRAGMA journal_mode = WAL;

-- Normal synchronous mode (balance of safety and speed)
PRAGMA synchronous = NORMAL;

-- Large page cache (64MB)
PRAGMA cache_size = -64000;

-- Store temp tables in memory
PRAGMA temp_store = MEMORY;

-- Memory-mapped I/O (30GB)
PRAGMA mmap_size = 30000000000;

-- Increase page size for better performance
PRAGMA page_size = 8192;

-- Optimize after modifications
PRAGMA optimize;

-- Auto-vacuum
PRAGMA auto_vacuum = INCREMENTAL;
```

Apply settings:

```bash
sudo -u smtp sqlite3 /var/lib/smtp/smtp.db << 'EOF'
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -64000;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 30000000000;
PRAGMA page_size = 8192;
PRAGMA auto_vacuum = INCREMENTAL;
VACUUM;
ANALYZE;
EOF
```

### Database Indexes

Ensure proper indexes exist:

```sql
-- Users table
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active) WHERE is_active = 1;

-- Messages table
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status);
CREATE INDEX IF NOT EXISTS idx_messages_composite ON messages(status, received_at DESC);

-- Audit log
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- Queue (if database-backed)
CREATE INDEX IF NOT EXISTS idx_queue_status ON queue(status, next_retry);
CREATE INDEX IF NOT EXISTS idx_queue_priority ON queue(priority DESC, created_at ASC);
```

### PostgreSQL Tuning

Edit `/etc/postgresql/16/main/postgresql.conf`:

```conf
# Memory Settings
shared_buffers = 4GB                    # 25% of RAM
effective_cache_size = 12GB             # 75% of RAM
maintenance_work_mem = 1GB
work_mem = 32MB                         # For complex queries

# Connections
max_connections = 200
max_prepared_transactions = 0

# WAL Settings
wal_level = replica
wal_buffers = 16MB
min_wal_size = 2GB
max_wal_size = 8GB
checkpoint_completion_target = 0.9

# Query Planning
random_page_cost = 1.1                  # For SSD
effective_io_concurrency = 200          # For SSD
default_statistics_target = 100

# Background Writer
bgwriter_delay = 200ms
bgwriter_lru_maxpages = 100
bgwriter_lru_multiplier = 2.0

# Autovacuum
autovacuum = on
autovacuum_max_workers = 4
autovacuum_naptime = 30s
```

Apply:

```bash
sudo systemctl restart postgresql
```

### Connection Pooling (PgBouncer)

Install and configure PgBouncer for connection pooling:

```ini
# /etc/pgbouncer/pgbouncer.ini
[databases]
smtp = host=localhost port=5432 dbname=smtp pool_size=25

[pgbouncer]
listen_port = 6432
listen_addr = 127.0.0.1
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt

# Pool mode
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25
min_pool_size = 5
reserve_pool_size = 5
reserve_pool_timeout = 3

# Connection limits
max_db_connections = 200
max_user_connections = 200

# Timeouts
server_idle_timeout = 600
server_connect_timeout = 15
server_login_retry = 15

# Performance
server_check_delay = 30
server_check_query = SELECT 1

# Logging
log_connections = 0
log_disconnections = 0
log_pooler_errors = 1
```

Update application configuration:

```bash
DB_HOST=localhost
DB_PORT=6432  # PgBouncer port instead of 5432
```

---

## Storage Optimization

### Storage Backend Selection

**Maildir:**
- Best for: Small to medium deployments
- Pros: Simple, reliable, atomic operations
- Cons: Many small files, inode intensive
- Tuning: Use filesystem with good small file performance (XFS, ext4)

**Database (SQLite/PostgreSQL):**
- Best for: All deployments with search requirements
- Pros: Transactional, searchable, efficient
- Cons: Requires tuning, potential bottleneck
- Tuning: See database optimization section

**Time-Series:**
- Best for: High-volume archival
- Pros: Organized by date, easy backup
- Cons: Slower access to old messages
- Tuning: Use fast storage, enable compression

**S3:**
- Best for: Large-scale, cost-effective archival
- Pros: Unlimited scale, cheap storage
- Cons: Higher latency, API costs
- Tuning: Use lifecycle policies, enable caching

### Filesystem Tuning

**XFS (Recommended for large deployments):**

```bash
# Mount options
# /etc/fstab
/dev/sda1 /var/lib/smtp xfs noatime,nodiratime,logbufs=8,logbsize=256k,largeio,swalloc 0 0

# Format options
sudo mkfs.xfs -f -d agcount=32 -l size=256m /dev/sda1
```

**ext4:**

```bash
# Mount options
# /etc/fstab
/dev/sda1 /var/lib/smtp ext4 noatime,nodiratime,data=writeback,barrier=0,commit=60 0 0

# Format options
sudo mkfs.ext4 -E stride=128,stripe-width=128 /dev/sda1
```

**ZFS (Advanced):**

```bash
# Create ZFS pool with optimization
sudo zpool create -o ashift=12 smtp-pool /dev/sda /dev/sdb

# Create dataset with tuning
sudo zfs create -o compression=lz4 \
                -o atime=off \
                -o recordsize=128K \
                -o primarycache=all \
                -o secondarycache=all \
                smtp-pool/smtp-data

# Mount point
sudo zfs set mountpoint=/var/lib/smtp smtp-pool/smtp-data
```

### I/O Scheduler

```bash
# For SSD/NVMe - use 'none' or 'mq-deadline'
echo none | sudo tee /sys/block/sda/queue/scheduler

# For HDD - use 'mq-deadline' or 'bfq'
echo mq-deadline | sudo tee /sys/block/sda/queue/scheduler

# Make persistent
# /etc/udev/rules.d/60-ioschedulers.rules
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="none"
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="mq-deadline"
```

### RAID Configuration

**RAID 10 (Recommended for performance + redundancy):**

```bash
# Create RAID 10 with 4 disks
sudo mdadm --create /dev/md0 --level=10 --raid-devices=4 /dev/sd[abcd]1

# Optimize chunk size for workload (512KB for databases)
sudo mdadm --create /dev/md0 --level=10 --chunk=512 --raid-devices=4 /dev/sd[abcd]1

# Monitor RAID performance
sudo cat /proc/mdstat
```

**RAID 0 (Maximum performance, no redundancy):**

```bash
# Create RAID 0 with 2 disks
sudo mdadm --create /dev/md0 --level=0 --raid-devices=2 /dev/sd[ab]1

# Stripe size optimization
sudo mdadm --create /dev/md0 --level=0 --chunk=256 --raid-devices=2 /dev/sd[ab]1
```

---

## Network Tuning

### Network Interface Configuration

```bash
# Increase ring buffer sizes
sudo ethtool -G eth0 rx 4096 tx 4096

# Enable hardware offloading
sudo ethtool -K eth0 tso on
sudo ethtool -K eth0 gso on
sudo ethtool -K eth0 gro on
sudo ethtool -K eth0 lro on

# Make persistent with netplan (Ubuntu)
# /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    eth0:
      receive-offload:
        generic: true
        tcp-segmentation: true
        large: true
      transmit-offload:
        generic: true
        tcp-segmentation: true
```

### TCP Tuning

Already covered in System-Level Tuning, but key highlights:

```bash
# Enable BBR congestion control (Linux 4.9+)
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo sysctl -w net.core.default_qdisc=fq

# Verify
sudo sysctl net.ipv4.tcp_congestion_control
```

### Network Buffer Tuning

```bash
# Application level (in smtp.env)
SOCKET_RECV_BUFFER=262144  # 256KB
SOCKET_SEND_BUFFER=262144  # 256KB

# System level (already in sysctl settings)
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
```

---

## Memory Optimization

### Application Memory Configuration

```bash
# Memory pool settings
MEMORY_POOL_ENABLED=true
MEMORY_POOL_BLOCK_SIZE=4096  # 4KB blocks
MEMORY_POOL_INITIAL_BLOCKS=1000
MEMORY_POOL_MAX_BLOCKS=10000

# Buffer pool settings
BUFFER_POOL_ENABLED=true
BUFFER_POOL_SIZES=1024,8192,65536  # 1KB, 8KB, 64KB buffers
BUFFER_POOL_COUNT=1000  # Per size

# Arena allocator
ARENA_ENABLED=true
ARENA_SIZE=1048576  # 1MB per arena
ARENA_MAX_ARENAS=100
```

### Cache Configuration

```bash
# Enable caching
CACHE_ENABLED=true
CACHE_SIZE=1073741824  # 1GB

# Cache TTL (seconds)
CACHE_TTL=300  # 5 minutes

# Cache eviction policy
CACHE_EVICTION=lru  # LRU, LFU, or FIFO

# Specific caches
USER_CACHE_SIZE=10000  # Number of user records
DNS_CACHE_SIZE=50000  # DNS lookup cache
QUOTA_CACHE_SIZE=10000  # Quota cache
```

### Memory Limits

```bash
# Application level (via systemd)
MemoryHigh=8G
MemoryMax=12G

# Disable swap for SMTP process
MemorySwapMax=0

# OOM score (higher = killed first, lower = killed last)
# -1000 to 1000, default 0
OOMScoreAdjust=-500  # Protect from OOM killer
```

### Huge Pages Usage

If enabled at system level, configure application:

```bash
# Enable huge pages in application
USE_HUGE_PAGES=true
HUGE_PAGE_SIZE=2097152  # 2MB
```

---

## CPU Optimization

### CPU Affinity

Pin SMTP server to specific CPU cores:

```bash
# Via systemd
sudo systemctl edit mail
# Add:
[Service]
CPUAffinity=0-7  # Use cores 0-7

# Or via taskset
sudo taskset -cp 0-7 $(pgrep mail)
```

### CPU Governor

```bash
# Set to performance mode for dedicated servers
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Or use on-demand for shared environments
echo ondemand | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Make persistent
sudo apt-get install -y cpufrequtils
echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils
sudo systemctl restart cpufrequtils
```

### NUMA Optimization

For multi-socket systems:

```bash
# Check NUMA configuration
numactl --hardware

# Run SMTP server on specific NUMA node
numactl --cpunodebind=0 --membind=0 /usr/local/bin/mail

# Or via systemd
sudo systemctl edit mail
# Add:
[Service]
ExecStart=
ExecStart=/usr/bin/numactl --cpunodebind=0 --membind=0 /usr/local/bin/mail
```

### Process Priority

```bash
# Set nice value (lower = higher priority)
sudo renice -n -10 -p $(pgrep mail)

# Or via systemd
sudo systemctl edit mail
# Add:
[Service]
Nice=-10

# Set I/O priority
sudo ionice -c 1 -n 0 -p $(pgrep mail)

# Or via systemd
[Service]
IOSchedulingClass=realtime
IOSchedulingPriority=0
```

---

## I/O Optimization

### Async I/O

Enable io_uring (Linux 5.1+):

```bash
# Application configuration
ASYNC_IO_ENABLED=true
ASYNC_IO_TYPE=io_uring
IO_URING_QUEUE_DEPTH=256
IO_URING_BATCH_SUBMIT=32
IO_URING_BATCH_COMPLETE=32
```

### Direct I/O

For database files (bypass page cache):

```bash
# SQLite
PRAGMA temp_store_directory = '/var/lib/smtp/tmp';
# Use O_DIRECT flag for writes (code modification required)

# PostgreSQL
# Already uses direct I/O for WAL
```

### Read-ahead Tuning

```bash
# Increase read-ahead for sequential workloads
sudo blockdev --setra 8192 /dev/sda  # 4MB read-ahead

# Decrease for random I/O workloads
sudo blockdev --setra 256 /dev/sda  # 128KB read-ahead

# Make persistent
echo 'ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{bdi/read_ahead_kb}="4096"' | \
  sudo tee /etc/udev/rules.d/60-read-ahead.rules
```

### I/O Queue Depth

```bash
# Increase queue depth for NVMe
echo 1024 | sudo tee /sys/block/nvme0n1/queue/nr_requests

# For SATA SSD
echo 512 | sudo tee /sys/block/sda/queue/nr_requests
```

---

## Caching Strategies

### Application-Level Caching

**User Cache:**
```bash
# Cache authenticated users
USER_CACHE_ENABLED=true
USER_CACHE_SIZE=10000
USER_CACHE_TTL=300  # 5 minutes
```

**DNS Cache:**
```bash
# Cache DNS lookups
DNS_CACHE_ENABLED=true
DNS_CACHE_SIZE=50000
DNS_CACHE_TTL=3600  # 1 hour
DNS_CACHE_NEGATIVE_TTL=300  # 5 minutes for NXDOMAIN
```

**SPF/DKIM Cache:**
```bash
# Cache SPF records
SPF_CACHE_ENABLED=true
SPF_CACHE_SIZE=10000
SPF_CACHE_TTL=3600

# Cache DKIM public keys
DKIM_CACHE_ENABLED=true
DKIM_CACHE_SIZE=10000
DKIM_CACHE_TTL=3600
```

### System-Level Caching

**Page Cache:**
```bash
# Tune page cache behavior
vm.vfs_cache_pressure = 50  # Keep inode cache longer
vm.dirty_ratio = 10  # Start writing at 10% dirty
vm.dirty_background_ratio = 5  # Background write at 5%
vm.dirty_expire_centisecs = 3000  # 30 seconds
vm.dirty_writeback_centisecs = 500  # 5 seconds
```

**Redis Cache (External):**

```bash
# Install Redis
sudo apt-get install -y redis-server

# Configure Redis (/etc/redis/redis.conf)
maxmemory 2gb
maxmemory-policy allkeys-lru
save ""  # Disable persistence for pure cache
appendonly no

# Application configuration
CACHE_BACKEND=redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_POOL_SIZE=20
```

---

## Load Balancing

### HAProxy Configuration

Optimized HAProxy for SMTP:

```
global
    maxconn 50000
    tune.ssl.default-dh-param 2048
    tune.bufsize 32768
    tune.maxrewrite 8192

defaults
    mode tcp
    option tcplog
    timeout connect 10s
    timeout client 5m
    timeout server 5m
    timeout tunnel 1h
    maxconn 50000

frontend smtp_front
    bind *:25
    default_backend smtp_servers

    # Connection rate limiting
    stick-table type ip size 100k expire 30s store conn_cur,conn_rate(10s)
    tcp-request connection track-sc0 src
    tcp-request connection reject if { sc_conn_rate(0) gt 100 }

frontend submission_front
    bind *:587
    default_backend smtp_servers

backend smtp_servers
    balance leastconn
    option tcp-check

    # Health check
    tcp-check connect
    tcp-check expect string "220"
    tcp-check send "QUIT\r\n"
    tcp-check expect string "221"

    # Servers
    server smtp1 10.0.1.10:25 check inter 10s rise 2 fall 3 maxconn 5000
    server smtp2 10.0.1.11:25 check inter 10s rise 2 fall 3 maxconn 5000
    server smtp3 10.0.1.12:25 check inter 10s rise 2 fall 3 maxconn 5000
```

### Nginx Stream Proxy

```nginx
stream {
    upstream smtp_backend {
        least_conn;
        server 10.0.1.10:25 max_conns=5000;
        server 10.0.1.11:25 max_conns=5000;
        server 10.0.1.12:25 max_conns=5000;
    }

    server {
        listen 25;
        proxy_pass smtp_backend;
        proxy_connect_timeout 10s;
        proxy_timeout 5m;
        proxy_buffer_size 16k;
    }

    server {
        listen 587;
        proxy_pass smtp_backend;
        proxy_connect_timeout 10s;
        proxy_timeout 5m;
        proxy_buffer_size 16k;
    }
}
```

### DNS Round-Robin

```bash
# Configure multiple A records
mail.example.com.  300  IN  A  203.0.113.10
mail.example.com.  300  IN  A  203.0.113.11
mail.example.com.  300  IN  A  203.0.113.12

# Or use SRV records
_smtp._tcp.example.com. 300 IN SRV 10 50 25 smtp1.example.com.
_smtp._tcp.example.com. 300 IN SRV 10 50 25 smtp2.example.com.
```

---

## Monitoring and Profiling

### Continuous Monitoring

**Prometheus Queries:**

```promql
# Throughput
rate(smtp_messages_received_total[5m])
rate(smtp_messages_sent_total[5m])

# Latency
histogram_quantile(0.95, rate(smtp_processing_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(smtp_processing_duration_seconds_bucket[5m]))

# Errors
rate(smtp_errors_total[5m])

# Queue depth
smtp_queue_size

# Resource usage
process_resident_memory_bytes
rate(process_cpu_seconds_total[5m])
```

**Grafana Dashboards:**

Import or create dashboard with panels for:
- Message throughput (line graph)
- Latency percentiles (heatmap)
- Active connections (gauge)
- Queue size (line graph)
- Error rate (single stat)
- CPU/Memory usage (line graphs)

### CPU Profiling

**perf (Linux):**

```bash
# Profile for 60 seconds
sudo perf record -F 99 -p $(pgrep mail) -g -- sleep 60

# Generate report
sudo perf report

# Generate flame graph
sudo perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > smtp-cpu.svg
```

**Valgrind/Callgrind:**

```bash
# Profile with callgrind
valgrind --tool=callgrind \
  --callgrind-out-file=callgrind.out \
  /usr/local/bin/mail

# Visualize with kcachegrind
kcachegrind callgrind.out
```

### Memory Profiling

**Valgrind/Massif:**

```bash
# Profile memory usage
valgrind --tool=massif \
  --massif-out-file=massif.out \
  /usr/local/bin/mail

# Visualize
ms_print massif.out
```

**Heaptrack:**

```bash
# Profile heap allocations
heaptrack /usr/local/bin/mail

# Analyze
heaptrack_gui heaptrack.mail.*.gz
```

### I/O Profiling

**iostat:**

```bash
# Monitor I/O every 5 seconds
iostat -xz 5

# Key metrics:
# - %util: Device utilization (should be < 80%)
# - await: Average I/O wait time
# - r/s, w/s: Read/write operations per second
```

**iotop:**

```bash
# Monitor I/O by process
sudo iotop -o -p $(pgrep mail)
```

**blktrace:**

```bash
# Trace block I/O
sudo blktrace -d /dev/sda -o trace
sudo blkparse trace > trace.txt
```

---

## Benchmarking

### Internal Benchmarks

Run built-in benchmark suite:

```bash
# Build with benchmark
zig build -Doptimize=ReleaseFast

# Run benchmarks
./zig-out/bin/mail --benchmark

# Specific benchmarks
./zig-out/bin/mail --benchmark=email_validation
./zig-out/bin/mail --benchmark=base64_encoding
./zig-out/bin/mail --benchmark=smtp_parsing
```

### Load Testing

**SMTP Load Test Tool:**

```bash
# Install smtp-source (from Postfix)
sudo apt-get install -y postfix-utils

# Send 10000 messages with 100 concurrent connections
smtp-source -c 100 -m 10000 -f sender@example.com -t recipient@example.com -S "Subject: Test" -l 1024 -s 10 localhost:25
```

**Custom Load Test Script:**

```python
#!/usr/bin/env python3
import smtplib
import threading
import time
from datetime import datetime

SMTP_HOST = "localhost"
SMTP_PORT = 25
CONCURRENT_CONNECTIONS = 100
MESSAGES_PER_CONNECTION = 100
MESSAGE_SIZE = 1024

def send_messages(thread_id):
    start = time.time()
    messages_sent = 0

    try:
        smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        smtp.set_debuglevel(0)

        for i in range(MESSAGES_PER_CONNECTION):
            msg = f"From: test{thread_id}@example.com\r\n"
            msg += f"To: recipient@example.com\r\n"
            msg += f"Subject: Load Test {thread_id}-{i}\r\n"
            msg += "\r\n"
            msg += "X" * MESSAGE_SIZE

            smtp.sendmail(
                f"test{thread_id}@example.com",
                ["recipient@example.com"],
                msg
            )
            messages_sent += 1

        smtp.quit()
    except Exception as e:
        print(f"Thread {thread_id} error: {e}")

    duration = time.time() - start
    print(f"Thread {thread_id}: {messages_sent} messages in {duration:.2f}s ({messages_sent/duration:.2f} msg/s)")

# Main load test
threads = []
start_time = time.time()

for i in range(CONCURRENT_CONNECTIONS):
    t = threading.Thread(target=send_messages, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

duration = time.time() - start_time
total_messages = CONCURRENT_CONNECTIONS * MESSAGES_PER_CONNECTION

print(f"\nTotal: {total_messages} messages in {duration:.2f}s")
print(f"Throughput: {total_messages/duration:.2f} messages/second")
```

### Comparison Benchmarks

Compare against other SMTP servers:

```bash
# Postfix
smtp-source -c 100 -m 10000 localhost:2525

# Your server
smtp-source -c 100 -m 10000 localhost:25

# Compare results
```

---

## Workload-Specific Tuning

### High-Volume Inbound

Optimized for receiving many emails:

```bash
# Increase connection limits
MAX_CONNECTIONS=10000

# Increase worker threads
WORKER_THREADS=16

# Disable expensive checks
SPAM_CHECK_ENABLED=false
VIRUS_SCAN_ENABLED=false
DKIM_VERIFY_ENABLED=false

# Use fast storage backend
STORAGE_TYPE=database
STORAGE_BATCH_INSERT=true
STORAGE_BATCH_SIZE=100

# Aggressive caching
USER_CACHE_SIZE=50000
DNS_CACHE_SIZE=100000
```

### High-Volume Outbound

Optimized for sending many emails:

```bash
# Queue optimization
QUEUE_WORKER_THREADS=8
QUEUE_BATCH_SIZE=200
QUEUE_INTERVAL=100  # Process every 100ms

# Connection pooling
RELAY_CONNECTION_POOL_SIZE=50
RELAY_CONNECTION_IDLE_TIMEOUT=300

# Aggressive retry
QUEUE_MAX_RETRIES=3
QUEUE_INITIAL_RETRY_DELAY=10
QUEUE_RETRY_BACKOFF=1.5

# Parallel delivery
QUEUE_PARALLEL_DELIVERY=true
QUEUE_PARALLEL_WORKERS=10
```

### Mixed Workload

Balanced configuration:

```bash
# Balanced connections
MAX_CONNECTIONS=5000
WORKER_THREADS=8
QUEUE_WORKER_THREADS=4

# Moderate caching
CACHE_SIZE=536870912  # 512MB
USER_CACHE_SIZE=20000
DNS_CACHE_SIZE=50000

# Balanced checks
SPAM_CHECK_ENABLED=true
SPAM_THRESHOLD=5.0  # More permissive
VIRUS_SCAN_ENABLED=true

# Moderate storage
STORAGE_TYPE=database
```

### Low-Latency

Optimized for minimum latency:

```bash
# Reduce timeouts
CONNECTION_TIMEOUT=60
IDLE_TIMEOUT=30

# Disable slow operations
SPAM_CHECK_ENABLED=false
VIRUS_SCAN_ENABLED=false
GREYLIST_ENABLED=false

# Use memory storage
STORAGE_TYPE=memory  # Or fast database

# Aggressive caching
CACHE_TTL=600  # 10 minutes
USER_CACHE_SIZE=100000

# Process priority
# Set via systemd:
Nice=-20
IOSchedulingClass=realtime
```

### High-Reliability

Optimized for data safety:

```bash
# Enable all checks
SPAM_CHECK_ENABLED=true
VIRUS_SCAN_ENABLED=true
SPF_CHECK_ENABLED=true
DKIM_VERIFY_ENABLED=true
DMARC_CHECK_ENABLED=true

# Safe database settings
# SQLite:
PRAGMA synchronous = FULL;
PRAGMA journal_mode = WAL;

# Backups
BACKUP_ENABLED=true
BACKUP_INTERVAL=3600  # Hourly
BACKUP_RETENTION=168  # 7 days

# Redundancy
STORAGE_REPLICATION=true
STORAGE_REPLICAS=3
```

---

## Performance Checklist

Use this checklist to verify optimization:

### System Level
- [ ] Kernel parameters tuned (`sysctl -a`)
- [ ] System limits increased (`ulimit -n`)
- [ ] Systemd service limits configured
- [ ] I/O scheduler optimized for storage type
- [ ] CPU governor set to performance
- [ ] Huge pages enabled (if applicable)
- [ ] Firewall optimized (conntrack limits)

### Network Level
- [ ] TCP BBR enabled
- [ ] Network buffers increased
- [ ] Network interface offloading enabled
- [ ] Connection limits raised
- [ ] TCP keepalive configured

### Storage Level
- [ ] Fast storage (SSD/NVMe) in use
- [ ] Filesystem tuned (XFS/ext4)
- [ ] Mount options optimized (noatime)
- [ ] RAID configured (if applicable)
- [ ] Database tuned (WAL mode, indexes)

### Application Level
- [ ] Worker threads match CPU cores
- [ ] Connection pooling enabled
- [ ] Caching enabled and sized
- [ ] Rate limiting configured
- [ ] Queue processing optimized
- [ ] Memory pools enabled

### Monitoring
- [ ] Prometheus metrics collection
- [ ] Grafana dashboards configured
- [ ] Alerting rules defined
- [ ] Log aggregation set up
- [ ] Performance baseline established

---

## Regression Testing

After tuning, verify performance hasn't regressed:

```bash
# Baseline benchmark
./load-test.py > baseline.txt

# After tuning
./load-test.py > tuned.txt

# Compare
echo "Baseline:"
grep "Throughput" baseline.txt
echo "Tuned:"
grep "Throughput" tuned.txt

# Calculate improvement
python3 -c "
baseline = float(open('baseline.txt').read().split('Throughput: ')[1].split()[0])
tuned = float(open('tuned.txt').read().split('Throughput: ')[1].split()[0])
improvement = ((tuned - baseline) / baseline) * 100
print(f'Improvement: {improvement:.2f}%')
"
```

---

## Additional Resources

- [Deployment Guide](./DEPLOYMENT.md) - Production deployment instructions
- [Architecture Documentation](./ARCHITECTURE.md) - System design and architecture
- [Troubleshooting Guide](./TROUBLESHOOTING.md) - Debugging performance issues
- [API Documentation](./API.md) - Metrics API reference

For performance-related questions:
- GitHub Issues: https://github.com/yourusername/mail/issues
- Discussion Forum: https://community.example.com/performance
