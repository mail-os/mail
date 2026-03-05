# Cross-Platform Support

Comprehensive documentation for building and deploying the SMTP server across multiple platforms and architectures.

## Supported Platforms

### Operating Systems

- **Linux** (x86_64, ARM64)
  - Ubuntu 20.04+
  - Debian 11+
  - RHEL/CentOS 8+
  - Alpine Linux 3.14+

- **macOS** (x86_64, ARM64/Apple Silicon)
  - macOS 11.0+ (Big Sur)
  - macOS 12.0+ (Monterey)
  - macOS 13.0+ (Ventura)
  - macOS 14.0+ (Sonoma)

- **Windows** (x86_64, ARM64)
  - Windows Server 2019+
  - Windows 10 20H2+
  - Windows 11

- **FreeBSD** (x86_64, ARM64)
  - FreeBSD 13.0+
  - FreeBSD 14.0+

- **OpenBSD** (x86_64)
  - OpenBSD 7.0+
  - OpenBSD 7.3+

### Architectures

- **x86_64** (AMD64) - Primary support
- **aarch64** (ARM64) - Full support
- **arm** (32-bit ARM) - Experimental
- **riscv64** - Experimental

## Building for Multiple Platforms

### Quick Start

Build for all supported platforms:

```bash
zig build -Dall-targets=true -Doptimize=ReleaseSafe
```

This will create binaries in `zig-out/bin/<platform>/` for each target.

### Build for Specific Platform

Build for a specific target:

```bash
# Linux x86_64
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseSafe

# Linux ARM64
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseSafe

# macOS x86_64
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe

# macOS ARM64 (Apple Silicon)
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe

# Windows x86_64
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseSafe

# Windows ARM64
zig build -Dtarget=aarch64-windows-gnu -Doptimize=ReleaseSafe

# FreeBSD x86_64
zig build -Dtarget=x86_64-freebsd -Doptimize=ReleaseSafe

# FreeBSD ARM64
zig build -Dtarget=aarch64-freebsd -Doptimize=ReleaseSafe

# OpenBSD x86_64
zig build -Dtarget=x86_64-openbsd -Doptimize=ReleaseSafe
```

### Using Build Script

The `scripts/build-cross-platform.sh` script automates building for all platforms:

```bash
# Build all platforms in ReleaseSafe mode
./scripts/build-cross-platform.sh ReleaseSafe

# Build all platforms in ReleaseSmall mode
./scripts/build-cross-platform.sh ReleaseSmall releases/

# Build all platforms in ReleaseFast mode
./scripts/build-cross-platform.sh ReleaseFast
```

Output binaries are placed in the `releases/` directory with checksums.

## Platform-Specific Features

### Linux

**Features:**
- systemd service integration
- io_uring async I/O (kernel 5.1+)
- Abstract Unix sockets
- Full IPv6 dual-stack support
- Netlink interface monitoring

**Service Management:**
```bash
# Install as systemd service
sudo systemctl enable mail
sudo systemctl start mail

# View logs
sudo journalctl -u mail -f
```

**Configuration:**
```bash
# Config location
/etc/mail/smtp.env

# Data directory
/var/lib/mail/

# Logs
/var/log/mail/
```

### macOS

**Features:**
- launchd integration
- Keychain integration for TLS certificates
- Gatekeeper compatibility
- Apple Silicon native support

**Service Management:**
```bash
# Install as launchd service
sudo launchctl load /Library/LaunchDaemons/com.mail.plist
sudo launchctl start com.mail

# View logs
tail -f /usr/local/var/log/mail.log
```

**Configuration:**
```bash
# Config location
/usr/local/etc/mail/smtp.env

# Data directory
/usr/local/var/lib/mail/

# Logs
/usr/local/var/log/mail/
```

### Windows

**Features:**
- Windows Service integration
- Event Log integration
- Windows Firewall rules
- Named pipes for IPC
- TLS with Windows Certificate Store

**Service Management:**
```powershell
# Install as Windows Service
sc create mail binPath="C:\Program Files\mail\mail.exe" start=auto
sc start mail

# View logs
Get-EventLog -LogName Application -Source mail -Newest 50
```

**Configuration:**
```powershell
# Config location
C:\ProgramData\mail\smtp.env

# Data directory
C:\ProgramData\mail\data\

# Logs
C:\ProgramData\mail\logs\
```

### FreeBSD

**Features:**
- rc.d service integration
- Capsicum sandboxing
- ZFS integration for storage
- jails support

**Service Management:**
```bash
# Install as rc.d service
sudo sysrc smtp_server_enable="YES"
sudo service mail start

# View logs
tail -f /var/log/mail.log
```

**Configuration:**
```bash
# Config location
/usr/local/etc/mail/smtp.env

# Data directory
/var/db/mail/

# Logs
/var/log/mail/
```

### OpenBSD

**Features:**
- rc.d service integration
- pledge() system call restrictions
- unveil() filesystem restrictions
- PF firewall integration

**Service Management:**
```bash
# Install as rc.d service
sudo rcctl enable smtp_server
sudo rcctl start smtp_server

# View logs
tail -f /var/log/mail.log
```

**Configuration:**
```bash
# Config location
/etc/mail/smtp.env

# Data directory
/var/mail/

# Logs
/var/log/mail/
```

## Platform Abstraction Layer

The `src/platform.zig` module provides a unified API across all platforms.

### Detecting Platform

```zig
const platform = @import("platform.zig");

const current_platform = platform.Platform.current();
const current_arch = platform.Architecture.current();

if (current_platform.isUnix()) {
    // Unix-specific code
}

if (current_platform.isWindows()) {
    // Windows-specific code
}

if (current_platform.isBSD()) {
    // BSD-specific code
}
```

### Path Handling

```zig
const path_sep = platform.Path.separator(); // "/" or "\\"
const list_sep = platform.Path.listSeparator(); // ":" or ";"

const home = try platform.Path.homeDir(allocator);
const temp = try platform.Path.tempDir(allocator);
```

### Service Management

```zig
const service = platform.Service{
    .name = "mail",
    .description = "SMTP Mail Server",
};

// Install service (platform-specific)
try service.install(allocator, "/usr/local/bin/mail");

// Start service
try service.start(allocator);

// Stop service
try service.stop(allocator);

// Uninstall service
try service.uninstall(allocator);
```

### Process Management

```zig
// Daemonize (Unix only)
try platform.Process.daemonize();

// Get PID
const pid = platform.Process.getPid();

// Write PID file
try platform.Process.writePidFile(allocator, "/var/run/mail.pid");
```

### Signal Handling

```zig
// Unix signal handling
const handler = struct {
    fn handleSignal(sig: i32) callconv(.C) void {
        // Handle signal
    }
}.handleSignal;

try platform.Signal.setupHandler(std.posix.SIG.TERM, handler);
try platform.Signal.ignore(std.posix.SIG.PIPE);
```

### Network Utilities

```zig
// Check IPv6 availability
const has_ipv6 = platform.Network.hasIPv6();

// Get preferred address family
const af = platform.Network.preferredAddressFamily();
```

## Unix Domain Sockets

Unix sockets are supported on all Unix-like platforms (Linux, macOS, BSD).

### Stream Sockets

```zig
const unix_socket = @import("unix_socket.zig");

// Create listener
const addr = unix_socket.UnixAddress.init("/tmp/smtp.sock");
var listener = try unix_socket.UnixListener.init(allocator, addr);
defer listener.deinit();

// Set permissions (owner only)
try listener.setPermissions(0o600);

// Accept connections
var stream = try listener.accept();
defer stream.deinit();

// Read/write
try stream.writeAll("Hello, Unix socket!");
var buffer: [1024]u8 = undefined;
const n = try stream.read(&buffer);
```

### Abstract Sockets (Linux)

```zig
// Linux-specific abstract namespace (no filesystem)
const addr = unix_socket.UnixAddress.initAbstract("mail");
var listener = try unix_socket.UnixListener.init(allocator, addr);
defer listener.deinit();
```

### Datagram Sockets

```zig
// Create datagram socket
const addr = unix_socket.UnixAddress.init("/tmp/smtp-dgram.sock");
var socket = try unix_socket.UnixDatagram.init(allocator, addr);
defer socket.deinit();

// Send to destination
const dest = unix_socket.UnixAddress.init("/tmp/other.sock");
_ = try socket.sendTo("Message", dest);

// Receive
var buffer: [1024]u8 = undefined;
const result = try socket.recvFrom(&buffer);
```

## Dependencies

### All Platforms

- **SQLite3** - Database storage
- **libc** - Standard C library

### Linux

- **liburing** (optional) - io_uring async I/O
- **systemd** - Service management

### Windows

- **ws2_32** - Winsock2 networking
- **advapi32** - Service management
- **crypt32** - Certificate store

### BSD

- No additional dependencies

## Cross-Compilation from macOS

### Install Cross-Compilation Tools

```bash
# Install Zig (includes cross-compiler)
brew install zig

# No additional tools needed - Zig includes cross-compilation!
```

### Build for Linux

```bash
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseSafe
```

### Build for Windows

```bash
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseSafe
```

### Build for ARM

```bash
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseSafe
```

## Cross-Compilation from Linux

### Build for macOS

```bash
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
```

### Build for Windows

```bash
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseSafe
```

### Build for ARM

```bash
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseSafe
```

## Cross-Compilation from Windows

### Build for Linux

```powershell
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseSafe
```

### Build for macOS

```powershell
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe
```

## Testing Cross-Platform Builds

### Run Tests for Native Platform

```bash
zig build test --summary all
```

### Run Tests for Specific Platform (requires emulation)

```bash
# Linux ARM64 via QEMU
zig build test -Dtarget=aarch64-linux-gnu

# Requires QEMU user-mode emulation
sudo apt install qemu-user-static
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Cross-Platform Build

on: [push, pull_request]

jobs:
  build:
    strategy:
      matrix:
        target:
          - x86_64-linux-gnu
          - aarch64-linux-gnu
          - x86_64-macos
          - aarch64-macos
          - x86_64-windows-gnu

    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Install Zig
        uses: goto-bus-stop/setup-zig@v2
        with:
          version: 0.15.1

      - name: Build
        run: |
          zig build -Dtarget=${{ matrix.target }} -Doptimize=ReleaseSafe

      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: mail-${{ matrix.target }}
          path: zig-out/bin/
```

## Troubleshooting

### Missing Dependencies

**Linux:**
```bash
# Ubuntu/Debian
sudo apt install libsqlite3-dev

# RHEL/CentOS
sudo yum install sqlite-devel
```

**macOS:**
```bash
brew install sqlite3
```

**Windows:**
```powershell
# Install SQLite3 from https://sqlite.org/download.html
# Add to PATH
```

### Permission Denied on Unix Sockets

```bash
# Check socket permissions
ls -l /tmp/smtp.sock

# Fix permissions
chmod 600 /tmp/smtp.sock
```

### Windows Service Won't Start

```powershell
# Check Event Log
Get-EventLog -LogName Application -Source mail -Newest 10

# Check service status
sc query mail

# Check file permissions
icacls "C:\Program Files\mail"
```

### BSD Firewall Issues

```bash
# FreeBSD - Check PF rules
sudo pfctl -sr

# OpenBSD - Check PF rules
sudo pfctl -sr
```

## Performance Considerations

### Linux (io_uring)

On Linux with kernel 5.1+, io_uring provides significant performance improvements:

- 30-40% lower CPU usage
- 2-3x higher throughput
- Lower latency

Enable with:
```bash
SMTP_USE_IO_URING=true ./mail
```

### macOS (kqueue)

macOS uses kqueue for event notification:

- Efficient with many connections
- Low CPU overhead
- Native integration

### Windows (IOCP)

Windows uses I/O Completion Ports:

- Scalable to thousands of connections
- Efficient thread pooling
- Native integration

## Security Considerations

### Unix Socket Permissions

Always set restrictive permissions on Unix sockets:

```zig
try listener.setPermissions(0o600); // Owner only
```

### Service User

Run as dedicated user:

```bash
# Linux
sudo useradd -r -s /bin/false smtp

# FreeBSD
sudo pw useradd smtp -s /usr/sbin/nologin

# macOS
sudo dscl . -create /Users/smtp
```

### Firewall Configuration

**Linux (ufw):**
```bash
sudo ufw allow 25/tcp
sudo ufw allow 587/tcp
sudo ufw allow 465/tcp
```

**FreeBSD (pf):**
```bash
# /etc/pf.conf
pass in proto tcp to port { 25, 587, 465 }
```

**Windows (netsh):**
```powershell
netsh advfirewall firewall add rule name="SMTP" dir=in action=allow protocol=TCP localport=25,587,465
```

## License

MIT License - See LICENSE file for details.
