# zig-tls

Pure Zig TLS 1.3 implementation for SMTP and other protocols.

## Features

- TLS 1.3 client and server support
- Pure Zig implementation (no C dependencies)
- Non-blocking I/O
- STARTTLS support for protocol upgrades
- Certificate and private key management

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .tls = .{
        .path = "../zig-tls",
    },
},
```

Add to your `build.zig`:

```zig
const tls = b.dependency("tls", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("tls", tls.module("tls"));
```

## Usage

### Server Example

```zig
const tls = @import("tls");

// Load certificate and key
var cert_key = try tls.config.CertKeyPair.fromFilePathAbsolute(
    allocator,
    "/path/to/cert.pem",
    "/path/to/key.pem",
);
defer cert_key.deinit(allocator);

// Create TLS connection from stream
const tls_conn = try tls.serverFromStream(stream, .{
    .auth = &cert_key,
});

// Read/write through TLS
const n = try tls_conn.read(buffer);
try tls_conn.write(data);
```

## License

MIT - Based on https://github.com/ianic/tls.zig
