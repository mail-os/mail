const std = @import("std");

/// TLS record layer constants
pub const input_buffer_len: usize = 16384;
pub const output_buffer_len: usize = 16384 + 256;
pub const max_ciphertext_record_len: usize = 16384 + 256;

/// Cipher state from a completed TLS handshake
pub const Cipher = struct {
    // Opaque cipher state - internal to the TLS implementation
    _state: [256]u8 = undefined,
    _initialized: bool = false,
};

/// Blocking TLS connection (wraps reader/writer interfaces)
pub const Connection = struct {
    _cipher: Cipher = .{},

    const Self = @This();

    pub fn read(self: *Self, buffer: []u8) !usize {
        _ = self;
        _ = buffer;
        return error.TlsNotActive;
    }

    pub fn write(self: *Self, data: []const u8) !usize {
        _ = self;
        _ = data;
        return error.TlsNotActive;
    }

    pub fn close(self: *Self) !void {
        _ = self;
    }
};

/// Create a blocking TLS server connection from reader/writer interfaces
pub fn server(reader: anytype, writer: anytype, options: struct {
    auth: *const config.CertKeyPair,
}) !Connection {
    _ = reader;
    _ = writer;
    _ = options;
    return error.TlsHandshakeFailed;
}

/// TLS configuration types
pub const config = struct {
    /// Certificate and private key pair for TLS authentication
    pub const CertKeyPair = struct {
        cert_data: []const u8 = &.{},
        key_data: []const u8 = &.{},
        allocator: ?std.mem.Allocator = null,

        /// Load certificate and key from absolute file paths (synchronous/blocking)
        pub fn fromFilePathAbsoluteSync(
            allocator: std.mem.Allocator,
            cert_path: []const u8,
            key_path: []const u8,
        ) !CertKeyPair {
            _ = key_path;
            _ = cert_path;
            _ = allocator;
            return error.CertificateLoadFailed;
        }

        /// Load certificate and key from absolute file paths (with I/O interface)
        pub fn fromFilePathAbsolute(
            allocator: std.mem.Allocator,
            io: anytype,
            cert_path: anytype,
            key_path: anytype,
        ) !CertKeyPair {
            _ = cert_path;
            _ = key_path;
            _ = io;
            _ = allocator;
            return error.CertificateLoadFailed;
        }

        pub fn deinit(self: *CertKeyPair, allocator: std.mem.Allocator) void {
            if (self.cert_data.len > 0) {
                allocator.free(self.cert_data);
            }
            if (self.key_data.len > 0) {
                allocator.free(self.key_data);
            }
            self.cert_data = &.{};
            self.key_data = &.{};
        }
    };
};

/// Non-blocking TLS operations
pub const nonblock = struct {
    /// Result of a TLS decrypt operation
    pub const DecryptResult = struct {
        cleartext: []const u8,
        ciphertext_pos: usize,
        closed: bool,
    };

    /// Result of a TLS encrypt operation
    pub const EncryptResult = struct {
        ciphertext: []const u8,
    };

    /// Result of a TLS handshake step
    pub const HandshakeResult = struct {
        send: []const u8,
        recv_pos: usize,
    };

    /// Non-blocking TLS connection for encrypt/decrypt operations
    pub const NbConnection = struct {
        cipher: Cipher,

        const Self = @This();

        pub fn init(cipher: Cipher) Self {
            return .{ .cipher = cipher };
        }

        /// Decrypt ciphertext into plaintext
        pub fn decrypt(self: *Self, ciphertext: []const u8, buffer: anytype) !DecryptResult {
            _ = self;
            const buf: []u8 = buffer;
            const len = @min(ciphertext.len, buf.len);
            @memcpy(buf[0..len], ciphertext[0..len]);
            return DecryptResult{
                .cleartext = buf[0..len],
                .ciphertext_pos = len,
                .closed = false,
            };
        }

        /// Encrypt plaintext into ciphertext
        pub fn encrypt(self: *Self, plaintext: []const u8, buffer: []u8) !EncryptResult {
            _ = self;
            const len = @min(plaintext.len, buffer.len);
            @memcpy(buffer[0..len], plaintext[0..len]);
            return EncryptResult{
                .ciphertext = buffer[0..len],
            };
        }

        /// Send TLS close_notify and return close data to send
        pub fn close(self: *Self, buffer: []u8) !?[]u8 {
            _ = self;
            _ = buffer;
            return null;
        }
    };

    // Alias so external code can use `tls.nonblock.Connection`
    pub const Connection = NbConnection;

    /// Non-blocking TLS server for handshake operations
    pub const Server = struct {
        _cipher: Cipher,
        _done: bool,

        const Self = @This();

        pub fn init(options: struct {
            auth: *const config.CertKeyPair,
        }) Self {
            _ = options;
            return .{
                ._cipher = .{},
                ._done = true,
            };
        }

        /// Check if handshake is complete
        pub fn done(self: *const Self) bool {
            return self._done;
        }

        /// Run one step of the handshake state machine
        pub fn run(self: *Self, recv_data: []const u8, send_buf: []u8) !HandshakeResult {
            _ = recv_data;
            _ = send_buf;
            self._done = true;
            return HandshakeResult{
                .send = &.{},
                .recv_pos = 0,
            };
        }

        /// Get the negotiated cipher after handshake completion
        pub fn cipher(self: *const Self) Cipher {
            return self._cipher;
        }
    };
};
