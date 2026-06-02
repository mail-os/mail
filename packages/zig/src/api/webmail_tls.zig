//! TLS plumbing for the webmail HTTP server.
//!
//! Provides a `Stream` that is either a plain socket or a TLS-wrapped socket,
//! exposing a uniform read/writeAll API so the HTTP request parser and response
//! writer work unchanged over both. The TLS path mirrors the proven nonblock
//! handshake + record handling in protocol/caldav.zig, including the subtlety
//! that the client's first HTTP request commonly piggybacks on the final
//! handshake TCP segment — so leftover ciphertext from the handshake is seeded
//! into the read buffer and decrypted before we ever block on a socket read.

const std = @import("std");
const socket = @import("../core/socket_compat.zig");
const tls = @import("tls");

pub const TlsError = error{
    NotConfigured,
    HandshakeFailed,
    Closed,
};

/// A read/write stream that is either plain TCP or TLS over TCP.
pub const Stream = struct {
    conn: socket.Connection,
    tls_conn: ?tls.nonblock.Connection = null,

    // TLS buffers (only used when tls_conn != null).
    cipher_buf: [tls.input_buffer_len]u8 = undefined,
    cipher_len: usize = 0, // unconsumed ciphertext at the front of cipher_buf
    clear_buf: [tls.input_buffer_len]u8 = undefined,
    clear_off: usize = 0, // start of unread cleartext
    clear_len: usize = 0, // end of valid cleartext
    closed: bool = false,

    pub fn plain(conn: socket.Connection) Stream {
        return .{ .conn = conn };
    }

    pub fn peerIp(self: *const Stream) []const u8 {
        return self.conn.peerIp();
    }

    /// Read up to buf.len bytes of cleartext. Returns 0 at end of stream.
    pub fn read(self: *Stream, buf: []u8) !usize {
        if (self.tls_conn == null) return self.conn.read(buf);

        // Serve any already-decrypted cleartext first.
        if (self.clear_off < self.clear_len) return self.copyOut(buf);
        if (self.closed) return 0;

        while (true) {
            // Decrypt whatever ciphertext is already buffered before blocking.
            if (self.cipher_len > 0) {
                const dec = self.tls_conn.?.decrypt(self.cipher_buf[0..self.cipher_len], &self.clear_buf) catch {
                    return TlsError.Closed;
                };
                if (dec.closed) self.closed = true;

                // Shift any unconsumed ciphertext (partial record) to the front.
                const consumed = dec.ciphertext_pos;
                const leftover = self.cipher_len - consumed;
                if (leftover > 0 and consumed > 0) {
                    std.mem.copyForwards(u8, self.cipher_buf[0..leftover], self.cipher_buf[consumed..self.cipher_len]);
                }
                self.cipher_len = leftover;

                if (dec.cleartext.len > 0) {
                    self.clear_off = 0;
                    self.clear_len = dec.cleartext.len;
                    return self.copyOut(buf);
                }
                if (self.closed) return 0;
                // Made progress but no cleartext yet (e.g. consumed a non-data
                // record); if more ciphertext remains, loop to decrypt it.
                if (consumed > 0 and self.cipher_len > 0) continue;
            }

            if (self.closed) return 0;
            // A single record larger than the buffer can never be decrypted.
            if (self.cipher_len >= self.cipher_buf.len) return TlsError.Closed;

            const n = self.conn.read(self.cipher_buf[self.cipher_len..]) catch return TlsError.Closed;
            if (n == 0) {
                self.closed = true;
                return 0;
            }
            self.cipher_len += n;
        }
    }

    fn copyOut(self: *Stream, buf: []u8) usize {
        const avail = self.clear_len - self.clear_off;
        const n = @min(avail, buf.len);
        @memcpy(buf[0..n], self.clear_buf[self.clear_off .. self.clear_off + n]);
        self.clear_off += n;
        return n;
    }

    /// Write all bytes (encrypting first on a TLS stream).
    pub fn writeAll(self: *Stream, data: []const u8) !void {
        if (self.tls_conn == null) {
            var off: usize = 0;
            while (off < data.len) {
                const n = try self.conn.write(data[off..]);
                if (n == 0) return TlsError.Closed;
                off += n;
            }
            return;
        }
        // One TLS record carries ~16 KiB of cleartext; chunk larger writes.
        const max_chunk: usize = 15000;
        var pos: usize = 0;
        while (pos < data.len) {
            const end = @min(pos + max_chunk, data.len);
            var send_buf: [tls.output_buffer_len]u8 = undefined;
            const enc = try self.tls_conn.?.encrypt(data[pos..end], &send_buf);
            var sent: usize = 0;
            while (sent < enc.ciphertext.len) {
                const n = try self.conn.write(enc.ciphertext[sent..]);
                if (n == 0) return TlsError.Closed;
                sent += n;
            }
            pos = end;
        }
    }

    /// Best-effort TLS close-notify (no-op for plain streams).
    pub fn closeTls(self: *Stream) void {
        if (self.tls_conn) |*c| {
            var close_buf: [64]u8 = undefined;
            if (c.close(&close_buf)) |close_data| {
                _ = self.conn.write(close_data) catch {};
            } else |_| {}
        }
    }
};

/// Perform a TLS server handshake on `conn` using `cert`, returning a TLS
/// `Stream` ready for read/writeAll. Leftover handshake ciphertext is preserved
/// in the stream so a piggybacked request isn't lost.
pub fn handshake(conn: socket.Connection, cert: *tls.config.CertKeyPair) !Stream {
    var server = tls.nonblock.Server.init(.{ .auth = cert });

    var recv_buf: [tls.input_buffer_len]u8 = undefined;
    var send_buf: [tls.output_buffer_len]u8 = undefined;
    var recv_len: usize = 0;

    while (!server.done()) {
        const result = server.run(recv_buf[0..recv_len], &send_buf) catch {
            return TlsError.HandshakeFailed;
        };

        if (result.recv_pos > 0) {
            const remaining = recv_len - result.recv_pos;
            if (remaining > 0) {
                std.mem.copyForwards(u8, &recv_buf, recv_buf[result.recv_pos..recv_len]);
            }
            recv_len = remaining;
        }

        if (result.send.len > 0) {
            var sent: usize = 0;
            while (sent < result.send.len) {
                const n = conn.write(result.send[sent..]) catch return TlsError.HandshakeFailed;
                if (n == 0) return TlsError.HandshakeFailed;
                sent += n;
            }
        }

        if (!server.done()) {
            const n = conn.read(recv_buf[recv_len..]) catch return TlsError.HandshakeFailed;
            if (n == 0) return TlsError.HandshakeFailed;
            recv_len += n;
        }
    }

    const cipher = server.cipher() orelse return TlsError.HandshakeFailed;
    var stream = Stream{ .conn = conn, .tls_conn = tls.nonblock.Connection.init(cipher) };
    // Seed leftover handshake ciphertext (the request may already be here).
    if (recv_len > 0) {
        @memcpy(stream.cipher_buf[0..recv_len], recv_buf[0..recv_len]);
        stream.cipher_len = recv_len;
    }
    return stream;
}
