//! Client-side STARTTLS for outbound SMTP delivery.
//!
//! Mirrors the proven nonblock-TLS record handling in `api/webmail_tls.zig`
//! (whose `Stream` we reuse for read/writeAll), but drives the *client* side of
//! the handshake so we can upgrade an outbound MX connection to TLS after the
//! `STARTTLS` command.
//!
//! Delivery is opportunistic: certificates are NOT verified
//! (`insecure_skip_verify`). The point is to encrypt the transport — receivers
//! such as Gmail score cleartext SMTP as untrusted ("encryption: none"), so any
//! TLS is a strict improvement over none. MTA-STS/DANE enforcement (verifying
//! the cert chain/name) is a separate, future hardening step.

const std = @import("std");
const socket = @import("../core/socket_compat.zig");
const tls = @import("tls");
const webmail_tls = @import("../api/webmail_tls.zig");

/// Reuse the plain/TLS read/writeAll stream from the webmail TLS plumbing — the
/// cipher state is identical whether it came from a server or client handshake.
pub const Stream = webmail_tls.Stream;

pub const ClientTlsError = error{HandshakeFailed};

/// Perform a TLS *client* handshake over an already-connected SMTP socket
/// (`conn`) after the server has answered `220` to `STARTTLS`. `host` is the MX
/// hostname, sent as SNI. Returns a TLS `Stream` ready for read/writeAll.
///
/// Opportunistic: the server certificate is not validated.
pub fn clientHandshake(conn: socket.Connection, host: []const u8) !Stream {
    var client = tls.nonblock.Client.init(.{
        .host = host,
        .root_ca = .empty,
        .insecure_skip_verify = true,
    });

    var recv_buf: [tls.input_buffer_len]u8 = undefined;
    var send_buf: [tls.output_buffer_len]u8 = undefined;
    var recv_len: usize = 0;

    while (!client.done()) {
        const result = client.run(recv_buf[0..recv_len], &send_buf) catch {
            return ClientTlsError.HandshakeFailed;
        };

        // Drop the consumed prefix of the receive buffer (a partial record may
        // remain at the tail and must be preserved for the next run()).
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
                const n = conn.write(result.send[sent..]) catch return ClientTlsError.HandshakeFailed;
                if (n == 0) return ClientTlsError.HandshakeFailed;
                sent += n;
            }
        }

        if (!client.done()) {
            const n = conn.read(recv_buf[recv_len..]) catch return ClientTlsError.HandshakeFailed;
            if (n == 0) return ClientTlsError.HandshakeFailed;
            recv_len += n;
        }
    }

    const cipher = client.cipher() orelse return ClientTlsError.HandshakeFailed;
    var stream = Stream{ .conn = conn, .tls_conn = tls.nonblock.Connection.init(cipher) };
    // Preserve any post-handshake ciphertext that arrived in the same segment.
    if (recv_len > 0) {
        @memcpy(stream.cipher_buf[0..recv_len], recv_buf[0..recv_len]);
        stream.cipher_len = recv_len;
    }
    return stream;
}
