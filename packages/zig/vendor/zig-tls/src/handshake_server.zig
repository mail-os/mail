const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const Io = std.Io;
const Certificate = crypto.Certificate;

const Cipher = @import("cipher.zig").Cipher;
const CipherSuite = @import("cipher.zig").CipherSuite;
const cipher_suites = @import("cipher.zig").cipher_suites;
const max_cleartext_len = @import("cipher.zig").max_cleartext_len;

const Transcript = @import("transcript.zig").Transcript;
const record = @import("record.zig");
const Record = record.Record;
const PrivateKey = @import("PrivateKey.zig");
const proto = @import("protocol.zig");

const common = @import("handshake_common.zig");
const CertificateBuilder = common.CertificateBuilder;
const CertificateParser = common.CertificateParser;
const DhKeyPair = common.DhKeyPair;
const CertKeyPair = common.CertKeyPair;
const cert = common.cert;

const rng = @import("random.zig");
const log = std.log.scoped(.tls);

pub const Options = struct {
    /// Server authentication. If null server will not send Certificate and
    /// CertificateVerify message.
    auth: ?*CertKeyPair,

    /// If not null server will request client certificate. If auth_type is
    /// .request empty client certificate message will be accepted.
    /// Client certificate will be verified with root_ca certificates.
    client_auth: ?ClientAuth = null,

    /// List of supported cipher suites (TLS 1.3 and/or TLS 1.2)
    /// Default includes both TLS 1.3 and TLS 1.2 secure ciphers for maximum compatibility.
    cipher_suites: []const CipherSuite = cipher_suites.all,

    /// Named groups (elliptic curves) to support for key exchange
    named_groups: []const proto.NamedGroup = &[_]proto.NamedGroup{ .x25519, .secp256r1, .secp384r1 },
};

pub const ClientAuth = struct {
    /// Set of root certificate authorities that server use when verifying
    /// client certificates.
    root_ca: cert.Bundle,

    auth_type: Type = .require,

    pub const Type = enum {
        /// Client certificate will be requested during the handshake, but does
        /// not require that the client send any certificates.
        request,
        /// Client certificate will be requested during the handshake, and client
        /// has to send valid certificate.
        require,
    };
};

pub const Handshake = struct {
    // public key len: x25519 = 32, secp256r1 = 65, secp384r1 = 97
    const max_pub_key_len = 98;
    const supported_named_groups = &[_]proto.NamedGroup{ .x25519, .secp256r1, .secp384r1 };

    /// Underlying network connection stream reader/writer pair.
    input: *Io.Reader,
    output: *Io.Writer,

    server_random: [32]u8 = undefined,
    client_random: [32]u8 = undefined,
    legacy_session_id_buf: [32]u8 = undefined,
    legacy_session_id: []u8 = &.{},
    cipher_suite: CipherSuite = @enumFromInt(0),
    signature_scheme: proto.SignatureScheme = @enumFromInt(0),
    named_group: proto.NamedGroup = @enumFromInt(0),
    client_pub_key_buf: [max_pub_key_len]u8 = undefined,
    client_pub_key: []u8 = &.{},
    server_pub_key_buf: [max_pub_key_len]u8 = undefined,
    server_pub_key: []u8 = &.{},

    cipher: Cipher = undefined,
    transcript: Transcript = .{},

    // TLS 1.2 specific fields
    tls_version: proto.Version = .tls_1_3,
    master_secret: [48]u8 = undefined,
    key_material: [48 * 4]u8 = undefined,
    dh_kp: DhKeyPair = undefined,

    const Self = @This();

    fn writeAlert(h: *Self, cph: ?*Cipher, err: anyerror) !void {
        if (cph) |c| {
            const cleartext = proto.alertFromError(err);
            const ciphertext = try c.encrypt(h.output.unusedCapacitySlice(), .alert, &cleartext);
            h.output.advance(ciphertext.len);
        } else {
            const alert = record.header(.alert, 2) ++ proto.alertFromError(err);
            try h.output.writeAll(&alert);
        }
        try h.output.flush();
    }

    pub fn handshake(h: *Self, opt: Options) !Cipher {
        h.initKeys(opt);

        h.readClientHello(opt.cipher_suites, opt.named_groups) catch |err| {
            try h.writeAlert(null, err);
            return err;
        };
        h.transcript.use(h.cipher_suite.hash());

        if (h.tls_version == .tls_1_3) {
            // TLS 1.3 handshake
            h.serverFlight(opt) catch |err| {
                try h.writeAlert(null, err);
                return err;
            };
            try h.output.flush();

            h.clientFlight2(opt) catch |err| {
                // Alert received from client
                if (!mem.startsWith(u8, @errorName(err), "TlsAlert")) {
                    try h.writeAlert(&h.cipher, err);
                }
                return err;
            };
        } else {
            // TLS 1.2 handshake
            h.serverFlightTls12(opt) catch |err| {
                try h.writeAlert(null, err);
                return err;
            };
            try h.output.flush();

            h.clientFlight2Tls12(opt) catch |err| {
                if (!mem.startsWith(u8, @errorName(err), "TlsAlert")) {
                    try h.writeAlert(if (h.cipher_suite.validate() == null) &h.cipher else null, err);
                }
                return err;
            };
        }
        return h.cipher;
    }

    fn initKeys(h: *Self, opt: Options) void {
        rng.fill(&h.server_random);
        if (opt.auth) |a| {
            // required signature scheme in client hello
            h.signature_scheme = a.key.signature_scheme;
        }
        // Initialize DH key pair for key exchange (used in TLS 1.2 ECDHE)
        var seed: [DhKeyPair.seed_len]u8 = undefined;
        rng.fill(&seed);
        h.dh_kp = DhKeyPair.init(seed, opt.named_groups) catch unreachable;
    }

    fn clientFlight1(h: *Self, opt: Options) !void {
        try h.readClientHello(opt.cipher_suites, opt.named_groups);
        h.transcript.use(h.cipher_suite.hash());
    }

    /// TLS 1.2 server flight: ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
    fn serverFlightTls12(h: *Self, opt: Options) !void {
        var w: record.Writer = .initFromIo(h.output);

        // Debug: log the selected named_group (use info level to show in production)
        log.info("TLS 1.2 serverFlightTls12: named_group={x}, cipher_suite={x}", .{ @intFromEnum(h.named_group), @intFromEnum(h.cipher_suite) });

        // Generate server's DH public key
        log.info("TLS 1.2: generating DH public key", .{});
        h.server_pub_key = try common.dupe(&h.server_pub_key_buf, try h.dh_kp.publicKey(h.named_group));
        log.info("TLS 1.2: DH public key generated, len={d}", .{h.server_pub_key.len});

        // ServerHello
        {
            log.info("TLS 1.2: making ServerHello", .{});
            const hello = try h.makeServerHelloTls12(&w);
            h.transcript.update(hello[record.header_len..]);
            log.info("TLS 1.2: ServerHello done, pos={d}", .{w.pos()});
        }

        // Certificate (if auth is enabled)
        if (opt.auth) |auth| {
            log.info("TLS 1.2: making Certificate at pos={d}", .{w.pos()});
            const cb = CertificateBuilder{
                .cert_key_pair = auth,
                .transcript = &h.transcript,
                .tls_version = .tls_1_2,
                .side = .server,
            };
            // Skip space for record header (5 bytes)
            const header_pos = try w.skip(record.header_len);
            const content_start = w.pos();
            try cb.makeCertificate(&w);
            const content_len = w.pos() - content_start;
            h.transcript.update(w.buffered()[content_start..]);
            // Go back and write the record header
            var hw = w.writerAt(header_pos);
            try hw.recordHeader(.handshake, content_len);
            log.info("TLS 1.2: Certificate done, content_len={d}, pos={d}", .{ content_len, w.pos() });
        }

        // ServerKeyExchange (for ECDHE cipher suites)
        if (h.cipher_suite.keyExchange() == .ecdhe) {
            if (opt.auth) |auth| {
                log.info("TLS 1.2: making ServerKeyExchange at pos={d}", .{w.pos()});
                // Skip space for record header (5 bytes)
                const header_pos = try w.skip(record.header_len);
                const content_start = w.pos();
                try h.makeServerKeyExchange(&w, auth);
                const content_len = w.pos() - content_start;
                h.transcript.update(w.buffered()[content_start..]);
                // Go back and write the record header
                var hw = w.writerAt(header_pos);
                try hw.recordHeader(.handshake, content_len);
                log.info("TLS 1.2: ServerKeyExchange done, content_len={d}, pos={d}", .{ content_len, w.pos() });
            }
        }

        // ServerHelloDone
        {
            log.info("TLS 1.2: making ServerHelloDone at pos={d}", .{w.pos()});
            // Skip space for record header (5 bytes)
            const header_pos = try w.skip(record.header_len);
            const content_start = w.pos();
            // ServerHelloDone is just a handshake header with 0 length body
            try w.handshakeRecordHeader(.server_hello_done, 0);
            const content_len = w.pos() - content_start;
            h.transcript.update(w.buffered()[content_start..]);
            // Go back and write the record header
            var hw = w.writerAt(header_pos);
            try hw.recordHeader(.handshake, content_len);
            log.info("TLS 1.2: ServerHelloDone done, content_len={d}, pos={d}", .{ content_len, w.pos() });
        }

        log.info("TLS 1.2: serverFlightTls12 complete, total bytes={d}", .{w.buffered().len});
        log.info("TLS 1.2: h.output.end before advance={d}", .{h.output.end});
        h.output.advance(w.buffered().len);
        log.info("TLS 1.2: h.output.end after advance={d}", .{h.output.end});
    }

    fn makeServerHelloTls12(h: *Self, w: *record.Writer) ![]const u8 {
        const header_pos = try w.skip(9);

        try w.enumValue(proto.Version.tls_1_2);
        try w.slice(&h.server_random);
        {
            try w.int(u8, h.legacy_session_id.len);
            if (h.legacy_session_id.len > 0) try w.slice(h.legacy_session_id);
        }
        try w.enumValue(h.cipher_suite);
        try w.slice(&[_]u8{0}); // compression method (null)

        // Extensions for TLS 1.2 ServerHello
        // RFC 5746: renegotiation_info extension is required by modern clients
        // Extension structure: type (2) + length (2) + data
        // renegotiation_info: type=0xff01, length=1, renegotiated_connection_length=0
        try w.int(u16, 5); // Extensions total length
        try w.int(u16, 0xff01); // Extension type: renegotiation_info
        try w.int(u16, 1); // Extension data length
        try w.int(u8, 0); // renegotiated_connection length (0 for initial handshake)

        var hw = w.writerAt(header_pos);
        try hw.recordHeader(.handshake, w.pos() - 5);
        try hw.handshakeRecordHeader(.server_hello, w.pos() - 9);

        return w.buffered();
    }

    fn makeServerKeyExchange(h: *Self, hw: *record.Writer, auth: *CertKeyPair) !void {
        const content_start = hw.pos();
        // Skip handshake header, write it at end
        _ = try hw.skip(4);

        // ECParameters - named_curve type + curve ID
        try hw.int(u8, @intFromEnum(proto.Curve.named_curve));
        try hw.enumValue(h.named_group);

        // ECPoint - public key
        const pub_key = h.server_pub_key;
        try hw.int(u8, pub_key.len);
        try hw.slice(pub_key);

        // Signature - sign (client_random + server_random + ec_params + ec_point)
        const params_end = hw.pos();
        const params = hw.buffered()[content_start + 4 .. params_end];

        // Build data to sign: client_random || server_random || ec_params
        var sign_buf: [32 + 32 + 256]u8 = undefined;
        @memcpy(sign_buf[0..32], &h.client_random);
        @memcpy(sign_buf[32..64], &h.server_random);
        @memcpy(sign_buf[64 .. 64 + params.len], params);
        const sign_data = sign_buf[0 .. 64 + params.len];

        // Sign the data using the appropriate signing method based on key type
        const signature_scheme = auth.key.signature_scheme;
        log.info("TLS 1.2 ServerKeyExchange: signature_scheme={x}, ecdsa_key_pair_present={}", .{ @intFromEnum(signature_scheme), auth.ecdsa_key_pair != null });
        try hw.enumValue(signature_scheme);

        const signature = switch (signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| brk: {
                log.info("TLS 1.2 ServerKeyExchange: entering ECDSA branch", .{});
                const Ecdsa = common.SchemeEcdsa(comptime_scheme);
                const key_pair = switch (comptime_scheme) {
                    .ecdsa_secp256r1_sha256 => auth.ecdsa_key_pair.?.ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384 => auth.ecdsa_key_pair.?.ecdsa_secp384r1_sha384,
                    else => unreachable,
                };
                log.info("TLS 1.2 ServerKeyExchange: got key_pair, creating signer", .{});
                var signer = try key_pair.signer(null);
                log.info("TLS 1.2 ServerKeyExchange: signer created, updating", .{});
                signer.update(sign_data);
                log.info("TLS 1.2 ServerKeyExchange: finalizing signature", .{});
                const sig = try signer.finalize();
                log.info("TLS 1.2 ServerKeyExchange: converting to DER", .{});
                var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                break :brk sig.toDer(&buf);
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| brk: {
                const Hash = common.SchemeHash(comptime_scheme);
                var signer = try auth.key.key.rsa.signerOaep(Hash, null);
                signer.update(sign_data);
                var buf: [512]u8 = undefined;
                const sig = try signer.finalize(&buf);
                break :brk sig.bytes;
            },
            else => return error.TlsUnknownSignatureScheme,
        };

        try hw.int(u16, signature.len);
        try hw.slice(signature);

        // Write handshake header
        var header_w = hw.writerAt(content_start);
        try header_w.handshakeRecordHeader(.server_key_exchange, hw.pos() - content_start - 4);
    }

    /// TLS 1.2 client flight 2: ClientKeyExchange, ChangeCipherSpec, Finished
    fn clientFlight2Tls12(h: *Self, _: Options) !void {
        log.info("TLS 1.2 clientFlight2Tls12: starting", .{});
        // Read ClientKeyExchange
        {
            var d = Record.decoder(h.input) catch |err| {
                log.err("TLS 1.2 clientFlight2Tls12: Record.decoder failed: {}", .{err});
                return err;
            };
            log.info("TLS 1.2 clientFlight2Tls12: got record, content_type={x}", .{@intFromEnum(d.content_type)});
            d.expectContentType(.handshake) catch |err| {
                log.err("TLS 1.2 clientFlight2Tls12: expected handshake but got content_type={x}, payload_len={d}", .{ @intFromEnum(d.content_type), d.payload.len });
                if (d.content_type == .alert and d.payload.len >= 2) {
                    log.err("TLS 1.2 clientFlight2Tls12: client sent alert: level={d}, desc={d}", .{ d.payload[0], d.payload[1] });
                }
                return err;
            };
            h.transcript.update(d.payload);

            const handshake_type = try d.decode(proto.Handshake);
            log.info("TLS 1.2 clientFlight2Tls12: handshake_type={x} (decimal={d}), expected client_key_exchange={x}", .{ @intFromEnum(handshake_type), @intFromEnum(handshake_type), @intFromEnum(proto.Handshake.client_key_exchange) });
            if (handshake_type != .client_key_exchange) {
                log.err("TLS 1.2 clientFlight2Tls12: handshake type mismatch! got={s}, expected=client_key_exchange", .{@tagName(handshake_type)});
                return error.TlsUnexpectedMessage;
            }
            log.info("TLS 1.2 clientFlight2Tls12: handshake type check passed", .{});
            const length = try d.decode(u24);
            log.info("TLS 1.2 clientFlight2Tls12: ClientKeyExchange length={d}", .{length});

            // For ECDHE, client sends its public key
            if (h.cipher_suite.keyExchange() == .ecdhe) {
                const client_pub_key_len = try d.decode(u8);
                log.info("TLS 1.2 clientFlight2Tls12: client pub key len={d}, expected={d}", .{ client_pub_key_len, length - 1 });
                if (client_pub_key_len != length - 1) return error.TlsDecodeError;
                h.client_pub_key = try common.dupe(&h.client_pub_key_buf, try d.slice(client_pub_key_len));
                log.info("TLS 1.2 clientFlight2Tls12: got client pub key, len={d}", .{h.client_pub_key.len});
            } else {
                // RSA key exchange - skip for now
                try d.skip(length);
            }
        }
        log.info("TLS 1.2 clientFlight2Tls12: finished reading ClientKeyExchange", .{});

        // Generate pre-master secret and derive keys
        if (h.cipher_suite.keyExchange() == .ecdhe) {
            log.info("TLS 1.2 clientFlight2Tls12: generating shared key, named_group={x}", .{@intFromEnum(h.named_group)});
            const pre_master_secret = try h.dh_kp.sharedKey(h.named_group, h.client_pub_key);
            log.info("TLS 1.2 clientFlight2Tls12: got pre_master_secret, len={d}", .{pre_master_secret.len});
            h.transcript.masterSecret(&h.master_secret, pre_master_secret, h.client_random, h.server_random);
            h.transcript.keyMaterial(&h.key_material, &h.master_secret, h.client_random, h.server_random);
            log.info("TLS 1.2 clientFlight2Tls12: derived keys", .{});
        }

        // Initialize cipher for decryption
        log.info("TLS 1.2 clientFlight2Tls12: initializing cipher", .{});
        h.cipher = try Cipher.initTls12(h.cipher_suite, &h.key_material, .server);
        log.info("TLS 1.2 clientFlight2Tls12: cipher initialized", .{});

        // Read ChangeCipherSpec
        log.info("TLS 1.2 clientFlight2Tls12: reading ChangeCipherSpec", .{});
        {
            var d = try Record.decoder(h.input);
            log.info("TLS 1.2 clientFlight2Tls12: got record, content_type={x}", .{@intFromEnum(d.content_type)});
            try d.expectContentType(.change_cipher_spec);
            log.info("TLS 1.2 clientFlight2Tls12: ChangeCipherSpec payload_len={d}, payload[0]={d}", .{ d.payload.len, if (d.payload.len > 0) d.payload[0] else 255 });
            if (d.payload.len != 1 or d.payload[0] != 1) return error.TlsUnexpectedMessage;
        }
        log.info("TLS 1.2 clientFlight2Tls12: ChangeCipherSpec OK", .{});

        // Read encrypted Finished
        // In TLS 1.2, the encrypted Finished message uses content_type=handshake (0x16)
        // The encryption is applied to the payload, but the record header type stays as handshake
        log.info("TLS 1.2 clientFlight2Tls12: reading encrypted Finished", .{});
        {
            const rec = try Record.read(h.input);
            log.info("TLS 1.2 clientFlight2Tls12: got record, content_type={x}", .{@intFromEnum(rec.content_type)});
            // TLS 1.2 encrypted Finished uses handshake (0x16) content type, NOT application_data
            if (rec.content_type != .handshake) {
                log.err("TLS 1.2 clientFlight2Tls12: expected handshake, got {x}", .{@intFromEnum(rec.content_type)});
                return error.TlsUnexpectedMessage;
            }

            var cleartext_buf: [128]u8 = undefined;
            // For TLS 1.2, decrypt returns the record's content_type (which is handshake)
            const content_type, const cleartext = try h.cipher.decrypt(&cleartext_buf, rec);
            log.info("TLS 1.2 clientFlight2Tls12: decrypted, content_type={x}, cleartext_len={d}", .{ @intFromEnum(content_type), cleartext.len });
            if (content_type != .handshake) return error.TlsUnexpectedMessage;

            // Parse Finished message
            var d = record.Decoder.init(content_type, cleartext);
            const handshake_type = try d.decode(proto.Handshake);
            if (handshake_type != .finished) return error.TlsUnexpectedMessage;
            const length = try d.decode(u24);
            if (length != 12) return error.TlsDecodeError;

            const client_verify_data = try d.slice(12);
            const expected_verify_data = h.transcript.clientFinishedTls12(&h.master_secret);
            if (!mem.eql(u8, client_verify_data, &expected_verify_data))
                return error.TlsDecryptError;

            // Update transcript with Finished message
            h.transcript.update(cleartext);
        }

        // Send ChangeCipherSpec and Finished
        {
            var w: record.Writer = .initFromIo(h.output);

            // ChangeCipherSpec
            try w.record(.change_cipher_spec, &[_]u8{1});

            // Finished (encrypted)
            const server_finished = &record.handshakeHeader(.finished, 12) ++
                h.transcript.serverFinishedTls12(&h.master_secret);
            const ciphertext = try h.cipher.encrypt(w.unused(), .handshake, server_finished);
            w.advance(ciphertext.len);

            h.output.advance(w.buffered().len);
            try h.output.flush();
        }
    }

    fn clientFlight2(h: *Self, opt: Options) !void {
        // calculate application cipher before updating transcript in readClientFlight2
        const application_secret = h.transcript.applicationSecret();
        const app_cipher = try Cipher.initTls13(h.cipher_suite, application_secret, .server);
        // set application cipher instead of EndOfStream error
        h.readClientFlight2(opt) catch |err| {
            if (err != error.EndOfStream and err != error.InputBufferUndersize) {
                // don't change on short reads: https://github.com/ianic/tls.zig/commit/2f3f23485e01e4be8219c4a1ceda01ed961da61d
                h.cipher = app_cipher;
            }
            return err;
        };
        h.cipher = app_cipher;
    }

    fn serverFlight(h: *Self, opt: Options) !void {
        var w: record.Writer = .initFromIo(h.output);

        const shared_key = brk: {
            var seed: [DhKeyPair.seed_len]u8 = undefined;
            rng.fill(&seed);
            var kp = try DhKeyPair.init(seed, &[_]proto.NamedGroup{h.named_group});
            h.server_pub_key = try common.dupe(&h.server_pub_key_buf, try kp.publicKey(h.named_group));
            break :brk try kp.sharedKey(h.named_group, h.client_pub_key);
        };
        {
            const hello = try h.makeServerHello(&w);
            h.transcript.update(hello[record.header_len..]);
        }
        {
            const handshake_secret = h.transcript.handshakeSecret(shared_key);
            h.cipher = try Cipher.initTls13(h.cipher_suite, handshake_secret, .server);
        }
        try w.record(.change_cipher_spec, &[_]u8{1});
        {
            var hw = try w.writerAdvance(record.header_len);
            try hw.handshakeRecord(.encrypted_extensions, &[_]u8{ 0, 0 });
            h.transcript.update(hw.buffered());
            try h.writeEncrypted(&w, hw.buffered());
        }
        if (opt.client_auth) |_| { // Certificate request
            var hw = try w.writerAdvance(record.header_len);
            try makeCertificateRequest(&hw);
            h.transcript.update(hw.buffered());
            try h.writeEncrypted(&w, hw.buffered());
        }
        if (opt.auth) |auth| {
            const cb = CertificateBuilder{
                .cert_key_pair = auth,
                .transcript = &h.transcript,
                .side = .server,
            };
            { // Certificate
                var hw = try w.writerAdvance(record.header_len);
                try cb.makeCertificate(&hw);
                h.transcript.update(hw.buffered());
                try h.writeEncrypted(&w, hw.buffered());
            }
            { // Certificate verify
                var hw = try w.writerAdvance(record.header_len);
                try cb.makeCertificateVerify(&hw);
                h.transcript.update(hw.buffered());
                try h.writeEncrypted(&w, hw.buffered());
            }
        }
        { // Finished
            var hw = try w.writerAdvance(record.header_len);
            try hw.handshakeRecord(.finished, h.transcript.serverFinishedTls13());
            h.transcript.update(hw.buffered());
            try h.writeEncrypted(&w, hw.buffered());
        }

        h.output.advance(w.buffered().len);
    }

    fn readClientFlight2(h: *Self, opt: Options) !void {
        // buffer for decrypted handshake records
        var cleartext_buffer: [max_cleartext_len]u8 = undefined;
        // cleartext writer
        var cw = Io.Writer.fixed(&cleartext_buffer);

        var handshake_state: proto.Handshake = .finished;
        var crt_parser: CertificateParser = undefined;
        if (opt.client_auth) |client_auth| {
            crt_parser = .{ .root_ca = client_auth.root_ca, .host = "" };
            handshake_state = .certificate;
        }

        outer: while (true) {
            const rec = try Record.read(h.input);
            if (rec.protocol_version != .tls_1_2 and rec.content_type != .alert)
                return error.TlsProtocolVersion;

            switch (rec.content_type) {
                .change_cipher_spec => {
                    if (rec.payload.len != 1) return error.TlsUnexpectedMessage;
                },
                .application_data => {
                    const content_type, const cleartext = try h.cipher.decrypt(cw.unusedCapacitySlice(), rec);
                    cw.advance(cleartext.len);

                    var d = record.Decoder.init(content_type, cw.buffered());
                    try d.expectContentType(.handshake);
                    while (!d.eof()) {
                        const handshake_type = try d.decode(proto.Handshake);
                        const length = try d.decode(u24);

                        if (length > max_cleartext_len)
                            return error.TlsRecordOverflow;
                        if (length > d.rest().len)
                            continue :outer; // fragmented handshake into multiple records

                        defer {
                            h.transcript.update(d.payload[0..d.idx]);
                            _ = cw.consume(d.idx);
                            d = record.Decoder.init(content_type, cw.buffered());
                        }

                        if (handshake_state != handshake_type)
                            return error.TlsUnexpectedMessage;

                        switch (handshake_type) {
                            .certificate => {
                                if (length == 4) {
                                    // got empty certificate message
                                    if (opt.client_auth.?.auth_type == .require)
                                        return error.TlsCertificateRequired;
                                    try d.skip(length);
                                    handshake_state = .finished;
                                } else {
                                    try crt_parser.parseCertificate(&d, .tls_1_3);
                                    handshake_state = .certificate_verify;
                                }
                            },
                            .certificate_verify => {
                                try crt_parser.parseCertificateVerify(&d);
                                crt_parser.verifySignature(h.transcript.clientCertificateVerify()) catch |err| return switch (err) {
                                    error.TlsUnknownSignatureScheme => error.TlsIllegalParameter,
                                    else => error.TlsDecryptError,
                                };
                                handshake_state = .finished;
                            },
                            .finished => {
                                const actual = try d.slice(length);
                                const expected = h.transcript.clientFinishedTls13();
                                if (!mem.eql(u8, expected, actual))
                                    return if (expected.len == actual.len)
                                        error.TlsDecryptError
                                    else
                                        error.TlsDecodeError;
                                return;
                            },
                            else => return error.TlsUnexpectedMessage,
                        }
                    }
                },
                .alert => {
                    var d = record.Decoder.init(rec.content_type, rec.payload);
                    return d.raiseAlert();
                },
                else => return error.TlsUnexpectedMessage,
            }
        }
    }

    /// Write encrypted handshake message into `w` Cleartext and write buffer
    /// `w.unused()` are reusing same buffer. Cleartext is written 5 bytes ahead
    /// (record header len) from w.unused() position to avoid memcopy in the
    /// encrypt. Encrypt will add tls record head in first 5 bytes, encrypt
    /// cleartext and add hmac at end.
    fn writeEncrypted(h: *Self, w: *record.Writer, cleartext: []const u8) !void {
        const ciphertext = try h.cipher.encrypt(w.unused(), .handshake, cleartext);
        w.advance(ciphertext.len);
    }

    fn makeServerHello(h: *Self, w: *record.Writer) ![]const u8 {
        const header_pos = try w.skip(9);

        try w.enumValue(proto.Version.tls_1_2);
        try w.slice(&h.server_random);
        {
            try w.int(u8, h.legacy_session_id.len);
            if (h.legacy_session_id.len > 0) try w.slice(h.legacy_session_id);
        }
        try w.enumValue(h.cipher_suite);
        try w.slice(&[_]u8{0}); // compression method

        const ext_len_pos = try w.skip(2); // extensions length placeholder writer
        { // supported versions extension
            try w.enumValue(proto.Extension.supported_versions);
            try w.int(u16, 2);
            try w.enumValue(proto.Version.tls_1_3);
        }
        { // key share extension
            const key_len: u16 = @intCast(h.server_pub_key.len);
            try w.enumValue(proto.Extension.key_share);
            try w.int(u16, key_len + 4);
            try w.enumValue(h.named_group);
            try w.int(u16, key_len);
            try w.slice(h.server_pub_key);
        }
        var ew = w.writerAt(ext_len_pos);
        try ew.int(u16, w.pos() - ext_len_pos - 2);
        var hw = w.writerAt(header_pos);
        try hw.recordHeader(.handshake, w.pos() - 5);
        try hw.handshakeRecordHeader(.server_hello, w.pos() - 9);

        return w.buffered();
    }

    fn makeCertificateRequest(w: *record.Writer) !void {
        const header_pos = try w.skip(4 + 1 + 2);
        const ext_head = w.pos();
        try w.extension(.signature_algorithms, common.supported_signature_algorithms);
        const ext_len = w.pos() - ext_head;
        var hw = w.writerAt(header_pos);
        try hw.handshakeRecordHeader(.certificate_request, ext_len + 3);
        try hw.int(u8, 0); // certificate request context length = 0
        try hw.int(u16, ext_len); // extensions length
    }

    fn readClientHello(h: *Self, supported_cipher_suites: []const CipherSuite, server_named_groups: []const proto.NamedGroup) !void {
        log.info("readClientHello: starting to parse ClientHello", .{});
        var d = try Record.decoder(h.input);
        if (d.payload.len > max_cleartext_len) return error.TlsRecordOverflow;
        try d.expectContentType(.handshake);
        h.transcript.update(d.payload);

        const handshake_type = try d.decode(proto.Handshake);
        if (handshake_type != .client_hello) return error.TlsUnexpectedMessage;
        _ = try d.decode(u24); // handshake length
        if (try d.decode(proto.Version) != .tls_1_2) return error.TlsProtocolVersion;

        h.client_random = try d.array(32);
        { // legacy session id
            const len = try d.decode(u8);
            h.legacy_session_id = try common.dupe(&h.legacy_session_id_buf, try d.slice(len));
        }
        // Track cipher suite candidates for both TLS versions separately
        // This is needed because we don't know which TLS version will be used yet
        var tls13_cipher: CipherSuite = @enumFromInt(0);
        var tls12_cipher: CipherSuite = @enumFromInt(0);
        { // cipher suites
            const end_idx = try d.decode(u16) + d.idx;

            while (d.idx < end_idx) {
                const cipher_suite = try d.decode(CipherSuite);
                if (cipher_suites.includes(supported_cipher_suites, cipher_suite)) {
                    // Track TLS 1.3 and TLS 1.2 ciphers separately
                    if (cipher_suites.includes(cipher_suites.tls13, cipher_suite)) {
                        if (@intFromEnum(tls13_cipher) == 0) {
                            tls13_cipher = cipher_suite;
                        }
                    } else if (cipher_suites.includes(cipher_suites.tls12, cipher_suite)) {
                        if (@intFromEnum(tls12_cipher) == 0) {
                            tls12_cipher = cipher_suite;
                        }
                    }
                }
            }
            // Must have at least one supported cipher
            if (@intFromEnum(tls13_cipher) == 0 and @intFromEnum(tls12_cipher) == 0)
                return error.TlsNoSupportedCiphers;
        }
        log.info("readClientHello: tls13_cipher={x}, tls12_cipher={x}", .{ @intFromEnum(tls13_cipher), @intFromEnum(tls12_cipher) });
        try d.skip(2); // compression methods

        var key_share_received = false;
        var tls_1_3_supported = false;
        var supported_groups_buf: [16]proto.NamedGroup = undefined;
        var supported_groups_len: usize = 0;

        // extensions
        const extensions_end_idx = try d.decode(u16) + d.idx;
        while (d.idx < extensions_end_idx) {
            const extension_type = try d.decode(proto.Extension);
            const extension_len = try d.decode(u16);

            switch (extension_type) {
                .supported_versions => {
                    const end_idx = try d.decode(u8) + d.idx;
                    while (d.idx < end_idx) {
                        const version = try d.decode(proto.Version);
                        if (version == proto.Version.tls_1_3) {
                            tls_1_3_supported = true;
                        }
                    }
                },
                .key_share => {
                    if (extension_len == 0) return error.TlsDecodeError;
                    key_share_received = true;
                    var selected_named_group_idx = supported_named_groups.len;
                    const end_idx = try d.decode(u16) + d.idx;
                    while (d.idx < end_idx) {
                        const named_group = try d.decode(proto.NamedGroup);
                        switch (@intFromEnum(named_group)) {
                            0x0001...0x0016,
                            0x001a...0x001c,
                            0xff01...0xff02,
                            => return error.TlsIllegalParameter,
                            else => {},
                        }
                        const client_pub_key = try d.slice(try d.decode(u16));
                        for (supported_named_groups, 0..) |supported, idx| {
                            if (named_group == supported and idx < selected_named_group_idx) {
                                h.named_group = named_group;
                                h.client_pub_key = try common.dupe(&h.client_pub_key_buf, client_pub_key);
                                selected_named_group_idx = idx;
                            }
                        }
                    }
                    if (@intFromEnum(h.named_group) == 0)
                        return error.TlsIllegalParameter;
                },
                .supported_groups => {
                    const end_idx = try d.decode(u16) + d.idx;
                    while (d.idx < end_idx) {
                        const named_group = try d.decode(proto.NamedGroup);
                        switch (@intFromEnum(named_group)) {
                            // Deprecated/insecure curves - skip silently for TLS 1.2 compatibility
                            // Some clients (including Apple SecureTransport) may include these
                            0x0001...0x0016,
                            0x001a...0x001c,
                            0xff01...0xff02,
                            => {},
                            else => {
                                // Store supported groups for TLS 1.2 fallback
                                if (supported_groups_len < supported_groups_buf.len) {
                                    supported_groups_buf[supported_groups_len] = named_group;
                                    supported_groups_len += 1;
                                }
                            },
                        }
                    }
                },
                .signature_algorithms => {
                    if (@intFromEnum(h.signature_scheme) == 0) {
                        try d.skip(extension_len);
                    } else {
                        var found = false;
                        const list_len = try d.decode(u16);
                        if (list_len == 0) return error.TlsDecodeError;
                        const end_idx = list_len + d.idx;
                        while (d.idx < end_idx) {
                            const signature_scheme = try d.decode(proto.SignatureScheme);
                            if (signature_scheme == h.signature_scheme) found = true;
                        }
                        if (!found) return error.TlsHandshakeFailure;
                    }
                },
                else => {
                    try d.skip(extension_len);
                },
            }
        }

        // Determine TLS version based on client capabilities
        log.info("readClientHello: tls_1_3_supported={}, key_share_received={}, supported_groups_len={}", .{ tls_1_3_supported, key_share_received, supported_groups_len });
        if (tls_1_3_supported and key_share_received and @intFromEnum(tls13_cipher) != 0) {
            // TLS 1.3 handshake - requires TLS 1.3 cipher
            h.tls_version = .tls_1_3;
            h.cipher_suite = tls13_cipher;
            if (@intFromEnum(h.named_group) == 0) return error.TlsIllegalParameter;
        } else if (@intFromEnum(tls12_cipher) != 0) {
            // TLS 1.2 handshake - need to select named group from supported_groups
            h.tls_version = .tls_1_2;
            h.cipher_suite = tls12_cipher;
            log.info("readClientHello: TLS 1.2 path, cipher keyExchange={}", .{h.cipher_suite.keyExchange()});

            // For TLS 1.2 ECDHE, select a named group from supported_groups extension
            if (h.cipher_suite.keyExchange() == .ecdhe) {
                // If no supported_groups extension was received, default to common curves
                // per RFC 8422 - most TLS 1.2 clients support secp256r1/secp384r1
                const client_groups = if (supported_groups_len > 0)
                    supported_groups_buf[0..supported_groups_len]
                else
                    &[_]proto.NamedGroup{ .secp256r1, .secp384r1 };

                log.info("readClientHello: client_groups count={}, server_named_groups count={}", .{ client_groups.len, server_named_groups.len });

                // Find first matching named group between server and client
                for (server_named_groups) |server_ng| {
                    for (client_groups) |client_ng| {
                        if (server_ng == client_ng) {
                            h.named_group = server_ng;
                            break;
                        }
                    }
                    if (@intFromEnum(h.named_group) != 0) break;
                }
                if (@intFromEnum(h.named_group) == 0) return error.TlsIllegalParameter;
            }
            log.info("TLS 1.2 readClientHello: selected named_group={x}", .{@intFromEnum(h.named_group)});
        } else {
            // No compatible cipher suite found
            return error.TlsNoSupportedCiphers;
        }
        log.info("readClientHello complete: tls_version={}, cipher_suite={x}, named_group={x}", .{ h.tls_version, @intFromEnum(h.cipher_suite), @intFromEnum(h.named_group) });
    }
};

const testing = std.testing;
const data13 = @import("testdata/tls13.zig");
const testu = @import("testu.zig");

test "read client hello" {
    var reader: Io.Reader = .fixed(&data13.client_hello);
    var h: Handshake = .{
        .input = &reader,
        .output = undefined,
    };
    h.signature_scheme = .ecdsa_secp521r1_sha512; // this must be supported in signature_algorithms extension
    try h.readClientHello(cipher_suites.tls13, &[_]proto.NamedGroup{ .x25519, .secp256r1, .secp384r1 });

    try testing.expectEqual(CipherSuite.AES_256_GCM_SHA384, h.cipher_suite);
    try testing.expectEqual(.x25519, h.named_group);
    try testing.expectEqualSlices(u8, &data13.client_random, &h.client_random);
    try testing.expectEqualSlices(u8, &data13.client_public_key, h.client_pub_key);
}

test "make server hello" {
    var h: Handshake = .{ .input = undefined, .output = undefined };

    h.cipher_suite = .AES_256_GCM_SHA384;
    testu.fillFrom(&h.server_random, 0);
    testu.fillFrom(&h.server_pub_key_buf, 0x20);
    h.named_group = .x25519;
    h.server_pub_key = h.server_pub_key_buf[0..32];

    const expected = &testu.hexToBytes(
        \\ 16 03 03 00 5a 02 00 00 56
        \\ 03 03
        \\ 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        \\ 00
        \\ 13 02 00
        \\ 00 2e 00 2b 00 02 03 04
        \\ 00 33 00 24 00 1d 00 20
        \\ 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
    );

    var buffer: [128]u8 = undefined;
    var w: record.Writer = .init(&buffer);
    const actual = try h.makeServerHello(&w);
    try testing.expectEqual(95, actual.len);
    try testing.expectEqualSlices(u8, expected, actual);
}

test "make certificate request" {
    var buffer: [32]u8 = undefined;

    const expected = testu.hexToBytes("0d 00 00 1b" ++ // handshake header
        "00 00 18" ++ // extension length
        "00 0d" ++ // signature algorithms extension
        "00 14" ++ // extension length
        "00 12" ++ // list length 6 * 2 bytes
        "04 03 05 03 08 04 08 05 08 06 08 07 02 01 04 01 05 01" // signature schemes
    );

    var w: record.Writer = .init(&buffer);
    try Handshake.makeCertificateRequest(&w);
    try testing.expectEqualSlices(u8, &expected, w.buffered());
}

pub const NonBlock = struct {
    const Self = @This();

    // inner sync handshake
    inner: Handshake = undefined,
    opt: Options = undefined,
    state: State = undefined,

    const State = enum {
        init,
        client_flight_1,
        server_flight,
        client_flight_2,

        fn next(self: *State) void {
            self.* = @enumFromInt(@intFromEnum(self.*) + 1);
        }
    };

    pub fn init(opt: Options) Self {
        var inner: Handshake = .{
            .input = undefined,
            .output = undefined,
        };
        inner.initKeys(opt);
        return .{
            .opt = opt,
            .inner = inner,
            .state = .init,
        };
    }

    fn recv(self: *Self) !void {
        const prev: Transcript = self.inner.transcript;
        errdefer self.inner.transcript = prev;

        switch (self.state) {
            .init => {
                try self.inner.clientFlight1(self.opt);
                self.state.next();
            },
            .server_flight => {
                // Use appropriate client flight based on TLS version
                if (self.inner.tls_version == .tls_1_2) {
                    try self.inner.clientFlight2Tls12(self.opt);
                } else {
                    try self.inner.clientFlight2(self.opt);
                }
                self.state.next();
            },
            else => return,
        }
    }

    /// True when handshake is successfully finished
    pub fn done(self: Self) bool {
        return self.state == .client_flight_2;
    }

    /// Runs next handshake step.
    pub fn run(
        self: *Self,
        /// Data received from the peer
        recv_buf: []const u8,
        /// Scratch buffer where data to be sent to the peer will be prepared
        send_buf: []u8,
    ) !struct {
        /// Number of bytes consumed from recv_buf
        recv_pos: usize,
        /// Number of bytes prepared in send_buf
        send_pos: usize,
        /// Unused part of the recv_buf,
        unused_recv: []const u8,
        /// Part of the send_buf that should be sent to the peer
        send: []const u8,
    } {
        if (self.done()) return .{
            .recv_pos = 0,
            .send_pos = 0,
            .unused_recv = &.{},
            .send = &.{},
        };

        var reader: Io.Reader = .fixed(recv_buf);
        self.inner.input = &reader;
        var writer: Io.Writer = .fixed(send_buf);
        self.inner.output = &writer;

        var recv_pos: usize = 0;
        out: switch (self.state) {
            .init, .server_flight => {
                self.recv() catch |err| switch (err) {
                    error.EndOfStream, error.InputBufferUndersize => {
                        return .{
                            .recv_pos = 0,
                            .send_pos = 0,
                            .unused_recv = recv_buf,
                            .send = &.{},
                        };
                    },
                    else => return err,
                };
                recv_pos = reader.seek;
                continue :out self.state;
            },
            .client_flight_1 => {
                if (recv_buf.ptr == send_buf.ptr and recv_pos != recv_buf.len) {
                    // recv buffer is fully consumed, same buffer can be used for write
                    return error.TlsUnexpectedMessage;
                }
                // Use appropriate server flight based on TLS version
                if (self.inner.tls_version == .tls_1_2) {
                    try self.inner.serverFlightTls12(self.opt);
                } else {
                    try self.inner.serverFlight(self.opt);
                }
                self.state.next();
            },
            .client_flight_2 => {
                // done
            },
        }

        log.info("NonBlock run() returning: recv_pos={d}, writer.end={d}, send.len={d}", .{ recv_pos, writer.end, writer.buffered().len });
        return .{
            .recv_pos = recv_pos,
            .send_pos = writer.end,
            .unused_recv = recv_buf[recv_pos..],
            .send = writer.buffered(),
        };
    }

    /// Cipher produced in handshake, null until successful handshake.
    pub fn cipher(self: Self) ?Cipher {
        return if (self.done()) self.inner.cipher else null;
    }
};
