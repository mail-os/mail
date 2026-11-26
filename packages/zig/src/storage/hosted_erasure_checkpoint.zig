//! Sign redacted lifecycle evidence for a recovery host without the original SQLite database.
const std = @import("std");
const restore = @import("hosted_erasure_restore.zig");
const preflight = @import("hosted_erasure_preflight.zig");
const refs = @import("message_refs.zig");
const clock = @import("../core/time_compat.zig");

const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const purpose = "mail.erasure.authority.v1";
const Payload = struct {
    purpose: []const u8 = purpose,
    scope: []const u8,
    state: restore.Snapshot,
};
pub const Document = struct {
    payload: Payload,
    public_key: restore.Digest,
    signature: [Ed25519.Signature.encoded_length * 2]u8,
};

pub const Pin = struct {
    scope: []const u8,
    public_key: []const u8,
    sha256: []const u8,
    not_before: i64,
};

fn read(a: Allocator, io: std.Io, path: []const u8, limit: u64, comptime private: bool) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false, .allow_directory = false });
    defer file.close(io);
    const info = try file.stat(io);
    if (info.kind != .file or info.size == 0 or info.size > limit) return error.InvalidErasureCheckpointFile;
    if (private and info.permissions.toMode() & 0o077 != 0) return error.ErasureCheckpointKeyNotPrivate;
    const bytes = try a.alloc(u8, @intCast(info.size));
    errdefer a.free(bytes);
    var input_buffer: [4096]u8 = undefined;
    var input = file.reader(io, &input_buffer);
    try input.interface.readSliceAll(bytes);
    return bytes;
}

fn decode(comptime length: usize, value: []const u8) ![length]u8 {
    if (value.len != length * 2) return error.InvalidErasureCheckpointEncoding;
    var result: [length]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidErasureCheckpointEncoding;
    return result;
}

pub fn seal(a: Allocator, io: std.Io, authority: []const u8, scope: []const u8, seed_path: []const u8) !Document {
    if (!preflight.validCaseReference(scope)) return error.InvalidErasureCheckpointScope;
    const raw = try read(a, io, seed_path, 128, true);
    defer std.crypto.secureZero(u8, raw);
    var seed = try decode(Ed25519.KeyPair.seed_length, std.mem.trim(u8, raw, &std.ascii.whitespace));
    defer std.crypto.secureZero(u8, &seed);
    var key = try Ed25519.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key.secret_key));

    const payload: Payload = .{ .scope = scope, .state = try restore.capture(a, authority) };
    const bytes = try std.json.Stringify.valueAlloc(a, payload, .{});
    var noise: [Ed25519.noise_length]u8 = undefined;
    io.random(&noise);
    const signature = try key.sign(bytes, noise);
    return .{
        .payload = payload,
        .public_key = std.fmt.bytesToHex(key.public_key.toBytes(), .lower),
        .signature = std.fmt.bytesToHex(signature.toBytes(), .lower),
    };
}

pub fn verify(a: Allocator, io: std.Io, path: []const u8, pin: Pin, restored_db: []const u8, maildir: []const u8, dav: ?[]const u8) !restore.Receipt {
    if (!preflight.validCaseReference(pin.scope) or pin.not_before < 1) return error.InvalidErasureCheckpointPin;
    const bytes = try read(a, io, path, 64 * 1024 * 1024, false);
    const digest = refs.digest(bytes);
    if (!std.mem.eql(u8, &digest, pin.sha256)) return error.ErasureCheckpointPinMismatch;
    const document = try std.json.parseFromSliceLeaky(Document, a, bytes, .{});
    if (!std.mem.eql(u8, document.payload.purpose, purpose) or !std.mem.eql(u8, document.payload.scope, pin.scope))
        return error.InvalidErasureCheckpointScope;
    if (!std.mem.eql(u8, &document.public_key, pin.public_key)) return error.ErasureCheckpointKeyMismatch;
    const key = try Ed25519.PublicKey.fromBytes(try decode(Ed25519.PublicKey.encoded_length, pin.public_key));
    const signature = Ed25519.Signature.fromBytes(try decode(Ed25519.Signature.encoded_length, &document.signature));
    const message = try std.json.Stringify.valueAlloc(a, document.payload, .{});
    signature.verifyStrict(message, key) catch return error.InvalidErasureCheckpointSignature;
    const state = document.payload.state;
    if (state.observed_at < pin.not_before or state.observed_at > clock.timestamp()) return error.ErasureCheckpointStale;

    var receipt = try restore.verifySnapshot(a, io, state, restored_db, maildir, dav);
    receipt.source = "signed_erasure_checkpoint";
    receipt.checkpoint_sha256 = digest;
    return receipt;
}
