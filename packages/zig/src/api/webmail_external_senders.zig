//! Operator-approved provider grants. Read a fresh snapshot at review,
//! queueing, and dispatch so removing a grant also revokes queued mail.
const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const time = @import("../core/time_compat.zig");
const submission = @import("../delivery/submission.zig");
const smtp_provider = @import("../delivery/smtp_provider.zig");
const team_store = @import("../storage/team_store.zig");
const database = @import("../storage/database.zig");
const store = @import("webmail_store.zig");

pub const prefix = "external-";
const proof_kind = "external-sender-proof";
const proof_lifetime = 30 * 60;
const Proof = struct {
    grant: []const u8,
    generation: []const u8,
    challenge: []const u8 = "",
    requested: i64 = 0,
};
pub const Status = struct {
    id: []const u8,
    address: []const u8,
    state: []const u8,
};
pub const Grant = struct {
    id: []const u8,
    mailbox: []const u8,
    address: []const u8,
    host: []const u8,
    port: u16 = 587,
    username: []const u8,
    password_file: []const u8,
    ca_file: ?[]const u8 = null,

    pub fn valid(self: Grant) bool {
        return validId(self.id) and submission.isSafeLocalPart(self.mailbox) and submission.isSafeAddress(self.address) and
            std.fs.path.isAbsolute(self.password_file) and self.provider("validation").valid();
    }

    pub fn provider(self: Grant, password: []const u8) smtp_provider.Config {
        return .{ .host = self.host, .port = self.port, .username = self.username, .password = password, .ca_file = self.ca_file };
    }

    // Keep the approved account, From address, and provider binding together.
    // A credential rotation at that endpoint does not invalidate pending mail.
    pub fn binding(self: Grant, a: std.mem.Allocator) ![]const u8 {
        const input = try std.json.Stringify.valueAlloc(a, .{
            .id = self.id,
            .mailbox = self.mailbox,
            .address = self.address,
            .host = self.host,
            .port = self.port,
            .username = self.username,
        }, .{});
        var bytes: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(input, &bytes, .{});
        const digest = std.fmt.bytesToHex(bytes, .lower);
        return a.dupe(u8, &digest);
    }
};

pub fn validId(id: []const u8) bool {
    if (!std.mem.startsWith(u8, id, prefix) or id.len <= prefix.len or id.len > 48) return false;
    for (id[prefix.len..]) |byte| {
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '-') return false;
    }
    return true;
}

pub fn readFile(a: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    if (!std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null) return error.ExternalSenderUnavailable;
    const io = io_compat.getIo();
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return error.ExternalSenderUnavailable;
    defer file.close(io);
    const length = file.length(io) catch return error.ExternalSenderUnavailable;
    if (length == 0 or length > limit) return error.ExternalSenderUnavailable;
    const data = time.readFileToEnd(a, file, limit + 1) catch return error.ExternalSenderUnavailable;
    if (data.len != length) return error.ExternalSenderUnavailable;
    return data;
}

fn load(a: std.mem.Allocator, path: ?[]const u8) ![]const Grant {
    const config = path orelse return &.{};
    const data = try readFile(a, config, 64 * 1024);
    const entries = std.json.parseFromSliceLeaky([]const Grant, a, data, .{}) catch return error.ExternalSenderUnavailable;
    for (entries, 0..) |grant, index| {
        if (!grant.valid()) return error.ExternalSenderUnavailable;
        for (entries[0..index]) |prior| {
            if (std.mem.eql(u8, grant.mailbox, prior.mailbox) and
                (std.mem.eql(u8, grant.id, prior.id) or std.ascii.eqlIgnoreCase(grant.address, prior.address)))
                return error.ExternalSenderUnavailable;
        }
    }
    return entries;
}

pub fn find(a: std.mem.Allocator, path: ?[]const u8, user: []const u8, id: []const u8) !Grant {
    if (!validId(id)) return error.ExternalSenderUnavailable;
    for (try load(a, path)) |grant| {
        if (std.mem.eql(u8, grant.mailbox, user) and std.mem.eql(u8, grant.id, id)) return grant;
    }
    return error.ExternalSenderUnavailable;
}

fn proofRow(a: std.mem.Allocator, db: *database.Database, grant: Grant) !?store.Record {
    return store.get(a, db, grant.mailbox, proof_kind, grant.id) catch |err| switch (err) {
        store.StoreError.NotFound => null,
        else => return err,
    };
}

fn proofData(a: std.mem.Allocator, row: store.Record) !Proof {
    return std.json.parseFromSliceLeaky(Proof, a, row.payload, .{});
}

pub fn verifiedBinding(a: std.mem.Allocator, db: *database.Database, grant: Grant) !?[]const u8 {
    const row = (try proofRow(a, db, grant)) orelse return null;
    if (!std.mem.eql(u8, row.state, "verified")) return null;
    const proof = try proofData(a, row);
    if (!std.mem.eql(u8, proof.grant, try grant.binding(a))) return null;
    return proof.generation;
}

pub fn choices(a: std.mem.Allocator, db: *database.Database, path: ?[]const u8, user: []const u8, target: *std.ArrayList(team_store.SenderIdentity)) !void {
    for (try load(a, path)) |grant| {
        if (!std.mem.eql(u8, grant.mailbox, user) or try verifiedBinding(a, db, grant) == null) continue;
        try target.append(a, .{ .id = grant.id, .address = grant.address });
    }
}

pub fn statuses(a: std.mem.Allocator, db: *database.Database, path: ?[]const u8, user: []const u8, now: i64) ![]Status {
    var result: std.ArrayList(Status) = .empty;
    for (try load(a, path)) |grant| {
        if (!std.mem.eql(u8, grant.mailbox, user)) continue;
        var state: []const u8 = "unverified";
        if (try proofRow(a, db, grant)) |row| {
            const proof = try proofData(a, row);
            if (std.mem.eql(u8, proof.grant, try grant.binding(a)) and (row.expires_at == 0 or row.expires_at > now)) state = row.state;
        }
        try result.append(a, .{ .id = grant.id, .address = grant.address, .state = state });
    }
    return result.toOwnedSlice(a);
}

fn codeHash(a: std.mem.Allocator, code: []const u8) ![]const u8 {
    const normalized = try std.ascii.allocLowerString(a, code);
    var bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(normalized, &bytes, .{});
    const hex = std.fmt.bytesToHex(bytes, .lower);
    return a.dupe(u8, &hex);
}

pub fn requestProof(a: std.mem.Allocator, db: *database.Database, grant: Grant, now: i64) ![]const u8 {
    const binding = try grant.binding(a);
    const existing = try proofRow(a, db, grant);
    if (existing) |row| {
        const proof = try proofData(a, row);
        if (std.mem.eql(u8, proof.grant, binding)) {
            if (std.mem.eql(u8, row.state, "verified")) return error.ExternalSenderAlreadyVerified;
            if (now - proof.requested < 60) return error.ExternalSenderRateLimited;
        }
    }
    const code = try store.newId(a);
    const payload = try std.json.Stringify.valueAlloc(a, Proof{
        .grant = binding,
        .generation = "",
        .challenge = try codeHash(a, code),
        .requested = now,
    }, .{});
    _ = try store.put(db, .{
        .username = grant.mailbox,
        .kind = proof_kind,
        .id = grant.id,
        .payload = payload,
        .state = "pending",
        .revision = 0,
        .due_at = 0,
        .expires_at = now + proof_lifetime,
    }, if (existing) |row| row.revision else 0);
    return code;
}

pub fn confirmProof(a: std.mem.Allocator, db: *database.Database, grant: Grant, input: []const u8, now: i64) !void {
    const code = std.mem.trim(u8, input, " \t\r\n");
    if (code.len != 32) return error.InvalidExternalSenderCode;
    for (code) |byte| if (!std.ascii.isHex(byte)) return error.InvalidExternalSenderCode;
    var row = (try proofRow(a, db, grant)) orelse return error.InvalidExternalSenderCode;
    if (!std.mem.eql(u8, row.state, "pending") or row.expires_at <= now) return error.InvalidExternalSenderCode;
    var proof = try proofData(a, row);
    const supplied = try codeHash(a, code);
    if (!std.mem.eql(u8, proof.grant, try grant.binding(a)) or proof.challenge.len != 64 or
        !std.crypto.timing_safe.eql([64]u8, proof.challenge[0..64].*, supplied[0..64].*))
        return error.InvalidExternalSenderCode;
    proof.challenge = "";
    proof.generation = try store.newId(a);
    row.payload = try std.json.Stringify.valueAlloc(a, proof, .{});
    row.state = "verified";
    row.expires_at = 0;
    _ = try store.put(db, row, row.revision);
}

pub fn revokeProof(a: std.mem.Allocator, db: *database.Database, grant: Grant, now: i64) !void {
    var row = (try proofRow(a, db, grant)) orelse return;
    var proof = try proofData(a, row);
    proof.challenge = "";
    proof.generation = "";
    row.payload = try std.json.Stringify.valueAlloc(a, proof, .{});
    row.state = "unverified";
    row.expires_at = now + proof_lifetime;
    _ = try store.put(db, row, row.revision);
}
