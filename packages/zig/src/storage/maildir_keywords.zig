//! Maildir keywords are lowercase flag letters scoped to one physical Maildir.
//! The dovecot-keywords file maps those letters to permanent IMAP atoms.
const std = @import("std");
const builtin = @import("builtin");
const durable_maildir = @import("../core/durable_maildir.zig");
const fs_compat = @import("../core/fs_compat.zig");
const io_compat = @import("../core/io_compat.zig");

fn getIo() std.Io {
    return if (builtin.is_test) std.testing.io else io_compat.getIo();
}

pub const count = 26;
pub const Bits = u26;
pub const mapping_name = "dovecot-keywords";
pub const suffix_capacity = ":2,".len + 5 + count;
pub const max_name_len = 255;

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;
    for (name) |byte| {
        if (byte <= ' ' or byte >= 127 or std.mem.indexOfScalar(u8, "(){}%*\"\\]", byte) != null) return false;
    }
    return true;
}

pub fn fromFilename(name: []const u8) Bits {
    const index = std.mem.indexOf(u8, name, ":2,") orelse return 0;
    var bits: Bits = 0;
    for (name[index + 3 ..]) |letter| {
        if (letter >= 'a' and letter <= 'z') bits |= bit(letter - 'a');
    }
    return bits;
}

pub fn writeLetters(writer: anytype, bits: Bits) !void {
    for (0..count) |index| {
        if (bits & bit(index) != 0) try writer.writeAll(&.{@as(u8, @intCast(index)) + 'a'});
    }
}

pub fn withBits(a: std.mem.Allocator, filename: []const u8, bits: Bits) ![]const u8 {
    const index = std.mem.indexOf(u8, filename, ":2,") orelse return error.InvalidMaildirKeywordSuffix;
    var bytes: std.Io.Writer.Allocating = .init(a);
    errdefer bytes.deinit();
    try bytes.writer.writeAll(filename[0 .. index + 3]);
    for (filename[index + 3 ..]) |letter| {
        if (letter < 'a' or letter > 'z') try bytes.writer.writeAll(&.{letter});
    }
    try writeLetters(&bytes.writer, bits);
    return bytes.toOwnedSlice();
}

fn bit(index: usize) Bits {
    return @as(Bits, 1) << @intCast(index);
}

pub const Names = struct {
    slots: [count]?[]const u8 = @splat(null),
    // Some Maildir consumers store additional keywords in their private index.
    // Leave those mapping entries intact when extending a pre-existing file.
    extra: std.ArrayList(u8) = .empty,
    changed: bool = false,

    pub fn parse(a: std.mem.Allocator, text: []const u8) !Names {
        var result: Names = .{};
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r");
            var parts = std.mem.tokenizeAny(u8, line, " \t");
            const index = std.fmt.parseUnsigned(usize, parts.next() orelse return error.InvalidKeywordMapping, 10) catch
                return error.InvalidKeywordMapping;
            const name = parts.next() orelse return error.InvalidKeywordMapping;
            if (!validName(name) or parts.next() != null) return error.InvalidKeywordMapping;
            if (index >= count) {
                try result.extra.appendSlice(a, line);
                try result.extra.append(a, '\n');
                continue;
            }
            if (result.slots[index] != null or result.find(name) != 0) return error.InvalidKeywordMapping;
            result.slots[index] = name;
        }
        return result;
    }

    pub fn find(self: *const Names, name: []const u8) Bits {
        for (self.slots, 0..) |slot, index| {
            if (slot) |existing| {
                if (std.ascii.eqlIgnoreCase(existing, name)) return bit(index);
            }
        }
        return 0;
    }

    pub fn hasCapacity(self: *const Names) bool {
        for (self.slots) |slot| {
            if (slot == null) return true;
        }
        return false;
    }

    pub fn insert(self: *Names, name: []const u8) !Bits {
        if (!validName(name)) return error.InvalidKeyword;
        const existing = self.find(name);
        if (existing != 0) return existing;
        for (&self.slots, 0..) |*slot, index| {
            if (slot.* != null) continue;
            slot.* = name;
            self.changed = true;
            return bit(index);
        }
        return error.KeywordLimit;
    }

    pub fn translate(self: *Names, source: *const Names, bits: Bits) !Bits {
        var result: Bits = 0;
        for (source.slots, 0..) |slot, index| {
            if (bits & bit(index) == 0) continue;
            result |= try self.insert(slot orelse return error.UnknownMaildirKeyword);
        }
        return result;
    }

    pub fn encode(self: *const Names, a: std.mem.Allocator) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(a);
        for (self.slots, 0..) |slot, index| {
            if (slot) |name| try out.print(a, "{d} {s}\n", .{ index, name });
        }
        try out.appendSlice(a, self.extra.items);
        return out.toOwnedSlice(a);
    }

    pub fn writeImap(self: *const Names, writer: anytype, bits: Bits, separated: bool) !void {
        var space = separated;
        for (self.slots, 0..) |slot, index| {
            if (bits & bit(index) == 0) continue;
            if (slot) |name| {
                if (space) try writer.writeAll(" ");
                try writer.writeAll(name);
                space = true;
            }
        }
    }

    pub fn defined(self: *const Names) Bits {
        var result: Bits = 0;
        for (self.slots, 0..) |slot, index| {
            if (slot != null) result |= bit(index);
        }
        return result;
    }
};

pub fn load(a: std.mem.Allocator, io: std.Io, folder: std.Io.Dir) !Names {
    const raw = folder.readFileAlloc(io, mapping_name, a, .limited(64 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    return Names.parse(a, raw);
}

/// Mediate access through the physical directory so the visible folder
/// symlink and Maildir++ cur/new slots agree on one map.
pub fn rootFor(a: std.mem.Allocator, message_dir: []const u8) ![]const u8 {
    const physical = try fs_compat.cwd().realpathAlloc(a, message_dir);
    const slot = std.fs.path.basename(physical);
    if (std.mem.eql(u8, slot, "new") or std.mem.eql(u8, slot, "cur"))
        return std.fs.path.dirname(physical) orelse return error.InvalidMaildirPath;
    return physical;
}

pub const Mapping = struct {
    root: []const u8,
    names: Names,

    pub fn open(a: std.mem.Allocator, message_dir: []const u8) !Mapping {
        return openRoot(a, try rootFor(a, message_dir));
    }

    pub fn openRoot(a: std.mem.Allocator, root: []const u8) !Mapping {
        const io = getIo();
        var folder = try std.Io.Dir.cwd().openDir(io, root, .{});
        defer folder.close(io);
        return .{ .root = root, .names = try load(a, io, folder) };
    }

    /// Serialize changes under the mailbox mutation lock. Publish the mapping
    /// before a message references any newly assigned letters.
    pub fn save(self: *const Mapping, a: std.mem.Allocator) !void {
        if (!self.names.changed) return;
        const io = getIo();
        var folder = try std.Io.Dir.cwd().openDir(io, self.root, .{});
        defer folder.close(io);
        var file = try folder.createFileAtomic(io, mapping_name, .{ .replace = true, .permissions = .fromMode(0o600) });
        defer file.deinit(io);
        try file.file.writeStreamingAll(io, try self.names.encode(a));
        try file.file.sync(io);
        try file.replace(io);
        try durable_maildir.syncDirectory(a, self.root);
    }
};

/// Translate flag letters for a destination in another physical Maildir.
/// Call with the mailbox mutation lock held and both directories present.
pub fn transferredBits(a: std.mem.Allocator, source: []const u8, destination: []const u8, bits: Bits) !Bits {
    if (bits == 0) return 0;
    const source_root = try rootFor(a, source);
    const target_root = try rootFor(a, destination);
    if (std.mem.eql(u8, source_root, target_root)) return bits;
    const source_names = try Mapping.openRoot(a, source_root);
    var target = try Mapping.openRoot(a, target_root);
    const translated = try target.names.translate(&source_names.names, bits);
    try target.save(a);
    return translated;
}
