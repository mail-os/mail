const std = @import("std");
const database = @import("../storage/database.zig");
const store = @import("webmail_store.zig");

pub const Entry = struct { id: []const u8, name: []const u8, text: []const u8 };
pub const Library = struct {
    revision: i64 = 0,
    snippets: []const Entry = &.{},
    signatures: []const Entry = &.{},
    defaultSignatureId: ?[]const u8 = null,
};
pub const max_bytes = 128 * 1024;
const kind = "preferences";
const id = "compose-library";

pub fn load(a: std.mem.Allocator, db: *database.Database, user: []const u8) !Library {
    const row = store.get(a, db, user, kind, id) catch |err| {
        if (err == store.StoreError.NotFound) return .{};
        return err;
    };
    var library = try std.json.parseFromSliceLeaky(Library, a, row.payload, .{ .ignore_unknown_fields = true });
    library.revision = row.revision;
    return library;
}

fn validEntries(entries: []const Entry, max_text: usize) bool {
    if (entries.len > 32) return false;
    for (entries, 0..) |entry, index| {
        if (!store.validId(entry.id)) return false;
        for (entries[0..index]) |prior| {
            if (std.mem.eql(u8, prior.id, entry.id)) return false;
        }
        if (entry.name.len > 80 or !std.unicode.utf8ValidateSlice(entry.name) or
            std.mem.trim(u8, entry.name, " ").len == 0) return false;
        for (entry.name) |byte| {
            if (byte < 32 or byte == 127) return false;
        }
        if (entry.text.len > max_text or !std.unicode.utf8ValidateSlice(entry.text) or
            std.mem.trim(u8, entry.text, " \t\r\n").len == 0) return false;
        for (entry.text) |byte| {
            if ((byte < 32 and byte != '\t' and byte != '\r' and byte != '\n') or byte == 127)
                return false;
        }
    }
    return true;
}

pub fn save(a: std.mem.Allocator, db: *database.Database, user: []const u8, library: Library) !Library {
    if (library.revision < 0 or !validEntries(library.snippets, 8192) or !validEntries(library.signatures, 4096))
        return error.InvalidComposeLibrary;
    if (library.defaultSignatureId) |default| {
        for (library.signatures) |entry| {
            if (std.mem.eql(u8, entry.id, default)) break;
        } else return error.InvalidComposeLibrary;
    }
    const payload = try std.json.Stringify.valueAlloc(a, library, .{});
    if (payload.len > max_bytes) return error.InvalidComposeLibrary;
    var saved = library;
    saved.revision = try store.put(db, .{
        .username = user,
        .kind = kind,
        .id = id,
        .payload = payload,
        .state = "saved",
        .revision = library.revision,
        .due_at = 0,
        .expires_at = 0,
    }, library.revision);
    return saved;
}
