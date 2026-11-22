const std = @import("std");

pub fn validFilename(name: []const u8) bool {
    if (name.len == 0 or name.len > 255 or !std.unicode.utf8ValidateSlice(name)) return false;
    for (name) |byte| if (byte < 0x20 or byte == 0x7f or byte == '/' or byte == '\\') return false;
    return true;
}

pub fn validContentType(value: []const u8) bool {
    if (value.len == 0 or value.len > 100 or std.mem.indexOfScalar(u8, value, '/') == null) return false;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '/' and byte != '-' and byte != '.' and byte != '+') return false;
    return true;
}
