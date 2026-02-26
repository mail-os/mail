const std = @import("std");
const time_compat = @import("time_compat.zig");
const io_compat = @import("io_compat.zig");

/// Simple TOML parser for configuration files
/// Supports basic TOML features needed for server configuration:
/// - Key-value pairs
/// - Sections (tables)
/// - String, integer, boolean, and float values
/// - Comments (# style)
pub const TomlParser = struct {
    allocator: std.mem.Allocator,
    current_section: ?[]const u8,

    pub const Value = union(enum) {
        string: []const u8,
        integer: i64,
        float: f64,
        boolean: bool,

        pub fn asString(self: Value) ?[]const u8 {
            return switch (self) {
                .string => |s| s,
                else => null,
            };
        }

        pub fn asInt(self: Value) ?i64 {
            return switch (self) {
                .integer => |i| i,
                else => null,
            };
        }

        pub fn asBool(self: Value) ?bool {
            return switch (self) {
                .boolean => |b| b,
                else => null,
            };
        }

        pub fn asFloat(self: Value) ?f64 {
            return switch (self) {
                .float => |f| f,
                else => null,
            };
        }
    };

    pub const TomlTable = struct {
        values: std.StringHashMap(Value),
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) TomlTable {
            return .{
                .values = std.StringHashMap(Value).init(allocator),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *TomlTable) void {
            var it = self.values.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                if (entry.value_ptr.* == .string) {
                    self.allocator.free(entry.value_ptr.string);
                }
            }
            self.values.deinit();
        }

        pub fn get(self: *const TomlTable, key: []const u8) ?Value {
            return self.values.get(key);
        }

        pub fn getString(self: *const TomlTable, key: []const u8) ?[]const u8 {
            if (self.values.get(key)) |val| {
                return val.asString();
            }
            return null;
        }

        pub fn getInt(self: *const TomlTable, key: []const u8) ?i64 {
            if (self.values.get(key)) |val| {
                return val.asInt();
            }
            return null;
        }

        pub fn getBool(self: *const TomlTable, key: []const u8) ?bool {
            if (self.values.get(key)) |val| {
                return val.asBool();
            }
            return null;
        }
    };

    pub const TomlDocument = struct {
        sections: std.StringHashMap(TomlTable),
        root: TomlTable,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) TomlDocument {
            return .{
                .sections = std.StringHashMap(TomlTable).init(allocator),
                .root = TomlTable.init(allocator),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *TomlDocument) void {
            var it = self.sections.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit();
            }
            self.sections.deinit();
            self.root.deinit();
        }

        pub fn getSection(self: *const TomlDocument, name: []const u8) ?*const TomlTable {
            if (self.sections.getPtr(name)) |table| {
                return table;
            }
            return null;
        }

        pub fn getRoot(self: *const TomlDocument) *const TomlTable {
            return &self.root;
        }
    };

    pub fn init(allocator: std.mem.Allocator) TomlParser {
        return .{
            .allocator = allocator,
            .current_section = null,
        };
    }

    /// Parse TOML content from a string
    pub fn parse(self: *TomlParser, content: []const u8) !TomlDocument {
        var doc = TomlDocument.init(self.allocator);
        errdefer doc.deinit();

        var lines = std.mem.splitScalar(u8, content, '\n');

        while (lines.next()) |raw_line| {
            // Remove carriage return if present (Windows line endings)
            const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
                raw_line[0 .. raw_line.len - 1]
            else
                raw_line;

            const trimmed = std.mem.trim(u8, line, " \t");

            // Skip empty lines and comments
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Check for section header [section]
            if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                const section_name = trimmed[1 .. trimmed.len - 1];
                self.current_section = try self.allocator.dupe(u8, section_name);

                const table = TomlTable.init(self.allocator);
                try doc.sections.put(self.current_section.?, table);
                continue;
            }

            // Parse key = value
            if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
                const value_str = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

                const key_copy = try self.allocator.dupe(u8, key);
                const value = try self.parseValue(value_str);

                if (self.current_section) |section| {
                    if (doc.sections.getPtr(section)) |table| {
                        try table.values.put(key_copy, value);
                    }
                } else {
                    try doc.root.values.put(key_copy, value);
                }
            }
        }

        return doc;
    }

    /// Parse TOML content from a file
    pub fn parseFile(self: *TomlParser, path: []const u8) !TomlDocument {
        const io = io_compat.getIo();
        const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| {
            return switch (err) {
                error.FileNotFound => error.ConfigFileNotFound,
                else => err,
            };
        };
        defer file.close(io);

        const content = try time_compat.readFileToEnd(self.allocator, file, 1024 * 1024); // 1MB max
        defer self.allocator.free(content);

        return try self.parse(content);
    }

    fn parseValue(self: *TomlParser, value_str: []const u8) !Value {
        // Boolean
        if (std.mem.eql(u8, value_str, "true")) {
            return Value{ .boolean = true };
        }
        if (std.mem.eql(u8, value_str, "false")) {
            return Value{ .boolean = false };
        }

        // Quoted string
        if (value_str.len >= 2) {
            if ((value_str[0] == '"' and value_str[value_str.len - 1] == '"') or
                (value_str[0] == '\'' and value_str[value_str.len - 1] == '\''))
            {
                const unquoted = value_str[1 .. value_str.len - 1];
                return Value{ .string = try self.allocator.dupe(u8, unquoted) };
            }
        }

        // Integer
        if (std.fmt.parseInt(i64, value_str, 10)) |int_val| {
            return Value{ .integer = int_val };
        } else |_| {}

        // Float
        if (std.fmt.parseFloat(f64, value_str)) |float_val| {
            return Value{ .float = float_val };
        } else |_| {}

        // Unquoted string (fallback)
        return Value{ .string = try self.allocator.dupe(u8, value_str) };
    }
};

pub const ParseError = error{
    ConfigFileNotFound,
    InvalidSyntax,
    OutOfMemory,
};

// Tests
test "parse basic key-value pairs" {
    const testing = std.testing;
    var parser = TomlParser.init(testing.allocator);

    const content =
        \\host = "0.0.0.0"
        \\port = 2525
        \\enable_tls = true
        \\timeout = 300.5
    ;

    var doc = try parser.parse(content);
    defer doc.deinit();

    const root = doc.getRoot();
    try testing.expectEqualStrings("0.0.0.0", root.getString("host").?);
    try testing.expectEqual(@as(i64, 2525), root.getInt("port").?);
    try testing.expectEqual(true, root.getBool("enable_tls").?);
}

test "parse sections" {
    const testing = std.testing;
    var parser = TomlParser.init(testing.allocator);

    const content =
        \\[server]
        \\host = "localhost"
        \\port = 25
        \\
        \\[tls]
        \\enabled = true
        \\cert_path = "/etc/ssl/cert.pem"
    ;

    var doc = try parser.parse(content);
    defer doc.deinit();

    const server = doc.getSection("server").?;
    try testing.expectEqualStrings("localhost", server.getString("host").?);
    try testing.expectEqual(@as(i64, 25), server.getInt("port").?);

    const tls = doc.getSection("tls").?;
    try testing.expectEqual(true, tls.getBool("enabled").?);
    try testing.expectEqualStrings("/etc/ssl/cert.pem", tls.getString("cert_path").?);
}

test "parse with comments" {
    const testing = std.testing;
    var parser = TomlParser.init(testing.allocator);

    const content =
        \\# This is a comment
        \\host = "localhost"
        \\# Another comment
        \\port = 25
    ;

    var doc = try parser.parse(content);
    defer doc.deinit();

    const root = doc.getRoot();
    try testing.expectEqualStrings("localhost", root.getString("host").?);
    try testing.expectEqual(@as(i64, 25), root.getInt("port").?);
}
