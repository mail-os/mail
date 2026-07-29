const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// Sieve Email Filtering Language (RFC 5228)
/// Implements parsing, evaluation, and script management for server-side
/// email filtering rules.

// ============================================================================
// Sieve AST Types
// ============================================================================

/// Sieve command types
pub const CommandType = enum {
    // Control commands
    @"if",
    elsif,
    @"else",
    require,
    stop,

    // Action commands
    keep,
    fileinto,
    redirect,
    discard,
    reject,
    ereject,

    // Extensions
    vacation,
    notify,
    setflag,
    addflag,
    removeflag,

    pub fn toString(self: CommandType) []const u8 {
        return switch (self) {
            .@"if" => "if",
            .elsif => "elsif",
            .@"else" => "else",
            .require => "require",
            .stop => "stop",
            .keep => "keep",
            .fileinto => "fileinto",
            .redirect => "redirect",
            .discard => "discard",
            .reject => "reject",
            .ereject => "ereject",
            .vacation => "vacation",
            .notify => "notify",
            .setflag => "setflag",
            .addflag => "addflag",
            .removeflag => "removeflag",
        };
    }

    pub fn isAction(self: CommandType) bool {
        return switch (self) {
            .keep,
            .fileinto,
            .redirect,
            .discard,
            .reject,
            .ereject,
            .vacation,
            .notify,
            .setflag,
            .addflag,
            .removeflag,
            => true,
            else => false,
        };
    }

    pub fn isControl(self: CommandType) bool {
        return switch (self) {
            .@"if", .elsif, .@"else", .require, .stop => true,
            else => false,
        };
    }
};

/// Sieve test types
pub const TestType = enum {
    // Address tests
    address,
    envelope,
    header,
    exists,

    // Size test
    size,

    // Boolean tests
    allof,
    anyof,
    not,

    // True/False
    true_test,
    false_test,

    pub fn toString(self: TestType) []const u8 {
        return switch (self) {
            .address => "address",
            .envelope => "envelope",
            .header => "header",
            .exists => "exists",
            .size => "size",
            .allof => "allof",
            .anyof => "anyof",
            .not => "not",
            .true_test => "true",
            .false_test => "false",
        };
    }
};

/// Match type for comparisons
pub const MatchType = enum {
    is,
    contains,
    matches,
    regex,

    pub fn toString(self: MatchType) []const u8 {
        return switch (self) {
            .is => ":is",
            .contains => ":contains",
            .matches => ":matches",
            .regex => ":regex",
        };
    }
};

/// Comparator for string comparisons
pub const Comparator = enum {
    ascii_casemap,
    ascii_numeric,
    octet,

    pub fn toString(self: Comparator) []const u8 {
        return switch (self) {
            .ascii_casemap => "i;ascii-casemap",
            .ascii_numeric => "i;ascii-numeric",
            .octet => "i;octet",
        };
    }
};

/// Size qualifier
pub const SizeQualifier = enum {
    over,
    under,
};

/// Sieve test node
pub const SieveTest = struct {
    test_type: TestType,
    match_type: MatchType = .is,
    comparator: Comparator = .ascii_casemap,
    header_names: []const []const u8 = &.{},
    key_list: []const []const u8 = &.{},
    size_value: usize = 0,
    size_qualifier: SizeQualifier = .over,
    sub_tests: []const SieveTest = &.{},
    negated: bool = false,
};

/// Sieve command node
pub const SieveCommand = struct {
    command_type: CommandType,
    arguments: []const []const u8 = &.{},
    test_expr: ?SieveTest = null,
    block: []const SieveCommand = &.{},
    elsif_branches: []const ElsifBranch = &.{},
    else_block: []const SieveCommand = &.{},
};

pub const ElsifBranch = struct {
    test_expr: SieveTest,
    block: []const SieveCommand,
};

/// Compiled Sieve script
pub const SieveScript = struct {
    allocator: std.mem.Allocator,
    requires: []const []const u8,
    commands: []const SieveCommand,
    source: []const u8,
    compiled_at: i64,
    is_valid: bool,
    errors: []const ParseError,

    pub fn deinit(self: *SieveScript) void {
        // Free commands and all nested allocations
        freeCommands(self.allocator, self.commands);

        self.allocator.free(self.source);
        for (self.errors) |err| {
            self.allocator.free(err.message);
        }
        if (self.errors.len > 0) self.allocator.free(self.errors);
        // Note: requires strings are shared with require command arguments
        // which are freed in freeCommands, so only free the slice here.
        if (self.requires.len > 0) self.allocator.free(self.requires);
    }

    fn freeTest(allocator: std.mem.Allocator, t: *const SieveTest) void {
        for (t.header_names) |s| {
            allocator.free(s);
        }
        if (t.header_names.len > 0) allocator.free(t.header_names);

        for (t.key_list) |s| {
            allocator.free(s);
        }
        if (t.key_list.len > 0) allocator.free(t.key_list);

        for (t.sub_tests) |*sub| {
            freeTest(allocator, sub);
        }
        if (t.sub_tests.len > 0) allocator.free(t.sub_tests);
    }

    fn freeCommands(allocator: std.mem.Allocator, commands: []const SieveCommand) void {
        for (commands) |*cmd| {
            // Free argument strings
            for (cmd.arguments) |arg| {
                allocator.free(arg);
            }
            if (cmd.arguments.len > 0) allocator.free(cmd.arguments);

            // Free test expression
            if (cmd.test_expr) |*te| {
                freeTest(allocator, te);
            }

            // Free block (recursive)
            freeCommands(allocator, cmd.block);

            // Free elsif branches
            for (cmd.elsif_branches) |*branch| {
                freeTest(allocator, &branch.test_expr);
                freeCommands(allocator, branch.block);
            }
            if (cmd.elsif_branches.len > 0) allocator.free(cmd.elsif_branches);

            // Free else block
            freeCommands(allocator, cmd.else_block);
        }
        if (commands.len > 0) allocator.free(commands);
    }
};

pub const ParseError = struct {
    line: usize,
    column: usize,
    message: []const u8,
};

// ============================================================================
// Sieve Parser
// ============================================================================

pub const SieveParser = struct {
    allocator: std.mem.Allocator,
    source: []const u8,
    pos: usize,
    line: usize,
    column: usize,
    errors: std.ArrayList(ParseError),
    requires: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator) SieveParser {
        return .{
            .allocator = allocator,
            .source = "",
            .pos = 0,
            .line = 1,
            .column = 1,
            .errors = .empty,
            .requires = .empty,
        };
    }

    pub fn deinit(self: *SieveParser) void {
        for (self.errors.items) |err| {
            self.allocator.free(err.message);
        }
        self.errors.deinit(self.allocator);
        self.requires.deinit(self.allocator);
    }

    /// Parse a Sieve script from source text
    pub fn parse(self: *SieveParser, source: []const u8) !SieveScript {
        self.source = source;
        self.pos = 0;
        self.line = 1;
        self.column = 1;
        self.errors.clearRetainingCapacity();
        self.requires.clearRetainingCapacity();

        var commands: std.ArrayList(SieveCommand) = .empty;
        defer commands.deinit(self.allocator);

        while (self.pos < self.source.len) {
            self.skipWhitespaceAndComments();
            if (self.pos >= self.source.len) break;

            const cmd = self.parseCommand() catch |err| {
                try self.errors.append(self.allocator, .{
                    .line = self.line,
                    .column = self.column,
                    .message = try std.fmt.allocPrint(self.allocator, "Parse error: {s}", .{@errorName(err)}),
                });
                // Skip to next semicolon or end
                while (self.pos < self.source.len and self.source[self.pos] != ';') {
                    self.advance();
                }
                if (self.pos < self.source.len) self.advance(); // skip ;
                continue;
            };
            try commands.append(self.allocator, cmd);
        }

        return SieveScript{
            .allocator = self.allocator,
            .requires = try self.requires.toOwnedSlice(self.allocator),
            .commands = try commands.toOwnedSlice(self.allocator),
            .source = try self.allocator.dupe(u8, source),
            .compiled_at = time_compat.timestamp(),
            .is_valid = self.errors.items.len == 0,
            .errors = try self.errors.toOwnedSlice(self.allocator),
        };
    }

    fn parseCommand(self: *SieveParser) !SieveCommand {
        self.skipWhitespaceAndComments();

        const identifier = self.readIdentifier() orelse return error.ExpectedIdentifier;

        // Determine command type
        if (std.mem.eql(u8, identifier, "require")) {
            return self.parseRequire();
        } else if (std.mem.eql(u8, identifier, "if")) {
            return self.parseIf();
        } else if (std.mem.eql(u8, identifier, "stop")) {
            try self.expectChar(';');
            return SieveCommand{ .command_type = .stop };
        } else if (std.mem.eql(u8, identifier, "keep")) {
            try self.expectChar(';');
            return SieveCommand{ .command_type = .keep };
        } else if (std.mem.eql(u8, identifier, "discard")) {
            try self.expectChar(';');
            return SieveCommand{ .command_type = .discard };
        } else if (std.mem.eql(u8, identifier, "fileinto")) {
            return self.parseFileinto();
        } else if (std.mem.eql(u8, identifier, "redirect")) {
            return self.parseRedirect();
        } else if (std.mem.eql(u8, identifier, "reject")) {
            return self.parseReject();
        } else {
            return error.UnknownCommand;
        }
    }

    fn parseRequire(self: *SieveParser) !SieveCommand {
        self.skipWhitespaceAndComments();
        var args: std.ArrayList([]const u8) = .empty;

        if (self.pos < self.source.len and self.source[self.pos] == '[') {
            // String list
            self.advance(); // skip [
            while (self.pos < self.source.len and self.source[self.pos] != ']') {
                self.skipWhitespaceAndComments();
                if (self.pos < self.source.len and self.source[self.pos] == ',') {
                    self.advance();
                    continue;
                }
                const str = try self.parseString();
                try args.append(self.allocator, str);
                try self.requires.append(self.allocator, str);
            }
            if (self.pos < self.source.len) self.advance(); // skip ]
        } else {
            // Single string
            const str = try self.parseString();
            try args.append(self.allocator, str);
            try self.requires.append(self.allocator, str);
        }

        try self.expectChar(';');

        return SieveCommand{
            .command_type = .require,
            .arguments = try args.toOwnedSlice(self.allocator),
        };
    }

    fn parseIf(self: *SieveParser) !SieveCommand {
        self.skipWhitespaceAndComments();
        const test_expr = try self.parseTest();

        self.skipWhitespaceAndComments();
        const block = try self.parseBlock();

        var elsif_branches: std.ArrayList(ElsifBranch) = .empty;
        var else_block: []const SieveCommand = &.{};

        // Check for elsif/else
        while (true) {
            self.skipWhitespaceAndComments();
            if (self.pos >= self.source.len) break;

            const saved_pos = self.pos;
            const next_id = self.readIdentifier() orelse break;

            if (std.mem.eql(u8, next_id, "elsif")) {
                self.skipWhitespaceAndComments();
                const elsif_test = try self.parseTest();
                self.skipWhitespaceAndComments();
                const elsif_block = try self.parseBlock();
                try elsif_branches.append(self.allocator, .{
                    .test_expr = elsif_test,
                    .block = elsif_block,
                });
            } else if (std.mem.eql(u8, next_id, "else")) {
                self.skipWhitespaceAndComments();
                else_block = try self.parseBlock();
                break;
            } else {
                // Not elsif/else, restore position
                self.pos = saved_pos;
                break;
            }
        }

        return SieveCommand{
            .command_type = .@"if",
            .test_expr = test_expr,
            .block = block,
            .elsif_branches = try elsif_branches.toOwnedSlice(self.allocator),
            .else_block = else_block,
        };
    }

    fn parseFileinto(self: *SieveParser) !SieveCommand {
        self.skipWhitespaceAndComments();
        const folder = try self.parseString();
        try self.expectChar(';');

        var args: std.ArrayList([]const u8) = .empty;
        try args.append(self.allocator, folder);

        return SieveCommand{
            .command_type = .fileinto,
            .arguments = try args.toOwnedSlice(self.allocator),
        };
    }

    fn parseRedirect(self: *SieveParser) !SieveCommand {
        self.skipWhitespaceAndComments();
        const address = try self.parseString();
        try self.expectChar(';');

        var args: std.ArrayList([]const u8) = .empty;
        try args.append(self.allocator, address);

        return SieveCommand{
            .command_type = .redirect,
            .arguments = try args.toOwnedSlice(self.allocator),
        };
    }

    fn parseReject(self: *SieveParser) !SieveCommand {
        self.skipWhitespaceAndComments();
        const reason = try self.parseString();
        try self.expectChar(';');

        var args: std.ArrayList([]const u8) = .empty;
        try args.append(self.allocator, reason);

        return SieveCommand{
            .command_type = .reject,
            .arguments = try args.toOwnedSlice(self.allocator),
        };
    }

    fn parseTest(self: *SieveParser) !SieveTest {
        self.skipWhitespaceAndComments();
        const identifier = self.readIdentifier() orelse return error.ExpectedTest;

        if (std.mem.eql(u8, identifier, "header")) {
            return self.parseHeaderTest();
        } else if (std.mem.eql(u8, identifier, "address")) {
            return self.parseAddressTest();
        } else if (std.mem.eql(u8, identifier, "size")) {
            return self.parseSizeTest();
        } else if (std.mem.eql(u8, identifier, "exists")) {
            return self.parseExistsTest();
        } else if (std.mem.eql(u8, identifier, "allof")) {
            return self.parseAllofTest();
        } else if (std.mem.eql(u8, identifier, "anyof")) {
            return self.parseAnyofTest();
        } else if (std.mem.eql(u8, identifier, "not")) {
            var inner = try self.parseTest();
            inner.negated = !inner.negated;
            return inner;
        } else if (std.mem.eql(u8, identifier, "true")) {
            return SieveTest{ .test_type = .true_test };
        } else if (std.mem.eql(u8, identifier, "false")) {
            return SieveTest{ .test_type = .false_test };
        } else if (std.mem.eql(u8, identifier, "envelope")) {
            return self.parseEnvelopeTest();
        } else {
            return error.UnknownTest;
        }
    }

    fn parseHeaderTest(self: *SieveParser) !SieveTest {
        var match_type: MatchType = .is;
        var comparator: Comparator = .ascii_casemap;

        // Parse optional tagged arguments
        while (self.pos < self.source.len) {
            self.skipWhitespaceAndComments();
            if (self.pos < self.source.len and self.source[self.pos] == ':') {
                const tag = self.readTag() orelse break;
                if (std.mem.eql(u8, tag, ":is")) {
                    match_type = .is;
                } else if (std.mem.eql(u8, tag, ":contains")) {
                    match_type = .contains;
                } else if (std.mem.eql(u8, tag, ":matches")) {
                    match_type = .matches;
                } else if (std.mem.eql(u8, tag, ":comparator")) {
                    self.skipWhitespaceAndComments();
                    const comp_str = try self.parseString();
                    if (std.mem.eql(u8, comp_str, "i;ascii-numeric")) {
                        comparator = .ascii_numeric;
                    } else if (std.mem.eql(u8, comp_str, "i;octet")) {
                        comparator = .octet;
                    }
                }
            } else {
                break;
            }
        }

        self.skipWhitespaceAndComments();
        const header_names = try self.parseStringList();
        self.skipWhitespaceAndComments();
        const key_list = try self.parseStringList();

        return SieveTest{
            .test_type = .header,
            .match_type = match_type,
            .comparator = comparator,
            .header_names = header_names,
            .key_list = key_list,
        };
    }

    fn parseAddressTest(self: *SieveParser) !SieveTest {
        var match_type: MatchType = .is;

        while (self.pos < self.source.len) {
            self.skipWhitespaceAndComments();
            if (self.pos < self.source.len and self.source[self.pos] == ':') {
                const tag = self.readTag() orelse break;
                if (std.mem.eql(u8, tag, ":is")) match_type = .is;
                if (std.mem.eql(u8, tag, ":contains")) match_type = .contains;
                if (std.mem.eql(u8, tag, ":matches")) match_type = .matches;
            } else break;
        }

        self.skipWhitespaceAndComments();
        const header_names = try self.parseStringList();
        self.skipWhitespaceAndComments();
        const key_list = try self.parseStringList();

        return SieveTest{
            .test_type = .address,
            .match_type = match_type,
            .header_names = header_names,
            .key_list = key_list,
        };
    }

    fn parseEnvelopeTest(self: *SieveParser) !SieveTest {
        var match_type: MatchType = .is;

        while (self.pos < self.source.len) {
            self.skipWhitespaceAndComments();
            if (self.pos < self.source.len and self.source[self.pos] == ':') {
                const tag = self.readTag() orelse break;
                if (std.mem.eql(u8, tag, ":is")) match_type = .is;
                if (std.mem.eql(u8, tag, ":contains")) match_type = .contains;
                if (std.mem.eql(u8, tag, ":matches")) match_type = .matches;
            } else break;
        }

        self.skipWhitespaceAndComments();
        const parts = try self.parseStringList();
        self.skipWhitespaceAndComments();
        const key_list = try self.parseStringList();

        return SieveTest{
            .test_type = .envelope,
            .match_type = match_type,
            .header_names = parts,
            .key_list = key_list,
        };
    }

    fn parseSizeTest(self: *SieveParser) !SieveTest {
        self.skipWhitespaceAndComments();
        var qualifier: SizeQualifier = .over;

        if (self.pos < self.source.len and self.source[self.pos] == ':') {
            const tag = self.readTag() orelse return error.ExpectedSizeQualifier;
            if (std.mem.eql(u8, tag, ":over")) qualifier = .over;
            if (std.mem.eql(u8, tag, ":under")) qualifier = .under;
        }

        self.skipWhitespaceAndComments();
        const size_str = self.readNumber() orelse return error.ExpectedNumber;
        var size_value = std.fmt.parseInt(usize, size_str, 10) catch return error.InvalidNumber;

        // Check for size suffix (K, M, G)
        if (self.pos < self.source.len) {
            const suffix = self.source[self.pos];
            if (suffix == 'K' or suffix == 'k') {
                size_value *= 1024;
                self.advance();
            } else if (suffix == 'M' or suffix == 'm') {
                size_value *= 1024 * 1024;
                self.advance();
            } else if (suffix == 'G' or suffix == 'g') {
                size_value *= 1024 * 1024 * 1024;
                self.advance();
            }
        }

        return SieveTest{
            .test_type = .size,
            .size_value = size_value,
            .size_qualifier = qualifier,
        };
    }

    fn parseExistsTest(self: *SieveParser) !SieveTest {
        self.skipWhitespaceAndComments();
        const header_names = try self.parseStringList();

        return SieveTest{
            .test_type = .exists,
            .header_names = header_names,
        };
    }

    fn parseAllofTest(self: *SieveParser) !SieveTest {
        self.skipWhitespaceAndComments();
        const sub_tests = try self.parseTestList();

        return SieveTest{
            .test_type = .allof,
            .sub_tests = sub_tests,
        };
    }

    fn parseAnyofTest(self: *SieveParser) !SieveTest {
        self.skipWhitespaceAndComments();
        const sub_tests = try self.parseTestList();

        return SieveTest{
            .test_type = .anyof,
            .sub_tests = sub_tests,
        };
    }

    fn parseTestList(self: *SieveParser) anyerror![]const SieveTest {
        self.skipWhitespaceAndComments();
        try self.expectChar('(');

        var tests: std.ArrayList(SieveTest) = .empty;

        while (self.pos < self.source.len and self.source[self.pos] != ')') {
            self.skipWhitespaceAndComments();
            if (self.pos < self.source.len and self.source[self.pos] == ',') {
                self.advance();
                continue;
            }
            if (self.pos < self.source.len and self.source[self.pos] == ')') break;
            const t = try self.parseTest();
            try tests.append(self.allocator, t);
        }

        try self.expectChar(')');
        return tests.toOwnedSlice(self.allocator);
    }

    fn parseBlock(self: *SieveParser) anyerror![]const SieveCommand {
        self.skipWhitespaceAndComments();
        try self.expectChar('{');

        var commands: std.ArrayList(SieveCommand) = .empty;

        while (self.pos < self.source.len and self.source[self.pos] != '}') {
            self.skipWhitespaceAndComments();
            if (self.pos < self.source.len and self.source[self.pos] == '}') break;
            const cmd = try self.parseCommand();
            try commands.append(self.allocator, cmd);
        }

        try self.expectChar('}');
        return commands.toOwnedSlice(self.allocator);
    }

    fn parseString(self: *SieveParser) ![]const u8 {
        self.skipWhitespaceAndComments();
        if (self.pos >= self.source.len) return error.UnexpectedEnd;

        if (self.source[self.pos] == '"') {
            return self.parseQuotedString();
        } else if (self.pos + 4 <= self.source.len and std.mem.eql(u8, self.source[self.pos .. self.pos + 4], "text")) {
            return self.parseMultiLineString();
        }

        return error.ExpectedString;
    }

    fn parseQuotedString(self: *SieveParser) ![]const u8 {
        if (self.pos >= self.source.len or self.source[self.pos] != '"') return error.ExpectedQuote;
        self.advance(); // skip opening quote

        var result: std.ArrayList(u8) = .empty;

        while (self.pos < self.source.len and self.source[self.pos] != '"') {
            if (self.source[self.pos] == '\\' and self.pos + 1 < self.source.len) {
                self.advance(); // skip backslash
                try result.append(self.allocator, self.source[self.pos]);
            } else {
                try result.append(self.allocator, self.source[self.pos]);
            }
            self.advance();
        }

        if (self.pos >= self.source.len) return error.UnterminatedString;
        self.advance(); // skip closing quote

        return result.toOwnedSlice(self.allocator);
    }

    fn parseMultiLineString(self: *SieveParser) ![]const u8 {
        // text:CRLF...CRLF.CRLF format
        _ = self;
        return error.MultiLineNotSupported;
    }

    fn parseStringList(self: *SieveParser) ![]const []const u8 {
        self.skipWhitespaceAndComments();
        if (self.pos >= self.source.len) return error.UnexpectedEnd;

        var list: std.ArrayList([]const u8) = .empty;

        if (self.source[self.pos] == '[') {
            self.advance(); // skip [
            while (self.pos < self.source.len and self.source[self.pos] != ']') {
                self.skipWhitespaceAndComments();
                if (self.pos < self.source.len and self.source[self.pos] == ',') {
                    self.advance();
                    continue;
                }
                if (self.pos < self.source.len and self.source[self.pos] == ']') break;
                const str = try self.parseString();
                try list.append(self.allocator, str);
            }
            if (self.pos < self.source.len) self.advance(); // skip ]
        } else {
            // Single string
            const str = try self.parseString();
            try list.append(self.allocator, str);
        }

        return list.toOwnedSlice(self.allocator);
    }

    fn readIdentifier(self: *SieveParser) ?[]const u8 {
        self.skipWhitespaceAndComments();
        if (self.pos >= self.source.len) return null;

        const start = self.pos;
        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (std.ascii.isAlphanumeric(c) or c == '_') {
                self.advance();
            } else {
                break;
            }
        }

        if (self.pos == start) return null;
        return self.source[start..self.pos];
    }

    fn readTag(self: *SieveParser) ?[]const u8 {
        if (self.pos >= self.source.len or self.source[self.pos] != ':') return null;

        const start = self.pos;
        self.advance(); // skip :

        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (std.ascii.isAlphanumeric(c) or c == '_') {
                self.advance();
            } else {
                break;
            }
        }

        return self.source[start..self.pos];
    }

    fn readNumber(self: *SieveParser) ?[]const u8 {
        if (self.pos >= self.source.len or !std.ascii.isDigit(self.source[self.pos])) return null;

        const start = self.pos;
        while (self.pos < self.source.len and std.ascii.isDigit(self.source[self.pos])) {
            self.advance();
        }

        return self.source[start..self.pos];
    }

    fn expectChar(self: *SieveParser, expected: u8) !void {
        self.skipWhitespaceAndComments();
        if (self.pos >= self.source.len or self.source[self.pos] != expected) {
            return error.UnexpectedCharacter;
        }
        self.advance();
    }

    fn advance(self: *SieveParser) void {
        if (self.pos < self.source.len) {
            if (self.source[self.pos] == '\n') {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
            self.pos += 1;
        }
    }

    fn skipWhitespaceAndComments(self: *SieveParser) void {
        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
                self.advance();
            } else if (c == '#') {
                // Line comment
                while (self.pos < self.source.len and self.source[self.pos] != '\n') {
                    self.advance();
                }
            } else if (c == '/' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == '*') {
                // Block comment
                self.advance();
                self.advance();
                while (self.pos + 1 < self.source.len) {
                    if (self.source[self.pos] == '*' and self.source[self.pos + 1] == '/') {
                        self.advance();
                        self.advance();
                        break;
                    }
                    self.advance();
                }
            } else {
                break;
            }
        }
    }
};

// ============================================================================
// Sieve Evaluator
// ============================================================================

/// Email message representation for Sieve evaluation
pub const SieveMessage = struct {
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    size: usize,
    envelope_from: []const u8,
    envelope_to: []const u8,

    pub fn init(allocator: std.mem.Allocator) SieveMessage {
        return .{
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .size = 0,
            .envelope_from = "",
            .envelope_to = "",
        };
    }

    pub fn deinit(self: *SieveMessage) void {
        self.headers.deinit();
    }

    pub fn getHeader(self: *const SieveMessage, name: []const u8) ?[]const u8 {
        // Case-insensitive header lookup
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, name)) {
                return entry.value_ptr.*;
            }
        }
        return null;
    }
};

/// Result of Sieve script evaluation
pub const SieveAction = struct {
    action_type: ActionType,
    argument: ?[]const u8,

    pub const ActionType = enum {
        keep,
        fileinto,
        redirect,
        discard,
        reject,
        vacation,
    };
};

/// Sieve script evaluator
pub const SieveEvaluator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SieveEvaluator {
        return .{ .allocator = allocator };
    }

    /// Evaluate a compiled Sieve script against a message
    pub fn evaluate(self: *SieveEvaluator, script: *const SieveScript, message: *const SieveMessage) ![]SieveAction {
        var actions: std.ArrayList(SieveAction) = .empty;
        var implicit_keep = true;

        for (script.commands) |cmd| {
            const result = try self.evaluateCommand(&cmd, message, &actions, &implicit_keep);
            if (result == .stop) break;
        }

        // Implicit keep if no action was taken
        if (implicit_keep and actions.items.len == 0) {
            try actions.append(self.allocator, .{ .action_type = .keep, .argument = null });
        }

        return actions.toOwnedSlice(self.allocator);
    }

    const EvalResult = enum { continue_eval, stop };

    fn evaluateCommand(
        self: *SieveEvaluator,
        cmd: *const SieveCommand,
        message: *const SieveMessage,
        actions: *std.ArrayList(SieveAction),
        implicit_keep: *bool,
    ) !EvalResult {
        switch (cmd.command_type) {
            .stop => return .stop,
            .keep => {
                try actions.append(self.allocator, .{ .action_type = .keep, .argument = null });
                implicit_keep.* = false;
                return .continue_eval;
            },
            .discard => {
                try actions.append(self.allocator, .{ .action_type = .discard, .argument = null });
                implicit_keep.* = false;
                return .continue_eval;
            },
            .fileinto => {
                const folder = if (cmd.arguments.len > 0) cmd.arguments[0] else null;
                try actions.append(self.allocator, .{ .action_type = .fileinto, .argument = folder });
                implicit_keep.* = false;
                return .continue_eval;
            },
            .redirect => {
                const address = if (cmd.arguments.len > 0) cmd.arguments[0] else null;
                try actions.append(self.allocator, .{ .action_type = .redirect, .argument = address });
                implicit_keep.* = false;
                return .continue_eval;
            },
            .reject => {
                const reason = if (cmd.arguments.len > 0) cmd.arguments[0] else null;
                try actions.append(self.allocator, .{ .action_type = .reject, .argument = reason });
                implicit_keep.* = false;
                return .continue_eval;
            },
            .@"if" => {
                if (cmd.test_expr) |test_expr| {
                    if (self.evaluateTest(&test_expr, message)) {
                        for (cmd.block) |block_cmd| {
                            const result = try self.evaluateCommand(&block_cmd, message, actions, implicit_keep);
                            if (result == .stop) return .stop;
                        }
                    } else {
                        // Check elsif branches
                        var matched = false;
                        for (cmd.elsif_branches) |branch| {
                            if (self.evaluateTest(&branch.test_expr, message)) {
                                for (branch.block) |block_cmd| {
                                    const result = try self.evaluateCommand(&block_cmd, message, actions, implicit_keep);
                                    if (result == .stop) return .stop;
                                }
                                matched = true;
                                break;
                            }
                        }
                        // Else block
                        if (!matched and cmd.else_block.len > 0) {
                            for (cmd.else_block) |block_cmd| {
                                const result = try self.evaluateCommand(&block_cmd, message, actions, implicit_keep);
                                if (result == .stop) return .stop;
                            }
                        }
                    }
                }
                return .continue_eval;
            },
            .require => return .continue_eval, // No-op at evaluation time
            else => return .continue_eval,
        }
    }

    fn evaluateTest(self: *SieveEvaluator, test_expr: *const SieveTest, message: *const SieveMessage) bool {
        const result = switch (test_expr.test_type) {
            .header => self.evalHeaderTest(test_expr, message),
            .address => self.evalAddressTest(test_expr, message),
            .envelope => self.evalEnvelopeTest(test_expr, message),
            .exists => self.evalExistsTest(test_expr, message),
            .size => self.evalSizeTest(test_expr, message),
            .allof => self.evalAllofTest(test_expr, message),
            .anyof => self.evalAnyofTest(test_expr, message),
            .not => !self.evaluateTest(&test_expr.sub_tests[0], message),
            .true_test => true,
            .false_test => false,
        };

        return if (test_expr.negated) !result else result;
    }

    fn evalHeaderTest(self: *SieveEvaluator, test_expr: *const SieveTest, message: *const SieveMessage) bool {
        _ = self;
        for (test_expr.header_names) |header_name| {
            if (message.getHeader(header_name)) |header_value| {
                for (test_expr.key_list) |key| {
                    if (matchString(header_value, key, test_expr.match_type)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    fn evalAddressTest(self: *SieveEvaluator, test_expr: *const SieveTest, message: *const SieveMessage) bool {
        _ = self;
        for (test_expr.header_names) |header_name| {
            if (message.getHeader(header_name)) |header_value| {
                // Extract email address from header value
                const addr = extractAddress(header_value);
                for (test_expr.key_list) |key| {
                    if (matchString(addr, key, test_expr.match_type)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    fn evalEnvelopeTest(self: *SieveEvaluator, test_expr: *const SieveTest, message: *const SieveMessage) bool {
        _ = self;
        for (test_expr.header_names) |part| {
            const value = if (std.ascii.eqlIgnoreCase(part, "from"))
                message.envelope_from
            else if (std.ascii.eqlIgnoreCase(part, "to"))
                message.envelope_to
            else
                continue;

            for (test_expr.key_list) |key| {
                if (matchString(value, key, test_expr.match_type)) {
                    return true;
                }
            }
        }
        return false;
    }

    fn evalExistsTest(self: *SieveEvaluator, test_expr: *const SieveTest, message: *const SieveMessage) bool {
        _ = self;
        for (test_expr.header_names) |header_name| {
            if (message.getHeader(header_name) == null) {
                return false;
            }
        }
        return true;
    }

    fn evalSizeTest(self: *SieveEvaluator, test_expr: *const SieveTest, message: *const SieveMessage) bool {
        _ = self;
        return switch (test_expr.size_qualifier) {
            .over => message.size > test_expr.size_value,
            .under => message.size < test_expr.size_value,
        };
    }

    fn evalAllofTest(self: *SieveEvaluator, test_expr: *const SieveTest, message: *const SieveMessage) bool {
        for (test_expr.sub_tests) |*sub| {
            if (!self.evaluateTest(sub, message)) return false;
        }
        return true;
    }

    fn evalAnyofTest(self: *SieveEvaluator, test_expr: *const SieveTest, message: *const SieveMessage) bool {
        for (test_expr.sub_tests) |*sub| {
            if (self.evaluateTest(sub, message)) return true;
        }
        return false;
    }
};

/// Match string based on match type
fn matchString(value: []const u8, pattern: []const u8, match_type: MatchType) bool {
    return switch (match_type) {
        .is => std.ascii.eqlIgnoreCase(value, pattern),
        .contains => containsIgnoreCase(value, pattern),
        .matches => wildcardMatch(value, pattern),
        .regex => false, // Regex support requires extension
    };
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    if (needle.len == 0) return true;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) {
            return true;
        }
    }
    return false;
}

fn wildcardMatch(value: []const u8, pattern: []const u8) bool {
    var vi: usize = 0;
    var pi: usize = 0;
    var star_pi: ?usize = null;
    var star_vi: usize = 0;

    while (vi < value.len) {
        if (pi < pattern.len and (pattern[pi] == '?' or std.ascii.toLower(pattern[pi]) == std.ascii.toLower(value[vi]))) {
            vi += 1;
            pi += 1;
        } else if (pi < pattern.len and pattern[pi] == '*') {
            star_pi = pi;
            star_vi = vi;
            pi += 1;
        } else if (star_pi) |sp| {
            pi = sp + 1;
            star_vi += 1;
            vi = star_vi;
        } else {
            return false;
        }
    }

    while (pi < pattern.len and pattern[pi] == '*') {
        pi += 1;
    }

    return pi == pattern.len;
}

/// Extract email address from a header value like "Name <addr>" or "addr"
fn extractAddress(value: []const u8) []const u8 {
    if (std.mem.indexOf(u8, value, "<")) |start| {
        if (std.mem.indexOfPos(u8, value, start, ">")) |end| {
            return value[start + 1 .. end];
        }
    }
    return std.mem.trim(u8, value, " \t");
}

// ============================================================================
// Script Manager
// ============================================================================

/// Manages Sieve scripts for users
pub const SieveScriptManager = struct {
    allocator: std.mem.Allocator,
    scripts: std.StringHashMap(UserScripts),
    mutex: mutex_compat.Mutex,

    pub const UserScripts = struct {
        active_script: ?[]const u8,
        scripts: std.StringHashMap(SieveScript),
    };

    pub fn init(allocator: std.mem.Allocator) SieveScriptManager {
        return .{
            .allocator = allocator,
            .scripts = std.StringHashMap(UserScripts).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *SieveScriptManager) void {
        var it = self.scripts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var script_it = entry.value_ptr.scripts.iterator();
            while (script_it.next()) |script_entry| {
                self.allocator.free(script_entry.key_ptr.*);
                var script = script_entry.value_ptr.*;
                script.deinit();
            }
            entry.value_ptr.scripts.deinit();
            if (entry.value_ptr.active_script) |name| self.allocator.free(name);
        }
        self.scripts.deinit();
    }

    /// Store a Sieve script for a user
    pub fn putScript(self: *SieveScriptManager, user: []const u8, name: []const u8, script: SieveScript) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (!self.scripts.contains(user)) {
            const key = try self.allocator.dupe(u8, user);
            try self.scripts.put(key, .{
                .active_script = null,
                .scripts = std.StringHashMap(SieveScript).init(self.allocator),
            });
        }

        if (self.scripts.getPtr(user)) |user_scripts| {
            const script_name = try self.allocator.dupe(u8, name);
            try user_scripts.scripts.put(script_name, script);
        }
    }

    /// Get the active script for a user
    pub fn getActiveScript(self: *SieveScriptManager, user: []const u8) ?*SieveScript {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.scripts.getPtr(user)) |user_scripts| {
            if (user_scripts.active_script) |active_name| {
                return user_scripts.scripts.getPtr(active_name);
            }
        }
        return null;
    }

    /// Set the active script for a user
    pub fn setActive(self: *SieveScriptManager, user: []const u8, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.scripts.getPtr(user)) |user_scripts| {
            if (!user_scripts.scripts.contains(name)) return error.ScriptNotFound;
            if (user_scripts.active_script) |old| self.allocator.free(old);
            user_scripts.active_script = try self.allocator.dupe(u8, name);
        } else {
            return error.UserNotFound;
        }
    }

    /// List scripts for a user
    pub fn listScripts(self: *SieveScriptManager, user: []const u8) ![]const []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var names: std.ArrayList([]const u8) = .empty;

        if (self.scripts.getPtr(user)) |user_scripts| {
            var it = user_scripts.scripts.iterator();
            while (it.next()) |entry| {
                try names.append(self.allocator, entry.key_ptr.*);
            }
        }

        return names.toOwnedSlice(self.allocator);
    }

    /// Delete a script
    pub fn deleteScript(self: *SieveScriptManager, user: []const u8, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.scripts.getPtr(user)) |user_scripts| {
            if (user_scripts.scripts.fetchRemove(name)) |kv| {
                self.allocator.free(kv.key);
                var script = kv.value;
                script.deinit();
            } else {
                return error.ScriptNotFound;
            }
        } else {
            return error.UserNotFound;
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "parse simple keep script" {
    var parser = SieveParser.init(std.testing.allocator);
    defer parser.deinit();

    var script = try parser.parse("keep;");
    defer script.deinit();

    try std.testing.expect(script.is_valid);
    try std.testing.expectEqual(@as(usize, 1), script.commands.len);
    try std.testing.expectEqual(CommandType.keep, script.commands[0].command_type);
}

test "parse discard script" {
    var parser = SieveParser.init(std.testing.allocator);
    defer parser.deinit();

    var script = try parser.parse("discard;");
    defer script.deinit();

    try std.testing.expect(script.is_valid);
    try std.testing.expectEqual(@as(usize, 1), script.commands.len);
    try std.testing.expectEqual(CommandType.discard, script.commands[0].command_type);
}

test "parse require command" {
    var parser = SieveParser.init(std.testing.allocator);
    defer parser.deinit();

    var script = try parser.parse(
        \\require "fileinto";
        \\keep;
    );
    defer script.deinit();

    try std.testing.expect(script.is_valid);
    try std.testing.expectEqual(@as(usize, 2), script.commands.len);
    try std.testing.expectEqual(CommandType.require, script.commands[0].command_type);
}

test "parse fileinto command" {
    var parser = SieveParser.init(std.testing.allocator);
    defer parser.deinit();

    var script = try parser.parse(
        \\require "fileinto";
        \\fileinto "INBOX.spam";
    );
    defer script.deinit();

    try std.testing.expect(script.is_valid);
    try std.testing.expectEqual(@as(usize, 2), script.commands.len);
    try std.testing.expectEqual(CommandType.fileinto, script.commands[1].command_type);
}

test "parse if/else command" {
    var parser = SieveParser.init(std.testing.allocator);
    defer parser.deinit();

    var script = try parser.parse(
        \\if header :contains "Subject" "SPAM" {
        \\    discard;
        \\} else {
        \\    keep;
        \\}
    );
    defer script.deinit();

    try std.testing.expect(script.is_valid);
    try std.testing.expectEqual(@as(usize, 1), script.commands.len);
    try std.testing.expectEqual(CommandType.@"if", script.commands[0].command_type);
}

test "wildcard matching" {
    try std.testing.expect(wildcardMatch("hello", "hello"));
    try std.testing.expect(wildcardMatch("hello", "*"));
    try std.testing.expect(wildcardMatch("hello", "h*o"));
    try std.testing.expect(wildcardMatch("hello", "?ello"));
    try std.testing.expect(!wildcardMatch("hello", "world"));
}

test "contains ignore case" {
    try std.testing.expect(containsIgnoreCase("Hello World", "world"));
    try std.testing.expect(containsIgnoreCase("SPAM message", "spam"));
    try std.testing.expect(!containsIgnoreCase("Hello", "xyz"));
}

test "extract address" {
    try std.testing.expectEqualStrings("user@example.com", extractAddress("User Name <user@example.com>"));
    try std.testing.expectEqualStrings("user@example.com", extractAddress("user@example.com"));
}

test "evaluator basic keep" {
    var evaluator = SieveEvaluator.init(std.testing.allocator);

    var parser = SieveParser.init(std.testing.allocator);
    defer parser.deinit();
    var script = try parser.parse("keep;");
    defer script.deinit();

    var msg = SieveMessage.init(std.testing.allocator);
    defer msg.deinit();

    const actions = try evaluator.evaluate(&script, &msg);
    defer std.testing.allocator.free(actions);

    try std.testing.expectEqual(@as(usize, 1), actions.len);
    try std.testing.expectEqual(SieveAction.ActionType.keep, actions[0].action_type);
}

test "evaluator implicit keep" {
    var evaluator = SieveEvaluator.init(std.testing.allocator);

    var parser = SieveParser.init(std.testing.allocator);
    defer parser.deinit();

    // Empty script with just require - should implicit keep
    var script = try parser.parse(
        \\require "fileinto";
    );
    defer script.deinit();

    var msg = SieveMessage.init(std.testing.allocator);
    defer msg.deinit();

    const actions = try evaluator.evaluate(&script, &msg);
    defer std.testing.allocator.free(actions);

    try std.testing.expectEqual(@as(usize, 1), actions.len);
    try std.testing.expectEqual(SieveAction.ActionType.keep, actions[0].action_type);
}

test "command type properties" {
    try std.testing.expect(CommandType.keep.isAction());
    try std.testing.expect(CommandType.fileinto.isAction());
    try std.testing.expect(!CommandType.@"if".isAction());
    try std.testing.expect(CommandType.@"if".isControl());
    try std.testing.expect(CommandType.require.isControl());
}

test "match type strings" {
    try std.testing.expectEqualStrings(":is", MatchType.is.toString());
    try std.testing.expectEqualStrings(":contains", MatchType.contains.toString());
}

test "script manager basic operations" {
    var manager = SieveScriptManager.init(std.testing.allocator);
    defer manager.deinit();

    var parser = SieveParser.init(std.testing.allocator);
    defer parser.deinit();

    const script = try parser.parse("keep;");
    try manager.putScript("user@example.com", "default", script);

    const names = try manager.listScripts("user@example.com");
    defer std.testing.allocator.free(names);
    try std.testing.expectEqual(@as(usize, 1), names.len);
}
