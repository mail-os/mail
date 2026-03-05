const std = @import("std");

/// SMTP PIPELINING support (RFC 2920)
/// Allows clients to send multiple commands without waiting for responses
pub const PipeliningHandler = struct {
    allocator: std.mem.Allocator,
    max_commands: usize, // Maximum number of commands in pipeline
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator, max_commands: usize) PipeliningHandler {
        return .{
            .allocator = allocator,
            .max_commands = max_commands,
            .enabled = true,
        };
    }

    /// Parse a pipelined command buffer into individual commands
    pub fn parseCommands(self: *PipeliningHandler, buffer: []const u8) ![][]const u8 {
        var commands = std.ArrayList([]const u8).init(self.allocator);
        errdefer commands.deinit(self.allocator);

        var lines = std.mem.splitSequence(u8, buffer, "\r\n");
        var count: usize = 0;

        while (lines.next()) |line| {
            if (line.len == 0) continue;

            // Enforce maximum pipeline depth
            if (count >= self.max_commands) {
                return error.TooManyPipelinedCommands;
            }

            try commands.append(self.allocator, try self.allocator.dupe(u8, line));
            count += 1;
        }

        return try commands.toOwnedSlice(self.allocator);
    }

    /// Check if a command can be pipelined
    pub fn canPipeline(self: *PipeliningHandler, command: []const u8) bool {
        _ = self;

        // Commands that CANNOT be pipelined:
        // - DATA (requires special handling)
        // - BDAT (requires chunk data)
        // - AUTH (requires multi-step exchange)
        // - STARTTLS (changes connection state)
        // - QUIT (terminates connection)

        const cmd_upper = std.ascii.upperString(self.allocator, command) catch return false;
        defer self.allocator.free(cmd_upper);

        const cmd_end = std.mem.indexOfScalar(u8, cmd_upper, ' ') orelse cmd_upper.len;
        const cmd_name = cmd_upper[0..cmd_end];

        // Pipelinable commands
        const pipelinable = [_][]const u8{
            "HELO",
            "EHLO",
            "MAIL",
            "RCPT",
            "RSET",
            "NOOP",
            "VRFY",
            "EXPN",
        };

        for (pipelinable) |allowed| {
            if (std.mem.eql(u8, cmd_name, allowed)) {
                return true;
            }
        }

        return false;
    }

    /// Validate a pipeline sequence
    pub fn validatePipeline(self: *PipeliningHandler, commands: []const []const u8) !void {
        if (commands.len == 0) {
            return error.EmptyPipeline;
        }

        if (commands.len > self.max_commands) {
            return error.PipelineTooLong;
        }

        // Check each command is pipelinable
        for (commands) |cmd| {
            if (!self.canPipeline(cmd)) {
                return error.NonPipelinableCommand;
            }
        }

        // Validate command sequence makes sense
        // Example: MAIL must come before RCPT
        var has_mail = false;

        for (commands) |cmd| {
            const cmd_upper = try std.ascii.allocUpperString(self.allocator, cmd);
            defer self.allocator.free(cmd_upper);

            if (std.mem.startsWith(u8, cmd_upper, "MAIL")) {
                has_mail = true;
            } else if (std.mem.startsWith(u8, cmd_upper, "RCPT")) {
                if (!has_mail) {
                    return error.InvalidCommandSequence;
                }
            }
        }
    }

    /// Batch responses for pipelined commands
    pub fn batchResponses(self: *PipeliningHandler, responses: []const []const u8) ![]const u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        for (responses) |response| {
            try buffer.appendSlice(response);
            // Ensure each response ends with \r\n
            if (!std.mem.endsWith(u8, response, "\r\n")) {
                try buffer.appendSlice("\r\n");
            }
        }

        return try buffer.toOwnedSlice();
    }

    /// Free parsed commands
    pub fn freeCommands(self: *PipeliningHandler, commands: [][]const u8) void {
        for (commands) |cmd| {
            self.allocator.free(cmd);
        }
        self.allocator.free(commands);
    }
};

/// Pipeline statistics for monitoring
pub const PipelineStats = struct {
    total_pipelines: usize,
    total_commands: usize,
    max_pipeline_depth: usize,
    avg_pipeline_depth: f64,
    errors: usize,

    pub fn init() PipelineStats {
        return .{
            .total_pipelines = 0,
            .total_commands = 0,
            .max_pipeline_depth = 0,
            .avg_pipeline_depth = 0.0,
            .errors = 0,
        };
    }

    pub fn recordPipeline(self: *PipelineStats, depth: usize) void {
        self.total_pipelines += 1;
        self.total_commands += depth;

        if (depth > self.max_pipeline_depth) {
            self.max_pipeline_depth = depth;
        }

        // Update average
        const total_f: f64 = @floatFromInt(self.total_commands);
        const pipelines_f: f64 = @floatFromInt(self.total_pipelines);
        self.avg_pipeline_depth = total_f / pipelines_f;
    }

    pub fn recordError(self: *PipelineStats) void {
        self.errors += 1;
    }
};

test "parse pipelined commands" {
    const testing = std.testing;

    var handler = PipeliningHandler.init(testing.allocator, 10);

    const buffer = "MAIL FROM:<sender@example.com>\r\nRCPT TO:<recipient@example.com>\r\nRCPT TO:<recipient2@example.com>\r\n";
    const commands = try handler.parseCommands(buffer);
    defer handler.freeCommands(commands);

    try testing.expectEqual(@as(usize, 3), commands.len);
    try testing.expect(std.mem.startsWith(u8, commands[0], "MAIL FROM"));
    try testing.expect(std.mem.startsWith(u8, commands[1], "RCPT TO"));
}

test "can pipeline commands" {
    const testing = std.testing;

    var handler = PipeliningHandler.init(testing.allocator, 10);

    // Pipelinable commands
    try testing.expect(handler.canPipeline("MAIL FROM:<test@example.com>"));
    try testing.expect(handler.canPipeline("RCPT TO:<test@example.com>"));
    try testing.expect(handler.canPipeline("RSET"));
    try testing.expect(handler.canPipeline("NOOP"));

    // Non-pipelinable commands
    try testing.expect(!handler.canPipeline("DATA"));
    try testing.expect(!handler.canPipeline("QUIT"));
    try testing.expect(!handler.canPipeline("STARTTLS"));
    try testing.expect(!handler.canPipeline("AUTH PLAIN"));
}

test "validate pipeline sequence" {
    const testing = std.testing;

    var handler = PipeliningHandler.init(testing.allocator, 10);

    // Valid sequence
    const valid = [_][]const u8{
        "MAIL FROM:<sender@example.com>",
        "RCPT TO:<recipient@example.com>",
    };
    try handler.validatePipeline(&valid);

    // Invalid: RCPT before MAIL
    const invalid = [_][]const u8{
        "RCPT TO:<recipient@example.com>",
    };
    try testing.expectError(error.InvalidCommandSequence, handler.validatePipeline(&invalid));
}

test "batch responses" {
    const testing = std.testing;

    var handler = PipeliningHandler.init(testing.allocator, 10);

    const responses = [_][]const u8{
        "250 OK\r\n",
        "250 Accepted\r\n",
        "250 OK\r\n",
    };

    const batched = try handler.batchResponses(&responses);
    defer testing.allocator.free(batched);

    try testing.expect(std.mem.indexOf(u8, batched, "250 OK") != null);
    try testing.expect(std.mem.indexOf(u8, batched, "250 Accepted") != null);
}

test "pipeline statistics" {
    const testing = std.testing;

    var stats = PipelineStats.init();

    stats.recordPipeline(3);
    stats.recordPipeline(5);
    stats.recordPipeline(2);

    try testing.expectEqual(@as(usize, 3), stats.total_pipelines);
    try testing.expectEqual(@as(usize, 10), stats.total_commands);
    try testing.expectEqual(@as(usize, 5), stats.max_pipeline_depth);

    const expected_avg = 10.0 / 3.0;
    try testing.expect(stats.avg_pipeline_depth > expected_avg - 0.1 and stats.avg_pipeline_depth < expected_avg + 0.1);
}

test "enforce max pipeline depth" {
    const testing = std.testing;

    var handler = PipeliningHandler.init(testing.allocator, 3);

    // Exactly at limit should work
    const at_limit = "MAIL FROM:<a>\r\nRCPT TO:<b>\r\nRSET\r\n";
    const commands_ok = try handler.parseCommands(at_limit);
    defer handler.freeCommands(commands_ok);
    try testing.expectEqual(@as(usize, 3), commands_ok.len);

    // Over limit should fail
    const over_limit = "MAIL FROM:<a>\r\nRCPT TO:<b>\r\nRCPT TO:<c>\r\nRSET\r\n";
    try testing.expectError(error.TooManyPipelinedCommands, handler.parseCommands(over_limit));
}
