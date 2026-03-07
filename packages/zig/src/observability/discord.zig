const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const env = @import("../core/env.zig");
const logger = @import("../core/logger.zig");

extern "c" fn system(command: [*:0]const u8) c_int;
extern "c" fn access(path: [*:0]const u8, mode: c_int) c_int;
extern "c" fn unlink(path: [*:0]const u8) c_int;

/// Discord Health Monitor
/// Sends health alerts to a Discord channel via webhook.
/// Runs as a background thread, periodically checking server health
/// and sending notifications for important events.
pub const DiscordHealthMonitor = struct {
    allocator: std.mem.Allocator,
    webhook_url: []const u8,
    check_interval_seconds: u32,
    active_connections: *const std.atomic.Value(u32),
    max_connections: usize,
    shutdown: *std.atomic.Value(bool),
    hostname: []const u8,
    start_time: i64,
    domain: []const u8,

    // Alert state tracking (prevents spam)
    last_high_connections_alert: i64 = 0,
    last_auth_failure_alert: i64 = 0,
    last_tls_cert_alert: i64 = 0,
    last_disk_alert: i64 = 0,
    last_db_alert: i64 = 0,
    last_heartbeat: i64 = 0,
    consecutive_db_failures: u32 = 0,

    // Thresholds
    connection_warn_pct: f64 = 0.75,
    connection_critical_pct: f64 = 0.90,
    cert_expiry_warn_days: u32 = 14,
    cert_expiry_critical_days: u32 = 7,
    disk_warn_pct: f64 = 85.0,
    disk_critical_pct: f64 = 95.0,
    heartbeat_interval_seconds: u32 = 3600, // hourly heartbeat
    alert_cooldown_seconds: i64 = 300, // 5 min between repeated alerts

    pub fn init(
        allocator: std.mem.Allocator,
        webhook_url: []const u8,
        active_connections: *const std.atomic.Value(u32),
        max_connections: usize,
        shutdown: *std.atomic.Value(bool),
    ) DiscordHealthMonitor {
        var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
        const hostname = std.posix.gethostname(&hostname_buf) catch "unknown";

        return .{
            .allocator = allocator,
            .webhook_url = webhook_url,
            .check_interval_seconds = 60,
            .active_connections = active_connections,
            .max_connections = max_connections,
            .shutdown = shutdown,
            .hostname = hostname,
            .start_time = time_compat.timestamp(),
            .domain = env.get("SMTP_HOSTNAME") orelse env.get("DOMAIN") orelse "mail.stacksjs.com",
        };
    }

    /// Run the health monitor loop (call from a spawned thread)
    pub fn run(self: *DiscordHealthMonitor) void {
        // Send startup notification
        self.sendStartupAlert();

        while (!self.shutdown.load(.acquire)) {
            // Sleep in small increments so we can check shutdown flag
            var slept: u32 = 0;
            while (slept < self.check_interval_seconds and !self.shutdown.load(.acquire)) {
                time_compat.sleep(1_000_000_000); // 1 second
                slept += 1;
            }

            if (self.shutdown.load(.acquire)) break;

            self.runHealthChecks();
        }

        // Send shutdown notification
        self.sendShutdownAlert();
    }

    fn runHealthChecks(self: *DiscordHealthMonitor) void {
        const now = time_compat.timestamp();

        // Check 1: Connection capacity
        self.checkConnections(now);

        // Check 2: Database accessibility
        self.checkDatabase(now);

        // Check 3: TLS certificate expiry
        self.checkTlsCertificate(now);

        // Check 4: Disk space
        self.checkDiskSpace(now);

        // Check 5: Periodic heartbeat
        self.checkHeartbeat(now);
    }

    // =========================================================================
    // Health checks
    // =========================================================================

    fn checkConnections(self: *DiscordHealthMonitor, now: i64) void {
        const active = self.active_connections.load(.monotonic);
        const ratio = @as(f64, @floatFromInt(active)) / @as(f64, @floatFromInt(self.max_connections));

        if (ratio >= self.connection_critical_pct and now - self.last_high_connections_alert > self.alert_cooldown_seconds) {
            self.last_high_connections_alert = now;
            self.sendEmbed(.{
                .title = "Connection Capacity Critical",
                .description = null,
                .color = Color.red,
                .fields = &[_]Field{
                    .{ .name = "Active", .value_fmt = .{ .uint = active }, .inline_field = true },
                    .{ .name = "Max", .value_fmt = .{ .uint = @intCast(self.max_connections) }, .inline_field = true },
                    .{ .name = "Usage", .value_fmt = .{ .pct = ratio * 100.0 }, .inline_field = true },
                },
            });
        } else if (ratio >= self.connection_warn_pct and now - self.last_high_connections_alert > self.alert_cooldown_seconds) {
            self.last_high_connections_alert = now;
            self.sendEmbed(.{
                .title = "Connection Capacity Warning",
                .description = null,
                .color = Color.orange,
                .fields = &[_]Field{
                    .{ .name = "Active", .value_fmt = .{ .uint = active }, .inline_field = true },
                    .{ .name = "Max", .value_fmt = .{ .uint = @intCast(self.max_connections) }, .inline_field = true },
                    .{ .name = "Usage", .value_fmt = .{ .pct = ratio * 100.0 }, .inline_field = true },
                },
            });
        }
    }

    fn checkDatabase(self: *DiscordHealthMonitor, now: i64) void {
        const db_path = env.get("SMTP_DB_PATH") orelse return;
        // Check file accessibility via libc access()
        const db_accessible = blk: {
            const z = std.heap.c_allocator.dupeZ(u8, db_path) catch break :blk false;
            defer std.heap.c_allocator.free(z);
            break :blk (access(z.ptr, 0) == 0); // F_OK = 0
        };
        if (!db_accessible) {
            self.consecutive_db_failures += 1;
            if (self.consecutive_db_failures >= 3 and now - self.last_db_alert > self.alert_cooldown_seconds) {
                self.last_db_alert = now;
                self.sendEmbed(.{
                    .title = "Database Unreachable",
                    .description = "Cannot access the SMTP database file. Mail delivery and authentication may be impacted.",
                    .color = Color.red,
                    .fields = &[_]Field{
                        .{ .name = "Path", .value_str = db_path, .inline_field = false },
                        .{ .name = "Consecutive Failures", .value_fmt = .{ .uint = self.consecutive_db_failures }, .inline_field = true },
                    },
                });
            }
            return;
        }
        if (self.consecutive_db_failures > 0) {
            // Recovered
            if (self.consecutive_db_failures >= 3) {
                self.sendEmbed(.{
                    .title = "Database Recovered",
                    .description = "Database is accessible again.",
                    .color = Color.green,
                    .fields = &[_]Field{},
                });
            }
            self.consecutive_db_failures = 0;
        }
    }

    fn checkTlsCertificate(self: *DiscordHealthMonitor, now: i64) void {
        const cert_path = env.get("TLS_CERT_PATH") orelse
            env.get("SMTP_TLS_CERT_PATH") orelse return;

        // Check cert file modification time as a proxy for expiry.
        // The actual expiry check is done via shell for simplicity.
        const result = runCommand(self.allocator, &.{
            "openssl", "x509", "-enddate", "-noout", "-in", cert_path,
        }) catch return;
        defer self.allocator.free(result);

        // Parse "notAfter=Mon DD HH:MM:SS YYYY GMT"
        const expiry_epoch = parseCertExpiry(result) orelse return;
        const days_left = @divTrunc(expiry_epoch - now, 86400);

        if (days_left <= self.cert_expiry_critical_days and now - self.last_tls_cert_alert > self.alert_cooldown_seconds) {
            self.last_tls_cert_alert = now;
            self.sendEmbed(.{
                .title = "TLS Certificate Expiring Soon!",
                .description = "The TLS certificate is about to expire. Renew immediately to avoid service disruption.",
                .color = Color.red,
                .fields = &[_]Field{
                    .{ .name = "Days Remaining", .value_fmt = .{ .int = days_left }, .inline_field = true },
                    .{ .name = "Certificate", .value_str = cert_path, .inline_field = false },
                },
            });
        } else if (days_left <= self.cert_expiry_warn_days and now - self.last_tls_cert_alert > 86400) { // Daily warning
            self.last_tls_cert_alert = now;
            self.sendEmbed(.{
                .title = "TLS Certificate Expiry Warning",
                .description = "The TLS certificate will expire soon. Plan for renewal.",
                .color = Color.orange,
                .fields = &[_]Field{
                    .{ .name = "Days Remaining", .value_fmt = .{ .int = days_left }, .inline_field = true },
                },
            });
        }
    }

    fn checkDiskSpace(self: *DiscordHealthMonitor, now: i64) void {
        const result = runCommand(self.allocator, &.{
            "df", "--output=pcent", "/",
        }) catch {
            // macOS doesn't support --output, try alternate
            const mac_result = runCommand(self.allocator, &.{
                "df", "-h", "/",
            }) catch return;
            defer self.allocator.free(mac_result);
            // Parse macOS df output: "Capacity" column
            self.parseMacDfAndAlert(mac_result, now);
            return;
        };
        defer self.allocator.free(result);

        // Parse "Use%\n XX%"
        var lines = std.mem.splitScalar(u8, result, '\n');
        _ = lines.next(); // skip header
        if (lines.next()) |pct_line| {
            const trimmed = std.mem.trim(u8, pct_line, " %\n\r\t");
            const pct = std.fmt.parseFloat(f64, trimmed) catch return;
            self.alertOnDiskUsage(pct, now);
        }
    }

    fn parseMacDfAndAlert(self: *DiscordHealthMonitor, output: []const u8, now: i64) void {
        // macOS df -h output has "Capacity" as second-to-last column
        var lines = std.mem.splitScalar(u8, output, '\n');
        _ = lines.next(); // skip header
        if (lines.next()) |data_line| {
            // Find percentage pattern (e.g., "52%")
            var it = std.mem.splitScalar(u8, data_line, ' ');
            while (it.next()) |field| {
                if (field.len == 0) continue;
                if (std.mem.endsWith(u8, field, "%")) {
                    const pct_str = field[0 .. field.len - 1];
                    const pct = std.fmt.parseFloat(f64, pct_str) catch continue;
                    if (pct > 10.0) { // Sanity check - skip tiny numbers like iuse%
                        self.alertOnDiskUsage(pct, now);
                        return;
                    }
                }
            }
        }
    }

    fn alertOnDiskUsage(self: *DiscordHealthMonitor, pct: f64, now: i64) void {
        if (pct >= self.disk_critical_pct and now - self.last_disk_alert > self.alert_cooldown_seconds) {
            self.last_disk_alert = now;
            self.sendEmbed(.{
                .title = "Disk Space Critical",
                .description = "Server disk is almost full. Mail delivery may fail.",
                .color = Color.red,
                .fields = &[_]Field{
                    .{ .name = "Usage", .value_fmt = .{ .pct = pct }, .inline_field = true },
                },
            });
        } else if (pct >= self.disk_warn_pct and now - self.last_disk_alert > 3600) { // Hourly warning
            self.last_disk_alert = now;
            self.sendEmbed(.{
                .title = "Disk Space Warning",
                .description = "Server disk usage is high.",
                .color = Color.orange,
                .fields = &[_]Field{
                    .{ .name = "Usage", .value_fmt = .{ .pct = pct }, .inline_field = true },
                },
            });
        }
    }

    fn checkHeartbeat(self: *DiscordHealthMonitor, now: i64) void {
        if (now - self.last_heartbeat < self.heartbeat_interval_seconds) return;
        self.last_heartbeat = now;

        const uptime = now - self.start_time;
        const active = self.active_connections.load(.monotonic);

        self.sendEmbed(.{
            .title = "Heartbeat",
            .description = "Server is healthy and running.",
            .color = Color.green,
            .fields = &[_]Field{
                .{ .name = "Uptime", .value_fmt = .{ .duration = uptime }, .inline_field = true },
                .{ .name = "Connections", .value_fmt = .{ .uint = active }, .inline_field = true },
            },
        });
    }

    // =========================================================================
    // Lifecycle alerts
    // =========================================================================

    fn sendStartupAlert(self: *DiscordHealthMonitor) void {
        self.last_heartbeat = time_compat.timestamp();
        self.sendEmbed(.{
            .title = "Server Started",
            .description = "Mail server is online and accepting connections.",
            .color = Color.green,
            .fields = &[_]Field{
                .{ .name = "Domain", .value_str = self.domain, .inline_field = true },
                .{ .name = "Host", .value_str = self.hostname, .inline_field = true },
                .{ .name = "Max Connections", .value_fmt = .{ .uint = @intCast(self.max_connections) }, .inline_field = true },
            },
        });
    }

    fn sendShutdownAlert(self: *DiscordHealthMonitor) void {
        const uptime = time_compat.timestamp() - self.start_time;
        self.sendEmbed(.{
            .title = "Server Shutting Down",
            .description = "Mail server is stopping gracefully.",
            .color = Color.orange,
            .fields = &[_]Field{
                .{ .name = "Uptime", .value_fmt = .{ .duration = uptime }, .inline_field = true },
            },
        });
    }

    // =========================================================================
    // Discord webhook posting
    // =========================================================================

    const Color = struct {
        const green: u32 = 0x2ECC71;
        const orange: u32 = 0xF39C12;
        const red: u32 = 0xE74C3C;
    };

    const FieldValue = union(enum) {
        uint: u32,
        int: i64,
        pct: f64,
        duration: i64, // seconds
    };

    const Field = struct {
        name: []const u8,
        value_str: ?[]const u8 = null,
        value_fmt: ?FieldValue = null,
        inline_field: bool = false,
    };

    const Embed = struct {
        title: []const u8,
        description: ?[]const u8,
        color: u32,
        fields: []const Field,
    };

    fn sendEmbed(self: *DiscordHealthMonitor, embed: Embed) void {
        // Build the JSON payload for Discord
        const json = self.buildPayload(embed) catch |err| {
            logger.err("Failed to build Discord payload: {}", .{err});
            return;
        };
        defer self.allocator.free(json);

        self.postWebhook(json) catch |err| {
            logger.err("Failed to send Discord webhook: {}", .{err});
        };
    }

    fn buildPayload(self: *DiscordHealthMonitor, embed: Embed) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "{\"embeds\":[{\"title\":\"");
        try appendJsonEscaped(&buf, self.allocator, embed.title);
        try buf.appendSlice(self.allocator, "\",\"color\":");
        try appendInt(&buf, self.allocator, embed.color);

        if (embed.description) |desc| {
            try buf.appendSlice(self.allocator, ",\"description\":\"");
            try appendJsonEscaped(&buf, self.allocator, desc);
            try buf.appendSlice(self.allocator, "\"");
        }

        if (embed.fields.len > 0) {
            try buf.appendSlice(self.allocator, ",\"fields\":[");
            for (embed.fields, 0..) |field, i| {
                if (i > 0) try buf.appendSlice(self.allocator, ",");
                try buf.appendSlice(self.allocator, "{\"name\":\"");
                try appendJsonEscaped(&buf, self.allocator, field.name);
                try buf.appendSlice(self.allocator, "\",\"value\":\"");

                if (field.value_str) |s| {
                    try appendJsonEscaped(&buf, self.allocator, s);
                } else if (field.value_fmt) |fmt| {
                    switch (fmt) {
                        .uint => |v| {
                            var num_buf: [20]u8 = undefined;
                            const num = std.fmt.bufPrint(&num_buf, "{d}", .{v}) catch "?";
                            try buf.appendSlice(self.allocator, num);
                        },
                        .int => |v| {
                            var num_buf: [20]u8 = undefined;
                            const num = std.fmt.bufPrint(&num_buf, "{d}", .{v}) catch "?";
                            try buf.appendSlice(self.allocator, num);
                        },
                        .pct => |v| {
                            var num_buf: [20]u8 = undefined;
                            const num = std.fmt.bufPrint(&num_buf, "{d:.1}%", .{v}) catch "?";
                            try buf.appendSlice(self.allocator, num);
                        },
                        .duration => |secs| {
                            try appendDuration(&buf, self.allocator, secs);
                        },
                    }
                }

                try buf.appendSlice(self.allocator, "\",\"inline\":");
                try buf.appendSlice(self.allocator, if (field.inline_field) "true" else "false");
                try buf.appendSlice(self.allocator, "}");
            }
            try buf.appendSlice(self.allocator, "]");
        }

        try buf.appendSlice(self.allocator, ",\"footer\":{\"text\":\"");
        try appendJsonEscaped(&buf, self.allocator, self.domain);
        try buf.appendSlice(self.allocator, "\"}}]}");

        return buf.toOwnedSlice(self.allocator);
    }

    fn postWebhook(self: *DiscordHealthMonitor, json: []const u8) !void {
        // Write JSON to a temp file to avoid shell escaping issues
        const tmp_path: [*:0]const u8 = "/tmp/.mail_discord_payload.json";
        const fp = std.c.fopen(tmp_path, "w") orelse {
            logger.err("Failed to create temp file for Discord webhook", .{});
            return error.TempFileCreationFailed;
        };
        _ = std.c.fwrite(json.ptr, 1, json.len, fp);
        _ = std.c.fclose(fp);

        // Use curl via system() - handles HTTPS natively
        var cmd_buf: [2048:0]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "curl -s -o /dev/null -X POST -H 'Content-Type: application/json' -d @/tmp/.mail_discord_payload.json '{s}' 2>/dev/null", .{self.webhook_url}) catch {
            logger.err("Discord webhook URL too long", .{});
            return;
        };
        cmd_buf[cmd.len] = 0;

        _ = system(&cmd_buf);

        // Cleanup
        _ = unlink(tmp_path);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    fn appendJsonEscaped(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
        for (s) |c| {
            switch (c) {
                '"' => try buf.appendSlice(allocator, "\\\""),
                '\\' => try buf.appendSlice(allocator, "\\\\"),
                '\n' => try buf.appendSlice(allocator, "\\n"),
                '\r' => try buf.appendSlice(allocator, "\\r"),
                '\t' => try buf.appendSlice(allocator, "\\t"),
                else => {
                    if (c < 0x20) {
                        try buf.appendSlice(allocator, "\\u00");
                        const hex = "0123456789abcdef";
                        try buf.append(allocator, hex[c >> 4]);
                        try buf.append(allocator, hex[c & 0x0f]);
                    } else {
                        try buf.append(allocator, c);
                    }
                },
            }
        }
    }

    fn appendInt(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u32) !void {
        var num_buf: [20]u8 = undefined;
        const num = std.fmt.bufPrint(&num_buf, "{d}", .{v}) catch return;
        try buf.appendSlice(allocator, num);
    }

    fn appendDuration(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, total_seconds: i64) !void {
        const secs = @as(u64, @intCast(@max(total_seconds, 0)));
        const days = secs / 86400;
        const hours = (secs % 86400) / 3600;
        const mins = (secs % 3600) / 60;

        var dur_buf: [64]u8 = undefined;
        const dur = if (days > 0)
            std.fmt.bufPrint(&dur_buf, "{d}d {d}h {d}m", .{ days, hours, mins }) catch "?"
        else if (hours > 0)
            std.fmt.bufPrint(&dur_buf, "{d}h {d}m", .{ hours, mins }) catch "?"
        else
            std.fmt.bufPrint(&dur_buf, "{d}m", .{mins}) catch "?";
        try buf.appendSlice(allocator, dur);
    }
};

/// Parse openssl x509 -enddate output to epoch timestamp
fn parseCertExpiry(output: []const u8) ?i64 {
    // Format: "notAfter=Mon  5 12:00:00 2025 GMT\n" or similar
    const prefix = "notAfter=";
    const start = std.mem.indexOf(u8, output, prefix) orelse return null;
    const date_start = start + prefix.len;
    const date_end = std.mem.indexOfPos(u8, output, date_start, "\n") orelse output.len;
    const date_str = std.mem.trim(u8, output[date_start..date_end], " \r\n");

    // Shell out to date for parsing (cross-platform)
    const alloc = std.heap.page_allocator;
    const result = runCommand(alloc, &.{ "date", "-d", date_str, "+%s" }) catch {
        // macOS date syntax differs
        const mac_result = runCommand(alloc, &.{ "date", "-jf", "%b %d %H:%M:%S %Y %Z", date_str, "+%s" }) catch return null;
        defer alloc.free(mac_result);
        return std.fmt.parseInt(i64, std.mem.trim(u8, mac_result, " \n\r"), 10) catch null;
    };
    defer alloc.free(result);
    return std.fmt.parseInt(i64, std.mem.trim(u8, result, " \n\r"), 10) catch null;
}

fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    // Build command string from argv
    var cmd_buf: [1024:0]u8 = undefined;
    var pos: usize = 0;
    for (argv, 0..) |arg, i| {
        if (i > 0) {
            if (pos >= 1024) return error.CommandTooLong;
            cmd_buf[pos] = ' ';
            pos += 1;
        }
        if (pos + arg.len >= 1024) return error.CommandTooLong;
        @memcpy(cmd_buf[pos..][0..arg.len], arg);
        pos += arg.len;
    }

    // Redirect to temp file
    const suffix = " > /tmp/.mail_cmd_output 2>/dev/null";
    if (pos + suffix.len >= 1024) return error.CommandTooLong;
    @memcpy(cmd_buf[pos..][0..suffix.len], suffix);
    pos += suffix.len;
    cmd_buf[pos] = 0;

    const ret = system(&cmd_buf);
    if (ret != 0) return error.CommandFailed;

    // Read output via C FILE
    const fp = std.c.fopen("/tmp/.mail_cmd_output", "r") orelse return error.CommandFailed;
    defer _ = std.c.fclose(fp);
    defer _ = unlink("/tmp/.mail_cmd_output");

    var out_buf: [4096]u8 = undefined;
    const n = std.c.fread(&out_buf, 1, out_buf.len, fp);
    if (n == 0) return error.CommandFailed;

    return try allocator.dupe(u8, out_buf[0..n]);
}

test "duration formatting" {
    const testing = std.testing;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);

    try DiscordHealthMonitor.appendDuration(&buf, testing.allocator, 90061); // 1d 1h 1m
    try testing.expectEqualStrings("1d 1h 1m", buf.items);

    buf.clearRetainingCapacity();
    try DiscordHealthMonitor.appendDuration(&buf, testing.allocator, 3661); // 1h 1m
    try testing.expectEqualStrings("1h 1m", buf.items);

    buf.clearRetainingCapacity();
    try DiscordHealthMonitor.appendDuration(&buf, testing.allocator, 300); // 5m
    try testing.expectEqualStrings("5m", buf.items);
}

test "json escaping" {
    const testing = std.testing;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);

    try DiscordHealthMonitor.appendJsonEscaped(&buf, testing.allocator, "hello \"world\"\nnewline");
    try testing.expectEqualStrings("hello \\\"world\\\"\\nnewline", buf.items);
}

test "embed payload structure" {
    const testing = std.testing;
    var connections = std.atomic.Value(u32).init(5);
    var shutdown = std.atomic.Value(bool).init(false);

    var monitor = DiscordHealthMonitor.init(
        testing.allocator,
        "https://discord.com/api/webhooks/test",
        &connections,
        100,
        &shutdown,
    );

    const json = try monitor.buildPayload(.{
        .title = "Test Alert",
        .description = "Something happened",
        .color = DiscordHealthMonitor.Color.green,
        .fields = &[_]DiscordHealthMonitor.Field{
            .{ .name = "Count", .value_fmt = .{ .uint = 42 }, .inline_field = true },
        },
    });
    defer testing.allocator.free(json);

    // Verify it's valid-ish JSON with expected content
    try testing.expect(std.mem.indexOf(u8, json, "\"title\":\"Test Alert\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"description\":\"Something happened\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"color\":3066993") != null); // 0x2ECC71
    try testing.expect(std.mem.indexOf(u8, json, "\"name\":\"Count\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"value\":\"42\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"embeds\"") != null);
}
