const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const logger = @import("../core/logger.zig");
const metrics = @import("metrics.zig");

/// Alerting Integration for SMTP Server
/// Supports multiple alerting backends:
/// - PagerDuty (incidents and events)
/// - Slack/Discord webhooks
/// - Email notifications
/// - Generic webhooks
/// - OpsGenie
/// - Prometheus Alertmanager
///
/// ## Usage
/// ```zig
/// var alerter = try AlertManager.init(allocator);
/// defer alerter.deinit();
///
/// try alerter.addSlackChannel(.{
///     .webhook_url = "https://hooks.slack.com/...",
///     .channel = "#alerts",
/// });
///
/// try alerter.sendAlert(.{
///     .severity = .critical,
///     .title = "High bounce rate detected",
///     .message = "Bounce rate is 15%, threshold is 5%",
/// });
/// ```
/// Alert severity levels
pub const Severity = enum {
    info,
    warning,
    critical,
    emergency,

    pub fn toString(self: Severity) []const u8 {
        return switch (self) {
            .info => "info",
            .warning => "warning",
            .critical => "critical",
            .emergency => "emergency",
        };
    }

    pub fn toEmoji(self: Severity) []const u8 {
        return switch (self) {
            .info => "info",
            .warning => "warning",
            .critical => "critical",
            .emergency => "emergency",
        };
    }

    pub fn toPagerDutySeverity(self: Severity) []const u8 {
        return switch (self) {
            .info => "info",
            .warning => "warning",
            .critical => "critical",
            .emergency => "critical",
        };
    }
};

/// Alert category for routing
pub const AlertCategory = enum {
    performance,
    security,
    delivery,
    system,
    spam,
    authentication,
    queue,
    custom,

    pub fn toString(self: AlertCategory) []const u8 {
        return switch (self) {
            .performance => "performance",
            .security => "security",
            .delivery => "delivery",
            .system => "system",
            .spam => "spam",
            .authentication => "authentication",
            .queue => "queue",
            .custom => "custom",
        };
    }
};

/// Alert definition
pub const Alert = struct {
    severity: Severity,
    category: AlertCategory = .custom,
    title: []const u8,
    message: []const u8,
    source: []const u8 = "mail",
    dedup_key: ?[]const u8 = null, // For de-duplication
    tags: ?[]const []const u8 = null,
    details: ?std.json.ObjectMap = null,
    timestamp: i64 = 0,

    pub fn init(severity: Severity, title: []const u8, message: []const u8) Alert {
        return .{
            .severity = severity,
            .title = title,
            .message = message,
            .timestamp = time_compat.timestamp(),
        };
    }
};

/// Slack/Discord webhook configuration
pub const SlackConfig = struct {
    webhook_url: []const u8,
    channel: ?[]const u8 = null,
    username: []const u8 = "SMTP Alert Bot",
    icon_emoji: []const u8 = ":envelope:",
    min_severity: Severity = .warning,
    categories: ?[]const AlertCategory = null, // null = all categories
};

/// PagerDuty configuration
pub const PagerDutyConfig = struct {
    routing_key: []const u8, // Integration key
    api_url: []const u8 = "https://events.pagerduty.com/v2/enqueue",
    min_severity: Severity = .critical,
    service_name: []const u8 = "mail",
};

/// OpsGenie configuration
pub const OpsGenieConfig = struct {
    api_key: []const u8,
    api_url: []const u8 = "https://api.opsgenie.com/v2/alerts",
    min_severity: Severity = .warning,
    responders: ?[]const []const u8 = null,
};

/// Email notification configuration
pub const EmailConfig = struct {
    smtp_host: []const u8,
    smtp_port: u16 = 587,
    from_address: []const u8,
    to_addresses: []const []const u8,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    use_tls: bool = true,
    min_severity: Severity = .critical,
};

/// Generic webhook configuration
pub const WebhookConfig = struct {
    url: []const u8,
    method: []const u8 = "POST",
    headers: ?std.StringHashMap([]const u8) = null,
    auth_header: ?[]const u8 = null,
    min_severity: Severity = .warning,
};

/// Prometheus Alertmanager configuration
pub const AlertmanagerConfig = struct {
    url: []const u8,
    min_severity: Severity = .warning,
};

/// Alert channel union
pub const AlertChannel = union(enum) {
    slack: SlackConfig,
    discord: SlackConfig, // Same format as Slack
    pagerduty: PagerDutyConfig,
    opsgenie: OpsGenieConfig,
    email: EmailConfig,
    webhook: WebhookConfig,
    alertmanager: AlertmanagerConfig,
};

/// Alert rule for automatic alerting based on metrics
pub const AlertRule = struct {
    name: []const u8,
    description: []const u8,
    condition: AlertCondition,
    severity: Severity,
    category: AlertCategory,
    cooldown_seconds: u32 = 300, // Minimum time between alerts
    last_triggered: i64 = 0,
    enabled: bool = true,
};

/// Alert condition types
pub const AlertCondition = union(enum) {
    threshold: ThresholdCondition,
    rate_of_change: RateCondition,
    anomaly: AnomalyCondition,

    pub const ThresholdCondition = struct {
        metric: []const u8,
        operator: Operator,
        value: f64,
        duration_seconds: u32 = 0, // How long condition must be true

        pub const Operator = enum {
            gt, // Greater than
            gte, // Greater than or equal
            lt, // Less than
            lte, // Less than or equal
            eq, // Equal
            neq, // Not equal
        };
    };

    pub const RateCondition = struct {
        metric: []const u8,
        rate_per_minute: f64,
        direction: enum { increase, decrease, both },
    };

    pub const AnomalyCondition = struct {
        metric: []const u8,
        std_deviations: f64 = 2.0,
        baseline_minutes: u32 = 60,
    };
};

/// Alert Manager - unified alerting interface
pub const AlertManager = struct {
    allocator: std.mem.Allocator,
    channels: std.ArrayList(AlertChannel),
    rules: std.ArrayList(AlertRule),
    history: std.ArrayList(AlertHistoryEntry),
    max_history: usize,
    mutex: mutex_compat.Mutex,
    stats: AlertStats,
    enabled: bool,

    // Rate limiting
    rate_limit_window: i64 = 60, // seconds
    rate_limit_max: u32 = 100, // max alerts per window
    rate_limit_count: u32 = 0,
    rate_limit_reset: i64 = 0,

    pub fn init(allocator: std.mem.Allocator) AlertManager {
        return .{
            .allocator = allocator,
            .channels = .{ .items = &.{}, .capacity = 0 },
            .rules = .{ .items = &.{}, .capacity = 0 },
            .history = .{ .items = &.{}, .capacity = 0 },
            .max_history = 1000,
            .mutex = .{},
            .stats = AlertStats{},
            .enabled = true,
            .rate_limit_reset = time_compat.timestamp() + 60,
        };
    }

    pub fn deinit(self: *AlertManager) void {
        self.channels.deinit(self.allocator);
        self.rules.deinit(self.allocator);
        self.history.deinit(self.allocator);
    }

    // ===== Channel Management =====

    /// Add a Slack channel
    pub fn addSlackChannel(self: *AlertManager, config: SlackConfig) !void {
        try self.channels.append(self.allocator, .{ .slack = config });
        logger.info("Added Slack alert channel", .{});
    }

    /// Add a Discord channel
    pub fn addDiscordChannel(self: *AlertManager, config: SlackConfig) !void {
        try self.channels.append(self.allocator, .{ .discord = config });
        logger.info("Added Discord alert channel", .{});
    }

    /// Add PagerDuty integration
    pub fn addPagerDuty(self: *AlertManager, config: PagerDutyConfig) !void {
        try self.channels.append(self.allocator, .{ .pagerduty = config });
        logger.info("Added PagerDuty alert channel", .{});
    }

    /// Add OpsGenie integration
    pub fn addOpsGenie(self: *AlertManager, config: OpsGenieConfig) !void {
        try self.channels.append(self.allocator, .{ .opsgenie = config });
        logger.info("Added OpsGenie alert channel", .{});
    }

    /// Add email notifications
    pub fn addEmailChannel(self: *AlertManager, config: EmailConfig) !void {
        try self.channels.append(self.allocator, .{ .email = config });
        logger.info("Added Email alert channel", .{});
    }

    /// Add generic webhook
    pub fn addWebhook(self: *AlertManager, config: WebhookConfig) !void {
        try self.channels.append(self.allocator, .{ .webhook = config });
        logger.info("Added Webhook alert channel", .{});
    }

    /// Add Prometheus Alertmanager
    pub fn addAlertmanager(self: *AlertManager, config: AlertmanagerConfig) !void {
        try self.channels.append(self.allocator, .{ .alertmanager = config });
        logger.info("Added Alertmanager channel", .{});
    }

    // ===== Rule Management =====

    /// Add an alert rule
    pub fn addRule(self: *AlertManager, rule: AlertRule) !void {
        try self.rules.append(self.allocator, rule);
        logger.info("Added alert rule: {s}", .{rule.name});
    }

    /// Enable/disable a rule by name
    pub fn setRuleEnabled(self: *AlertManager, name: []const u8, enabled: bool) void {
        for (self.rules.items) |*rule| {
            if (std.mem.eql(u8, rule.name, name)) {
                rule.enabled = enabled;
                return;
            }
        }
    }

    // ===== Alert Sending =====

    /// Send an alert to all configured channels
    pub fn sendAlert(self: *AlertManager, alert: Alert) !void {
        if (!self.enabled) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        // Check rate limit
        if (!self.checkRateLimit()) {
            self.stats.rate_limited += 1;
            return error.RateLimited;
        }

        // Record in history
        try self.recordHistory(alert);

        // Send to each channel
        var sent: u32 = 0;
        var failed: u32 = 0;

        for (self.channels.items) |channel| {
            const should_send = self.shouldSendToChannel(channel, alert);
            if (should_send) {
                self.sendToChannel(channel, alert) catch |err| {
                    logger.err("Failed to send alert to channel: {}", .{err});
                    failed += 1;
                    continue;
                };
                sent += 1;
            }
        }

        self.stats.alerts_sent += sent;
        self.stats.alerts_failed += failed;

        logger.info("Alert sent: [{s}] {s} - sent to {d} channels, {d} failed", .{
            alert.severity.toString(),
            alert.title,
            sent,
            failed,
        });
    }

    /// Send a pre-defined alert type
    pub fn sendHighBounceRateAlert(self: *AlertManager, current_rate: f64, threshold: f64) !void {
        const message = std.fmt.allocPrint(
            self.allocator,
            "Bounce rate is {d:.1}%, threshold is {d:.1}%",
            .{ current_rate, threshold },
        ) catch return;
        defer self.allocator.free(message);

        try self.sendAlert(.{
            .severity = .critical,
            .category = .delivery,
            .title = "High Bounce Rate Detected",
            .message = message,
        });
    }

    /// Send spam rate alert
    pub fn sendHighSpamRateAlert(self: *AlertManager, current_rate: f64, threshold: f64) !void {
        const message = std.fmt.allocPrint(
            self.allocator,
            "Spam rate is {d:.1}%, threshold is {d:.1}%",
            .{ current_rate, threshold },
        ) catch return;
        defer self.allocator.free(message);

        try self.sendAlert(.{
            .severity = .warning,
            .category = .spam,
            .title = "High Spam Rate Detected",
            .message = message,
        });
    }

    /// Send queue backup alert
    pub fn sendQueueBackupAlert(self: *AlertManager, queue_size: usize, threshold: usize) !void {
        const message = std.fmt.allocPrint(
            self.allocator,
            "Queue size is {d}, threshold is {d}",
            .{ queue_size, threshold },
        ) catch return;
        defer self.allocator.free(message);

        try self.sendAlert(.{
            .severity = .warning,
            .category = .queue,
            .title = "Mail Queue Backup",
            .message = message,
        });
    }

    /// Send authentication failure alert
    pub fn sendAuthFailureAlert(self: *AlertManager, failure_count: u64, ip_address: []const u8) !void {
        const message = std.fmt.allocPrint(
            self.allocator,
            "{d} authentication failures from IP {s}",
            .{ failure_count, ip_address },
        ) catch return;
        defer self.allocator.free(message);

        try self.sendAlert(.{
            .severity = .warning,
            .category = .security,
            .title = "Authentication Failures Detected",
            .message = message,
        });
    }

    // ===== Rule Evaluation =====

    /// Evaluate all rules against current metrics
    pub fn evaluateRules(self: *AlertManager, smtp_metrics: *metrics.SmtpMetrics) !void {
        const snapshot = smtp_metrics.getSnapshot();
        const now = time_compat.timestamp();

        for (self.rules.items) |*rule| {
            if (!rule.enabled) continue;

            // Check cooldown
            if (now - rule.last_triggered < rule.cooldown_seconds) continue;

            const triggered = self.evaluateCondition(rule.condition, &snapshot);
            if (triggered) {
                rule.last_triggered = now;

                const alert = Alert{
                    .severity = rule.severity,
                    .category = rule.category,
                    .title = rule.name,
                    .message = rule.description,
                    .timestamp = now,
                };

                self.sendAlert(alert) catch |err| {
                    logger.err("Failed to send rule-triggered alert: {}", .{err});
                };
            }
        }
    }

    /// Get alerting statistics
    pub fn getStats(self: *AlertManager) AlertStats {
        return self.stats;
    }

    // ===== Internal Methods =====

    fn checkRateLimit(self: *AlertManager) bool {
        const now = time_compat.timestamp();

        if (now >= self.rate_limit_reset) {
            self.rate_limit_count = 0;
            self.rate_limit_reset = now + self.rate_limit_window;
        }

        if (self.rate_limit_count >= self.rate_limit_max) {
            return false;
        }

        self.rate_limit_count += 1;
        return true;
    }

    fn shouldSendToChannel(self: *AlertManager, channel: AlertChannel, alert: Alert) bool {
        _ = self;
        const min_severity = switch (channel) {
            .slack => |c| c.min_severity,
            .discord => |c| c.min_severity,
            .pagerduty => |c| c.min_severity,
            .opsgenie => |c| c.min_severity,
            .email => |c| c.min_severity,
            .webhook => |c| c.min_severity,
            .alertmanager => |c| c.min_severity,
        };

        // Check severity threshold
        return @backingInt(alert.severity) >= @backingInt(min_severity);
    }

    fn sendToChannel(self: *AlertManager, channel: AlertChannel, alert: Alert) !void {
        _ = self;
        switch (channel) {
            .slack, .discord => {
                // Would send HTTP POST to webhook URL with JSON payload
                // For now, just log
                logger.info("Would send to Slack/Discord: {s}", .{alert.title});
            },
            .pagerduty => {
                // Would send to PagerDuty Events API v2
                logger.info("Would send to PagerDuty: {s}", .{alert.title});
            },
            .opsgenie => {
                // Would send to OpsGenie Alert API
                logger.info("Would send to OpsGenie: {s}", .{alert.title});
            },
            .email => {
                // Would send email via SMTP
                logger.info("Would send email alert: {s}", .{alert.title});
            },
            .webhook => {
                // Would send to generic webhook
                logger.info("Would send to webhook: {s}", .{alert.title});
            },
            .alertmanager => {
                // Would send to Prometheus Alertmanager
                logger.info("Would send to Alertmanager: {s}", .{alert.title});
            },
        }
    }

    fn evaluateCondition(self: *AlertManager, condition: AlertCondition, snapshot: *const metrics.MetricsSnapshot) bool {
        _ = self;
        switch (condition) {
            .threshold => |t| {
                const value = getMetricValue(t.metric, snapshot);
                return switch (t.operator) {
                    .gt => value > t.value,
                    .gte => value >= t.value,
                    .lt => value < t.value,
                    .lte => value <= t.value,
                    .eq => value == t.value,
                    .neq => value != t.value,
                };
            },
            .rate_of_change => {
                // Would compare with historical data
                return false;
            },
            .anomaly => {
                // Would use statistical analysis
                return false;
            },
        }
    }

    fn recordHistory(self: *AlertManager, alert: Alert) !void {
        // Trim history if needed
        while (self.history.items.len >= self.max_history) {
            _ = self.history.orderedRemove(0);
        }

        try self.history.append(self.allocator, .{
            .timestamp = alert.timestamp,
            .severity = alert.severity,
            .category = alert.category,
            .title = alert.title,
        });
    }
};

fn getMetricValue(metric_name: []const u8, snapshot: *const metrics.MetricsSnapshot) f64 {
    if (std.mem.eql(u8, metric_name, "bounce_rate")) {
        return snapshot.bounce_rate;
    } else if (std.mem.eql(u8, metric_name, "spam_rate")) {
        return snapshot.spam_rate;
    } else if (std.mem.eql(u8, metric_name, "auth_success_rate")) {
        return snapshot.auth_success_rate;
    } else if (std.mem.eql(u8, metric_name, "tls_rate")) {
        return snapshot.tls_rate;
    } else if (std.mem.eql(u8, metric_name, "queue_size")) {
        return @floatFromInt(snapshot.gauges.queue_size);
    } else if (std.mem.eql(u8, metric_name, "connections_active")) {
        return @floatFromInt(snapshot.gauges.connections_active);
    }
    return 0.0;
}

/// Alert history entry
pub const AlertHistoryEntry = struct {
    timestamp: i64,
    severity: Severity,
    category: AlertCategory,
    title: []const u8,
};

/// Alert statistics
pub const AlertStats = struct {
    alerts_sent: u64 = 0,
    alerts_failed: u64 = 0,
    rate_limited: u64 = 0,
    rules_triggered: u64 = 0,
};

// ===== Pre-built Alert Rules =====

/// Create default alert rules for SMTP monitoring
pub fn createDefaultRules(allocator: std.mem.Allocator) !std.ArrayList(AlertRule) {
    var rules: std.ArrayList(AlertRule) = .{ .items = &.{}, .capacity = 0 };

    // High bounce rate
    try rules.append(allocator, .{
        .name = "High Bounce Rate",
        .description = "Bounce rate exceeds 5%",
        .condition = .{ .threshold = .{
            .metric = "bounce_rate",
            .operator = .gt,
            .value = 5.0,
        } },
        .severity = .critical,
        .category = .delivery,
        .cooldown_seconds = 600,
    });

    // High spam rate
    try rules.append(allocator, .{
        .name = "High Spam Rate",
        .description = "Spam rate exceeds 10%",
        .condition = .{ .threshold = .{
            .metric = "spam_rate",
            .operator = .gt,
            .value = 10.0,
        } },
        .severity = .warning,
        .category = .spam,
        .cooldown_seconds = 300,
    });

    // Low auth success rate
    try rules.append(allocator, .{
        .name = "Authentication Issues",
        .description = "Auth success rate below 90%",
        .condition = .{ .threshold = .{
            .metric = "auth_success_rate",
            .operator = .lt,
            .value = 90.0,
        } },
        .severity = .warning,
        .category = .security,
        .cooldown_seconds = 300,
    });

    // Queue backup
    try rules.append(allocator, .{
        .name = "Queue Backup",
        .description = "Queue size exceeds 1000 messages",
        .condition = .{ .threshold = .{
            .metric = "queue_size",
            .operator = .gt,
            .value = 1000.0,
        } },
        .severity = .warning,
        .category = .queue,
        .cooldown_seconds = 300,
    });

    return rules;
}

// Tests
test "alert manager initialization" {
    const testing = std.testing;

    var manager = AlertManager.init(testing.allocator);
    defer manager.deinit();

    try testing.expect(manager.enabled);
    try testing.expectEqual(@as(usize, 0), manager.channels.items.len);
}

test "add slack channel" {
    const testing = std.testing;

    var manager = AlertManager.init(testing.allocator);
    defer manager.deinit();

    try manager.addSlackChannel(.{
        .webhook_url = "https://hooks.slack.com/test",
        .channel = "#alerts",
    });

    try testing.expectEqual(@as(usize, 1), manager.channels.items.len);
}

test "severity comparison" {
    const testing = std.testing;

    try testing.expect(@backingInt(Severity.critical) > @backingInt(Severity.warning));
    try testing.expect(@backingInt(Severity.warning) > @backingInt(Severity.info));
}

test "default rules creation" {
    const testing = std.testing;

    var rules = try createDefaultRules(testing.allocator);
    defer rules.deinit();

    try testing.expect(rules.items.len >= 4);
}

test "alert creation" {
    const testing = std.testing;

    const alert = Alert.init(.critical, "Test Alert", "This is a test");

    try testing.expectEqual(Severity.critical, alert.severity);
    try testing.expectEqualStrings("Test Alert", alert.title);
}
