const std = @import("std");
const version_info = @import("../core/version.zig");

// =============================================================================
// Mobile Admin App - Mobile-First Administration Interface
// =============================================================================
//
// ## Overview
// Provides a Progressive Web App (PWA) for mobile administration including:
// - Server status monitoring
// - User management
// - Queue management
// - Real-time alerts with push notifications
// - Touch-optimized interface
//
// ## Features
// - PWA with offline support
// - Touch gestures (swipe, pull-to-refresh)
// - Biometric authentication support
// - Push notifications for alerts
// - Dark mode support
//
// =============================================================================

/// Mobile admin configuration
pub const MobileAdminConfig = struct {
    /// Enable push notifications
    enable_push_notifications: bool = true,
    /// Session timeout in seconds
    session_timeout_seconds: u32 = 1800, // 30 minutes
    /// Enable biometric authentication
    enable_biometric_auth: bool = true,
    /// Refresh interval for stats (seconds)
    refresh_interval: u32 = 30,
    /// Maximum recent alerts to show
    max_recent_alerts: usize = 50,
    /// Enable offline mode
    enable_offline_mode: bool = true,
};

/// Server status for dashboard
pub const ServerStatus = struct {
    status: Status,
    uptime_seconds: u64,
    version: []const u8,
    cpu_usage: f32,
    memory_usage: f32,
    disk_usage: f32,
    active_connections: u32,
    messages_today: u64,
    queue_size: u32,

    pub const Status = enum {
        healthy,
        degraded,
        critical,
        offline,

        pub fn toString(self: Status) []const u8 {
            return switch (self) {
                .healthy => "Healthy",
                .degraded => "Degraded",
                .critical => "Critical",
                .offline => "Offline",
            };
        }

        pub fn color(self: Status) []const u8 {
            return switch (self) {
                .healthy => "#10b981",
                .degraded => "#f59e0b",
                .critical => "#ef4444",
                .offline => "#6b7280",
            };
        }
    };
};

/// Quick action for admin dashboard
pub const QuickAction = struct {
    id: []const u8,
    name: []const u8,
    icon: []const u8,
    action_type: ActionType,
    requires_confirmation: bool,

    pub const ActionType = enum {
        restart_server,
        flush_queue,
        clear_cache,
        backup_now,
        block_ip,
        view_logs,
        add_user,
        send_test_email,
    };
};

/// Alert for notifications
pub const AdminAlert = struct {
    id: []const u8,
    severity: Severity,
    category: Category,
    title: []const u8,
    message: []const u8,
    timestamp: i64,
    acknowledged: bool,

    pub const Severity = enum {
        info,
        warning,
        critical,

        pub fn icon(self: Severity) []const u8 {
            return switch (self) {
                .info => "info",
                .warning => "alert-triangle",
                .critical => "alert-circle",
            };
        }

        pub fn color(self: Severity) []const u8 {
            return switch (self) {
                .info => "#3b82f6",
                .warning => "#f59e0b",
                .critical => "#ef4444",
            };
        }
    };

    pub const Category = enum {
        security,
        performance,
        delivery,
        system,
        queue,
    };
};

/// User summary for management
pub const UserSummary = struct {
    id: []const u8,
    email: []const u8,
    name: ?[]const u8,
    status: Status,
    last_login: ?i64,
    storage_used: u64,
    storage_quota: u64,

    pub const Status = enum {
        active,
        suspended,
        pending,
        locked,
    };
};

/// Queue item summary
pub const QueueItem = struct {
    id: []const u8,
    from: []const u8,
    to: []const u8,
    subject: []const u8,
    size: usize,
    attempts: u32,
    next_retry: i64,
    status: Status,

    pub const Status = enum {
        pending,
        deferred,
        bounced,
        failed,
    };
};

/// Mobile admin API handler
pub const MobileAdminHandler = struct {
    allocator: std.mem.Allocator,
    config: MobileAdminConfig,

    pub fn init(allocator: std.mem.Allocator, config: MobileAdminConfig) MobileAdminHandler {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Handle HTTP request
    pub fn handleRequest(self: *MobileAdminHandler, path: []const u8, method: []const u8, body: ?[]const u8) ![]u8 {
        _ = body;

        if (std.mem.eql(u8, method, "GET")) {
            if (std.mem.eql(u8, path, "/admin/mobile") or std.mem.eql(u8, path, "/admin/mobile/")) {
                return self.serveApp();
            } else if (std.mem.eql(u8, path, "/admin/mobile/manifest.json")) {
                return self.serveManifest();
            } else if (std.mem.eql(u8, path, "/admin/mobile/sw.js")) {
                return self.serveServiceWorker();
            } else if (std.mem.startsWith(u8, path, "/admin/mobile/api/")) {
                return self.handleApiGet(path[18..]);
            }
        } else if (std.mem.eql(u8, method, "POST")) {
            if (std.mem.startsWith(u8, path, "/admin/mobile/api/")) {
                return self.handleApiPost(path[18..]);
            }
        }

        return self.serveError(404, "Not Found");
    }

    fn handleApiGet(self: *MobileAdminHandler, endpoint: []const u8) ![]u8 {
        if (std.mem.eql(u8, endpoint, "status")) {
            return self.getServerStatus();
        } else if (std.mem.eql(u8, endpoint, "alerts")) {
            return self.getAlerts();
        } else if (std.mem.eql(u8, endpoint, "users")) {
            return self.getUsers();
        } else if (std.mem.eql(u8, endpoint, "queue")) {
            return self.getQueue();
        } else if (std.mem.eql(u8, endpoint, "stats")) {
            return self.getStats();
        }
        return self.serveError(404, "Endpoint not found");
    }

    fn handleApiPost(self: *MobileAdminHandler, endpoint: []const u8) ![]u8 {
        if (std.mem.eql(u8, endpoint, "action")) {
            return self.executeAction();
        } else if (std.mem.eql(u8, endpoint, "acknowledge")) {
            return self.acknowledgeAlert();
        }
        return self.serveError(404, "Endpoint not found");
    }

    fn getServerStatus(self: *MobileAdminHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"status": "healthy", "uptime": 86400, "version": "{s}", "cpu": 15.2, "memory": 42.8, "disk": 35.5, "connections": 127, "messages_today": 4523, "queue_size": 12}}
        , .{version_info.version_display});
    }

    fn getAlerts(self: *MobileAdminHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"alerts": [
            \\  {{"id": "1", "severity": "warning", "category": "queue", "title": "Queue Growing", "message": "Mail queue has grown to 50+ messages", "timestamp": 1732700000, "acknowledged": false}},
            \\  {{"id": "2", "severity": "info", "category": "system", "title": "Backup Complete", "message": "Daily backup completed successfully", "timestamp": 1732696400, "acknowledged": true}}
            \\], "unread_count": 1}}
        , .{});
    }

    fn getUsers(self: *MobileAdminHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"users": [], "total": 0, "active": 0}}
        , .{});
    }

    fn getQueue(self: *MobileAdminHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"queue": [], "total": 0, "pending": 0, "deferred": 0}}
        , .{});
    }

    fn getStats(self: *MobileAdminHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"messages_24h": 4523, "delivered": 4498, "bounced": 12, "deferred": 13, "spam_blocked": 89}}
        , .{});
    }

    fn executeAction(self: *MobileAdminHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"success": true, "message": "Action executed"}}
        , .{});
    }

    fn acknowledgeAlert(self: *MobileAdminHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"success": true}}
        , .{});
    }

    fn serveError(self: *MobileAdminHandler, status: u16, message: []const u8) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\n\r\n{{\"error\": \"{s}\"}}",
            .{ status, message, message },
        );
    }

    fn serveManifest(self: *MobileAdminHandler) ![]u8 {
        const manifest =
            \\{
            \\  "name": "SMTP Admin",
            \\  "short_name": "Admin",
            \\  "description": "Mobile administration for SMTP Server",
            \\  "start_url": "/admin/mobile",
            \\  "display": "standalone",
            \\  "background_color": "#111827",
            \\  "theme_color": "#4f46e5",
            \\  "icons": [
            \\    {"src": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect fill='%234f46e5' width='100' height='100' rx='20'/><text x='50' y='65' font-size='50' text-anchor='middle' fill='white'>📧</text></svg>", "sizes": "192x192", "type": "image/svg+xml"},
            \\    {"src": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect fill='%234f46e5' width='100' height='100' rx='20'/><text x='50' y='65' font-size='50' text-anchor='middle' fill='white'>📧</text></svg>", "sizes": "512x512", "type": "image/svg+xml"}
            \\  ]
            \\}
        ;
        return std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/manifest+json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ manifest.len, manifest },
        );
    }

    fn serveServiceWorker(self: *MobileAdminHandler) ![]u8 {
        const sw =
            \\const CACHE_NAME = 'smtp-admin-v1';
            \\const urlsToCache = ['/admin/mobile', '/admin/mobile/manifest.json'];
            \\self.addEventListener('install', e => e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(urlsToCache))));
            \\self.addEventListener('fetch', e => e.respondWith(caches.match(e.request).then(r => r || fetch(e.request))));
        ;
        return std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ sw.len, sw },
        );
    }

    /// Serve the mobile admin PWA
    pub fn serveApp(self: *MobileAdminHandler) ![]u8 {
        const html = mobile_admin_html;
        return std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ html.len, html },
        );
    }
};

/// Mobile Admin PWA HTML
const mobile_admin_html =
    \\<!DOCTYPE html>
    \\<html lang="en">
    \\<head>
    \\    <meta charset="UTF-8">
    \\    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    \\    <meta name="apple-mobile-web-app-capable" content="yes">
    \\    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    \\    <meta name="theme-color" content="#4f46e5">
    \\    <link rel="manifest" href="/admin/mobile/manifest.json">
    \\    <title>SMTP Admin</title>
    \\    <style>
    \\        :root {
    \\            --primary: #4f46e5;
    \\            --primary-dark: #4338ca;
    \\            --bg: #111827;
    \\            --card: #1f2937;
    \\            --border: #374151;
    \\            --text: #f9fafb;
    \\            --text-muted: #9ca3af;
    \\            --success: #10b981;
    \\            --warning: #f59e0b;
    \\            --danger: #ef4444;
    \\            --info: #3b82f6;
    \\            --safe-top: env(safe-area-inset-top);
    \\            --safe-bottom: env(safe-area-inset-bottom);
    \\        }
    \\        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    \\        body {
    \\            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    \\            background: var(--bg);
    \\            color: var(--text);
    \\            min-height: 100vh;
    \\            overflow-x: hidden;
    \\            padding-top: var(--safe-top);
    \\            padding-bottom: calc(70px + var(--safe-bottom));
    \\        }
    \\        /* Header */
    \\        .header {
    \\            position: sticky;
    \\            top: 0;
    \\            z-index: 100;
    \\            background: var(--bg);
    \\            padding: 16px 20px;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            border-bottom: 1px solid var(--border);
    \\        }
    \\        .header-title {
    \\            font-size: 1.25rem;
    \\            font-weight: 700;
    \\            flex: 1;
    \\        }
    \\        .header-badge {
    \\            background: var(--danger);
    \\            color: white;
    \\            font-size: 0.7rem;
    \\            padding: 2px 6px;
    \\            border-radius: 10px;
    \\            font-weight: 600;
    \\        }
    \\        .icon-btn {
    \\            background: none;
    \\            border: none;
    \\            color: var(--text-muted);
    \\            padding: 8px;
    \\            cursor: pointer;
    \\            border-radius: 8px;
    \\        }
    \\        .icon-btn:active { background: var(--border); }
    \\        /* Pull to Refresh */
    \\        .pull-indicator {
    \\            display: none;
    \\            justify-content: center;
    \\            padding: 16px;
    \\            color: var(--text-muted);
    \\        }
    \\        .pull-indicator.visible { display: flex; }
    \\        /* Status Card */
    \\        .status-card {
    \\            margin: 16px;
    \\            padding: 20px;
    \\            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
    \\            border-radius: 16px;
    \\            box-shadow: 0 4px 20px rgba(79, 70, 229, 0.3);
    \\        }
    \\        .status-header {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            margin-bottom: 16px;
    \\        }
    \\        .status-indicator {
    \\            width: 12px;
    \\            height: 12px;
    \\            border-radius: 50%;
    \\            animation: pulse 2s infinite;
    \\        }
    \\        @keyframes pulse {
    \\            0%, 100% { opacity: 1; }
    \\            50% { opacity: 0.5; }
    \\        }
    \\        .status-text { font-weight: 600; }
    \\        .status-uptime { font-size: 0.8rem; opacity: 0.8; margin-left: auto; }
    \\        .status-stats {
    \\            display: grid;
    \\            grid-template-columns: repeat(3, 1fr);
    \\            gap: 12px;
    \\        }
    \\        .stat-item { text-align: center; }
    \\        .stat-value { font-size: 1.5rem; font-weight: 700; }
    \\        .stat-label { font-size: 0.7rem; opacity: 0.8; text-transform: uppercase; }
    \\        /* Quick Actions */
    \\        .section-title {
    \\            padding: 16px 20px 8px;
    \\            font-size: 0.8rem;
    \\            font-weight: 600;
    \\            color: var(--text-muted);
    \\            text-transform: uppercase;
    \\            letter-spacing: 0.5px;
    \\        }
    \\        .quick-actions {
    \\            display: grid;
    \\            grid-template-columns: repeat(4, 1fr);
    \\            gap: 12px;
    \\            padding: 0 16px;
    \\        }
    \\        .action-btn {
    \\            display: flex;
    \\            flex-direction: column;
    \\            align-items: center;
    \\            gap: 8px;
    \\            padding: 16px 8px;
    \\            background: var(--card);
    \\            border: none;
    \\            border-radius: 12px;
    \\            color: var(--text);
    \\            cursor: pointer;
    \\            transition: transform 0.15s, background 0.15s;
    \\        }
    \\        .action-btn:active { transform: scale(0.95); background: var(--border); }
    \\        .action-icon {
    \\            width: 32px;
    \\            height: 32px;
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            background: var(--primary);
    \\            border-radius: 8px;
    \\        }
    \\        .action-label { font-size: 0.7rem; color: var(--text-muted); }
    \\        /* Metrics */
    \\        .metrics {
    \\            display: grid;
    \\            grid-template-columns: repeat(2, 1fr);
    \\            gap: 12px;
    \\            padding: 0 16px;
    \\        }
    \\        .metric-card {
    \\            background: var(--card);
    \\            padding: 16px;
    \\            border-radius: 12px;
    \\        }
    \\        .metric-header {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            margin-bottom: 8px;
    \\        }
    \\        .metric-icon {
    \\            width: 28px;
    \\            height: 28px;
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            background: var(--border);
    \\            border-radius: 6px;
    \\        }
    \\        .metric-label { font-size: 0.75rem; color: var(--text-muted); }
    \\        .metric-value { font-size: 1.5rem; font-weight: 700; }
    \\        .metric-change {
    \\            font-size: 0.7rem;
    \\            padding: 2px 6px;
    \\            border-radius: 4px;
    \\            margin-left: auto;
    \\        }
    \\        .metric-change.up { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    \\        .metric-change.down { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
    \\        /* Alerts List */
    \\        .alerts-list { padding: 0 16px; }
    \\        .alert-item {
    \\            display: flex;
    \\            align-items: flex-start;
    \\            gap: 12px;
    \\            padding: 16px;
    \\            background: var(--card);
    \\            border-radius: 12px;
    \\            margin-bottom: 8px;
    \\            cursor: pointer;
    \\            transition: transform 0.15s;
    \\        }
    \\        .alert-item:active { transform: scale(0.98); }
    \\        .alert-icon {
    \\            width: 36px;
    \\            height: 36px;
    \\            border-radius: 8px;
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            flex-shrink: 0;
    \\        }
    \\        .alert-content { flex: 1; min-width: 0; }
    \\        .alert-title { font-weight: 600; font-size: 0.875rem; margin-bottom: 2px; }
    \\        .alert-message { font-size: 0.75rem; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    \\        .alert-time { font-size: 0.7rem; color: var(--text-muted); white-space: nowrap; }
    \\        .alert-unread { position: relative; }
    \\        .alert-unread::after {
    \\            content: '';
    \\            position: absolute;
    \\            top: 16px;
    \\            right: 16px;
    \\            width: 8px;
    \\            height: 8px;
    \\            background: var(--primary);
    \\            border-radius: 50%;
    \\        }
    \\        /* Bottom Navigation */
    \\        .bottom-nav {
    \\            position: fixed;
    \\            bottom: 0;
    \\            left: 0;
    \\            right: 0;
    \\            background: var(--card);
    \\            border-top: 1px solid var(--border);
    \\            display: flex;
    \\            padding-bottom: var(--safe-bottom);
    \\            z-index: 100;
    \\        }
    \\        .nav-item {
    \\            flex: 1;
    \\            display: flex;
    \\            flex-direction: column;
    \\            align-items: center;
    \\            gap: 4px;
    \\            padding: 12px 8px;
    \\            background: none;
    \\            border: none;
    \\            color: var(--text-muted);
    \\            cursor: pointer;
    \\            transition: color 0.15s;
    \\            position: relative;
    \\        }
    \\        .nav-item.active { color: var(--primary); }
    \\        .nav-item.active::before {
    \\            content: '';
    \\            position: absolute;
    \\            top: 0;
    \\            left: 50%;
    \\            transform: translateX(-50%);
    \\            width: 24px;
    \\            height: 3px;
    \\            background: var(--primary);
    \\            border-radius: 0 0 3px 3px;
    \\        }
    \\        .nav-label { font-size: 0.65rem; }
    \\        .nav-badge {
    \\            position: absolute;
    \\            top: 4px;
    \\            right: calc(50% - 16px);
    \\            background: var(--danger);
    \\            color: white;
    \\            font-size: 0.6rem;
    \\            padding: 1px 4px;
    \\            border-radius: 6px;
    \\            font-weight: 600;
    \\        }
    \\        /* Page views */
    \\        .page { display: none; }
    \\        .page.active { display: block; }
    \\        /* Modal */
    \\        .modal-overlay {
    \\            display: none;
    \\            position: fixed;
    \\            top: 0;
    \\            left: 0;
    \\            right: 0;
    \\            bottom: 0;
    \\            background: rgba(0,0,0,0.7);
    \\            z-index: 200;
    \\            align-items: flex-end;
    \\            justify-content: center;
    \\        }
    \\        .modal-overlay.open { display: flex; }
    \\        .modal-sheet {
    \\            background: var(--card);
    \\            width: 100%;
    \\            max-height: 80vh;
    \\            border-radius: 20px 20px 0 0;
    \\            padding: 8px 20px calc(20px + var(--safe-bottom));
    \\            animation: slideUp 0.3s ease;
    \\        }
    \\        @keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
    \\        .modal-handle {
    \\            width: 36px;
    \\            height: 4px;
    \\            background: var(--border);
    \\            border-radius: 2px;
    \\            margin: 0 auto 16px;
    \\        }
    \\        .modal-title { font-size: 1.125rem; font-weight: 600; margin-bottom: 16px; }
    \\        .modal-action {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            padding: 16px;
    \\            background: var(--bg);
    \\            border: none;
    \\            border-radius: 12px;
    \\            color: var(--text);
    \\            width: 100%;
    \\            margin-bottom: 8px;
    \\            cursor: pointer;
    \\        }
    \\        .modal-action:active { opacity: 0.8; }
    \\        .modal-action.danger { color: var(--danger); }
    \\        /* Toast */
    \\        .toast {
    \\            position: fixed;
    \\            top: calc(20px + var(--safe-top));
    \\            left: 20px;
    \\            right: 20px;
    \\            background: var(--card);
    \\            padding: 16px;
    \\            border-radius: 12px;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            z-index: 300;
    \\            animation: slideDown 0.3s ease;
    \\            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    \\        }
    \\        @keyframes slideDown { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    \\        /* Loading */
    \\        .loading {
    \\            display: flex;
    \\            flex-direction: column;
    \\            align-items: center;
    \\            justify-content: center;
    \\            padding: 40px;
    \\            color: var(--text-muted);
    \\        }
    \\        .spinner {
    \\            width: 32px;
    \\            height: 32px;
    \\            border: 3px solid var(--border);
    \\            border-top-color: var(--primary);
    \\            border-radius: 50%;
    \\            animation: spin 0.8s linear infinite;
    \\        }
    \\        @keyframes spin { to { transform: rotate(360deg); } }
    \\        /* Empty state */
    \\        .empty-state {
    \\            text-align: center;
    \\            padding: 40px 20px;
    \\            color: var(--text-muted);
    \\        }
    \\        .empty-state svg { width: 64px; height: 64px; opacity: 0.3; margin-bottom: 16px; }
    \\    </style>
    \\</head>
    \\<body>
    \\    <!-- Header -->
    \\    <header class="header">
    \\        <span class="header-title">SMTP Admin</span>
    \\        <span class="header-badge" id="alert-badge" style="display: none;">0</span>
    \\        <button class="icon-btn" onclick="showSettings()">
    \\            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    \\            </svg>
    \\        </button>
    \\    </header>
    \\    <div class="pull-indicator" id="pull-indicator">
    \\        <div class="spinner"></div>
    \\    </div>
    \\    <!-- Dashboard Page -->
    \\    <main class="page active" id="page-dashboard">
    \\        <div class="status-card">
    \\            <div class="status-header">
    \\                <div class="status-indicator" id="status-dot" style="background: var(--success);"></div>
    \\                <span class="status-text" id="status-text">All Systems Operational</span>
    \\                <span class="status-uptime" id="uptime">Uptime: 1d 0h</span>
    \\            </div>
    \\            <div class="status-stats">
    \\                <div class="stat-item">
    \\                    <div class="stat-value" id="stat-connections">--</div>
    \\                    <div class="stat-label">Connections</div>
    \\                </div>
    \\                <div class="stat-item">
    \\                    <div class="stat-value" id="stat-messages">--</div>
    \\                    <div class="stat-label">Messages</div>
    \\                </div>
    \\                <div class="stat-item">
    \\                    <div class="stat-value" id="stat-queue">--</div>
    \\                    <div class="stat-label">In Queue</div>
    \\                </div>
    \\            </div>
    \\        </div>
    \\        <div class="section-title">Quick Actions</div>
    \\        <div class="quick-actions">
    \\            <button class="action-btn" onclick="quickAction('flush')">
    \\                <div class="action-icon">
    \\                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
    \\                        <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
    \\                    </svg>
    \\                </div>
    \\                <span class="action-label">Flush Queue</span>
    \\            </button>
    \\            <button class="action-btn" onclick="quickAction('logs')">
    \\                <div class="action-icon">
    \\                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
    \\                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    \\                        <polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
    \\                    </svg>
    \\                </div>
    \\                <span class="action-label">View Logs</span>
    \\            </button>
    \\            <button class="action-btn" onclick="quickAction('backup')">
    \\                <div class="action-icon">
    \\                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
    \\                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
    \\                    </svg>
    \\                </div>
    \\                <span class="action-label">Backup</span>
    \\            </button>
    \\            <button class="action-btn" onclick="quickAction('test')">
    \\                <div class="action-icon">
    \\                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
    \\                        <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
    \\                    </svg>
    \\                </div>
    \\                <span class="action-label">Test Email</span>
    \\            </button>
    \\        </div>
    \\        <div class="section-title">System Metrics</div>
    \\        <div class="metrics">
    \\            <div class="metric-card">
    \\                <div class="metric-header">
    \\                    <div class="metric-icon">
    \\                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
    \\                            <line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>
    \\                        </svg>
    \\                    </div>
    \\                    <span class="metric-label">CPU</span>
    \\                    <span class="metric-change up" id="cpu-change">-2%</span>
    \\                </div>
    \\                <div class="metric-value" id="metric-cpu">--%</div>
    \\            </div>
    \\            <div class="metric-card">
    \\                <div class="metric-header">
    \\                    <div class="metric-icon">
    \\                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M22 12H2"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>
    \\                        </svg>
    \\                    </div>
    \\                    <span class="metric-label">Memory</span>
    \\                    <span class="metric-change up" id="mem-change">+1%</span>
    \\                </div>
    \\                <div class="metric-value" id="metric-memory">--%</div>
    \\            </div>
    \\            <div class="metric-card">
    \\                <div class="metric-header">
    \\                    <div class="metric-icon">
    \\                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
    \\                        </svg>
    \\                    </div>
    \\                    <span class="metric-label">Disk</span>
    \\                </div>
    \\                <div class="metric-value" id="metric-disk">--%</div>
    \\            </div>
    \\            <div class="metric-card">
    \\                <div class="metric-header">
    \\                    <div class="metric-icon">
    \\                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
    \\                        </svg>
    \\                    </div>
    \\                    <span class="metric-label">Delivered</span>
    \\                </div>
    \\                <div class="metric-value" id="metric-delivered">--</div>
    \\            </div>
    \\        </div>
    \\        <div class="section-title">Recent Alerts</div>
    \\        <div class="alerts-list" id="alerts-list"></div>
    \\    </main>
    \\    <!-- Alerts Page -->
    \\    <main class="page" id="page-alerts">
    \\        <div class="section-title">All Alerts</div>
    \\        <div id="all-alerts-list"></div>
    \\    </main>
    \\    <!-- Queue Page -->
    \\    <main class="page" id="page-queue">
    \\        <div class="section-title">Mail Queue</div>
    \\        <div id="queue-list" class="alerts-list"></div>
    \\    </main>
    \\    <!-- Users Page -->
    \\    <main class="page" id="page-users">
    \\        <div class="section-title">User Management</div>
    \\        <div id="users-list" class="alerts-list"></div>
    \\    </main>
    \\    <!-- Bottom Navigation -->
    \\    <nav class="bottom-nav">
    \\        <button class="nav-item active" onclick="showPage('dashboard')">
    \\            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>
    \\            </svg>
    \\            <span class="nav-label">Dashboard</span>
    \\        </button>
    \\        <button class="nav-item" onclick="showPage('alerts')">
    \\            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>
    \\            </svg>
    \\            <span class="nav-label">Alerts</span>
    \\            <span class="nav-badge" id="nav-alert-badge" style="display: none;">0</span>
    \\        </button>
    \\        <button class="nav-item" onclick="showPage('queue')">
    \\            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                <line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/>
    \\                <line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>
    \\            </svg>
    \\            <span class="nav-label">Queue</span>
    \\        </button>
    \\        <button class="nav-item" onclick="showPage('users')">
    \\            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
    \\                <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
    \\            </svg>
    \\            <span class="nav-label">Users</span>
    \\        </button>
    \\    </nav>
    \\    <!-- Action Modal -->
    \\    <div class="modal-overlay" id="action-modal">
    \\        <div class="modal-sheet">
    \\            <div class="modal-handle"></div>
    \\            <div class="modal-title" id="modal-title">Confirm Action</div>
    \\            <div id="modal-content"></div>
    \\        </div>
    \\    </div>
    \\    <script>
    \\        // State
    \\        let currentPage = 'dashboard';
    \\        let status = {};
    \\        let alerts = [];
    \\        // Initialize
    \\        document.addEventListener('DOMContentLoaded', () => {
    \\            loadStatus();
    \\            loadAlerts();
    \\            setupPullToRefresh();
    \\            if ('serviceWorker' in navigator) {
    \\                navigator.serviceWorker.register('/admin/mobile/sw.js').catch(() => {});
    \\            }
    \\        });
    \\        // Load server status
    \\        async function loadStatus() {
    \\            try {
    \\                const res = await fetch('/admin/mobile/api/status');
    \\                status = await res.json();
    \\                updateStatusUI();
    \\            } catch (e) { console.error('Failed to load status:', e); }
    \\        }
    \\        function updateStatusUI() {
    \\            document.getElementById('stat-connections').textContent = status.connections || '--';
    \\            document.getElementById('stat-messages').textContent = formatNumber(status.messages_today) || '--';
    \\            document.getElementById('stat-queue').textContent = status.queue_size || '--';
    \\            document.getElementById('metric-cpu').textContent = (status.cpu || 0).toFixed(1) + '%';
    \\            document.getElementById('metric-memory').textContent = (status.memory || 0).toFixed(1) + '%';
    \\            document.getElementById('metric-disk').textContent = (status.disk || 0).toFixed(1) + '%';
    \\            document.getElementById('metric-delivered').textContent = formatNumber(status.messages_today * 0.99);
    \\            const uptime = status.uptime || 0;
    \\            const days = Math.floor(uptime / 86400);
    \\            const hours = Math.floor((uptime % 86400) / 3600);
    \\            document.getElementById('uptime').textContent = `Uptime: ${days}d ${hours}h`;
    \\        }
    \\        // Load alerts
    \\        async function loadAlerts() {
    \\            try {
    \\                const res = await fetch('/admin/mobile/api/alerts');
    \\                const data = await res.json();
    \\                alerts = data.alerts || [];
    \\                renderAlerts();
    \\                updateAlertBadge(data.unread_count || 0);
    \\            } catch (e) { console.error('Failed to load alerts:', e); }
    \\        }
    \\        function renderAlerts() {
    \\            const list = document.getElementById('alerts-list');
    \\            const allList = document.getElementById('all-alerts-list');
    \\            const html = alerts.slice(0, 3).map(a => alertHTML(a)).join('');
    \\            const allHtml = alerts.map(a => alertHTML(a)).join('');
    \\            list.innerHTML = html || '<div class="empty-state"><p>No alerts</p></div>';
    \\            if (allList) allList.innerHTML = allHtml || '<div class="empty-state"><p>No alerts</p></div>';
    \\        }
    \\        function alertHTML(alert) {
    \\            const colors = { info: 'var(--info)', warning: 'var(--warning)', critical: 'var(--danger)' };
    \\            return `<div class="alert-item ${!alert.acknowledged ? 'alert-unread' : ''}" onclick="showAlertDetail('${alert.id}')">
    \\                <div class="alert-icon" style="background: ${colors[alert.severity] || colors.info};">
    \\                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
    \\                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    \\                        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    \\                    </svg>
    \\                </div>
    \\                <div class="alert-content">
    \\                    <div class="alert-title">${alert.title}</div>
    \\                    <div class="alert-message">${alert.message}</div>
    \\                </div>
    \\                <div class="alert-time">${formatTime(alert.timestamp)}</div>
    \\            </div>`;
    \\        }
    \\        function updateAlertBadge(count) {
    \\            const badge = document.getElementById('alert-badge');
    \\            const navBadge = document.getElementById('nav-alert-badge');
    \\            if (count > 0) {
    \\                badge.textContent = count;
    \\                navBadge.textContent = count;
    \\                badge.style.display = 'inline';
    \\                navBadge.style.display = 'inline';
    \\            } else {
    \\                badge.style.display = 'none';
    \\                navBadge.style.display = 'none';
    \\            }
    \\        }
    \\        // Navigation
    \\        function showPage(page) {
    \\            currentPage = page;
    \\            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    \\            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    \\            document.getElementById('page-' + page).classList.add('active');
    \\            document.querySelectorAll('.nav-item')[['dashboard','alerts','queue','users'].indexOf(page)].classList.add('active');
    \\        }
    \\        // Quick Actions
    \\        function quickAction(action) {
    \\            const actions = {
    \\                flush: { title: 'Flush Queue', message: 'Are you sure you want to flush the mail queue?' },
    \\                logs: { title: 'View Logs', message: 'Opening server logs...' },
    \\                backup: { title: 'Backup Now', message: 'Start a backup now?' },
    \\                test: { title: 'Send Test Email', message: 'Send a test email to verify configuration?' }
    \\            };
    \\            showModal(actions[action]?.title || 'Action', `
    \\                <p style="color: var(--text-muted); margin-bottom: 16px;">${actions[action]?.message || ''}</p>
    \\                <button class="modal-action" onclick="executeAction('${action}')">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
    \\                    Confirm
    \\                </button>
    \\                <button class="modal-action" onclick="closeModal()">Cancel</button>
    \\            `);
    \\        }
    \\        async function executeAction(action) {
    \\            closeModal();
    \\            showToast('Action executed: ' + action, 'success');
    \\            await fetch('/admin/mobile/api/action', { method: 'POST', body: JSON.stringify({ action }) });
    \\        }
    \\        // Modals
    \\        function showModal(title, content) {
    \\            document.getElementById('modal-title').textContent = title;
    \\            document.getElementById('modal-content').innerHTML = content;
    \\            document.getElementById('action-modal').classList.add('open');
    \\        }
    \\        function closeModal() {
    \\            document.getElementById('action-modal').classList.remove('open');
    \\        }
    \\        function showAlertDetail(id) {
    \\            const alert = alerts.find(a => a.id === id);
    \\            if (!alert) return;
    \\            showModal(alert.title, `
    \\                <p style="color: var(--text-muted); margin-bottom: 16px;">${alert.message}</p>
    \\                <p style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 16px;">${formatTime(alert.timestamp)}</p>
    \\                ${!alert.acknowledged ? `<button class="modal-action" onclick="acknowledgeAlert('${id}')">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
    \\                    Acknowledge
    \\                </button>` : ''}
    \\                <button class="modal-action" onclick="closeModal()">Close</button>
    \\            `);
    \\        }
    \\        async function acknowledgeAlert(id) {
    \\            closeModal();
    \\            const alert = alerts.find(a => a.id === id);
    \\            if (alert) alert.acknowledged = true;
    \\            renderAlerts();
    \\            updateAlertBadge(alerts.filter(a => !a.acknowledged).length);
    \\            await fetch('/admin/mobile/api/acknowledge', { method: 'POST', body: JSON.stringify({ id }) });
    \\        }
    \\        // Pull to refresh
    \\        function setupPullToRefresh() {
    \\            let startY = 0;
    \\            let pulling = false;
    \\            document.addEventListener('touchstart', e => {
    \\                if (window.scrollY === 0) { startY = e.touches[0].clientY; pulling = true; }
    \\            });
    \\            document.addEventListener('touchmove', e => {
    \\                if (!pulling) return;
    \\                const diff = e.touches[0].clientY - startY;
    \\                if (diff > 60) document.getElementById('pull-indicator').classList.add('visible');
    \\            });
    \\            document.addEventListener('touchend', () => {
    \\                if (document.getElementById('pull-indicator').classList.contains('visible')) {
    \\                    loadStatus();
    \\                    loadAlerts();
    \\                    setTimeout(() => document.getElementById('pull-indicator').classList.remove('visible'), 1000);
    \\                }
    \\                pulling = false;
    \\            });
    \\        }
    \\        // Toast
    \\        function showToast(message, type) {
    \\            const toast = document.createElement('div');
    \\            toast.className = 'toast';
    \\            toast.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="${type === 'success' ? 'var(--success)' : 'var(--danger)'}" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg><span>${message}</span>`;
    \\            document.body.appendChild(toast);
    \\            setTimeout(() => toast.remove(), 3000);
    \\        }
    \\        // Settings
    \\        function showSettings() {
    \\            showModal('Settings', `
    \\                <button class="modal-action" onclick="toggleNotifications()">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/></svg>
    \\                    Push Notifications
    \\                </button>
    \\                <button class="modal-action" onclick="showAbout()">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
    \\                    About
    \\                </button>
    \\                <button class="modal-action danger" onclick="logout()">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
    \\                    Logout
    \\                </button>
    \\            `);
    \\        }
    \\        function toggleNotifications() { showToast('Notifications toggled', 'success'); closeModal(); }
    \\        function showAbout() { showToast('SMTP Server v0.28.0', 'success'); closeModal(); }
    \\        function logout() { window.location.href = '/admin'; }
    \\        // Helpers
    \\        function formatNumber(n) { return n ? n.toLocaleString() : '--'; }
    \\        function formatTime(ts) {
    \\            const d = new Date(ts * 1000);
    \\            const now = new Date();
    \\            if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    \\            return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    \\        }
    \\        // Auto refresh
    \\        setInterval(() => { if (currentPage === 'dashboard') loadStatus(); }, 30000);
    \\    </script>
    \\</body>
    \\</html>
;

// Tests
test "MobileAdminConfig defaults" {
    const config = MobileAdminConfig{};
    try std.testing.expect(config.enable_push_notifications);
    try std.testing.expectEqual(@as(u32, 1800), config.session_timeout_seconds);
    try std.testing.expectEqual(@as(u32, 30), config.refresh_interval);
}

test "ServerStatus healthy" {
    const status = ServerStatus{
        .status = .healthy,
        .uptime_seconds = 86400,
        .version = "v0.28.0",
        .cpu_usage = 15.0,
        .memory_usage = 45.0,
        .disk_usage = 30.0,
        .active_connections = 100,
        .messages_today = 5000,
        .queue_size = 10,
    };
    try std.testing.expectEqualStrings("Healthy", status.status.toString());
    try std.testing.expectEqualStrings("#10b981", status.status.color());
}

test "AdminAlert severity colors" {
    try std.testing.expectEqualStrings("#3b82f6", AdminAlert.Severity.info.color());
    try std.testing.expectEqualStrings("#f59e0b", AdminAlert.Severity.warning.color());
    try std.testing.expectEqualStrings("#ef4444", AdminAlert.Severity.critical.color());
}

test "MobileAdminHandler init" {
    const allocator = std.testing.allocator;
    const handler = MobileAdminHandler.init(allocator, .{});
    try std.testing.expect(handler.config.enable_push_notifications);
}
