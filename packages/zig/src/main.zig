const std = @import("std");
const smtp = @import("core/smtp.zig");
const config = @import("core/config.zig");
const logger = @import("core/logger.zig");
const args_parser = @import("core/args.zig");
const env = @import("core/env.zig");
const database = @import("storage/database.zig");
const auth = @import("auth/auth.zig");
const greylist_mod = @import("antispam/greylist.zig");
const imap = @import("protocol/imap.zig");
const caldav = @import("protocol/caldav.zig");
const caldav_store_mod = @import("storage/caldav_store.zig");

// Cluster and multi-tenancy support
const cluster = @import("infrastructure/cluster.zig");
const multitenancy = @import("features/multitenancy.zig");
const metrics_mod = @import("observability/metrics.zig");
const alerting = @import("observability/alerting.zig");
const discord = @import("observability/discord.zig");
const secrets = @import("security/secrets.zig");
const hot_reload = @import("core/hot_reload.zig");

// New feature modules
const dkim_rotation = @import("features/dkim_rotation.zig");
const sieve = @import("features/sieve.zig");
const dane = @import("antispam/dane.zig");
const mta_sts = @import("antispam/mta_sts.zig");
const acme = @import("security/acme.zig");
const tls_rpt = @import("delivery/tls_rpt.zig");
const arc = @import("antispam/arc.zig");
const bimi = @import("antispam/bimi.zig");
const list_unsub = @import("features/list_unsubscribe.zig");
const autoconfig_mod = @import("api/autoconfig.zig");
const managesieve = @import("protocol/managesieve.zig");
const milter = @import("protocol/milter.zig");

// Global shutdown flag
var shutdown_requested = std.atomic.Value(bool).init(false);

// Global reload flag for SIGHUP
var reload_requested = std.atomic.Value(bool).init(false);

// Global reload manager pointer for callback
var global_reload_manager: ?*hot_reload.HotReloadManager = null;

fn reloadConfigCallback() void {
    if (global_reload_manager) |manager| {
        _ = manager.checkAndReload(&reload_requested);
    }
}

fn signalHandler(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    shutdown_requested.store(true, .release);
}

fn reloadHandler(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    reload_requested.store(true, .release);
}

pub fn main(init: std.process.Init) !void {
    const io_compat = @import("core/io_compat.zig");
    io_compat.initIo(init.io);
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cli_args = args_parser.parseArgs(allocator, init.minimal.args) catch |err| {
        if (err != error.UnknownArgument) {
            args_parser.printHelp();
        }
        return err;
    };
    defer cli_args.deinit(allocator);

    if (cli_args.help) {
        args_parser.printHelp();
        return;
    }

    if (cli_args.version) {
        args_parser.printVersion();
        return;
    }

    try run(allocator, cli_args);
}

pub fn run(allocator: std.mem.Allocator, cli_args: args_parser.Args) !void {
    // Load configuration first (with CLI args and env vars)
    // Configuration validation is automatically performed during loading
    // Using var to allow hot reload to update configuration
    var cfg = config.loadConfig(allocator, cli_args) catch |err| {
        std.debug.print("Configuration validation failed: {}\n", .{err});
        return err;
    };
    defer cfg.deinit(allocator);

    // Initialize logger with configuration settings
    const log_level = cli_args.log_level orelse .info;
    const log_file = cli_args.log_file orelse "mail.log";
    const log_format: logger.LogFormat = if (cfg.enable_json_logging) .json else .text;
    var log = try logger.Logger.initWithFormat(allocator, log_level, log_file, log_format);
    defer log.deinit();
    logger.setGlobalLogger(&log);

    log.info("=== SMTP Server Starting ===", .{});

    log.info("Configuration loaded and validated successfully:", .{});
    log.info("  Host: {s}:{d}", .{ cfg.host, cfg.port });
    log.info("  Max connections: {d}", .{cfg.max_connections});
    log.info("  TLS enabled: {}", .{cfg.enable_tls});
    log.info("  Auth enabled: {}", .{cfg.enable_auth});
    log.info("  Max message size: {d} bytes", .{cfg.max_message_size});

    // Handle --validate-only flag
    if (cli_args.validate_only) {
        std.debug.print("\n✓ Configuration validation successful!\n", .{});
        std.debug.print("All configuration values are within acceptable ranges.\n", .{});
        return;
    }

    // Setup signal handlers for graceful shutdown and hot reload
    const empty_set = std.posix.sigemptyset();

    const shutdown_act = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = empty_set,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &shutdown_act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &shutdown_act, null);

    // Setup SIGHUP for configuration hot reload
    const reload_act = std.posix.Sigaction{
        .handler = .{ .handler = reloadHandler },
        .mask = empty_set,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.HUP, &reload_act, null);

    log.info("Signal handlers installed (SIGINT, SIGTERM for shutdown, SIGHUP for reload)", .{});

    // Initialize hot reload manager
    var reload_manager = hot_reload.HotReloadManager.init(allocator, &cfg, cli_args.config_file);
    defer reload_manager.deinit();
    global_reload_manager = &reload_manager;
    defer global_reload_manager = null;
    log.info("Hot reload manager initialized (send SIGHUP to reload configuration)", .{});

    // Initialize database and auth backend if auth is enabled
    var db: ?database.Database = null;
    var auth_backend: ?auth.AuthBackend = null;
    var db_ptr: ?*database.Database = null;
    var auth_ptr: ?*auth.AuthBackend = null;

    if (cfg.enable_auth) {
        const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
        log.info("Initializing database at: {s}", .{db_path});

        db = try database.Database.init(allocator, db_path);
        errdefer if (db) |*d| d.deinit();

        db_ptr = &db.?;
        auth_backend = auth.AuthBackend.init(allocator, db_ptr.?);
        auth_ptr = &auth_backend.?;

        log.info("Database-backed authentication enabled", .{});
    } else {
        log.info("Authentication disabled", .{});
    }

    defer if (db) |*d| d.deinit();

    // Initialize greylisting if enabled
    var greylist: ?greylist_mod.Greylist = null;
    var greylist_ptr: ?*greylist_mod.Greylist = null;

    if (cfg.enable_greylist) {
        greylist = greylist_mod.Greylist.init(allocator);
        greylist_ptr = &greylist.?;
        log.info("Greylisting enabled (5 min delay, 4 hour retry window)", .{});
    }

    defer if (greylist) |*g| g.deinit();

    // Initialize metrics collection
    var smtp_metrics: ?metrics_mod.SmtpMetrics = null;
    const statsd_host = env.get("STATSD_HOST");
    const statsd_port: u16 = blk: {
        const port_str = env.get("STATSD_PORT") orelse "8125";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 8125;
    };

    if (statsd_host != null or env.get("SMTP_METRICS_ENABLED") != null) {
        smtp_metrics = try metrics_mod.SmtpMetrics.init(allocator, statsd_host, statsd_port, "smtp");
        log.info("Metrics collection enabled (StatsD: {s}:{d})", .{ statsd_host orelse "local-only", statsd_port });
    }
    defer if (smtp_metrics) |*m| m.deinit();

    // Initialize alerting
    var alert_manager: ?alerting.AlertManager = null;
    if (env.get("SMTP_ALERTING_ENABLED") != null) {
        alert_manager = alerting.AlertManager.init(allocator);

        // Configure Slack if webhook URL is provided
        if (env.get("SLACK_WEBHOOK_URL")) |webhook_url| {
            try alert_manager.?.addSlackChannel(.{
                .webhook_url = webhook_url,
                .channel = env.get("SLACK_CHANNEL"),
            });
            log.info("Slack alerting enabled", .{});
        }

        // Add default alert rules
        var default_rules = try alerting.createDefaultRules(allocator);
        defer default_rules.deinit(allocator);
        for (default_rules.items) |rule| {
            try alert_manager.?.addRule(rule);
        }

        log.info("Alerting enabled with {d} default rules", .{alert_manager.?.rules.items.len});
    }
    defer if (alert_manager) |*a| a.deinit();

    // Initialize secret manager
    var secret_manager: ?secrets.SecretManager = null;
    const secret_backend_str = env.get("SECRET_BACKEND") orelse "environment";
    if (!std.mem.eql(u8, secret_backend_str, "none")) {
        secret_manager = secrets.SecretManager.init(allocator, .environment);

        if (std.mem.eql(u8, secret_backend_str, "kubernetes")) {
            secret_manager.?.configureKubernetes(.{
                .secrets_path = env.get("K8S_SECRETS_PATH") orelse "/var/run/secrets",
            });
        } else if (std.mem.eql(u8, secret_backend_str, "vault")) {
            if (env.get("VAULT_ADDR")) |vault_addr| {
                try secret_manager.?.configureVault(.{
                    .address = vault_addr,
                    .token = env.get("VAULT_TOKEN"),
                });
            }
        }

        log.info("Secret management enabled (backend: {s})", .{secret_backend_str});
    }
    defer if (secret_manager) |*s| s.deinit();

    // Initialize cluster mode if enabled
    var cluster_manager: ?*cluster.ClusterManager = null;
    const enable_cluster = env.get("SMTP_CLUSTER_ENABLED") != null;

    if (enable_cluster) {
        const node_id = env.get("SMTP_NODE_ID") orelse "node-1";
        const cluster_port: u16 = blk: {
            const port_str = env.get("SMTP_CLUSTER_PORT") orelse "9000";
            break :blk std.fmt.parseInt(u16, port_str, 10) catch 9000;
        };
        const enable_raft = env.get("SMTP_RAFT_DISABLED") == null;

        const cluster_config = cluster.ClusterConfig{
            .node_id = node_id,
            .bind_address = cfg.host,
            .bind_port = cluster_port,
            .peers = &[_][]const u8{}, // Peers configured via env or discovery
            .enable_raft = enable_raft,
        };

        cluster_manager = try cluster.ClusterManager.init(allocator, cluster_config);
        try cluster_manager.?.start();

        log.info("Cluster mode enabled - Node ID: {s}, Port: {d}, Raft: {}", .{
            node_id,
            cluster_port,
            enable_raft,
        });
    }
    defer if (cluster_manager) |cm| cm.deinit();

    // Initialize multi-tenancy if enabled
    // Note: MultiTenancyManager requires a TenantDB - disabled for now
    const tenant_manager: ?*multitenancy.MultiTenancyManager = null;
    if (env.get("SMTP_MULTITENANCY_ENABLED") != null) {
        log.info("Multi-tenancy requested but not yet configured", .{});
    }
    // tenant_manager is used in logging below

    // Initialize DKIM key rotation scheduler
    var dkim_key_manager: ?dkim_rotation.dkim.DKIMKeyManager = null;
    var rotation_scheduler: ?dkim_rotation.DKIMRotationScheduler = null;
    if (cfg.enable_dkim_rotation) {
        dkim_key_manager = try dkim_rotation.dkim.DKIMKeyManager.init(allocator, null);
        rotation_scheduler = dkim_rotation.DKIMRotationScheduler.init(
            allocator,
            &dkim_key_manager.?,
            .{ .rotation_interval_days = cfg.dkim_rotation_interval_days },
        );
        log.info("DKIM key rotation enabled (interval: {d} days)", .{cfg.dkim_rotation_interval_days});
    }
    defer if (rotation_scheduler) |*rs| rs.deinit();
    defer if (dkim_key_manager) |*km| km.deinit();

    // Initialize Sieve filtering
    var sieve_manager: ?sieve.SieveScriptManager = null;
    if (cfg.enable_sieve) {
        sieve_manager = sieve.SieveScriptManager.init(allocator);
        log.info("Sieve filtering enabled", .{});
    }
    defer if (sieve_manager) |*sm| sm.deinit();

    // Initialize DANE validator
    var dane_validator: ?dane.DANEValidator = null;
    if (cfg.enable_dane) {
        dane_validator = dane.DANEValidator.init(allocator);
        log.info("DANE (TLSA) validation enabled", .{});
    }
    defer if (dane_validator) |*dv| dv.deinit();

    // Initialize MTA-STS validator
    var mta_sts_validator: ?mta_sts.MTASTSValidator = null;
    if (cfg.enable_mta_sts) {
        mta_sts_validator = mta_sts.MTASTSValidator.init(allocator);
        log.info("MTA-STS policy enforcement enabled", .{});
    }
    defer if (mta_sts_validator) |*mv| mv.deinit();

    // Initialize ACME certificate manager
    var cert_manager: ?acme.CertificateManager = null;
    if (cfg.enable_acme) {
        const acme_config = acme.ACMEConfig{
            .email = cfg.acme_email orelse "",
        };
        cert_manager = acme.CertificateManager.init(allocator, acme_config);
        log.info("ACME/Let's Encrypt auto-provisioning enabled", .{});
    }
    defer if (cert_manager) |*cm| cm.deinit();

    // Initialize TLS-RPT aggregator
    var tls_rpt_aggregator: ?tls_rpt.TLSReportAggregator = null;
    if (cfg.enable_tls_rpt) {
        tls_rpt_aggregator = tls_rpt.TLSReportAggregator.init(allocator);
        log.info("TLS-RPT reporting enabled", .{});
    }
    defer if (tls_rpt_aggregator) |*ta| ta.deinit();

    // Initialize ARC validator
    var arc_validator: ?arc.ARCValidator = null;
    if (cfg.enable_arc) {
        arc_validator = arc.ARCValidator.init(allocator);
        log.info("ARC chain validation enabled", .{});
    }
    defer if (arc_validator) |*av| av.deinit();

    // Initialize BIMI validator
    var bimi_validator: ?bimi.BIMIValidator = null;
    if (cfg.enable_bimi) {
        bimi_validator = bimi.BIMIValidator.init(allocator);
        log.info("BIMI brand indicator support enabled", .{});
    }
    defer if (bimi_validator) |*bv| bv.deinit();

    // Initialize List-Unsubscribe handler
    _ = cfg.enable_list_unsubscribe; // Used by protocol.zig hooks
    if (cfg.enable_list_unsubscribe) {
        log.info("RFC 8058 List-Unsubscribe One-Click enabled", .{});
    }

    // Initialize autoconfig handler
    _ = cfg.enable_autoconfig; // Used by api.zig route handler
    if (cfg.enable_autoconfig) {
        log.info("Email autoconfiguration enabled (Thunderbird/Outlook/Apple)", .{});
    }

    // Initialize ManageSieve server
    var managesieve_server: ?managesieve.ManageSieveServer = null;
    var managesieve_thread: ?std.Thread = null;
    if (cfg.enable_managesieve) {
        const ms_config = managesieve.ManageSieveConfig{
            .port = cfg.managesieve_port,
        };
        managesieve_server = managesieve.ManageSieveServer.init(allocator, ms_config, null);
        log.info("ManageSieve server configured on port {d}", .{cfg.managesieve_port});
    }
    defer if (managesieve_server) |*ms| ms.deinit();

    // Initialize Milter support
    _ = cfg.enable_milter; // Used by protocol.zig hooks
    if (cfg.enable_milter) {
        log.info("Milter protocol support enabled", .{});
    }

    // Create and start SMTP server
    var server = try smtp.Server.init(allocator, cfg, &log, db_ptr, auth_ptr, greylist_ptr);
    defer server.deinit();

    // Start SMTPS (port 465) if TLS is enabled
    var smtps_thread: ?std.Thread = null;
    const smtps_port: u16 = blk: {
        const port_str = env.get("SMTPS_PORT") orelse "465";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 465;
    };

    // Initialize IMAP server if auth is enabled
    var imap_server: ?imap.ImapServer = null;
    var imap_thread: ?std.Thread = null;
    const enable_imap = env.get("IMAP_ENABLED") != null or cfg.enable_auth;
    const imap_port: u16 = blk: {
        const port_str = env.get("IMAP_PORT") orelse "143";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 143;
    };

    if (enable_imap and auth_ptr != null) {
        const imap_config = imap.ImapConfig{
            .port = imap_port,
            .ssl_port = 993,
            .enable_ssl = cfg.enable_tls,
            .max_connections = @intCast(cfg.max_connections),
            .cert_path = cfg.tls_cert_path,
            .key_path = cfg.tls_key_path,
        };
        imap_server = imap.ImapServer.init(allocator, imap_config, auth_ptr.?, db_ptr);
        log.info("IMAP server configured on port {d}", .{imap_port});
        if (cfg.enable_tls and cfg.tls_cert_path != null) {
            log.info("IMAPS server configured on port 993 (SSL/TLS)", .{});
        }
    }
    defer if (imap_server) |*is| is.deinit();

    // Initialize CalDAV/CardDAV store and server if auth is enabled
    var caldav_store_inst: ?caldav_store_mod.CalDavStore = null;
    var caldav_server: ?caldav.CalDavServer = null;
    var caldav_thread: ?std.Thread = null;
    const enable_caldav = env.get("CALDAV_ENABLED") != null or cfg.enable_auth;
    const caldav_port: u16 = blk: {
        const port_str = env.get("CALDAV_PORT") orelse "80";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 80;
    };
    const caldav_ssl_port: u16 = blk: {
        const port_str = env.get("CALDAV_SSL_PORT") orelse "443";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 443;
    };

    if (enable_caldav and auth_ptr != null) {
        caldav_store_inst = try caldav_store_mod.CalDavStore.init(allocator, .{});

        const caldav_config = caldav.CalDavConfig{
            .port = caldav_port,
            .ssl_port = caldav_ssl_port,
            .enable_ssl = cfg.enable_tls,
            .max_connections = @intCast(cfg.max_connections),
            .cert_path = cfg.tls_cert_path,
            .key_path = cfg.tls_key_path,
            .public_hostname = cfg.hostname,
            .imaps_port = 993,
            .submission_port = 587,
            .display_name = cfg.hostname,
        };
        caldav_server = caldav.CalDavServer.init(allocator, caldav_config, auth_ptr.?, &caldav_store_inst.?);
        log.info("CalDAV/CardDAV server configured on port {d}", .{caldav_port});
        if (cfg.enable_tls and cfg.tls_cert_path != null) {
            log.info("CalDAV SSL server configured on port {d} (HTTPS)", .{caldav_ssl_port});
        }
    }
    defer if (caldav_server) |*cs| cs.deinit();
    defer if (caldav_store_inst) |*s| s.deinit();

    // Start ManageSieve server in a separate thread
    if (managesieve_server) |*ms| {
        managesieve_thread = try std.Thread.spawn(.{}, struct {
            fn run(ms_srv: *managesieve.ManageSieveServer) void {
                ms_srv.start() catch |err| {
                    std.log.err("ManageSieve server error: {}", .{err});
                };
            }
        }.run, .{ms});
        log.info("ManageSieve Server listening on 0.0.0.0:{d}", .{cfg.managesieve_port});
    }

    // Log startup summary
    log.info("Starting SMTP server...", .{});
    log.info("  IMAP enabled: {}", .{imap_server != null});
    log.info("  CalDAV enabled: {}", .{caldav_server != null});
    log.info("  ManageSieve enabled: {}", .{managesieve_server != null});
    log.info("  Cluster mode: {}", .{enable_cluster});
    log.info("  Multi-tenancy: {}", .{tenant_manager != null});
    log.info("  Metrics: {}", .{smtp_metrics != null});
    log.info("  Alerting: {}", .{alert_manager != null});
    log.info("  DKIM rotation: {}", .{rotation_scheduler != null});
    log.info("  Sieve: {}", .{sieve_manager != null});
    log.info("  DANE: {}", .{dane_validator != null});
    log.info("  MTA-STS: {}", .{mta_sts_validator != null});
    log.info("  ACME: {}", .{cert_manager != null});
    log.info("  TLS-RPT: {}", .{tls_rpt_aggregator != null});
    log.info("  ARC: {}", .{arc_validator != null});
    log.info("  BIMI: {}", .{bimi_validator != null});

    // Start SMTPS server (port 465, implicit TLS) in a separate thread
    if (cfg.enable_tls and cfg.tls_cert_path != null) {
        smtps_thread = try std.Thread.spawn(.{}, struct {
            fn run(smtp_srv: *smtp.Server, port: u16, shutdown: *std.atomic.Value(bool)) void {
                smtp_srv.startSmtps(port, shutdown);
            }
        }.run, .{ &server, smtps_port, &shutdown_requested });
        log.info("SMTPS Server listening on 0.0.0.0:{d} (implicit TLS)", .{smtps_port});
    }

    // Start Submission server (port 587, STARTTLS) in a separate thread
    var submission_thread: ?std.Thread = null;
    const submission_port: u16 = blk: {
        const port_str = env.get("SUBMISSION_PORT") orelse "587";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 587;
    };
    if (cfg.enable_tls and cfg.tls_cert_path != null) {
        submission_thread = try std.Thread.spawn(.{}, struct {
            fn run(smtp_srv: *smtp.Server, port: u16, shutdown: *std.atomic.Value(bool)) void {
                smtp_srv.startSubmission(port, shutdown);
            }
        }.run, .{ &server, submission_port, &shutdown_requested });
        log.info("Submission Server listening on 0.0.0.0:{d} (STARTTLS)", .{submission_port});
    }

    // Start IMAP server in a separate thread
    if (imap_server) |*is| {
        imap_thread = try std.Thread.spawn(.{}, struct {
            fn run(imap_srv: *imap.ImapServer) void {
                imap_srv.start() catch |err| {
                    std.log.err("IMAP server error: {}", .{err});
                };
            }
        }.run, .{is});
        log.info("IMAP Server listening on 0.0.0.0:{d}", .{imap_port});
    }

    // Start CalDAV server in a separate thread
    if (caldav_server) |*cs| {
        caldav_thread = try std.Thread.spawn(.{}, struct {
            fn run(caldav_srv: *caldav.CalDavServer) void {
                caldav_srv.start() catch |err| {
                    std.log.err("CalDAV server error: {}", .{err});
                };
            }
        }.run, .{cs});
        log.info("CalDAV Server listening on 0.0.0.0:{d}", .{caldav_port});
        if (cfg.enable_tls and cfg.tls_cert_path != null) {
            log.info("CalDAV SSL Server listening on 0.0.0.0:{d}", .{caldav_ssl_port});
        }
    }

    // Start Discord health monitor if webhook URL is configured
    var discord_monitor: ?discord.DiscordHealthMonitor = null;
    var discord_thread: ?std.Thread = null;
    const discord_webhook_url = env.get("DISCORD_WEBHOOK_URL");
    if (discord_webhook_url) |webhook_url| {
        discord_monitor = discord.DiscordHealthMonitor.init(
            allocator,
            webhook_url,
            &server.active_connections,
            cfg.max_connections,
            &shutdown_requested,
        );
        discord_thread = try std.Thread.spawn(.{}, struct {
            fn run(monitor: *discord.DiscordHealthMonitor) void {
                monitor.run();
            }
        }.run, .{&discord_monitor.?});
        log.info("Discord health monitor enabled", .{});
    }

    server.startWithReload(&shutdown_requested, &reload_requested, reloadConfigCallback) catch |err| {
        log.critical("Server error: {}", .{err});
        // Stop IMAP server on error
        if (imap_server) |*is| {
            is.stop();
        }
        if (imap_thread) |t| {
            t.join();
        }
        // Stop CalDAV server on error
        if (caldav_server) |*cs| {
            cs.stop();
        }
        if (caldav_thread) |t| {
            t.join();
        }
        // Stop ManageSieve server on error
        if (managesieve_server) |*ms| {
            ms.stop();
        }
        if (managesieve_thread) |t| {
            t.join();
        }
        return err;
    };

    // Stop SMTPS thread on shutdown (it checks shutdown_requested flag)
    if (smtps_thread) |t| {
        t.join();
        log.info("SMTPS server stopped", .{});
    }

    // Stop Submission thread on shutdown
    if (submission_thread) |t| {
        t.join();
        log.info("Submission server stopped", .{});
    }

    // Stop IMAP server on shutdown
    if (imap_server) |*is| {
        is.stop();
        log.info("IMAP server stopped", .{});
    }
    if (imap_thread) |t| {
        t.join();
    }

    // Stop CalDAV server on shutdown
    if (caldav_server) |*cs| {
        cs.stop();
        log.info("CalDAV server stopped", .{});
    }
    if (caldav_thread) |t| {
        t.join();
    }

    // Stop ManageSieve server on shutdown
    if (managesieve_server) |*ms| {
        ms.stop();
        log.info("ManageSieve server stopped", .{});
    }
    if (managesieve_thread) |t| {
        t.join();
    }

    // Stop Discord health monitor
    if (discord_thread) |t| {
        t.join();
        log.info("Discord health monitor stopped", .{});
    }

    // Cleanup
    if (cluster_manager) |cm| {
        cm.stop();
        log.info("Cluster manager stopped", .{});
    }

    log.info("=== SMTP Server Shutdown Complete ===", .{});
}
