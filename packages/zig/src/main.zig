const std = @import("std");
const smtp = @import("core/smtp.zig");
const config = @import("core/config.zig");
const logger = @import("core/logger.zig");
const args_parser = @import("core/args.zig");
const env = @import("core/env.zig");
const writer = @import("core/maildir_writer.zig");
const database = @import("storage/database.zig");
const auth = @import("auth/auth.zig");
const greylist_mod = @import("antispam/greylist.zig");
const clamav = @import("antispam/clamav.zig");
const delivery_retry = @import("delivery/retry.zig");
const local_routing = @import("delivery/local_routing.zig");
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
const outbound = @import("delivery/outbound.zig");
const fs_compat = @import("core/fs_compat.zig");
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
const webmail_http = @import("api/webmail_http.zig");
const smtp_monitoring = @import("api/smtp_monitoring.zig");

// Global shutdown flag
var shutdown_requested = std.atomic.Value(bool).init(false);

// Global reload flag for SIGHUP
var reload_requested = std.atomic.Value(bool).init(false);

// Global reload manager pointer for callback
var global_reload_manager: ?*hot_reload.HotReloadManager = null;

/// Read an environment variable as an on/off flag, or `null` when it is unset.
///
/// `null` is the point of it. A caller can then say "unset means default to X"
/// without conflating that with an explicit `false` — which is the bug this
/// replaced: `env.get("IMAP_ENABLED") != null` treated *every* value as yes, so
/// `IMAP_ENABLED=0` switched IMAP on and there was no way to switch it off.
///
/// `0`, `false`, `no` and `off` are false; anything else present is true, so a
/// variable set to a version string or a path still reads as "on" the way the
/// old check did.
fn envFlag(name: [*:0]const u8) ?bool {
    const value = env.get(name) orelse return null;
    const trimmed = std.mem.trim(u8, value, " \t\r\n");

    if (trimmed.len == 0) return null;

    if (std.mem.eql(u8, trimmed, "0") or
        std.ascii.eqlIgnoreCase(trimmed, "false") or
        std.ascii.eqlIgnoreCase(trimmed, "no") or
        std.ascii.eqlIgnoreCase(trimmed, "off")) return false;

    return true;
}

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

fn loadOutboundDkim(allocator: std.mem.Allocator, log: *logger.Logger) !void {
    const domain = env.get("DKIM_DOMAIN") orelse "";
    const selector = env.get("DKIM_SELECTOR") orelse "";
    const path = env.get("DKIM_PRIVATE_KEY_PATH") orelse "";
    if (domain.len != 0 or selector.len != 0 or path.len != 0) {
        if (domain.len == 0 or selector.len == 0 or path.len == 0) {
            log.err("Set DKIM_DOMAIN, DKIM_SELECTOR and DKIM_PRIVATE_KEY_PATH together", .{});
            return error.InvalidDkimConfiguration;
        }
        try loadDkimSigner(allocator, log, domain, selector, path);
    }

    // Environment-backed slices outlive the registry.
    if (env.get("DKIM_EXTRA_KEYS")) |spec| {
        var entries = std.mem.splitScalar(u8, spec, ',');
        while (entries.next()) |raw| {
            const entry = std.mem.trim(u8, raw, " \t");
            if (entry.len == 0) continue;
            var parts = std.mem.splitScalar(u8, entry, ':');
            const extra_domain = parts.next().?;
            const extra_selector = parts.next() orelse "";
            const extra_path = parts.rest();
            if (extra_domain.len == 0 or extra_selector.len == 0 or extra_path.len == 0) {
                log.err("Invalid DKIM_EXTRA_KEYS entry; expected domain:selector:/path/to/key.pem", .{});
                return error.InvalidDkimConfiguration;
            }
            try loadDkimSigner(allocator, log, extra_domain, extra_selector, extra_path);
        }
    }
}

fn loadDkimSigner(allocator: std.mem.Allocator, log: *logger.Logger, domain: []const u8, selector: []const u8, path: []const u8) !void {
    const pem = fs_compat.readFileAlloc(allocator, path) catch |err| {
        log.err("Outbound DKIM key read failed (d={s} s={s}, {s}): {s}", .{ domain, selector, path, @errorName(err) });
        return err;
    };
    defer {
        std.crypto.secureZero(u8, pem);
        allocator.free(pem);
    }
    outbound.configureDkim(domain, selector, pem) catch |err| {
        log.err("Outbound DKIM signer failed (d={s} s={s}): {s}. Use an unencrypted RSA PKCS#1 or PKCS#8 PEM key", .{ domain, selector, @errorName(err) });
        return err;
    };
    log.info("Outbound DKIM signing enabled (d={s} s={s})", .{ domain, selector });
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

    const enable_cluster = envFlag("SMTP_CLUSTER_ENABLED") orelse false;
    const provisioning_port: ?u16 = if (env.get("SMTP_PROVISIONING_PORT")) |value|
        std.fmt.parseInt(u16, value, 10) catch return error.InvalidProvisioningPort
    else
        null;
    if (enable_cluster and provisioning_port != null) {
        log.err("Hosted provisioning requires one Mail writer. Disable SMTP_CLUSTER_ENABLED before starting.", .{});
        return error.HostedClusterUnsupported;
    }

    // Validate signers before claiming readiness or opening any listeners.
    try loadOutboundDkim(allocator, &log);

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

    const maildir_writer = writer.openForDaemon() catch |err| {
        log.err("Could not acquire Maildir write authority: {s}", .{@errorName(err)});
        return err;
    };
    defer _ = std.c.close(maildir_writer);

    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    const database_writer = writer.openDatabaseForDaemon(allocator, db_path, null) catch |err| {
        log.err("Could not acquire SMTP database write authority: {s}", .{@errorName(err)});
        return err;
    };
    defer if (database_writer) |lock| lock.close(allocator);

    if (enable_cluster and database_writer != null) {
        const hosted = database.Database.pathHasHostedAuthority(allocator, db_path) catch |err| {
            log.err("Could not verify hosted mailbox state before cluster startup: {s}", .{@errorName(err)});
            return err;
        };
        if (hosted) {
            log.err("This database contains hosted mailbox state. Disable SMTP_CLUSTER_ENABLED before starting.", .{});
            return error.HostedClusterUnsupported;
        }
    }

    const use_auth_backend = cfg.enable_auth or cfg.enable_webmail or provisioning_port != null;
    const enable_caldav = use_auth_backend and (envFlag("CALDAV_ENABLED") orelse cfg.enable_auth);
    const caldav_db_path = env.get("CALDAV_DB_PATH") orelse "./caldav.db";
    const caldav_writer = if (enable_caldav)
        writer.openDatabaseForDaemon(allocator, caldav_db_path, database_writer) catch |err| {
            log.err("Could not acquire DAV database write authority: {s}", .{@errorName(err)});
            return err;
        }
    else
        null;
    defer if (caldav_writer) |lock| lock.close(allocator);

    var smtp_monitor: ?smtp_monitoring.Listener = null;
    if (env.get("SMTP_MONITORING_PORT")) |value| {
        const port = std.fmt.parseInt(u16, value, 10) catch return error.InvalidSmtpMonitoringPort;
        if (port == 0) return error.InvalidSmtpMonitoringPort;
        const host = env.get("SMTP_MONITORING_HOST") orelse "127.0.0.1";
        smtp_monitor = try smtp_monitoring.Listener.bind(host, port);
        log.info("SMTP monitoring listening on {s}:{d}", .{ host, port });
    }
    defer if (smtp_monitor) |*listener| listener.deinit();

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

    // The acceptance journal is needed on SMTP-only installations, too.
    log.info("Initializing database at: {s}", .{db_path});
    var db = try database.Database.init(allocator, db_path);
    defer db.deinit();
    var auth_backend: ?auth.AuthBackend = null;
    const db_ptr: ?*database.Database = &db;
    var auth_ptr: ?*auth.AuthBackend = null;

    // The database and auth backend exist whenever *anything* needs them, and
    // the webmail client does: it reads mailboxes through the database and
    // authenticates sessions through the backend. Gating them on `enable_auth`
    // alone meant a server with webmail on and SMTP AUTH off logged
    // "Webmail enabled but auth/database are not — skipping webmail server"
    // and then served no webmail at all, having reported itself started.
    //
    // That combination is not exotic. It is exactly a development mail catcher:
    // no SMTP AUTH, because there are no accounts to authenticate, and a
    // webmail UI, because reading the caught mail is the entire point.
    if (use_auth_backend) {
        auth_backend = auth.AuthBackend.init(allocator, &db);
        auth_backend.?.exact_mailbox_domains = cfg.exact_mailbox_domains;
        const auth_default_domain = cfg.auth_default_domain orelse if (std.mem.indexOfScalar(u8, cfg.hostname, '.')) |dot|
            cfg.hostname[dot + 1 ..]
        else
            null;
        if (auth_default_domain) |domain| {
            try auth_backend.?.setDefaultDomain(domain);
            log.info("Bare mailbox logins use the configured default domain", .{});
        }
        auth_ptr = &auth_backend.?;

        // A trap needs one account, or its webmail has a login page and nothing
        // that gets past it — which is a catcher that catches mail nobody can
        // read. Created once, only when absent, and only in catch_all mode:
        // this must never invent an account on a real server.
        //
        // The password is fixed and printed rather than generated. A trap is
        // loopback-only by construction (see Config.validate), so the secret
        // protects nothing, and a generated one would have to be fished out of
        // a log every time the container restarted.
        if (cfg.catch_all) {
            const exists = auth_ptr.?.db.userExists(cfg.catch_all_mailbox) catch false;
            if (!exists) {
                const email = std.fmt.allocPrint(allocator, "{s}@{s}", .{ cfg.catch_all_mailbox, cfg.hostname }) catch null;
                defer if (email) |e| allocator.free(e);
                if (auth_ptr.?.createUser(cfg.catch_all_mailbox, "dev", email orelse cfg.catch_all_mailbox)) |_| {
                    log.info("Trap mailbox created: sign in to webmail as '{s}' with the password 'dev'", .{cfg.catch_all_mailbox});
                } else |err| {
                    log.err("Could not create the trap mailbox '{s}': {s}", .{ cfg.catch_all_mailbox, @errorName(err) });
                }
            }
        }

        log.info("Database-backed authentication enabled", .{});
    } else {
        log.info("Authentication disabled", .{});
    }

    // Recover published copies before clients can move or delete them.
    try @import("storage/folder_edits.zig").recover(allocator, &db);
    try local_routing.recover(allocator, &db);
    try @import("storage/maildir_upgrade.zig").recover(allocator, &db);
    try delivery_retry.start(allocator, &db, cfg.hostname, cfg.extra_local_domains, cfg.delivery_method, cfg.ses_region);
    defer delivery_retry.stop();
    var stop_routing: std.atomic.Value(bool) = .init(false);
    const recovery_thread = try std.Thread.spawn(.{}, local_routing.runRecovery, .{ allocator, &db, &stop_routing, cfg.junkFolder() });
    defer {
        stop_routing.store(true, .release);
        recovery_thread.join();
    }
    const effects_thread = try std.Thread.spawn(.{}, local_routing.runEffects, .{
        allocator, &db, &stop_routing, &reload_manager, &log,
    });
    defer {
        stop_routing.store(true, .release);
        effects_thread.join();
    }

    // Initialize greylisting if enabled
    var greylist: ?greylist_mod.Greylist = null;
    var greylist_ptr: ?*greylist_mod.Greylist = null;

    if (cfg.enable_greylist) {
        // Persist triplets in the main DB when available — a memory-only
        // greylist forgets everything on restart, so every deploy made every
        // active sender re-serve the full initial delay.
        greylist = if (db_ptr) |dptr|
            greylist_mod.Greylist.initWithDB(allocator, dptr) catch |err| blk: {
                log.warn("Greylist DB persistence unavailable ({}); falling back to in-memory", .{err});
                break :blk greylist_mod.Greylist.init(allocator);
            }
        else
            greylist_mod.Greylist.init(allocator);
        greylist_ptr = &greylist.?;
        const mode: []const u8 = if (db_ptr != null) ", persistent" else ", in-memory";
        log.info("Greylisting enabled (5 min delay, 4 hour retry window{s})", .{mode});
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

    var content_scanner = if (cfg.clamav_scan) |scanner_config|
        try clamav.ClamAVScanner.init(allocator, scanner_config)
    else
        null;
    defer if (content_scanner) |*scanner| scanner.deinit();
    const scanner: ?*clamav.ClamAVScanner = if (content_scanner) |*active| active else null;
    if (scanner) |active| {
        log.info("Malware scanning enabled (transport={s}, fail mode={s}, scan limit={d} bytes)", .{
            @tagName(active.config.transport), @tagName(active.config.fail_mode), active.config.max_stream_bytes,
        });
    }

    // Initialize Webmail HTTP server (browser client API). Requires auth+DB.
    const operator_id: ?i64 = if (env.get("SMTP_WEBMAIL_OPERATOR_ID")) |value| blk: {
        const id = std.fmt.parseInt(i64, value, 10) catch return error.InvalidWebmailOperatorConfiguration;
        if (id < 1 or provisioning_port != null or cfg.catch_all or !cfg.enable_webmail or !cfg.webmail_secure_cookies)
            return error.InvalidWebmailOperatorConfiguration;
        break :blk id;
    } else null;
    const hosted_sign_in_origin = env.get("SMTP_HOSTED_SIGN_IN_ORIGIN");
    const mfa_key = if (env.get("SMTP_WEBMAIL_MFA_KEY")) |value| blk: {
        var bytes: @import("storage/webmail_mfa.zig").Key = undefined;
        if (value.len != bytes.len * 2 or !cfg.enable_webmail or !cfg.webmail_secure_cookies or cfg.catch_all)
            return error.InvalidWebmailMfaConfiguration;
        _ = std.fmt.hexToBytes(&bytes, value) catch return error.InvalidWebmailMfaConfiguration;
        break :blk bytes;
    } else null;
    if (hosted_sign_in_origin) |origin| {
        if (provisioning_port == null or !cfg.enable_webmail or !cfg.webmail_secure_cookies or
            !webmail_http.validHostedSignInOrigin(origin)) return error.InvalidHostedSignInConfiguration;
        // A restored database can predate a successful exchange.
        try db_ptr.?.exec("DELETE FROM hosted_sign_in_proofs");
    }
    var webmail_server: ?webmail_http.WebmailHttpServer = null;
    var webmail_thread: ?std.Thread = null;
    if (cfg.enable_webmail) {
        if (auth_ptr != null and db_ptr != null) {
            // When TLS is enabled, the webmail server terminates HTTPS itself
            // (like IMAPS/CalDAV) and must bind a public interface; otherwise it
            // stays plain HTTP on localhost (dev / behind a proxy).
            const wm_tls = cfg.webmail_tls and cfg.enable_tls and cfg.tls_cert_path != null and cfg.tls_key_path != null;
            const wm_config = webmail_http.WebmailHttpConfig{
                .port = cfg.webmail_port,
                .bind_host = if (wm_tls) "0.0.0.0" else "127.0.0.1",
                // Cookies are Secure only over HTTPS; respect the explicit override too.
                .secure_cookies = cfg.webmail_secure_cookies,
                .max_attachment_file_bytes = cfg.webmail_attachment_max_file,
                .max_attachment_total_bytes = cfg.webmail_attachment_max_total,
                .max_attachment_count = cfg.webmail_attachment_max_count,
                .undo_send_seconds = cfg.webmail_undo_send_seconds,
                .scanner = scanner,
                .operator_id = operator_id,
                // Outbound send settings: mirror the server's so webmail mail is
                // delivered + DKIM-signed identically to SMTP submission.
                .hostname = cfg.hostname,
                .mail_config = &cfg,
                .hosted_sign_in_origin = hosted_sign_in_origin,
                .mfa_key = mfa_key,
                .hosted_team_domains = if (provisioning_port != null) env.get("SMTP_PROVISIONING_ADDITIONAL_DOMAINS") else null,
                .primary_provisioning_domain = env.get("SMTP_PROVISIONING_DOMAIN"),
                .delivery_method = cfg.delivery_method,
                .ses_region = cfg.ses_region,
                .enable_tls = wm_tls,
                .tls_cert_path = cfg.tls_cert_path,
                .tls_key_path = cfg.tls_key_path,
            };
            webmail_server = try webmail_http.WebmailHttpServer.init(allocator, wm_config, db_ptr.?, auth_ptr.?);
            log.info("Webmail HTTP server configured on {s}:{d} (TLS={})", .{ wm_config.bind_host, cfg.webmail_port, wm_tls });
        } else {
            log.warn("Webmail enabled but auth/database are not — skipping webmail server", .{});
        }
    }
    defer if (webmail_server) |*ws| ws.deinit();

    var provisioning_server: ?webmail_http.WebmailHttpServer = null;
    var provisioning_thread: ?std.Thread = null;
    defer if (provisioning_server) |*listener| {
        listener.requestStop();
        if (provisioning_thread) |thread| thread.join();
        listener.deinit();
    };
    if (provisioning_port) |port| {
        const token = env.get("SMTP_PROVISIONING_TOKEN") orelse return error.MissingProvisioningToken;
        const domain = env.get("SMTP_PROVISIONING_DOMAIN") orelse return error.MissingProvisioningDomain;
        if (port == 0 or port == cfg.port or (cfg.enable_webmail and port == cfg.webmail_port) or
            cfg.catch_all or !cfg.isLocalDomain(domain)) return error.InvalidProvisioningConfiguration;
        provisioning_server = try webmail_http.WebmailHttpServer.init(allocator, .{
            .port = port,
            .mail_config = &cfg,
            .hosted_sign_in_origin = hosted_sign_in_origin,
            .provisioning = .{
                .token = token,
                .domain = domain,
                .additional_domains = env.get("SMTP_PROVISIONING_ADDITIONAL_DOMAINS"),
            },
        }, db_ptr.?, auth_ptr.?);
        try provisioning_server.?.bind();
        provisioning_thread = try std.Thread.spawn(.{}, struct {
            fn run(listener: *webmail_http.WebmailHttpServer) void {
                listener.start() catch |err| std.log.err("Provisioning listener stopped: {}", .{err});
            }
        }.run, .{&provisioning_server.?});
    }

    // Initialize Milter support
    _ = cfg.enable_milter; // Used by protocol.zig hooks
    if (cfg.enable_milter) {
        log.info("Milter protocol support enabled", .{});
    }

    // Create and start SMTP server
    var server = try smtp.Server.init(allocator, cfg, &log, db_ptr, auth_ptr, greylist_ptr);
    defer server.deinit();

    const monitor_thread = if (smtp_monitor) |*listener|
        try std.Thread.spawn(.{}, smtp_monitoring.Listener.run, .{ listener, &server, &shutdown_requested })
    else
        null;
    defer if (monitor_thread) |thread| {
        smtp_monitor.?.stopped.store(true, .release);
        thread.join();
    };

    server.scanner = scanner;

    // Start SMTPS (port 465) if TLS is enabled
    var smtps_thread: ?std.Thread = null;
    const smtps_port: u16 = blk: {
        const port_str = env.get("SMTPS_PORT") orelse "465";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 465;
    };

    // Initialize IMAP server if auth is enabled
    var imap_server: ?imap.ImapServer = null;
    var imap_thread: ?std.Thread = null;
    // `IMAP_ENABLED=0` used to *enable* IMAP: the test was `!= null`, so any
    // value at all — including the one somebody sets to turn it off — read as
    // yes. It is parsed as a boolean now, and defaults to whether this server
    // has SMTP AUTH, which is the closest thing to "this server has accounts".
    //
    // Deliberately not `or cfg.enable_webmail`: a catcher that starts a database
    // so its UI can read mail must not thereby publish an IMAP server.
    const enable_imap = envFlag("IMAP_ENABLED") orelse cfg.enable_auth;
    const imap_port: u16 = blk: {
        const port_str = env.get("IMAP_PORT") orelse "143";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 143;
    };
    const imaps_port: u16 = blk: {
        const port_str = env.get("IMAPS_PORT") orelse "993";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 993;
    };

    if (enable_imap and auth_ptr != null) {
        const imap_config = imap.ImapConfig{
            .port = imap_port,
            .ssl_port = imaps_port,
            // The interface SMTP was told to use. A server told to bind
            // 127.0.0.1 meant it, and an IMAP listener that ignored that and
            // took 0.0.0.0 published mailboxes to the local network from a
            // process the operator had confined to loopback.
            .bind_host = cfg.host,
            .enable_ssl = cfg.enable_tls,
            .max_connections = @intCast(cfg.max_connections),
            .cert_path = cfg.tls_cert_path,
            .key_path = cfg.tls_key_path,
            .junk_folder = cfg.junkFolder(),
            .enable_gmail_labels = if (env.get("IMAP_GMAIL_LABELS_ENABLED")) |value|
                std.ascii.eqlIgnoreCase(value, "true") or std.mem.eql(u8, value, "1")
            else
                true,
        };
        imap_server = imap.ImapServer.init(allocator, imap_config, auth_ptr.?, db_ptr);
        imap_server.?.scanner = scanner;
        log.info("IMAP server configured on port {d}", .{imap_port});
        if (cfg.enable_tls and cfg.tls_cert_path != null) {
            log.info("IMAPS server configured on port {d} (SSL/TLS)", .{imaps_port});
        }
    }
    defer if (imap_server) |*is| is.deinit();

    // Initialize CalDAV/CardDAV store and server if auth is enabled
    var caldav_store_inst: ?caldav_store_mod.CalDavStore = null;
    var caldav_server: ?caldav.CalDavServer = null;
    var caldav_thread: ?std.Thread = null;
    const caldav_port: u16 = blk: {
        const port_str = env.get("CALDAV_PORT") orelse "80";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 80;
    };
    const caldav_ssl_port: u16 = blk: {
        const port_str = env.get("CALDAV_SSL_PORT") orelse "443";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 443;
    };
    // Publicly reachable HTTPS port advertised in the Apple .mobileconfig for
    // CalDAV/CardDAV. Defaults to 443 (the standard HTTPS port clients try),
    // independent of the internal bind port above — set CALDAV_PUBLIC_SSL_PORT
    // only if DAV is reachable on a non-standard public port.
    const caldav_public_ssl_port: u16 = blk: {
        const port_str = env.get("CALDAV_PUBLIC_SSL_PORT") orelse "443";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 443;
    };

    if (enable_caldav) {
        // Persist CalDAV/CardDAV data to SQLite so calendars/contacts survive
        // restarts (and so the ActiveSync server has real data to sync).
        var store_config = caldav_store_mod.StoreConfig{ .db_path = caldav_db_path, .account_db = db_ptr.? };
        if (env.get("CALDAV_MAX_SYNC_HISTORY")) |value| {
            store_config.max_sync_history = std.fmt.parseInt(u32, value, 10) catch store_config.max_sync_history;
        }
        if (env.get("CALDAV_SYNC_CANARY_MAILBOX")) |mailbox| {
            if (mailbox.len != 0) {
                if (db_ptr.?.getUserByUsername(mailbox)) |found| {
                    var account = found;
                    defer account.deinit(db_ptr.?.allocator);
                    store_config.sync_canary_mailbox_id = account.id;
                } else |err| {
                    if (err != error.NotFound) return err;
                    log.warn("CALDAV_SYNC_CANARY_MAILBOX did not resolve to a provisioned mailbox", .{});
                }
            }
        }
        caldav_store_inst = try caldav_store_mod.CalDavStore.init(allocator, store_config);
        log.info("CalDAV/CardDAV store persisting to: {s}", .{caldav_db_path});

        const caldav_config = caldav.CalDavConfig{
            .scanner = scanner,
            .draft_service = if (webmail_server) |*ws| &ws.service else null,
            .port = caldav_port,
            .ssl_port = caldav_ssl_port,
            // Same reason as IMAP above: honour the interface the server was
            // told to bind rather than publishing calendars on every one.
            .bind_host = cfg.host,
            .enable_ssl = cfg.enable_tls,
            .max_connections = @intCast(cfg.max_connections),
            .cert_path = cfg.tls_cert_path,
            .key_path = cfg.tls_key_path,
            .public_hostname = cfg.hostname,
            .imaps_port = 993,
            .submission_port = 587,
            .public_dav_port = caldav_public_ssl_port,
            .display_name = cfg.hostname,
            // MTA-STS policy mode (default enforce); override with MTA_STS_MODE=testing.
            .mta_sts_mode = env.get("MTA_STS_MODE") orelse "enforce",
            .delivery_method = cfg.delivery_method,
            .mail_config = &cfg,
            .ses_region = cfg.ses_region,
        };
        caldav_server = caldav.CalDavServer.init(allocator, caldav_config, auth_ptr.?, &caldav_store_inst.?);
        if (webmail_server) |*ws| ws.dav_store = &caldav_store_inst.?;
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

    // Start Webmail HTTP server in a separate thread
    if (webmail_server) |*ws| {
        webmail_thread = try std.Thread.spawn(.{}, struct {
            fn run(wm_srv: *webmail_http.WebmailHttpServer) void {
                wm_srv.start() catch |err| {
                    std.log.err("Webmail HTTP server error: {}", .{err});
                };
            }
        }.run, .{ws});
        log.info("Webmail HTTP Server listening on 127.0.0.1:{d}", .{cfg.webmail_port});
    }

    // Log startup summary
    log.info("Starting SMTP server...", .{});
    log.info("  IMAP enabled: {}", .{imap_server != null});
    log.info("  CalDAV enabled: {}", .{caldav_server != null});
    log.info("  ManageSieve enabled: {}", .{managesieve_server != null});
    log.info("  Webmail HTTP enabled: {}", .{webmail_server != null});
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
        // Stop Webmail HTTP server on error
        if (webmail_server) |*ws| {
            ws.stop();
        }
        if (webmail_thread) |t| {
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

    // Stop Webmail HTTP server on shutdown
    if (webmail_server) |*ws| {
        ws.stop();
        log.info("Webmail HTTP server stopped", .{});
    }
    if (webmail_thread) |t| {
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
