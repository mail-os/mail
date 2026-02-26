const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const socket = @import("../core/socket_compat.zig");

// ManageSieve Protocol (RFC 5804) - remote Sieve script management on port 4190

pub const ManageSieveConfig = struct {
    port: u16 = 4190,
    max_connections: usize = 100,
    enable_tls: bool = true,
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    hostname: []const u8 = "localhost",
    connection_timeout_seconds: u64 = 1800,
    max_script_size: usize = 1024 * 1024,
    max_scripts_per_user: usize = 100,
    sieve_extensions: []const u8 = "fileinto reject envelope vacation imapflags notify subaddress relational comparator-i;ascii-numeric body regex",
    max_redirects: u32 = 5,
    implementation_name: []const u8 = "Zig Mail ManageSieve v1.0",
    script_dir: []const u8 = "/var/sieve",
};

pub const ManageSieveCommand = enum {
    AUTHENTICATE, CAPABILITY, HAVESPACE, PUTSCRIPT, LISTSCRIPTS, SETACTIVE,
    GETSCRIPT, DELETESCRIPT, RENAMESCRIPT, CHECKSCRIPT, NOOP, LOGOUT, STARTTLS,

    pub fn fromString(str: []const u8) ?ManageSieveCommand {
        if (str.len == 0 or str.len > 16) return null;
        var buf: [16]u8 = undefined;
        const u = buf[0..str.len];
        _ = std.ascii.upperString(u, str);
        if (std.mem.eql(u8, u, "AUTHENTICATE")) return .AUTHENTICATE;
        if (std.mem.eql(u8, u, "CAPABILITY")) return .CAPABILITY;
        if (std.mem.eql(u8, u, "HAVESPACE")) return .HAVESPACE;
        if (std.mem.eql(u8, u, "PUTSCRIPT")) return .PUTSCRIPT;
        if (std.mem.eql(u8, u, "LISTSCRIPTS")) return .LISTSCRIPTS;
        if (std.mem.eql(u8, u, "SETACTIVE")) return .SETACTIVE;
        if (std.mem.eql(u8, u, "GETSCRIPT")) return .GETSCRIPT;
        if (std.mem.eql(u8, u, "DELETESCRIPT")) return .DELETESCRIPT;
        if (std.mem.eql(u8, u, "RENAMESCRIPT")) return .RENAMESCRIPT;
        if (std.mem.eql(u8, u, "CHECKSCRIPT")) return .CHECKSCRIPT;
        if (std.mem.eql(u8, u, "NOOP")) return .NOOP;
        if (std.mem.eql(u8, u, "LOGOUT")) return .LOGOUT;
        if (std.mem.eql(u8, u, "STARTTLS")) return .STARTTLS;
        return null;
    }

    pub fn toString(self: ManageSieveCommand) []const u8 {
        return switch (self) {
            .AUTHENTICATE => "AUTHENTICATE", .CAPABILITY => "CAPABILITY",
            .HAVESPACE => "HAVESPACE", .PUTSCRIPT => "PUTSCRIPT",
            .LISTSCRIPTS => "LISTSCRIPTS", .SETACTIVE => "SETACTIVE",
            .GETSCRIPT => "GETSCRIPT", .DELETESCRIPT => "DELETESCRIPT",
            .RENAMESCRIPT => "RENAMESCRIPT", .CHECKSCRIPT => "CHECKSCRIPT",
            .NOOP => "NOOP", .LOGOUT => "LOGOUT", .STARTTLS => "STARTTLS",
        };
    }
};

pub const ManageSieveState = enum { connected, tls_negotiating, authenticated, closing };

pub const ResponseCode = enum {
    AUTH_TOO_WEAK, ENCRYPT_NEEDED, QUOTA, QUOTA_MAXSCRIPTS, QUOTA_MAXSIZE,
    REFERRAL, SASL, TRANSITION_NEEDED, TRYLATER, ACTIVE, NONEXISTENT, ALREADYEXISTS, TAG,

    pub fn toString(self: ResponseCode) []const u8 {
        return switch (self) {
            .AUTH_TOO_WEAK => "AUTH-TOO-WEAK", .ENCRYPT_NEEDED => "ENCRYPT-NEEDED",
            .QUOTA => "QUOTA", .QUOTA_MAXSCRIPTS => "QUOTA/MAXSCRIPTS",
            .QUOTA_MAXSIZE => "QUOTA/MAXSIZE", .REFERRAL => "REFERRAL",
            .SASL => "SASL", .TRANSITION_NEEDED => "TRANSITION-NEEDED",
            .TRYLATER => "TRYLATER", .ACTIVE => "ACTIVE",
            .NONEXISTENT => "NONEXISTENT", .ALREADYEXISTS => "ALREADYEXISTS",
            .TAG => "TAG",
        };
    }
};

pub const ManageSieveCapability = struct {
    implementation: []const u8,
    sasl_mechanisms: []const u8,
    sieve_extensions: []const u8,
    starttls: bool,
    notify_methods: ?[]const u8,
    max_redirects: ?u32,
    version: []const u8,

    pub fn init(config: *const ManageSieveConfig) ManageSieveCapability {
        return .{
            .implementation = config.implementation_name, .sasl_mechanisms = "PLAIN",
            .sieve_extensions = config.sieve_extensions, .starttls = config.enable_tls,
            .notify_methods = "mailto", .max_redirects = config.max_redirects, .version = "1.0",
        };
    }

    pub fn format(self: *const ManageSieveCapability, allocator: std.mem.Allocator) ![]const u8 {
        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(allocator);
        try buf.print(allocator, "\"IMPLEMENTATION\" \"{s}\"\r\n", .{self.implementation});
        try buf.print(allocator, "\"SASL\" \"{s}\"\r\n", .{self.sasl_mechanisms});
        try buf.print(allocator, "\"SIEVE\" \"{s}\"\r\n", .{self.sieve_extensions});
        if (self.starttls) try buf.appendSlice(allocator, "\"STARTTLS\"\r\n");
        if (self.notify_methods) |m| try buf.print(allocator, "\"NOTIFY\" \"{s}\"\r\n", .{m});
        if (self.max_redirects) |n| try buf.print(allocator, "\"MAXREDIRECTS\" \"{d}\"\r\n", .{n});
        try buf.print(allocator, "\"VERSION\" \"{s}\"\r\n", .{self.version});
        return try allocator.dupe(u8, buf.items);
    }
};

pub const SieveScript = struct {
    name: []const u8,
    content: []const u8,
    active: bool,
    size: usize,
    created_at: i64,
    modified_at: i64,

    pub fn deinit(self: *SieveScript, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.content);
    }
};

/// SASL PLAIN credentials (RFC 4616): [authzid] NUL authcid NUL passwd
pub const SaslPlainCredentials = struct {
    authzid: []const u8,
    authcid: []const u8,
    passwd: []const u8,

    pub fn decode(allocator: std.mem.Allocator, b64: []const u8) !?SaslPlainCredentials {
        const len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return null;
        const dec = try allocator.alloc(u8, len);
        defer allocator.free(dec);
        std.base64.standard.Decoder.decode(dec, b64) catch return null;
        const n1 = std.mem.indexOfScalar(u8, dec, 0) orelse return null;
        if (n1 + 1 >= dec.len) return null;
        const rest = dec[n1 + 1 ..];
        const n2 = std.mem.indexOfScalar(u8, rest, 0) orelse return null;
        if (n2 + 1 > rest.len) return null;
        const authcid = rest[0..n2];
        const passwd = rest[n2 + 1 ..];
        if (authcid.len == 0 or passwd.len == 0) return null;
        return .{
            .authzid = try allocator.dupe(u8, dec[0..n1]),
            .authcid = try allocator.dupe(u8, authcid),
            .passwd = try allocator.dupe(u8, passwd),
        };
    }

    pub fn deinit(self: *SaslPlainCredentials, allocator: std.mem.Allocator) void {
        if (self.passwd.len > 0) { const p: []u8 = @constCast(self.passwd); @memset(p, 0); allocator.free(p); }
        if (self.authcid.len > 0) allocator.free(self.authcid);
        if (self.authzid.len > 0) allocator.free(self.authzid);
    }
};

pub const ResponseFormatter = struct {
    pub fn ok(a: std.mem.Allocator, code: ?ResponseCode, msg: ?[]const u8) ![]const u8 { return fmtResp(a, "OK", code, msg); }
    pub fn no(a: std.mem.Allocator, code: ?ResponseCode, msg: ?[]const u8) ![]const u8 { return fmtResp(a, "NO", code, msg); }
    pub fn bye(a: std.mem.Allocator, code: ?ResponseCode, msg: ?[]const u8) ![]const u8 { return fmtResp(a, "BYE", code, msg); }

    fn fmtResp(a: std.mem.Allocator, tag: []const u8, code: ?ResponseCode, msg: ?[]const u8) ![]const u8 {
        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(a);
        try buf.appendSlice(a, tag);
        if (code) |c| try buf.print(a, " ({s})", .{c.toString()});
        if (msg) |m| try buf.print(a, " \"{s}\"", .{m});
        try buf.appendSlice(a, "\r\n");
        return try a.dupe(u8, buf.items);
    }

    pub fn encodeLiteral(a: std.mem.Allocator, data: []const u8) ![]const u8 {
        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(a);
        try buf.print(a, "{{{d}+}}\r\n{s}", .{ data.len, data });
        return try a.dupe(u8, buf.items);
    }

    pub fn encodeQuoted(a: std.mem.Allocator, data: []const u8) ![]const u8 {
        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(a);
        try buf.append(a, '"');
        for (data) |c| { if (c == '\\' or c == '"') try buf.append(a, '\\'); try buf.append(a, c); }
        try buf.append(a, '"');
        return try a.dupe(u8, buf.items);
    }
};

pub const LiteralParser = struct {
    length: usize,
    non_sync: bool,
    prefix_len: usize,

    pub fn parse(input: []const u8) ?LiteralParser {
        if (input.len < 4 or input[0] != '{') return null;
        var i: usize = 1;
        const ds = i;
        while (i < input.len and input[i] >= '0' and input[i] <= '9') : (i += 1) {}
        if (i == ds) return null;
        const length = std.fmt.parseInt(usize, input[ds..i], 10) catch return null;
        var ns = false;
        if (i < input.len and input[i] == '+') { ns = true; i += 1; }
        if (i >= input.len or input[i] != '}') return null;
        i += 1;
        if (i + 1 >= input.len or input[i] != '\r' or input[i + 1] != '\n') return null;
        i += 2;
        return .{ .length = length, .non_sync = ns, .prefix_len = i };
    }
};

const QStr = struct { value: []const u8, end: usize };

fn extractQuotedString(input: []const u8) ?QStr {
    const tr = std.mem.trimStart(u8, input, " \t");
    if (tr.len == 0 or tr[0] != '"') return null;
    const off = @intFromPtr(tr.ptr) - @intFromPtr(input.ptr);
    var i: usize = 1;
    while (i < tr.len) {
        if (tr[i] == '\\' and i + 1 < tr.len) { i += 2; continue; }
        if (tr[i] == '"') return .{ .value = tr[1..i], .end = off + i + 1 };
        i += 1;
    }
    return null;
}

fn validateSieveScript(script: []const u8) bool {
    if (script.len == 0 or !std.unicode.utf8ValidateSlice(script)) return false;
    var d: i32 = 0;
    for (script) |c| {
        if (c == '{') d += 1;
        if (c == '}') d -= 1;
        if (d < 0) return false;
    }
    return d == 0;
}

pub fn checkScriptSize(size: usize, max: usize) bool { return size <= max; }

pub const ManageSieveSession = struct {
    allocator: std.mem.Allocator,
    stream: socket.Connection,
    server: *ManageSieveServer,
    state: ManageSieveState,
    username: ?[]const u8,
    tls_active: bool,
    scripts: std.StringHashMap(SieveScript),
    active_script: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, connection: socket.Connection, server: *ManageSieveServer) ManageSieveSession {
        return .{
            .allocator = allocator, .stream = connection, .server = server,
            .state = .connected, .username = null, .tls_active = false,
            .scripts = std.StringHashMap(SieveScript).init(allocator), .active_script = null,
        };
    }

    pub fn deinit(self: *ManageSieveSession) void {
        if (self.username) |u| self.allocator.free(u);
        if (self.active_script) |a| self.allocator.free(a);
        var it = self.scripts.iterator();
        while (it.next()) |e| { var s = e.value_ptr.*; s.deinit(self.allocator); }
        self.scripts.deinit();
    }

    fn send(self: *ManageSieveSession, data: []const u8) !void {
        var sent: usize = 0;
        while (sent < data.len) {
            sent += self.stream.write(data[sent..]) catch return error.BrokenPipe;
        }
    }

    fn sendOk(self: *ManageSieveSession, code: ?ResponseCode, msg: ?[]const u8) !void {
        const r = try ResponseFormatter.ok(self.allocator, code, msg); defer self.allocator.free(r); try self.send(r);
    }
    fn sendNo(self: *ManageSieveSession, code: ?ResponseCode, msg: ?[]const u8) !void {
        const r = try ResponseFormatter.no(self.allocator, code, msg); defer self.allocator.free(r); try self.send(r);
    }
    fn sendBye(self: *ManageSieveSession, code: ?ResponseCode, msg: ?[]const u8) !void {
        const r = try ResponseFormatter.bye(self.allocator, code, msg); defer self.allocator.free(r); try self.send(r);
    }

    fn sendCapabilities(self: *ManageSieveSession) !void {
        var cap = ManageSieveCapability.init(&self.server.config);
        if (self.tls_active) cap.starttls = false;
        const s = try cap.format(self.allocator); defer self.allocator.free(s);
        try self.send(s);
        try self.sendOk(null, null);
    }

    pub fn handleConnection(self: *ManageSieveSession) !void {
        try self.sendCapabilities();
        var rbuf: [8192]u8 = undefined;
        var lbuf = std.ArrayList(u8){}; defer lbuf.deinit(self.allocator);
        while (self.state != .closing) {
            const n = self.stream.read(&rbuf) catch |err| { std.log.err("ManageSieve read: {}", .{err}); break; };
            if (n == 0) break;
            try lbuf.appendSlice(self.allocator, rbuf[0..n]);
            while (self.state != .closing) {
                const end = std.mem.indexOf(u8, lbuf.items, "\r\n") orelse break;
                const line = lbuf.items[0..end];
                const cont = try self.processLine(line);
                const consumed = end + 2;
                if (consumed < lbuf.items.len) std.mem.copyForwards(u8, lbuf.items[0..], lbuf.items[consumed..]);
                lbuf.shrinkRetainingCapacity(lbuf.items.len - consumed);
                if (!cont) { self.state = .closing; break; }
            }
        }
    }

    fn processLine(self: *ManageSieveSession, line: []const u8) !bool {
        const t = std.mem.trim(u8, line, " \t");
        if (t.len == 0) return true;
        var parts = std.mem.splitScalar(u8, t, ' ');
        const cs = parts.next() orelse return true;
        const rest = if (parts.next()) |f| blk: {
            break :blk t[@intFromPtr(f.ptr) - @intFromPtr(t.ptr) ..];
        } else "";
        const cmd = ManageSieveCommand.fromString(cs) orelse { try self.sendNo(null, "Unknown command"); return true; };
        switch (cmd) {
            .CAPABILITY => { try self.sendCapabilities(); return true; },
            .LOGOUT => { try self.handleLogout(); return false; },
            .STARTTLS => { try self.handleStartTls(); return true; },
            .AUTHENTICATE => { try self.handleAuthenticate(rest); return true; },
            .NOOP => { try self.handleNoop(rest); return true; },
            else => {},
        }
        if (self.state != .authenticated) { try self.sendNo(null, "Authenticate first"); return true; }
        switch (cmd) {
            .HAVESPACE => try self.handleHaveSpace(rest),
            .PUTSCRIPT => try self.handlePutScript(rest),
            .LISTSCRIPTS => try self.handleListScripts(),
            .SETACTIVE => try self.handleSetActive(rest),
            .GETSCRIPT => try self.handleGetScript(rest),
            .DELETESCRIPT => try self.handleDeleteScript(rest),
            .RENAMESCRIPT => try self.handleRenameScript(rest),
            .CHECKSCRIPT => try self.handleCheckScript(rest),
            .CAPABILITY, .LOGOUT, .STARTTLS, .AUTHENTICATE, .NOOP => unreachable,
        }
        return true;
    }

    fn handleAuthenticate(self: *ManageSieveSession, args: []const u8) !void {
        if (self.state == .authenticated) { try self.sendNo(null, "Already authenticated"); return; }
        const mech = extractQuotedString(args) orelse { try self.sendNo(null, "Missing authentication mechanism"); return; };
        var mb: [16]u8 = undefined;
        if (mech.value.len > 16) { try self.sendNo(.AUTH_TOO_WEAK, "Unsupported mechanism"); return; }
        const mu = mb[0..mech.value.len];
        _ = std.ascii.upperString(mu, mech.value);
        if (!std.mem.eql(u8, mu, "PLAIN")) { try self.sendNo(.AUTH_TOO_WEAK, "Only PLAIN is supported"); return; }
        const rem = std.mem.trim(u8, args[mech.end..], " \t");
        const cs = extractQuotedString(rem) orelse { try self.sendNo(null, "SASL PLAIN initial response required"); return; };
        var creds = (try SaslPlainCredentials.decode(self.allocator, cs.value)) orelse {
            try self.sendNo(null, "Invalid SASL PLAIN credentials"); return;
        };
        defer creds.deinit(self.allocator);
        const auth = self.server.auth_backend orelse {
            try self.sendNo(.TRYLATER, "No auth backend configured"); return;
        };
        const valid = auth.verifyCredentials(creds.authcid, creds.passwd) catch {
            try self.sendNo(.TRYLATER, "Auth backend unavailable"); return;
        };
        if (!valid) { std.log.warn("ManageSieve auth failed: {s}", .{creds.authcid}); try self.sendNo(null, "Authentication failed"); return; }
        self.username = try self.allocator.dupe(u8, creds.authcid);
        self.state = .authenticated;
        std.log.info("ManageSieve authenticated: {s}", .{creds.authcid});
        try self.sendOk(null, "Authentication successful");
    }

    fn handleStartTls(self: *ManageSieveSession) !void {
        if (self.tls_active) { try self.sendNo(null, "TLS already active"); return; }
        if (!self.server.config.enable_tls) { try self.sendNo(null, "STARTTLS not available"); return; }
        if (self.state == .authenticated) { try self.sendNo(null, "STARTTLS not allowed after auth"); return; }
        try self.sendOk(null, "Begin TLS negotiation now");
        self.tls_active = true;
        self.state = .connected; // client must re-authenticate
    }

    fn handleHaveSpace(self: *ManageSieveSession, args: []const u8) !void {
        const nm = extractQuotedString(args) orelse { try self.sendNo(null, "Missing script name"); return; };
        const rem = std.mem.trim(u8, args[nm.end..], " \t");
        const sz = std.fmt.parseInt(usize, rem, 10) catch { try self.sendNo(null, "Invalid size"); return; };
        if (sz > self.server.config.max_script_size) { try self.sendNo(.QUOTA_MAXSIZE, "Script too large"); return; }
        if (self.scripts.count() >= self.server.config.max_scripts_per_user and !self.scripts.contains(nm.value)) {
            try self.sendNo(.QUOTA_MAXSCRIPTS, "Too many scripts"); return;
        }
        try self.sendOk(null, "Space available");
    }

    fn handlePutScript(self: *ManageSieveSession, args: []const u8) !void {
        const nm = extractQuotedString(args) orelse { try self.sendNo(null, "Missing script name"); return; };
        if (nm.value.len == 0) { try self.sendNo(null, "Script name must not be empty"); return; }
        const rem = std.mem.trim(u8, args[nm.end..], " \t");
        var content: []const u8 = undefined;
        if (LiteralParser.parse(rem)) |lit| {
            if (lit.prefix_len + lit.length > rem.len) { try self.sendNo(null, "Incomplete literal"); return; }
            content = rem[lit.prefix_len .. lit.prefix_len + lit.length];
        } else if (extractQuotedString(rem)) |qs| { content = qs.value; }
        else { try self.sendNo(null, "Missing script content"); return; }
        if (content.len > self.server.config.max_script_size) { try self.sendNo(.QUOTA_MAXSIZE, "Script too large"); return; }
        if (!self.scripts.contains(nm.value) and self.scripts.count() >= self.server.config.max_scripts_per_user) {
            try self.sendNo(.QUOTA_MAXSCRIPTS, "Too many scripts"); return;
        }
        if (!validateSieveScript(content)) { try self.sendNo(null, "Script validation failed"); return; }
        const now = time_compat.timestamp();
        const nc = try self.allocator.dupe(u8, nm.value); errdefer self.allocator.free(nc);
        const cc = try self.allocator.dupe(u8, content); errdefer self.allocator.free(cc);
        if (self.scripts.fetchRemove(nm.value)) |old| { var s = old.value; s.deinit(self.allocator); }
        try self.scripts.put(nc, .{ .name = nc, .content = cc, .active = false, .size = cc.len, .created_at = now, .modified_at = now });
        try self.sendOk(null, "Script stored");
    }

    fn handleListScripts(self: *ManageSieveSession) !void {
        var it = self.scripts.iterator();
        while (it.next()) |e| {
            const s = e.value_ptr.*;
            const q = try ResponseFormatter.encodeQuoted(self.allocator, s.name); defer self.allocator.free(q);
            if (s.active) {
                const l = try std.fmt.allocPrint(self.allocator, "{s} ACTIVE\r\n", .{q}); defer self.allocator.free(l); try self.send(l);
            } else {
                const l = try std.fmt.allocPrint(self.allocator, "{s}\r\n", .{q}); defer self.allocator.free(l); try self.send(l);
            }
        }
        try self.sendOk(null, null);
    }

    fn handleSetActive(self: *ManageSieveSession, args: []const u8) !void {
        const nm = extractQuotedString(args) orelse { try self.sendNo(null, "Missing script name"); return; };
        if (nm.value.len == 0) {
            var it = self.scripts.iterator(); while (it.next()) |e| e.value_ptr.*.active = false;
            if (self.active_script) |a| { self.allocator.free(a); self.active_script = null; }
            try self.sendOk(null, "All scripts deactivated"); return;
        }
        if (!self.scripts.contains(nm.value)) { try self.sendNo(.NONEXISTENT, "Script does not exist"); return; }
        var it = self.scripts.iterator(); while (it.next()) |e| e.value_ptr.*.active = false;
        if (self.scripts.getPtr(nm.value)) |s| s.active = true;
        if (self.active_script) |a| self.allocator.free(a);
        self.active_script = try self.allocator.dupe(u8, nm.value);
        try self.sendOk(null, "Script activated");
    }

    fn handleGetScript(self: *ManageSieveSession, args: []const u8) !void {
        const nm = extractQuotedString(args) orelse { try self.sendNo(null, "Missing script name"); return; };
        const sc = self.scripts.get(nm.value) orelse { try self.sendNo(.NONEXISTENT, "No such script"); return; };
        const lit = try ResponseFormatter.encodeLiteral(self.allocator, sc.content); defer self.allocator.free(lit);
        try self.send(lit); try self.send("\r\n"); try self.sendOk(null, null);
    }

    fn handleDeleteScript(self: *ManageSieveSession, args: []const u8) !void {
        const nm = extractQuotedString(args) orelse { try self.sendNo(null, "Missing script name"); return; };
        const sc = self.scripts.get(nm.value) orelse { try self.sendNo(.NONEXISTENT, "No such script"); return; };
        if (sc.active) { try self.sendNo(.ACTIVE, "Cannot delete active script"); return; }
        if (self.scripts.fetchRemove(nm.value)) |old| { var s = old.value; s.deinit(self.allocator); }
        try self.sendOk(null, "Script deleted");
    }

    fn handleRenameScript(self: *ManageSieveSession, args: []const u8) !void {
        const on = extractQuotedString(args) orelse { try self.sendNo(null, "Missing old name"); return; };
        const rem = std.mem.trim(u8, args[on.end..], " \t");
        const nn = extractQuotedString(rem) orelse { try self.sendNo(null, "Missing new name"); return; };
        if (nn.value.len == 0) { try self.sendNo(null, "New name must not be empty"); return; }
        const old = self.scripts.get(on.value) orelse { try self.sendNo(.NONEXISTENT, "No such script"); return; };
        if (self.scripts.contains(nn.value)) { try self.sendNo(.ALREADYEXISTS, "Name already in use"); return; }
        const nk = try self.allocator.dupe(u8, nn.value); errdefer self.allocator.free(nk);
        const cc = try self.allocator.dupe(u8, old.content); errdefer self.allocator.free(cc);
        const wa = old.active; const cr = old.created_at;
        if (self.scripts.fetchRemove(on.value)) |o| { var s = o.value; s.deinit(self.allocator); }
        try self.scripts.put(nk, .{ .name = nk, .content = cc, .active = wa, .size = cc.len, .created_at = cr, .modified_at = time_compat.timestamp() });
        if (wa) { if (self.active_script) |a| self.allocator.free(a); self.active_script = try self.allocator.dupe(u8, nn.value); }
        try self.sendOk(null, "Script renamed");
    }

    fn handleCheckScript(self: *ManageSieveSession, args: []const u8) !void {
        const tr = std.mem.trim(u8, args, " \t");
        var content: []const u8 = undefined;
        if (LiteralParser.parse(tr)) |lit| {
            if (lit.prefix_len + lit.length > tr.len) { try self.sendNo(null, "Incomplete literal"); return; }
            content = tr[lit.prefix_len .. lit.prefix_len + lit.length];
        } else if (extractQuotedString(tr)) |qs| { content = qs.value; }
        else { try self.sendNo(null, "Missing script content"); return; }
        if (!validateSieveScript(content)) { try self.sendNo(null, "Script validation failed"); return; }
        try self.sendOk(null, "Script is valid");
    }

    fn handleNoop(self: *ManageSieveSession, args: []const u8) !void {
        const tr = std.mem.trim(u8, args, " \t");
        if (tr.len > 0) {
            if (extractQuotedString(tr)) |tag| {
                var buf: std.ArrayList(u8) = .{}; defer buf.deinit(self.allocator);
                try buf.print(self.allocator, "OK (TAG \"{s}\") \"NOOP completed\"\r\n", .{tag.value});
                const r = try self.allocator.dupe(u8, buf.items); defer self.allocator.free(r);
                try self.send(r); return;
            }
        }
        try self.sendOk(null, "NOOP completed");
    }

    fn handleLogout(self: *ManageSieveSession) !void {
        try self.sendOk(null, "Logging out");
        self.state = .closing;
    }
};

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub const ManageSieveServer = struct {
    allocator: std.mem.Allocator,
    config: ManageSieveConfig,
    listener: ?socket.Server,
    running: std.atomic.Value(bool),
    mutex: std.Thread.Mutex,
    active_sessions: usize,
    auth_backend: ?*AuthBackendInterface,

    pub const AuthBackendInterface = struct {
        ptr: *anyopaque,
        verifyFn: *const fn (ptr: *anyopaque, username: []const u8, password: []const u8) VerifyError!bool,
        pub const VerifyError = error{ DatabaseError, PasswordHashError, OutOfMemory, Unexpected };

        pub fn verifyCredentials(self: *AuthBackendInterface, u: []const u8, p: []const u8) VerifyError!bool {
            return self.verifyFn(self.ptr, u, p);
        }
        pub fn from(backend: anytype) AuthBackendInterface {
            const Ptr = @TypeOf(backend);
            const gen = struct {
                fn verify(ptr: *anyopaque, user: []const u8, pass: []const u8) VerifyError!bool {
                    const s: Ptr = @ptrCast(@alignCast(ptr));
                    return s.verifyCredentials(user, pass) catch return VerifyError.Unexpected;
                }
            };
            return .{ .ptr = @ptrCast(backend), .verifyFn = &gen.verify };
        }
    };

    pub fn init(allocator: std.mem.Allocator, config: ManageSieveConfig, auth_backend: ?*AuthBackendInterface) ManageSieveServer {
        return .{
            .allocator = allocator, .config = config, .listener = null,
            .running = std.atomic.Value(bool).init(false), .mutex = .{},
            .active_sessions = 0, .auth_backend = auth_backend,
        };
    }

    pub fn deinit(self: *ManageSieveServer) void { self.stop(); }

    pub fn start(self: *ManageSieveServer) !void {
        const addr = try socket.Address.parseIp("0.0.0.0", self.config.port);
        const listener = try socket.Server.listen(addr, .{ .reuse_address = true });
        self.listener = listener;
        self.running.store(true, .monotonic);
        std.log.info("ManageSieve listening on port {d}", .{self.config.port});
        while (self.running.load(.monotonic)) {
            const conn = self.listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break;
                std.log.err("ManageSieve accept: {}", .{err});
                continue;
            };
            self.mutex.lock();
            if (self.active_sessions >= self.config.max_connections) {
                self.mutex.unlock();
                const b = ResponseFormatter.bye(self.allocator, .TRYLATER, "Too many connections") catch { conn.close(); continue; };
                defer self.allocator.free(b);
                _ = conn.write(b) catch {};
                conn.close();
                continue;
            }
            self.active_sessions += 1;
            self.mutex.unlock();
            self.handleConn(conn) catch |err| {
                std.log.err("ManageSieve conn error: {}", .{err});
                conn.close();
                self.mutex.lock(); self.active_sessions -|= 1; self.mutex.unlock();
            };
        }
    }

    pub fn stop(self: *ManageSieveServer) void {
        self.running.store(false, .monotonic);
        if (self.listener) |*l| { l.close(); self.listener = null; }
    }

    fn handleConn(self: *ManageSieveServer, stream: socket.Connection) !void {
        var sess = ManageSieveSession.init(self.allocator, stream, self);
        defer { sess.deinit(); stream.close(); self.mutex.lock(); self.active_sessions -|= 1; self.mutex.unlock(); }
        sess.handleConnection() catch |err| {
            std.log.err("ManageSieve session: {}", .{err});
            sess.sendBye(.TRYLATER, "Internal error") catch {};
        };
    }

    pub fn getActiveSessionCount(self: *ManageSieveServer) usize {
        self.mutex.lock(); defer self.mutex.unlock(); return self.active_sessions;
    }
};

// ===========================================================================
// Tests
// ===========================================================================

test "command parsing - all valid commands" {
    const T = std.testing;
    try T.expectEqual(ManageSieveCommand.AUTHENTICATE, ManageSieveCommand.fromString("AUTHENTICATE").?);
    try T.expectEqual(ManageSieveCommand.CAPABILITY, ManageSieveCommand.fromString("CAPABILITY").?);
    try T.expectEqual(ManageSieveCommand.HAVESPACE, ManageSieveCommand.fromString("HAVESPACE").?);
    try T.expectEqual(ManageSieveCommand.PUTSCRIPT, ManageSieveCommand.fromString("PUTSCRIPT").?);
    try T.expectEqual(ManageSieveCommand.LISTSCRIPTS, ManageSieveCommand.fromString("LISTSCRIPTS").?);
    try T.expectEqual(ManageSieveCommand.SETACTIVE, ManageSieveCommand.fromString("SETACTIVE").?);
    try T.expectEqual(ManageSieveCommand.GETSCRIPT, ManageSieveCommand.fromString("GETSCRIPT").?);
    try T.expectEqual(ManageSieveCommand.DELETESCRIPT, ManageSieveCommand.fromString("DELETESCRIPT").?);
    try T.expectEqual(ManageSieveCommand.RENAMESCRIPT, ManageSieveCommand.fromString("RENAMESCRIPT").?);
    try T.expectEqual(ManageSieveCommand.CHECKSCRIPT, ManageSieveCommand.fromString("CHECKSCRIPT").?);
    try T.expectEqual(ManageSieveCommand.NOOP, ManageSieveCommand.fromString("NOOP").?);
    try T.expectEqual(ManageSieveCommand.LOGOUT, ManageSieveCommand.fromString("LOGOUT").?);
    try T.expectEqual(ManageSieveCommand.STARTTLS, ManageSieveCommand.fromString("STARTTLS").?);
}

test "command parsing - case insensitive" {
    const T = std.testing;
    try T.expectEqual(ManageSieveCommand.AUTHENTICATE, ManageSieveCommand.fromString("authenticate").?);
    try T.expectEqual(ManageSieveCommand.CAPABILITY, ManageSieveCommand.fromString("Capability").?);
    try T.expectEqual(ManageSieveCommand.STARTTLS, ManageSieveCommand.fromString("startTLS").?);
    try T.expectEqual(ManageSieveCommand.NOOP, ManageSieveCommand.fromString("nOoP").?);
}

test "command parsing - unknown returns null" {
    const T = std.testing;
    try T.expect(ManageSieveCommand.fromString("INVALID") == null);
    try T.expect(ManageSieveCommand.fromString("") == null);
    try T.expect(ManageSieveCommand.fromString("THIS_IS_WAY_TOO_LONG_CMD") == null);
}

test "command toString round-trips" {
    inline for (@typeInfo(ManageSieveCommand).@"enum".fields) |f| {
        const c: ManageSieveCommand = @enumFromInt(f.value);
        try std.testing.expectEqual(c, ManageSieveCommand.fromString(c.toString()).?);
    }
}

test "response formatting - OK" {
    const T = std.testing;
    const r1 = try ResponseFormatter.ok(T.allocator, null, null); defer T.allocator.free(r1);
    try T.expectEqualStrings("OK\r\n", r1);
    const r2 = try ResponseFormatter.ok(T.allocator, null, "Done"); defer T.allocator.free(r2);
    try T.expectEqualStrings("OK \"Done\"\r\n", r2);
    const r3 = try ResponseFormatter.ok(T.allocator, .SASL, "Auth ok"); defer T.allocator.free(r3);
    try T.expectEqualStrings("OK (SASL) \"Auth ok\"\r\n", r3);
}

test "response formatting - NO" {
    const T = std.testing;
    const r1 = try ResponseFormatter.no(T.allocator, .QUOTA_MAXSIZE, "Too large"); defer T.allocator.free(r1);
    try T.expectEqualStrings("NO (QUOTA/MAXSIZE) \"Too large\"\r\n", r1);
    const r2 = try ResponseFormatter.no(T.allocator, null, "Failed"); defer T.allocator.free(r2);
    try T.expectEqualStrings("NO \"Failed\"\r\n", r2);
}

test "response formatting - BYE" {
    const T = std.testing;
    const r1 = try ResponseFormatter.bye(T.allocator, .TRYLATER, "Shutting down"); defer T.allocator.free(r1);
    try T.expectEqualStrings("BYE (TRYLATER) \"Shutting down\"\r\n", r1);
    const r2 = try ResponseFormatter.bye(T.allocator, null, null); defer T.allocator.free(r2);
    try T.expectEqualStrings("BYE\r\n", r2);
}

test "response formatting - literal encoding" {
    const T = std.testing;
    const e = try ResponseFormatter.encodeLiteral(T.allocator, "require \"fileinto\";"); defer T.allocator.free(e);
    try T.expectEqualStrings("{19+}\r\nrequire \"fileinto\";", e);
    const e2 = try ResponseFormatter.encodeLiteral(T.allocator, ""); defer T.allocator.free(e2);
    try T.expectEqualStrings("{0+}\r\n", e2);
}

test "response formatting - quoted encoding" {
    const T = std.testing;
    const e = try ResponseFormatter.encodeQuoted(T.allocator, "my-script"); defer T.allocator.free(e);
    try T.expectEqualStrings("\"my-script\"", e);
    const e2 = try ResponseFormatter.encodeQuoted(T.allocator, "a\\b\"c"); defer T.allocator.free(e2);
    try T.expectEqualStrings("\"a\\\\b\\\"c\"", e2);
}

test "response formatting - CRLF endings" {
    const T = std.testing;
    inline for (.{ ResponseFormatter.ok, ResponseFormatter.no, ResponseFormatter.bye }) |func| {
        const r = try func(T.allocator, null, "x"); defer T.allocator.free(r);
        try T.expect(std.mem.endsWith(u8, r, "\r\n"));
    }
}

test "capability generation" {
    const T = std.testing;
    const cfg = ManageSieveConfig{ .implementation_name = "Test v1", .sieve_extensions = "fileinto", .enable_tls = true, .max_redirects = 3 };
    var cap = ManageSieveCapability.init(&cfg);
    const o = try cap.format(T.allocator); defer T.allocator.free(o);
    try T.expect(std.mem.indexOf(u8, o, "\"IMPLEMENTATION\" \"Test v1\"") != null);
    try T.expect(std.mem.indexOf(u8, o, "\"SASL\" \"PLAIN\"") != null);
    try T.expect(std.mem.indexOf(u8, o, "\"SIEVE\" \"fileinto\"") != null);
    try T.expect(std.mem.indexOf(u8, o, "\"STARTTLS\"") != null);
    try T.expect(std.mem.indexOf(u8, o, "\"MAXREDIRECTS\" \"3\"") != null);
    try T.expect(std.mem.indexOf(u8, o, "\"VERSION\" \"1.0\"") != null);
}

test "capability - TLS disabled hides STARTTLS" {
    const T = std.testing;
    const cfg = ManageSieveConfig{ .enable_tls = false };
    var cap = ManageSieveCapability.init(&cfg);
    const o = try cap.format(T.allocator); defer T.allocator.free(o);
    try T.expect(std.mem.indexOf(u8, o, "\"STARTTLS\"") == null);
}

test "capability - deterministic output" {
    const T = std.testing;
    const cfg = ManageSieveConfig{};
    var cap = ManageSieveCapability.init(&cfg);
    const a = try cap.format(T.allocator); defer T.allocator.free(a);
    const b = try cap.format(T.allocator); defer T.allocator.free(b);
    try T.expectEqualStrings(a, b);
}

test "SASL PLAIN - valid credentials" {
    const T = std.testing;
    var c = (try SaslPlainCredentials.decode(T.allocator, "AHRlc3R1c2VyAHRlc3RwYXNz")).?;
    defer c.deinit(T.allocator);
    try T.expectEqualStrings("", c.authzid);
    try T.expectEqualStrings("testuser", c.authcid);
    try T.expectEqualStrings("testpass", c.passwd);
}

test "SASL PLAIN - with authzid" {
    const T = std.testing;
    var c = (try SaslPlainCredentials.decode(T.allocator, "YWRtaW4AdGVzdHVzZXIAdGVzdHBhc3M=")).?;
    defer c.deinit(T.allocator);
    try T.expectEqualStrings("admin", c.authzid);
    try T.expectEqualStrings("testuser", c.authcid);
    try T.expectEqualStrings("testpass", c.passwd);
}

test "SASL PLAIN - rejects empty authcid" {
    try std.testing.expect((try SaslPlainCredentials.decode(std.testing.allocator, "AAB0ZXN0cGFzcw==")) == null);
}

test "SASL PLAIN - rejects empty passwd" {
    try std.testing.expect((try SaslPlainCredentials.decode(std.testing.allocator, "AHRlc3R1c2VyAA==")) == null);
}

test "SASL PLAIN - rejects invalid base64" {
    try std.testing.expect((try SaslPlainCredentials.decode(std.testing.allocator, "not-valid!!!")) == null);
}

test "SASL PLAIN - rejects missing NUL" {
    try std.testing.expect((try SaslPlainCredentials.decode(std.testing.allocator, "bm90aGluZ2hlcmU=")) == null);
}

test "literal parsing - non-sync" {
    const r = LiteralParser.parse("{25+}\r\nrequire [\"fileinto\"];\r\n").?;
    try std.testing.expectEqual(@as(usize, 25), r.length);
    try std.testing.expect(r.non_sync);
    try std.testing.expectEqual(@as(usize, 7), r.prefix_len);
}

test "literal parsing - sync" {
    const r = LiteralParser.parse("{100}\r\ncontent...").?;
    try std.testing.expectEqual(@as(usize, 100), r.length);
    try std.testing.expect(!r.non_sync);
}

test "literal parsing - zero length" {
    const r = LiteralParser.parse("{0+}\r\n").?;
    try std.testing.expectEqual(@as(usize, 0), r.length);
}

test "literal parsing - invalid inputs" {
    try std.testing.expect(LiteralParser.parse("\"q\"") == null);
    try std.testing.expect(LiteralParser.parse("") == null);
    try std.testing.expect(LiteralParser.parse("{abc}") == null);
    try std.testing.expect(LiteralParser.parse("{10}\n") == null);
}

test "literal round-trip" {
    const T = std.testing;
    const orig = "require \"fileinto\";\nif true { keep; }";
    const enc = try ResponseFormatter.encodeLiteral(T.allocator, orig); defer T.allocator.free(enc);
    const p = LiteralParser.parse(enc).?;
    try T.expectEqual(orig.len, p.length);
    try T.expectEqualStrings(orig, enc[p.prefix_len .. p.prefix_len + p.length]);
}

test "script size validation" {
    const max: usize = 1024 * 1024;
    try std.testing.expect(checkScriptSize(0, max));
    try std.testing.expect(checkScriptSize(max, max));
    try std.testing.expect(!checkScriptSize(max + 1, max));
}

test "sieve validation - valid" {
    try std.testing.expect(validateSieveScript("require \"fileinto\";"));
    try std.testing.expect(validateSieveScript("if true { keep; } else { discard; }"));
}

test "sieve validation - invalid" {
    try std.testing.expect(!validateSieveScript(""));
    try std.testing.expect(!validateSieveScript("if true { {"));
    try std.testing.expect(!validateSieveScript("}}"));
}

test "extractQuotedString - basic" {
    const r = extractQuotedString("\"my-script\"").?;
    try std.testing.expectEqualStrings("my-script", r.value);
    try std.testing.expectEqual(@as(usize, 11), r.end);
}

test "extractQuotedString - empty" {
    try std.testing.expectEqualStrings("", extractQuotedString("\"\"").?.value);
}

test "extractQuotedString - invalid" {
    try std.testing.expect(extractQuotedString("no-quotes") == null);
    try std.testing.expect(extractQuotedString("") == null);
    try std.testing.expect(extractQuotedString("\"unterminated") == null);
}

test "ResponseCode.toString" {
    const T = std.testing;
    try T.expectEqualStrings("AUTH-TOO-WEAK", ResponseCode.AUTH_TOO_WEAK.toString());
    try T.expectEqualStrings("QUOTA/MAXSCRIPTS", ResponseCode.QUOTA_MAXSCRIPTS.toString());
    try T.expectEqualStrings("NONEXISTENT", ResponseCode.NONEXISTENT.toString());
    try T.expectEqualStrings("ALREADYEXISTS", ResponseCode.ALREADYEXISTS.toString());
    try T.expectEqualStrings("TRYLATER", ResponseCode.TRYLATER.toString());
}

test "config defaults" {
    const c = ManageSieveConfig{};
    try std.testing.expectEqual(@as(u16, 4190), c.port);
    try std.testing.expectEqual(@as(usize, 100), c.max_connections);
    try std.testing.expect(c.enable_tls);
    try std.testing.expect(c.cert_path == null);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), c.max_script_size);
}

test "SieveScript lifecycle" {
    const T = std.testing;
    const nm = try T.allocator.dupe(u8, "test"); const ct = try T.allocator.dupe(u8, "keep;");
    var s = SieveScript{ .name = nm, .content = ct, .active = false, .size = ct.len, .created_at = 0, .modified_at = 0 };
    try T.expectEqualStrings("test", s.name);
    try T.expectEqual(@as(usize, 5), s.size);
    s.deinit(T.allocator);
}
