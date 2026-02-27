const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

// =============================================================================
// Email Autoconfiguration Server
// =============================================================================
//
// ## Overview
// Implements email client autoconfiguration for automatic mail account setup.
// Supports three major protocols:
//
// - **Thunderbird/Mozilla Autoconfig** (config-v1.1.xml)
//   Served at: /.well-known/autoconfig/mail/config-v1.1.xml
//   Also at:   /mail/config-v1.1.xml
//
// - **Outlook/Microsoft Autodiscover** (autodiscover.xml)
//   Served at: /autodiscover/autodiscover.xml
//   Also at:   /Autodiscover/Autodiscover.xml
//
// - **Apple Mobileconfig** (profile.mobileconfig)
//   Served at: /email.mobileconfig
//   Also at:   /.well-known/autoconfig/email.mobileconfig
//
// ## References
// - Mozilla: https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
// - Microsoft: https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/autodiscover-web-service-reference-for-exchange
// - Apple: https://developer.apple.com/business/documentation/Configuration-Profile-Reference.pdf
//
// =============================================================================

/// Configuration for the autoconfiguration server.
/// Defines the mail server parameters that will be advertised to clients.
pub const AutoconfigConfig = struct {
    /// Mail server hostname (e.g., "mail.example.com")
    hostname: []const u8 = "localhost",

    /// Primary domain served by this mail server
    domain: []const u8 = "localhost",

    /// IMAP port (STARTTLS)
    imap_port: u16 = 143,

    /// IMAPS port (implicit TLS)
    imaps_port: u16 = 993,

    /// SMTP submission port (STARTTLS)
    smtp_port: u16 = 587,

    /// POP3S port (implicit TLS)
    pop3_port: u16 = 995,

    /// Whether IMAP is enabled
    enable_imap: bool = true,

    /// Whether POP3 is enabled
    enable_pop3: bool = false,

    /// Display name shown to users in client setup (e.g., "Example Mail")
    display_name: []const u8 = "Mail Server",

    /// Short display name (e.g., "Example")
    display_short_name: []const u8 = "Mail",

    /// Whether CardDAV (contacts) is enabled in Apple mobileconfig
    enable_carddav: bool = true,

    /// Whether CalDAV (calendar) is enabled in Apple mobileconfig
    enable_caldav_profile: bool = true,

    /// CardDAV/CalDAV server hostname (defaults to main hostname)
    caldav_hostname: ?[]const u8 = null,

    /// CardDAV/CalDAV server port
    caldav_port: u16 = 443,
};

/// HTTP response with status, content type, and body.
pub const HttpResponse = struct {
    status_code: u16,
    content_type: []const u8,
    body: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *HttpResponse) void {
        self.allocator.free(self.body);
    }

    /// Format the response as a raw HTTP response string.
    pub fn toHttp(self: *const HttpResponse, allocator: std.mem.Allocator) ![]u8 {
        const status_text = switch (self.status_code) {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            else => "Unknown",
        };

        return try std.fmt.allocPrint(
            allocator,
            "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nCache-Control: no-cache, no-store\r\nConnection: close\r\n\r\n{s}",
            .{ self.status_code, status_text, self.content_type, self.body.len, self.body },
        );
    }
};

/// Email autoconfiguration server.
/// Handles requests from Thunderbird, Outlook, and Apple Mail clients to
/// automatically configure mail accounts.
pub const AutoconfigServer = struct {
    allocator: std.mem.Allocator,
    config: AutoconfigConfig,

    /// Initialize a new autoconfiguration server.
    pub fn init(allocator: std.mem.Allocator, config: AutoconfigConfig) AutoconfigServer {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Deinitialize the server and release resources.
    pub fn deinit(self: *AutoconfigServer) void {
        // Currently no owned resources to free; the config fields are
        // borrowed slices. This is provided for API symmetry and future
        // extensibility (e.g., cached responses, TLS contexts).
        _ = self;
    }

    // =========================================================================
    // Request Handlers
    // =========================================================================

    /// Handle a Thunderbird/Mozilla autoconfig request.
    /// The `domain` parameter is the mail domain the client is configuring
    /// (extracted from the request URL or query string).
    ///
    /// Returns an HttpResponse with Content-Type: application/xml containing
    /// the config-v1.1.xml format.
    pub fn handleThunderbirdRequest(self: *AutoconfigServer, domain: []const u8) !HttpResponse {
        const effective_domain = if (domain.len > 0) domain else self.config.domain;
        const xml = try generateThunderbirdXML(self.allocator, self.config, effective_domain);

        return HttpResponse{
            .status_code = 200,
            .content_type = "application/xml; charset=utf-8",
            .body = xml,
            .allocator = self.allocator,
        };
    }

    /// Handle an Outlook/Microsoft autodiscover request.
    /// The `email` parameter is the email address being configured.
    /// The `request_body` is the raw XML POST body from the Outlook client,
    /// from which the email address can alternatively be extracted.
    ///
    /// Returns an HttpResponse with Content-Type: application/xml containing
    /// the Autodiscover response XML.
    pub fn handleOutlookRequest(self: *AutoconfigServer, email: []const u8, request_body: ?[]const u8) !HttpResponse {
        // Try to extract email from the request body if not provided directly
        var effective_email = email;
        if (effective_email.len == 0) {
            if (request_body) |body| {
                effective_email = extractEmailFromAutodiscover(body) orelse self.config.domain;
            }
        }

        const xml = try generateOutlookXML(self.allocator, self.config, effective_email);

        return HttpResponse{
            .status_code = 200,
            .content_type = "application/xml; charset=utf-8",
            .body = xml,
            .allocator = self.allocator,
        };
    }

    /// Handle an Apple mobileconfig request.
    /// The `email` parameter is the email address being configured.
    ///
    /// Returns an HttpResponse with Content-Type: application/x-apple-aspen-config
    /// containing an unsigned mobileconfig profile plist XML.
    pub fn handleAppleRequest(self: *AutoconfigServer, email: []const u8) !HttpResponse {
        const xml = try generateAppleMobileconfig(self.allocator, self.config, email);

        return HttpResponse{
            .status_code = 200,
            .content_type = "application/x-apple-aspen-config; charset=utf-8",
            .body = xml,
            .allocator = self.allocator,
        };
    }

    // =========================================================================
    // Route Dispatcher
    // =========================================================================

    /// Route an incoming HTTP request to the appropriate handler.
    /// Parses the method and path to determine which autoconfig protocol
    /// is being requested and dispatches accordingly.
    ///
    /// Supported routes:
    ///   GET  /.well-known/autoconfig/mail/config-v1.1.xml  (Thunderbird)
    ///   GET  /mail/config-v1.1.xml                          (Thunderbird)
    ///   POST /autodiscover/autodiscover.xml                 (Outlook)
    ///   POST /Autodiscover/Autodiscover.xml                 (Outlook)
    ///   GET  /email.mobileconfig?email=user@domain          (Apple)
    ///   GET  /.well-known/autoconfig/email.mobileconfig     (Apple)
    pub fn routeRequest(
        self: *AutoconfigServer,
        method: []const u8,
        path: []const u8,
        query: ?[]const u8,
        body: ?[]const u8,
    ) !HttpResponse {
        // Thunderbird autoconfig routes (GET only)
        if (std.mem.eql(u8, method, "GET")) {
            if (std.mem.eql(u8, path, "/.well-known/autoconfig/mail/config-v1.1.xml") or
                std.mem.eql(u8, path, "/mail/config-v1.1.xml"))
            {
                const domain = extractQueryParam(query, "domain") orelse self.config.domain;
                return self.handleThunderbirdRequest(domain);
            }

            // Apple mobileconfig routes (GET)
            if (std.mem.eql(u8, path, "/email.mobileconfig") or
                std.mem.eql(u8, path, "/.well-known/autoconfig/email.mobileconfig"))
            {
                const email = extractQueryParam(query, "email") orelse "";
                return self.handleAppleRequest(email);
            }
        }

        // Outlook autodiscover routes (POST only)
        if (std.mem.eql(u8, method, "POST")) {
            if (std.ascii.eqlIgnoreCase(path, "/autodiscover/autodiscover.xml")) {
                const email = extractQueryParam(query, "email") orelse "";
                return self.handleOutlookRequest(email, body);
            }
        }

        // Method not allowed for known paths
        if (std.ascii.eqlIgnoreCase(path, "/autodiscover/autodiscover.xml")) {
            return HttpResponse{
                .status_code = 405,
                .content_type = "text/plain",
                .body = try self.allocator.dupe(u8, "Method Not Allowed. Use POST for autodiscover."),
                .allocator = self.allocator,
            };
        }

        return HttpResponse{
            .status_code = 404,
            .content_type = "text/plain",
            .body = try self.allocator.dupe(u8, "Not Found"),
            .allocator = self.allocator,
        };
    }
};

// =============================================================================
// XML Generation Functions
// =============================================================================

/// Generate Thunderbird/Mozilla autoconfig XML (config-v1.1.xml format).
///
/// Produces XML conforming to the Mozilla autoconfig schema that Thunderbird
/// and other compatible clients use for automatic account setup.
///
/// The generated XML includes:
/// - Email provider identification (domain-based)
/// - Incoming server configuration (IMAP and/or POP3)
/// - Outgoing server configuration (SMTP)
/// - Authentication and socket type details
pub fn generateThunderbirdXML(
    allocator: std.mem.Allocator,
    config: AutoconfigConfig,
    domain: []const u8,
) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    // XML declaration and root element
    try buf.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    try buf.appendSlice(allocator, "<clientConfig version=\"1.1\">\n");

    // Email provider section
    try buf.print(allocator, "  <emailProvider id=\"{s}\">\n", .{domain});
    try buf.print(allocator, "    <domain>{s}</domain>\n", .{domain});
    try buf.print(allocator, "    <displayName>{s}</displayName>\n", .{config.display_name});
    try buf.print(allocator, "    <displayShortName>{s}</displayShortName>\n", .{config.display_short_name});

    // IMAP incoming server (if enabled)
    if (config.enable_imap) {
        // Primary: IMAPS (implicit TLS on port 993)
        try buf.appendSlice(allocator, "    <incomingServer type=\"imap\">\n");
        try buf.print(allocator, "      <hostname>{s}</hostname>\n", .{config.hostname});
        try buf.print(allocator, "      <port>{d}</port>\n", .{config.imaps_port});
        try buf.appendSlice(allocator, "      <socketType>SSL</socketType>\n");
        try buf.appendSlice(allocator, "      <authentication>password-cleartext</authentication>\n");
        try buf.appendSlice(allocator, "      <username>%EMAILADDRESS%</username>\n");
        try buf.appendSlice(allocator, "    </incomingServer>\n");

        // Secondary: IMAP with STARTTLS (port 143)
        try buf.appendSlice(allocator, "    <incomingServer type=\"imap\">\n");
        try buf.print(allocator, "      <hostname>{s}</hostname>\n", .{config.hostname});
        try buf.print(allocator, "      <port>{d}</port>\n", .{config.imap_port});
        try buf.appendSlice(allocator, "      <socketType>STARTTLS</socketType>\n");
        try buf.appendSlice(allocator, "      <authentication>password-cleartext</authentication>\n");
        try buf.appendSlice(allocator, "      <username>%EMAILADDRESS%</username>\n");
        try buf.appendSlice(allocator, "    </incomingServer>\n");
    }

    // POP3 incoming server (if enabled)
    if (config.enable_pop3) {
        try buf.appendSlice(allocator, "    <incomingServer type=\"pop3\">\n");
        try buf.print(allocator, "      <hostname>{s}</hostname>\n", .{config.hostname});
        try buf.print(allocator, "      <port>{d}</port>\n", .{config.pop3_port});
        try buf.appendSlice(allocator, "      <socketType>SSL</socketType>\n");
        try buf.appendSlice(allocator, "      <authentication>password-cleartext</authentication>\n");
        try buf.appendSlice(allocator, "      <username>%EMAILADDRESS%</username>\n");
        try buf.appendSlice(allocator, "    </incomingServer>\n");
    }

    // SMTP outgoing server
    try buf.appendSlice(allocator, "    <outgoingServer type=\"smtp\">\n");
    try buf.print(allocator, "      <hostname>{s}</hostname>\n", .{config.hostname});
    try buf.print(allocator, "      <port>{d}</port>\n", .{config.smtp_port});
    try buf.appendSlice(allocator, "      <socketType>STARTTLS</socketType>\n");
    try buf.appendSlice(allocator, "      <authentication>password-cleartext</authentication>\n");
    try buf.appendSlice(allocator, "      <username>%EMAILADDRESS%</username>\n");
    try buf.appendSlice(allocator, "    </outgoingServer>\n");

    // Documentation URL
    try buf.print(allocator, "    <documentation url=\"https://{s}/help/email-setup\">\n", .{domain});
    try buf.print(allocator, "      <descr lang=\"en\">Email setup instructions for {s}</descr>\n", .{config.display_name});
    try buf.appendSlice(allocator, "    </documentation>\n");

    try buf.appendSlice(allocator, "  </emailProvider>\n");

    // CardDAV addressbook (Thunderbird supports this since v102+)
    if (config.enable_carddav) {
        const carddav_host = config.caldav_hostname orelse config.hostname;
        try buf.appendSlice(allocator, "  <addressBook type=\"carddav\">\n");
        try buf.print(allocator, "    <hostname>{s}</hostname>\n", .{carddav_host});
        try buf.print(allocator, "    <port>{d}</port>\n", .{config.caldav_port});
        try buf.appendSlice(allocator, "    <socketType>SSL</socketType>\n");
        try buf.appendSlice(allocator, "    <authentication>password-cleartext</authentication>\n");
        try buf.appendSlice(allocator, "    <username>%EMAILADDRESS%</username>\n");
        try buf.print(allocator, "    <url>https://{s}:{d}/addressbooks/%EMAILADDRESS%/</url>\n", .{ carddav_host, config.caldav_port });
        try buf.appendSlice(allocator, "  </addressBook>\n");
    }

    try buf.appendSlice(allocator, "</clientConfig>\n");

    return buf.toOwnedSlice(allocator);
}

/// Generate Outlook/Microsoft autodiscover XML response.
///
/// Produces XML conforming to the Microsoft Autodiscover protocol that
/// Outlook and other Microsoft clients use for account configuration.
///
/// The generated XML includes:
/// - Account type (email)
/// - IMAP and SMTP protocol configurations
/// - Server hostnames, ports, and encryption settings
/// - Login name (full email address)
pub fn generateOutlookXML(
    allocator: std.mem.Allocator,
    config: AutoconfigConfig,
    email: []const u8,
) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    // XML declaration and Autodiscover envelope
    try buf.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    try buf.appendSlice(allocator, "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">\n");
    try buf.appendSlice(allocator, "  <Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">\n");
    try buf.appendSlice(allocator, "    <Account>\n");
    try buf.appendSlice(allocator, "      <AccountType>email</AccountType>\n");
    try buf.appendSlice(allocator, "      <Action>settings</Action>\n");

    // IMAP protocol (if enabled)
    if (config.enable_imap) {
        try buf.appendSlice(allocator, "      <Protocol>\n");
        try buf.appendSlice(allocator, "        <Type>IMAP</Type>\n");
        try buf.print(allocator, "        <Server>{s}</Server>\n", .{config.hostname});
        try buf.print(allocator, "        <Port>{d}</Port>\n", .{config.imaps_port});
        try buf.print(allocator, "        <LoginName>{s}</LoginName>\n", .{email});
        try buf.appendSlice(allocator, "        <DomainRequired>off</DomainRequired>\n");
        try buf.appendSlice(allocator, "        <SPA>off</SPA>\n");
        try buf.appendSlice(allocator, "        <SSL>on</SSL>\n");
        try buf.appendSlice(allocator, "        <AuthRequired>on</AuthRequired>\n");
        try buf.appendSlice(allocator, "      </Protocol>\n");
    }

    // POP3 protocol (if enabled)
    if (config.enable_pop3) {
        try buf.appendSlice(allocator, "      <Protocol>\n");
        try buf.appendSlice(allocator, "        <Type>POP3</Type>\n");
        try buf.print(allocator, "        <Server>{s}</Server>\n", .{config.hostname});
        try buf.print(allocator, "        <Port>{d}</Port>\n", .{config.pop3_port});
        try buf.print(allocator, "        <LoginName>{s}</LoginName>\n", .{email});
        try buf.appendSlice(allocator, "        <DomainRequired>off</DomainRequired>\n");
        try buf.appendSlice(allocator, "        <SPA>off</SPA>\n");
        try buf.appendSlice(allocator, "        <SSL>on</SSL>\n");
        try buf.appendSlice(allocator, "        <AuthRequired>on</AuthRequired>\n");
        try buf.appendSlice(allocator, "      </Protocol>\n");
    }

    // SMTP protocol
    try buf.appendSlice(allocator, "      <Protocol>\n");
    try buf.appendSlice(allocator, "        <Type>SMTP</Type>\n");
    try buf.print(allocator, "        <Server>{s}</Server>\n", .{config.hostname});
    try buf.print(allocator, "        <Port>{d}</Port>\n", .{config.smtp_port});
    try buf.print(allocator, "        <LoginName>{s}</LoginName>\n", .{email});
    try buf.appendSlice(allocator, "        <DomainRequired>off</DomainRequired>\n");
    try buf.appendSlice(allocator, "        <SPA>off</SPA>\n");
    try buf.appendSlice(allocator, "        <Encryption>TLS</Encryption>\n");
    try buf.appendSlice(allocator, "        <AuthRequired>on</AuthRequired>\n");
    try buf.appendSlice(allocator, "        <SMTPLast>off</SMTPLast>\n");
    try buf.appendSlice(allocator, "      </Protocol>\n");

    try buf.appendSlice(allocator, "    </Account>\n");
    try buf.appendSlice(allocator, "  </Response>\n");
    try buf.appendSlice(allocator, "</Autodiscover>\n");

    return buf.toOwnedSlice(allocator);
}

/// Generate Apple mobileconfig profile XML (unsigned).
///
/// Produces a Configuration Profile plist XML that Apple Mail on macOS and
/// iOS can use to automatically configure mail accounts. The profile is
/// unsigned, which means the user will see a warning during installation.
///
/// The generated profile includes:
/// - Profile identification (UUID, display name, description)
/// - IMAP incoming mail account configuration
/// - SMTP outgoing mail account configuration
/// - Authentication and SSL settings
pub fn generateAppleMobileconfig(
    allocator: std.mem.Allocator,
    config: AutoconfigConfig,
    email: []const u8,
) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    // Extract username and domain from the email address
    const username = extractLocalPart(email) orelse email;
    const email_domain = extractDomainFromEmail(email) orelse config.domain;

    // Generate deterministic UUIDs from the email and domain.
    // These are not cryptographically random but are stable for the same input,
    // which helps clients recognize previously installed profiles.
    const profile_uuid = try generateDeterministicUUID(allocator, config.domain, "profile");
    defer allocator.free(profile_uuid);

    const imap_uuid = try generateDeterministicUUID(allocator, email, "imap");
    defer allocator.free(imap_uuid);

    const smtp_uuid = try generateDeterministicUUID(allocator, email, "smtp");
    defer allocator.free(smtp_uuid);

    // Plist XML header
    try buf.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    try buf.appendSlice(allocator, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    try buf.appendSlice(allocator, "<plist version=\"1.0\">\n");
    try buf.appendSlice(allocator, "<dict>\n");

    // Profile metadata
    try buf.appendSlice(allocator, "  <key>PayloadContent</key>\n");
    try buf.appendSlice(allocator, "  <array>\n");

    // Email account payload
    try buf.appendSlice(allocator, "    <dict>\n");

    // Incoming mail server (IMAP)
    try buf.appendSlice(allocator, "      <key>EmailAccountDescription</key>\n");
    try buf.print(allocator, "      <string>{s}</string>\n", .{config.display_name});
    try buf.appendSlice(allocator, "      <key>EmailAccountName</key>\n");
    try buf.print(allocator, "      <string>{s}</string>\n", .{username});
    try buf.appendSlice(allocator, "      <key>EmailAccountType</key>\n");
    try buf.appendSlice(allocator, "      <string>EmailTypeIMAP</string>\n");
    try buf.appendSlice(allocator, "      <key>EmailAddress</key>\n");
    try buf.print(allocator, "      <string>{s}</string>\n", .{email});

    // Incoming server settings
    try buf.appendSlice(allocator, "      <key>IncomingMailServerAuthentication</key>\n");
    try buf.appendSlice(allocator, "      <string>EmailAuthPassword</string>\n");
    try buf.appendSlice(allocator, "      <key>IncomingMailServerHostName</key>\n");
    try buf.print(allocator, "      <string>{s}</string>\n", .{config.hostname});
    try buf.appendSlice(allocator, "      <key>IncomingMailServerPortNumber</key>\n");
    try buf.print(allocator, "      <integer>{d}</integer>\n", .{config.imaps_port});
    try buf.appendSlice(allocator, "      <key>IncomingMailServerUseSSL</key>\n");
    try buf.appendSlice(allocator, "      <true/>\n");
    try buf.appendSlice(allocator, "      <key>IncomingMailServerUsername</key>\n");
    try buf.print(allocator, "      <string>{s}</string>\n", .{email});
    try buf.appendSlice(allocator, "      <key>IncomingPassword</key>\n");
    try buf.appendSlice(allocator, "      <string></string>\n");

    // Outgoing server settings
    try buf.appendSlice(allocator, "      <key>OutgoingMailServerAuthentication</key>\n");
    try buf.appendSlice(allocator, "      <string>EmailAuthPassword</string>\n");
    try buf.appendSlice(allocator, "      <key>OutgoingMailServerHostName</key>\n");
    try buf.print(allocator, "      <string>{s}</string>\n", .{config.hostname});
    try buf.appendSlice(allocator, "      <key>OutgoingMailServerPortNumber</key>\n");
    try buf.print(allocator, "      <integer>{d}</integer>\n", .{config.smtp_port});
    try buf.appendSlice(allocator, "      <key>OutgoingMailServerUseSSL</key>\n");
    try buf.appendSlice(allocator, "      <true/>\n");
    try buf.appendSlice(allocator, "      <key>OutgoingMailServerUsername</key>\n");
    try buf.print(allocator, "      <string>{s}</string>\n", .{email});
    try buf.appendSlice(allocator, "      <key>OutgoingPassword</key>\n");
    try buf.appendSlice(allocator, "      <string></string>\n");
    try buf.appendSlice(allocator, "      <key>OutgoingPasswordSameAsIncomingPassword</key>\n");
    try buf.appendSlice(allocator, "      <true/>\n");

    // Payload identification for the email account
    try buf.appendSlice(allocator, "      <key>PayloadDescription</key>\n");
    try buf.print(allocator, "      <string>Email account configuration for {s}</string>\n", .{email_domain});
    try buf.appendSlice(allocator, "      <key>PayloadDisplayName</key>\n");
    try buf.print(allocator, "      <string>{s} Email</string>\n", .{config.display_name});
    try buf.appendSlice(allocator, "      <key>PayloadIdentifier</key>\n");
    try buf.print(allocator, "      <string>com.{s}.email.account</string>\n", .{email_domain});
    try buf.appendSlice(allocator, "      <key>PayloadType</key>\n");
    try buf.appendSlice(allocator, "      <string>com.apple.mail.managed</string>\n");
    try buf.appendSlice(allocator, "      <key>PayloadUUID</key>\n");
    try buf.print(allocator, "      <string>{s}</string>\n", .{imap_uuid});
    try buf.appendSlice(allocator, "      <key>PayloadVersion</key>\n");
    try buf.appendSlice(allocator, "      <integer>1</integer>\n");
    try buf.appendSlice(allocator, "      <key>PreventAppSheet</key>\n");
    try buf.appendSlice(allocator, "      <false/>\n");
    try buf.appendSlice(allocator, "      <key>PreventMove</key>\n");
    try buf.appendSlice(allocator, "      <false/>\n");
    try buf.appendSlice(allocator, "      <key>SMIMEEnabled</key>\n");
    try buf.appendSlice(allocator, "      <false/>\n");

    try buf.appendSlice(allocator, "    </dict>\n");

    // CardDAV (Contacts) payload
    if (config.enable_carddav) {
        const carddav_uuid = try generateDeterministicUUID(allocator, email, "carddav");
        defer allocator.free(carddav_uuid);
        const carddav_host = config.caldav_hostname orelse config.hostname;

        try buf.appendSlice(allocator, "    <dict>\n");
        try buf.appendSlice(allocator, "      <key>CardDAVAccountDescription</key>\n");
        try buf.print(allocator, "      <string>{s} Contacts</string>\n", .{config.display_name});
        try buf.appendSlice(allocator, "      <key>CardDAVHostName</key>\n");
        try buf.print(allocator, "      <string>{s}</string>\n", .{carddav_host});
        try buf.appendSlice(allocator, "      <key>CardDAVPort</key>\n");
        try buf.print(allocator, "      <integer>{d}</integer>\n", .{config.caldav_port});
        try buf.appendSlice(allocator, "      <key>CardDAVPrincipalURL</key>\n");
        try buf.print(allocator, "      <string>/principals/{s}</string>\n", .{email});
        try buf.appendSlice(allocator, "      <key>CardDAVUseSSL</key>\n");
        try buf.appendSlice(allocator, "      <true/>\n");
        try buf.appendSlice(allocator, "      <key>CardDAVUsername</key>\n");
        try buf.print(allocator, "      <string>{s}</string>\n", .{email});
        try buf.appendSlice(allocator, "      <key>PayloadDescription</key>\n");
        try buf.print(allocator, "      <string>CardDAV contacts for {s}</string>\n", .{email_domain});
        try buf.appendSlice(allocator, "      <key>PayloadDisplayName</key>\n");
        try buf.print(allocator, "      <string>{s} Contacts</string>\n", .{config.display_name});
        try buf.appendSlice(allocator, "      <key>PayloadIdentifier</key>\n");
        try buf.print(allocator, "      <string>com.{s}.carddav.account</string>\n", .{email_domain});
        try buf.appendSlice(allocator, "      <key>PayloadType</key>\n");
        try buf.appendSlice(allocator, "      <string>com.apple.carddav.account</string>\n");
        try buf.appendSlice(allocator, "      <key>PayloadUUID</key>\n");
        try buf.print(allocator, "      <string>{s}</string>\n", .{carddav_uuid});
        try buf.appendSlice(allocator, "      <key>PayloadVersion</key>\n");
        try buf.appendSlice(allocator, "      <integer>1</integer>\n");
        try buf.appendSlice(allocator, "    </dict>\n");
    }

    // CalDAV (Calendar) payload
    if (config.enable_caldav_profile) {
        const caldav_uuid = try generateDeterministicUUID(allocator, email, "caldav");
        defer allocator.free(caldav_uuid);
        const caldav_host = config.caldav_hostname orelse config.hostname;

        try buf.appendSlice(allocator, "    <dict>\n");
        try buf.appendSlice(allocator, "      <key>CalDAVAccountDescription</key>\n");
        try buf.print(allocator, "      <string>{s} Calendar</string>\n", .{config.display_name});
        try buf.appendSlice(allocator, "      <key>CalDAVHostName</key>\n");
        try buf.print(allocator, "      <string>{s}</string>\n", .{caldav_host});
        try buf.appendSlice(allocator, "      <key>CalDAVPort</key>\n");
        try buf.print(allocator, "      <integer>{d}</integer>\n", .{config.caldav_port});
        try buf.appendSlice(allocator, "      <key>CalDAVPrincipalURL</key>\n");
        try buf.print(allocator, "      <string>/principals/{s}</string>\n", .{email});
        try buf.appendSlice(allocator, "      <key>CalDAVUseSSL</key>\n");
        try buf.appendSlice(allocator, "      <true/>\n");
        try buf.appendSlice(allocator, "      <key>CalDAVUsername</key>\n");
        try buf.print(allocator, "      <string>{s}</string>\n", .{email});
        try buf.appendSlice(allocator, "      <key>PayloadDescription</key>\n");
        try buf.print(allocator, "      <string>CalDAV calendar for {s}</string>\n", .{email_domain});
        try buf.appendSlice(allocator, "      <key>PayloadDisplayName</key>\n");
        try buf.print(allocator, "      <string>{s} Calendar</string>\n", .{config.display_name});
        try buf.appendSlice(allocator, "      <key>PayloadIdentifier</key>\n");
        try buf.print(allocator, "      <string>com.{s}.caldav.account</string>\n", .{email_domain});
        try buf.appendSlice(allocator, "      <key>PayloadType</key>\n");
        try buf.appendSlice(allocator, "      <string>com.apple.caldav.account</string>\n");
        try buf.appendSlice(allocator, "      <key>PayloadUUID</key>\n");
        try buf.print(allocator, "      <string>{s}</string>\n", .{caldav_uuid});
        try buf.appendSlice(allocator, "      <key>PayloadVersion</key>\n");
        try buf.appendSlice(allocator, "      <integer>1</integer>\n");
        try buf.appendSlice(allocator, "    </dict>\n");
    }

    try buf.appendSlice(allocator, "  </array>\n");

    // Profile-level metadata
    try buf.appendSlice(allocator, "  <key>PayloadDescription</key>\n");
    try buf.print(allocator, "  <string>Configures email account for {s}</string>\n", .{email_domain});
    try buf.appendSlice(allocator, "  <key>PayloadDisplayName</key>\n");
    try buf.print(allocator, "  <string>{s} Mail</string>\n", .{config.display_name});
    try buf.appendSlice(allocator, "  <key>PayloadIdentifier</key>\n");
    try buf.print(allocator, "  <string>com.{s}.email.profile</string>\n", .{email_domain});
    try buf.appendSlice(allocator, "  <key>PayloadOrganization</key>\n");
    try buf.print(allocator, "  <string>{s}</string>\n", .{config.display_name});
    try buf.appendSlice(allocator, "  <key>PayloadRemovalDisallowed</key>\n");
    try buf.appendSlice(allocator, "  <false/>\n");
    try buf.appendSlice(allocator, "  <key>PayloadType</key>\n");
    try buf.appendSlice(allocator, "  <string>Configuration</string>\n");
    try buf.appendSlice(allocator, "  <key>PayloadUUID</key>\n");
    try buf.print(allocator, "  <string>{s}</string>\n", .{profile_uuid});
    try buf.appendSlice(allocator, "  <key>PayloadVersion</key>\n");
    try buf.appendSlice(allocator, "  <integer>1</integer>\n");

    // SMTP payload UUID reference (for multi-payload tracking)
    try buf.print(allocator, "  <!-- SMTP Payload UUID: {s} -->\n", .{smtp_uuid});

    try buf.appendSlice(allocator, "</dict>\n");
    try buf.appendSlice(allocator, "</plist>\n");

    return buf.toOwnedSlice(allocator);
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Extract the domain part from an email address.
/// Returns null if the email does not contain an '@' character.
///
/// Example: "user@example.com" -> "example.com"
pub fn extractDomainFromEmail(email: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, email, "@")) |at_pos| {
        const domain = email[at_pos + 1 ..];
        if (domain.len > 0) return domain;
    }
    return null;
}

/// Extract the local part (username) from an email address.
/// Returns null if the email does not contain an '@' character.
///
/// Example: "user@example.com" -> "user"
pub fn extractLocalPart(email: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, email, "@")) |at_pos| {
        const local = email[0..at_pos];
        if (local.len > 0) return local;
    }
    return null;
}

/// Extract a query parameter value from a URL query string.
/// Performs a simple linear scan; does not handle URL-encoded values.
///
/// Example: extractQueryParam("email=user@ex.com&foo=bar", "email") -> "user@ex.com"
pub fn extractQueryParam(query: ?[]const u8, param_name: []const u8) ?[]const u8 {
    const q = query orelse return null;
    if (q.len == 0) return null;

    // Build the search prefix: "param_name="
    var iter = std.mem.splitScalar(u8, q, '&');
    while (iter.next()) |part| {
        if (std.mem.indexOf(u8, part, "=")) |eq_pos| {
            const key = part[0..eq_pos];
            if (std.mem.eql(u8, key, param_name)) {
                const value = part[eq_pos + 1 ..];
                if (value.len > 0) return value;
            }
        }
    }
    return null;
}

/// Extract an email address from an Outlook Autodiscover XML request body.
/// Looks for the <EMailAddress> element in the XML.
///
/// This is a lightweight parser that does not validate the full XML structure;
/// it simply searches for the element content.
pub fn extractEmailFromAutodiscover(body: []const u8) ?[]const u8 {
    const open_tag = "<EMailAddress>";
    const close_tag = "</EMailAddress>";

    const start_pos = (std.mem.indexOf(u8, body, open_tag) orelse return null) + open_tag.len;
    const end_pos = std.mem.indexOf(u8, body[start_pos..], close_tag) orelse return null;

    const email = body[start_pos .. start_pos + end_pos];
    if (email.len == 0) return null;

    // Basic sanity check: must contain '@'
    if (std.mem.indexOf(u8, email, "@") == null) return null;

    return email;
}

/// Generate a deterministic UUID-like string from a seed and a salt.
///
/// This is NOT a cryptographic UUID but a stable identifier derived from the
/// input strings via FNV-1a hashing. It produces a string in the standard
/// UUID format (8-4-4-4-12 hex digits) for compatibility with Apple's
/// mobileconfig format, which requires PayloadUUID fields.
fn generateDeterministicUUID(allocator: std.mem.Allocator, seed: []const u8, salt: []const u8) ![]u8 {
    // FNV-1a hash of concatenated seed and salt
    var hash: u128 = 14695981039346656037;
    const fnv_prime: u128 = 1099511628211;

    for (seed) |byte| {
        hash ^= byte;
        hash *%= fnv_prime;
    }
    // Separator to prevent collisions between "ab"+"c" and "a"+"bc"
    hash ^= 0xFF;
    hash *%= fnv_prime;
    for (salt) |byte| {
        hash ^= byte;
        hash *%= fnv_prime;
    }

    // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    const bytes = std.mem.toBytes(hash);
    return try std.fmt.allocPrint(allocator, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        bytes[0],  bytes[1],  bytes[2],  bytes[3],
        bytes[4],  bytes[5],  bytes[6],  bytes[7],
        bytes[8],  bytes[9],  bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    });
}

/// Escape a string for use in XML content.
/// Replaces &, <, >, ", and ' with their XML entity equivalents.
pub fn xmlEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    for (input) |c| {
        switch (c) {
            '&' => try buf.appendSlice(allocator, "&amp;"),
            '<' => try buf.appendSlice(allocator, "&lt;"),
            '>' => try buf.appendSlice(allocator, "&gt;"),
            '"' => try buf.appendSlice(allocator, "&quot;"),
            '\'' => try buf.appendSlice(allocator, "&apos;"),
            else => try buf.append(allocator, c),
        }
    }

    return buf.toOwnedSlice(allocator);
}

// =============================================================================
// Route Handler Functions
// =============================================================================

/// Format an HTTP response with correct Content-Type for Thunderbird autoconfig.
/// Wraps the generated XML with appropriate HTTP headers.
pub fn handleThunderbirdRoute(allocator: std.mem.Allocator, config: AutoconfigConfig, domain: []const u8) ![]u8 {
    const xml = try generateThunderbirdXML(allocator, config, domain);
    defer allocator.free(xml);

    return try std.fmt.allocPrint(
        allocator,
        "HTTP/1.1 200 OK\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{s}",
        .{ xml.len, xml },
    );
}

/// Format an HTTP response with correct Content-Type for Outlook autodiscover.
/// Wraps the generated XML with appropriate HTTP headers.
pub fn handleOutlookRoute(allocator: std.mem.Allocator, config: AutoconfigConfig, email: []const u8) ![]u8 {
    const xml = try generateOutlookXML(allocator, config, email);
    defer allocator.free(xml);

    return try std.fmt.allocPrint(
        allocator,
        "HTTP/1.1 200 OK\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{s}",
        .{ xml.len, xml },
    );
}

/// Format an HTTP response with correct Content-Type for Apple mobileconfig.
/// Uses the application/x-apple-aspen-config MIME type that triggers iOS/macOS
/// profile installation when downloaded.
pub fn handleAppleRoute(allocator: std.mem.Allocator, config: AutoconfigConfig, email: []const u8) ![]u8 {
    const xml = try generateAppleMobileconfig(allocator, config, email);
    defer allocator.free(xml);

    return try std.fmt.allocPrint(
        allocator,
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-apple-aspen-config; charset=utf-8\r\nContent-Disposition: attachment; filename=\"email.mobileconfig\"\r\nContent-Length: {d}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{s}",
        .{ xml.len, xml },
    );
}

/// Format a generic error HTTP response.
pub fn handleErrorRoute(allocator: std.mem.Allocator, status_code: u16, message: []const u8) ![]u8 {
    const status_text = switch (status_code) {
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        else => "Error",
    };

    return try std.fmt.allocPrint(
        allocator,
        "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ status_code, status_text, message.len, message },
    );
}

// =============================================================================
// Tests
// =============================================================================

test "config defaults" {
    const config = AutoconfigConfig{};

    try std.testing.expectEqual(@as(u16, 143), config.imap_port);
    try std.testing.expectEqual(@as(u16, 993), config.imaps_port);
    try std.testing.expectEqual(@as(u16, 587), config.smtp_port);
    try std.testing.expectEqual(@as(u16, 995), config.pop3_port);
    try std.testing.expect(config.enable_imap);
    try std.testing.expect(!config.enable_pop3);
    try std.testing.expectEqualStrings("localhost", config.hostname);
    try std.testing.expectEqualStrings("localhost", config.domain);
    try std.testing.expectEqualStrings("Mail Server", config.display_name);
    try std.testing.expectEqualStrings("Mail", config.display_short_name);
}

test "config custom values" {
    const config = AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .imap_port = 1143,
        .imaps_port = 1993,
        .smtp_port = 1587,
        .pop3_port = 1995,
        .enable_imap = true,
        .enable_pop3 = true,
        .display_name = "Example Mail",
        .display_short_name = "Example",
    };

    try std.testing.expectEqual(@as(u16, 1143), config.imap_port);
    try std.testing.expectEqual(@as(u16, 1993), config.imaps_port);
    try std.testing.expectEqual(@as(u16, 1587), config.smtp_port);
    try std.testing.expectEqual(@as(u16, 1995), config.pop3_port);
    try std.testing.expect(config.enable_pop3);
    try std.testing.expectEqualStrings("mail.example.com", config.hostname);
}

test "domain extraction from email" {
    try std.testing.expectEqualStrings("example.com", extractDomainFromEmail("user@example.com").?);
    try std.testing.expectEqualStrings("sub.domain.org", extractDomainFromEmail("admin@sub.domain.org").?);
    try std.testing.expect(extractDomainFromEmail("nodomain") == null);
    try std.testing.expect(extractDomainFromEmail("") == null);
    try std.testing.expect(extractDomainFromEmail("user@") == null);
}

test "local part extraction from email" {
    try std.testing.expectEqualStrings("user", extractLocalPart("user@example.com").?);
    try std.testing.expectEqualStrings("admin", extractLocalPart("admin@sub.domain.org").?);
    try std.testing.expect(extractLocalPart("nodomain") == null);
    try std.testing.expect(extractLocalPart("") == null);
    try std.testing.expect(extractLocalPart("@example.com") == null);
}

test "query parameter extraction" {
    try std.testing.expectEqualStrings("user@example.com", extractQueryParam("email=user@example.com", "email").?);
    try std.testing.expectEqualStrings("bar", extractQueryParam("foo=bar&baz=qux", "foo").?);
    try std.testing.expectEqualStrings("qux", extractQueryParam("foo=bar&baz=qux", "baz").?);
    try std.testing.expect(extractQueryParam("foo=bar", "missing") == null);
    try std.testing.expect(extractQueryParam(null, "email") == null);
    try std.testing.expect(extractQueryParam("", "email") == null);
}

test "email extraction from Autodiscover XML" {
    const body =
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        \\  <Request>
        \\    <EMailAddress>user@example.com</EMailAddress>
        \\    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        \\  </Request>
        \\</Autodiscover>
    ;

    const email = extractEmailFromAutodiscover(body).?;
    try std.testing.expectEqualStrings("user@example.com", email);
}

test "email extraction from Autodiscover XML - no email" {
    const body =
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<Autodiscover><Request></Request></Autodiscover>
    ;

    try std.testing.expect(extractEmailFromAutodiscover(body) == null);
}

test "Thunderbird XML generation - valid structure and ports" {
    const allocator = std.testing.allocator;
    const config = AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .imaps_port = 993,
        .imap_port = 143,
        .smtp_port = 587,
        .enable_imap = true,
        .enable_pop3 = false,
        .display_name = "Example Mail",
        .display_short_name = "Example",
    };

    const xml = try generateThunderbirdXML(allocator, config, "example.com");
    defer allocator.free(xml);

    // Verify XML declaration
    try std.testing.expect(std.mem.startsWith(u8, xml, "<?xml version=\"1.0\""));

    // Verify root element and version
    try std.testing.expect(std.mem.indexOf(u8, xml, "<clientConfig version=\"1.1\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "</clientConfig>") != null);

    // Verify emailProvider with domain ID
    try std.testing.expect(std.mem.indexOf(u8, xml, "<emailProvider id=\"example.com\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<domain>example.com</domain>") != null);

    // Verify display names
    try std.testing.expect(std.mem.indexOf(u8, xml, "<displayName>Example Mail</displayName>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<displayShortName>Example</displayShortName>") != null);

    // Verify IMAP incoming server with correct ports
    try std.testing.expect(std.mem.indexOf(u8, xml, "<incomingServer type=\"imap\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<port>993</port>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<port>143</port>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<socketType>SSL</socketType>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<socketType>STARTTLS</socketType>") != null);

    // Verify SMTP outgoing server
    try std.testing.expect(std.mem.indexOf(u8, xml, "<outgoingServer type=\"smtp\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<port>587</port>") != null);

    // Verify hostname
    try std.testing.expect(std.mem.indexOf(u8, xml, "<hostname>mail.example.com</hostname>") != null);

    // Verify authentication and username placeholder
    try std.testing.expect(std.mem.indexOf(u8, xml, "<authentication>password-cleartext</authentication>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<username>%EMAILADDRESS%</username>") != null);

    // POP3 should NOT be present when disabled
    try std.testing.expect(std.mem.indexOf(u8, xml, "<incomingServer type=\"pop3\">") == null);
}

test "Thunderbird XML generation - with POP3 enabled" {
    const allocator = std.testing.allocator;
    const config = AutoconfigConfig{
        .hostname = "mail.test.org",
        .domain = "test.org",
        .pop3_port = 995,
        .enable_imap = true,
        .enable_pop3 = true,
    };

    const xml = try generateThunderbirdXML(allocator, config, "test.org");
    defer allocator.free(xml);

    // Both IMAP and POP3 should be present
    try std.testing.expect(std.mem.indexOf(u8, xml, "<incomingServer type=\"imap\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<incomingServer type=\"pop3\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<port>995</port>") != null);
}

test "Outlook XML generation" {
    const allocator = std.testing.allocator;
    const config = AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .imaps_port = 993,
        .smtp_port = 587,
        .enable_imap = true,
        .enable_pop3 = false,
    };

    const xml = try generateOutlookXML(allocator, config, "user@example.com");
    defer allocator.free(xml);

    // Verify XML declaration
    try std.testing.expect(std.mem.startsWith(u8, xml, "<?xml version=\"1.0\""));

    // Verify Autodiscover envelope
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "</Autodiscover>") != null);

    // Verify Response namespace
    try std.testing.expect(std.mem.indexOf(u8, xml, "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a") != null);

    // Verify Account settings
    try std.testing.expect(std.mem.indexOf(u8, xml, "<AccountType>email</AccountType>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Action>settings</Action>") != null);

    // Verify IMAP protocol
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Type>IMAP</Type>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Server>mail.example.com</Server>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Port>993</Port>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<LoginName>user@example.com</LoginName>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<SSL>on</SSL>") != null);

    // Verify SMTP protocol
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Type>SMTP</Type>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Port>587</Port>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Encryption>TLS</Encryption>") != null);

    // POP3 should NOT be present
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Type>POP3</Type>") == null);

    // Verify common Outlook settings
    try std.testing.expect(std.mem.indexOf(u8, xml, "<DomainRequired>off</DomainRequired>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<SPA>off</SPA>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<AuthRequired>on</AuthRequired>") != null);
}

test "Outlook XML generation - with POP3" {
    const allocator = std.testing.allocator;
    const config = AutoconfigConfig{
        .hostname = "mail.test.org",
        .domain = "test.org",
        .pop3_port = 995,
        .enable_imap = true,
        .enable_pop3 = true,
    };

    const xml = try generateOutlookXML(allocator, config, "admin@test.org");
    defer allocator.free(xml);

    try std.testing.expect(std.mem.indexOf(u8, xml, "<Type>IMAP</Type>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Type>POP3</Type>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Type>SMTP</Type>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Port>995</Port>") != null);
}

test "Apple mobileconfig generation" {
    const allocator = std.testing.allocator;
    const config = AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .imaps_port = 993,
        .smtp_port = 587,
        .display_name = "Example Mail",
    };

    const xml = try generateAppleMobileconfig(allocator, config, "user@example.com");
    defer allocator.free(xml);

    // Verify plist structure
    try std.testing.expect(std.mem.startsWith(u8, xml, "<?xml version=\"1.0\""));
    try std.testing.expect(std.mem.indexOf(u8, xml, "<!DOCTYPE plist") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<plist version=\"1.0\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "</plist>") != null);

    // Verify email account type
    try std.testing.expect(std.mem.indexOf(u8, xml, "<string>EmailTypeIMAP</string>") != null);

    // Verify email address
    try std.testing.expect(std.mem.indexOf(u8, xml, "<string>user@example.com</string>") != null);

    // Verify incoming server settings
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>IncomingMailServerHostName</key>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<string>mail.example.com</string>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>IncomingMailServerPortNumber</key>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<integer>993</integer>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>IncomingMailServerUseSSL</key>") != null);

    // Verify outgoing server settings
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>OutgoingMailServerHostName</key>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>OutgoingMailServerPortNumber</key>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<integer>587</integer>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>OutgoingMailServerUseSSL</key>") != null);

    // Verify authentication settings
    try std.testing.expect(std.mem.indexOf(u8, xml, "<string>EmailAuthPassword</string>") != null);

    // Verify profile metadata
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>PayloadType</key>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<string>Configuration</string>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<string>com.apple.mail.managed</string>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>PayloadVersion</key>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<integer>1</integer>") != null);

    // Verify display name is present
    try std.testing.expect(std.mem.indexOf(u8, xml, "Example Mail") != null);

    // Verify PayloadUUID is present (deterministic UUID format)
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>PayloadUUID</key>") != null);

    // Verify password same as incoming flag
    try std.testing.expect(std.mem.indexOf(u8, xml, "<key>OutgoingPasswordSameAsIncomingPassword</key>") != null);
}

test "Apple mobileconfig - deterministic UUIDs" {
    const allocator = std.testing.allocator;
    const config = AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
    };

    // Generate twice with the same input - UUIDs should be identical
    const xml1 = try generateAppleMobileconfig(allocator, config, "user@example.com");
    defer allocator.free(xml1);

    const xml2 = try generateAppleMobileconfig(allocator, config, "user@example.com");
    defer allocator.free(xml2);

    try std.testing.expectEqualStrings(xml1, xml2);

    // Generate with different input - UUIDs should differ
    const xml3 = try generateAppleMobileconfig(allocator, config, "other@example.com");
    defer allocator.free(xml3);

    try std.testing.expect(!std.mem.eql(u8, xml1, xml3));
}

test "XML escape" {
    const allocator = std.testing.allocator;

    const escaped = try xmlEscape(allocator, "Tom & Jerry <friends> \"best\" pair's");
    defer allocator.free(escaped);

    try std.testing.expectEqualStrings("Tom &amp; Jerry &lt;friends&gt; &quot;best&quot; pair&apos;s", escaped);
}

test "XML escape - no special characters" {
    const allocator = std.testing.allocator;

    const escaped = try xmlEscape(allocator, "plain text 123");
    defer allocator.free(escaped);

    try std.testing.expectEqualStrings("plain text 123", escaped);
}

test "deterministic UUID generation" {
    const allocator = std.testing.allocator;

    // Same inputs produce same output
    const uuid1 = try generateDeterministicUUID(allocator, "test", "salt");
    defer allocator.free(uuid1);

    const uuid2 = try generateDeterministicUUID(allocator, "test", "salt");
    defer allocator.free(uuid2);

    try std.testing.expectEqualStrings(uuid1, uuid2);

    // Different inputs produce different output
    const uuid3 = try generateDeterministicUUID(allocator, "different", "salt");
    defer allocator.free(uuid3);

    try std.testing.expect(!std.mem.eql(u8, uuid1, uuid3));

    // Verify UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
    try std.testing.expectEqual(@as(usize, 36), uuid1.len);
    try std.testing.expectEqual(@as(u8, '-'), uuid1[8]);
    try std.testing.expectEqual(@as(u8, '-'), uuid1[13]);
    try std.testing.expectEqual(@as(u8, '-'), uuid1[18]);
    try std.testing.expectEqual(@as(u8, '-'), uuid1[23]);
}

test "AutoconfigServer init and deinit" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.test.com",
        .domain = "test.com",
        .display_name = "Test Mail",
    });
    defer server.deinit();

    try std.testing.expectEqualStrings("mail.test.com", server.config.hostname);
    try std.testing.expectEqualStrings("test.com", server.config.domain);
    try std.testing.expectEqualStrings("Test Mail", server.config.display_name);
}

test "AutoconfigServer handleThunderbirdRequest" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .display_name = "Example Mail",
    });
    defer server.deinit();

    var response = try server.handleThunderbirdRequest("example.com");
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("application/xml; charset=utf-8", response.content_type);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "<clientConfig") != null);
}

test "AutoconfigServer handleOutlookRequest" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
    });
    defer server.deinit();

    var response = try server.handleOutlookRequest("user@example.com", null);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "<Autodiscover") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "user@example.com") != null);
}

test "AutoconfigServer handleOutlookRequest - email from body" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
    });
    defer server.deinit();

    const body = "<Autodiscover><Request><EMailAddress>extracted@example.com</EMailAddress></Request></Autodiscover>";
    var response = try server.handleOutlookRequest("", body);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "extracted@example.com") != null);
}

test "AutoconfigServer handleAppleRequest" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .display_name = "Example Mail",
    });
    defer server.deinit();

    var response = try server.handleAppleRequest("user@example.com");
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("application/x-apple-aspen-config; charset=utf-8", response.content_type);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "<plist") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "user@example.com") != null);
}

test "HttpResponse toHttp" {
    const allocator = std.testing.allocator;

    var response = HttpResponse{
        .status_code = 200,
        .content_type = "application/xml; charset=utf-8",
        .body = try allocator.dupe(u8, "<test/>"),
        .allocator = allocator,
    };
    defer response.deinit();

    const http = try response.toHttp(allocator);
    defer allocator.free(http);

    try std.testing.expect(std.mem.startsWith(u8, http, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, http, "Content-Type: application/xml; charset=utf-8") != null);
    try std.testing.expect(std.mem.indexOf(u8, http, "Content-Length: 7") != null);
    try std.testing.expect(std.mem.endsWith(u8, http, "<test/>"));
}

test "route handler - Thunderbird" {
    const allocator = std.testing.allocator;
    const config = AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
    };

    const http = try handleThunderbirdRoute(allocator, config, "example.com");
    defer allocator.free(http);

    try std.testing.expect(std.mem.startsWith(u8, http, "HTTP/1.1 200 OK"));
    try std.testing.expect(std.mem.indexOf(u8, http, "Content-Type: application/xml") != null);
    try std.testing.expect(std.mem.indexOf(u8, http, "<clientConfig") != null);
}

test "route handler - Outlook" {
    const allocator = std.testing.allocator;
    const config = AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
    };

    const http = try handleOutlookRoute(allocator, config, "user@example.com");
    defer allocator.free(http);

    try std.testing.expect(std.mem.startsWith(u8, http, "HTTP/1.1 200 OK"));
    try std.testing.expect(std.mem.indexOf(u8, http, "Content-Type: application/xml") != null);
    try std.testing.expect(std.mem.indexOf(u8, http, "<Autodiscover") != null);
}

test "route handler - Apple" {
    const allocator = std.testing.allocator;
    const config = AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
    };

    const http = try handleAppleRoute(allocator, config, "user@example.com");
    defer allocator.free(http);

    try std.testing.expect(std.mem.startsWith(u8, http, "HTTP/1.1 200 OK"));
    try std.testing.expect(std.mem.indexOf(u8, http, "application/x-apple-aspen-config") != null);
    try std.testing.expect(std.mem.indexOf(u8, http, "Content-Disposition: attachment") != null);
    try std.testing.expect(std.mem.indexOf(u8, http, "<plist") != null);
}

test "route handler - error" {
    const allocator = std.testing.allocator;

    const http = try handleErrorRoute(allocator, 404, "Not Found");
    defer allocator.free(http);

    try std.testing.expect(std.mem.startsWith(u8, http, "HTTP/1.1 404 Not Found"));
    try std.testing.expect(std.mem.indexOf(u8, http, "Content-Type: text/plain") != null);
}

test "AutoconfigServer routeRequest - Thunderbird well-known" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
    });
    defer server.deinit();

    var response = try server.routeRequest("GET", "/.well-known/autoconfig/mail/config-v1.1.xml", null, null);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "<clientConfig") != null);
}

test "AutoconfigServer routeRequest - Outlook POST" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
    });
    defer server.deinit();

    const body = "<Autodiscover><Request><EMailAddress>user@example.com</EMailAddress></Request></Autodiscover>";
    var response = try server.routeRequest("POST", "/autodiscover/autodiscover.xml", null, body);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "<Autodiscover") != null);
}

test "AutoconfigServer routeRequest - Apple mobileconfig" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
    });
    defer server.deinit();

    var response = try server.routeRequest("GET", "/email.mobileconfig", "email=user@example.com", null);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("application/x-apple-aspen-config; charset=utf-8", response.content_type);
}

test "AutoconfigServer routeRequest - 404" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
    });
    defer server.deinit();

    var response = try server.routeRequest("GET", "/nonexistent", null, null);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 404), response.status_code);
}

test "AutoconfigServer routeRequest - method not allowed for autodiscover" {
    var server = AutoconfigServer.init(std.testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
    });
    defer server.deinit();

    var response = try server.routeRequest("GET", "/autodiscover/autodiscover.xml", null, null);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 405), response.status_code);
}
