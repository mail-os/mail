// Autoconfig (Thunderbird / Outlook / Apple) Test Suite
// Tests for email client autoconfiguration XML generation.

const std = @import("std");
const testing = std.testing;
const autoconfig = @import("mail").autoconfig;

// =============================================================================
// AutoconfigConfig Defaults
// =============================================================================

test "autoconfig: default config has expected values" {
    const config = autoconfig.AutoconfigConfig{};

    try testing.expectEqualStrings("localhost", config.hostname);
    try testing.expectEqualStrings("localhost", config.domain);
    try testing.expectEqual(@as(u16, 143), config.imap_port);
    try testing.expectEqual(@as(u16, 993), config.imaps_port);
    try testing.expectEqual(@as(u16, 587), config.smtp_port);
    try testing.expectEqual(@as(u16, 995), config.pop3_port);
    try testing.expect(config.enable_imap);
    try testing.expect(!config.enable_pop3);
    try testing.expectEqualStrings("Mail Server", config.display_name);
    try testing.expectEqualStrings("Mail", config.display_short_name);
}

// =============================================================================
// Thunderbird Autoconfig XML
// =============================================================================

test "Thunderbird autoconfig XML contains required elements" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .display_name = "Example Mail",
        .display_short_name = "Example",
    };

    const xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, "example.com");
    defer testing.allocator.free(xml);

    // XML declaration
    try testing.expect(std.mem.indexOf(u8, xml, "<?xml version=\"1.0\"") != null);
    // Root element
    try testing.expect(std.mem.indexOf(u8, xml, "<clientConfig version=\"1.1\">") != null);
    // Email provider with domain
    try testing.expect(std.mem.indexOf(u8, xml, "<emailProvider id=\"example.com\">") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<domain>example.com</domain>") != null);
    // Display names
    try testing.expect(std.mem.indexOf(u8, xml, "<displayName>Example Mail</displayName>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<displayShortName>Example</displayShortName>") != null);
    // Closing elements
    try testing.expect(std.mem.indexOf(u8, xml, "</clientConfig>") != null);
}

test "Thunderbird autoconfig XML includes IMAP when enabled" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .enable_imap = true,
        .imaps_port = 993,
        .imap_port = 143,
    };

    const xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, "example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<incomingServer type=\"imap\">") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<port>993</port>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<socketType>SSL</socketType>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<username>%EMAILADDRESS%</username>") != null);
}

test "Thunderbird autoconfig XML includes SMTP outgoing server" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .smtp_port = 587,
    };

    const xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, "example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<outgoingServer type=\"smtp\">") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<port>587</port>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<socketType>STARTTLS</socketType>") != null);
}

test "Thunderbird autoconfig XML includes POP3 when enabled" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .enable_pop3 = true,
        .pop3_port = 995,
    };

    const xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, "example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<incomingServer type=\"pop3\">") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<port>995</port>") != null);
}

test "Thunderbird autoconfig XML excludes POP3 when disabled" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .enable_pop3 = false,
    };

    const xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, "example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<incomingServer type=\"pop3\">") == null);
}

// =============================================================================
// Outlook Autodiscover XML
// =============================================================================

test "Outlook autodiscover XML contains required elements" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
    };

    const xml = try autoconfig.generateOutlookXML(testing.allocator, config, "user@example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<?xml version=\"1.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<Autodiscover") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<AccountType>email</AccountType>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<Action>settings</Action>") != null);
}

test "Outlook autodiscover XML includes IMAP protocol" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .enable_imap = true,
        .imaps_port = 993,
    };

    const xml = try autoconfig.generateOutlookXML(testing.allocator, config, "user@example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<Type>IMAP</Type>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<Port>993</Port>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<LoginName>user@example.com</LoginName>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<SSL>on</SSL>") != null);
}

test "Outlook autodiscover XML includes SMTP protocol" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .smtp_port = 587,
    };

    const xml = try autoconfig.generateOutlookXML(testing.allocator, config, "user@example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<Type>SMTP</Type>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<Port>587</Port>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<Encryption>TLS</Encryption>") != null);
}

test "Outlook autodiscover XML excludes POP3 when disabled" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .enable_pop3 = false,
    };

    const xml = try autoconfig.generateOutlookXML(testing.allocator, config, "user@example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<Type>POP3</Type>") == null);
}

// =============================================================================
// Apple Mobileconfig XML
// =============================================================================

test "Apple mobileconfig XML contains plist structure" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .display_name = "Example Mail",
    };

    const xml = try autoconfig.generateAppleMobileconfig(testing.allocator, config, "user@example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<?xml version=\"1.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<!DOCTYPE plist") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<plist version=\"1.0\">") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "</plist>") != null);
}

test "Apple mobileconfig XML includes email account type" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
    };

    const xml = try autoconfig.generateAppleMobileconfig(testing.allocator, config, "user@example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<string>EmailTypeIMAP</string>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<string>user@example.com</string>") != null);
}

test "Apple mobileconfig XML includes mail server config" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .imaps_port = 993,
        .smtp_port = 587,
    };

    const xml = try autoconfig.generateAppleMobileconfig(testing.allocator, config, "user@example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<string>mail.example.com</string>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<integer>993</integer>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<integer>587</integer>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<key>IncomingMailServerUseSSL</key>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<true/>") != null);
}

test "Apple mobileconfig XML includes payload metadata" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .display_name = "Example Mail",
    };

    const xml = try autoconfig.generateAppleMobileconfig(testing.allocator, config, "user@example.com");
    defer testing.allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "<key>PayloadType</key>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<string>com.apple.mail.managed</string>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<key>PayloadUUID</key>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<key>PayloadVersion</key>") != null);
}

// =============================================================================
// Domain Extraction from Email
// =============================================================================

test "autoconfig: extractDomainFromEmail" {
    try testing.expectEqualStrings("example.com", autoconfig.extractDomainFromEmail("user@example.com").?);
    try testing.expectEqualStrings("sub.domain.com", autoconfig.extractDomainFromEmail("admin@sub.domain.com").?);
    try testing.expect(autoconfig.extractDomainFromEmail("no-at-sign") == null);
    try testing.expect(autoconfig.extractDomainFromEmail("trailing@") == null);
}

test "autoconfig: extractLocalPart" {
    try testing.expectEqualStrings("user", autoconfig.extractLocalPart("user@example.com").?);
    try testing.expectEqualStrings("admin", autoconfig.extractLocalPart("admin@sub.domain.com").?);
    try testing.expect(autoconfig.extractLocalPart("no-at-sign") == null);
    try testing.expect(autoconfig.extractLocalPart("@nodomain.com") == null);
}

test "autoconfig: extractQueryParam" {
    try testing.expectEqualStrings("user@ex.com", autoconfig.extractQueryParam("email=user@ex.com&foo=bar", "email").?);
    try testing.expectEqualStrings("bar", autoconfig.extractQueryParam("email=user@ex.com&foo=bar", "foo").?);
    try testing.expect(autoconfig.extractQueryParam("email=user@ex.com", "missing") == null);
    try testing.expect(autoconfig.extractQueryParam(null, "email") == null);
    try testing.expect(autoconfig.extractQueryParam("", "email") == null);
}

test "autoconfig: extractEmailFromAutodiscover" {
    const body =
        \\<?xml version="1.0"?>
        \\<Autodiscover>
        \\  <Request>
        \\    <EMailAddress>user@example.com</EMailAddress>
        \\  </Request>
        \\</Autodiscover>
    ;

    try testing.expectEqualStrings("user@example.com", autoconfig.extractEmailFromAutodiscover(body).?);
}

test "autoconfig: extractEmailFromAutodiscover with missing element" {
    try testing.expect(autoconfig.extractEmailFromAutodiscover("<xml>no email here</xml>") == null);
}

test "autoconfig: extractEmailFromAutodiscover with empty email" {
    try testing.expect(autoconfig.extractEmailFromAutodiscover("<EMailAddress></EMailAddress>") == null);
}

test "autoconfig: extractEmailFromAutodiscover with no at-sign" {
    try testing.expect(autoconfig.extractEmailFromAutodiscover("<EMailAddress>notanemail</EMailAddress>") == null);
}

// =============================================================================
// AutoconfigServer Route Dispatcher
// =============================================================================

test "autoconfig: routeRequest handles Thunderbird path" {
    var server = autoconfig.AutoconfigServer.init(testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
    });
    defer server.deinit();

    var resp = try server.routeRequest("GET", "/.well-known/autoconfig/mail/config-v1.1.xml", null, null);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 200), resp.status_code);
    try testing.expect(std.mem.indexOf(u8, resp.content_type, "xml") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "<clientConfig") != null);
}

test "autoconfig: routeRequest handles alternate Thunderbird path" {
    var server = autoconfig.AutoconfigServer.init(testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
    });
    defer server.deinit();

    var resp = try server.routeRequest("GET", "/mail/config-v1.1.xml", null, null);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 200), resp.status_code);
}

test "autoconfig: routeRequest returns 404 for unknown path" {
    var server = autoconfig.AutoconfigServer.init(testing.allocator, .{});
    defer server.deinit();

    var resp = try server.routeRequest("GET", "/unknown/path", null, null);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 404), resp.status_code);
}

test "autoconfig: routeRequest returns 405 for POST to Thunderbird path" {
    var server = autoconfig.AutoconfigServer.init(testing.allocator, .{});
    defer server.deinit();

    // POST to autodiscover path with GET method should return 405
    var resp = try server.routeRequest("GET", "/autodiscover/autodiscover.xml", null, null);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 405), resp.status_code);
}

// =============================================================================
// XML Escape Helper
// =============================================================================

test "autoconfig: xmlEscape escapes special characters" {
    const escaped = try autoconfig.xmlEscape(testing.allocator, "Hello <world> & \"friends\" 'here'");
    defer testing.allocator.free(escaped);

    try testing.expectEqualStrings("Hello &lt;world&gt; &amp; &quot;friends&quot; &apos;here&apos;", escaped);
}

test "autoconfig: xmlEscape passes through safe text" {
    const escaped = try autoconfig.xmlEscape(testing.allocator, "Hello world 123");
    defer testing.allocator.free(escaped);

    try testing.expectEqualStrings("Hello world 123", escaped);
}

// =============================================================================
// HttpResponse
// =============================================================================

test "autoconfig: HttpResponse toHttp formats correctly" {
    var resp = autoconfig.HttpResponse{
        .status_code = 200,
        .content_type = "application/xml",
        .body = try testing.allocator.dupe(u8, "<root/>"),
        .allocator = testing.allocator,
    };
    defer resp.deinit();

    const http = try resp.toHttp(testing.allocator);
    defer testing.allocator.free(http);

    try testing.expect(std.mem.indexOf(u8, http, "HTTP/1.1 200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, http, "Content-Type: application/xml") != null);
    try testing.expect(std.mem.indexOf(u8, http, "<root/>") != null);
}
