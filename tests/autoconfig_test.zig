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

// =============================================================================
// Edge Case Tests
// =============================================================================

test "autoconfig edge case: generate config for empty domain" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "",
        .display_name = "Test Mail",
        .display_short_name = "Test",
    };

    // Thunderbird XML with empty domain
    const tb_xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, "");
    defer testing.allocator.free(tb_xml);

    // Should still produce valid XML structure even with empty domain
    try testing.expect(std.mem.indexOf(u8, tb_xml, "<?xml version=\"1.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, tb_xml, "<clientConfig version=\"1.1\">") != null);
    try testing.expect(std.mem.indexOf(u8, tb_xml, "</clientConfig>") != null);
    // emailProvider should have empty id
    try testing.expect(std.mem.indexOf(u8, tb_xml, "<emailProvider id=\"\">") != null);

    // Outlook XML with empty email
    const ol_xml = try autoconfig.generateOutlookXML(testing.allocator, config, "");
    defer testing.allocator.free(ol_xml);
    try testing.expect(std.mem.indexOf(u8, ol_xml, "<Autodiscover") != null);
    try testing.expect(std.mem.indexOf(u8, ol_xml, "</Autodiscover>") != null);
}

test "autoconfig edge case: generate config for IDN (internationalized domain)" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .display_name = "Test Mail",
    };

    // Punycode-encoded IDN domain (xn-- prefix)
    const xml = try autoconfig.generateThunderbirdXML(
        testing.allocator,
        config,
        "xn--nxasmq6b.xn--jxalpdlp",
    );
    defer testing.allocator.free(xml);

    // The punycode domain should be embedded in the XML as-is
    try testing.expect(std.mem.indexOf(u8, xml, "<domain>xn--nxasmq6b.xn--jxalpdlp</domain>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<emailProvider id=\"xn--nxasmq6b.xn--jxalpdlp\">") != null);
}

test "autoconfig edge case: generate config with very long domain" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
    };

    // A domain with 200+ characters (subdomains separated by dots)
    const long_domain = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z." ++
        "aa.bb.cc.dd.ee.ff.gg.hh.ii.jj.kk.ll.mm.nn.oo.pp.qq.rr.ss.tt.uu.vv.ww.xx.yy.zz." ++
        "aaa.bbb.ccc.ddd.eee.fff.ggg.hhh.iii.jjj.kkk.example.com";

    const xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, long_domain);
    defer testing.allocator.free(xml);

    // Should not crash or truncate -- the full domain should appear in the XML
    try testing.expect(std.mem.indexOf(u8, xml, long_domain) != null);
    try testing.expect(std.mem.indexOf(u8, xml, "</clientConfig>") != null);
}

test "autoconfig edge case: Thunderbird XML escaping with special chars" {
    // Test the xmlEscape function with all five XML special characters
    const escaped_amp = try autoconfig.xmlEscape(testing.allocator, "AT&T");
    defer testing.allocator.free(escaped_amp);
    try testing.expectEqualStrings("AT&amp;T", escaped_amp);

    const escaped_lt = try autoconfig.xmlEscape(testing.allocator, "a < b");
    defer testing.allocator.free(escaped_lt);
    try testing.expectEqualStrings("a &lt; b", escaped_lt);

    const escaped_gt = try autoconfig.xmlEscape(testing.allocator, "a > b");
    defer testing.allocator.free(escaped_gt);
    try testing.expectEqualStrings("a &gt; b", escaped_gt);

    const escaped_quot = try autoconfig.xmlEscape(testing.allocator, "say \"hello\"");
    defer testing.allocator.free(escaped_quot);
    try testing.expectEqualStrings("say &quot;hello&quot;", escaped_quot);

    // All special characters in one string
    const escaped_all = try autoconfig.xmlEscape(testing.allocator, "<tag attr=\"val\" & 'x'>");
    defer testing.allocator.free(escaped_all);
    try testing.expectEqualStrings("&lt;tag attr=&quot;val&quot; &amp; &apos;x&apos;&gt;", escaped_all);

    // Empty string should remain empty
    const escaped_empty = try autoconfig.xmlEscape(testing.allocator, "");
    defer testing.allocator.free(escaped_empty);
    try testing.expectEqualStrings("", escaped_empty);

    // String with no special chars passes through unchanged
    const escaped_plain = try autoconfig.xmlEscape(testing.allocator, "plain text 123");
    defer testing.allocator.free(escaped_plain);
    try testing.expectEqualStrings("plain text 123", escaped_plain);
}

test "autoconfig edge case: Outlook XML format validation" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.corp.example.com",
        .domain = "corp.example.com",
        .enable_imap = true,
        .enable_pop3 = true,
        .imaps_port = 993,
        .pop3_port = 995,
        .smtp_port = 587,
    };

    const xml = try autoconfig.generateOutlookXML(testing.allocator, config, "admin@corp.example.com");
    defer testing.allocator.free(xml);

    // Must have the Microsoft Autodiscover namespace
    try testing.expect(std.mem.indexOf(u8, xml, "schemas.microsoft.com/exchange/autodiscover") != null);

    // Must contain Account element with correct children
    try testing.expect(std.mem.indexOf(u8, xml, "<AccountType>email</AccountType>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<Action>settings</Action>") != null);

    // When both IMAP and POP3 are enabled, both should appear
    try testing.expect(std.mem.indexOf(u8, xml, "<Type>IMAP</Type>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<Type>POP3</Type>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<Type>SMTP</Type>") != null);

    // Login name should be the full email
    try testing.expect(std.mem.indexOf(u8, xml, "<LoginName>admin@corp.example.com</LoginName>") != null);

    // Server hostname should appear in all protocol sections
    // Count occurrences of the hostname
    var count: usize = 0;
    var search_start: usize = 0;
    while (std.mem.indexOf(u8, xml[search_start..], "<Server>mail.corp.example.com</Server>")) |pos| {
        count += 1;
        search_start += pos + 1;
    }
    // Should appear at least 3 times: IMAP, POP3, SMTP
    try testing.expect(count >= 3);
}

test "autoconfig edge case: Apple mobileconfig profile generation" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .display_name = "Example Corp Mail",
        .imaps_port = 993,
        .smtp_port = 587,
    };

    const xml = try autoconfig.generateAppleMobileconfig(testing.allocator, config, "ceo@example.com");
    defer testing.allocator.free(xml);

    // Must be a valid plist structure
    try testing.expect(std.mem.indexOf(u8, xml, "<?xml version=\"1.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<!DOCTYPE plist") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<plist version=\"1.0\">") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "</plist>") != null);

    // Must contain the email address
    try testing.expect(std.mem.indexOf(u8, xml, "<string>ceo@example.com</string>") != null);

    // Must contain the IMAP account type
    try testing.expect(std.mem.indexOf(u8, xml, "<string>EmailTypeIMAP</string>") != null);

    // Must contain PayloadType for mail
    try testing.expect(std.mem.indexOf(u8, xml, "<string>com.apple.mail.managed</string>") != null);

    // PayloadUUID should be present (deterministic)
    try testing.expect(std.mem.indexOf(u8, xml, "<key>PayloadUUID</key>") != null);

    // Profile description should reference the domain
    try testing.expect(std.mem.indexOf(u8, xml, "example.com") != null);

    // Display name should appear
    try testing.expect(std.mem.indexOf(u8, xml, "Example Corp Mail") != null);

    // SSL should be enabled for incoming mail
    try testing.expect(std.mem.indexOf(u8, xml, "<key>IncomingMailServerUseSSL</key>") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<true/>") != null);
}

test "autoconfig edge case: config with non-standard ports" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.custom.com",
        .domain = "custom.com",
        .imap_port = 10143,
        .imaps_port = 10993,
        .smtp_port = 10587,
        .pop3_port = 10995,
        .enable_imap = true,
        .enable_pop3 = true,
    };

    // Thunderbird XML should use the custom ports
    const tb_xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, "custom.com");
    defer testing.allocator.free(tb_xml);

    try testing.expect(std.mem.indexOf(u8, tb_xml, "<port>10993</port>") != null);
    try testing.expect(std.mem.indexOf(u8, tb_xml, "<port>10143</port>") != null);
    try testing.expect(std.mem.indexOf(u8, tb_xml, "<port>10587</port>") != null);
    try testing.expect(std.mem.indexOf(u8, tb_xml, "<port>10995</port>") != null);

    // Outlook XML should use the custom ports
    const ol_xml = try autoconfig.generateOutlookXML(testing.allocator, config, "user@custom.com");
    defer testing.allocator.free(ol_xml);

    try testing.expect(std.mem.indexOf(u8, ol_xml, "<Port>10993</Port>") != null);
    try testing.expect(std.mem.indexOf(u8, ol_xml, "<Port>10995</Port>") != null);
    try testing.expect(std.mem.indexOf(u8, ol_xml, "<Port>10587</Port>") != null);

    // Apple mobileconfig should use the custom ports
    const apple_xml = try autoconfig.generateAppleMobileconfig(testing.allocator, config, "user@custom.com");
    defer testing.allocator.free(apple_xml);

    try testing.expect(std.mem.indexOf(u8, apple_xml, "<integer>10993</integer>") != null);
    try testing.expect(std.mem.indexOf(u8, apple_xml, "<integer>10587</integer>") != null);
}

test "autoconfig edge case: config with custom server hostnames" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "imap-cluster-01.prod.internal.example.com",
        .domain = "example.com",
        .display_name = "Production Mail",
        .display_short_name = "Prod",
    };

    const tb_xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, "example.com");
    defer testing.allocator.free(tb_xml);

    // The long hostname should appear in incoming and outgoing server configs
    try testing.expect(std.mem.indexOf(u8, tb_xml, "<hostname>imap-cluster-01.prod.internal.example.com</hostname>") != null);

    const ol_xml = try autoconfig.generateOutlookXML(testing.allocator, config, "user@example.com");
    defer testing.allocator.free(ol_xml);

    try testing.expect(std.mem.indexOf(u8, ol_xml, "<Server>imap-cluster-01.prod.internal.example.com</Server>") != null);
}

test "autoconfig edge case: email address with special characters for config lookup" {
    // The extractDomainFromEmail and extractLocalPart functions handle various edge cases

    // Plus addressing
    try testing.expectEqualStrings("example.com", autoconfig.extractDomainFromEmail("user+tag@example.com").?);
    try testing.expectEqualStrings("user+tag", autoconfig.extractLocalPart("user+tag@example.com").?);

    // Dots in local part
    try testing.expectEqualStrings("example.com", autoconfig.extractDomainFromEmail("first.last@example.com").?);
    try testing.expectEqualStrings("first.last", autoconfig.extractLocalPart("first.last@example.com").?);

    // Hyphenated domain
    try testing.expectEqualStrings("my-company.co.uk", autoconfig.extractDomainFromEmail("admin@my-company.co.uk").?);

    // Multiple @ signs -- should split on first @
    const multi_at_domain = autoconfig.extractDomainFromEmail("user@host@example.com");
    try testing.expect(multi_at_domain != null);
    // indexOf finds first @, so domain part is "host@example.com"
    try testing.expectEqualStrings("host@example.com", multi_at_domain.?);

    // Just @ with empty parts
    try testing.expect(autoconfig.extractDomainFromEmail("@") == null);
    try testing.expect(autoconfig.extractLocalPart("@domain.com") == null);

    // Numeric local part
    try testing.expectEqualStrings("123456", autoconfig.extractLocalPart("123456@example.com").?);
}

test "autoconfig edge case: generate config with all features disabled" {
    const config = autoconfig.AutoconfigConfig{
        .hostname = "mail.minimal.com",
        .domain = "minimal.com",
        .enable_imap = false,
        .enable_pop3 = false,
        .display_name = "Minimal",
        .display_short_name = "Min",
    };

    // Thunderbird XML: no IMAP, no POP3, but SMTP should still be present
    const tb_xml = try autoconfig.generateThunderbirdXML(testing.allocator, config, "minimal.com");
    defer testing.allocator.free(tb_xml);

    try testing.expect(std.mem.indexOf(u8, tb_xml, "<incomingServer type=\"imap\">") == null);
    try testing.expect(std.mem.indexOf(u8, tb_xml, "<incomingServer type=\"pop3\">") == null);
    try testing.expect(std.mem.indexOf(u8, tb_xml, "<outgoingServer type=\"smtp\">") != null);

    // Outlook XML: no IMAP, no POP3
    const ol_xml = try autoconfig.generateOutlookXML(testing.allocator, config, "user@minimal.com");
    defer testing.allocator.free(ol_xml);

    try testing.expect(std.mem.indexOf(u8, ol_xml, "<Type>IMAP</Type>") == null);
    try testing.expect(std.mem.indexOf(u8, ol_xml, "<Type>POP3</Type>") == null);
    try testing.expect(std.mem.indexOf(u8, ol_xml, "<Type>SMTP</Type>") != null);
}

test "autoconfig edge case: routeRequest handles Apple mobileconfig paths" {
    var server = autoconfig.AutoconfigServer.init(testing.allocator, .{
        .hostname = "mail.example.com",
        .domain = "example.com",
        .display_name = "Example",
    });
    defer server.deinit();

    // Direct mobileconfig path
    var resp1 = try server.routeRequest("GET", "/email.mobileconfig", "email=user@example.com", null);
    defer resp1.deinit();
    try testing.expectEqual(@as(u16, 200), resp1.status_code);
    try testing.expect(std.mem.indexOf(u8, resp1.content_type, "apple-aspen-config") != null);
    try testing.expect(std.mem.indexOf(u8, resp1.body, "<plist") != null);

    // Well-known mobileconfig path
    var resp2 = try server.routeRequest("GET", "/.well-known/autoconfig/email.mobileconfig", "email=admin@example.com", null);
    defer resp2.deinit();
    try testing.expectEqual(@as(u16, 200), resp2.status_code);
    try testing.expect(std.mem.indexOf(u8, resp2.body, "admin@example.com") != null);

    // POST to Outlook autodiscover path
    const autodiscover_body =
        \\<?xml version="1.0"?>
        \\<Autodiscover>
        \\  <Request>
        \\    <EMailAddress>test@example.com</EMailAddress>
        \\  </Request>
        \\</Autodiscover>
    ;
    var resp3 = try server.routeRequest("POST", "/autodiscover/autodiscover.xml", null, autodiscover_body);
    defer resp3.deinit();
    try testing.expectEqual(@as(u16, 200), resp3.status_code);
    try testing.expect(std.mem.indexOf(u8, resp3.body, "<Autodiscover") != null);
}
