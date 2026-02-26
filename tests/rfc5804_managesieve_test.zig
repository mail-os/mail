// RFC 5804 (ManageSieve Protocol) Test Suite
// Tests for compliance with RFC 5804 - A Protocol for Remotely Managing Sieve Scripts
// https://datatracker.ietf.org/doc/html/rfc5804

const std = @import("std");
const testing = std.testing;
const managesieve = @import("mail").managesieve;

// =============================================================================
// RFC 5804 Section 2.3: Command Parsing
// =============================================================================

test "RFC 5804: ManageSieveCommand fromString parses all commands" {
    try testing.expect(managesieve.ManageSieveCommand.fromString("AUTHENTICATE") == .AUTHENTICATE);
    try testing.expect(managesieve.ManageSieveCommand.fromString("CAPABILITY") == .CAPABILITY);
    try testing.expect(managesieve.ManageSieveCommand.fromString("HAVESPACE") == .HAVESPACE);
    try testing.expect(managesieve.ManageSieveCommand.fromString("PUTSCRIPT") == .PUTSCRIPT);
    try testing.expect(managesieve.ManageSieveCommand.fromString("LISTSCRIPTS") == .LISTSCRIPTS);
    try testing.expect(managesieve.ManageSieveCommand.fromString("SETACTIVE") == .SETACTIVE);
    try testing.expect(managesieve.ManageSieveCommand.fromString("GETSCRIPT") == .GETSCRIPT);
    try testing.expect(managesieve.ManageSieveCommand.fromString("DELETESCRIPT") == .DELETESCRIPT);
    try testing.expect(managesieve.ManageSieveCommand.fromString("RENAMESCRIPT") == .RENAMESCRIPT);
    try testing.expect(managesieve.ManageSieveCommand.fromString("CHECKSCRIPT") == .CHECKSCRIPT);
    try testing.expect(managesieve.ManageSieveCommand.fromString("NOOP") == .NOOP);
    try testing.expect(managesieve.ManageSieveCommand.fromString("LOGOUT") == .LOGOUT);
    try testing.expect(managesieve.ManageSieveCommand.fromString("STARTTLS") == .STARTTLS);
}

test "RFC 5804: ManageSieveCommand fromString is case-insensitive" {
    try testing.expect(managesieve.ManageSieveCommand.fromString("authenticate") == .AUTHENTICATE);
    try testing.expect(managesieve.ManageSieveCommand.fromString("Capability") == .CAPABILITY);
    try testing.expect(managesieve.ManageSieveCommand.fromString("logout") == .LOGOUT);
    try testing.expect(managesieve.ManageSieveCommand.fromString("noop") == .NOOP);
    try testing.expect(managesieve.ManageSieveCommand.fromString("putScript") == .PUTSCRIPT);
}

test "RFC 5804: ManageSieveCommand fromString returns null for unknown commands" {
    try testing.expect(managesieve.ManageSieveCommand.fromString("UNKNOWN") == null);
    try testing.expect(managesieve.ManageSieveCommand.fromString("") == null);
    try testing.expect(managesieve.ManageSieveCommand.fromString("QUIT") == null);
    try testing.expect(managesieve.ManageSieveCommand.fromString("DATA") == null);
}

test "RFC 5804: ManageSieveCommand fromString rejects overly long input" {
    try testing.expect(managesieve.ManageSieveCommand.fromString("THISISAVERYLONGCOMMANDNAME") == null);
}

test "RFC 5804: ManageSieveCommand toString round-trips" {
    const commands = [_]managesieve.ManageSieveCommand{
        .AUTHENTICATE, .CAPABILITY, .HAVESPACE, .PUTSCRIPT,
        .LISTSCRIPTS,  .SETACTIVE,  .GETSCRIPT, .DELETESCRIPT,
        .RENAMESCRIPT,  .CHECKSCRIPT, .NOOP,     .LOGOUT,
        .STARTTLS,
    };

    for (commands) |cmd| {
        const name = cmd.toString();
        const parsed = managesieve.ManageSieveCommand.fromString(name);
        try testing.expect(parsed != null);
        try testing.expect(parsed.? == cmd);
    }
}

// =============================================================================
// RFC 5804 Section 2.4: Response Formatting
// =============================================================================

test "RFC 5804: ResponseFormatter.ok produces OK response" {
    const resp = try managesieve.ResponseFormatter.ok(testing.allocator, null, null);
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.startsWith(u8, resp, "OK"));
    try testing.expect(std.mem.endsWith(u8, resp, "\r\n"));
}

test "RFC 5804: ResponseFormatter.ok with response code" {
    const resp = try managesieve.ResponseFormatter.ok(testing.allocator, .ACTIVE, null);
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.indexOf(u8, resp, "OK") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "(ACTIVE)") != null);
}

test "RFC 5804: ResponseFormatter.ok with message" {
    const resp = try managesieve.ResponseFormatter.ok(testing.allocator, null, "Script stored");
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.indexOf(u8, resp, "OK") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "\"Script stored\"") != null);
}

test "RFC 5804: ResponseFormatter.ok with both code and message" {
    const resp = try managesieve.ResponseFormatter.ok(testing.allocator, .ACTIVE, "Done");
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.indexOf(u8, resp, "OK") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "(ACTIVE)") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "\"Done\"") != null);
}

test "RFC 5804: ResponseFormatter.no produces NO response" {
    const resp = try managesieve.ResponseFormatter.no(testing.allocator, null, "Error occurred");
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.startsWith(u8, resp, "NO"));
    try testing.expect(std.mem.indexOf(u8, resp, "\"Error occurred\"") != null);
}

test "RFC 5804: ResponseFormatter.no with response code" {
    const resp = try managesieve.ResponseFormatter.no(testing.allocator, .NONEXISTENT, "Script not found");
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.indexOf(u8, resp, "NO") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "(NONEXISTENT)") != null);
}

test "RFC 5804: ResponseFormatter.bye produces BYE response" {
    const resp = try managesieve.ResponseFormatter.bye(testing.allocator, null, "Goodbye");
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.startsWith(u8, resp, "BYE"));
    try testing.expect(std.mem.indexOf(u8, resp, "\"Goodbye\"") != null);
    try testing.expect(std.mem.endsWith(u8, resp, "\r\n"));
}

// =============================================================================
// RFC 5804 Section 2.5: Response Code Strings
// =============================================================================

test "RFC 5804: ResponseCode toString produces correct strings" {
    try testing.expectEqualStrings("AUTH-TOO-WEAK", managesieve.ResponseCode.AUTH_TOO_WEAK.toString());
    try testing.expectEqualStrings("ENCRYPT-NEEDED", managesieve.ResponseCode.ENCRYPT_NEEDED.toString());
    try testing.expectEqualStrings("QUOTA", managesieve.ResponseCode.QUOTA.toString());
    try testing.expectEqualStrings("QUOTA/MAXSCRIPTS", managesieve.ResponseCode.QUOTA_MAXSCRIPTS.toString());
    try testing.expectEqualStrings("QUOTA/MAXSIZE", managesieve.ResponseCode.QUOTA_MAXSIZE.toString());
    try testing.expectEqualStrings("REFERRAL", managesieve.ResponseCode.REFERRAL.toString());
    try testing.expectEqualStrings("SASL", managesieve.ResponseCode.SASL.toString());
    try testing.expectEqualStrings("TRANSITION-NEEDED", managesieve.ResponseCode.TRANSITION_NEEDED.toString());
    try testing.expectEqualStrings("TRYLATER", managesieve.ResponseCode.TRYLATER.toString());
    try testing.expectEqualStrings("ACTIVE", managesieve.ResponseCode.ACTIVE.toString());
    try testing.expectEqualStrings("NONEXISTENT", managesieve.ResponseCode.NONEXISTENT.toString());
    try testing.expectEqualStrings("ALREADYEXISTS", managesieve.ResponseCode.ALREADYEXISTS.toString());
    try testing.expectEqualStrings("TAG", managesieve.ResponseCode.TAG.toString());
}

// =============================================================================
// RFC 5804 Section 3.1: Capability Generation
// =============================================================================

test "RFC 5804: ManageSieveCapability init from config" {
    const config = managesieve.ManageSieveConfig{
        .implementation_name = "TestSieve v1.0",
        .enable_tls = true,
        .max_redirects = 5,
        .sieve_extensions = "fileinto reject envelope",
    };

    const cap = managesieve.ManageSieveCapability.init(&config);

    try testing.expectEqualStrings("TestSieve v1.0", cap.implementation);
    try testing.expectEqualStrings("PLAIN", cap.sasl_mechanisms);
    try testing.expectEqualStrings("fileinto reject envelope", cap.sieve_extensions);
    try testing.expect(cap.starttls);
    try testing.expectEqualStrings("mailto", cap.notify_methods.?);
    try testing.expectEqual(@as(u32, 5), cap.max_redirects.?);
    try testing.expectEqualStrings("1.0", cap.version);
}

test "RFC 5804: ManageSieveCapability format produces valid output" {
    const config = managesieve.ManageSieveConfig{
        .implementation_name = "TestSieve v1.0",
        .enable_tls = true,
        .max_redirects = 5,
        .sieve_extensions = "fileinto reject",
    };

    const cap = managesieve.ManageSieveCapability.init(&config);
    const output = try cap.format(testing.allocator);
    defer testing.allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "\"IMPLEMENTATION\" \"TestSieve v1.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"SASL\" \"PLAIN\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"SIEVE\" \"fileinto reject\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"STARTTLS\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"NOTIFY\" \"mailto\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"MAXREDIRECTS\" \"5\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"VERSION\" \"1.0\"") != null);
}

test "RFC 5804: ManageSieveCapability without TLS" {
    const config = managesieve.ManageSieveConfig{
        .enable_tls = false,
    };

    const cap = managesieve.ManageSieveCapability.init(&config);
    const output = try cap.format(testing.allocator);
    defer testing.allocator.free(output);

    // Should NOT contain STARTTLS when TLS is disabled
    try testing.expect(std.mem.indexOf(u8, output, "\"STARTTLS\"") == null);
}

// =============================================================================
// RFC 5804 Section 4.2: SASL PLAIN Decoding (RFC 4616)
// =============================================================================

test "RFC 5804: SASL PLAIN decoding valid credentials" {
    // SASL PLAIN format: [authzid] NUL authcid NUL passwd
    // Base64 encode: "\x00user\x00password" -> "AHVzZXIAcGFzc3dvcmQ="
    const b64 = "AHVzZXIAcGFzc3dvcmQ=";
    var creds = (try managesieve.SaslPlainCredentials.decode(testing.allocator, b64)).?;
    defer creds.deinit(testing.allocator);

    try testing.expectEqualStrings("", creds.authzid);
    try testing.expectEqualStrings("user", creds.authcid);
    try testing.expectEqualStrings("password", creds.passwd);
}

test "RFC 5804: SASL PLAIN decoding with authzid" {
    // SASL PLAIN: "admin\x00user\x00pass" -> "YWRtaW4AdXNlcgBwYXNz"
    const b64 = "YWRtaW4AdXNlcgBwYXNz";
    var creds = (try managesieve.SaslPlainCredentials.decode(testing.allocator, b64)).?;
    defer creds.deinit(testing.allocator);

    try testing.expectEqualStrings("admin", creds.authzid);
    try testing.expectEqualStrings("user", creds.authcid);
    try testing.expectEqualStrings("pass", creds.passwd);
}

test "RFC 5804: SASL PLAIN decoding returns null for invalid base64" {
    const result = try managesieve.SaslPlainCredentials.decode(testing.allocator, "!!!invalid!!!");
    try testing.expect(result == null);
}

test "RFC 5804: SASL PLAIN decoding returns null for missing NUL separators" {
    // "noseperators" in base64 has no NUL bytes
    const b64 = "bm9zZXBlcmF0b3Jz";
    const result = try managesieve.SaslPlainCredentials.decode(testing.allocator, b64);
    try testing.expect(result == null);
}

// =============================================================================
// RFC 5804 Section 4.3: String Literal Parsing
// =============================================================================

test "RFC 5804: LiteralParser parses non-synchronizing literal" {
    const input = "{14+}\r\nHello, World!\n";
    const result = managesieve.LiteralParser.parse(input);

    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 14), result.?.length);
    try testing.expect(result.?.non_sync);
}

test "RFC 5804: LiteralParser parses synchronizing literal" {
    const input = "{10}\r\n0123456789";
    const result = managesieve.LiteralParser.parse(input);

    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 10), result.?.length);
    try testing.expect(!result.?.non_sync);
}

test "RFC 5804: LiteralParser returns null for invalid input" {
    try testing.expect(managesieve.LiteralParser.parse("") == null);
    try testing.expect(managesieve.LiteralParser.parse("not a literal") == null);
    try testing.expect(managesieve.LiteralParser.parse("{") == null);
    try testing.expect(managesieve.LiteralParser.parse("{abc}") == null);
    try testing.expect(managesieve.LiteralParser.parse("{10}") == null); // missing CRLF
    try testing.expect(managesieve.LiteralParser.parse("{10}\n") == null); // missing CR
}

test "RFC 5804: LiteralParser zero-length literal" {
    const input = "{0}\r\n";
    const result = managesieve.LiteralParser.parse(input);

    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 0), result.?.length);
}

// =============================================================================
// RFC 5804: ResponseFormatter Literal and Quoted Encoding
// =============================================================================

test "RFC 5804: ResponseFormatter encodeLiteral" {
    const encoded = try managesieve.ResponseFormatter.encodeLiteral(testing.allocator, "Hello World");
    defer testing.allocator.free(encoded);

    // Should produce "{11+}\r\nHello World"
    try testing.expect(std.mem.indexOf(u8, encoded, "{11+}") != null);
    try testing.expect(std.mem.indexOf(u8, encoded, "\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, encoded, "Hello World") != null);
}

test "RFC 5804: ResponseFormatter encodeQuoted" {
    const encoded = try managesieve.ResponseFormatter.encodeQuoted(testing.allocator, "simple");
    defer testing.allocator.free(encoded);

    try testing.expectEqualStrings("\"simple\"", encoded);
}

test "RFC 5804: ResponseFormatter encodeQuoted escapes special characters" {
    const encoded = try managesieve.ResponseFormatter.encodeQuoted(testing.allocator, "back\\slash");
    defer testing.allocator.free(encoded);

    try testing.expect(std.mem.indexOf(u8, encoded, "back\\\\slash") != null);
}

test "RFC 5804: ResponseFormatter encodeQuoted escapes double quotes" {
    const encoded = try managesieve.ResponseFormatter.encodeQuoted(testing.allocator, "say \"hello\"");
    defer testing.allocator.free(encoded);

    try testing.expect(std.mem.indexOf(u8, encoded, "\\\"hello\\\"") != null);
}

// =============================================================================
// RFC 5804: ManageSieveState
// =============================================================================

test "RFC 5804: ManageSieveState enum values" {
    // Verify all states exist and are distinct
    const connected = managesieve.ManageSieveState.connected;
    const tls = managesieve.ManageSieveState.tls_negotiating;
    const auth = managesieve.ManageSieveState.authenticated;
    const closing = managesieve.ManageSieveState.closing;

    try testing.expect(connected != tls);
    try testing.expect(tls != auth);
    try testing.expect(auth != closing);
    try testing.expect(connected != closing);
}

// =============================================================================
// RFC 5804: Configuration Defaults
// =============================================================================

test "RFC 5804: ManageSieveConfig defaults" {
    const config = managesieve.ManageSieveConfig{};

    try testing.expectEqual(@as(u16, 4190), config.port);
    try testing.expectEqual(@as(usize, 100), config.max_connections);
    try testing.expect(config.enable_tls);
    try testing.expect(config.cert_path == null);
    try testing.expect(config.key_path == null);
    try testing.expectEqualStrings("localhost", config.hostname);
    try testing.expectEqual(@as(u64, 1800), config.connection_timeout_seconds);
    try testing.expectEqual(@as(usize, 1024 * 1024), config.max_script_size);
    try testing.expectEqual(@as(usize, 100), config.max_scripts_per_user);
    try testing.expectEqual(@as(u32, 5), config.max_redirects);
}

// =============================================================================
// RFC 5804: Script Size Validation
// =============================================================================

test "RFC 5804: checkScriptSize within limit" {
    try testing.expect(managesieve.checkScriptSize(100, 1024));
    try testing.expect(managesieve.checkScriptSize(1024, 1024));
    try testing.expect(managesieve.checkScriptSize(0, 1024));
}

test "RFC 5804: checkScriptSize exceeding limit" {
    try testing.expect(!managesieve.checkScriptSize(1025, 1024));
    try testing.expect(!managesieve.checkScriptSize(2048, 1024));
}

// =============================================================================
// RFC 5804: SieveScript Struct
// =============================================================================

test "RFC 5804: SieveScript deinit frees resources" {
    var script = managesieve.SieveScript{
        .name = try testing.allocator.dupe(u8, "test_script"),
        .content = try testing.allocator.dupe(u8, "require \"fileinto\";\nfileinto \"INBOX\";"),
        .active = false,
        .size = 36,
        .created_at = 1700000000,
        .modified_at = 1700000000,
    };
    defer script.deinit(testing.allocator);

    try testing.expectEqualStrings("test_script", script.name);
    try testing.expect(!script.active);
}
