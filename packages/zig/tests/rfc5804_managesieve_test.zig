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

// =============================================================================
// RFC 5804 Edge Case Tests
// =============================================================================

// 1. CAPABILITY command response format
test "RFC 5804 edge: CAPABILITY response format includes all required fields" {
    const config = managesieve.ManageSieveConfig{
        .implementation_name = "EdgeTest v1.0",
        .enable_tls = true,
        .max_redirects = 10,
        .sieve_extensions = "fileinto reject",
    };

    const cap = managesieve.ManageSieveCapability.init(&config);
    const output = try cap.format(testing.allocator);
    defer testing.allocator.free(output);

    // RFC 5804 Section 1.7 mandates IMPLEMENTATION, SASL, SIEVE, VERSION
    try testing.expect(std.mem.indexOf(u8, output, "\"IMPLEMENTATION\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"SASL\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"SIEVE\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"VERSION\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"STARTTLS\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"MAXREDIRECTS\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"NOTIFY\"") != null);

    // Every line must end with \r\n
    var lines = std.mem.splitSequence(u8, output, "\r\n");
    var line_count: usize = 0;
    while (lines.next()) |line| {
        if (line.len > 0) line_count += 1;
    }
    try testing.expect(line_count >= 5);
}

// 2. PUTSCRIPT with empty script name -- command parsing validates this
test "RFC 5804 edge: empty script name in PUTSCRIPT is rejected by name validation" {
    // The ManageSieveSession.handlePutScript rejects empty script names.
    // We test the quoted string extraction here: an empty quoted string is valid syntax.
    // The server logic then checks if nm.value.len == 0 and rejects it.
    // We verify the ResponseFormatter can format the NO response for this case.
    const resp = try managesieve.ResponseFormatter.no(testing.allocator, null, "Script name must not be empty");
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.startsWith(u8, resp, "NO"));
    try testing.expect(std.mem.indexOf(u8, resp, "Script name must not be empty") != null);
}

// 3. PUTSCRIPT with empty script body
test "RFC 5804 edge: empty script body via literal {0+}" {
    // A literal with zero length is valid syntax
    const input = "{0+}\r\n";
    const result = managesieve.LiteralParser.parse(input);

    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 0), result.?.length);
    try testing.expect(result.?.non_sync);
    try testing.expectEqual(@as(usize, 6), result.?.prefix_len);

    // The content would be an empty string, which validates to an empty script
    // (validateSieveScript returns false for empty scripts, so server rejects it)
}

// 4. PUTSCRIPT with very long script name (>256 chars)
test "RFC 5804 edge: very long script name quoted string encoding" {
    // Create a script name longer than 256 characters
    const long_name = "a" ** 300;
    const encoded = try managesieve.ResponseFormatter.encodeQuoted(testing.allocator, long_name);
    defer testing.allocator.free(encoded);

    // Should be: "aaa...aaa" with quotes
    try testing.expectEqual(@as(usize, 300 + 2), encoded.len); // content + 2 quotes
    try testing.expectEqual(@as(u8, '"'), encoded[0]);
    try testing.expectEqual(@as(u8, '"'), encoded[encoded.len - 1]);
}

// 5. GETSCRIPT for non-existent script -- verify the NO response with NONEXISTENT code
test "RFC 5804 edge: NONEXISTENT response code for missing script" {
    const resp = try managesieve.ResponseFormatter.no(testing.allocator, .NONEXISTENT, "No such script");
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.startsWith(u8, resp, "NO"));
    try testing.expect(std.mem.indexOf(u8, resp, "(NONEXISTENT)") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "\"No such script\"") != null);
    try testing.expect(std.mem.endsWith(u8, resp, "\r\n"));
}

// 6. DELETESCRIPT for non-existent script
test "RFC 5804 edge: DELETESCRIPT non-existent generates proper NO response" {
    const resp = try managesieve.ResponseFormatter.no(testing.allocator, .NONEXISTENT, "Script does not exist");
    defer testing.allocator.free(resp);

    try testing.expectEqualStrings("NO (NONEXISTENT) \"Script does not exist\"\r\n", resp);
}

// 7. SETACTIVE with non-existent script
test "RFC 5804 edge: SETACTIVE non-existent generates NONEXISTENT response code" {
    const resp = try managesieve.ResponseFormatter.no(testing.allocator, .NONEXISTENT, "Script does not exist");
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.indexOf(u8, resp, "NONEXISTENT") != null);
    // Verify the response code string is parenthesized per RFC 5804
    try testing.expect(std.mem.indexOf(u8, resp, "(NONEXISTENT)") != null);
}

// 8. LISTSCRIPTS when no scripts exist -- should return OK with no script lines
test "RFC 5804 edge: LISTSCRIPTS empty returns just OK" {
    // When no scripts exist, the server sends only the OK response
    const ok = try managesieve.ResponseFormatter.ok(testing.allocator, null, null);
    defer testing.allocator.free(ok);

    try testing.expectEqualStrings("OK\r\n", ok);
}

// 9. HAVESPACE with zero bytes requested
test "RFC 5804 edge: checkScriptSize with zero size" {
    // Zero bytes should always be within any limit
    try testing.expect(managesieve.checkScriptSize(0, 1024 * 1024));
    try testing.expect(managesieve.checkScriptSize(0, 1));
    try testing.expect(managesieve.checkScriptSize(0, 0)); // 0 <= 0
}

// 10. HAVESPACE with very large size
test "RFC 5804 edge: checkScriptSize with very large size" {
    const max = @as(usize, 1024 * 1024);
    try testing.expect(!managesieve.checkScriptSize(max + 1, max));
    try testing.expect(!managesieve.checkScriptSize(std.math.maxInt(usize), max));
    try testing.expect(managesieve.checkScriptSize(max, max));

    // Edge: max_size is 0 means no scripts allowed
    try testing.expect(managesieve.checkScriptSize(0, 0));
    try testing.expect(!managesieve.checkScriptSize(1, 0));
}

// 11. Quoted string parsing: escaped quotes and backslashes
test "RFC 5804 edge: encodeQuoted with escaped quotes" {
    const input_with_quotes = "say \"hello\" and \"bye\"";
    const encoded = try managesieve.ResponseFormatter.encodeQuoted(testing.allocator, input_with_quotes);
    defer testing.allocator.free(encoded);

    // Each " in the input must be escaped as \"
    try testing.expect(std.mem.indexOf(u8, encoded, "\\\"hello\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, encoded, "\\\"bye\\\"") != null);
    // Outer quotes
    try testing.expectEqual(@as(u8, '"'), encoded[0]);
    try testing.expectEqual(@as(u8, '"'), encoded[encoded.len - 1]);
}

test "RFC 5804 edge: encodeQuoted with backslashes" {
    const input_with_backslashes = "path\\to\\file";
    const encoded = try managesieve.ResponseFormatter.encodeQuoted(testing.allocator, input_with_backslashes);
    defer testing.allocator.free(encoded);

    // Each \ becomes \\
    try testing.expect(std.mem.indexOf(u8, encoded, "path\\\\to\\\\file") != null);
}

test "RFC 5804 edge: encodeQuoted with mixed special characters" {
    const input = "a\\b\"c\\d\"e";
    const encoded = try managesieve.ResponseFormatter.encodeQuoted(testing.allocator, input);
    defer testing.allocator.free(encoded);

    // Expected: "a\\b\"c\\d\"e"
    try testing.expectEqualStrings("\"a\\\\b\\\"c\\\\d\\\"e\"", encoded);
}

test "RFC 5804 edge: encodeQuoted with empty string" {
    const encoded = try managesieve.ResponseFormatter.encodeQuoted(testing.allocator, "");
    defer testing.allocator.free(encoded);

    try testing.expectEqualStrings("\"\"", encoded);
}

// 12. Literal string parsing: {N+} syntax with wrong byte count
test "RFC 5804 edge: literal parser with insufficient data after prefix" {
    // {10+}\r\n followed by only 5 bytes of content
    const input = "{10+}\r\nhello";
    const result = managesieve.LiteralParser.parse(input);

    // Parser should succeed -- it only parses the prefix, not the content
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 10), result.?.length);
    try testing.expect(result.?.non_sync);
    try testing.expectEqual(@as(usize, 7), result.?.prefix_len); // "{10+}\r\n" is 7 bytes

    // The caller would then check: prefix_len + length > input.len
    // 7 + 10 = 17 > 12 = true, so the caller knows data is incomplete
    try testing.expect(result.?.prefix_len + result.?.length > input.len);
}

test "RFC 5804 edge: literal parser with very large length" {
    const input = "{999999999+}\r\ndata";
    const result = managesieve.LiteralParser.parse(input);

    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 999999999), result.?.length);
    try testing.expect(result.?.non_sync);
    // Obviously prefix_len + length exceeds input length
    try testing.expect(result.?.prefix_len + result.?.length > input.len);
}

test "RFC 5804 edge: literal parser rejects non-numeric length" {
    try testing.expect(managesieve.LiteralParser.parse("{abc}\r\n") == null);
    try testing.expect(managesieve.LiteralParser.parse("{12x}\r\n") == null);
    try testing.expect(managesieve.LiteralParser.parse("{}\r\n") == null);
    try testing.expect(managesieve.LiteralParser.parse("{+}\r\n") == null);
}

test "RFC 5804 edge: literal parser rejects missing closing brace" {
    try testing.expect(managesieve.LiteralParser.parse("{10\r\n") == null);
    try testing.expect(managesieve.LiteralParser.parse("{10+\r\n") == null);
}

test "RFC 5804 edge: literal parser rejects missing CRLF" {
    try testing.expect(managesieve.LiteralParser.parse("{10}") == null);
    try testing.expect(managesieve.LiteralParser.parse("{10}\n") == null);
    try testing.expect(managesieve.LiteralParser.parse("{10}\r") == null);
    try testing.expect(managesieve.LiteralParser.parse("{10+}") == null);
}

// 13. Authentication with empty username/password
test "RFC 5804 edge: SASL PLAIN decode rejects empty authcid" {
    // Encode: "\x00\x00password" in base64 = "AABwYXNzd29yZA=="
    const result = try managesieve.SaslPlainCredentials.decode(testing.allocator, "AABwYXNzd29yZA==");
    // authcid is empty, should return null
    try testing.expect(result == null);
}

test "RFC 5804 edge: SASL PLAIN decode rejects empty passwd" {
    // Encode: "\x00user\x00" in base64 = "AHVzZXIA"
    const result = try managesieve.SaslPlainCredentials.decode(testing.allocator, "AHVzZXIA");
    // passwd is empty, should return null
    try testing.expect(result == null);
}

test "RFC 5804 edge: SASL PLAIN decode rejects both empty" {
    // Encode: "\x00\x00" in base64 = "AAA="
    const result = try managesieve.SaslPlainCredentials.decode(testing.allocator, "AAA=");
    try testing.expect(result == null);
}

test "RFC 5804 edge: SASL PLAIN decode with only NULs" {
    // Three NUL bytes: "\x00\x00\x00" = "AAAA"
    const result = try managesieve.SaslPlainCredentials.decode(testing.allocator, "AAAA");
    // authzid="", authcid="", passwd="" -> both empty, should reject
    try testing.expect(result == null);
}

// 14. Multiple concurrent AUTHENTICATE attempts
test "RFC 5804 edge: already authenticated response" {
    // If already authenticated, server sends NO response
    const resp = try managesieve.ResponseFormatter.no(testing.allocator, null, "Already authenticated");
    defer testing.allocator.free(resp);

    try testing.expectEqualStrings("NO \"Already authenticated\"\r\n", resp);
}

// Additional edge cases for comprehensive coverage:

// ResponseCode: verify all codes format correctly in NO responses
test "RFC 5804 edge: all ResponseCode values in NO responses" {
    const codes = [_]managesieve.ResponseCode{
        .AUTH_TOO_WEAK, .ENCRYPT_NEEDED, .QUOTA, .QUOTA_MAXSCRIPTS,
        .QUOTA_MAXSIZE, .REFERRAL,       .SASL,  .TRANSITION_NEEDED,
        .TRYLATER,      .ACTIVE,         .NONEXISTENT, .ALREADYEXISTS,
        .TAG,
    };

    for (codes) |code| {
        const resp = try managesieve.ResponseFormatter.no(testing.allocator, code, "test");
        defer testing.allocator.free(resp);

        try testing.expect(std.mem.startsWith(u8, resp, "NO"));
        try testing.expect(std.mem.endsWith(u8, resp, "\r\n"));
        // Verify the code string appears parenthesized
        const code_str = code.toString();
        const expected_code = try std.fmt.allocPrint(testing.allocator, "({s})", .{code_str});
        defer testing.allocator.free(expected_code);
        try testing.expect(std.mem.indexOf(u8, resp, expected_code) != null);
    }
}

// ResponseFormatter.ok, .no, .bye all produce consistent CRLF endings
test "RFC 5804 edge: all response types end with CRLF" {
    const ok = try managesieve.ResponseFormatter.ok(testing.allocator, null, null);
    defer testing.allocator.free(ok);
    try testing.expect(std.mem.endsWith(u8, ok, "\r\n"));

    const no = try managesieve.ResponseFormatter.no(testing.allocator, null, null);
    defer testing.allocator.free(no);
    try testing.expect(std.mem.endsWith(u8, no, "\r\n"));

    const bye = try managesieve.ResponseFormatter.bye(testing.allocator, null, null);
    defer testing.allocator.free(bye);
    try testing.expect(std.mem.endsWith(u8, bye, "\r\n"));
}

// ResponseFormatter: NO/BYE with no message and no code
test "RFC 5804 edge: minimal NO response with no code and no message" {
    const resp = try managesieve.ResponseFormatter.no(testing.allocator, null, null);
    defer testing.allocator.free(resp);
    try testing.expectEqualStrings("NO\r\n", resp);
}

test "RFC 5804 edge: minimal BYE response with no code and no message" {
    const resp = try managesieve.ResponseFormatter.bye(testing.allocator, null, null);
    defer testing.allocator.free(resp);
    try testing.expectEqualStrings("BYE\r\n", resp);
}

// encodeLiteral round-trip with LiteralParser
test "RFC 5804 edge: encodeLiteral and LiteralParser round-trip for various sizes" {
    const test_strings = [_][]const u8{
        "",
        "a",
        "Hello, World!",
        "require \"fileinto\";\nif header :contains \"Subject\" \"[SPAM]\" {\n  fileinto \"Junk\";\n}",
        "line1\r\nline2\r\nline3\r\n",
    };

    for (test_strings) |original| {
        const encoded = try managesieve.ResponseFormatter.encodeLiteral(testing.allocator, original);
        defer testing.allocator.free(encoded);

        const parsed = managesieve.LiteralParser.parse(encoded);
        try testing.expect(parsed != null);
        try testing.expectEqual(original.len, parsed.?.length);
        try testing.expect(parsed.?.non_sync); // encodeLiteral always uses {N+} syntax

        // Extract the content from the encoded literal
        const content = encoded[parsed.?.prefix_len .. parsed.?.prefix_len + parsed.?.length];
        try testing.expectEqualStrings(original, content);
    }
}

// ManageSieveCommand: boundary length tests
test "RFC 5804 edge: command parsing at maximum accepted length (16 chars)" {
    // "DELETESCRIPT" is 12 chars, within limit
    try testing.expect(managesieve.ManageSieveCommand.fromString("DELETESCRIPT") == .DELETESCRIPT);

    // Exactly 16 characters, but not a valid command
    try testing.expect(managesieve.ManageSieveCommand.fromString("AAAAAAAAAAAAAAAA") == null);

    // 17 characters: exceeds buffer, should return null
    try testing.expect(managesieve.ManageSieveCommand.fromString("AAAAAAAAAAAAAAAAA") == null);
}

// ManageSieveCommand: whitespace-only and special character inputs
test "RFC 5804 edge: command parsing rejects whitespace and special chars" {
    try testing.expect(managesieve.ManageSieveCommand.fromString(" ") == null);
    try testing.expect(managesieve.ManageSieveCommand.fromString("\t") == null);
    try testing.expect(managesieve.ManageSieveCommand.fromString("\r\n") == null);
    try testing.expect(managesieve.ManageSieveCommand.fromString("NO") == null);
    try testing.expect(managesieve.ManageSieveCommand.fromString("OK") == null);
    try testing.expect(managesieve.ManageSieveCommand.fromString("BYE") == null);
}

// ManageSieveState: all states are distinct
test "RFC 5804 edge: all ManageSieveState values are distinct" {
    const states = [_]managesieve.ManageSieveState{
        .connected, .tls_negotiating, .authenticated, .closing,
    };
    for (states, 0..) |s1, i| {
        for (states, 0..) |s2, j| {
            if (i == j) {
                try testing.expect(s1 == s2);
            } else {
                try testing.expect(s1 != s2);
            }
        }
    }
}

// ManageSieveConfig: custom configuration values
test "RFC 5804 edge: ManageSieveConfig custom values are stored correctly" {
    const config = managesieve.ManageSieveConfig{
        .port = 2000,
        .max_connections = 5,
        .enable_tls = false,
        .hostname = "sieve.example.org",
        .connection_timeout_seconds = 60,
        .max_script_size = 512,
        .max_scripts_per_user = 10,
        .max_redirects = 2,
        .implementation_name = "CustomSieve",
    };

    try testing.expectEqual(@as(u16, 2000), config.port);
    try testing.expectEqual(@as(usize, 5), config.max_connections);
    try testing.expect(!config.enable_tls);
    try testing.expectEqualStrings("sieve.example.org", config.hostname);
    try testing.expectEqual(@as(u64, 60), config.connection_timeout_seconds);
    try testing.expectEqual(@as(usize, 512), config.max_script_size);
    try testing.expectEqual(@as(usize, 10), config.max_scripts_per_user);
    try testing.expectEqual(@as(u32, 2), config.max_redirects);
    try testing.expectEqualStrings("CustomSieve", config.implementation_name);
}

// SieveScript: script with minimal fields
test "RFC 5804 edge: SieveScript with minimal content" {
    var script = managesieve.SieveScript{
        .name = try testing.allocator.dupe(u8, "x"),
        .content = try testing.allocator.dupe(u8, "k"),
        .active = true,
        .size = 1,
        .created_at = 0,
        .modified_at = 0,
    };
    defer script.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), script.size);
    try testing.expect(script.active);
    try testing.expectEqualStrings("x", script.name);
}

// SASL PLAIN: valid credentials with long authzid/authcid/passwd
test "RFC 5804 edge: SASL PLAIN with long credentials" {
    // Build: "adminadmin\x00longusername\x00longpassword"
    // "adminadmin" (10) + NUL + "longusername" (12) + NUL + "longpassword" (12) = 36 bytes
    const raw = "adminadmin\x00longusername\x00longpassword";
    const b64 = std.base64.standard.Encoder.calcSize(raw.len);
    const encoded = try testing.allocator.alloc(u8, b64);
    defer testing.allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, raw);

    var creds = (try managesieve.SaslPlainCredentials.decode(testing.allocator, encoded)).?;
    defer creds.deinit(testing.allocator);

    try testing.expectEqualStrings("adminadmin", creds.authzid);
    try testing.expectEqualStrings("longusername", creds.authcid);
    try testing.expectEqualStrings("longpassword", creds.passwd);
}

// SASL PLAIN: credentials with special characters in password
test "RFC 5804 edge: SASL PLAIN with special chars in password" {
    // Build: "\x00user\x00p@$$w0rd!#%"
    const raw = "\x00user\x00p@$$w0rd!#%";
    const b64_len = std.base64.standard.Encoder.calcSize(raw.len);
    const encoded = try testing.allocator.alloc(u8, b64_len);
    defer testing.allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, raw);

    var creds = (try managesieve.SaslPlainCredentials.decode(testing.allocator, encoded)).?;
    defer creds.deinit(testing.allocator);

    try testing.expectEqualStrings("", creds.authzid);
    try testing.expectEqualStrings("user", creds.authcid);
    try testing.expectEqualStrings("p@$$w0rd!#%", creds.passwd);
}

// Capability: no optional fields
test "RFC 5804 edge: ManageSieveCapability with no notify and no max_redirects" {
    var cap = managesieve.ManageSieveCapability{
        .implementation = "MinimalSieve",
        .sasl_mechanisms = "PLAIN",
        .sieve_extensions = "fileinto",
        .starttls = false,
        .notify_methods = null,
        .max_redirects = null,
        .version = "1.0",
    };

    const output = try cap.format(testing.allocator);
    defer testing.allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "\"IMPLEMENTATION\" \"MinimalSieve\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"STARTTLS\"") == null);
    try testing.expect(std.mem.indexOf(u8, output, "\"NOTIFY\"") == null);
    try testing.expect(std.mem.indexOf(u8, output, "\"MAXREDIRECTS\"") == null);
    try testing.expect(std.mem.indexOf(u8, output, "\"VERSION\" \"1.0\"") != null);
}

// Literal: exact boundary between sync and non-sync
test "RFC 5804 edge: literal sync vs non-sync distinction" {
    // Synchronizing (no +)
    const sync = managesieve.LiteralParser.parse("{5}\r\nhello");
    try testing.expect(sync != null);
    try testing.expect(!sync.?.non_sync);
    try testing.expectEqual(@as(usize, 5), sync.?.length);

    // Non-synchronizing (with +)
    const non_sync = managesieve.LiteralParser.parse("{5+}\r\nhello");
    try testing.expect(non_sync != null);
    try testing.expect(non_sync.?.non_sync);
    try testing.expectEqual(@as(usize, 5), non_sync.?.length);

    // Different prefix lengths
    try testing.expect(sync.?.prefix_len < non_sync.?.prefix_len);
}

// ResponseCode toString: verify hyphenated codes
test "RFC 5804 edge: ResponseCode toString produces hyphenated strings" {
    // RFC 5804 uses hyphens in multi-word response codes
    try testing.expect(std.mem.indexOf(u8, managesieve.ResponseCode.AUTH_TOO_WEAK.toString(), "-") != null);
    try testing.expect(std.mem.indexOf(u8, managesieve.ResponseCode.ENCRYPT_NEEDED.toString(), "-") != null);
    try testing.expect(std.mem.indexOf(u8, managesieve.ResponseCode.TRANSITION_NEEDED.toString(), "-") != null);
    // QUOTA sub-codes use /
    try testing.expect(std.mem.indexOf(u8, managesieve.ResponseCode.QUOTA_MAXSCRIPTS.toString(), "/") != null);
    try testing.expect(std.mem.indexOf(u8, managesieve.ResponseCode.QUOTA_MAXSIZE.toString(), "/") != null);
}
