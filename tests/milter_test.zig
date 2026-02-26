// Milter (Mail Filter Protocol) Test Suite
// Tests for the Sendmail milter binary protocol implementation.
// Reference: https://www.postfix.org/MILTER_README.html

const std = @import("std");
const testing = std.testing;
const milter = @import("mail").milter;

// =============================================================================
// Milter Command Byte Values
// =============================================================================

test "Milter: command byte values match SMFIC constants" {
    try testing.expectEqual(@as(u8, 'A'), @intFromEnum(milter.MilterCommand.abort));
    try testing.expectEqual(@as(u8, 'B'), @intFromEnum(milter.MilterCommand.body));
    try testing.expectEqual(@as(u8, 'C'), @intFromEnum(milter.MilterCommand.connect));
    try testing.expectEqual(@as(u8, 'D'), @intFromEnum(milter.MilterCommand.macro));
    try testing.expectEqual(@as(u8, 'E'), @intFromEnum(milter.MilterCommand.end_of_body));
    try testing.expectEqual(@as(u8, 'H'), @intFromEnum(milter.MilterCommand.helo));
    try testing.expectEqual(@as(u8, 'L'), @intFromEnum(milter.MilterCommand.header));
    try testing.expectEqual(@as(u8, 'N'), @intFromEnum(milter.MilterCommand.end_of_headers));
    try testing.expectEqual(@as(u8, 'M'), @intFromEnum(milter.MilterCommand.mail_from));
    try testing.expectEqual(@as(u8, 'O'), @intFromEnum(milter.MilterCommand.option_negotiation));
    try testing.expectEqual(@as(u8, 'Q'), @intFromEnum(milter.MilterCommand.quit));
    try testing.expectEqual(@as(u8, 'R'), @intFromEnum(milter.MilterCommand.rcpt_to));
    try testing.expectEqual(@as(u8, 'T'), @intFromEnum(milter.MilterCommand.data));
    try testing.expectEqual(@as(u8, 'K'), @intFromEnum(milter.MilterCommand.quit_new_connection));
    try testing.expectEqual(@as(u8, 'U'), @intFromEnum(milter.MilterCommand.unknown));
}

test "Milter: MilterCommand fromByte valid bytes" {
    try testing.expect(milter.MilterCommand.fromByte('A') == .abort);
    try testing.expect(milter.MilterCommand.fromByte('B') == .body);
    try testing.expect(milter.MilterCommand.fromByte('C') == .connect);
    try testing.expect(milter.MilterCommand.fromByte('Q') == .quit);
    try testing.expect(milter.MilterCommand.fromByte('O') == .option_negotiation);
}

test "Milter: MilterCommand fromByte invalid byte returns null" {
    try testing.expect(milter.MilterCommand.fromByte(0) == null);
    try testing.expect(milter.MilterCommand.fromByte('X') == null);
    try testing.expect(milter.MilterCommand.fromByte('Z') == null);
    try testing.expect(milter.MilterCommand.fromByte(0xFF) == null);
}

test "Milter: MilterCommand toString returns SMFIC names" {
    try testing.expectEqualStrings("SMFIC_ABORT", milter.MilterCommand.abort.toString());
    try testing.expectEqualStrings("SMFIC_BODY", milter.MilterCommand.body.toString());
    try testing.expectEqualStrings("SMFIC_CONNECT", milter.MilterCommand.connect.toString());
    try testing.expectEqualStrings("SMFIC_MACRO", milter.MilterCommand.macro.toString());
    try testing.expectEqualStrings("SMFIC_BODYEOB", milter.MilterCommand.end_of_body.toString());
    try testing.expectEqualStrings("SMFIC_HELO", milter.MilterCommand.helo.toString());
    try testing.expectEqualStrings("SMFIC_HEADER", milter.MilterCommand.header.toString());
    try testing.expectEqualStrings("SMFIC_EOH", milter.MilterCommand.end_of_headers.toString());
    try testing.expectEqualStrings("SMFIC_MAIL", milter.MilterCommand.mail_from.toString());
    try testing.expectEqualStrings("SMFIC_OPTNEG", milter.MilterCommand.option_negotiation.toString());
    try testing.expectEqualStrings("SMFIC_QUIT", milter.MilterCommand.quit.toString());
    try testing.expectEqualStrings("SMFIC_RCPT", milter.MilterCommand.rcpt_to.toString());
    try testing.expectEqualStrings("SMFIC_DATA", milter.MilterCommand.data.toString());
    try testing.expectEqualStrings("SMFIC_QUIT_NC", milter.MilterCommand.quit_new_connection.toString());
    try testing.expectEqualStrings("SMFIC_UNKNOWN", milter.MilterCommand.unknown.toString());
}

// =============================================================================
// Milter Response Types
// =============================================================================

test "Milter: response byte values match SMFIR constants" {
    try testing.expectEqual(@as(u8, '+'), @intFromEnum(milter.MilterResponse.add_recipient));
    try testing.expectEqual(@as(u8, '-'), @intFromEnum(milter.MilterResponse.delete_recipient));
    try testing.expectEqual(@as(u8, 'a'), @intFromEnum(milter.MilterResponse.accept));
    try testing.expectEqual(@as(u8, 'b'), @intFromEnum(milter.MilterResponse.replace_body));
    try testing.expectEqual(@as(u8, 'c'), @intFromEnum(milter.MilterResponse.@"continue"));
    try testing.expectEqual(@as(u8, 'd'), @intFromEnum(milter.MilterResponse.discard));
    try testing.expectEqual(@as(u8, 'h'), @intFromEnum(milter.MilterResponse.add_header));
    try testing.expectEqual(@as(u8, 'i'), @intFromEnum(milter.MilterResponse.insert_header));
    try testing.expectEqual(@as(u8, 'm'), @intFromEnum(milter.MilterResponse.change_header));
    try testing.expectEqual(@as(u8, 'p'), @intFromEnum(milter.MilterResponse.progress));
    try testing.expectEqual(@as(u8, 'q'), @intFromEnum(milter.MilterResponse.quarantine));
    try testing.expectEqual(@as(u8, 'r'), @intFromEnum(milter.MilterResponse.reject));
    try testing.expectEqual(@as(u8, 't'), @intFromEnum(milter.MilterResponse.temp_fail));
    try testing.expectEqual(@as(u8, 'y'), @intFromEnum(milter.MilterResponse.reply_code));
    try testing.expectEqual(@as(u8, 's'), @intFromEnum(milter.MilterResponse.skip));
    try testing.expectEqual(@as(u8, 'e'), @intFromEnum(milter.MilterResponse.change_from));
    try testing.expectEqual(@as(u8, '2'), @intFromEnum(milter.MilterResponse.add_recipient_par));
    try testing.expectEqual(@as(u8, 'O'), @intFromEnum(milter.MilterResponse.option_negotiation));
}

test "Milter: MilterResponse fromByte valid bytes" {
    try testing.expect(milter.MilterResponse.fromByte('a') == .accept);
    try testing.expect(milter.MilterResponse.fromByte('c') == .@"continue");
    try testing.expect(milter.MilterResponse.fromByte('r') == .reject);
    try testing.expect(milter.MilterResponse.fromByte('d') == .discard);
    try testing.expect(milter.MilterResponse.fromByte('t') == .temp_fail);
}

test "Milter: MilterResponse fromByte invalid byte returns null" {
    try testing.expect(milter.MilterResponse.fromByte(0) == null);
    try testing.expect(milter.MilterResponse.fromByte('X') == null);
    try testing.expect(milter.MilterResponse.fromByte(0xFF) == null);
}

test "Milter: MilterResponse isFinalAction" {
    // Final actions
    try testing.expect(milter.MilterResponse.accept.isFinalAction());
    try testing.expect(milter.MilterResponse.reject.isFinalAction());
    try testing.expect(milter.MilterResponse.discard.isFinalAction());
    try testing.expect(milter.MilterResponse.temp_fail.isFinalAction());
    try testing.expect(milter.MilterResponse.reply_code.isFinalAction());

    // Non-final
    try testing.expect(!milter.MilterResponse.@"continue".isFinalAction());
    try testing.expect(!milter.MilterResponse.progress.isFinalAction());
    try testing.expect(!milter.MilterResponse.add_header.isFinalAction());
    try testing.expect(!milter.MilterResponse.skip.isFinalAction());
}

test "Milter: MilterResponse isModification" {
    // Modifications
    try testing.expect(milter.MilterResponse.add_recipient.isModification());
    try testing.expect(milter.MilterResponse.delete_recipient.isModification());
    try testing.expect(milter.MilterResponse.replace_body.isModification());
    try testing.expect(milter.MilterResponse.add_header.isModification());
    try testing.expect(milter.MilterResponse.insert_header.isModification());
    try testing.expect(milter.MilterResponse.change_header.isModification());
    try testing.expect(milter.MilterResponse.quarantine.isModification());
    try testing.expect(milter.MilterResponse.change_from.isModification());
    try testing.expect(milter.MilterResponse.add_recipient_par.isModification());

    // Non-modifications
    try testing.expect(!milter.MilterResponse.accept.isModification());
    try testing.expect(!milter.MilterResponse.reject.isModification());
    try testing.expect(!milter.MilterResponse.@"continue".isModification());
    try testing.expect(!milter.MilterResponse.progress.isModification());
}

test "Milter: MilterResponse toString returns SMFIR names" {
    try testing.expectEqualStrings("SMFIR_ACCEPT", milter.MilterResponse.accept.toString());
    try testing.expectEqualStrings("SMFIR_REJECT", milter.MilterResponse.reject.toString());
    try testing.expectEqualStrings("SMFIR_CONTINUE", milter.MilterResponse.@"continue".toString());
    try testing.expectEqualStrings("SMFIR_DISCARD", milter.MilterResponse.discard.toString());
    try testing.expectEqualStrings("SMFIR_TEMPFAIL", milter.MilterResponse.temp_fail.toString());
    try testing.expectEqualStrings("SMFIR_QUARANTINE", milter.MilterResponse.quarantine.toString());
}

// =============================================================================
// Milter Action Flags
// =============================================================================

test "Milter: MilterActions.none has no flags set" {
    const flags = milter.MilterActions.none;
    try testing.expect(!flags.add_headers);
    try testing.expect(!flags.change_body);
    try testing.expect(!flags.add_recipients);
    try testing.expect(!flags.delete_recipients);
    try testing.expect(!flags.change_headers);
    try testing.expect(!flags.quarantine);
    try testing.expect(!flags.change_from);
    try testing.expect(!flags.add_recipients_par);
    try testing.expect(!flags.set_symbol_list);
}

test "Milter: MilterActions.all has all flags set" {
    const flags = milter.MilterActions.all;
    try testing.expect(flags.add_headers);
    try testing.expect(flags.change_body);
    try testing.expect(flags.add_recipients);
    try testing.expect(flags.delete_recipients);
    try testing.expect(flags.change_headers);
    try testing.expect(flags.quarantine);
    try testing.expect(flags.change_from);
    try testing.expect(flags.add_recipients_par);
    try testing.expect(flags.set_symbol_list);
}

test "Milter: MilterActions merge (union)" {
    const a = milter.MilterActions{ .add_headers = true };
    const b = milter.MilterActions{ .change_body = true };
    const merged = a.merge(b);

    try testing.expect(merged.add_headers);
    try testing.expect(merged.change_body);
    try testing.expect(!merged.quarantine);
}

test "Milter: MilterActions intersect" {
    const a = milter.MilterActions{ .add_headers = true, .change_body = true };
    const b = milter.MilterActions{ .change_body = true, .quarantine = true };
    const intersection = a.intersect(b);

    try testing.expect(!intersection.add_headers);
    try testing.expect(intersection.change_body);
    try testing.expect(!intersection.quarantine);
}

test "Milter: MilterActions hasAll" {
    const all = milter.MilterActions.all;
    const some = milter.MilterActions{ .add_headers = true, .change_body = true };

    try testing.expect(all.hasAll(some));
    try testing.expect(!some.hasAll(all));
    try testing.expect(some.hasAll(milter.MilterActions.none));
}

test "Milter: MilterActions toNetworkU32 and fromU32 round-trip" {
    const original = milter.MilterActions{ .add_headers = true, .quarantine = true };
    const encoded = original.toNetworkU32();
    const decoded = milter.MilterActions.fromU32(encoded);

    try testing.expect(decoded.add_headers);
    try testing.expect(decoded.quarantine);
    try testing.expect(!decoded.change_body);
}

// =============================================================================
// Milter Protocol Flags
// =============================================================================

test "Milter: MilterProtocol.all_callbacks has no skip flags" {
    const flags = milter.MilterProtocol.all_callbacks;
    try testing.expect(!flags.no_connect);
    try testing.expect(!flags.no_helo);
    try testing.expect(!flags.no_mail);
    try testing.expect(!flags.no_rcpt);
    try testing.expect(!flags.no_body);
    try testing.expect(!flags.no_headers);
    try testing.expect(!flags.no_eoh);
}

test "Milter: MilterProtocol.minimal skips most callbacks" {
    const flags = milter.MilterProtocol.minimal;
    try testing.expect(flags.no_connect);
    try testing.expect(flags.no_helo);
    try testing.expect(flags.no_mail);
    try testing.expect(flags.no_rcpt);
    try testing.expect(flags.no_body);
    try testing.expect(flags.no_headers);
    try testing.expect(flags.no_eoh);
}

test "Milter: MilterProtocol merge and intersect" {
    const a = milter.MilterProtocol{ .no_connect = true, .no_helo = true };
    const b = milter.MilterProtocol{ .no_helo = true, .no_body = true };

    const merged = a.merge(b);
    try testing.expect(merged.no_connect);
    try testing.expect(merged.no_helo);
    try testing.expect(merged.no_body);

    const inter = a.intersect(b);
    try testing.expect(!inter.no_connect);
    try testing.expect(inter.no_helo);
    try testing.expect(!inter.no_body);
}

test "Milter: MilterProtocol toNetworkU32 and fromU32 round-trip" {
    const original = milter.MilterProtocol{ .no_connect = true, .no_body = true, .skip = true };
    const encoded = original.toNetworkU32();
    const decoded = milter.MilterProtocol.fromU32(encoded);

    try testing.expect(decoded.no_connect);
    try testing.expect(decoded.no_body);
    try testing.expect(decoded.skip);
    try testing.expect(!decoded.no_helo);
}

// =============================================================================
// Milter Packet Encoding
// =============================================================================

test "Milter: packet encoding command-only" {
    const pkt = milter.MilterPacket.commandOnly(.quit);

    try testing.expectEqual(@as(u8, 'Q'), pkt.command);
    try testing.expectEqual(@as(usize, 0), pkt.data.len);
    try testing.expectEqual(@as(usize, 5), pkt.encodedLen());

    var buf: [64]u8 = undefined;
    const encoded = try pkt.encode(&buf);

    // Length field = 1 (command only, no data)
    const payload_len = std.mem.readInt(u32, encoded[0..4], .big);
    try testing.expectEqual(@as(u32, 1), payload_len);
    try testing.expectEqual(@as(u8, 'Q'), encoded[4]);
}

test "Milter: packet encoding with data" {
    const data = "test body content";
    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.body),
        .data = data,
    };

    try testing.expectEqual(@as(usize, 4 + 1 + data.len), pkt.encodedLen());

    var buf: [256]u8 = undefined;
    const encoded = try pkt.encode(&buf);

    const payload_len = std.mem.readInt(u32, encoded[0..4], .big);
    try testing.expectEqual(@as(u32, 1 + data.len), payload_len);
    try testing.expectEqual(@as(u8, 'B'), encoded[4]);
    try testing.expectEqualStrings(data, encoded[5 .. 5 + data.len]);
}

test "Milter: packet encoding fails with buffer too small" {
    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.body),
        .data = "some data",
    };

    var small_buf: [3]u8 = undefined;
    const result = pkt.encode(&small_buf);
    try testing.expectError(error.BufferTooSmall, result);
}

test "Milter: packet encodeAlloc" {
    const pkt = milter.MilterPacket.commandOnly(.abort);
    const encoded = try pkt.encodeAlloc(testing.allocator);
    defer testing.allocator.free(encoded);

    try testing.expectEqual(@as(usize, 5), encoded.len);
    try testing.expectEqual(@as(u8, 'A'), encoded[4]);
}

// =============================================================================
// Milter Packet Decoding
// =============================================================================

test "Milter: packet decoding command-only" {
    // Build a valid packet: len=1 (big-endian), cmd='Q'
    var buf: [5]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 1, .big);
    buf[4] = 'Q';

    const result = try milter.MilterPacket.decode(&buf);
    try testing.expectEqual(@as(u8, 'Q'), result.packet.command);
    try testing.expectEqual(@as(usize, 0), result.packet.data.len);
    try testing.expectEqual(@as(usize, 5), result.consumed);
}

test "Milter: packet decoding with data" {
    const data = "hello";
    var buf: [10]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], @as(u32, 1 + data.len), .big);
    buf[4] = 'B'; // body command
    @memcpy(buf[5..10], data);

    const result = try milter.MilterPacket.decode(&buf);
    try testing.expectEqual(@as(u8, 'B'), result.packet.command);
    try testing.expectEqualStrings("hello", result.packet.data);
    try testing.expectEqual(@as(usize, 10), result.consumed);
}

test "Milter: packet decoding incomplete buffer" {
    // Only 3 bytes -- not enough for length field
    var buf = [_]u8{ 0, 0, 0 };
    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.Incomplete, result);
}

test "Milter: packet decoding incomplete payload" {
    // Length says 10 bytes payload, but only 5 provided
    var buf: [9]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 10, .big);
    @memset(buf[4..], 0);

    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.Incomplete, result);
}

test "Milter: packet decoding zero-length payload is invalid" {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 0, .big);

    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.InvalidPacket, result);
}

test "Milter: packet decoding oversized packet" {
    var buf: [5]u8 = undefined;
    // Set length to > MILTER_MAX_PACKET_SIZE
    std.mem.writeInt(u32, buf[0..4], @as(u32, milter.MILTER_MAX_PACKET_SIZE + 1), .big);
    buf[4] = 'Q';

    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.PacketTooLarge, result);
}

test "Milter: packet encode-decode round-trip" {
    const original = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.helo),
        .data = "mail.example.com",
    };

    var buf: [256]u8 = undefined;
    const encoded = try original.encode(&buf);

    const decoded = try milter.MilterPacket.decode(encoded);
    try testing.expectEqual(original.command, decoded.packet.command);
    try testing.expectEqualStrings(original.data, decoded.packet.data);
}

// =============================================================================
// Milter Address Family
// =============================================================================

test "Milter: MilterFamily byte values" {
    try testing.expectEqual(@as(u8, 'U'), @intFromEnum(milter.MilterFamily.unknown));
    try testing.expectEqual(@as(u8, 'L'), @intFromEnum(milter.MilterFamily.unix));
    try testing.expectEqual(@as(u8, '4'), @intFromEnum(milter.MilterFamily.inet));
    try testing.expectEqual(@as(u8, '6'), @intFromEnum(milter.MilterFamily.inet6));
}

test "Milter: MilterFamily fromByte" {
    try testing.expect(milter.MilterFamily.fromByte('U') == .unknown);
    try testing.expect(milter.MilterFamily.fromByte('L') == .unix);
    try testing.expect(milter.MilterFamily.fromByte('4') == .inet);
    try testing.expect(milter.MilterFamily.fromByte('6') == .inet6);
    try testing.expect(milter.MilterFamily.fromByte('X') == null);
}

test "Milter: MilterFamily toString" {
    try testing.expectEqualStrings("unknown", milter.MilterFamily.unknown.toString());
    try testing.expectEqualStrings("unix", milter.MilterFamily.unix.toString());
    try testing.expectEqualStrings("inet", milter.MilterFamily.inet.toString());
    try testing.expectEqualStrings("inet6", milter.MilterFamily.inet6.toString());
}

// =============================================================================
// Milter Protocol Version Constants
// =============================================================================

test "Milter: protocol version constants" {
    try testing.expectEqual(@as(u32, 2), milter.MILTER_VERSION_2);
    try testing.expectEqual(@as(u32, 6), milter.MILTER_VERSION_6);
    try testing.expectEqual(@as(u32, 6), milter.MILTER_VERSION_DEFAULT);
    try testing.expectEqual(@as(usize, 65535), milter.MILTER_CHUNK_SIZE);
    try testing.expectEqual(@as(usize, 256 * 1024), milter.MILTER_MAX_PACKET_SIZE);
}

// =============================================================================
// Milter Config Validation
// =============================================================================

test "Milter: config validation requires connection method" {
    const config = milter.MilterConfig{};
    const result = config.validate();
    try testing.expectError(error.NoConnectionMethod, result);
}

test "Milter: config validation with socket path" {
    const config = milter.MilterConfig{
        .socket_path = "/var/run/milter.sock",
    };
    try config.validate();
}

test "Milter: config validation with host and port" {
    const config = milter.MilterConfig{
        .host = "127.0.0.1",
        .port = 8893,
    };
    try config.validate();
}

test "Milter: config validation rejects both socket and host" {
    const config = milter.MilterConfig{
        .socket_path = "/var/run/milter.sock",
        .host = "127.0.0.1",
        .port = 8893,
    };
    try testing.expectError(error.AmbiguousConnectionMethod, config.validate());
}

test "Milter: config validation requires port when host is set" {
    const config = milter.MilterConfig{
        .host = "127.0.0.1",
        .port = 0,
    };
    try testing.expectError(error.MissingPort, config.validate());
}

test "Milter: config validation rejects zero timeout" {
    const config = milter.MilterConfig{
        .socket_path = "/var/run/milter.sock",
        .timeout_ms = 0,
    };
    try testing.expectError(error.InvalidTimeout, config.validate());
}

test "Milter: config defaults" {
    const config = milter.MilterConfig{};

    try testing.expect(config.socket_path == null);
    try testing.expect(config.host == null);
    try testing.expectEqual(@as(u16, 0), config.port);
    try testing.expectEqual(@as(u32, 30_000), config.timeout_ms);
    try testing.expectEqual(milter.MILTER_VERSION_DEFAULT, config.protocol_version);
    try testing.expectEqualStrings("milter", config.name);
}
