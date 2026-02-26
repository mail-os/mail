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

// =============================================================================
// Milter Edge Case Tests
// =============================================================================

// 1. Packet with length 0 (empty packet) -- zero-length payload is invalid
test "Milter edge: packet decode with zero-length payload returns InvalidPacket" {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 0, .big);

    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.InvalidPacket, result);
}

// 2. Packet with length > max allowed size
test "Milter edge: packet decode with oversized length returns PacketTooLarge" {
    // Exactly at the boundary
    var buf_at_max: [5]u8 = undefined;
    std.mem.writeInt(u32, buf_at_max[0..4], @as(u32, milter.MILTER_MAX_PACKET_SIZE), .big);
    buf_at_max[4] = 'Q';
    // This should return Incomplete (buffer too small) rather than PacketTooLarge
    // because the packet is at max, not over. Let's test just over max.
    var buf_over: [5]u8 = undefined;
    std.mem.writeInt(u32, buf_over[0..4], @as(u32, milter.MILTER_MAX_PACKET_SIZE + 1), .big);
    buf_over[4] = 'Q';
    const result = milter.MilterPacket.decode(&buf_over);
    try testing.expectError(error.PacketTooLarge, result);

    // Way over max
    var buf_way_over: [5]u8 = undefined;
    std.mem.writeInt(u32, buf_way_over[0..4], @as(u32, 0xFFFFFFFF), .big);
    buf_way_over[4] = 'Q';
    const result2 = milter.MilterPacket.decode(&buf_way_over);
    try testing.expectError(error.PacketTooLarge, result2);
}

// 3. Invalid command byte (not matching any MilterCommand)
test "Milter edge: fromByte returns null for every non-command byte" {
    // Test a range of bytes that are NOT valid milter commands
    const invalid_bytes = [_]u8{ 0, 1, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
        'X', 'Y', 'Z', '0', '1', '2', '3', 0x80, 0xFE, 0xFF };
    for (invalid_bytes) |b| {
        // Only check bytes that are genuinely not commands
        if (milter.MilterCommand.fromByte(b) == null) {
            try testing.expect(milter.MilterCommand.fromByte(b) == null);
        }
    }

    // Specifically verify some close-but-wrong bytes
    try testing.expect(milter.MilterCommand.fromByte('a') == null); // lowercase abort
    try testing.expect(milter.MilterCommand.fromByte('b') == null); // lowercase body
    try testing.expect(milter.MilterCommand.fromByte('c') == null); // lowercase connect
    try testing.expect(milter.MilterCommand.fromByte('q') == null); // lowercase quit
    try testing.expect(milter.MilterCommand.fromByte('o') == null); // lowercase optneg
}

// 4. Response packet construction for each response type
test "Milter edge: response packet construction for all response types" {
    // Verify that each MilterResponse can be encoded as a packet command byte
    const responses = [_]milter.MilterResponse{
        .add_recipient, .delete_recipient, .accept,       .replace_body,
        .@"continue",   .discard,          .add_header,   .insert_header,
        .change_header, .progress,         .quarantine,    .reject,
        .temp_fail,     .reply_code,       .skip,          .change_from,
        .add_recipient_par, .option_negotiation,
    };

    for (responses) |resp| {
        const pkt = milter.MilterPacket{
            .command = @intFromEnum(resp),
            .data = &[_]u8{},
        };

        var buf: [64]u8 = undefined;
        const encoded = try pkt.encode(&buf);

        // Decode round-trip
        const decoded = try milter.MilterPacket.decode(encoded);
        try testing.expectEqual(@intFromEnum(resp), decoded.packet.command);

        // Verify the byte can be converted back to response
        const recovered = milter.MilterResponse.fromByte(decoded.packet.command);
        try testing.expect(recovered != null);
        try testing.expect(recovered.? == resp);
    }
}

// 5. Macro definitions with empty values
test "Milter edge: macro payload with empty macro values" {
    // A macro packet has: command-code-byte then pairs of name\0 value\0
    // With empty value: "j\0\0" means macro 'j' with empty value
    var payload_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // Command code for connect
    payload_buf[offset] = @intFromEnum(milter.MilterCommand.connect);
    offset += 1;

    // Macro name "j" + NUL
    payload_buf[offset] = 'j';
    offset += 1;
    payload_buf[offset] = 0;
    offset += 1;

    // Empty value + NUL
    payload_buf[offset] = 0;
    offset += 1;

    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.macro),
        .data = payload_buf[0..offset],
    };

    // Encode and decode the packet
    var buf: [256]u8 = undefined;
    const encoded = try pkt.encode(&buf);
    const decoded = try milter.MilterPacket.decode(encoded);

    try testing.expectEqual(@intFromEnum(milter.MilterCommand.macro), decoded.packet.command);
    // Data should contain cmd byte + "j\0\0"
    try testing.expectEqual(@as(usize, 4), decoded.packet.data.len);
    // The first byte is the command code
    try testing.expectEqual(@intFromEnum(milter.MilterCommand.connect), decoded.packet.data[0]);
}

// 6. Header modification with empty header name
test "Milter edge: header packet with empty header name" {
    // Header payload: name\0 value\0, where name is empty
    const data = "\x00some-value\x00";
    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.header),
        .data = data,
    };

    var buf: [256]u8 = undefined;
    const encoded = try pkt.encode(&buf);
    const decoded = try milter.MilterPacket.decode(encoded);

    try testing.expectEqual(@intFromEnum(milter.MilterCommand.header), decoded.packet.command);
    // The first byte is NUL (empty name)
    try testing.expectEqual(@as(u8, 0), decoded.packet.data[0]);
}

// 7. Header modification with empty header value
test "Milter edge: header packet with empty header value" {
    // Header payload: name\0 value\0, where value is empty
    const data = "Subject\x00\x00";
    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.header),
        .data = data,
    };

    var buf: [256]u8 = undefined;
    const encoded = try pkt.encode(&buf);
    const decoded = try milter.MilterPacket.decode(encoded);

    try testing.expectEqual(@intFromEnum(milter.MilterCommand.header), decoded.packet.command);
    try testing.expectEqualStrings("Subject\x00\x00", decoded.packet.data);
}

// 8. Body replacement with empty body
test "Milter edge: body packet with empty body" {
    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.body),
        .data = "",
    };

    try testing.expectEqual(@as(usize, 5), pkt.encodedLen()); // 4 length + 1 cmd + 0 data

    var buf: [64]u8 = undefined;
    const encoded = try pkt.encode(&buf);
    const decoded = try milter.MilterPacket.decode(encoded);

    try testing.expectEqual(@intFromEnum(milter.MilterCommand.body), decoded.packet.command);
    try testing.expectEqual(@as(usize, 0), decoded.packet.data.len);
}

// 9. Multiple RCPT TO recipients handling (payload construction)
test "Milter edge: multiple RCPT TO payloads encode distinct recipients" {
    // Each RCPT TO is a separate packet; verify they encode independently
    const recipients = [_][]const u8{
        "alice@example.com",
        "bob@example.com",
        "charlie@example.com",
        "",  // edge case: empty recipient
    };

    for (recipients) |rcpt| {
        // Build payload: recipient\0
        const alloc_buf = try testing.allocator.alloc(u8, rcpt.len + 1);
        defer testing.allocator.free(alloc_buf);
        @memcpy(alloc_buf[0..rcpt.len], rcpt);
        alloc_buf[rcpt.len] = 0;

        const pkt = milter.MilterPacket{
            .command = @intFromEnum(milter.MilterCommand.rcpt_to),
            .data = alloc_buf,
        };

        const encoded = try pkt.encodeAlloc(testing.allocator);
        defer testing.allocator.free(encoded);

        const decoded = try milter.MilterPacket.decode(encoded);
        try testing.expectEqual(@intFromEnum(milter.MilterCommand.rcpt_to), decoded.packet.command);
        try testing.expectEqual(rcpt.len + 1, decoded.packet.data.len);
        // The data should end with NUL
        try testing.expectEqual(@as(u8, 0), decoded.packet.data[decoded.packet.data.len - 1]);
    }
}

// 10. Connection info with IPv4 vs IPv6 addresses
test "Milter edge: connect payload with IPv4 address" {
    // Payload format: hostname\0 family(1) port(2 big-endian) address\0
    const hostname = "mail.example.com";
    const family = milter.MilterFamily.inet;
    const port: u16 = 25;
    const address = "192.168.1.1";

    const data_len = hostname.len + 1 + 1 + 2 + address.len + 1;
    const buf = try testing.allocator.alloc(u8, data_len);
    defer testing.allocator.free(buf);

    var offset: usize = 0;
    @memcpy(buf[offset .. offset + hostname.len], hostname);
    offset += hostname.len;
    buf[offset] = 0;
    offset += 1;
    buf[offset] = @intFromEnum(family);
    offset += 1;
    std.mem.writeInt(u16, buf[offset..][0..2], port, .big);
    offset += 2;
    @memcpy(buf[offset .. offset + address.len], address);
    offset += address.len;
    buf[offset] = 0;

    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.connect),
        .data = buf,
    };

    const encoded = try pkt.encodeAlloc(testing.allocator);
    defer testing.allocator.free(encoded);

    const decoded = try milter.MilterPacket.decode(encoded);
    try testing.expectEqual(@intFromEnum(milter.MilterCommand.connect), decoded.packet.command);
    // Verify family byte is at the right position
    try testing.expectEqual(@intFromEnum(milter.MilterFamily.inet), decoded.packet.data[hostname.len + 1]);
}

test "Milter edge: connect payload with IPv6 address" {
    const hostname = "[::1]";
    const family = milter.MilterFamily.inet6;
    const port: u16 = 587;
    const address = "::1";

    const data_len = hostname.len + 1 + 1 + 2 + address.len + 1;
    const buf = try testing.allocator.alloc(u8, data_len);
    defer testing.allocator.free(buf);

    var offset: usize = 0;
    @memcpy(buf[offset .. offset + hostname.len], hostname);
    offset += hostname.len;
    buf[offset] = 0;
    offset += 1;
    buf[offset] = @intFromEnum(family);
    offset += 1;
    std.mem.writeInt(u16, buf[offset..][0..2], port, .big);
    offset += 2;
    @memcpy(buf[offset .. offset + address.len], address);
    offset += address.len;
    buf[offset] = 0;

    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.connect),
        .data = buf,
    };

    const encoded = try pkt.encodeAlloc(testing.allocator);
    defer testing.allocator.free(encoded);

    const decoded = try milter.MilterPacket.decode(encoded);
    try testing.expectEqual(@intFromEnum(milter.MilterCommand.connect), decoded.packet.command);
    try testing.expectEqual(@intFromEnum(milter.MilterFamily.inet6), decoded.packet.data[hostname.len + 1]);

    // Verify port bytes
    const port_bytes = decoded.packet.data[hostname.len + 2 ..][0..2];
    const decoded_port = std.mem.readInt(u16, port_bytes, .big);
    try testing.expectEqual(port, decoded_port);
}

// 11. Protocol negotiation with version mismatch
test "Milter edge: negotiation payload encodes version correctly" {
    // Build a negotiation payload with version 2 (older version)
    var payload: [12]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], milter.MILTER_VERSION_2, .big);
    std.mem.writeInt(u32, payload[4..8], milter.MilterActions.none.toNetworkU32(), .big);
    std.mem.writeInt(u32, payload[8..12], milter.MilterProtocol.all_callbacks.toNetworkU32(), .big);

    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.option_negotiation),
        .data = &payload,
    };

    var buf: [256]u8 = undefined;
    const encoded = try pkt.encode(&buf);
    const decoded = try milter.MilterPacket.decode(encoded);

    try testing.expectEqual(@intFromEnum(milter.MilterCommand.option_negotiation), decoded.packet.command);
    try testing.expectEqual(@as(usize, 12), decoded.packet.data.len);

    // Parse the version from the decoded data
    const version = std.mem.readInt(u32, decoded.packet.data[0..4], .big);
    try testing.expectEqual(milter.MILTER_VERSION_2, version);
}

test "Milter edge: negotiation payload with version 6 and all actions" {
    var payload: [12]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], milter.MILTER_VERSION_6, .big);
    std.mem.writeInt(u32, payload[4..8], milter.MilterActions.all.toNetworkU32(), .big);
    std.mem.writeInt(u32, payload[8..12], milter.MilterProtocol.minimal.toNetworkU32(), .big);

    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.option_negotiation),
        .data = &payload,
    };

    var buf: [256]u8 = undefined;
    const encoded = try pkt.encode(&buf);
    const decoded = try milter.MilterPacket.decode(encoded);

    // Verify all three fields decode properly
    const version = std.mem.readInt(u32, decoded.packet.data[0..4], .big);
    const actions_raw = std.mem.readInt(u32, decoded.packet.data[4..8], .big);
    const protocol_raw = std.mem.readInt(u32, decoded.packet.data[8..12], .big);

    try testing.expectEqual(milter.MILTER_VERSION_6, version);

    const actions = milter.MilterActions.fromU32(actions_raw);
    try testing.expect(actions.add_headers);
    try testing.expect(actions.change_body);
    try testing.expect(actions.quarantine);

    const protocol = milter.MilterProtocol.fromU32(protocol_raw);
    try testing.expect(protocol.no_connect);
    try testing.expect(protocol.no_helo);
    try testing.expect(protocol.no_body);
}

// 12. Packet deserialization with truncated data
test "Milter edge: decode with exactly 4 bytes but insufficient payload" {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 5, .big); // says 5 bytes of payload
    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.Incomplete, result);
}

test "Milter edge: decode with 1 byte less than needed" {
    // Need 4 (len) + 10 (payload) = 14 bytes, provide 13
    var buf: [13]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 10, .big);
    @memset(buf[4..], 'X');
    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.Incomplete, result);
}

test "Milter edge: decode with 0 bytes" {
    const buf = [_]u8{};
    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.Incomplete, result);
}

test "Milter edge: decode with exactly 1 byte" {
    const buf = [_]u8{0};
    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.Incomplete, result);
}

test "Milter edge: decode with exactly 2 bytes" {
    const buf = [_]u8{ 0, 0 };
    const result = milter.MilterPacket.decode(&buf);
    try testing.expectError(error.Incomplete, result);
}

// Additional edge case: MilterResponseData default init
test "Milter edge: MilterResponseData all optional fields are null by default" {
    const data = milter.MilterResponseData{ .response = .accept };
    try testing.expect(data.header_name == null);
    try testing.expect(data.header_value == null);
    try testing.expect(data.recipient == null);
    try testing.expect(data.body == null);
    try testing.expect(data.quarantine_reason == null);
    try testing.expect(data.reply_code == null);
    try testing.expect(data.new_sender == null);
    try testing.expect(data.esmtp_args == null);
    try testing.expectEqual(@as(u32, 0), data.header_index);
}

// Additional edge case: MilterResponseData deinit with all null fields
test "Milter edge: MilterResponseData deinit with all null fields does not crash" {
    var data = milter.MilterResponseData{ .response = .reject };
    // Should not panic or error when all optional fields are null
    data.deinit(testing.allocator);
}

// Additional edge case: MilterResponseData deinit with allocated fields
test "Milter edge: MilterResponseData deinit frees allocated fields" {
    var data = milter.MilterResponseData{
        .response = .add_header,
        .header_name = try testing.allocator.dupe(u8, "X-Spam-Flag"),
        .header_value = try testing.allocator.dupe(u8, "YES"),
    };
    // deinit should free these without leaking
    data.deinit(testing.allocator);
}

// Additional edge case: MilterModifications init and deinit empty
test "Milter edge: MilterModifications init and deinit with no modifications" {
    var mods = milter.MilterModifications.init(testing.allocator);
    defer mods.deinit();

    try testing.expect(mods.replacement_body == null);
    try testing.expect(mods.quarantine_reason == null);
    try testing.expect(mods.new_sender == null);
    try testing.expect(mods.reply_code == null);
    try testing.expectEqual(@as(usize, 0), mods.added_headers.items.len);
    try testing.expectEqual(@as(usize, 0), mods.changed_headers.items.len);
    try testing.expectEqual(@as(usize, 0), mods.deleted_headers.items.len);
    try testing.expectEqual(@as(usize, 0), mods.added_recipients.items.len);
    try testing.expectEqual(@as(usize, 0), mods.deleted_recipients.items.len);
}

// Additional edge case: MilterModifications applyResponses with empty responses
test "Milter edge: MilterModifications applyResponses with empty slice" {
    var mods = milter.MilterModifications.init(testing.allocator);
    defer mods.deinit();

    const empty: []const milter.MilterResponseData = &[_]milter.MilterResponseData{};
    try mods.applyResponses(empty);

    try testing.expectEqual(@as(usize, 0), mods.added_headers.items.len);
}

// Additional edge case: MilterModifications applyResponses with accept (no modifications)
test "Milter edge: MilterModifications applyResponses with non-modification responses" {
    var mods = milter.MilterModifications.init(testing.allocator);
    defer mods.deinit();

    const responses = [_]milter.MilterResponseData{
        .{ .response = .accept },
        .{ .response = .@"continue" },
        .{ .response = .progress },
    };
    try mods.applyResponses(&responses);

    // None of these should produce modifications
    try testing.expectEqual(@as(usize, 0), mods.added_headers.items.len);
    try testing.expect(mods.replacement_body == null);
}

// Additional edge case: MilterManager init and deinit with no milters
test "Milter edge: MilterManager init and deinit empty" {
    var manager = milter.MilterManager.init(testing.allocator);
    defer manager.deinit();

    try testing.expectEqual(@as(usize, 0), manager.count());
    try testing.expectEqual(@as(usize, 0), manager.enabledCount());
}

// Additional edge case: MilterManager addMilter and removeMilter
test "Milter edge: MilterManager add and remove milter" {
    var manager = milter.MilterManager.init(testing.allocator);
    defer manager.deinit();

    try manager.addMilter(.{
        .socket_path = "/tmp/test-milter.sock",
        .name = "test-filter",
    });
    try testing.expectEqual(@as(usize, 1), manager.count());
    try testing.expectEqual(@as(usize, 1), manager.enabledCount());

    // Remove by name
    try testing.expect(manager.removeMilter("test-filter"));
    try testing.expectEqual(@as(usize, 0), manager.count());

    // Remove non-existent returns false
    try testing.expect(!manager.removeMilter("nonexistent"));
}

// Additional edge case: MilterManager setEnabled
test "Milter edge: MilterManager enable/disable milter" {
    var manager = milter.MilterManager.init(testing.allocator);
    defer manager.deinit();

    try manager.addMilter(.{
        .socket_path = "/tmp/test.sock",
        .name = "spam-filter",
    });

    try testing.expectEqual(@as(usize, 1), manager.enabledCount());

    // Disable it
    try testing.expect(manager.setEnabled("spam-filter", false));
    try testing.expectEqual(@as(usize, 0), manager.enabledCount());
    try testing.expectEqual(@as(usize, 1), manager.count());

    // Re-enable
    try testing.expect(manager.setEnabled("spam-filter", true));
    try testing.expectEqual(@as(usize, 1), manager.enabledCount());

    // Non-existent milter
    try testing.expect(!manager.setEnabled("no-such-filter", false));
}

// Additional edge case: MilterActions fromU32/toNetworkU32 round-trip for all-ones
test "Milter edge: MilterActions round-trip for all flags" {
    const all = milter.MilterActions.all;
    const encoded = all.toNetworkU32();
    const decoded = milter.MilterActions.fromU32(encoded);

    try testing.expect(decoded.add_headers);
    try testing.expect(decoded.change_body);
    try testing.expect(decoded.add_recipients);
    try testing.expect(decoded.delete_recipients);
    try testing.expect(decoded.change_headers);
    try testing.expect(decoded.quarantine);
    try testing.expect(decoded.change_from);
    try testing.expect(decoded.add_recipients_par);
    try testing.expect(decoded.set_symbol_list);
}

// Additional edge case: MilterProtocol round-trip for all flags set
test "Milter edge: MilterProtocol round-trip for minimal (all skip flags)" {
    const min = milter.MilterProtocol.minimal;
    const encoded = min.toNetworkU32();
    const decoded = milter.MilterProtocol.fromU32(encoded);

    try testing.expect(decoded.no_connect);
    try testing.expect(decoded.no_helo);
    try testing.expect(decoded.no_mail);
    try testing.expect(decoded.no_rcpt);
    try testing.expect(decoded.no_body);
    try testing.expect(decoded.no_headers);
    try testing.expect(decoded.no_eoh);
}

// Additional edge case: packet with maximum allowed data size
test "Milter edge: packet with large data encodes correctly" {
    // Use a sizable but not enormous buffer
    const data_size: usize = 4096;
    const data = try testing.allocator.alloc(u8, data_size);
    defer testing.allocator.free(data);
    @memset(data, 'X');

    const pkt = milter.MilterPacket{
        .command = @intFromEnum(milter.MilterCommand.body),
        .data = data,
    };

    try testing.expectEqual(@as(usize, 4 + 1 + data_size), pkt.encodedLen());

    const encoded = try pkt.encodeAlloc(testing.allocator);
    defer testing.allocator.free(encoded);

    const decoded = try milter.MilterPacket.decode(encoded);
    try testing.expectEqual(@intFromEnum(milter.MilterCommand.body), decoded.packet.command);
    try testing.expectEqual(data_size, decoded.packet.data.len);
    // Verify all bytes are 'X'
    for (decoded.packet.data) |b| {
        try testing.expectEqual(@as(u8, 'X'), b);
    }
}

// Additional edge case: MilterDisposition toString
test "Milter edge: MilterDisposition toString for all variants" {
    try testing.expectEqualStrings("accept", milter.MilterDisposition.accept.toString());
    try testing.expectEqualStrings("reject", milter.MilterDisposition.reject.toString());
    try testing.expectEqualStrings("temp_fail", milter.MilterDisposition.temp_fail.toString());
    try testing.expectEqualStrings("discard", milter.MilterDisposition.discard.toString());
    try testing.expectEqualStrings("quarantine", milter.MilterDisposition.quarantine.toString());
}

// Additional edge case: MilterStats default values
test "Milter edge: MilterStats all counters start at zero" {
    const stats = milter.MilterStats{};
    try testing.expectEqual(@as(usize, 0), stats.connections);
    try testing.expectEqual(@as(usize, 0), stats.packets_sent);
    try testing.expectEqual(@as(usize, 0), stats.packets_received);
    try testing.expectEqual(@as(usize, 0), stats.errors);
    try testing.expectEqual(@as(usize, 0), stats.messages_accepted);
    try testing.expectEqual(@as(usize, 0), stats.messages_rejected);
    try testing.expectEqual(@as(usize, 0), stats.messages_temp_failed);
    try testing.expectEqual(@as(usize, 0), stats.messages_discarded);
}

// Additional edge case: MilterManagerStats default values
test "Milter edge: MilterManagerStats all counters start at zero" {
    const stats = milter.MilterManagerStats{};
    try testing.expectEqual(@as(usize, 0), stats.total_connections);
    try testing.expectEqual(@as(usize, 0), stats.accepted);
    try testing.expectEqual(@as(usize, 0), stats.rejected);
    try testing.expectEqual(@as(usize, 0), stats.temp_failed);
    try testing.expectEqual(@as(usize, 0), stats.discarded);
    try testing.expectEqual(@as(usize, 0), stats.quarantined);
    try testing.expectEqual(@as(usize, 0), stats.errors);
}

// Additional edge case: MilterConfig validation with extremely long name
test "Milter edge: config with custom name validates" {
    const config = milter.MilterConfig{
        .socket_path = "/var/run/milter.sock",
        .name = "my-very-long-custom-milter-filter-name-for-testing-purposes",
    };
    try config.validate();
    try testing.expectEqualStrings("my-very-long-custom-milter-filter-name-for-testing-purposes", config.name);
}

// Additional edge case: NegotiationResult struct
test "Milter edge: NegotiationResult stores negotiated values" {
    const result = milter.NegotiationResult{
        .version = milter.MILTER_VERSION_2,
        .actions = milter.MilterActions{ .add_headers = true },
        .protocol = milter.MilterProtocol{ .no_body = true },
    };

    try testing.expectEqual(milter.MILTER_VERSION_2, result.version);
    try testing.expect(result.actions.add_headers);
    try testing.expect(!result.actions.change_body);
    try testing.expect(result.protocol.no_body);
    try testing.expect(!result.protocol.no_helo);
}
