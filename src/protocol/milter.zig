const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// Milter (Mail Filter) Protocol Implementation
///
/// Implements the Sendmail Mail Filter (milter) binary protocol as defined in
/// the Sendmail milter specification. This allows integration with external
/// mail filters such as SpamAssassin (via spamass-milter), ClamAV (via
/// clamav-milter), OpenDKIM, OpenDMARC, and other milter-compatible filters.
///
/// The milter protocol uses a simple binary packet format over TCP or Unix
/// domain sockets:
///
///   +--------+--------+------------------+
///   | uint32 |  uint8 |  variable data   |
///   |  len   |  cmd   |   (len-1 bytes)  |
///   +--------+--------+------------------+
///
/// All multi-byte integers are in network byte order (big-endian).
///
/// Protocol flow:
///   1. Client connects to milter server
///   2. Option negotiation (SMFIC_OPTNEG)
///   3. SMFIC_CONNECT -> SMFIC_HELO -> SMFIC_MAIL -> SMFIC_RCPT ->
///      SMFIC_HEADER (repeated) -> SMFIC_EOH -> SMFIC_BODY (repeated) ->
///      SMFIC_BODYEOB
///   4. Milter responds with action at each step
///   5. SMFIC_QUIT to disconnect

// ---------------------------------------------------------------------------
// Milter command bytes (client -> milter server)
// ---------------------------------------------------------------------------

/// Commands sent from MTA to the milter filter.
pub const MilterCommand = enum(u8) {
    /// Abort current message processing (SMFIC_ABORT)
    abort = 'A',
    /// Body chunk (SMFIC_BODY)
    body = 'B',
    /// Connection information (SMFIC_CONNECT)
    connect = 'C',
    /// Define a macro (SMFIC_MACRO)
    macro = 'D',
    /// End of body (SMFIC_BODYEOB)
    end_of_body = 'E',
    /// HELO/EHLO hostname (SMFIC_HELO)
    helo = 'H',
    /// Header (SMFIC_HEADER)
    header = 'L',
    /// End of headers (SMFIC_EOH)
    end_of_headers = 'N',
    /// MAIL FROM (SMFIC_MAIL)
    mail_from = 'M',
    /// Option negotiation (SMFIC_OPTNEG)
    option_negotiation = 'O',
    /// Quit (SMFIC_QUIT)
    quit = 'Q',
    /// RCPT TO (SMFIC_RCPT)
    rcpt_to = 'R',
    /// DATA command (SMFIC_DATA) - milter protocol v6
    data = 'T',
    /// Quit and do not close connection (SMFIC_QUIT_NC) - milter protocol v6
    quit_new_connection = 'K',
    /// Unknown SMTP command (SMFIC_UNKNOWN)
    unknown = 'U',

    /// Convert a raw byte to a MilterCommand, returning null if unrecognized.
    pub fn fromByte(byte: u8) ?MilterCommand {
        inline for (@typeInfo(MilterCommand).@"enum".fields) |field| {
            if (byte == field.value) return @enumFromInt(field.value);
        }
        return null;
    }

    /// Return the human-readable name of this command.
    pub fn toString(self: MilterCommand) []const u8 {
        return switch (self) {
            .abort => "SMFIC_ABORT",
            .body => "SMFIC_BODY",
            .connect => "SMFIC_CONNECT",
            .macro => "SMFIC_MACRO",
            .end_of_body => "SMFIC_BODYEOB",
            .helo => "SMFIC_HELO",
            .header => "SMFIC_HEADER",
            .end_of_headers => "SMFIC_EOH",
            .mail_from => "SMFIC_MAIL",
            .option_negotiation => "SMFIC_OPTNEG",
            .quit => "SMFIC_QUIT",
            .rcpt_to => "SMFIC_RCPT",
            .data => "SMFIC_DATA",
            .quit_new_connection => "SMFIC_QUIT_NC",
            .unknown => "SMFIC_UNKNOWN",
        };
    }
};

// ---------------------------------------------------------------------------
// Milter response bytes (milter server -> client)
// ---------------------------------------------------------------------------

/// Responses sent from the milter filter back to the MTA.
pub const MilterResponse = enum(u8) {
    /// Add a recipient (SMFIR_ADDRCPT)
    add_recipient = '+',
    /// Remove a recipient (SMFIR_DELRCPT)
    delete_recipient = '-',
    /// Accept the message (SMFIR_ACCEPT)
    accept = 'a',
    /// Replace the message body (SMFIR_REPLBODY)
    replace_body = 'b',
    /// Continue processing (SMFIR_CONTINUE)
    @"continue" = 'c',
    /// Discard the message silently (SMFIR_DISCARD)
    discard = 'd',
    /// Add a header (SMFIR_ADDHEADER)
    add_header = 'h',
    /// Insert a header at a specific position (SMFIR_INSHEADER)
    insert_header = 'i',
    /// Change/modify a header (SMFIR_CHGHEADER)
    change_header = 'm',
    /// Report progress (SMFIR_PROGRESS)
    progress = 'p',
    /// Quarantine the message (SMFIR_QUARANTINE)
    quarantine = 'q',
    /// Reject the message (SMFIR_REJECT)
    reject = 'r',
    /// Return a temporary failure (SMFIR_TEMPFAIL)
    temp_fail = 't',
    /// Reply with specific SMTP code (SMFIR_REPLYCODE)
    reply_code = 'y',
    /// Skip further callbacks of this type (SMFIR_SKIP) - v6
    skip = 's',
    /// Change sender (SMFIR_CHGFROM) - v6
    change_from = 'e',
    /// Add recipient with ESMTP args (SMFIR_ADDRCPT_PAR) - v6
    add_recipient_par = '2',
    /// Option negotiation response (SMFIR_OPTNEG)
    option_negotiation = 'O',

    /// Convert a raw byte to a MilterResponse, returning null if unrecognized.
    pub fn fromByte(byte: u8) ?MilterResponse {
        inline for (@typeInfo(MilterResponse).@"enum".fields) |field| {
            if (byte == field.value) return @enumFromInt(field.value);
        }
        return null;
    }

    /// Return the human-readable name of this response.
    pub fn toString(self: MilterResponse) []const u8 {
        return switch (self) {
            .add_recipient => "SMFIR_ADDRCPT",
            .delete_recipient => "SMFIR_DELRCPT",
            .accept => "SMFIR_ACCEPT",
            .replace_body => "SMFIR_REPLBODY",
            .@"continue" => "SMFIR_CONTINUE",
            .discard => "SMFIR_DISCARD",
            .add_header => "SMFIR_ADDHEADER",
            .insert_header => "SMFIR_INSHEADER",
            .change_header => "SMFIR_CHGHEADER",
            .progress => "SMFIR_PROGRESS",
            .quarantine => "SMFIR_QUARANTINE",
            .reject => "SMFIR_REJECT",
            .temp_fail => "SMFIR_TEMPFAIL",
            .reply_code => "SMFIR_REPLYCODE",
            .skip => "SMFIR_SKIP",
            .change_from => "SMFIR_CHGFROM",
            .add_recipient_par => "SMFIR_ADDRCPT_PAR",
            .option_negotiation => "SMFIR_OPTNEG",
        };
    }

    /// Returns true if this response is a final disposition (accept/reject/discard/tempfail).
    pub fn isFinalAction(self: MilterResponse) bool {
        return switch (self) {
            .accept, .reject, .discard, .temp_fail, .reply_code => true,
            else => false,
        };
    }

    /// Returns true if this response requests a message modification.
    pub fn isModification(self: MilterResponse) bool {
        return switch (self) {
            .add_recipient,
            .delete_recipient,
            .replace_body,
            .add_header,
            .insert_header,
            .change_header,
            .quarantine,
            .change_from,
            .add_recipient_par,
            => true,
            else => false,
        };
    }
};

// ---------------------------------------------------------------------------
// Action flags (SMFIF_*)
// ---------------------------------------------------------------------------

/// Bit flags describing actions the milter is allowed to perform.
/// These are negotiated during the SMFIC_OPTNEG handshake.
pub const MilterActions = packed struct(u32) {
    /// Filter may add headers (SMFIF_ADDHDRS)
    add_headers: bool = false,
    /// Filter may change/delete body (SMFIF_CHGBODY)
    change_body: bool = false,
    /// Filter may add recipients (SMFIF_ADDRCPT)
    add_recipients: bool = false,
    /// Filter may delete recipients (SMFIF_DELRCPT)
    delete_recipients: bool = false,
    /// Filter may change/delete headers (SMFIF_CHGHDRS)
    change_headers: bool = false,
    /// Filter may quarantine message (SMFIF_QUARANTINE)
    quarantine: bool = false,
    /// Filter may change envelope sender (SMFIF_CHGFROM) - v6
    change_from: bool = false,
    /// Filter may add recipients with ESMTP args (SMFIF_ADDRCPT_PAR) - v6
    add_recipients_par: bool = false,
    /// Filter may send set of symbols (macros) that it wants (SMFIF_SETSYMLIST) - v6
    set_symbol_list: bool = false,
    _padding: u23 = 0,

    /// Constant: all actions enabled.
    pub const all = MilterActions{
        .add_headers = true,
        .change_body = true,
        .add_recipients = true,
        .delete_recipients = true,
        .change_headers = true,
        .quarantine = true,
        .change_from = true,
        .add_recipients_par = true,
        .set_symbol_list = true,
    };

    /// Constant: no actions enabled.
    pub const none = MilterActions{};

    /// Encode to a 32-bit network byte order value.
    pub fn toNetworkU32(self: MilterActions) u32 {
        return @bitCast(self);
    }

    /// Decode from a 32-bit native value (already converted from network order).
    pub fn fromU32(value: u32) MilterActions {
        return @bitCast(value);
    }

    /// Return the bitwise OR of two action flag sets.
    pub fn merge(self: MilterActions, other: MilterActions) MilterActions {
        const a: u32 = @bitCast(self);
        const b: u32 = @bitCast(other);
        return @bitCast(a | b);
    }

    /// Return the bitwise AND of two action flag sets (intersection).
    pub fn intersect(self: MilterActions, other: MilterActions) MilterActions {
        const a: u32 = @bitCast(self);
        const b: u32 = @bitCast(other);
        return @bitCast(a & b);
    }

    /// Check whether all flags in `required` are set.
    pub fn hasAll(self: MilterActions, required: MilterActions) bool {
        const a: u32 = @bitCast(self);
        const b: u32 = @bitCast(required);
        return (a & b) == b;
    }
};

// ---------------------------------------------------------------------------
// Protocol step flags (SMFIP_*)
// ---------------------------------------------------------------------------

/// Bit flags describing which protocol steps the milter does NOT need.
/// Setting a flag tells the MTA to skip that callback, reducing overhead.
pub const MilterProtocol = packed struct(u32) {
    /// MTA should not send connect info (SMFIP_NOCONNECT)
    no_connect: bool = false,
    /// MTA should not send HELO info (SMFIP_NOHELO)
    no_helo: bool = false,
    /// MTA should not send MAIL FROM info (SMFIP_NOMAIL)
    no_mail: bool = false,
    /// MTA should not send RCPT TO info (SMFIP_NORCPT)
    no_rcpt: bool = false,
    /// MTA should not send body chunks (SMFIP_NOBODY)
    no_body: bool = false,
    /// MTA should not send headers (SMFIP_NOHDRS)
    no_headers: bool = false,
    /// MTA should not send end-of-headers (SMFIP_NOEOH)
    no_eoh: bool = false,
    /// Filter does not reply to body chunks (SMFIP_NR_BODY) - v6
    no_reply_body: bool = false,
    /// MTA should not send connect info (SMFIP_NODATA) - v6
    no_data: bool = false,
    /// MTA should not send unknown SMTP commands (SMFIP_NOUNKNOWN) - v6
    no_unknown: bool = false,
    /// Filter does not reply to RCPT TO (SMFIP_NR_RCPT) - v6
    no_reply_rcpt: bool = false,
    /// Filter does not reply to connect (SMFIP_NR_CONN) - v6
    no_reply_connect: bool = false,
    /// Filter does not reply to HELO (SMFIP_NR_HELO) - v6
    no_reply_helo: bool = false,
    /// Filter does not reply to MAIL FROM (SMFIP_NR_MAIL) - v6
    no_reply_mail: bool = false,
    /// Filter does not reply to headers (SMFIP_NR_HDR) - v6
    no_reply_headers: bool = false,
    /// Filter does not reply to EOH (SMFIP_NR_EOH) - v6
    no_reply_eoh: bool = false,
    /// MTA understands SMFIR_SKIP (SMFIP_SKIP) - v6
    skip: bool = false,
    /// MTA should also send rejected recipients (SMFIP_RCPT_REJ) - v6
    rejected_rcpt: bool = false,
    /// Header value includes leading space (SMFIP_HDR_LEADSPC) - v6
    header_leading_space: bool = false,
    _padding: u13 = 0,

    /// Constant: request all protocol steps (no skipping).
    pub const all_callbacks = MilterProtocol{};

    /// Constant: skip everything (milter only wants EOB).
    pub const minimal = MilterProtocol{
        .no_connect = true,
        .no_helo = true,
        .no_mail = true,
        .no_rcpt = true,
        .no_body = true,
        .no_headers = true,
        .no_eoh = true,
    };

    /// Encode to 32-bit value for wire format.
    pub fn toNetworkU32(self: MilterProtocol) u32 {
        return @bitCast(self);
    }

    /// Decode from 32-bit value.
    pub fn fromU32(value: u32) MilterProtocol {
        return @bitCast(value);
    }

    /// Merge (union) two protocol flag sets.
    pub fn merge(self: MilterProtocol, other: MilterProtocol) MilterProtocol {
        const a: u32 = @bitCast(self);
        const b: u32 = @bitCast(other);
        return @bitCast(a | b);
    }

    /// Intersect two protocol flag sets.
    pub fn intersect(self: MilterProtocol, other: MilterProtocol) MilterProtocol {
        const a: u32 = @bitCast(self);
        const b: u32 = @bitCast(other);
        return @bitCast(a & b);
    }
};

// ---------------------------------------------------------------------------
// Address family constants
// ---------------------------------------------------------------------------

/// Address families used in SMFIC_CONNECT.
pub const MilterFamily = enum(u8) {
    unknown = 'U',
    unix = 'L',
    inet = '4',
    inet6 = '6',

    pub fn fromByte(byte: u8) ?MilterFamily {
        inline for (@typeInfo(MilterFamily).@"enum".fields) |field| {
            if (byte == field.value) return @enumFromInt(field.value);
        }
        return null;
    }

    pub fn toString(self: MilterFamily) []const u8 {
        return switch (self) {
            .unknown => "unknown",
            .unix => "unix",
            .inet => "inet",
            .inet6 => "inet6",
        };
    }
};

// ---------------------------------------------------------------------------
// Protocol version constants
// ---------------------------------------------------------------------------

/// Milter protocol version 2 (basic, widely supported).
pub const MILTER_VERSION_2: u32 = 2;
/// Milter protocol version 6 (extended, supports SKIP, DATA, etc.).
pub const MILTER_VERSION_6: u32 = 6;
/// Default protocol version used for negotiation.
pub const MILTER_VERSION_DEFAULT: u32 = MILTER_VERSION_6;

/// Maximum body chunk size per SMFIC_BODY command (65535 bytes).
pub const MILTER_CHUNK_SIZE: usize = 65535;

/// Maximum total packet size (including the 4-byte length prefix).
pub const MILTER_MAX_PACKET_SIZE: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// MilterPacket: binary packet encoding / decoding
// ---------------------------------------------------------------------------

/// Represents a single milter protocol packet.
///
/// Wire format:
///   [uint32 big-endian length] [uint8 command] [data ...]
///
/// The `length` field covers the command byte + data, so:
///   length = 1 + data.len
pub const MilterPacket = struct {
    command: u8,
    data: []const u8,

    /// Encode this packet into a caller-supplied buffer.
    /// The buffer must be at least `encodedLen()` bytes.
    pub fn encode(self: MilterPacket, buf: []u8) ![]u8 {
        const total = self.encodedLen();
        if (buf.len < total) return error.BufferTooSmall;

        // Length field = command byte + data length
        const payload_len: u32 = @intCast(1 + self.data.len);
        std.mem.writeInt(u32, buf[0..4], payload_len, .big);
        buf[4] = self.command;
        if (self.data.len > 0) {
            @memcpy(buf[5 .. 5 + self.data.len], self.data);
        }
        return buf[0..total];
    }

    /// Encode this packet into a newly allocated buffer.
    pub fn encodeAlloc(self: MilterPacket, allocator: std.mem.Allocator) ![]u8 {
        const total = self.encodedLen();
        const buf = try allocator.alloc(u8, total);
        errdefer allocator.free(buf);
        _ = try self.encode(buf);
        return buf;
    }

    /// Total number of bytes this packet occupies on the wire.
    pub fn encodedLen(self: MilterPacket) usize {
        return 4 + 1 + self.data.len;
    }

    /// Decode a packet from a byte buffer.  Returns the packet and the number
    /// of bytes consumed.  Returns `error.Incomplete` if the buffer does not
    /// contain a full packet.
    pub fn decode(buf: []const u8) !struct { packet: MilterPacket, consumed: usize } {
        if (buf.len < 4) return error.Incomplete;

        const payload_len = std.mem.readInt(u32, buf[0..4], .big);
        if (payload_len == 0) return error.InvalidPacket;
        if (payload_len > MILTER_MAX_PACKET_SIZE) return error.PacketTooLarge;

        const total: usize = 4 + @as(usize, payload_len);
        if (buf.len < total) return error.Incomplete;

        const command = buf[4];
        const data_len = @as(usize, payload_len) - 1;
        const data = buf[5 .. 5 + data_len];

        return .{
            .packet = MilterPacket{
                .command = command,
                .data = data,
            },
            .consumed = total,
        };
    }

    /// Convenience: create a command-only packet with no data.
    pub fn commandOnly(cmd: MilterCommand) MilterPacket {
        return .{
            .command = @intFromEnum(cmd),
            .data = &[_]u8{},
        };
    }
};

// ---------------------------------------------------------------------------
// MilterConfig
// ---------------------------------------------------------------------------

/// Configuration for connecting to a milter server.
pub const MilterConfig = struct {
    /// Path to Unix domain socket (mutually exclusive with host/port).
    socket_path: ?[]const u8 = null,
    /// TCP host for remote milter.
    host: ?[]const u8 = null,
    /// TCP port for remote milter.
    port: u16 = 0,
    /// Timeout for individual read/write operations (milliseconds).
    timeout_ms: u32 = 30_000,
    /// Protocol version to offer during negotiation.
    protocol_version: u32 = MILTER_VERSION_DEFAULT,
    /// Human-readable name for logging.
    name: []const u8 = "milter",
    /// Actions the MTA is willing to allow the milter to perform.
    offered_actions: MilterActions = MilterActions.all,
    /// Protocol steps the MTA supports skipping.
    offered_protocol: MilterProtocol = MilterProtocol.all_callbacks,

    /// Validate the configuration.  At least one connection method must be set.
    pub fn validate(self: MilterConfig) !void {
        if (self.socket_path == null and self.host == null) {
            return error.NoConnectionMethod;
        }
        if (self.socket_path != null and self.host != null) {
            return error.AmbiguousConnectionMethod;
        }
        if (self.host != null and self.port == 0) {
            return error.MissingPort;
        }
        if (self.timeout_ms == 0) {
            return error.InvalidTimeout;
        }
    }
};

// ---------------------------------------------------------------------------
// Parsed response with optional payload
// ---------------------------------------------------------------------------

/// A fully parsed milter response including any action data.
pub const MilterResponseData = struct {
    response: MilterResponse,
    /// For SMFIR_ADDHEADER / SMFIR_CHGHEADER: header name
    header_name: ?[]const u8 = null,
    /// For SMFIR_ADDHEADER / SMFIR_CHGHEADER: header value
    header_value: ?[]const u8 = null,
    /// For SMFIR_CHGHEADER: header index
    header_index: u32 = 0,
    /// For SMFIR_ADDRCPT / SMFIR_DELRCPT: recipient address
    recipient: ?[]const u8 = null,
    /// For SMFIR_REPLBODY: replacement body
    body: ?[]const u8 = null,
    /// For SMFIR_QUARANTINE: quarantine reason
    quarantine_reason: ?[]const u8 = null,
    /// For SMFIR_REPLYCODE: SMTP reply code and text
    reply_code: ?[]const u8 = null,
    /// For SMFIR_CHGFROM: new sender
    new_sender: ?[]const u8 = null,
    /// ESMTP args for SMFIR_ADDRCPT_PAR
    esmtp_args: ?[]const u8 = null,

    pub fn deinit(self: *MilterResponseData, allocator: std.mem.Allocator) void {
        if (self.header_name) |v| allocator.free(v);
        if (self.header_value) |v| allocator.free(v);
        if (self.recipient) |v| allocator.free(v);
        if (self.body) |v| allocator.free(v);
        if (self.quarantine_reason) |v| allocator.free(v);
        if (self.reply_code) |v| allocator.free(v);
        if (self.new_sender) |v| allocator.free(v);
        if (self.esmtp_args) |v| allocator.free(v);
    }
};

// ---------------------------------------------------------------------------
// NegotiationResult
// ---------------------------------------------------------------------------

/// Result of the SMFIC_OPTNEG option negotiation handshake.
pub const NegotiationResult = struct {
    version: u32,
    actions: MilterActions,
    protocol: MilterProtocol,
};

// ---------------------------------------------------------------------------
// MilterClient
// ---------------------------------------------------------------------------

/// A client that speaks the milter binary protocol to an external filter.
///
/// Typical usage:
///
/// ```
/// var client = try MilterClient.init(allocator, config);
/// defer client.deinit();
/// try client.connect("inet:127.0.0.1:8893");
/// const neg = try client.negotiate(MilterActions.all, MilterProtocol.all_callbacks);
/// try client.sendConnect("localhost", .inet, 25, "127.0.0.1");
/// try client.sendHelo("mail.example.com");
/// try client.sendMailFrom("sender@example.com", null);
/// try client.sendRcptTo("rcpt@example.com", null);
/// try client.sendHeader("Subject", "Hello");
/// try client.sendEndOfHeaders();
/// try client.sendBody("Hello, world!\r\n");
/// const responses = try client.sendEndOfMessage();
/// try client.sendQuit();
/// client.disconnect();
/// ```
pub const MilterClient = struct {
    allocator: std.mem.Allocator,
    config: MilterConfig,
    /// Duplicated config strings owned by this struct.
    owned_socket_path: ?[]u8 = null,
    owned_host: ?[]u8 = null,
    owned_name: []u8,
    /// Underlying network stream.
    stream: ?std.net.Stream = null,
    /// Negotiated capabilities.
    negotiated_actions: MilterActions = MilterActions.none,
    negotiated_protocol: MilterProtocol = MilterProtocol.all_callbacks,
    negotiated_version: u32 = 0,
    /// Read buffer for receiving packets.
    read_buf: [MILTER_MAX_PACKET_SIZE + 4]u8 = undefined,
    read_pos: usize = 0,
    /// Statistics.
    stats: MilterStats = .{},
    /// Mutex for stats.
    mutex: std.Thread.Mutex = .{},

    /// Create a new MilterClient. The config strings are duplicated internally.
    pub fn init(allocator: std.mem.Allocator, config: MilterConfig) !MilterClient {
        const owned_name = try allocator.dupe(u8, config.name);
        errdefer allocator.free(owned_name);

        var owned_socket_path: ?[]u8 = null;
        if (config.socket_path) |sp| {
            owned_socket_path = try allocator.dupe(u8, sp);
        }
        errdefer if (owned_socket_path) |p| allocator.free(p);

        var owned_host: ?[]u8 = null;
        if (config.host) |h| {
            owned_host = try allocator.dupe(u8, h);
        }
        errdefer if (owned_host) |h| allocator.free(h);

        return MilterClient{
            .allocator = allocator,
            .config = config,
            .owned_socket_path = owned_socket_path,
            .owned_host = owned_host,
            .owned_name = owned_name,
        };
    }

    /// Release all resources.
    pub fn deinit(self: *MilterClient) void {
        self.disconnect();
        if (self.owned_socket_path) |p| self.allocator.free(p);
        if (self.owned_host) |h| self.allocator.free(h);
        self.allocator.free(self.owned_name);
    }

    // -- Connection management ----------------------------------------------

    /// Connect to the milter server using the configured address.
    pub fn connect(self: *MilterClient, address: []const u8) !void {
        // Disconnect any existing connection.
        self.disconnect();

        // Parse the address string.  Supported forms:
        //   "unix:/path/to/socket"
        //   "inet:host:port"
        //   "inet6:host:port"
        //   "/path/to/socket"        (implicit Unix)
        //   "host:port"              (implicit inet)
        if (std.mem.startsWith(u8, address, "unix:")) {
            const path = address[5..];
            try self.connectUnix(path);
        } else if (std.mem.startsWith(u8, address, "inet6:") or std.mem.startsWith(u8, address, "inet:")) {
            const prefix_len = if (std.mem.startsWith(u8, address, "inet6:")) @as(usize, 6) else @as(usize, 5);
            const rest = address[prefix_len..];
            try self.connectTcp(rest);
        } else if (address.len > 0 and address[0] == '/') {
            try self.connectUnix(address);
        } else {
            try self.connectTcp(address);
        }

        self.read_pos = 0;
    }

    /// Connect via TCP.
    fn connectTcp(self: *MilterClient, host_port: []const u8) !void {
        // Separate host and port.  Last colon wins (handles IPv6 [::1]:port).
        var host: []const u8 = undefined;
        var port: u16 = 0;

        if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |colon| {
            host = host_port[0..colon];
            port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return error.InvalidPort;
        } else {
            // Use configured host/port if the address is just a hostname.
            host = host_port;
            port = self.config.port;
        }

        if (port == 0) return error.MissingPort;

        const addr = try std.net.Address.parseIp(host, port);
        const stream = try std.net.tcpConnectToAddress(addr);
        self.stream = stream;

        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.connections += 1;
    }

    /// Connect via Unix domain socket.
    fn connectUnix(self: *MilterClient, path: []const u8) !void {
        const addr = try std.net.Address.initUnix(path);
        const stream = try std.net.tcpConnectToAddress(addr);
        self.stream = stream;

        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.connections += 1;
    }

    /// Disconnect from the milter server.
    pub fn disconnect(self: *MilterClient) void {
        if (self.stream) |stream| {
            stream.close();
            self.stream = null;
        }
        self.read_pos = 0;
        self.negotiated_version = 0;
        self.negotiated_actions = MilterActions.none;
        self.negotiated_protocol = MilterProtocol.all_callbacks;
    }

    /// Returns true if the client is currently connected.
    pub fn isConnected(self: *const MilterClient) bool {
        return self.stream != null;
    }

    // -- Protocol commands --------------------------------------------------

    /// Perform the SMFIC_OPTNEG option negotiation handshake.
    ///
    /// `offered_actions` and `offered_protocol` describe what the MTA supports.
    /// The milter responds with the subset it actually needs. The intersection
    /// is stored and returned.
    pub fn negotiate(
        self: *MilterClient,
        offered_actions: MilterActions,
        offered_protocol: MilterProtocol,
    ) !NegotiationResult {
        // Build the SMFIC_OPTNEG payload:
        //   uint32 version  |  uint32 actions  |  uint32 protocol
        var payload: [12]u8 = undefined;
        std.mem.writeInt(u32, payload[0..4], self.config.protocol_version, .big);
        std.mem.writeInt(u32, payload[4..8], offered_actions.toNetworkU32(), .big);
        std.mem.writeInt(u32, payload[8..12], offered_protocol.toNetworkU32(), .big);

        try self.sendPacket(.{
            .command = @intFromEnum(MilterCommand.option_negotiation),
            .data = &payload,
        });

        // Read the SMFIR_OPTNEG response.
        const pkt = try self.readPacket();

        if (pkt.command != @intFromEnum(MilterResponse.option_negotiation)) {
            return error.UnexpectedResponse;
        }
        if (pkt.data.len < 12) {
            return error.InvalidPacket;
        }

        const version = std.mem.readInt(u32, pkt.data[0..4], .big);
        const milter_actions_raw = std.mem.readInt(u32, pkt.data[4..8], .big);
        const milter_protocol_raw = std.mem.readInt(u32, pkt.data[8..12], .big);

        // The negotiated result is the intersection of what both sides support.
        self.negotiated_version = @min(self.config.protocol_version, version);
        self.negotiated_actions = offered_actions.intersect(MilterActions.fromU32(milter_actions_raw));
        self.negotiated_protocol = offered_protocol.intersect(MilterProtocol.fromU32(milter_protocol_raw));

        return NegotiationResult{
            .version = self.negotiated_version,
            .actions = self.negotiated_actions,
            .protocol = self.negotiated_protocol,
        };
    }

    /// Send SMFIC_CONNECT with the connecting client information.
    ///
    /// `hostname`  - the connecting hostname (or "[address]")
    /// `family`    - address family
    /// `port`      - connecting port (host byte order)
    /// `address`   - the address string (e.g., "127.0.0.1")
    pub fn sendConnect(
        self: *MilterClient,
        hostname: []const u8,
        family: MilterFamily,
        port: u16,
        address: []const u8,
    ) !MilterResponseData {
        // Payload: hostname\0 + family(1) + port(2, network order) + address\0
        const data_len = hostname.len + 1 + 1 + 2 + address.len + 1;
        const buf = try self.allocator.alloc(u8, data_len);
        defer self.allocator.free(buf);

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

        try self.sendPacket(.{
            .command = @intFromEnum(MilterCommand.connect),
            .data = buf,
        });

        return try self.readResponse();
    }

    /// Send SMFIC_HELO with the HELO/EHLO hostname.
    pub fn sendHelo(self: *MilterClient, hostname: []const u8) !MilterResponseData {
        // Payload: hostname\0
        const buf = try self.allocator.alloc(u8, hostname.len + 1);
        defer self.allocator.free(buf);
        @memcpy(buf[0..hostname.len], hostname);
        buf[hostname.len] = 0;

        try self.sendPacket(.{
            .command = @intFromEnum(MilterCommand.helo),
            .data = buf,
        });

        return try self.readResponse();
    }

    /// Send SMFIC_MAIL with the MAIL FROM sender and optional ESMTP args.
    pub fn sendMailFrom(
        self: *MilterClient,
        sender: []const u8,
        esmtp_args: ?[]const []const u8,
    ) !MilterResponseData {
        var payload: std.ArrayList(u8) = .{};
        defer payload.deinit(self.allocator);

        // sender\0
        try payload.appendSlice(self.allocator, sender);
        try payload.append(self.allocator, 0);

        // Each ESMTP arg is followed by \0
        if (esmtp_args) |args| {
            for (args) |arg| {
                try payload.appendSlice(self.allocator, arg);
                try payload.append(self.allocator, 0);
            }
        }

        try self.sendPacket(.{
            .command = @intFromEnum(MilterCommand.mail_from),
            .data = payload.items,
        });

        return try self.readResponse();
    }

    /// Send SMFIC_RCPT with the RCPT TO recipient and optional ESMTP args.
    pub fn sendRcptTo(
        self: *MilterClient,
        recipient: []const u8,
        esmtp_args: ?[]const []const u8,
    ) !MilterResponseData {
        var payload: std.ArrayList(u8) = .{};
        defer payload.deinit(self.allocator);

        // recipient\0
        try payload.appendSlice(self.allocator, recipient);
        try payload.append(self.allocator, 0);

        if (esmtp_args) |args| {
            for (args) |arg| {
                try payload.appendSlice(self.allocator, arg);
                try payload.append(self.allocator, 0);
            }
        }

        try self.sendPacket(.{
            .command = @intFromEnum(MilterCommand.rcpt_to),
            .data = payload.items,
        });

        return try self.readResponse();
    }

    /// Send SMFIC_HEADER with a single header name and value.
    pub fn sendHeader(
        self: *MilterClient,
        name: []const u8,
        value: []const u8,
    ) !MilterResponseData {
        // Payload: name\0 + value\0
        const buf = try self.allocator.alloc(u8, name.len + 1 + value.len + 1);
        defer self.allocator.free(buf);

        @memcpy(buf[0..name.len], name);
        buf[name.len] = 0;
        @memcpy(buf[name.len + 1 .. name.len + 1 + value.len], value);
        buf[name.len + 1 + value.len] = 0;

        try self.sendPacket(.{
            .command = @intFromEnum(MilterCommand.header),
            .data = buf,
        });

        return try self.readResponse();
    }

    /// Send SMFIC_EOH (end of headers).
    pub fn sendEndOfHeaders(self: *MilterClient) !MilterResponseData {
        try self.sendPacket(MilterPacket.commandOnly(.end_of_headers));
        return try self.readResponse();
    }

    /// Send SMFIC_BODY with a chunk of message body data.
    ///
    /// The chunk must not exceed `MILTER_CHUNK_SIZE` bytes.  For large bodies
    /// the caller should split into multiple chunks.
    pub fn sendBody(self: *MilterClient, chunk: []const u8) !MilterResponseData {
        if (chunk.len > MILTER_CHUNK_SIZE) return error.ChunkTooLarge;

        try self.sendPacket(.{
            .command = @intFromEnum(MilterCommand.body),
            .data = chunk,
        });

        return try self.readResponse();
    }

    /// Send SMFIC_BODYEOB (end of message body).
    ///
    /// This is the point at which the milter may return modification commands
    /// (add/change headers, add/delete recipients, replace body, quarantine).
    /// All modification responses are collected and returned as a list.
    pub fn sendEndOfMessage(self: *MilterClient) ![]MilterResponseData {
        try self.sendPacket(MilterPacket.commandOnly(.end_of_body));

        // Collect all responses until we get a final action.
        var responses: std.ArrayList(MilterResponseData) = .{};
        errdefer {
            for (responses.items) |*r| r.deinit(self.allocator);
            responses.deinit(self.allocator);
        }

        while (true) {
            const resp = try self.readResponse();
            const is_final = resp.response.isFinalAction();
            const is_continue = resp.response == .@"continue";
            try responses.append(self.allocator, resp);

            if (is_final or is_continue) break;
        }

        return try responses.toOwnedSlice(self.allocator);
    }

    /// Send SMFIC_ABORT to cancel processing of the current message.
    /// The connection remains open for a new message.
    pub fn sendAbort(self: *MilterClient) !void {
        try self.sendPacket(MilterPacket.commandOnly(.abort));
        // SMFIC_ABORT does not expect a response.
    }

    /// Send SMFIC_QUIT to terminate the milter session.
    pub fn sendQuit(self: *MilterClient) !void {
        try self.sendPacket(MilterPacket.commandOnly(.quit));
        // SMFIC_QUIT does not expect a response.
    }

    /// Send SMFIC_DATA (milter v6).  Sent after all RCPT TO commands,
    /// before any headers.
    pub fn sendData(self: *MilterClient) !MilterResponseData {
        try self.sendPacket(MilterPacket.commandOnly(.data));
        return try self.readResponse();
    }

    /// Send a macro definition (SMFIC_MACRO).
    ///
    /// `cmd_code` is the command this macro relates to (e.g., MilterCommand.connect).
    /// `macros` is a list of name-value pairs.
    pub fn sendMacro(
        self: *MilterClient,
        cmd_code: MilterCommand,
        macros: []const [2][]const u8,
    ) !void {
        var payload: std.ArrayList(u8) = .{};
        defer payload.deinit(self.allocator);

        try payload.append(self.allocator, @intFromEnum(cmd_code));

        for (macros) |pair| {
            try payload.appendSlice(self.allocator, pair[0]);
            try payload.append(self.allocator, 0);
            try payload.appendSlice(self.allocator, pair[1]);
            try payload.append(self.allocator, 0);
        }

        try self.sendPacket(.{
            .command = @intFromEnum(MilterCommand.macro),
            .data = payload.items,
        });
        // Macros do not expect a response.
    }

    // -- Low-level I/O ------------------------------------------------------

    /// Send a raw packet over the wire.
    fn sendPacket(self: *MilterClient, packet: MilterPacket) !void {
        const s = self.stream orelse return error.NotConnected;

        const encoded = try packet.encodeAlloc(self.allocator);
        defer self.allocator.free(encoded);

        var written: usize = 0;
        while (written < encoded.len) {
            written += s.write(encoded[written..]) catch |err| {
                self.recordError();
                return err;
            };
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.packets_sent += 1;
    }

    /// Read a single packet from the connection.
    fn readPacket(self: *MilterClient) !MilterPacket {
        const s = self.stream orelse return error.NotConnected;

        // We may already have a complete packet in the read buffer.
        while (true) {
            if (self.read_pos >= 4) {
                const payload_len = std.mem.readInt(u32, self.read_buf[0..4], .big);
                const total: usize = 4 + @as(usize, payload_len);
                if (self.read_pos >= total) {
                    // We have a complete packet.
                    const result = try MilterPacket.decode(self.read_buf[0..self.read_pos]);
                    // Shift remaining data to the front.
                    const remaining = self.read_pos - result.consumed;
                    if (remaining > 0) {
                        std.mem.copyForwards(u8, self.read_buf[0..remaining], self.read_buf[result.consumed .. result.consumed + remaining]);
                    }
                    self.read_pos = remaining;

                    self.mutex.lock();
                    defer self.mutex.unlock();
                    self.stats.packets_received += 1;

                    return result.packet;
                }
            }

            // Need more data.
            const n = s.read(self.read_buf[self.read_pos..]) catch |err| {
                self.recordError();
                return err;
            };
            if (n == 0) return error.ConnectionClosed;
            self.read_pos += n;
        }
    }

    /// Read a response packet and parse it into a MilterResponseData.
    fn readResponse(self: *MilterClient) !MilterResponseData {
        const pkt = try self.readPacket();
        return try self.parseResponsePacket(pkt);
    }

    /// Parse a response packet into structured data.
    fn parseResponsePacket(self: *MilterClient, pkt: MilterPacket) !MilterResponseData {
        const resp = MilterResponse.fromByte(pkt.command) orelse return error.UnknownResponse;

        var result = MilterResponseData{ .response = resp };

        switch (resp) {
            .add_header => {
                // name\0 value\0
                if (findNullTerminated(pkt.data, 0)) |name_end| {
                    result.header_name = try self.allocator.dupe(u8, pkt.data[0..name_end]);
                    const val_start = name_end + 1;
                    if (findNullTerminated(pkt.data, val_start)) |val_end| {
                        result.header_value = try self.allocator.dupe(u8, pkt.data[val_start..val_end]);
                    } else if (val_start < pkt.data.len) {
                        result.header_value = try self.allocator.dupe(u8, pkt.data[val_start..]);
                    }
                }
            },
            .insert_header => {
                // uint32 index + name\0 + value\0
                if (pkt.data.len >= 4) {
                    result.header_index = std.mem.readInt(u32, pkt.data[0..4], .big);
                    if (findNullTerminated(pkt.data, 4)) |name_end| {
                        result.header_name = try self.allocator.dupe(u8, pkt.data[4..name_end]);
                        const val_start = name_end + 1;
                        if (findNullTerminated(pkt.data, val_start)) |val_end| {
                            result.header_value = try self.allocator.dupe(u8, pkt.data[val_start..val_end]);
                        } else if (val_start < pkt.data.len) {
                            result.header_value = try self.allocator.dupe(u8, pkt.data[val_start..]);
                        }
                    }
                }
            },
            .change_header => {
                // uint32 index + name\0 + value\0
                if (pkt.data.len >= 4) {
                    result.header_index = std.mem.readInt(u32, pkt.data[0..4], .big);
                    if (findNullTerminated(pkt.data, 4)) |name_end| {
                        result.header_name = try self.allocator.dupe(u8, pkt.data[4..name_end]);
                        const val_start = name_end + 1;
                        if (val_start < pkt.data.len) {
                            if (findNullTerminated(pkt.data, val_start)) |val_end| {
                                result.header_value = try self.allocator.dupe(u8, pkt.data[val_start..val_end]);
                            } else {
                                result.header_value = try self.allocator.dupe(u8, pkt.data[val_start..]);
                            }
                        }
                    }
                }
            },
            .add_recipient => {
                // recipient\0
                if (findNullTerminated(pkt.data, 0)) |end| {
                    result.recipient = try self.allocator.dupe(u8, pkt.data[0..end]);
                } else if (pkt.data.len > 0) {
                    result.recipient = try self.allocator.dupe(u8, pkt.data);
                }
            },
            .add_recipient_par => {
                // recipient\0 args\0
                if (findNullTerminated(pkt.data, 0)) |rcpt_end| {
                    result.recipient = try self.allocator.dupe(u8, pkt.data[0..rcpt_end]);
                    const args_start = rcpt_end + 1;
                    if (args_start < pkt.data.len) {
                        if (findNullTerminated(pkt.data, args_start)) |args_end| {
                            result.esmtp_args = try self.allocator.dupe(u8, pkt.data[args_start..args_end]);
                        } else {
                            result.esmtp_args = try self.allocator.dupe(u8, pkt.data[args_start..]);
                        }
                    }
                }
            },
            .delete_recipient => {
                if (findNullTerminated(pkt.data, 0)) |end| {
                    result.recipient = try self.allocator.dupe(u8, pkt.data[0..end]);
                } else if (pkt.data.len > 0) {
                    result.recipient = try self.allocator.dupe(u8, pkt.data);
                }
            },
            .replace_body => {
                if (pkt.data.len > 0) {
                    result.body = try self.allocator.dupe(u8, pkt.data);
                }
            },
            .quarantine => {
                if (findNullTerminated(pkt.data, 0)) |end| {
                    result.quarantine_reason = try self.allocator.dupe(u8, pkt.data[0..end]);
                } else if (pkt.data.len > 0) {
                    result.quarantine_reason = try self.allocator.dupe(u8, pkt.data);
                }
            },
            .reply_code => {
                if (pkt.data.len > 0) {
                    result.reply_code = try self.allocator.dupe(u8, pkt.data);
                }
            },
            .change_from => {
                if (findNullTerminated(pkt.data, 0)) |end| {
                    result.new_sender = try self.allocator.dupe(u8, pkt.data[0..end]);
                } else if (pkt.data.len > 0) {
                    result.new_sender = try self.allocator.dupe(u8, pkt.data);
                }
            },
            // Simple responses: accept, continue, discard, reject, temp_fail, progress, skip
            else => {},
        }

        return result;
    }

    /// Record an error in statistics.
    fn recordError(self: *MilterClient) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.errors += 1;
    }

    /// Get a snapshot of the client statistics.
    pub fn getStats(self: *MilterClient) MilterStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    /// Reset statistics counters to zero.
    pub fn resetStats(self: *MilterClient) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats = .{};
    }
};

/// Find the absolute position of the first null byte at or after `start`.
fn findNullTerminated(data: []const u8, start: usize) ?usize {
    if (start >= data.len) return null;
    const rel = std.mem.indexOfScalar(u8, data[start..], 0) orelse return null;
    return start + rel;
}

/// Alias for findNullTerminated (kept for readability in tests).
fn findNull(data: []const u8, start: usize) ?usize {
    return findNullTerminated(data, start);
}

// ---------------------------------------------------------------------------
// MilterStats
// ---------------------------------------------------------------------------

/// Counters for milter client operations.
pub const MilterStats = struct {
    connections: usize = 0,
    packets_sent: usize = 0,
    packets_received: usize = 0,
    errors: usize = 0,
    messages_accepted: usize = 0,
    messages_rejected: usize = 0,
    messages_temp_failed: usize = 0,
    messages_discarded: usize = 0,
};

// ---------------------------------------------------------------------------
// MilterManager: manage a pipeline of multiple milter connections
// ---------------------------------------------------------------------------

/// Disposition applied to a message after running through the milter pipeline.
pub const MilterDisposition = enum {
    accept,
    reject,
    temp_fail,
    discard,
    quarantine,

    pub fn toString(self: MilterDisposition) []const u8 {
        return switch (self) {
            .accept => "accept",
            .reject => "reject",
            .temp_fail => "temp_fail",
            .discard => "discard",
            .quarantine => "quarantine",
        };
    }
};

/// Modifications requested by milters during the end-of-message phase.
pub const MilterModifications = struct {
    added_headers: std.ArrayList(HeaderPair) = .{},
    changed_headers: std.ArrayList(HeaderChange) = .{},
    deleted_headers: std.ArrayList(HeaderDelete) = .{},
    added_recipients: std.ArrayList([]const u8) = .{},
    deleted_recipients: std.ArrayList([]const u8) = .{},
    replacement_body: ?[]const u8 = null,
    quarantine_reason: ?[]const u8 = null,
    new_sender: ?[]const u8 = null,
    reply_code: ?[]const u8 = null,
    allocator: std.mem.Allocator,

    pub const HeaderPair = struct {
        name: []const u8,
        value: []const u8,
    };

    pub const HeaderChange = struct {
        index: u32,
        name: []const u8,
        value: []const u8,
    };

    pub const HeaderDelete = struct {
        index: u32,
        name: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator) MilterModifications {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MilterModifications) void {
        for (self.added_headers.items) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.added_headers.deinit(self.allocator);
        for (self.changed_headers.items) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.changed_headers.deinit(self.allocator);
        for (self.deleted_headers.items) |h| {
            self.allocator.free(h.name);
        }
        self.deleted_headers.deinit(self.allocator);
        for (self.added_recipients.items) |r| {
            self.allocator.free(r);
        }
        self.added_recipients.deinit(self.allocator);
        for (self.deleted_recipients.items) |r| {
            self.allocator.free(r);
        }
        self.deleted_recipients.deinit(self.allocator);
        if (self.replacement_body) |b| self.allocator.free(b);
        if (self.quarantine_reason) |q| self.allocator.free(q);
        if (self.new_sender) |s| self.allocator.free(s);
        if (self.reply_code) |c| self.allocator.free(c);
    }

    /// Apply a list of MilterResponseData modifications into this aggregate.
    pub fn applyResponses(self: *MilterModifications, responses: []const MilterResponseData) !void {
        for (responses) |resp| {
            switch (resp.response) {
                .add_header => {
                    if (resp.header_name != null and resp.header_value != null) {
                        try self.added_headers.append(self.allocator, .{
                            .name = try self.allocator.dupe(u8, resp.header_name.?),
                            .value = try self.allocator.dupe(u8, resp.header_value.?),
                        });
                    }
                },
                .insert_header => {
                    if (resp.header_name != null and resp.header_value != null) {
                        try self.added_headers.append(self.allocator, .{
                            .name = try self.allocator.dupe(u8, resp.header_name.?),
                            .value = try self.allocator.dupe(u8, resp.header_value.?),
                        });
                    }
                },
                .change_header => {
                    if (resp.header_name != null) {
                        if (resp.header_value) |val| {
                            if (val.len == 0) {
                                // Empty value means delete
                                try self.deleted_headers.append(self.allocator, .{
                                    .index = resp.header_index,
                                    .name = try self.allocator.dupe(u8, resp.header_name.?),
                                });
                            } else {
                                try self.changed_headers.append(self.allocator, .{
                                    .index = resp.header_index,
                                    .name = try self.allocator.dupe(u8, resp.header_name.?),
                                    .value = try self.allocator.dupe(u8, val),
                                });
                            }
                        }
                    }
                },
                .add_recipient, .add_recipient_par => {
                    if (resp.recipient) |rcpt| {
                        try self.added_recipients.append(self.allocator, try self.allocator.dupe(u8, rcpt));
                    }
                },
                .delete_recipient => {
                    if (resp.recipient) |rcpt| {
                        try self.deleted_recipients.append(self.allocator, try self.allocator.dupe(u8, rcpt));
                    }
                },
                .replace_body => {
                    if (self.replacement_body) |old| self.allocator.free(old);
                    if (resp.body) |body| {
                        self.replacement_body = try self.allocator.dupe(u8, body);
                    }
                },
                .quarantine => {
                    if (self.quarantine_reason) |old| self.allocator.free(old);
                    if (resp.quarantine_reason) |reason| {
                        self.quarantine_reason = try self.allocator.dupe(u8, reason);
                    }
                },
                .change_from => {
                    if (self.new_sender) |old| self.allocator.free(old);
                    if (resp.new_sender) |sender| {
                        self.new_sender = try self.allocator.dupe(u8, sender);
                    }
                },
                else => {},
            }
        }
    }
};

/// Manages a pipeline of milter filters for processing messages.
///
/// Messages flow through each milter in order.  If any milter rejects,
/// the pipeline short-circuits.  Modifications from all milters are
/// aggregated.
pub const MilterManager = struct {
    allocator: std.mem.Allocator,
    milters: std.ArrayList(ManagedMilter) = .{},
    stats: MilterManagerStats = .{},
    mutex: std.Thread.Mutex = .{},

    pub const ManagedMilter = struct {
        config: MilterConfig,
        client: ?*MilterClient,
        enabled: bool,
        /// Duplicated name for logging.
        name: []const u8,
    };

    /// Create a new MilterManager.
    pub fn init(allocator: std.mem.Allocator) MilterManager {
        return .{
            .allocator = allocator,
        };
    }

    /// Release all resources and disconnect all milter clients.
    pub fn deinit(self: *MilterManager) void {
        for (self.milters.items) |*m| {
            if (m.client) |client| {
                client.deinit();
                self.allocator.destroy(client);
            }
            self.allocator.free(m.name);
        }
        self.milters.deinit(self.allocator);
    }

    /// Add a milter to the pipeline.
    pub fn addMilter(self: *MilterManager, config: MilterConfig) !void {
        const name = try self.allocator.dupe(u8, config.name);
        try self.milters.append(self.allocator, .{
            .config = config,
            .client = null,
            .enabled = true,
            .name = name,
        });
    }

    /// Remove a milter from the pipeline by name.
    pub fn removeMilter(self: *MilterManager, name: []const u8) bool {
        for (self.milters.items, 0..) |*m, i| {
            if (std.mem.eql(u8, m.name, name)) {
                if (m.client) |client| {
                    client.deinit();
                    self.allocator.destroy(client);
                }
                self.allocator.free(m.name);
                _ = self.milters.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Enable or disable a milter by name.
    pub fn setEnabled(self: *MilterManager, name: []const u8, enabled: bool) bool {
        for (self.milters.items) |*m| {
            if (std.mem.eql(u8, m.name, name)) {
                m.enabled = enabled;
                return true;
            }
        }
        return false;
    }

    /// Connect and negotiate with all enabled milters.
    pub fn connectAll(self: *MilterManager) !void {
        for (self.milters.items) |*m| {
            if (!m.enabled) continue;
            if (m.client != null) continue;

            const client = try self.allocator.create(MilterClient);
            errdefer self.allocator.destroy(client);
            client.* = try MilterClient.init(self.allocator, m.config);
            errdefer client.deinit();

            // Build address string for connect().
            if (m.config.socket_path) |path| {
                try client.connect(path);
            } else if (m.config.host) |host| {
                var addr_buf: [512]u8 = undefined;
                const addr = std.fmt.bufPrint(&addr_buf, "{s}:{d}", .{ host, m.config.port }) catch return error.AddressTooLong;
                try client.connect(addr);
            } else {
                return error.NoConnectionMethod;
            }

            _ = try client.negotiate(m.config.offered_actions, m.config.offered_protocol);
            m.client = client;
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.total_connections += 1;
    }

    /// Disconnect all milters.
    pub fn disconnectAll(self: *MilterManager) void {
        for (self.milters.items) |*m| {
            if (m.client) |client| {
                client.sendQuit() catch {};
                client.deinit();
                self.allocator.destroy(client);
                m.client = null;
            }
        }
    }

    /// Run SMFIC_CONNECT through all milters.
    pub fn runConnect(
        self: *MilterManager,
        hostname: []const u8,
        family: MilterFamily,
        port: u16,
        address: []const u8,
    ) !MilterDisposition {
        for (self.milters.items) |*m| {
            if (!m.enabled) continue;
            const client = m.client orelse continue;

            const resp = try client.sendConnect(hostname, family, port, address);
            const disposition = responseToDisposition(resp.response);
            if (disposition != .accept) return disposition;
        }
        return .accept;
    }

    /// Run SMFIC_HELO through all milters.
    pub fn runHelo(self: *MilterManager, hostname: []const u8) !MilterDisposition {
        for (self.milters.items) |*m| {
            if (!m.enabled) continue;
            const client = m.client orelse continue;

            const resp = try client.sendHelo(hostname);
            const disposition = responseToDisposition(resp.response);
            if (disposition != .accept) return disposition;
        }
        return .accept;
    }

    /// Run SMFIC_MAIL through all milters.
    pub fn runMailFrom(
        self: *MilterManager,
        sender: []const u8,
        esmtp_args: ?[]const []const u8,
    ) !MilterDisposition {
        for (self.milters.items) |*m| {
            if (!m.enabled) continue;
            const client = m.client orelse continue;

            const resp = try client.sendMailFrom(sender, esmtp_args);
            const disposition = responseToDisposition(resp.response);
            if (disposition != .accept) return disposition;
        }
        return .accept;
    }

    /// Run SMFIC_RCPT through all milters.
    pub fn runRcptTo(
        self: *MilterManager,
        recipient: []const u8,
        esmtp_args: ?[]const []const u8,
    ) !MilterDisposition {
        for (self.milters.items) |*m| {
            if (!m.enabled) continue;
            const client = m.client orelse continue;

            const resp = try client.sendRcptTo(recipient, esmtp_args);
            const disposition = responseToDisposition(resp.response);
            if (disposition != .accept) return disposition;
        }
        return .accept;
    }

    /// Run headers through all milters.
    pub fn runHeaders(
        self: *MilterManager,
        headers: []const [2][]const u8,
    ) !MilterDisposition {
        for (self.milters.items) |*m| {
            if (!m.enabled) continue;
            const client = m.client orelse continue;

            for (headers) |hdr| {
                const resp = try client.sendHeader(hdr[0], hdr[1]);
                const disposition = responseToDisposition(resp.response);
                if (disposition != .accept) return disposition;
            }

            const eoh_resp = try client.sendEndOfHeaders();
            const eoh_disposition = responseToDisposition(eoh_resp.response);
            if (eoh_disposition != .accept) return eoh_disposition;
        }
        return .accept;
    }

    /// Run body through all milters (handles chunking automatically).
    pub fn runBody(self: *MilterManager, body: []const u8) !MilterDisposition {
        for (self.milters.items) |*m| {
            if (!m.enabled) continue;
            const client = m.client orelse continue;

            var offset: usize = 0;
            while (offset < body.len) {
                const remaining = body.len - offset;
                const chunk_size = @min(remaining, MILTER_CHUNK_SIZE);
                const resp = try client.sendBody(body[offset .. offset + chunk_size]);
                const disposition = responseToDisposition(resp.response);
                if (disposition != .accept) return disposition;
                offset += chunk_size;
            }
        }
        return .accept;
    }

    /// Run end-of-message through all milters and aggregate modifications.
    pub fn runEndOfMessage(self: *MilterManager) !struct {
        disposition: MilterDisposition,
        modifications: MilterModifications,
    } {
        var mods = MilterModifications.init(self.allocator);
        errdefer mods.deinit();

        for (self.milters.items) |*m| {
            if (!m.enabled) continue;
            const client = m.client orelse continue;

            const responses = try client.sendEndOfMessage();
            defer {
                for (responses) |*r| {
                    var resp = r.*;
                    resp.deinit(self.allocator);
                }
                self.allocator.free(responses);
            }

            // Check final disposition from each milter.
            for (responses) |resp| {
                if (resp.response.isFinalAction()) {
                    const disposition = responseToDisposition(resp.response);
                    if (disposition != .accept) {
                        self.mutex.lock();
                        defer self.mutex.unlock();
                        switch (disposition) {
                            .reject => self.stats.rejected += 1,
                            .temp_fail => self.stats.temp_failed += 1,
                            .discard => self.stats.discarded += 1,
                            else => {},
                        }
                        return .{
                            .disposition = disposition,
                            .modifications = mods,
                        };
                    }
                }
            }

            // Aggregate modifications.
            try mods.applyResponses(responses);
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        if (mods.quarantine_reason != null) {
            self.stats.quarantined += 1;
            return .{
                .disposition = .quarantine,
                .modifications = mods,
            };
        }

        self.stats.accepted += 1;
        return .{
            .disposition = .accept,
            .modifications = mods,
        };
    }

    /// Abort current message on all milters (connection stays open).
    pub fn abortAll(self: *MilterManager) void {
        for (self.milters.items) |*m| {
            if (!m.enabled) continue;
            if (m.client) |client| {
                client.sendAbort() catch {};
            }
        }
    }

    /// Get aggregated statistics.
    pub fn getStats(self: *MilterManager) MilterManagerStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    /// Reset statistics.
    pub fn resetStats(self: *MilterManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats = .{};
    }

    /// Return the number of registered milters.
    pub fn count(self: *const MilterManager) usize {
        return self.milters.items.len;
    }

    /// Return the number of enabled milters.
    pub fn enabledCount(self: *const MilterManager) usize {
        var n: usize = 0;
        for (self.milters.items) |m| {
            if (m.enabled) n += 1;
        }
        return n;
    }
};

/// Convert a milter response code to a disposition for the message pipeline.
fn responseToDisposition(resp: MilterResponse) MilterDisposition {
    return switch (resp) {
        .reject => .reject,
        .temp_fail => .temp_fail,
        .discard => .discard,
        .reply_code => .reject,
        else => .accept,
    };
}

/// Statistics tracked by the MilterManager.
pub const MilterManagerStats = struct {
    total_connections: usize = 0,
    accepted: usize = 0,
    rejected: usize = 0,
    temp_failed: usize = 0,
    discarded: usize = 0,
    quarantined: usize = 0,
    errors: usize = 0,
};

// ===========================================================================
// Tests
// ===========================================================================

test "MilterCommand byte values" {
    const testing = std.testing;

    try testing.expectEqual(@as(u8, 'A'), @intFromEnum(MilterCommand.abort));
    try testing.expectEqual(@as(u8, 'B'), @intFromEnum(MilterCommand.body));
    try testing.expectEqual(@as(u8, 'C'), @intFromEnum(MilterCommand.connect));
    try testing.expectEqual(@as(u8, 'D'), @intFromEnum(MilterCommand.macro));
    try testing.expectEqual(@as(u8, 'E'), @intFromEnum(MilterCommand.end_of_body));
    try testing.expectEqual(@as(u8, 'H'), @intFromEnum(MilterCommand.helo));
    try testing.expectEqual(@as(u8, 'L'), @intFromEnum(MilterCommand.header));
    try testing.expectEqual(@as(u8, 'N'), @intFromEnum(MilterCommand.end_of_headers));
    try testing.expectEqual(@as(u8, 'M'), @intFromEnum(MilterCommand.mail_from));
    try testing.expectEqual(@as(u8, 'O'), @intFromEnum(MilterCommand.option_negotiation));
    try testing.expectEqual(@as(u8, 'Q'), @intFromEnum(MilterCommand.quit));
    try testing.expectEqual(@as(u8, 'R'), @intFromEnum(MilterCommand.rcpt_to));
    try testing.expectEqual(@as(u8, 'T'), @intFromEnum(MilterCommand.data));
    try testing.expectEqual(@as(u8, 'K'), @intFromEnum(MilterCommand.quit_new_connection));
    try testing.expectEqual(@as(u8, 'U'), @intFromEnum(MilterCommand.unknown));
}

test "MilterCommand fromByte round-trips" {
    const testing = std.testing;

    const cmd = MilterCommand.fromByte('O');
    try testing.expect(cmd != null);
    try testing.expectEqual(MilterCommand.option_negotiation, cmd.?);

    // Unknown byte returns null
    try testing.expect(MilterCommand.fromByte(0xFF) == null);
}

test "MilterCommand toString" {
    const testing = std.testing;
    try testing.expectEqualStrings("SMFIC_OPTNEG", MilterCommand.option_negotiation.toString());
    try testing.expectEqualStrings("SMFIC_CONNECT", MilterCommand.connect.toString());
    try testing.expectEqualStrings("SMFIC_HELO", MilterCommand.helo.toString());
    try testing.expectEqualStrings("SMFIC_MAIL", MilterCommand.mail_from.toString());
    try testing.expectEqualStrings("SMFIC_RCPT", MilterCommand.rcpt_to.toString());
    try testing.expectEqualStrings("SMFIC_QUIT", MilterCommand.quit.toString());
}

test "MilterResponse byte values" {
    const testing = std.testing;

    try testing.expectEqual(@as(u8, '+'), @intFromEnum(MilterResponse.add_recipient));
    try testing.expectEqual(@as(u8, '-'), @intFromEnum(MilterResponse.delete_recipient));
    try testing.expectEqual(@as(u8, 'a'), @intFromEnum(MilterResponse.accept));
    try testing.expectEqual(@as(u8, 'b'), @intFromEnum(MilterResponse.replace_body));
    try testing.expectEqual(@as(u8, 'c'), @intFromEnum(MilterResponse.@"continue"));
    try testing.expectEqual(@as(u8, 'd'), @intFromEnum(MilterResponse.discard));
    try testing.expectEqual(@as(u8, 'h'), @intFromEnum(MilterResponse.add_header));
    try testing.expectEqual(@as(u8, 'i'), @intFromEnum(MilterResponse.insert_header));
    try testing.expectEqual(@as(u8, 'm'), @intFromEnum(MilterResponse.change_header));
    try testing.expectEqual(@as(u8, 'p'), @intFromEnum(MilterResponse.progress));
    try testing.expectEqual(@as(u8, 'q'), @intFromEnum(MilterResponse.quarantine));
    try testing.expectEqual(@as(u8, 'r'), @intFromEnum(MilterResponse.reject));
    try testing.expectEqual(@as(u8, 't'), @intFromEnum(MilterResponse.temp_fail));
    try testing.expectEqual(@as(u8, 'y'), @intFromEnum(MilterResponse.reply_code));
    try testing.expectEqual(@as(u8, 's'), @intFromEnum(MilterResponse.skip));
}

test "MilterResponse fromByte round-trips" {
    const testing = std.testing;

    const resp = MilterResponse.fromByte('c');
    try testing.expect(resp != null);
    try testing.expectEqual(MilterResponse.@"continue", resp.?);

    try testing.expect(MilterResponse.fromByte(0x00) == null);
}

test "MilterResponse isFinalAction" {
    const testing = std.testing;

    try testing.expect(MilterResponse.accept.isFinalAction());
    try testing.expect(MilterResponse.reject.isFinalAction());
    try testing.expect(MilterResponse.discard.isFinalAction());
    try testing.expect(MilterResponse.temp_fail.isFinalAction());
    try testing.expect(MilterResponse.reply_code.isFinalAction());

    try testing.expect(!MilterResponse.@"continue".isFinalAction());
    try testing.expect(!MilterResponse.progress.isFinalAction());
    try testing.expect(!MilterResponse.add_header.isFinalAction());
    try testing.expect(!MilterResponse.skip.isFinalAction());
}

test "MilterResponse isModification" {
    const testing = std.testing;

    try testing.expect(MilterResponse.add_header.isModification());
    try testing.expect(MilterResponse.change_header.isModification());
    try testing.expect(MilterResponse.add_recipient.isModification());
    try testing.expect(MilterResponse.delete_recipient.isModification());
    try testing.expect(MilterResponse.replace_body.isModification());
    try testing.expect(MilterResponse.quarantine.isModification());
    try testing.expect(MilterResponse.insert_header.isModification());

    try testing.expect(!MilterResponse.accept.isModification());
    try testing.expect(!MilterResponse.reject.isModification());
    try testing.expect(!MilterResponse.@"continue".isModification());
}

test "MilterActions packed struct layout" {
    const testing = std.testing;

    // Size must be exactly 4 bytes (u32)
    try testing.expectEqual(@as(usize, 4), @sizeOf(MilterActions));

    // Default (none) should be zero
    const none = MilterActions.none;
    try testing.expectEqual(@as(u32, 0), none.toNetworkU32());
}

test "MilterActions individual flags" {
    const testing = std.testing;

    const add_hdrs = MilterActions{ .add_headers = true };
    try testing.expect(add_hdrs.add_headers);
    try testing.expect(!add_hdrs.change_body);
    try testing.expect(add_hdrs.toNetworkU32() != 0);

    const chg_body = MilterActions{ .change_body = true };
    try testing.expect(!chg_body.add_headers);
    try testing.expect(chg_body.change_body);
}

test "MilterActions merge and intersect" {
    const testing = std.testing;

    const a = MilterActions{ .add_headers = true, .change_body = true };
    const b = MilterActions{ .change_body = true, .add_recipients = true };

    const merged = a.merge(b);
    try testing.expect(merged.add_headers);
    try testing.expect(merged.change_body);
    try testing.expect(merged.add_recipients);

    const intersected = a.intersect(b);
    try testing.expect(!intersected.add_headers);
    try testing.expect(intersected.change_body);
    try testing.expect(!intersected.add_recipients);
}

test "MilterActions hasAll" {
    const testing = std.testing;

    const flags = MilterActions{ .add_headers = true, .change_body = true, .quarantine = true };
    const required = MilterActions{ .add_headers = true, .quarantine = true };

    try testing.expect(flags.hasAll(required));

    const missing = MilterActions{ .add_headers = true, .add_recipients = true };
    try testing.expect(!flags.hasAll(missing));
}

test "MilterActions fromU32 round-trip" {
    const testing = std.testing;

    const original = MilterActions{
        .add_headers = true,
        .change_headers = true,
        .quarantine = true,
    };

    const wire = original.toNetworkU32();
    const decoded = MilterActions.fromU32(wire);

    try testing.expect(decoded.add_headers);
    try testing.expect(decoded.change_headers);
    try testing.expect(decoded.quarantine);
    try testing.expect(!decoded.change_body);
    try testing.expect(!decoded.add_recipients);
}

test "MilterProtocol packed struct layout" {
    const testing = std.testing;

    try testing.expectEqual(@as(usize, 4), @sizeOf(MilterProtocol));

    const none = MilterProtocol.all_callbacks;
    try testing.expectEqual(@as(u32, 0), none.toNetworkU32());
}

test "MilterProtocol individual flags" {
    const testing = std.testing;

    const no_body = MilterProtocol{ .no_body = true };
    try testing.expect(no_body.no_body);
    try testing.expect(!no_body.no_connect);
    try testing.expect(no_body.toNetworkU32() != 0);
}

test "MilterProtocol minimal skips all basic callbacks" {
    const testing = std.testing;

    const minimal = MilterProtocol.minimal;
    try testing.expect(minimal.no_connect);
    try testing.expect(minimal.no_helo);
    try testing.expect(minimal.no_mail);
    try testing.expect(minimal.no_rcpt);
    try testing.expect(minimal.no_body);
    try testing.expect(minimal.no_headers);
    try testing.expect(minimal.no_eoh);
}

test "MilterProtocol merge and intersect" {
    const testing = std.testing;

    const a = MilterProtocol{ .no_connect = true, .no_helo = true };
    const b = MilterProtocol{ .no_helo = true, .no_body = true };

    const merged = a.merge(b);
    try testing.expect(merged.no_connect);
    try testing.expect(merged.no_helo);
    try testing.expect(merged.no_body);

    const intersected = a.intersect(b);
    try testing.expect(!intersected.no_connect);
    try testing.expect(intersected.no_helo);
    try testing.expect(!intersected.no_body);
}

test "MilterFamily byte values" {
    const testing = std.testing;

    try testing.expectEqual(@as(u8, 'U'), @intFromEnum(MilterFamily.unknown));
    try testing.expectEqual(@as(u8, 'L'), @intFromEnum(MilterFamily.unix));
    try testing.expectEqual(@as(u8, '4'), @intFromEnum(MilterFamily.inet));
    try testing.expectEqual(@as(u8, '6'), @intFromEnum(MilterFamily.inet6));
}

test "MilterPacket encode command-only packet" {
    const testing = std.testing;

    const pkt = MilterPacket.commandOnly(.quit);
    var buf: [16]u8 = undefined;
    const encoded = try pkt.encode(&buf);

    // Length field = 1 (command only, no data)
    try testing.expectEqual(@as(usize, 5), encoded.len);
    // Network byte order length: 0x00000001
    try testing.expectEqual(@as(u8, 0), encoded[0]);
    try testing.expectEqual(@as(u8, 0), encoded[1]);
    try testing.expectEqual(@as(u8, 0), encoded[2]);
    try testing.expectEqual(@as(u8, 1), encoded[3]);
    // Command byte
    try testing.expectEqual(@as(u8, 'Q'), encoded[4]);
}

test "MilterPacket encode with data" {
    const testing = std.testing;

    const data = "test.example.com\x00";
    const pkt = MilterPacket{
        .command = @intFromEnum(MilterCommand.helo),
        .data = data,
    };

    var buf: [64]u8 = undefined;
    const encoded = try pkt.encode(&buf);

    // Total = 4 (len) + 1 (cmd) + 17 (data with null)
    try testing.expectEqual(@as(usize, 22), encoded.len);

    // Length field = 1 + 17 = 18 (0x00000012)
    const payload_len = std.mem.readInt(u32, encoded[0..4], .big);
    try testing.expectEqual(@as(u32, 18), payload_len);

    // Command
    try testing.expectEqual(@as(u8, 'H'), encoded[4]);

    // Data
    try testing.expectEqualStrings("test.example.com\x00", encoded[5..22]);
}

test "MilterPacket decode" {
    const testing = std.testing;

    // Manually construct a packet: len=1, cmd='a' (accept), no data
    const wire = [_]u8{ 0x00, 0x00, 0x00, 0x01, 'a' };
    const result = try MilterPacket.decode(&wire);

    try testing.expectEqual(@as(u8, 'a'), result.packet.command);
    try testing.expectEqual(@as(usize, 0), result.packet.data.len);
    try testing.expectEqual(@as(usize, 5), result.consumed);
}

test "MilterPacket decode with data" {
    const testing = std.testing;

    // len=6, cmd='h' (add_header), data = "To\x00me\x00"
    const wire = [_]u8{ 0x00, 0x00, 0x00, 0x06, 'h', 'T', 'o', 0x00, 'm', 'e' };
    const result = try MilterPacket.decode(&wire);

    try testing.expectEqual(@as(u8, 'h'), result.packet.command);
    try testing.expectEqual(@as(usize, 5), result.packet.data.len);
    try testing.expectEqualStrings("To\x00me", result.packet.data);
    try testing.expectEqual(@as(usize, 10), result.consumed);
}

test "MilterPacket encode-decode round-trip" {
    const testing = std.testing;

    const original = MilterPacket{
        .command = @intFromEnum(MilterCommand.header),
        .data = "Subject\x00Hello World\x00",
    };

    const encoded = try original.encodeAlloc(testing.allocator);
    defer testing.allocator.free(encoded);

    const result = try MilterPacket.decode(encoded);
    try testing.expectEqual(original.command, result.packet.command);
    try testing.expectEqualStrings(original.data, result.packet.data);
}

test "MilterPacket decode incomplete returns error" {
    const testing = std.testing;

    // Only 3 bytes (need 4 for length)
    const short = [_]u8{ 0x00, 0x00, 0x00 };
    try testing.expectError(error.Incomplete, MilterPacket.decode(&short));

    // Length says 10, but only 5 bytes total
    const partial = [_]u8{ 0x00, 0x00, 0x00, 0x0A, 'O' };
    try testing.expectError(error.Incomplete, MilterPacket.decode(&partial));
}

test "MilterPacket decode zero-length payload returns error" {
    const testing = std.testing;

    const wire = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(error.InvalidPacket, MilterPacket.decode(&wire));
}

test "MilterPacket decode oversized payload returns error" {
    const testing = std.testing;

    // Length = 0x10000000 (way too big)
    const wire = [_]u8{ 0x10, 0x00, 0x00, 0x00, 'O' };
    try testing.expectError(error.PacketTooLarge, MilterPacket.decode(&wire));
}

test "MilterPacket encode buffer too small" {
    const testing = std.testing;

    const pkt = MilterPacket{
        .command = @intFromEnum(MilterCommand.body),
        .data = "some body data",
    };

    var tiny_buf: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, pkt.encode(&tiny_buf));
}

test "MilterPacket encodedLen" {
    const testing = std.testing;

    const pkt_no_data = MilterPacket.commandOnly(.quit);
    try testing.expectEqual(@as(usize, 5), pkt_no_data.encodedLen());

    const pkt_with_data = MilterPacket{
        .command = @intFromEnum(MilterCommand.body),
        .data = "Hello",
    };
    try testing.expectEqual(@as(usize, 10), pkt_with_data.encodedLen());
}

test "negotiation packet encoding" {
    const testing = std.testing;

    // Build a SMFIC_OPTNEG packet like the client would
    var payload: [12]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], MILTER_VERSION_6, .big);
    std.mem.writeInt(u32, payload[4..8], MilterActions.all.toNetworkU32(), .big);
    std.mem.writeInt(u32, payload[8..12], MilterProtocol.all_callbacks.toNetworkU32(), .big);

    const pkt = MilterPacket{
        .command = @intFromEnum(MilterCommand.option_negotiation),
        .data = &payload,
    };

    const encoded = try pkt.encodeAlloc(testing.allocator);
    defer testing.allocator.free(encoded);

    // Decode and verify
    const result = try MilterPacket.decode(encoded);
    try testing.expectEqual(@as(u8, 'O'), result.packet.command);
    try testing.expectEqual(@as(usize, 12), result.packet.data.len);

    // Verify version field
    const version = std.mem.readInt(u32, result.packet.data[0..4], .big);
    try testing.expectEqual(MILTER_VERSION_6, version);
}

test "negotiation response parsing" {
    const testing = std.testing;

    // Simulate a milter negotiation response
    var response_data: [12]u8 = undefined;
    std.mem.writeInt(u32, response_data[0..4], MILTER_VERSION_6, .big);

    const milter_actions = MilterActions{
        .add_headers = true,
        .change_headers = true,
    };
    std.mem.writeInt(u32, response_data[4..8], milter_actions.toNetworkU32(), .big);

    const milter_protocol = MilterProtocol{
        .no_connect = true,
        .no_helo = true,
    };
    std.mem.writeInt(u32, response_data[8..12], milter_protocol.toNetworkU32(), .big);

    // Verify we can parse the response fields
    const version = std.mem.readInt(u32, response_data[0..4], .big);
    try testing.expectEqual(MILTER_VERSION_6, version);

    const parsed_actions = MilterActions.fromU32(std.mem.readInt(u32, response_data[4..8], .big));
    try testing.expect(parsed_actions.add_headers);
    try testing.expect(parsed_actions.change_headers);
    try testing.expect(!parsed_actions.change_body);

    const parsed_protocol = MilterProtocol.fromU32(std.mem.readInt(u32, response_data[8..12], .big));
    try testing.expect(parsed_protocol.no_connect);
    try testing.expect(parsed_protocol.no_helo);
    try testing.expect(!parsed_protocol.no_body);
}

test "negotiation intersection logic" {
    const testing = std.testing;

    // MTA offers everything
    const mta_actions = MilterActions.all;
    const mta_protocol = MilterProtocol.all_callbacks;

    // Milter only wants add_headers and no_body
    const milter_actions = MilterActions{ .add_headers = true };
    const milter_protocol = MilterProtocol{ .no_body = true };

    // Intersection = what both agree on
    const negotiated_actions = mta_actions.intersect(milter_actions);
    try testing.expect(negotiated_actions.add_headers);
    try testing.expect(!negotiated_actions.change_body);
    try testing.expect(!negotiated_actions.add_recipients);

    const negotiated_protocol = mta_protocol.intersect(milter_protocol);
    // all_callbacks is all-zeros, so intersection with anything is all-zeros
    try testing.expect(!negotiated_protocol.no_body);
}

test "MilterConfig validation" {
    const testing = std.testing;

    // Valid Unix socket config
    const unix_config = MilterConfig{
        .socket_path = "/var/run/milter.sock",
    };
    try unix_config.validate();

    // Valid TCP config
    const tcp_config = MilterConfig{
        .host = "127.0.0.1",
        .port = 8893,
    };
    try tcp_config.validate();

    // Invalid: no connection method
    const no_method = MilterConfig{};
    try testing.expectError(error.NoConnectionMethod, no_method.validate());

    // Invalid: both methods
    const both = MilterConfig{
        .socket_path = "/var/run/milter.sock",
        .host = "127.0.0.1",
        .port = 8893,
    };
    try testing.expectError(error.AmbiguousConnectionMethod, both.validate());

    // Invalid: TCP without port
    const no_port = MilterConfig{
        .host = "127.0.0.1",
    };
    try testing.expectError(error.MissingPort, no_port.validate());
}

test "MilterClient initialization" {
    const testing = std.testing;

    const config = MilterConfig{
        .socket_path = "/var/run/milter.sock",
        .timeout_ms = 10_000,
        .name = "test-milter",
    };

    var client = try MilterClient.init(testing.allocator, config);
    defer client.deinit();

    try testing.expect(!client.isConnected());
    try testing.expectEqual(@as(u32, 0), client.negotiated_version);
}

test "MilterClient stats tracking" {
    const testing = std.testing;

    const config = MilterConfig{
        .socket_path = "/var/run/milter.sock",
        .name = "stats-test",
    };

    var client = try MilterClient.init(testing.allocator, config);
    defer client.deinit();

    const stats = client.getStats();
    try testing.expectEqual(@as(usize, 0), stats.connections);
    try testing.expectEqual(@as(usize, 0), stats.packets_sent);
    try testing.expectEqual(@as(usize, 0), stats.packets_received);
    try testing.expectEqual(@as(usize, 0), stats.errors);
}

test "MilterDisposition toString" {
    const testing = std.testing;

    try testing.expectEqualStrings("accept", MilterDisposition.accept.toString());
    try testing.expectEqualStrings("reject", MilterDisposition.reject.toString());
    try testing.expectEqualStrings("temp_fail", MilterDisposition.temp_fail.toString());
    try testing.expectEqualStrings("discard", MilterDisposition.discard.toString());
    try testing.expectEqualStrings("quarantine", MilterDisposition.quarantine.toString());
}

test "responseToDisposition mapping" {
    const testing = std.testing;

    try testing.expectEqual(MilterDisposition.reject, responseToDisposition(.reject));
    try testing.expectEqual(MilterDisposition.temp_fail, responseToDisposition(.temp_fail));
    try testing.expectEqual(MilterDisposition.discard, responseToDisposition(.discard));
    try testing.expectEqual(MilterDisposition.reject, responseToDisposition(.reply_code));
    try testing.expectEqual(MilterDisposition.accept, responseToDisposition(.accept));
    try testing.expectEqual(MilterDisposition.accept, responseToDisposition(.@"continue"));
    try testing.expectEqual(MilterDisposition.accept, responseToDisposition(.progress));
}

test "MilterManager initialization and milter registration" {
    const testing = std.testing;

    var manager = MilterManager.init(testing.allocator);
    defer manager.deinit();

    try testing.expectEqual(@as(usize, 0), manager.count());

    try manager.addMilter(.{
        .socket_path = "/var/run/opendkim.sock",
        .name = "opendkim",
    });
    try manager.addMilter(.{
        .host = "127.0.0.1",
        .port = 8893,
        .name = "spamass-milter",
    });
    try manager.addMilter(.{
        .socket_path = "/var/run/clamav-milter.sock",
        .name = "clamav-milter",
    });

    try testing.expectEqual(@as(usize, 3), manager.count());
    try testing.expectEqual(@as(usize, 3), manager.enabledCount());
}

test "MilterManager enable/disable" {
    const testing = std.testing;

    var manager = MilterManager.init(testing.allocator);
    defer manager.deinit();

    try manager.addMilter(.{
        .socket_path = "/var/run/milter1.sock",
        .name = "milter1",
    });
    try manager.addMilter(.{
        .socket_path = "/var/run/milter2.sock",
        .name = "milter2",
    });

    try testing.expectEqual(@as(usize, 2), manager.enabledCount());

    const found = manager.setEnabled("milter1", false);
    try testing.expect(found);
    try testing.expectEqual(@as(usize, 1), manager.enabledCount());

    // Non-existent milter
    const not_found = manager.setEnabled("nonexistent", false);
    try testing.expect(!not_found);
}

test "MilterManager remove milter" {
    const testing = std.testing;

    var manager = MilterManager.init(testing.allocator);
    defer manager.deinit();

    try manager.addMilter(.{
        .socket_path = "/var/run/milter1.sock",
        .name = "milter1",
    });
    try manager.addMilter(.{
        .socket_path = "/var/run/milter2.sock",
        .name = "milter2",
    });

    try testing.expectEqual(@as(usize, 2), manager.count());

    const removed = manager.removeMilter("milter1");
    try testing.expect(removed);
    try testing.expectEqual(@as(usize, 1), manager.count());

    const not_removed = manager.removeMilter("nonexistent");
    try testing.expect(!not_removed);
}

test "MilterManager stats" {
    const testing = std.testing;

    var manager = MilterManager.init(testing.allocator);
    defer manager.deinit();

    const stats = manager.getStats();
    try testing.expectEqual(@as(usize, 0), stats.total_connections);
    try testing.expectEqual(@as(usize, 0), stats.accepted);
    try testing.expectEqual(@as(usize, 0), stats.rejected);
}

test "MilterModifications init and deinit" {
    const testing = std.testing;

    var mods = MilterModifications.init(testing.allocator);
    defer mods.deinit();

    // Add some modifications
    try mods.added_headers.append(testing.allocator, .{
        .name = try testing.allocator.dupe(u8, "X-Milter"),
        .value = try testing.allocator.dupe(u8, "Processed"),
    });

    try mods.added_recipients.append(testing.allocator, try testing.allocator.dupe(u8, "bcc@example.com"));

    try testing.expectEqual(@as(usize, 1), mods.added_headers.items.len);
    try testing.expectEqual(@as(usize, 1), mods.added_recipients.items.len);
}

test "MilterModifications applyResponses" {
    const testing = std.testing;

    var mods = MilterModifications.init(testing.allocator);
    defer mods.deinit();

    // Create mock response data
    const responses = [_]MilterResponseData{
        .{
            .response = .add_header,
            .header_name = "X-Spam-Flag",
            .header_value = "YES",
        },
        .{
            .response = .add_recipient,
            .recipient = "archive@example.com",
        },
        .{
            .response = .delete_recipient,
            .recipient = "blocked@example.com",
        },
        .{
            .response = .accept,
        },
    };

    try mods.applyResponses(&responses);

    try testing.expectEqual(@as(usize, 1), mods.added_headers.items.len);
    try testing.expectEqualStrings("X-Spam-Flag", mods.added_headers.items[0].name);
    try testing.expectEqualStrings("YES", mods.added_headers.items[0].value);

    try testing.expectEqual(@as(usize, 1), mods.added_recipients.items.len);
    try testing.expectEqualStrings("archive@example.com", mods.added_recipients.items[0]);

    try testing.expectEqual(@as(usize, 1), mods.deleted_recipients.items.len);
    try testing.expectEqualStrings("blocked@example.com", mods.deleted_recipients.items[0]);
}

test "findNull helper" {
    const testing = std.testing;

    const data = "hello\x00world\x00";
    try testing.expectEqual(@as(?usize, 5), findNull(data, 0));
    try testing.expectEqual(@as(?usize, 11), findNull(data, 6));
    try testing.expect(findNull(data, 20) == null);
}

test "MilterResponseData toString coverage" {
    const testing = std.testing;

    try testing.expectEqualStrings("SMFIR_ACCEPT", MilterResponse.accept.toString());
    try testing.expectEqualStrings("SMFIR_REJECT", MilterResponse.reject.toString());
    try testing.expectEqualStrings("SMFIR_CONTINUE", MilterResponse.@"continue".toString());
    try testing.expectEqualStrings("SMFIR_TEMPFAIL", MilterResponse.temp_fail.toString());
    try testing.expectEqualStrings("SMFIR_DISCARD", MilterResponse.discard.toString());
    try testing.expectEqualStrings("SMFIR_QUARANTINE", MilterResponse.quarantine.toString());
    try testing.expectEqualStrings("SMFIR_ADDHEADER", MilterResponse.add_header.toString());
    try testing.expectEqualStrings("SMFIR_CHGHEADER", MilterResponse.change_header.toString());
    try testing.expectEqualStrings("SMFIR_ADDRCPT", MilterResponse.add_recipient.toString());
    try testing.expectEqualStrings("SMFIR_DELRCPT", MilterResponse.delete_recipient.toString());
    try testing.expectEqualStrings("SMFIR_REPLBODY", MilterResponse.replace_body.toString());
    try testing.expectEqualStrings("SMFIR_PROGRESS", MilterResponse.progress.toString());
    try testing.expectEqualStrings("SMFIR_REPLYCODE", MilterResponse.reply_code.toString());
    try testing.expectEqualStrings("SMFIR_SKIP", MilterResponse.skip.toString());
}

test "protocol version constants" {
    const testing = std.testing;

    try testing.expectEqual(@as(u32, 2), MILTER_VERSION_2);
    try testing.expectEqual(@as(u32, 6), MILTER_VERSION_6);
    try testing.expectEqual(@as(u32, 6), MILTER_VERSION_DEFAULT);
    try testing.expectEqual(@as(usize, 65535), MILTER_CHUNK_SIZE);
}

test "MilterActions all has expected flags" {
    const testing = std.testing;

    const all = MilterActions.all;
    try testing.expect(all.add_headers);
    try testing.expect(all.change_body);
    try testing.expect(all.add_recipients);
    try testing.expect(all.delete_recipients);
    try testing.expect(all.change_headers);
    try testing.expect(all.quarantine);
    try testing.expect(all.change_from);
    try testing.expect(all.add_recipients_par);
    try testing.expect(all.set_symbol_list);
}

test "MilterFamily toString" {
    const testing = std.testing;

    try testing.expectEqualStrings("unknown", MilterFamily.unknown.toString());
    try testing.expectEqualStrings("unix", MilterFamily.unix.toString());
    try testing.expectEqualStrings("inet", MilterFamily.inet.toString());
    try testing.expectEqualStrings("inet6", MilterFamily.inet6.toString());
}

test "MilterPacket multiple packets in buffer" {
    const testing = std.testing;

    // Two packets concatenated: accept + continue
    const wire = [_]u8{
        // Packet 1: accept (no data)
        0x00, 0x00, 0x00, 0x01, 'a',
        // Packet 2: continue (no data)
        0x00, 0x00, 0x00, 0x01, 'c',
    };

    const result1 = try MilterPacket.decode(&wire);
    try testing.expectEqual(@as(u8, 'a'), result1.packet.command);
    try testing.expectEqual(@as(usize, 5), result1.consumed);

    const result2 = try MilterPacket.decode(wire[result1.consumed..]);
    try testing.expectEqual(@as(u8, 'c'), result2.packet.command);
    try testing.expectEqual(@as(usize, 5), result2.consumed);
}

test "MilterPacket network byte order verification" {
    const testing = std.testing;

    // Verify that a packet with data length 256 (0x100) is encoded correctly
    var data: [256]u8 = undefined;
    @memset(&data, 'X');

    const pkt = MilterPacket{
        .command = @intFromEnum(MilterCommand.body),
        .data = &data,
    };

    const encoded = try pkt.encodeAlloc(testing.allocator);
    defer testing.allocator.free(encoded);

    // Length field should be 257 (1 cmd + 256 data) = 0x00000101
    try testing.expectEqual(@as(u8, 0x00), encoded[0]);
    try testing.expectEqual(@as(u8, 0x00), encoded[1]);
    try testing.expectEqual(@as(u8, 0x01), encoded[2]);
    try testing.expectEqual(@as(u8, 0x01), encoded[3]);

    // Verify round-trip
    const result = try MilterPacket.decode(encoded);
    try testing.expectEqual(@as(u8, 'B'), result.packet.command);
    try testing.expectEqual(@as(usize, 256), result.packet.data.len);
}
