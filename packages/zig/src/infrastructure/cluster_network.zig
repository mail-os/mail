const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const cluster = @import("cluster.zig");

/// Network communication for cluster nodes
pub const ClusterNetwork = struct {
    allocator: std.mem.Allocator,
    local_address: std.net.Address,
    listener: ?std.net.Server,
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !*ClusterNetwork {
        const network = try allocator.create(ClusterNetwork);

        const address = try std.net.Address.parseIp(host, port);

        network.* = .{
            .allocator = allocator,
            .local_address = address,
            .listener = null,
            .running = std.atomic.Value(bool).init(false),
        };

        return network;
    }

    pub fn deinit(self: *ClusterNetwork) void {
        self.stop();
        self.allocator.destroy(self);
    }

    /// Start listening for cluster messages
    pub fn start(self: *ClusterNetwork) !void {
        self.listener = try self.local_address.listen(.{
            .reuse_address = true,
        });

        self.running.store(true, .release);

        std.log.info("Cluster network listening on {}", .{self.local_address});
    }

    /// Stop listening
    pub fn stop(self: *ClusterNetwork) void {
        self.running.store(false, .release);

        if (self.listener) |*listener| {
            listener.deinit();
            self.listener = null;
        }
    }

    /// Accept incoming connection (blocking)
    pub fn accept(self: *ClusterNetwork) !std.net.Server.Connection {
        if (self.listener) |*listener| {
            return try listener.accept();
        }
        return error.NotListening;
    }

    /// Send heartbeat to a node
    pub fn sendHeartbeat(self: *ClusterNetwork, node: *cluster.ClusterNode, local_node: *cluster.ClusterNode) !void {
        const address = try std.net.Address.parseIp(node.address, node.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        const message = HeartbeatMessage{
            .node_id = local_node.id,
            .role = local_node.role,
            .timestamp = time_compat.timestamp(),
            .metadata = local_node.metadata,
        };

        try self.sendMessage(stream, .heartbeat, message);
    }

    /// Send state replication message
    pub fn sendStateUpdate(self: *ClusterNetwork, node: *cluster.ClusterNode, key: []const u8, value: []const u8) !void {
        const address = try std.net.Address.parseIp(node.address, node.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        const message = StateUpdateMessage{
            .key = key,
            .value = value,
            .timestamp = time_compat.timestamp(),
        };

        try self.sendMessage(stream, .state_update, message);
    }

    /// Send leader election message
    pub fn sendElectionRequest(self: *ClusterNetwork, node: *cluster.ClusterNode, candidate_id: []const u8) !void {
        const address = try std.net.Address.parseIp(node.address, node.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        const message = ElectionMessage{
            .candidate_id = candidate_id,
            .timestamp = time_compat.timestamp(),
        };

        try self.sendMessage(stream, .election, message);
    }

    /// Receive message (blocking)
    pub fn receiveMessage(self: *ClusterNetwork, stream: std.net.Stream) !ClusterMessage {
        _ = self;

        // Read message type (1 byte)
        var type_buf: [1]u8 = undefined;
        _ = try stream.read(&type_buf);

        const msg_type = std.meta.intToEnum(MessageType, type_buf[0]) catch {
            return error.InvalidMessageType;
        };

        // Read message length (4 bytes, big-endian)
        var len_buf: [4]u8 = undefined;
        _ = try stream.read(&len_buf);
        const msg_len = std.mem.readInt(u32, &len_buf, .big);

        if (msg_len > 1024 * 1024) { // 1MB max
            return error.MessageTooLarge;
        }

        // Read message body
        const body = try self.allocator.alloc(u8, msg_len);
        errdefer self.allocator.free(body);

        _ = try stream.readAll(body);

        return ClusterMessage{
            .type = msg_type,
            .body = body,
        };
    }

    /// Send a cluster message
    fn sendMessage(self: *ClusterNetwork, stream: std.net.Stream, msg_type: MessageType, message: anytype) !void {
        var body = std.ArrayList(u8).init(self.allocator);
        defer body.deinit();

        try std.json.stringify(message, .{}, body.writer());

        // Write message type (1 byte)
        const type_byte = [1]u8{@intFromEnum(msg_type)};
        _ = try stream.write(&type_byte);

        // Write message length (4 bytes, big-endian)
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(body.items.len), .big);
        _ = try stream.write(&len_buf);

        // Write message body
        _ = try stream.write(body.items);
    }
};

/// Cluster message types
pub const MessageType = enum(u8) {
    heartbeat = 1,
    state_update = 2,
    election = 3,
    vote = 4,
    leader_announce = 5,
};

/// Cluster message wrapper
pub const ClusterMessage = struct {
    type: MessageType,
    body: []const u8,
};

/// Heartbeat message
pub const HeartbeatMessage = struct {
    node_id: []const u8,
    role: cluster.NodeRole,
    timestamp: i64,
    metadata: cluster.NodeMetadata,
};

/// State update message
pub const StateUpdateMessage = struct {
    key: []const u8,
    value: []const u8,
    timestamp: i64,
};

/// Election message
pub const ElectionMessage = struct {
    candidate_id: []const u8,
    timestamp: i64,
};

/// Vote message
pub const VoteMessage = struct {
    voter_id: []const u8,
    candidate_id: []const u8,
    granted: bool,
};

/// Leader announcement message
pub const LeaderAnnounceMessage = struct {
    leader_id: []const u8,
    term: u64,
};

test "cluster network init" {
    const allocator = std.testing.allocator;

    const network = try ClusterNetwork.init(allocator, "127.0.0.1", 9000);
    defer network.deinit();

    try std.testing.expect(!network.running.load(.acquire));
}
