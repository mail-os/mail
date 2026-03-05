const std = @import("std");
const database = @import("../storage/database.zig");
const auth_mod = @import("../auth/auth.zig");
const password_mod = @import("../auth/password.zig");

/// GraphQL API for user management
/// Supports queries and mutations for CRUD operations on users
pub const GraphQLError = error{
    ParseError,
    ValidationError,
    ExecutionError,
    Unauthorized,
    NotFound,
    AlreadyExists,
    InvalidInput,
    OutOfMemory,
};

/// GraphQL operation type
pub const OperationType = enum {
    query,
    mutation,
};

/// Parsed GraphQL operation
pub const Operation = struct {
    op_type: OperationType,
    name: ?[]const u8,
    selection_set: []const Field,
};

/// GraphQL field selection
pub const Field = struct {
    name: []const u8,
    arguments: []const Argument,
    selection_set: []const Field,
};

/// GraphQL argument
pub const Argument = struct {
    name: []const u8,
    value: Value,
};

/// GraphQL value types
pub const Value = union(enum) {
    string: []const u8,
    int: i64,
    float: f64,
    boolean: bool,
    null_value: void,
};

/// GraphQL executor for user management
pub const GraphQLExecutor = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    auth: *auth_mod.AuthBackend,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, auth: *auth_mod.AuthBackend) GraphQLExecutor {
        return .{
            .allocator = allocator,
            .db = db,
            .auth = auth,
        };
    }

    /// Execute a GraphQL query string
    pub fn execute(self: *GraphQLExecutor, query: []const u8) ![]u8 {
        // Parse the query
        var parser = GraphQLParser.init(self.allocator, query);
        const operation = parser.parse() catch |err| {
            return self.formatError("Parse error: {}", .{err});
        };

        // Execute based on operation type
        return switch (operation.op_type) {
            .query => self.executeQuery(operation),
            .mutation => self.executeMutation(operation),
        };
    }

    fn executeQuery(self: *GraphQLExecutor, operation: Operation) ![]u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        defer result.deinit();

        const writer = result.writer();
        try writer.writeAll("{\"data\":{");

        var first = true;
        for (operation.selection_set) |field| {
            if (!first) try writer.writeAll(",");
            first = false;

            if (std.mem.eql(u8, field.name, "users")) {
                try self.resolveUsers(writer, field);
            } else if (std.mem.eql(u8, field.name, "user")) {
                try self.resolveUser(writer, field);
            } else if (std.mem.eql(u8, field.name, "__schema")) {
                try self.resolveSchema(writer);
            } else {
                try writer.print("\"{s}\":null", .{field.name});
            }
        }

        try writer.writeAll("}}");
        return result.toOwnedSlice();
    }

    fn executeMutation(self: *GraphQLExecutor, operation: Operation) ![]u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        defer result.deinit();

        const writer = result.writer();
        try writer.writeAll("{\"data\":{");

        var first = true;
        for (operation.selection_set) |field| {
            if (!first) try writer.writeAll(",");
            first = false;

            if (std.mem.eql(u8, field.name, "createUser")) {
                try self.resolveCreateUser(writer, field);
            } else if (std.mem.eql(u8, field.name, "updateUser")) {
                try self.resolveUpdateUser(writer, field);
            } else if (std.mem.eql(u8, field.name, "deleteUser")) {
                try self.resolveDeleteUser(writer, field);
            } else if (std.mem.eql(u8, field.name, "changePassword")) {
                try self.resolveChangePassword(writer, field);
            } else if (std.mem.eql(u8, field.name, "setUserEnabled")) {
                try self.resolveSetUserEnabled(writer, field);
            } else {
                try writer.print("\"{s}\":null", .{field.name});
            }
        }

        try writer.writeAll("}}");
        return result.toOwnedSlice();
    }

    // Query resolvers

    fn resolveUsers(self: *GraphQLExecutor, writer: anytype, field: Field) !void {
        try writer.writeAll("\"users\":[");

        // Get all users from database
        const users = self.db.getAllUsers() catch |err| {
            try writer.print("]", .{});
            _ = err;
            return;
        };
        defer {
            for (users) |*user| {
                user.deinit(self.allocator);
            }
            self.allocator.free(users);
        }

        var first = true;
        for (users) |user| {
            if (!first) try writer.writeAll(",");
            first = false;
            try self.writeUserFields(writer, user, field.selection_set);
        }

        try writer.writeAll("]");
    }

    fn resolveUser(self: *GraphQLExecutor, writer: anytype, field: Field) !void {
        // Get username argument
        const username = self.getStringArg(field.arguments, "username") orelse {
            try writer.writeAll("\"user\":null");
            return;
        };

        const user = self.db.getUserByUsername(username) catch {
            try writer.writeAll("\"user\":null");
            return;
        };
        defer user.deinit(self.allocator);

        try writer.writeAll("\"user\":");
        try self.writeUserFields(writer, user, field.selection_set);
    }

    fn resolveSchema(self: *GraphQLExecutor, writer: anytype) !void {
        _ = self;
        try writer.writeAll("\"__schema\":{");
        try writer.writeAll("\"types\":[");
        try writer.writeAll("{\"name\":\"User\",\"fields\":[");
        try writer.writeAll("{\"name\":\"id\",\"type\":\"ID\"},");
        try writer.writeAll("{\"name\":\"username\",\"type\":\"String\"},");
        try writer.writeAll("{\"name\":\"email\",\"type\":\"String\"},");
        try writer.writeAll("{\"name\":\"enabled\",\"type\":\"Boolean\"},");
        try writer.writeAll("{\"name\":\"createdAt\",\"type\":\"Int\"},");
        try writer.writeAll("{\"name\":\"updatedAt\",\"type\":\"Int\"}");
        try writer.writeAll("]}");
        try writer.writeAll("],\"queryType\":{\"name\":\"Query\"},\"mutationType\":{\"name\":\"Mutation\"}}");
    }

    // Mutation resolvers

    fn resolveCreateUser(self: *GraphQLExecutor, writer: anytype, field: Field) !void {
        const username = self.getStringArg(field.arguments, "username") orelse {
            try writer.writeAll("\"createUser\":null");
            return;
        };
        const password = self.getStringArg(field.arguments, "password") orelse {
            try writer.writeAll("\"createUser\":null");
            return;
        };
        const email = self.getStringArg(field.arguments, "email") orelse {
            try writer.writeAll("\"createUser\":null");
            return;
        };

        // Hash the password
        var hasher = password_mod.PasswordHasher.init();
        const password_hash = hasher.hash(password, self.allocator) catch {
            try writer.writeAll("\"createUser\":null");
            return;
        };
        defer self.allocator.free(password_hash);

        // Create user
        _ = self.db.createUser(username, password_hash, email) catch |err| {
            if (err == database.DatabaseError.AlreadyExists) {
                try writer.writeAll("\"createUser\":{\"success\":false,\"error\":\"User already exists\"}");
            } else {
                try writer.writeAll("\"createUser\":{\"success\":false,\"error\":\"Database error\"}");
            }
            return;
        };

        // Fetch the created user to return
        const user = self.db.getUserByUsername(username) catch {
            try writer.writeAll("\"createUser\":{\"success\":true}");
            return;
        };
        defer user.deinit(self.allocator);

        try writer.writeAll("\"createUser\":{\"success\":true,\"user\":");
        try self.writeUserFields(writer, user, field.selection_set);
        try writer.writeAll("}");
    }

    fn resolveUpdateUser(self: *GraphQLExecutor, writer: anytype, field: Field) !void {
        const username = self.getStringArg(field.arguments, "username") orelse {
            try writer.writeAll("\"updateUser\":null");
            return;
        };

        // Check if user exists
        var user = self.db.getUserByUsername(username) catch {
            try writer.writeAll("\"updateUser\":{\"success\":false,\"error\":\"User not found\"}");
            return;
        };
        defer user.deinit(self.allocator);

        // Update email if provided
        if (self.getStringArg(field.arguments, "email")) |email| {
            self.db.updateUserEmail(username, email) catch {
                try writer.writeAll("\"updateUser\":{\"success\":false,\"error\":\"Failed to update email\"}");
                return;
            };
        }

        // Update enabled status if provided
        if (self.getBoolArg(field.arguments, "enabled")) |enabled| {
            self.db.setUserEnabled(username, enabled) catch {
                try writer.writeAll("\"updateUser\":{\"success\":false,\"error\":\"Failed to update status\"}");
                return;
            };
        }

        // Refetch updated user
        const updated_user = self.db.getUserByUsername(username) catch {
            try writer.writeAll("\"updateUser\":{\"success\":true}");
            return;
        };
        defer updated_user.deinit(self.allocator);

        try writer.writeAll("\"updateUser\":{\"success\":true,\"user\":");
        try self.writeUserFields(writer, updated_user, field.selection_set);
        try writer.writeAll("}");
    }

    fn resolveDeleteUser(self: *GraphQLExecutor, writer: anytype, field: Field) !void {
        const username = self.getStringArg(field.arguments, "username") orelse {
            try writer.writeAll("\"deleteUser\":{\"success\":false,\"error\":\"Username required\"}");
            return;
        };

        self.db.deleteUser(username) catch {
            try writer.writeAll("\"deleteUser\":{\"success\":false,\"error\":\"User not found\"}");
            return;
        };

        try writer.print("\"deleteUser\":{{\"success\":true,\"username\":\"{s}\"}}", .{username});
    }

    fn resolveChangePassword(self: *GraphQLExecutor, writer: anytype, field: Field) !void {
        const username = self.getStringArg(field.arguments, "username") orelse {
            try writer.writeAll("\"changePassword\":{\"success\":false,\"error\":\"Username required\"}");
            return;
        };
        const new_password = self.getStringArg(field.arguments, "newPassword") orelse {
            try writer.writeAll("\"changePassword\":{\"success\":false,\"error\":\"New password required\"}");
            return;
        };

        // Hash the new password
        var hasher = password_mod.PasswordHasher.init();
        const password_hash = hasher.hash(new_password, self.allocator) catch {
            try writer.writeAll("\"changePassword\":{\"success\":false,\"error\":\"Failed to hash password\"}");
            return;
        };
        defer self.allocator.free(password_hash);

        self.db.updateUserPassword(username, password_hash) catch {
            try writer.writeAll("\"changePassword\":{\"success\":false,\"error\":\"User not found\"}");
            return;
        };

        try writer.writeAll("\"changePassword\":{\"success\":true}");
    }

    fn resolveSetUserEnabled(self: *GraphQLExecutor, writer: anytype, field: Field) !void {
        const username = self.getStringArg(field.arguments, "username") orelse {
            try writer.writeAll("\"setUserEnabled\":{\"success\":false,\"error\":\"Username required\"}");
            return;
        };
        const enabled = self.getBoolArg(field.arguments, "enabled") orelse {
            try writer.writeAll("\"setUserEnabled\":{\"success\":false,\"error\":\"Enabled status required\"}");
            return;
        };

        self.db.setUserEnabled(username, enabled) catch {
            try writer.writeAll("\"setUserEnabled\":{\"success\":false,\"error\":\"User not found\"}");
            return;
        };

        try writer.print("\"setUserEnabled\":{{\"success\":true,\"username\":\"{s}\",\"enabled\":{}}}", .{ username, enabled });
    }

    // Helper functions

    fn writeUserFields(self: *GraphQLExecutor, writer: anytype, user: database.User, selection: []const Field) !void {
        _ = self;
        try writer.writeAll("{");

        var first = true;

        // If no selection set, return all fields
        if (selection.len == 0) {
            try writer.print("\"id\":{d},", .{user.id});
            try writer.print("\"username\":\"{s}\",", .{user.username});
            try writer.print("\"email\":\"{s}\",", .{user.email});
            try writer.print("\"enabled\":{},", .{user.enabled});
            try writer.print("\"createdAt\":{d},", .{user.created_at});
            try writer.print("\"updatedAt\":{d}", .{user.updated_at});
        } else {
            for (selection) |field| {
                if (!first) try writer.writeAll(",");
                first = false;

                if (std.mem.eql(u8, field.name, "id")) {
                    try writer.print("\"id\":{d}", .{user.id});
                } else if (std.mem.eql(u8, field.name, "username")) {
                    try writer.print("\"username\":\"{s}\"", .{user.username});
                } else if (std.mem.eql(u8, field.name, "email")) {
                    try writer.print("\"email\":\"{s}\"", .{user.email});
                } else if (std.mem.eql(u8, field.name, "enabled")) {
                    try writer.print("\"enabled\":{}", .{user.enabled});
                } else if (std.mem.eql(u8, field.name, "createdAt")) {
                    try writer.print("\"createdAt\":{d}", .{user.created_at});
                } else if (std.mem.eql(u8, field.name, "updatedAt")) {
                    try writer.print("\"updatedAt\":{d}", .{user.updated_at});
                }
            }
        }

        try writer.writeAll("}");
    }

    fn getStringArg(self: *GraphQLExecutor, args: []const Argument, name: []const u8) ?[]const u8 {
        _ = self;
        for (args) |arg| {
            if (std.mem.eql(u8, arg.name, name)) {
                return switch (arg.value) {
                    .string => |s| s,
                    else => null,
                };
            }
        }
        return null;
    }

    fn getBoolArg(self: *GraphQLExecutor, args: []const Argument, name: []const u8) ?bool {
        _ = self;
        for (args) |arg| {
            if (std.mem.eql(u8, arg.name, name)) {
                return switch (arg.value) {
                    .boolean => |b| b,
                    else => null,
                };
            }
        }
        return null;
    }

    fn formatError(self: *GraphQLExecutor, comptime fmt: []const u8, args: anytype) ![]u8 {
        // First format the raw message, then JSON-escape it
        var msg_buf: std.ArrayList(u8) = .{};
        defer msg_buf.deinit(self.allocator);
        try msg_buf.writer(self.allocator).print(fmt, args);

        var result: std.ArrayList(u8) = .{};
        errdefer result.deinit(self.allocator);
        try result.appendSlice(self.allocator, "{\"errors\":[{\"message\":\"");
        // Escape JSON special characters in the message
        for (msg_buf.items) |c| {
            switch (c) {
                '"' => try result.appendSlice(self.allocator, "\\\""),
                '\\' => try result.appendSlice(self.allocator, "\\\\"),
                '\n' => try result.appendSlice(self.allocator, "\\n"),
                '\r' => try result.appendSlice(self.allocator, "\\r"),
                '\t' => try result.appendSlice(self.allocator, "\\t"),
                else => try result.append(self.allocator, c),
            }
        }
        try result.appendSlice(self.allocator, "\"}]}");
        return try result.toOwnedSlice(self.allocator);
    }
};

/// Simple GraphQL parser
pub const GraphQLParser = struct {
    allocator: std.mem.Allocator,
    source: []const u8,
    pos: usize,
    fields: std.ArrayList(Field),
    arguments: std.ArrayList(Argument),

    pub fn init(allocator: std.mem.Allocator, source: []const u8) GraphQLParser {
        return .{
            .allocator = allocator,
            .source = source,
            .pos = 0,
            .fields = std.ArrayList(Field).init(allocator),
            .arguments = std.ArrayList(Argument).init(allocator),
        };
    }

    pub fn deinit(self: *GraphQLParser) void {
        self.fields.deinit();
        self.arguments.deinit();
    }

    pub fn parse(self: *GraphQLParser) !Operation {
        self.skipWhitespace();

        // Parse operation type
        var op_type: OperationType = .query;
        var name: ?[]const u8 = null;

        if (self.matchKeyword("mutation")) {
            op_type = .mutation;
            self.skipWhitespace();
            name = self.parseOptionalName();
        } else if (self.matchKeyword("query")) {
            op_type = .query;
            self.skipWhitespace();
            name = self.parseOptionalName();
        }

        // Parse selection set
        self.skipWhitespace();
        const selection_set = try self.parseSelectionSet();

        return Operation{
            .op_type = op_type,
            .name = name,
            .selection_set = selection_set,
        };
    }

    fn parseSelectionSet(self: *GraphQLParser) ![]const Field {
        self.skipWhitespace();

        if (!self.consume('{')) {
            return &[_]Field{};
        }

        var fields = std.ArrayList(Field).init(self.allocator);

        while (true) {
            self.skipWhitespace();

            if (self.peek() == '}' or self.pos >= self.source.len) {
                break;
            }

            const field = try self.parseField();
            try fields.append(field);
        }

        _ = self.consume('}');

        return fields.toOwnedSlice();
    }

    fn parseField(self: *GraphQLParser) !Field {
        self.skipWhitespace();

        const name = self.parseName() orelse return error.ParseError;

        self.skipWhitespace();

        // Parse arguments if present
        var arguments: []const Argument = &[_]Argument{};
        if (self.peek() == '(') {
            arguments = try self.parseArguments();
        }

        self.skipWhitespace();

        // Parse nested selection set if present
        var selection_set: []const Field = &[_]Field{};
        if (self.peek() == '{') {
            selection_set = try self.parseSelectionSet();
        }

        return Field{
            .name = name,
            .arguments = arguments,
            .selection_set = selection_set,
        };
    }

    fn parseArguments(self: *GraphQLParser) ![]const Argument {
        if (!self.consume('(')) {
            return &[_]Argument{};
        }

        var args = std.ArrayList(Argument).init(self.allocator);

        while (true) {
            self.skipWhitespace();

            if (self.peek() == ')' or self.pos >= self.source.len) {
                break;
            }

            const arg = try self.parseArgument();
            try args.append(arg);

            self.skipWhitespace();
            _ = self.consume(',');
        }

        _ = self.consume(')');

        return args.toOwnedSlice();
    }

    fn parseArgument(self: *GraphQLParser) !Argument {
        self.skipWhitespace();

        const name = self.parseName() orelse return error.ParseError;

        self.skipWhitespace();

        if (!self.consume(':')) {
            return error.ParseError;
        }

        self.skipWhitespace();

        const value = try self.parseValue();

        return Argument{
            .name = name,
            .value = value,
        };
    }

    fn parseValue(self: *GraphQLParser) !Value {
        self.skipWhitespace();

        const c = self.peek();

        if (c == '"') {
            return Value{ .string = try self.parseString() };
        } else if (c == 't' or c == 'f') {
            return Value{ .boolean = try self.parseBoolean() };
        } else if (c == 'n') {
            if (self.matchKeyword("null")) {
                return Value{ .null_value = {} };
            }
        } else if (c == '-' or std.ascii.isDigit(c)) {
            return Value{ .int = try self.parseInt() };
        }

        return error.ParseError;
    }

    fn parseString(self: *GraphQLParser) ![]const u8 {
        if (!self.consume('"')) {
            return error.ParseError;
        }

        const start = self.pos;

        while (self.pos < self.source.len and self.source[self.pos] != '"') {
            if (self.source[self.pos] == '\\' and self.pos + 1 < self.source.len) {
                self.pos += 2; // Skip escape sequence
            } else {
                self.pos += 1;
            }
        }

        const end = self.pos;
        _ = self.consume('"');

        return self.source[start..end];
    }

    fn parseBoolean(self: *GraphQLParser) !bool {
        if (self.matchKeyword("true")) {
            return true;
        } else if (self.matchKeyword("false")) {
            return false;
        }
        return error.ParseError;
    }

    fn parseInt(self: *GraphQLParser) !i64 {
        const start = self.pos;

        if (self.peek() == '-') {
            self.pos += 1;
        }

        while (self.pos < self.source.len and std.ascii.isDigit(self.source[self.pos])) {
            self.pos += 1;
        }

        if (self.pos == start) {
            return error.ParseError;
        }

        return std.fmt.parseInt(i64, self.source[start..self.pos], 10) catch return error.ParseError;
    }

    fn parseName(self: *GraphQLParser) ?[]const u8 {
        const start = self.pos;

        if (self.pos >= self.source.len) return null;

        const first = self.source[self.pos];
        if (!std.ascii.isAlphabetic(first) and first != '_') {
            return null;
        }

        self.pos += 1;

        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (!std.ascii.isAlphanumeric(c) and c != '_') {
                break;
            }
            self.pos += 1;
        }

        if (self.pos == start) return null;

        return self.source[start..self.pos];
    }

    fn parseOptionalName(self: *GraphQLParser) ?[]const u8 {
        self.skipWhitespace();
        return self.parseName();
    }

    fn matchKeyword(self: *GraphQLParser, keyword: []const u8) bool {
        if (self.pos + keyword.len > self.source.len) {
            return false;
        }

        if (std.mem.eql(u8, self.source[self.pos .. self.pos + keyword.len], keyword)) {
            // Make sure it's not part of a longer identifier
            if (self.pos + keyword.len < self.source.len) {
                const next = self.source[self.pos + keyword.len];
                if (std.ascii.isAlphanumeric(next) or next == '_') {
                    return false;
                }
            }
            self.pos += keyword.len;
            return true;
        }

        return false;
    }

    fn peek(self: *GraphQLParser) u8 {
        if (self.pos >= self.source.len) return 0;
        return self.source[self.pos];
    }

    fn consume(self: *GraphQLParser, expected: u8) bool {
        if (self.pos < self.source.len and self.source[self.pos] == expected) {
            self.pos += 1;
            return true;
        }
        return false;
    }

    fn skipWhitespace(self: *GraphQLParser) void {
        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == ',') {
                self.pos += 1;
            } else if (c == '#') {
                // Skip comments
                while (self.pos < self.source.len and self.source[self.pos] != '\n') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }
};

/// GraphQL schema definition (for introspection)
pub const schema =
    \\type Query {
    \\  users: [User!]!
    \\  user(username: String!): User
    \\}
    \\
    \\type Mutation {
    \\  createUser(username: String!, password: String!, email: String!): CreateUserResult!
    \\  updateUser(username: String!, email: String, enabled: Boolean): UpdateUserResult!
    \\  deleteUser(username: String!): DeleteUserResult!
    \\  changePassword(username: String!, newPassword: String!): ChangePasswordResult!
    \\  setUserEnabled(username: String!, enabled: Boolean!): SetUserEnabledResult!
    \\}
    \\
    \\type User {
    \\  id: ID!
    \\  username: String!
    \\  email: String!
    \\  enabled: Boolean!
    \\  createdAt: Int!
    \\  updatedAt: Int!
    \\}
    \\
    \\type CreateUserResult {
    \\  success: Boolean!
    \\  user: User
    \\  error: String
    \\}
    \\
    \\type UpdateUserResult {
    \\  success: Boolean!
    \\  user: User
    \\  error: String
    \\}
    \\
    \\type DeleteUserResult {
    \\  success: Boolean!
    \\  username: String
    \\  error: String
    \\}
    \\
    \\type ChangePasswordResult {
    \\  success: Boolean!
    \\  error: String
    \\}
    \\
    \\type SetUserEnabledResult {
    \\  success: Boolean!
    \\  username: String
    \\  enabled: Boolean
    \\  error: String
    \\}
;

// Tests
test "parse simple query" {
    const allocator = std.testing.allocator;

    const query = "{ users { id username email } }";
    var parser = GraphQLParser.init(allocator, query);
    defer parser.deinit();

    const operation = try parser.parse();

    try std.testing.expectEqual(OperationType.query, operation.op_type);
    try std.testing.expectEqual(@as(usize, 1), operation.selection_set.len);
    try std.testing.expectEqualStrings("users", operation.selection_set[0].name);
}

test "parse mutation with arguments" {
    const allocator = std.testing.allocator;

    const query =
        \\mutation {
        \\  createUser(username: "test", password: "pass123", email: "test@example.com") {
        \\    success
        \\    user { id username }
        \\  }
        \\}
    ;

    var parser = GraphQLParser.init(allocator, query);
    defer parser.deinit();

    const operation = try parser.parse();

    try std.testing.expectEqual(OperationType.mutation, operation.op_type);
    try std.testing.expectEqual(@as(usize, 1), operation.selection_set.len);
    try std.testing.expectEqualStrings("createUser", operation.selection_set[0].name);
    try std.testing.expectEqual(@as(usize, 3), operation.selection_set[0].arguments.len);
}
