//! zig-search-engine — search-engine integrations for Zig services.
//!
//! A Zig port of the ideas in @stacksjs/search-engine: collections are
//! declared as model-style `Schema`s (searchable / filterable / sortable
//! attributes) and a driver turns that declaration into the engine-native
//! data structure. Typesense is the first driver.
//!
//! ```zig
//! const se = @import("search-engine");
//!
//! const messages_schema = se.Schema{
//!     .name = "messages",
//!     .searchable = &.{ .{ .name = "subject" }, .{ .name = "body" } },
//!     .filterable = &.{ .{ .name = "username" }, .{ .name = "mailbox" } },
//!     .sortable = &.{ .{ .name = "date", .type = .int64 } },
//! };
//!
//! const engine = se.Typesense.init(.{ .api_key = key });
//! try engine.ensureCollection(allocator, messages_schema);
//!
//! var doc = se.DocBuilder.init(allocator);
//! defer doc.deinit();
//! try doc.putString("id", "msg-1");
//! try doc.putString("subject", "hello");
//! const json = try doc.toOwned();
//! defer allocator.free(json);
//! try engine.upsertDocument(allocator, "messages", json);
//!
//! var result = try engine.search(allocator, "messages", .{
//!     .query = "hello",
//!     .query_by = "subject,body",
//!     .filter_by = "username:=`chris`",
//! });
//! defer result.deinit();
//! ```

const std = @import("std");

pub const types = @import("types.zig");
pub const http = @import("http.zig");

pub const Schema = types.Schema;
pub const Field = types.Field;
pub const FieldType = types.FieldType;
pub const SearchParams = types.SearchParams;
pub const Error = types.Error;

pub const typesense = @import("drivers/typesense.zig");
pub const Typesense = typesense.Typesense;
pub const TypesenseConfig = typesense.Config;
pub const SearchResponse = typesense.SearchResponse;
pub const DocBuilder = typesense.DocBuilder;

test {
    std.testing.refAllDecls(@This());
    _ = @import("http.zig");
    _ = @import("drivers/typesense.zig");
}
