# zig-search-engine

Search-engine integrations for Zig services — a Zig take on
[`@stacksjs/search-engine`](https://github.com/stacksjs/stacks/tree/main/storage/framework/core/search-engine).

Collections are declared as model-style `Schema`s (searchable / filterable /
sortable attributes), and a driver turns that declaration into the
engine-native data structure. **Typesense** is the first driver.

## Usage

```zig
const se = @import("search-engine");

// The model: which attributes are searchable, filterable (facets), sortable.
const messages_schema = se.Schema{
    .name = "messages",
    .searchable = &.{ .{ .name = "subject" }, .{ .name = "body" } },
    .filterable = &.{ .{ .name = "username" }, .{ .name = "mailbox" } },
    .sortable = &.{ .{ .name = "date", .type = .int64 } },
};

const engine = se.Typesense.init(.{ .api_key = key }); // host/port default to 127.0.0.1:8108
try engine.ensureCollection(allocator, messages_schema);

// Index a document
var doc = se.DocBuilder.init(allocator);
defer doc.deinit();
try doc.putString("id", "msg-1");
try doc.putString("subject", "hello world");
const json = try doc.toOwned();
defer allocator.free(json);
try engine.upsertDocument(allocator, "messages", json);

// Search
var result = try engine.search(allocator, "messages", .{
    .query = "hello",
    .query_by = "subject,body",
    .filter_by = "username:=`chris`",
});
defer result.deinit();

var it = result.hits();
while (it.next()) |hit| {
    std.debug.print("{s}\n", .{se.SearchResponse.docString(hit, "subject")});
}
```

Also provided: `importDocuments` (JSONL bulk upsert), `deleteDocument`,
`deleteCollection`, `healthy`, and JSON/URL encoding helpers under
`se.http`.

## Requirements

- Zig `0.16.0-dev`+ (developed against `0.17.0-dev`)
- libc (the HTTP client uses libc sockets)

## Install

```sh
zig fetch --save https://github.com/zig-utils/zig-search-engine/archive/<commit>.tar.gz
```

Then in `build.zig`:

```zig
const search_engine = b.dependency("search_engine", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("search-engine", search_engine.module("search-engine"));
```

## License

MIT
