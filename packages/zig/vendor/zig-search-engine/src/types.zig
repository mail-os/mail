//! Shared types for the search-engine drivers.
//!
//! A `Schema` plays the role the Stacks model's `useSearch` trait plays in
//! @stacksjs/search-engine: it declares which attributes of a collection
//! are searchable, filterable (facets), and sortable, and the driver turns
//! that declaration into the engine-native collection structure.

const std = @import("std");

pub const FieldType = enum {
    string,
    int64,
    float,
    bool_,

    pub fn typesenseName(self: FieldType) []const u8 {
        return switch (self) {
            .string => "string",
            .int64 => "int64",
            .float => "float",
            .bool_ => "bool",
        };
    }
};

pub const Field = struct {
    name: []const u8,
    type: FieldType = .string,
};

/// Model-style declaration of a searchable collection.
pub const Schema = struct {
    /// Collection (index/table) name.
    name: []const u8,
    /// Attributes full-text queries run against.
    searchable: []const Field = &.{},
    /// Attributes usable in filter expressions (engine facets).
    filterable: []const Field = &.{},
    /// Attributes usable for sorting.
    sortable: []const Field = &.{},
    /// Stored-only attributes (returned with hits, not searched).
    displayed: []const Field = &.{},
};

pub const SearchParams = struct {
    query: []const u8,
    /// Comma-separated field list to query (e.g. "subject,body").
    query_by: []const u8,
    /// Raw engine filter expression (driver-specific syntax), if any.
    filter_by: ?[]const u8 = null,
    /// Comma-separated "field:asc|desc" list, if any.
    sort_by: ?[]const u8 = null,
    page: u32 = 1,
    per_page: u32 = 50,
};

pub const Error = error{
    Disabled,
    ConnectFailed,
    WriteFailed,
    BadResponse,
    RequestFailed,
    OutOfMemory,
};
