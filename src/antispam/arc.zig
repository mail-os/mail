const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

// =============================================================================
// ARC (Authenticated Received Chain) - RFC 8617
//
// ARC provides an authenticated chain of custody for messages that pass through
// intermediaries (mailing lists, forwarders). It builds on DKIM infrastructure
// and consists of three headers per hop:
//   - ARC-Authentication-Results (AAR)
//   - ARC-Message-Signature (AMS)
//   - ARC-Seal (AS)
//
// Each set is numbered with an instance (i=) starting at 1, forming a chain
// that allows downstream receivers to verify the authentication status at
// each hop.
// =============================================================================

/// ARC validation result
pub const ARCResult = enum {
    pass,
    fail,
    none,
    temperror,
    permerror,

    pub fn toString(self: ARCResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .none => "none",
            .temperror => "temperror",
            .permerror => "permerror",
        };
    }

    pub fn fromString(s: []const u8) ARCResult {
        if (std.ascii.eqlIgnoreCase(s, "pass")) return .pass;
        if (std.ascii.eqlIgnoreCase(s, "fail")) return .fail;
        if (std.ascii.eqlIgnoreCase(s, "none")) return .none;
        if (std.ascii.eqlIgnoreCase(s, "temperror")) return .temperror;
        if (std.ascii.eqlIgnoreCase(s, "permerror")) return .permerror;
        return .none;
    }
};

/// Chain validation status (cv= tag in ARC-Seal)
pub const ARCChainValidation = enum {
    none,
    pass,
    fail,

    pub fn toString(self: ARCChainValidation) []const u8 {
        return switch (self) {
            .none => "none",
            .pass => "pass",
            .fail => "fail",
        };
    }

    pub fn fromString(s: []const u8) ARCChainValidation {
        if (std.ascii.eqlIgnoreCase(s, "pass")) return .pass;
        if (std.ascii.eqlIgnoreCase(s, "fail")) return .fail;
        return .none;
    }
};

/// ARC-Authentication-Results header (AAR)
/// Contains the authentication results observed at this hop.
pub const ARCAuthenticationResults = struct {
    instance: u32, // i= tag
    results: []const u8, // authentication results string
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ARCAuthenticationResults) void {
        self.allocator.free(self.results);
    }

    /// Parse ARC-Authentication-Results header value
    /// Format: i=1; mx.example.com; dkim=pass header.d=example.com; spf=pass
    pub fn parse(allocator: std.mem.Allocator, header_value: []const u8) !ARCAuthenticationResults {
        var aar = ARCAuthenticationResults{
            .instance = 0,
            .results = "",
            .allocator = allocator,
        };
        errdefer {
            if (aar.results.len > 0) allocator.free(aar.results);
        }

        // The AAR header value starts with i=N; followed by the results
        const trimmed = std.mem.trim(u8, header_value, " \t\r\n");

        // Extract instance number from i= tag
        if (std.mem.startsWith(u8, trimmed, "i=")) {
            const semicolon_pos = std.mem.indexOf(u8, trimmed, ";") orelse {
                return error.InvalidAARHeader;
            };
            const instance_str = std.mem.trim(u8, trimmed[2..semicolon_pos], " \t");
            aar.instance = std.fmt.parseInt(u32, instance_str, 10) catch {
                return error.InvalidInstanceNumber;
            };

            // Everything after the first semicolon is the results
            const results_part = std.mem.trim(u8, trimmed[semicolon_pos + 1 ..], " \t");
            aar.results = try allocator.dupe(u8, results_part);
        } else {
            return error.InvalidAARHeader;
        }

        if (aar.instance == 0) {
            return error.InvalidInstanceNumber;
        }

        return aar;
    }

    /// Format as a complete header line
    pub fn format(self: *const ARCAuthenticationResults, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "ARC-Authentication-Results: i={d}; {s}",
            .{ self.instance, self.results },
        );
    }
};

/// ARC-Message-Signature header (AMS)
/// Reuses the DKIM signature format with an additional instance number (i=).
pub const ARCMessageSignature = struct {
    instance: u32, // i= tag
    algorithm: []const u8, // a= tag (e.g., "rsa-sha256")
    domain: []const u8, // d= tag
    selector: []const u8, // s= tag
    headers: []const u8, // h= tag (signed headers list)
    body_hash: []const u8, // bh= tag
    signature: []const u8, // b= tag
    canonicalization: []const u8, // c= tag (default: relaxed/relaxed)
    timestamp: ?i64, // t= tag (signature timestamp)
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ARCMessageSignature) void {
        self.allocator.free(self.algorithm);
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        self.allocator.free(self.headers);
        self.allocator.free(self.body_hash);
        self.allocator.free(self.signature);
        self.allocator.free(self.canonicalization);
    }

    /// Parse ARC-Message-Signature header value
    /// Format: i=1; a=rsa-sha256; d=example.com; s=selector; h=from:to:subject;
    ///         bh=BODYHASH==; b=SIGNATURE==
    pub fn parse(allocator: std.mem.Allocator, header_value: []const u8) !ARCMessageSignature {
        var ams = ARCMessageSignature{
            .instance = 0,
            .algorithm = "",
            .domain = "",
            .selector = "",
            .headers = "",
            .body_hash = "",
            .signature = "",
            .canonicalization = try allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = allocator,
        };
        errdefer {
            if (ams.algorithm.len > 0) allocator.free(ams.algorithm);
            if (ams.domain.len > 0) allocator.free(ams.domain);
            if (ams.selector.len > 0) allocator.free(ams.selector);
            if (ams.headers.len > 0) allocator.free(ams.headers);
            if (ams.body_hash.len > 0) allocator.free(ams.body_hash);
            if (ams.signature.len > 0) allocator.free(ams.signature);
            allocator.free(ams.canonicalization);
        }

        // Parse tag=value pairs separated by semicolons
        var tags = std.mem.splitScalar(u8, header_value, ';');
        while (tags.next()) |tag| {
            const trimmed = std.mem.trim(u8, tag, " \t\r\n");
            if (trimmed.len == 0) continue;

            const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const tag_name = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const tag_value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (std.mem.eql(u8, tag_name, "i")) {
                ams.instance = std.fmt.parseInt(u32, tag_value, 10) catch {
                    return error.InvalidInstanceNumber;
                };
            } else if (std.mem.eql(u8, tag_name, "a")) {
                ams.algorithm = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "d")) {
                ams.domain = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "s")) {
                ams.selector = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "h")) {
                ams.headers = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "bh")) {
                ams.body_hash = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "b")) {
                ams.signature = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "c")) {
                allocator.free(ams.canonicalization);
                ams.canonicalization = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "t")) {
                ams.timestamp = std.fmt.parseInt(i64, tag_value, 10) catch null;
            }
        }

        // Validate required fields
        if (ams.instance == 0) {
            return error.InvalidInstanceNumber;
        }
        if (ams.algorithm.len == 0 or ams.domain.len == 0 or
            ams.selector.len == 0 or ams.signature.len == 0)
        {
            return error.InvalidAMSHeader;
        }

        return ams;
    }

    /// Format as a complete header line
    pub fn format(self: *const ARCMessageSignature, allocator: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .{};
        errdefer buf.deinit(allocator);

        try buf.print(allocator,
            "ARC-Message-Signature: i={d}; a={s}; c={s}; d={s}; s={s};\r\n" ++
                "\th={s};\r\n" ++
                "\tbh={s};\r\n",
            .{
                self.instance,
                self.algorithm,
                self.canonicalization,
                self.domain,
                self.selector,
                self.headers,
                self.body_hash,
            },
        );
        if (self.timestamp) |ts| {
            try buf.print(allocator, "\tt={d};\r\n", .{ts});
        }
        try buf.print(allocator, "\tb={s}", .{self.signature});

        return buf.toOwnedSlice(allocator);
    }
};

/// ARC-Seal header (AS)
/// Contains the seal signature that covers the ARC chain headers.
pub const ARCSeal = struct {
    instance: u32, // i= tag
    algorithm: []const u8, // a= tag (e.g., "rsa-sha256")
    domain: []const u8, // d= tag
    selector: []const u8, // s= tag
    signature: []const u8, // b= tag (seal signature)
    chain_validation: ARCChainValidation, // cv= tag
    timestamp: ?i64, // t= tag (seal timestamp)
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ARCSeal) void {
        self.allocator.free(self.algorithm);
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        self.allocator.free(self.signature);
    }

    /// Parse ARC-Seal header value
    /// Format: i=1; a=rsa-sha256; d=example.com; s=selector; cv=none; b=SIGNATURE==
    pub fn parse(allocator: std.mem.Allocator, header_value: []const u8) !ARCSeal {
        var seal = ARCSeal{
            .instance = 0,
            .algorithm = "",
            .domain = "",
            .selector = "",
            .signature = "",
            .chain_validation = .none,
            .timestamp = null,
            .allocator = allocator,
        };
        errdefer {
            if (seal.algorithm.len > 0) allocator.free(seal.algorithm);
            if (seal.domain.len > 0) allocator.free(seal.domain);
            if (seal.selector.len > 0) allocator.free(seal.selector);
            if (seal.signature.len > 0) allocator.free(seal.signature);
        }

        // Parse tag=value pairs separated by semicolons
        var tags = std.mem.splitScalar(u8, header_value, ';');
        while (tags.next()) |tag| {
            const trimmed = std.mem.trim(u8, tag, " \t\r\n");
            if (trimmed.len == 0) continue;

            const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const tag_name = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const tag_value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (std.mem.eql(u8, tag_name, "i")) {
                seal.instance = std.fmt.parseInt(u32, tag_value, 10) catch {
                    return error.InvalidInstanceNumber;
                };
            } else if (std.mem.eql(u8, tag_name, "a")) {
                seal.algorithm = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "d")) {
                seal.domain = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "s")) {
                seal.selector = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "b")) {
                seal.signature = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "cv")) {
                seal.chain_validation = ARCChainValidation.fromString(tag_value);
            } else if (std.mem.eql(u8, tag_name, "t")) {
                seal.timestamp = std.fmt.parseInt(i64, tag_value, 10) catch null;
            }
        }

        // Validate required fields
        if (seal.instance == 0) {
            return error.InvalidInstanceNumber;
        }
        if (seal.algorithm.len == 0 or seal.domain.len == 0 or
            seal.selector.len == 0 or seal.signature.len == 0)
        {
            return error.InvalidASSeal;
        }

        return seal;
    }

    /// Format as a complete header line
    pub fn format(self: *const ARCSeal, allocator: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .{};
        errdefer buf.deinit(allocator);

        try buf.print(allocator,
            "ARC-Seal: i={d}; a={s}; d={s}; s={s};\r\n" ++
                "\tcv={s};",
            .{
                self.instance,
                self.algorithm,
                self.domain,
                self.selector,
                self.chain_validation.toString(),
            },
        );
        if (self.timestamp) |ts| {
            try buf.print(allocator, "\r\n\tt={d};", .{ts});
        }
        try buf.print(allocator, "\r\n\tb={s}", .{self.signature});

        return buf.toOwnedSlice(allocator);
    }
};

/// A complete ARC set for a single hop (instance number).
/// Each set consists of exactly one AAR, AMS, and AS with the same instance number.
pub const ARCSet = struct {
    instance: u32,
    aar: ARCAuthenticationResults,
    ams: ARCMessageSignature,
    seal: ARCSeal,

    pub fn deinit(self: *ARCSet) void {
        self.aar.deinit();
        self.ams.deinit();
        self.seal.deinit();
    }

    /// Validate that all components have the same instance number
    pub fn validateInstanceConsistency(self: *const ARCSet) bool {
        return self.aar.instance == self.instance and
            self.ams.instance == self.instance and
            self.seal.instance == self.instance;
    }
};

/// The full ARC chain: an ordered list of ARC sets.
pub const ARCChain = struct {
    sets: std.ArrayList(ARCSet),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ARCChain {
        return .{
            .sets = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ARCChain) void {
        for (self.sets.items) |*set| {
            set.deinit();
        }
        self.sets.deinit(self.allocator);
    }

    /// Add a set to the chain
    pub fn addSet(self: *ARCChain, set: ARCSet) !void {
        try self.sets.append(self.allocator, set);
    }

    /// Get the number of sets in the chain
    pub fn count(self: *const ARCChain) usize {
        return self.sets.items.len;
    }

    /// Get a set by instance number (1-based)
    pub fn getSet(self: *const ARCChain, instance: u32) ?*const ARCSet {
        for (self.sets.items) |*set| {
            if (set.instance == instance) {
                return set;
            }
        }
        return null;
    }

    /// Validate the entire chain:
    /// - Instance numbers must be sequential 1..n
    /// - Each set must have consistent instance numbers across its three headers
    /// - Chain validation (cv=) must be correct:
    ///   * i=1 must have cv=none
    ///   * i>1 must have cv=pass (if chain was valid at that point)
    ///   * Any cv=fail means the chain is broken from that point
    pub fn validateChainIntegrity(self: *const ARCChain) ARCChainValidation {
        const n = self.sets.items.len;
        if (n == 0) return .none;

        // Sort sets by instance number for validation
        // (we validate that they are sequential 1..n)
        for (self.sets.items) |*set| {
            if (!set.validateInstanceConsistency()) {
                return .fail;
            }
        }

        // Check that instance numbers form a complete sequence 1..n
        var i: u32 = 1;
        while (i <= @as(u32, @intCast(n))) : (i += 1) {
            const set = self.getSet(i) orelse return .fail;

            // Validate cv= tag rules per RFC 8617
            if (i == 1) {
                // First set must have cv=none
                if (set.seal.chain_validation != .none) {
                    return .fail;
                }
            } else {
                // Subsequent sets must have cv=pass to indicate valid chain
                // If cv=fail, the chain is broken
                if (set.seal.chain_validation == .fail) {
                    return .fail;
                }
                if (set.seal.chain_validation == .none) {
                    // cv=none is only valid for i=1
                    return .fail;
                }
            }
        }

        return .pass;
    }

    /// Get the latest chain validation status from the most recent set
    pub fn latestChainValidation(self: *const ARCChain) ARCChainValidation {
        const n = self.sets.items.len;
        if (n == 0) return .none;

        // Find the set with the highest instance number
        var max_instance: u32 = 0;
        var latest_cv: ARCChainValidation = .none;

        for (self.sets.items) |set| {
            if (set.instance > max_instance) {
                max_instance = set.instance;
                latest_cv = set.seal.chain_validation;
            }
        }

        return latest_cv;
    }
};

/// Formatted ARC header strings ready for injection into a message
pub const ARCHeaderSet = struct {
    aar_header: []const u8, // Complete ARC-Authentication-Results header line
    ams_header: []const u8, // Complete ARC-Message-Signature header line
    seal_header: []const u8, // Complete ARC-Seal header line
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ARCHeaderSet) void {
        self.allocator.free(self.aar_header);
        self.allocator.free(self.ams_header);
        self.allocator.free(self.seal_header);
    }

    /// Produce the full header block (all three headers separated by CRLF)
    pub fn toHeaderBlock(self: *const ARCHeaderSet, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "{s}\r\n{s}\r\n{s}",
            .{ self.aar_header, self.ams_header, self.seal_header },
        );
    }
};

/// ARC Validator: extracts and validates ARC sets from message headers.
pub const ARCValidator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ARCValidator {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ARCValidator) void {
        _ = self;
        // No persistent state to clean up
    }

    /// Validate the ARC chain present in the given message headers.
    /// Returns the overall ARC validation result.
    pub fn validateChain(self: *ARCValidator, headers: []const u8) !ARCResult {
        // Extract ARC sets from headers
        var chain = self.extractARCSets(headers) catch |err| {
            return switch (err) {
                error.InvalidInstanceNumber,
                error.InvalidAARHeader,
                error.InvalidAMSHeader,
                error.InvalidASSeal,
                => .permerror,
                error.OutOfMemory => .temperror,
                else => .temperror,
            };
        };
        defer chain.deinit();

        // If no ARC sets found, result is none
        if (chain.count() == 0) {
            return .none;
        }

        // RFC 8617: no more than 50 ARC sets
        if (chain.count() > 50) {
            return .permerror;
        }

        // Validate chain order (instance numbers sequential 1..n)
        const order_result = self.validateChainOrder(&chain);
        if (!order_result) {
            return .fail;
        }

        // Validate chain integrity (cv= tags, consistency)
        const integrity = chain.validateChainIntegrity();
        if (integrity == .fail) {
            return .fail;
        }

        // Validate each individual set
        for (chain.sets.items) |*set| {
            const set_valid = self.validateSet(set, set.instance);
            if (!set_valid) {
                return .fail;
            }
        }

        // If we reach here, the chain structure is valid
        // In a production system we would also verify cryptographic signatures
        // using DNS-fetched public keys, similar to DKIM validation
        return .pass;
    }

    /// Extract ARC sets from raw message headers.
    /// Parses all ARC-Authentication-Results, ARC-Message-Signature, and
    /// ARC-Seal headers, then groups them by instance number.
    pub fn extractARCSets(self: *ARCValidator, headers: []const u8) !ARCChain {
        var chain = ARCChain.init(self.allocator);
        errdefer chain.deinit();

        // Collect individual ARC headers
        var aars: std.ArrayList(ARCAuthenticationResults) = .{};
        defer {
            for (aars.items) |*aar| aar.deinit();
            aars.deinit(self.allocator);
        }

        var amss: std.ArrayList(ARCMessageSignature) = .{};
        defer {
            for (amss.items) |*ams| ams.deinit();
            amss.deinit(self.allocator);
        }

        var seals: std.ArrayList(ARCSeal) = .{};
        defer {
            for (seals.items) |*seal| seal.deinit();
            seals.deinit(self.allocator);
        }

        // Parse headers line by line, handling folded headers (continuation lines)
        var lines = std.mem.splitSequence(u8, headers, "\r\n");
        var current_header_name: ?[]const u8 = null;
        var current_value: std.ArrayList(u8) = .{};
        defer current_value.deinit(self.allocator);

        while (lines.next()) |line| {
            if (line.len == 0) {
                // End of headers
                break;
            }

            // Check if this is a continuation line (starts with whitespace)
            if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
                // Continuation of previous header
                if (current_header_name != null) {
                    const trimmed_continuation = std.mem.trim(u8, line, " \t");
                    try current_value.append(self.allocator, ' ');
                    try current_value.appendSlice(self.allocator, trimmed_continuation);
                }
                continue;
            }

            // Process the completed previous header
            if (current_header_name) |name| {
                try self.processExtractedHeader(
                    name,
                    current_value.items,
                    &aars,
                    &amss,
                    &seals,
                );
            }

            // Start a new header
            current_value.clearRetainingCapacity();

            const colon_pos = std.mem.indexOf(u8, line, ":") orelse {
                current_header_name = null;
                continue;
            };

            const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
            const header_value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");

            if (std.ascii.eqlIgnoreCase(header_name, "ARC-Authentication-Results") or
                std.ascii.eqlIgnoreCase(header_name, "ARC-Message-Signature") or
                std.ascii.eqlIgnoreCase(header_name, "ARC-Seal"))
            {
                current_header_name = header_name;
                try current_value.appendSlice(self.allocator, header_value);
            } else {
                current_header_name = null;
            }
        }

        // Process last header if it was an ARC header
        if (current_header_name) |name| {
            try self.processExtractedHeader(
                name,
                current_value.items,
                &aars,
                &amss,
                &seals,
            );
        }

        // Group headers into ARC sets by instance number
        // Find max instance number
        var max_instance: u32 = 0;
        for (aars.items) |aar| {
            if (aar.instance > max_instance) max_instance = aar.instance;
        }
        for (amss.items) |ams| {
            if (ams.instance > max_instance) max_instance = ams.instance;
        }
        for (seals.items) |seal| {
            if (seal.instance > max_instance) max_instance = seal.instance;
        }

        // Build complete ARC sets
        var i: u32 = 1;
        while (i <= max_instance) : (i += 1) {
            const aar = self.findAndRemoveAAR(&aars, i) orelse continue;
            const ams = self.findAndRemoveAMS(&amss, i) orelse {
                // Incomplete set -- clean up the AAR we already took
                var aar_copy = aar;
                aar_copy.deinit();
                continue;
            };
            const seal = self.findAndRemoveSeal(&seals, i) orelse {
                // Incomplete set -- clean up
                var aar_copy = aar;
                aar_copy.deinit();
                var ams_copy = ams;
                ams_copy.deinit();
                continue;
            };

            try chain.addSet(.{
                .instance = i,
                .aar = aar,
                .ams = ams,
                .seal = seal,
            });
        }

        return chain;
    }

    fn processExtractedHeader(
        self: *ARCValidator,
        header_name: []const u8,
        header_value: []const u8,
        aars: *std.ArrayList(ARCAuthenticationResults),
        amss: *std.ArrayList(ARCMessageSignature),
        seals: *std.ArrayList(ARCSeal),
    ) !void {
        if (std.ascii.eqlIgnoreCase(header_name, "ARC-Authentication-Results")) {
            const aar = try ARCAuthenticationResults.parse(self.allocator, header_value);
            try aars.append(self.allocator, aar);
        } else if (std.ascii.eqlIgnoreCase(header_name, "ARC-Message-Signature")) {
            const ams = try ARCMessageSignature.parse(self.allocator, header_value);
            try amss.append(self.allocator, ams);
        } else if (std.ascii.eqlIgnoreCase(header_name, "ARC-Seal")) {
            const seal = try ARCSeal.parse(self.allocator, header_value);
            try seals.append(self.allocator, seal);
        }
    }

    fn findAndRemoveAAR(self: *ARCValidator, list: *std.ArrayList(ARCAuthenticationResults), instance: u32) ?ARCAuthenticationResults {
        _ = self;
        for (list.items, 0..) |item, idx| {
            if (item.instance == instance) {
                return list.orderedRemove(idx);
            }
        }
        return null;
    }

    fn findAndRemoveAMS(self: *ARCValidator, list: *std.ArrayList(ARCMessageSignature), instance: u32) ?ARCMessageSignature {
        _ = self;
        for (list.items, 0..) |item, idx| {
            if (item.instance == instance) {
                return list.orderedRemove(idx);
            }
        }
        return null;
    }

    fn findAndRemoveSeal(self: *ARCValidator, list: *std.ArrayList(ARCSeal), instance: u32) ?ARCSeal {
        _ = self;
        for (list.items, 0..) |item, idx| {
            if (item.instance == instance) {
                return list.orderedRemove(idx);
            }
        }
        return null;
    }

    /// Validate an individual ARC set.
    /// Checks internal consistency: matching instance numbers, required fields present,
    /// and algorithm support.
    pub fn validateSet(self: *ARCValidator, set: *const ARCSet, expected_instance: u32) bool {
        _ = self;

        // All components must have the correct instance number
        if (set.instance != expected_instance) return false;
        if (!set.validateInstanceConsistency()) return false;

        // Verify the algorithm is supported
        if (!isSupportedAlgorithm(set.ams.algorithm)) return false;
        if (!isSupportedAlgorithm(set.seal.algorithm)) return false;

        // Instance 1 must have cv=none
        if (expected_instance == 1 and set.seal.chain_validation != .none) return false;

        // Instance > 1 must have cv=pass or cv=fail (not cv=none)
        if (expected_instance > 1 and set.seal.chain_validation == .none) return false;

        return true;
    }

    /// Validate that ARC sets have sequential instance numbers 1..n with no gaps
    pub fn validateChainOrder(self: *ARCValidator, chain: *const ARCChain) bool {
        _ = self;

        const n = chain.count();
        if (n == 0) return true;

        // Check that we have exactly instances 1..n
        var i: u32 = 1;
        while (i <= @as(u32, @intCast(n))) : (i += 1) {
            if (chain.getSet(i) == null) {
                return false;
            }
        }

        return true;
    }
};

/// Check whether an algorithm string is a supported ARC/DKIM algorithm
fn isSupportedAlgorithm(algorithm: []const u8) bool {
    if (std.mem.eql(u8, algorithm, "rsa-sha256")) return true;
    if (std.mem.eql(u8, algorithm, "rsa-sha1")) return true;
    if (std.mem.eql(u8, algorithm, "ed25519-sha256")) return true;
    return false;
}

/// ARC Sealer: creates new ARC sets for outgoing or relayed messages.
/// Reuses DKIM infrastructure for signing.
pub const ARCSealer = struct {
    allocator: std.mem.Allocator,
    domain: []const u8,
    selector: []const u8,
    private_key: []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        domain: []const u8,
        selector: []const u8,
        private_key: []const u8,
    ) !ARCSealer {
        return .{
            .allocator = allocator,
            .domain = try allocator.dupe(u8, domain),
            .selector = try allocator.dupe(u8, selector),
            .private_key = try allocator.dupe(u8, private_key),
        };
    }

    pub fn deinit(self: *ARCSealer) void {
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        // Securely zero private key before freeing
        @memset(@as([]u8, @constCast(self.private_key)), 0);
        self.allocator.free(self.private_key);
    }

    /// Create a new ARC set and return the formatted header strings.
    ///
    /// Parameters:
    ///   - headers: the current message headers
    ///   - body: the message body
    ///   - auth_results: authentication results string for this hop
    ///   - chain_status: the validation status of the existing ARC chain
    ///   - existing_chain_length: number of existing ARC sets (0 if none)
    pub fn seal(
        self: *ARCSealer,
        headers: []const u8,
        body: []const u8,
        auth_results: []const u8,
        chain_status: ARCChainValidation,
        existing_chain_length: u32,
    ) !ARCHeaderSet {
        const instance = existing_chain_length + 1;

        // RFC 8617: maximum 50 ARC sets
        if (instance > 50) {
            return error.ARCChainTooLong;
        }

        // Determine the cv= value for this new seal
        const cv = self.determineChainValidation(instance, chain_status);

        // Generate the three ARC headers
        const aar_header = try self.generateARCAuthenticationResults(instance, auth_results);
        errdefer self.allocator.free(aar_header);

        const ams_header = try self.generateARCMessageSignature(instance, headers, body);
        errdefer self.allocator.free(ams_header);

        const seal_header = try self.generateARCSeal(instance, cv, aar_header, ams_header);

        return .{
            .aar_header = aar_header,
            .ams_header = ams_header,
            .seal_header = seal_header,
            .allocator = self.allocator,
        };
    }

    /// Format the ARC-Authentication-Results header
    pub fn generateARCAuthenticationResults(
        self: *ARCSealer,
        instance: u32,
        results: []const u8,
    ) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "ARC-Authentication-Results: i={d}; {s}",
            .{ instance, results },
        );
    }

    /// Format the ARC-Message-Signature header.
    /// Computes a DKIM-like signature over specified headers and body.
    pub fn generateARCMessageSignature(
        self: *ARCSealer,
        instance: u32,
        headers: []const u8,
        body: []const u8,
    ) ![]u8 {
        // Compute body hash (in production, SHA-256 of canonicalized body)
        const body_hash = try self.computeBodyHash(body);
        defer self.allocator.free(body_hash);

        // Determine signed headers
        const signed_headers = try self.extractSignedHeaderNames(headers);
        defer self.allocator.free(signed_headers);

        // Compute signature (in production, RSA/Ed25519 signature)
        const signature = try self.computeMessageSignature(headers, body_hash);
        defer self.allocator.free(signature);

        const now = time_compat.timestamp();

        return std.fmt.allocPrint(
            self.allocator,
            "ARC-Message-Signature: i={d}; a=rsa-sha256; c=relaxed/relaxed; d={s}; s={s};\r\n" ++
                "\th={s};\r\n" ++
                "\tbh={s};\r\n" ++
                "\tt={d};\r\n" ++
                "\tb={s}",
            .{
                instance,
                self.domain,
                self.selector,
                signed_headers,
                body_hash,
                now,
                signature,
            },
        );
    }

    /// Format the ARC-Seal header.
    /// Signs over the ARC chain headers (existing ARC headers + new AAR and AMS).
    pub fn generateARCSeal(
        self: *ARCSealer,
        instance: u32,
        chain_validation: ARCChainValidation,
        aar_header: []const u8,
        ams_header: []const u8,
    ) ![]u8 {
        // Build the data to be signed:
        // All previous ARC-Seal headers + current AAR + current AMS
        const seal_input = try std.fmt.allocPrint(
            self.allocator,
            "{s}\r\n{s}",
            .{ aar_header, ams_header },
        );
        defer self.allocator.free(seal_input);

        // Compute seal signature (in production, RSA/Ed25519 signature over seal_input)
        const signature = try self.computeSealSignature(seal_input);
        defer self.allocator.free(signature);

        const now = time_compat.timestamp();

        return std.fmt.allocPrint(
            self.allocator,
            "ARC-Seal: i={d}; a=rsa-sha256; d={s}; s={s};\r\n" ++
                "\tcv={s};\r\n" ++
                "\tt={d};\r\n" ++
                "\tb={s}",
            .{
                instance,
                self.domain,
                self.selector,
                chain_validation.toString(),
                now,
                signature,
            },
        );
    }

    /// Determine the appropriate cv= value for a new ARC set
    fn determineChainValidation(self: *ARCSealer, instance: u32, chain_status: ARCChainValidation) ARCChainValidation {
        _ = self;
        if (instance == 1) {
            // First ARC set always has cv=none
            return .none;
        }

        // For subsequent sets, cv reflects the validation result of the existing chain
        return chain_status;
    }

    /// Compute a hash of the message body.
    /// In production this would compute SHA-256 over the canonicalized body and
    /// return the base64-encoded result. For now, returns a placeholder.
    fn computeBodyHash(self: *ARCSealer, body: []const u8) ![]u8 {
        // In production: canonicalize body per c= tag, hash with SHA-256,
        // and base64-encode the result
        var hash: [32]u8 = undefined;
        // Simple hash placeholder: XOR-fold the body bytes
        @memset(&hash, 0);
        for (body, 0..) |byte, idx| {
            hash[idx % 32] ^= byte;
        }

        // Base64-encode the hash
        const base64_len = std.base64.standard.Encoder.calcSize(hash.len);
        const encoded = try self.allocator.alloc(u8, base64_len);
        _ = std.base64.standard.Encoder.encode(encoded, &hash);
        return encoded;
    }

    /// Extract header names from the message for the h= tag.
    fn extractSignedHeaderNames(self: *ARCSealer, headers: []const u8) ![]u8 {
        var names: std.ArrayList(u8) = .{};
        errdefer names.deinit(self.allocator);

        var seen = std.StringHashMap(void).init(self.allocator);
        defer seen.deinit();

        var lines = std.mem.splitSequence(u8, headers, "\r\n");
        var first = true;

        while (lines.next()) |line| {
            if (line.len == 0) break;
            // Skip continuation lines
            if (line[0] == ' ' or line[0] == '\t') continue;

            const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
            const header_name_raw = line[0..colon_pos];
            const header_name_lower = try std.ascii.allocLowerString(self.allocator, header_name_raw);
            defer self.allocator.free(header_name_lower);

            // Skip ARC headers from signed headers list (they are covered by the seal)
            if (std.mem.startsWith(u8, header_name_lower, "arc-")) continue;

            // Skip duplicates
            if (seen.contains(header_name_lower)) continue;
            try seen.put(try self.allocator.dupe(u8, header_name_lower), {});

            if (!first) {
                try names.append(self.allocator, ':');
            }
            try names.appendSlice(self.allocator, header_name_raw);
            first = false;
        }

        // Free the keys in the seen map
        var it = seen.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }

        if (names.items.len == 0) {
            return try self.allocator.dupe(u8, "from:to:subject:date");
        }

        return names.toOwnedSlice(self.allocator);
    }

    /// Compute the message signature (b= tag).
    /// In production, this would perform RSA-SHA256 or Ed25519-SHA256 signing
    /// over the canonicalized signed headers + the AMS header itself (with empty b=).
    fn computeMessageSignature(self: *ARCSealer, headers: []const u8, body_hash: []const u8) ![]u8 {
        // In production: canonicalize headers, append AMS with b= empty,
        // sign with private key, base64-encode
        _ = headers;
        _ = body_hash;

        // Generate a placeholder signature by hashing the private key and timestamp
        var sig_data: [64]u8 = undefined;
        @memset(&sig_data, 0);
        for (self.private_key, 0..) |byte, idx| {
            if (idx >= 64) break;
            sig_data[idx] = byte;
        }
        // Mix in current timestamp for uniqueness
        const ts = time_compat.timestamp();
        const ts_bytes = std.mem.asBytes(&ts);
        for (ts_bytes, 0..) |byte, idx| {
            sig_data[idx % 64] ^= byte;
        }

        const base64_len = std.base64.standard.Encoder.calcSize(sig_data.len);
        const encoded = try self.allocator.alloc(u8, base64_len);
        _ = std.base64.standard.Encoder.encode(encoded, &sig_data);
        return encoded;
    }

    /// Compute the seal signature (b= tag in ARC-Seal).
    /// In production, this would sign over all ARC-Seal headers in the chain
    /// (with the current one having an empty b=) plus the current AAR and AMS.
    fn computeSealSignature(self: *ARCSealer, seal_input: []const u8) ![]u8 {
        // In production: sign over the seal input with the private key
        var sig_data: [64]u8 = undefined;
        @memset(&sig_data, 0);
        for (seal_input, 0..) |byte, idx| {
            if (idx >= 64) break;
            sig_data[idx] = byte;
        }
        for (self.private_key, 0..) |byte, idx| {
            sig_data[idx % 64] ^= byte;
        }

        const base64_len = std.base64.standard.Encoder.calcSize(sig_data.len);
        const encoded = try self.allocator.alloc(u8, base64_len);
        _ = std.base64.standard.Encoder.encode(encoded, &sig_data);
        return encoded;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "ARCResult toString and fromString" {
    const testing = std.testing;

    try testing.expectEqualStrings("pass", ARCResult.pass.toString());
    try testing.expectEqualStrings("fail", ARCResult.fail.toString());
    try testing.expectEqualStrings("none", ARCResult.none.toString());
    try testing.expectEqualStrings("temperror", ARCResult.temperror.toString());
    try testing.expectEqualStrings("permerror", ARCResult.permerror.toString());

    try testing.expectEqual(ARCResult.pass, ARCResult.fromString("pass"));
    try testing.expectEqual(ARCResult.fail, ARCResult.fromString("FAIL"));
    try testing.expectEqual(ARCResult.none, ARCResult.fromString("unknown"));
}

test "ARCChainValidation toString and fromString" {
    const testing = std.testing;

    try testing.expectEqualStrings("none", ARCChainValidation.none.toString());
    try testing.expectEqualStrings("pass", ARCChainValidation.pass.toString());
    try testing.expectEqualStrings("fail", ARCChainValidation.fail.toString());

    try testing.expectEqual(ARCChainValidation.pass, ARCChainValidation.fromString("pass"));
    try testing.expectEqual(ARCChainValidation.fail, ARCChainValidation.fromString("fail"));
    try testing.expectEqual(ARCChainValidation.none, ARCChainValidation.fromString("none"));
    try testing.expectEqual(ARCChainValidation.none, ARCChainValidation.fromString("bogus"));
}

test "ARC-Authentication-Results parsing" {
    const testing = std.testing;

    const header_value = "i=1; mx.example.com; dkim=pass header.d=example.com; spf=pass";
    var aar = try ARCAuthenticationResults.parse(testing.allocator, header_value);
    defer aar.deinit();

    try testing.expectEqual(@as(u32, 1), aar.instance);
    try testing.expectEqualStrings("mx.example.com; dkim=pass header.d=example.com; spf=pass", aar.results);
}

test "ARC-Authentication-Results parsing instance 3" {
    const testing = std.testing;

    const header_value = "i=3; relay.example.org; dkim=fail; arc=pass";
    var aar = try ARCAuthenticationResults.parse(testing.allocator, header_value);
    defer aar.deinit();

    try testing.expectEqual(@as(u32, 3), aar.instance);
    try testing.expectEqualStrings("relay.example.org; dkim=fail; arc=pass", aar.results);
}

test "ARC-Authentication-Results invalid missing instance" {
    const testing = std.testing;

    const header_value = "mx.example.com; dkim=pass";
    const result = ARCAuthenticationResults.parse(testing.allocator, header_value);
    try testing.expectError(error.InvalidAARHeader, result);
}

test "ARC-Authentication-Results format" {
    const testing = std.testing;

    var aar = ARCAuthenticationResults{
        .instance = 2,
        .results = try testing.allocator.dupe(u8, "mx.example.com; spf=pass"),
        .allocator = testing.allocator,
    };
    defer aar.deinit();

    const formatted = try aar.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings("ARC-Authentication-Results: i=2; mx.example.com; spf=pass", formatted);
}

test "ARC-Message-Signature parsing" {
    const testing = std.testing;

    const header_value =
        "i=1; a=rsa-sha256; d=example.com; s=arc-20160816;" ++
        " h=from:to:subject:date; bh=BODYHASH==; b=SIGNATURE==; c=relaxed/relaxed";
    var ams = try ARCMessageSignature.parse(testing.allocator, header_value);
    defer ams.deinit();

    try testing.expectEqual(@as(u32, 1), ams.instance);
    try testing.expectEqualStrings("rsa-sha256", ams.algorithm);
    try testing.expectEqualStrings("example.com", ams.domain);
    try testing.expectEqualStrings("arc-20160816", ams.selector);
    try testing.expectEqualStrings("from:to:subject:date", ams.headers);
    try testing.expectEqualStrings("BODYHASH==", ams.body_hash);
    try testing.expectEqualStrings("SIGNATURE==", ams.signature);
    try testing.expectEqualStrings("relaxed/relaxed", ams.canonicalization);
}

test "ARC-Message-Signature invalid missing fields" {
    const testing = std.testing;

    // Missing algorithm and domain
    const header_value = "i=1; s=selector; b=SIGNATURE==";
    const result = ARCMessageSignature.parse(testing.allocator, header_value);
    try testing.expectError(error.InvalidAMSHeader, result);
}

test "ARC-Message-Signature with timestamp" {
    const testing = std.testing;

    const header_value =
        "i=2; a=rsa-sha256; d=relay.example.com; s=sel;" ++
        " h=from:to:subject; bh=abc123==; b=sig456==; t=1609459200";
    var ams = try ARCMessageSignature.parse(testing.allocator, header_value);
    defer ams.deinit();

    try testing.expectEqual(@as(u32, 2), ams.instance);
    try testing.expectEqual(@as(i64, 1609459200), ams.timestamp.?);
}

test "ARC-Seal parsing" {
    const testing = std.testing;

    const header_value =
        "i=1; a=rsa-sha256; d=example.com; s=arc-20160816;" ++
        " cv=none; b=SEALSIG==";
    var seal = try ARCSeal.parse(testing.allocator, header_value);
    defer seal.deinit();

    try testing.expectEqual(@as(u32, 1), seal.instance);
    try testing.expectEqualStrings("rsa-sha256", seal.algorithm);
    try testing.expectEqualStrings("example.com", seal.domain);
    try testing.expectEqualStrings("arc-20160816", seal.selector);
    try testing.expectEqualStrings("SEALSIG==", seal.signature);
    try testing.expectEqual(ARCChainValidation.none, seal.chain_validation);
}

test "ARC-Seal parsing with cv=pass" {
    const testing = std.testing;

    const header_value =
        "i=2; a=rsa-sha256; d=relay.example.com; s=sel;" ++
        " cv=pass; b=ANOTHERSIG==; t=1609459200";
    var seal = try ARCSeal.parse(testing.allocator, header_value);
    defer seal.deinit();

    try testing.expectEqual(@as(u32, 2), seal.instance);
    try testing.expectEqual(ARCChainValidation.pass, seal.chain_validation);
    try testing.expectEqual(@as(i64, 1609459200), seal.timestamp.?);
}

test "ARC-Seal invalid missing fields" {
    const testing = std.testing;

    const header_value = "i=1; cv=none; b=SIG==";
    const result = ARCSeal.parse(testing.allocator, header_value);
    try testing.expectError(error.InvalidASSeal, result);
}

test "ARCSet instance consistency" {
    const testing = std.testing;

    var set = ARCSet{
        .instance = 1,
        .aar = .{
            .instance = 1,
            .results = try testing.allocator.dupe(u8, "mx.example.com; spf=pass"),
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "example.com"),
            .selector = try testing.allocator.dupe(u8, "sel"),
            .headers = try testing.allocator.dupe(u8, "from:to:subject"),
            .body_hash = try testing.allocator.dupe(u8, "hash=="),
            .signature = try testing.allocator.dupe(u8, "sig=="),
            .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "example.com"),
            .selector = try testing.allocator.dupe(u8, "sel"),
            .signature = try testing.allocator.dupe(u8, "sealsig=="),
            .chain_validation = .none,
            .timestamp = null,
            .allocator = testing.allocator,
        },
    };
    defer set.deinit();

    try testing.expect(set.validateInstanceConsistency());
}

test "ARCSet instance inconsistency" {
    const testing = std.testing;

    var set = ARCSet{
        .instance = 1,
        .aar = .{
            .instance = 1,
            .results = try testing.allocator.dupe(u8, "results"),
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 2, // mismatch
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "example.com"),
            .selector = try testing.allocator.dupe(u8, "sel"),
            .headers = try testing.allocator.dupe(u8, "from:to"),
            .body_hash = try testing.allocator.dupe(u8, "hash=="),
            .signature = try testing.allocator.dupe(u8, "sig=="),
            .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "example.com"),
            .selector = try testing.allocator.dupe(u8, "sel"),
            .signature = try testing.allocator.dupe(u8, "sig=="),
            .chain_validation = .none,
            .timestamp = null,
            .allocator = testing.allocator,
        },
    };
    defer set.deinit();

    try testing.expect(!set.validateInstanceConsistency());
}

test "ARCChain validation - valid sequential chain" {
    const testing = std.testing;

    var chain = ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Add set i=1 with cv=none
    try chain.addSet(.{
        .instance = 1,
        .aar = .{
            .instance = 1,
            .results = try testing.allocator.dupe(u8, "mx.example.com; spf=pass"),
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "example.com"),
            .selector = try testing.allocator.dupe(u8, "sel"),
            .headers = try testing.allocator.dupe(u8, "from:to:subject"),
            .body_hash = try testing.allocator.dupe(u8, "hash1=="),
            .signature = try testing.allocator.dupe(u8, "sig1=="),
            .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "example.com"),
            .selector = try testing.allocator.dupe(u8, "sel"),
            .signature = try testing.allocator.dupe(u8, "seal1=="),
            .chain_validation = .none,
            .timestamp = null,
            .allocator = testing.allocator,
        },
    });

    // Add set i=2 with cv=pass
    try chain.addSet(.{
        .instance = 2,
        .aar = .{
            .instance = 2,
            .results = try testing.allocator.dupe(u8, "relay.example.org; dkim=pass"),
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 2,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "relay.example.org"),
            .selector = try testing.allocator.dupe(u8, "sel2"),
            .headers = try testing.allocator.dupe(u8, "from:to:subject"),
            .body_hash = try testing.allocator.dupe(u8, "hash2=="),
            .signature = try testing.allocator.dupe(u8, "sig2=="),
            .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 2,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "relay.example.org"),
            .selector = try testing.allocator.dupe(u8, "sel2"),
            .signature = try testing.allocator.dupe(u8, "seal2=="),
            .chain_validation = .pass,
            .timestamp = null,
            .allocator = testing.allocator,
        },
    });

    const result = chain.validateChainIntegrity();
    try testing.expectEqual(ARCChainValidation.pass, result);
}

test "ARCChain validation - invalid gap in instance numbers" {
    const testing = std.testing;

    var chain = ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Add set i=1
    try chain.addSet(.{
        .instance = 1,
        .aar = .{
            .instance = 1,
            .results = try testing.allocator.dupe(u8, "mx.example.com; spf=pass"),
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "example.com"),
            .selector = try testing.allocator.dupe(u8, "sel"),
            .headers = try testing.allocator.dupe(u8, "from:to"),
            .body_hash = try testing.allocator.dupe(u8, "h=="),
            .signature = try testing.allocator.dupe(u8, "s=="),
            .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "example.com"),
            .selector = try testing.allocator.dupe(u8, "sel"),
            .signature = try testing.allocator.dupe(u8, "seal=="),
            .chain_validation = .none,
            .timestamp = null,
            .allocator = testing.allocator,
        },
    });

    // Add set i=3 (skipping i=2 -- gap!)
    try chain.addSet(.{
        .instance = 3,
        .aar = .{
            .instance = 3,
            .results = try testing.allocator.dupe(u8, "relay; dkim=pass"),
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 3,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "relay.com"),
            .selector = try testing.allocator.dupe(u8, "sel3"),
            .headers = try testing.allocator.dupe(u8, "from:to"),
            .body_hash = try testing.allocator.dupe(u8, "h3=="),
            .signature = try testing.allocator.dupe(u8, "s3=="),
            .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 3,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "relay.com"),
            .selector = try testing.allocator.dupe(u8, "sel3"),
            .signature = try testing.allocator.dupe(u8, "seal3=="),
            .chain_validation = .pass,
            .timestamp = null,
            .allocator = testing.allocator,
        },
    });

    // validateChainIntegrity checks for sequential 1..n, which will fail because n=2 but
    // there is no set with instance=2
    const result = chain.validateChainIntegrity();
    try testing.expectEqual(ARCChainValidation.fail, result);
}

test "ARCChain validation - empty chain" {
    const testing = std.testing;

    var chain = ARCChain.init(testing.allocator);
    defer chain.deinit();

    const result = chain.validateChainIntegrity();
    try testing.expectEqual(ARCChainValidation.none, result);
}

test "ARCChain validation - cv=fail breaks chain" {
    const testing = std.testing;

    var chain = ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Add set i=1 with cv=none
    try chain.addSet(.{
        .instance = 1,
        .aar = .{
            .instance = 1,
            .results = try testing.allocator.dupe(u8, "mx; spf=pass"),
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "ex.com"),
            .selector = try testing.allocator.dupe(u8, "s"),
            .headers = try testing.allocator.dupe(u8, "from"),
            .body_hash = try testing.allocator.dupe(u8, "h=="),
            .signature = try testing.allocator.dupe(u8, "s=="),
            .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "ex.com"),
            .selector = try testing.allocator.dupe(u8, "s"),
            .signature = try testing.allocator.dupe(u8, "seal=="),
            .chain_validation = .none,
            .timestamp = null,
            .allocator = testing.allocator,
        },
    });

    // Add set i=2 with cv=fail
    try chain.addSet(.{
        .instance = 2,
        .aar = .{
            .instance = 2,
            .results = try testing.allocator.dupe(u8, "relay; dkim=fail"),
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 2,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "relay.com"),
            .selector = try testing.allocator.dupe(u8, "s2"),
            .headers = try testing.allocator.dupe(u8, "from"),
            .body_hash = try testing.allocator.dupe(u8, "h2=="),
            .signature = try testing.allocator.dupe(u8, "s2=="),
            .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 2,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "relay.com"),
            .selector = try testing.allocator.dupe(u8, "s2"),
            .signature = try testing.allocator.dupe(u8, "seal2=="),
            .chain_validation = .fail, // Chain is broken
            .timestamp = null,
            .allocator = testing.allocator,
        },
    });

    const result = chain.validateChainIntegrity();
    try testing.expectEqual(ARCChainValidation.fail, result);
}

test "ARCChain validation - i=1 must have cv=none" {
    const testing = std.testing;

    var chain = ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Add set i=1 with cv=pass (invalid for first set)
    try chain.addSet(.{
        .instance = 1,
        .aar = .{
            .instance = 1,
            .results = try testing.allocator.dupe(u8, "mx; spf=pass"),
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "ex.com"),
            .selector = try testing.allocator.dupe(u8, "s"),
            .headers = try testing.allocator.dupe(u8, "from"),
            .body_hash = try testing.allocator.dupe(u8, "h=="),
            .signature = try testing.allocator.dupe(u8, "s=="),
            .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 1,
            .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
            .domain = try testing.allocator.dupe(u8, "ex.com"),
            .selector = try testing.allocator.dupe(u8, "s"),
            .signature = try testing.allocator.dupe(u8, "seal=="),
            .chain_validation = .pass, // Invalid for i=1
            .timestamp = null,
            .allocator = testing.allocator,
        },
    });

    const result = chain.validateChainIntegrity();
    try testing.expectEqual(ARCChainValidation.fail, result);
}

test "ARCValidator extract ARC sets from headers" {
    const testing = std.testing;

    const headers =
        "From: sender@example.com\r\n" ++
        "To: receiver@example.com\r\n" ++
        "Subject: Test\r\n" ++
        "ARC-Authentication-Results: i=1; mx.example.com;\r\n" ++
        " dkim=pass header.d=example.com; spf=pass\r\n" ++
        "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc;\r\n" ++
        " h=from:to:subject; bh=HASH==; b=SIG==\r\n" ++
        "ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=arc;\r\n" ++
        " cv=none; b=SEAL==\r\n" ++
        "\r\n";

    var validator = ARCValidator.init(testing.allocator);
    defer validator.deinit();

    var chain = try validator.extractARCSets(headers);
    defer chain.deinit();

    try testing.expectEqual(@as(usize, 1), chain.count());

    const set = chain.getSet(1).?;
    try testing.expectEqual(@as(u32, 1), set.instance);
    try testing.expectEqual(@as(u32, 1), set.aar.instance);
    try testing.expectEqual(@as(u32, 1), set.ams.instance);
    try testing.expectEqual(@as(u32, 1), set.seal.instance);
    try testing.expectEqual(ARCChainValidation.none, set.seal.chain_validation);
    try testing.expectEqualStrings("example.com", set.ams.domain);
}

test "ARCValidator extract multiple ARC sets" {
    const testing = std.testing;

    const headers =
        "From: sender@example.com\r\n" ++
        "ARC-Authentication-Results: i=1; mx.example.com; spf=pass\r\n" ++
        "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel;\r\n" ++
        " h=from:to; bh=H1==; b=S1==\r\n" ++
        "ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=SEAL1==\r\n" ++
        "ARC-Authentication-Results: i=2; relay.example.org; dkim=pass\r\n" ++
        "ARC-Message-Signature: i=2; a=rsa-sha256; d=relay.example.org; s=sel2;\r\n" ++
        " h=from:to; bh=H2==; b=S2==\r\n" ++
        "ARC-Seal: i=2; a=rsa-sha256; d=relay.example.org; s=sel2; cv=pass; b=SEAL2==\r\n" ++
        "\r\n";

    var validator = ARCValidator.init(testing.allocator);
    defer validator.deinit();

    var chain = try validator.extractARCSets(headers);
    defer chain.deinit();

    try testing.expectEqual(@as(usize, 2), chain.count());

    const set1 = chain.getSet(1).?;
    try testing.expectEqual(@as(u32, 1), set1.instance);
    try testing.expectEqual(ARCChainValidation.none, set1.seal.chain_validation);

    const set2 = chain.getSet(2).?;
    try testing.expectEqual(@as(u32, 2), set2.instance);
    try testing.expectEqual(ARCChainValidation.pass, set2.seal.chain_validation);
    try testing.expectEqualStrings("relay.example.org", set2.ams.domain);
}

test "ARCValidator validate chain - no ARC headers" {
    const testing = std.testing;

    const headers =
        "From: sender@example.com\r\n" ++
        "To: receiver@example.com\r\n" ++
        "Subject: Test message\r\n" ++
        "\r\n";

    var validator = ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.validateChain(headers);
    try testing.expectEqual(ARCResult.none, result);
}

test "ARCValidator validate chain - valid single set" {
    const testing = std.testing;

    const headers =
        "From: sender@example.com\r\n" ++
        "ARC-Authentication-Results: i=1; mx.example.com; spf=pass\r\n" ++
        "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel;\r\n" ++
        " h=from:to; bh=H==; b=S==\r\n" ++
        "ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=SEAL==\r\n" ++
        "\r\n";

    var validator = ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.validateChain(headers);
    try testing.expectEqual(ARCResult.pass, result);
}

test "ARCValidator validateSet - valid first set" {
    const testing = std.testing;

    var validator = ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const set = ARCSet{
        .instance = 1,
        .aar = .{
            .instance = 1,
            .results = "",
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 1,
            .algorithm = "rsa-sha256",
            .domain = "example.com",
            .selector = "sel",
            .headers = "from:to",
            .body_hash = "h==",
            .signature = "s==",
            .canonicalization = "relaxed/relaxed",
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 1,
            .algorithm = "rsa-sha256",
            .domain = "example.com",
            .selector = "sel",
            .signature = "seal==",
            .chain_validation = .none,
            .timestamp = null,
            .allocator = testing.allocator,
        },
    };

    try testing.expect(validator.validateSet(&set, 1));
}

test "ARCValidator validateSet - unsupported algorithm" {
    const testing = std.testing;

    var validator = ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const set = ARCSet{
        .instance = 1,
        .aar = .{
            .instance = 1,
            .results = "",
            .allocator = testing.allocator,
        },
        .ams = .{
            .instance = 1,
            .algorithm = "unsupported-algo",
            .domain = "example.com",
            .selector = "sel",
            .headers = "from:to",
            .body_hash = "h==",
            .signature = "s==",
            .canonicalization = "relaxed/relaxed",
            .timestamp = null,
            .allocator = testing.allocator,
        },
        .seal = .{
            .instance = 1,
            .algorithm = "rsa-sha256",
            .domain = "example.com",
            .selector = "sel",
            .signature = "seal==",
            .chain_validation = .none,
            .timestamp = null,
            .allocator = testing.allocator,
        },
    };

    try testing.expect(!validator.validateSet(&set, 1));
}

test "ARCValidator validateChainOrder - valid" {
    const testing = std.testing;

    var validator = ARCValidator.init(testing.allocator);
    defer validator.deinit();

    var chain = ARCChain.init(testing.allocator);
    defer chain.deinit();

    try chain.addSet(.{
        .instance = 1,
        .aar = .{ .instance = 1, .results = "", .allocator = testing.allocator },
        .ams = .{ .instance = 1, .algorithm = "rsa-sha256", .domain = "a.com", .selector = "s", .headers = "from", .body_hash = "h", .signature = "s", .canonicalization = "relaxed/relaxed", .timestamp = null, .allocator = testing.allocator },
        .seal = .{ .instance = 1, .algorithm = "rsa-sha256", .domain = "a.com", .selector = "s", .signature = "seal", .chain_validation = .none, .timestamp = null, .allocator = testing.allocator },
    });

    try chain.addSet(.{
        .instance = 2,
        .aar = .{ .instance = 2, .results = "", .allocator = testing.allocator },
        .ams = .{ .instance = 2, .algorithm = "rsa-sha256", .domain = "b.com", .selector = "s", .headers = "from", .body_hash = "h", .signature = "s", .canonicalization = "relaxed/relaxed", .timestamp = null, .allocator = testing.allocator },
        .seal = .{ .instance = 2, .algorithm = "rsa-sha256", .domain = "b.com", .selector = "s", .signature = "seal", .chain_validation = .pass, .timestamp = null, .allocator = testing.allocator },
    });

    try testing.expect(validator.validateChainOrder(&chain));
}

test "ARCValidator validateChainOrder - invalid gap" {
    const testing = std.testing;

    var validator = ARCValidator.init(testing.allocator);
    defer validator.deinit();

    var chain = ARCChain.init(testing.allocator);
    defer chain.deinit();

    try chain.addSet(.{
        .instance = 1,
        .aar = .{ .instance = 1, .results = "", .allocator = testing.allocator },
        .ams = .{ .instance = 1, .algorithm = "rsa-sha256", .domain = "a.com", .selector = "s", .headers = "from", .body_hash = "h", .signature = "s", .canonicalization = "relaxed/relaxed", .timestamp = null, .allocator = testing.allocator },
        .seal = .{ .instance = 1, .algorithm = "rsa-sha256", .domain = "a.com", .selector = "s", .signature = "seal", .chain_validation = .none, .timestamp = null, .allocator = testing.allocator },
    });

    try chain.addSet(.{
        .instance = 3, // Gap: missing i=2
        .aar = .{ .instance = 3, .results = "", .allocator = testing.allocator },
        .ams = .{ .instance = 3, .algorithm = "rsa-sha256", .domain = "b.com", .selector = "s", .headers = "from", .body_hash = "h", .signature = "s", .canonicalization = "relaxed/relaxed", .timestamp = null, .allocator = testing.allocator },
        .seal = .{ .instance = 3, .algorithm = "rsa-sha256", .domain = "b.com", .selector = "s", .signature = "seal", .chain_validation = .pass, .timestamp = null, .allocator = testing.allocator },
    });

    // Chain has 2 items but instances are 1 and 3, so checking for instance 2 will fail
    try testing.expect(!validator.validateChainOrder(&chain));
}

test "ARCValidator validateChainOrder - empty chain" {
    const testing = std.testing;

    var validator = ARCValidator.init(testing.allocator);
    defer validator.deinit();

    var chain = ARCChain.init(testing.allocator);
    defer chain.deinit();

    try testing.expect(validator.validateChainOrder(&chain));
}

test "ARCSealer seal generation - first set" {
    const testing = std.testing;

    var sealer = try ARCSealer.init(
        testing.allocator,
        "example.com",
        "arc-20230101",
        "test-private-key-data",
    );
    defer sealer.deinit();

    const headers =
        "From: sender@example.com\r\n" ++
        "To: receiver@example.com\r\n" ++
        "Subject: Test\r\n" ++
        "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n";

    const body = "Hello, this is a test message.\r\n";
    const auth_results = "mx.example.com; dkim=pass header.d=example.com; spf=pass";

    var header_set = try sealer.seal(headers, body, auth_results, .none, 0);
    defer header_set.deinit();

    // Verify i=1 is present in all three headers
    try testing.expect(std.mem.indexOf(u8, header_set.aar_header, "i=1") != null);
    try testing.expect(std.mem.indexOf(u8, header_set.ams_header, "i=1") != null);
    try testing.expect(std.mem.indexOf(u8, header_set.seal_header, "i=1") != null);

    // Verify cv=none for first set
    try testing.expect(std.mem.indexOf(u8, header_set.seal_header, "cv=none") != null);

    // Verify domain and selector
    try testing.expect(std.mem.indexOf(u8, header_set.ams_header, "d=example.com") != null);
    try testing.expect(std.mem.indexOf(u8, header_set.ams_header, "s=arc-20230101") != null);

    // Verify header prefixes
    try testing.expect(std.mem.startsWith(u8, header_set.aar_header, "ARC-Authentication-Results:"));
    try testing.expect(std.mem.startsWith(u8, header_set.ams_header, "ARC-Message-Signature:"));
    try testing.expect(std.mem.startsWith(u8, header_set.seal_header, "ARC-Seal:"));
}

test "ARCSealer seal generation - second set" {
    const testing = std.testing;

    var sealer = try ARCSealer.init(
        testing.allocator,
        "relay.example.org",
        "arc-relay",
        "relay-private-key",
    );
    defer sealer.deinit();

    const headers =
        "From: sender@example.com\r\n" ++
        "To: receiver@example.com\r\n" ++
        "Subject: Forwarded\r\n";

    const body = "Forwarded message body.\r\n";
    const auth_results = "relay.example.org; arc=pass; dkim=fail (signature broken by forwarding)";

    // Existing chain has 1 set, chain status is pass
    var header_set = try sealer.seal(headers, body, auth_results, .pass, 1);
    defer header_set.deinit();

    // Verify i=2 (existing_chain_length + 1)
    try testing.expect(std.mem.indexOf(u8, header_set.aar_header, "i=2") != null);
    try testing.expect(std.mem.indexOf(u8, header_set.ams_header, "i=2") != null);
    try testing.expect(std.mem.indexOf(u8, header_set.seal_header, "i=2") != null);

    // Verify cv=pass for second set (chain was valid)
    try testing.expect(std.mem.indexOf(u8, header_set.seal_header, "cv=pass") != null);
}

test "ARCSealer seal generation - chain too long" {
    const testing = std.testing;

    var sealer = try ARCSealer.init(
        testing.allocator,
        "example.com",
        "sel",
        "key",
    );
    defer sealer.deinit();

    const result = sealer.seal("From: test\r\n", "body", "results", .pass, 50);
    try testing.expectError(error.ARCChainTooLong, result);
}

test "ARCSealer determineChainValidation" {
    const testing = std.testing;

    var sealer = try ARCSealer.init(
        testing.allocator,
        "example.com",
        "sel",
        "key",
    );
    defer sealer.deinit();

    // First instance always gets cv=none
    try testing.expectEqual(ARCChainValidation.none, sealer.determineChainValidation(1, .pass));
    try testing.expectEqual(ARCChainValidation.none, sealer.determineChainValidation(1, .fail));
    try testing.expectEqual(ARCChainValidation.none, sealer.determineChainValidation(1, .none));

    // Subsequent instances reflect chain status
    try testing.expectEqual(ARCChainValidation.pass, sealer.determineChainValidation(2, .pass));
    try testing.expectEqual(ARCChainValidation.fail, sealer.determineChainValidation(2, .fail));
    try testing.expectEqual(ARCChainValidation.none, sealer.determineChainValidation(3, .none));
}

test "ARCHeaderSet toHeaderBlock" {
    const testing = std.testing;

    var header_set = ARCHeaderSet{
        .aar_header = try testing.allocator.dupe(u8, "ARC-Authentication-Results: i=1; mx.example.com; spf=pass"),
        .ams_header = try testing.allocator.dupe(u8, "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=from:to; bh=H==; b=S=="),
        .seal_header = try testing.allocator.dupe(u8, "ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=SEAL=="),
        .allocator = testing.allocator,
    };
    defer header_set.deinit();

    const block = try header_set.toHeaderBlock(testing.allocator);
    defer testing.allocator.free(block);

    // Verify the block contains all three headers separated by CRLF
    try testing.expect(std.mem.indexOf(u8, block, "ARC-Authentication-Results:") != null);
    try testing.expect(std.mem.indexOf(u8, block, "ARC-Message-Signature:") != null);
    try testing.expect(std.mem.indexOf(u8, block, "ARC-Seal:") != null);
    try testing.expect(std.mem.indexOf(u8, block, "\r\n") != null);
}

test "ARCSeal format" {
    const testing = std.testing;

    var seal = ARCSeal{
        .instance = 1,
        .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
        .domain = try testing.allocator.dupe(u8, "example.com"),
        .selector = try testing.allocator.dupe(u8, "arc-sel"),
        .signature = try testing.allocator.dupe(u8, "base64signature=="),
        .chain_validation = .none,
        .timestamp = 1609459200,
        .allocator = testing.allocator,
    };
    defer seal.deinit();

    const formatted = try seal.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expect(std.mem.startsWith(u8, formatted, "ARC-Seal:"));
    try testing.expect(std.mem.indexOf(u8, formatted, "i=1") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "cv=none") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "d=example.com") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "t=1609459200") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "b=base64signature==") != null);
}

test "ARCMessageSignature format" {
    const testing = std.testing;

    var ams = ARCMessageSignature{
        .instance = 2,
        .algorithm = try testing.allocator.dupe(u8, "rsa-sha256"),
        .domain = try testing.allocator.dupe(u8, "relay.example.org"),
        .selector = try testing.allocator.dupe(u8, "relay-sel"),
        .headers = try testing.allocator.dupe(u8, "from:to:subject:date"),
        .body_hash = try testing.allocator.dupe(u8, "bodyhash=="),
        .signature = try testing.allocator.dupe(u8, "msgsig=="),
        .canonicalization = try testing.allocator.dupe(u8, "relaxed/relaxed"),
        .timestamp = null,
        .allocator = testing.allocator,
    };
    defer ams.deinit();

    const formatted = try ams.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expect(std.mem.startsWith(u8, formatted, "ARC-Message-Signature:"));
    try testing.expect(std.mem.indexOf(u8, formatted, "i=2") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "d=relay.example.org") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "s=relay-sel") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "h=from:to:subject:date") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "bh=bodyhash==") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "b=msgsig==") != null);
}

test "isSupportedAlgorithm" {
    const testing = std.testing;

    try testing.expect(isSupportedAlgorithm("rsa-sha256"));
    try testing.expect(isSupportedAlgorithm("rsa-sha1"));
    try testing.expect(isSupportedAlgorithm("ed25519-sha256"));
    try testing.expect(!isSupportedAlgorithm("unknown-algo"));
    try testing.expect(!isSupportedAlgorithm(""));
}

test "ARCChain latestChainValidation" {
    const testing = std.testing;

    var chain = ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Empty chain
    try testing.expectEqual(ARCChainValidation.none, chain.latestChainValidation());

    // Add set i=1
    try chain.addSet(.{
        .instance = 1,
        .aar = .{ .instance = 1, .results = "", .allocator = testing.allocator },
        .ams = .{ .instance = 1, .algorithm = "rsa-sha256", .domain = "a.com", .selector = "s", .headers = "from", .body_hash = "h", .signature = "s", .canonicalization = "relaxed/relaxed", .timestamp = null, .allocator = testing.allocator },
        .seal = .{ .instance = 1, .algorithm = "rsa-sha256", .domain = "a.com", .selector = "s", .signature = "seal", .chain_validation = .none, .timestamp = null, .allocator = testing.allocator },
    });

    try testing.expectEqual(ARCChainValidation.none, chain.latestChainValidation());

    // Add set i=2 with cv=pass
    try chain.addSet(.{
        .instance = 2,
        .aar = .{ .instance = 2, .results = "", .allocator = testing.allocator },
        .ams = .{ .instance = 2, .algorithm = "rsa-sha256", .domain = "b.com", .selector = "s", .headers = "from", .body_hash = "h", .signature = "s", .canonicalization = "relaxed/relaxed", .timestamp = null, .allocator = testing.allocator },
        .seal = .{ .instance = 2, .algorithm = "rsa-sha256", .domain = "b.com", .selector = "s", .signature = "seal", .chain_validation = .pass, .timestamp = null, .allocator = testing.allocator },
    });

    try testing.expectEqual(ARCChainValidation.pass, chain.latestChainValidation());
}

test "ARCSealer generateARCAuthenticationResults" {
    const testing = std.testing;

    var sealer = try ARCSealer.init(
        testing.allocator,
        "example.com",
        "sel",
        "key",
    );
    defer sealer.deinit();

    const result = try sealer.generateARCAuthenticationResults(
        3,
        "mx.example.com; dkim=pass; spf=pass",
    );
    defer testing.allocator.free(result);

    try testing.expectEqualStrings(
        "ARC-Authentication-Results: i=3; mx.example.com; dkim=pass; spf=pass",
        result,
    );
}
