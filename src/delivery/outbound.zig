const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// Outbound email delivery via AWS SES.
///
/// AWS blocks outbound port 25 on EC2 instances, so we relay through
/// SES using the AWS CLI (which uses the instance IAM role credentials).
/// The instance role has ses:SendRawEmail permission.
/// Deliver an email to a remote recipient via AWS SES.
/// Base64-encodes the raw message, writes a JSON input file, and calls
/// `aws ses send-raw-email --cli-input-json`.
pub fn deliverToRemote(
    allocator: std.mem.Allocator,
    from: []const u8,
    to: []const u8,
    message_data: []const u8,
    our_hostname: []const u8,
) !void {
    _ = our_hostname;

    // Build the full RFC 5322 message if not already present.
    // Apple Mail sends a complete message with headers, so just use it as-is.
    var raw_message: []const u8 = message_data;
    var owned_message: ?[]u8 = null;
    defer if (owned_message) |m| allocator.free(m);

    // Check if message has a From header — if not, prepend minimal headers
    if (!hasHeader(message_data, "From:")) {
        owned_message = try std.fmt.allocPrint(allocator, "From: {s}\r\nTo: {s}\r\n{s}", .{ from, to, message_data });
        raw_message = owned_message.?;
    }

    // Base64-encode the raw message
    const encoder = std.base64.standard;
    const b64_len = encoder.Encoder.calcSize(raw_message.len);
    const b64_buf = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64_buf);
    const b64_data = encoder.Encoder.encode(b64_buf, raw_message);

    // Build JSON input for AWS CLI
    // {"Source":"from","Destinations":["to"],"RawMessage":{"Data":"base64..."}}
    const json_input = try std.fmt.allocPrint(
        allocator,
        "{{\"Source\":\"{s}\",\"Destinations\":[\"{s}\"],\"RawMessage\":{{\"Data\":\"{s}\"}}}}",
        .{ from, to, b64_data },
    );
    defer allocator.free(json_input);

    // Write JSON to temp file
    const timestamp = time_compat.milliTimestamp();
    const tmp_path_z = try std.fmt.allocPrint(allocator, "/tmp/ses-input-{d}.json", .{timestamp});
    defer allocator.free(tmp_path_z);

    const path_z = try allocator.dupeZ(u8, tmp_path_z);
    defer allocator.free(path_z);

    const fd = std.c.open(path_z.ptr, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
        .CLOEXEC = true,
    }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return error.TempFileCreateFailed;

    var written: usize = 0;
    while (written < json_input.len) {
        const n = std.c.write(fd, json_input[written..].ptr, json_input.len - written);
        if (n <= 0) {
            _ = std.c.close(fd);
            return error.TempFileWriteFailed;
        }
        written += @intCast(n);
    }
    _ = std.c.close(fd);

    // Build file:// argument for AWS CLI
    const file_arg = try std.fmt.allocPrint(allocator, "file://{s}", .{tmp_path_z});
    defer allocator.free(file_arg);

    const io = io_compat.getIo();

    // Spawn `aws ses send-raw-email --cli-input-json file:///tmp/ses-input-{ts}.json`
    var child = try std.process.spawn(io, .{
        .argv = &[_][]const u8{
            "aws",            "ses",
            "send-raw-email", "--region",
            "us-east-1",      "--cli-input-json",
            file_arg,
        },
    });

    const term = try child.wait(io);

    // Clean up temp file
    _ = std.c.unlink(path_z.ptr);

    // Check exit status
    switch (term) {
        .exited => |code| {
            if (code != 0) {
                std.log.err("aws ses send-raw-email exited with code {d} for recipient {s}", .{ code, to });
                return error.SesDeliveryFailed;
            }
        },
        else => {
            std.log.err("aws ses send-raw-email terminated abnormally for recipient {s}", .{to});
            return error.SesDeliveryFailed;
        },
    }

    std.log.info("Email delivered to {s} via AWS SES", .{to});
}

/// Check if a message contains a specific header.
fn hasHeader(data: []const u8, header: []const u8) bool {
    var pos: usize = 0;
    while (pos < data.len) {
        if (pos + header.len <= data.len) {
            if (std.ascii.startsWithIgnoreCase(data[pos..], header)) {
                return true;
            }
        }

        // Find next line
        while (pos < data.len and data[pos] != '\n') : (pos += 1) {}
        pos += 1;

        // Empty line = end of headers
        if (pos < data.len and (data[pos] == '\n' or
            (pos + 1 < data.len and data[pos] == '\r' and data[pos + 1] == '\n')))
        {
            break;
        }
    }
    return false;
}
