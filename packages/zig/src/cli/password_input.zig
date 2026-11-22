const std = @import("std");
const cli = @import("zig-cli");

const max_input_password_bytes = 4096;
pub const Buffer = [max_input_password_bytes + 1]u8;
const password_input_signals = [_]std.posix.SIG{ .HUP, .INT, .QUIT, .TERM, .TSTP };
var saved_terminal: std.posix.termios = undefined;

fn restoreTerminalOnSignal(signal: std.posix.SIG) callconv(.c) void {
    _ = std.c.tcsetattr(std.posix.STDIN_FILENO, .NOW, &saved_terminal);
    std.c._exit(@intCast(128 + @backingInt(signal)));
}

fn readPasswordLine(buffer: *Buffer, complete: bool) ![]const u8 {
    var length: usize = 0;
    var byte: [1]u8 = undefined;
    defer std.crypto.secureZero(u8, &byte);
    while (true) {
        if (try std.posix.read(std.posix.STDIN_FILENO, &byte) == 0) {
            if (complete) return error.IncompletePasswordLine;
            break;
        }
        if (byte[0] == '\n') break;
        if (length == buffer.len) return error.PasswordTooLong;
        buffer[length] = byte[0];
        length += 1;
    }
    if (length > 0 and buffer[length - 1] == '\r') length -= 1;
    if (length > max_input_password_bytes) return error.PasswordTooLong;
    if (length == 0) return error.EmptyPassword;
    return buffer[0..length];
}

fn promptPassword(buffer: *Buffer, prompt: []const u8, complete: bool) ![]const u8 {
    const stdin = std.posix.STDIN_FILENO;
    if (std.c.isatty(stdin) == 0) return readPasswordLine(buffer, complete);

    saved_terminal = try std.posix.tcgetattr(stdin);
    const action = std.posix.Sigaction{
        .handler = .{ .handler = restoreTerminalOnSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    var previous: [password_input_signals.len]std.posix.Sigaction = undefined;
    for (password_input_signals, &previous) |signal, *old| std.posix.sigaction(signal, &action, old);
    defer for (password_input_signals, &previous) |signal, *old| std.posix.sigaction(signal, old, null);

    var hidden = saved_terminal;
    hidden.lflag.ECHO = false;
    hidden.lflag.ECHONL = false;
    try std.posix.tcsetattr(stdin, .FLUSH, hidden);
    defer std.posix.tcsetattr(stdin, .NOW, saved_terminal) catch {};

    std.debug.print("{s}: ", .{prompt});
    defer std.debug.print("\n", .{});
    return readPasswordLine(buffer, complete);
}

pub fn read(ctx: *cli.BaseCommand.ParseContext, provided: ?[]const u8, buffer: *Buffer, prompt: []const u8) ![]const u8 {
    const complete = ctx.hasOption("remote-stdin");
    if (provided) |password| {
        if (ctx.hasOption("password-stdin") or complete) {
            std.debug.print("Error: supply a password argument or --password-stdin\n", .{});
            return error.ConflictingPasswordSources;
        }
        return password;
    }
    return promptPassword(buffer, prompt, complete) catch |err| {
        switch (err) {
            error.IncompletePasswordLine => std.debug.print("Error: the password line ended before its newline\n", .{}),
            error.EmptyPassword => std.debug.print("Error: standard input did not contain a password\n", .{}),
            error.PasswordTooLong => std.debug.print("Error: password exceeds {d} bytes\n", .{max_input_password_bytes}),
            else => {},
        }
        return err;
    };
}

pub fn addOption(cmd: *cli.BaseCommand) !void {
    _ = try cmd.addOption(cli.Option.init("password-stdin", "password-stdin", "Read one password line from standard input", .bool));
}

/// A remote stream must end its password line before the host can act on it.
pub fn addRemoteOption(cmd: *cli.BaseCommand) !void {
    try addOption(cmd);
    _ = try cmd.addOption(cli.Option.init("remote-stdin", "remote-stdin", "Require a complete password line and return failure status for remote callers", .bool));
}

pub fn validateForwarded(password: []const u8) !void {
    if (password.len == 0) return error.EmptyPassword;
    if (password.len > max_input_password_bytes) return error.PasswordTooLong;
    if (std.mem.indexOfScalar(u8, password, '\n') != null) return error.InvalidPasswordLine;
}
