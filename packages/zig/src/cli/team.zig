const std = @import("std");
const cli = @import("zig-cli");
const database = @import("../storage/database.zig");
const env = @import("../core/env.zig");
const teams = @import("../storage/team_store.zig");

fn openDb(a: std.mem.Allocator) !database.Database {
    return database.Database.init(a, env.get("SMTP_DB_PATH") orelse "./smtp.db");
}

fn operator(a: std.mem.Allocator) ![]const u8 {
    return std.fmt.allocPrint(a, "local-operator:{d}", .{std.c.geteuid()});
}

fn create(ctx: *cli.BaseCommand.ParseContext) !void {
    const a = ctx.allocator;
    const id = ctx.getArgument(0) orelse return error.TeamIdRequired;
    const name = ctx.getArgument(1) orelse return error.TeamNameRequired;
    const owner = ctx.getArgument(2) orelse return error.MailboxRequired;
    var db = try openDb(a);
    defer db.deinit();
    const actor = try operator(a);
    defer a.free(actor);
    try teams.create(&db, a, actor, id, name, owner);
}

fn show(ctx: *cli.BaseCommand.ParseContext) !void {
    const id = ctx.getArgument(0) orelse return error.TeamIdRequired;
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try openDb(a);
    defer db.deinit();
    const details = try teams.details(&db, a, .{ .operator = try operator(a) }, id);
    var buf: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(std.Options.debug_io, &buf);
    try std.json.Stringify.value(details, .{ .whitespace = .indent_2 }, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn member(ctx: *cli.BaseCommand.ParseContext) !void {
    const a = ctx.allocator;
    const id = ctx.getArgument(0) orelse return error.TeamIdRequired;
    const mailbox = ctx.getArgument(1) orelse return error.MailboxRequired;
    const role = ctx.getArgument(2) orelse return error.TeamRoleRequired;
    const next: ?teams.Role = if (std.mem.eql(u8, role, "remove"))
        null
    else
        std.meta.stringToEnum(teams.Role, role) orelse return error.InvalidTeamRole;
    var db = try openDb(a);
    defer db.deinit();
    const actor = try operator(a);
    defer a.free(actor);
    try teams.setMember(&db, a, .{ .operator = actor }, id, mailbox, next);
}

fn grantAction(ctx: *cli.BaseCommand.ParseContext, allowed: bool) !void {
    const a = ctx.allocator;
    const id = ctx.getArgument(0) orelse return error.TeamIdRequired;
    const source = ctx.getArgument(1) orelse return error.SourceMailboxRequired;
    const grantee = ctx.getArgument(2) orelse return error.GranteeMailboxRequired;
    const scope = std.meta.stringToEnum(teams.Scope, ctx.getArgument(3) orelse "") orelse return error.InvalidGrantScope;
    var db = try openDb(a);
    defer db.deinit();
    const actor = try operator(a);
    defer a.free(actor);
    try teams.setGrant(&db, a, .{ .operator = actor }, id, .{
        .source = source,
        .grantee = grantee,
        .scope = scope,
        .resource = ctx.getArgument(4) orelse "",
    }, allowed);
}

fn grant(ctx: *cli.BaseCommand.ParseContext) !void {
    return grantAction(ctx, true);
}

fn revoke(ctx: *cli.BaseCommand.ParseContext) !void {
    return grantAction(ctx, false);
}

pub fn setup(a: std.mem.Allocator) !*cli.BaseCommand {
    const root = try cli.BaseCommand.init(a, "team", "Manage self-hosted teams and their explicit grants");
    const commands = .{
        .{ "create", "Create a team with an existing mailbox as owner", create, .{ "team-id", "display-name", "owner" } },
        .{ "show", "Show team members and grants", show, .{"team-id"} },
        .{ "member", "Set a role (owner, admin, member) or remove a member", member, .{ "team-id", "mailbox", "role-or-remove" } },
        .{ "grant", "Grant a specific resource to another team member", grant, .{ "team-id", "source", "grantee", "scope", "resource" } },
        .{ "revoke", "Revoke a resource grant", revoke, .{ "team-id", "source", "grantee", "scope", "resource" } },
    };
    inline for (commands) |spec| {
        const command = try cli.BaseCommand.init(a, spec[0], spec[1]);
        _ = command.setAction(spec[2]);
        inline for (spec[3]) |name| {
            _ = try command.addArgument(cli.Argument.init(name, name, .string).withRequired(!std.mem.eql(u8, name, "resource")));
        }
        _ = try root.addCommand(command);
    }
    return root;
}
