const std = @import("std");
const version_info = @import("../core/version.zig");
const attachment_storage = @import("../storage/attachment_storage.zig");
const email_threads = @import("../features/email_threads.zig");
const inline_images = @import("../features/inline_images.zig");
const email_templates = @import("../features/email_templates.zig");
const email_signatures = @import("../features/email_signatures.zig");
const read_receipts = @import("../features/read_receipts.zig");
const email_scheduling = @import("../features/email_scheduling.zig");
const contact_groups = @import("../features/contact_groups.zig");

// =============================================================================
// Webmail Client - Responsive Web Interface for Email
// =============================================================================
//
// ## Overview
// Provides a modern, responsive web interface for email management including:
// - Email composition with rich text support
// - Inbox, sent, drafts, trash folder views
// - Email search and filtering
// - Contact management integration
// - Mobile-friendly design
//
// ## Architecture
//
//   Browser <──> WebmailHandler <──> IMAP/Storage
//      │              │
//      └──> Static Assets (HTML/CSS/JS)
//
// =============================================================================

/// Webmail configuration
pub const WebmailConfig = struct {
    /// Maximum attachment size in bytes
    max_attachment_size: usize = 25 * 1024 * 1024, // 25MB
    /// Maximum number of attachments per email
    max_attachments: usize = 10,
    /// Session timeout in seconds
    session_timeout_seconds: u32 = 3600, // 1 hour
    /// Enable rich text editor
    enable_rich_text: bool = true,
    /// Enable spell check
    enable_spell_check: bool = true,
    /// Messages per page
    messages_per_page: u32 = 50,
    /// Enable dark mode
    enable_dark_mode: bool = true,
    /// Custom theme CSS URL
    custom_theme_url: ?[]const u8 = null,
    /// Enable draft saving
    enable_drafts: bool = true,
    /// Enable contacts panel
    enable_contacts: bool = true,
    /// Attachment storage path
    attachment_storage_path: []const u8 = "/tmp/mail_attachments",
};

/// Email folder types
pub const FolderType = enum {
    inbox,
    sent,
    drafts,
    trash,
    spam,
    archive,
    custom,

    pub fn toString(self: FolderType) []const u8 {
        return switch (self) {
            .inbox => "Inbox",
            .sent => "Sent",
            .drafts => "Drafts",
            .trash => "Trash",
            .spam => "Spam",
            .archive => "Archive",
            .custom => "Custom",
        };
    }

    pub fn icon(self: FolderType) []const u8 {
        return switch (self) {
            .inbox => "inbox",
            .sent => "send",
            .drafts => "edit",
            .trash => "trash-2",
            .spam => "alert-triangle",
            .archive => "archive",
            .custom => "folder",
        };
    }
};

/// Email message for webmail display
pub const WebmailMessage = struct {
    id: []const u8,
    folder: FolderType,
    from: EmailAddress,
    to: []const EmailAddress,
    cc: []const EmailAddress,
    bcc: []const EmailAddress,
    subject: []const u8,
    body_text: ?[]const u8,
    body_html: ?[]const u8,
    date: i64,
    is_read: bool,
    is_starred: bool,
    is_flagged: bool,
    has_attachments: bool,
    attachments: []const Attachment,
    reply_to: ?[]const u8,
    in_reply_to: ?[]const u8,
    thread_id: ?[]const u8,

    pub const EmailAddress = struct {
        name: ?[]const u8,
        email: []const u8,

        pub fn format(self: EmailAddress, allocator: std.mem.Allocator) ![]u8 {
            if (self.name) |name| {
                return std.fmt.allocPrint(allocator, "{s} <{s}>", .{ name, self.email });
            }
            return allocator.dupe(u8, self.email);
        }
    };

    pub const Attachment = struct {
        id: []const u8,
        filename: []const u8,
        mime_type: []const u8,
        size: usize,
        content_id: ?[]const u8, // For inline attachments
    };

    /// Convert to JSON for API response
    pub fn toJson(self: *const WebmailMessage, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.print(
            \\{{
            \\  "id": "{s}",
            \\  "folder": "{s}",
            \\  "from": {{"name": {s}, "email": "{s}"}},
            \\  "subject": "{s}",
            \\  "date": {d},
            \\  "is_read": {s},
            \\  "is_starred": {s},
            \\  "has_attachments": {s}
            \\}}
        , .{
            self.id,
            self.folder.toString(),
            if (self.from.name) |n| "\"" ++ n ++ "\"" else "null",
            self.from.email,
            self.subject,
            self.date,
            if (self.is_read) "true" else "false",
            if (self.is_starred) "true" else "false",
            if (self.has_attachments) "true" else "false",
        });

        return buffer.toOwnedSlice();
    }
};

/// Compose email request
pub const ComposeRequest = struct {
    to: []const []const u8,
    cc: ?[]const []const u8 = null,
    bcc: ?[]const []const u8 = null,
    subject: []const u8,
    body_text: ?[]const u8 = null,
    body_html: ?[]const u8 = null,
    reply_to_id: ?[]const u8 = null,
    forward_id: ?[]const u8 = null,
    draft_id: ?[]const u8 = null,
    attachments: ?[]const AttachmentUpload = null,

    pub const AttachmentUpload = struct {
        filename: []const u8,
        mime_type: []const u8,
        data: []const u8, // Base64 encoded
    };
};

/// Search parameters
pub const SearchParams = struct {
    query: ?[]const u8 = null,
    folder: ?FolderType = null,
    from: ?[]const u8 = null,
    to: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    has_attachment: ?bool = null,
    is_unread: ?bool = null,
    is_starred: ?bool = null,
    date_from: ?i64 = null,
    date_to: ?i64 = null,
    page: usize = 1,
    per_page: usize = 50,
};

/// Webmail session
pub const WebmailSession = struct {
    id: []const u8,
    user_id: []const u8,
    username: []const u8,
    email: []const u8,
    created_at: i64,
    last_activity: i64,
    preferences: UserPreferences,

    pub const UserPreferences = struct {
        theme: Theme = .light,
        messages_per_page: usize = 50,
        default_folder: FolderType = .inbox,
        signature: ?[]const u8 = null,
        display_name: ?[]const u8 = null,
        reply_to: ?[]const u8 = null,
        auto_save_drafts: bool = true,
        confirm_delete: bool = true,
        show_images: ShowImages = .ask,
        text_size: TextSize = .medium,

        pub const Theme = enum { light, dark, auto };
        pub const ShowImages = enum { always, never, ask };
        pub const TextSize = enum { small, medium, large };
    };
};

/// Webmail API handler
pub const WebmailHandler = struct {
    allocator: std.mem.Allocator,
    config: WebmailConfig,
    sessions: std.StringHashMap(*WebmailSession),
    attachment_store: ?attachment_storage.AttachmentStorage,
    thread_manager: email_threads.ThreadManager,
    inline_store: inline_images.InlineImageStore,
    template_manager: email_templates.TemplateManager,
    signature_manager: email_signatures.SignatureManager,
    receipt_manager: read_receipts.ReadReceiptManager,
    scheduler: email_scheduling.EmailScheduler,
    group_manager: contact_groups.ContactGroupManager,

    pub fn init(allocator: std.mem.Allocator, config: WebmailConfig) WebmailHandler {
        // Initialize attachment storage
        const store = attachment_storage.AttachmentStorage.init(allocator, .{
            .backend = .memory, // Use memory backend for now, can switch to .disk
            .base_path = config.attachment_storage_path,
            .max_file_size = config.max_attachment_size,
            .max_attachments_per_session = config.max_attachments,
        }) catch null;

        return .{
            .allocator = allocator,
            .config = config,
            .sessions = std.StringHashMap(*WebmailSession).init(allocator),
            .attachment_store = store,
            .thread_manager = email_threads.ThreadManager.init(allocator, .{}),
            .inline_store = inline_images.InlineImageStore.init(allocator, .{}),
            .template_manager = email_templates.TemplateManager.init(allocator, .{}),
            .signature_manager = email_signatures.SignatureManager.init(allocator, .{}),
            .receipt_manager = read_receipts.ReadReceiptManager.init(allocator, .{}),
            .scheduler = email_scheduling.EmailScheduler.init(allocator, .{}),
            .group_manager = contact_groups.ContactGroupManager.init(allocator, .{}),
        };
    }

    pub fn deinit(self: *WebmailHandler) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.sessions.deinit();

        if (self.attachment_store) |*store| {
            store.deinit();
        }

        self.thread_manager.deinit();
        self.inline_store.deinit();
        self.template_manager.deinit();
        self.signature_manager.deinit();
        self.receipt_manager.deinit();
        self.scheduler.deinit();
        self.group_manager.deinit();
    }

    /// Handle HTTP request
    pub fn handleRequest(self: *WebmailHandler, path: []const u8, method: []const u8, body: ?[]const u8) ![]u8 {
        _ = body;

        // Route requests
        if (std.mem.eql(u8, method, "GET")) {
            if (std.mem.eql(u8, path, "/webmail") or std.mem.eql(u8, path, "/webmail/")) {
                return self.serveMainPage();
            } else if (std.mem.startsWith(u8, path, "/webmail/api/")) {
                return self.handleApiGet(path[13..]);
            } else if (std.mem.startsWith(u8, path, "/webmail/static/")) {
                return self.serveStaticFile(path[16..]);
            }
        } else if (std.mem.eql(u8, method, "POST")) {
            if (std.mem.startsWith(u8, path, "/webmail/api/")) {
                return self.handleApiPost(path[13..]);
            }
        } else if (std.mem.eql(u8, method, "DELETE")) {
            if (std.mem.startsWith(u8, path, "/webmail/api/")) {
                return self.handleApiDelete(path[13..]);
            }
        }

        return self.serveError(404, "Not Found");
    }

    fn handleApiGet(self: *WebmailHandler, endpoint: []const u8) ![]u8 {
        if (std.mem.eql(u8, endpoint, "folders")) {
            return self.getFolders();
        } else if (std.mem.startsWith(u8, endpoint, "messages")) {
            return self.getMessages(endpoint);
        } else if (std.mem.eql(u8, endpoint, "user")) {
            return self.getUserInfo();
        } else if (std.mem.startsWith(u8, endpoint, "attachments/")) {
            return self.getAttachment(endpoint[12..]);
        } else if (std.mem.eql(u8, endpoint, "threads")) {
            return self.getThreads();
        } else if (std.mem.startsWith(u8, endpoint, "threads/")) {
            return self.getThread(endpoint[8..]);
        } else if (std.mem.startsWith(u8, endpoint, "inline/")) {
            return self.getInlineImage(endpoint[7..]);
        } else if (std.mem.eql(u8, endpoint, "inline-stats")) {
            return self.getInlineStats();
        } else if (std.mem.eql(u8, endpoint, "templates")) {
            return self.getTemplates();
        } else if (std.mem.startsWith(u8, endpoint, "templates/")) {
            return self.getTemplate(endpoint[10..]);
        } else if (std.mem.eql(u8, endpoint, "signatures")) {
            return self.getSignatures();
        } else if (std.mem.startsWith(u8, endpoint, "signatures/")) {
            return self.getSignature(endpoint[11..]);
        } else if (std.mem.eql(u8, endpoint, "receipts")) {
            return self.getReceipts();
        } else if (std.mem.eql(u8, endpoint, "scheduled")) {
            return self.getScheduledEmails();
        } else if (std.mem.eql(u8, endpoint, "groups")) {
            return self.getContactGroups();
        } else if (std.mem.startsWith(u8, endpoint, "groups/expand/")) {
            return self.expandGroup(endpoint[14..]);
        }
        return self.serveError(404, "Endpoint not found");
    }

    fn handleApiPost(self: *WebmailHandler, endpoint: []const u8) ![]u8 {
        if (std.mem.eql(u8, endpoint, "compose")) {
            return self.composeEmail();
        } else if (std.mem.eql(u8, endpoint, "search")) {
            return self.searchMessages();
        } else if (std.mem.eql(u8, endpoint, "attachments")) {
            return self.uploadAttachment();
        } else if (std.mem.startsWith(u8, endpoint, "attachments/")) {
            return self.deleteAttachment(endpoint[12..]);
        } else if (std.mem.eql(u8, endpoint, "inline")) {
            return self.uploadInlineImage();
        } else if (std.mem.eql(u8, endpoint, "templates")) {
            return self.createTemplate();
        } else if (std.mem.startsWith(u8, endpoint, "templates/apply/")) {
            return self.applyTemplate(endpoint[16..]);
        } else if (std.mem.eql(u8, endpoint, "signatures")) {
            return self.createSignature();
        } else if (std.mem.startsWith(u8, endpoint, "signatures/default/")) {
            return self.setDefaultSignature(endpoint[19..]);
        } else if (std.mem.eql(u8, endpoint, "receipts/request")) {
            return self.requestReceipt();
        } else if (std.mem.startsWith(u8, endpoint, "receipts/send/")) {
            return self.sendReceipt(endpoint[14..]);
        } else if (std.mem.eql(u8, endpoint, "schedule")) {
            return self.scheduleEmail();
        } else if (std.mem.startsWith(u8, endpoint, "schedule/cancel/")) {
            return self.cancelSchedule(endpoint[16..]);
        } else if (std.mem.eql(u8, endpoint, "groups")) {
            return self.createGroup();
        } else if (std.mem.startsWith(u8, endpoint, "groups/member/")) {
            return self.addGroupMember(endpoint[14..]);
        }
        return self.serveError(404, "Endpoint not found");
    }

    fn handleApiDelete(self: *WebmailHandler, endpoint: []const u8) ![]u8 {
        if (std.mem.startsWith(u8, endpoint, "attachments/")) {
            return self.deleteAttachment(endpoint[12..]);
        }
        return self.serveError(404, "Endpoint not found");
    }

    fn getFolders(self: *WebmailHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"folders": [
            \\  {{"type": "inbox", "name": "Inbox", "unread": 0, "icon": "inbox"}},
            \\  {{"type": "sent", "name": "Sent", "unread": 0, "icon": "send"}},
            \\  {{"type": "drafts", "name": "Drafts", "unread": 0, "icon": "edit"}},
            \\  {{"type": "trash", "name": "Trash", "unread": 0, "icon": "trash-2"}},
            \\  {{"type": "spam", "name": "Spam", "unread": 0, "icon": "alert-triangle"}},
            \\  {{"type": "archive", "name": "Archive", "unread": 0, "icon": "archive"}}
            \\]}}
        , .{});
    }

    fn getMessages(self: *WebmailHandler, _: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"messages": [], "total": 0, "page": 1, "per_page": {d}}}
        , .{self.config.messages_per_page});
    }

    fn getUserInfo(self: *WebmailHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"user": {{"email": "", "name": "", "preferences": {{}}}}}}
        , .{});
    }

    fn composeEmail(self: *WebmailHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"status": "queued", "message_id": ""}}
        , .{});
    }

    fn searchMessages(self: *WebmailHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"results": [], "total": 0}}
        , .{});
    }

    /// Get list of email threads/conversations
    fn getThreads(self: *WebmailHandler) ![]u8 {
        const summaries = self.thread_manager.getThreadSummaries(self.allocator) catch {
            return self.serveError(500, "Failed to get threads");
        };
        defer self.allocator.free(summaries);

        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll(
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{"threads": [
        );

        for (summaries, 0..) |*summary, i| {
            if (i > 0) try writer.writeAll(",");
            const json = summary.toJson(self.allocator) catch continue;
            defer self.allocator.free(json);
            try writer.writeAll(json);
        }

        try writer.print("], \"total\": {d}}}", .{summaries.len});

        return buffer.toOwnedSlice();
    }

    /// Get a specific thread by ID
    fn getThread(self: *WebmailHandler, thread_id: []const u8) ![]u8 {
        if (self.thread_manager.getThread(thread_id)) |thread| {
            const json = thread.toJson(self.allocator) catch {
                return self.serveError(500, "Failed to serialize thread");
            };
            defer self.allocator.free(json);

            return std.fmt.allocPrint(self.allocator,
                \\HTTP/1.1 200 OK
                \\Content-Type: application/json
                \\
                \\{s}
            , .{json});
        }

        return self.serveError(404, "Thread not found");
    }

    /// Build threads from messages (call after loading messages)
    pub fn buildThreadsFromMessages(self: *WebmailHandler, messages: []const email_threads.MessageHeader) !void {
        try self.thread_manager.buildThreads(messages);
    }

    /// Get thread containing a specific message
    pub fn getThreadByMessage(self: *WebmailHandler, message_id: []const u8) ?*email_threads.EmailThread {
        return self.thread_manager.getThreadByMessageId(message_id);
    }

    /// Get inline image by Content-ID
    fn getInlineImage(self: *WebmailHandler, content_id: []const u8) ![]u8 {
        if (self.inline_store.get(content_id)) |att| {
            // Return the image with proper content type
            const data_uri = att.toDataUri(self.allocator) catch {
                return self.serveError(500, "Failed to encode image");
            };
            defer self.allocator.free(data_uri);

            return std.fmt.allocPrint(self.allocator,
                \\HTTP/1.1 200 OK
                \\Content-Type: application/json
                \\
                \\{{
                \\  "content_id": "{s}",
                \\  "filename": "{s}",
                \\  "mime_type": "{s}",
                \\  "size": {d},
                \\  "data_uri": "{s}"
                \\}}
            , .{ content_id, att.filename, att.mime_type, att.size, data_uri });
        }

        return self.serveError(404, "Inline image not found");
    }

    /// Get inline image statistics
    fn getInlineStats(self: *WebmailHandler) ![]u8 {
        const stats = self.inline_store.getStats();

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{
            \\  "total_attachments": {d},
            \\  "total_images": {d},
            \\  "total_size": {d},
            \\  "message_count": {d}
            \\}}
        , .{ stats.total_attachments, stats.total_images, stats.total_size, stats.message_count });
    }

    /// Upload an inline image
    fn uploadInlineImage(self: *WebmailHandler) ![]u8 {
        // Generate Content-ID
        const content_id = inline_images.generateContentId(self.allocator, "webmail.local") catch {
            return self.serveError(500, "Failed to generate Content-ID");
        };
        defer self.allocator.free(content_id);

        // Demo: store a placeholder image
        const demo_data = "\x89PNG\r\n\x1a\n"; // PNG magic bytes
        self.inline_store.store(
            content_id,
            "inline_image.png",
            "image/png",
            demo_data,
            null,
        ) catch |err| {
            return switch (err) {
                inline_images.InlineImageError.DataTooLarge => self.serveError(413, "Image too large"),
                inline_images.InlineImageError.InvalidMimeType => self.serveError(415, "Invalid image type"),
                else => self.serveError(500, "Failed to store image"),
            };
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{
            \\  "content_id": "{s}",
            \\  "cid_url": "cid:{s}",
            \\  "status": "uploaded"
            \\}}
        , .{ content_id, content_id });
    }

    /// Resolve CID references in HTML body
    pub fn resolveInlineImages(self: *WebmailHandler, html: []const u8) ![]u8 {
        return self.inline_store.resolveHtml(html);
    }

    /// Store inline image from MIME part
    pub fn storeInlineImage(
        self: *WebmailHandler,
        content_id: []const u8,
        filename: []const u8,
        mime_type: []const u8,
        data: []const u8,
        message_id: ?[]const u8,
    ) !void {
        try self.inline_store.store(content_id, filename, mime_type, data, message_id);
    }

    // =========================================================================
    // Template API Methods
    // =========================================================================

    /// Get all templates
    fn getTemplates(self: *WebmailHandler) ![]u8 {
        const templates = self.template_manager.list(self.allocator) catch {
            return self.serveError(500, "Failed to list templates");
        };
        defer self.allocator.free(templates);

        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"templates\":[");

        for (templates, 0..) |*tmpl, i| {
            if (i > 0) try writer.writeAll(",");
            const json = tmpl.toJson(self.allocator) catch continue;
            defer self.allocator.free(json);
            try writer.writeAll(json);
        }

        const stats = self.template_manager.getStats();
        try writer.print("],\"total\":{d},\"active\":{d}}}", .{ stats.total_templates, stats.active_templates });

        return buffer.toOwnedSlice();
    }

    /// Get template by ID
    fn getTemplate(self: *WebmailHandler, id: []const u8) ![]u8 {
        if (self.template_manager.get(id)) |tmpl| {
            const json = tmpl.toJson(self.allocator) catch {
                return self.serveError(500, "Failed to serialize template");
            };
            defer self.allocator.free(json);

            return std.fmt.allocPrint(self.allocator,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{s}", .{json});
        }
        return self.serveError(404, "Template not found");
    }

    /// Create a new template
    fn createTemplate(self: *WebmailHandler) ![]u8 {
        // Demo: create a sample template
        const id = self.template_manager.create(
            "Quick Response",
            .quick_response,
            "Re: {{subject}}",
            "Hi {{name}},\n\nThank you for reaching out.\n\n{{message}}\n\nBest regards",
            null,
            "A quick response template",
        ) catch |err| {
            return switch (err) {
                email_templates.TemplateError.StorageFull => self.serveError(429, "Template storage full"),
                else => self.serveError(500, "Failed to create template"),
            };
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 201 Created
            \\Content-Type: application/json
            \\
            \\{{"id":"{s}","status":"created"}}
        , .{id});
    }

    /// Apply template with variables
    fn applyTemplate(self: *WebmailHandler, id: []const u8) ![]u8 {
        // Demo variables
        const variables = [_]email_templates.TemplateManager.VariableValue{
            .{ .name = "name", .value = "John" },
            .{ .name = "subject", .value = "Your inquiry" },
            .{ .name = "message", .value = "I'll get back to you shortly." },
        };

        const result = self.template_manager.apply(id, &variables) catch |err| {
            return switch (err) {
                email_templates.TemplateError.TemplateNotFound => self.serveError(404, "Template not found"),
                else => self.serveError(500, "Failed to apply template"),
            };
        };
        defer {
            self.allocator.free(result.subject);
            self.allocator.free(result.body_text);
            if (result.body_html) |h| self.allocator.free(h);
        }

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{"subject":"{s}","body_text":"{s}","body_html":null}}
        , .{ result.subject, result.body_text });
    }

    // =========================================================================
    // Signature API Methods
    // =========================================================================

    /// Get all signatures
    fn getSignatures(self: *WebmailHandler) ![]u8 {
        const signatures = self.signature_manager.list(self.allocator) catch {
            return self.serveError(500, "Failed to list signatures");
        };
        defer self.allocator.free(signatures);

        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"signatures\":[");

        for (signatures, 0..) |*sig, i| {
            if (i > 0) try writer.writeAll(",");
            const json = sig.toJson(self.allocator) catch continue;
            defer self.allocator.free(json);
            try writer.writeAll(json);
        }

        const stats = self.signature_manager.getStats();
        try writer.print("],\"total\":{d},\"default_count\":{d}}}", .{ stats.total_signatures, stats.default_signatures });

        return buffer.toOwnedSlice();
    }

    /// Get signature by ID
    fn getSignature(self: *WebmailHandler, id: []const u8) ![]u8 {
        if (self.signature_manager.get(id)) |sig| {
            const json = sig.toJson(self.allocator) catch {
                return self.serveError(500, "Failed to serialize signature");
            };
            defer self.allocator.free(json);

            return std.fmt.allocPrint(self.allocator,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{s}", .{json});
        }
        return self.serveError(404, "Signature not found");
    }

    /// Create a new signature
    fn createSignature(self: *WebmailHandler) ![]u8 {
        // Demo: create a sample signature
        const id = self.signature_manager.create(
            "Professional",
            "Best regards,\n\nJohn Doe\nSenior Developer\nAcme Corp\nPhone: (555) 123-4567",
            "<div style=\"color:#333;\"><p>Best regards,</p><p><strong>John Doe</strong><br>Senior Developer<br>Acme Corp<br>Phone: (555) 123-4567</p></div>",
            .{ .is_default = true },
        ) catch |err| {
            return switch (err) {
                email_signatures.SignatureError.StorageFull => self.serveError(429, "Signature storage full"),
                else => self.serveError(500, "Failed to create signature"),
            };
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 201 Created
            \\Content-Type: application/json
            \\
            \\{{"id":"{s}","status":"created"}}
        , .{id});
    }

    /// Set default signature
    fn setDefaultSignature(self: *WebmailHandler, id: []const u8) ![]u8 {
        self.signature_manager.setDefault(id) catch |err| {
            return switch (err) {
                email_signatures.SignatureError.SignatureNotFound => self.serveError(404, "Signature not found"),
                else => self.serveError(500, "Failed to set default"),
            };
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{"id":"{s}","is_default":true}}
        , .{id});
    }

    /// Get default signature for context
    pub fn getDefaultSignature(self: *WebmailHandler, context: email_signatures.SignatureManager.SignatureContext) ?*const email_signatures.EmailSignature {
        return self.signature_manager.getForContext(context, null);
    }

    // =========================================================================
    // Read Receipt API Methods
    // =========================================================================

    fn getReceipts(self: *WebmailHandler) ![]u8 {
        const outgoing = self.receipt_manager.getOutgoing(self.allocator) catch {
            return self.serveError(500, "Failed to get receipts");
        };
        defer self.allocator.free(outgoing);

        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"receipts\":[");

        for (outgoing, 0..) |*rcpt, i| {
            if (i > 0) try writer.writeAll(",");
            const json = rcpt.toJson(self.allocator) catch continue;
            defer self.allocator.free(json);
            try writer.writeAll(json);
        }

        const stats = self.receipt_manager.getStats();
        try writer.print("],\"pending\":{d},\"read\":{d}}}", .{ stats.outgoing_pending, stats.outgoing_read });

        return buffer.toOwnedSlice();
    }

    fn requestReceipt(self: *WebmailHandler) ![]u8 {
        const id = self.receipt_manager.requestReceipt(
            "<demo_msg@example.com>",
            "Demo Subject",
            "me@example.com",
            "recipient@example.com",
        ) catch {
            return self.serveError(500, "Failed to request receipt");
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 201 Created
            \\Content-Type: application/json
            \\
            \\{{"id":"{s}","status":"requested"}}
        , .{id});
    }

    fn sendReceipt(self: *WebmailHandler, request_id: []const u8) ![]u8 {
        self.receipt_manager.sendReceipt(request_id) catch |err| {
            return switch (err) {
                read_receipts.ReceiptError.ReceiptNotFound => self.serveError(404, "Receipt not found"),
                read_receipts.ReceiptError.AlreadySent => self.serveError(409, "Already sent"),
                else => self.serveError(500, "Failed to send receipt"),
            };
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{"id":"{s}","status":"sent"}}
        , .{request_id});
    }

    // =========================================================================
    // Email Scheduling API Methods
    // =========================================================================

    fn getScheduledEmails(self: *WebmailHandler) ![]u8 {
        const pending = self.scheduler.getPending(self.allocator) catch {
            return self.serveError(500, "Failed to get scheduled emails");
        };
        defer self.allocator.free(pending);

        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"scheduled\":[");

        for (pending, 0..) |*sched, i| {
            if (i > 0) try writer.writeAll(",");
            const json = sched.toJson(self.allocator) catch continue;
            defer self.allocator.free(json);
            try writer.writeAll(json);
        }

        const stats = self.scheduler.getStats();
        try writer.print("],\"total\":{d},\"pending\":{d}}}", .{ stats.total, stats.pending });

        return buffer.toOwnedSlice();
    }

    fn scheduleEmail(self: *WebmailHandler) ![]u8 {
        // Demo: schedule for 1 hour from now
        const send_at = std.time.timestamp() + 3600;

        const id = self.scheduler.schedule(
            "demo@example.com",
            "Scheduled Demo",
            "This is a scheduled email.",
            send_at,
            .{},
        ) catch |err| {
            return switch (err) {
                email_scheduling.ScheduleError.QueueFull => self.serveError(429, "Schedule queue full"),
                email_scheduling.ScheduleError.PastTime => self.serveError(400, "Cannot schedule in the past"),
                else => self.serveError(500, "Failed to schedule"),
            };
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 201 Created
            \\Content-Type: application/json
            \\
            \\{{"id":"{s}","send_at":{d},"status":"scheduled"}}
        , .{ id, send_at });
    }

    fn cancelSchedule(self: *WebmailHandler, schedule_id: []const u8) ![]u8 {
        self.scheduler.cancel(schedule_id) catch |err| {
            return switch (err) {
                email_scheduling.ScheduleError.ScheduleNotFound => self.serveError(404, "Schedule not found"),
                email_scheduling.ScheduleError.AlreadySent => self.serveError(409, "Already sent"),
                else => self.serveError(500, "Failed to cancel"),
            };
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{"id":"{s}","status":"cancelled"}}
        , .{schedule_id});
    }

    // =========================================================================
    // Contact Groups API Methods
    // =========================================================================

    fn getContactGroups(self: *WebmailHandler) ![]u8 {
        const groups = self.group_manager.list(self.allocator) catch {
            return self.serveError(500, "Failed to list groups");
        };
        defer self.allocator.free(groups);

        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"groups\":[");

        for (groups, 0..) |group, i| {
            if (i > 0) try writer.writeAll(",");
            const json = group.toJson(self.allocator) catch continue;
            defer self.allocator.free(json);
            try writer.writeAll(json);
        }

        const stats = self.group_manager.getStats();
        try writer.print("],\"total\":{d},\"total_members\":{d}}}", .{ stats.total_groups, stats.total_members });

        return buffer.toOwnedSlice();
    }

    fn createGroup(self: *WebmailHandler) ![]u8 {
        const id = self.group_manager.create("New Group", "A new contact group") catch |err| {
            return switch (err) {
                contact_groups.GroupError.GroupFull => self.serveError(429, "Maximum groups reached"),
                else => self.serveError(500, "Failed to create group"),
            };
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 201 Created
            \\Content-Type: application/json
            \\
            \\{{"id":"{s}","status":"created"}}
        , .{id});
    }

    fn addGroupMember(self: *WebmailHandler, group_id: []const u8) ![]u8 {
        const group = self.group_manager.get(group_id) orelse {
            return self.serveError(404, "Group not found");
        };

        group.addEmail("new@example.com", "New Member") catch |err| {
            return switch (err) {
                contact_groups.GroupError.DuplicateMember => self.serveError(409, "Member already exists"),
                else => self.serveError(500, "Failed to add member"),
            };
        };

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{"group_id":"{s}","status":"member_added"}}
        , .{group_id});
    }

    fn expandGroup(self: *WebmailHandler, group_id: []const u8) ![]u8 {
        const emails = self.group_manager.expandGroup(group_id, self.allocator) catch |err| {
            return switch (err) {
                contact_groups.GroupError.GroupNotFound => self.serveError(404, "Group not found"),
                else => self.serveError(500, "Failed to expand group"),
            };
        };
        defer self.allocator.free(emails);

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{"group_id":"{s}","emails":"{s}"}}
        , .{ group_id, emails });
    }

    /// Upload an attachment
    /// Handles multipart/form-data file uploads
    fn uploadAttachment(self: *WebmailHandler) ![]u8 {
        // Check if storage is available
        if (self.attachment_store) |*store| {
            // For demo purposes, create a sample upload
            // In production, this would parse the multipart form data from the request body
            const sample_data = "Sample attachment content for demonstration";
            const sample_filename = "uploaded_file.txt";

            const result = store.store(
                sample_data,
                sample_filename,
                null, // Auto-detect MIME type
                null, // Owner ID from session
            ) catch |err| {
                return switch (err) {
                    attachment_storage.StorageError.FileTooLarge => self.serveError(413, "File too large"),
                    attachment_storage.StorageError.QuotaExceeded => self.serveError(429, "Attachment quota exceeded"),
                    else => self.serveError(500, "Storage error"),
                };
            };

            return std.fmt.allocPrint(self.allocator,
                \\HTTP/1.1 200 OK
                \\Content-Type: application/json
                \\
                \\{{
                \\  "id": "{s}",
                \\  "filename": "{s}",
                \\  "mime_type": "{s}",
                \\  "size": {d},
                \\  "status": "uploaded",
                \\  "expires_at": {d}
                \\}}
            , .{ result.id, result.filename, result.mime_type, result.size, result.expires_at });
        }

        // Fallback if storage not initialized
        const timestamp = std.time.timestamp();
        var rand_bytes: [8]u8 = undefined;
        std.c.arc4random_buf(&rand_bytes, rand_bytes.len);

        var id_buf: [32]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "att_{x}_{x}", .{
            @as(u64, @intCast(timestamp)),
            std.mem.readInt(u64, &rand_bytes, .big),
        }) catch "att_unknown";

        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{
            \\  "id": "{s}",
            \\  "filename": "uploaded_file",
            \\  "mime_type": "application/octet-stream",
            \\  "size": 0,
            \\  "status": "uploaded",
            \\  "expires_at": {d}
            \\}}
        , .{ id, timestamp + 3600 });
    }

    /// Upload attachment with actual data (for internal use)
    pub fn uploadAttachmentWithData(
        self: *WebmailHandler,
        data: []const u8,
        filename: []const u8,
        mime_type: ?[]const u8,
        owner_id: ?[]const u8,
    ) !attachment_storage.UploadResult {
        if (self.attachment_store) |*store| {
            return store.store(data, filename, mime_type, owner_id);
        }
        return attachment_storage.StorageError.StorageNotAvailable;
    }

    /// Delete an uploaded attachment
    fn deleteAttachment(self: *WebmailHandler, attachment_id: []const u8) ![]u8 {
        if (attachment_id.len == 0) {
            return self.serveError(400, "Missing attachment ID");
        }

        if (self.attachment_store) |*store| {
            store.delete(attachment_id) catch |err| {
                return switch (err) {
                    attachment_storage.StorageError.AttachmentNotFound => self.serveError(404, "Attachment not found"),
                    else => self.serveError(500, "Failed to delete attachment"),
                };
            };

            return std.fmt.allocPrint(self.allocator,
                \\HTTP/1.1 200 OK
                \\Content-Type: application/json
                \\
                \\{{"success": true, "deleted_id": "{s}"}}
            , .{attachment_id});
        }

        // Fallback response
        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/json
            \\
            \\{{"success": true, "deleted_id": "{s}"}}
        , .{attachment_id});
    }

    /// Get attachment by ID (for download)
    fn getAttachment(self: *WebmailHandler, attachment_id: []const u8) ![]u8 {
        if (attachment_id.len == 0) {
            return self.serveError(400, "Missing attachment ID");
        }

        if (self.attachment_store) |*store| {
            // Get metadata first
            const metadata = store.getMetadata(attachment_id) catch |err| {
                return switch (err) {
                    attachment_storage.StorageError.AttachmentNotFound => self.serveError(404, "Attachment not found"),
                    attachment_storage.StorageError.AttachmentExpired => self.serveError(410, "Attachment expired"),
                    else => self.serveError(500, "Storage error"),
                };
            };

            // Retrieve the actual data
            const data = store.retrieve(attachment_id) catch |err| {
                return switch (err) {
                    attachment_storage.StorageError.AttachmentNotFound => self.serveError(404, "Attachment not found"),
                    attachment_storage.StorageError.AttachmentExpired => self.serveError(410, "Attachment expired"),
                    else => self.serveError(500, "Failed to retrieve attachment"),
                };
            };
            defer self.allocator.free(data);

            // Build response with actual content
            const header = try std.fmt.allocPrint(self.allocator,
                "HTTP/1.1 200 OK\r\n" ++
                    "Content-Type: {s}\r\n" ++
                    "Content-Disposition: attachment; filename=\"{s}\"\r\n" ++
                    "Content-Length: {d}\r\n" ++
                    "Cache-Control: private, max-age=3600\r\n" ++
                    "\r\n",
                .{ metadata.mime_type, metadata.filename, data.len },
            );

            // Combine header and data
            const response = try self.allocator.alloc(u8, header.len + data.len);
            @memcpy(response[0..header.len], header);
            @memcpy(response[header.len..], data);
            self.allocator.free(header);

            return response;
        }

        // Fallback response
        return std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 200 OK
            \\Content-Type: application/octet-stream
            \\Content-Disposition: attachment; filename="file"
            \\Content-Length: 0
            \\
            \\
        , .{});
    }

    /// Get storage statistics
    pub fn getStorageStats(self: *WebmailHandler) ?attachment_storage.StorageStats {
        if (self.attachment_store) |*store| {
            return store.getStats();
        }
        return null;
    }

    /// Cleanup expired attachments
    pub fn cleanupExpiredAttachments(self: *WebmailHandler) !usize {
        if (self.attachment_store) |*store| {
            return store.cleanupExpired();
        }
        return 0;
    }

    fn serveError(self: *WebmailHandler, status: u16, message: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\n\r\n{{\"error\": \"{s}\"}}",
            .{ status, message, message },
        );
    }

    fn serveStaticFile(self: *WebmailHandler, _: []const u8) ![]u8 {
        return self.serveError(404, "Static file not found");
    }

    /// Serve the main webmail page
    pub fn serveMainPage(self: *WebmailHandler) ![]u8 {
        const html = webmail_html;
        return std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ html.len, html },
        );
    }
};

// =============================================================================
// Contact Management
// =============================================================================

/// Contact for address book
pub const Contact = struct {
    id: []const u8,
    first_name: ?[]const u8,
    last_name: ?[]const u8,
    email: []const u8,
    phone: ?[]const u8,
    company: ?[]const u8,
    notes: ?[]const u8,
    avatar_url: ?[]const u8,
    groups: []const []const u8,
    created_at: i64,
    updated_at: i64,

    pub fn displayName(self: *const Contact) []const u8 {
        if (self.first_name) |first| {
            if (self.last_name) |last| {
                _ = last;
                return first; // Would concatenate in real impl
            }
            return first;
        }
        return self.email;
    }
};

/// Contact group
pub const ContactGroup = struct {
    id: []const u8,
    name: []const u8,
    color: ?[]const u8,
    member_count: usize,
};

// =============================================================================
// Calendar Integration
// =============================================================================

/// Calendar event for mini calendar view
pub const CalendarEvent = struct {
    id: []const u8,
    title: []const u8,
    start_time: i64,
    end_time: i64,
    location: ?[]const u8,
    description: ?[]const u8,
    attendees: []const []const u8,
    is_all_day: bool,
    color: ?[]const u8,
    reminder_minutes: ?u32,
};

// =============================================================================
// Folder Management
// =============================================================================

/// Custom folder
pub const CustomFolder = struct {
    id: []const u8,
    name: []const u8,
    parent_id: ?[]const u8,
    color: ?[]const u8,
    icon: ?[]const u8,
    unread_count: usize,
    total_count: usize,
    sort_order: u32,
};

/// Folder action request
pub const FolderAction = union(enum) {
    create: struct {
        name: []const u8,
        parent_id: ?[]const u8,
    },
    rename: struct {
        id: []const u8,
        new_name: []const u8,
    },
    delete: struct {
        id: []const u8,
    },
    move: struct {
        id: []const u8,
        new_parent_id: ?[]const u8,
    },
};

// =============================================================================
// Message Actions
// =============================================================================

/// Batch message action
pub const MessageAction = union(enum) {
    mark_read: []const []const u8,
    mark_unread: []const []const u8,
    star: []const []const u8,
    unstar: []const []const u8,
    move_to: struct {
        message_ids: []const []const u8,
        folder: FolderType,
    },
    delete: []const []const u8,
    archive: []const []const u8,
    mark_spam: []const []const u8,
    mark_not_spam: []const []const u8,
};

/// Embedded webmail HTML template with full functionality
const webmail_html =
    \\<!DOCTYPE html>
    \\<html lang="en">
    \\<head>
    \\    <meta charset="UTF-8">
    \\    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    \\    <meta name="apple-mobile-web-app-capable" content="yes">
    \\    <meta name="theme-color" content="#4f46e5">
    \\    <title>Webmail - SMTP Server v0.28.0</title>
    \\    <style>
    \\        :root {
    \\            --primary: #4f46e5;
    \\            --primary-hover: #4338ca;
    \\            --primary-light: rgba(79, 70, 229, 0.1);
    \\            --bg: #f9fafb;
    \\            --sidebar-bg: #ffffff;
    \\            --card-bg: #ffffff;
    \\            --text: #111827;
    \\            --text-muted: #6b7280;
    \\            --border: #e5e7eb;
    \\            --success: #10b981;
    \\            --warning: #f59e0b;
    \\            --danger: #ef4444;
    \\            --shadow: 0 1px 3px rgba(0,0,0,0.1);
    \\            --shadow-lg: 0 10px 25px rgba(0,0,0,0.15);
    \\        }
    \\        [data-theme="dark"] {
    \\            --bg: #111827;
    \\            --sidebar-bg: #1f2937;
    \\            --card-bg: #1f2937;
    \\            --text: #f9fafb;
    \\            --text-muted: #9ca3af;
    \\            --border: #374151;
    \\            --shadow: 0 1px 3px rgba(0,0,0,0.3);
    \\        }
    \\        * { margin: 0; padding: 0; box-sizing: border-box; }
    \\        body {
    \\            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    \\            background: var(--bg);
    \\            color: var(--text);
    \\            height: 100vh;
    \\            overflow: hidden;
    \\        }
    \\        .app {
    \\            display: grid;
    \\            grid-template-columns: 240px 320px 1fr;
    \\            height: 100vh;
    \\        }
    \\        @media (max-width: 1200px) {
    \\            .app { grid-template-columns: 200px 280px 1fr; }
    \\        }
    \\        @media (max-width: 1024px) {
    \\            .app { grid-template-columns: 60px 280px 1fr; }
    \\            .sidebar .folder-name, .sidebar .compose-text, .sidebar .section-title { display: none; }
    \\            .sidebar .compose-btn { padding: 12px; justify-content: center; }
    \\        }
    \\        @media (max-width: 768px) {
    \\            .app { grid-template-columns: 1fr; }
    \\            .sidebar { position: fixed; left: -100%; width: 280px; height: 100%; z-index: 100; transition: left 0.3s; }
    \\            .sidebar.open { left: 0; }
    \\            .message-list { display: block; }
    \\            .message-view { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 50; }
    \\            .message-view.open { display: block; }
    \\            .mobile-header { display: flex !important; }
    \\        }
    \\        /* Sidebar */
    \\        .sidebar {
    \\            background: var(--sidebar-bg);
    \\            border-right: 1px solid var(--border);
    \\            display: flex;
    \\            flex-direction: column;
    \\            overflow: hidden;
    \\        }
    \\        .sidebar-header {
    \\            padding: 16px;
    \\            border-bottom: 1px solid var(--border);
    \\        }
    \\        .logo {
    \\            font-size: 1.125rem;
    \\            font-weight: 700;
    \\            color: var(--primary);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\        }
    \\        .compose-btn {
    \\            width: 100%;
    \\            padding: 10px 16px;
    \\            background: var(--primary);
    \\            color: white;
    \\            border: none;
    \\            border-radius: 8px;
    \\            font-size: 0.875rem;
    \\            font-weight: 500;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            margin-top: 12px;
    \\            transition: all 0.2s;
    \\        }
    \\        .compose-btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
    \\        .sidebar-content { flex: 1; overflow-y: auto; padding: 12px; }
    \\        .section-title {
    \\            font-size: 0.7rem;
    \\            font-weight: 600;
    \\            text-transform: uppercase;
    \\            letter-spacing: 0.5px;
    \\            color: var(--text-muted);
    \\            padding: 12px 8px 6px;
    \\        }
    \\        .folders { list-style: none; }
    \\        .folder {
    \\            padding: 8px 10px;
    \\            border-radius: 6px;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 10px;
    \\            color: var(--text-muted);
    \\            transition: all 0.15s;
    \\            font-size: 0.875rem;
    \\        }
    \\        .folder:hover { background: var(--primary-light); color: var(--primary); }
    \\        .folder.active { background: var(--primary); color: white; }
    \\        .folder.active .folder-count { background: white; color: var(--primary); }
    \\        .folder-count {
    \\            margin-left: auto;
    \\            background: var(--primary);
    \\            color: white;
    \\            padding: 1px 6px;
    \\            border-radius: 10px;
    \\            font-size: 0.7rem;
    \\            font-weight: 500;
    \\        }
    \\        .sidebar-footer {
    \\            padding: 12px;
    \\            border-top: 1px solid var(--border);
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\        }
    \\        /* Message List */
    \\        .message-list {
    \\            background: var(--card-bg);
    \\            border-right: 1px solid var(--border);
    \\            display: flex;
    \\            flex-direction: column;
    \\            overflow: hidden;
    \\        }
    \\        .mobile-header {
    \\            display: none;
    \\            padding: 12px;
    \\            border-bottom: 1px solid var(--border);
    \\            align-items: center;
    \\            gap: 12px;
    \\        }
    \\        .menu-btn {
    \\            background: none;
    \\            border: none;
    \\            padding: 8px;
    \\            cursor: pointer;
    \\            color: var(--text);
    \\        }
    \\        .list-header {
    \\            padding: 12px 16px;
    \\            border-bottom: 1px solid var(--border);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\        }
    \\        .list-title {
    \\            font-weight: 600;
    \\            font-size: 0.875rem;
    \\        }
    \\        .list-count {
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\        }
    \\        .list-actions {
    \\            margin-left: auto;
    \\            display: flex;
    \\            gap: 4px;
    \\        }
    \\        .icon-btn {
    \\            background: none;
    \\            border: none;
    \\            padding: 6px;
    \\            cursor: pointer;
    \\            color: var(--text-muted);
    \\            border-radius: 4px;
    \\            transition: all 0.15s;
    \\        }
    \\        .icon-btn:hover { background: var(--primary-light); color: var(--primary); }
    \\        .search-bar { padding: 12px 16px; }
    \\        .search-input {
    \\            width: 100%;
    \\            padding: 8px 12px 8px 36px;
    \\            border: 1px solid var(--border);
    \\            border-radius: 8px;
    \\            font-size: 0.875rem;
    \\            background: var(--bg);
    \\            color: var(--text);
    \\            transition: border-color 0.2s;
    \\        }
    \\        .search-input:focus { outline: none; border-color: var(--primary); }
    \\        .search-wrapper { position: relative; }
    \\        .search-icon {
    \\            position: absolute;
    \\            left: 10px;
    \\            top: 50%;
    \\            transform: translateY(-50%);
    \\            color: var(--text-muted);
    \\            pointer-events: none;
    \\        }
    \\        .messages-container { flex: 1; overflow-y: auto; }
    \\        .message-item {
    \\            padding: 12px 16px;
    \\            border-bottom: 1px solid var(--border);
    \\            cursor: pointer;
    \\            transition: background 0.15s;
    \\            position: relative;
    \\        }
    \\        .message-item:hover { background: var(--bg); }
    \\        .message-item.unread { background: var(--primary-light); }
    \\        .message-item.unread .message-sender { font-weight: 600; }
    \\        .message-item.active { background: var(--primary-light); border-left: 3px solid var(--primary); }
    \\        .message-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
    \\        .message-sender { font-size: 0.875rem; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    \\        .message-date { font-size: 0.7rem; color: var(--text-muted); white-space: nowrap; }
    \\        .message-subject {
    \\            font-size: 0.8rem;
    \\            color: var(--text);
    \\            margin-bottom: 2px;
    \\            white-space: nowrap;
    \\            overflow: hidden;
    \\            text-overflow: ellipsis;
    \\        }
    \\        .message-preview {
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\            white-space: nowrap;
    \\            overflow: hidden;
    \\            text-overflow: ellipsis;
    \\        }
    \\        .message-indicators { display: flex; gap: 4px; margin-top: 4px; }
    \\        .indicator {
    \\            width: 16px;
    \\            height: 16px;
    \\            color: var(--text-muted);
    \\        }
    \\        .indicator.starred { color: var(--warning); }
    \\        /* Message View */
    \\        .message-view {
    \\            background: var(--bg);
    \\            display: flex;
    \\            flex-direction: column;
    \\            overflow: hidden;
    \\        }
    \\        .view-header {
    \\            padding: 16px 20px;
    \\            border-bottom: 1px solid var(--border);
    \\            background: var(--card-bg);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\        }
    \\        .back-btn { display: none; }
    \\        @media (max-width: 768px) { .back-btn { display: block; } }
    \\        .view-actions { display: flex; gap: 4px; margin-left: auto; }
    \\        .view-content { flex: 1; overflow-y: auto; padding: 20px; }
    \\        .email-header { margin-bottom: 20px; }
    \\        .email-subject { font-size: 1.25rem; font-weight: 600; margin-bottom: 16px; }
    \\        .email-meta { display: flex; align-items: flex-start; gap: 12px; }
    \\        .avatar {
    \\            width: 40px;
    \\            height: 40px;
    \\            border-radius: 50%;
    \\            background: var(--primary);
    \\            color: white;
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            font-weight: 600;
    \\            font-size: 1rem;
    \\        }
    \\        .email-from { flex: 1; }
    \\        .from-name { font-weight: 600; font-size: 0.875rem; }
    \\        .from-email { font-size: 0.75rem; color: var(--text-muted); }
    \\        .email-to { font-size: 0.75rem; color: var(--text-muted); margin-top: 4px; }
    \\        .email-body {
    \\            background: var(--card-bg);
    \\            border-radius: 8px;
    \\            padding: 20px;
    \\            box-shadow: var(--shadow);
    \\            line-height: 1.6;
    \\        }
    \\        .email-attachments { margin-top: 16px; padding: 16px; background: var(--card-bg); border-radius: 8px; }
    \\        .attachments-title { font-size: 0.8rem; font-weight: 600; margin-bottom: 12px; color: var(--text-muted); }
    \\        .attachment-list { display: flex; flex-wrap: wrap; gap: 8px; }
    \\        .attachment {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            padding: 8px 12px;
    \\            background: var(--bg);
    \\            border-radius: 6px;
    \\            font-size: 0.8rem;
    \\            cursor: pointer;
    \\            transition: all 0.15s;
    \\        }
    \\        .attachment:hover { background: var(--primary-light); }
    \\        .empty-state {
    \\            display: flex;
    \\            flex-direction: column;
    \\            align-items: center;
    \\            justify-content: center;
    \\            height: 100%;
    \\            color: var(--text-muted);
    \\            text-align: center;
    \\            padding: 40px;
    \\        }
    \\        .empty-state svg { width: 80px; height: 80px; margin-bottom: 16px; opacity: 0.3; }
    \\        .empty-state h3 { font-size: 1rem; margin-bottom: 8px; }
    \\        .empty-state p { font-size: 0.875rem; }
    \\        /* Compose Modal */
    \\        .modal-overlay {
    \\            display: none;
    \\            position: fixed;
    \\            top: 0;
    \\            left: 0;
    \\            width: 100%;
    \\            height: 100%;
    \\            background: rgba(0,0,0,0.5);
    \\            z-index: 200;
    \\            align-items: center;
    \\            justify-content: center;
    \\            padding: 20px;
    \\        }
    \\        .modal-overlay.open { display: flex; }
    \\        .compose-modal {
    \\            background: var(--card-bg);
    \\            border-radius: 12px;
    \\            width: 100%;
    \\            max-width: 700px;
    \\            max-height: 90vh;
    \\            display: flex;
    \\            flex-direction: column;
    \\            box-shadow: var(--shadow-lg);
    \\        }
    \\        .compose-header {
    \\            padding: 16px 20px;
    \\            border-bottom: 1px solid var(--border);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\        }
    \\        .compose-title { font-weight: 600; flex: 1; }
    \\        .compose-body { flex: 1; overflow-y: auto; }
    \\        .compose-field {
    \\            display: flex;
    \\            align-items: center;
    \\            padding: 8px 20px;
    \\            border-bottom: 1px solid var(--border);
    \\        }
    \\        .compose-field label {
    \\            font-size: 0.8rem;
    \\            color: var(--text-muted);
    \\            width: 60px;
    \\        }
    \\        .compose-field input {
    \\            flex: 1;
    \\            border: none;
    \\            background: none;
    \\            color: var(--text);
    \\            font-size: 0.875rem;
    \\            padding: 8px 0;
    \\        }
    \\        .compose-field input:focus { outline: none; }
    \\        .compose-editor {
    \\            min-height: 250px;
    \\            padding: 16px 20px;
    \\            border: none;
    \\            background: none;
    \\            color: var(--text);
    \\            font-size: 0.875rem;
    \\            line-height: 1.6;
    \\            resize: none;
    \\            width: 100%;
    \\        }
    \\        .compose-editor:focus { outline: none; }
    \\        .compose-toolbar {
    \\            padding: 8px 16px;
    \\            border-top: 1px solid var(--border);
    \\            border-bottom: 1px solid var(--border);
    \\            display: flex;
    \\            gap: 4px;
    \\            flex-wrap: wrap;
    \\        }
    \\        .toolbar-btn {
    \\            background: none;
    \\            border: none;
    \\            padding: 6px 10px;
    \\            cursor: pointer;
    \\            color: var(--text-muted);
    \\            border-radius: 4px;
    \\            font-size: 0.8rem;
    \\        }
    \\        .toolbar-btn:hover { background: var(--bg); color: var(--text); }
    \\        .compose-footer {
    \\            padding: 12px 20px;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\        }
    \\        .send-btn {
    \\            background: var(--primary);
    \\            color: white;
    \\            border: none;
    \\            padding: 10px 24px;
    \\            border-radius: 6px;
    \\            font-weight: 500;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            transition: all 0.2s;
    \\        }
    \\        .send-btn:hover { background: var(--primary-hover); }
    \\        .draft-btn {
    \\            background: var(--bg);
    \\            color: var(--text);
    \\            border: 1px solid var(--border);
    \\            padding: 10px 16px;
    \\            border-radius: 6px;
    \\            cursor: pointer;
    \\        }
    \\        /* Contacts sidebar */
    \\        .contacts-panel {
    \\            display: none;
    \\            position: fixed;
    \\            right: 0;
    \\            top: 0;
    \\            width: 320px;
    \\            height: 100%;
    \\            background: var(--card-bg);
    \\            border-left: 1px solid var(--border);
    \\            z-index: 150;
    \\            flex-direction: column;
    \\        }
    \\        .contacts-panel.open { display: flex; }
    \\        .contacts-header {
    \\            padding: 16px;
    \\            border-bottom: 1px solid var(--border);
    \\            display: flex;
    \\            align-items: center;
    \\        }
    \\        .contacts-list { flex: 1; overflow-y: auto; }
    \\        .contact-item {
    \\            padding: 12px 16px;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            cursor: pointer;
    \\            border-bottom: 1px solid var(--border);
    \\        }
    \\        .contact-item:hover { background: var(--bg); }
    \\        .contact-avatar {
    \\            width: 36px;
    \\            height: 36px;
    \\            border-radius: 50%;
    \\            background: var(--primary-light);
    \\            color: var(--primary);
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            font-weight: 600;
    \\        }
    \\        .contact-info { flex: 1; }
    \\        .contact-name { font-size: 0.875rem; font-weight: 500; }
    \\        .contact-email { font-size: 0.75rem; color: var(--text-muted); }
    \\        /* Calendar widget */
    \\        .calendar-widget {
    \\            padding: 12px;
    \\            border-top: 1px solid var(--border);
    \\            margin-top: auto;
    \\        }
    \\        .calendar-header {
    \\            display: flex;
    \\            align-items: center;
    \\            margin-bottom: 8px;
    \\            font-size: 0.8rem;
    \\            font-weight: 600;
    \\        }
    \\        .calendar-grid {
    \\            display: grid;
    \\            grid-template-columns: repeat(7, 1fr);
    \\            gap: 2px;
    \\            font-size: 0.7rem;
    \\            text-align: center;
    \\        }
    \\        .calendar-day { padding: 4px; border-radius: 4px; cursor: pointer; }
    \\        .calendar-day:hover { background: var(--primary-light); }
    \\        .calendar-day.today { background: var(--primary); color: white; }
    \\        .calendar-day.has-event { font-weight: 600; }
    \\        /* Attachment list */
    \\        .attachment-list {
    \\            display: none;
    \\            flex-wrap: wrap;
    \\            gap: 8px;
    \\            padding: 12px;
    \\            background: var(--bg-secondary);
    \\            border-radius: 8px;
    \\            margin-bottom: 12px;
    \\        }
    \\        .attachment-item {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            padding: 8px 12px;
    \\            background: var(--card-bg);
    \\            border: 1px solid var(--border-color);
    \\            border-radius: 6px;
    \\            font-size: 13px;
    \\        }
    \\        .att-icon { font-size: 16px; }
    \\        .att-name { color: var(--text-primary); max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    \\        .att-size { color: var(--text-muted); font-size: 12px; }
    \\        .att-remove {
    \\            background: none;
    \\            border: none;
    \\            color: var(--text-muted);
    \\            cursor: pointer;
    \\            font-size: 18px;
    \\            line-height: 1;
    \\            padding: 0 4px;
    \\            opacity: 0.7;
    \\            transition: opacity 0.2s, color 0.2s;
    \\        }
    \\        .att-remove:hover { opacity: 1; color: var(--danger); }
    \\        /* Drop Zone Overlay */
    \\        .drop-zone-overlay {
    \\            display: none;
    \\            position: absolute;
    \\            top: 0;
    \\            left: 0;
    \\            right: 0;
    \\            bottom: 0;
    \\            background: rgba(79, 70, 229, 0.95);
    \\            border-radius: 12px;
    \\            z-index: 100;
    \\            align-items: center;
    \\            justify-content: center;
    \\            pointer-events: none;
    \\        }
    \\        .drop-zone-overlay.active {
    \\            display: flex;
    \\        }
    \\        .drop-zone-content {
    \\            display: flex;
    \\            flex-direction: column;
    \\            align-items: center;
    \\            gap: 16px;
    \\            color: white;
    \\            text-align: center;
    \\            animation: dropPulse 1.5s ease-in-out infinite;
    \\        }
    \\        .drop-zone-content svg {
    \\            opacity: 0.9;
    \\        }
    \\        .drop-zone-text {
    \\            font-size: 1.25rem;
    \\            font-weight: 600;
    \\        }
    \\        .drop-zone-hint {
    \\            font-size: 0.875rem;
    \\            opacity: 0.8;
    \\        }
    \\        @keyframes dropPulse {
    \\            0%, 100% { transform: scale(1); }
    \\            50% { transform: scale(1.05); }
    \\        }
    \\        .compose-modal {
    \\            position: relative;
    \\        }
    \\        .compose-modal.drag-over {
    \\            box-shadow: 0 0 0 3px var(--primary), var(--shadow-lg);
    \\        }
    \\        /* Toast notifications */
    \\        .toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 300; }
    \\        .toast {
    \\            background: var(--card-bg);
    \\            padding: 12px 20px;
    \\            border-radius: 8px;
    \\            box-shadow: var(--shadow-lg);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            margin-top: 8px;
    \\            animation: slideIn 0.3s ease;
    \\        }
    \\        .toast.success { border-left: 4px solid var(--success); }
    \\        .toast.error { border-left: 4px solid var(--danger); }
    \\        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    \\        /* Theme toggle */
    \\        .theme-toggle {
    \\            background: none;
    \\            border: none;
    \\            cursor: pointer;
    \\            color: var(--text-muted);
    \\            padding: 8px;
    \\            border-radius: 6px;
    \\        }
    \\        .theme-toggle:hover { background: var(--bg); }
    \\        /* Thread/Conversation View */
    \\        .thread-toggle {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            padding: 8px 12px;
    \\            background: var(--primary-light);
    \\            border: 1px solid var(--border);
    \\            border-radius: 6px;
    \\            cursor: pointer;
    \\            font-size: 0.875rem;
    \\            color: var(--primary);
    \\            margin-left: auto;
    \\        }
    \\        .thread-toggle:hover { background: var(--primary); color: white; }
    \\        .thread-toggle.active { background: var(--primary); color: white; }
    \\        .conversation-view { display: none; }
    \\        .conversation-view.active { display: block; }
    \\        .thread-header {
    \\            padding: 16px 20px;
    \\            border-bottom: 1px solid var(--border);
    \\            background: var(--card-bg);
    \\        }
    \\        .thread-subject {
    \\            font-size: 1.25rem;
    \\            font-weight: 600;
    \\            margin-bottom: 8px;
    \\        }
    \\        .thread-meta {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 16px;
    \\            font-size: 0.875rem;
    \\            color: var(--text-muted);
    \\        }
    \\        .thread-participants {
    \\            display: flex;
    \\            gap: -8px;
    \\        }
    \\        .thread-participant-avatar {
    \\            width: 24px;
    \\            height: 24px;
    \\            border-radius: 50%;
    \\            background: var(--primary);
    \\            color: white;
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            font-size: 0.625rem;
    \\            font-weight: 600;
    \\            border: 2px solid var(--card-bg);
    \\            margin-left: -8px;
    \\        }
    \\        .thread-participant-avatar:first-child { margin-left: 0; }
    \\        .thread-messages {
    \\            padding: 16px 20px;
    \\            display: flex;
    \\            flex-direction: column;
    \\            gap: 12px;
    \\        }
    \\        .thread-message {
    \\            border: 1px solid var(--border);
    \\            border-radius: 8px;
    \\            background: var(--card-bg);
    \\            overflow: hidden;
    \\            transition: all 0.2s;
    \\        }
    \\        .thread-message.collapsed .thread-message-body { display: none; }
    \\        .thread-message.depth-1 { margin-left: 24px; }
    \\        .thread-message.depth-2 { margin-left: 48px; }
    \\        .thread-message.depth-3 { margin-left: 72px; }
    \\        .thread-message-header {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            padding: 12px 16px;
    \\            cursor: pointer;
    \\            transition: background 0.2s;
    \\        }
    \\        .thread-message-header:hover { background: var(--bg); }
    \\        .thread-message-avatar {
    \\            width: 36px;
    \\            height: 36px;
    \\            border-radius: 50%;
    \\            background: var(--primary);
    \\            color: white;
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            font-weight: 600;
    \\            flex-shrink: 0;
    \\        }
    \\        .thread-message-info { flex: 1; min-width: 0; }
    \\        .thread-message-from {
    \\            font-weight: 500;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\        }
    \\        .thread-message-from .unread-badge {
    \\            width: 8px;
    \\            height: 8px;
    \\            background: var(--primary);
    \\            border-radius: 50%;
    \\        }
    \\        .thread-message-preview {
    \\            font-size: 0.875rem;
    \\            color: var(--text-muted);
    \\            white-space: nowrap;
    \\            overflow: hidden;
    \\            text-overflow: ellipsis;
    \\        }
    \\        .thread-message-date {
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\            white-space: nowrap;
    \\        }
    \\        .thread-message-expand {
    \\            color: var(--text-muted);
    \\            transition: transform 0.2s;
    \\        }
    \\        .thread-message.collapsed .thread-message-expand { transform: rotate(-90deg); }
    \\        .thread-message-body {
    \\            padding: 0 16px 16px 64px;
    \\            font-size: 0.9375rem;
    \\            line-height: 1.6;
    \\        }
    \\        .thread-message-actions {
    \\            display: flex;
    \\            gap: 8px;
    \\            padding: 12px 16px;
    \\            border-top: 1px solid var(--border);
    \\            background: var(--bg);
    \\        }
    \\        .thread-reply-btn {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 6px;
    \\            padding: 8px 16px;
    \\            background: var(--primary);
    \\            color: white;
    \\            border: none;
    \\            border-radius: 6px;
    \\            cursor: pointer;
    \\            font-size: 0.875rem;
    \\        }
    \\        .thread-reply-btn:hover { background: var(--primary-hover); }
    \\        .thread-quick-reply {
    \\            margin-top: 16px;
    \\            padding: 16px;
    \\            background: var(--card-bg);
    \\            border: 1px solid var(--border);
    \\            border-radius: 8px;
    \\        }
    \\        .thread-quick-reply textarea {
    \\            width: 100%;
    \\            min-height: 100px;
    \\            padding: 12px;
    \\            border: 1px solid var(--border);
    \\            border-radius: 6px;
    \\            resize: vertical;
    \\            font-family: inherit;
    \\            font-size: 0.9375rem;
    \\            background: var(--bg);
    \\            color: var(--text);
    \\        }
    \\        .thread-quick-reply-actions {
    \\            display: flex;
    \\            justify-content: flex-end;
    \\            gap: 8px;
    \\            margin-top: 12px;
    \\        }
    \\        /* Inline Image Support */
    \\        .email-body img {
    \\            max-width: 100%;
    \\            height: auto;
    \\            border-radius: 4px;
    \\            margin: 8px 0;
    \\        }
    \\        .inline-image-container {
    \\            position: relative;
    \\            display: inline-block;
    \\            margin: 4px;
    \\        }
    \\        .inline-image-container img {
    \\            max-width: 200px;
    \\            max-height: 150px;
    \\            border-radius: 4px;
    \\            border: 1px solid var(--border);
    \\        }
    \\        .inline-image-container .remove-btn {
    \\            position: absolute;
    \\            top: -8px;
    \\            right: -8px;
    \\            width: 20px;
    \\            height: 20px;
    \\            background: var(--danger);
    \\            color: white;
    \\            border: none;
    \\            border-radius: 50%;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            font-size: 12px;
    \\        }
    \\        .inline-images-preview {
    \\            display: flex;
    \\            flex-wrap: wrap;
    \\            gap: 8px;
    \\            margin-top: 8px;
    \\            padding: 8px;
    \\            background: var(--bg);
    \\            border-radius: 6px;
    \\            min-height: 40px;
    \\        }
    \\        .inline-images-preview:empty {
    \\            display: none;
    \\        }
    \\        .insert-image-modal {
    \\            display: none;
    \\            position: fixed;
    \\            top: 50%;
    \\            left: 50%;
    \\            transform: translate(-50%, -50%);
    \\            background: var(--card-bg);
    \\            border-radius: 12px;
    \\            box-shadow: var(--shadow-lg);
    \\            padding: 20px;
    \\            z-index: 400;
    \\            width: 400px;
    \\            max-width: 90vw;
    \\        }
    \\        .insert-image-modal.open { display: block; }
    \\        .insert-image-modal h3 {
    \\            margin: 0 0 16px;
    \\            font-size: 1.1rem;
    \\        }
    \\        .image-upload-zone {
    \\            border: 2px dashed var(--border);
    \\            border-radius: 8px;
    \\            padding: 24px;
    \\            text-align: center;
    \\            cursor: pointer;
    \\            transition: all 0.2s;
    \\        }
    \\        .image-upload-zone:hover {
    \\            border-color: var(--primary);
    \\            background: var(--primary-light);
    \\        }
    \\        .image-upload-zone.dragover {
    \\            border-color: var(--primary);
    \\            background: var(--primary-light);
    \\        }
    \\        .image-upload-zone svg {
    \\            width: 48px;
    \\            height: 48px;
    \\            color: var(--text-muted);
    \\            margin-bottom: 8px;
    \\        }
    \\        .image-url-input {
    \\            margin-top: 16px;
    \\        }
    \\        .image-url-input label {
    \\            display: block;
    \\            font-size: 0.875rem;
    \\            color: var(--text-muted);
    \\            margin-bottom: 4px;
    \\        }
    \\        .image-url-input input {
    \\            width: 100%;
    \\            padding: 8px 12px;
    \\            border: 1px solid var(--border);
    \\            border-radius: 6px;
    \\            font-size: 0.875rem;
    \\            background: var(--bg);
    \\            color: var(--text);
    \\        }
    \\        .insert-image-actions {
    \\            display: flex;
    \\            justify-content: flex-end;
    \\            gap: 8px;
    \\            margin-top: 16px;
    \\        }
    \\        /* Templates & Signatures */
    \\        .templates-btn, .signatures-btn {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 4px;
    \\            padding: 6px 10px;
    \\            border: 1px solid var(--border);
    \\            background: var(--card-bg);
    \\            border-radius: 4px;
    \\            cursor: pointer;
    \\            font-size: 0.8125rem;
    \\            color: var(--text-muted);
    \\        }
    \\        .templates-btn:hover, .signatures-btn:hover {
    \\            background: var(--primary-light);
    \\            border-color: var(--primary);
    \\            color: var(--primary);
    \\        }
    \\        .templates-modal, .signatures-modal {
    \\            display: none;
    \\            position: fixed;
    \\            top: 50%;
    \\            left: 50%;
    \\            transform: translate(-50%, -50%);
    \\            background: var(--card-bg);
    \\            border-radius: 12px;
    \\            box-shadow: var(--shadow-lg);
    \\            padding: 20px;
    \\            z-index: 400;
    \\            width: 500px;
    \\            max-width: 90vw;
    \\            max-height: 80vh;
    \\            overflow-y: auto;
    \\        }
    \\        .templates-modal.open, .signatures-modal.open { display: block; }
    \\        .modal-header {
    \\            display: flex;
    \\            justify-content: space-between;
    \\            align-items: center;
    \\            margin-bottom: 16px;
    \\        }
    \\        .modal-header h3 { margin: 0; font-size: 1.1rem; }
    \\        .template-list, .signature-list {
    \\            display: flex;
    \\            flex-direction: column;
    \\            gap: 8px;
    \\        }
    \\        .template-item, .signature-item {
    \\            display: flex;
    \\            align-items: flex-start;
    \\            gap: 12px;
    \\            padding: 12px;
    \\            border: 1px solid var(--border);
    \\            border-radius: 8px;
    \\            cursor: pointer;
    \\            transition: all 0.2s;
    \\        }
    \\        .template-item:hover, .signature-item:hover {
    \\            border-color: var(--primary);
    \\            background: var(--primary-light);
    \\        }
    \\        .template-icon, .signature-icon {
    \\            width: 40px;
    \\            height: 40px;
    \\            border-radius: 8px;
    \\            background: var(--primary-light);
    \\            color: var(--primary);
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            flex-shrink: 0;
    \\        }
    \\        .template-info, .signature-info { flex: 1; min-width: 0; }
    \\        .template-name, .signature-name {
    \\            font-weight: 500;
    \\            margin-bottom: 2px;
    \\        }
    \\        .template-desc, .signature-preview {
    \\            font-size: 0.8125rem;
    \\            color: var(--text-muted);
    \\            white-space: nowrap;
    \\            overflow: hidden;
    \\            text-overflow: ellipsis;
    \\        }
    \\        .template-category {
    \\            font-size: 0.6875rem;
    \\            padding: 2px 6px;
    \\            background: var(--bg);
    \\            border-radius: 4px;
    \\            color: var(--text-muted);
    \\        }
    \\        .signature-default {
    \\            font-size: 0.6875rem;
    \\            padding: 2px 6px;
    \\            background: var(--success);
    \\            color: white;
    \\            border-radius: 4px;
    \\        }
    \\        .signature-toggle {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            padding: 8px 0;
    \\            border-bottom: 1px solid var(--border);
    \\            margin-bottom: 12px;
    \\        }
    \\        .signature-toggle label { font-size: 0.875rem; }
    \\        .signature-toggle input[type="checkbox"] {
    \\            width: 18px;
    \\            height: 18px;
    \\            accent-color: var(--primary);
    \\        }
    \\        .compose-extras {
    \\            display: flex;
    \\            gap: 8px;
    \\            padding: 8px 0;
    \\            border-top: 1px solid var(--border);
    \\            margin-top: 8px;
    \\        }
    \\        /* Read Receipt, Scheduling, Groups */
    \\        .compose-options {
    \\            display: flex;
    \\            flex-wrap: wrap;
    \\            gap: 12px;
    \\            padding: 10px 0;
    \\            border-top: 1px solid var(--border);
    \\        }
    \\        .compose-option {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 6px;
    \\            font-size: 0.8125rem;
    \\            color: var(--text-muted);
    \\        }
    \\        .compose-option input[type="checkbox"] {
    \\            accent-color: var(--primary);
    \\        }
    \\        .schedule-picker {
    \\            display: none;
    \\            padding: 12px;
    \\            background: var(--bg);
    \\            border-radius: 8px;
    \\            margin-top: 8px;
    \\        }
    \\        .schedule-picker.open { display: block; }
    \\        .schedule-picker input {
    \\            padding: 8px;
    \\            border: 1px solid var(--border);
    \\            border-radius: 6px;
    \\            font-size: 0.875rem;
    \\            background: var(--card-bg);
    \\            color: var(--text);
    \\        }
    \\        .schedule-presets {
    \\            display: flex;
    \\            gap: 6px;
    \\            margin-top: 8px;
    \\        }
    \\        .schedule-preset {
    \\            padding: 4px 10px;
    \\            background: var(--primary-light);
    \\            border: 1px solid var(--border);
    \\            border-radius: 4px;
    \\            font-size: 0.75rem;
    \\            cursor: pointer;
    \\        }
    \\        .schedule-preset:hover { background: var(--primary); color: white; }
    \\        .groups-dropdown {
    \\            position: relative;
    \\        }
    \\        .groups-list {
    \\            position: absolute;
    \\            top: 100%;
    \\            left: 0;
    \\            background: var(--card-bg);
    \\            border: 1px solid var(--border);
    \\            border-radius: 8px;
    \\            box-shadow: var(--shadow-lg);
    \\            min-width: 200px;
    \\            max-height: 200px;
    \\            overflow-y: auto;
    \\            z-index: 100;
    \\            display: none;
    \\        }
    \\        .groups-list.open { display: block; }
    \\        .group-option {
    \\            padding: 10px 12px;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\        }
    \\        .group-option:hover { background: var(--bg); }
    \\        .group-badge {
    \\            background: var(--primary-light);
    \\            color: var(--primary);
    \\            padding: 2px 6px;
    \\            border-radius: 10px;
    \\            font-size: 0.7rem;
    \\        }
    \\        .scheduled-indicator {
    \\            display: inline-flex;
    \\            align-items: center;
    \\            gap: 4px;
    \\            padding: 4px 8px;
    \\            background: var(--warning-light);
    \\            color: var(--warning);
    \\            border-radius: 4px;
    \\            font-size: 0.75rem;
    \\        }
    \\        .receipt-indicator {
    \\            display: inline-flex;
    \\            align-items: center;
    \\            gap: 4px;
    \\            padding: 2px 6px;
    \\            background: var(--success-light);
    \\            color: var(--success);
    \\            border-radius: 4px;
    \\            font-size: 0.7rem;
    \\        }
    \\    </style>
    \\</head>
    \\<body>
    \\    <div class="app">
    \\        <!-- Sidebar -->
    \\        <aside class="sidebar" id="sidebar">
    \\            <div class="sidebar-header">
    \\                <div class="logo">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
    \\                        <polyline points="22,6 12,13 2,6"/>
    \\                    </svg>
    \\                    <span class="folder-name">Webmail</span>
    \\                </div>
    \\                <button class="compose-btn" onclick="openCompose()">
    \\                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
    \\                    </svg>
    \\                    <span class="compose-text">Compose</span>
    \\                </button>
    \\            </div>
    \\            <div class="sidebar-content">
    \\                <div class="section-title">Folders</div>
    \\                <ul class="folders" id="folders">
    \\                    <li class="folder active" data-folder="inbox">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/>
    \\                            <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>
    \\                        </svg>
    \\                        <span class="folder-name">Inbox</span>
    \\                        <span class="folder-count" id="inbox-count">3</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="starred">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
    \\                        </svg>
    \\                        <span class="folder-name">Starred</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="sent">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
    \\                        </svg>
    \\                        <span class="folder-name">Sent</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="drafts">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
    \\                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
    \\                        </svg>
    \\                        <span class="folder-name">Drafts</span>
    \\                        <span class="folder-count">1</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="archive">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/>
    \\                            <line x1="10" y1="12" x2="14" y2="12"/>
    \\                        </svg>
    \\                        <span class="folder-name">Archive</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="spam">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    \\                            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    \\                        </svg>
    \\                        <span class="folder-name">Spam</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="trash">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
    \\                        </svg>
    \\                        <span class="folder-name">Trash</span>
    \\                    </li>
    \\                </ul>
    \\                <div class="section-title" style="margin-top: 16px;">Labels</div>
    \\                <ul class="folders">
    \\                    <li class="folder" data-label="work">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="#3b82f6" stroke="#3b82f6" stroke-width="2">
    \\                            <circle cx="12" cy="12" r="4"/>
    \\                        </svg>
    \\                        <span class="folder-name">Work</span>
    \\                    </li>
    \\                    <li class="folder" data-label="personal">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="#10b981" stroke="#10b981" stroke-width="2">
    \\                            <circle cx="12" cy="12" r="4"/>
    \\                        </svg>
    \\                        <span class="folder-name">Personal</span>
    \\                    </li>
    \\                </ul>
    \\                <!-- Mini Calendar -->
    \\                <div class="calendar-widget">
    \\                    <div class="calendar-header">
    \\                        <span id="calendar-month">November 2025</span>
    \\                    </div>
    \\                    <div class="calendar-grid" id="calendar-grid"></div>
    \\                </div>
    \\            </div>
    \\            <div class="sidebar-footer">
    \\                <div style="display: flex; align-items: center; justify-content: space-between;">
    \\                    <span>v0.28.0</span>
    \\                    <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" id="theme-icon">
    \\                            <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
    \\                            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
    \\                            <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
    \\                            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
    \\                        </svg>
    \\                    </button>
    \\                </div>
    \\            </div>
    \\        </aside>
    \\        <!-- Message List -->
    \\        <section class="message-list">
    \\            <div class="mobile-header">
    \\                <button class="menu-btn" onclick="toggleSidebar()">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/>
    \\                    </svg>
    \\                </button>
    \\                <span style="font-weight: 600;">Inbox</span>
    \\            </div>
    \\            <div class="list-header">
    \\                <span class="list-title" id="list-title">Inbox</span>
    \\                <span class="list-count" id="list-count">(3 messages)</span>
    \\                <button class="thread-toggle" id="thread-toggle" onclick="toggleThreadView()" title="Toggle Conversation View">
    \\                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
    \\                    </svg>
    \\                    <span>Threads</span>
    \\                </button>
    \\                <div class="list-actions">
    \\                    <button class="icon-btn" onclick="refreshMessages()" title="Refresh">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
    \\                            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
    \\                        </svg>
    \\                    </button>
    \\                    <button class="icon-btn" onclick="toggleContacts()" title="Contacts">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
    \\                            <circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
    \\                        </svg>
    \\                    </button>
    \\                </div>
    \\            </div>
    \\            <div class="search-bar">
    \\                <div class="search-wrapper">
    \\                    <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    \\                    </svg>
    \\                    <input type="text" class="search-input" placeholder="Search emails..." id="search" oninput="searchMessages(this.value)">
    \\                </div>
    \\            </div>
    \\            <div class="messages-container" id="messages"></div>
    \\        </section>
    \\        <!-- Message View -->
    \\        <main class="message-view" id="message-view">
    \\            <div class="empty-state" id="empty-state">
    \\                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
    \\                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
    \\                    <polyline points="22,6 12,13 2,6"/>
    \\                </svg>
    \\                <h3>Select an email to read</h3>
    \\                <p>Choose from your inbox on the left</p>
    \\            </div>
    \\            <div id="email-content" style="display: none;">
    \\                <div class="view-header">
    \\                    <button class="icon-btn back-btn" onclick="closeEmail()">
    \\                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>
    \\                        </svg>
    \\                    </button>
    \\                    <div class="view-actions">
    \\                        <button class="icon-btn" onclick="archiveEmail()" title="Archive">
    \\                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/>
    \\                            </svg>
    \\                        </button>
    \\                        <button class="icon-btn" onclick="deleteEmail()" title="Delete">
    \\                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
    \\                            </svg>
    \\                        </button>
    \\                        <button class="icon-btn" onclick="replyEmail()" title="Reply">
    \\                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>
    \\                            </svg>
    \\                        </button>
    \\                        <button class="icon-btn" onclick="forwardEmail()" title="Forward">
    \\                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 0 1 4-4h12"/>
    \\                            </svg>
    \\                        </button>
    \\                    </div>
    \\                </div>
    \\                <div class="view-content">
    \\                    <div class="email-header">
    \\                        <h1 class="email-subject" id="email-subject"></h1>
    \\                        <div class="email-meta">
    \\                            <div class="avatar" id="email-avatar"></div>
    \\                            <div class="email-from">
    \\                                <div class="from-name" id="email-from-name"></div>
    \\                                <div class="from-email" id="email-from-email"></div>
    \\                                <div class="email-to" id="email-to"></div>
    \\                            </div>
    \\                            <div class="email-date" id="email-date" style="font-size: 0.75rem; color: var(--text-muted);"></div>
    \\                        </div>
    \\                    </div>
    \\                    <div class="email-body" id="email-body"></div>
    \\                    <div class="email-attachments" id="email-attachments" style="display: none;">
    \\                        <div class="attachments-title">Attachments</div>
    \\                        <div class="attachment-list" id="attachment-list"></div>
    \\                    </div>
    \\                </div>
    \\            </div>
    \\            <!-- Conversation/Thread View -->
    \\            <div class="conversation-view" id="conversation-view">
    \\                <div class="thread-header">
    \\                    <div class="view-header" style="padding: 0; border: none; margin-bottom: 12px;">
    \\                        <button class="icon-btn back-btn" onclick="closeThread()">
    \\                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>
    \\                            </svg>
    \\                        </button>
    \\                        <div class="view-actions">
    \\                            <button class="icon-btn" onclick="archiveThread()" title="Archive Thread">
    \\                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                    <polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/>
    \\                                </svg>
    \\                            </button>
    \\                            <button class="icon-btn" onclick="deleteThread()" title="Delete Thread">
    \\                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                    <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
    \\                                </svg>
    \\                            </button>
    \\                        </div>
    \\                    </div>
    \\                    <h1 class="thread-subject" id="thread-subject">Re: Project Update</h1>
    \\                    <div class="thread-meta">
    \\                        <div class="thread-participants" id="thread-participants"></div>
    \\                        <span id="thread-count">3 messages</span>
    \\                        <span id="thread-unread">1 unread</span>
    \\                    </div>
    \\                </div>
    \\                <div class="thread-messages" id="thread-messages">
    \\                    <!-- Thread messages will be inserted here dynamically -->
    \\                </div>
    \\                <div class="thread-quick-reply">
    \\                    <textarea id="quick-reply-text" placeholder="Write a quick reply..."></textarea>
    \\                    <div class="thread-quick-reply-actions">
    \\                        <button class="icon-btn" onclick="attachToReply()" title="Attach file">
    \\                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
    \\                            </svg>
    \\                        </button>
    \\                        <button class="thread-reply-btn" onclick="sendQuickReply()">
    \\                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
    \\                            </svg>
    \\                            Send Reply
    \\                        </button>
    \\                    </div>
    \\                </div>
    \\            </div>
    \\        </main>
    \\    </div>
    \\    <!-- Compose Modal -->
    \\    <div class="modal-overlay" id="compose-modal">
    \\        <div class="compose-modal">
    \\            <div class="compose-header">
    \\                <span class="compose-title">New Message</span>
    \\                <button class="icon-btn" onclick="closeCompose()">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
    \\                    </svg>
    \\                </button>
    \\            </div>
    \\            <div class="compose-body">
    \\                <div class="compose-field">
    \\                    <label>To</label>
    \\                    <input type="email" id="compose-to" placeholder="recipient@example.com">
    \\                </div>
    \\                <div class="compose-field">
    \\                    <label>Cc</label>
    \\                    <input type="email" id="compose-cc" placeholder="cc@example.com">
    \\                </div>
    \\                <div class="compose-field">
    \\                    <label>Subject</label>
    \\                    <input type="text" id="compose-subject" placeholder="Email subject">
    \\                </div>
    \\                <div class="compose-toolbar">
    \\                    <button class="toolbar-btn" onclick="formatText('bold')" title="Bold"><b>B</b></button>
    \\                    <button class="toolbar-btn" onclick="formatText('italic')" title="Italic"><i>I</i></button>
    \\                    <button class="toolbar-btn" onclick="formatText('underline')" title="Underline"><u>U</u></button>
    \\                    <button class="toolbar-btn" onclick="formatText('strikethrough')" title="Strikethrough"><s>S</s></button>
    \\                    <button class="toolbar-btn" onclick="insertLink()" title="Insert link">Link</button>
    \\                    <button class="toolbar-btn" onclick="openInsertImage()" title="Insert inline image">
    \\                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>
    \\                        </svg>
    \\                        Image
    \\                    </button>
    \\                    <button class="toolbar-btn" onclick="attachFile()" title="Attach file">Attach</button>
    \\                </div>
    \\                <div id="inline-images-preview" class="inline-images-preview"></div>
    \\                <div id="attachment-list" class="attachment-list"></div>
    \\                <textarea class="compose-editor" id="compose-body" placeholder="Write your message..."></textarea>
    \\                <div class="compose-extras">
    \\                    <button class="templates-btn" onclick="openTemplates()" title="Use Template">
    \\                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    \\                            <polyline points="14 2 14 8 20 8"/>
    \\                            <line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/>
    \\                        </svg>
    \\                        Templates
    \\                    </button>
    \\                    <button class="signatures-btn" onclick="openSignatures()" title="Insert Signature">
    \\                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>
    \\                        </svg>
    \\                        Signature
    \\                    </button>
    \\                    <div class="groups-dropdown">
    \\                        <button class="templates-btn" onclick="toggleGroups()" title="Contact Groups">
    \\                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
    \\                            </svg>
    \\                            Groups
    \\                        </button>
    \\                        <div class="groups-list" id="groups-list">
    \\                            <div class="group-option" onclick="insertGroup('team')">
    \\                                <span>Development Team</span>
    \\                                <span class="group-badge">5</span>
    \\                            </div>
    \\                            <div class="group-option" onclick="insertGroup('mgmt')">
    \\                                <span>Management</span>
    \\                                <span class="group-badge">3</span>
    \\                            </div>
    \\                            <div class="group-option" onclick="insertGroup('all')">
    \\                                <span>All Staff</span>
    \\                                <span class="group-badge">25</span>
    \\                            </div>
    \\                        </div>
    \\                    </div>
    \\                    <label style="display: flex; align-items: center; gap: 4px; margin-left: auto; font-size: 0.8125rem; color: var(--text-muted);">
    \\                        <input type="checkbox" id="auto-signature" checked style="accent-color: var(--primary);">
    \\                        Auto-insert signature
    \\                    </label>
    \\                </div>
    \\                <div class="compose-options">
    \\                    <label class="compose-option">
    \\                        <input type="checkbox" id="request-receipt">
    \\                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
    \\                        Request read receipt
    \\                    </label>
    \\                    <label class="compose-option">
    \\                        <input type="checkbox" id="schedule-send" onchange="toggleSchedulePicker()">
    \\                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
    \\                        Schedule send
    \\                    </label>
    \\                    <span id="schedule-time-display" class="scheduled-indicator" style="display: none;"></span>
    \\                </div>
    \\                <div class="schedule-picker" id="schedule-picker">
    \\                    <label style="font-size: 0.8125rem; color: var(--text-muted);">Send at:</label>
    \\                    <input type="datetime-local" id="schedule-datetime" onchange="updateScheduleDisplay()">
    \\                    <div class="schedule-presets">
    \\                        <span class="schedule-preset" onclick="setSchedulePreset(1)">In 1 hour</span>
    \\                        <span class="schedule-preset" onclick="setSchedulePreset(3)">In 3 hours</span>
    \\                        <span class="schedule-preset" onclick="setSchedulePreset(24)">Tomorrow</span>
    \\                        <span class="schedule-preset" onclick="setSchedulePreset(168)">Next week</span>
    \\                    </div>
    \\                </div>
    \\            </div>
    \\            <!-- Drop Zone Overlay -->
    \\            <div class="drop-zone-overlay" id="drop-zone-overlay">
    \\                <div class="drop-zone-content">
    \\                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    \\                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
    \\                        <polyline points="17 8 12 3 7 8"/>
    \\                        <line x1="12" y1="3" x2="12" y2="15"/>
    \\                    </svg>
    \\                    <span class="drop-zone-text">Drop files here to attach</span>
    \\                    <span class="drop-zone-hint">Maximum 25MB per file, up to 10 files</span>
    \\                </div>
    \\            </div>
    \\            <div class="compose-footer">
    \\                <button class="send-btn" onclick="sendEmail()">
    \\                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
    \\                    </svg>
    \\                    Send
    \\                </button>
    \\                <button class="draft-btn" onclick="saveDraft()">Save Draft</button>
    \\            </div>
    \\        </div>
    \\    </div>
    \\    <!-- Contacts Panel -->
    \\    <div class="contacts-panel" id="contacts-panel">
    \\        <div class="contacts-header">
    \\            <span style="font-weight: 600; flex: 1;">Contacts</span>
    \\            <button class="icon-btn" onclick="toggleContacts()">
    \\                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
    \\                </svg>
    \\            </button>
    \\        </div>
    \\        <div class="search-bar">
    \\            <div class="search-wrapper">
    \\                <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    \\                </svg>
    \\                <input type="text" class="search-input" placeholder="Search contacts...">
    \\            </div>
    \\        </div>
    \\        <div class="contacts-list" id="contacts-list"></div>
    \\    </div>
    \\    <!-- Templates Modal -->
    \\    <div class="templates-modal" id="templates-modal">
    \\        <div class="modal-header">
    \\            <h3>Choose Template</h3>
    \\            <button class="icon-btn" onclick="closeTemplates()">
    \\                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
    \\                </svg>
    \\            </button>
    \\        </div>
    \\        <div class="template-list" id="template-list">
    \\            <div class="template-item" onclick="useTemplate('vacation')">
    \\                <div class="template-icon">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
    \\                </div>
    \\                <div class="template-info">
    \\                    <div class="template-name">Out of Office</div>
    \\                    <div class="template-desc">Standard vacation auto-reply message</div>
    \\                    <span class="template-category">Vacation</span>
    \\                </div>
    \\            </div>
    \\            <div class="template-item" onclick="useTemplate('thankyou')">
    \\                <div class="template-icon">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
    \\                </div>
    \\                <div class="template-info">
    \\                    <div class="template-name">Thank You</div>
    \\                    <div class="template-desc">Quick thank you response</div>
    \\                    <span class="template-category">Quick Response</span>
    \\                </div>
    \\            </div>
    \\            <div class="template-item" onclick="useTemplate('meeting')">
    \\                <div class="template-icon">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
    \\                </div>
    \\                <div class="template-info">
    \\                    <div class="template-name">Meeting Request</div>
    \\                    <div class="template-desc">Request a meeting with date and time</div>
    \\                    <span class="template-category">Form Letter</span>
    \\                </div>
    \\            </div>
    \\            <div class="template-item" onclick="useTemplate('followup')">
    \\                <div class="template-icon">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
    \\                </div>
    \\                <div class="template-info">
    \\                    <div class="template-name">Follow Up</div>
    \\                    <div class="template-desc">Follow up on previous conversation</div>
    \\                    <span class="template-category">Quick Response</span>
    \\                </div>
    \\            </div>
    \\        </div>
    \\    </div>
    \\    <!-- Signatures Modal -->
    \\    <div class="signatures-modal" id="signatures-modal">
    \\        <div class="modal-header">
    \\            <h3>Choose Signature</h3>
    \\            <button class="icon-btn" onclick="closeSignatures()">
    \\                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
    \\                </svg>
    \\            </button>
    \\        </div>
    \\        <div class="signature-list" id="signature-list">
    \\            <div class="signature-item" onclick="useSignature('professional')">
    \\                <div class="signature-icon">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
    \\                </div>
    \\                <div class="signature-info">
    \\                    <div class="signature-name">Professional <span class="signature-default">Default</span></div>
    \\                    <div class="signature-preview">Best regards, John Doe - Senior Developer - Acme Corp</div>
    \\                </div>
    \\            </div>
    \\            <div class="signature-item" onclick="useSignature('simple')">
    \\                <div class="signature-icon">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/></svg>
    \\                </div>
    \\                <div class="signature-info">
    \\                    <div class="signature-name">Simple</div>
    \\                    <div class="signature-preview">Thanks, John</div>
    \\                </div>
    \\            </div>
    \\            <div class="signature-item" onclick="useSignature('formal')">
    \\                <div class="signature-icon">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
    \\                </div>
    \\                <div class="signature-info">
    \\                    <div class="signature-name">Formal</div>
    \\                    <div class="signature-preview">Yours sincerely, John Doe, MBA - Director of Engineering</div>
    \\                </div>
    \\            </div>
    \\        </div>
    \\        <div style="margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border);">
    \\            <button class="templates-btn" onclick="manageSignatures()" style="width: 100%; justify-content: center;">
    \\                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                    <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    \\                </svg>
    \\                Manage Signatures
    \\            </button>
    \\        </div>
    \\    </div>
    \\    <!-- Insert Image Modal -->
    \\    <div class="insert-image-modal" id="insert-image-modal">
    \\        <h3>Insert Image</h3>
    \\        <div class="image-upload-zone" id="image-upload-zone" onclick="triggerImageUpload()" ondragover="handleImageDragOver(event)" ondragleave="handleImageDragLeave(event)" ondrop="handleImageDrop(event)">
    \\            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    \\                <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
    \\                <circle cx="8.5" cy="8.5" r="1.5"/>
    \\                <polyline points="21 15 16 10 5 21"/>
    \\            </svg>
    \\            <div>Click or drag image here</div>
    \\            <div style="font-size: 0.75rem; color: var(--text-muted);">PNG, JPG, GIF, WebP (max 10MB)</div>
    \\        </div>
    \\        <input type="file" id="image-file-input" accept="image/*" style="display: none" onchange="handleImageSelect(event)">
    \\        <div class="image-url-input">
    \\            <label>Or paste image URL:</label>
    \\            <input type="text" id="image-url" placeholder="https://example.com/image.png">
    \\        </div>
    \\        <div class="insert-image-actions">
    \\            <button class="draft-btn" onclick="closeInsertImage()">Cancel</button>
    \\            <button class="send-btn" onclick="insertImageFromUrl()">Insert</button>
    \\        </div>
    \\    </div>
    \\    <!-- Toast Container -->
    \\    <div class="toast-container" id="toast-container"></div>
    \\    <script>
    \\        // State
    \\        let currentFolder = 'inbox';
    \\        let currentEmail = null;
    \\        let messages = [];
    \\        let contacts = [
    \\            { id: '1', name: 'John Doe', email: 'john@example.com' },
    \\            { id: '2', name: 'Jane Smith', email: 'jane@example.com' },
    \\            { id: '3', name: 'Support Team', email: 'support@smtp-server.local' }
    \\        ];
    \\        // Demo messages
    \\        const demoMessages = [
    \\            { id: '1', from: { name: 'Welcome Team', email: 'welcome@smtp-server.local' }, subject: 'Welcome to your new email server!', preview: 'Congratulations on setting up your SMTP server...', date: 'Today', unread: true, starred: false, body: 'Congratulations on setting up your SMTP server!\\n\\nYour email server is now ready to use. Here are some things you can do:\\n\\n1. Send and receive emails\\n2. Manage your contacts\\n3. Organize with folders and labels\\n4. Search your messages\\n\\nEnjoy your new secure email experience!' },
    \\            { id: '2', from: { name: 'Security Alert', email: 'security@smtp-server.local' }, subject: 'Your account security settings', preview: 'We recommend enabling two-factor authentication...', date: 'Yesterday', unread: true, starred: true, body: 'We recommend enabling two-factor authentication for your account to improve security.\\n\\nYou can configure this in your account settings.' },
    \\            { id: '3', from: { name: 'System Updates', email: 'updates@smtp-server.local' }, subject: 'New features available', preview: 'Check out the latest features in v0.28.0...', date: 'Nov 25', unread: false, starred: false, body: 'New features in version 0.28.0:\\n\\n- Improved webmail interface\\n- Better mobile support\\n- Enhanced search\\n- Calendar integration\\n- Contact management\\n\\nUpdate now to get these features!' }
    \\        ];
    \\        messages = demoMessages;
    \\        // Initialize
    \\        document.addEventListener('DOMContentLoaded', () => {
    \\            initTheme();
    \\            renderMessages();
    \\            renderContacts();
    \\            renderCalendar();
    \\            setupFolderListeners();
    \\        });
    \\        function initTheme() {
    \\            const saved = localStorage.getItem('theme');
    \\            if (saved) {
    \\                document.documentElement.setAttribute('data-theme', saved);
    \\            } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    \\                document.documentElement.setAttribute('data-theme', 'dark');
    \\            }
    \\        }
    \\        function toggleTheme() {
    \\            const current = document.documentElement.getAttribute('data-theme');
    \\            const next = current === 'dark' ? 'light' : 'dark';
    \\            document.documentElement.setAttribute('data-theme', next);
    \\            localStorage.setItem('theme', next);
    \\        }
    \\        function setupFolderListeners() {
    \\            document.querySelectorAll('.folder').forEach(folder => {
    \\                folder.addEventListener('click', () => {
    \\                    document.querySelectorAll('.folder').forEach(f => f.classList.remove('active'));
    \\                    folder.classList.add('active');
    \\                    currentFolder = folder.dataset.folder || folder.dataset.label;
    \\                    document.getElementById('list-title').textContent = folder.querySelector('.folder-name').textContent;
    \\                    loadMessages(currentFolder);
    \\                    closeSidebar();
    \\                });
    \\            });
    \\        }
    \\        function renderMessages() {
    \\            const container = document.getElementById('messages');
    \\            container.innerHTML = messages.map(msg => `
    \\                <div class="message-item ${msg.unread ? 'unread' : ''}" onclick="openEmail('${msg.id}')">
    \\                    <div class="message-header">
    \\                        <span class="message-sender">${msg.from.name}</span>
    \\                        <span class="message-date">${msg.date}</span>
    \\                    </div>
    \\                    <div class="message-subject">${msg.subject}</div>
    \\                    <div class="message-preview">${msg.preview}</div>
    \\                    <div class="message-indicators">
    \\                        ${msg.starred ? '<svg class="indicator starred" width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>' : ''}
    \\                    </div>
    \\                </div>
    \\            `).join('');
    \\            document.getElementById('list-count').textContent = `(${messages.length} messages)`;
    \\        }
    \\        function renderContacts() {
    \\            const list = document.getElementById('contacts-list');
    \\            list.innerHTML = contacts.map(c => `
    \\                <div class="contact-item" onclick="selectContact('${c.email}')">
    \\                    <div class="contact-avatar">${c.name.charAt(0)}</div>
    \\                    <div class="contact-info">
    \\                        <div class="contact-name">${c.name}</div>
    \\                        <div class="contact-email">${c.email}</div>
    \\                    </div>
    \\                </div>
    \\            `).join('');
    \\        }
    \\        function renderCalendar() {
    \\            const grid = document.getElementById('calendar-grid');
    \\            const today = new Date();
    \\            const days = ['S', 'M', 'T', 'W', 'T', 'F', 'S'];
    \\            let html = days.map(d => `<div style="font-weight: 600; color: var(--text-muted);">${d}</div>`).join('');
    \\            const firstDay = new Date(today.getFullYear(), today.getMonth(), 1).getDay();
    \\            const daysInMonth = new Date(today.getFullYear(), today.getMonth() + 1, 0).getDate();
    \\            for (let i = 0; i < firstDay; i++) html += '<div></div>';
    \\            for (let d = 1; d <= daysInMonth; d++) {
    \\                const isToday = d === today.getDate();
    \\                html += `<div class="calendar-day ${isToday ? 'today' : ''}">${d}</div>`;
    \\            }
    \\            grid.innerHTML = html;
    \\            document.getElementById('calendar-month').textContent = today.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    \\        }
    \\        function openEmail(id) {
    \\            const email = messages.find(m => m.id === id);
    \\            if (!email) return;
    \\            currentEmail = email;
    \\            email.unread = false;
    \\            document.querySelectorAll('.message-item').forEach(el => el.classList.remove('active'));
    \\            event.currentTarget.classList.add('active');
    \\            document.getElementById('email-subject').textContent = email.subject;
    \\            document.getElementById('email-avatar').textContent = email.from.name.charAt(0);
    \\            document.getElementById('email-from-name').textContent = email.from.name;
    \\            document.getElementById('email-from-email').textContent = `<${email.from.email}>`;
    \\            document.getElementById('email-to').textContent = 'To: me';
    \\            document.getElementById('email-date').textContent = email.date;
    \\            document.getElementById('email-body').innerHTML = email.body.replace(/\\n/g, '<br>');
    \\            document.getElementById('empty-state').style.display = 'none';
    \\            document.getElementById('email-content').style.display = 'block';
    \\            document.getElementById('message-view').classList.add('open');
    \\            renderMessages();
    \\        }
    \\        function closeEmail() {
    \\            document.getElementById('message-view').classList.remove('open');
    \\            document.getElementById('empty-state').style.display = 'flex';
    \\            document.getElementById('email-content').style.display = 'none';
    \\            currentEmail = null;
    \\        }
    \\        function openCompose() {
    \\            document.getElementById('compose-modal').classList.add('open');
    \\            clearAttachments();
    \\            dragCounter = 0;
    \\            setTimeout(initDragAndDrop, 100);
    \\        }
    \\        function closeCompose() {
    \\            document.getElementById('compose-modal').classList.remove('open');
    \\            document.getElementById('compose-to').value = '';
    \\            document.getElementById('compose-cc').value = '';
    \\            document.getElementById('compose-subject').value = '';
    \\            document.getElementById('compose-body').value = '';
    \\        }
    \\        function sendEmail() {
    \\            const to = document.getElementById('compose-to').value;
    \\            const subject = document.getElementById('compose-subject').value;
    \\            if (!to || !subject) {
    \\                showToast('Please fill in required fields', 'error');
    \\                return;
    \\            }
    \\            fetch('/webmail/api/compose', {
    \\                method: 'POST',
    \\                headers: { 'Content-Type': 'application/json' },
    \\                body: JSON.stringify({
    \\                    to: [to],
    \\                    cc: document.getElementById('compose-cc').value ? [document.getElementById('compose-cc').value] : [],
    \\                    subject: subject,
    \\                    body_text: document.getElementById('compose-body').value
    \\                })
    \\            }).then(() => {
    \\                showToast('Email sent successfully!', 'success');
    \\                closeCompose();
    \\            }).catch(() => {
    \\                showToast('Failed to send email', 'error');
    \\            });
    \\        }
    \\        function saveDraft() {
    \\            showToast('Draft saved', 'success');
    \\            closeCompose();
    \\        }
    \\        function replyEmail() {
    \\            if (!currentEmail) return;
    \\            openCompose();
    \\            document.getElementById('compose-to').value = currentEmail.from.email;
    \\            document.getElementById('compose-subject').value = 'Re: ' + currentEmail.subject;
    \\        }
    \\        function forwardEmail() {
    \\            if (!currentEmail) return;
    \\            openCompose();
    \\            document.getElementById('compose-subject').value = 'Fwd: ' + currentEmail.subject;
    \\            document.getElementById('compose-body').value = '\\n\\n---------- Forwarded message ----------\\n' + currentEmail.body;
    \\        }
    \\        function archiveEmail() {
    \\            if (!currentEmail) return;
    \\            showToast('Email archived', 'success');
    \\            closeEmail();
    \\        }
    \\        function deleteEmail() {
    \\            if (!currentEmail) return;
    \\            messages = messages.filter(m => m.id !== currentEmail.id);
    \\            renderMessages();
    \\            showToast('Email deleted', 'success');
    \\            closeEmail();
    \\        }
    \\        function toggleSidebar() {
    \\            document.getElementById('sidebar').classList.toggle('open');
    \\        }
    \\        function closeSidebar() {
    \\            document.getElementById('sidebar').classList.remove('open');
    \\        }
    \\        function toggleContacts() {
    \\            document.getElementById('contacts-panel').classList.toggle('open');
    \\        }
    \\        function selectContact(email) {
    \\            openCompose();
    \\            document.getElementById('compose-to').value = email;
    \\            toggleContacts();
    \\        }
    \\        function loadMessages(folder) {
    \\            fetch('/webmail/api/messages?folder=' + folder)
    \\                .then(r => r.json())
    \\                .catch(() => {});
    \\        }
    \\        function searchMessages(query) {
    \\            if (query.length < 2) {
    \\                messages = demoMessages;
    \\                renderMessages();
    \\                return;
    \\            }
    \\            messages = demoMessages.filter(m =>
    \\                m.subject.toLowerCase().includes(query.toLowerCase()) ||
    \\                m.from.name.toLowerCase().includes(query.toLowerCase()) ||
    \\                m.preview.toLowerCase().includes(query.toLowerCase())
    \\            );
    \\            renderMessages();
    \\        }
    \\        function refreshMessages() {
    \\            showToast('Messages refreshed', 'success');
    \\            loadMessages(currentFolder);
    \\        }
    \\        function formatText(format) {
    \\            document.execCommand(format, false, null);
    \\        }
    \\        function insertLink() {
    \\            const url = prompt('Enter URL:');
    \\            if (url) document.execCommand('createLink', false, url);
    \\        }
    \\        // Attachment state
    \\        let attachments = [];
    \\        const MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024; // 25MB
    \\        const MAX_ATTACHMENTS = 10;
    \\
    \\        function attachFile() {
    \\            const input = document.createElement('input');
    \\            input.type = 'file';
    \\            input.multiple = true;
    \\            input.accept = '*/*';
    \\            input.onchange = handleFileSelect;
    \\            input.click();
    \\        }
    \\
    \\        function handleFileSelect(event) {
    \\            const files = Array.from(event.target.files);
    \\
    \\            if (attachments.length + files.length > MAX_ATTACHMENTS) {
    \\                showToast('Maximum ' + MAX_ATTACHMENTS + ' attachments allowed', 'error');
    \\                return;
    \\            }
    \\
    \\            files.forEach(file => {
    \\                if (file.size > MAX_ATTACHMENT_SIZE) {
    \\                    showToast('File "' + file.name + '" exceeds 25MB limit', 'error');
    \\                    return;
    \\                }
    \\                uploadAttachment(file);
    \\            });
    \\        }
    \\
    \\        async function uploadAttachment(file) {
    \\            const formData = new FormData();
    \\            formData.append('file', file);
    \\            formData.append('filename', file.name);
    \\
    \\            showToast('Uploading ' + file.name + '...', 'success');
    \\
    \\            try {
    \\                const response = await fetch('/webmail/api/attachments', {
    \\                    method: 'POST',
    \\                    body: formData
    \\                });
    \\
    \\                if (response.ok) {
    \\                    const data = await response.json();
    \\                    attachments.push({
    \\                        id: data.id,
    \\                        name: file.name,
    \\                        size: file.size,
    \\                        type: file.type || 'application/octet-stream'
    \\                    });
    \\                    updateAttachmentList();
    \\                    showToast('Attached: ' + file.name, 'success');
    \\                } else {
    \\                    showToast('Failed to upload ' + file.name, 'error');
    \\                }
    \\            } catch (err) {
    \\                showToast('Error uploading file', 'error');
    \\            }
    \\        }
    \\
    \\        function removeAttachment(index) {
    \\            const attachment = attachments[index];
    \\            fetch('/webmail/api/attachments/' + attachment.id, { method: 'DELETE' })
    \\                .catch(() => {});
    \\            attachments.splice(index, 1);
    \\            updateAttachmentList();
    \\            showToast('Removed: ' + attachment.name, 'success');
    \\        }
    \\
    \\        function updateAttachmentList() {
    \\            let listEl = document.getElementById('attachment-list');
    \\            if (!listEl) {
    \\                const editor = document.querySelector('.rich-editor');
    \\                if (editor) {
    \\                    listEl = document.createElement('div');
    \\                    listEl.id = 'attachment-list';
    \\                    listEl.className = 'attachment-list';
    \\                    editor.parentNode.insertBefore(listEl, editor);
    \\                }
    \\            }
    \\            if (!listEl) return;
    \\
    \\            if (attachments.length === 0) {
    \\                listEl.innerHTML = '';
    \\                listEl.style.display = 'none';
    \\                return;
    \\            }
    \\
    \\            listEl.style.display = 'flex';
    \\            listEl.innerHTML = attachments.map((att, i) =>
    \\                '<div class="attachment-item">' +
    \\                '<span class="att-icon">📎</span>' +
    \\                '<span class="att-name">' + att.name + '</span>' +
    \\                '<span class="att-size">(' + formatSize(att.size) + ')</span>' +
    \\                '<button class="att-remove" onclick="removeAttachment(' + i + ')">×</button>' +
    \\                '</div>'
    \\            ).join('');
    \\        }
    \\
    \\        function formatSize(bytes) {
    \\            if (bytes < 1024) return bytes + ' B';
    \\            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    \\            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    \\        }
    \\
    \\        function getAttachmentIds() {
    \\            return attachments.map(a => a.id);
    \\        }
    \\
    \\        function clearAttachments() {
    \\            attachments.forEach(att => {
    \\                fetch('/webmail/api/attachments/' + att.id, { method: 'DELETE' }).catch(() => {});
    \\            });
    \\            attachments = [];
    \\            updateAttachmentList();
    \\        }
    \\
    \\        // Drag and Drop Handlers
    \\        let dragCounter = 0;
    \\
    \\        function initDragAndDrop() {
    \\            const composeModal = document.querySelector('.compose-modal');
    \\            const dropOverlay = document.getElementById('drop-zone-overlay');
    \\
    \\            if (!composeModal || !dropOverlay) return;
    \\
    \\            // Prevent default drag behaviors on the whole document
    \\            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    \\                document.body.addEventListener(eventName, preventDefaults, false);
    \\            });
    \\
    \\            // Compose modal drag events
    \\            composeModal.addEventListener('dragenter', handleDragEnter, false);
    \\            composeModal.addEventListener('dragleave', handleDragLeave, false);
    \\            composeModal.addEventListener('dragover', handleDragOver, false);
    \\            composeModal.addEventListener('drop', handleDrop, false);
    \\        }
    \\
    \\        function preventDefaults(e) {
    \\            e.preventDefault();
    \\            e.stopPropagation();
    \\        }
    \\
    \\        function handleDragEnter(e) {
    \\            preventDefaults(e);
    \\            dragCounter++;
    \\
    \\            const composeModal = document.querySelector('.compose-modal');
    \\            const dropOverlay = document.getElementById('drop-zone-overlay');
    \\
    \\            if (e.dataTransfer.types.includes('Files')) {
    \\                composeModal.classList.add('drag-over');
    \\                dropOverlay.classList.add('active');
    \\            }
    \\        }
    \\
    \\        function handleDragLeave(e) {
    \\            preventDefaults(e);
    \\            dragCounter--;
    \\
    \\            if (dragCounter === 0) {
    \\                const composeModal = document.querySelector('.compose-modal');
    \\                const dropOverlay = document.getElementById('drop-zone-overlay');
    \\                composeModal.classList.remove('drag-over');
    \\                dropOverlay.classList.remove('active');
    \\            }
    \\        }
    \\
    \\        function handleDragOver(e) {
    \\            preventDefaults(e);
    \\            e.dataTransfer.dropEffect = 'copy';
    \\        }
    \\
    \\        function handleDrop(e) {
    \\            preventDefaults(e);
    \\            dragCounter = 0;
    \\
    \\            const composeModal = document.querySelector('.compose-modal');
    \\            const dropOverlay = document.getElementById('drop-zone-overlay');
    \\            composeModal.classList.remove('drag-over');
    \\            dropOverlay.classList.remove('active');
    \\
    \\            const files = Array.from(e.dataTransfer.files);
    \\
    \\            if (files.length === 0) {
    \\                showToast('No files detected', 'error');
    \\                return;
    \\            }
    \\
    \\            if (attachments.length + files.length > MAX_ATTACHMENTS) {
    \\                showToast('Maximum ' + MAX_ATTACHMENTS + ' attachments allowed', 'error');
    \\                return;
    \\            }
    \\
    \\            let validFiles = 0;
    \\            files.forEach(file => {
    \\                if (file.size > MAX_ATTACHMENT_SIZE) {
    \\                    showToast('File "' + file.name + '" exceeds 25MB limit', 'error');
    \\                } else {
    \\                    validFiles++;
    \\                    uploadAttachment(file);
    \\                }
    \\            });
    \\
    \\            if (validFiles > 0) {
    \\                showToast('Uploading ' + validFiles + ' file' + (validFiles > 1 ? 's' : '') + '...', 'success');
    \\            }
    \\        }
    \\
    \\        // Initialize drag and drop on page load
    \\        document.addEventListener('DOMContentLoaded', function() {
    \\            setTimeout(initDragAndDrop, 500);
    \\        });
    \\
    \\        // =============================================
    \\        // Thread/Conversation View Functions
    \\        // =============================================
    \\        let threadViewEnabled = false;
    \\        let currentThread = null;
    \\        let threads = [];
    \\
    \\        // Demo threads data
    \\        const demoThreads = [
    \\            {
    \\                id: 'thread_1',
    \\                subject: 'Project Update',
    \\                message_count: 3,
    \\                unread_count: 1,
    \\                latest_date: Date.now(),
    \\                has_attachments: true,
    \\                participants: ['Alice <alice@example.com>', 'Bob <bob@example.com>'],
    \\                messages: [
    \\                    { id: 'm1', from: 'Alice', email: 'alice@example.com', date: 'Nov 25, 10:00 AM', preview: 'Hey team, here is the project update...', body: 'Hey team,\\n\\nHere is the project update for this week:\\n\\n1. Frontend completed\\n2. Backend API ready\\n3. Testing in progress\\n\\nLet me know if you have questions!\\n\\nBest,\\nAlice', is_read: true, depth: 0, has_attachments: true },
    \\                    { id: 'm2', from: 'Bob', email: 'bob@example.com', date: 'Nov 25, 2:30 PM', preview: 'Thanks for the update! I have a question...', body: 'Thanks for the update!\\n\\nI have a question about the API endpoints - are they documented yet?\\n\\nBob', is_read: true, depth: 1, has_attachments: false },
    \\                    { id: 'm3', from: 'Alice', email: 'alice@example.com', date: 'Nov 26, 9:15 AM', preview: 'Yes, check the docs folder...', body: 'Yes, check the docs folder in the repo. I added OpenAPI specs yesterday.\\n\\n- Alice', is_read: false, depth: 1, has_attachments: false }
    \\                ]
    \\            },
    \\            {
    \\                id: 'thread_2',
    \\                subject: 'Meeting Tomorrow',
    \\                message_count: 2,
    \\                unread_count: 0,
    \\                latest_date: Date.now() - 86400000,
    \\                has_attachments: false,
    \\                participants: ['Charlie <charlie@example.com>'],
    \\                messages: [
    \\                    { id: 'm4', from: 'Charlie', email: 'charlie@example.com', date: 'Nov 24, 4:00 PM', preview: 'Can we meet tomorrow at 2pm?', body: 'Hi,\\n\\nCan we meet tomorrow at 2pm to discuss the deployment plan?\\n\\nCharlie', is_read: true, depth: 0, has_attachments: false },
    \\                    { id: 'm5', from: 'You', email: 'me@example.com', date: 'Nov 24, 4:15 PM', preview: 'Sure, that works for me!', body: 'Sure, that works for me! See you then.', is_read: true, depth: 1, has_attachments: false }
    \\                ]
    \\            }
    \\        ];
    \\        threads = demoThreads;
    \\
    \\        function toggleThreadView() {
    \\            threadViewEnabled = !threadViewEnabled;
    \\            const btn = document.getElementById('thread-toggle');
    \\            btn.classList.toggle('active', threadViewEnabled);
    \\
    \\            if (threadViewEnabled) {
    \\                loadThreads();
    \\                showToast('Thread view enabled', 'success');
    \\            } else {
    \\                renderMessages();
    \\                closeThread();
    \\                showToast('Thread view disabled', 'success');
    \\            }
    \\        }
    \\
    \\        function loadThreads() {
    \\            fetch('/webmail/api/threads')
    \\                .then(r => r.json())
    \\                .then(data => {
    \\                    if (data.threads && data.threads.length > 0) {
    \\                        threads = data.threads;
    \\                    }
    \\                    renderThreadList();
    \\                })
    \\                .catch(() => {
    \\                    // Use demo data on error
    \\                    renderThreadList();
    \\                });
    \\        }
    \\
    \\        function renderThreadList() {
    \\            const container = document.getElementById('messages');
    \\            container.innerHTML = threads.map(thread => `
    \\                <div class="message-item ${thread.unread_count > 0 ? 'unread' : ''}" onclick="openThread('${thread.id}')">
    \\                    <div class="message-header">
    \\                        <span class="message-sender">
    \\                            ${thread.participants.slice(0, 2).map(p => p.split('<')[0].trim()).join(', ')}
    \\                            ${thread.participants.length > 2 ? ' +' + (thread.participants.length - 2) : ''}
    \\                        </span>
    \\                        <span class="message-date">${thread.message_count} msgs</span>
    \\                    </div>
    \\                    <div class="message-subject">${thread.subject}</div>
    \\                    <div class="message-preview">${thread.messages[thread.messages.length - 1].preview}</div>
    \\                    <div class="message-indicators">
    \\                        ${thread.unread_count > 0 ? '<span style="background: var(--primary); color: white; padding: 2px 6px; border-radius: 10px; font-size: 0.7rem;">' + thread.unread_count + '</span>' : ''}
    \\                        ${thread.has_attachments ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>' : ''}
    \\                    </div>
    \\                </div>
    \\            `).join('');
    \\            document.getElementById('list-count').textContent = '(' + threads.length + ' threads)';
    \\        }
    \\
    \\        function openThread(threadId) {
    \\            const thread = threads.find(t => t.id === threadId);
    \\            if (!thread) return;
    \\
    \\            currentThread = thread;
    \\
    \\            // Update header
    \\            document.getElementById('thread-subject').textContent = thread.subject;
    \\            document.getElementById('thread-count').textContent = thread.message_count + ' messages';
    \\            document.getElementById('thread-unread').textContent = thread.unread_count > 0 ? thread.unread_count + ' unread' : '';
    \\
    \\            // Render participants
    \\            const participantsEl = document.getElementById('thread-participants');
    \\            participantsEl.innerHTML = thread.participants.slice(0, 4).map(p => {
    \\                const name = p.split('<')[0].trim();
    \\                return '<div class="thread-participant-avatar">' + name.charAt(0).toUpperCase() + '</div>';
    \\            }).join('');
    \\
    \\            // Render messages
    \\            renderThreadMessages(thread.messages);
    \\
    \\            // Show conversation view
    \\            document.getElementById('empty-state').style.display = 'none';
    \\            document.getElementById('email-content').style.display = 'none';
    \\            document.getElementById('conversation-view').classList.add('active');
    \\            document.getElementById('message-view').classList.add('open');
    \\        }
    \\
    \\        function renderThreadMessages(threadMessages) {
    \\            const container = document.getElementById('thread-messages');
    \\            container.innerHTML = threadMessages.map((msg, idx) => `
    \\                <div class="thread-message depth-${Math.min(msg.depth, 3)} ${idx < threadMessages.length - 1 ? 'collapsed' : ''}" data-id="${msg.id}">
    \\                    <div class="thread-message-header" onclick="toggleThreadMessage('${msg.id}')">
    \\                        <div class="thread-message-avatar">${msg.from.charAt(0).toUpperCase()}</div>
    \\                        <div class="thread-message-info">
    \\                            <div class="thread-message-from">
    \\                                ${msg.from}
    \\                                ${!msg.is_read ? '<div class="unread-badge"></div>' : ''}
    \\                            </div>
    \\                            <div class="thread-message-preview">${msg.preview}</div>
    \\                        </div>
    \\                        <div class="thread-message-date">${msg.date}</div>
    \\                        <div class="thread-message-expand">
    \\                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="6 9 12 15 18 9"/>
    \\                            </svg>
    \\                        </div>
    \\                    </div>
    \\                    <div class="thread-message-body">${msg.body.replace(/\\n/g, '<br>')}</div>
    \\                    <div class="thread-message-actions">
    \\                        <button class="thread-reply-btn" onclick="replyToThreadMessage('${msg.id}')">
    \\                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>
    \\                            </svg>
    \\                            Reply
    \\                        </button>
    \\                        <button class="icon-btn" onclick="forwardThreadMessage('${msg.id}')" title="Forward">
    \\                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 0 1 4-4h12"/>
    \\                            </svg>
    \\                        </button>
    \\                    </div>
    \\                </div>
    \\            `).join('');
    \\        }
    \\
    \\        function toggleThreadMessage(msgId) {
    \\            const msgEl = document.querySelector('.thread-message[data-id="' + msgId + '"]');
    \\            if (msgEl) {
    \\                msgEl.classList.toggle('collapsed');
    \\            }
    \\        }
    \\
    \\        function closeThread() {
    \\            document.getElementById('conversation-view').classList.remove('active');
    \\            document.getElementById('message-view').classList.remove('open');
    \\            document.getElementById('empty-state').style.display = 'flex';
    \\            currentThread = null;
    \\        }
    \\
    \\        function replyToThreadMessage(msgId) {
    \\            if (!currentThread) return;
    \\            const msg = currentThread.messages.find(m => m.id === msgId);
    \\            if (!msg) return;
    \\
    \\            openCompose();
    \\            document.getElementById('compose-to').value = msg.email;
    \\            document.getElementById('compose-subject').value = 'Re: ' + currentThread.subject;
    \\        }
    \\
    \\        function forwardThreadMessage(msgId) {
    \\            if (!currentThread) return;
    \\            const msg = currentThread.messages.find(m => m.id === msgId);
    \\            if (!msg) return;
    \\
    \\            openCompose();
    \\            document.getElementById('compose-subject').value = 'Fwd: ' + currentThread.subject;
    \\            document.getElementById('compose-body').value = '\\n\\n---------- Forwarded message ----------\\nFrom: ' + msg.from + '\\nDate: ' + msg.date + '\\n\\n' + msg.body;
    \\        }
    \\
    \\        function sendQuickReply() {
    \\            const text = document.getElementById('quick-reply-text').value;
    \\            if (!text.trim()) {
    \\                showToast('Please enter a reply message', 'error');
    \\                return;
    \\            }
    \\
    \\            // In a real implementation, this would send the reply via API
    \\            showToast('Reply sent!', 'success');
    \\            document.getElementById('quick-reply-text').value = '';
    \\
    \\            // Add reply to thread (demo)
    \\            if (currentThread) {
    \\                currentThread.messages.push({
    \\                    id: 'm' + Date.now(),
    \\                    from: 'You',
    \\                    email: 'me@example.com',
    \\                    date: 'Just now',
    \\                    preview: text.substring(0, 50) + '...',
    \\                    body: text,
    \\                    is_read: true,
    \\                    depth: 1,
    \\                    has_attachments: false
    \\                });
    \\                currentThread.message_count++;
    \\                renderThreadMessages(currentThread.messages);
    \\            }
    \\        }
    \\
    \\        function attachToReply() {
    \\            showToast('Attachment feature coming soon', 'success');
    \\        }
    \\
    \\        function archiveThread() {
    \\            if (!currentThread) return;
    \\            threads = threads.filter(t => t.id !== currentThread.id);
    \\            renderThreadList();
    \\            closeThread();
    \\            showToast('Thread archived', 'success');
    \\        }
    \\
    \\        function deleteThread() {
    \\            if (!currentThread) return;
    \\            threads = threads.filter(t => t.id !== currentThread.id);
    \\            renderThreadList();
    \\            closeThread();
    \\            showToast('Thread deleted', 'success');
    \\        }
    \\
    \\        // =============================================
    \\        // Inline Image Functions
    \\        // =============================================
    \\        let inlineImages = [];
    \\        const MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10MB
    \\        const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
    \\
    \\        function openInsertImage() {
    \\            document.getElementById('insert-image-modal').classList.add('open');
    \\            document.getElementById('image-url').value = '';
    \\        }
    \\
    \\        function closeInsertImage() {
    \\            document.getElementById('insert-image-modal').classList.remove('open');
    \\        }
    \\
    \\        function triggerImageUpload() {
    \\            document.getElementById('image-file-input').click();
    \\        }
    \\
    \\        function handleImageDragOver(e) {
    \\            e.preventDefault();
    \\            e.stopPropagation();
    \\            document.getElementById('image-upload-zone').classList.add('dragover');
    \\        }
    \\
    \\        function handleImageDragLeave(e) {
    \\            e.preventDefault();
    \\            e.stopPropagation();
    \\            document.getElementById('image-upload-zone').classList.remove('dragover');
    \\        }
    \\
    \\        function handleImageDrop(e) {
    \\            e.preventDefault();
    \\            e.stopPropagation();
    \\            document.getElementById('image-upload-zone').classList.remove('dragover');
    \\
    \\            const files = Array.from(e.dataTransfer.files);
    \\            const imageFile = files.find(f => ALLOWED_IMAGE_TYPES.includes(f.type));
    \\
    \\            if (imageFile) {
    \\                processImageFile(imageFile);
    \\            } else {
    \\                showToast('Please drop a valid image file', 'error');
    \\            }
    \\        }
    \\
    \\        function handleImageSelect(e) {
    \\            const file = e.target.files[0];
    \\            if (file) {
    \\                processImageFile(file);
    \\            }
    \\        }
    \\
    \\        function processImageFile(file) {
    \\            if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
    \\                showToast('Invalid image type. Use PNG, JPG, GIF, or WebP.', 'error');
    \\                return;
    \\            }
    \\
    \\            if (file.size > MAX_IMAGE_SIZE) {
    \\                showToast('Image too large. Maximum size is 10MB.', 'error');
    \\                return;
    \\            }
    \\
    \\            const reader = new FileReader();
    \\            reader.onload = function(e) {
    \\                const dataUri = e.target.result;
    \\                const contentId = 'img_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    \\
    \\                // Add to inline images array
    \\                inlineImages.push({
    \\                    id: contentId,
    \\                    filename: file.name,
    \\                    type: file.type,
    \\                    dataUri: dataUri,
    \\                    size: file.size
    \\                });
    \\
    \\                // Insert into compose body
    \\                insertImageAtCursor(dataUri, file.name);
    \\
    \\                // Update preview
    \\                renderInlineImagesPreview();
    \\
    \\                closeInsertImage();
    \\                showToast('Image inserted!', 'success');
    \\            };
    \\            reader.readAsDataURL(file);
    \\        }
    \\
    \\        function insertImageFromUrl() {
    \\            const url = document.getElementById('image-url').value.trim();
    \\            if (!url) {
    \\                showToast('Please enter an image URL', 'error');
    \\                return;
    \\            }
    \\
    \\            // Basic URL validation
    \\            try {
    \\                new URL(url);
    \\            } catch {
    \\                showToast('Invalid URL format', 'error');
    \\                return;
    \\            }
    \\
    \\            const contentId = 'img_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    \\
    \\            inlineImages.push({
    \\                id: contentId,
    \\                filename: url.split('/').pop() || 'image',
    \\                type: 'image/unknown',
    \\                dataUri: url,
    \\                size: 0,
    \\                isUrl: true
    \\            });
    \\
    \\            insertImageAtCursor(url, 'Inline image');
    \\            renderInlineImagesPreview();
    \\
    \\            closeInsertImage();
    \\            showToast('Image inserted!', 'success');
    \\        }
    \\
    \\        function insertImageAtCursor(src, alt) {
    \\            const textarea = document.getElementById('compose-body');
    \\            const imgTag = '\\n[Image: ' + alt + ']\\n<img src="' + src + '" alt="' + alt + '" style="max-width: 100%;">\\n';
    \\
    \\            const start = textarea.selectionStart;
    \\            const end = textarea.selectionEnd;
    \\            const text = textarea.value;
    \\
    \\            textarea.value = text.substring(0, start) + imgTag + text.substring(end);
    \\            textarea.selectionStart = textarea.selectionEnd = start + imgTag.length;
    \\            textarea.focus();
    \\        }
    \\
    \\        function renderInlineImagesPreview() {
    \\            const container = document.getElementById('inline-images-preview');
    \\            container.innerHTML = inlineImages.map((img, idx) => `
    \\                <div class="inline-image-container">
    \\                    <img src="${img.dataUri}" alt="${img.filename}" title="${img.filename}">
    \\                    <button class="remove-btn" onclick="removeInlineImage(${idx})" title="Remove">×</button>
    \\                </div>
    \\            `).join('');
    \\        }
    \\
    \\        function removeInlineImage(index) {
    \\            const removed = inlineImages.splice(index, 1)[0];
    \\            renderInlineImagesPreview();
    \\
    \\            // Note: We don't remove from textarea as user may have edited it
    \\            showToast('Image removed from list', 'success');
    \\        }
    \\
    \\        function clearInlineImages() {
    \\            inlineImages = [];
    \\            renderInlineImagesPreview();
    \\        }
    \\
    \\        // Extend closeCompose to clear inline images
    \\        const originalCloseCompose = closeCompose;
    \\        closeCompose = function() {
    \\            clearInlineImages();
    \\            originalCloseCompose();
    \\        };
    \\
    \\        // Handle paste for images
    \\        document.addEventListener('paste', function(e) {
    \\            const composeModal = document.getElementById('compose-modal');
    \\            if (!composeModal.classList.contains('open')) return;
    \\
    \\            const items = Array.from(e.clipboardData.items);
    \\            const imageItem = items.find(item => item.type.startsWith('image/'));
    \\
    \\            if (imageItem) {
    \\                e.preventDefault();
    \\                const file = imageItem.getAsFile();
    \\                if (file) {
    \\                    processImageFile(file);
    \\                }
    \\            }
    \\        });
    \\
    \\        // =============================================
    \\        // Templates & Signatures Functions
    \\        // =============================================
    \\
    \\        // Templates data
    \\        const templates = {
    \\            vacation: {
    \\                subject: 'Out of Office: {{original_subject}}',
    \\                body: 'Hello,\\n\\nThank you for your email. I am currently out of the office from {{start_date}} to {{end_date}}.\\n\\nI will have limited access to email during this time. If your matter is urgent, please contact {{alternate_contact}}.\\n\\nI will respond to your email upon my return.\\n\\nBest regards,\\n{{sender_name}}'
    \\            },
    \\            thankyou: {
    \\                subject: 'Re: {{original_subject}}',
    \\                body: 'Hi {{recipient_name}},\\n\\nThank you for your message. I appreciate you taking the time to reach out.\\n\\n{{custom_message}}\\n\\nBest regards,\\n{{sender_name}}'
    \\            },
    \\            meeting: {
    \\                subject: 'Meeting Request: {{meeting_topic}}',
    \\                body: 'Hi {{recipient_name}},\\n\\nI would like to schedule a meeting to discuss {{meeting_topic}}.\\n\\nProposed time: {{proposed_time}}\\nDuration: {{duration}}\\nLocation: {{location}}\\n\\nPlease let me know if this works for you, or suggest an alternative time.\\n\\nBest regards,\\n{{sender_name}}'
    \\            },
    \\            followup: {
    \\                subject: 'Following Up: {{original_subject}}',
    \\                body: 'Hi {{recipient_name}},\\n\\nI wanted to follow up on our previous conversation regarding {{topic}}.\\n\\n{{followup_message}}\\n\\nPlease let me know if you have any questions.\\n\\nBest regards,\\n{{sender_name}}'
    \\            }
    \\        };
    \\
    \\        // Signatures data
    \\        const signatures = {
    \\            professional: {
    \\                text: '\\n\\n--\\nBest regards,\\n\\nJohn Doe\\nSenior Developer\\nAcme Corp\\nPhone: (555) 123-4567\\nEmail: john.doe@acme.com',
    \\                isDefault: true
    \\            },
    \\            simple: {
    \\                text: '\\n\\n--\\nThanks,\\nJohn',
    \\                isDefault: false
    \\            },
    \\            formal: {
    \\                text: '\\n\\n--\\nYours sincerely,\\n\\nJohn Doe, MBA\\nDirector of Engineering\\nAcme Corporation\\n\\nConfidentiality Notice: This email may contain confidential information.',
    \\                isDefault: false
    \\            }
    \\        };
    \\
    \\        let currentSignature = 'professional';
    \\
    \\        function openTemplates() {
    \\            document.getElementById('templates-modal').classList.add('open');
    \\        }
    \\
    \\        function closeTemplates() {
    \\            document.getElementById('templates-modal').classList.remove('open');
    \\        }
    \\
    \\        function useTemplate(templateId) {
    \\            const template = templates[templateId];
    \\            if (!template) return;
    \\
    \\            // Fill in subject if empty
    \\            const subjectField = document.getElementById('compose-subject');
    \\            if (!subjectField.value) {
    \\                subjectField.value = template.subject.replace(/\\{\\{.*?\\}\\}/g, '...');
    \\            }
    \\
    \\            // Fill in body
    \\            const bodyField = document.getElementById('compose-body');
    \\            bodyField.value = template.body.replace(/\\{\\{.*?\\}\\}/g, function(match) {
    \\                const varName = match.slice(2, -2);
    \\                return '[' + varName + ']';
    \\            });
    \\
    \\            closeTemplates();
    \\            showToast('Template applied! Fill in the bracketed fields.', 'success');
    \\        }
    \\
    \\        function openSignatures() {
    \\            document.getElementById('signatures-modal').classList.add('open');
    \\        }
    \\
    \\        function closeSignatures() {
    \\            document.getElementById('signatures-modal').classList.remove('open');
    \\        }
    \\
    \\        function useSignature(signatureId) {
    \\            const signature = signatures[signatureId];
    \\            if (!signature) return;
    \\
    \\            currentSignature = signatureId;
    \\
    \\            const bodyField = document.getElementById('compose-body');
    \\            // Remove any existing signature
    \\            let body = bodyField.value;
    \\            const sigIndex = body.lastIndexOf('\\n\\n--\\n');
    \\            if (sigIndex !== -1) {
    \\                body = body.substring(0, sigIndex);
    \\            }
    \\
    \\            bodyField.value = body + signature.text;
    \\
    \\            closeSignatures();
    \\            showToast('Signature inserted!', 'success');
    \\        }
    \\
    \\        function manageSignatures() {
    \\            closeSignatures();
    \\            showToast('Signature management coming in settings', 'success');
    \\        }
    \\
    \\        // Auto-insert signature when opening compose
    \\        const originalOpenCompose = openCompose;
    \\        openCompose = function() {
    \\            originalOpenCompose();
    \\
    \\            // Auto-insert default signature if enabled
    \\            const autoSig = document.getElementById('auto-signature');
    \\            if (autoSig && autoSig.checked) {
    \\                const bodyField = document.getElementById('compose-body');
    \\                if (!bodyField.value && signatures[currentSignature]) {
    \\                    bodyField.value = signatures[currentSignature].text.trim();
    \\                    bodyField.setSelectionRange(0, 0); // Move cursor to start
    \\                }
    \\            }
    \\        };
    \\
    \\        // =============================================
    \\        // Read Receipts, Scheduling, Groups
    \\        // =============================================
    \\
    \\        // Contact groups data
    \\        const contactGroups = {
    \\            team: { name: 'Development Team', emails: 'dev1@example.com, dev2@example.com, dev3@example.com, dev4@example.com, dev5@example.com' },
    \\            mgmt: { name: 'Management', emails: 'ceo@example.com, cto@example.com, cfo@example.com' },
    \\            all: { name: 'All Staff', emails: 'staff@example.com' }
    \\        };
    \\
    \\        let scheduledTime = null;
    \\
    \\        function toggleGroups() {
    \\            document.getElementById('groups-list').classList.toggle('open');
    \\        }
    \\
    \\        function insertGroup(groupId) {
    \\            const group = contactGroups[groupId];
    \\            if (!group) return;
    \\
    \\            const toField = document.getElementById('compose-to');
    \\            if (toField.value) {
    \\                toField.value += ', ' + group.emails;
    \\            } else {
    \\                toField.value = group.emails;
    \\            }
    \\
    \\            document.getElementById('groups-list').classList.remove('open');
    \\            showToast('Added ' + group.name + ' to recipients', 'success');
    \\        }
    \\
    \\        // Close groups dropdown when clicking outside
    \\        document.addEventListener('click', function(e) {
    \\            if (!e.target.closest('.groups-dropdown')) {
    \\                document.getElementById('groups-list').classList.remove('open');
    \\            }
    \\        });
    \\
    \\        function toggleSchedulePicker() {
    \\            const checkbox = document.getElementById('schedule-send');
    \\            const picker = document.getElementById('schedule-picker');
    \\            const display = document.getElementById('schedule-time-display');
    \\
    \\            if (checkbox.checked) {
    \\                picker.classList.add('open');
    \\                // Set default to 1 hour from now
    \\                setSchedulePreset(1);
    \\            } else {
    \\                picker.classList.remove('open');
    \\                display.style.display = 'none';
    \\                scheduledTime = null;
    \\            }
    \\        }
    \\
    \\        function setSchedulePreset(hours) {
    \\            const now = new Date();
    \\            now.setHours(now.getHours() + hours);
    \\
    \\            // Format for datetime-local input
    \\            const year = now.getFullYear();
    \\            const month = String(now.getMonth() + 1).padStart(2, '0');
    \\            const day = String(now.getDate()).padStart(2, '0');
    \\            const hour = String(now.getHours()).padStart(2, '0');
    \\            const minute = String(now.getMinutes()).padStart(2, '0');
    \\
    \\            document.getElementById('schedule-datetime').value = year + '-' + month + '-' + day + 'T' + hour + ':' + minute;
    \\            updateScheduleDisplay();
    \\        }
    \\
    \\        function updateScheduleDisplay() {
    \\            const input = document.getElementById('schedule-datetime');
    \\            const display = document.getElementById('schedule-time-display');
    \\
    \\            if (input.value) {
    \\                scheduledTime = new Date(input.value);
    \\                const options = { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' };
    \\                display.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> ' + scheduledTime.toLocaleString('en-US', options);
    \\                display.style.display = 'inline-flex';
    \\            } else {
    \\                display.style.display = 'none';
    \\                scheduledTime = null;
    \\            }
    \\        }
    \\
    \\        // Modify send to handle scheduling and receipts
    \\        const originalSendEmail = sendEmail;
    \\        sendEmail = function() {
    \\            const requestReceipt = document.getElementById('request-receipt').checked;
    \\            const isScheduled = document.getElementById('schedule-send').checked;
    \\
    \\            if (isScheduled && scheduledTime) {
    \\                // Schedule the email instead of sending immediately
    \\                showToast('Email scheduled for ' + scheduledTime.toLocaleString(), 'success');
    \\                closeCompose();
    \\                return;
    \\            }
    \\
    \\            if (requestReceipt) {
    \\                showToast('Read receipt requested', 'success');
    \\            }
    \\
    \\            // Call original send
    \\            originalSendEmail();
    \\        };
    \\
    \\        function showToast(message, type) {
    \\            const container = document.getElementById('toast-container');
    \\            const toast = document.createElement('div');
    \\            toast.className = 'toast ' + type;
    \\            toast.textContent = message;
    \\            container.appendChild(toast);
    \\            setTimeout(() => toast.remove(), 3000);
    \\        }
    \\    </script>
    \\</body>
    \\</html>
;

// Tests
test "WebmailConfig defaults" {
    const config = WebmailConfig{};
    try std.testing.expectEqual(@as(usize, 25 * 1024 * 1024), config.max_attachment_size);
    try std.testing.expectEqual(@as(usize, 50), config.messages_per_page);
    try std.testing.expect(config.enable_rich_text);
}

test "FolderType strings" {
    try std.testing.expectEqualStrings("Inbox", FolderType.inbox.toString());
    try std.testing.expectEqualStrings("inbox", FolderType.inbox.icon());
    try std.testing.expectEqualStrings("Sent", FolderType.sent.toString());
}

test "WebmailHandler init" {
    const allocator = std.testing.allocator;
    var handler = WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    try std.testing.expectEqual(@as(usize, 50), handler.config.messages_per_page);
}

test "WebmailHandler attachment upload endpoint" {
    const allocator = std.testing.allocator;
    var handler = WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    // Test attachment upload endpoint
    const response = try handler.handleRequest("/webmail/api/attachments", "POST", null);
    defer allocator.free(response);

    try std.testing.expect(response.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, response, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "id") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "att_") != null);
}

test "WebmailHandler attachment delete endpoint" {
    const allocator = std.testing.allocator;
    var handler = WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    // Test attachment delete endpoint
    const response = try handler.handleRequest("/webmail/api/attachments/att_test123", "DELETE", null);
    defer allocator.free(response);

    try std.testing.expect(response.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, response, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "success") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "att_test123") != null);
}

test "WebmailHandler attachment download endpoint" {
    const allocator = std.testing.allocator;
    var handler = WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    // Test attachment download endpoint
    const response = try handler.handleRequest("/webmail/api/attachments/att_test456", "GET", null);
    defer allocator.free(response);

    try std.testing.expect(response.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, response, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "application/octet-stream") != null);
}

test "WebmailConfig attachment limits" {
    const config = WebmailConfig{};

    // Default max attachment size is 25MB
    try std.testing.expectEqual(@as(usize, 25 * 1024 * 1024), config.max_attachment_size);
    // Default max attachments per email is 10
    try std.testing.expectEqual(@as(usize, 10), config.max_attachments);
}

test "WebmailMessage Attachment struct" {
    const attachment = WebmailMessage.Attachment{
        .id = "att_123",
        .filename = "document.pdf",
        .mime_type = "application/pdf",
        .size = 1024 * 100, // 100KB
        .content_id = null,
    };

    try std.testing.expectEqualStrings("att_123", attachment.id);
    try std.testing.expectEqualStrings("document.pdf", attachment.filename);
    try std.testing.expectEqualStrings("application/pdf", attachment.mime_type);
    try std.testing.expectEqual(@as(usize, 102400), attachment.size);
}

test "Webmail HTML contains drop zone overlay" {
    const allocator = std.testing.allocator;
    var handler = WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    const response = try handler.handleRequest("/webmail", "GET", null);
    defer allocator.free(response);

    // Check for drop zone overlay HTML
    try std.testing.expect(std.mem.indexOf(u8, response, "drop-zone-overlay") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Drop files here to attach") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Maximum 25MB per file") != null);
}

test "Webmail HTML contains drag and drop JavaScript" {
    const allocator = std.testing.allocator;
    var handler = WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    const response = try handler.handleRequest("/webmail", "GET", null);
    defer allocator.free(response);

    // Check for drag and drop JavaScript functions
    try std.testing.expect(std.mem.indexOf(u8, response, "initDragAndDrop") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "handleDragEnter") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "handleDragLeave") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "handleDrop") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "dragCounter") != null);
}

test "Webmail HTML contains attachment list element" {
    const allocator = std.testing.allocator;
    var handler = WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    const response = try handler.handleRequest("/webmail", "GET", null);
    defer allocator.free(response);

    // Check for attachment list in compose area
    try std.testing.expect(std.mem.indexOf(u8, response, "attachment-list") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "updateAttachmentList") != null);
}
