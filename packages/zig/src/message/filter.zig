const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");

// ============================================================================
// Gmail-Style Email Categorization
// ============================================================================

/// Email category for automatic folder placement (Gmail-style)
pub const EmailCategory = enum {
    primary, // Default - personal/important emails
    social, // Social network notifications
    forums, // Mailing lists and forums
    updates, // Transactional/notification emails
    promotions, // Marketing/promotional emails

    pub fn toString(self: EmailCategory) []const u8 {
        return switch (self) {
            .primary => "Primary",
            .social => "Social",
            .forums => "Forums",
            .updates => "Updates",
            .promotions => "Promotions",
        };
    }

    /// Get the folder name for this category
    pub fn getFolderName(self: EmailCategory) []const u8 {
        return switch (self) {
            .primary => "INBOX",
            .social => "Social",
            .forums => "Forums",
            .updates => "Updates",
            .promotions => "Promotions",
        };
    }
};

/// Default patterns for social network emails
pub const SOCIAL_DOMAINS = [_][]const u8{
    "facebookmail.com", "facebook.com",   "fb.com",
    "twitter.com",      "x.com",          "linkedin.com",
    "linkedinmail.com", "instagram.com",  "pinterest.com",
    "snapchat.com",     "tiktok.com",     "reddit.com",
    "redditmail.com",   "tumblr.com",     "whatsapp.com",
    "telegram.org",     "discord.com",    "discordapp.com",
    "slack.com",        "meetup.com",     "nextdoor.com",
    "quora.com",        "medium.com",     "mastodon.social",
    "threads.net",      "bluesky.social",
};

pub const SOCIAL_SUBSTRINGS = [_][]const u8{
    "notification@", "notifications@",
    "noreply@",      "no-reply@",
    "@social.",      "@notifications.",
};

/// Default patterns for forum/mailing list emails
pub const FORUMS_DOMAINS = [_][]const u8{
    "googlegroups.com",  "groups.google.com",
    "discourse.org",     "stackoverflow.com",
    "stackexchange.com", "freelancer.com",
    "upwork.com",        "mailman.org",
    "listserv.net",      "yahoogroups.com",
    "gnu.org",           "sourceforge.net",
    "launchpad.net",
};

pub const FORUMS_SUBSTRINGS = [_][]const u8{
    "-list@",    "-users@",  "-dev@",      "-announce@",
    "forum@",    "discuss@", "community@", "@lists.",
    "@mailman.", "@groups.",
    "reply+", // GitHub discussion replies
};

/// Default patterns for update/transactional emails
pub const UPDATES_DOMAINS = [_][]const u8{
    "github.com", "gitlab.com", "bitbucket.org",
    "stripe.com", "paypal.com", "square.com",
    "venmo.com",  "ups.com",    "fedex.com",
    "usps.com",   "dhl.com",
    "amazonses.com", // Amazon SES transactional emails
    "google.com",
    "accounts.google.com",
    "apple.com",
    "id.apple.com",
    "microsoft.com",
    "live.com",
    "outlook.com",
    "dropbox.com",
    "box.com",
    "atlassian.com",
    "jira.com",
    "trello.com",
    "notion.so",
    "airtable.com",
    "asana.com",
    "vercel.com",
    "netlify.com",
    "heroku.com",
    "cloudflare.com",
    "digitalocean.com",
    "twilio.com",
    "sendgrid.com",
    "intercom.io",
    "zendesk.com",
    "freshdesk.com",
    "calendly.com",
    "cal.com",
    "zoom.us",
    "zoom.com",
    "doordash.com",
    "ubereats.com",
    "grubhub.com",
    "airbnb.com",
    "booking.com",
    "expedia.com",
    "uber.com",
    "lyft.com",
    "netflix.com",
    "spotify.com",
    "hulu.com",
};

pub const UPDATES_SUBSTRINGS = [_][]const u8{
    "alert@",             "alerts@",
    "notification@",      "notifications@",
    "noreply@",           "no-reply@",
    "security@",          "support@",
    "confirm@",           "confirmation@",
    "receipt@",           "invoice@",
    "billing@",           "shipping@",
    "delivery@",          "order@",
    "orders@",            "account@",
    "password@",          "verify@",
    "verification@",
    // Amazon transactional prefixes
         "auto-confirm@",
    "ship-notify@",       "order-update@",
    "payments-messages@",
    "return-", // return confirmations
};

/// Default patterns for promotional/marketing emails
pub const PROMOTIONS_DOMAINS = [_][]const u8{
    "mailchimp.com",       "mail.mailchimp.com",
    "sendgrid.net",        "sendgrid.com",
    "constantcontact.com", "mailerlite.com",
    "hubspot.com",         "hubspotmail.com",
    "klaviyo.com",         "convertkit.com",
    "drip.com",            "getresponse.com",
    "aweber.com",          "campaignmonitor.com",
    "sendinblue.com",      "brevo.com",
    "activecampaign.com",  "emarsys.net",
    "salesforce.com",      "exacttarget.com",
    "amazonsellerservices.com", // Amazon promotional - generic amazon.com removed to avoid conflict with transactional
    "walmart.com",
    "target.com",
    "bestbuy.com",
    "ebay.com",
    "etsy.com",
    "shopify.com",
    "wish.com",
    "aliexpress.com",
    "wayfair.com",
    "homedepot.com",
    "lowes.com",
    "sephora.com",
    "ulta.com",
    "groupon.com",
    "retailmenot.com",
};

pub const PROMOTIONS_SUBSTRINGS = [_][]const u8{
    "promo@",     "promotions@",
    "marketing@", "newsletter@",
    "news@",      "deals@",
    "offers@",    "sale@",
    "sales@",     "shop@",
    "store@",     "rewards@",
    "loyalty@",
    "unsubscribe", // common in promotional emails
    "campaign",
    "blast@",
    // Amazon promotional prefixes
    "store-news@",
    "kindle-offers@",
    "vfe-campaign@",
};

/// Case-insensitive string contains check
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    if (needle.len == 0) return true;

    var i: usize = 0;
    outer: while (i <= haystack.len - needle.len) : (i += 1) {
        for (needle, 0..) |c, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(c)) {
                continue :outer;
            }
        }
        return true;
    }
    return false;
}

/// Categorize an email based on the sender address and headers
/// Priority: Headers > Domains > Substrings
/// This ensures specific domain matches (github.com) override generic substrings (notification@)
pub fn categorizeEmail(from_address: []const u8, headers: *const std.StringHashMap([]const u8)) EmailCategory {
    // =========================================================================
    // PHASE 1: Check headers (most specific/reliable signal)
    // =========================================================================

    // Check for forum/mailing list indicators (headers are strongest signal)
    if (headers.get("list-unsubscribe") != null or
        headers.get("list-id") != null or
        headers.get("x-mailing-list") != null)
    {
        // Check precedence header
        if (headers.get("precedence")) |prec| {
            if (containsIgnoreCase(prec, "list") or containsIgnoreCase(prec, "bulk")) {
                return .forums;
            }
        }
        return .forums;
    }

    // Check for auto-generated (updates)
    if (headers.get("auto-submitted")) |auto| {
        if (containsIgnoreCase(auto, "auto-generated") or containsIgnoreCase(auto, "auto-replied")) {
            return .updates;
        }
    }

    // Check for promotional headers
    if (headers.get("x-campaign") != null or
        headers.get("x-mailchimp-id") != null or
        headers.get("x-mc-user") != null or
        headers.get("x-sg-eid") != null)
    {
        return .promotions;
    }

    // =========================================================================
    // PHASE 2: Check ALL domains (more specific than substrings)
    // Order matters: updates has github.com which should override social's notification@ substring
    // =========================================================================

    // Check updates domains FIRST (github.com, stripe.com, etc.)
    // These are often sent with notification@/noreply@ prefixes
    for (UPDATES_DOMAINS) |domain| {
        if (containsIgnoreCase(from_address, domain)) {
            return .updates;
        }
    }

    // Check social networks by domain
    for (SOCIAL_DOMAINS) |domain| {
        if (containsIgnoreCase(from_address, domain)) {
            return .social;
        }
    }

    // Check forums by domain
    for (FORUMS_DOMAINS) |domain| {
        if (containsIgnoreCase(from_address, domain)) {
            return .forums;
        }
    }

    // Check promotions by domain
    for (PROMOTIONS_DOMAINS) |domain| {
        if (containsIgnoreCase(from_address, domain)) {
            return .promotions;
        }
    }

    // =========================================================================
    // PHASE 3: Check substrings (least specific, fallback)
    // Only if no domain matched
    // =========================================================================

    // Check social by substrings
    for (SOCIAL_SUBSTRINGS) |substr| {
        if (containsIgnoreCase(from_address, substr)) {
            return .social;
        }
    }

    // Check forums by substrings
    for (FORUMS_SUBSTRINGS) |substr| {
        if (containsIgnoreCase(from_address, substr)) {
            return .forums;
        }
    }

    // Check updates by substrings
    for (UPDATES_SUBSTRINGS) |substr| {
        if (containsIgnoreCase(from_address, substr)) {
            return .updates;
        }
    }

    // Check promotions by substrings
    for (PROMOTIONS_SUBSTRINGS) |substr| {
        if (containsIgnoreCase(from_address, substr)) {
            return .promotions;
        }
    }

    // Default to primary (inbox)
    return .primary;
}

/// Helper to convert a string to lowercase (allocates)
fn toLowerAlloc(allocator: std.mem.Allocator, str: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, str.len);
    for (str, 0..) |c, i| {
        result[i] = std.ascii.toLower(c);
    }
    return result;
}

// ============================================================================
// Generic Message Filtering (existing functionality)
// ============================================================================

/// Filter action to take when a rule matches
pub const FilterAction = enum {
    accept,
    reject,
    forward,
    discard,
    tag,

    pub fn toString(self: FilterAction) []const u8 {
        return switch (self) {
            .accept => "accept",
            .reject => "reject",
            .forward => "forward",
            .discard => "discard",
            .tag => "tag",
        };
    }
};

/// Filter condition type
pub const FilterConditionType = enum {
    from,
    to,
    subject,
    header,
    body_contains,
    size_greater,
    size_less,
    has_attachment,

    pub fn toString(self: FilterConditionType) []const u8 {
        return switch (self) {
            .from => "from",
            .to => "to",
            .subject => "subject",
            .header => "header",
            .body_contains => "body_contains",
            .size_greater => "size_greater",
            .size_less => "size_less",
            .has_attachment => "has_attachment",
        };
    }
};

/// Filter condition
pub const FilterCondition = struct {
    condition_type: FilterConditionType,
    pattern: []const u8,
    case_sensitive: bool,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *FilterCondition) void {
        self.allocator.free(self.pattern);
    }

    pub fn matches(self: *const FilterCondition, message: *const Message) bool {
        return switch (self.condition_type) {
            .from => self.matchesString(message.from, self.pattern, self.case_sensitive),
            .to => self.matchesString(message.to, self.pattern, self.case_sensitive),
            .subject => self.matchesString(message.subject, self.pattern, self.case_sensitive),
            .header => blk: {
                // Check if any header matches
                var it = message.headers.iterator();
                while (it.next()) |entry| {
                    if (self.matchesString(entry.value_ptr.*, self.pattern, self.case_sensitive)) {
                        break :blk true;
                    }
                }
                break :blk false;
            },
            .body_contains => self.matchesString(message.body, self.pattern, self.case_sensitive),
            .size_greater => blk: {
                const size_limit = std.fmt.parseInt(usize, self.pattern, 10) catch 0;
                break :blk message.size > size_limit;
            },
            .size_less => blk: {
                const size_limit = std.fmt.parseInt(usize, self.pattern, 10) catch 0;
                break :blk message.size < size_limit;
            },
            .has_attachment => message.has_attachment,
        };
    }

    fn matchesString(_: *const FilterCondition, text: []const u8, pattern: []const u8, case_sensitive: bool) bool {
        if (case_sensitive) {
            return std.mem.indexOf(u8, text, pattern) != null;
        } else {
            // Use our efficient case-insensitive search
            return containsIgnoreCase(text, pattern);
        }
    }
};

/// Filter rule
pub const FilterRule = struct {
    name: []const u8,
    enabled: bool,
    conditions: std.ArrayList(FilterCondition),
    action: FilterAction,
    action_parameter: ?[]const u8, // e.g., forward address, tag name
    priority: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, name: []const u8, action: FilterAction) !FilterRule {
        return .{
            .name = try allocator.dupe(u8, name),
            .enabled = true,
            .conditions = .{},
            .action = action,
            .action_parameter = null,
            .priority = 100,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FilterRule) void {
        self.allocator.free(self.name);
        for (self.conditions.items) |*cond| {
            cond.deinit();
        }
        self.conditions.deinit(self.allocator);
        if (self.action_parameter) |param| {
            self.allocator.free(param);
        }
    }

    pub fn addCondition(
        self: *FilterRule,
        condition_type: FilterConditionType,
        pattern: []const u8,
        case_sensitive: bool,
    ) !void {
        const condition = FilterCondition{
            .condition_type = condition_type,
            .pattern = try self.allocator.dupe(u8, pattern),
            .case_sensitive = case_sensitive,
            .allocator = self.allocator,
        };
        try self.conditions.append(self.allocator, condition);
    }

    pub fn setActionParameter(self: *FilterRule, param: []const u8) !void {
        if (self.action_parameter) |old| {
            self.allocator.free(old);
        }
        self.action_parameter = try self.allocator.dupe(u8, param);
    }

    /// Check if this rule matches a message (all conditions must match)
    pub fn matches(self: *const FilterRule, message: *const Message) bool {
        if (!self.enabled) return false;
        if (self.conditions.items.len == 0) return false;

        // All conditions must match (AND logic)
        for (self.conditions.items) |*cond| {
            if (!cond.matches(message)) {
                return false;
            }
        }

        return true;
    }
};

/// Message representation for filtering
pub const Message = struct {
    from: []const u8,
    to: []const u8,
    subject: []const u8,
    body: []const u8,
    headers: std.StringHashMap([]const u8),
    size: usize,
    has_attachment: bool,
};

/// Message filter engine
pub const FilterEngine = struct {
    allocator: std.mem.Allocator,
    rules: std.ArrayList(*FilterRule),
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) FilterEngine {
        return .{
            .allocator = allocator,
            .rules = .{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *FilterEngine) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.rules.items) |rule| {
            rule.deinit();
            self.allocator.destroy(rule);
        }
        self.rules.deinit(self.allocator);
    }

    /// Add a filter rule
    pub fn addRule(self: *FilterEngine, rule: *FilterRule) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.rules.append(self.allocator, rule);

        // Sort rules by priority (higher priority first)
        std.mem.sort(*FilterRule, self.rules.items, {}, struct {
            fn lessThan(_: void, a: *FilterRule, b: *FilterRule) bool {
                return a.priority > b.priority;
            }
        }.lessThan);
    }

    /// Process a message through all filter rules
    pub fn processMessage(self: *FilterEngine, message: *const Message) ?FilterResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Apply first matching rule
        for (self.rules.items) |rule| {
            if (rule.matches(message)) {
                return FilterResult{
                    .action = rule.action,
                    .action_parameter = rule.action_parameter,
                    .rule_name = rule.name,
                };
            }
        }

        // No rules matched - default action
        return null;
    }

    /// Get all rules
    pub fn getRules(self: *FilterEngine) []*FilterRule {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.rules.items;
    }

    /// Remove a rule by name
    pub fn removeRule(self: *FilterEngine, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.rules.items, 0..) |rule, i| {
            if (std.mem.eql(u8, rule.name, name)) {
                _ = self.rules.swapRemove(i);
                rule.deinit();
                self.allocator.destroy(rule);
                return;
            }
        }

        return error.RuleNotFound;
    }
};

pub const FilterResult = struct {
    action: FilterAction,
    action_parameter: ?[]const u8,
    rule_name: []const u8,
};

test "filter condition matching" {
    const testing = std.testing;

    const condition = FilterCondition{
        .condition_type = .from,
        .pattern = try testing.allocator.dupe(u8, "spam@example.com"),
        .case_sensitive = false,
        .allocator = testing.allocator,
    };
    defer testing.allocator.free(condition.pattern);

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    const message = Message{
        .from = "spam@example.com",
        .to = "user@test.com",
        .subject = "Test",
        .body = "Body",
        .headers = headers,
        .size = 100,
        .has_attachment = false,
    };

    try testing.expect(condition.matches(&message));
}

test "filter rule with multiple conditions" {
    const testing = std.testing;

    var rule = try FilterRule.init(testing.allocator, "spam-filter", .reject);
    defer rule.deinit();

    try rule.addCondition(.from, "spam", false);
    try rule.addCondition(.subject, "urgent", false);

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    const message = Message{
        .from = "spam@example.com",
        .to = "user@test.com",
        .subject = "Urgent: Click here",
        .body = "Body",
        .headers = headers,
        .size = 100,
        .has_attachment = false,
    };

    try testing.expect(rule.matches(&message));
}

test "filter engine rule processing" {
    const testing = std.testing;

    var engine = FilterEngine.init(testing.allocator);
    defer engine.deinit();

    var rule = try testing.allocator.create(FilterRule);
    rule.* = try FilterRule.init(testing.allocator, "test-rule", .reject);
    try rule.addCondition(.from, "spam", false);

    try engine.addRule(rule);

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    const message = Message{
        .from = "spam@example.com",
        .to = "user@test.com",
        .subject = "Test",
        .body = "Body",
        .headers = headers,
        .size = 100,
        .has_attachment = false,
    };

    const result = engine.processMessage(&message);
    try testing.expect(result != null);
    try testing.expect(result.?.action == .reject);
}

// ============================================================================
// Email Categorization Tests
// ============================================================================

test "categorize social email by domain" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    // Facebook notification
    const category1 = categorizeEmail("notification@facebookmail.com", &headers);
    try testing.expectEqual(EmailCategory.social, category1);

    // Twitter notification
    const category2 = categorizeEmail("alerts@twitter.com", &headers);
    try testing.expectEqual(EmailCategory.social, category2);

    // LinkedIn (case insensitive)
    const category3 = categorizeEmail("noreply@LinkedIn.com", &headers);
    try testing.expectEqual(EmailCategory.social, category3);
}

test "categorize forum email by list-id header" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    try headers.put("list-id", "<zig-dev.lists.ziglang.org>");

    // Even with a non-forum domain, list-id header should trigger forums
    const category = categorizeEmail("random@example.com", &headers);
    try testing.expectEqual(EmailCategory.forums, category);
}

test "categorize forum email by list-unsubscribe header" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    try headers.put("list-unsubscribe", "<mailto:unsubscribe@example.com>");

    const category = categorizeEmail("newsletter@example.com", &headers);
    try testing.expectEqual(EmailCategory.forums, category);
}

test "categorize promotional email by x-mailchimp-id header" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    try headers.put("x-mailchimp-id", "abc123xyz");

    const category = categorizeEmail("marketing@somecompany.com", &headers);
    try testing.expectEqual(EmailCategory.promotions, category);
}

test "categorize promotional email by x-campaign header" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    try headers.put("x-campaign", "summer-sale-2024");

    const category = categorizeEmail("deals@shop.com", &headers);
    try testing.expectEqual(EmailCategory.promotions, category);
}

test "categorize updates email by auto-submitted header" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    try headers.put("auto-submitted", "auto-generated");

    const category = categorizeEmail("noreply@service.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category);
}

test "categorize updates email by domain" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    // GitHub - domain takes priority over social substrings
    const category1 = categorizeEmail("hello@github.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category1);

    // Stripe receipt
    const category2 = categorizeEmail("receipt@stripe.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category2);

    // Vercel deployment
    const category3 = categorizeEmail("deploy@vercel.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category3);
}

test "domain priority over substrings - notifications@github.com should be updates not social" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    // This is the key fix: notifications@github.com was previously categorized as social
    // because "notification@" substring matched before github.com domain was checked.
    // Now domains are checked first across ALL categories before substrings.
    const category1 = categorizeEmail("notifications@github.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category1);

    // Similarly for noreply addresses from updates domains
    const category2 = categorizeEmail("noreply@github.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category2);

    // Stripe also uses noreply
    const category3 = categorizeEmail("no-reply@stripe.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category3);

    // Vercel uses notifications
    const category4 = categorizeEmail("notification@vercel.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category4);
}

test "categorize promotional email by domain" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    // Mailchimp
    const category1 = categorizeEmail("campaign@mail.mailchimp.com", &headers);
    try testing.expectEqual(EmailCategory.promotions, category1);

    // Shopify marketing
    const category2 = categorizeEmail("marketing@shopify.com", &headers);
    try testing.expectEqual(EmailCategory.promotions, category2);
}

test "categorize unknown email as primary" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    // Personal email from unknown domain
    const category = categorizeEmail("john.doe@personaldomain.org", &headers);
    try testing.expectEqual(EmailCategory.primary, category);
}

test "email category folder names" {
    const testing = std.testing;

    try testing.expectEqualStrings("INBOX", EmailCategory.primary.getFolderName());
    try testing.expectEqualStrings("Social", EmailCategory.social.getFolderName());
    try testing.expectEqualStrings("Forums", EmailCategory.forums.getFolderName());
    try testing.expectEqualStrings("Updates", EmailCategory.updates.getFolderName());
    try testing.expectEqualStrings("Promotions", EmailCategory.promotions.getFolderName());
}

test "containsIgnoreCase basic functionality" {
    const testing = std.testing;

    try testing.expect(containsIgnoreCase("Hello World", "world"));
    try testing.expect(containsIgnoreCase("HELLO WORLD", "hello"));
    try testing.expect(containsIgnoreCase("notification@FaceBook.com", "facebook"));
    try testing.expect(!containsIgnoreCase("Hello", "World"));
    try testing.expect(containsIgnoreCase("test@list-users@example.com", "-users@"));
}

test "Amazon email categorization - transactional vs promotional" {
    const testing = std.testing;

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    // Amazon transactional emails should go to Updates
    const category1 = categorizeEmail("auto-confirm@amazon.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category1);

    const category2 = categorizeEmail("ship-notify@amazon.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category2);

    const category3 = categorizeEmail("order-update@amazon.com", &headers);
    try testing.expectEqual(EmailCategory.updates, category3);

    // Amazon promotional emails should go to Promotions
    const category4 = categorizeEmail("store-news@amazon.com", &headers);
    try testing.expectEqual(EmailCategory.promotions, category4);

    const category5 = categorizeEmail("kindle-offers@amazon.com", &headers);
    try testing.expectEqual(EmailCategory.promotions, category5);

    // Generic amazon.com should NOT match any specific category anymore
    // (falls through to primary since no substring matches)
    const category6 = categorizeEmail("random@amazon.com", &headers);
    try testing.expectEqual(EmailCategory.primary, category6);
}
