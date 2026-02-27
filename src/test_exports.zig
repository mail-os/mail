// Re-exports for RFC compliance test modules.
// This file lives in src/ so all relative imports resolve correctly.
pub const dkim_rotation = @import("features/dkim_rotation.zig");
pub const dkim = @import("antispam/dkim.zig");
pub const sieve = @import("features/sieve.zig");
pub const dane = @import("antispam/dane.zig");
pub const mta_sts = @import("antispam/mta_sts.zig");
pub const acme = @import("security/acme.zig");
pub const time_compat = @import("core/time_compat.zig");
pub const tls_rpt = @import("delivery/tls_rpt.zig");
pub const arc = @import("antispam/arc.zig");
pub const bimi = @import("antispam/bimi.zig");
pub const list_unsubscribe = @import("features/list_unsubscribe.zig");
pub const autoconfig = @import("api/autoconfig.zig");
pub const managesieve = @import("protocol/managesieve.zig");
pub const milter = @import("protocol/milter.zig");
pub const caldav_store = @import("storage/caldav_store.zig");
pub const caldav = @import("protocol/caldav.zig");
pub const imap = @import("protocol/imap.zig");
