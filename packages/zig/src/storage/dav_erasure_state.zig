//! Durable markers and ID high-water marks for offline DAV erasure.

pub const schema =
    \\CREATE TABLE IF NOT EXISTS dav_erasure_receipts (
    \\    nonce TEXT PRIMARY KEY,
    \\    native_user_id INTEGER NOT NULL,
    \\    dav_owner_id INTEGER,
    \\    max_owner INTEGER NOT NULL,
    \\    max_calendar INTEGER NOT NULL,
    \\    max_event INTEGER NOT NULL,
    \\    max_book INTEGER NOT NULL,
    \\    max_contact INTEGER NOT NULL
    \\)
;

pub const watermarks =
    \\SELECT coalesce(max(max_owner),0),coalesce(max(max_calendar),0),
    \\       coalesce(max(max_event),0),coalesce(max(max_book),0),coalesce(max(max_contact),0)
    \\FROM dav_erasure_receipts
;
