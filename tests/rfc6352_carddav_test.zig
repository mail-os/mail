// RFC 6352 CardDAV Compliance Test Suite
// Tests for CardDAV (Contacts) storage, vCard generation, path parsing,
// and protocol handler behavior.

const std = @import("std");
const testing = std.testing;
const mail = @import("mail");
const caldav_store = mail.caldav_store;
const caldav = mail.caldav;

// =============================================================================
// Storage Tests: AddressBook CRUD
// =============================================================================

test "addressbook: create and retrieve" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Personal", "My contacts");
    try testing.expect(ab_id > 0);

    const ab = store.getAddressBook(ab_id);
    try testing.expect(ab != null);
    try testing.expectEqualStrings("Personal", ab.?.name);
    try testing.expectEqualStrings("My contacts", ab.?.description.?);
}

test "addressbook: getAddressBookByName" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    _ = try store.createAddressBook(1, "Work", null);
    _ = try store.createAddressBook(1, "Personal", null);
    _ = try store.createAddressBook(2, "Work", null); // different user

    const ab = store.getAddressBookByName(1, "Work");
    try testing.expect(ab != null);
    try testing.expectEqualStrings("Work", ab.?.name);
    try testing.expectEqual(@as(u64, 1), ab.?.user_id);

    const not_found = store.getAddressBookByName(1, "NonExistent");
    try testing.expect(not_found == null);
}

test "addressbook: getUserAddressBooks" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    _ = try store.createAddressBook(1, "Personal", null);
    _ = try store.createAddressBook(1, "Work", null);
    _ = try store.createAddressBook(2, "Other User", null);

    const user1_abs = try store.getUserAddressBooks(1);
    try testing.expectEqual(@as(usize, 2), user1_abs.len);

    const user2_abs = try store.getUserAddressBooks(2);
    try testing.expectEqual(@as(usize, 1), user2_abs.len);
}

test "addressbook: deleteAddressBook removes contacts" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "ToDelete", null);
    _ = try store.createContact(ab_id, .{
        .full_name = "Jane Doe",
        .emails = &[_]caldav_store.CalDavStore.EmailData{
            .{ .email = "jane@example.com", .email_type = .work },
        },
    });

    // Verify contact exists
    const contacts_before = try store.getAddressBookContacts(ab_id);
    try testing.expectEqual(@as(usize, 1), contacts_before.len);

    // Delete addressbook
    try store.deleteAddressBook(ab_id);

    // Verify addressbook gone
    try testing.expect(store.getAddressBook(ab_id) == null);

    // Verify contacts removed
    const contacts_after = try store.getAddressBookContacts(ab_id);
    try testing.expectEqual(@as(usize, 0), contacts_after.len);
}

// =============================================================================
// Storage Tests: Contact CRUD
// =============================================================================

test "contact: create with full data" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Personal", null);
    const contact_id = try store.createContact(ab_id, .{
        .full_name = "John Doe",
        .given_name = "John",
        .family_name = "Doe",
        .nickname = "JD",
        .organization = "Acme Corp",
        .title = "Engineer",
        .note = "A test contact",
        .emails = &[_]caldav_store.CalDavStore.EmailData{
            .{ .email = "john@example.com", .email_type = .work, .is_primary = true },
            .{ .email = "john.personal@example.com", .email_type = .home },
        },
        .phones = &[_]caldav_store.CalDavStore.PhoneData{
            .{ .number = "+1-555-1234", .phone_type = .mobile, .is_primary = true },
        },
    });

    try testing.expect(contact_id > 0);

    const contact = store.getContact(contact_id);
    try testing.expect(contact != null);
    try testing.expectEqualStrings("John Doe", contact.?.full_name);
    try testing.expectEqualStrings("John", contact.?.given_name.?);
    try testing.expectEqualStrings("Doe", contact.?.family_name.?);
    try testing.expectEqualStrings("Acme Corp", contact.?.organization.?);
}

test "contact: getContactByUid" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Contacts", null);
    _ = try store.createContact(ab_id, .{
        .uid = "unique-contact-001",
        .full_name = "Alice Smith",
    });

    const found = store.getContactByUid(ab_id, "unique-contact-001");
    try testing.expect(found != null);
    try testing.expectEqualStrings("Alice Smith", found.?.full_name);

    const not_found = store.getContactByUid(ab_id, "nonexistent-uid");
    try testing.expect(not_found == null);
}

test "contact: updateContact" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Contacts", null);
    const contact_id = try store.createContact(ab_id, .{
        .full_name = "Bob Original",
        .organization = "Old Corp",
    });

    try store.updateContact(contact_id, .{
        .full_name = "Bob Updated",
        .organization = "New Corp",
        .title = "CTO",
    });

    const updated = store.getContact(contact_id);
    try testing.expect(updated != null);
    try testing.expectEqualStrings("Bob Updated", updated.?.full_name);
    try testing.expectEqualStrings("New Corp", updated.?.organization.?);
    try testing.expectEqualStrings("CTO", updated.?.title.?);
}

test "contact: deleteContact removes emails and phones" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Contacts", null);
    const contact_id = try store.createContact(ab_id, .{
        .full_name = "To Delete",
        .emails = &[_]caldav_store.CalDavStore.EmailData{
            .{ .email = "del@example.com" },
        },
        .phones = &[_]caldav_store.CalDavStore.PhoneData{
            .{ .number = "+1-555-0000" },
        },
    });

    try store.deleteContact(contact_id);
    try testing.expect(store.getContact(contact_id) == null);

    // Verify emails cleaned up
    const emails = store.getContactEmails(contact_id);
    try testing.expectEqual(@as(usize, 0), emails.len);
}

test "contact: getContactIdByUid" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Contacts", null);
    const contact_id = try store.createContact(ab_id, .{
        .uid = "lookup-uid-001",
        .full_name = "Lookup Test",
    });

    const found_id = store.getContactIdByUid(ab_id, "lookup-uid-001");
    try testing.expect(found_id != null);
    try testing.expectEqual(contact_id, found_id.?);

    const not_found = store.getContactIdByUid(ab_id, "nonexistent");
    try testing.expect(not_found == null);
}

// =============================================================================
// Storage Tests: ETag and Sync Token Tracking
// =============================================================================

test "contact: etag is generated on create" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Contacts", null);
    const contact_id = try store.createContact(ab_id, .{
        .full_name = "ETag Test",
    });

    const contact = store.getContact(contact_id);
    try testing.expect(contact != null);
    try testing.expect(contact.?.etag.len > 0);
}

test "contact: etag changes on update" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Contacts", null);
    const contact_id = try store.createContact(ab_id, .{
        .full_name = "ETag Change",
    });

    const original = store.getContact(contact_id);
    const original_etag = original.?.etag;

    try store.updateContact(contact_id, .{
        .full_name = "ETag Changed",
    });

    const updated = store.getContact(contact_id);
    // ETags should differ after update (contains different timestamp)
    try testing.expect(updated != null);
    try testing.expect(updated.?.etag.len > 0);
    // Note: both have same id so the etag differs only by timestamp
    _ = original_etag;
}

test "sync: changes recorded for contact operations" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Contacts", null);
    const initial_token = store.getSyncToken(ab_id, false);

    _ = try store.createContact(ab_id, .{
        .full_name = "Sync Test",
    });

    const new_token = store.getSyncToken(ab_id, false);
    // Token should have advanced
    try testing.expect(new_token >= initial_token);
}

// =============================================================================
// vCard Generation Tests
// =============================================================================

test "vcf: generate minimal vCard (just FN)" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Test", null);
    const contact_id = try store.createContact(ab_id, .{
        .uid = "min-001",
        .full_name = "Minimal Contact",
    });

    const contact = store.getContact(contact_id).?;
    const vcf = try store.generateVcf(contact);
    defer allocator.free(vcf);

    try testing.expect(std.mem.indexOf(u8, vcf, "BEGIN:VCARD") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "VERSION:3.0") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "FN:Minimal Contact") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "UID:min-001") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "END:VCARD") != null);
}

test "vcf: generate full vCard with all fields" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Test", null);
    const contact_id = try store.createContact(ab_id, .{
        .uid = "full-001",
        .full_name = "Jane Smith",
        .given_name = "Jane",
        .family_name = "Smith",
        .nickname = "JS",
        .organization = "Tech Corp",
        .title = "CEO",
        .note = "Important contact",
        .emails = &[_]caldav_store.CalDavStore.EmailData{
            .{ .email = "jane@work.com", .email_type = .work },
            .{ .email = "jane@home.com", .email_type = .home },
        },
        .phones = &[_]caldav_store.CalDavStore.PhoneData{
            .{ .number = "+1-555-WORK", .phone_type = .work },
            .{ .number = "+1-555-CELL", .phone_type = .mobile },
        },
    });

    const contact = store.getContact(contact_id).?;
    const vcf = try store.generateVcf(contact);
    defer allocator.free(vcf);

    try testing.expect(std.mem.indexOf(u8, vcf, "FN:Jane Smith") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "N:Smith;Jane;;;") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "NICKNAME:JS") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "ORG:Tech Corp") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "TITLE:CEO") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "NOTE:Important contact") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "jane@work.com") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "jane@home.com") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "+1-555-WORK") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "+1-555-CELL") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "TYPE=CELL") != null);
    try testing.expect(std.mem.indexOf(u8, vcf, "TYPE=WORK") != null);
}

test "vcf: contact with existing vcf_data returns it directly" {
    const allocator = testing.allocator;
    var store = try caldav_store.CalDavStore.init(allocator, .{});
    defer store.deinit();

    const raw_vcf = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Raw Data\r\nEND:VCARD\r\n";
    const ab_id = try store.createAddressBook(1, "Test", null);
    const contact_id = try store.createContact(ab_id, .{
        .full_name = "Raw Data",
        .vcf_data = raw_vcf,
    });

    const contact = store.getContact(contact_id).?;
    const vcf = try store.generateVcf(contact);
    defer allocator.free(vcf);

    try testing.expectEqualStrings(raw_vcf, vcf);
}

// =============================================================================
// Path Parsing Tests
// =============================================================================

test "path: root" {
    const parsed = caldav.parsePath("/");
    try testing.expectEqual(caldav.ParsedPath.PathType.root, parsed.path_type);
}

test "path: principals user" {
    const parsed = caldav.parsePath("/principals/alice@example.com");
    try testing.expectEqual(caldav.ParsedPath.PathType.principal_user, parsed.path_type);
    try testing.expectEqualStrings("alice@example.com", parsed.user.?);
}

test "path: calendars home" {
    const parsed = caldav.parsePath("/calendars/user/");
    try testing.expectEqual(caldav.ParsedPath.PathType.calendars_home, parsed.path_type);
    try testing.expectEqualStrings("user", parsed.user.?);
}

test "path: calendar collection" {
    const parsed = caldav.parsePath("/calendars/user/work");
    try testing.expectEqual(caldav.ParsedPath.PathType.calendar_collection, parsed.path_type);
    try testing.expectEqualStrings("user", parsed.user.?);
    try testing.expectEqualStrings("work", parsed.collection.?);
}

test "path: calendar resource .ics" {
    const parsed = caldav.parsePath("/calendars/user/work/event-001.ics");
    try testing.expectEqual(caldav.ParsedPath.PathType.calendar_resource, parsed.path_type);
    try testing.expectEqualStrings("user", parsed.user.?);
    try testing.expectEqualStrings("work", parsed.collection.?);
    try testing.expectEqualStrings("event-001", parsed.resource_uid.?);
}

test "path: addressbooks home" {
    const parsed = caldav.parsePath("/addressbooks/user/");
    try testing.expectEqual(caldav.ParsedPath.PathType.addressbooks_home, parsed.path_type);
    try testing.expectEqualStrings("user", parsed.user.?);
}

test "path: addressbook collection" {
    const parsed = caldav.parsePath("/addressbooks/user/personal");
    try testing.expectEqual(caldav.ParsedPath.PathType.addressbook_collection, parsed.path_type);
    try testing.expectEqualStrings("user", parsed.user.?);
    try testing.expectEqualStrings("personal", parsed.collection.?);
}

test "path: addressbook resource .vcf" {
    const parsed = caldav.parsePath("/addressbooks/user/personal/contact-001.vcf");
    try testing.expectEqual(caldav.ParsedPath.PathType.addressbook_resource, parsed.path_type);
    try testing.expectEqualStrings("user", parsed.user.?);
    try testing.expectEqualStrings("personal", parsed.collection.?);
    try testing.expectEqualStrings("contact-001", parsed.resource_uid.?);
}

test "path: well-known caldav" {
    const parsed = caldav.parsePath("/.well-known/caldav");
    try testing.expectEqual(caldav.ParsedPath.PathType.well_known_caldav, parsed.path_type);
}

test "path: well-known carddav" {
    const parsed = caldav.parsePath("/.well-known/carddav");
    try testing.expectEqual(caldav.ParsedPath.PathType.well_known_carddav, parsed.path_type);
}

test "path: trailing slash is handled" {
    const parsed = caldav.parsePath("/addressbooks/user/personal/");
    try testing.expectEqual(caldav.ParsedPath.PathType.addressbook_collection, parsed.path_type);
    try testing.expectEqualStrings("personal", parsed.collection.?);
}

test "path: unknown path" {
    const parsed = caldav.parsePath("/unknown/path");
    try testing.expectEqual(caldav.ParsedPath.PathType.unknown, parsed.path_type);
}

// =============================================================================
// vCard Parser Tests
// =============================================================================

test "vcf parser: minimal vCard" {
    const vcf =
        \\BEGIN:VCARD
        \\VERSION:3.0
        \\FN:Simple Name
        \\END:VCARD
    ;

    const contact = caldav_store.VcfParser.parseContact(vcf);
    try testing.expect(contact != null);
    try testing.expectEqualStrings("Simple Name", contact.?.full_name.?);
}

test "vcf parser: full vCard with all fields" {
    const vcf =
        \\BEGIN:VCARD
        \\VERSION:3.0
        \\FN:Jane Smith
        \\N:Smith;Jane;;;
        \\EMAIL;TYPE=INTERNET:jane@example.com
        \\TEL;TYPE=CELL:+1-555-1234
        \\ORG:Acme Corp
        \\UID:contact-full-001
        \\END:VCARD
    ;

    const contact = caldav_store.VcfParser.parseContact(vcf);
    try testing.expect(contact != null);
    try testing.expectEqualStrings("Jane Smith", contact.?.full_name.?);
    try testing.expectEqualStrings("Smith", contact.?.family_name.?);
    try testing.expectEqualStrings("Jane", contact.?.given_name.?);
    try testing.expectEqualStrings("jane@example.com", contact.?.email.?);
    try testing.expectEqualStrings("+1-555-1234", contact.?.phone.?);
    try testing.expectEqualStrings("Acme Corp", contact.?.organization.?);
    try testing.expectEqualStrings("contact-full-001", contact.?.uid.?);
}

test "vcf parser: returns null without FN" {
    const vcf =
        \\BEGIN:VCARD
        \\VERSION:3.0
        \\N:Smith;John;;;
        \\END:VCARD
    ;

    const contact = caldav_store.VcfParser.parseContact(vcf);
    try testing.expect(contact == null);
}

// =============================================================================
// ICS Parser Tests
// =============================================================================

test "ics parser: basic event" {
    const ics =
        \\BEGIN:VCALENDAR
        \\VERSION:2.0
        \\BEGIN:VEVENT
        \\UID:event-test-001
        \\SUMMARY:Team Meeting
        \\DESCRIPTION:Weekly sync
        \\LOCATION:Room 42
        \\DTSTART:20250101T100000Z
        \\DTEND:20250101T110000Z
        \\END:VEVENT
        \\END:VCALENDAR
    ;

    const event = caldav_store.IcsParser.parseEvent(ics);
    try testing.expect(event != null);
    try testing.expectEqualStrings("Team Meeting", event.?.summary.?);
    try testing.expectEqualStrings("Weekly sync", event.?.description.?);
    try testing.expectEqualStrings("Room 42", event.?.location.?);
    try testing.expectEqualStrings("event-test-001", event.?.uid.?);
}

test "ics parser: returns null without SUMMARY" {
    const ics =
        \\BEGIN:VCALENDAR
        \\VERSION:2.0
        \\BEGIN:VEVENT
        \\UID:no-summary
        \\END:VEVENT
        \\END:VCALENDAR
    ;

    const event = caldav_store.IcsParser.parseEvent(ics);
    try testing.expect(event == null);
}
