# Mail Server - Examples & Developer Tools

Welcome to the examples directory! This folder contains beautiful, production-ready web interfaces for developing, testing, and using your SMTP server.

## 🌟 Quick Start

### 1. Start the Servers

```bash
# Build and run the SMTP server
zig build run
```

### 2. Open the Web Interfaces

**Option A: Direct (if running a web server)**
```bash
# Serve the examples directory
python3 -m http.server 8000

# Then open in browser:
# http://localhost:8000/webmail.html
# http://localhost:8000/helo.html
# http://localhost:8000/websocket_client.html
```

**Option B: Direct File Access**
```bash
# macOS
open webmail.html
open helo.html

# Linux
xdg-open webmail.html
xdg-open helo.html

# Windows
start webmail.html
start helo.html
```

---

## 📧 Webmail Client (`webmail.html`)

A beautiful, full-featured webmail client inspired by Apple Mail.

![Webmail Preview](https://via.placeholder.com/800x400/667eea/ffffff?text=Webmail+Client)

### Features

- ✉️ **Full Email Client**: Send, receive, read, organize emails
- 🎨 **Apple Mail Design**: Beautiful three-pane layout
- 📁 **Folder Management**: Inbox, Sent, Drafts, Trash, Labels
- 🔍 **Real-Time Search**: Instant search across all emails
- 🔔 **Live Notifications**: WebSocket-powered real-time updates
- 🔧 **Built-in Dev Tools**: SMTP test, IMAP monitor, WebSocket viewer
- 💻 **Professional UI**: macOS-inspired interface

### How to Use

1. **Read Emails**
   - Click on any email in the list to read
   - Navigate with keyboard (↑/↓ arrows)
   - Search using the search bar

2. **Compose Email**
   - Click "New Message" button
   - Fill in To, Subject, Message
   - Click "Send"

3. **Developer Tools**
   - Click "Dev Tools" button in toolbar
   - View SMTP/IMAP logs in Console tab
   - Test SMTP in SMTP Test tab
   - Monitor WebSocket events
   - View API documentation

4. **Organize Emails**
   - Click folders in sidebar
   - Delete emails with Delete button
   - Search across all messages

---

## 🧪 Email Testing Dashboard (`helo.html`)

A Helo.com-inspired email testing platform for developers.

![Helo Preview](https://via.placeholder.com/800x400/764ba2/ffffff?text=Email+Testing+Dashboard)

### Features

- 📤 **Quick Email Sending**: Simple and advanced modes
- 📧 **Email Templates**: Pre-built templates for common scenarios
- 📊 **Real-Time Statistics**: Delivery rates, timing, counts
- 🎯 **Bulk Testing**: Send multiple emails at once
- 💾 **Export Logs**: Download all email data as JSON
- ⚡ **Quick Actions**: Common operations at your fingertips
- 🔔 **Live Updates**: WebSocket-powered inbox

### How to Use

1. **Send Simple Email**
   - Go to "Simple" tab
   - Enter To, Subject, Message
   - Click "Send Email"

2. **Send Advanced Email**
   - Go to "Advanced" tab
   - Configure From, CC, BCC, Priority
   - Choose content type (Text/HTML)
   - Send email

3. **Use Templates**
   - Go to "Templates" tab
   - Click on a template:
     - 👋 Welcome
     - 🔒 Password Reset
     - 💰 Invoice
     - 📰 Newsletter
     - ⏰ Reminder
     - 🔔 Notification
   - Customize and send

4. **Test Performance**
   - Click "Send Bulk Emails (10x)"
   - Watch delivery statistics update
   - Monitor average delivery time
   - Check inbox for all emails

5. **Monitor & Export**
   - View statistics in top cards
   - Check inbox for received emails
   - Click "Export Logs" to download JSON

---

## 🔔 WebSocket Notifications (`websocket_client.html`)

Real-time notification testing interface.

### Features

- 🌐 **Live Connection**: WebSocket connection status
- 📬 **Event Subscriptions**: Subscribe to specific events
- 📊 **Statistics Dashboard**: Track all events
- 🔔 **Desktop Notifications**: Browser notifications
- 🎨 **Color-Coded Events**: Visual event categorization

### How to Use

1. Click "Connect" to establish WebSocket connection
2. Subscribe to events:
   - 📧 New Email
   - 📅 Calendar Events
   - 👤 Contacts
   - 🔄 Sync Status
   - ✨ All Events
3. Watch live events appear in the feed
4. Monitor statistics in the cards

---

## 🎮 Integration Examples

### All Protocols Demo (`all_protocols.zig`)

Shows how all protocols work together:

```bash
zig run examples/all_protocols.zig
```

Demonstrates:
- SMTP for sending/receiving
- IMAP for email access
- POP3 for simple retrieval
- CalDAV for calendars
- CardDAV for contacts
- ActiveSync for mobile sync
- WebSocket for notifications

### WebSocket Integration (`websocket_integration.zig`)

Shows real-time notification flow:

```bash
zig run examples/websocket_integration.zig
```

Demonstrates:
- WebSocket handshake
- Event subscriptions
- Notification broadcasting
- Client/server integration

### Plugin Example (`plugins/hello_world.zig`)

Example plugin implementation:

```bash
# Build plugin
zig build-lib examples/plugins/hello_world.zig -dynamic --name hello_world

# Load in server
./mail --plugin-dir ./zig-out/lib
```

---

## 🔥 Features Comparison

| Feature | Webmail | Helo Dashboard | WebSocket Client |
|---------|---------|----------------|------------------|
| Send Email | ✅ | ✅ | ❌ |
| Receive Email | ✅ | ✅ | ❌ |
| Email Templates | ❌ | ✅ | ❌ |
| Dev Tools | ✅ | ❌ | ❌ |
| Real-time Updates | ✅ | ✅ | ✅ |
| Bulk Testing | ❌ | ✅ | ❌ |
| Export Logs | ❌ | ✅ | ❌ |
| SMTP Test | ✅ | ✅ | ❌ |
| IMAP Monitor | ✅ | ❌ | ❌ |
| Statistics | ❌ | ✅ | ✅ |
| Apple Mail UI | ✅ | ❌ | ❌ |

---

## 💡 Use Cases

### Development

**Use Webmail:**
- Full email client for development
- Test complete email workflows
- Debug SMTP/IMAP interactions
- Monitor real-time events

**Use Helo Dashboard:**
- Quick email testing
- Template-based sending
- Performance testing
- Bulk email scenarios

### Testing

**Use Webmail:**
- End-to-end email testing
- UI/UX testing
- Integration testing
- Real-world simulation

**Use Helo Dashboard:**
- Unit testing email sends
- Template validation
- Load testing (bulk sends)
- Delivery time monitoring

### Debugging

**Use Webmail:**
- Open Dev Tools console
- Watch SMTP commands
- Monitor IMAP operations
- Track WebSocket events

**Use Helo Dashboard:**
- Check delivery statistics
- Monitor success rates
- Export logs for analysis
- Quick smoke tests

---

## 🎨 Customization

### Webmail Client

**Change Theme:**
Edit the CSS variables in `webmail.html`:
```css
/* Line ~15 */
:root {
    --primary-color: #007aff;
    --background: #f5f5f7;
    --text-color: #1d1d1f;
}
```

**Add Custom Folders:**
Edit the sidebar section around line ~150:
```html
<div class="sidebar-item" onclick="selectFolder('custom')">
    <span>📂</span>
    <span>Custom Folder</span>
</div>
```

### Helo Dashboard

**Add Custom Template:**
Edit the `templates` object around line ~650:
```javascript
templates.custom = {
    subject: 'Custom Template',
    body: 'Your custom email content here'
};
```

**Modify Statistics:**
Edit the `stats` object around line ~40:
```javascript
let stats = {
    sent: 0,
    received: 0,
    deliveryRate: 100,
    avgTime: 0,
    customMetric: 0  // Add your own
};
```

---

## 🐛 Troubleshooting

### Webmail Won't Connect

1. Check WebSocket server is running on port 8080
2. Open browser console (F12) for errors
3. Verify server address in JavaScript:
   ```javascript
   // Line ~150 in webmail.html
   ws = new WebSocket('ws://localhost:8080/notifications');
   ```

### Emails Not Sending

1. Check SMTP server is running on port 25/587
2. Open Dev Tools to see SMTP errors
3. Verify recipient address format
4. Check server logs

### Templates Not Loading

1. Clear browser cache
2. Check JavaScript console for errors
3. Verify template definitions in code
4. Refresh page

### Dev Tools Not Opening

1. Click "Dev Tools" button in toolbar
2. Check if panel is minimized (look at bottom)
3. Refresh page if panel is stuck
4. Clear browser cache

---

## 📚 Further Reading

- [Developer Experience Guide](../docs/DEVELOPER_EXPERIENCE.md)
- [WebSocket Notifications](../docs/WEBSOCKET_NOTIFICATIONS.md)
- [IMAP/POP3 Guide](../docs/IMAP_POP3.md)
- [CalDAV/CardDAV/ActiveSync](../docs/CALDAV_CARDDAV_ACTIVESYNC.md)

---

## 🤝 Contributing

Found a bug or have a feature request?
1. Open an issue
2. Submit a pull request
3. Share your customizations!

---

## 📝 License

Same as the main Mail Server project.

---

**Enjoy testing your emails!** 🚀
