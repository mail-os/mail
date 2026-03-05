# Message Search API Documentation

## Overview

The SMTP server provides powerful full-text search capabilities using SQLite's FTS5 (Full-Text Search 5) engine. Search functionality is available through both a REST API and a command-line interface.

## Features

- **Full-Text Search (FTS5)**: Fast, relevance-ranked search with Porter stemming and Unicode tokenization
- **Fallback Search**: Automatic fallback to LIKE-based search if FTS5 is unavailable
- **Advanced Filtering**: Filter by sender, folder, date range, attachments, and more
- **Pagination**: Limit and offset support for large result sets
- **Multiple Sort Options**: Sort by received date, relevance, sender, or subject
- **Search Statistics**: Database metrics including message counts, sizes, and index status
- **Index Management**: Rebuild search index on demand

## REST API Endpoints

### 1. Search Messages

**Endpoint:** `GET /api/search`

**Description:** Search email messages using full-text search or filters.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | Yes | Search query (supports FTS5 syntax) |
| `email` | string | No | Filter by email address |
| `folder` | string | No | Filter by folder (default: INBOX) |
| `limit` | integer | No | Maximum results to return (default: 100) |
| `offset` | integer | No | Number of results to skip (default: 0) |
| `from_date` | integer | No | Unix timestamp for start of date range |
| `to_date` | integer | No | Unix timestamp for end of date range |
| `attachments` | boolean | No | Only show messages with attachments (true/false) |

**FTS5 Query Syntax:**

- **Words**: `hello world` (AND by default)
- **Phrases**: `"exact phrase"`
- **OR operator**: `hello OR world`
- **NOT operator**: `hello NOT world`
- **Field-specific**: `sender:john` or `subject:meeting`

**Example Requests:**

```bash
# Basic search
GET /api/search?q=meeting

# Search with filters
GET /api/search?q=invoice&email=user@example.com&limit=50

# Date range search
GET /api/search?q=report&from_date=1698796800&to_date=1701388800

# Messages with attachments
GET /api/search?q=contract&attachments=true

# Field-specific search
GET /api/search?q=sender:john+subject:proposal

# Phrase search
GET /api/search?q="quarterly+report"
```

**Response Format:**

```json
{
  "results": [
    {
      "id": 123,
      "message_id": "<abc123@example.com>",
      "email": "user@example.com",
      "sender": "john@example.com",
      "subject": "Meeting notes",
      "snippet": "...text snippet with search highlights...",
      "received_at": 1698796800,
      "size": 4567,
      "folder": "INBOX",
      "relevance": 0.85
    }
  ],
  "count": 1
}
```

**HTTP Status Codes:**

- `200 OK`: Search successful
- `400 Bad Request`: Missing or invalid query parameter
- `503 Service Unavailable`: Search functionality not enabled

---

### 2. Get Search Statistics

**Endpoint:** `GET /api/search/stats`

**Description:** Retrieve database statistics and search index status.

**Example Request:**

```bash
GET /api/search/stats
```

**Response Format:**

```json
{
  "total_messages": 15234,
  "total_size": 45678901,
  "unique_senders": 523,
  "total_folders": 12,
  "oldest_message": 1609459200,
  "newest_message": 1701388800,
  "fts_enabled": true
}
```

**HTTP Status Codes:**

- `200 OK`: Statistics retrieved successfully
- `503 Service Unavailable`: Search functionality not enabled

---

### 3. Rebuild Search Index

**Endpoint:** `POST /api/search/rebuild`

**Description:** Rebuild the FTS5 search index. This operation may take time for large databases.

**Example Request:**

```bash
POST /api/search/rebuild
```

**Response Format:**

```json
{
  "message": "Search index rebuilt successfully"
}
```

**Error Response:**

```json
{
  "error": "Failed to rebuild index: <error details>"
}
```

**HTTP Status Codes:**

- `200 OK`: Index rebuilt successfully
- `500 Internal Server Error`: Index rebuild failed
- `503 Service Unavailable`: Search functionality not enabled

---

## Command-Line Interface

The `search-cli` tool provides command-line access to search functionality.

### Installation

```bash
zig build
# Binary will be available at: zig-out/bin/search-cli
```

### Usage

```bash
search-cli <command> [options]
```

### Commands

#### 1. search

Search messages using full-text search.

**Syntax:**

```bash
search-cli search <query> [options]
```

**Options:**

- `--email <email>`: Filter by email address
- `--folder <folder>`: Filter by folder
- `--limit <n>`: Limit results (default: 100)
- `--offset <n>`: Skip N results (default: 0)
- `--sort <field>`: Sort by field (received-asc, received-desc, relevance, sender-asc, sender-desc, subject-asc, subject-desc)
- `--from-date <ts>`: Filter from date (Unix timestamp)
- `--to-date <ts>`: Filter to date (Unix timestamp)
- `--attachments`: Only show messages with attachments

**Examples:**

```bash
# Basic search
search-cli search meeting

# Search with exact phrase
search-cli search '"project update"'

# Search in subject only
search-cli search 'subject:invoice'

# Search with filters
search-cli search "urgent OR important" --email user@example.com --attachments

# Sorted by relevance
search-cli search report --sort relevance --limit 10
```

#### 2. sender

Search messages by sender.

**Syntax:**

```bash
search-cli sender <sender> [--limit <n>]
```

**Example:**

```bash
search-cli sender john@example.com --limit 50
```

#### 3. subject

Search messages by subject.

**Syntax:**

```bash
search-cli subject <subject> [--limit <n>]
```

**Example:**

```bash
search-cli subject "invoice" --limit 25
```

#### 4. date-range

Search messages within a date range.

**Syntax:**

```bash
search-cli date-range <from-date> <to-date> [--email <email>]
```

**Example:**

```bash
# Search messages from Nov 1, 2023 to Dec 1, 2023
search-cli date-range 1698796800 1701388800
```

#### 5. stats

Show database statistics and search index status.

**Syntax:**

```bash
search-cli stats
```

**Example Output:**

```
Database Statistics:
═══════════════════════════════════════════════════════════

Total Messages: 15234
Total Size: 45678901 bytes (43.56 MB)
Unique Senders: 523
Total Folders: 12

Oldest Message: 1609459200 (Unix timestamp)
Newest Message: 1701388800 (Unix timestamp)

FTS5 Full-Text Search: ENABLED ✓
```

#### 6. rebuild-index

Rebuild the FTS5 search index.

**Syntax:**

```bash
search-cli rebuild-index
```

**Example:**

```bash
search-cli rebuild-index
# Output: ✓ Index rebuilt successfully
```

---

## Environment Variables

### SMTP_DB_PATH

Path to the SQLite database file.

**Default:** `smtp.db`

**Example:**

```bash
export SMTP_DB_PATH=/var/lib/smtp/messages.db
search-cli search meeting
```

---

## Integration Guide

### Enabling Search in Your Application

To enable search functionality in your SMTP server:

```zig
const std = @import("std");
const database = @import("database.zig");
const search = @import("search.zig");
const api = @import("api.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize database
    var db = try database.Database.init(allocator, "smtp.db");
    defer db.deinit();

    // Initialize search engine
    var search_engine = try search.MessageSearch.init(allocator, &db);
    defer search_engine.deinit();

    // Initialize API server with search support
    var api_server = api.APIServer.init(
        allocator,
        8080,
        &db,
        &auth_backend,
        &message_queue,
        &filter_engine,
        &search_engine,  // Pass search engine
    );

    try api_server.run();
}
```

### Checking FTS5 Availability

FTS5 may not be available in all SQLite builds. The search engine automatically falls back to LIKE-based search if FTS5 is unavailable.

To check FTS5 status:

```bash
search-cli stats
# Look for: "FTS5 Full-Text Search: ENABLED ✓"
```

Or via API:

```bash
curl http://localhost:8080/api/search/stats
# Check: "fts_enabled": true
```

---

## Performance Considerations

### FTS5 vs LIKE-based Search

| Feature | FTS5 | LIKE-based |
|---------|------|------------|
| Speed | Fast (indexed) | Slow (full table scan) |
| Relevance Ranking | Yes | No |
| Porter Stemming | Yes | No |
| Unicode Support | Yes | Limited |
| Query Syntax | Rich | Basic |
| Database Size | +10-20% | No overhead |

### Optimization Tips

1. **Rebuild Index Regularly**: After bulk imports, rebuild the search index:
   ```bash
   search-cli rebuild-index
   ```

2. **Use Pagination**: For large result sets, use `limit` and `offset`:
   ```bash
   GET /api/search?q=report&limit=50&offset=100
   ```

3. **Filter Early**: Use email, folder, or date filters to reduce result sets:
   ```bash
   GET /api/search?q=meeting&email=user@example.com&folder=INBOX
   ```

4. **Leverage FTS5 Syntax**: Use field-specific queries for better performance:
   ```bash
   # Faster
   GET /api/search?q=sender:john

   # Slower (searches all fields)
   GET /api/search?q=john
   ```

---

## Troubleshooting

### Common Issues

#### 1. "Search functionality not enabled" Error

**Problem:** API returns 503 Service Unavailable

**Solution:** Ensure the search engine is initialized and passed to the API server:

```zig
var search_engine = try search.MessageSearch.init(allocator, &db);
var api_server = api.APIServer.init(..., &search_engine);
```

#### 2. No Results Found

**Problem:** Search returns empty results

**Possible Causes:**

- FTS5 index not built: Run `search-cli rebuild-index`
- Query syntax error: Check FTS5 query syntax
- Incorrect filters: Verify email, folder, date parameters

#### 3. FTS5 Not Available

**Problem:** `fts_enabled: false` in stats

**Solution:**

- Ensure SQLite is compiled with FTS5 support
- Check SQLite version: `sqlite3 --version` (requires 3.20.0+)
- Rebuild SQLite with `--enable-fts5` flag

#### 4. Slow Search Performance

**Problem:** Searches take too long

**Solutions:**

- Rebuild the search index: `search-cli rebuild-index`
- Reduce result set with filters
- Use pagination with `limit` parameter
- Check database size and consider archiving old messages

---

## Security Considerations

### Input Validation

- All query parameters are URL-decoded and sanitized
- No raw SQL injection risk (uses prepared statements)
- Unicode characters properly handled

### Access Control

Currently, the search API has no built-in authentication. For production use:

1. **Add Authentication**: Implement authentication middleware
2. **Rate Limiting**: Limit search requests per user/IP
3. **Query Restrictions**: Limit query complexity and result sizes
4. **User Isolation**: Filter results by user/mailbox

**Example Authentication Check:**

```zig
fn handleSearch(self: *APIServer, stream: std.net.Stream, path: []const u8) !void {
    // Check authentication
    const auth_token = self.extractAuthToken(request) orelse {
        try self.send401(stream);
        return;
    };

    const user = try self.auth_backend.validateToken(auth_token);

    // Filter search by user's mailbox
    options.email = user.email;

    // Continue with search...
}
```

---

## Examples

### Example 1: Search Recent Messages

Find all messages from the last 7 days containing "invoice":

```bash
# Calculate timestamps
FROM_DATE=$(date -d '7 days ago' +%s)
TO_DATE=$(date +%s)

# CLI
search-cli search invoice --from-date $FROM_DATE --to-date $TO_DATE

# API
curl "http://localhost:8080/api/search?q=invoice&from_date=$FROM_DATE&to_date=$TO_DATE"
```

### Example 2: Find Messages with Large Attachments

Find messages with attachments from a specific sender:

```bash
# CLI
search-cli sender sales@company.com --attachments

# API
curl "http://localhost:8080/api/search?q=sender:sales@company.com&attachments=true"
```

### Example 3: Search Multiple Folders

Find messages containing "proposal" in multiple folders:

```bash
# Search INBOX
curl "http://localhost:8080/api/search?q=proposal&folder=INBOX"

# Search Sent
curl "http://localhost:8080/api/search?q=proposal&folder=Sent"

# Search Archive
curl "http://localhost:8080/api/search?q=proposal&folder=Archive"
```

### Example 4: Complex Query with Filters

Find urgent messages about projects, excluding spam:

```bash
search-cli search '(urgent OR important) AND subject:project NOT spam' \
  --email user@example.com \
  --folder INBOX \
  --from-date 1698796800 \
  --limit 100 \
  --sort relevance
```

---

## API Client Examples

### cURL

```bash
# Basic search
curl "http://localhost:8080/api/search?q=meeting"

# With filters
curl "http://localhost:8080/api/search?q=invoice&email=user@example.com&limit=50"

# Get statistics
curl "http://localhost:8080/api/search/stats"

# Rebuild index
curl -X POST "http://localhost:8080/api/search/rebuild"
```

### Python

```python
import requests
import urllib.parse

def search_messages(query, email=None, limit=100):
    params = {
        'q': query,
        'limit': limit
    }
    if email:
        params['email'] = email

    response = requests.get(
        'http://localhost:8080/api/search',
        params=params
    )
    response.raise_for_status()
    return response.json()

# Usage
results = search_messages('meeting', email='user@example.com')
print(f"Found {results['count']} messages")

for msg in results['results']:
    print(f"{msg['sender']}: {msg['subject']}")
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

async function searchMessages(query, options = {}) {
    const params = new URLSearchParams({
        q: query,
        limit: options.limit || 100,
        ...options
    });

    const response = await axios.get(
        `http://localhost:8080/api/search?${params}`
    );

    return response.data;
}

// Usage
searchMessages('invoice', { email: 'user@example.com', limit: 50 })
    .then(data => {
        console.log(`Found ${data.count} messages`);
        data.results.forEach(msg => {
            console.log(`${msg.sender}: ${msg.subject}`);
        });
    })
    .catch(error => {
        console.error('Search failed:', error.message);
    });
```

---

## Version History

### v0.19.0 (Current)

- ✅ FTS5 full-text search implementation
- ✅ REST API endpoints
- ✅ Command-line search tool
- ✅ Advanced filtering and sorting
- ✅ URL encoding/decoding
- ✅ Search statistics
- ✅ Index rebuilding

### Future Enhancements

- 🔄 Authentication and authorization
- 🔄 Search result highlighting in snippets
- 🔄 Saved searches and search history
- 🔄 Search suggestions and auto-complete
- 🔄 Export search results (CSV, JSON)
- 🔄 Advanced query builder UI
- 🔄 Search performance metrics

---

## Support

For issues, questions, or feature requests:

- GitHub Issues: https://github.com/yourusername/mail/issues
- Documentation: https://github.com/yourusername/mail/docs
- Email: support@example.com

---

**Last Updated:** 2025-01-24
**Version:** v0.19.0
