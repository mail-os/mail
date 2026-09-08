# MIME corpus fixtures

Five real messages, copied byte-for-byte from [postal-mime](https://github.com/postalsys/postal-mime)'s
`test/fixtures`. They are redistributed here under postal-mime's **MIT-0** license, which
places no conditions on redistribution.

| File | What it covers |
| --- | --- |
| `arf.eml` | An RFC 5965 abuse report, with a `message/rfc822` original nested inside |
| `bounce.eml` | A delivery status notification: `multipart/report` plus the returned message |
| `calendar-event.eml` | A Google Calendar invite — `text/calendar`, encoded-word subject, 44 KB |
| `mimetorture.eml` | Ryan Finnie's MIME Torture Test: deeply nested and deliberately awkward |
| `mixed.eml` | A small `multipart/mixed`, the ordinary case |

They cover shapes that are tedious and error-prone to write by hand, which is why the
parity tests read real messages rather than only generated ones.

## Why these are committed despite `*.eml` being ignored

The repo ignores `*.eml` to keep scratch and runtime mail out of git. This directory is
negated in `.gitignore` because the parity tests and the benchmarks read these files at
module load and cannot run without them — when they went missing, CI failed with a bare
`ENOENT` on a path while every local run stayed green.

Verify a fixture still matches upstream with:

```bash
shasum -a 256 arf.eml && curl -sL https://raw.githubusercontent.com/postalsys/postal-mime/master/test/fixtures/arf.eml | shasum -a 256
```
