# SchoolVerse Architecture

## Request flow
Browser -> Workers Static Assets / Worker API -> D1 / R2 / KV

## Trust boundaries
1. Browser is untrusted.
2. Worker authenticates every protected API.
3. Secrets exist only in Workers environment / secrets.
4. D1 stores relational metadata and transaction ledger.
5. R2 stores binary objects only.
6. KV is cache, never the source of truth for balances, permissions, grades, or audit logs.

## Money safety
Balance-changing operations use D1 `batch()` so the statements commit atomically. Do not move money by calling multiple independent requests from the browser.

## File safety
The browser requests a file record, receives a fileID, then uploads bytes with `PUT /api/files/:fileID/content`. The Worker checks ownership, streams bytes to R2, and marks metadata `ready`. Downloads go through `GET /api/files/:fileID/content` so private objects do not need to be public.

## Scaling notes
- Cache dashboards/settings through KV only where staleness is acceptable.
- Paginate feeds, comments, transactions and logs.
- Add rate limiting at the edge for login, upload, top-up, and transaction endpoints.
- For high-volume video, consider direct R2 multipart/presigned uploads and a queue for post-processing.
