# API Quick Reference

Base URL: `/api`

## Public
- GET `/health`
- POST `/setup/bootstrap` (one-time, requires `X-Bootstrap-Key`)
- POST `/auth/register`
- POST `/auth/login`
- POST `/auth/logout`
- GET `/auth/me`

## Authenticated
- GET `/dashboard`
- GET `/profile`
- PATCH `/profile`
- POST `/profile/password`
- POST `/files`
- PUT `/files/:fileID/content`
- GET `/files/:fileID/content`
- GET `/feed`
- POST `/posts`
- POST `/posts/:id/approve`
- POST `/posts/:id/reject`
- POST `/posts/:id/report`
- POST `/posts/:id/reaction`
- POST `/posts/:id/comment`
- POST `/posts/:id/delete`
- GET/POST `/classes`
- GET/POST `/classes/:id/members`
- GET/POST `/lessons`
- POST `/lessons/:id/progress`
- GET/POST `/assignments`
- GET/POST `/assignments/:id/submissions`
- POST `/submissions/:id/grade`
- GET/POST `/quizzes`
- GET `/quizzes/:id`
- POST `/quizzes/:id/start`
- POST `/quizzes/:id/submit`
- GET `/wallet`
- PATCH `/wallet/limit`
- POST `/transactions/transfer`
- POST `/topups`
- POST `/topups/:id/approve`
- POST `/topups/:id/reject`
- GET/POST `/shops`
- GET/POST `/products`
- POST `/orders`
- GET `/orders/:id`
- POST `/orders/:id/confirm`
- POST `/orders/:id/reject`
- POST `/orders/:id/ship`
- POST `/orders/:id/receive`
- GET/POST `/auctions`
- POST `/auctions/:id/bid`
- GET `/leaderboard`
- GET `/game-stats`
- GET `/notifications`
- POST `/notifications/read-all`
- POST `/notifications/:id/read`
- POST `/notifications/:id/delete`

## Admin
- GET `/admin/users`
- POST `/admin/users/:id/approve`
- POST `/admin/users/:id/reject`
- POST `/admin/users/:id/suspend`
- POST `/admin/users/:id/unsuspend`
- POST `/admin/users/:id/role`
- POST `/admin/users/:id/reset-password`
- GET/PATCH `/admin/settings`
- GET `/admin/topups`
- GET `/admin/audit-logs`
- GET `/admin/moderation`
- GET/POST `/admin/parent-links`
- POST `/admin/shops/:id/approve`
- POST `/admin/shops/:id/reject`
- POST `/admin/shops/:id/suspend`

## Staff
- POST `/teacher-admin/wallet/credit`

## Parent
- GET `/parent/children`
- POST `/parent/topup-child`
