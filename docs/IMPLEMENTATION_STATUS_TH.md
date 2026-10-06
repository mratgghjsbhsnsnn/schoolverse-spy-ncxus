# สถานะสิ่งที่อยู่ใน ZIP

## ทำงานแล้วในโค้ด

- Worker API + Static Assets
- Login / Logout / Register
- PBKDF2 password hashing
- 8 ชั่วโมง session, Secure/HttpOnly/SameSite cookie
- lock หลัง Login ผิด 5 ครั้ง / 15 นาที
- Audit Login / Logout / Action สำคัญ
- D1 schema แบบ relational และ migration
- R2 metadata + streamed binary upload/download
- KV cache helper สำหรับ settings
- Cron session cleanup / assignment reminder / assignment lock / auction close / daily quest reset
- Role: admin / teacher / student / parent
- Parent–Child link และ parent-funded wallet
- Dashboard แยกตาม Role
- Social Feed + moderation + reaction + comment + report
- Class / Class members / Lesson / Lesson progress / Unlock พื้นฐาน
- Assignment / Submission / Grade / Feedback / late penalty
- Quiz: multiple choice, multiple answer, essay, matching, fill blank; attempt limit; auto grading สำหรับประเภทที่ทำได้
- Wallet / transfer / topup request / staff credit / spending limit
- Marketplace / shop approval API / products / orders / escrow / refund / receive
- Auction create / bid / cron settlement
- XP event idempotency
- Level 1–10
- Daily Quest state
- Streak state
- Leaderboard
- Notification center
- Generic Email Provider adapter + EMAIL_LOGS
- Admin user management
- Admin settings
- Admin audit log
- Admin export JSON
- Teacher analytics endpoint พื้นฐาน

## ยังต้องต่อยอดก่อน production โรงเรียนจริง

- Provider จริงสำหรับ Email
- Rate limiting/abuse protection แบบ edge
- Full authorization ของไฟล์ตามความสัมพันธ์ Class/Lesson/Assignment/Submission ทุกกรณี
- Direct R2 multipart/presigned upload สำหรับ video ขนาดใหญ่
- Rich Text editor + HTML sanitization
- Question bank/template UI และ analytics ขั้นสูง
- Badge Rules Engine ที่ประเมินเงื่อนไขอัตโนมัติครบทุก badge
- Season rollover อัตโนมัติครบวงจรและ archive ranking
- Parent UI สำหรับเลือก/เติมเงินลูกจาก Dashboard
- UI จัดการ Parent–Child link
- UI Admin shop moderation ครบทุก action
- UI สำหรับสร้าง Auction และประวัติ Bid
- รายงาน Export CSV/XLSX/PDF
- Payment reconciliation สำหรับเงินจริง
- Malware/file scanning
- Backup/restore automation เต็มรูปแบบ
- Privacy/retention policy และ consent flow สำหรับโรงเรียนจริง

หมายเหตุ: จุดที่อยู่ในหัวข้อ "ยังต้องต่อยอด" เป็นการป้องกันไม่ให้โปรเจกต์ถูกเข้าใจว่าเป็น production-ready ในทันที แม้ architecture หลักจะเตรียมไว้แล้ว
