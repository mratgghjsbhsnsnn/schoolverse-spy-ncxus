# คู่มือตั้งค่า SchoolVerse — SPY Ncxus แบบละเอียด

เอกสารนี้เป็นลำดับตั้งแต่ศูนย์จนเปิดเว็บใช้งานบน Cloudflare

## 0. สิ่งที่ต้องมี

- บัญชี Cloudflare
- Node.js รุ่นปัจจุบัน
- คอมพิวเตอร์หรือ Android ที่เปิด terminal/Termux ได้
- Domain ไม่จำเป็น เพราะใช้ `workers.dev` ก่อนก็ได้

โปรเจกต์นี้ใช้ Workers Static Assets เพื่อเสิร์ฟ HTML/CSS/JS และ Worker ตัวเดียวเป็น API โดยตั้ง `/api/*` ให้เข้า Worker ก่อน ส่วน asset ปกติให้ Cloudflare เสิร์ฟตรงได้

## 1. ติดตั้งโปรเจกต์

เปิดโฟลเดอร์นี้ใน terminal แล้วรัน

```bash
npm install
```

ล็อกอิน Cloudflare

```bash
npx wrangler login
```

ตรวจสอบบัญชี

```bash
npx wrangler whoami
```

## 2. ตั้ง Secret สำคัญ

สร้างค่าแบบสุ่มยาว ๆ สำหรับ bootstrap และ pepper

```bash
npx wrangler secret put BOOTSTRAP_KEY
npx wrangler secret put SESSION_PEPPER
```

สำหรับ `BOOTSTRAP_KEY` ใช้ครั้งแรกเท่านั้นเพื่อสร้าง Admin คนแรก

ห้ามใส่ Secret ไว้ใน `public/app.js`, `wrangler.jsonc` หรือ Git

## 3. Deploy ครั้งแรกเพื่อให้ Cloudflare สร้าง Resources

ใน `wrangler.jsonc` มีการประกาศ binding สำหรับ

- D1: `DB`
- R2: `FILES`
- KV: `CACHE`
- Assets: `ASSETS`

Wrangler รุ่นปัจจุบันรองรับ automatic provisioning ของ resource หลายชนิด รวมถึง D1, R2 และ KV เมื่อ configuration ยังไม่มี resource ID ดังนั้นการ deploy ครั้งแรกสามารถเป็นขั้นสร้าง resource ได้

รัน

```bash
npx wrangler deploy
```

จบแล้ว Wrangler จะแสดง URL ของ Worker เช่น

```text
https://schoolverse-spy-ncxus.<subdomain>.workers.dev
```

เก็บ URL นี้ไว้

## 4. Apply D1 migration

หลัง resource ถูกสร้างแล้ว ให้ apply schema ไปยัง D1 production

```bash
npx wrangler d1 migrations apply DB --remote
```

ตรวจสอบตาราง

```bash
npx wrangler d1 execute DB --remote --command="SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

ควรเห็น USERS, SESSIONS, FILES, POSTS, WALLETS, TRANSACTIONS และตารางอื่น ๆ ตาม `migrations/0001_initial.sql`

> D1 แยก local กับ remote การใช้ `--local` จะไม่ใส่ข้อมูลลง production

## 5. สร้าง Admin คนแรก

ยังไม่มีหน้า Admin สร้างตัวเองในระบบ จึงใช้ bootstrap endpoint เพียงครั้งแรก

ตัวอย่าง

```bash
curl -X POST "https://YOUR-WORKER.workers.dev/api/setup/bootstrap" \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Key: YOUR_BOOTSTRAP_KEY" \
  -d '{
    "firstName":"System",
    "lastName":"Admin",
    "email":"admin@example.com",
    "password":"เปลี่ยนรหัสนี้ทันที"
  }'
```

สำเร็จแล้วจะได้ `userID`

Bootstrap จะถูกปิดทันทีเมื่อพบว่ามี Admin อยู่แล้ว

หลังสร้าง Admin เสร็จ ไม่ต้องเรียก endpoint นี้อีก

## 6. เปิดเว็บไซต์

เปิด Worker URL ใน browser

```text
https://YOUR-WORKER.workers.dev
```

เข้าสู่ระบบด้วย Admin ที่สร้างไว้

## 7. สมัครผู้ใช้

หน้าเว็บรองรับ

- นักเรียน
- ครู
- ผู้ปกครอง

บัญชีใหม่เข้าสถานะ `pending` และยัง Login ไม่ได้จนกว่า Admin อนุมัติ

เพื่อความปลอดภัย ระบบไม่อนุญาตให้ผู้ใช้ทั่วไปสมัครเป็น `admin`

## 8. อนุมัติบัญชี

เข้า Admin → ผู้ใช้รออนุมัติ → Approve

หลัง Approve ผู้ใช้จึง Login ได้

## 9. สร้างห้อง/วิชา

ครูหรือ Admin สามารถสร้าง Class จากหน้า การเรียน

ฟิลด์หลัก

- ชื่อห้อง
- ชื่อวิชา
- ระดับชั้น
- ห้อง
- ปีการศึกษา
- เทอม

ระบบสร้าง Join Code ให้ด้วย

## 10. เพิ่มนักเรียนเข้าวิชา

API ที่ใช้

```http
POST /api/classes/:classID/members
```

Body

```json
{
  "userID": "usr_xxx"
}
```

ผู้ส่งต้องเป็นครูประจำวิชาหรือ Admin

## 11. อัปโหลดไฟล์เข้า R2

การออกแบบไม่ส่ง Binary ลง D1

ขั้นตอนคือ

1. `POST /api/files` เพื่อสร้าง metadata
2. Worker สร้าง `fileID` และ `r2Key`
3. Browser ส่ง Binary ด้วย `PUT /api/files/:fileID/content`
4. Worker stream Binary เข้า R2
5. D1 เปลี่ยนสถานะไฟล์เป็น `ready`

ตัวอย่าง metadata

```json
{
  "originalName":"assignment.pdf",
  "mimeType":"application/pdf",
  "category":"assignment",
  "visibility":"private"
}
```

ใน UI การ Upload ใช้ `fetch()` ส่งตัว File ตรงเป็น request body จึงไม่เอาไฟล์ไป encode เป็น Base64

## 12. เรื่องรูปภาพและวิดีโอ

รูป, PDF และไฟล์แนบใช้ R2 ได้โดยตรง

วิดีโอสามารถส่งเข้า R2 ได้เช่นเดียวกัน แต่สำหรับระบบโรงเรียนจริง แนะนำให้ตั้ง policy ขนาดไฟล์และอายุของไฟล์ก่อน เพราะวิดีโอใช้พื้นที่และ bandwidth สูงกว่าไฟล์เอกสาร

ค่าเริ่มต้นในโปรเจกต์นี้คือ `MAX_UPLOAD_MB=100`

เปลี่ยนได้ใน `wrangler.jsonc`

สำหรับระบบขนาดใหญ่ สามารถต่อยอดเป็น direct R2 upload/presigned URL เพื่อให้ Worker ไม่ต้องรับ byte ทั้งก้อนเอง

## 13. ตั้ง Email Provider

โค้ดแยก Email Provider ออกจากระบบ Authentication แล้ว

ตั้ง

```bash
npx wrangler secret put EMAIL_PROVIDER_TOKEN
```

แล้วแก้ `EMAIL_PROVIDER_URL` และ `EMAIL_FROM` ใน `wrangler.jsonc`

Contract ที่ Worker คาดหวังคือ HTTP POST JSON รูปแบบใกล้เคียง

```json
{
  "from":"SchoolVerse <no-reply@example.com>",
  "to":"user@example.com",
  "subject":"คะแนนออกแล้ว",
  "html":"<p>...</p>",
  "text":"คะแนนออกแล้ว"
}
```

ผู้ให้บริการแต่ละรายใช้ API ต่างกัน จึงควรปรับฟังก์ชัน `sendEmail` ใน `src/index.js` ให้ตรง provider ที่เลือกก่อนเปิดใช้งานจริง

## 14. Local Development

Apply local migration

```bash
npx wrangler d1 migrations apply DB --local
```

แล้ว

```bash
npx wrangler dev
```

ระบบ local จะจำลอง D1/R2/KV ใน `.wrangler/state`

ถ้าต้องการทดสอบกับ production resource แบบ remote bindings ให้ใช้โหมด remote ตามความเหมาะสม และอย่าผูกการทดสอบที่มีข้อมูลจริงกับขั้นตอนพัฒนาโดยไม่ตั้งใจ

## 15. การตั้งค่า XP

Admin ใช้ API

```http
PATCH /api/admin/settings
```

ตัวอย่าง

```json
{
  "transactionLimitTHB":5000,
  "xp":{
    "login":5,
    "lesson_complete":20,
    "assignment_on_time":30,
    "assignment_late":10,
    "quiz_attempt":15,
    "quiz_over_80":25,
    "post_approved":10,
    "review":5,
    "reaction_received":2
  }
}
```

## 16. การเงิน

หลักการสำคัญ

- Browser ห้ามแก้ balance ตรง ๆ
- Worker เป็นผู้ตรวจสิทธิ์และยอดเงิน
- D1 เป็น source of truth
- Transfer ใช้ `DB.batch()`
- บันทึก `balanceBefore` / `balanceAfter`
- มี source/destination
- มี reference ID
- มี Audit Log สำหรับ action สำคัญ

สำหรับยอดเงินจริงใน production ควรเพิ่ม reconciliation และระบบตรวจหลักฐานการชำระเงินของ provider อีกชั้นหนึ่ง

## 17. Parent–Child

Admin ใช้ endpoint

```http
POST /api/admin/parent-links
```

Body

```json
{
  "parentID":"usr_parent",
  "childID":"usr_student"
}
```

หลังเชื่อมแล้ว ผู้ปกครองจึงใช้ `/api/parent/topup-child` เพื่อเติมเงินเข้า Wallet ของลูกได้

## 18. Spending Limit

ตั้งวงเงินรายวัน

```http
PATCH /api/wallet/limit
```

```json
{
  "dailySpendingLimit":300
}
```

ระบบตรวจวงเงินตอนสั่งซื้อด้วย THB และเก็บยอดใช้ประจำวันใน WALLETS

## 19. Marketplace + Escrow

Flow การซื้อ

```text
Buyer -> ตรวจ balance -> ตรวจ stock -> หัก Wallet
      -> สร้าง Order -> สร้าง Escrow -> ลด Stock
```

เมื่อร้าน Confirm

```text
Escrow -> Seller Wallet
```

เมื่อ Reject

```text
Escrow -> Buyer Wallet
```

ขั้นตอน balance/escrow ที่เกี่ยวข้องต้องอยู่ใน transaction เดียวกัน

## 20. Auction

สร้าง Auction ผ่าน

```http
POST /api/auctions
```

Bid ผ่าน

```http
POST /api/auctions/:auctionID/bid
```

ระบบไม่พัก Coin ระหว่างการประมูลตามสเปกนี้

เมื่อหมดเวลา Cron จะปิด Auction และหากผู้ชนะมียอดเพียงพอ จะหัก Coin และโอนเข้า Wallet ร้านแบบ atomic

## 21. Cron

ใน `wrangler.jsonc` มี

```text
0 * * * *
0 0 * * *
```

ใช้สำหรับ

- session cleanup
- reminder งานก่อนครบกำหนด
- lock งานที่หมดเวลา
- close auction
- งาน reset รายวัน

การเพิ่ม automation อื่นให้แก้ `scheduledJobs()`

## 22. การ deploy หลังแก้โค้ด

```bash
npm install
npx wrangler deploy
```

ถ้าแก้ schema ให้สร้าง migration ใหม่ เช่น

```text
migrations/0002_add_xxx.sql
```

แล้ว

```bash
npx wrangler d1 migrations apply DB --remote
```

อย่าแก้ migration ที่ apply ไปแล้วใน production ให้สร้าง migration ใหม่แทน

## 23. Backup / Export

โปรเจกต์นี้เตรียม schema สำหรับการ export แต่การ backup production ไม่ควรพึ่งการ copy D1 แบบไฟล์เดียวอย่างเดียว

แนะนำให้มีอย่างน้อย

- D1 export/snapshot ตามวิธีของ Cloudflare ที่ใช้อยู่
- SQL migration ใน Git
- R2 lifecycle/retention policy
- export สำคัญของ transaction และ audit
- ทดสอบ restore จริงเป็นระยะ

## 24. Security checklist ก่อนเปิดจริง

1. เปลี่ยน `BOOTSTRAP_KEY`
2. ตั้ง `SESSION_PEPPER`
3. ตั้ง rate limiting สำหรับ Login / Upload / Transfer / Topup
4. ตั้ง limit ขนาดไฟล์และชนิดไฟล์
5. เปิด moderation workflow ตามนโยบายโรงเรียน
6. ตรวจ ACL ของไฟล์ทุกหมวดก่อนให้เป็น public
7. เพิ่ม antivirus/content scanning หากรับไฟล์จากผู้ใช้ทั่วไป
8. ตั้งโดเมน HTTPS และตรวจ cookie security
9. ตรวจ privacy/retention ของข้อมูลนักเรียนและผู้ปกครอง
10. ทดสอบ backup + restore
11. ทดสอบ transaction concurrency
12. ทดสอบ session revoke หลัง Suspend

## 25. จุดที่ต้องแก้ต่อเมื่อทำ production จริง

- Email provider integration จริง
- Rich text editor ที่ sanitize HTML อย่างเข้มงวด
- Direct R2 multipart/presigned upload สำหรับไฟล์วิดีโอใหญ่
- Full file ACL ตาม class/assignment/lesson/submission
- Question bank/template และ analytics ขั้นสูง
- Parent notification ข้ามหลายเหตุการณ์
- Season rollover และ badge rules engine เต็มรูปแบบ
- Admin UI สำหรับ shop moderation และ parent link
- Export รายงานเป็น CSV/XLSX/PDF ตามกฎองค์กร
- Edge rate limiting และ abuse prevention
- Reconciliation สำหรับยอดเงินจริง

## 26. ตั้งค่าจาก Android ด้วย Termux

เนื่องจาก Wrangler เป็น CLI สามารถใช้เครื่อง Android ได้

ติดตั้ง Termux จากแหล่งที่เชื่อถือได้ แล้วรัน

```bash
pkg update
pkg upgrade
pkg install nodejs git unzip
```

แตก ZIP

```bash
unzip SchoolVerse-SPY-Ncxus.zip
cd SchoolVerse-SPY-Ncxus
```

ติดตั้ง dependency

```bash
npm install
```

ล็อกอิน Cloudflare

```bash
npx wrangler login
```

จากนั้นทำตามลำดับในหัวข้อ 2 → 3 → 4 → 5

ถ้า browser ใน Termux ไม่เปิดสำหรับ OAuth ให้ใช้คำสั่ง/flow ของ Wrangler รุ่นที่ติดตั้งแสดง แล้วทำ authorization ผ่าน browser ปกติของ Android

## 27. การเชื่อมข้อมูลจาก Frontend ไป D1/R2 ไม่ต้องใส่ ID ใน JavaScript

Frontend เรียก URL เช่น

```text
/api/dashboard
/api/feed
/api/wallet
/api/files
```

ตัว frontend ไม่รู้ D1 database ID และไม่รู้ R2 credential

Worker เป็นผู้เชื่อมต่อผ่าน binding

```text
env.DB      -> D1
 env.FILES  -> R2
 env.CACHE  -> KV
 env.ASSETS -> Static Assets
```

ดังนั้นจุดเชื่อมข้อมูลจริงอยู่ที่ `wrangler.jsonc` ไม่ใช่ใน `public/app.js`

## 28. ถ้าจะเปลี่ยนชื่อ resource

แก้ใน `wrangler.jsonc`

```json
"database_name": "schoolverse-db"
```

```json
"bucket_name": "schoolverse-files"
```

แล้ว deploy ใหม่ตามขั้นตอน

อย่าเปลี่ยน binding name (`DB`, `FILES`, `CACHE`) โดยไม่แก้ `src/index.js` ด้วย

## 29. ถ้าจะใช้ Domain ของตัวเอง

หลัง Worker deploy สำเร็จ สามารถผูก Custom Domain ใน Cloudflare Workers/Routes ตามบัญชี Cloudflare ของคุณได้

Frontend ไม่ต้องแก้ base URL เพราะ API ใช้ relative path `/api/...`

## 30. การอัปเดตเวอร์ชัน

แนวทางที่แนะนำ

```text
แก้โค้ด
  ↓
ทดสอบ local
  ↓
สร้าง migration ใหม่ถ้ามี schema change
  ↓
apply migration remote
  ↓
deploy worker
  ↓
ทดสอบ health / login / transaction
```
