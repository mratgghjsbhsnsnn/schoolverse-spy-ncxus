const jsonHeaders = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store'
};

const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { ...jsonHeaders, ...extra }
});

const text = (data, status = 200, extra = {}) => new Response(data, {
  status,
  headers: { 'Content-Type': 'text/plain; charset=utf-8', ...extra }
});

const nowISO = () => new Date().toISOString();
const uid = (prefix = 'id') => `${prefix}_${crypto.randomUUID().replaceAll('-', '')}`;

function parseCookies(request) {
  const raw = request.headers.get('Cookie') || '';
  const out = {};
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function b64url(bytes) {
  let s = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
function fromB64url(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const raw = atob(s.replaceAll('-', '+').replaceAll('_', '/') + pad);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
async function sha256(input) {
  const bytes = new TextEncoder().encode(input);
  return b64url(await crypto.subtle.digest('SHA-256', bytes));
}

async function hashPassword(password, env) {
  const iterations = Number(env.PASSWORD_ITERATIONS || 120000);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256);
  return `pbkdf2_sha256$${iterations}$${b64url(salt)}$${b64url(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  try {
    const [scheme, iterationsRaw, saltB64, hashB64] = stored.split('$');
    if (scheme !== 'pbkdf2_sha256') return false;
    const iterations = Number(iterationsRaw);
    const salt = fromB64url(saltB64);
    const expected = fromB64url(hashB64);
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256);
    const actual = new Uint8Array(bits);
    if (actual.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
    return diff === 0;
  } catch {
    return false;
  }
}

async function ipHash(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  return sha256(`${ip}|${env.SESSION_PEPPER || env.BOOTSTRAP_KEY || 'default-pepper'}`);
}

function requireString(value, name, max = 10000) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${name} is required`);
  if (value.length > max) throw new Error(`${name} is too long`);
  return value.trim();
}
function normalizeEmail(v) { return String(v || '').trim().toLowerCase(); }
function safeFilename(name) {
  return String(name || 'file').replace(/[^\w.()\-\u0E00-\u0E7F ]+/g, '_').slice(0, 150);
}
function cookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge != null) parts.push(`Max-Age=${options.maxAge}`);
  parts.push(`Path=${options.path || '/'}`);
  if (options.httpOnly !== false) parts.push('HttpOnly');
  parts.push(`SameSite=${options.sameSite || 'Lax'}`);
  if (options.secure !== false) parts.push('Secure');
  return parts.join('; ');
}

async function getAuth(request, env) {
  const token = parseCookies(request).sv_session;
  if (!token) return null;
  const tokenHash = await sha256(token);
  const result = await env.DB.prepare(`
    SELECT s.sessionID, s.userID, s.expiresAt, u.*
    FROM SESSIONS s JOIN USERS u ON u.userID = s.userID
    WHERE s.sessionTokenHash = ? AND s.status = 'active'
      AND s.expiresAt > ? AND u.status = 'approved'
    LIMIT 1
  `).bind(tokenHash, nowISO()).first();
  if (!result) return null;
  return result;
}

async function requireAuth(request, env) {
  const user = await getAuth(request, env);
  if (!user) throw Object.assign(new Error('Authentication required'), { status: 401 });
  return user;
}
function requireRole(user, roles) {
  const allowed = Array.isArray(roles) ? roles : [roles];
  if (!allowed.includes(user.role)) throw Object.assign(new Error('Forbidden'), { status: 403 });
}

async function audit(env, request, userID, action, entityType = null, entityID = null, details = {}, sessionReference = null) {
  await env.DB.prepare(`INSERT INTO AUDIT_LOGS (logID,userID,action,entityType,entityID,detailsJSON,ipHash,sessionReference,createdAt) VALUES (?,?,?,?,?,?,?,?,?)`)
    .bind(uid('log'), userID, action, entityType, entityID, JSON.stringify(details), await ipHash(request, env), sessionReference, nowISO()).run();
}

async function sendEmail(env, userID, recipient, subject, textContent, htmlContent=null) {
  const createdAt=nowISO();
  if(!env.EMAIL_PROVIDER_URL || !env.EMAIL_PROVIDER_TOKEN || !recipient){
    await env.DB.prepare(`INSERT INTO EMAIL_LOGS(emailID,userID,recipient,subject,content,status,createdAt) VALUES(?,?,?,?,?,?,?)`).bind(uid('email'),userID,recipient||'',subject,textContent,'skipped',createdAt).run().catch(()=>{});
    return {status:'skipped'};
  }
  try{
    const res=await fetch(env.EMAIL_PROVIDER_URL,{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${env.EMAIL_PROVIDER_TOKEN}`},body:JSON.stringify({from:env.EMAIL_FROM,to:recipient,subject,html:htmlContent||`<p>${escapeHtml(textContent)}</p>`,text:textContent})});
    const status=res.ok?'sent':'failed';
    await env.DB.prepare(`INSERT INTO EMAIL_LOGS(emailID,userID,recipient,subject,content,status,createdAt) VALUES(?,?,?,?,?,?,?)`).bind(uid('email'),userID,recipient,subject,textContent,status,createdAt).run().catch(()=>{});
    return {status};
  }catch(e){
    await env.DB.prepare(`INSERT INTO EMAIL_LOGS(emailID,userID,recipient,subject,content,status,createdAt) VALUES(?,?,?,?,?,?,?)`).bind(uid('email'),userID,recipient,subject,textContent,'failed',createdAt).run().catch(()=>{});
    return {status:'failed'};
  }
}
function escapeHtml(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}

async function notify(env, userID, type, title, content = '', targetURL = null) {
  await env.DB.prepare(`INSERT INTO NOTIFICATIONS (notiID,userID,type,title,content,targetURL,isRead,createdAt) VALUES (?,?,?,?,?,?,0,?)`)
    .bind(uid('noti'), userID, type, title, content, targetURL, nowISO()).run();
}

const defaultXP = {
  login: 5,
  lesson_complete: 20,
  assignment_on_time: 30,
  assignment_late: 10,
  quiz_attempt: 15,
  quiz_over_80: 25,
  post_approved: 10,
  review: 5,
  reaction_received: 2
};

async function getSettings(env) {
  const cacheKey = 'settings:all';
  try {
    const cached = await env.CACHE.get(cacheKey, 'json');
    if (cached) return cached;
  } catch {}
  const rows = await env.DB.prepare(`SELECT settingKey, settingValueJSON FROM SYSTEM_SETTINGS`).all();
  const settings = { xp: defaultXP, transactionLimitTHB: 5000, modules: {}, leaderboard: true, season: null, academicYear: null, semester: null };
  for (const r of rows.results || []) {
    try { settings[r.settingKey] = JSON.parse(r.settingValueJSON); } catch { settings[r.settingKey] = r.settingValueJSON; }
  }
  try { await env.CACHE.put(cacheKey, JSON.stringify(settings), { expirationTtl: 60 }); } catch {}
  return settings;
}

async function setSetting(env, userID, key, value) {
  await env.DB.prepare(`INSERT INTO SYSTEM_SETTINGS(settingKey,settingValueJSON,updatedAt,updatedBy) VALUES(?,?,?,?) ON CONFLICT(settingKey) DO UPDATE SET settingValueJSON=excluded.settingValueJSON,updatedAt=excluded.updatedAt,updatedBy=excluded.updatedBy`)
    .bind(key, JSON.stringify(value), nowISO(), userID).run();
  try { await env.CACHE.delete('settings:all'); } catch {}
}

function calcLevel(xp) {
  const thresholds = [0, 100, 300, 600, 1000, 1500, 2200, 3200, 4500, 6000];
  let level = 1;
  for (let i = 0; i < thresholds.length; i++) if (xp >= thresholds[i]) level = i + 1;
  return Math.min(10, level);
}

async function addXP(env, userID, eventType, amount, referenceID) {
  if (!amount || amount <= 0) return false;
  const exists = await env.DB.prepare(`SELECT eventID FROM XP_EVENTS WHERE userID=? AND eventType=? AND referenceID IS ? LIMIT 1`).bind(userID,eventType,referenceID).first();
  if (exists) return false;
  const eventID = uid('xp');
  const createdAt = nowISO();
  const user = await env.DB.prepare(`SELECT xp,level FROM USERS WHERE userID=?`).bind(userID).first();
  if (!user) return false;
  const newXP = Number(user.xp || 0) + Number(amount);
  const newLevel = calcLevel(newXP);
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO XP_EVENTS(eventID,userID,eventType,amount,referenceID,createdAt) VALUES(?,?,?,?,?,?)`).bind(eventID,userID,eventType,amount,referenceID,createdAt),
    env.DB.prepare(`UPDATE USERS SET xp=?,level=? WHERE userID=?`).bind(newXP,newLevel,userID),
    env.DB.prepare(`INSERT INTO GAME_STATS(statID,userID,totalXP,level,streak,lastLoginDate,badgesJSON,dailyQuestJSON,season,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(userID) DO UPDATE SET totalXP=excluded.totalXP,level=excluded.level,updatedAt=excluded.updatedAt`).bind(uid('stat'),userID,newXP,newLevel,0,null,'[]','{}',null,createdAt)
  ]);
  return true;
}

async function touchLoginGame(env, userID) {
  const date = new Date().toISOString().slice(0,10);
  const settings = await getSettings(env);
  const bonus = Number(settings.xp?.login ?? defaultXP.login);
  const stat = await env.DB.prepare(`SELECT * FROM GAME_STATS WHERE userID=?`).bind(userID).first();
  if (!stat) {
    await env.DB.prepare(`INSERT INTO GAME_STATS(statID,userID,totalXP,level,streak,lastLoginDate,badgesJSON,dailyQuestJSON,season,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?)`)
      .bind(uid('stat'),userID,0,1,1,date,'[]',JSON.stringify({date,login:false,lesson:false,assignment:false,post:false}),null,nowISO()).run();
    await addXP(env,userID,'login',bonus,`login:${date}`);
    return;
  }
  if (stat.lastLoginDate === date) return;
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0,10);
  const streak = stat.lastLoginDate === yesterday ? Number(stat.streak || 0) + 1 : 1;
  let quests = {};
  try { quests = JSON.parse(stat.dailyQuestJSON || '{}'); } catch {}
  quests = { date, login: true, lesson: false, assignment: false, post: false };
  await env.DB.prepare(`UPDATE GAME_STATS SET streak=?,lastLoginDate=?,dailyQuestJSON=?,updatedAt=? WHERE userID=?`).bind(streak,date,JSON.stringify(quests),nowISO(),userID).run();
  await addXP(env,userID,'login',bonus,`login:${date}`);
}

async function requireClassMember(env, classID, userID, roles = ['student','teacher']) {
  const row = await env.DB.prepare(`SELECT cm.*, c.teacherID, c.status AS classStatus FROM CLASS_MEMBERS cm JOIN CLASSES c ON c.classID=cm.classID WHERE cm.classID=? AND cm.userID=? AND cm.status='active'`).bind(classID,userID).first();
  if (!row || !roles.includes(row.role)) throw Object.assign(new Error('Not a class member'), { status: 403 });
  return row;
}

async function getAccessibleClassIds(env, user) {
  if (user.role === 'admin') return null;
  const rows = await env.DB.prepare(`SELECT classID FROM CLASS_MEMBERS WHERE userID=? AND status='active'`).bind(user.userID).all();
  return (rows.results || []).map(r => r.classID);
}

async function routeAPI(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': url.origin, 'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token', 'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS' } });

  try {
    if (path === '/api/health' && method === 'GET') return json({ ok: true, service: env.APP_NAME || 'SchoolVerse', time: nowISO() });

    if (path === '/api/setup/bootstrap' && method === 'POST') {
      const key = request.headers.get('X-Bootstrap-Key');
      if (!env.BOOTSTRAP_KEY || key !== env.BOOTSTRAP_KEY) return json({ error: 'Invalid bootstrap key' }, 403);
      const existing = await env.DB.prepare(`SELECT userID FROM USERS WHERE role='admin' LIMIT 1`).first();
      if (existing) return json({ error: 'Bootstrap already completed' }, 409);
      const body = await request.json();
      const firstName = requireString(body.firstName, 'firstName', 100);
      const lastName = requireString(body.lastName, 'lastName', 100);
      const email = normalizeEmail(body.email);
      const password = requireString(body.password, 'password', 200);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Invalid email' }, 400);
      if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);
      const userID = uid('usr'), walletID = uid('wal'), createdAt = nowISO();
      const hash = await hashPassword(password, env);
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO USERS(userID,firstName,lastName,email,passwordHash,role,walletID,status,createdAt) VALUES(?,?,?,?,?,?,?,?,?)`).bind(userID,firstName,lastName,email,hash,'admin',walletID,'approved',createdAt),
        env.DB.prepare(`INSERT INTO WALLETS(walletID,userID,updatedAt) VALUES(?,?,?)`).bind(walletID,userID,createdAt),
        env.DB.prepare(`INSERT INTO GAME_STATS(statID,userID,totalXP,level,streak,lastLoginDate,badgesJSON,dailyQuestJSON,season,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(uid('stat'),userID,0,1,0,null,'[]','{}',null,createdAt)
      ]);
      const defaults = [
        ['xp', defaultXP], ['transactionLimitTHB',5000], ['modules',{feed:true,learning:true,assignments:true,quizzes:true,marketplace:true,wallet:true,gamification:true,analytics:true}], ['leaderboard',true]
      ];
      for (const [k,v] of defaults) await setSetting(env,userID,k,v);
      await audit(env,request,userID,'BOOTSTRAP','USER',userID,{email});
      return json({ ok: true, userID });
    }

    if (path === '/api/auth/register' && method === 'POST') {
      const body = await request.json();
      const firstName = requireString(body.firstName, 'firstName', 100);
      const lastName = requireString(body.lastName, 'lastName', 100);
      const email = normalizeEmail(body.email);
      const password = requireString(body.password, 'password', 200);
      const requestedRole = ['student','teacher','parent'].includes(body.role) ? body.role : 'student';
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Invalid email' }, 400);
      if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);
      const taken = await env.DB.prepare(`SELECT userID FROM USERS WHERE email=?`).bind(email).first();
      if (taken) return json({ error: 'Email already registered' }, 409);
      const userID = uid('usr'), walletID = uid('wal'), createdAt = nowISO(), hash = await hashPassword(password, env);
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO USERS(userID,firstName,lastName,email,passwordHash,role,classID,gradeLevel,walletID,status,createdAt) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(userID,firstName,lastName,email,hash,requestedRole,body.classID || null,body.gradeLevel || null,walletID,'pending',createdAt),
        env.DB.prepare(`INSERT INTO WALLETS(walletID,userID,updatedAt) VALUES(?,?,?)`).bind(walletID,userID,createdAt),
        env.DB.prepare(`INSERT INTO GAME_STATS(statID,userID,totalXP,level,streak,badgesJSON,dailyQuestJSON,updatedAt) VALUES(?,?,?,?,?,?,?,?)`).bind(uid('stat'),userID,0,1,0,'[]','{}',createdAt)
      ]);
      const admins = await env.DB.prepare(`SELECT userID FROM USERS WHERE role='admin' AND status='approved'`).all();
      for (const a of admins.results || []) await notify(env,a.userID,'account_pending','มีบัญชีใหม่รออนุมัติ',`${firstName} ${lastName} (${requestedRole})`, '/?view=admin-users');
      return json({ ok: true, message: 'Registration submitted for approval', userID }, 201);
    }

    if (path === '/api/auth/login' && method === 'POST') {
      const body = await request.json();
      const email = normalizeEmail(body.email);
      const password = String(body.password || '');
      const user = await env.DB.prepare(`SELECT * FROM USERS WHERE email=?`).bind(email).first();
      if (!user) return json({ error: 'Invalid email or password' }, 401);
      if (user.lockedUntil && user.lockedUntil > nowISO()) return json({ error: 'Account temporarily locked', lockedUntil: user.lockedUntil }, 423);
      if (user.status !== 'approved') return json({ error: `Account status: ${user.status}` }, 403);
      const ok = await verifyPassword(password, user.passwordHash);
      if (!ok) {
        const attempts = Number(user.failedLoginAttempts || 0) + 1;
        if (attempts >= 5) {
          const lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
          await env.DB.prepare(`UPDATE USERS SET failedLoginAttempts=0,lockedUntil=? WHERE userID=?`).bind(lockedUntil,user.userID).run();
          await audit(env,request,user.userID,'LOGIN_LOCKED','USER',user.userID,{attempts:5});
          return json({ error: 'Too many failed attempts. Locked for 15 minutes.' }, 423);
        }
        await env.DB.prepare(`UPDATE USERS SET failedLoginAttempts=? WHERE userID=?`).bind(attempts,user.userID).run();
        return json({ error: 'Invalid email or password' }, 401);
      }
      const sessionID = uid('ses');
      const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
      const token = b64url(tokenBytes);
      const tokenHash = await sha256(token);
      const createdAt = nowISO();
      const expiresAt = new Date(Date.now() + Number(env.SESSION_HOURS || 8) * 3600000).toISOString();
      await env.DB.batch([
        env.DB.prepare(`UPDATE USERS SET failedLoginAttempts=0,lockedUntil=NULL,lastLoginAt=? WHERE userID=?`).bind(createdAt,user.userID),
        env.DB.prepare(`INSERT INTO SESSIONS(sessionID,sessionTokenHash,userID,createdAt,expiresAt,lastActivityAt,ipHash,userAgent,status) VALUES(?,?,?,?,?,?,?,?,?)`).bind(sessionID,tokenHash,user.userID,createdAt,expiresAt,createdAt,await ipHash(request,env),request.headers.get('User-Agent') || '', 'active')
      ]);
      await touchLoginGame(env,user.userID);
      await audit(env,request,user.userID,'LOGIN','SESSION',sessionID,{},sessionID);
      return json({ ok: true, user: publicUser(user) }, 200, { 'Set-Cookie': cookie('sv_session',token,{maxAge:Number(env.SESSION_HOURS||8)*3600}) });
    }

    if (path === '/api/auth/logout' && method === 'POST') {
      const user = await getAuth(request,env);
      const token = parseCookies(request).sv_session;
      if (token) {
        await env.DB.prepare(`UPDATE SESSIONS SET status='revoked' WHERE sessionTokenHash=?`).bind(await sha256(token)).run();
      }
      if (user) await audit(env,request,user.userID,'LOGOUT','SESSION',user.sessionID,{},user.sessionID);
      return json({ ok:true },200,{ 'Set-Cookie': cookie('sv_session','',{maxAge:0}) });
    }

    if (path === '/api/auth/me' && method === 'GET') {
      const user = await requireAuth(request,env);
      return json({ user: publicUser(user), settings: await getSettings(env) });
    }

    const user = await requireAuth(request,env);
    if (user.sessionID) {
      ctx.waitUntil(env.DB.prepare(`UPDATE SESSIONS SET lastActivityAt=? WHERE sessionID=?`).bind(nowISO(),user.sessionID).run().catch(()=>{}));
    }

    if (path === '/api/dashboard' && method === 'GET') return json(await dashboard(env,user));

    if (path === '/api/notifications' && method === 'GET') {
      const limit = Math.min(Number(url.searchParams.get('limit')||30),100);
      const rows = await env.DB.prepare(`SELECT * FROM NOTIFICATIONS WHERE userID=? ORDER BY createdAt DESC LIMIT ?`).bind(user.userID,limit).all();
      const unread = await env.DB.prepare(`SELECT COUNT(*) AS n FROM NOTIFICATIONS WHERE userID=? AND isRead=0`).bind(user.userID).first();
      return json({items:rows.results||[],unread:Number(unread?.n||0)});
    }
    const notiMatch = path.match(/^\/api\/notifications\/([^/]+)(?:\/(read|delete))?$/);
    if (notiMatch && method !== 'POST') {
      const [,id,action] = notiMatch;
      if (action === 'read' && method === 'POST') {}
    }
    if (path === '/api/notifications/read-all' && method === 'POST') {
      await env.DB.prepare(`UPDATE NOTIFICATIONS SET isRead=1 WHERE userID=?`).bind(user.userID).run();
      return json({ok:true});
    }
    if (notiMatch && notiMatch[2] === 'read' && method === 'POST') {
      await env.DB.prepare(`UPDATE NOTIFICATIONS SET isRead=1 WHERE notiID=? AND userID=?`).bind(notiMatch[1],user.userID).run();
      return json({ok:true});
    }
    if (notiMatch && notiMatch[2] === 'delete' && method === 'POST') {
      await env.DB.prepare(`DELETE FROM NOTIFICATIONS WHERE notiID=? AND userID=?`).bind(notiMatch[1],user.userID).run();
      return json({ok:true});
    }

    if (path === '/api/profile' && method === 'GET') return json({user:publicUser(user)});
    if (path === '/api/profile' && method === 'PATCH') {
      const body = await request.json();
      const firstName = body.firstName == null ? user.firstName : requireString(body.firstName,'firstName',100);
      const lastName = body.lastName == null ? user.lastName : requireString(body.lastName,'lastName',100);
      await env.DB.prepare(`UPDATE USERS SET firstName=?,lastName=? WHERE userID=?`).bind(firstName,lastName,user.userID).run();
      await audit(env,request,user.userID,'UPDATE_PROFILE','USER',user.userID,{firstName,lastName});
      return json({ok:true});
    }
    if (path === '/api/profile/password' && method === 'POST') {
      const body = await request.json();
      const oldPassword = String(body.oldPassword||''), newPassword = String(body.newPassword||'');
      if (!(await verifyPassword(oldPassword,user.passwordHash))) return json({error:'Current password is incorrect'},400);
      if (newPassword.length < 8) return json({error:'New password must be at least 8 characters'},400);
      const hash = await hashPassword(newPassword,env);
      await env.DB.prepare(`UPDATE USERS SET passwordHash=? WHERE userID=?`).bind(hash,user.userID).run();
      await env.DB.prepare(`UPDATE SESSIONS SET status='revoked' WHERE userID=? AND sessionID<>?`).bind(user.userID,user.sessionID).run();
      await audit(env,request,user.userID,'CHANGE_PASSWORD','USER',user.userID);
      return json({ok:true});
    }

    // Files: metadata -> streamed content -> controlled download.
    if (path === '/api/files' && method === 'POST') {
      const body = await request.json();
      const originalName = safeFilename(requireString(body.originalName,'originalName',150));
      const mimeType = requireString(body.mimeType,'mimeType',150);
      const category = String(body.category||'attachment').slice(0,50);
      const visibility = body.visibility === 'public' ? 'public' : 'private';
      const fileID = uid('file');
      const r2Key = `${category}/${user.userID}/${fileID}-${originalName}`;
      await env.DB.prepare(`INSERT INTO FILES(fileID,ownerID,r2Key,originalName,mimeType,fileSize,category,visibility,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(fileID,user.userID,r2Key,originalName,mimeType,0,category,visibility,nowISO(),'pending').run();
      return json({fileID,uploadURL:`/api/files/${fileID}/content`},201);
    }
    const fileContentMatch = path.match(/^\/api\/files\/([^/]+)\/content$/);
    if (fileContentMatch && method === 'PUT') {
      const fileID = fileContentMatch[1];
      const file = await env.DB.prepare(`SELECT * FROM FILES WHERE fileID=?`).bind(fileID).first();
      if (!file || file.ownerID !== user.userID) return json({error:'File not found'},404);
      const len = Number(request.headers.get('Content-Length')||0);
      const max = Number(env.MAX_UPLOAD_MB||100)*1024*1024;
      if (len && len > max) return json({error:`File exceeds ${env.MAX_UPLOAD_MB||100} MB limit`},413);
      try {
        await env.FILES.put(file.r2Key,request.body,{httpMetadata:{contentType:file.mimeType,cacheControl:file.visibility==='public'?'public, max-age=3600':'private, max-age=300'}});
        const head = await env.FILES.head(file.r2Key);
        await env.DB.prepare(`UPDATE FILES SET fileSize=?,status='ready' WHERE fileID=?`).bind(Number(head?.size||len||0),fileID).run();
        await audit(env,request,user.userID,'UPLOAD_FILE','FILE',fileID,{category:file.category,mimeType:file.mimeType,size:Number(head?.size||len||0)});
        return json({ok:true,fileID,size:Number(head?.size||len||0)});
      } catch (e) {
        await env.DB.prepare(`UPDATE FILES SET status='failed' WHERE fileID=?`).bind(fileID).run().catch(()=>{});
        throw e;
      }
    }
    const fileGetMatch = path.match(/^\/api\/files\/([^/]+)\/content$/);
    if (fileGetMatch && method === 'GET') {
      const file = await env.DB.prepare(`SELECT * FROM FILES WHERE fileID=?`).bind(fileGetMatch[1]).first();
      if (!file || file.status !== 'ready') return text('Not found',404);
      if (file.visibility !== 'public' && file.ownerID !== user.userID && user.role !== 'admin') return text('Forbidden',403);
      const obj = await env.FILES.get(file.r2Key);
      if (!obj) return text('Not found',404);
      const h = new Headers();
      obj.writeHttpMetadata(h); h.set('etag',obj.httpEtag); h.set('X-Content-Type-Options','nosniff');
      return new Response(obj.body,{headers:h});
    }

    // Social Feed
    if (path === '/api/feed' && method === 'GET') return json(await getFeed(env,user,url));
    if (path === '/api/posts' && method === 'POST') {
      const body = await request.json();
      const postType = ['text','image','youtube','file'].includes(body.postType) ? body.postType : 'text';
      const targetType = ['school','class','subject'].includes(body.targetType) ? body.targetType : 'school';
      if (targetType !== 'school' && !body.targetID) return json({error:'targetID is required'},400);
      if (targetType !== 'school') {
        await requireClassMember(env,String(body.targetID),user.userID,user.role==='teacher'?['teacher','student']:['student','teacher']);
      }
      const content = String(body.content||'').slice(0,20000);
      const status = user.role === 'student' ? 'pending' : 'approved';
      const postID = uid('post'), createdAt = nowISO();
      await env.DB.prepare(`INSERT INTO POSTS(postID,userID,postType,content,targetType,targetID,status,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?)`).bind(postID,user.userID,postType,content,targetType,body.targetID||null,status,createdAt,createdAt).run();
      const fileIds = Array.isArray(body.fileIDs) ? body.fileIDs.slice(0,5) : [];
      for (let i=0;i<fileIds.length;i++) {
        const f = await env.DB.prepare(`SELECT fileID FROM FILES WHERE fileID=? AND ownerID=? AND status='ready'`).bind(fileIds[i],user.userID).first();
        if (f) await env.DB.prepare(`INSERT INTO POST_FILES(postFileID,postID,fileID,sortOrder) VALUES(?,?,?,?)`).bind(uid('pf'),postID,f.fileID,i).run();
      }
      await audit(env,request,user.userID,'CREATE_POST','POST',postID,{status,targetType});
      if (user.role === 'student') await updateQuest(env,user.userID,'post');
      if (status === 'pending') {
        const admins = await env.DB.prepare(`SELECT userID FROM USERS WHERE role='admin' AND status='approved'`).all();
        for (const a of admins.results||[]) await notify(env,a.userID,'post_pending','มีโพสต์นักเรียนรออนุมัติ','ตรวจสอบโพสต์ใหม่',`/?view=feed&post=${postID}`);
      }
      return json({ok:true,postID,status},201);
    }
    const postAction = path.match(/^\/api\/posts\/([^/]+)\/(approve|reject|report|pin|delete|reaction|comment)$/);
    if (postAction) {
      const postID = postAction[1], action = postAction[2];
      const post = await env.DB.prepare(`SELECT * FROM POSTS WHERE postID=?`).bind(postID).first();
      if (!post) return json({error:'Post not found'},404);
      if (action === 'approve' || action === 'reject') {
        requireRole(user,['admin','teacher']);
        if (user.role === 'teacher') await requireClassMember(env,post.targetID,user.userID,['teacher']);
        if (action === 'approve') {
          await env.DB.prepare(`UPDATE POSTS SET status='approved',rejectionReason=NULL,updatedAt=? WHERE postID=?`).bind(nowISO(),postID).run();
          await notify(env,post.userID,'post_approved','โพสต์ได้รับการอนุมัติ','โพสต์ของคุณแสดงใน Feed แล้ว',`/?view=feed&post=${postID}`);
          const settings = await getSettings(env); await addXP(env,post.userID,'post_approved',Number(settings.xp?.post_approved||10),postID);
          await audit(env,request,user.userID,'APPROVE_POST','POST',postID);
        } else {
          const body = await request.json();
          const reason = String(body.reason||'ไม่ผ่านการอนุมัติ').slice(0,1000);
          await env.DB.prepare(`UPDATE POSTS SET status='rejected',rejectionReason=?,updatedAt=? WHERE postID=?`).bind(reason,nowISO(),postID).run();
          await notify(env,post.userID,'post_rejected','โพสต์ถูกปฏิเสธ',reason,`/?view=feed&post=${postID}`);
          await audit(env,request,user.userID,'REJECT_POST','POST',postID,{reason});
        }
        return json({ok:true});
      }
      if (action === 'pin') { requireRole(user,'admin'); await env.DB.prepare(`UPDATE POSTS SET pinned=CASE WHEN pinned=1 THEN 0 ELSE 1 END WHERE postID=?`).bind(postID).run(); await audit(env,request,user.userID,'PIN_POST','POST',postID); return json({ok:true}); }
      if (action === 'delete') {
        if (user.role !== 'admin' && post.userID !== user.userID) return json({error:'Forbidden'},403);
        await env.DB.prepare(`UPDATE POSTS SET status='deleted',updatedAt=? WHERE postID=?`).bind(nowISO(),postID).run(); await audit(env,request,user.userID,'DELETE_POST','POST',postID); return json({ok:true});
      }
      if (action === 'report') {
        const body = await request.json(); const reason = requireString(body.reason,'reason',1000);
        try { await env.DB.prepare(`INSERT INTO POST_REPORTS(reportID,postID,userID,reason,createdAt) VALUES(?,?,?,?,?)`).bind(uid('report'),postID,user.userID,reason,nowISO()).run(); await env.DB.prepare(`UPDATE POSTS SET reportCount=reportCount+1 WHERE postID=?`).bind(postID).run(); } catch { return json({error:'Already reported'},409); }
        await notifyToAdmins(env,'post_reported','มีโพสต์ถูกรายงาน','ตรวจสอบรายงานโพสต์',`/?view=admin-moderation&post=${postID}`); return json({ok:true});
      }
      if (action === 'reaction' && method === 'POST') {
        const body = await request.json(); const type = ['like','clap','agree'].includes(body.reactionType)?body.reactionType:'like';
        const old = await env.DB.prepare(`SELECT reactionID,reactionType FROM REACTIONS WHERE postID=? AND userID=?`).bind(postID,user.userID).first();
        if (old && old.reactionType === type) await env.DB.prepare(`DELETE FROM REACTIONS WHERE reactionID=?`).bind(old.reactionID).run();
        else if (old) await env.DB.prepare(`UPDATE REACTIONS SET reactionType=?,createdAt=? WHERE reactionID=?`).bind(type,nowISO(),old.reactionID).run();
        else await env.DB.prepare(`INSERT INTO REACTIONS(reactionID,postID,userID,reactionType,createdAt) VALUES(?,?,?,?,?)`).bind(uid('rxn'),postID,user.userID,type,nowISO()).run();
        if (post.userID !== user.userID) { const settings=await getSettings(env); await addXP(env,post.userID,'reaction_received',Number(settings.xp?.reaction_received||2),`${postID}:${user.userID}`); }
        return json({ok:true});
      }
      if (action === 'comment' && method === 'POST') {
        const body = await request.json(); const content=requireString(body.content,'content',3000);
        const id=uid('comment'); await env.DB.prepare(`INSERT INTO COMMENTS(commentID,postID,userID,content,status,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?)`).bind(id,postID,user.userID,content,'approved',nowISO(),nowISO()).run();
        if (post.userID !== user.userID) await notify(env,post.userID,'comment','มีความคิดเห็นใหม่',`${user.firstName} ${user.lastName} แสดงความคิดเห็น`, `/?view=feed&post=${postID}`);
        return json({ok:true,commentID:id},201);
      }
    }

    // Classes / learning
    if (path === '/api/classes' && method === 'GET') {
      let rows;
      if (user.role === 'admin') rows = await env.DB.prepare(`SELECT c.*,u.firstName||' '||u.lastName AS teacherName FROM CLASSES c JOIN USERS u ON u.userID=c.teacherID ORDER BY c.createdAt DESC LIMIT 200`).all();
      else rows = await env.DB.prepare(`SELECT c.*,u.firstName||' '||u.lastName AS teacherName FROM CLASSES c JOIN USERS u ON u.userID=c.teacherID JOIN CLASS_MEMBERS cm ON cm.classID=c.classID WHERE cm.userID=? AND cm.status='active' ORDER BY c.createdAt DESC LIMIT 200`).bind(user.userID).all();
      return json({items:rows.results||[]});
    }
    if (path === '/api/classes' && method === 'POST') {
      requireRole(user,['admin','teacher']); const body=await request.json();
      const classID=uid('cls'); const joinCode=(Math.random().toString(36).slice(2,8)).toUpperCase(); const createdAt=nowISO();
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO CLASSES(classID,className,subjectName,teacherID,gradeLevel,room,academicYear,semester,joinCode,status,createdAt) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(classID,requireString(body.className,'className',150),requireString(body.subjectName,'subjectName',150),user.role==='teacher'?user.userID:String(body.teacherID||user.userID),body.gradeLevel||null,body.room||null,body.academicYear||null,body.semester||null,joinCode,'open',createdAt),
        env.DB.prepare(`INSERT INTO CLASS_MEMBERS(memberID,classID,userID,role,joinedAt,status) VALUES(?,?,?,?,?,?)`).bind(uid('member'),classID,user.role==='teacher'?user.userID:String(body.teacherID||user.userID),'teacher',createdAt,'active')
      ]);
      await audit(env,request,user.userID,'CREATE_CLASS','CLASS',classID,{joinCode});
      return json({ok:true,classID,joinCode},201);
    }
    const classMembersMatch = path.match(/^\/api\/classes\/([^/]+)\/members$/);
    if (classMembersMatch && method === 'GET') { await requireClassMember(env,classMembersMatch[1],user.userID,user.role==='admin'?['student','teacher']:['teacher','student']); const rows=await env.DB.prepare(`SELECT cm.*,u.firstName,u.lastName,u.email,u.role AS userRole FROM CLASS_MEMBERS cm JOIN USERS u ON u.userID=cm.userID WHERE cm.classID=? AND cm.status='active' ORDER BY u.lastName,u.firstName`).bind(classMembersMatch[1]).all(); return json({items:rows.results||[]}); }
    if (classMembersMatch && method === 'POST') { requireRole(user,['admin','teacher']); const classID=classMembersMatch[1]; if(user.role==='teacher') await requireClassMember(env,classID,user.userID,['teacher']); const body=await request.json(); const target=await env.DB.prepare(`SELECT userID FROM USERS WHERE userID=? AND status='approved'`).bind(body.userID).first(); if(!target) return json({error:'User not found'},404); await env.DB.prepare(`INSERT OR IGNORE INTO CLASS_MEMBERS(memberID,classID,userID,role,joinedAt,status) VALUES(?,?,?,?,?,?)`).bind(uid('member'),classID,target.userID,'student',nowISO(),'active').run(); return json({ok:true}); }

    if (path === '/api/lessons' && method === 'GET') {
      const classID=url.searchParams.get('classID'); if(!classID)return json({error:'classID required'},400); await requireClassMember(env,classID,user.userID,['student','teacher']); const rows=await env.DB.prepare(`SELECT l.*, lp.status AS progressStatus, lp.percentage FROM LESSONS l LEFT JOIN LESSON_PROGRESS lp ON lp.lessonID=l.lessonID AND lp.userID=? WHERE l.classID=? AND l.status!='archived' ORDER BY l.orderIndex`).bind(user.userID,classID).all(); return json({items:rows.results||[]});
    }
    if (path === '/api/lessons' && method === 'POST') {
      requireRole(user,['admin','teacher']); const body=await request.json(); await requireClassMember(env,body.classID,user.userID,['teacher']); const id=uid('lesson'); const t=nowISO(); await env.DB.prepare(`INSERT INTO LESSONS(lessonID,classID,orderIndex,title,content,youtubeVideoID,publishedAt,unlockType,unlockLessonID,status,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,body.classID,Number(body.orderIndex||0),requireString(body.title,'title',250),String(body.content||''),body.youtubeVideoID||null,body.publishedAt||t,body.unlockType||'none',body.unlockLessonID||null,body.status||'draft',t,t).run(); return json({ok:true,lessonID:id},201);
    }
    const progressMatch=path.match(/^\/api\/lessons\/([^/]+)\/progress$/);
    if(progressMatch&&method==='POST') { const lesson=await env.DB.prepare(`SELECT l.* FROM LESSONS l JOIN CLASS_MEMBERS cm ON cm.classID=l.classID WHERE l.lessonID=? AND cm.userID=? AND cm.status='active'`).bind(progressMatch[1],user.userID).first(); if(!lesson)return json({error:'Lesson not found'},404); const body=await request.json(); const percentage=Math.max(0,Math.min(100,Number(body.percentage||0))); const completed=percentage>=100; await env.DB.prepare(`INSERT INTO LESSON_PROGRESS(progressID,lessonID,userID,status,percentage,startedAt,completedAt,updatedAt) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(lessonID,userID) DO UPDATE SET status=excluded.status,percentage=excluded.percentage,completedAt=excluded.completedAt,updatedAt=excluded.updatedAt`).bind(uid('progress'),lesson.lessonID,user.userID,completed?'completed':'started',percentage,nowISO(),completed?nowISO():null,nowISO()).run(); if(completed){const settings=await getSettings(env); await addXP(env,user.userID,'lesson_complete',Number(settings.xp?.lesson_complete||20),lesson.lessonID); await updateQuest(env,user.userID,'lesson');} return json({ok:true,completed}); }

    // Assignments
    if(path==='/api/assignments'&&method==='GET'){const classID=url.searchParams.get('classID'); let q=`SELECT a.*,c.className, (SELECT COUNT(*) FROM SUBMISSIONS s WHERE s.assignID=a.assignID) AS submissions FROM ASSIGNMENTS a JOIN CLASSES c ON c.classID=a.classID`; const bind=[]; if(classID){q+=` WHERE a.classID=?`;bind.push(classID);} else if(user.role!=='admin'){q+=` JOIN CLASS_MEMBERS cmx ON cmx.classID=a.classID AND cmx.userID=? AND cmx.status='active'`;bind.push(user.userID);} q+=` ORDER BY a.dueAt`; const rows=await env.DB.prepare(q).bind(...bind).all(); return json({items:rows.results||[]});}
    if(path==='/api/assignments'&&method==='POST'){requireRole(user,['teacher','admin']);const body=await request.json();await requireClassMember(env,body.classID,user.userID,['teacher']);const id=uid('assign');const t=nowISO();await env.DB.prepare(`INSERT INTO ASSIGNMENTS(assignID,classID,teacherID,title,description,maxScore,assignedAt,dueAt,acceptedFileTypes,allowLate,latePenaltyPercent,exampleFileID,status,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,body.classID,user.userID,requireString(body.title,'title',250),String(body.description||''),Number(body.maxScore||100),body.assignedAt||t,requireString(body.dueAt,'dueAt',50),String(body.acceptedFileTypes||''),body.allowLate?1:0,Number(body.latePenaltyPercent||0),body.exampleFileID||null,body.status||'open',t,t).run();const members=await env.DB.prepare(`SELECT userID FROM CLASS_MEMBERS WHERE classID=? AND role='student' AND status='active'`).bind(body.classID).all();for(const m of members.results||[]) await notify(env,m.userID,'assignment','มีงานใหม่',body.title,`/?view=assignments&id=${id}`);return json({ok:true,assignID:id},201);}
    const submitMatch=path.match(/^\/api\/assignments\/([^/]+)\/submissions$/);
    if(submitMatch&&method==='GET'){const aid=submitMatch[1];const a=await env.DB.prepare(`SELECT * FROM ASSIGNMENTS WHERE assignID=?`).bind(aid).first();if(!a)return json({error:'Assignment not found'},404);if(user.role==='student'){await requireClassMember(env,a.classID,user.userID,['student']);const s=await env.DB.prepare(`SELECT * FROM SUBMISSIONS WHERE assignID=? AND userID=?`).bind(aid,user.userID).first();return json({item:s||null});}requireRole(user,['teacher','admin']);await requireClassMember(env,a.classID,user.userID,['teacher']);const rows=await env.DB.prepare(`SELECT s.*,u.firstName,u.lastName,u.email FROM SUBMISSIONS s JOIN USERS u ON u.userID=s.userID WHERE s.assignID=? ORDER BY s.submittedAt DESC`).bind(aid).all();return json({items:rows.results||[]});}
    if(submitMatch&&method==='POST'){const aid=submitMatch[1];const a=await env.DB.prepare(`SELECT * FROM ASSIGNMENTS WHERE assignID=?`).bind(aid).first();if(!a)return json({error:'Assignment not found'},404);await requireClassMember(env,a.classID,user.userID,['student']);if(a.status==='locked')return json({error:'Assignment locked'},409);const body=await request.json();const late=Date.now()>Date.parse(a.dueAt);if(late&&!a.allowLate)return json({error:'Late submissions are closed'},409);const id=(await env.DB.prepare(`SELECT submitID FROM SUBMISSIONS WHERE assignID=? AND userID=?`).bind(aid,user.userID).first())?.submitID||uid('submit');const t=nowISO();await env.DB.prepare(`INSERT INTO SUBMISSIONS(submitID,assignID,userID,content,submittedAt,status,isLate,updatedAt) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(assignID,userID) DO UPDATE SET content=excluded.content,submittedAt=excluded.submittedAt,status='submitted',isLate=excluded.isLate,updatedAt=excluded.updatedAt`).bind(id,aid,user.userID,String(body.content||''),t,'submitted',late?1:0,t).run();await updateQuest(env,user.userID,'assignment');return json({ok:true,submitID:id});}
    const gradeMatch=path.match(/^\/api\/submissions\/([^/]+)\/grade$/); if(gradeMatch&&method==='POST'){
      const body = await request.json();
      const sub=await env.DB.prepare(`SELECT s.*,a.classID,a.maxScore,a.title,a.allowLate,a.latePenaltyPercent FROM SUBMISSIONS s JOIN ASSIGNMENTS a ON a.assignID=s.assignID WHERE s.submitID=?`).bind(gradeMatch[1]).first();
      if(!sub)return json({error:'Submission not found'},404); requireRole(user,['teacher','admin']); await requireClassMember(env,sub.classID,user.userID,['teacher']); const rawScore=Math.max(0,Math.min(Number(sub.maxScore),Number(body.score))); const penalty=(sub.isLate&&sub.allowLate)?Math.max(0,Math.min(100,Number(sub.latePenaltyPercent||0))):0; const score=Number((rawScore*(1-penalty/100)).toFixed(2)); const feedback=String(body.feedback||'').slice(0,5000); await env.DB.prepare(`UPDATE SUBMISSIONS SET score=?,feedback=?,status='graded',gradedAt=?,gradedBy=?,updatedAt=? WHERE submitID=?`).bind(score,feedback,nowISO(),user.userID,nowISO(),sub.submitID).run(); await notify(env,sub.userID,'grade','คะแนนออกแล้ว',`${sub.title}: ${score}/${sub.maxScore}`,`/?view=assignments&id=${sub.assignID}`); const gradeUser=await env.DB.prepare(`SELECT email FROM USERS WHERE userID=?`).bind(sub.userID).first(); await sendEmail(env,sub.userID,gradeUser?.email||'',`SchoolVerse: คะแนนออกแล้ว — ${sub.title}`,`${sub.title}: ${score}/${sub.maxScore}`); const settings=await getSettings(env); const latePenalty=Number(sub.isLate? settings.xp?.assignment_late||10 : settings.xp?.assignment_on_time||30); await addXP(env,sub.userID,sub.isLate?'assignment_late':'assignment_on_time',latePenalty,sub.submitID); return json({ok:true});
    }

    // Quizzes
    if(path==='/api/quizzes'&&method==='GET'){const classID=url.searchParams.get('classID');let q=`SELECT q.*,c.className FROM QUIZZES q JOIN CLASSES c ON c.classID=q.classID`;const b=[];if(classID){q+=` WHERE q.classID=?`;b.push(classID);}else if(user.role!=='admin'){q+=` JOIN CLASS_MEMBERS cm ON cm.classID=q.classID AND cm.userID=? AND cm.status='active'`;b.push(user.userID);}q+=` ORDER BY q.openAt DESC`;const rows=await env.DB.prepare(q).bind(...b).all();return json({items:rows.results||[]});}
    if(path==='/api/quizzes'&&method==='POST'){requireRole(user,['teacher','admin']);const body=await request.json();await requireClassMember(env,body.classID,user.userID,['teacher']);const id=uid('quiz'),t=nowISO();await env.DB.prepare(`INSERT INTO QUIZZES(quizID,classID,title,description,durationMinutes,maxScore,randomQuestions,randomChoices,showAnswers,maxAttempts,passingPercent,openAt,closeAt,status,templateID,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,body.classID,requireString(body.title,'title',250),String(body.description||''),Number(body.durationMinutes||30),Number(body.maxScore||100),body.randomQuestions?1:0,body.randomChoices?1:0,body.showAnswers?1:0,Number(body.maxAttempts||1),Number(body.passingPercent||50),body.openAt||null,body.closeAt||null,body.status||'draft',body.templateID||null,t,t).run();const questions=Array.isArray(body.questions)?body.questions:[];for(let i=0;i<questions.length;i++){const qq=questions[i];await env.DB.prepare(`INSERT INTO QUIZ_QUESTIONS(questionID,quizID,orderIndex,questionType,questionText,choicesJSON,correctAnswerJSON,score,imageFileID) VALUES(?,?,?,?,?,?,?,?,?)`).bind(uid('question'),id,i,qq.questionType,requireString(qq.questionText,'questionText',5000),JSON.stringify(qq.choices||[]),JSON.stringify(qq.correctAnswer??null),Number(qq.score||1),qq.imageFileID||null).run();}return json({ok:true,quizID:id},201);}
    const quizDetail=path.match(/^\/api\/quizzes\/([^/]+)$/); if(quizDetail&&method==='GET'){const q=await env.DB.prepare(`SELECT * FROM QUIZZES WHERE quizID=?`).bind(quizDetail[1]).first();if(!q)return json({error:'Quiz not found'},404);await requireClassMember(env,q.classID,user.userID,['student','teacher']);const rows=await env.DB.prepare(`SELECT questionID,orderIndex,questionType,questionText,choicesJSON,score,imageFileID FROM QUIZ_QUESTIONS WHERE quizID=? ORDER BY orderIndex`).bind(q.quizID).all();return json({quiz:q,questions:rows.results||[]});}
    const quizStart=path.match(/^\/api\/quizzes\/([^/]+)\/start$/); if(quizStart&&method==='POST'){const q=await env.DB.prepare(`SELECT * FROM QUIZZES WHERE quizID=?`).bind(quizStart[1]).first();if(!q)return json({error:'Quiz not found'},404);await requireClassMember(env,q.classID,user.userID,['student']);const n=await env.DB.prepare(`SELECT COUNT(*) AS n FROM QUIZ_RESULTS WHERE quizID=? AND userID=?`).bind(q.quizID,user.userID).first();const attempt=Number(n?.n||0)+1;if(attempt>q.maxAttempts)return json({error:'Maximum attempts reached'},409);const id=uid('result'),t=nowISO();await env.DB.prepare(`INSERT INTO QUIZ_RESULTS(resultID,quizID,userID,score,maxScore,startedAt,attemptNumber,status) VALUES(?,?,?,?,?,?,?,?)`).bind(id,q.quizID,user.userID,0,q.maxScore,t,attempt,'in_progress').run();return json({resultID:id,attemptNumber:attempt,startedAt:t});}
    const quizSubmit=path.match(/^\/api\/quizzes\/([^/]+)\/submit$/); if(quizSubmit&&method==='POST'){const body=await request.json();const q=await env.DB.prepare(`SELECT * FROM QUIZZES WHERE quizID=?`).bind(quizSubmit[1]).first();if(!q)return json({error:'Quiz not found'},404);await requireClassMember(env,q.classID,user.userID,['student']);const result=await env.DB.prepare(`SELECT * FROM QUIZ_RESULTS WHERE resultID=? AND quizID=? AND userID=? AND status='in_progress'`).bind(body.resultID,q.quizID,user.userID).first();if(!result)return json({error:'Invalid attempt'},409);const questions=(await env.DB.prepare(`SELECT * FROM QUIZ_QUESTIONS WHERE quizID=? ORDER BY orderIndex`).bind(q.quizID).all()).results||[];const answers=body.answers||{};let score=0,manual=false;for(const qu of questions){const a=answers[qu.questionID];let correct;try{correct=JSON.parse(qu.correctAnswerJSON||'null')}catch{correct=null}if(qu.questionType==='essay'||qu.questionType==='matching') manual=true; else if(qu.questionType==='multiple_choice' || qu.questionType==='fill_blank'){const ca=String(correct??'').trim().toLowerCase();if(String(a??'').trim().toLowerCase()===ca)score+=Number(qu.score||0);} else if(qu.questionType==='multiple_answer'){const aa=Array.isArray(a)?[...a].map(String).sort():[];const ca=Array.isArray(correct)?[...correct].map(String).sort():[];if(JSON.stringify(aa)===JSON.stringify(ca))score+=Number(qu.score||0);}}
      const status=manual?'submitted':'graded'; await env.DB.prepare(`UPDATE QUIZ_RESULTS SET score=?,submittedAt=?,answersJSON=?,status=? WHERE resultID=?`).bind(score,nowISO(),JSON.stringify(answers),status,result.resultID).run();const settings=await getSettings(env);await addXP(env,user.userID,'quiz_attempt',Number(settings.xp?.quiz_attempt||15),result.resultID);if(!manual && q.maxScore>0 && score/q.maxScore>=.8)await addXP(env,user.userID,'quiz_over_80',Number(settings.xp?.quiz_over_80||25),result.resultID);await notify(env,user.userID,'quiz_submitted','ส่งข้อสอบแล้ว',manual?'รอครูตรวจ':'ระบบตรวจข้อสอบให้แล้ว',`/?view=quizzes&id=${q.quizID}`);return json({ok:true,score,maxScore:q.maxScore,status});}

    // Wallet / transfer / topups.
    if(path==='/api/wallet'&&method==='GET'){const w=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(user.userID).first();const tx=await env.DB.prepare(`SELECT * FROM TRANSACTIONS WHERE sourceUserID=? OR destinationUserID=? ORDER BY createdAt DESC LIMIT 20`).bind(user.userID,user.userID).all();return json({wallet:w,transactions:tx.results||[]});}
    if(path==='/api/transactions/transfer'&&method==='POST'){const body=await request.json();const destinationID=String(body.destinationUserID||'');if(!destinationID||destinationID===user.userID)return json({error:'Invalid destination'},400);const currency=['THB','COIN'].includes(body.currency)?body.currency:'COIN';const amount=Number(body.amount);if(!Number.isFinite(amount)||amount<=0)return json({error:'Invalid amount'},400);const settings=await getSettings(env);if(currency==='THB'&&amount>Number(settings.transactionLimitTHB||5000))return json({error:'Transaction limit exceeded'},400);const dest=await env.DB.prepare(`SELECT userID FROM USERS WHERE userID=? AND status='approved'`).bind(destinationID).first();if(!dest)return json({error:'Destination not found'},404);const sourceWallet=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(user.userID).first();const destWallet=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(destinationID).first();if(!sourceWallet||!destWallet)return json({error:'Wallet not found'},404);const srcBal=currency==='THB'?Number(sourceWallet.balanceTHB):Number(sourceWallet.balanceCoin);if(srcBal<amount)return json({error:'Insufficient balance'},400);const dstBal=currency==='THB'?Number(destWallet.balanceTHB):Number(destWallet.balanceCoin);const ref=uid('transfer');const beforeSrc=srcBal,afterSrc=srcBal-amount,beforeDst=dstBal,afterDst=dstBal+amount;const limitResetDate=new Date().toISOString().slice(0,10);const dailyLimit=Number(sourceWallet.dailySpendingLimit||0);const dailySpentDate=sourceWallet.dailySpentDate;const dailySpent= dailySpentDate===limitResetDate?Number(sourceWallet.dailySpentTHB||0):0;if(currency==='THB'&&dailyLimit>0&&dailySpent+amount>dailyLimit)return json({error:'Daily spending limit exceeded'},400);const fields=currency==='THB'?['balanceTHB','balanceCoin']:['balanceCoin','balanceTHB'];await env.DB.batch([
      env.DB.prepare(`UPDATE WALLETS SET ${fields[0]}=?,dailySpentTHB=?,dailySpentDate=?,updatedAt=? WHERE walletID=?`).bind(afterSrc,currency==='THB'?dailySpent+amount:dailySpent,limitResetDate,nowISO(),sourceWallet.walletID),
      env.DB.prepare(`UPDATE WALLETS SET ${fields[0]}=?,updatedAt=? WHERE walletID=?`).bind(afterDst,nowISO(),destWallet.walletID),
      env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,note,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),user.userID,destinationID,'transfer_out',currency,amount,beforeSrc,afterSrc,String(body.note||''),ref,nowISO(),'completed'),
      env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,note,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),user.userID,destinationID,'transfer_in',currency,amount,beforeDst,afterDst,String(body.note||''),ref,nowISO(),'completed')
    ]);await notify(env,destinationID,'wallet_in','มีเงินเข้า Wallet',`${amount} ${currency}`,`/?view=wallet`);await audit(env,request,user.userID,'CREATE_TRANSACTION','TRANSACTION',ref,{currency,amount,destinationID});return json({ok:true,referenceID:ref});}
    if(path==='/api/topups'&&method==='POST'){const body=await request.json();const amount=Number(body.amount);if(!(amount>0))return json({error:'Invalid amount'},400);const id=uid('topup');await env.DB.prepare(`INSERT INTO TOPUP_REQUESTS(requestID,userID,amount,slipFileID,channel,requestedAt,status) VALUES(?,?,?,?,?,?,?)`).bind(id,user.userID,amount,body.slipFileID||null,String(body.channel||'bank_transfer'),nowISO(),'pending').run();await notifyToAdmins(env,'topup','มีคำขอเติมเงินใหม่',`${amount.toFixed(2)} บาท`,`/?view=admin-topups&id=${id}`);return json({ok:true,requestID:id},201);}
    const topupAction=path.match(/^\/api\/topups\/([^/]+)\/(approve|reject)$/);if(topupAction&&method==='POST'){requireRole(user,['admin','teacher']);const req=await env.DB.prepare(`SELECT * FROM TOPUP_REQUESTS WHERE requestID=?`).bind(topupAction[1]).first();if(!req||req.status!=='pending')return json({error:'Request not found or already processed'},404);const body=await request.json().catch(()=>({}));if(topupAction[2]==='reject'){const reason=String(body.reason||'ไม่ผ่านการอนุมัติ').slice(0,1000);await env.DB.prepare(`UPDATE TOPUP_REQUESTS SET status='rejected',approvedBy=?,approvedAt=?,rejectionReason=? WHERE requestID=?`).bind(user.userID,nowISO(),reason,req.requestID).run();await notify(env,req.userID,'topup_rejected','คำขอเติมเงินถูกปฏิเสธ',reason,'/?view=wallet');const ru=await env.DB.prepare(`SELECT email FROM USERS WHERE userID=?`).bind(req.userID).first();await sendEmail(env,req.userID,ru?.email||'','SchoolVerse: Top Up ถูกปฏิเสธ',reason);return json({ok:true});}
      const w=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(req.userID).first();const before=Number(w.balanceTHB||0),after=before+Number(req.amount),ref=uid('topup');await env.DB.batch([
        env.DB.prepare(`UPDATE TOPUP_REQUESTS SET status='approved',approvedBy=?,approvedAt=? WHERE requestID=?`).bind(user.userID,nowISO(),req.requestID),
        env.DB.prepare(`UPDATE WALLETS SET balanceTHB=?,updatedAt=? WHERE userID=?`).bind(after,nowISO(),req.userID),
        env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),null,req.userID,'topup','THB',req.amount,before,after,ref,nowISO(),'completed')
      ]);await notify(env,req.userID,'topup_approved','เติมเงินสำเร็จ',`${req.amount.toFixed(2)} บาท`,`/?view=wallet`);const ru=await env.DB.prepare(`SELECT email FROM USERS WHERE userID=?`).bind(req.userID).first();await sendEmail(env,req.userID,ru?.email||'','SchoolVerse: เติมเงินสำเร็จ',`เติมเงิน ${req.amount.toFixed(2)} บาทสำเร็จ`);await audit(env,request,user.userID,'APPROVE_TOPUP','TOPUP',req.requestID,{amount:req.amount});return json({ok:true});}

    // Marketplace
    if(path==='/api/shops'&&method==='GET'){const rows=await env.DB.prepare(`SELECT s.*,u.firstName,u.lastName FROM SHOPS s JOIN USERS u ON u.userID=s.userID WHERE s.status='approved' ORDER BY s.createdAt DESC`).all();return json({items:rows.results||[]});}
    if(path==='/api/shops'&&method==='POST'){const body=await request.json();const existing=await env.DB.prepare(`SELECT shopID FROM SHOPS WHERE userID=? AND status IN ('pending','approved')`).bind(user.userID).first();if(existing)return json({error:'You already have a shop'},409);const id=uid('shop');await env.DB.prepare(`INSERT INTO SHOPS(shopID,userID,ownerName,shopName,category,description,logoFileID,status,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(id,user.userID,`${user.firstName} ${user.lastName}`,requireString(body.shopName,'shopName',200),String(body.category||''),String(body.description||''),body.logoFileID||null,'pending',nowISO(),nowISO()).run();await notifyToAdmins(env,'shop_pending','มีร้านค้าใหม่รออนุมัติ',body.shopName,`/?view=admin-shops&id=${id}`);return json({ok:true,shopID:id},201);}
    if(path==='/api/products'&&method==='GET'){const shopID=url.searchParams.get('shopID');let q=`SELECT p,s.shopName FROM PRODUCTS p JOIN SHOPS s ON s.shopID=p.shopID WHERE p.status IN ('active','sold_out') AND s.status='approved'`;const b=[];if(shopID){q+=` AND p.shopID=?`;b.push(shopID);}q+=` ORDER BY p.createdAt DESC LIMIT 200`;const rows=await env.DB.prepare(q).bind(...b).all();return json({items:rows.results||[]});}
    if(path==='/api/products'&&method==='POST'){requireRole(user,['student','admin']);const body=await request.json();const shop=await env.DB.prepare(`SELECT * FROM SHOPS WHERE shopID=? AND userID=? AND status='approved'`).bind(body.shopID,user.userID).first();if(!shop)return json({error:'Shop not found or not approved'},403);if(!(Number(body.priceTHB)>0||Number(body.priceCoin)>0))return json({error:'Set a price'},400);const id=uid('product');await env.DB.prepare(`INSERT INTO PRODUCTS(productID,shopID,name,description,priceTHB,priceCoin,stock,category,status,createdAt,updatedAt,promotionPrice,promotionStart,promotionEnd) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,shop.shopID,requireString(body.name,'name',250),String(body.description||''),body.priceTHB===''?null:Number(body.priceTHB||0),body.priceCoin===''?null:Number(body.priceCoin||0),Math.max(0,Number(body.stock||0)),String(body.category||''),Number(body.stock||0)>0?'active':'sold_out',nowISO(),nowISO(),body.promotionPrice===''?null:(body.promotionPrice==null?null:Number(body.promotionPrice)),body.promotionStart||null,body.promotionEnd||null).run();return json({ok:true,productID:id},201);}
    const orderPath=path.match(/^\/api\/orders\/([^/]+)$/);if(path==='/api/orders'&&method==='POST'){const body=await request.json();const p=await env.DB.prepare(`SELECT p.*,s.userID AS sellerID,s.shopID FROM PRODUCTS p JOIN SHOPS s ON s.shopID=p.shopID WHERE p.productID=? AND p.status='active' AND s.status='approved'`).bind(body.productID).first();if(!p)return json({error:'Product not available'},404);const quantity=Math.max(1,Math.floor(Number(body.quantity||1)));if(Number(p.stock)<quantity)return json({error:'Insufficient stock'},400);const currency=body.currency==='COIN'?'COIN':'THB';const unit=currency==='THB'?Number(p.promotionPrice&&inPromotion(p)?p.promotionPrice:p.priceTHB):Number(p.priceCoin);if(!(unit>0))return json({error:'Selected currency is not supported'},400);const total=unit*quantity;const w=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(user.userID).first();const bal=currency==='THB'?Number(w.balanceTHB):Number(w.balanceCoin);if(bal<total)return json({error:'Insufficient wallet balance'},400);const today=new Date().toISOString().slice(0,10);const spentDate=w.dailySpentDate===today?w.dailySpentDate:null;const dailySpent=spentDate?Number(w.dailySpentTHB||0):0;if(currency==='THB'&&Number(w.dailySpendingLimit||0)>0&&dailySpent+total>Number(w.dailySpendingLimit))return json({error:'Daily spending limit exceeded'},400);const id=uid('order'),esc=uid('escrow'),ref=uid('orderpay'),before=bal,after=bal-total,t=nowISO();await env.DB.batch([
      env.DB.prepare(`UPDATE WALLETS SET ${currency==='THB'?'balanceTHB':'balanceCoin'}=?,dailySpentTHB=?,dailySpentDate=?,updatedAt=? WHERE userID=?`).bind(after,currency==='THB'?dailySpent+total:dailySpent,today,t,user.userID),
      env.DB.prepare(`UPDATE PRODUCTS SET stock=stock-?,soldCount=soldCount+?,status=CASE WHEN stock-?<=0 THEN 'sold_out' ELSE status END,updatedAt=? WHERE productID=?`).bind(quantity,quantity,quantity,t,p.productID),
      env.DB.prepare(`INSERT INTO ORDERS(orderID,productID,shopID,buyerID,quantity,totalPrice,currency,paymentMethod,status,note,orderedAt,updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,p.productID,p.shopID,user.userID,quantity,total,currency,currency,'pending',String(body.note||''),t,t),
      env.DB.prepare(`INSERT INTO ESCROW(escrowID,orderID,buyerID,shopID,amount,currency,status,createdAt) VALUES(?,?,?,?,?,?,?,?)`).bind(esc,id,user.userID,p.shopID,total,currency,'held',t),
      env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,orderID,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),user.userID,p.sellerID,'purchase_hold',currency,total,before,after,id,ref,t,'completed')
    ]);await notify(env,p.sellerID,'order','มีคำสั่งซื้อใหม่',`${p.name} × ${quantity}`,`/?view=shop-orders&id=${id}`);return json({ok:true,orderID:id},201);}
    if(orderPath&&method==='GET'){const o=await env.DB.prepare(`SELECT o.*,p.name,s.shopName FROM ORDERS o JOIN PRODUCTS p ON p.productID=o.productID JOIN SHOPS s ON s.shopID=o.shopID WHERE o.orderID=? AND (o.buyerID=? OR s.userID=?)`).bind(orderPath[1],user.userID,user.userID).first();if(!o)return json({error:'Order not found'},404);const e=await env.DB.prepare(`SELECT * FROM ESCROW WHERE orderID=?`).bind(o.orderID).first();return json({order:o,escrow:e});}
    const orderAction=path.match(/^\/api\/orders\/([^/]+)\/(confirm|reject|ship|receive)$/);if(orderAction&&method==='POST'){const o=await env.DB.prepare(`SELECT o.*,s.userID AS sellerID FROM ORDERS o JOIN SHOPS s ON s.shopID=o.shopID WHERE o.orderID=?`).bind(orderAction[1]).first();if(!o)return json({error:'Order not found'},404);const e=await env.DB.prepare(`SELECT * FROM ESCROW WHERE orderID=?`).bind(o.orderID).first();const body=await request.json().catch(()=>({}));if(orderAction[2]==='receive'){if(o.buyerID!==user.userID)return json({error:'Forbidden'},403);await env.DB.prepare(`UPDATE ORDERS SET status='received',receivedAt=?,updatedAt=? WHERE orderID=?`).bind(nowISO(),nowISO(),o.orderID).run();return json({ok:true});}if(o.sellerID!==user.userID&&user.role!=='admin')return json({error:'Forbidden'},403);if(orderAction[2]==='confirm'||orderAction[2]==='ship'){if(orderAction[2]==='confirm'){const shopWallet=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(o.sellerID).first();const before=Number(shopWallet.balanceTHB||0),afterTHB=o.currency==='THB'?before+Number(o.totalPrice):before,beforeCoin=Number(shopWallet.balanceCoin||0),afterCoin=o.currency==='COIN'?beforeCoin+Number(o.totalPrice):beforeCoin;await env.DB.batch([env.DB.prepare(`UPDATE ESCROW SET status='released',releasedAt=? WHERE orderID=?`).bind(nowISO(),o.orderID),env.DB.prepare(`UPDATE ORDERS SET status='confirmed',updatedAt=? WHERE orderID=?`).bind(nowISO(),o.orderID),env.DB.prepare(`UPDATE WALLETS SET balanceTHB=?,balanceCoin=?,updatedAt=? WHERE userID=?`).bind(afterTHB,afterCoin,nowISO(),o.sellerID),env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,orderID,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),o.buyerID,o.sellerID,'escrow_release',o.currency,o.totalPrice,o.currency==='THB'?before:beforeCoin,o.currency==='THB'?afterTHB:afterCoin,o.orderID,uid('release'),nowISO(),'completed')]);await notify(env,o.buyerID,'order_confirmed','ร้านยืนยันคำสั่งซื้อ','เงินถูกปล่อยจาก Escrow แล้ว',`/?view=wallet`);return json({ok:true});}await env.DB.prepare(`UPDATE ORDERS SET status='shipped',updatedAt=? WHERE orderID=?`).bind(nowISO(),o.orderID).run();return json({ok:true});}
      if(orderAction[2]==='reject'){await env.DB.batch([env.DB.prepare(`UPDATE ESCROW SET status='refunded',refundedAt=? WHERE orderID=?`).bind(nowISO(),o.orderID),env.DB.prepare(`UPDATE ORDERS SET status='rejected',note=?,updatedAt=? WHERE orderID=?`).bind(String(body.reason||'ร้านค้าปฏิเสธคำสั่งซื้อ'),nowISO(),o.orderID),env.DB.prepare(`UPDATE PRODUCTS SET stock=stock+?,status='active',updatedAt=? WHERE productID=?`).bind(o.quantity,nowISO(),o.productID)]);const w=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(o.buyerID).first();const before=Number(o.currency==='THB'?w.balanceTHB:w.balanceCoin),after=before+Number(o.totalPrice);await env.DB.prepare(`UPDATE WALLETS SET ${o.currency==='THB'?'balanceTHB':'balanceCoin'}=?,updatedAt=? WHERE userID=?`).bind(after,nowISO(),o.buyerID).run();await env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,orderID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),o.sellerID,o.buyerID,'escrow_refund',o.currency,o.totalPrice,before,after,o.orderID,nowISO(),'completed').run();await notify(env,o.buyerID,'order_rejected','คำสั่งซื้อถูกปฏิเสธ','เงินถูกคืนเข้า Wallet แล้ว',`/?view=wallet`);return json({ok:true});}
    }

    // Parent-child management and parent-funded wallet.
    if(path==='/api/parent/children'&&method==='GET'){
      requireRole(user,'parent');
      const rows=await env.DB.prepare(`SELECT u.userID,u.firstName,u.lastName,u.email,u.xp,u.level,u.gradeLevel FROM PARENT_LINKS p JOIN USERS u ON u.userID=p.childID WHERE p.parentID=? AND p.status='active' ORDER BY u.lastName,u.firstName`).bind(user.userID).all();
      return json({items:rows.results||[]});
    }
    if(path==='/api/parent/topup-child'&&method==='POST'){
      requireRole(user,'parent');
      const body=await request.json(); const childID=String(body.childID||''), amount=Number(body.amount), currency=body.currency==='COIN'?'COIN':'THB';
      if(!childID||childID===user.userID||!(amount>0)) return json({error:'Invalid child or amount'},400);
      const link=await env.DB.prepare(`SELECT linkID FROM PARENT_LINKS WHERE parentID=? AND childID=? AND status='active'`).bind(user.userID,childID).first(); if(!link)return json({error:'Child is not linked to this parent'},403);
      const parentWallet=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(user.userID).first(); const childWallet=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(childID).first();
      if(!parentWallet||!childWallet)return json({error:'Wallet not found'},404); const pbal=currency==='THB'?Number(parentWallet.balanceTHB):Number(parentWallet.balanceCoin); if(pbal<amount)return json({error:'Insufficient parent balance'},400); const cbal=currency==='THB'?Number(childWallet.balanceTHB):Number(childWallet.balanceCoin); const ref=uid('parenttransfer');
      await env.DB.batch([
        env.DB.prepare(`UPDATE WALLETS SET ${currency==='THB'?'balanceTHB':'balanceCoin'}=?,updatedAt=? WHERE userID=?`).bind(pbal-amount,nowISO(),user.userID),
        env.DB.prepare(`UPDATE WALLETS SET ${currency==='THB'?'balanceTHB':'balanceCoin'}=?,updatedAt=? WHERE userID=?`).bind(cbal+amount,nowISO(),childID),
        env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,note,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),user.userID,childID,'parent_transfer_out',currency,amount,pbal,pbal-amount,String(body.note||''),ref,nowISO(),'completed'),
        env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,note,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),user.userID,childID,'parent_transfer_in',currency,amount,cbal,cbal+amount,String(body.note||''),ref,nowISO(),'completed')
      ]); await notify(env,childID,'wallet_in','ผู้ปกครองเติมเงินให้คุณ',`${amount} ${currency}`,'/?view=wallet'); return json({ok:true,referenceID:ref});
    }

    if(path==='/api/wallet/limit'&&method==='PATCH'){
      requireRole(user,['student','parent','admin','teacher']); const body=await request.json(); const limit=body.dailySpendingLimit===''||body.dailySpendingLimit==null?null:Math.max(0,Number(body.dailySpendingLimit));
      await env.DB.prepare(`UPDATE WALLETS SET dailySpendingLimit=?,updatedAt=? WHERE userID=?`).bind(limit,nowISO(),user.userID).run(); await audit(env,request,user.userID,'SET_SPENDING_LIMIT','WALLET',user.userID,{limit}); return json({ok:true});
    }
    if(path==='/api/teacher-admin/wallet/credit'&&method==='POST'){
      requireRole(user,['teacher','admin']); const body=await request.json(); const destinationUserID=String(body.destinationUserID||''),amount=Number(body.amount),currency=body.currency==='COIN'?'COIN':'THB'; if(!destinationUserID||destinationUserID===user.userID||!(amount>0))return json({error:'Invalid destination or amount'},400);
      const dest=await env.DB.prepare(`SELECT userID,status FROM USERS WHERE userID=?`).bind(destinationUserID).first();if(!dest||dest.status!=='approved')return json({error:'Destination not found'},404); const w=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(destinationUserID).first(); const before=currency==='THB'?Number(w.balanceTHB):Number(w.balanceCoin),after=before+amount,ref=uid('credit');
      await env.DB.batch([env.DB.prepare(`UPDATE WALLETS SET ${currency==='THB'?'balanceTHB':'balanceCoin'}=?,updatedAt=? WHERE userID=?`).bind(after,nowISO(),destinationUserID),env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,note,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),user.userID,destinationUserID,'staff_credit',currency,amount,before,after,String(body.note||''),ref,nowISO(),'completed')]); await notify(env,destinationUserID,'wallet_in','ได้รับเงินจากเจ้าหน้าที่',`${amount} ${currency}`,`/?view=wallet`); await audit(env,request,user.userID,'CREDIT_WALLET','WALLET',destinationUserID,{amount,currency,referenceID:ref}); return json({ok:true,referenceID:ref});
    }

    // Parent links: Admin establishes verified family relationships.
    const linkMatch=path.match(/^\/api\/admin\/parent-links(?:\/([^/]+))?$/);
    if(linkMatch&&method==='GET'){requireRole(user,'admin');const rows=await env.DB.prepare(`SELECT p.*,pa.firstName AS parentFirstName,pa.lastName AS parentLastName,ch.firstName AS childFirstName,ch.lastName AS childLastName FROM PARENT_LINKS p JOIN USERS pa ON pa.userID=p.parentID JOIN USERS ch ON ch.userID=p.childID ORDER BY p.createdAt DESC`).all();return json({items:rows.results||[]});}
    if(linkMatch&&method==='POST'){requireRole(user,'admin');const body=await request.json();const parentID=String(body.parentID||''),childID=String(body.childID||'');if(!parentID||!childID||parentID===childID)return json({error:'Invalid users'},400);const p=await env.DB.prepare(`SELECT userID,role,status FROM USERS WHERE userID=?`).bind(parentID).first();const c=await env.DB.prepare(`SELECT userID,role,status FROM USERS WHERE userID=?`).bind(childID).first();if(!p||p.role!=='parent'||p.status!=='approved'||!c||c.role!=='student'||c.status!=='approved')return json({error:'Parent/child accounts are invalid'},400);await env.DB.prepare(`INSERT INTO PARENT_LINKS(linkID,parentID,childID,createdAt,status) VALUES(?,?,?,?,?) ON CONFLICT(parentID,childID) DO UPDATE SET status='active'`).bind(uid('link'),parentID,childID,nowISO(),'active').run();await notify(env,parentID,'parent_link','เชื่อมบัญชีบุตรแล้ว',`${c.userID}`,'/?view=dashboard');return json({ok:true});}

    // Marketplace admin moderation.
    if(path==='/api/admin/shops'&&method==='GET'){requireRole(user,'admin');const rows=await env.DB.prepare(`SELECT s.*,u.firstName,u.lastName,u.email FROM SHOPS s JOIN USERS u ON u.userID=s.userID ORDER BY s.createdAt DESC LIMIT 300`).all();return json({items:rows.results||[]});}
    const shopAction=path.match(/^\/api\/admin\/shops\/([^/]+)\/(approve|reject|suspend)$/); if(shopAction&&method==='POST'){requireRole(user,'admin');const body=await request.json().catch(()=>({}));const shop=await env.DB.prepare(`SELECT * FROM SHOPS WHERE shopID=?`).bind(shopAction[1]).first();if(!shop)return json({error:'Shop not found'},404);const status=shopAction[2]==='approve'?'approved':shopAction[2]==='reject'?'closed':'suspended';await env.DB.prepare(`UPDATE SHOPS SET status=?,updatedAt=? WHERE shopID=?`).bind(status,nowISO(),shop.shopID).run();await notify(env,shop.userID,`shop_${shopAction[2]}`,`ร้านค้า ${shopAction[2]}`,String(body.reason||''),`/?view=marketplace`);await audit(env,request,user.userID,`${shopAction[2].toUpperCase()}_SHOP`,'SHOP',shop.shopID,{reason:body.reason||null});return json({ok:true,status});}

    // Auctions.
    if(path==='/api/auctions'&&method==='GET'){const rows=await env.DB.prepare(`SELECT a.*,p.name AS productName,s.shopName,u.firstName,u.lastName FROM AUCTIONS a JOIN PRODUCTS p ON p.productID=a.productID JOIN SHOPS s ON s.shopID=a.shopID LEFT JOIN USERS u ON u.userID=a.highestBidderID WHERE a.status IN ('open','closed') ORDER BY a.closesAt ASC LIMIT 200`).all();return json({items:rows.results||[]});}
    if(path==='/api/auctions'&&method==='POST'){const body=await request.json();const p=await env.DB.prepare(`SELECT p.*,s.userID AS sellerID,s.status AS shopStatus FROM PRODUCTS p JOIN SHOPS s ON s.shopID=p.shopID WHERE p.productID=?`).bind(body.productID).first();if(!p||p.sellerID!==user.userID||p.shopStatus!=='approved')return json({error:'Product not found or shop not approved'},403);const start=Math.max(0,Math.floor(Number(body.startPrice||0)));const closesAt=requireString(body.closesAt,'closesAt',50);if(start<=0||Date.parse(closesAt)<=Date.now())return json({error:'Invalid auction'},400);const id=uid('auction');await env.DB.prepare(`INSERT INTO AUCTIONS(auctionID,productID,shopID,startPrice,currentPrice,closesAt,status,createdAt) VALUES(?,?,?,?,?,?,?,?)`).bind(id,p.productID,p.shopID,start,start,closesAt,'open',nowISO()).run();return json({ok:true,auctionID:id},201);}
    const bidMatch=path.match(/^\/api\/auctions\/([^/]+)\/bid$/);if(bidMatch&&method==='POST'){requireRole(user,'student');const a=await env.DB.prepare(`SELECT a.*,s.userID AS sellerID FROM AUCTIONS a JOIN SHOPS s ON s.shopID=a.shopID WHERE a.auctionID=? AND a.status='open'`).bind(bidMatch[1]).first();if(!a)return json({error:'Auction not open'},404);if(a.sellerID===user.userID)return json({error:'Seller cannot bid on own auction'},400);if(Date.parse(a.closesAt)<=Date.now())return json({error:'Auction closed'},409);const amount=Math.floor(Number((await request.json()).amount));if(amount<=Number(a.currentPrice))return json({error:'Bid must be higher than current price'},400);await env.DB.batch([env.DB.prepare(`INSERT INTO AUCTION_BIDS(bidID,auctionID,userID,amount,createdAt) VALUES(?,?,?,?,?)`).bind(uid('bid'),a.auctionID,user.userID,amount,nowISO()),env.DB.prepare(`UPDATE AUCTIONS SET currentPrice=?,highestBidderID=? WHERE auctionID=?`).bind(amount,user.userID,a.auctionID)]);await notify(env,user.userID,'auction_bid','บันทึกการประมูลแล้ว',`ราคา ${amount} Coin`,`/?view=marketplace`);return json({ok:true,currentPrice:amount});}

    if(path==='/api/admin/export'&&method==='GET'){
      requireRole(user,'admin');
      const tables=['USERS','WALLETS','TRANSACTIONS','TOPUP_REQUESTS','SHOPS','PRODUCTS','ORDERS','ESCROW','POSTS','COMMENTS','REACTIONS','CLASSES','CLASS_MEMBERS','LESSONS','LESSON_PROGRESS','ASSIGNMENTS','SUBMISSIONS','QUIZZES','QUIZ_QUESTIONS','QUIZ_RESULTS','GAME_STATS','XP_EVENTS','ACHIEVEMENTS','BADGE_RULES','SEASONS','SEASON_RESULTS','NOTIFICATIONS','EMAIL_LOGS','AUDIT_LOGS','SYSTEM_SETTINGS','PARENT_LINKS','AUCTIONS','AUCTION_BIDS'];
      const out={exportedAt:nowISO(),version:'1.0.0',tables:{}};
      for(const t of tables){if(t==='USERS')out.tables[t]=(await env.DB.prepare(`SELECT userID,firstName,lastName,email,role,classID,gradeLevel,walletID,xp,level,status,profileFileID,createdAt,lastLoginAt,failedLoginAttempts,lockedUntil FROM USERS`).all()).results||[];else if(t==='SYSTEM_SETTINGS')out.tables[t]=(await env.DB.prepare(`SELECT settingKey,settingValueJSON,updatedAt,updatedBy FROM SYSTEM_SETTINGS`).all()).results||[];else out.tables[t]=(await env.DB.prepare(`SELECT * FROM ${t}`).all()).results||[];}
      await audit(env,request,user.userID,'EXPORT_DATA','SYSTEM',null,{tables:tables.length});
      return new Response(JSON.stringify(out,null,2),{status:200,headers:{'Content-Type':'application/json; charset=utf-8','Content-Disposition':`attachment; filename="schoolverse-export-${new Date().toISOString().slice(0,10)}.json"`,'Cache-Control':'no-store'}});
    }
    if(path==='/api/analytics/teacher'&&method==='GET'){
      requireRole(user,['teacher','admin']);
      const rows=await env.DB.prepare(`SELECT a.assignID,a.title,c.subjectName,ROUND(AVG(s.score),2) AS averageScore,COUNT(s.submitID) AS submissions,COUNT(cm.userID) AS enrolled,ROUND(CASE WHEN COUNT(cm.userID)=0 THEN 0 ELSE 100.0*COUNT(s.submitID)/COUNT(cm.userID) END,2) AS submissionRate FROM ASSIGNMENTS a JOIN CLASSES c ON c.classID=a.classID JOIN CLASS_MEMBERS cm ON cm.classID=a.classID AND cm.role='student' LEFT JOIN SUBMISSIONS s ON s.assignID=a.assignID WHERE c.teacherID=? GROUP BY a.assignID ORDER BY a.dueAt DESC LIMIT 200`).bind(user.userID).all();
      return json({items:rows.results||[]});
    }

    // Leaderboard and game stats.
    if(path==='/api/leaderboard'&&method==='GET'){const limit=Math.min(Number(url.searchParams.get('limit')||10),50);const rows=await env.DB.prepare(`SELECT userID,firstName,lastName,xp,level FROM USERS WHERE status='approved' AND role='student' ORDER BY xp DESC LIMIT ?`).bind(limit).all();const me=await env.DB.prepare(`SELECT COUNT(*)+1 AS rank FROM USERS WHERE status='approved' AND role='student' AND xp>(SELECT xp FROM USERS WHERE userID=?)`).bind(user.userID).first();return json({items:rows.results||[],myRank:Number(me?.rank||0)});}
    if(path==='/api/game-stats'&&method==='GET'){const stat=await env.DB.prepare(`SELECT * FROM GAME_STATS WHERE userID=?`).bind(user.userID).first();return json({stat});}

    // Admin.
    if(path==='/api/admin/users'&&method==='GET'){requireRole(user,'admin');const role=url.searchParams.get('role'),status=url.searchParams.get('status'),qtext=url.searchParams.get('q');let q=`SELECT userID,firstName,lastName,email,role,classID,gradeLevel,xp,level,status,createdAt,lastLoginAt,failedLoginAttempts,lockedUntil FROM USERS WHERE 1=1`;const b=[];if(role){q+=` AND role=?`;b.push(role);}if(status){q+=` AND status=?`;b.push(status);}if(qtext){q+=` AND (firstName||' '||lastName LIKE ? OR email LIKE ?)`;b.push(`%${qtext}%`,`%${qtext}%`);}q+=` ORDER BY createdAt DESC LIMIT 500`;const rows=await env.DB.prepare(q).bind(...b).all();return json({items:rows.results||[]});}
    const userAction=path.match(/^\/api\/admin\/users\/([^/]+)\/(approve|reject|suspend|unsuspend|role|reset-password)$/);if(userAction&&method==='POST'){requireRole(user,'admin');const targetID=userAction[1];if(targetID===user.userID&&['suspend','role'].includes(userAction[2]))return json({error:'Cannot change your own critical role/status'},400);const target=await env.DB.prepare(`SELECT * FROM USERS WHERE userID=?`).bind(targetID).first();if(!target)return json({error:'User not found'},404);const action=userAction[2];if(action==='approve'){await env.DB.prepare(`UPDATE USERS SET status='approved' WHERE userID=?`).bind(targetID).run();await notify(env,targetID,'account_approved','บัญชีได้รับการอนุมัติ','สามารถเข้าสู่ระบบได้แล้ว','/');await sendEmail(env,targetID,target.email,'SchoolVerse: บัญชีได้รับการอนุมัติ','บัญชีของคุณได้รับการอนุมัติและสามารถเข้าสู่ระบบ SchoolVerse ได้แล้ว');await audit(env,request,user.userID,'APPROVE_USER','USER',targetID);return json({ok:true});}if(action==='reject'){await env.DB.prepare(`UPDATE USERS SET status='rejected' WHERE userID=?`).bind(targetID).run();await audit(env,request,user.userID,'REJECT_USER','USER',targetID);return json({ok:true});}if(action==='suspend'){await env.DB.batch([env.DB.prepare(`UPDATE USERS SET status='suspended' WHERE userID=?`).bind(targetID),env.DB.prepare(`UPDATE SESSIONS SET status='revoked' WHERE userID=?`).bind(targetID)]);await audit(env,request,user.userID,'SUSPEND_USER','USER',targetID);return json({ok:true});}if(action==='unsuspend'){await env.DB.prepare(`UPDATE USERS SET status='approved' WHERE userID=?`).bind(targetID).run();await audit(env,request,user.userID,'UNSUSPEND_USER','USER',targetID);return json({ok:true});}if(action==='role'){const body=await request.json();const role=['admin','teacher','student','parent'].includes(body.role)?body.role:null;if(!role)return json({error:'Invalid role'},400);await env.DB.prepare(`UPDATE USERS SET role=? WHERE userID=?`).bind(role,targetID).run();await audit(env,request,user.userID,'CHANGE_ROLE','USER',targetID,{role});return json({ok:true});}if(action==='reset-password'){const body=await request.json();const password=requireString(body.password,'password',200);if(password.length<8)return json({error:'Password must be at least 8 characters'},400);const hash=await hashPassword(password,env);await env.DB.prepare(`UPDATE USERS SET passwordHash=?,failedLoginAttempts=0,lockedUntil=NULL WHERE userID=?`).bind(hash,targetID).run();await env.DB.prepare(`UPDATE SESSIONS SET status='revoked' WHERE userID=?`).bind(targetID).run();await audit(env,request,user.userID,'RESET_PASSWORD','USER',targetID);return json({ok:true});}}
    if(path==='/api/admin/settings'&&method==='GET'){requireRole(user,'admin');return json(await getSettings(env));}
    if(path==='/api/admin/settings'&&method==='PATCH'){requireRole(user,'admin');const body=await request.json();for(const [k,v] of Object.entries(body)) await setSetting(env,user.userID,k,v);await audit(env,request,user.userID,'CHANGE_SYSTEM_SETTING','SETTING',null,body);return json({ok:true});}
    if(path==='/api/admin/topups'&&method==='GET'){requireRole(user,'admin');const rows=await env.DB.prepare(`SELECT t.*,u.firstName,u.lastName,u.email FROM TOPUP_REQUESTS t JOIN USERS u ON u.userID=t.userID ORDER BY t.requestedAt DESC LIMIT 300`).all();return json({items:rows.results||[]});}
    if(path==='/api/admin/audit-logs'&&method==='GET'){requireRole(user,'admin');const rows=await env.DB.prepare(`SELECT a.*,u.firstName,u.lastName FROM AUDIT_LOGS a LEFT JOIN USERS u ON u.userID=a.userID ORDER BY a.createdAt DESC LIMIT 300`).all();return json({items:rows.results||[]});}
    if(path==='/api/admin/moderation'&&method==='GET'){requireRole(user,'admin');const rows=await env.DB.prepare(`SELECT p.*,u.firstName,u.lastName,COUNT(r.reportID) AS reports FROM POSTS p JOIN USERS u ON u.userID=p.userID LEFT JOIN POST_REPORTS r ON r.postID=p.postID AND r.status='open' WHERE p.status='approved' AND p.reportCount>0 GROUP BY p.postID ORDER BY reports DESC,p.createdAt DESC LIMIT 200`).all();return json({items:rows.results||[]});}

    return json({error:'Route not found'},404);
  } catch (e) {
    const status = Number(e?.status || 500);
    if (status >= 500) console.error(e);
    return json({ error: status === 500 ? 'Internal server error' : e.message }, status);
  }
}

function publicUser(u) { return { userID:u.userID,firstName:u.firstName,lastName:u.lastName,email:u.email,role:u.role,classID:u.classID,gradeLevel:u.gradeLevel,xp:Number(u.xp||0),level:Number(u.level||1),status:u.status,profileFileID:u.profileFileID,createdAt:u.createdAt,lastLoginAt:u.lastLoginAt }; }

async function getFeed(env,user,url){
  const limit=Math.min(Number(url.searchParams.get('limit')||10),50);const offset=Math.max(0,Number(url.searchParams.get('offset')||0));
  let q=`SELECT p.*,u.firstName,u.lastName,u.role,
    (SELECT COUNT(*) FROM REACTIONS r WHERE r.postID=p.postID AND r.reactionType='like') AS likes,
    (SELECT COUNT(*) FROM REACTIONS r WHERE r.postID=p.postID AND r.reactionType='clap') AS claps,
    (SELECT COUNT(*) FROM REACTIONS r WHERE r.postID=p.postID AND r.reactionType='agree') AS agrees,
    (SELECT reactionType FROM REACTIONS r WHERE r.postID=p.postID AND r.userID=? LIMIT 1) AS myReaction
    FROM POSTS p JOIN USERS u ON u.userID=p.userID WHERE p.status='approved'`;
  const b=[user.userID];
  if(user.role!=='admin'){
    const classes=await getAccessibleClassIds(env,user);
    if(classes?.length){q+=` AND (p.targetType='school' OR (p.targetType IN ('class','subject') AND p.targetID IN (${classes.map(()=>'?').join(',')})))`;b.push(...classes);}else q+=` AND p.targetType='school'`;
  }
  q+=` ORDER BY p.pinned DESC,p.createdAt DESC LIMIT ? OFFSET ?`;b.push(limit,offset);const rows=await env.DB.prepare(q).bind(...b).all();
  for(const p of rows.results||[]){const f=await env.DB.prepare(`SELECT pf.fileID,f.originalName,f.mimeType FROM POST_FILES pf JOIN FILES f ON f.fileID=pf.fileID WHERE pf.postID=? ORDER BY pf.sortOrder`).bind(p.postID).all();p.files=f.results||[];const c=await env.DB.prepare(`SELECT c.*,u.firstName,u.lastName FROM COMMENTS c JOIN USERS u ON u.userID=c.userID WHERE c.postID=? AND c.status='approved' ORDER BY c.createdAt ASC LIMIT 50`).bind(p.postID).all();p.comments=c.results||[];}
  const pending = user.role==='student' ? await env.DB.prepare(`SELECT COUNT(*) AS n FROM POSTS WHERE userID=? AND status='pending'`).bind(user.userID).first() : null;
  return {items:rows.results||[],nextOffset:offset+limit,pendingMine:Number(pending?.n||0)};
}

async function dashboard(env,user){
  const base={user:publicUser(user)};
  if(user.role==='student'){
    const [assign,avg,lessons,noti,feed,stat]=await Promise.all([
      env.DB.prepare(`SELECT a.assignID,a.title,a.dueAt,a.maxScore,a.classID,COALESCE(s.status,'missing') AS submissionStatus,s.score,s.isLate FROM ASSIGNMENTS a JOIN CLASS_MEMBERS cm ON cm.classID=a.classID AND cm.userID=? AND cm.status='active' LEFT JOIN SUBMISSIONS s ON s.assignID=a.assignID AND s.userID=? WHERE a.status IN ('open','locked') ORDER BY a.dueAt LIMIT 10`).bind(user.userID,user.userID).all(),
      env.DB.prepare(`SELECT c.subjectName,ROUND(AVG(s.score),2) AS avgScore,a.maxScore FROM SUBMISSIONS s JOIN ASSIGNMENTS a ON a.assignID=s.assignID JOIN CLASSES c ON c.classID=a.classID WHERE s.userID=? AND s.status='graded' GROUP BY c.classID ORDER BY c.subjectName`).bind(user.userID).all(),
      env.DB.prepare(`SELECT l.lessonID,l.title,l.classID,l.orderIndex,COALESCE(lp.percentage,0) AS percentage FROM LESSONS l JOIN CLASS_MEMBERS cm ON cm.classID=l.classID AND cm.userID=? AND cm.status='active' LEFT JOIN LESSON_PROGRESS lp ON lp.lessonID=l.lessonID AND lp.userID=? WHERE l.status='published' ORDER BY l.updatedAt DESC LIMIT 10`).bind(user.userID,user.userID).all(),
      env.DB.prepare(`SELECT * FROM NOTIFICATIONS WHERE userID=? AND isRead=0 ORDER BY createdAt DESC LIMIT 5`).bind(user.userID).all(),
      env.DB.prepare(`SELECT p.postID,p.content,p.createdAt,u.firstName,u.lastName FROM POSTS p JOIN USERS u ON u.userID=p.userID WHERE p.status='approved' ORDER BY p.pinned DESC,p.createdAt DESC LIMIT 5`).all(),
      env.DB.prepare(`SELECT * FROM GAME_STATS WHERE userID=?`).bind(user.userID).first()
    ]);return {...base,role:'student',assignments:assign.results||[],averages:avg.results||[],lessons:lessons.results||[],notifications:noti.results||[],feed:feed.results||[],game:stat||{streak:0,dailyQuestJSON:'{}'}};
  }
  if(user.role==='teacher'){
    const [pending,missing,graded,quizzes]=await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) n FROM POSTS p JOIN CLASSES c ON c.classID=p.targetID WHERE p.status='pending' AND c.teacherID=?`).bind(user.userID).first(),
      env.DB.prepare(`SELECT COUNT(*) n FROM ASSIGNMENTS a JOIN CLASSES c ON c.classID=a.classID LEFT JOIN SUBMISSIONS s ON s.assignID=a.assignID AND s.userID IN (SELECT userID FROM CLASS_MEMBERS WHERE classID=a.classID AND role='student') WHERE c.teacherID=? AND a.status IN ('open','locked') AND s.submitID IS NULL`).bind(user.userID).first(),
      env.DB.prepare(`SELECT COUNT(*) n FROM SUBMISSIONS s JOIN ASSIGNMENTS a ON a.assignID=s.assignID WHERE a.teacherID=? AND s.status='submitted'`).bind(user.userID).first(),
      env.DB.prepare(`SELECT quizID,title,openAt,closeAt,status FROM QUIZZES q JOIN CLASSES c ON c.classID=q.classID WHERE c.teacherID=? ORDER BY openAt DESC LIMIT 10`).bind(user.userID).all()
    ]);return {...base,role:'teacher',pendingPosts:Number(pending?.n||0),missingSubmissions:Number(missing?.n||0),toGrade:Number(graded?.n||0),quizzes:quizzes.results||[]};
  }
  if(user.role==='parent'){
    const links=await env.DB.prepare(`SELECT u.userID,u.firstName,u.lastName,u.xp,u.level FROM PARENT_LINKS p JOIN USERS u ON u.userID=p.childID WHERE p.parentID=? AND p.status='active'`).bind(user.userID).all();const childIds=(links.results||[]).map(x=>x.userID);const children=[];for(const child of links.results||[]){const wallet=await env.DB.prepare(`SELECT balanceTHB,balanceCoin FROM WALLETS WHERE userID=?`).bind(child.userID).first();const scores=await env.DB.prepare(`SELECT ROUND(AVG(score),2) avgScore FROM SUBMISSIONS WHERE userID=? AND status='graded'`).bind(child.userID).first();children.push({...child,wallet,scores});}return {...base,role:'parent',children};
  }
  const [users,roles,pendingShops,topups,tx,auditRows]=await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) n FROM USERS`).first(),env.DB.prepare(`SELECT role,COUNT(*) n FROM USERS GROUP BY role`).all(),env.DB.prepare(`SELECT COUNT(*) n FROM SHOPS WHERE status='pending'`).first(),env.DB.prepare(`SELECT COUNT(*) n FROM TOPUP_REQUESTS WHERE status='pending'`).first(),env.DB.prepare(`SELECT COUNT(*) n FROM TRANSACTIONS WHERE date(createdAt)=date('now')`).first(),env.DB.prepare(`SELECT a.action,a.entityType,a.entityID,a.createdAt,u.firstName,u.lastName FROM AUDIT_LOGS a LEFT JOIN USERS u ON u.userID=a.userID ORDER BY a.createdAt DESC LIMIT 10`).all()
  ]);return {...base,role:'admin',users:Number(users?.n||0),roles:roles.results||[],pendingShops:Number(pendingShops?.n||0),pendingTopups:Number(topups?.n||0),transactionsToday:Number(tx?.n||0),audit:auditRows.results||[]};
}

async function updateQuest(env,userID,key){
  const stat=await env.DB.prepare(`SELECT dailyQuestJSON FROM GAME_STATS WHERE userID=?`).bind(userID).first();if(!stat)return;let q={};try{q=JSON.parse(stat.dailyQuestJSON||'{}')}catch{};q[key]=true;if(q.login&&q.lesson&&q.assignment&&q.post&&!q.bonus){q.bonus=true;const settings=await getSettings(env);await env.DB.prepare(`UPDATE WALLETS SET balanceCoin=balanceCoin+?,updatedAt=? WHERE userID=?`).bind(25,nowISO(),userID).run();await env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,referenceID,createdAt,status) SELECT ?,userID,'daily_quest_bonus','COIN',25,balanceCoin-25,balanceCoin,?,?, 'completed' FROM WALLETS WHERE userID=?`).bind(uid('tx'),`daily:${new Date().toISOString().slice(0,10)}`,nowISO(),userID).run();await notify(env,userID,'quest_complete','Daily Quest ครบแล้ว','ได้รับ 25 SchoolCoin','/?view=gamification');}await env.DB.prepare(`UPDATE GAME_STATS SET dailyQuestJSON=?,updatedAt=? WHERE userID=?`).bind(JSON.stringify(q),nowISO(),userID).run();}

function inPromotion(p){const t=Date.now();return p.promotionPrice!=null && (!p.promotionStart||t>=Date.parse(p.promotionStart)) && (!p.promotionEnd||t<=Date.parse(p.promotionEnd));}
async function notifyToAdmins(env,type,title,content,targetURL){const rows=await env.DB.prepare(`SELECT userID FROM USERS WHERE role='admin' AND status='approved'`).all();for(const r of rows.results||[])await notify(env,r.userID,type,title,content,targetURL);}

async function scheduledJobs(env){
  const now=nowISO();
  const today=new Date().toISOString().slice(0,10);
  await env.DB.prepare(`UPDATE SESSIONS SET status='expired' WHERE status='active' AND expiresAt<=?`).bind(now).run();
  const stats=await env.DB.prepare(`SELECT userID,dailyQuestJSON FROM GAME_STATS`).all();
  for(const st of stats.results||[]){let q={};try{q=JSON.parse(st.dailyQuestJSON||'{}')}catch{};if(q.date!==today){await env.DB.prepare(`UPDATE GAME_STATS SET dailyQuestJSON=?,updatedAt=? WHERE userID=?`).bind(JSON.stringify({date:today,login:false,lesson:false,assignment:false,post:false}),now,st.userID).run();}}
  const overdue=await env.DB.prepare(`SELECT a.assignID,a.title,a.classID,a.dueAt FROM ASSIGNMENTS a WHERE a.status='open' AND a.dueAt<=datetime('now')`).all();
  for(const a of overdue.results||[]) await env.DB.prepare(`UPDATE ASSIGNMENTS SET status='locked',updatedAt=? WHERE assignID=? AND status='open' AND allowLate=0`).bind(now,a.assignID).run();
  const due=await env.DB.prepare(`SELECT a.assignID,a.title,a.dueAt,a.classID FROM ASSIGNMENTS a WHERE a.status='open' AND a.dueAt BETWEEN datetime('now','+23 hours') AND datetime('now','+25 hours')`).all();
  for(const a of due.results||[]){const ms=await env.DB.prepare(`SELECT userID FROM CLASS_MEMBERS cm WHERE cm.classID=? AND cm.role='student' AND cm.status='active' AND NOT EXISTS(SELECT 1 FROM SUBMISSIONS s WHERE s.assignID=? AND s.userID=cm.userID)`).bind(a.classID,a.assignID).all();for(const m of ms.results||[])await notify(env,m.userID,'assignment_reminder','ใกล้ครบกำหนดส่งงาน',`${a.title} เหลือประมาณ 24 ชั่วโมง`,`/?view=assignments&id=${a.assignID}`);}
  const auctions=await env.DB.prepare(`SELECT auctionID FROM AUCTIONS WHERE status='open' AND closesAt<=?`).bind(now).all();for(const a of auctions.results||[])await closeAuction(env,a.auctionID);
}
async function closeAuction(env,auctionID){
  const a=await env.DB.prepare(`SELECT a.*,s.userID AS sellerID,p.name AS productName FROM AUCTIONS a JOIN SHOPS s ON s.shopID=a.shopID JOIN PRODUCTS p ON p.productID=a.productID WHERE a.auctionID=? AND a.status='open'`).bind(auctionID).first();
  if(!a)return;
  const winner=await env.DB.prepare(`SELECT * FROM AUCTION_BIDS WHERE auctionID=? ORDER BY amount DESC,createdAt ASC LIMIT 1`).bind(auctionID).first();
  if(!winner){await env.DB.prepare(`UPDATE AUCTIONS SET status='closed' WHERE auctionID=?`).bind(auctionID).run();return;}
  const ww=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(winner.userID).first();
  const sw=await env.DB.prepare(`SELECT * FROM WALLETS WHERE userID=?`).bind(a.sellerID).first();
  if(!ww||!sw||Number(ww.balanceCoin)<Number(winner.amount)){
    await env.DB.prepare(`UPDATE AUCTIONS SET status='closed',highestBidderID=?,currentPrice=? WHERE auctionID=?`).bind(winner.userID,winner.amount,a.auctionID).run();
    await notify(env,winner.userID,'auction_failed','ประมูลชนะ แต่ยอด Coin ไม่เพียงพอ',`สินค้า ${a.productName}`,'/?view=marketplace');
    await notifyToAdmins(env,'auction_payment_failed','การชำระ Auction ล้มเหลว',`Auction ${a.auctionID} ยอด Coin ไม่พอ`,'/?view=marketplace');
    return;
  }
  const wb=Number(ww.balanceCoin),wa=wb-Number(winner.amount),sb=Number(sw.balanceCoin),sa=sb+Number(winner.amount),ref=uid('auctionpay'),t=nowISO();
  await env.DB.batch([
    env.DB.prepare(`UPDATE AUCTIONS SET status='closed',highestBidderID=?,currentPrice=? WHERE auctionID=?`).bind(winner.userID,winner.amount,a.auctionID),
    env.DB.prepare(`UPDATE WALLETS SET balanceCoin=?,updatedAt=? WHERE userID=?`).bind(wa,t,winner.userID),
    env.DB.prepare(`UPDATE WALLETS SET balanceCoin=?,updatedAt=? WHERE userID=?`).bind(sa,t,a.sellerID),
    env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),winner.userID,a.sellerID,'auction_payment_out','COIN',winner.amount,wb,wa,ref,t,'completed'),
    env.DB.prepare(`INSERT INTO TRANSACTIONS(txID,sourceUserID,destinationUserID,transactionType,currency,amount,balanceBefore,balanceAfter,referenceID,createdAt,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(uid('tx'),winner.userID,a.sellerID,'auction_payment_in','COIN',winner.amount,sb,sa,ref,t,'completed')
  ]);
  await notify(env,winner.userID,'auction_won','คุณชนะการประมูล',`${a.productName} · ${winner.amount} Coin`,'/?view=marketplace');
  await notify(env,a.sellerID,'auction_sold','Auction ปิดแล้ว',`${a.productName} · ${winner.amount} Coin`,'/?view=marketplace');
}


export default {
  async fetch(request, env, ctx) {
    if (new URL(request.url).pathname.startsWith('/api/')) {
      const res = await routeAPI(request, env, ctx);
      const h = new Headers(res.headers);
      h.set('X-Content-Type-Options','nosniff');
      h.set('Referrer-Policy','strict-origin-when-cross-origin');
      h.set('Permissions-Policy','camera=(), microphone=(), geolocation=()');
      h.set('Content-Security-Policy',"default-src 'self'; img-src 'self' data: blob:; media-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-src https://www.youtube.com https://www.youtube-nocookie.com; base-uri 'self'; form-action 'self'");
      return new Response(res.body,{status:res.status,headers:h});
    }
    const asset = await env.ASSETS.fetch(request);
    const h = new Headers(asset.headers);
    h.set('X-Content-Type-Options','nosniff');
    h.set('Referrer-Policy','strict-origin-when-cross-origin');
    h.set('Permissions-Policy','camera=(), microphone=(), geolocation=()');
    h.set('Content-Security-Policy',"default-src 'self'; img-src 'self' data: blob:; media-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-src https://www.youtube.com https://www.youtube-nocookie.com; base-uri 'self'; form-action 'self'");
    return new Response(asset.body,{status:asset.status,headers:h});
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(scheduledJobs(env)); }
};
