import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

export const config = { path: '/api/*' };

/*
 * Multi-college ("workspace") design: every college is an org with its own users, sections, students and attendance.
 * All of an org's data lives under its own key prefix, and every request is bound to the org stored in the caller's
 * session, so one college can never read or write another's data. The original single-college data uses org "main"
 * with un-prefixed keys, so nothing had to be migrated.
 */

const SESSION_MS = 12 * 60 * 60 * 1000;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const STATUSES = ['present', 'late', 'absent', 'excused'];
const ID_RE = /^[A-Za-z0-9_-]{1,40}$/;
const USER_RE = /^[a-z0-9._@+-]{3,60}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const MAX_STUDENTS = 600;
const MAX_NEW_COLLEGES_PER_HOUR = 5;

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function json(status, body, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra },
  });
}

/* ---------- blob helpers (strong consistency, optimistic concurrency via etags) ---------- */
function db() { return getStore({ name: 'attendance', consistency: 'strong' }); }
// Per-college key: the original college ("main") keeps its old un-prefixed keys.
const K = (org, name) => (org === 'main' ? name : `o/${org}/${name}`);

function chains() { return (globalThis.__attChains ||= new Map()); }
function serialized(key, fn) { // one writer at a time per key inside this server instance
  const prev = chains().get(key) || Promise.resolve();
  const run = prev.then(fn, fn);
  chains().set(key, run.catch(() => {}));
  return run;
}
function update(key, mutate, tries = 8) {
  // Read-modify-write a JSON doc. In-process queue + etag check across instances; retries on a clash.
  return serialized(key, async () => {
    const s = db();
    for (let i = 0; i < tries; i++) {
      const cur = await s.getWithMetadata(key, { type: 'json' });
      const next = await mutate(cur ? structuredClone(cur.data) : null);
      if (next === undefined) return null; // mutate decided nothing to write
      const opts = cur ? (cur.etag ? { onlyIfMatch: cur.etag } : {}) : { onlyIfNew: true };
      const r = await s.setJSON(key, next, opts);
      if (r.modified !== false) return next;
    }
    throw new ApiError(503, 'The server is busy, please try again.');
  });
}

/* ---------- colleges (orgs) ---------- */
const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function genCode() {
  const b = crypto.randomBytes(8);
  return Array.from(b, (x) => CODE_CHARS[x % CODE_CHARS.length]).join('');
}
const normCode = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

async function claimCode(orgId) { // reserve a unique join code for an org
  const s = db();
  for (let i = 0; i < 6; i++) {
    const code = genCode();
    const r = await s.setJSON('code:' + code, { org: orgId }, { onlyIfNew: true });
    if (r.modified !== false) return code;
  }
  throw new ApiError(503, 'Please try again.');
}
async function getOrg(orgId) {
  const s = db();
  let o = await s.get('org:' + orgId, { type: 'json' });
  if (!o && orgId === 'main') { // the original college: created lazily
    o = { id: 'main', name: 'My College', code: await claimCode('main'), created: Date.now() };
    await update('org:main', async (cur) => cur || o);
    o = await s.get('org:main', { type: 'json' });
  }
  return o;
}
async function orgByCode(code) {
  const c = normCode(code);
  if (c.length < 6) return null;
  const hit = await db().get('code:' + c, { type: 'json' });
  return hit ? hit.org : null;
}
async function lookupOrgOfUser(username) { // which college does this login belong to?
  const hit = await db().get('acct:' + sha(username), { type: 'json' });
  if (hit) return hit.org;
  const main = await readUsers('main'); // accounts created before multi-college support
  return main.users.some((u) => u.username === username) ? 'main' : null;
}
async function claimUsername(username, orgId) { // usernames/emails are unique across all colleges
  const s = db();
  const taken = await lookupOrgOfUser(username);
  if (taken) throw new ApiError(409, 'That email/username is already registered.');
  const r = await s.setJSON('acct:' + sha(username), { org: orgId }, { onlyIfNew: true });
  if (r.modified === false) throw new ApiError(409, 'That email/username is already registered.');
}
const releaseUsername = (username) => db().delete('acct:' + sha(username));

/* ---------- users / sessions ---------- */
async function readUsers(org) { return (await db().get(K(org, 'users'), { type: 'json' })) || { users: [] }; }
const publicUser = (u) => ({ id: u.id, username: u.username, name: u.name, role: u.role, status: u.status || 'active' });

async function hashNew(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: (await scrypt(password, salt)).toString('hex') };
}
async function checkPassword(user, password) {
  const salt = user ? user.salt : 'ffffffffffffffffffffffffffffffff'; // dummy work for unknown users
  const got = await scrypt(String(password), salt);
  if (!user) return false;
  const want = Buffer.from(user.hash, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
function validPassword(p) {
  if (typeof p !== 'string' || p.length < 8 || p.length > 200) throw new ApiError(400, 'Password must be 8-200 characters.');
}
function sessionCookie(token, secure, maxAge) {
  return `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}
function getToken(req) {
  const m = /(?:^|;\s*)sid=([A-Za-z0-9_-]+)/.exec(req.headers.get('cookie') || '');
  return m ? m[1] : null;
}
async function currentUser(req) { // returns the user plus the org the session is bound to
  const token = getToken(req);
  if (!token) return null;
  const key = 'session:' + sha(token);
  const sess = await db().get(key, { type: 'json' });
  if (!sess) return null;
  if (sess.exp < Date.now()) { await db().delete(key); return null; }
  const org = sess.org || 'main';
  const doc = await readUsers(org);
  const u = doc.users.find((x) => x.id === sess.uid);
  if (!u || (u.status === 'pending' && doc.requireApproval) || (u.sv || 0) !== (sess.sv || 0)) return null;
  return { ...u, org };
}
async function startSession(user, org, secure) {
  const token = crypto.randomBytes(32).toString('base64url');
  await db().setJSON('session:' + sha(token), { org, uid: user.id, sv: user.sv || 0, exp: Date.now() + SESSION_MS });
  return { 'Set-Cookie': sessionCookie(token, secure, SESSION_MS / 1000) };
}
// Bumping a user's "sv" (session version) instantly invalidates all of their existing sessions.

function clientIp(req) { return req.headers.get('x-nf-client-connection-ip') || req.headers.get('x-forwarded-for') || 'unknown'; }
async function throttle(key, max, windowMs, msg) { // simple fixed-window limiter; call before the action
  const s = db();
  const f = (await s.get(key, { type: 'json' })) || { n: 0, until: 0 };
  if (f.until > Date.now()) throw new ApiError(429, msg);
  return {
    fail: async () => { f.n += 1; if (f.n >= max) { f.until = Date.now() + windowMs; f.n = 0; } await s.setJSON(key, f); },
    ok: () => s.delete(key),
  };
}

/* ---------- data validation / patching ---------- */
function validKey(k) {
  const i = k.indexOf('|');
  if (i !== 10 || !DATE_RE.test(k.slice(0, 10))) return false;
  const d = new Date(k.slice(0, 10) + 'T00:00:00Z');
  return !isNaN(d) && d.toISOString().slice(0, 10) === k.slice(0, 10) && k.length <= 52;
}
function today() { return new Date().toISOString().slice(0, 10); }

/* ---------- who owns which data ---------- */
// Every user's sections, students and attendance live under their own key prefix, so no other account (teacher or admin,
// in any college) can ever read or change them. The original un-prefixed data belongs to the first admin of the
// original college (org 'main').
async function dataScope(user) {
  if (user.org === 'main') {
    const d = await readUsers('main');
    const owner = d.users.find((u) => u.role === 'admin') || d.users[0];
    if (owner && owner.id === user.id) return '';
  }
  return `u/${user.id}/`;
}

/* ---------- period locking (manual: a teacher locks a finished period, an admin can unlock) ---------- */
// A 'session' is one period on one date: id = date|period. Record keys are date|period|subject (older data: date|subject).
function sessionId(recordKey) {
  const m = /^([1-8])\|/.exec(recordKey.slice(11));
  return recordKey.slice(0, 10) + '|' + (m ? m[1] : '0');
}
const isLocked = (meta) => !!meta && !!meta.lockedAt;
function normSessions(doc) {
  const sessions = doc.sessions || (doc.sessions = {});
  for (const [sid, m] of Object.entries(sessions)) { // drop leftovers of the removed automatic-lock feature
    if (!m.lockedAt || String(m.lockedBy || '').startsWith('system')) delete sessions[sid];
  }
  return sessions;
}
function lockedError(sid) {
  const [date, p] = sid.split('|');
  return new ApiError(423, (p === '0' ? 'Attendance' : 'Period ' + p) + ' on ' + date + ' is locked, so your last change was not saved. Unlock it first to make changes.');
}

function applySectionPatch(doc, sp) {
  if (!sp || typeof sp !== 'object') throw new ApiError(400, 'Bad patch.');
  normSessions(doc);
  if (sp.meta !== undefined) {
    const year = Math.round(Number(sp.meta && sp.meta.year));
    const name = str(sp.meta && sp.meta.name, 40);
    if (!(year >= 1 && year <= 4) || !name) throw new ApiError(400, 'Bad section details.');
    doc.year = year; doc.name = name;
  }
  if (sp.students !== undefined) {
    if (!sp.students || typeof sp.students !== 'object') throw new ApiError(400, 'Bad students.');
    for (const [sid, v] of Object.entries(sp.students)) {
      if (!ID_RE.test(sid)) throw new ApiError(400, 'Bad student id.');
      const idx = doc.students.findIndex((s) => s.id === sid);
      if (v === null) {
        if (idx >= 0) doc.students.splice(idx, 1);
        for (const k of Object.keys(doc.records)) {
          delete doc.records[k][sid];
          if (!Object.keys(doc.records[k]).length) delete doc.records[k];
        }
      } else {
        const name = str(v && v.name, 80);
        if (!name) throw new ApiError(400, 'Student name required.');
        const st = { id: sid, name, roll: str(v.roll, 20) };
        if (idx >= 0) doc.students[idx] = st; else doc.students.push(st);
      }
    }
    if (doc.students.length > MAX_STUDENTS) throw new ApiError(400, 'Too many students in one section.');
  }
  if (sp.records !== undefined) {
    if (!sp.records || typeof sp.records !== 'object') throw new ApiError(400, 'Bad records.');
    const have = new Set(doc.students.map((s) => s.id));
    for (const [key, day] of Object.entries(sp.records)) {
      if (!validKey(key) || !day || typeof day !== 'object') throw new ApiError(400, 'Bad record key.');
      const sid0 = sessionId(key);
      if (isLocked(doc.sessions[sid0])) throw lockedError(sid0);
      const subj = str(key.slice(11), 40);
      const k = key.slice(0, 11) + subj;
      const cur = doc.records[k] || (doc.records[k] = {});
      for (const [sid, status] of Object.entries(day)) {
        if (status === null) delete cur[sid];
        else if (STATUSES.includes(status) && have.has(sid)) cur[sid] = status;
        else if (!STATUSES.includes(status)) throw new ApiError(400, 'Bad status.');
      }
      if (!Object.keys(cur).length) delete doc.records[k];
    }
  }
}

async function patchSection(ns, id, sp) {
  if (!ID_RE.test(id)) throw new ApiError(400, 'Bad section id.');
  const s = db();
  const backupKey = (ns + `bak:${today()}:${id}`);
  let doc;
  await update((ns + 'sec:' + id), async (cur) => {
    if (!cur) {
      if (!sp || sp.meta === undefined) return undefined; // patch for a deleted section: ignore
      cur = { id, year: 1, name: 'Section', students: [], records: {} };
    } else if (!(await s.getMetadata(backupKey))) {
      await s.setJSON(backupKey, cur, { onlyIfNew: true }); // one snapshot per section per day
    }
    applySectionPatch(cur, sp);
    cur.rev = (cur.rev || 0) + 1; // change counter used by clients to notice updates
    doc = cur;
    return cur;
  });
  if (!doc) return;
  await update((ns + 'idx'), async (cur) => {
    cur = cur || { sections: [] };
    const e = { id, year: doc.year, name: doc.name, count: doc.students.length };
    const i = cur.sections.findIndex((x) => x.id === id);
    if (i >= 0) cur.sections[i] = e; else cur.sections.push(e);
    return cur;
  });
  return doc.sessions;
}
async function setLock(ns, id, date, period, user, lock) {
  if (!ID_RE.test(id) || !DATE_RE.test(String(date)) || !Number.isInteger(period) || period < 0 || period > 8) throw new ApiError(400, 'Bad request.');
  const sid = date + '|' + period;
  let meta;
  await update((ns + 'sec:' + id), async (cur) => {
    if (!cur) throw new ApiError(404, 'No such section.');
    const sessions = normSessions(cur);
    if (lock) {
      if (!Object.keys(cur.records).some((k) => sessionId(k) === sid)) throw new ApiError(400, 'Nothing has been marked for that period yet.');
      meta = sessions[sid] = { lockedAt: Date.now(), lockedBy: user.name };
    } else {
      delete sessions[sid]; meta = null; // unlocked: editable again
    }
    cur.rev = (cur.rev || 0) + 1;
    return cur;
  });
  return meta;
}
async function deleteSection(ns, id) {
  if (!ID_RE.test(id)) throw new ApiError(400, 'Bad section id.');
  const s = db();
  const cur = await s.get((ns + 'sec:' + id), { type: 'json' });
  if (cur) await s.setJSON((ns + `bak:${today()}:${id}`), cur); // keep a last copy
  await s.delete((ns + 'sec:' + id));
  await update((ns + 'idx'), async (c) => {
    c = c || { sections: [] };
    c.sections = c.sections.filter((x) => x.id !== id);
    return c;
  });
}

/* ---------- request handling ---------- */
function requireAuth(user) { if (!user) throw new ApiError(401, 'Please log in.'); return user; }
function requireAdmin(user) { requireAuth(user); if (user.role !== 'admin') throw new ApiError(403, 'Admins only.'); return user; }
async function body(req) {
  try { const t = await req.text(); if (t.length > 4_000_000) throw 0; return t ? JSON.parse(t) : {}; }
  catch { throw new ApiError(400, 'Invalid request body.'); }
}

export default async (req) => {
  try {
    const url = new URL(req.url);
    const secure = url.protocol === 'https:';
    const parts = url.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
    const method = req.method;

    if (method !== 'GET') { // CSRF defence on top of SameSite=Strict
      if (req.headers.get('x-attendance') !== '1') throw new ApiError(403, 'Forbidden.');
      const origin = req.headers.get('origin');
      if (origin && new URL(origin).host !== url.host) throw new ApiError(403, 'Forbidden.');
    }

    const route = parts[0];
    const user = ['login', 'recover', 'register'].includes(route) ? null : await currentUser(req);

    if (route === 'session' && method === 'GET') {
      if (user) return json(200, { cloud: true, user: publicUser(user) });
      return json(200, { cloud: true, user: null });
    }

    if (route === 'recover' && method === 'POST') {
      // Site owner only (needs the SETUP_CODE environment variable): set a new password for any account, e.g. a
      // college admin who lost theirs. All of that user's sessions are ended.
      const b = await body(req);
      const code = Netlify.env.get('SETUP_CODE');
      if (!code) throw new ApiError(503, 'Recovery is disabled: SETUP_CODE is not set.');
      const t = await throttle('fail:__recover', MAX_FAILS, LOCK_MS, 'Too many attempts. Try again later.');
      const a = Buffer.from(sha(String(b.setupCode || ''))), c = Buffer.from(sha(code));
      if (!crypto.timingSafeEqual(a, c)) { await t.fail(); throw new ApiError(403, 'Wrong setup code.'); }
      await t.ok();
      const username = str(b.username, 60).toLowerCase();
      validPassword(b.password);
      const org = await lookupOrgOfUser(username);
      if (!org) throw new ApiError(404, 'No such user.');
      const h = await hashNew(b.password);
      await update(K(org, 'users'), async (d) => {
        const u = d.users.find((x) => x.username === username);
        if (!u) throw new ApiError(404, 'No such user.');
        Object.assign(u, h); u.sv = (u.sv || 0) + 1; u.status = 'active'; return d;
      });
      return json(200, { ok: true });
    }

    if (route === 'register' && method === 'POST') {
      // Self sign-up: either create a NEW college (you become its admin) or JOIN one with its college code.
      const b = await body(req);
      const username = str(b.username, 60).toLowerCase(), name = str(b.name, 60) || username;
      if (!USER_RE.test(username)) throw new ApiError(400, 'Use a valid email or username (3-60 characters).');
      validPassword(b.password);
      const h = await hashNew(b.password);
      const ip = sha(clientIp(req));

      if (b.mode === 'new') {
        const college = str(b.college, 80);
        if (college.length < 2) throw new ApiError(400, 'Enter your college name.');
        const bucket = `newrate:${ip}:${Math.floor(Date.now() / 3600000)}`;
        const n = ((await db().get(bucket, { type: 'json' })) || { n: 0 }).n;
        if (n >= MAX_NEW_COLLEGES_PER_HOUR) throw new ApiError(429, 'Too many new colleges from this network. Try again later.');
        await claimUsername(username, 'pending-org'); // fails fast if the email is already used
        const orgId = crypto.randomBytes(6).toString('hex');
        const nu = { id: crypto.randomUUID(), username, name, role: 'admin', status: 'active', ...h };
        try {
          const code = await claimCode(orgId);
          await db().setJSON('org:' + orgId, { id: orgId, name: college, code, created: Date.now() });
          await db().setJSON(K(orgId, 'users'), { users: [nu] });
          await db().setJSON('acct:' + sha(username), { org: orgId });
          await db().setJSON(bucket, { n: n + 1 });
        } catch (e) { await releaseUsername(username); throw e; }
        return json(200, { ok: true, user: publicUser(nu) }, await startSession(nu, orgId, secure));
      }

      const t = await throttle('fail:join:' + ip, 10, LOCK_MS, 'Too many wrong college codes. Try again in a few minutes.');
      const org = await orgByCode(b.code);
      if (!org) { await t.fail(); throw new ApiError(404, 'College code not found. Ask your administrator for the code.'); }
      await claimUsername(username, org);
      const nu = { id: crypto.randomUUID(), username, name, role: 'teacher', status: 'active', ...h };
      try {
        await update(K(org, 'users'), async (d) => {
          d = d || { users: [] };
          if (d.users.filter((x) => x.status === 'pending').length >= 50) throw new ApiError(429, 'Too many pending sign-ups. Please try later.');
          nu.status = d.requireApproval ? 'pending' : 'active';
          d.users.push(nu); return d;
        });
      } catch (e) { await releaseUsername(username); throw e; }
      if (nu.status === 'pending') return json(200, { ok: true, pending: true });
      return json(200, { ok: true, user: publicUser(nu) }, await startSession(nu, org, secure));
    }

    if (route === 'login' && method === 'POST') {
      const b = await body(req);
      const username = str(b.username, 60).toLowerCase();
      const t = await throttle('fail:' + sha(username), MAX_FAILS, LOCK_MS, 'Too many attempts. Try again in a few minutes.');
      const org = await lookupOrgOfUser(username);
      const udoc = org ? await readUsers(org) : { users: [] };
      const u = udoc.users.find((x) => x.username === username) || null;
      const ok = await checkPassword(u, b.password);
      if (!ok) { await t.fail(); throw new ApiError(401, 'Wrong username or password.'); }
      await t.ok();
      if (u.status === 'pending' && udoc.requireApproval) throw new ApiError(403, 'Your account is waiting for the administrator to approve it.');
      return json(200, { user: publicUser(u) }, await startSession(u, org, secure));
    }

    if (route === 'logout' && method === 'POST') {
      const t = getToken(req);
      if (t) await db().delete('session:' + sha(t));
      return json(200, { ok: true }, { 'Set-Cookie': sessionCookie('', secure, 0) });
    }

    requireAuth(user);
    const org = user.org;
    const ns = await dataScope(user);

    if (route === 'org') { // the college's name, and (for admins) its join code
      const o = await getOrg(org);
      if (method === 'GET') return json(200, { name: o.name, code: user.role === 'admin' ? o.code : undefined });
      requireAdmin(user);
      const b = await body(req);
      if (parts[1] === 'code') { // issue a fresh join code; the old one stops working
        const code = await claimCode(org);
        await db().delete('code:' + o.code);
        await update('org:' + org, async (d) => { d.code = code; return d; });
        return json(200, { name: o.name, code });
      }
      const name = str(b.name, 80);
      if (name.length < 2) throw new ApiError(400, 'Enter a college name.');
      await update('org:' + org, async (d) => { d.name = name; return d; });
      return json(200, { name, code: o.code });
    }

    if (route === 'password' && method === 'POST') {
      const b = await body(req);
      validPassword(b.password);
      if (!(await checkPassword(user, b.current))) throw new ApiError(403, 'Current password is wrong.');
      const h = await hashNew(b.password);
      let me;
      await update(K(org, 'users'), async (d) => {
        const u = d.users.find((x) => x.id === user.id);
        Object.assign(u, h); u.sv = (u.sv || 0) + 1; me = u; return d; // other devices get logged out
      });
      return json(200, { ok: true }, await startSession(me, org, secure));
    }

    if (route === 'users') {
      requireAdmin(user);
      const id = parts[1];
      if (method === 'GET' && !id) { const ud = await readUsers(org); return json(200, { users: ud.users.map(publicUser), requireApproval: !!ud.requireApproval }); }
      if (method === 'POST' && !id) {
        const b = await body(req);
        const username = str(b.username, 60).toLowerCase(), name = str(b.name, 60) || username;
        if (!USER_RE.test(username)) throw new ApiError(400, 'Username: 3-60 characters (letters, numbers, . _ - @ +).');
        validPassword(b.password);
        const role = b.role === 'admin' ? 'admin' : 'teacher';
        const h = await hashNew(b.password);
        const nu = { id: crypto.randomUUID(), username, name, role, ...h };
        await claimUsername(username, org);
        try {
          await update(K(org, 'users'), async (d) => { d.users.push(nu); return d; });
        } catch (e) { await releaseUsername(username); throw e; }
        return json(200, { user: publicUser(nu) });
      }
      if (method === 'PUT' && id) {
        const b = await body(req);
        let h = null;
        if (b.password === undefined && b.approve !== true) throw new ApiError(400, 'Nothing to change.');
        if (b.password !== undefined) { validPassword(b.password); h = await hashNew(b.password); }
        await update(K(org, 'users'), async (d) => {
          const u = d.users.find((x) => x.id === id);
          if (!u) throw new ApiError(404, 'No such user.');
          if (h) { Object.assign(u, h); u.sv = (u.sv || 0) + 1; }
          if (b.approve === true) u.status = 'active';
          return d;
        });
        return json(200, { ok: true });
      }
      if (method === 'DELETE' && id) {
        if (id === user.id) throw new ApiError(400, 'You cannot delete your own account.');
        let gone;
        await update(K(org, 'users'), async (d) => {
          const u = d.users.find((x) => x.id === id);
          if (!u) throw new ApiError(404, 'No such user.');
          gone = u.username;
          d.users = d.users.filter((x) => x.id !== id); return d;
        });
        await releaseUsername(gone);
        return json(200, { ok: true });
      }
    }

    if (route === 'settings' && method === 'PUT') {
      requireAdmin(user);
      const b = await body(req);
      await update(K(org, 'users'), async (d) => { d.requireApproval = b.requireApproval === true; return d; });
      return json(200, { ok: true });
    }

    if (route === 'sections' && method === 'GET') {
      if (!parts[1]) return json(200, { sections: ((await db().get(ns + 'idx', { type: 'json' })) || { sections: [] }).sections });
      if (!ID_RE.test(parts[1])) throw new ApiError(400, 'Bad section id.');
      const cur = await db().getWithMetadata(ns + 'sec:' + parts[1], { type: 'json' });
      if (!cur) throw new ApiError(404, 'No such section.');
      const rev = String(cur.data.rev || 0);
      if (url.searchParams.get('have') === rev) return json(200, { unchanged: true }, { 'X-Rev': rev });
      const sec = cur.data; sec.sessions = normSessions(sec);
      return json(200, { section: sec }, { 'X-Rev': rev });
    }

    if (route === 'patch' && method === 'POST') {
      const b = await body(req);
      const secs = b && b.sections;
      if (!secs || typeof secs !== 'object' || Object.keys(secs).length > 60) throw new ApiError(400, 'Bad patch.');
      const results = {};
      for (const [id, sp] of Object.entries(secs)) {
        try {
          if (sp === null) { await deleteSection(ns, id); results[id] = { ok: true }; }
          else results[id] = { ok: true, sessions: await patchSection(ns, id, sp) };
        } catch (e) {
          if (!(e instanceof ApiError)) throw e;
          results[id] = { error: e.message, status: e.status };
        }
      }
      return json(200, { ok: true, results });
    }

    if ((route === 'lock' || route === 'unlock') && method === 'POST') {
      const b = await body(req);
      const meta = await setLock(ns, String(b.sectionId || ''), String(b.date || ''), Number(b.period), user, route === 'lock');
      return json(200, { ok: true, session: meta });
    }

    throw new ApiError(404, 'Not found.');
  } catch (e) {
    if (e instanceof ApiError) return json(e.status, { error: e.message });
    console.error(e);
    return json(500, { error: 'Server error.' });
  }
};
