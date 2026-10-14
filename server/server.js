import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { Pool } from 'pg';

const scrypt = promisify(scryptCallback);
const port = Number(process.env.PORT || 10000);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
  max: 8,
  idleTimeoutMillis: 30_000
});
const publicDir = new URL('./public/', import.meta.url);
const allowedOrigins = new Set((process.env.ALLOWED_ORIGINS || 'https://localhost,capacitor://localhost,http://localhost,http://127.0.0.1:4173,http://localhost:4173')
  .split(',').map(value => value.trim()).filter(Boolean));
const adminEmails = new Set((process.env.ADMIN_EMAILS || '').split(',').map(email => email.trim().toLowerCase()).filter(Boolean));
const policyVersion = '2026-10-14';
const cookieName = 'tdci_session';
const defaultTargets = { obedience: 12, scripture: 16, prayerMinutes: 180 };

function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function cookie(res, value, maxAge = 60 * 60 * 24 * 30) {
  res.setHeader('Set-Cookie', `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAge}`);
}

function clearCookie(res) { cookie(res, '', 0); }

function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map(part => part.trim().split(/=(.*)/s, 2)).filter(pair => pair.length === 2));
}

async function body(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1_048_576) throw Object.assign(new Error('Request is too large.'), { status: 413 });
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if ((req.headers['content-type'] || '').includes('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(raw));
  try { return raw ? JSON.parse(raw) : {}; } catch { throw Object.assign(new Error('Invalid request body.'), { status: 400 }); }
}

function emailValue(value) {
  const email = String(value || '').trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw Object.assign(new Error('Enter a valid email address.'), { status: 400 });
  return email;
}

function monthValue(value) {
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(value || '')) throw Object.assign(new Error('Month must use YYYY-MM format.'), { status: 400 });
  return value;
}

async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 10 || password.length > 256) throw Object.assign(new Error('Use a password with at least 10 characters.'), { status: 400 });
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('base64url')}$${Buffer.from(key).toString('base64url')}`;
}

async function verifyPassword(password, encoded) {
  if (typeof password !== 'string' || !encoded) return false;
  try {
    const [kind, salt, expected] = encoded.split('$');
    if (kind !== 'scrypt') return false;
    const actual = Buffer.from(await scrypt(password, Buffer.from(salt, 'base64url'), 64, { N: 16384, r: 8, p: 1 }));
    const target = Buffer.from(expected, 'base64url');
    return actual.length === target.length && timingSafeEqual(actual, target);
  } catch { return false; }
}

function tokenHash(value) { return createHash('sha256').update(value).digest('hex'); }

async function createSession(res, userId) {
  const token = randomBytes(32).toString('base64url');
  await pool.query('INSERT INTO tdci_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval \'30 days\')', [tokenHash(token), userId]);
  cookie(res, token);
}

async function currentUser(req) {
  const token = parseCookies(req.headers.cookie)[cookieName];
  if (!token) return null;
  const result = await pool.query(`SELECT u.id, u.email, u.role FROM tdci_sessions s
    JOIN tdci_users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now()`, [tokenHash(token)]);
  return result.rows[0] || null;
}

function publicUser(user) { return { id: user.id, email: user.email, role: user.role }; }

async function registerAccount(data, role, res) {
  const email = emailValue(data.email);
  if (role === 'admin' && !adminEmails.has(email)) {
    throw Object.assign(new Error('This email is not approved for TDCI admin access. Ask the church to add it to ADMIN_EMAILS.'), { status: 403 });
  }
  if (role === 'member' && adminEmails.has(email)) {
    throw Object.assign(new Error('This email is reserved for TDCI admin access. Choose the Church admin sign-in.'), { status: 403 });
  }
  if (data.privacyConsent !== true || data.privacyPolicyVersion !== policyVersion) {
    throw Object.assign(new Error('Review and accept the current privacy policy to create a cloud account.'), { status: 400 });
  }
  const passwordHash = await hashPassword(data.password);
  try {
    const inserted = await pool.query(`INSERT INTO tdci_users (email, password_hash, role, privacy_consent_version)
      VALUES ($1, $2, $3, $4) RETURNING id, email, role`, [email, passwordHash, role, policyVersion]);
    await createSession(res, inserted.rows[0].id);
    json(res, 201, { user: publicUser(inserted.rows[0]) });
  } catch (error) {
    if (error.code === '23505') throw Object.assign(new Error('An account with that email already exists. Sign in instead.'), { status: 409 });
    throw error;
  }
}

async function loginAccount(data, role, res) {
  const email = emailValue(data.email);
  const result = await pool.query('SELECT id, email, role, password_hash FROM tdci_users WHERE email = $1', [email]);
  const account = result.rows[0];
  const allowedRole = role === 'admin'
    ? account?.role === 'admin' && adminEmails.has(email)
    : account?.role === 'member';
  if (!allowedRole || !(await verifyPassword(String(data.password || ''), account?.password_hash))) {
    const message = role === 'admin'
      ? 'Admin sign-in could not be verified. Check your details and TDCI admin approval.'
      : 'Member sign-in could not be verified. Use Church admin sign-in for a TDCI administrator account.';
    throw Object.assign(new Error(message), { status: 401 });
  }
  await createSession(res, account.id);
  json(res, 200, { user: publicUser(account) });
}

async function initializeDatabase() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required.');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tdci_users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email text NOT NULL UNIQUE,
      password_hash text NOT NULL,
      role text NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'admin')),
      privacy_consent_version text NOT NULL,
      privacy_consent_at timestamptz NOT NULL DEFAULT now(),
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS tdci_sessions (
      token_hash text PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES tdci_users(id) ON DELETE CASCADE,
      expires_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS tdci_sessions_expiry_idx ON tdci_sessions (expires_at);
    CREATE TABLE IF NOT EXISTS tdci_member_states (
      user_id uuid PRIMARY KEY REFERENCES tdci_users(id) ON DELETE CASCADE,
      state jsonb NOT NULL DEFAULT '{}'::jsonb,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS tdci_monthly_plans (
      month text PRIMARY KEY CHECK (month ~ '^\\d{4}-(0[1-9]|1[0-2])$'),
      targets jsonb NOT NULL,
      focus text NOT NULL DEFAULT '',
      updated_by uuid REFERENCES tdci_users(id) ON DELETE SET NULL,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS tdci_church_resources (
      id text PRIMARY KEY DEFAULT 'main' CHECK (id = 'main'),
      prayer_url text NOT NULL DEFAULT '',
      messages_url text NOT NULL DEFAULT '',
      updated_by uuid REFERENCES tdci_users(id) ON DELETE SET NULL,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);
}

async function deleteAccount(userId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE tdci_monthly_plans SET updated_by = NULL WHERE updated_by = $1', [userId]);
    await client.query('DELETE FROM tdci_sessions WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM tdci_users WHERE id = $1', [userId]);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

function validState(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Object.assign(new Error('Invalid member state.'), { status: 400 });
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded) > 900_000) throw Object.assign(new Error('Member state is too large.'), { status: 413 });
  return value;
}

async function route(req, res) {
  const url = new URL(req.url || '/', `https://${req.headers.host || 'localhost'}`);
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin) && url.pathname.startsWith('/api/')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  }
  if (req.method === 'OPTIONS' && url.pathname.startsWith('/api/')) { res.writeHead(204); res.end(); return; }

  if (url.pathname === '/privacy' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(await readFile(new URL('privacy.html', publicDir))); return;
  }
  if (url.pathname === '/delete-account' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(await readFile(new URL('delete-account.html', publicDir))); return;
  }
  if (url.pathname === '/delete-account' && req.method === 'POST') {
    const form = await body(req);
    try {
      const email = emailValue(form.email);
      const found = await pool.query('SELECT id, password_hash FROM tdci_users WHERE email = $1', [email]);
      if (!found.rows[0] || !(await verifyPassword(String(form.password || ''), found.rows[0].password_hash))) throw new Error('The account details could not be verified.');
      await deleteAccount(found.rows[0].id);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Account deleted</title><main style="font:16px/1.6 system-ui;max-width:40rem;margin:12vh auto;padding:24px"><h1>Account deleted</h1><p>Your TDCI cloud account and synced records have been deleted. Records saved only on a device remain there until removed from that device.</p></main>');
      return;
    } catch (error) {
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Could not delete account</title><main style="font:16px/1.6 system-ui;max-width:40rem;margin:12vh auto;padding:24px"><h1>Could not delete account</h1><p>${String(error.message).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])}</p><p>Go back and check the email and password.</p></main>`);
      return;
    }
  }

  if (url.pathname === '/api/health' && req.method === 'GET') { await pool.query('SELECT 1'); json(res, 200, { ok: true, service: 'TDCI Discipleship API' }); return; }
  if (url.pathname === '/api/church/resources' && req.method === 'GET') {
    const result = await pool.query('SELECT prayer_url, messages_url, updated_at FROM tdci_church_resources WHERE id = $1', ['main']);
    const row = result.rows[0];
    json(res, 200, { resources: { prayerUrl: row?.prayer_url || '', messagesUrl: row?.messages_url || '' }, updated_at: row?.updated_at || null });
    return;
  }
  if (!url.pathname.startsWith('/api/')) { json(res, 404, { error: 'Not found.' }); return; }

  const data = ['POST', 'PUT'].includes(req.method) ? await body(req) : {};
  if (url.pathname === '/api/auth/register' && req.method === 'POST') { await registerAccount(data, 'member', res); return; }
  if (url.pathname === '/api/auth/admin/register' && req.method === 'POST') { await registerAccount(data, 'admin', res); return; }
  if (url.pathname === '/api/auth/login' && req.method === 'POST') { await loginAccount(data, 'member', res); return; }
  if (url.pathname === '/api/auth/admin/login' && req.method === 'POST') { await loginAccount(data, 'admin', res); return; }
  if (url.pathname === '/api/auth/me' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) throw Object.assign(new Error('Sign in to continue.'), { status: 401 });
    json(res, 200, { user: publicUser(user) }); return;
  }
  if (url.pathname === '/api/auth/logout' && req.method === 'POST') {
    const token = parseCookies(req.headers.cookie)[cookieName];
    if (token) await pool.query('DELETE FROM tdci_sessions WHERE token_hash = $1', [tokenHash(token)]);
    clearCookie(res); json(res, 200, { ok: true }); return;
  }
  if (url.pathname === '/api/auth/delete' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) throw Object.assign(new Error('Sign in to continue.'), { status: 401 });
    const found = await pool.query('SELECT password_hash FROM tdci_users WHERE id = $1', [user.id]);
    if (!found.rows[0] || !(await verifyPassword(String(data.password || ''), found.rows[0].password_hash))) throw Object.assign(new Error('Password is incorrect.'), { status: 403 });
    await deleteAccount(user.id); clearCookie(res); json(res, 200, { ok: true }); return;
  }

  const user = await currentUser(req);
  if (!user) throw Object.assign(new Error('Sign in to continue.'), { status: 401 });
  if (url.pathname === '/api/me/state' && req.method === 'GET') {
    const result = await pool.query('SELECT state, updated_at FROM tdci_member_states WHERE user_id = $1', [user.id]);
    json(res, 200, { state: result.rows[0]?.state || { entries: [], reflections: {}, timer: null }, updated_at: result.rows[0]?.updated_at || null }); return;
  }
  if (url.pathname === '/api/me/state' && req.method === 'PUT') {
    const state = validState(data);
    const result = await pool.query(`INSERT INTO tdci_member_states (user_id, state, updated_at) VALUES ($1, $2, now())
      ON CONFLICT (user_id) DO UPDATE SET state = EXCLUDED.state, updated_at = now() RETURNING updated_at`, [user.id, state]);
    json(res, 200, { ok: true, updated_at: result.rows[0].updated_at }); return;
  }
  if (url.pathname === '/api/church/resources' && req.method === 'PUT') {
    if (user.role !== 'admin') throw Object.assign(new Error('Only a TDCI administrator can publish church links.'), { status: 403 });
    const validLink = (value, name) => {
      const raw = String(value || '').trim();
      if (!raw) return '';
      let parsed;
      try { parsed = new URL(raw); } catch { throw Object.assign(new Error(`${name} must be a valid HTTPS link.`), { status: 400 }); }
      if (parsed.protocol !== 'https:' || raw.length > 1000) throw Object.assign(new Error(`${name} must be a valid HTTPS link up to 1,000 characters.`), { status: 400 });
      return parsed.toString();
    };
    const prayerUrl = validLink(data.prayerUrl, 'Prayer link');
    const messagesUrl = validLink(data.messagesUrl, 'Messages link');
    const result = await pool.query(`INSERT INTO tdci_church_resources (id, prayer_url, messages_url, updated_by, updated_at)
      VALUES ('main', $1, $2, $3, now()) ON CONFLICT (id) DO UPDATE SET prayer_url = EXCLUDED.prayer_url,
      messages_url = EXCLUDED.messages_url, updated_by = EXCLUDED.updated_by, updated_at = now()
      RETURNING prayer_url, messages_url, updated_at`, [prayerUrl, messagesUrl, user.id]);
    const row = result.rows[0];
    json(res, 200, { resources: { prayerUrl: row.prayer_url, messagesUrl: row.messages_url }, updated_at: row.updated_at });
    return;
  }
  const planMatch = url.pathname.match(/^\/api\/plans\/(\d{4}-(?:0[1-9]|1[0-2]))$/);
  if (planMatch && req.method === 'GET') {
    const month = monthValue(planMatch[1]);
    const result = await pool.query('SELECT targets, focus, updated_at FROM tdci_monthly_plans WHERE month = $1', [month]);
    const plan = result.rows[0];
    json(res, 200, { plan: plan ? { targets: plan.targets, focus: plan.focus, updated_at: plan.updated_at, unconfigured: false } : { targets: defaultTargets, focus: '', updated_at: null, unconfigured: true } }); return;
  }
  if (planMatch && req.method === 'PUT') {
    if (user.role !== 'admin') throw Object.assign(new Error('Only a TDCI administrator can publish monthly goals.'), { status: 403 });
    const month = monthValue(planMatch[1]);
    const targets = data.targets;
    if (!targets || ['obedience', 'scripture', 'prayerMinutes'].some(key => !Number.isInteger(targets[key]) || targets[key] < 0 || targets[key] > 100_000)) throw Object.assign(new Error('Enter whole-number monthly targets.'), { status: 400 });
    const focus = String(data.focus || '').trim();
    if (focus.length > 500) throw Object.assign(new Error('Monthly focus must be 500 characters or fewer.'), { status: 400 });
    const result = await pool.query(`INSERT INTO tdci_monthly_plans (month, targets, focus, updated_by, updated_at)
      VALUES ($1, $2, $3, $4, now()) ON CONFLICT (month) DO UPDATE SET targets = EXCLUDED.targets, focus = EXCLUDED.focus, updated_by = EXCLUDED.updated_by, updated_at = now()
      RETURNING targets, focus, updated_at`, [month, targets, focus, user.id]);
    json(res, 200, { plan: { ...result.rows[0], unconfigured: false } }); return;
  }
  json(res, 404, { error: 'Not found.' });
}

const server = createServer(async (req, res) => {
  try { await route(req, res); }
  catch (error) {
    if (!res.headersSent) json(res, error.status || 500, { error: error.status ? error.message : 'The service could not complete that request.' });
    if (!error.status) console.error('Request failed:', error.message);
  }
});

initializeDatabase().then(() => {
  server.listen(port, '0.0.0.0', () => console.log(`TDCI Discipleship API listening on ${port}`));
}).catch(error => {
  console.error('Database initialization failed:', error.message);
  process.exit(1);
});

process.on('SIGTERM', async () => { server.close(); await pool.end(); process.exit(0); });
