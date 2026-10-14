import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { Pool } from 'pg';

const scrypt = promisify(scryptCallback);
const port = Number(process.env.PORT || 10000);
const pgPoolMax = Math.max(1, Math.min(50, Number.parseInt(process.env.PG_POOL_MAX || '8', 10) || 8));
const pgConnectionTimeoutMillis = Math.max(1_000, Math.min(30_000, Number.parseInt(process.env.PG_CONNECTION_TIMEOUT_MS || '5000', 10) || 5_000));
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
  max: pgPoolMax,
  min: 0,
  connectionTimeoutMillis: pgConnectionTimeoutMillis,
  idleTimeoutMillis: 30_000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10_000,
  maxUses: 7_500
});
pool.on('error', error => console.error('Unexpected idle PostgreSQL connection error:', error.message));
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
    CREATE TABLE IF NOT EXISTS tdci_member_entries (
      user_id uuid NOT NULL REFERENCES tdci_users(id) ON DELETE CASCADE,
      entry_id text NOT NULL,
      kind text NOT NULL CHECK (kind IN ('prayer', 'scripture', 'obedience')),
      activity_date date NOT NULL,
      record jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (user_id, entry_id)
    );
    CREATE INDEX IF NOT EXISTS tdci_member_entries_month_idx ON tdci_member_entries (user_id, activity_date, kind);
    CREATE INDEX IF NOT EXISTS tdci_member_entries_page_idx ON tdci_member_entries (user_id, activity_date, entry_id);
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
  await pool.query(`INSERT INTO tdci_member_entries (user_id, entry_id, kind, activity_date, record)
    SELECT s.user_id, e.record->>'id', e.record->>'kind', (e.record->>'date')::date, e.record
    FROM tdci_member_states s
    CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(s.state->'entries') = 'array' THEN s.state->'entries' ELSE '[]'::jsonb END) AS e(record)
    WHERE e.record->>'id' IS NOT NULL AND e.record->>'kind' IN ('prayer', 'scripture', 'obedience') AND e.record->>'date' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
    ON CONFLICT (user_id, entry_id) DO NOTHING`);
  await pool.query(`UPDATE tdci_member_states SET state = state - 'entries', updated_at = now() WHERE state ? 'entries'`);
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
  if (value.entries !== undefined && !Array.isArray(value.entries)) throw Object.assign(new Error('Member entries must be a list.'), { status: 400 });
  for (const entry of value.entries || []) validMemberEntry(entry);
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded) > 900_000) throw Object.assign(new Error('Member state is too large.'), { status: 413 });
  return value;
}

function validMemberEntry(entry) {
  const parsedDate = typeof entry?.date === 'string' ? new Date(`${entry.date}T12:00:00Z`) : null;
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || !['prayer', 'scripture', 'obedience'].includes(entry.kind) ||
      typeof entry.id !== 'string' || !entry.id.length || entry.id.length > 120 || !/^\d{4}-\d{2}-\d{2}$/.test(entry.date || '') ||
      !parsedDate || Number.isNaN(parsedDate.valueOf()) || parsedDate.toISOString().slice(0, 10) !== entry.date) {
    throw Object.assign(new Error('One of the member entries is invalid.'), { status: 400 });
  }
  if (Buffer.byteLength(JSON.stringify(entry)) > 16_384) throw Object.assign(new Error('An activity record is too large.'), { status: 413 });
  return entry;
}

async function route(req, res) {
  const url = new URL(req.url || '/', `https://${req.headers.host || 'localhost'}`);
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin) && url.pathname.startsWith('/api/')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
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
    const saved = result.rows[0]?.state || { reflections: {}, timer: null };
    if (url.searchParams.get('includeEntries') === 'false') {
      json(res, 200, { state: saved, updated_at: result.rows[0]?.updated_at || null }); return;
    }
    const entries = await pool.query('SELECT record FROM tdci_member_entries WHERE user_id = $1 ORDER BY activity_date, entry_id', [user.id]);
    json(res, 200, { state: { ...saved, entries: entries.rows.map(row => row.record) }, updated_at: result.rows[0]?.updated_at || null }); return;
  }
  const memberMonthMatch = url.pathname.match(/^\/api\/me\/entries\/(\d{4}-(?:0[1-9]|1[0-2]))$/);
  if (memberMonthMatch && req.method === 'GET') {
    const month = monthValue(memberMonthMatch[1]);
    const requestedLimit = Number.parseInt(url.searchParams.get('limit') || '100', 10);
    const limit = Number.isInteger(requestedLimit) ? Math.max(1, Math.min(250, requestedLimit)) : 100;
    const afterDate = url.searchParams.get('afterDate');
    const afterId = url.searchParams.get('afterId');
    if ((afterDate && !/^\d{4}-\d{2}-\d{2}$/.test(afterDate)) || (afterId && afterId.length > 120)) throw Object.assign(new Error('Invalid entry page cursor.'), { status: 400 });
    const result = await pool.query(`SELECT entry_id, activity_date, record FROM tdci_member_entries
      WHERE user_id = $1 AND activity_date >= ($2 || '-01')::date AND activity_date < (($2 || '-01')::date + interval '1 month')
      AND ($3::date IS NULL OR (activity_date, entry_id) > ($3::date, $4::text))
      ORDER BY activity_date, entry_id LIMIT $5`, [user.id, month, afterDate || null, afterId || '', limit + 1]);
    const hasMore = result.rows.length > limit;
    const rows = hasMore ? result.rows.slice(0, limit) : result.rows;
    const last = rows[rows.length - 1];
    const nextCursor = hasMore && last ? { date: String(last.activity_date).slice(0, 10), id: last.entry_id } : null;
    json(res, 200, { entries: rows.map(row => row.record), nextCursor });
    return;
  }
  if (url.pathname === '/api/me/entries' && req.method === 'PUT') {
    const entry = validMemberEntry(data.entry);
    await pool.query(`INSERT INTO tdci_member_entries (user_id, entry_id, kind, activity_date, record)
      VALUES ($1, $2, $3, $4::date, $5) ON CONFLICT (user_id, entry_id)
      DO UPDATE SET kind = EXCLUDED.kind, activity_date = EXCLUDED.activity_date, record = EXCLUDED.record`,
    [user.id, entry.id, entry.kind, entry.date, entry]);
    json(res, 200, { ok: true });
    return;
  }
  const memberEntryMatch = url.pathname.match(/^\/api\/me\/entries\/([^/]+)$/);
  if (memberEntryMatch && req.method === 'DELETE') {
    const id = decodeURIComponent(memberEntryMatch[1]);
    if (id.length > 120) throw Object.assign(new Error('Invalid entry identifier.'), { status: 400 });
    await pool.query('DELETE FROM tdci_member_entries WHERE user_id = $1 AND entry_id = $2', [user.id, id]);
    json(res, 200, { ok: true });
    return;
  }
  if (url.pathname === '/api/me/state' && req.method === 'PUT') {
    const submitted = validState(data);
    const entries = submitted.entries || [];
    const metadata = { ...submitted };
    delete metadata.entries;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(`INSERT INTO tdci_member_states (user_id, state, updated_at) VALUES ($1, $2, now())
        ON CONFLICT (user_id) DO UPDATE SET state = EXCLUDED.state, updated_at = now() RETURNING updated_at`, [user.id, metadata]);
      if (Array.isArray(submitted.entries)) {
        await client.query(`INSERT INTO tdci_member_entries (user_id, entry_id, kind, activity_date, record)
          SELECT $1, item.record->>'id', item.record->>'kind', (item.record->>'date')::date, item.record
          FROM jsonb_array_elements($2::jsonb) AS item(record)
          ON CONFLICT (user_id, entry_id) DO UPDATE SET kind = EXCLUDED.kind, activity_date = EXCLUDED.activity_date, record = EXCLUDED.record`, [user.id, JSON.stringify(entries)]);
        await client.query('DELETE FROM tdci_member_entries WHERE user_id = $1 AND entry_id <> ALL($2::text[])', [user.id, entries.map(entry => entry.id)]);
      }
      await client.query('COMMIT');
      json(res, 200, { ok: true, updated_at: result.rows[0].updated_at });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally { client.release(); }
    return;
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

let isShuttingDown = false;
function shutdown() {
  if (isShuttingDown) return;
  isShuttingDown = true;
  const forceExit = setTimeout(() => process.exit(1), 10_000);
  forceExit.unref();
  server.close(async () => {
    clearTimeout(forceExit);
    try { await pool.end(); process.exit(0); }
    catch (error) { console.error('Database pool shutdown failed:', error.message); process.exit(1); }
  });
  server.closeIdleConnections?.();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
