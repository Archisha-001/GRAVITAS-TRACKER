const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const { exec } = require('child_process');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const USER_STORE = path.join(DATA_DIR, 'users.json');
const SECRET_FILE = path.join(DATA_DIR, '.session_secret');
const PORT = Number(process.env.PORT || 4000);
const HOST = process.env.HOST || '127.0.0.1';
const ALLOWED_EMAIL_DOMAINS = String(process.env.ALLOWED_EMAIL_DOMAINS || 'vitstudent.ac.in,vit.ac.in')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const JWT_EXPIRES_SECONDS = 30 * 24 * 60 * 60;

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USER_STORE)) fs.writeFileSync(USER_STORE, '[]\n', 'utf8');
let JWT_SECRET = '';
try { JWT_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim(); } catch (_) {}
if (!JWT_SECRET) {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(SECRET_FILE, JWT_SECRET, { encoding: 'utf8', mode: 0o600 });
}

function readUsers() {
  try {
    const parsed = JSON.parse(fs.readFileSync(USER_STORE, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('Could not read local account store:', err.message);
    return [];
  }
}

function writeUsers(users) {
  const tmp = USER_STORE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2) + '\n', 'utf8');
  fs.renameSync(tmp, USER_STORE);
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function isVitEmail(email) {
  const domain = email.trim().toLowerCase().split('@')[1] || '';
  return ALLOWED_EMAIL_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}

function verifyPassword(password, salt, expectedHash) {
  try {
    const actual = crypto.scryptSync(password, salt, 64).toString('hex');
    const a = Buffer.from(actual, 'hex');
    const b = Buffer.from(expectedHash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
}

function b64url(value) {
  return Buffer.from(value).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function signToken(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const unsigned = `${header}.${body}`;
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(unsigned).digest('base64url');
  return `${unsigned}.${sig}`;
}
function verifyToken(token) {
  try {
    const [header, body, sig] = String(token || '').split('.');
    if (!header || !body || !sig) return null;
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    const a = Buffer.from(sig), b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() >= payload.exp * 1000) return null;
    return payload;
  } catch (_) { return null; }
}

function sendJson(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
  });
  res.end(text);
}

function serveFile(res, pathname) {
  const requested = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.resolve(PUBLIC_DIR, '.' + requested);
  if (!filePath.startsWith(path.resolve(PUBLIC_DIR) + path.sep)) return sendJson(res, 403, { error: 'Forbidden' });
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return sendJson(res, 404, { error: 'Not found' });
  const ext = path.extname(filePath).toLowerCase();
  const types = {
    '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'application/javascript; charset=utf-8',
    '.json':'application/json; charset=utf-8', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg',
    '.svg':'image/svg+xml', '.ico':'image/x-icon', '.webp':'image/webp'
  };
  res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream', 'Cache-Control': 'no-store' });
  fs.createReadStream(filePath).pipe(res);
}

function parseJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 100_000) reject(new Error('Request body too large'));
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); } catch (_) { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function publicUser(user) {
  return { id: user.id, email: user.email, accountType: user.accountType };
}
function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : '';
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
      });
      return res.end();
    }

    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'GET' && url.pathname === '/api/health') {
      return sendJson(res, 200, { ok: true, service: 'gravitrack-local', database: 'data/users.json' });
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/signup') {
      const body = await parseJson(req);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      const accountType = body.accountType === 'external' ? 'external' : 'vit';

      if (!isValidEmail(email)) return sendJson(res, 400, { error: 'Enter a valid email address.' });
      if (password.length < 8) return sendJson(res, 400, { error: 'Password must be at least 8 characters.' });
      if (accountType === 'vit' && !isVitEmail(email)) {
        return sendJson(res, 400, { error: `VIT students must use a college email (${ALLOWED_EMAIL_DOMAINS[0] || 'your college domain'}).` });
      }

      const users = readUsers();
      if (users.some(u => u.email === email)) return sendJson(res, 409, { error: 'An account with that email already exists. Log in instead.' });

      const { salt, hash } = hashPassword(password);
      const user = { id: crypto.randomUUID(), email, accountType, salt, passwordHash: hash, createdAt: new Date().toISOString() };
      users.push(user);
      writeUsers(users);

      const now = Math.floor(Date.now() / 1000);
      const token = signToken({ sub: user.id, email: user.email, accountType: user.accountType, iat: now, exp: now + JWT_EXPIRES_SECONDS });
      return sendJson(res, 201, { token, user: publicUser(user) });
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/login') {
      const body = await parseJson(req);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      if (!isValidEmail(email) || !password) return sendJson(res, 400, { error: 'Enter your email and password.' });
      const user = readUsers().find(u => u.email === email);
      if (!user || !verifyPassword(password, user.salt, user.passwordHash)) return sendJson(res, 401, { error: 'Invalid email or password.' });
      const now = Math.floor(Date.now() / 1000);
      const token = signToken({ sub: user.id, email: user.email, accountType: user.accountType, iat: now, exp: now + JWT_EXPIRES_SECONDS });
      return sendJson(res, 200, { token, user: publicUser(user) });
    }

    if (req.method === 'GET' && url.pathname === '/api/auth/me') {
      const payload = verifyToken(bearer(req));
      if (!payload) return sendJson(res, 401, { error: 'Invalid or expired session.' });
      return sendJson(res, 200, { user: { id: payload.sub, email: payload.email, accountType: payload.accountType } });
    }

    if (req.method === 'GET' || req.method === 'HEAD') return serveFile(res, url.pathname);
    return sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    return sendJson(res, err.message === 'Invalid JSON' ? 400 : 500, { error: err.message || 'Server error' });
  }
});

function openBrowser(url) {
  const command = process.platform === 'win32' ? `start "" "${url}"` : process.platform === 'darwin' ? `open "${url}"` : `xdg-open "${url}"`;
  exec(command, () => {});
}

server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\nPort ${PORT} is already in use. Close the program using port ${PORT}, then run GraviTrack again.\n`);
    process.exit(1);
  }
  console.error(err);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  const url = `http://localhost:${PORT}`;
  console.log('\n========================================');
  console.log('  GraviTrack is running locally');
  console.log(`  ${url}`);
  console.log('  Account data: data/users.json');
  console.log('========================================\n');
  if (process.env.OPEN_BROWSER !== 'false') setTimeout(() => openBrowser(url), 500);
});
