/**
 * LandGuard NG — Complete Server
 * Zero dependencies — built-in Node.js modules only
 * Run: node server.js
 * Open: http://localhost:3000
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');
const crypto = require('crypto');

const PORT        = process.env.PORT || 3000;
const DATA_FILE   = path.join(__dirname, 'data.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Admin credentials — change these to your own
const ADMIN_USER  = 'david';
const ADMIN_PASS  = 'landguard2026';

// Create uploads folder if needed
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

// ── Data helpers ──────────────────────────────────────────────
function readData() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return { users: [], sessions: {}, reports: [], consultations: [] }; }
}
function writeData(d) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2), 'utf8');
}
function genId(p)    { return p + '-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase(); }
function genToken()  { return crypto.randomBytes(32).toString('hex'); }
function hashPw(pw, salt) { return crypto.createHmac('sha256', salt).update(pw).digest('hex'); }

// ── Auth helpers ──────────────────────────────────────────────
function getToken(req) {
  const auth = req.headers['authorization'] || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  const m = (req.headers['cookie'] || '').match(/lg_token=([a-f0-9]+)/);
  return m ? m[1] : null;
}
function getUser(token) {
  if (!token) return null;
  const d = readData(), s = d.sessions[token];
  if (!s) return null;
  if (Date.now() - s.createdAt > 7 * 86400000) { delete d.sessions[token]; writeData(d); return null; }
  return d.users.find(u => u.id === s.userId) || null;
}
function requireAuth(req, res) {
  const u = getUser(getToken(req));
  if (!u) { sendJSON(res, 401, { error: 'Please log in.' }); return null; }
  return u;
}

// ── Response helpers ──────────────────────────────────────────
function sendJSON(res, code, payload, extra = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type,Authorization', ...extra });
  res.end(body);
}
function sendFile(res, fp, extra = {}) {
  const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.json': 'application/json', '.ico': 'image/x-icon', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.pdf': 'application/pdf', '.gif': 'image/gif', '.webp': 'image/webp' };
  fs.readFile(fp, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not Found'); }
    res.writeHead(200, { 'Content-Type': mime[path.extname(fp)] || 'text/plain', ...extra });
    res.end(data);
  });
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > 10 * 1024 * 1024) reject(new Error('Too large')); });
    req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch { reject(new Error('Bad JSON')); } });
    req.on('error', reject);
  });
}

// ── AUTH ROUTES ───────────────────────────────────────────────
async function handleRegister(req, res) {
  let b; try { b = await parseBody(req); } catch { return sendJSON(res, 400, { error: 'Invalid request' }); }
  const { username, password, fullName, phone } = b;
  if (!username || !password) return sendJSON(res, 400, { error: 'Username and password are required.' });
  if (username.length < 3)    return sendJSON(res, 400, { error: 'Username must be at least 3 characters.' });
  if (password.length < 6)    return sendJSON(res, 400, { error: 'Password must be at least 6 characters.' });
  if (!phone)                  return sendJSON(res, 400, { error: 'Phone number is required.' });
  const d = readData();
  if (d.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return sendJSON(res, 409, { error: 'Username already taken.' });
  const salt = crypto.randomBytes(16).toString('hex');
  const token = genToken();
  const user = { id: genId('USR'), username: username.trim(), fullName: (fullName||'').trim(), phone: phone.trim(), salt, password: hashPw(password, salt), createdAt: new Date().toISOString() };
  d.users.push(user);
  d.sessions[token] = { userId: user.id, createdAt: Date.now() };
  writeData(d);
  console.log(`[REGISTER] ${username}`);
  sendJSON(res, 200, { message: 'Account created! Welcome to LandGuard NG.', token, username: user.username, fullName: user.fullName, phone: user.phone }, { 'Set-Cookie': `lg_token=${token}; Path=/; HttpOnly; Max-Age=${7*86400}` });
}

async function handleLogin(req, res) {
  let b; try { b = await parseBody(req); } catch { return sendJSON(res, 400, { error: 'Invalid request' }); }
  const { username, password } = b;
  if (!username || !password) return sendJSON(res, 400, { error: 'Username and password are required.' });
  const d = readData();
  const user = d.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user || hashPw(password, user.salt) !== user.password) return sendJSON(res, 401, { error: 'Invalid username or password.' });
  const token = genToken();
  d.sessions[token] = { userId: user.id, createdAt: Date.now() };
  writeData(d);
  console.log(`[LOGIN] ${username}`);
  sendJSON(res, 200, { message: `Welcome back, ${user.fullName || user.username}!`, token, username: user.username, fullName: user.fullName, phone: user.phone || '' }, { 'Set-Cookie': `lg_token=${token}; Path=/; HttpOnly; Max-Age=${7*86400}` });
}

function handleLogout(req, res) {
  const token = getToken(req);
  if (token) { const d = readData(); delete d.sessions[token]; writeData(d); }
  sendJSON(res, 200, { message: 'Logged out.' }, { 'Set-Cookie': 'lg_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT' });
}

function handleMe(req, res) {
  const u = getUser(getToken(req));
  if (!u) return sendJSON(res, 401, { error: 'Not logged in.' });
  sendJSON(res, 200, { username: u.username, fullName: u.fullName, phone: u.phone || '' });
}

// ── PROTECTED ROUTES ──────────────────────────────────────────
function handleStats(req, res) {
  const u = requireAuth(req, res); if (!u) return;
  const d = readData();
  sendJSON(res, 200, { totalReports: d.reports.length, totalConsultations: d.consultations.length });
}

async function handleReport(req, res) {
  const u = requireAuth(req, res); if (!u) return;
  let b; try { b = await parseBody(req); } catch { return sendJSON(res, 400, { error: 'Invalid request' }); }
  if (!b.location || !b.issue) return sendJSON(res, 400, { error: 'Location and issue are required.' });

  // Save evidence file
  let evidenceFile = null;
  if (b.evidenceBase64 && b.evidenceName) {
    try {
      const ext = path.extname(b.evidenceName).toLowerCase();
      if (['.jpg','.jpeg','.png','.gif','.webp','.pdf'].includes(ext)) {
        const fname = 'evidence-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, fname), Buffer.from(b.evidenceBase64.replace(/^data:[^;]+;base64,/, ''), 'base64'));
        evidenceFile = fname;
      }
    } catch(e) { console.error('Evidence save error:', e.message); }
  }

  const d = readData();
  const reportId = genId('RPT');
  d.reports.push({ reportId, submittedBy: u.username, location: b.location.trim(), agent: (b.agent||'').trim(), reporterName: (b.reporterName||u.username).trim(), reporterEmail: (b.reporterEmail||'').trim(), phone: (b.phone||'').trim(), issue: b.issue.trim(), evidenceFile, status: 'Pending Review', submittedAt: new Date().toISOString() });
  writeData(d);
  console.log(`[REPORT] ${reportId} by ${u.username}`);
  sendJSON(res, 200, { message: 'Report submitted!', reportId, hasEvidence: !!evidenceFile });
}

async function handleConsult(req, res) {
  const u = requireAuth(req, res); if (!u) return;
  let b; try { b = await parseBody(req); } catch { return sendJSON(res, 400, { error: 'Invalid request' }); }
  if (!b.name || !b.email) return sendJSON(res, 400, { error: 'Name and email are required.' });
  const d = readData();
  const consultId = genId('CONS');
  d.consultations.push({ consultId, submittedBy: u.username, name: b.name.trim(), email: b.email.trim(), phone: (b.phone||'').trim(), service: (b.service||'General Inquiry').trim(), message: (b.message||'').trim(), status: 'Awaiting Callback', submittedAt: new Date().toISOString() });
  writeData(d);
  console.log(`[CONSULT] ${consultId} by ${u.username}`);
  sendJSON(res, 200, { message: `Thank you ${b.name.trim()}! We'll reach out within 24 hours.`, consultId });
}

// ── ADMIN DASHBOARD ───────────────────────────────────────────
function handleAdmin(req, res) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Basic ')) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="LandGuard Admin"', 'Content-Type': 'text/plain' });
    return res.end('Login required.');
  }
  const [user, pass] = Buffer.from(auth.slice(6), 'base64').toString().split(':');
  if (user !== ADMIN_USER || pass !== ADMIN_PASS) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="LandGuard Admin"', 'Content-Type': 'text/plain' });
    return res.end('Wrong credentials.');
  }
  const d = readData();
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LandGuard NG Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0a1f14;color:#e5e7eb;padding:24px}
h1{color:#c9a84c;font-size:22px;margin-bottom:4px}
.meta{color:#6b7280;font-size:13px;margin-bottom:28px}
h2{color:#22c55e;margin:36px 0 10px;font-size:16px}
.stats{display:flex;gap:20px;margin-bottom:32px;flex-wrap:wrap}
.stat-box{background:#0d3322;border-radius:10px;padding:18px 26px;border:1px solid #1a3a26;min-width:120px}
.stat-num{font-size:28px;font-weight:700;color:#c9a84c;font-family:Georgia,serif}
.stat-label{font-size:11px;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:1px}
table{border-collapse:collapse;width:100%;font-size:12px;margin-bottom:32px}
th{background:#145c38;color:#fff;padding:9px 12px;text-align:left;white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid #1a3a26;vertical-align:top;max-width:240px;word-break:break-word}
tr:hover td{background:#0d2c1c}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;background:#1a7a4a;color:#fff}
a{color:#c9a84c}
</style></head><body>
<h1>🛡 LandGuard NG — Admin Dashboard</h1>
<p class="meta">Last refreshed: ${new Date().toLocaleString('en-NG')}</p>
<div class="stats">
  <div class="stat-box"><div class="stat-num">${d.reports.length}</div><div class="stat-label">Reports</div></div>
  <div class="stat-box"><div class="stat-num">${d.consultations.length}</div><div class="stat-label">Consultations</div></div>
  <div class="stat-box"><div class="stat-num">${d.users.length}</div><div class="stat-label">Users</div></div>
</div>

<h2>👥 Registered Users (${d.users.length})</h2>
<table><tr><th>#</th><th>Username</th><th>Full Name</th><th>Phone</th><th>Joined</th></tr>
${d.users.map((u,i)=>`<tr><td>${i+1}</td><td>${u.username}</td><td>${u.fullName||'—'}</td><td>${u.phone||'—'}</td><td>${new Date(u.createdAt).toLocaleString('en-NG')}</td></tr>`).join('')||'<tr><td colspan="5" style="text-align:center;color:#6b7280">No users yet</td></tr>'}
</table>

<h2>📋 Fraud Reports (${d.reports.length})</h2>
<table><tr><th>#</th><th>ID</th><th>Location</th><th>Agent</th><th>Reporter</th><th>Phone</th><th>Issue</th><th>Evidence</th><th>By</th><th>Date</th><th>Status</th></tr>
${d.reports.slice().reverse().map((r,i)=>`<tr><td>${i+1}</td><td style="font-size:10px">${r.reportId}</td><td>${r.location}</td><td>${r.agent||'—'}</td><td>${r.reporterName}</td><td>${r.phone||'—'}</td><td>${(r.issue||'').slice(0,80)}${r.issue&&r.issue.length>80?'…':''}</td><td>${r.evidenceFile?`<a href="/uploads/${r.evidenceFile}" target="_blank">View 🖼</a>`:'—'}</td><td>${r.submittedBy||'—'}</td><td style="font-size:10px">${new Date(r.submittedAt).toLocaleString('en-NG')}</td><td><span class="badge">${r.status}</span></td></tr>`).join('')||'<tr><td colspan="11" style="text-align:center;color:#6b7280">No reports yet</td></tr>'}
</table>

<h2>📅 Consultation Requests (${d.consultations.length})</h2>
<table><tr><th>#</th><th>ID</th><th>Name</th><th>Email</th><th>Phone</th><th>Service</th><th>Message</th><th>By</th><th>Date</th><th>Status</th></tr>
${d.consultations.slice().reverse().map((c,i)=>`<tr><td>${i+1}</td><td style="font-size:10px">${c.consultId}</td><td>${c.name}</td><td>${c.email}</td><td>${c.phone||'—'}</td><td>${c.service}</td><td>${(c.message||'—').slice(0,60)}${(c.message||'').length>60?'…':''}</td><td>${c.submittedBy||'—'}</td><td style="font-size:10px">${new Date(c.submittedAt).toLocaleString('en-NG')}</td><td><span class="badge">${c.status}</span></td></tr>`).join('')||'<tr><td colspan="10" style="text-align:center;color:#6b7280">No consultations yet</td></tr>'}
</table>
</body></html>`;
  res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html);
}

// ── ROUTER ────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const { pathname } = url.parse(req.url);
  const method = req.method.toUpperCase();
  if (method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,Authorization' }); return res.end(); }
  console.log(`${method} ${pathname}`);
  if (pathname === '/api/auth/register' && method === 'POST') return handleRegister(req, res);
  if (pathname === '/api/auth/login'    && method === 'POST') return handleLogin(req, res);
  if (pathname === '/api/auth/logout'   && method === 'POST') return handleLogout(req, res);
  if (pathname === '/api/auth/me'       && method === 'GET')  return handleMe(req, res);
  if (pathname === '/api/stats'         && method === 'GET')  return handleStats(req, res);
  if (pathname === '/api/report'        && method === 'POST') return handleReport(req, res);
  if (pathname === '/api/consult'       && method === 'POST') return handleConsult(req, res);
  if (pathname === '/admin'             && method === 'GET')  return handleAdmin(req, res);
  if (pathname.startsWith('/uploads/')) {
    const fp = path.join(UPLOADS_DIR, path.basename(pathname));
    return fs.existsSync(fp) ? sendFile(res, fp) : (res.writeHead(404), res.end('Not found'));
  }
  if (pathname === '/login' || pathname === '/login.html') return sendFile(res, path.join(__dirname, 'login.html'));
  if (pathname === '/' || pathname === '/index.html')      return sendFile(res, path.join(__dirname, 'index.html'));
  const fp = path.join(__dirname, pathname.replace(/^\//, ''));
  if (fs.existsSync(fp) && fs.statSync(fp).isFile()) return sendFile(res, fp);
  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found');
});

server.listen(PORT, () => {
  console.log('\n  ╔══════════════════════════════════════════╗');
  console.log('  ║   🛡  LandGuard NG — Server Started!    ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log(`\n  🌐  Website : http://localhost:${PORT}`);
  console.log(`  📊  Admin   : http://localhost:${PORT}/admin`);
  console.log(`  📁  Data    : ${DATA_FILE}`);
  console.log('\n  Press Ctrl+C to stop.\n');
});
