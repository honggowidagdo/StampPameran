// Digital Stamp - server
// Express + SQLite (built-in node:sqlite) + session login
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const QRCode = require('qrcode');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const MAX_STAMPS = 10;

// ---------- Database ----------
const db = new DatabaseSync(path.join(__dirname, 'stamp.db'));
db.exec(`
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    role          TEXT NOT NULL CHECK (role IN ('visitor','outlet')),
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    name          TEXT NOT NULL,
    booth_name    TEXT,
    stamp_code    TEXT UNIQUE,
    created_at    TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );
  CREATE TABLE IF NOT EXISTS stamps (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor_id INTEGER NOT NULL REFERENCES users(id),
    outlet_id  INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );
`);

// ---------- Helpers ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), test);
}
function newStampCode() {
  // Kode unik pengunjung yang dimasukkan ke QR, contoh: VST-8F3A2C91
  return 'VST-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}
function countStamps(visitorId) {
  return db.prepare('SELECT COUNT(*) AS c FROM stamps WHERE visitor_id = ?').get(visitorId).c;
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Silakan login terlebih dahulu.' });
    if (req.session.user.role !== role) return res.status(403).json({ error: 'Akses ditolak.' });
    next();
  };
}

// ---------- App ----------
const app = express();
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 12 },
}));

// Halaman dashboard dilindungi: arahkan ke login bila belum masuk / salah peran
app.get('/visitor.html', (req, res, next) =>
  req.session.user?.role === 'visitor' ? next() : res.redirect('/'));
app.get('/outlet.html', (req, res, next) =>
  req.session.user?.role === 'outlet' ? next() : res.redirect('/'));

app.use(express.static(path.join(__dirname, 'public')));
app.get('/vendor/html5-qrcode.min.js', (req, res) =>
  res.sendFile(require.resolve('html5-qrcode/html5-qrcode.min.js')));

// ---------- Auth ----------
app.post('/api/register', (req, res) => {
  const { role, username, password, name, booth_name } = req.body || {};
  if (!['visitor', 'outlet'].includes(role)) return res.status(400).json({ error: 'Peran tidak valid.' });
  if (!username || !/^[a-zA-Z0-9_.]{3,30}$/.test(username))
    return res.status(400).json({ error: 'Username 3-30 karakter (huruf, angka, _ atau .).' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter.' });
  if (!name || !name.trim()) return res.status(400).json({ error: 'Nama wajib diisi.' });
  if (role === 'outlet' && (!booth_name || !booth_name.trim()))
    return res.status(400).json({ error: 'Nama outlet/booth wajib diisi.' });

  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username))
    return res.status(409).json({ error: 'Username sudah dipakai.' });

  db.prepare(`INSERT INTO users (role, username, password_hash, name, booth_name, stamp_code)
              VALUES (?, ?, ?, ?, ?, ?)`)
    .run(role, username, hashPassword(password), name.trim(),
         role === 'outlet' ? booth_name.trim() : null,
         role === 'visitor' ? newStampCode() : null);

  res.json({ ok: true, message: 'Pendaftaran berhasil. Silakan login.' });
});

app.post('/api/login', (req, res) => {
  const { role, username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username || '');
  if (!user || !verifyPassword(password || '', user.password_hash))
    return res.status(401).json({ error: 'Username atau password salah.' });
  if (user.role !== role) {
    const label = user.role === 'visitor' ? 'Pengunjung' : 'Outlet Pameran';
    return res.status(403).json({ error: `Akun ini terdaftar sebagai ${label}.` });
  }
  req.session.user = { id: user.id, role: user.role, name: user.name };
  res.json({ ok: true, redirect: role === 'visitor' ? '/visitor.html' : '/outlet.html' });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Belum login.' });
  const u = db.prepare('SELECT id, role, username, name, booth_name FROM users WHERE id = ?')
    .get(req.session.user.id);
  res.json(u);
});

// ---------- Pengunjung ----------
app.get('/api/visitor/card', requireRole('visitor'), async (req, res) => {
  const me = db.prepare('SELECT stamp_code FROM users WHERE id = ?').get(req.session.user.id);
  const stamps = db.prepare(`
    SELECT s.id, s.created_at, u.booth_name
    FROM stamps s JOIN users u ON u.id = s.outlet_id
    WHERE s.visitor_id = ? ORDER BY s.id ASC`).all(req.session.user.id);
  const qr = await QRCode.toDataURL(me.stamp_code, { width: 320, margin: 1 });
  res.json({ code: me.stamp_code, qr, max: MAX_STAMPS, stamps });
});

// ---------- Outlet ----------
function findVisitorByCode(code) {
  return db.prepare("SELECT id, name, username FROM users WHERE role = 'visitor' AND stamp_code = ?")
    .get(String(code || '').trim().toUpperCase());
}

app.get('/api/outlet/lookup', requireRole('outlet'), (req, res) => {
  const v = findVisitorByCode(req.query.code);
  if (!v) return res.status(404).json({ error: 'Kode pengunjung tidak ditemukan.' });
  res.json({ name: v.name, username: v.username, count: countStamps(v.id), max: MAX_STAMPS });
});

app.post('/api/outlet/stamp', requireRole('outlet'), (req, res) => {
  const v = findVisitorByCode(req.body?.code);
  if (!v) return res.status(404).json({ error: 'Kode pengunjung tidak ditemukan.' });
  const count = countStamps(v.id);
  if (count >= MAX_STAMPS)
    return res.status(400).json({ error: `Kartu ${v.name} sudah penuh (${MAX_STAMPS}/${MAX_STAMPS}).` });
  db.prepare('INSERT INTO stamps (visitor_id, outlet_id) VALUES (?, ?)').run(v.id, req.session.user.id);
  res.json({ ok: true, name: v.name, count: count + 1, max: MAX_STAMPS });
});

app.get('/api/outlet/history', requireRole('outlet'), (req, res) => {
  const rows = db.prepare(`
    SELECT s.id, s.created_at, u.name AS visitor_name, u.username
    FROM stamps s JOIN users u ON u.id = s.visitor_id
    WHERE s.outlet_id = ? ORDER BY s.id DESC LIMIT 100`).all(req.session.user.id);
  const total = db.prepare('SELECT COUNT(*) AS c FROM stamps WHERE outlet_id = ?').get(req.session.user.id).c;
  res.json({ total, rows });
});

app.listen(PORT, () => console.log(`Digital Stamp berjalan di http://localhost:${PORT}`));
