// Backend (Node + Express + SQLite). كل العمليات المالية تتم هنا فقط.
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const JWT_SECRET = process.env.JWT_SECRET;
const WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET;
if (!JWT_SECRET || !WEBHOOK_SECRET) throw new Error('Set JWT_SECRET and PAYMENT_WEBHOOK_SECRET');

const db = new Database(process.env.DB_FILE || 'app.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, phone TEXT UNIQUE,
  password_hash TEXT NOT NULL, role TEXT DEFAULT 'user', name TEXT, bio TEXT DEFAULT '',
  avatar_url TEXT, cover_url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id),
  body TEXT, image_url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id), body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS likes(post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id), PRIMARY KEY(post_id,user_id));
CREATE TABLE IF NOT EXISTS friend_requests(id INTEGER PRIMARY KEY, from_id INTEGER, to_id INTEGER,
  status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(from_id,to_id));
CREATE TABLE IF NOT EXISTS friends(user_id INTEGER, friend_id INTEGER, PRIMARY KEY(user_id,friend_id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, from_id INTEGER, to_id INTEGER,
  body TEXT NOT NULL, read INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER, type TEXT, data TEXT,
  read INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS stories(id INTEGER PRIMARY KEY, user_id INTEGER, image_url TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS point_packages(id INTEGER PRIMARY KEY, price_cents INTEGER, currency TEXT DEFAULT 'USD',
  points INTEGER, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS gifts(id INTEGER PRIMARY KEY, name TEXT, image_url TEXT, price_points INTEGER, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS wallets(user_id INTEGER PRIMARY KEY REFERENCES users(id),
  points_balance INTEGER DEFAULT 0 CHECK(points_balance>=0),
  cash_balance_cents INTEGER DEFAULT 0 CHECK(cash_balance_cents>=0));
CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY, user_id INTEGER, kind TEXT, points INTEGER DEFAULT 0,
  cash_cents INTEGER DEFAULT 0, ref TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS gift_transactions(id INTEGER PRIMARY KEY, gift_id INTEGER, from_id INTEGER, to_id INTEGER,
  points INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS payment_transactions(id INTEGER PRIMARY KEY, user_id INTEGER, package_id INTEGER,
  amount_cents INTEGER, currency TEXT, points INTEGER, method TEXT, provider_ref TEXT UNIQUE,
  status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP, confirmed_at TEXT);
CREATE TABLE IF NOT EXISTS withdrawals(id INTEGER PRIMARY KEY, user_id INTEGER, amount_cents INTEGER, method TEXT,
  recipient TEXT, status TEXT DEFAULT 'pending', ref TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);

try { db.exec('ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0'); } catch {}
db.exec(`CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, reporter_id INTEGER, post_id INTEGER,
  reason TEXT, status TEXT DEFAULT 'open', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);

db.exec(`CREATE TABLE IF NOT EXISTS password_resets(user_id INTEGER PRIMARY KEY, code_hash TEXT, expires_at INTEGER, attempts INTEGER DEFAULT 0)`);

if (process.env.ADMIN_EMAIL) db.prepare("UPDATE users SET role='admin' WHERE email=?").run(process.env.ADMIN_EMAIL);

// بيانات أولية قابلة للتعديل من لوحة الإدارة
if (!db.prepare('SELECT 1 FROM point_packages').get()) {
  const p = db.prepare('INSERT INTO point_packages(price_cents,points) VALUES(?,?)');
  [[50,50],[100,100],[200,200],[500,500],[1000,1000]].forEach(r => p.run(...r));
  const g = db.prepare('INSERT INTO gifts(name,image_url,price_points) VALUES(?,?,?)');
  [['وردة','/gifts/rose.png',5],['قلب','/gifts/heart.png',10],['نجمة','/gifts/star.png',20],
   ['هدية','/gifts/gift.png',50],['هدية كبيرة','/gifts/big.png',100]].forEach(r => g.run(...r));
}

fs.mkdirSync('uploads', { recursive: true });
const app = express();
app.set('trust proxy', 1);
app.use('/uploads', express.static('uploads', { maxAge: '7d' }));
// ملفات الواجهة (كلها في نفس المجلد لتسهيل الرفع من الهاتف)
for (const f of ['index.html', 'manifest.json', 'icon-180.png', 'icon-512.png'])
  app.get(f === 'index.html' ? '/' : '/' + f, (_q, r) => r.sendFile(path.join(__dirname, f)));
app.use(express.json({ limit: '6mb', verify: (req, _res, buf) => { req.raw = buf; } }));

const wrap = fn => (req, res) => { try { fn(req, res); } catch (e) {
  res.status(e.status || 500).json({ error: e.status ? e.message : 'خطأ في الخادم' }); if (!e.status) console.error(e); } };
const fail = (status, message) => Object.assign(new Error(message), { status });
const notify = (userId, type, data) =>
  db.prepare('INSERT INTO notifications(user_id,type,data) VALUES(?,?,?)').run(userId, type, JSON.stringify(data));

const auth = (req, _res, next) => {
  let u;
  try { u = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET); }
  catch { return next(fail(401, 'يجب تسجيل الدخول')); }
  const row = db.prepare('SELECT banned FROM users WHERE id=?').get(u.id);
  if (!row) return next(fail(401, 'يجب تسجيل الدخول'));
  if (row.banned) return next(fail(403, 'الحساب موقوف'));
  req.user = u; next();
};
const admin = (req, _res, next) => {
  const u = db.prepare('SELECT role FROM users WHERE id=?').get(req.user.id);
  u && u.role === 'admin' ? next() : next(fail(403, 'غير مصرح'));
};
const token = id => jwt.sign({ id }, JWT_SECRET, { expiresIn: '30d' });

const hash = v => crypto.createHash('sha256').update(String(v)).digest('hex');
const hits = new Map(); // حد بسيط للمحاولات: 10 في الدقيقة لكل IP
const authLimit = (req, _res, next) => {
  const now = Date.now(), a = (hits.get(req.ip) || []).filter(t => now - t < 60000);
  a.push(now); hits.set(req.ip, a);
  a.length > 10 ? next(fail(429, 'محاولات كثيرة، حاول بعد قليل')) : next();
};

// ---------- الحسابات ----------
app.post('/auth/register', authLimit, wrap((req, res) => {
  const { email, phone, password, name } = req.body;
  if ((!email && !phone) || !password || password.length < 8) throw fail(400, 'بيانات غير صالحة');
  if (db.prepare('SELECT 1 FROM users WHERE email=? OR phone=?').get(email || null, phone || null))
    throw fail(409, 'الحساب موجود مسبقًا');
  const id = db.transaction(() => {
    const r = db.prepare('INSERT INTO users(email,phone,password_hash,name) VALUES(?,?,?,?)')
      .run(email || null, phone || null, bcrypt.hashSync(password, 12), name || '');
    db.prepare('INSERT INTO wallets(user_id) VALUES(?)').run(r.lastInsertRowid);
    return r.lastInsertRowid;
  })();
  res.json({ token: token(id) });
}));

app.post('/auth/login', authLimit, wrap((req, res) => {
  const { identifier, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email=? OR phone=?').get(identifier, identifier);
  if (!u || !bcrypt.compareSync(password || '', u.password_hash)) throw fail(401, 'بيانات الدخول غير صحيحة');
  if (u.banned) throw fail(403, 'الحساب موقوف');
  res.json({ token: token(u.id) });
}));
// تسجيل الخروج: يحذف التطبيق التوكن محليًا. التحقق بـ OTP واستعادة كلمة المرور تحتاجان مزود SMS/بريد (المرحلة التالية).

// ---------- رفع الصور (صور مضغوطة من التطبيق، حد 4MB) ----------
const EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };
app.post('/upload', auth, wrap((req, res) => {
  const { mime, data } = req.body;
  const ext = EXT[mime];
  if (!ext || typeof data !== 'string') throw fail(400, 'صيغة الصورة غير مدعومة');
  const buf = Buffer.from(data, 'base64');
  if (buf.length < 100 || buf.length > 4 * 1024 * 1024) throw fail(400, 'حجم الصورة غير صالح');
  const name = `${crypto.randomUUID()}.${ext}`;
  fs.writeFileSync(path.join('uploads', name), buf);
  res.json({ url: `/uploads/${name}` });
}));

// ---------- الملف الشخصي والبحث ----------
const pub = 'id,name,bio,avatar_url,cover_url';
app.get('/me', auth, wrap((req, res) => res.json(
  db.prepare(`SELECT ${pub},email,phone,role FROM users WHERE id=?`).get(req.user.id))));
app.patch('/me', auth, wrap((req, res) => {
  const { name, bio, avatar_url, cover_url } = req.body;
  db.prepare(`UPDATE users SET name=COALESCE(?,name),bio=COALESCE(?,bio),
    avatar_url=COALESCE(?,avatar_url),cover_url=COALESCE(?,cover_url) WHERE id=?`)
    .run(name ?? null, bio ?? null, avatar_url ?? null, cover_url ?? null, req.user.id);
  res.json({ ok: true });
}));
app.get('/users/search', auth, wrap((req, res) => res.json(
  db.prepare(`SELECT ${pub} FROM users WHERE name LIKE ? AND id!=? LIMIT 30`).all(`%${req.query.q || ''}%`, req.user.id))));
app.get('/users/:id', auth, wrap((req, res) => res.json({
  user: db.prepare(`SELECT ${pub} FROM users WHERE id=?`).get(req.params.id),
  posts: db.prepare('SELECT * FROM posts WHERE user_id=? ORDER BY id DESC').all(req.params.id),
  friends: db.prepare(`SELECT ${pub} FROM users WHERE id IN (SELECT friend_id FROM friends WHERE user_id=?)`).all(req.params.id) })));

// ---------- المنشورات (الوقت يُخزَّن UTC ويُعرض بتوقيت الجهاز في التطبيق) ----------
app.post('/posts', auth, wrap((req, res) => {
  const { body, image_url } = req.body;
  if (!body?.trim() && !image_url) throw fail(400, 'المنشور فارغ');
  const r = db.prepare('INSERT INTO posts(user_id,body,image_url) VALUES(?,?,?)').run(req.user.id, body || '', image_url || null);
  res.json(db.prepare('SELECT * FROM posts WHERE id=?').get(r.lastInsertRowid));
}));
app.get('/feed', auth, wrap((req, res) => res.json(db.prepare(`
  SELECT p.*, u.name, u.avatar_url,
   (SELECT COUNT(*) FROM likes WHERE post_id=p.id) likes,
   (SELECT COUNT(*) FROM comments WHERE post_id=p.id) comments
  FROM posts p JOIN users u ON u.id=p.user_id
  WHERE p.user_id=@me OR p.user_id IN (SELECT friend_id FROM friends WHERE user_id=@me)
  ORDER BY p.id DESC LIMIT 50`).all({ me: req.user.id }))));
app.patch('/posts/:id', auth, wrap((req, res) => {
  const r = db.prepare("UPDATE posts SET body=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?")
    .run(req.body.body, req.params.id, req.user.id);
  if (!r.changes) throw fail(404, 'غير موجود'); res.json({ ok: true });
}));
app.delete('/posts/:id', auth, wrap((req, res) => {
  db.prepare('DELETE FROM posts WHERE id=? AND user_id=?').run(req.params.id, req.user.id); res.json({ ok: true });
}));
app.post('/posts/:id/like', auth, wrap((req, res) => {
  const r = db.prepare('INSERT OR IGNORE INTO likes VALUES(?,?)').run(req.params.id, req.user.id);
  const p = db.prepare('SELECT user_id FROM posts WHERE id=?').get(req.params.id);
  if (r.changes && p && p.user_id !== req.user.id) notify(p.user_id, 'like', { by: req.user.id, post: +req.params.id });
  res.json({ ok: true });
}));
app.post('/posts/:id/comments', auth, wrap((req, res) => {
  if (!req.body.body?.trim()) throw fail(400, 'تعليق فارغ');
  db.prepare('INSERT INTO comments(post_id,user_id,body) VALUES(?,?,?)').run(req.params.id, req.user.id, req.body.body);
  const p = db.prepare('SELECT user_id FROM posts WHERE id=?').get(req.params.id);
  if (p && p.user_id !== req.user.id) notify(p.user_id, 'comment', { by: req.user.id, post: +req.params.id });
  res.json({ ok: true });
}));

app.get('/posts/:id/comments', auth, wrap((req, res) => res.json(db.prepare(
  `SELECT c.id, c.body, c.created_at, u.id user_id, u.name, u.avatar_url FROM comments c
   JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id ASC LIMIT 200`).all(req.params.id))));
app.delete('/comments/:id', auth, wrap((req, res) => {
  db.prepare('DELETE FROM comments WHERE id=? AND user_id=?').run(req.params.id, req.user.id); res.json({ ok: true });
}));

// ---------- الأصدقاء ----------
app.post('/friends/request/:id', auth, wrap((req, res) => {
  if (+req.params.id === req.user.id) throw fail(400, 'غير ممكن');
  db.prepare('INSERT OR IGNORE INTO friend_requests(from_id,to_id) VALUES(?,?)').run(req.user.id, req.params.id);
  notify(+req.params.id, 'friend_request', { by: req.user.id }); res.json({ ok: true });
}));
app.get('/friends/requests', auth, wrap((req, res) => res.json(db.prepare(
  `SELECT r.id, u.id user_id, u.name, u.avatar_url FROM friend_requests r JOIN users u ON u.id=r.from_id
   WHERE r.to_id=? AND r.status='pending'`).all(req.user.id))));
app.post('/friends/requests/:id/:action', auth, wrap((req, res) => {
  const r = db.prepare("SELECT * FROM friend_requests WHERE id=? AND to_id=? AND status='pending'").get(req.params.id, req.user.id);
  if (!r) throw fail(404, 'غير موجود');
  const accept = req.params.action === 'accept';
  db.transaction(() => {
    db.prepare('UPDATE friend_requests SET status=? WHERE id=?').run(accept ? 'accepted' : 'rejected', r.id);
    if (accept) { const i = db.prepare('INSERT OR IGNORE INTO friends VALUES(?,?)'); i.run(r.from_id, r.to_id); i.run(r.to_id, r.from_id);
      notify(r.from_id, 'friend_accepted', { by: req.user.id }); }
  })();
  res.json({ ok: true });
}));
app.get('/friends', auth, wrap((req, res) => res.json(db.prepare(
  `SELECT ${pub} FROM users WHERE id IN (SELECT friend_id FROM friends WHERE user_id=?)`).all(req.user.id))));
app.delete('/friends/:id', auth, wrap((req, res) => {
  db.prepare('DELETE FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)')
    .run(req.user.id, req.params.id, req.params.id, req.user.id); res.json({ ok: true });
}));

// ---------- الرسائل والإشعارات ----------
app.post('/messages/:to', auth, wrap((req, res) => {
  if (!req.body.body?.trim()) throw fail(400, 'رسالة فارغة');
  db.prepare('INSERT INTO messages(from_id,to_id,body) VALUES(?,?,?)').run(req.user.id, req.params.to, req.body.body);
  notify(+req.params.to, 'message', { by: req.user.id }); res.json({ ok: true });
}));
app.get('/messages/unread', auth, wrap((req, res) => res.json(
  db.prepare('SELECT from_id, COUNT(*) n FROM messages WHERE to_id=? AND read=0 GROUP BY from_id').all(req.user.id))));
app.get('/messages/:with', auth, wrap((req, res) => {
  db.prepare('UPDATE messages SET read=1 WHERE to_id=? AND from_id=?').run(req.user.id, req.params.with);
  res.json(db.prepare(`SELECT * FROM messages WHERE (from_id=@a AND to_id=@b) OR (from_id=@b AND to_id=@a)
    ORDER BY id ASC LIMIT 200`).all({ a: req.user.id, b: req.params.with }));
}));
app.get('/notifications', auth, wrap((req, res) => res.json(
  db.prepare('SELECT n.*, u.name by_name FROM notifications n LEFT JOIN users u ON u.id=json_extract(n.data,\'$.by\') WHERE n.user_id=? ORDER BY n.id DESC LIMIT 100').all(req.user.id))));

// ---------- المحفظة والنقاط ----------
const count1 = (q, id) => db.prepare(q).get(id).n;
app.get('/wallet', auth, wrap((req, res) => res.json({
  wallet: db.prepare('SELECT * FROM wallets WHERE user_id=?').get(req.user.id),
  transactions: db.prepare('SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 100').all(req.user.id),
  totals: {
    purchased: count1("SELECT COALESCE(SUM(points),0) n FROM transactions WHERE user_id=? AND kind='purchase_points'", req.user.id),
    spent: count1('SELECT COALESCE(-SUM(points),0) n FROM transactions WHERE user_id=? AND points<0', req.user.id),
    gifts_sent: count1('SELECT COUNT(*) n FROM gift_transactions WHERE from_id=?', req.user.id),
    gifts_received: count1('SELECT COUNT(*) n FROM gift_transactions WHERE to_id=?', req.user.id) } })));
app.get('/packages', wrap((_req, res) => res.json(db.prepare('SELECT * FROM point_packages WHERE active=1').all())));

// بدء الدفع: يُنشئ سجلًا pending فقط. لا نقاط هنا.
// اربط createCheckout بالمزود الرسمي (بطاقات/Qi/ZainCash) واحفظ مفاتيحه في متغيرات البيئة.
app.post('/payments/checkout', auth, wrap((req, res) => {
  const { package_id, method } = req.body;
  if (!['card', 'qi', 'zaincash'].includes(method)) throw fail(400, 'وسيلة دفع غير مدعومة');
  const pkg = db.prepare('SELECT * FROM point_packages WHERE id=? AND active=1').get(package_id);
  if (!pkg) throw fail(404, 'الباقة غير موجودة');
  const ref = crypto.randomUUID(); // استبدله برقم عملية المزود عند الربط
  db.prepare(`INSERT INTO payment_transactions(user_id,package_id,amount_cents,currency,points,method,provider_ref)
    VALUES(?,?,?,?,?,?,?)`).run(req.user.id, pkg.id, pkg.price_cents, pkg.currency, pkg.points, method, ref);
  res.json({ provider_ref: ref /*, checkout_url: await createCheckout(...) */ });
}));

// تأكيد الدفع: مرة واحدة فقط، داخل Transaction. تستدعيه الـ Webhook فقط.
function settle(provider_ref, status) {
  db.transaction(() => {
    const t = db.prepare('SELECT * FROM payment_transactions WHERE provider_ref=?').get(provider_ref);
    if (!t || t.status !== 'pending') return; // مكرر أو مجهول
    if (status !== 'paid') { db.prepare("UPDATE payment_transactions SET status='failed' WHERE id=?").run(t.id); return; }
    db.prepare("UPDATE payment_transactions SET status='paid',confirmed_at=CURRENT_TIMESTAMP WHERE id=?").run(t.id);
    db.prepare('UPDATE wallets SET points_balance=points_balance+? WHERE user_id=?').run(t.points, t.user_id);
    db.prepare("INSERT INTO transactions(user_id,kind,points,ref) VALUES(?,'purchase_points',?,?)").run(t.user_id, t.points, provider_ref);
  })();
}

app.get('/payments/:ref', auth, wrap((req, res) => {
  const t = db.prepare('SELECT status, points FROM payment_transactions WHERE provider_ref=? AND user_id=?').get(req.params.ref, req.user.id);
  if (!t) throw fail(404, 'غير موجود');
  res.json(t);
}));

// Webhook: النقاط تُضاف هنا فقط بعد التحقق من التوقيع، ومرة واحدة (idempotent).
// عدّل طريقة التحقق حسب توثيق كل مزود.
app.post('/webhooks/payment', wrap((req, res) => {
  const sig = Buffer.from(req.headers['x-signature'] || '', 'hex');
  const mac = crypto.createHmac('sha256', WEBHOOK_SECRET).update(req.raw).digest();
  if (sig.length !== mac.length || !crypto.timingSafeEqual(sig, mac)) throw fail(401, 'توقيع غير صالح');
  settle(req.body.provider_ref, req.body.status);
  res.json({ ok: true });
}));

// للتجربة فقط: يعمل إذا ضبطت ALLOW_TEST_PAYMENTS=1. اتركه معطلًا في الإنتاج.
if (process.env.ALLOW_TEST_PAYMENTS === '1') {
  app.post('/dev/confirm/:ref', auth, wrap((req, res) => {
    const t = db.prepare('SELECT user_id FROM payment_transactions WHERE provider_ref=?').get(req.params.ref);
    if (!t || t.user_id !== req.user.id) throw fail(404, 'غير موجود');
    settle(req.params.ref, 'paid');
    res.json({ ok: true });
  }));
}

// ---------- الهدايا ----------
app.get('/gifts', auth, wrap((_req, res) => res.json(db.prepare('SELECT * FROM gifts WHERE active=1').all())));
app.post('/gifts/:id/send', auth, wrap((req, res) => {
  const to = +req.body.to_id;
  if (!to || to === req.user.id || !db.prepare('SELECT 1 FROM users WHERE id=?').get(to)) throw fail(400, 'مستلم غير صالح');
  db.transaction(() => {
    const g = db.prepare('SELECT * FROM gifts WHERE id=? AND active=1').get(req.params.id);
    if (!g) throw fail(404, 'الهدية غير متاحة');
    // الخصم الذري: لا ينجح إلا إذا كان الرصيد كافيًا
    const r = db.prepare('UPDATE wallets SET points_balance=points_balance-? WHERE user_id=? AND points_balance>=?')
      .run(g.price_points, req.user.id, g.price_points);
    if (!r.changes) throw fail(402, 'رصيد النقاط غير كافٍ');
    db.prepare('INSERT INTO gift_transactions(gift_id,from_id,to_id,points) VALUES(?,?,?,?)').run(g.id, req.user.id, to, g.price_points);
    db.prepare("INSERT INTO transactions(user_id,kind,points,ref) VALUES(?,'send_gift',?,?)").run(req.user.id, -g.price_points, `to:${to}`);
    db.prepare("INSERT INTO transactions(user_id,kind,points,ref) VALUES(?,'receive_gift',0,?)").run(to, `from:${req.user.id}:${g.name}`);
    notify(to, 'gift', { by: req.user.id, gift: g.name });
  })();
  res.json({ ok: true });
}));
app.get('/gifts/received', auth, wrap((req, res) => res.json(db.prepare(
  `SELECT t.*, g.name, g.image_url, (SELECT name FROM users WHERE id=t.from_id) from_name FROM gift_transactions t JOIN gifts g ON g.id=t.gift_id
   WHERE t.to_id=? ORDER BY t.id DESC`).all(req.user.id))));

// ---------- لوحة الإدارة ----------
const adm = [auth, admin];
const count = q => db.prepare(q).get().n;
app.get('/admin/stats', adm, wrap((_req, res) => res.json({
  users: count('SELECT COUNT(*) n FROM users'),
  posts: count('SELECT COUNT(*) n FROM posts'),
  points_sold: count("SELECT COALESCE(SUM(points),0) n FROM payment_transactions WHERE status='paid'"),
  revenue_cents: count("SELECT COALESCE(SUM(amount_cents),0) n FROM payment_transactions WHERE status='paid'"),
  gifts_sent: count('SELECT COUNT(*) n FROM gift_transactions'),
  pending_withdrawals: count("SELECT COUNT(*) n FROM withdrawals WHERE status='pending'") })));
app.get('/admin/payments', adm, wrap((_req, res) => res.json(db.prepare('SELECT * FROM payment_transactions ORDER BY id DESC LIMIT 200').all())));
app.put('/admin/packages/:id', adm, wrap((req, res) => {
  db.prepare('UPDATE point_packages SET price_cents=?,points=?,active=? WHERE id=?')
    .run(req.body.price_cents, req.body.points, req.body.active ?? 1, req.params.id); res.json({ ok: true });
}));
app.post('/admin/gifts', adm, wrap((req, res) => {
  const r = db.prepare('INSERT INTO gifts(name,image_url,price_points) VALUES(?,?,?)').run(req.body.name, req.body.image_url, req.body.price_points);
  res.json({ id: r.lastInsertRowid });
}));
app.put('/admin/gifts/:id', adm, wrap((req, res) => {
  db.prepare('UPDATE gifts SET name=?,image_url=?,price_points=?,active=? WHERE id=?')
    .run(req.body.name, req.body.image_url, req.body.price_points, req.body.active ?? 1, req.params.id); res.json({ ok: true });
}));
app.delete('/admin/gifts/:id', adm, wrap((req, res) => {
  db.prepare('UPDATE gifts SET active=0 WHERE id=?').run(req.params.id); res.json({ ok: true });
}));
app.get('/admin/withdrawals', adm, wrap((_req, res) => res.json(db.prepare('SELECT * FROM withdrawals ORDER BY id DESC').all())));

// ---------- بلاغات المستخدمين ----------
app.post('/posts/:id/report', auth, wrap((req, res) => {
  db.prepare('INSERT INTO reports(reporter_id,post_id,reason) VALUES(?,?,?)').run(req.user.id, req.params.id, String(req.body.reason || '').slice(0, 300));
  res.json({ ok: true });
}));

// ---------- إدارة إضافية ----------
app.get('/admin-panel', (_req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/admin/packages', adm, wrap((_req, res) => res.json(db.prepare('SELECT * FROM point_packages ORDER BY price_cents').all())));
app.post('/admin/packages', adm, wrap((req, res) => {
  const { price_cents, points } = req.body;
  if (!(price_cents > 0) || !(points > 0)) throw fail(400, 'قيم غير صالحة');
  db.prepare('INSERT INTO point_packages(price_cents,points) VALUES(?,?)').run(price_cents, points); res.json({ ok: true });
}));
app.get('/admin/gifts', adm, wrap((_req, res) => res.json(db.prepare('SELECT * FROM gifts ORDER BY price_points').all())));
app.get('/admin/posts', adm, wrap((_req, res) => res.json(db.prepare(
  'SELECT p.id, p.body, p.created_at, u.name FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 200').all())));
app.delete('/admin/posts/:id', adm, wrap((req, res) => { db.prepare('DELETE FROM posts WHERE id=?').run(req.params.id); res.json({ ok: true }); }));
app.get('/admin/reports', adm, wrap((_req, res) => res.json(db.prepare(
  'SELECT r.*, p.body post_body FROM reports r LEFT JOIN posts p ON p.id=r.post_id ORDER BY r.id DESC LIMIT 200').all())));
app.put('/admin/reports/:id', adm, wrap((req, res) => { db.prepare("UPDATE reports SET status='resolved' WHERE id=?").run(req.params.id); res.json({ ok: true }); }));
app.put('/admin/users/:id/ban', adm, wrap((req, res) => {
  if (+req.params.id === req.user.id) throw fail(400, 'لا يمكنك حظر نفسك');
  db.prepare('UPDATE users SET banned=? WHERE id=?').run(req.body.banned ? 1 : 0, req.params.id); res.json({ ok: true });
}));
app.get('/admin/users', adm, wrap((_req, res) => res.json(db.prepare('SELECT id,name,email,phone,role,banned,created_at FROM users ORDER BY id DESC LIMIT 200').all())));

// ---------- استعادة كلمة المرور ----------
// اربط مزود SMS/بريد هنا (Twilio, SendGrid, ...). في التطوير يُطبع الكود في سجل الخادم فقط.
async function sendCode(identifier, code) {
  if (process.env.NODE_ENV !== 'production') console.log(`[كود] ${identifier}: ${code}`);
  else console.warn('لم يُربط مزود رسائل: لم يُرسل الكود');
}
app.post('/auth/forgot', authLimit, wrap((req, res) => {
  const id = String(req.body.identifier || '').trim();
  const u = db.prepare('SELECT id FROM users WHERE email=? OR phone=?').get(id, id);
  if (u) {
    const code = String(crypto.randomInt(100000, 1000000));
    db.prepare('INSERT OR REPLACE INTO password_resets(user_id,code_hash,expires_at,attempts) VALUES(?,?,?,0)').run(u.id, hash(code), Date.now() + 15 * 60000);
    sendCode(id, code).catch(console.error);
  }
  res.json({ ok: true }); // نفس الرد دائمًا حتى لا نكشف وجود الحساب
}));
app.post('/auth/reset', authLimit, wrap((req, res) => {
  const { identifier, code, password } = req.body;
  if (!password || password.length < 8) throw fail(400, 'كلمة المرور قصيرة');
  const u = db.prepare('SELECT id FROM users WHERE email=? OR phone=?').get(identifier, identifier);
  const r = u && db.prepare('SELECT * FROM password_resets WHERE user_id=?').get(u.id);
  if (!r || r.expires_at < Date.now() || r.attempts >= 5) throw fail(400, 'الكود غير صالح أو منتهي');
  if (hash(code) !== r.code_hash) {
    db.prepare('UPDATE password_resets SET attempts=attempts+1 WHERE user_id=?').run(u.id);
    throw fail(400, 'الكود غير صحيح');
  }
  db.transaction(() => {
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(password, 12), u.id);
    db.prepare('DELETE FROM password_resets WHERE user_id=?').run(u.id);
  })();
  res.json({ ok: true });
}));

// ---------- القصص (تظهر 24 ساعة) ----------
app.post('/stories', auth, wrap((req, res) => {
  if (!req.body.image_url) throw fail(400, 'الصورة مطلوبة');
  db.prepare('INSERT INTO stories(user_id,image_url) VALUES(?,?)').run(req.user.id, req.body.image_url); res.json({ ok: true });
}));
app.get('/stories', auth, wrap((req, res) => res.json(db.prepare(
  `SELECT s.id, s.image_url, s.created_at, u.id user_id, u.name, u.avatar_url FROM stories s JOIN users u ON u.id=s.user_id
   WHERE s.created_at > datetime('now','-1 day')
   AND (s.user_id=@me OR s.user_id IN (SELECT friend_id FROM friends WHERE user_id=@me)) ORDER BY s.id ASC`).all({ me: req.user.id }))));

// ---------- السحب ----------
const MIN_WITHDRAW = +process.env.MIN_WITHDRAW_CENTS || 1000;
app.post('/withdrawals', auth, wrap((req, res) => {
  if (process.env.WITHDRAWALS_ENABLED !== '1') throw fail(403, 'السحب غير مفعّل حاليًا');
  const { amount_cents, method, recipient } = req.body;
  if (!Number.isInteger(amount_cents) || amount_cents < MIN_WITHDRAW) throw fail(400, `الحد الأدنى للسحب $${(MIN_WITHDRAW / 100).toFixed(2)}`);
  if (!['zaincash', 'qi', 'bank'].includes(method) || !String(recipient || '').trim()) throw fail(400, 'بيانات المستلم مطلوبة');
  const ref = crypto.randomUUID();
  db.transaction(() => { // يُحجز المبلغ فورًا لمنع السحب المزدوج
    const r = db.prepare('UPDATE wallets SET cash_balance_cents=cash_balance_cents-? WHERE user_id=? AND cash_balance_cents>=?')
      .run(amount_cents, req.user.id, amount_cents);
    if (!r.changes) throw fail(402, 'الرصيد القابل للسحب غير كافٍ');
    db.prepare('INSERT INTO withdrawals(user_id,amount_cents,method,recipient,ref) VALUES(?,?,?,?,?)').run(req.user.id, amount_cents, method, String(recipient).slice(0, 200), ref);
    db.prepare("INSERT INTO transactions(user_id,kind,cash_cents,ref) VALUES(?,'withdrawal',?,?)").run(req.user.id, -amount_cents, ref);
  })();
  res.json({ ok: true, ref });
}));
app.get('/withdrawals', auth, wrap((req, res) => res.json(db.prepare('SELECT id,amount_cents,method,status,created_at FROM withdrawals WHERE user_id=? ORDER BY id DESC').all(req.user.id))));
app.put('/admin/withdrawals/:id', adm, wrap((req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected', 'paid'].includes(status)) throw fail(400, 'حالة غير صالحة');
  db.transaction(() => {
    const w = db.prepare('SELECT * FROM withdrawals WHERE id=?').get(req.params.id);
    if (!w) throw fail(404, 'غير موجود');
    if (['paid', 'rejected'].includes(w.status)) throw fail(409, 'الطلب منتهٍ ولا يمكن تغييره');
    if (status === 'paid' && w.status !== 'approved') throw fail(409, 'يجب قبول الطلب أولًا');
    if (status === 'rejected') { // استرداد المبلغ للمستخدم
      db.prepare('UPDATE wallets SET cash_balance_cents=cash_balance_cents+? WHERE user_id=?').run(w.amount_cents, w.user_id);
      db.prepare("INSERT INTO transactions(user_id,kind,cash_cents,ref) VALUES(?,'refund',?,?)").run(w.user_id, w.amount_cents, w.ref);
    }
    db.prepare('UPDATE withdrawals SET status=? WHERE id=?').run(status, w.id);
  })();
  res.json({ ok: true });
}));
// إضافة رصيد نقدي مستحق (أرباح) من الإدارة
app.post('/admin/users/:id/credit', adm, wrap((req, res) => {
  const c = req.body.amount_cents;
  if (!Number.isInteger(c) || c <= 0) throw fail(400, 'مبلغ غير صالح');
  db.transaction(() => {
    db.prepare('UPDATE wallets SET cash_balance_cents=cash_balance_cents+? WHERE user_id=?').run(c, req.params.id);
    db.prepare("INSERT INTO transactions(user_id,kind,cash_cents,ref) VALUES(?,'earnings',?,?)").run(req.params.id, c, `admin:${req.user.id}`);
  })();
  res.json({ ok: true });
}));

// ---------- حذف الحساب (مطلوب من المتاجر). تبقى السجلات المالية للمحاسبة ----------
app.delete('/me', auth, wrap((req, res) => {
  const u = db.prepare('SELECT password_hash FROM users WHERE id=?').get(req.user.id);
  if (!bcrypt.compareSync(req.body?.password || '', u.password_hash)) throw fail(403, 'كلمة المرور غير صحيحة');
  db.transaction(() => {
    for (const q of ['DELETE FROM likes WHERE user_id=@id', 'DELETE FROM comments WHERE user_id=@id', 'DELETE FROM posts WHERE user_id=@id',
      'DELETE FROM friends WHERE user_id=@id OR friend_id=@id', 'DELETE FROM friend_requests WHERE from_id=@id OR to_id=@id',
      'DELETE FROM messages WHERE from_id=@id OR to_id=@id', 'DELETE FROM notifications WHERE user_id=@id',
      'DELETE FROM stories WHERE user_id=@id', 'DELETE FROM reports WHERE reporter_id=@id',
      'DELETE FROM password_resets WHERE user_id=@id', 'DELETE FROM wallets WHERE user_id=@id', 'DELETE FROM users WHERE id=@id'])
      db.prepare(q).run({ id: req.user.id });
  })();
  res.json({ ok: true });
}));

// ---------- صفحات قانونية (نصوص مبدئية تحتاج مراجعة قانونية قبل الإطلاق) ----------
const legal = (t, b) => `<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${t}</title><body style="font-family:system-ui;max-width:720px;margin:auto;padding:16px;line-height:1.8"><h1>${t}</h1>${b}`;
app.get('/privacy', (_req, res) => res.send(legal('سياسة الخصوصية', '<p>نص مبدئي: نجمع البريد أو الهاتف والاسم والمحتوى الذي تنشره لتشغيل Family. لا نبيع بياناتك. يمكنك حذف حسابك من صفحتك الشخصية. تُحفظ سجلات المدفوعات للمحاسبة. استبدل هذا النص بسياسة معتمدة قانونيًا.</p>')));
app.get('/terms', (_req, res) => res.send(legal('شروط الاستخدام', '<p>نص مبدئي: النقاط ليست أموالًا وغير قابلة للاسترداد إلا وفق السياسة. يُمنع المحتوى المسيء وللإدارة حذفه وحظر المخالفين. استبدل هذا النص بشروط معتمدة قانونيًا.</p>')));

app.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message }));
app.listen(process.env.PORT || 3000, () => console.log('API running'));
