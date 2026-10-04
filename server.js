const express = require("express"), { Pool, types } = require("pg"), bcrypt = require("bcryptjs"), jwt = require("jsonwebtoken"), crypto = require("crypto"), path = require("path");

// ---------- الإعدادات ----------
const PROD = process.env.NODE_ENV === "production";
const TZ = process.env.APP_TZ || "Asia/Baghdad";
const SECRET = process.env.JWT_SECRET || (PROD ? null : "dev-only-secret");
if (!SECRET) { console.error("JWT_SECRET is required in production"); process.exit(1); }
if (!process.env.DATABASE_URL) { console.error("DATABASE_URL is required"); process.exit(1); }

// إرجاع التواريخ كنص YYYY-MM-DD والأرقام الكبيرة كأرقام عادية
types.setTypeParser(1082, v => v);            // date
types.setTypeParser(20, v => parseInt(v, 10)); // bigint
types.setTypeParser(1700, v => parseFloat(v)); // numeric

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5, idleTimeoutMillis: 30000 });
const q = (sql, params) => pool.query(sql, params);
const one = async (sql, params) => (await q(sql, params)).rows[0];
const all = async (sql, params) => (await q(sql, params)).rows;

const today = () => new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const intOrNull = v => (v === "" || v == null || isNaN(Number(v)) ? null : Math.trunc(Number(v)));

// ---------- قاعدة البيانات ----------
async function init() {
  await q(`
CREATE TABLE IF NOT EXISTS employees(id SERIAL PRIMARY KEY,name TEXT UNIQUE NOT NULL,active BOOLEAN NOT NULL DEFAULT TRUE);
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'worker',active BOOLEAN NOT NULL DEFAULT TRUE,employee_id INTEGER REFERENCES employees(id));
CREATE TABLE IF NOT EXISTS orders(id SERIAL PRIMARY KEY,customer_name TEXT,phone TEXT,area TEXT,car_type TEXT,service TEXT,employee_id INTEGER REFERENCES employees(id),appointment TEXT,price BIGINT NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'جديد',notes TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),created_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS subscriptions(id SERIAL PRIMARY KEY,customer_name TEXT,phone TEXT,plan TEXT,price BIGINT NOT NULL DEFAULT 0,washes_total INTEGER NOT NULL DEFAULT 5,washes_used INTEGER NOT NULL DEFAULT 0,start_date DATE,end_date DATE,day TEXT,time TEXT,notes TEXT);
CREATE TABLE IF NOT EXISTS expenses(id SERIAL PRIMARY KEY,title TEXT,category TEXT,amount BIGINT NOT NULL DEFAULT 0,date DATE NOT NULL DEFAULT CURRENT_DATE,notes TEXT,created_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS audit(id SERIAL PRIMARY KEY,user_id INTEGER,action TEXT,entity TEXT,entity_id INTEGER,details TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);
CREATE INDEX IF NOT EXISTS orders_created_at_idx ON orders(created_at);
CREATE INDEX IF NOT EXISTS orders_phone_idx ON orders(phone);
CREATE INDEX IF NOT EXISTS expenses_date_idx ON expenses(date);
`);
  for (const n of ["عباس", "أيمن", "فهد", "سيف"]) await q("INSERT INTO employees(name) VALUES($1) ON CONFLICT DO NOTHING", [n]);
  const defaults = { "عادي-ناصية": 15000, "عادي-عالية": 18000, "VIP-ناصية": 20000, "VIP-عالية": 20000, "اشتراك-ناصية": 58000, "اشتراك-عالية": 69000, "اشتراك-VIP": 78000 };
  for (const [k, v] of Object.entries(defaults)) await q("INSERT INTO settings(k,v) VALUES($1,$2) ON CONFLICT DO NOTHING", [k, String(v)]);

  // الحسابات الإدارية الأولى تُنشأ مرة واحدة فقط عندما يكون جدول المستخدمين فارغاً
  const { c } = await one("SELECT COUNT(*)::int c FROM users");
  if (c === 0) {
    let pw = process.env.INITIAL_ADMIN_PASSWORD;
    if (!pw) { pw = crypto.randomBytes(9).toString("base64url"); console.log(`[seed] INITIAL_ADMIN_PASSWORD not set — generated password: ${pw}`); }
    for (const u of ["hassan", "haider"]) await q("INSERT INTO users(username,password_hash,role) VALUES($1,$2,'admin')", [u, bcrypt.hashSync(pw, 10)]);
    console.log("[seed] created admin users: hassan, haider — change their passwords after first login");
  }
}

// ---------- الحماية ----------
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use((req, res, next) => { res.set({ "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin" }); next(); });
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const auth = wrap(async (req, res, next) => {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "غير مسجل الدخول" });
  let p; try { p = jwt.verify(h.slice(7), SECRET); } catch (e) { return res.status(401).json({ error: "جلسة منتهية" }); }
  // نقرأ المستخدم من القاعدة في كل طلب حتى يسري إيقاف الحساب أو تغيير الصلاحية فوراً
  const u = await one("SELECT id,username,role,employee_id FROM users WHERE id=$1 AND active", [p.id]);
  if (!u) return res.status(401).json({ error: "الحساب غير فعال" });
  req.user = u; next();
});
function admin(req, res, next) { if (req.user.role !== "admin") return res.status(403).json({ error: "صلاحية غير كافية" }); next(); }
const audit = (u, a, e, id, d = "") => q("INSERT INTO audit(user_id,action,entity,entity_id,details) VALUES($1,$2,$3,$4,$5)", [u, a, e, id, d]);

// تحديد محاولات الدخول: 10 محاولات فاشلة لكل عنوان خلال 15 دقيقة
const attempts = new Map();
function loginLimiter(req, res, next) {
  const now = Date.now(), k = req.ip, a = attempts.get(k);
  if (a && now - a.t < 15 * 60e3 && a.n >= 10) return res.status(429).json({ error: "محاولات كثيرة، حاول بعد 15 دقيقة" });
  if (a && now - a.t >= 15 * 60e3) attempts.delete(k);
  next();
}
const failLogin = ip => { const a = attempts.get(ip) || { n: 0, t: Date.now() }; a.n++; attempts.set(ip, a); };

// ---------- الواجهات ----------
app.get("/healthz", wrap(async (req, res) => { await q("SELECT 1"); res.json({ ok: true }); }));

app.post("/api/login", loginLimiter, wrap(async (req, res) => {
  const { username, password } = req.body || {};
  const u = username && await one("SELECT * FROM users WHERE username=$1 AND active", [String(username).trim().toLowerCase()]);
  if (!u || !password || !bcrypt.compareSync(String(password), u.password_hash)) { failLogin(req.ip); return res.status(401).json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة" }); }
  attempts.delete(req.ip);
  const token = jwt.sign({ id: u.id }, SECRET, { expiresIn: "12h" });
  res.json({ token, user: { username: u.username, role: u.role } });
}));
app.get("/api/me", auth, (req, res) => res.json(req.user));
app.post("/api/me/password", auth, wrap(async (req, res) => {
  const { current, next: np } = req.body || {};
  if (!np || String(np).length < 8) return res.status(400).json({ error: "كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف" });
  const u = await one("SELECT password_hash FROM users WHERE id=$1", [req.user.id]);
  if (!bcrypt.compareSync(String(current || ""), u.password_hash)) return res.status(400).json({ error: "كلمة المرور الحالية غير صحيحة" });
  await q("UPDATE users SET password_hash=$1 WHERE id=$2", [bcrypt.hashSync(String(np), 10), req.user.id]);
  await audit(req.user.id, "تغيير كلمة المرور", "user", req.user.id);
  res.json({ ok: true });
}));

app.get("/api/dashboard", auth, wrap(async (req, res) => {
  const d = today(), worker = req.user.role === "worker";
  const o = await one(`SELECT COUNT(*)::int c,COALESCE(SUM(price),0) r FROM orders WHERE (created_at AT TIME ZONE $1)::date=$2::date AND status<>'ملغي' ${worker ? "AND employee_id=$3" : ""}`, worker ? [TZ, d, req.user.employee_id] : [TZ, d]);
  if (worker) return res.json({ orders: o.c });
  const e = await one("SELECT COALESCE(SUM(amount),0) x FROM expenses WHERE date=$1", [d]);
  const s = await one("SELECT COUNT(*)::int c FROM subscriptions WHERE end_date>=$1", [d]);
  const w = await one("SELECT COUNT(*)::int c FROM employees WHERE active");
  res.json({ orders: o.c, revenue: o.r, expenses: e.x, net: o.r - e.x, subscriptions: s.c, workers: w.c });
}));
app.get("/api/employees", auth, wrap(async (req, res) => res.json(await all("SELECT * FROM employees WHERE active ORDER BY id"))));

app.get("/api/orders", auth, wrap(async (req, res) => {
  const worker = req.user.role === "worker";
  res.json(await all(`SELECT o.*,e.name employee FROM orders o LEFT JOIN employees e ON e.id=o.employee_id ${worker ? "WHERE o.employee_id=$1" : ""} ORDER BY o.id DESC LIMIT 1000`, worker ? [req.user.employee_id] : []));
}));
app.post("/api/orders", auth, wrap(async (req, res) => {
  const b = req.body || {};
  if (!b.customer_name && !b.phone) return res.status(400).json({ error: "أدخل اسم العميل أو رقم الهاتف" });
  const empId = req.user.role === "worker" ? req.user.employee_id : intOrNull(b.employee_id);
  const r = await one(`INSERT INTO orders(customer_name,phone,area,car_type,service,employee_id,appointment,price,status,notes,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
    [b.customer_name || "", (b.phone || "").trim(), b.area || "", b.car_type, b.service, empId, b.appointment, intOrNull(b.price) || 0, b.status || "جديد", b.notes || "", req.user.id]);
  await audit(req.user.id, "إضافة", "order", r.id, JSON.stringify(b));
  res.json({ id: r.id });
}));
app.patch("/api/orders/:id", auth, wrap(async (req, res) => {
  const old = await one("SELECT * FROM orders WHERE id=$1", [intOrNull(req.params.id)]);
  if (!old) return res.status(404).json({ error: "الطلب غير موجود" });
  if (req.user.role === "worker" && old.employee_id !== req.user.employee_id) return res.status(403).json({ error: "لا يمكنك تعديل طلب غير تابع لك" });
  const b = req.body || {};
  // الكابتن يغيّر الحالة فقط، والسعر والملاحظات للإدارة
  const price = req.user.role === "admin" ? intOrNull(b.price) : null, notes = req.user.role === "admin" ? (b.notes ?? null) : null;
  await q("UPDATE orders SET status=COALESCE($1,status),price=COALESCE($2,price),notes=COALESCE($3,notes) WHERE id=$4", [b.status ?? null, price, notes, old.id]);
  await audit(req.user.id, "تعديل", "order", old.id, JSON.stringify({ before: old, after: b }));
  res.json({ ok: true });
}));

app.get("/api/customers", auth, admin, wrap(async (req, res) => res.json(await all(`SELECT phone,MAX(customer_name) customer_name,MAX(area) area,COUNT(*)::int washes,COALESCE(SUM(price) FILTER (WHERE status<>'ملغي'),0) total_paid,MAX(created_at) last_wash FROM orders WHERE phone<>'' GROUP BY phone ORDER BY last_wash DESC`))));

app.get("/api/subscriptions", auth, admin, wrap(async (req, res) => res.json(await all("SELECT * FROM subscriptions ORDER BY id DESC"))));
app.post("/api/subscriptions", auth, admin, wrap(async (req, res) => {
  const b = req.body || {};
  const r = await one(`INSERT INTO subscriptions(customer_name,phone,plan,price,washes_total,washes_used,start_date,end_date,day,time,notes) VALUES($1,$2,$3,$4,$5,0,$6,$7,$8,$9,$10) RETURNING id`,
    [b.customer_name || "", b.phone || "", b.plan, intOrNull(b.price) || 0, intOrNull(b.washes_total) || 5, b.start_date || null, b.end_date || null, b.day || "", b.time || "", b.notes || ""]);
  await audit(req.user.id, "إضافة", "subscription", r.id, JSON.stringify(b));
  res.json({ id: r.id });
}));
app.patch("/api/subscriptions/:id/use", auth, admin, wrap(async (req, res) => {
  const id = intOrNull(req.params.id);
  await q("UPDATE subscriptions SET washes_used=LEAST(washes_total,washes_used+1) WHERE id=$1", [id]);
  await audit(req.user.id, "استخدام غسلة", "subscription", id);
  res.json({ ok: true });
}));

app.get("/api/expenses", auth, admin, wrap(async (req, res) => res.json(await all("SELECT * FROM expenses ORDER BY date DESC,id DESC LIMIT 1000"))));
app.post("/api/expenses", auth, admin, wrap(async (req, res) => {
  const b = req.body || {};
  const r = await one("INSERT INTO expenses(title,category,amount,date,notes,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id", [b.title || "", b.category, intOrNull(b.amount) || 0, b.date || today(), b.notes || "", req.user.id]);
  await audit(req.user.id, "إضافة", "expense", r.id, JSON.stringify(b));
  res.json({ id: r.id });
}));

app.get("/api/reports", auth, admin, wrap(async (req, res) => {
  const byEmp = await all(`SELECT COALESCE(e.name,'غير محدد') employee,COUNT(o.id)::int orders,COALESCE(SUM(o.price),0) revenue FROM orders o LEFT JOIN employees e ON e.id=o.employee_id WHERE o.status<>'ملغي' GROUP BY 1 ORDER BY revenue DESC`);
  const byService = await all("SELECT service,COUNT(*)::int orders,COALESCE(SUM(price),0) revenue FROM orders WHERE status<>'ملغي' GROUP BY service ORDER BY revenue DESC");
  res.json({ byEmp, byService });
}));
app.get("/api/audit", auth, admin, wrap(async (req, res) => res.json(await all(`SELECT a.*,u.username FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 300`))));

app.get("/api/users", auth, admin, wrap(async (req, res) => res.json(await all("SELECT u.id,u.username,u.role,u.active,e.name employee FROM users u LEFT JOIN employees e ON e.id=u.employee_id ORDER BY u.id"))));
app.post("/api/users", auth, admin, wrap(async (req, res) => {
  const p = req.body || {}, username = String(p.username || "").trim().toLowerCase(), role = p.role === "admin" ? "admin" : "worker";
  if (!username || !p.password) return res.status(400).json({ error: "بيانات ناقصة" });
  if (String(p.password).length < 8) return res.status(400).json({ error: "كلمة المرور يجب ألا تقل عن 8 أحرف" });
  const empId = role === "worker" ? intOrNull(p.employee_id) : null;
  if (role === "worker" && !empId) return res.status(400).json({ error: "اختر الكابتن المرتبط بهذا الحساب" });
  try {
    const r = await one("INSERT INTO users(username,password_hash,role,employee_id) VALUES($1,$2,$3,$4) RETURNING id", [username, bcrypt.hashSync(String(p.password), 10), role, empId]);
    await audit(req.user.id, "إضافة مستخدم", "user", r.id, username);
    res.json({ id: r.id });
  } catch (e) { if (e.code === "23505") return res.status(400).json({ error: "اسم المستخدم موجود" }); throw e; }
}));
app.patch("/api/users/:id/password", auth, admin, wrap(async (req, res) => {
  const id = intOrNull(req.params.id), np = String((req.body || {}).password || "");
  if (np.length < 8) return res.status(400).json({ error: "كلمة المرور يجب ألا تقل عن 8 أحرف" });
  const r = await one("UPDATE users SET password_hash=$1 WHERE id=$2 RETURNING username", [bcrypt.hashSync(np, 10), id]);
  if (!r) return res.status(404).json({ error: "المستخدم غير موجود" });
  await audit(req.user.id, "إعادة تعيين كلمة المرور", "user", id, r.username);
  res.json({ ok: true });
}));
app.patch("/api/users/:id/active", auth, admin, wrap(async (req, res) => {
  const id = intOrNull(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: "لا يمكنك إيقاف حسابك" });
  const r = await one("UPDATE users SET active=NOT active WHERE id=$1 RETURNING active", [id]);
  if (!r) return res.status(404).json({ error: "المستخدم غير موجود" });
  await audit(req.user.id, r.active ? "تفعيل مستخدم" : "إيقاف مستخدم", "user", id);
  res.json(r);
}));

app.get("/api/backup", auth, admin, wrap(async (req, res) => {
  const out = { date: new Date().toISOString() };
  out.users = await all("SELECT id,username,role,active,employee_id FROM users");
  for (const t of ["employees", "orders", "subscriptions", "expenses", "audit", "settings"]) out[t] = await all(`SELECT * FROM ${t}`);
  await audit(req.user.id, "نسخة احتياطية", "backup", null);
  res.json(out);
}));

app.use("/api", (req, res) => res.status(404).json({ error: "غير موجود" }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public/index.html")));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: "خطأ في الخادم" }); });

init().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Flash Wash V3 ready on :${port}`));
}).catch(e => { console.error("Database init failed:", e); process.exit(1); });
