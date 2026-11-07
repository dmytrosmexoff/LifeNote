'use strict';
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const fs = require('fs');
const PORT = Number(process.env.PORT) || 3000;
const ALLOW_REG = process.env.ALLOW_REGISTRATION === 'true';
const CONFIG_PATH = process.env.CONFIG_PATH || '/data/config.json';
const SESSION_DAYS = 30;
const sleep = ms => new Promise(r => setTimeout(r, ms));
let pool = null;
let lastError = '';

function readCfg() { try { return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); } catch (e) { return null; } }
function writeCfg(c) {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(c), { mode: 0o600 });
}
function dbError(e) {
  const m = {
    ECONNREFUSED: 'Сервер отклонил подключение. Проверьте хост и порт',
    ENOTFOUND: 'Хост не найден. Проверьте адрес',
    ETIMEDOUT: 'Нет ответа от сервера (таймаут). Проверьте адрес, порт и файрвол',
    EHOSTUNREACH: 'Хост недоступен из контейнера',
    ER_ACCESS_DENIED_ERROR: 'Неверный логин или пароль',
    ER_BAD_DB_ERROR: 'Такой базы данных нет. Создайте её заранее',
    ER_DBACCESS_DENIED_ERROR: 'У пользователя нет доступа к этой базе',
    ER_TABLEACCESS_DENIED_ERROR: 'У пользователя нет прав создавать таблицы (нужны CREATE, ALTER, INSERT, SELECT, UPDATE, DELETE, DROP)',
    ER_SPECIFIC_ACCESS_DENIED_ERROR: 'Не хватает прав у пользователя БД'
  };
  return m[e.code] || ('Ошибка подключения: ' + (e.code || e.message));
}
function cleanCfg(b) {
  b = b || {};
  const c = {
    host: String(b.host || '').trim(),
    port: parseInt(b.port, 10) || 3306,
    user: String(b.user || '').trim(),
    password: String(b.password || ''),
    database: String(b.database || '').trim()
  };
  if (!c.host || c.host.length > 255 || !/^[\w.\-:]+$/.test(c.host)) throw new Error('Укажите хост (например 192.168.1.10)');
  if (c.port < 1 || c.port > 65535) throw new Error('Порт от 1 до 65535');
  if (!c.user || c.user.length > 80) throw new Error('Укажите пользователя БД');
  if (c.password.length > 200) throw new Error('Слишком длинный пароль');
  if (!/^[\w$\-]{1,64}$/.test(c.database)) throw new Error('Имя базы: буквы, цифры, _ и -');
  return c;
}
// проверка: подключение, версия, права на создание таблиц
async function testConn(c) {
  const conn = await mysql.createConnection({ host: c.host, port: c.port, user: c.user, password: c.password,
    database: c.database, connectTimeout: 8000, charset: 'utf8mb4' });
  try {
    const [[r]] = await conn.query('SELECT VERSION() AS v');
    await conn.query('CREATE TABLE IF NOT EXISTS _diary_probe (id INT)');
    await conn.query('DROP TABLE _diary_probe');
    return r.v;
  } finally { await conn.end().catch(() => {}); }
}

async function initDb(c) {
  const p = mysql.createPool({ host: c.host, port: c.port, user: c.user, password: c.password, database: c.database,
    waitForConnections: true, connectionLimit: 10, connectTimeout: 8000, charset: 'utf8mb4', dateStrings: true });
  try {
    await p.query('SELECT 1');
    await createTables(p);
  } catch (e) { await p.end().catch(() => {}); throw e; }
  const old = pool;
  pool = p;
  if (old) old.end().catch(() => {});
  lastError = '';
  console.log('MySQL подключён: ' + c.host + ':' + c.port + '/' + c.database);
}

async function createTables(pool) {
  const T = 'CHARACTER SET utf8mb4';
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    city VARCHAR(100) NOT NULL DEFAULT 'Фукуяма',
    lat DECIMAL(8,5) NOT NULL DEFAULT 34.48583,
    lon DECIMAL(8,5) NOT NULL DEFAULT 133.36250,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) ${T}`);
  await pool.query(`CREATE TABLE IF NOT EXISTS sessions (
    token_hash CHAR(64) PRIMARY KEY,
    user_id INT NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ${T}`);
  await pool.query(`CREATE TABLE IF NOT EXISTS entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    entry_date DATE NOT NULL,
    rate TINYINT NOT NULL,
    body TEXT,
    feel_tags TEXT,
    feel_text VARCHAR(500),
    weather VARCHAR(600),
    wtype VARCHAR(10),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_user_date (user_id, entry_date),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ${T}`);
  await pool.query(`CREATE TABLE IF NOT EXISTS weather_cache (
    cache_key VARCHAR(255) PRIMARY KEY,
    payload MEDIUMTEXT NOT NULL,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) ${T}`);
  await pool.query('DELETE FROM sessions WHERE expires_at < NOW()');
}

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '50kb' }));

const h = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(e => {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  });

function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) { try { o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch (e) {} }
  });
  return o;
}
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

async function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query(
    'INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? DAY))',
    [sha(token), userId, SESSION_DAYS]);
  res.setHeader('Set-Cookie',
    `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}`);
}

const needAuth = h(async (req, res, next) => {
  const t = cookies(req).sid;
  if (!t) return res.status(401).json({ error: 'Нужен вход' });
  const [rows] = await pool.query(
    `SELECT u.id, u.username, u.city, u.lat, u.lon FROM sessions s
     JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > NOW()`, [sha(t)]);
  if (!rows.length) return res.status(401).json({ error: 'Нужен вход' });
  req.user = rows[0];
  next();
});

// защита от подбора пароля
const tries = { login: new Map(), setup: new Map() };
function tooMany(req, bucket = 'login') {
  const now = Date.now(), k = req.ip, m = tries[bucket];
  const r = m.get(k) || { n: 0, t: now };
  if (now - r.t > 10 * 60 * 1000) { r.n = 0; r.t = now; }
  r.n++; m.set(k, r);
  return r.n > (bucket === 'setup' ? 40 : 15);
}

const userView = u => ({ username: u.username, city: u.city, lat: Number(u.lat), lon: Number(u.lon) });

// ---- настройка своей базы данных ----
// пока БД не подключена, настройка открыта; после подключения менять её может только вошедший пользователь
const setupGuard = (req, res, next) => (pool ? needAuth(req, res, next) : next());

app.get('/api/status', (req, res) => {
  const c = readCfg();
  const out = { configured: !!c, connected: !!pool, error: pool ? '' : lastError };
  if (!pool && c) out.db = { host: c.host, port: c.port, user: c.user, database: c.database };
  res.json(out);
});

app.get('/api/setup/current', setupGuard, (req, res) => {
  const c = readCfg() || {};
  res.json({ host: c.host || '', port: c.port || 3306, user: c.user || '', database: c.database || '' });
});

function setupInput(req) {
  const c = cleanCfg(req.body);
  if (!c.password && req.user) c.password = (readCfg() || {}).password || ''; // пустой пароль = оставить прежний
  return c;
}

app.post('/api/setup/test', setupGuard, h(async (req, res) => {
  if (tooMany(req, 'setup')) return res.status(429).json({ ok: false, error: 'Слишком много попыток, подождите' });
  let c;
  try { c = setupInput(req); } catch (e) { return res.status(400).json({ ok: false, error: e.message }); }
  try {
    const v = await testConn(c);
    res.json({ ok: true, message: 'Подключение успешно. Сервер: ' + v + ', база: ' + c.database + ', права на таблицы есть' });
  } catch (e) { res.json({ ok: false, error: dbError(e) }); }
}));

app.post('/api/setup/save', setupGuard, h(async (req, res) => {
  if (tooMany(req, 'setup')) return res.status(429).json({ ok: false, error: 'Слишком много попыток, подождите' });
  let c;
  try { c = setupInput(req); } catch (e) { return res.status(400).json({ ok: false, error: e.message }); }
  try {
    await testConn(c);
    await initDb(c);
    writeCfg(c);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: dbError(e) }); }
}));

// остальное API работает только при подключённой БД
app.use('/api', (req, res, next) =>
  pool ? next() : res.status(503).json({ error: 'База данных не подключена', setup: true }));

app.post('/api/register', h(async (req, res) => {
  if (tooMany(req)) return res.status(429).json({ error: 'Слишком много попыток, подождите 10 минут' });
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const [[{ c }]] = await pool.query('SELECT COUNT(*) c FROM users');
  if (!ALLOW_REG && c > 0) return res.status(403).json({ error: 'Регистрация закрыта' });
  if (!/^[\wа-яА-ЯёЁ.\-]{3,30}$/.test(username))
    return res.status(400).json({ error: 'Логин: 3-30 символов, буквы, цифры, . _ -' });
  if (password.length < 8 || Buffer.byteLength(password) > 72)
    return res.status(400).json({ error: 'Пароль: от 8 до 72 символов' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const [r] = await pool.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
    await startSession(res, r.insertId);
    const [[u]] = await pool.query('SELECT username, city, lat, lon FROM users WHERE id = ?', [r.insertId]);
    res.json(userView(u));
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Такой логин уже занят' });
    throw e;
  }
}));

app.post('/api/login', h(async (req, res) => {
  if (tooMany(req)) return res.status(429).json({ error: 'Слишком много попыток, подождите 10 минут' });
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
  const ok = rows.length && await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'Неверный логин или пароль' });
  await startSession(res, rows[0].id);
  res.json(userView(rows[0]));
}));

app.post('/api/logout', h(async (req, res) => {
  const t = cookies(req).sid;
  if (t) await pool.query('DELETE FROM sessions WHERE token_hash = ?', [sha(t)]);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
}));

app.get('/api/me', needAuth, (req, res) => res.json(userView(req.user)));

app.post('/api/location', needAuth, h(async (req, res) => {
  const q = String(req.body.q || '').trim().slice(0, 100);
  if (!q) return res.status(400).json({ error: 'Введите город' });
  const r = await fetch('https://geocoding-api.open-meteo.com/v1/search?count=1&language=ru&name=' + encodeURIComponent(q),
    { signal: AbortSignal.timeout(10000) });
  const j = await r.json();
  if (!j.results || !j.results.length) return res.status(404).json({ error: 'Город не найден' });
  const p = j.results[0];
  await pool.query('UPDATE users SET city = ?, lat = ?, lon = ? WHERE id = ?',
    [String(p.name).slice(0, 100), p.latitude, p.longitude, req.user.id]);
  res.json({ city: p.name, lat: p.latitude, lon: p.longitude });
}));

// ---- погода с кэшем в MySQL ----
async function cached(key, ttl, url) {
  const [rows] = await pool.query(
    'SELECT payload, TIMESTAMPDIFF(SECOND, fetched_at, NOW()) AS age FROM weather_cache WHERE cache_key = ?', [key]);
  if (rows.length && rows[0].age < ttl) return JSON.parse(rows[0].payload);
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) throw new Error('Open-Meteo HTTP ' + r.status);
    const j = await r.json();
    await pool.query('REPLACE INTO weather_cache (cache_key, payload) VALUES (?, ?)', [key, JSON.stringify(j)]);
    return j;
  } catch (e) {
    if (rows.length) return JSON.parse(rows[0].payload);
    throw e;
  }
}
const coord = u => [Number(u.lat).toFixed(2), Number(u.lon).toFixed(2)];

app.get('/api/wx/forecast', needAuth, h(async (req, res) => {
  const [la, lo] = coord(req.user);
  const url = `https://api.open-meteo.com/v1/forecast?latitude=${la}&longitude=${lo}&timezone=auto&forecast_days=7&wind_speed_unit=ms` +
    '&current=temperature_2m,apparent_temperature,relative_humidity_2m,precipitation,weather_code,cloud_cover,pressure_msl,wind_speed_10m,wind_direction_10m,wind_gusts_10m' +
    '&hourly=temperature_2m,precipitation_probability,weather_code' +
    '&daily=weather_code,temperature_2m_max,temperature_2m_min,sunrise,sunset,uv_index_max,precipitation_sum,snowfall_sum,precipitation_probability_max,wind_speed_10m_max';
  try { res.json(await cached(`f:${la}:${lo}`, 900, url)); }
  catch (e) { res.status(502).json({ error: 'Не удалось получить погоду' }); }
}));

app.get('/api/wx/archive', needAuth, h(async (req, res) => {
  const { start, end } = req.query;
  const re = /^\d{4}-\d{2}-\d{2}$/;
  if (!re.test(start) || !re.test(end)) return res.status(400).json({ error: 'Неверные даты' });
  const days = (Date.parse(end) - Date.parse(start)) / 86400000;
  if (!(days >= 0 && days <= 62)) return res.status(400).json({ error: 'Слишком большой период' });
  const [la, lo] = coord(req.user);
  const url = `https://archive-api.open-meteo.com/v1/archive?latitude=${la}&longitude=${lo}&start_date=${start}&end_date=${end}` +
    '&timezone=auto&wind_speed_unit=ms&daily=temperature_2m_mean,temperature_2m_max,temperature_2m_min,precipitation_sum,snowfall_sum,weather_code,wind_speed_10m_max,sunshine_duration';
  try {
    const j = await cached(`a:${la}:${lo}:${start}:${end}`, 86400, url);
    res.json({ daily: j.daily });
  } catch (e) { res.status(502).json({ error: 'Не удалось получить архив погоды' }); }
}));

// ---- записи дневника ----
app.get('/api/entries', needAuth, h(async (req, res) => {
  const [rows] = await pool.query(
    'SELECT id, entry_date, rate, body, feel_tags, feel_text, weather, wtype FROM entries WHERE user_id = ? ORDER BY entry_date DESC LIMIT 400',
    [req.user.id]);
  res.json({ entries: rows.map(r => {
    let feel = []; try { feel = JSON.parse(r.feel_tags || '[]'); } catch (e) {}
    return { id: r.id, date: r.entry_date, rate: r.rate, text: r.body || '', feel,
             feelText: r.feel_text || '', weather: r.weather || '', wtype: r.wtype };
  }) });
}));

app.post('/api/entries', needAuth, h(async (req, res) => {
  const b = req.body || {};
  const rate = parseInt(b.rate, 10);
  if (!(rate >= 1 && rate <= 6)) return res.status(400).json({ error: 'Оценка от 1 до 6' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(b.date))) return res.status(400).json({ error: 'Неверная дата' });
  const feel = Array.isArray(b.feel) ? b.feel.slice(0, 12).map(x => String(x).slice(0, 40)) : [];
  const wtype = ['sun', 'cloud', 'rain', 'snow'].includes(b.wtype) ? b.wtype : null;
  await pool.query(
    `INSERT INTO entries (user_id, entry_date, rate, body, feel_tags, feel_text, weather, wtype)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE rate = VALUES(rate), body = VALUES(body), feel_tags = VALUES(feel_tags),
       feel_text = VALUES(feel_text), weather = VALUES(weather), wtype = VALUES(wtype)`,
    [req.user.id, b.date, rate, String(b.text || '').slice(0, 10000), JSON.stringify(feel),
     String(b.feelText || '').slice(0, 500), String(b.weather || '').slice(0, 600), wtype]);
  res.json({ ok: true });
}));

app.delete('/api/entries/:id', needAuth, h(async (req, res) => {
  await pool.query('DELETE FROM entries WHERE id = ? AND user_id = ?', [parseInt(req.params.id, 10) || 0, req.user.id]);
  res.json({ ok: true });
}));

app.use(express.static(path.join(__dirname, 'public')));

(async () => {
  const c = readCfg();
  if (c) {
    for (let i = 1; i <= 5 && !pool; i++) {
      try { await initDb(c); }
      catch (e) { lastError = dbError(e); console.log('БД недоступна (' + i + '/5): ' + lastError); await sleep(2000); }
    }
  } else console.log('БД не настроена: откройте приложение и введите данные подключения');
  setInterval(() => pool && pool.query('DELETE FROM sessions WHERE expires_at < NOW()').catch(() => {}), 3600 * 1000);
  app.listen(PORT, () => console.log('Дневник слушает порт ' + PORT));
})();
