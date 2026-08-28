// ============================================================
// NEXTRA STORE - Backend Server
// ============================================================
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// ====== DATA STORAGE ======
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readData(key, fallback) {
  const fp = path.join(DATA_DIR, key + '.json');
  try {
    if (!fs.existsSync(fp)) {
      fs.writeFileSync(fp, JSON.stringify(fallback, null, 2));
      return fallback;
    }
    const raw = fs.readFileSync(fp, 'utf8');
    if (!raw.trim()) {
      fs.writeFileSync(fp, JSON.stringify(fallback, null, 2));
      return fallback;
    }
    return JSON.parse(raw);
  } catch (e) {
    console.error('readData error', key, e);
    return fallback;
  }
}

function writeData(key, val) {
  try {
    fs.writeFileSync(path.join(DATA_DIR, key + '.json'), JSON.stringify(val, null, 2));
    return true;
  } catch (e) {
    console.error('writeData error', key, e);
    return false;
  }
}

// ====== DEFAULTS ======
const DEFAULTS = {
  users: {},
  cats: [
    { id: 'roblox', name: 'Roblox', icon: 'roblox', desc: 'เกม Roblox' },
    { id: 'valorant', name: 'Valorant', icon: 'valorant', desc: 'Valorant Points' },
    { id: 'pubg', name: 'PUBG', icon: 'pubg', desc: 'PUBG UC' },
    { id: 'netflix', name: 'Netflix', icon: 'netflix', desc: 'Netflix Premium' },
    { id: 'webtemplate', name: 'เทมเพลตเว็บ', icon: 'globe', desc: 'เทมเพลตเว็บไซต์' },
    { id: 'game', name: 'เกม', icon: 'game', desc: 'เกมและไอเทม' },
    { id: 'webproduct', name: 'เว็บไซต์', icon: 'globe', desc: 'สินค้าเว็บไซต์' }
  ],
  prods: [
    { id: 1, cat: 'roblox', name: 'Roblox Gift Card $10', desc: 'เติม Robux', price: 350, agentPrice: 280, img: 'roblox', tag: 'HOT' },
    { id: 2, cat: 'roblox', name: 'Roblox Gift Card $25', desc: 'เติม Robux คุ้มๆ', price: 850, agentPrice: 680, img: 'roblox', tag: 'HOT' },
    { id: 3, cat: 'valorant', name: 'Valorant Points 125', desc: 'VP', price: 75, agentPrice: 55, img: 'valorant' },
    { id: 4, cat: 'valorant', name: 'Valorant Points 700', desc: 'VP', price: 380, agentPrice: 300, img: 'valorant' },
    { id: 5, cat: 'pubg', name: 'PUBG UC 60', desc: 'UC', price: 35, agentPrice: 25, img: 'pubg' },
    { id: 6, cat: 'netflix', name: 'Netflix 1 เดือน', desc: '4K', price: 380, agentPrice: 300, img: 'netflix' }
  ],
  webprods: [
    { id: 1, cat: 'webtemplate', name: 'เว็บร้านค้า', desc: 'ระบบครบ', price: 1500, agentPrice: 1100, img: 'globe', expDay: 31, expMonth: 12, expYear: 2026 },
    { id: 2, cat: 'webtemplate', name: 'เว็บเกม', desc: 'Landing สวย', price: 800, agentPrice: 600, img: 'game', expDay: 1, expMonth: 6, expYear: 2026 }
  ],
  globalData: { allTopups: [], allOrders: [] },
  siteImg: { logo: '', banner: '', avatar: '' },
  shop: { name: 'NEXTRA STORE', logo: '' },
  settings: { systemEnabled: true, ppEnabled: true, tmEnabled: true, bankEnabled: true },
  payments: {
    ppKey: 'f3655a6c7248ab6292fc74612fa229e5a2c79c91ce5f501cb8167ea69d9df7f3',
    ppName: '', ppQr: '', tmPhone: '', bankKey: '', bankName: '', bankAccount: ''
  },
  usedVouchers: [],
  sessions: {}
};

// Init all data files
Object.keys(DEFAULTS).forEach(k => readData(k, DEFAULTS[k]));

// ====== AUTH MIDDLEWARE ======
function authMW(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'No token' });

  const sessions = readData('sessions', {});
  const session = sessions[token];
  if (!session) return res.status(401).json({ error: 'Session หมดอายุ กรุณาเข้าสู่ระบบใหม่' });

  const users = readData('users', {});
  const user = users[session.username];
  if (!user) return res.status(401).json({ error: 'ไม่พบผู้ใช้' });

  req.user = { username: session.username, ...user };
  req.token = token;
  next();
}

function adminMW(req, res, next) {
  const isHardAdmin = req.user.username === 'nextrastore';
  if (req.user.rank !== 'admin' && !isHardAdmin) {
    return res.status(403).json({ error: 'ต้องเป็นแอดมินเท่านั้น' });
  }
  next();
}

function genToken() { return crypto.randomBytes(32).toString('hex'); }
function hashPwd(p) { return crypto.createHash('sha256').update(p).digest('hex'); }

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'กรอกให้ครบ' });
  if (username.length < 3) return res.status(400).json({ error: 'ชื่อผู้ใช้ 3 ตัวขึ้นไป' });
  if (password.length < 4) return res.status(400).json({ error: 'รหัสผ่าน 4 ตัวขึ้นไป' });

  const users = readData('users', {});
  if (users[username]) return res.status(400).json({ error: 'ชื่อนี้ถูกใช้แล้ว' });

  const newUser = {
    password: hashPwd(password),
    balance: 0,
    topupCount: 0,
    totalTopup: 0,
    joined: Date.now(),
    rank: 'user',
    email: email || ''
  };
  users[username] = newUser;
  writeData('users', users);

  const token = genToken();
  const sessions = readData('sessions', {});
  sessions[token] = { username, created: Date.now() };
  writeData('sessions', sessions);

  const { password: _, ...safeUser } = newUser;
  res.json({ success: true, token, user: { username, ...safeUser } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'กรอกให้ครบ' });

  // Hardcoded admin
  if (username === 'nextrastore' && password === 'gghhgg879K') {
    const token = genToken();
    const sessions = readData('sessions', {});
    sessions[token] = { username, created: Date.now() };
    writeData('sessions', sessions);
    return res.json({
      success: true,
      token,
      user: { username, rank: 'admin', balance: 99999, topupCount: 0, totalTopup: 0, joined: Date.now() }
    });
  }

  const users = readData('users', {});
  const user = users[username];
  if (!user || user.password !== hashPwd(password)) {
    return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านผิด' });
  }

  const token = genToken();
  const sessions = readData('sessions', {});
  sessions[token] = { username, created: Date.now() };
  writeData('sessions', sessions);

  const { password: _, ...safeUser } = user;
  res.json({ success: true, token, user: { username, ...safeUser } });
});

app.post('/api/logout', authMW, (req, res) => {
  const sessions = readData('sessions', {});
  delete sessions[req.token];
  writeData('sessions', sessions);
  res.json({ success: true });
});

app.get('/api/me', authMW, (req, res) => {
  const { password, ...safe } = req.user;
  res.json({ user: { username: req.user.username, ...safe } });
});

// ============================================================
// GENERIC CRUD FACTORY
// ============================================================
function makeCRUD(key, adminOnly = true) {
  const router = express.Router();

  const list = () => readData(key, []);

  router.get('/', (req, res) => res.json(list()));

  router.post('/', authMW, adminOnly ? adminMW : (req, res, next) => next(), (req, res) => {
    const items = list();
    const newItem = { id: req.body.id || Date.now() + Math.floor(Math.random() * 1000), ...req.body };
    items.push(newItem);
    writeData(key, items);
    res.json({ success: true, item: newItem });
  });

  router.put('/:id', authMW, adminOnly ? adminMW : (req, res, next) => next(), (req, res) => {
    const items = list();
    const idx = items.findIndex(i => String(i.id) === String(req.params.id));
    if (idx < 0) return res.status(404).json({ error: 'ไม่พบรายการ' });
    items[idx] = { ...items[idx], ...req.body, id: items[idx].id };
    writeData(key, items);
    res.json({ success: true, item: items[idx] });
  });

  router.delete('/:id', authMW, adminOnly ? adminMW : (req, res, next) => next(), (req, res) => {
    const items = list();
    const before = items.length;
    const filtered = items.filter(i => String(i.id) !== String(req.params.id));
    if (filtered.length === before) return res.status(404).json({ error: 'ไม่พบรายการ' });
    writeData(key, filtered);
    res.json({ success: true, deleted: before - filtered.length });
  });

  return router;
}

app.use('/api/products', makeCRUD('prods'));
app.use('/api/categories', makeCRUD('cats'));
app.use('/api/webproducts', makeCRUD('webprods'));

// ============================================================
// USERS (admin manage)
// ============================================================
app.get('/api/users', authMW, adminMW, (req, res) => {
  const users = readData('users', {});
  const safe = {};
  Object.keys(users).forEach(u => {
    const { password, ...rest } = users[u];
    safe[u] = { username: u, ...rest };
  });
  res.json(safe);
});

app.put('/api/users/:username', authMW, adminMW, (req, res) => {
  const users = readData('users', {});
  const username = req.params.username;
  if (!users[username]) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
  const allowed = ['balance', 'topupCount', 'totalTopup', 'rank', 'email'];
  const update = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });
  users[username] = { ...users[username], ...update };
  writeData('users', users);
  res.json({ success: true });
});

app.delete('/api/users/:username', authMW, adminMW, (req, res) => {
  const users = readData('users', {});
  const username = req.params.username;
  if (!users[username]) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
  if (username === 'nextrastore') return res.status(403).json({ error: 'ลบแอดมินหลักไม่ได้' });
  delete users[username];
  writeData('users', users);
  res.json({ success: true });
});

// Self balance update (for topup / buy)
app.put('/api/me/balance', authMW, (req, res) => {
  const users = readData('users', {});
  const u = users[req.user.username];
  if (!u) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
  const { balance, topupCount, totalTopup } = req.body;
  if (balance !== undefined) u.balance = balance;
  if (topupCount !== undefined) u.topupCount = topupCount;
  if (totalTopup !== undefined) u.totalTopup = totalTopup;
  users[req.user.username] = u;
  writeData('users', users);
  res.json({ success: true });
});

// ============================================================
// SHOP / SETTINGS / PAYMENTS / SITE-IMG
// ============================================================
app.get('/api/shop', (req, res) => res.json(readData('shop', { name: 'NEXTRA STORE', logo: '' })));
app.put('/api/shop', authMW, adminMW, (req, res) => { writeData('shop', req.body); res.json({ success: true }); });

app.get('/api/site-img', (req, res) => res.json(readData('siteImg', { logo: '', banner: '', avatar: '' })));
app.put('/api/site-img', authMW, adminMW, (req, res) => { writeData('siteImg', req.body); res.json({ success: true }); });

app.get('/api/settings', (req, res) => res.json(readData('settings', {})));
app.put('/api/settings', authMW, adminMW, (req, res) => { writeData('settings', req.body); res.json({ success: true }); });

app.get('/api/payments', (req, res) => res.json(readData('payments', {})));
app.put('/api/payments', authMW, adminMW, (req, res) => { writeData('payments', req.body); res.json({ success: true }); });

// ============================================================
// VOUCHER CHECK
// ============================================================
app.post('/api/check-voucher', (req, res) => {
  const { voucher, key } = req.body;
  if (!voucher) return res.json({ success: false, error: 'ไม่พบ voucher' });

  const used = readData('usedVouchers', []);
  if (used.includes(voucher)) return res.json({ success: false, error: 'ซองนี้ถูกใช้ไปแล้ว' });
  if (voucher.length < 10) return res.json({ success: false, error: 'ซองไม่ถูกต้อง' });

  // TODO: call real TrueMoney API here
  const amounts = [50, 100, 150, 200, 300, 500, 1000];
  const amount = amounts[Math.floor(Math.random() * amounts.length)];
  used.push(voucher);
  writeData('usedVouchers', used);

  res.json({ success: true, amount, owner: 'ทรูมันนี่' });
});

// ============================================================
// TOPUP / ORDERS (log)
// ============================================================
app.get('/api/logs', authMW, adminMW, (req, res) => {
  res.json(readData('globalData', { allTopups: [], allOrders: [] }));
});

app.post('/api/logs/topup', authMW, (req, res) => {
  const gd = readData('globalData', { allTopups: [], allOrders: [] });
  gd.allTopups = gd.allTopups || [];
  gd.allTopups.unshift({ user: req.user.username, ...req.body, time: Date.now() });
  writeData('globalData', gd);
  res.json({ success: true });
});

app.post('/api/logs/order', authMW, (req, res) => {
  const gd = readData('globalData', { allTopups: [], allOrders: [] });
  gd.allOrders = gd.allOrders || [];
  gd.allOrders.unshift({ user: req.user.username, ...req.body, time: Date.now() });
  writeData('globalData', gd);
  res.json({ success: true });
});

// ============================================================
// STATS
// ============================================================
app.get('/api/admin/stats', authMW, adminMW, (req, res) => {
  const users = readData('users', {});
  const prods = readData('prods', []);
  const gd = readData('globalData', { allTopups: [], allOrders: [] });
  const totalRev = (gd.allTopups || []).reduce((s, t) => s + (t.amount || 0), 0);
  const today = new Date().toDateString();
  const todayOrders = (gd.allOrders || []).filter(o => new Date(o.time).toDateString() === today).length;
  res.json({
    userCount: Object.keys(users).length,
    totalRevenue: totalRev,
    todayOrders,
    productCount: prods.length
  });
});

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true, time: Date.now() }));

app.listen(PORT, '0.0.0.0', () => {
  console.log('========================================');
  console.log('✅ NEXTRA STORE Backend running');
  console.log('🌐 http://localhost:' + PORT);
  console.log('========================================');
});
