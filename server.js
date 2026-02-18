const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const multer = require('multer');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'cameraman';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeThisPassword123!';

if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
  fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
}

const db = new Database(DB_PATH);

function runMigrations() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      trial_expires_at TEXT NOT NULL,
      premium_expires_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS assets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      type TEXT NOT NULL CHECK(type IN ('image', 'video')),
      price_cents INTEGER NOT NULL,
      filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      uploaded_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS purchases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      asset_id INTEGER,
      purchase_type TEXT NOT NULL CHECK(purchase_type IN ('asset', 'premium')),
      amount_cents INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(asset_id) REFERENCES assets(id)
    );
  `);
}

runMigrations();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
    secret: process.env.SESSION_SECRET || 'replace-this-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }
  })
);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (_req, file, cb) => {
    const uniquePrefix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${uniquePrefix}-${file.originalname.replace(/\s+/g, '_')}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 1000 * 1000 * 200 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
      cb(null, true);
      return;
    }
    cb(new Error('Only image and video files are allowed.'));
  }
});

function formatMoney(cents) {
  return `$${(cents / 100).toFixed(2)}`;
}

function currentISODate() {
  return new Date().toISOString();
}

function plusDaysISO(days) {
  const date = new Date();
  date.setDate(date.getDate() + days);
  return date.toISOString();
}

function getUserById(userId) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
}

function loadSessionUser(req, _res, next) {
  if (!req.session.userId) {
    req.currentUser = null;
    req.isAdmin = false;
    return next();
  }

  const user = getUserById(req.session.userId);
  req.currentUser = user || null;
  req.isAdmin = req.session.isAdmin === true;
  next();
}

function requireAuth(req, res, next) {
  if (!req.currentUser) {
    res.redirect('/login');
    return;
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.isAdmin) {
    res.redirect('/admin/login');
    return;
  }
  next();
}

function getAccessFlags(user, assetId) {
  const now = new Date();
  const trialActive = user && new Date(user.trial_expires_at) > now;
  const premiumActive = user && user.premium_expires_at && new Date(user.premium_expires_at) > now;

  const hasPurchased = user
    ? !!db
        .prepare(
          'SELECT 1 FROM purchases WHERE user_id = ? AND asset_id = ? AND purchase_type = "asset" LIMIT 1'
        )
        .get(user.id, assetId)
    : false;

  return {
    trialActive,
    premiumActive,
    hasPurchased,
    canDownload: trialActive || premiumActive || hasPurchased
  };
}

app.use(loadSessionUser);

app.use((req, res, next) => {
  res.locals.currentUser = req.currentUser;
  res.locals.isAdmin = req.isAdmin;
  res.locals.formatMoney = formatMoney;
  next();
});

app.get('/', (req, res) => {
  const assets = db.prepare('SELECT * FROM assets ORDER BY created_at DESC').all();
  res.render('index', { assets, message: null });
});

app.get('/register', (_req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) {
    return res.render('register', { error: 'All fields are required.' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) {
    return res.render('register', { error: 'Email already exists. Please login.' });
  }

  const hash = await bcrypt.hash(password, 10);
  const trialExpiresAt = plusDaysISO(30);
  const createdAt = currentISODate();

  const info = db
    .prepare(
      'INSERT INTO users (full_name, email, password_hash, trial_expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
    )
    .run(fullName.trim(), email.toLowerCase().trim(), hash, trialExpiresAt, createdAt);

  req.session.userId = info.lastInsertRowid;
  req.session.isAdmin = false;
  res.redirect('/dashboard');
});

app.get('/login', (_req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get((email || '').toLowerCase().trim());

  if (!user) {
    return res.render('login', { error: 'Invalid credentials.' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.render('login', { error: 'Invalid credentials.' });
  }

  req.session.userId = user.id;
  req.session.isAdmin = false;
  res.redirect('/dashboard');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.currentUser;
  const purchases = db
    .prepare(
      `SELECT p.*, a.title AS asset_title
       FROM purchases p
       LEFT JOIN assets a ON a.id = p.asset_id
       WHERE p.user_id = ?
       ORDER BY p.created_at DESC`
    )
    .all(user.id);

  const trialDaysLeft = Math.max(
    0,
    Math.ceil((new Date(user.trial_expires_at).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
  );

  const premiumDaysLeft = user.premium_expires_at
    ? Math.max(0, Math.ceil((new Date(user.premium_expires_at).getTime() - Date.now()) / (1000 * 60 * 60 * 24)))
    : 0;

  res.render('dashboard', { user, purchases, trialDaysLeft, premiumDaysLeft });
});

app.get('/assets/:id', (req, res) => {
  const asset = db.prepare('SELECT * FROM assets WHERE id = ?').get(req.params.id);
  if (!asset) {
    return res.status(404).render('message', { title: 'Not found', message: 'Asset not found.' });
  }

  const access = req.currentUser ? getAccessFlags(req.currentUser, asset.id) : null;
  res.render('asset-details', { asset, access });
});

app.post('/assets/:id/buy', requireAuth, (req, res) => {
  const asset = db.prepare('SELECT * FROM assets WHERE id = ?').get(req.params.id);
  if (!asset) {
    return res.status(404).render('message', { title: 'Not found', message: 'Asset not found.' });
  }

  const alreadyBought = db
    .prepare('SELECT id FROM purchases WHERE user_id = ? AND asset_id = ? AND purchase_type = "asset"')
    .get(req.currentUser.id, asset.id);

  if (!alreadyBought) {
    db.prepare(
      'INSERT INTO purchases (user_id, asset_id, purchase_type, amount_cents, created_at) VALUES (?, ?, "asset", ?, ?)'
    ).run(req.currentUser.id, asset.id, asset.price_cents, currentISODate());
  }

  res.redirect(`/assets/${asset.id}`);
});

app.post('/premium/subscribe', requireAuth, (req, res) => {
  const premiumPrice = 1999;
  const newPremiumDate = plusDaysISO(30);

  db.prepare('UPDATE users SET premium_expires_at = ? WHERE id = ?').run(newPremiumDate, req.currentUser.id);
  db.prepare(
    'INSERT INTO purchases (user_id, asset_id, purchase_type, amount_cents, created_at) VALUES (?, NULL, "premium", ?, ?)'
  ).run(req.currentUser.id, premiumPrice, currentISODate());

  res.redirect('/dashboard');
});

app.get('/download/:id', requireAuth, (req, res) => {
  const asset = db.prepare('SELECT * FROM assets WHERE id = ?').get(req.params.id);
  if (!asset) {
    return res.status(404).render('message', { title: 'Not found', message: 'Asset not found.' });
  }

  const access = getAccessFlags(req.currentUser, asset.id);
  if (!access.canDownload) {
    return res.status(403).render('message', {
      title: 'Payment required',
      message: 'Your trial has ended. Buy this asset or subscribe to premium before downloading.'
    });
  }

  const fullPath = path.join(__dirname, 'uploads', asset.filename);
  if (!fs.existsSync(fullPath)) {
    return res.status(404).render('message', { title: 'Missing file', message: 'File not found on server.' });
  }

  res.download(fullPath, asset.filename);
});

app.get('/admin/login', (_req, res) => {
  res.render('admin-login', { error: null });
});

app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const usernameOk = username === ADMIN_USERNAME;
  const passwordOk = await bcrypt.compare(password || '', await bcrypt.hash(ADMIN_PASSWORD, 10));

  if (!usernameOk || !passwordOk) {
    return res.render('admin-login', { error: 'Invalid admin credentials.' });
  }

  req.session.userId = null;
  req.session.isAdmin = true;
  res.redirect('/admin/upload');
});

app.get('/admin/upload', requireAdmin, (_req, res) => {
  const assets = db.prepare('SELECT * FROM assets ORDER BY created_at DESC').all();
  res.render('admin-upload', { error: null, success: null, assets });
});

app.post('/admin/upload', requireAdmin, upload.single('mediaFile'), (req, res) => {
  const { title, description, price } = req.body;

  if (!req.file || !title || !price) {
    const assets = db.prepare('SELECT * FROM assets ORDER BY created_at DESC').all();
    return res.render('admin-upload', {
      error: 'Title, price, and media file are required.',
      success: null,
      assets
    });
  }

  const priceCents = Math.round(Number(price) * 100);
  if (!Number.isFinite(priceCents) || priceCents <= 0) {
    const assets = db.prepare('SELECT * FROM assets ORDER BY created_at DESC').all();
    return res.render('admin-upload', {
      error: 'Price must be greater than 0.',
      success: null,
      assets
    });
  }

  const type = req.file.mimetype.startsWith('image/') ? 'image' : 'video';

  db.prepare(
    `INSERT INTO assets (title, description, type, price_cents, filename, mime_type, uploaded_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    title.trim(),
    (description || '').trim(),
    type,
    priceCents,
    req.file.filename,
    req.file.mimetype,
    ADMIN_USERNAME,
    currentISODate()
  );

  const assets = db.prepare('SELECT * FROM assets ORDER BY created_at DESC').all();
  res.render('admin-upload', {
    error: null,
    success: 'Asset uploaded successfully.',
    assets
  });
});

app.use((err, _req, res, _next) => {
  res.status(400).render('message', {
    title: 'Error',
    message: err.message || 'Unexpected error occurred.'
  });
});

app.listen(PORT, () => {
  console.log(`BJC MEDIA STUDIO is running on http://localhost:${PORT}`);
});
