{
  "name": "starfalltxt",
  "version": "1.0.0",
  "private": true,
  "description": "Minecraft-Texturepacks mit Bewertungen und Kommentaren",
  "main": "server.js",
  "scripts": { "start": "node server.js" },
  "engines": { "node": ">=18" },
  "dependencies": {
    "express": "^4.21.0",
    "multer": "^2.0.0"
  }
}
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SITE_URL = (process.env.SITE_URL || '').replace(/\/$/, '');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS = path.join(DATA_DIR, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'db.json');

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error('Bitte ADMIN_PASSWORD setzen (mindestens 8 Zeichen).');
  process.exit(1);
}
fs.mkdirSync(UPLOADS, { recursive: true });

let db = { packs: [], reviews: [] };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch {}
const save = () => {
  fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(db));
  fs.renameSync(DB_FILE + '.tmp', DB_FILE);
};
const uid = () => crypto.randomBytes(6).toString('hex');
const clean = (s, n) => String(s || '').replace(/[\u0000-\u0008\u000b-\u001f]/g, ' ').trim().slice(0, n);

// Einfaches Limit pro IP (gegen Spam und Passwort-Raten)
const hits = new Map();
const limited = (key, max, ms) => {
  const now = Date.now();
  const list = (hits.get(key) || []).filter(t => now - t < ms);
  list.push(now);
  hits.set(key, list);
  return list.length > max;
};
setInterval(() => hits.clear(), 3600e3).unref();

// Admin-Login
const tokens = new Set();
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const auth = (req, res, next) =>
  tokens.has(req.get('x-token')) ? next() : res.status(401).json({ error: 'Nicht erlaubt.' });

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS,
    filename: (req, f, cb) => cb(null, uid() + uid() + path.extname(f.originalname).toLowerCase())
  }),
  limits: { fileSize: 200 * 1024 * 1024, files: 2 },
  fileFilter: (req, f, cb) =>
    cb(null, f.fieldname === 'zip' ? /\.zip$/i.test(f.originalname) : /\.(png|jpe?g|webp)$/i.test(f.originalname))
}).fields([{ name: 'zip', maxCount: 1 }, { name: 'image', maxCount: 1 }]);

const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin'
  });
  next();
});
app.use(express.json({ limit: '20kb' }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/robots.txt', (req, res) =>
  res.type('text/plain').send(`User-agent: *\nAllow: /\n${SITE_URL ? `Sitemap: ${SITE_URL}/sitemap.xml\n` : ''}`));
app.get('/sitemap.xml', (req, res) =>
  res.type('application/xml').send(
    `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${SITE_URL}/</loc></url></urlset>`));
app.use('/uploads', express.static(UPLOADS, {
  setHeaders: (res, file) => { if (file.endsWith('.zip')) res.attachment(); }
}));

app.post('/api/login', (req, res) => {
  if (limited('login' + req.ip, 5, 60000)) return res.status(429).json({ error: 'Zu viele Versuche. Warte kurz.' });
  if (!crypto.timingSafeEqual(sha(req.body.password), sha(ADMIN_PASSWORD)))
    return res.status(401).json({ error: 'Falsches Passwort.' });
  const token = crypto.randomBytes(24).toString('hex');
  tokens.add(token);
  res.json({ token });
});

app.get('/api/packs', (req, res) => {
  res.json(db.packs.map(p => {
    const rated = db.reviews.filter(r => r.pack === p.id && r.rating);
    const avg = rated.length ? rated.reduce((s, r) => s + r.rating, 0) / rated.length : 0;
    return { ...p, count: rated.length, avg };
  }));
});

// Nur mit Login: Pack hochladen
app.post('/api/packs', auth, upload, (req, res) => {
  const zip = req.files && req.files.zip && req.files.zip[0];
  const img = req.files && req.files.image && req.files.image[0];
  const name = clean(req.body.name, 60);
  if (!zip || !name) {
    [zip, img].forEach(f => f && fs.unlink(f.path, () => {}));
    return res.status(400).json({ error: 'Name und ZIP-Datei fehlen.' });
  }
  db.packs.unshift({
    id: uid(), name, desc: clean(req.body.desc, 600), mc: clean(req.body.mc, 20),
    zip: zip.filename, image: img ? img.filename : '', size: zip.size, date: Date.now()
  });
  save();
  res.json({ ok: true });
});

app.delete('/api/packs/:id', auth, (req, res) => {
  const p = db.packs.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Nicht gefunden.' });
  [p.zip, p.image].forEach(f => f && fs.unlink(path.join(UPLOADS, f), () => {}));
  db.packs = db.packs.filter(x => x !== p);
  db.reviews = db.reviews.filter(r => r.pack !== p.id);
  save();
  res.json({ ok: true });
});

// Öffentlich: Bewertungen, Kommentare und allgemeines Feedback (pack = "site")
app.get('/api/reviews/:pack', (req, res) =>
  res.json(db.reviews.filter(r => r.pack === req.params.pack).sort((a, b) => b.date - a.date)));

app.post('/api/reviews', (req, res) => {
  if (limited('rev' + req.ip, 3, 60000)) return res.status(429).json({ error: 'Bitte warte kurz.' });
  const { pack } = req.body;
  const site = pack === 'site';
  if (!site && !db.packs.some(p => p.id === pack)) return res.status(404).json({ error: 'Pack nicht gefunden.' });
  const rating = site ? 0 : Math.round(Number(req.body.rating));
  const text = clean(req.body.text, 800);
  if (!site && !(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'Bitte wähle 1 bis 5 Sterne.' });
  if (site && !text) return res.status(400).json({ error: 'Bitte schreib etwas.' });
  db.reviews.push({ id: uid(), pack, name: clean(req.body.name, 30) || 'Anonym', rating, text, date: Date.now() });
  save();
  res.json({ ok: true });
});

app.delete('/api/reviews/:id', auth, (req, res) => {
  db.reviews = db.reviews.filter(r => r.id !== req.params.id);
  save();
  res.json({ ok: true });
});

app.use((err, req, res, next) =>
  res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400)
    .json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Datei zu groß (max. 200 MB).' : 'Ungültige Anfrage.' }));

app.listen(PORT, () => console.log(`starfalltxt läuft auf Port ${PORT}`));
