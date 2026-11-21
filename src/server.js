'use strict';
const express = require('express');
const multer = require('multer');
const dns = require('dns').promises, https = require('https'), net = require('net');
const { analyzeApk, securityScore, grade, diffAnalyses } = require('./scan');
const { buildPdf } = require('./report');

const MAX_MB = 150;
const app = express();
app.set('trust proxy', 1);
app.use(express.static(require('path').join(__dirname, '..', 'public')));
app.use(express.json({ limit: '200kb' }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_MB * 1024 * 1024, files: 2 } });

// ---------- tiny per-IP rate limiter (in-memory, resets on deploy) ----------
const HITS = new Map();
function limited(key, max, perMs) {
  const now = Date.now(); const arr = (HITS.get(key) || []).filter((t) => now - t < perMs);
  arr.push(now); HITS.set(key, arr); if (HITS.size > 20000) HITS.clear();
  return arr.length > max;
}
const ipOf = (req) => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'x').split(',')[0].trim();

function isApk(file) { return file && /\.(apk|xapk)$/i.test(file.originalname) && file.buffer && file.buffer.length > 4 && file.buffer.slice(0, 2).toString() === 'PK'; }

app.post('/api/analyze', upload.single('apk'), async (req, res) => {
  try {
    if (limited('an:' + ipOf(req), 20, 60 * 60 * 1000)) return res.status(429).json({ error: 'Too many uploads from this connection. Please wait a while and try again.' });
    if (!req.file) return res.status(400).json({ error: 'Please choose an .apk file.' });
    if (!isApk(req.file)) return res.status(400).json({ error: 'That does not look like a valid APK file.' });
    const r = await analyzeApk(req.file.buffer);
    r.score = securityScore(r.vulnerabilities, r.secrets); r.grade = grade(r.score);
    delete r.certificate?.error;
    res.json({ meta: { filename: req.file.originalname, size: req.file.size }, result: r });
  } catch (e) { console.error('analyze error', e); res.status(400).json({ error: 'Could not read this file. Make sure it is a valid, unencrypted .apk file.' }); }
});

app.post('/api/diff', upload.fields([{ name: 'apkA', maxCount: 1 }, { name: 'apkB', maxCount: 1 }]), async (req, res) => {
  try {
    if (limited('df:' + ipOf(req), 10, 60 * 60 * 1000)) return res.status(429).json({ error: 'Too many requests. Please wait and try again.' });
    const fa = req.files && req.files.apkA && req.files.apkA[0], fb = req.files && req.files.apkB && req.files.apkB[0];
    if (!isApk(fa) || !isApk(fb)) return res.status(400).json({ error: 'Please choose two valid .apk files.' });
    const a = await analyzeApk(fa.buffer), b = await analyzeApk(fb.buffer);
    res.json(diffAnalyses(a, b));
  } catch (e) { console.error('diff error', e); res.status(400).json({ error: 'Could not compare these files.' }); }
});

app.post('/api/report.pdf', express.json({ limit: '15mb' }), (req, res) => {
  try {
    const { result, meta } = req.body || {};
    if (!result || !meta) return res.status(400).json({ error: 'Missing report data.' });
    res.setHeader('content-type', 'application/pdf');
    res.setHeader('content-disposition', 'attachment; filename="apk-security-report.pdf"');
    buildPdf(res, result, meta);
  } catch (e) { console.error('pdf error', e); res.status(500).json({ error: 'Could not build the PDF.' }); }
});

// ---------- optional, opt-in: check if a found Firebase Realtime Database URL is publicly readable ----------
function isPublicIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) { const [a, b] = ip.split('.').map(Number); return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)); }
  if (v === 6) { const l = ip.toLowerCase(); return !(l === '::1' || l === '::' || /^f[cd]/.test(l) || /^fe[89ab]/.test(l)); }
  return false;
}
async function safeGet(urlStr) {
  const u = new URL(urlStr);
  if (u.protocol !== 'https:' || u.username || u.password || net.isIP(u.hostname)) throw new Error('blocked');
  const addrs = await dns.lookup(u.hostname, { all: true });
  if (!addrs.length || !addrs.every((a) => isPublicIp(a.address))) throw new Error('blocked');
  return new Promise((resolve, reject) => {
    const req = https.request({ host: u.hostname, servername: u.hostname, port: 443, path: u.pathname + u.search, method: 'GET', timeout: 6000, headers: { 'user-agent': 'APK-Analyzer-by-Abhigyan/1.0' } }, (r) => {
      const chunks = []; let n = 0;
      r.on('data', (c) => { n += c.length; if (n > 50000) { req.destroy(new Error('too_big')); return; } chunks.push(c); });
      r.on('end', () => resolve({ status: r.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      r.on('error', reject);
    }); req.on('timeout', () => req.destroy(new Error('timeout'))); req.on('error', reject); req.end();
  });
}
const FIREBASE_HOST = /\.firebaseio\.com$|^firestore\.googleapis\.com$/i;
app.post('/api/check-firebase', async (req, res) => {
  try {
    if (limited('fb:' + ipOf(req), 15, 60 * 60 * 1000)) return res.status(429).json({ error: 'Too many requests. Please wait and try again.' });
    const url = String((req.body || {}).url || '');
    let u; try { u = new URL(url); } catch { return res.status(400).json({ error: 'Not a valid URL.' }); }
    if (!FIREBASE_HOST.test(u.hostname)) return res.status(400).json({ error: 'Only Firebase Realtime Database hosts (*.firebaseio.com) can be checked here.' });
    const target = `https://${u.hostname}/.json?shallow=true`;
    try {
      const r = await safeGet(target);
      const open = r.status === 200 && r.body.trim() !== 'null';
      res.json({ checked: target, status: r.status, publiclyReadable: open, note: open ? 'This database answered an unauthenticated read request. Check your Realtime Database security rules immediately.' : 'This database did not return readable data to an anonymous request (status ' + r.status + ').' });
    } catch { res.json({ checked: target, error: 'Could not reach this host, or it refused the connection.' }); }
  } catch (e) { res.status(500).json({ error: 'Something went wrong.' }); }
});

app.get('/healthz', (req, res) => res.send('ok'));
app.listen(process.env.PORT || 10000, () => console.log('listening'));
