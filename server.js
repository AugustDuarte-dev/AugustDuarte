require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const multerS3 = require('multer-s3');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const {
  S3Client,
  ListObjectsV2Command,
  GetObjectCommand,
  DeleteObjectCommand,
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

// ── Config ────────────────────────────────────────────────────────────────────

const PORT           = process.env.PORT           || 3000;
const SITE_USER      = process.env.SITE_USER      || 'admin';
const SITE_PASS      = process.env.SITE_PASS      || 'changeme123';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const MAX_FILE_MB    = parseInt(process.env.MAX_FILE_SIZE_MB || '500');

const R2_ACCOUNT_ID  = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY  = process.env.R2_ACCESS_KEY;
const R2_SECRET_KEY  = process.env.R2_SECRET_KEY;
const R2_BUCKET      = process.env.R2_BUCKET;

// ── R2 Client ─────────────────────────────────────────────────────────────────

const s3 = new S3Client({
  region: 'auto',
  endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: R2_ACCESS_KEY,
    secretAccessKey: R2_SECRET_KEY,
  },
});

// ── Multer → R2 ───────────────────────────────────────────────────────────────

const upload = multer({
  storage: multerS3({
    s3,
    bucket: R2_BUCKET,
    key: (_req, file, cb) => {
      const safe = path.basename(file.originalname).replace(/[^\w.\-\s]/g, '_');
      cb(null, safe);
    },
  }),
  limits: { fileSize: MAX_FILE_MB * 1024 * 1024 },
});

// ── Express setup ─────────────────────────────────────────────────────────────

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:']
    }
  }
}));

// Trust Cloudflare proxy
app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

// Brute-force protection on login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' }
});

// Auth guard
const requireAuth = (req, res, next) => {
  if (req.session.authenticated) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
};

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ── Pages ────────────────────────────────────────────────────────────────────

app.get('/', requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  if (req.session.authenticated) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (username === SITE_USER && password === SITE_PASS) {
    req.session.authenticated = true;
    req.session.save(() => res.redirect('/'));
  } else {
    res.redirect('/login?error=1');
  }
});

app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ── API: List files ───────────────────────────────────────────────────────────

app.get('/api/files', requireAuth, async (_req, res) => {
  try {
    const data = await s3.send(new ListObjectsV2Command({ Bucket: R2_BUCKET }));
    const files = (data.Contents || [])
      .map(obj => ({ name: obj.Key, size: obj.Size, modified: obj.LastModified }))
      .sort((a, b) => new Date(b.modified) - new Date(a.modified));
    res.json(files);
  } catch (err) {
    console.error('List error:', err);
    res.status(500).json({ error: 'Failed to list files' });
  }
});

// ── API: Upload files ─────────────────────────────────────────────────────────

app.post('/api/upload', requireAuth, upload.array('files', 50), (req, res) => {
  if (!req.files || req.files.length === 0)
    return res.status(400).json({ error: 'No files received' });
  res.json({ success: true, uploaded: req.files.map(f => f.key) });
});

// ── API: Download (signed URL, 5-min expiry) ──────────────────────────────────

app.get('/api/download/:filename', requireAuth, async (req, res) => {
  const key = path.basename(req.params.filename);
  try {
    const url = await getSignedUrl(
      s3,
      new GetObjectCommand({
        Bucket: R2_BUCKET,
        Key: key,
        ResponseContentDisposition: `attachment; filename="${key}"`,
      }),
      { expiresIn: 300 }
    );
    res.redirect(url);
  } catch (err) {
    console.error('Download error:', err);
    res.status(404).json({ error: 'File not found' });
  }
});

// ── API: Delete file ──────────────────────────────────────────────────────────

app.delete('/api/files/:filename', requireAuth, async (req, res) => {
  const key = path.basename(req.params.filename);
  try {
    await s3.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key }));
    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// ── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`✓ AugustDuarte running → http://localhost:${PORT}`);
  console.log(`  Upload limit: ${MAX_FILE_SIZE_MB} MB`);
});
