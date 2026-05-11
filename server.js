const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';
const AUTH_USER = process.env.AUTH_USER || 'admin';
const AUTH_PASS = process.env.AUTH_PASS || 'changeme';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || 'claude-haiku-4-5-20251001';

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------
const DATA_DIR = process.env.NODE_ENV === 'production' ? '/data' : path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new Database(path.join(DATA_DIR, 'fitdash.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS kv_store (
    key   TEXT PRIMARY KEY,
    value TEXT
  )
`);

// ---------------------------------------------------------------------------
// SQLite session store (survives server restarts / Fly suspends)
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    sid     TEXT PRIMARY KEY,
    data    TEXT NOT NULL,
    expires INTEGER NOT NULL
  )
`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)`);

const sessGet = db.prepare('SELECT data, expires FROM sessions WHERE sid = ?');
const sessSet = db.prepare(`
  INSERT INTO sessions (sid, data, expires) VALUES (?, ?, ?)
  ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires = excluded.expires
`);
const sessDel = db.prepare('DELETE FROM sessions WHERE sid = ?');
const sessClean = db.prepare('DELETE FROM sessions WHERE expires < ?');

class SQLiteStore extends session.Store {
  get(sid, cb) {
    try {
      const row = sessGet.get(sid);
      if (!row) return cb(null, null);
      if (row.expires < Date.now()) { sessDel.run(sid); return cb(null, null); }
      cb(null, JSON.parse(row.data));
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const maxAge = (sess.cookie && sess.cookie.maxAge) || 7 * 24 * 60 * 60 * 1000;
      const expires = Date.now() + maxAge;
      sessSet.run(sid, JSON.stringify(sess), expires);
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
  destroy(sid, cb) {
    try { sessDel.run(sid); cb && cb(null); } catch (e) { cb && cb(e); }
  }
}

// Clean expired sessions every hour
setInterval(() => { try { sessClean.run(Date.now()); } catch (_) {} }, 60 * 60 * 1000);

// ---------------------------------------------------------------------------
// Automatic SQLite backups — keep last 7 daily copies
// ---------------------------------------------------------------------------
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

function createBackup() {
  try {
    const stamp = new Date().toISOString().slice(0, 10);
    const dest = path.join(BACKUP_DIR, `fitdash-${stamp}.db`);
    db.backup(dest).then(() => {
      console.log('Backup created:', dest);
      // Prune old backups, keep last 7
      const files = fs.readdirSync(BACKUP_DIR)
        .filter(f => f.startsWith('fitdash-') && f.endsWith('.db'))
        .sort();
      while (files.length > 7) {
        const old = files.shift();
        fs.unlinkSync(path.join(BACKUP_DIR, old));
        console.log('Pruned old backup:', old);
      }
    }).catch(err => console.error('Backup failed:', err));
  } catch (err) {
    console.error('Backup error:', err);
  }
}

// Backup on startup, then every 6 hours
createBackup();
setInterval(createBackup, 6 * 60 * 60 * 1000);

// Prepared statements for performance
const stmtGet = db.prepare('SELECT value FROM kv_store WHERE key = ?');
const stmtGetAll = db.prepare('SELECT key, value FROM kv_store');
const stmtUpsert = db.prepare(`
  INSERT INTO kv_store (key, value) VALUES (?, ?)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value
`);
const stmtDelete = db.prepare('DELETE FROM kv_store WHERE key = ?');

// ---------------------------------------------------------------------------
// Hash password at startup
// ---------------------------------------------------------------------------
let passwordHash;
const hashReady = bcrypt.hash(AUTH_PASS, 10).then(h => { passwordHash = h; });

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();

app.set('trust proxy', 1);
app.use(express.json({ limit: '12mb' }));

app.use(session({
  store: new SQLiteStore(),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  }
}));

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

// ---------------------------------------------------------------------------
// Login / Logout
// ---------------------------------------------------------------------------
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(401).json({ error: 'Missing credentials' });
    }
    if (username !== AUTH_USER) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const match = await bcrypt.compare(password, passwordHash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.authenticated = true;
    return res.json({ ok: true });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// Protected data API
// ---------------------------------------------------------------------------
app.get('/api/data', requireAuth, (_req, res) => {
  try {
    const rows = stmtGetAll.all();
    const result = {};
    for (const row of rows) {
      try {
        result[row.key] = JSON.parse(row.value);
      } catch {
        result[row.key] = row.value;
      }
    }
    return res.json(result);
  } catch (err) {
    console.error('GET /api/data error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/data/:key', requireAuth, (req, res) => {
  try {
    const row = stmtGet.get(req.params.key);
    if (!row) {
      return res.json([]);
    }
    try {
      return res.json(JSON.parse(row.value));
    } catch {
      return res.json(row.value);
    }
  } catch (err) {
    console.error('GET /api/data/:key error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/data/:key', requireAuth, (req, res) => {
  try {
    const value = JSON.stringify(req.body.value);
    stmtUpsert.run(req.params.key, value);
    return res.json({ ok: true });
  } catch (err) {
    console.error('PUT /api/data/:key error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/backup', requireAuth, (_req, res) => {
  try {
    const rows = stmtGetAll.all();
    const result = {};
    for (const row of rows) {
      try { result[row.key] = JSON.parse(row.value); } catch { result[row.key] = row.value; }
    }
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-');
    res.setHeader('Content-Disposition', `attachment; filename="fitdash-backup-${stamp}.json"`);
    res.setHeader('Content-Type', 'application/json');
    return res.json(result);
  } catch (err) {
    console.error('GET /api/backup error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/data/:key', requireAuth, (req, res) => {
  try {
    stmtDelete.run(req.params.key);
    return res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/data/:key error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// AI Assistant — Claude API integration
// ---------------------------------------------------------------------------
const AI_SYSTEM_PROMPT = `You are a nutrition assistant for a personal food log. The user will describe food they ate or send a photo of a meal. Your job is to identify each distinct food item and estimate its nutrition: calories, protein (g), carbs (g), fat (g).

Rules:
- Return JSON only, no markdown fences, no commentary.
- Schema: {"items": [{"type": "Breakfast"|"Lunch"|"Dinner"|"Snack", "desc": string, "cal": number, "protein": number, "carbs": number, "fat": number}]}
- Use typical serving sizes when not specified. Round to whole numbers.
- "type" should match the meal time mentioned by the user; if none mentioned, infer from food (cereal/eggs/oatmeal=Breakfast, sandwich/salad=Lunch, full plate with protein+side=Dinner, bar/yogurt/fruit=Snack).
- If the user specifies a quantity (e.g. "2 bagels"), multiply macros accordingly and put "x2" in the desc.
- Combine items only when they form a single named dish (e.g. "PB&J sandwich"). Keep separate plate components separate (chicken, rice, broccoli = 3 items).
- If nothing food-related is found, return {"items": []}.`;

async function callClaude(messages, maxTokens = 1024) {
  if (!ANTHROPIC_API_KEY) {
    throw new Error('ANTHROPIC_API_KEY not configured on server');
  }
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: maxTokens,
      system: [{ type: 'text', text: AI_SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
      messages
    })
  });
  if (!resp.ok) {
    const errText = await resp.text();
    console.error('Claude API error:', resp.status, errText);
    let detail = errText;
    try { detail = JSON.parse(errText).error?.message || errText; } catch (_) {}
    throw new Error(`Claude API ${resp.status}: ${detail}`);
  }
  const data = await resp.json();
  const text = (data.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
  return text;
}

function parseAIResponse(text) {
  // Strip optional markdown fences
  let cleaned = text.trim();
  const fenceMatch = cleaned.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) cleaned = fenceMatch[1].trim();
  // Find first { and last }
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start === -1 || end === -1) throw new Error('No JSON object in response');
  const parsed = JSON.parse(cleaned.slice(start, end + 1));
  if (!parsed || !Array.isArray(parsed.items)) throw new Error('Missing items array');
  return parsed.items;
}

app.post('/api/ai/parse-food', requireAuth, async (req, res) => {
  try {
    const { text } = req.body || {};
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return res.status(400).json({ error: 'Missing text' });
    }
    if (text.length > 2000) {
      return res.status(400).json({ error: 'Text too long' });
    }
    const reply = await callClaude([
      { role: 'user', content: text.trim() }
    ], 1024);
    const items = parseAIResponse(reply);
    return res.json({ items });
  } catch (err) {
    console.error('parse-food error:', err);
    return res.status(500).json({ error: err.message || 'AI request failed' });
  }
});

app.post('/api/ai/analyze-photo', requireAuth, async (req, res) => {
  try {
    const { image, mediaType } = req.body || {};
    if (!image || typeof image !== 'string') {
      return res.status(400).json({ error: 'Missing image' });
    }
    // Accept either data URL or raw base64
    let base64 = image;
    let detectedType = mediaType || 'image/jpeg';
    const dataMatch = image.match(/^data:([^;]+);base64,(.+)$/);
    if (dataMatch) {
      detectedType = dataMatch[1];
      base64 = dataMatch[2];
    }
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowed.includes(detectedType)) {
      return res.status(400).json({ error: 'Unsupported image type' });
    }
    if (base64.length > 14 * 1024 * 1024) {
      return res.status(400).json({ error: 'Image too large' });
    }
    const reply = await callClaude([
      {
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: detectedType, data: base64 } },
          { type: 'text', text: 'Identify each food item in this photo and estimate its nutrition. Return JSON per the schema.' }
        ]
      }
    ], 1024);
    const items = parseAIResponse(reply);
    return res.json({ items });
  } catch (err) {
    console.error('analyze-photo error:', err);
    return res.status(500).json({ error: err.message || 'AI request failed' });
  }
});

// ---------------------------------------------------------------------------
// Static files & auth redirect
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
  return res.redirect('/login.html');
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
hashReady.then(() => {
  app.listen(PORT, () => {
    console.log(`FitDash server listening on port ${PORT}`);
  });
});
