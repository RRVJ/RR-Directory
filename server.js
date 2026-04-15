const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const Anthropic = require('@anthropic-ai/sdk');
const path = require('path');

// ── Load .env manually (no dotenv dependency) ──
const fs = require('fs');
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim();
        const val = trimmed.slice(eqIdx + 1).trim();
        if (!process.env[key]) process.env[key] = val;
      }
    }
  });
}

const PORT = process.env.PORT || 3000;
const app = express();

// ── Middleware ──
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'reqroute-default-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// ── SQLite Database ──
const db = new Database(path.join(__dirname, 'reqroute.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS employees (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL DEFAULT 'internal',
    name TEXT NOT NULL,
    title TEXT,
    department TEXT,
    email TEXT,
    phone TEXT,
    location TEXT,
    manager TEXT,
    employee_id TEXT,
    start_date TEXT,
    end_date TEXT,
    status TEXT DEFAULT 'Active',
    client_name TEXT,
    vendor_name TEXT,
    process_name TEXT,
    bill_rate TEXT,
    pay_rate TEXT,
    recruiter TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    updated_by TEXT
  );

  CREATE TABLE IF NOT EXISTS ai_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    timestamp TEXT DEFAULT (datetime('now')),
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    model TEXT,
    cost_usd REAL DEFAULT 0
  );
`);

// ── SSE: Real-time updates ──
const sseClients = new Set();

function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    res.write(msg);
  }
}

app.get('/api/events', (req, res) => {
  if (!req.session.userId) return res.status(401).end();
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });
  res.write(`data: connected\n\n`);
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

// ── Auth helpers ──
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ── Auth Routes ──
app.post('/api/auth/signup', (req, res) => {
  const { email, password, displayName } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const userCount = db.prepare('SELECT COUNT(*) as cnt FROM users').get().cnt;
  const role = userCount === 0 ? 'admin' : 'user';
  const id = uuidv4();
  const hash = bcrypt.hashSync(password, 10);
  const name = displayName || email.split('@')[0];

  db.prepare('INSERT INTO users (id, email, password, display_name, role) VALUES (?, ?, ?, ?, ?)')
    .run(id, email, hash, name, role);

  req.session.userId = id;
  res.json({ id, email, displayName: name, role, firstUser: role === 'admin' });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  req.session.userId = user.id;
  res.json({ id: user.id, email: user.email, displayName: user.display_name, role: user.role });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const user = db.prepare('SELECT id, email, display_name, role FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'User not found' });
  res.json({ id: user.id, email: user.email, displayName: user.display_name, role: user.role });
});

// ── Employee CRUD ──
app.get('/api/employees', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM employees ORDER BY name ASC').all();
  res.json(rows);
});

app.post('/api/employees', requireAdmin, (req, res) => {
  const d = req.body;
  const id = uuidv4();
  const user = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.session.userId);
  db.prepare(`INSERT INTO employees (id, type, name, title, department, email, phone, location, manager,
    employee_id, start_date, end_date, status, client_name, vendor_name, process_name, bill_rate, pay_rate,
    recruiter, notes, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, d.type || 'internal', d.name, d.title, d.department, d.email, d.phone, d.location, d.manager,
      d.employeeId, d.startDate, d.endDate, d.status || 'Active', d.clientName, d.vendorName, d.processName,
      d.billRate, d.payRate, d.recruiter, d.notes, user?.display_name);
  const emp = db.prepare('SELECT * FROM employees WHERE id = ?').get(id);
  broadcast('employee-change', { action: 'add', employee: emp });
  res.json(emp);
});

app.put('/api/employees/:id', requireAdmin, (req, res) => {
  const d = req.body;
  const user = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.session.userId);
  db.prepare(`UPDATE employees SET name=?, title=?, department=?, email=?, phone=?, location=?, manager=?,
    employee_id=?, start_date=?, end_date=?, status=?, client_name=?, vendor_name=?, process_name=?,
    bill_rate=?, pay_rate=?, recruiter=?, notes=?, updated_at=datetime('now'), updated_by=? WHERE id=?`)
    .run(d.name, d.title, d.department, d.email, d.phone, d.location, d.manager,
      d.employeeId, d.startDate, d.endDate, d.status, d.clientName, d.vendorName, d.processName,
      d.billRate, d.payRate, d.recruiter, d.notes, user?.display_name, req.params.id);
  const emp = db.prepare('SELECT * FROM employees WHERE id = ?').get(req.params.id);
  broadcast('employee-change', { action: 'update', employee: emp });
  res.json(emp);
});

app.delete('/api/employees/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM employees WHERE id = ?').run(req.params.id);
  broadcast('employee-change', { action: 'delete', id: req.params.id });
  res.json({ ok: true });
});

app.post('/api/employees/import', requireAdmin, (req, res) => {
  const { rows, type } = req.body;
  const user = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.session.userId);
  const insert = db.prepare(`INSERT INTO employees (id, type, name, title, department, email, phone, location, manager,
    employee_id, start_date, end_date, status, client_name, vendor_name, process_name, bill_rate, pay_rate,
    recruiter, notes, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const tx = db.transaction((rows) => {
    for (const d of rows) {
      if (!d.name) continue;
      insert.run(uuidv4(), type || 'internal', d.name, d.title, d.department, d.email, d.phone, d.location,
        d.manager, d.employeeId, d.startDate, d.endDate, d.status || 'Active', d.clientName, d.vendorName,
        d.processName, d.billRate, d.payRate, d.recruiter, d.notes, user?.display_name);
    }
  });
  tx(rows);
  const all = db.prepare('SELECT * FROM employees ORDER BY name ASC').all();
  broadcast('employee-change', { action: 'reload', employees: all });
  res.json({ imported: rows.filter(r => r.name).length });
});

// ── Users management (admin only) ──
app.get('/api/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, email, display_name, role, created_at FROM users ORDER BY created_at ASC').all();
  res.json(users);
});

app.put('/api/users/:id/role', requireAdmin, (req, res) => {
  const { role } = req.body;
  if (req.params.id === req.session.userId) return res.status(400).json({ error: 'Cannot change your own role' });
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
  res.json({ ok: true });
});

// ── Claude AI Assistant ──
const CLAUDE_MODEL = 'claude-sonnet-4-5-20250514';
const INPUT_COST_PER_M = 3.00;   // $3 per 1M input tokens
const OUTPUT_COST_PER_M = 15.00; // $15 per 1M output tokens

app.post('/api/ai/ask', requireAuth, async (req, res) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || apiKey.includes('XXXX')) {
    return res.status(503).json({ error: 'Claude API key not configured. Add ANTHROPIC_API_KEY to your .env file.' });
  }

  const { question } = req.body;
  if (!question) return res.status(400).json({ error: 'Question required' });

  const employees = db.prepare('SELECT * FROM employees ORDER BY name').all();
  const summary = employees.map(e => {
    const parts = [`Name: ${e.name}`, `Type: ${e.type}`, `Title: ${e.title || 'N/A'}`];
    if (e.department) parts.push(`Dept: ${e.department}`);
    if (e.status) parts.push(`Status: ${e.status}`);
    if (e.client_name) parts.push(`Client: ${e.client_name}`);
    if (e.vendor_name) parts.push(`Vendor: ${e.vendor_name}`);
    if (e.process_name) parts.push(`Project: ${e.process_name}`);
    if (e.location) parts.push(`Location: ${e.location}`);
    if (e.start_date) parts.push(`Start: ${e.start_date}`);
    if (e.email) parts.push(`Email: ${e.email}`);
    return parts.join(' | ');
  }).join('\n');

  const systemPrompt = `You are an AI assistant for the ReqRoute Employee & Resource Directory. You help users query and understand their workforce data. Be concise, helpful, and format responses with markdown when useful.

Current directory data (${employees.length} total records):
${summary || '(No records in directory yet)'}

Answer the user's question based on this data. If the data doesn't contain enough info, say so. For numerical questions, show your count. Use tables when comparing multiple records.`;

  try {
    const client = new Anthropic({ apiKey });
    const response = await client.messages.create({
      model: CLAUDE_MODEL,
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: 'user', content: question }]
    });

    const inputTokens = response.usage.input_tokens;
    const outputTokens = response.usage.output_tokens;
    const cost = (inputTokens / 1_000_000) * INPUT_COST_PER_M + (outputTokens / 1_000_000) * OUTPUT_COST_PER_M;

    db.prepare('INSERT INTO ai_usage (user_id, input_tokens, output_tokens, model, cost_usd) VALUES (?, ?, ?, ?, ?)')
      .run(req.session.userId, inputTokens, outputTokens, CLAUDE_MODEL, cost);

    const answer = response.content.map(c => c.text).join('');
    res.json({ answer, usage: { inputTokens, outputTokens, cost: cost.toFixed(6), model: CLAUDE_MODEL } });
  } catch (err) {
    console.error('Claude API error:', err.message);
    res.status(500).json({ error: 'AI request failed: ' + err.message });
  }
});

app.get('/api/ai/usage', requireAuth, (req, res) => {
  const totals = db.prepare(`SELECT
    COUNT(*) as total_queries,
    COALESCE(SUM(input_tokens), 0) as total_input_tokens,
    COALESCE(SUM(output_tokens), 0) as total_output_tokens,
    COALESCE(SUM(cost_usd), 0) as total_cost
    FROM ai_usage`).get();

  const today = db.prepare(`SELECT
    COUNT(*) as queries,
    COALESCE(SUM(cost_usd), 0) as cost
    FROM ai_usage WHERE date(timestamp) = date('now')`).get();

  const recent = db.prepare(`SELECT ai_usage.*, users.display_name
    FROM ai_usage JOIN users ON ai_usage.user_id = users.id
    ORDER BY timestamp DESC LIMIT 20`).all();

  res.json({ totals, today, recent, model: CLAUDE_MODEL, pricing: { inputPerMillion: INPUT_COST_PER_M, outputPerMillion: OUTPUT_COST_PER_M } });
});

// ── Start ──
app.listen(PORT, () => {
  console.log(`\n  ReqRoute Directory running at http://localhost:${PORT}\n`);
  console.log(`  Share this URL on your local network for others to access.`);
  console.log(`  First user to sign up gets admin access.\n`);
});
