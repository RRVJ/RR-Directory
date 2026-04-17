"""
ReqRoute Directory — Python/Flask backend
  - SQLite, SSE real-time, session auth, bcrypt
  - Default accounts: admin/admin@123, user1/user1
  - No signup — admin-only user management
  - Full resource columns, simplified internal columns
  - Gross margin tracking
"""

import os, json, sqlite3, uuid, re, time, threading, queue, secrets, functools, csv, io
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from flask import Flask, request, jsonify, session, send_from_directory, Response
import bcrypt

# Optional Postgres driver (only required when DATABASE_URL is set)
try:
    import psycopg2
    import psycopg2.extras
    _HAS_PG = True
except ImportError:
    _HAS_PG = False

# ── Load .env ──
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

PORT = int(os.environ.get('PORT', 3000))
DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
USE_POSTGRES = bool(DATABASE_URL)
if USE_POSTGRES and not _HAS_PG:
    raise RuntimeError('DATABASE_URL is set but psycopg2 is not installed. Run: pip install psycopg2-binary')
# Normalize old-style postgres:// URLs
if USE_POSTGRES and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = 'postgresql://' + DATABASE_URL[len('postgres://'):]
# Use /data (Render persistent disk) if available, otherwise local
_data_dir = Path('/data') if Path('/data').exists() else Path(__file__).parent
DB_PATH = _data_dir / 'reqroute.db'

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SECURE_COOKIES', '') == 'true',
    PERMANENT_SESSION_LIFETIME=86400,
)

# ── Rate Limiter ──
rate_limit_store = {}
def rate_limit(max_requests=60):
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr or 'unknown'
            key = f"{ip}:{f.__name__}"
            now = time.time()
            entry = rate_limit_store.get(key, {'count': 0, 'start': now})
            if now - entry['start'] > 60:
                entry = {'count': 0, 'start': now}
            entry['count'] += 1
            rate_limit_store[key] = entry
            if entry['count'] > max_requests:
                return jsonify(error='Too many requests. Please wait.'), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ── Security Headers ──
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
    )
    return response

# ── Input Validation ──
MAX_FIELD_LEN = 500
MAX_NOTES_LEN = 5000
def sanitize_str(val, max_len=MAX_FIELD_LEN):
    if val is None: return None
    s = str(val).strip()
    return s[:max_len] if s else None

# ── Database dialect abstraction ──
# We write SQL using SQLite syntax (? placeholders, datetime('now'))
# and translate to Postgres at execute-time when DATABASE_URL is set.

def _translate_sql(sql):
    """Translate SQLite-flavored SQL to Postgres at execute-time."""
    # datetime('now') -> CURRENT_TIMESTAMP (match both quote styles)
    sql = re.sub(r"datetime\(\s*['\"]now['\"]\s*\)", "CURRENT_TIMESTAMP", sql, flags=re.IGNORECASE)
    # ? placeholders -> %s (but don't touch ? inside string literals; we don't use any)
    sql = sql.replace('?', '%s')
    return sql

class _PGCursorWrapper:
    """Makes psycopg2 cursor/connection mimic sqlite3 enough for our code."""
    def __init__(self, conn):
        self._conn = conn
        self._cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        self._last_rowcount = 0

    def execute(self, sql, params=()):
        self._cur.execute(_translate_sql(sql), tuple(params) if params else None)
        self._last_rowcount = self._cur.rowcount
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def close(self):
        self._cur.close()

class _PGConnWrapper:
    def __init__(self):
        self._conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        self._conn.autocommit = False

    def execute(self, sql, params=()):
        cur = _PGCursorWrapper(self._conn)
        return cur.execute(sql, params)

    def executescript(self, script):
        cur = self._conn.cursor()
        cur.execute(script)
        cur.close()
        self._conn.commit()

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try: self._conn.close()
        except: pass

def get_db():
    if USE_POSTGRES:
        return _PGConnWrapper()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

# Schema — use TEXT for everything so SQLite and Postgres both accept it
_SCHEMA_STATEMENTS = [
    '''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''',
    '''CREATE TABLE IF NOT EXISTS resources (
        id TEXT PRIMARY KEY,
        type TEXT,
        name TEXT NOT NULL,
        client TEXT, project TEXT,
        status TEXT DEFAULT 'Active',
        start_date TEXT, end_date TEXT,
        vendor_name TEXT, vendor_phone TEXT, vendor_email TEXT,
        fe_rate_regular TEXT, be_rate_regular TEXT, gross_margin TEXT,
        notes TEXT,
        -- legacy columns kept for backwards-compat with old rows
        counter TEXT, s_no TEXT, month_added TEXT,
        type_of_hire TEXT, skill_set TEXT,
        contractor_phone TEXT, contractor_email TEXT,
        jc_cats TEXT, candidate_cats TEXT, assignment_no TEXT,
        contract_status TEXT,
        customer TEXT, client_contact TEXT,
        client_employee_id TEXT, client_po_number TEXT,
        client_timesheet_cycle TEXT, client_payment_terms TEXT,
        invoicing_type TEXT, rate_type TEXT,
        fe_rate_ot TEXT, be_rate_ot TEXT,
        expenses_paid TEXT, hc TEXT, hc_cost_month TEXT,
        per_diem_rate TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_by TEXT
    )''',
    '''CREATE TABLE IF NOT EXISTS employees (
        id TEXT PRIMARY KEY,
        type TEXT,
        name TEXT NOT NULL,
        client TEXT, project TEXT,
        status TEXT DEFAULT 'Active',
        start_date TEXT, end_date TEXT,
        vendor_name TEXT, vendor_phone TEXT, vendor_email TEXT,
        fe_rate_regular TEXT, be_rate_regular TEXT, gross_margin TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_by TEXT
    )'''
]

def _get_existing_columns(conn, table):
    if USE_POSTGRES:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name=?",
            (table,)
        ).fetchall()
        return {r['column_name'] for r in rows}
    # SQLite
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r['name'] for r in rows}

def _ensure_column(conn, table, col, decl):
    if col not in _get_existing_columns(conn, table):
        # No placeholders in DDL — safe because col/decl are hard-coded literals below
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

def migrate_resources(conn):
    """Add simplified columns to resources table & copy from legacy columns."""
    cols = _get_existing_columns(conn, 'resources')
    if not cols:
        return  # Table doesn't exist yet (schema create will handle it)
    # Ensure new columns exist
    _ensure_column(conn, 'resources', 'type', 'TEXT')
    _ensure_column(conn, 'resources', 'project', 'TEXT')
    _ensure_column(conn, 'resources', 'status', 'TEXT')
    # Copy data from legacy columns where new ones are empty
    if 'type_of_hire' in cols:
        conn.execute("UPDATE resources SET type=type_of_hire WHERE (type IS NULL OR type='') AND type_of_hire IS NOT NULL AND type_of_hire<>''")
    if 'contract_status' in cols:
        conn.execute("UPDATE resources SET status=contract_status WHERE (status IS NULL OR status='') AND contract_status IS NOT NULL AND contract_status<>''")
    conn.commit()

def init_db():
    conn = get_db()
    if USE_POSTGRES:
        for stmt in _SCHEMA_STATEMENTS:
            conn.execute(stmt)
        conn.commit()
    else:
        conn.executescript(';\n'.join(_SCHEMA_STATEMENTS) + ';')
    # Run migration for existing tables (adds new columns + backfills)
    migrate_resources(conn)
    # ── Create default accounts ──
    row = conn.execute('SELECT COUNT(*) as cnt FROM users').fetchone()
    existing = row['cnt'] if row else 0
    if existing == 0:
        admin_hash = bcrypt.hashpw(b'admin@123', bcrypt.gensalt()).decode('utf-8')
        user_hash = bcrypt.hashpw(b'user1', bcrypt.gensalt()).decode('utf-8')
        conn.execute('INSERT INTO users (id,username,password,display_name,role) VALUES (?,?,?,?,?)',
                     (str(uuid.uuid4()), 'admin', admin_hash, 'Admin', 'admin'))
        conn.execute('INSERT INTO users (id,username,password,display_name,role) VALUES (?,?,?,?,?)',
                     (str(uuid.uuid4()), 'user1', user_hash, 'User 1', 'user'))
        conn.commit()
    conn.close()

init_db()

# ── SSE ──
sse_queues = []
sse_lock = threading.Lock()

def broadcast(event, data):
    msg = f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
    with sse_lock:
        dead = []
        for q in sse_queues:
            try: q.put_nowait(msg)
            except queue.Full: dead.append(q)
        for q in dead: sse_queues.remove(q)

@app.route('/api/events')
def sse_stream():
    if 'user_id' not in session: return 'Unauthorized', 401
    q = queue.Queue(maxsize=50)
    with sse_lock: sse_queues.append(q)
    def generate():
        yield "data: connected\n\n"
        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit: pass
        finally:
            with sse_lock:
                if q in sse_queues: sse_queues.remove(q)
    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

# ── Auth helpers ──
def require_auth():
    return session.get('user_id')

def get_user_role(uid):
    conn = get_db()
    row = conn.execute('SELECT role FROM users WHERE id=?', (uid,)).fetchone()
    conn.close()
    return row['role'] if row else None

def get_display_name(uid):
    conn = get_db()
    row = conn.execute('SELECT display_name FROM users WHERE id=?', (uid,)).fetchone()
    conn.close()
    return row['display_name'] if row else 'unknown'

# ── Auth Routes (no signup) ──
@app.route('/api/auth/login', methods=['POST'])
@rate_limit(max_requests=15)
def login():
    d = request.json or {}
    username = d.get('username', '').strip()
    pw = d.get('password', '')
    if not username or not pw:
        return jsonify(error='Username and password required'), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    conn.close()
    if not user or not bcrypt.checkpw(pw.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify(error='Invalid username or password'), 401
    session['user_id'] = user['id']
    session.permanent = True
    return jsonify(id=user['id'], username=user['username'], displayName=user['display_name'], role=user['role'])

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify(ok=True)

@app.route('/api/auth/me')
def me():
    if 'user_id' not in session: return jsonify(error='Not authenticated'), 401
    conn = get_db()
    user = conn.execute('SELECT id,username,display_name,role FROM users WHERE id=?', (session['user_id'],)).fetchone()
    conn.close()
    if not user: session.clear(); return jsonify(error='User not found'), 401
    return jsonify(id=user['id'], username=user['username'], displayName=user['display_name'], role=user['role'])

@app.route('/api/auth/change-password', methods=['POST'])
@rate_limit(max_requests=10)
def change_password():
    uid = require_auth()
    if not uid: return jsonify(error='Not authenticated'), 401
    d = request.json or {}
    cur, new = d.get('currentPassword', ''), d.get('newPassword', '')
    if not cur or not new or len(new) < 4:
        return jsonify(error='Password must be at least 4 characters'), 400
    conn = get_db()
    user = conn.execute('SELECT password FROM users WHERE id=?', (uid,)).fetchone()
    if not user or not bcrypt.checkpw(cur.encode('utf-8'), user['password'].encode('utf-8')):
        conn.close(); return jsonify(error='Current password is incorrect'), 401
    hashed = bcrypt.hashpw(new.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn.execute('UPDATE users SET password=? WHERE id=?', (hashed, uid))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.route('/api/users/<tid>/reset-password', methods=['POST'])
@rate_limit(max_requests=10)
def admin_reset_password(tid):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    new = (request.json or {}).get('newPassword', '')
    if not new or len(new) < 4: return jsonify(error='Password must be at least 4 characters'), 400
    conn = get_db()
    hashed = bcrypt.hashpw(new.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn.execute('UPDATE users SET password=? WHERE id=?', (hashed, tid))
    conn.commit(); conn.close()
    return jsonify(ok=True)

# ── Users management ──
@app.route('/api/users')
def list_users():
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    conn = get_db()
    rows = conn.execute('SELECT id,username,display_name,role,created_at FROM users ORDER BY created_at').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/users', methods=['POST'])
@rate_limit(max_requests=20)
def create_user():
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    d = request.json or {}
    username = sanitize_str(d.get('username', ''), 50)
    display_name = sanitize_str(d.get('display_name', ''), 100)
    password = d.get('password', '')
    role = d.get('role', 'user')
    if not username or not password or not display_name:
        return jsonify(error='Username, display name and password are required'), 400
    if len(password) < 4:
        return jsonify(error='Password must be at least 4 characters'), 400
    if role not in ('admin', 'user'):
        role = 'user'
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return jsonify(error='Username can only contain letters, numbers, dots, dashes, underscores'), 400
    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify(error='Username already exists'), 409
    new_id = str(uuid.uuid4())
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn.execute('INSERT INTO users (id,username,password,display_name,role) VALUES (?,?,?,?,?)',
                 (new_id, username, hashed, display_name, role))
    conn.commit(); conn.close()
    return jsonify(id=new_id, username=username, display_name=display_name, role=role)

@app.route('/api/users/<tid>', methods=['DELETE'])
def delete_user(tid):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    if tid == uid: return jsonify(error='Cannot delete yourself'), 400
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id=?', (tid,))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.route('/api/users/<tid>/role', methods=['PUT'])
def update_role(tid):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    if tid == uid: return jsonify(error='Cannot change your own role'), 400
    role = (request.json or {}).get('role', 'user')
    if role not in ('admin', 'user'): return jsonify(error='Invalid role'), 400
    conn = get_db()
    conn.execute('UPDATE users SET role=? WHERE id=?', (role, tid))
    conn.commit(); conn.close()
    return jsonify(ok=True)

# ── Resources CRUD ──
# Unified 13-field schema (same fields for resources & employees)
RESOURCE_COLS = ['type','name','client','project','status','start_date','end_date',
    'vendor_name','vendor_phone','vendor_email','fe_rate_regular','be_rate_regular',
    'gross_margin','notes']

def _calc_gm_if_missing(vals):
    """Preserve provided gross_margin; calculate only if absent."""
    if vals.get('gross_margin'):
        return
    try:
        bill = float(vals.get('fe_rate_regular') or 0)
        pay = float(vals.get('be_rate_regular') or 0)
        if bill or pay:
            vals['gross_margin'] = str(round(bill - pay, 2))
    except Exception:
        pass

def _signature(vals, cols):
    """Stable signature for duplicate detection — normalized on all business fields."""
    parts = []
    for c in cols:
        v = vals.get(c)
        parts.append('' if v is None else str(v).strip().lower())
    return '|'.join(parts)

@app.route('/api/resources')
def list_resources():
    uid = require_auth()
    if not uid: return jsonify(error='Not authenticated'), 401
    conn = get_db()
    rows = conn.execute('SELECT * FROM resources ORDER BY name ASC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/resources', methods=['POST'])
def add_resource():
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    d = request.json or {}
    if not d.get('name'): return jsonify(error='Name is required'), 400
    eid = str(uuid.uuid4())
    uname = get_display_name(uid)
    vals = {c: sanitize_str(d.get(c)) for c in RESOURCE_COLS}
    _calc_gm_if_missing(vals)
    conn = get_db()
    cols_str = ','.join(RESOURCE_COLS)
    placeholders = ','.join(['?'] * len(RESOURCE_COLS))
    conn.execute(f'INSERT INTO resources (id,{cols_str},updated_by) VALUES (?,{placeholders},?)',
                 [eid] + [vals[c] for c in RESOURCE_COLS] + [uname])
    conn.commit()
    emp = dict(conn.execute('SELECT * FROM resources WHERE id=?', (eid,)).fetchone())
    conn.close()
    broadcast('data-change', {'action': 'add', 'type': 'resource', 'record': emp})
    return jsonify(emp)

@app.route('/api/resources/<eid>', methods=['PUT'])
def update_resource(eid):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    d = request.json or {}
    if not d.get('name'): return jsonify(error='Name is required'), 400
    uname = get_display_name(uid)
    vals = {c: sanitize_str(d.get(c)) for c in RESOURCE_COLS}
    _calc_gm_if_missing(vals)
    sets = ','.join([f'{c}=?' for c in RESOURCE_COLS])
    conn = get_db()
    conn.execute(f"UPDATE resources SET {sets},updated_at=datetime('now'),updated_by=? WHERE id=?",
                 [vals[c] for c in RESOURCE_COLS] + [uname, eid])
    conn.commit()
    emp = dict(conn.execute('SELECT * FROM resources WHERE id=?', (eid,)).fetchone())
    conn.close()
    broadcast('data-change', {'action': 'update', 'type': 'resource', 'record': emp})
    return jsonify(emp)

@app.route('/api/resources/<eid>', methods=['DELETE'])
def delete_resource(eid):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    conn = get_db()
    conn.execute('DELETE FROM resources WHERE id=?', (eid,))
    conn.commit(); conn.close()
    broadcast('data-change', {'action': 'delete', 'type': 'resource', 'id': eid})
    return jsonify(ok=True)

@app.route('/api/gsheet/fetch', methods=['POST'])
@rate_limit(max_requests=10)
def fetch_gsheet():
    """Fetch a Google Sheet as CSV and return parsed rows for column mapping."""
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin':
        return jsonify(error='Admin access required'), 403
    d = request.json or {}
    url = (d.get('url') or '').strip()
    if not url:
        return jsonify(error='Google Sheet URL is required'), 400

    # Extract sheet ID from various Google Sheets URL formats
    sheet_id = None
    m = re.search(r'/spreadsheets/d/([a-zA-Z0-9_-]+)', url)
    if m:
        sheet_id = m.group(1)
    if not sheet_id:
        return jsonify(error='Invalid Google Sheets URL. Use the share link from Google Sheets.'), 400

    # Extract gid (sheet tab) if present
    gid = '0'
    gid_match = re.search(r'[#&?]gid=(\d+)', url)
    if gid_match:
        gid = gid_match.group(1)

    csv_url = f'https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}'

    try:
        req = Request(csv_url, headers={
            'User-Agent': 'Mozilla/5.0 ReqRoute/1.0'
        })
        response = urlopen(req, timeout=30)
        raw = response.read().decode('utf-8-sig')
    except HTTPError as e:
        if e.code == 401 or e.code == 403:
            return jsonify(error='Cannot access this sheet. Make sure sharing is set to "Anyone with the link" → Viewer.'), 403
        return jsonify(error=f'Failed to fetch sheet (HTTP {e.code})'), 500
    except URLError as e:
        return jsonify(error=f'Network error: {str(e.reason)}'), 500
    except Exception as e:
        return jsonify(error=f'Failed to fetch: {str(e)}'), 500

    # Parse CSV
    try:
        reader = csv.reader(io.StringIO(raw))
        rows = list(reader)
    except Exception as e:
        return jsonify(error=f'Failed to parse CSV: {str(e)}'), 500

    if len(rows) < 2:
        return jsonify(error='Sheet appears empty (no data rows found)'), 400
    if len(rows) > 5000:
        rows = rows[:5001]  # header + 5000 data rows

    return jsonify(headers=rows[0], rows=rows[1:], total=len(rows)-1)

@app.route('/api/resources/import', methods=['POST'])
def import_resources():
    return _do_import('resources', RESOURCE_COLS)

# ── Employees CRUD ──
EMP_COLS = ['type','name','client','project','status','start_date','end_date','vendor_name','vendor_phone','vendor_email','fe_rate_regular','be_rate_regular','gross_margin','notes']

@app.route('/api/employees')
def list_employees():
    uid = require_auth()
    if not uid: return jsonify(error='Not authenticated'), 401
    conn = get_db()
    rows = conn.execute('SELECT * FROM employees ORDER BY name ASC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/employees', methods=['POST'])
def add_employee():
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    d = request.json or {}
    if not d.get('name'): return jsonify(error='Name is required'), 400
    eid = str(uuid.uuid4())
    uname = get_display_name(uid)
    vals = {c: sanitize_str(d.get(c)) for c in EMP_COLS}
    _calc_gm_if_missing(vals)
    conn = get_db()
    cols_str = ','.join(EMP_COLS)
    placeholders = ','.join(['?'] * len(EMP_COLS))
    conn.execute(f'INSERT INTO employees (id,{cols_str},updated_by) VALUES (?,{placeholders},?)',
                 [eid] + [vals[c] for c in EMP_COLS] + [uname])
    conn.commit()
    emp = dict(conn.execute('SELECT * FROM employees WHERE id=?', (eid,)).fetchone())
    conn.close()
    broadcast('data-change', {'action': 'add', 'type': 'employee', 'record': emp})
    return jsonify(emp)

@app.route('/api/employees/<eid>', methods=['PUT'])
def update_employee(eid):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    d = request.json or {}
    if not d.get('name'): return jsonify(error='Name is required'), 400
    uname = get_display_name(uid)
    vals = {c: sanitize_str(d.get(c)) for c in EMP_COLS}
    _calc_gm_if_missing(vals)
    sets = ','.join([f'{c}=?' for c in EMP_COLS])
    conn = get_db()
    conn.execute(f"UPDATE employees SET {sets},updated_at=datetime('now'),updated_by=? WHERE id=?",
                 [vals[c] for c in EMP_COLS] + [uname, eid])
    conn.commit()
    emp = dict(conn.execute('SELECT * FROM employees WHERE id=?', (eid,)).fetchone())
    conn.close()
    broadcast('data-change', {'action': 'update', 'type': 'employee', 'record': emp})
    return jsonify(emp)

@app.route('/api/employees/<eid>', methods=['DELETE'])
def delete_employee(eid):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    conn = get_db()
    conn.execute('DELETE FROM employees WHERE id=?', (eid,))
    conn.commit(); conn.close()
    broadcast('data-change', {'action': 'delete', 'type': 'employee', 'id': eid})
    return jsonify(ok=True)

@app.route('/api/employees/import', methods=['POST'])
def import_employees():
    return _do_import('employees', EMP_COLS)

def _do_import(table, cols):
    """Unified import handler with dedup + upsert support.

    Request body:
      - rows: list of row dicts
      - mode: 'add' (default, skip exact duplicates)
            | 'update' (only update matching name+client, skip if not found)
            | 'replace' (delete all then insert)
    Response: { imported, updated, skipped_duplicate, not_found, new_ids }
    """
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    body = request.json or {}
    rows = body.get('rows', [])
    mode = body.get('mode', 'add')
    if mode not in ('add', 'update', 'replace'):
        mode = 'add'
    if len(rows) > 5000:
        return jsonify(error='Max 5000 rows'), 400
    uname = get_display_name(uid)
    singular = 'resource' if table == 'resources' else 'employee'

    conn = get_db()

    if mode == 'replace':
        conn.execute(f'DELETE FROM {table}')

    # Preload existing rows for dedup / match lookups
    existing = conn.execute(f'SELECT * FROM {table}').fetchall()
    existing_by_sig = {}
    existing_by_key = {}  # match key for upsert: name+client (lowercased)
    for r in existing:
        rd = dict(r)
        existing_by_sig[_signature(rd, cols)] = rd['id']
        key = f"{(rd.get('name') or '').strip().lower()}|{(rd.get('client') or '').strip().lower()}|{(rd.get('start_date') or '').strip()}"
        existing_by_key[key] = rd['id']

    cols_str = ','.join(cols)
    placeholders = ','.join(['?'] * len(cols))
    sets_sql = ','.join([f'{c}=?' for c in cols])

    imported = 0
    updated = 0
    skipped_duplicate = 0
    not_found = 0
    new_ids = []
    seen_sigs_this_batch = set()

    for r in rows:
        if not r.get('name'):
            continue
        vals = {c: sanitize_str(r.get(c)) for c in cols}
        _calc_gm_if_missing(vals)
        sig = _signature(vals, cols)
        key = f"{(vals.get('name') or '').strip().lower()}|{(vals.get('client') or '').strip().lower()}|{(vals.get('start_date') or '').strip()}"

        if mode == 'update':
            # Only update existing matching records; do not insert new ones
            target_id = existing_by_key.get(key)
            if not target_id:
                not_found += 1
                continue
            conn.execute(
                f"UPDATE {table} SET {sets_sql}, updated_at=datetime('now'), updated_by=? WHERE id=?",
                [vals[c] for c in cols] + [uname, target_id]
            )
            updated += 1
            continue

        # mode == 'add' (also post-replace)
        # Skip exact duplicates (against existing DB AND against rows earlier in this batch)
        if sig in existing_by_sig or sig in seen_sigs_this_batch:
            skipped_duplicate += 1
            continue
        seen_sigs_this_batch.add(sig)
        new_id = str(uuid.uuid4())
        conn.execute(
            f'INSERT INTO {table} (id,{cols_str},updated_by) VALUES (?,{placeholders},?)',
            [new_id] + [vals[c] for c in cols] + [uname]
        )
        imported += 1
        new_ids.append(new_id)

    conn.commit()
    all_rows = [dict(r) for r in conn.execute(f'SELECT * FROM {table} ORDER BY name').fetchall()]
    conn.close()
    broadcast('data-change', {'action': 'reload', 'type': singular, 'records': all_rows})
    return jsonify(
        imported=imported,
        updated=updated,
        skipped_duplicate=skipped_duplicate,
        not_found=not_found,
        new_ids=new_ids,
        mode=mode,
    )

# ── Detail API (for new-tab view) ──
@app.route('/api/resources/<eid>/detail')
def resource_detail(eid):
    uid = require_auth()
    if not uid: return jsonify(error='Not authenticated'), 401
    conn = get_db()
    row = conn.execute('SELECT * FROM resources WHERE id=?', (eid,)).fetchone()
    conn.close()
    if not row: return jsonify(error='Not found'), 404
    return jsonify(dict(row))

@app.route('/api/employees/<eid>/detail')
def employee_detail(eid):
    uid = require_auth()
    if not uid: return jsonify(error='Not authenticated'), 401
    conn = get_db()
    row = conn.execute('SELECT * FROM employees WHERE id=?', (eid,)).fetchone()
    conn.close()
    if not row: return jsonify(error='Not found'), 404
    return jsonify(dict(row))

# ── Serve frontend ──
@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/detail')
def detail_page():
    return send_from_directory('public', 'detail.html')

if __name__ == '__main__':
    print(f'\n  ReqRoute Directory running at http://localhost:{PORT}')
    print(f'  Default accounts: admin/admin@123, user1/user1\n')
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
