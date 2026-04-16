"""
ReqRoute Directory — Python/Flask backend
  - SQLite, SSE real-time, session auth, bcrypt
  - Default accounts: admin/admin@123, user1/user1
  - No signup — admin-only user management
  - Full resource columns, simplified internal columns
  - Gross margin tracking
"""

import os, json, sqlite3, uuid, re, time, threading, queue, secrets, functools
from pathlib import Path
from flask import Flask, request, jsonify, session, send_from_directory, Response
import bcrypt

# ── Load .env ──
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

PORT = int(os.environ.get('PORT', 3000))
DB_PATH = Path(__file__).parent / 'reqroute.db'

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

# ── Database ──
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS resources (
            id TEXT PRIMARY KEY,
            counter TEXT,
            s_no TEXT,
            month_added TEXT,
            name TEXT NOT NULL,
            type_of_hire TEXT,
            skill_set TEXT,
            contractor_phone TEXT,
            contractor_email TEXT,
            jc_cats TEXT,
            candidate_cats TEXT,
            assignment_no TEXT,
            start_date TEXT,
            end_date TEXT,
            contract_status TEXT DEFAULT 'Active',
            client TEXT,
            customer TEXT,
            client_contact TEXT,
            client_employee_id TEXT,
            client_po_number TEXT,
            client_timesheet_cycle TEXT,
            client_payment_terms TEXT,
            invoicing_type TEXT,
            rate_type TEXT,
            fe_rate_regular TEXT,
            fe_rate_ot TEXT,
            be_rate_regular TEXT,
            be_rate_ot TEXT,
            expenses_paid TEXT,
            hc TEXT,
            hc_cost_month TEXT,
            per_diem_rate TEXT,
            gross_margin TEXT,
            vendor_name TEXT,
            vendor_email TEXT,
            vendor_phone TEXT,
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            updated_by TEXT
        );
        CREATE TABLE IF NOT EXISTS employees (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            title TEXT,
            department TEXT,
            email TEXT,
            phone TEXT,
            location TEXT,
            manager TEXT,
            employee_id TEXT,
            start_date TEXT,
            status TEXT DEFAULT 'Active',
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            updated_by TEXT
        );
    ''')
    # ── Create default accounts ──
    existing = conn.execute('SELECT COUNT(*) as cnt FROM users').fetchone()['cnt']
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
    msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
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
RESOURCE_COLS = ['counter','s_no','month_added','name','type_of_hire','skill_set','contractor_phone',
    'contractor_email','jc_cats','candidate_cats','assignment_no','start_date','end_date','contract_status',
    'client','customer','client_contact','client_employee_id','client_po_number','client_timesheet_cycle',
    'client_payment_terms','invoicing_type','rate_type','fe_rate_regular','fe_rate_ot','be_rate_regular',
    'be_rate_ot','expenses_paid','hc','hc_cost_month','per_diem_rate','gross_margin','vendor_name',
    'vendor_email','vendor_phone','notes']

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
    # Auto-calculate gross margin
    try:
        bill = float(vals.get('fe_rate_regular') or 0)
        pay = float(vals.get('be_rate_regular') or 0)
        vals['gross_margin'] = str(round(bill - pay, 2))
    except: pass
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
    try:
        bill = float(vals.get('fe_rate_regular') or 0)
        pay = float(vals.get('be_rate_regular') or 0)
        vals['gross_margin'] = str(round(bill - pay, 2))
    except: pass
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

@app.route('/api/resources/import', methods=['POST'])
def import_resources():
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    d = request.json or {}
    rows = d.get('rows', [])
    if len(rows) > 5000: return jsonify(error='Max 5000 rows'), 400
    uname = get_display_name(uid)
    conn = get_db()
    cols_str = ','.join(RESOURCE_COLS)
    placeholders = ','.join(['?'] * len(RESOURCE_COLS))
    imported = 0
    for r in rows:
        if not r.get('name'): continue
        vals = {c: sanitize_str(r.get(c)) for c in RESOURCE_COLS}
        try:
            bill = float(vals.get('fe_rate_regular') or 0)
            pay = float(vals.get('be_rate_regular') or 0)
            vals['gross_margin'] = str(round(bill - pay, 2))
        except: pass
        conn.execute(f'INSERT INTO resources (id,{cols_str},updated_by) VALUES (?,{placeholders},?)',
                     [str(uuid.uuid4())] + [vals[c] for c in RESOURCE_COLS] + [uname])
        imported += 1
    conn.commit()
    all_res = [dict(r) for r in conn.execute('SELECT * FROM resources ORDER BY name').fetchall()]
    conn.close()
    broadcast('data-change', {'action': 'reload', 'type': 'resource', 'records': all_res})
    return jsonify(imported=imported)

# ── Employees CRUD ──
EMP_COLS = ['name','title','department','email','phone','location','manager','employee_id','start_date','status','notes']

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
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin': return jsonify(error='Admin access required'), 403
    rows = (request.json or {}).get('rows', [])
    if len(rows) > 5000: return jsonify(error='Max 5000 rows'), 400
    uname = get_display_name(uid)
    conn = get_db()
    cols_str = ','.join(EMP_COLS)
    placeholders = ','.join(['?'] * len(EMP_COLS))
    imported = 0
    for r in rows:
        if not r.get('name'): continue
        vals = {c: sanitize_str(r.get(c)) for c in EMP_COLS}
        conn.execute(f'INSERT INTO employees (id,{cols_str},updated_by) VALUES (?,{placeholders},?)',
                     [str(uuid.uuid4())] + [vals[c] for c in EMP_COLS] + [uname])
        imported += 1
    conn.commit()
    all_emps = [dict(r) for r in conn.execute('SELECT * FROM employees ORDER BY name').fetchall()]
    conn.close()
    broadcast('data-change', {'action': 'reload', 'type': 'employee', 'records': all_emps})
    return jsonify(imported=imported)

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
