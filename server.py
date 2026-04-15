"""
ReqRoute Directory — Python/Flask backend
  - SQLite for persistence
  - SSE for real-time updates across clients
  - Session-based auth with bcrypt
  - Security: rate limiting, CSRF protection, secure headers, input validation
"""

import os, json, sqlite3, uuid, re, time, threading, queue, secrets, functools
from pathlib import Path
from flask import Flask, request, jsonify, session, send_from_directory, Response, abort

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
    SESSION_COOKIE_HTTPONLY=True,      # JS can't read session cookie
    SESSION_COOKIE_SAMESITE='Lax',     # CSRF protection
    SESSION_COOKIE_SECURE=os.environ.get('SECURE_COOKIES', '') == 'true',  # Set true in production with HTTPS
    PERMANENT_SESSION_LIFETIME=86400,  # 24 hours
)

# ── Security: Rate Limiter ──
rate_limit_store = {}  # ip -> {count, window_start}
RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX = 60       # max requests per window for auth endpoints
RATE_LIMIT_MAX_GENERAL = 200  # for general endpoints

def rate_limit(max_requests=RATE_LIMIT_MAX):
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr or 'unknown'
            key = f"{ip}:{f.__name__}"
            now = time.time()
            entry = rate_limit_store.get(key, {'count': 0, 'start': now})
            if now - entry['start'] > RATE_LIMIT_WINDOW:
                entry = {'count': 0, 'start': now}
            entry['count'] += 1
            rate_limit_store[key] = entry
            if entry['count'] > max_requests:
                return jsonify(error='Too many requests. Please wait a moment.'), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ── Security: Headers ──
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response

# ── Input Validation ──
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
MAX_FIELD_LEN = 500
MAX_NOTES_LEN = 5000

def sanitize_str(val, max_len=MAX_FIELD_LEN):
    if val is None:
        return None
    s = str(val).strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s if s else None

def validate_email(email):
    return bool(email and EMAIL_RE.match(email) and len(email) <= 254)

def validate_password(pw):
    if not pw or len(pw) < 6:
        return False, 'Password must be at least 6 characters'
    if len(pw) > 128:
        return False, 'Password too long'
    return True, ''

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
            title TEXT, department TEXT, email TEXT, phone TEXT,
            location TEXT, manager TEXT, employee_id TEXT,
            start_date TEXT, end_date TEXT,
            status TEXT DEFAULT 'Active',
            client_name TEXT, vendor_name TEXT, process_name TEXT,
            bill_rate TEXT, pay_rate TEXT, recruiter TEXT, notes TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            updated_by TEXT
        );
    ''')
    conn.close()

init_db()

# ── SSE: Real-time updates ──
sse_queues = []
sse_lock = threading.Lock()

def broadcast(event, data):
    msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    with sse_lock:
        dead = []
        for q in sse_queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            sse_queues.remove(q)

@app.route('/api/events')
def sse_stream():
    if 'user_id' not in session:
        return 'Unauthorized', 401
    q = queue.Queue(maxsize=50)
    with sse_lock:
        sse_queues.append(q)
    def generate():
        yield "data: connected\n\n"
        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with sse_lock:
                if q in sse_queues:
                    sse_queues.remove(q)
    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

# ── Auth helpers ──
def require_auth():
    if 'user_id' not in session:
        return None
    return session['user_id']

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

# ── Auth Routes ──
@app.route('/api/auth/signup', methods=['POST'])
@rate_limit(max_requests=10)  # Strict: 10 signups/min per IP
def signup():
    d = request.json or {}
    email = sanitize_str(d.get('email', ''), 254)
    pw = d.get('password', '')
    name = sanitize_str(d.get('displayName', ''), 100)

    if not email or not validate_email(email):
        return jsonify(error='Valid email address required'), 400
    ok, msg = validate_password(pw)
    if not ok:
        return jsonify(error=msg), 400
    if not name:
        name = email.split('@')[0]

    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
        conn.close()
        return jsonify(error='Email already registered'), 409
    count = conn.execute('SELECT COUNT(*) as cnt FROM users').fetchone()['cnt']
    role = 'admin' if count == 0 else 'user'
    uid = str(uuid.uuid4())
    hashed = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn.execute('INSERT INTO users (id,email,password,display_name,role) VALUES (?,?,?,?,?)',
                 (uid, email, hashed, name, role))
    conn.commit()
    conn.close()
    session['user_id'] = uid
    session.permanent = True
    return jsonify(id=uid, email=email, displayName=name, role=role, firstUser=(role == 'admin'))

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(max_requests=15)  # Strict: 15 login attempts/min per IP
def login():
    d = request.json or {}
    email = d.get('email', '').strip()
    pw = d.get('password', '')
    if not email or not pw:
        return jsonify(error='Email and password required'), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    conn.close()
    # Constant-time comparison — don't reveal which field is wrong
    if not user or not bcrypt.checkpw(pw.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify(error='Invalid email or password'), 401
    session['user_id'] = user['id']
    session.permanent = True
    return jsonify(id=user['id'], email=user['email'], displayName=user['display_name'], role=user['role'])

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify(ok=True)

@app.route('/api/auth/me')
def me():
    if 'user_id' not in session:
        return jsonify(error='Not authenticated'), 401
    conn = get_db()
    user = conn.execute('SELECT id,email,display_name,role FROM users WHERE id=?', (session['user_id'],)).fetchone()
    conn.close()
    if not user:
        session.clear()
        return jsonify(error='User not found'), 401
    return jsonify(id=user['id'], email=user['email'], displayName=user['display_name'], role=user['role'])

# ── Change Password (logged-in user) ──
@app.route('/api/auth/change-password', methods=['POST'])
@rate_limit(max_requests=10)
def change_password():
    uid = require_auth()
    if not uid:
        return jsonify(error='Not authenticated'), 401
    d = request.json or {}
    current_pw = d.get('currentPassword', '')
    new_pw = d.get('newPassword', '')
    if not current_pw or not new_pw:
        return jsonify(error='Current and new password required'), 400
    ok, msg = validate_password(new_pw)
    if not ok:
        return jsonify(error=msg), 400
    conn = get_db()
    user = conn.execute('SELECT password FROM users WHERE id=?', (uid,)).fetchone()
    if not user or not bcrypt.checkpw(current_pw.encode('utf-8'), user['password'].encode('utf-8')):
        conn.close()
        return jsonify(error='Current password is incorrect'), 401
    hashed = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn.execute('UPDATE users SET password=? WHERE id=?', (hashed, uid))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

# ── Admin: Reset another user's password ──
@app.route('/api/users/<target_id>/reset-password', methods=['POST'])
@rate_limit(max_requests=10)
def admin_reset_password(target_id):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin':
        return jsonify(error='Admin access required'), 403
    d = request.json or {}
    new_pw = d.get('newPassword', '')
    ok, msg = validate_password(new_pw)
    if not ok:
        return jsonify(error=msg), 400
    conn = get_db()
    target = conn.execute('SELECT id FROM users WHERE id=?', (target_id,)).fetchone()
    if not target:
        conn.close()
        return jsonify(error='User not found'), 404
    hashed = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn.execute('UPDATE users SET password=? WHERE id=?', (hashed, target_id))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

# ── Employees CRUD ──
VALID_TYPES = {'internal', 'resources'}
VALID_STATUSES_INT = {'Active', 'On Leave', 'Inactive'}
VALID_STATUSES_RES = {'Active', 'On Assignment', 'Available', 'Ended'}

def sanitize_employee(d):
    """Sanitize and validate employee input data."""
    emp_type = d.get('type', 'internal')
    if emp_type not in VALID_TYPES:
        emp_type = 'internal'
    status = sanitize_str(d.get('status'))
    valid_statuses = VALID_STATUSES_RES if emp_type == 'resources' else VALID_STATUSES_INT
    if status and status not in valid_statuses:
        status = 'Active'
    return {
        'type': emp_type,
        'name': sanitize_str(d.get('name')),
        'title': sanitize_str(d.get('title')),
        'department': sanitize_str(d.get('department')),
        'email': sanitize_str(d.get('email'), 254),
        'phone': sanitize_str(d.get('phone'), 30),
        'location': sanitize_str(d.get('location')),
        'manager': sanitize_str(d.get('manager')),
        'employeeId': sanitize_str(d.get('employeeId'), 50),
        'startDate': sanitize_str(d.get('startDate'), 20),
        'endDate': sanitize_str(d.get('endDate'), 20),
        'status': status or 'Active',
        'clientName': sanitize_str(d.get('clientName')),
        'vendorName': sanitize_str(d.get('vendorName')),
        'processName': sanitize_str(d.get('processName')),
        'billRate': sanitize_str(d.get('billRate'), 20),
        'payRate': sanitize_str(d.get('payRate'), 20),
        'recruiter': sanitize_str(d.get('recruiter')),
        'notes': sanitize_str(d.get('notes'), MAX_NOTES_LEN),
    }

@app.route('/api/employees')
@rate_limit(max_requests=RATE_LIMIT_MAX_GENERAL)
def list_employees():
    uid = require_auth()
    if not uid:
        return jsonify(error='Not authenticated'), 401
    conn = get_db()
    rows = conn.execute('SELECT * FROM employees ORDER BY name ASC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/employees', methods=['POST'])
@rate_limit(max_requests=60)
def add_employee():
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin':
        return jsonify(error='Admin access required'), 403
    d = sanitize_employee(request.json or {})
    if not d['name']:
        return jsonify(error='Name is required'), 400
    eid = str(uuid.uuid4())
    uname = get_display_name(uid)
    conn = get_db()
    conn.execute('''INSERT INTO employees (id,type,name,title,department,email,phone,location,manager,
        employee_id,start_date,end_date,status,client_name,vendor_name,process_name,bill_rate,pay_rate,
        recruiter,notes,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (eid, d['type'], d['name'], d['title'], d['department'], d['email'], d['phone'],
         d['location'], d['manager'], d['employeeId'], d['startDate'], d['endDate'],
         d['status'], d['clientName'], d['vendorName'], d['processName'],
         d['billRate'], d['payRate'], d['recruiter'], d['notes'], uname))
    conn.commit()
    emp = dict(conn.execute('SELECT * FROM employees WHERE id=?', (eid,)).fetchone())
    conn.close()
    broadcast('employee-change', {'action': 'add', 'employee': emp})
    return jsonify(emp)

@app.route('/api/employees/<eid>', methods=['PUT'])
@rate_limit(max_requests=60)
def update_employee(eid):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin':
        return jsonify(error='Admin access required'), 403
    # Validate UUID format
    try:
        uuid.UUID(eid)
    except ValueError:
        return jsonify(error='Invalid ID'), 400
    d = sanitize_employee(request.json or {})
    if not d['name']:
        return jsonify(error='Name is required'), 400
    uname = get_display_name(uid)
    conn = get_db()
    existing = conn.execute('SELECT id FROM employees WHERE id=?', (eid,)).fetchone()
    if not existing:
        conn.close()
        return jsonify(error='Record not found'), 404
    conn.execute('''UPDATE employees SET name=?,title=?,department=?,email=?,phone=?,location=?,manager=?,
        employee_id=?,start_date=?,end_date=?,status=?,client_name=?,vendor_name=?,process_name=?,
        bill_rate=?,pay_rate=?,recruiter=?,notes=?,updated_at=datetime('now'),updated_by=? WHERE id=?''',
        (d['name'], d['title'], d['department'], d['email'], d['phone'],
         d['location'], d['manager'], d['employeeId'], d['startDate'], d['endDate'],
         d['status'], d['clientName'], d['vendorName'], d['processName'],
         d['billRate'], d['payRate'], d['recruiter'], d['notes'], uname, eid))
    conn.commit()
    emp = dict(conn.execute('SELECT * FROM employees WHERE id=?', (eid,)).fetchone())
    conn.close()
    broadcast('employee-change', {'action': 'update', 'employee': emp})
    return jsonify(emp)

@app.route('/api/employees/<eid>', methods=['DELETE'])
@rate_limit(max_requests=30)
def delete_employee(eid):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin':
        return jsonify(error='Admin access required'), 403
    try:
        uuid.UUID(eid)
    except ValueError:
        return jsonify(error='Invalid ID'), 400
    conn = get_db()
    conn.execute('DELETE FROM employees WHERE id=?', (eid,))
    conn.commit()
    conn.close()
    broadcast('employee-change', {'action': 'delete', 'id': eid})
    return jsonify(ok=True)

@app.route('/api/employees/import', methods=['POST'])
@rate_limit(max_requests=10)
def import_employees():
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin':
        return jsonify(error='Admin access required'), 403
    d = request.json or {}
    rows = d.get('rows', [])
    if len(rows) > 5000:
        return jsonify(error='Maximum 5000 rows per import'), 400
    emp_type = d.get('type', 'internal')
    if emp_type not in VALID_TYPES:
        emp_type = 'internal'
    uname = get_display_name(uid)
    conn = get_db()
    imported = 0
    for r in rows:
        clean = sanitize_employee({**r, 'type': emp_type})
        if not clean['name']:
            continue
        conn.execute('''INSERT INTO employees (id,type,name,title,department,email,phone,location,manager,
            employee_id,start_date,end_date,status,client_name,vendor_name,process_name,bill_rate,pay_rate,
            recruiter,notes,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (str(uuid.uuid4()), clean['type'], clean['name'], clean['title'], clean['department'],
             clean['email'], clean['phone'], clean['location'], clean['manager'], clean['employeeId'],
             clean['startDate'], clean['endDate'], clean['status'], clean['clientName'],
             clean['vendorName'], clean['processName'], clean['billRate'], clean['payRate'],
             clean['recruiter'], clean['notes'], uname))
        imported += 1
    conn.commit()
    all_emps = [dict(r) for r in conn.execute('SELECT * FROM employees ORDER BY name ASC').fetchall()]
    conn.close()
    broadcast('employee-change', {'action': 'reload', 'employees': all_emps})
    return jsonify(imported=imported)

# ── Users management (admin only) ──
@app.route('/api/users')
@rate_limit(max_requests=30)
def list_users():
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin':
        return jsonify(error='Admin access required'), 403
    conn = get_db()
    rows = conn.execute('SELECT id,email,display_name,role,created_at FROM users ORDER BY created_at ASC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/users/<target_id>/role', methods=['PUT'])
@rate_limit(max_requests=20)
def update_role(target_id):
    uid = require_auth()
    if not uid or get_user_role(uid) != 'admin':
        return jsonify(error='Admin access required'), 403
    if target_id == uid:
        return jsonify(error='Cannot change your own role'), 400
    role = request.json.get('role', 'user')
    if role not in ('admin', 'user'):
        return jsonify(error='Invalid role'), 400
    conn = get_db()
    conn.execute('UPDATE users SET role=? WHERE id=?', (role, target_id))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

# ── Serve frontend ──
@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

if __name__ == '__main__':
    print(f'\n  ReqRoute Directory running at http://localhost:{PORT}\n')
    print(f'  Share this URL on your local network for others to access.')
    print(f'  First user to sign up gets admin access.\n')
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
