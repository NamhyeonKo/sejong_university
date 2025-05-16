# Flask-based simulation for OAuth 2.0 with honeytoken logic
# Modules: Client Server, Auth Server, Resource Server

from flask import Flask, request, jsonify, redirect, render_template_string, make_response
import time, jwt, uuid, sqlite3
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = 'super-secret-key'

# === CONFIG ===
JWT_SECRET = 'jwt-secret'
ACCESS_TOKEN_LIFESPAN = 30  # seconds
REFRESH_TOKEN_LIFESPAN = 300  # seconds
DB_PATH = 'tokens.db'

# === Initialize DB ===
def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE tokens (
                        token TEXT PRIMARY KEY,
                        username TEXT,
                        expires_at REAL
                    )''')
        c.execute('''CREATE TABLE honeytokens (
                        token TEXT PRIMARY KEY,
                        username TEXT,
                        issued_time TEXT
                    )''')
        c.execute('''CREATE TABLE honeytoken_logs (
                        token TEXT,
                        username TEXT,
                        attempt_time TEXT,
                        status TEXT
                    )''')
        conn.commit()
        conn.close()

init_db()

# === In-memory users and refresh tokens ===
USERS = {'alice': 'password123'}
REFRESH_TOKENS = {}  # refresh_token: username

# === Utility: Load honeytokens into set for O(1) lookup ===
def load_honeytoken_set():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT token FROM honeytokens")
    tokens = {row[0] for row in c.fetchall()}
    conn.close()
    return tokens

# === AUTH SERVER ===
@app.route('/auth/token', methods=['POST'])
def issue_token():
    username = request.form.get('username')
    password = request.form.get('password')
    if USERS.get(username) == password:
        access_token = jwt.encode({
            'sub': username,
            'exp': datetime.utcnow() + timedelta(seconds=ACCESS_TOKEN_LIFESPAN)
        }, JWT_SECRET, algorithm='HS256')
        if isinstance(access_token, bytes):
            access_token = access_token.decode()

        refresh_token = str(uuid.uuid4())
        expires_at = time.time() + ACCESS_TOKEN_LIFESPAN

        conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
        conn.execute("INSERT INTO tokens (token, username, expires_at) VALUES (?, ?, ?)",
                     (access_token, username, expires_at))
        conn.commit()
        conn.close()

        REFRESH_TOKENS[refresh_token] = username

        response = make_response(redirect('/'))
        response.set_cookie('access_token', access_token, max_age=ACCESS_TOKEN_LIFESPAN, httponly=True)
        response.set_cookie('refresh_token', refresh_token, max_age=REFRESH_TOKEN_LIFESPAN, httponly=True)
        return response

    return 'Invalid credentials', 401

@app.route('/auth/refresh', methods=['POST'])
def refresh_token():
    refresh_token = request.cookies.get('refresh_token') or request.form.get('refresh_token')
    username = REFRESH_TOKENS.get(refresh_token)
    if not username:
        return 'Invalid refresh token', 401

    old_access_token = request.cookies.get('access_token')

    new_access_token = jwt.encode({
        'sub': username,
        'exp': datetime.utcnow() + timedelta(seconds=ACCESS_TOKEN_LIFESPAN)
    }, JWT_SECRET, algorithm='HS256')
    if isinstance(new_access_token, bytes):
        new_access_token = new_access_token.decode()

    expires_at = time.time() + ACCESS_TOKEN_LIFESPAN

    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    if old_access_token:
        conn.execute("INSERT OR IGNORE INTO honeytokens (token, username, issued_time) VALUES (?, ?, ?)",
                     (old_access_token, username, datetime.utcnow().isoformat()))
    conn.execute("INSERT INTO tokens (token, username, expires_at) VALUES (?, ?, ?)",
                 (new_access_token, username, expires_at))
    conn.commit()
    conn.close()

    response = make_response(redirect('/'))
    response.set_cookie('access_token', new_access_token, max_age=ACCESS_TOKEN_LIFESPAN, httponly=True)
    return response

@app.route('/auth/introspect', methods=['POST'])
def introspect():
    token = request.form.get('token')
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT username, expires_at FROM tokens WHERE token = ?", (token,))
    row = c.fetchone()
    if row:
        username, expires_at = row
        if expires_at < time.time():
            c.execute("INSERT OR IGNORE INTO honeytokens (token, username, issued_time) VALUES (?, ?, ?)",
                      (token, username, datetime.utcnow().isoformat()))
            c.execute("INSERT INTO honeytoken_logs (token, username, attempt_time, status) VALUES (?, ?, ?, ?)",
                      (token, username, datetime.utcnow().isoformat(), 'honeytoken_registered (introspect)'))
            conn.commit()
            conn.close()
            return jsonify(active=False)
        else:
            conn.close()
            return jsonify(active=True, username=username)
    else:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], options={"verify_exp": False})
            c.execute("INSERT INTO honeytoken_logs (token, username, attempt_time, status) VALUES (?, ?, ?, ?)",
                      (token, decoded.get('sub', 'unknown'), datetime.utcnow().isoformat(), 'invalid/introspect'))
            conn.commit()
        except Exception:
            pass
        conn.close()
        return jsonify(active=False)

# === RESOURCE SERVER ===
@app.route('/resource', methods=['GET', 'POST'])
def protected_resource():
    token = request.form.get('token')
    if not token:
        token = request.cookies.get('access_token') or request.headers.get('Authorization', '').replace('Bearer ', '')

    if not token:
        return 'No token provided', 401

    # Step 1: Check honeytoken set (O(1) lookup)
    honeytoken_set = load_honeytoken_set()
    if token in honeytoken_set:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], options={"verify_exp": False})
            conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
            conn.execute("INSERT INTO honeytoken_logs (token, username, attempt_time, status) VALUES (?, ?, ?, ?)",
                         (token, decoded.get('sub', 'unknown'), datetime.utcnow().isoformat(), 'honeytoken_detected (resource)'))
            conn.commit()
            conn.close()
            return 'Honeytoken detected - access denied', 403
        except jwt.InvalidTokenError:
            return 'Unauthorized - invalid token structure', 401

    # Step 2: If not honeytoken, validate with auth server (introspection)
    introspect_response = app.test_client().post('/auth/introspect', data={'token': token})
    result = introspect_response.get_json()

    if result.get('active'):
        return f"Welcome, {result['username']}! This is protected data."
    else:
        return 'Access denied - invalid or expired token', 403

# === CLIENT UI ===
@app.route('/')
def home():
    token = request.cookies.get('access_token')
    return render_template_string("""
        <h1>OAuth 2.0 Honeytoken Simulation</h1>

        <h3>1. Login (issue token)</h3>
        <form method='post' action='/auth/token'>
            Username: <input name='username'><br>
            Password: <input name='password' type='password'><br>
            <input type='submit' value='Login & Issue Token'>
        </form>

        <h3>2. Refresh Access Token</h3>
        <form method='post' action='/auth/refresh'>
            <input type='submit' value='Refresh Token'>
        </form>

        <h3>3. Access Protected Resource</h3>
        <form method='post' action='/resource'>
            Access Token (입력 시 해당 토큰으로 요청): <input name='token'><br>
            <input type='submit' value='Access Resource'>
        </form>

        <p><strong>Current Access Token (from Cookie):</strong><br>{{ token }}</p>

        <h3>4. View Honeytoken Logs</h3>
        <a href='/debug/honeytokens'>View Logs</a>
    """, token=token)

# === DEBUG ===
@app.route('/debug/honeytokens')
def show_honeytokens():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT * FROM honeytoken_logs ORDER BY attempt_time DESC")
    rows = c.fetchall()
    conn.close()
    return render_template_string("""
    <h2>Honeytoken Log</h2>
    <table border='1'>
        <tr><th>Token</th><th>Username</th><th>Attempt Time</th><th>Status</th></tr>
        {% for row in rows %}
            <tr>
                <td>{{ row[0] }}</td>
                <td>{{ row[1] }}</td>
                <td>{{ row[2] }}</td>
                <td>{{ row[3] }}</td>
            </tr>
        {% endfor %}
    </table>
    <a href='/'>Back</a>
    """, rows=rows)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
