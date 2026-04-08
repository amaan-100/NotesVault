from flask import Flask, request, session, jsonify, send_file
from functools import wraps
from datetime import timedelta
from urllib.parse import urlparse
import os
import sqlite3
import bcrypt

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None
    RealDictCursor = None

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'nv-production-secret-x9k2')
app.permanent_session_lifetime = timedelta(days=30)

DATABASE = 'notesvault.db'


def is_postgres():
    db_url = os.environ.get('DATABASE_URL', '')
    return db_url.startswith('postgres://') or db_url.startswith('postgresql://')


def get_db():
    db_url = os.environ.get('DATABASE_URL')

    if db_url and is_postgres():
        if psycopg2 is None:
            raise RuntimeError("psycopg2 is required for PostgreSQL but is not installed.")

        url = urlparse(db_url)
        conn = psycopg2.connect(
            dbname=url.path.lstrip('/'),
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port or 5432
        )
        conn.autocommit = False
        return conn

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def translate_query(query):
    if is_postgres():
        return query.replace('?', '%s')
    return query


def row_to_dict(row):
    if row is None:
        return None
    if isinstance(row, dict):
        return dict(row)
    try:
        return {k: row[k] for k in row.keys()}
    except Exception:
        return dict(row)


def rows_to_dicts(rows):
    return [row_to_dict(r) for r in rows]


def db_cursor(conn):
    if is_postgres():
        return conn.cursor(cursor_factory=RealDictCursor)
    return conn.cursor()


def db_fetchone(conn, query, params=()):
    cur = db_cursor(conn)
    try:
        cur.execute(translate_query(query), params)
        return cur.fetchone()
    finally:
        cur.close()


def db_fetchall(conn, query, params=()):
    cur = db_cursor(conn)
    try:
        cur.execute(translate_query(query), params)
        return cur.fetchall()
    finally:
        cur.close()


def db_execute(conn, query, params=()):
    cur = db_cursor(conn)
    cur.execute(translate_query(query), params)
    return cur


def init_db():
    conn = get_db()
    try:
        if is_postgres():
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW(),
                        last_login TIMESTAMP
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS notes (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        title TEXT NOT NULL DEFAULT 'Untitled',
                        content TEXT DEFAULT '',
                        drawing TEXT DEFAULT '',
                        tags TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT NOW(),
                        updated_at TIMESTAMP DEFAULT NOW()
                    )
                """)
            conn.commit()
        else:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL DEFAULT 'Untitled',
                    content TEXT DEFAULT '',
                    drawing TEXT DEFAULT '',
                    tags TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            ''')
            conn.commit()
    finally:
        conn.close()


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


# ── Serve Frontend ──
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if path.startswith('api/'):
        return jsonify({'error': 'Not Found'}), 404
    return send_file('templates/index.html')


# ── Auth ──
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if '@' not in email or '.' not in email.split('@')[-1]:
        return jsonify({'error': 'Invalid email address'}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    try:
        cur = db_execute(
            conn,
            'INSERT INTO users (username, email, password_hash) VALUES (?,?,?)',
            (username, email, pw_hash)
        )
        conn.commit()
        cur.close()
        return jsonify({'message': 'Account created'}), 201
    except (sqlite3.IntegrityError, Exception) as e:
        conn.rollback()
        if psycopg2 is not None and isinstance(e, psycopg2.IntegrityError):
            return jsonify({'error': 'Username or email already exists'}), 409
        if isinstance(e, sqlite3.IntegrityError):
            return jsonify({'error': 'Username or email already exists'}), 409
        return jsonify({'error': 'Registration failed'}), 500
    finally:
        conn.close()


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    conn = get_db()
    try:
        user = db_fetchone(conn, 'SELECT * FROM users WHERE username = ?', (username,))
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        user = row_to_dict(user)
        stored_hash = user['password_hash']

        if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
            return jsonify({'error': 'Invalid credentials'}), 401

        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']

        db_execute(conn, 'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
        conn.commit()

        return jsonify({
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email']
            }
        })
    finally:
        conn.close()


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})


@app.route('/api/me', methods=['GET'])
@require_auth
def me():
    conn = get_db()
    try:
        user = db_fetchone(
            conn,
            'SELECT id, username, email, created_at, last_login FROM users WHERE id = ?',
            (session['user_id'],)
        )
        if not user:
            session.clear()
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'user': row_to_dict(user)})
    finally:
        conn.close()


# ── Notes ──
@app.route('/api/notes', methods=['GET'])
@require_auth
def get_notes():
    sort = request.args.get('sort', 'newest')
    search = request.args.get('search', '').strip()

    q = '''SELECT id, title, content, tags, created_at, updated_at,
           CASE WHEN drawing IS NOT NULL AND drawing != '' THEN 1 ELSE 0 END as has_drawing
           FROM notes WHERE user_id = ?'''
    p = [session['user_id']]

    if search:
        q += ' AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)'
        p.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    if sort == 'last-edited':
        q += ' ORDER BY updated_at DESC'
    elif sort == 'title':
        q += ' ORDER BY title ASC'
    else:
        q += ' ORDER BY created_at DESC'

    conn = get_db()
    try:
        notes = db_fetchall(conn, q, tuple(p))
        return jsonify({'notes': rows_to_dicts(notes)})
    finally:
        conn.close()


@app.route('/api/notes', methods=['POST'])
@require_auth
def create_note():
    data = request.get_json() or {}
    title = (data.get('title') or '').strip() or 'Untitled'
    content = data.get('content', '')
    drawing = data.get('drawing', '')
    tags = ','.join(t.strip() for t in (data.get('tags') or '').split(',') if t.strip())

    conn = get_db()
    try:
        if is_postgres():
            cur = db_execute(
                conn,
                'INSERT INTO notes (user_id, title, content, drawing, tags) VALUES (?,?,?,?,?) RETURNING id',
                (session['user_id'], title, content, drawing, tags)
            )
            note_id = cur.fetchone()['id']
            cur.close()
        else:
            cur = db_execute(
                conn,
                'INSERT INTO notes (user_id, title, content, drawing, tags) VALUES (?,?,?,?,?)',
                (session['user_id'], title, content, drawing, tags)
            )
            note_id = cur.lastrowid
            cur.close()

        conn.commit()
        note = db_fetchone(conn, 'SELECT * FROM notes WHERE id = ?', (note_id,))
        return jsonify({'note': row_to_dict(note)}), 201
    finally:
        conn.close()


@app.route('/api/notes/<int:nid>', methods=['GET'])
@require_auth
def get_note(nid):
    conn = get_db()
    try:
        note = db_fetchone(
            conn,
            'SELECT * FROM notes WHERE id = ? AND user_id = ?',
            (nid, session['user_id'])
        )
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        return jsonify({'note': row_to_dict(note)})
    finally:
        conn.close()


@app.route('/api/notes/<int:nid>', methods=['PUT'])
@require_auth
def update_note(nid):
    data = request.get_json() or {}
    title = (data.get('title') or '').strip() or 'Untitled'
    content = data.get('content', '')
    drawing = data.get('drawing', '')
    tags = ','.join(t.strip() for t in (data.get('tags') or '').split(',') if t.strip())

    conn = get_db()
    try:
        existing = db_fetchone(
            conn,
            'SELECT id FROM notes WHERE id = ? AND user_id = ?',
            (nid, session['user_id'])
        )
        if not existing:
            return jsonify({'error': 'Note not found'}), 404

        db_execute(
            conn,
            'UPDATE notes SET title=?, content=?, drawing=?, tags=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (title, content, drawing, tags, nid)
        )
        conn.commit()

        note = db_fetchone(conn, 'SELECT * FROM notes WHERE id = ?', (nid,))
        return jsonify({'note': row_to_dict(note)})
    finally:
        conn.close()


@app.route('/api/notes/<int:nid>', methods=['DELETE'])
@require_auth
def delete_note(nid):
    conn = get_db()
    try:
        existing = db_fetchone(
            conn,
            'SELECT id FROM notes WHERE id = ? AND user_id = ?',
            (nid, session['user_id'])
        )
        if not existing:
            return jsonify({'error': 'Note not found'}), 404

        db_execute(conn, 'DELETE FROM notes WHERE id = ?', (nid,))
        conn.commit()
        return jsonify({'message': 'Note deleted'})
    finally:
        conn.close()


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f'  NotesVault → http://0.0.0.0:{port}')
    app.run(host='0.0.0.0', port=port, debug=False)
