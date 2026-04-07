from flask import Flask, request, session, jsonify, send_file, render_template
from functools import wraps
import sqlite3, bcrypt, os
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'nv-production-secret-x9k2')
app.permanent_session_lifetime = timedelta(days=30)

DATABASE = 'notesvault.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def init_db():
    conn = get_db()
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
    # Let API routes handle themselves, serve SPA for frontend routes
    if path.startswith('api/'):
        return jsonify({'error': 'Not Found'}), 404
    return send_file('templates/index.html')

# ── Auth ──
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
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
        conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?,?,?)',
                     (username, email, pw_hash))
        conn.commit()
        return jsonify({'message': 'Account created'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username or email already exists'}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    session.permanent = True
    session['user_id'] = user['id']
    session['username'] = user['username']
    conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
    conn.commit()
    conn.close()
    return jsonify({'user': {'id': user['id'], 'username': user['username'], 'email': user['email']}})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/me', methods=['GET'])
@require_auth
def me():
    conn = get_db()
    user = conn.execute(
        'SELECT id, username, email, created_at, last_login FROM users WHERE id = ?',
        (session['user_id'],)).fetchone()
    conn.close()
    if not user:
        session.clear()
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': dict(user)})

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
    notes = conn.execute(q, p).fetchall()
    conn.close()
    return jsonify({'notes': [dict(n) for n in notes]})

@app.route('/api/notes', methods=['POST'])
@require_auth
def create_note():
    data = request.get_json()
    title = (data.get('title') or '').strip() or 'Untitled'
    content = data.get('content', '')
    drawing = data.get('drawing', '')
    tags = ','.join(t.strip() for t in (data.get('tags') or '').split(',') if t.strip())
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO notes (user_id, title, content, drawing, tags) VALUES (?,?,?,?,?)',
        (session['user_id'], title, content, drawing, tags))
    conn.commit()
    note = conn.execute('SELECT * FROM notes WHERE id = ?', (cur.lastrowid,)).fetchone()
    conn.close()
    return jsonify({'note': dict(note)}), 201

@app.route('/api/notes/<int:nid>', methods=['GET'])
@require_auth
def get_note(nid):
    conn = get_db()
    note = conn.execute(
        'SELECT * FROM notes WHERE id = ? AND user_id = ?', (nid, session['user_id'])).fetchone()
    conn.close()
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    return jsonify({'note': dict(note)})

@app.route('/api/notes/<int:nid>', methods=['PUT'])
@require_auth
def update_note(nid):
    data = request.get_json()
    title = (data.get('title') or '').strip() or 'Untitled'
    content = data.get('content', '')
    drawing = data.get('drawing', '')
    tags = ','.join(t.strip() for t in (data.get('tags') or '').split(',') if t.strip())
    conn = get_db()
    if not conn.execute('SELECT id FROM notes WHERE id = ? AND user_id = ?', (nid, session['user_id'])).fetchone():
        conn.close()
        return jsonify({'error': 'Note not found'}), 404
    conn.execute(
        'UPDATE notes SET title=?, content=?, drawing=?, tags=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
        (title, content, drawing, tags, nid))
    conn.commit()
    note = conn.execute('SELECT * FROM notes WHERE id = ?', (nid,)).fetchone()
    conn.close()
    return jsonify({'note': dict(note)})

@app.route('/api/notes/<int:nid>', methods=['DELETE'])
@require_auth
def delete_note(nid):
    conn = get_db()
    if not conn.execute('SELECT id FROM notes WHERE id = ? AND user_id = ?', (nid, session['user_id'])).fetchone():
        conn.close()
        return jsonify({'error': 'Note not found'}), 404
    conn.execute('DELETE FROM notes WHERE id = ?', (nid,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Note deleted'})

#if __name__ == '__main__':
#    init_db()
#    print('  NotesVault → http://localhost:5000')
#    app.run(debug=True, port=5000) 

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))  # Render sets PORT
    app.run(host='0.0.0.0', port=port, debug=False)  # Bind to all interfaces
    print(f'  NotesVault → http://0.0.0.0:{port}')
