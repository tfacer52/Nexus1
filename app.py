import hashlib
import sqlite3
import secrets
import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from game import RetroPingPongGame

app = Flask(__name__, static_folder='.')
CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*")

DB_FILE = 'nexus.db'
SESSIONS = {}
PING_PONG = RetroPingPongGame()

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Инициализация БД
def init_db():
    with get_db_connection() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            balance INTEGER,
            status TEXT,
            bio TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            status TEXT,
            task_type TEXT
        )""")
        
        seed_users = [
            ('NexusAdmin', hash_password('admin123'), 'admin', 99999, 'online', 'Администратор платформы'),
            ('NexusPlayer', hash_password('player123'), 'user', 4500, 'online', 'Игрок Nexus')
        ]
        for user in seed_users:
            conn.execute("INSERT OR IGNORE INTO users (username, password_hash, role, balance, status, bio) VALUES (?,?,?,?,?,?)", user)
        conn.commit()

init_db()

# --- Auth Helper ---
def get_current_user():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    return SESSIONS.get(token)

# --- РОУТИНГ СТРАНИЦ ---
@app.route('/')
def index(): return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(path):
        return send_from_directory('.', path)
    # Если запрашивают /shop, отдаем shop.html
    html_path = f"{path}.html"
    if os.path.exists(html_path):
        return send_from_directory('.', html_path)
    return jsonify({'error': 'Not Found'}), 404

# --- API AUTH ---
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username, password = data.get('username', '').strip(), data.get('password', '').strip()
    if len(username) < 3: return jsonify({'error': 'Слишком короткий логин'}), 400
    
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("INSERT INTO users (username, password_hash, role, balance, status, bio) VALUES (?, ?, 'user', 0, 'online', '')",
                                 (username, hash_password(password)))
            conn.commit()
            user_id = cursor.lastrowid
        token = secrets.token_hex(24)
        user_obj = {'id': user_id, 'username': username, 'role': 'user'}
        SESSIONS[token] = user_obj
        return jsonify({'token': token, 'user': user_obj}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Пользователь уже существует'}), 409

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    pwd_hash = hash_password(data.get('password', ''))
    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", 
                            (data.get('username'), pwd_hash)).fetchone()
    if user:
        token = secrets.token_hex(24)
        user_obj = {'id': user['id'], 'username': user['username'], 'role': user['role']}
        SESSIONS[token] = user_obj
        return jsonify({'token': token, 'user': user_obj})
    return jsonify({'error': 'Неверный логин или пароль'}), 401

@app.route('/api/auth/me', methods=['GET'])
def me():
    user = get_current_user()
    if not user: return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'user': user})

# --- API PROFILE ---
@app.route('/api/profile', methods=['GET', 'PUT'])
def profile():
    user_session = get_current_user()
    if not user_session: return jsonify({'error': 'Unauthorized'}), 401
    
    if request.method == 'GET':
        with get_db_connection() as conn:
            user = conn.execute("SELECT id, username, role, balance, status, bio FROM users WHERE id = ?", (user_session['id'],)).fetchone()
        return jsonify(dict(user))
    
    data = request.json
    with get_db_connection() as conn:
        conn.execute("UPDATE users SET username=?, status=?, bio=? WHERE id=?",
                     (data['username'], data.get('status', 'online'), data.get('bio', ''), user_session['id']))
        conn.commit()
    SESSIONS[request.headers.get('Authorization').replace('Bearer ', '')]['username'] = data['username']
    return jsonify({'message': 'Обновлено'})

# --- API ADMIN ---
@app.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    user = get_current_user()
    if not user or user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    with get_db_connection() as conn:
        u_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        t_count = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        o_tasks = conn.execute("SELECT COUNT(*) FROM tasks WHERE status = 'open'").fetchone()[0]
    return jsonify({'users': u_count, 'tasks': t_count, 'open_tasks': o_tasks, 'online_streams': 1})

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    user = get_current_user()
    if not user or user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    with get_db_connection() as conn:
        users = conn.execute("SELECT id, username, role, balance, status FROM users").fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    with get_db_connection() as conn:
        tasks = conn.execute("SELECT id, title, status, task_type as type FROM tasks").fetchall()

    return jsonify([dict(t) for t in tasks])

@app.route('/api/admin/task', methods=['POST'])
def add_task():
    user = get_current_user()
    if not user or user['role'] != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    data = request.json
    title = data.get('title')
    task_type = data.get('type', 'general')

    if not title:
        return jsonify({'error': 'Title required'}), 400

    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO tasks (title, status, task_type) VALUES (?, 'open', ?)",
            (title, task_type)
        )
        conn.commit()

    return jsonify({'message': 'Task created'}), 201

@app.route('/api/admin/broadcast', methods=['POST'])
def broadcast():
    user = get_current_user()
    if not user or user['role'] != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    data = request.json
    message = data.get('message')

    if not message:
        return jsonify({'error': 'Message required'}), 400

    print(f"[BROADCAST]: {message}")

    return jsonify({'message': 'Broadcast sent'})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    if token in SESSIONS:
        del SESSIONS[token]
    return jsonify({'message': 'Logged out'})

# --- RETRO PING PONG API ---
@app.route('/api/pong/state', methods=['GET'])
def pong_state():
    return jsonify(PING_PONG.get_state())


@app.route('/api/pong/step', methods=['POST'])
def pong_step():
    data = request.json or {}
    direction = int(data.get('direction', 0))
    direction = -1 if direction < 0 else (1 if direction > 0 else 0)
    return jsonify(PING_PONG.step(direction))


@app.route('/api/pong/reset', methods=['POST'])
def pong_reset():
    PING_PONG.full_reset()
    return jsonify(PING_PONG.get_state())


@app.route('/pong')
def pong_game():
    return send_from_directory('.', 'pong.html')

# Обработка движений игрока
@socketio.on('player_move')
def handle_move(data):
    # data содержит {y: значение, side: 'left' или 'right'}
    emit('opponent_update', data, broadcast=True, include_self=False)

# Синхронизация мяча (обычно делает первый зашедший игрок)
@socketio.on('ball_sync')
def handle_ball(data):
    emit('ball_update', data, broadcast=True, include_self=False)
    
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True, use_reloader=False)