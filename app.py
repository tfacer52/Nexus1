import hashlib
import sqlite3
import secrets
import os
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit, disconnect, join_room, leave_room
from game import RetroPingPongGame

app = Flask(__name__, static_folder='.')
CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*")

DB_FILE = 'nexus.db'
SESSIONS = {}
PING_PONG = RetroPingPongGame()
ONLINE_USERS = {}
SID_TO_USER = {}
SID_ROOM = {}

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
        conn.execute("""CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            friend_id INTEGER,
            UNIQUE(user_id, friend_id)
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            message TEXT,
            created_at TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS friend_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER,
            to_user_id INTEGER,
            status TEXT,
            created_at TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER,
            to_user_id INTEGER,
            message TEXT,
            created_at TEXT
        )""")

        # миграция: room для общего чата
        try:
            conn.execute("ALTER TABLE chat_messages ADD COLUMN room TEXT DEFAULT 'global'")
        except sqlite3.OperationalError:
            pass
        
        seed_users = [
            ('NexusAdmin', hash_password('admin123'), 'admin', 99999, 'online', 'Администратор платформы'),
            ('NexusPlayer', hash_password('player123'), 'user', 4500, 'online', 'Игрок Nexus')
        ]
        for user in seed_users:
            conn.execute("INSERT OR IGNORE INTO users (username, password_hash, role, balance, status, bio) VALUES (?,?,?,?,?,?)", user)

        # Дефолтная дружба (двусторонняя)
        admin = conn.execute("SELECT id FROM users WHERE username='NexusAdmin'").fetchone()
        player = conn.execute("SELECT id FROM users WHERE username='NexusPlayer'").fetchone()
        if admin and player:
            conn.execute("INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)", (admin['id'], player['id']))
            conn.execute("INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)", (player['id'], admin['id']))

        conn.commit()

init_db()

# --- Auth Helper ---
def get_current_user():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    return SESSIONS.get(token)


def user_from_token(token):
    if not token:
        return None
    return SESSIONS.get(token)


def get_online_list_payload():
    return [
        {'id': uid, 'username': data['username']}
        for uid, data in ONLINE_USERS.items()
    ]


def emit_online_users():
    socketio.emit('online_users', get_online_list_payload())

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
        user = SESSIONS[token]
        uid = user.get('id')
        if uid in ONLINE_USERS:
            del ONLINE_USERS[uid]
            emit_online_users()
        del SESSIONS[token]
    return jsonify({'message': 'Logged out'})


# --- SOCIAL / ONLINE API ---
@app.route('/api/social/friends', methods=['GET'])
def social_friends():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT u.id, u.username, u.status
            FROM friends f
            JOIN users u ON u.id = f.friend_id
            WHERE f.user_id = ?
            ORDER BY u.username
            """,
            (user['id'],)
        ).fetchall()

    friends = []
    for r in rows:
        friends.append({
            'id': r['id'],
            'username': r['username'],
            'status': 'online' if r['id'] in ONLINE_USERS else 'offline'
        })
    return jsonify(friends)


@app.route('/api/social/online', methods=['GET'])
def social_online():
    return jsonify(get_online_list_payload())


@app.route('/api/social/users', methods=['GET'])
def social_users():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify([])

    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT id, username FROM users WHERE LOWER(username) LIKE ? AND id != ? ORDER BY username LIMIT 15",
            (f'%{query}%', user['id'])
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/social/request', methods=['POST'])
def send_friend_request():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json or {}
    to_user_id = int(data.get('to_user_id', 0))
    if not to_user_id or to_user_id == user['id']:
        return jsonify({'error': 'Некорректный получатель'}), 400

    with get_db_connection() as conn:
        target = conn.execute("SELECT id FROM users WHERE id = ?", (to_user_id,)).fetchone()
        if not target:
            return jsonify({'error': 'Пользователь не найден'}), 404

        exists = conn.execute(
            "SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?",
            (user['id'], to_user_id)
        ).fetchone()
        if exists:
            return jsonify({'error': 'Уже в друзьях'}), 409

        pending = conn.execute(
            """
            SELECT 1 FROM friend_requests
            WHERE ((from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?))
              AND status = 'pending'
            """,
            (user['id'], to_user_id, to_user_id, user['id'])
        ).fetchone()
        if pending:
            return jsonify({'error': 'Заявка уже существует'}), 409

        conn.execute(
            "INSERT INTO friend_requests (from_user_id, to_user_id, status, created_at) VALUES (?, ?, 'pending', ?)",
            (user['id'], to_user_id, datetime.utcnow().isoformat(timespec='seconds') + 'Z')
        )
        conn.commit()

    return jsonify({'message': 'Заявка отправлена'})


@app.route('/api/social/requests', methods=['GET'])
def get_friend_requests():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT fr.id, fr.from_user_id, u.username AS from_username, fr.created_at
            FROM friend_requests fr
            JOIN users u ON u.id = fr.from_user_id
            WHERE fr.to_user_id = ? AND fr.status = 'pending'
            ORDER BY fr.id DESC
            """,
            (user['id'],)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/social/request/<int:req_id>/accept', methods=['POST'])
def accept_friend_request(req_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    with get_db_connection() as conn:
        req = conn.execute(
            "SELECT id, from_user_id, to_user_id, status FROM friend_requests WHERE id = ?",
            (req_id,)
        ).fetchone()
        if not req or req['to_user_id'] != user['id']:
            return jsonify({'error': 'Заявка не найдена'}), 404
        if req['status'] != 'pending':
            return jsonify({'error': 'Заявка уже обработана'}), 400

        conn.execute("UPDATE friend_requests SET status = 'accepted' WHERE id = ?", (req_id,))
        conn.execute(
            "INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)",
            (user['id'], req['from_user_id'])
        )
        conn.execute(
            "INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)",
            (req['from_user_id'], user['id'])
        )
        conn.commit()

    return jsonify({'message': 'Заявка принята'})


@app.route('/api/social/request/<int:req_id>/reject', methods=['POST'])
def reject_friend_request(req_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    with get_db_connection() as conn:
        req = conn.execute(
            "SELECT id, to_user_id, status FROM friend_requests WHERE id = ?",
            (req_id,)
        ).fetchone()
        if not req or req['to_user_id'] != user['id']:
            return jsonify({'error': 'Заявка не найдена'}), 404
        if req['status'] != 'pending':
            return jsonify({'error': 'Заявка уже обработана'}), 400
        conn.execute("UPDATE friend_requests SET status = 'rejected' WHERE id = ?", (req_id,))
        conn.commit()

    return jsonify({'message': 'Заявка отклонена'})


@app.route('/api/chat/history', methods=['GET'])
def chat_history():
    room = request.args.get('room', 'global').strip() or 'global'
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT username, message, created_at, room FROM chat_messages WHERE room = ? ORDER BY id DESC LIMIT 50",
            (room,)
        ).fetchall()
    messages = [dict(r) for r in rows][::-1]
    return jsonify(messages)


@app.route('/api/chat/private/<int:peer_id>', methods=['GET'])
def private_history(peer_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT from_user_id, to_user_id, message, created_at
            FROM private_messages
            WHERE (from_user_id = ? AND to_user_id = ?)
               OR (from_user_id = ? AND to_user_id = ?)
            ORDER BY id DESC LIMIT 50
            """,
            (user['id'], peer_id, peer_id, user['id'])
        ).fetchall()
    return jsonify([dict(r) for r in rows][::-1])


@app.route('/api/chat/private/<int:peer_id>', methods=['POST'])
def private_send(peer_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json or {}
    text = str(data.get('message', '')).strip()
    if not text:
        return jsonify({'error': 'Пустое сообщение'}), 400

    msg = {
        'from_user_id': user['id'],
        'to_user_id': peer_id,
        'message': text[:300],
        'created_at': datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    }

    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO private_messages (from_user_id, to_user_id, message, created_at) VALUES (?, ?, ?, ?)",
            (msg['from_user_id'], msg['to_user_id'], msg['message'], msg['created_at'])
        )
        conn.commit()

    if peer_id in ONLINE_USERS:
        socketio.emit('private_message', msg, to=ONLINE_USERS[peer_id]['sid'])

    return jsonify(msg)

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

@socketio.on('connect')
def handle_connect(auth):
    token = None
    if isinstance(auth, dict):
        token = auth.get('token')

    user = user_from_token(token)
    if not user:
        disconnect()
        return

    uid = user['id']
    ONLINE_USERS[uid] = {'username': user['username'], 'sid': request.sid}
    SID_TO_USER[request.sid] = uid
    SID_ROOM[request.sid] = 'global'

    join_room('room:global')

    emit_online_users()

    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT username, message, created_at, room FROM chat_messages WHERE room = 'global' ORDER BY id DESC LIMIT 50"
        ).fetchall()
    emit('chat_history', [dict(r) for r in rows][::-1])


@socketio.on('disconnect')
def handle_disconnect():
    uid = SID_TO_USER.get(request.sid)
    if uid:
        SID_TO_USER.pop(request.sid, None)
        SID_ROOM.pop(request.sid, None)
        if uid in ONLINE_USERS and ONLINE_USERS[uid].get('sid') == request.sid:
            del ONLINE_USERS[uid]
        emit_online_users()


@socketio.on('chat_join')
def handle_chat_join(payload):
    room = str((payload or {}).get('room', 'global')).strip().lower() or 'global'
    old_room = SID_ROOM.get(request.sid, 'global')

    if old_room != room:
        leave_room(f'room:{old_room}')
        join_room(f'room:{room}')
        SID_ROOM[request.sid] = room

    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT username, message, created_at, room FROM chat_messages WHERE room = ? ORDER BY id DESC LIMIT 50",
            (room,)
        ).fetchall()
    emit('chat_history', [dict(r) for r in rows][::-1])


@socketio.on('chat_send')
def handle_chat_send(payload):
    uid = SID_TO_USER.get(request.sid)
    if not uid:
        return

    text = str((payload or {}).get('message', '')).strip()
    if not text:
        return

    username = ONLINE_USERS.get(uid, {}).get('username', 'User')
    room = str((payload or {}).get('room', SID_ROOM.get(request.sid, 'global'))).strip().lower() or 'global'

    msg = {
        'username': username,
        'message': text[:300],
        'created_at': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'room': room
    }

    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO chat_messages (user_id, username, message, created_at, room) VALUES (?, ?, ?, ?, ?)",
            (uid, msg['username'], msg['message'], msg['created_at'], msg['room'])
        )
        conn.commit()

    socketio.emit('chat_message', msg, to=f"room:{room}")
    
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True, use_reloader=False)