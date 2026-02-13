import hashlib
import json
import os
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

DB_FILE = 'nexus.db'
SESSIONS = {}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            balance INTEGER,
            status TEXT,
            bio TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY,
            title TEXT,
            status TEXT,
            task_type TEXT
        )
        """
    )

    # Миграция для старой БД
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    except sqlite3.OperationalError:
        pass

    # Базовые аккаунты
    seed_users = [
        ('NexusAdmin', hash_password('admin123'), 'admin', 99999, 'online', 'Администратор платформы NEXUS'),
        ('NexusPlayer', hash_password('player123'), 'user', 4500, 'online', 'Люблю кооператив и PvP-соревнования.'),
    ]
    for username, pwd_hash, role, balance, status, bio in seed_users:
        cursor.execute(
            """
            INSERT OR IGNORE INTO users (username, password_hash, role, balance, status, bio)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (username, pwd_hash, role, balance, status, bio)
        )
        cursor.execute(
            """
            UPDATE users
            SET password_hash = COALESCE(password_hash, ?),
                role = COALESCE(role, ?),
                balance = COALESCE(balance, ?),
                status = COALESCE(status, ?),
                bio = COALESCE(bio, ?)
            WHERE username = ?
            """,
            (pwd_hash, role, balance, status, bio, username)
        )

    cursor.execute("SELECT COUNT(*) FROM tasks")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO tasks (title, status, task_type) VALUES (?, ?, ?)",
            [
                ('Проверить жалобы сообщества', 'open', 'moderation'),
                ('Подготовить турнирный анонс', 'in_progress', 'event'),
                ('Проверка цен в магазине', 'open', 'store')
            ]
        )

    conn.commit()
    conn.close()


def get_conn():
    return sqlite3.connect(DB_FILE)


def read_json_body(handler):
    length = int(handler.headers.get('Content-Length', 0))
    if length <= 0:
        return {}

    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode('utf-8'))
    except Exception:
        return {}


def get_token_from_headers(handler):
    auth_header = handler.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header.split(' ', 1)[1].strip()
    return None


class RequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200, content_type='application/json'):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS')
        self.end_headers()

    def _json_response(self, data, status=200):
        self._set_headers(status, 'application/json; charset=utf-8')
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

    def serve_file(self, file_path, content_type='text/html; charset=utf-8'):
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                self._set_headers(200, content_type)
                self.wfile.write(f.read())
        else:
            self._json_response({'error': 'File not found'}, 404)

    def _require_auth(self):
        token = get_token_from_headers(self)
        if not token or token not in SESSIONS:
            self._json_response({'error': 'Unauthorized'}, 401)
            return None
        return SESSIONS[token]

    def _require_admin(self):
        user = self._require_auth()
        if not user:
            return None
        if user.get('role') != 'admin':
            self._json_response({'error': 'Forbidden: admin only'}, 403)
            return None
        return user

    def do_OPTIONS(self):
        self._set_headers(204, 'text/plain; charset=utf-8')

    def do_GET(self):
        path = urlparse(self.path).path

        routes = {
            '/': 'index.html',
            '/shop': 'shop.html',
            '/community': 'community.html',
            '/stream': 'stream.html',
            '/profile': 'profile.html',
            '/admin': 'admin.html',
            '/auth': 'auth.html'
        }

        if path in routes:
            self.serve_file(routes[path], 'text/html; charset=utf-8')
            return

        if path.startswith('/css/') or path.startswith('/js/'):
            file_path = path.lstrip('/')
            content_type = 'text/plain; charset=utf-8'
            if file_path.endswith('.css'):
                content_type = 'text/css; charset=utf-8'
            elif file_path.endswith('.js'):
                content_type = 'application/javascript; charset=utf-8'
            self.serve_file(file_path, content_type)
            return

        # Auth API
        if path == '/api/auth/me':
            user = self._require_auth()
            if not user:
                return
            self._json_response({'user': user})
            return

        # Public API
        if path == '/api/tasks':
            with get_conn() as conn:
                rows = conn.execute("SELECT id, title, status, task_type FROM tasks ORDER BY id DESC").fetchall()
            self._json_response([{'id': r[0], 'title': r[1], 'status': r[2], 'type': r[3]} for r in rows])
            return

        # Protected profile API
        if path == '/api/profile':
            user = self._require_auth()
            if not user:
                return
            with get_conn() as conn:
                row = conn.execute(
                    "SELECT id, username, role, balance, status, bio FROM users WHERE id = ?",
                    (user['id'],)
                ).fetchone()
            if not row:
                self._json_response({'error': 'Profile not found'}, 404)
                return
            self._json_response({
                'id': row[0],
                'username': row[1],
                'role': row[2],
                'balance': row[3],
                'status': row[4],
                'bio': row[5]
            })
            return

        # Admin API
        if path == '/api/admin/stats':
            if not self._require_admin():
                return
            with get_conn() as conn:
                users_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                tasks_count = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
                open_tasks = conn.execute("SELECT COUNT(*) FROM tasks WHERE status = 'open'").fetchone()[0]
            self._json_response({
                'users': users_count,
                'tasks': tasks_count,
                'open_tasks': open_tasks,
                'online_streams': 1
            })
            return

        if path == '/api/admin/users':
            if not self._require_admin():
                return
            with get_conn() as conn:
                rows = conn.execute("SELECT id, username, role, balance, status FROM users ORDER BY id").fetchall()
            self._json_response([
                {'id': r[0], 'username': r[1], 'role': r[2], 'balance': r[3], 'status': r[4]}
                for r in rows
            ])
            return

        self._json_response({'error': 'Not Found'}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        payload = read_json_body(self)

        # Auth API
        if path == '/api/auth/register':
            username = str(payload.get('username', '')).strip()
            password = str(payload.get('password', '')).strip()

            if len(username) < 3 or len(password) < 4:
                self._json_response({'error': 'Логин/пароль слишком короткие'}, 400)
                return

            with get_conn() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM users WHERE username = ? LIMIT 1",
                    (username,)
                ).fetchone()
            if exists:
                self._json_response({'error': 'Пользователь уже существует'}, 409)
                return

            try:
                with get_conn() as conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO users (username, password_hash, role, balance, status, bio)
                        VALUES (?, ?, 'user', 0, 'online', '')
                        """,
                        (username, hash_password(password))
                    )
                    conn.commit()
                    user_id = cursor.lastrowid
            except Exception:
                self._json_response({'error': 'Ошибка регистрации'}, 500)
                return

            token = secrets.token_hex(24)
            user_obj = {'id': user_id, 'username': username, 'role': 'user'}
            SESSIONS[token] = user_obj
            self._json_response({'token': token, 'user': user_obj}, 201)
            return

        if path == '/api/auth/login':
            username = str(payload.get('username', '')).strip()
            password = str(payload.get('password', '')).strip()
            pwd_hash = hash_password(password)

            with get_conn() as conn:
                row = conn.execute(
                    "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?",
                    (username, pwd_hash)
                ).fetchone()

            if not row:
                self._json_response({'error': 'Неверный логин или пароль'}, 401)
                return

            token = secrets.token_hex(24)
            user_obj = {'id': row[0], 'username': row[1], 'role': row[2]}
            SESSIONS[token] = user_obj
            self._json_response({'token': token, 'user': user_obj})
            return

        if path == '/api/auth/logout':
            token = get_token_from_headers(self)
            if token in SESSIONS:
                del SESSIONS[token]
            self._json_response({'message': 'Logged out'})
            return

        # Admin API
        if path == '/api/admin/task':
            if not self._require_admin():
                return
            title = str(payload.get('title', '')).strip()
            task_type = str(payload.get('type', 'general')).strip() or 'general'

            if not title:
                self._json_response({'error': 'Title is required'}, 400)
                return

            with get_conn() as conn:
                cursor = conn.execute(
                    "INSERT INTO tasks (title, status, task_type) VALUES (?, 'open', ?)",
                    (title, task_type)
                )
                conn.commit()
                task_id = cursor.lastrowid

            self._json_response({'message': 'Задача создана', 'id': task_id}, 201)
            return

        if path == '/api/admin/broadcast':
            if not self._require_admin():
                return
            message = str(payload.get('message', '')).strip()
            if not message:
                self._json_response({'error': 'Message is required'}, 400)
                return
            self._json_response({'message': f'Рассылка отправлена: {message}'})
            return

        self._json_response({'error': 'Not Found'}, 404)

    def do_PUT(self):
        path = urlparse(self.path).path
        payload = read_json_body(self)

        if path == '/api/profile':
            user = self._require_auth()
            if not user:
                return

            username = str(payload.get('username', '')).strip()
            status = str(payload.get('status', 'online')).strip() or 'online'
            bio = str(payload.get('bio', '')).strip()

            if not username:
                self._json_response({'error': 'Username is required'}, 400)
                return

            try:
                with get_conn() as conn:
                    conn.execute(
                        "UPDATE users SET username = ?, status = ?, bio = ? WHERE id = ?",
                        (username, status, bio, user['id'])
                    )
                    conn.commit()
            except sqlite3.IntegrityError:
                self._json_response({'error': 'Username already exists'}, 409)
                return

            # обновляем сессию
            token = get_token_from_headers(self)
            if token in SESSIONS:
                SESSIONS[token]['username'] = username

            self._json_response({'message': 'Профиль обновлен'})
            return

        self._json_response({'error': 'Not Found'}, 404)


def run():
    init_db()
    port = int(os.environ.get('PORT', 8000))
    host = os.environ.get('HOST', '0.0.0.0')
    server = HTTPServer((host, port), RequestHandler)
    print(f"🚀 Nexus Server запущен: http://{host}:{port}")
    server.serve_forever()


if __name__ == '__main__':
    run()
