const AUTH_TOKEN_KEY = 'nexus_auth_token';

document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupSearch();
    setupSidebarInteraction();
    highlightActiveNav();
    setupQuickActions();
    setupCartButtons();
    setupStreamChat();
    setupAuthUi();
    initAuthPage();
    initProfilePage();
    initAdminPage();
    enforcePageAccess();
});

function getToken() {
    return localStorage.getItem(AUTH_TOKEN_KEY);
}

function setToken(token) {
    if (token) localStorage.setItem(AUTH_TOKEN_KEY, token);
}

function clearToken() {
    localStorage.removeItem(AUTH_TOKEN_KEY);
}

async function apiFetch(url, options = {}) {
    const token = getToken();
    const headers = { ...(options.headers || {}) };
    if (token) headers.Authorization = `Bearer ${token}`;

    const response = await fetch(url, { ...options, headers });
    let data = {};
    try { data = await response.json(); } catch (_) {}

    if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
    }

    return data;
}

/* --- НАВИГАЦИЯ --- */
function setupNavigation() {
    const clickableItems = document.querySelectorAll('.nav-item, .user-profile[data-page], .logo');
    clickableItems.forEach(item => {
        item.addEventListener('click', () => {
            const page = item.classList.contains('logo') ? '/' : item.getAttribute('data-page');
            if (page) window.location.href = page;
        });
    });
}

function highlightActiveNav() {
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-item').forEach(item => {
        const page = item.getAttribute('data-page');
        item.classList.toggle('active', page === currentPath || (currentPath === '/' && page === '/'));
    });
}

function setupSearch() {
    const searchInput = document.getElementById('gameSearch');
    const gameRows = document.querySelectorAll('.game-row');
    if (!searchInput) return;

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        gameRows.forEach(row => {
            row.style.display = row.textContent.toLowerCase().includes(query) ? 'flex' : 'none';
        });
    });
}

function setupSidebarInteraction() {
    const gameRows = document.querySelectorAll('.game-row');
    gameRows.forEach(row => {
        row.addEventListener('click', () => {
            gameRows.forEach(r => r.classList.remove('active'));
            row.classList.add('active');
            showNotification(`Библиотека: ${row.textContent.trim()}`);
        });
    });
}

function showNotification(message, type = 'info') {
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.25s forwards';
        setTimeout(() => toast.remove(), 250);
    }, 2800);
}

function setupQuickActions() {
    document.getElementById('playNowBtn')?.addEventListener('click', () => {
        showNotification('Игра запускается...', 'success');
    });
    document.getElementById('heroDetailsBtn')?.addEventListener('click', () => {
        showNotification('Открываем страницу игры Galactic Frontier', 'info');
    });
}

function setupCartButtons() {
    document.querySelectorAll('[data-cart-item]').forEach(button => {
        button.addEventListener('click', () => {
            const item = button.getAttribute('data-cart-item') || 'Товар';
            showNotification(`${item} добавлен в корзину`, 'success');
        });
    });
}

function setupStreamChat() {
    const chatInput = document.getElementById('streamChatInput');
    const sendButton = document.getElementById('streamChatSend');
    const chatMessages = document.getElementById('streamChatMessages');
    if (!chatInput || !sendButton || !chatMessages) return;

    const sendMessage = () => {
        const text = chatInput.value.trim();
        if (!text) return;
        const row = document.createElement('div');
        row.innerHTML = `<span style="color: #fbbf24; font-weight: bold;">Вы:</span> ${text}`;
        chatMessages.appendChild(row);
        chatMessages.scrollTop = chatMessages.scrollHeight;
        chatInput.value = '';
    };

    sendButton.addEventListener('click', sendMessage);
    chatInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            sendMessage();
        }
    });
}

async function getCurrentUser() {
    const token = getToken();
    if (!token) return null;
    try {
        const data = await apiFetch('/api/auth/me');
        return data.user || null;
    } catch (_) {
        clearToken();
        return null;
    }
}

async function setupAuthUi() {
    const nav = document.querySelector('.nav-links');
    if (!nav) return;

    const existing = document.getElementById('authControlItem');
    if (existing) existing.remove();

    const user = await getCurrentUser();
    const item = document.createElement('div');
    item.className = 'nav-item';
    item.id = 'authControlItem';

    if (user) {
        item.textContent = 'Выйти';
        item.addEventListener('click', async () => {
            try { await apiFetch('/api/auth/logout', { method: 'POST' }); } catch (_) {}
            clearToken();
            window.location.href = '/auth';
        });
    } else {
        item.textContent = 'Войти';
        item.addEventListener('click', () => { window.location.href = '/auth'; });
    }

    nav.appendChild(item);
}

async function enforcePageAccess() {
    const path = window.location.pathname;
    if (!['/profile', '/admin'].includes(path)) return;

    const user = await getCurrentUser();
    if (!user) {
        showNotification('Сначала выполните вход', 'warning');
        setTimeout(() => { window.location.href = '/auth'; }, 500);
        return;
    }

    if (path === '/admin' && user.role !== 'admin') {
        showNotification('Доступ только для админа', 'warning');
        setTimeout(() => { window.location.href = '/'; }, 600);
    }
}

function initAuthPage() {
    const authPage = document.getElementById('authPage');
    if (!authPage) return;

    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    loginForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('loginUsername').value.trim();
        const password = document.getElementById('loginPassword').value.trim();

        try {
            const data = await apiFetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            setToken(data.token);
            showNotification('Вход выполнен', 'success');
            setTimeout(() => { window.location.href = '/'; }, 400);
        } catch (err) {
            showNotification(err.message, 'warning');
        }
    });

    registerForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('registerUsername').value.trim();
        const password = document.getElementById('registerPassword').value.trim();

        try {
            const data = await apiFetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            setToken(data.token);
            showNotification('Регистрация успешна', 'success');
            setTimeout(() => { window.location.href = '/'; }, 400);
        } catch (err) {
            showNotification(err.message, 'warning');
        }
    });
}

async function initProfilePage() {
    const profileForm = document.getElementById('profileForm');
    if (!profileForm) return;

    const usernameInput = document.getElementById('profileUsername');
    const statusInput = document.getElementById('profileStatus');
    const bioInput = document.getElementById('profileBio');
    const roleLabel = document.getElementById('profileRole');
    const balanceLabel = document.getElementById('profileBalance');

    try {
        const profile = await apiFetch('/api/profile');
        usernameInput.value = profile.username || '';
        statusInput.value = profile.status || 'online';
        bioInput.value = profile.bio || '';
        roleLabel.textContent = profile.role || 'user';
        balanceLabel.textContent = `${profile.balance || 0} ₸`;
    } catch (err) {
        showNotification(err.message || 'Не удалось загрузить профиль', 'warning');
        return;
    }

    profileForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            await apiFetch('/api/profile', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: usernameInput.value.trim(),
                    status: statusInput.value.trim(),
                    bio: bioInput.value.trim()
                })
            });
            showNotification('Профиль успешно обновлен', 'success');
        } catch (err) {
            showNotification(err.message || 'Ошибка сохранения профиля', 'warning');
        }
    });
}

async function initAdminPage() {
    const adminPage = document.getElementById('adminPage');
    if (!adminPage) return;

    const usersList = document.getElementById('adminUsersList');
    const tasksList = document.getElementById('adminTasksList');
    const statsUsers = document.getElementById('statsUsers');
    const statsTasks = document.getElementById('statsTasks');
    const statsOpenTasks = document.getElementById('statsOpenTasks');
    const statsStreams = document.getElementById('statsStreams');
    const addTaskForm = document.getElementById('addTaskForm');
    const broadcastForm = document.getElementById('broadcastForm');

    const loadAdminData = async () => {
        try {
            const [stats, users, tasks] = await Promise.all([
                apiFetch('/api/admin/stats'),
                apiFetch('/api/admin/users'),
                apiFetch('/api/tasks')
            ]);

            statsUsers.textContent = stats.users;
            statsTasks.textContent = stats.tasks;
            statsOpenTasks.textContent = stats.open_tasks;
            statsStreams.textContent = stats.online_streams;

            usersList.innerHTML = users
                .map((u) => `<tr><td>${u.id}</td><td>${u.username}</td><td>${u.role}</td><td>${u.status}</td><td>${u.balance} ₸</td></tr>`)
                .join('');

            tasksList.innerHTML = tasks
                .map((t) => `<tr><td>${t.id}</td><td>${t.title}</td><td>${t.type}</td><td>${t.status}</td></tr>`)
                .join('');
        } catch (err) {
            showNotification(err.message || 'Ошибка загрузки админ-данных', 'warning');
        }
    };

    await loadAdminData();

    addTaskForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const titleInput = document.getElementById('adminTaskTitle');
        const typeInput = document.getElementById('adminTaskType');
        const title = titleInput.value.trim();
        const type = typeInput.value.trim() || 'general';
        if (!title) return;

        try {
            await apiFetch('/api/admin/task', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title, type })
            });
            titleInput.value = '';
            showNotification('Задача добавлена', 'success');
            await loadAdminData();
        } catch (err) {
            showNotification(err.message || 'Не удалось добавить задачу', 'warning');
        }
    });

    broadcastForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const input = document.getElementById('broadcastMessage');
        const message = input.value.trim();
        if (!message) return;

        try {
            await apiFetch('/api/admin/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message })
            });
            input.value = '';
            showNotification('Рассылка отправлена', 'info');
        } catch (err) {
            showNotification(err.message || 'Ошибка отправки рассылки', 'warning');
        }
    });
}

window.showNotification = showNotification;