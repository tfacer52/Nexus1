const AUTH_TOKEN_KEY = 'nexus_auth_token';
let socialSocket = null;
let currentRoom = 'global';
let selectedPrivatePeerId = null;
let profileRealtimeBound = false;

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
    initSocialFeatures();
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
    // Реальная логика чата и онлайна подключается в initSocialFeatures
}

function renderChatMessage(container, msg) {
    const row = document.createElement('div');
    const username = msg.username || 'User';
    const text = String(msg.message || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    row.innerHTML = `<span style="color: #a78bfa; font-weight: bold;">${username}:</span> ${text}`;
    container.appendChild(row);
}

async function loadFriendsPanel() {
    const listEl = document.getElementById('friendsListDynamic');
    const countEl = document.getElementById('friendsOnlineCount');
    if (!listEl) return;

    try {
        const friends = await apiFetch('/api/social/friends');
        const onlineCount = friends.filter(f => f.status === 'online').length;
        if (countEl) countEl.textContent = `${onlineCount} онлайн`;

        listEl.innerHTML = friends.length
            ? friends.map((f) => `
                <div class="friend-item">
                    <div class="friend-avatar">
                        <div class="status-dot ${f.status === 'online' ? 'status-online' : 'status-offline'}"></div>
                    </div>
                    <div class="friend-info">
                        <div class="friend-name">${f.username}</div>
                        <div class="friend-status">${f.status === 'online' ? 'В сети' : 'Не в сети'}</div>
                    </div>
                </div>
            `).join('')
            : '<div style="color: var(--text-muted); font-size: 12px;">Друзей пока нет</div>';
    } catch (_) {
        listEl.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">Войдите, чтобы видеть друзей</div>';
        if (countEl) countEl.textContent = '0 онлайн';
    }
}

async function initSocialFeatures() {
    await loadFriendsPanel();

    initProfileSocial();

    const chatInput = document.getElementById('streamChatInput');
    const sendButton = document.getElementById('streamChatSend');
    const chatMessages = document.getElementById('streamChatMessages');
    const roomSelect = document.getElementById('streamRoomSelect');
    const token = getToken();

    if (token && typeof window.io === 'function' && !socialSocket) {
        socialSocket = window.io({ auth: { token } });
    }

    if (!chatInput || !sendButton || !chatMessages) return;

    if (!token) {
        const note = document.createElement('div');
        note.style.opacity = '0.7';
        note.textContent = 'Войдите в аккаунт, чтобы отправлять сообщения в общий чат.';
        chatMessages.appendChild(note);
        sendButton.disabled = true;
        return;
    }

    // Fallback history через API
    try {
        const history = await apiFetch('/api/chat/history');
        chatMessages.innerHTML = '';
        history.forEach((m) => renderChatMessage(chatMessages, m));
        chatMessages.scrollTop = chatMessages.scrollHeight;
    } catch (_) {}

    // Real-time через Socket.IO
    if (socialSocket) {

        socialSocket.on('chat_history', (messages) => {
            chatMessages.innerHTML = '';
            (messages || []).forEach((m) => renderChatMessage(chatMessages, m));
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });

        socialSocket.on('chat_message', (msg) => {
            if ((msg.room || 'global') !== currentRoom) return;
            renderChatMessage(chatMessages, msg);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });

        socialSocket.on('online_users', () => {
            loadFriendsPanel();
        });

        socialSocket.on('private_message', (msg) => {
            if (!selectedPrivatePeerId) return;
            const isCurrentPeer = msg.from_user_id === selectedPrivatePeerId || msg.to_user_id === selectedPrivatePeerId;
            if (isCurrentPeer && typeof window.loadPrivateMessages === 'function') {
                window.loadPrivateMessages(selectedPrivatePeerId);
            }
        });

        roomSelect?.addEventListener('change', () => {
            currentRoom = roomSelect.value || 'global';
            socialSocket.emit('chat_join', { room: currentRoom });
        });

        socialSocket.emit('chat_join', { room: currentRoom });

        const send = () => {
            const text = chatInput.value.trim();
            if (!text) return;
            socialSocket.emit('chat_send', { message: text, room: currentRoom });
            chatInput.value = '';
        };

        sendButton.addEventListener('click', send);
        chatInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                send();
            }
        });
    }
}

async function initProfileSocial() {
    const friendSearchInput = document.getElementById('friendSearchInput');
    const friendSearchBtn = document.getElementById('friendSearchBtn');
    const friendSearchResults = document.getElementById('friendSearchResults');
    const incomingRequests = document.getElementById('incomingRequests');
    const profileFriendsList = document.getElementById('profileFriendsList');
    const privatePeerLabel = document.getElementById('privatePeerLabel');
    const privateMessages = document.getElementById('privateMessages');
    const privateMessageInput = document.getElementById('privateMessageInput');
    const privateMessageSend = document.getElementById('privateMessageSend');

    if (!friendSearchBtn && !incomingRequests && !profileFriendsList) return;

    const renderIncomingRequests = async () => {
        if (!incomingRequests) return;
        try {
            const reqs = await apiFetch('/api/social/requests');
            incomingRequests.innerHTML = reqs.length
                ? reqs.map((r) => `
                    <div style="display:flex; justify-content:space-between; gap:8px; align-items:center; background:rgba(255,255,255,0.04); padding:8px; border-radius:8px;">
                        <div style="font-size:13px;">${r.from_username}</div>
                        <div style="display:flex; gap:6px;">
                            <button type="button" class="btn btn-primary" data-accept-id="${r.id}" style="padding:6px 10px; font-size:11px;">Принять</button>
                            <button type="button" class="btn btn-secondary" data-reject-id="${r.id}" style="padding:6px 10px; font-size:11px;">Отклонить</button>
                        </div>
                    </div>
                `).join('')
                : '<div style="color: var(--text-muted); font-size: 12px;">Нет входящих заявок</div>';

            incomingRequests.querySelectorAll('[data-accept-id]').forEach((btn) => {
                btn.addEventListener('click', async () => {
                    await apiFetch(`/api/social/request/${btn.getAttribute('data-accept-id')}/accept`, { method: 'POST' });
                    showNotification('Заявка принята', 'success');
                    await renderIncomingRequests();
                    await renderProfileFriends();
                    await loadFriendsPanel();
                });
            });

            incomingRequests.querySelectorAll('[data-reject-id]').forEach((btn) => {
                btn.addEventListener('click', async () => {
                    await apiFetch(`/api/social/request/${btn.getAttribute('data-reject-id')}/reject`, { method: 'POST' });
                    showNotification('Заявка отклонена', 'info');
                    await renderIncomingRequests();
                });
            });
        } catch (_) {
            incomingRequests.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">Войдите для просмотра заявок</div>';
        }
    };

    const renderProfileFriends = async () => {
        if (!profileFriendsList) return;
        try {
            const friends = await apiFetch('/api/social/friends');
            profileFriendsList.innerHTML = friends.length
                ? friends.map((f) => `
                    <button type="button" data-peer-id="${f.id}" data-peer-name="${f.username}" class="btn btn-secondary" style="justify-content:space-between; padding:8px 10px; font-size:12px;">
                        <span>${f.username}</span><span>${f.status === 'online' ? '🟢' : '⚪'}</span>
                    </button>
                `).join('')
                : '<div style="color: var(--text-muted); font-size: 12px;">Нет друзей</div>';

            profileFriendsList.querySelectorAll('[data-peer-id]').forEach((btn) => {
                btn.addEventListener('click', async () => {
                    selectedPrivatePeerId = Number(btn.getAttribute('data-peer-id'));
                    const name = btn.getAttribute('data-peer-name');
                    if (privatePeerLabel) privatePeerLabel.textContent = `Собеседник: ${name}`;
                    await loadPrivateMessages(selectedPrivatePeerId);
                });
            });
        } catch (_) {
            profileFriendsList.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">Недоступно</div>';
        }
    };

    friendSearchBtn?.addEventListener('click', async () => {
        const q = friendSearchInput?.value.trim();
        if (!q) return;
        try {
            const users = await apiFetch(`/api/social/users?q=${encodeURIComponent(q)}`);
            friendSearchResults.innerHTML = users.length
                ? users.map((u) => `
                    <div style="display:flex; justify-content:space-between; gap:8px; align-items:center; background:rgba(255,255,255,0.04); padding:8px; border-radius:8px;">
                        <div style="font-size:13px;">${u.username}</div>
                        <button type="button" class="btn btn-primary" data-add-id="${u.id}" style="padding:6px 10px; font-size:11px;">+ Друзья</button>
                    </div>
                `).join('')
                : '<div style="color: var(--text-muted); font-size: 12px;">Никого не найдено</div>';

            friendSearchResults.querySelectorAll('[data-add-id]').forEach((btn) => {
                btn.addEventListener('click', async () => {
                    try {
                        await apiFetch('/api/social/request', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ to_user_id: Number(btn.getAttribute('data-add-id')) })
                        });
                        showNotification('Заявка отправлена', 'success');
                    } catch (err) {
                        showNotification(err.message || 'Не удалось отправить заявку', 'warning');
                    }
                });
            });
        } catch (err) {
            friendSearchResults.innerHTML = `<div style="color: var(--text-muted); font-size: 12px;">${err.message}</div>`;
        }
    });

    privateMessageSend?.addEventListener('click', async () => {
        const text = privateMessageInput?.value.trim();
        if (!selectedPrivatePeerId || !text) return;
        try {
            await apiFetch(`/api/chat/private/${selectedPrivatePeerId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text })
            });
            privateMessageInput.value = '';
            await loadPrivateMessages(selectedPrivatePeerId);
        } catch (err) {
            showNotification(err.message || 'Ошибка отправки личного сообщения', 'warning');
        }
    });

    async function loadPrivateMessages(peerId) {
        if (!privateMessages || !peerId) return;
        try {
            const items = await apiFetch(`/api/chat/private/${peerId}`);
            privateMessages.innerHTML = items.length
                ? items.map((m) => `<div style="font-size:12px;"><span style="color:#a78bfa;">${m.from_user_id === peerId ? 'Друг' : 'Вы'}:</span> ${String(m.message).replace(/</g, '&lt;')}</div>`).join('')
                : '<div style="color: var(--text-muted); font-size: 12px;">Нет сообщений</div>';
            privateMessages.scrollTop = privateMessages.scrollHeight;
        } catch (_) {
            privateMessages.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">Чат недоступен</div>';
        }
    }

    // expose for socket callback
    window.loadPrivateMessages = loadPrivateMessages;

    const token = getToken();
    if (token && typeof window.io === 'function' && !socialSocket) {
        socialSocket = window.io({ auth: { token } });
    }

    if (socialSocket && !profileRealtimeBound) {
        profileRealtimeBound = true;

        socialSocket.on('social_refresh', async () => {
            await renderIncomingRequests();
            await renderProfileFriends();
            await loadFriendsPanel();
            if (selectedPrivatePeerId) {
                await loadPrivateMessages(selectedPrivatePeerId);
            }
        });

        socialSocket.on('online_users', async () => {
            await renderProfileFriends();
            await loadFriendsPanel();
        });
    }

    await renderIncomingRequests();
    await renderProfileFriends();
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

    const token = getToken();
    if (token && typeof window.io === 'function') {
        const adminSocket = window.io({ auth: { token } });
        adminSocket.on('admin_refresh', () => {
            loadAdminData();
        });
        adminSocket.on('online_users', () => {
            loadAdminData();
        });
    }

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