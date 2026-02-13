-- Инициализация базы данных Nexus
-- Сохраните этот код как nexus_schema.sql

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    task_type TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    content TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Базовые данные для тестирования
INSERT OR IGNORE INTO tasks (id, title, status, task_type) VALUES 
('t1', 'Настроить WebSockets (Python)', 'In Progress', 'backend'),
('t2', 'Сделать 3D графы (Vanilla JS)', 'Todo', 'spatial'),
('t3', 'Дизайн окна терминала (CSS)', 'Done', 'ui');

INSERT OR IGNORE INTO files (filename, content) VALUES 
('core_engine.js', '// Nexus Core Engine (Vanilla)
class NexusEntity {
  constructor(id, type) {
    this.id = id;
    this.type = type;
  }
}
const system = new NexusEntity("core", "system");');