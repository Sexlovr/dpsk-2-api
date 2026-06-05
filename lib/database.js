import path from 'path';
import fs from 'fs';
import initSqlJs from 'sql.js';

const dataDir = (process.env.DATA_DIR || path.join(process.cwd(), 'data')).trim();
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const dbPath = path.join(dataDir, 'deepseek.db');

let db = null;
let SQL = null;

export async function initDB() {
    SQL = await initSqlJs();
    if (fs.existsSync(dbPath)) {
        const buf = fs.readFileSync(dbPath);
        db = new SQL.Database(buf);
    } else {
        db = new SQL.Database();
    }

    db.run(`
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            token TEXT,
            expires_at INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            request_count INTEGER DEFAULT 0,
            last_used DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT DEFAULT '',
            key TEXT NOT NULL UNIQUE,
            active INTEGER DEFAULT 1,
            request_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS models (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_id TEXT NOT NULL UNIQUE,
            display_name TEXT,
            active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conv_key TEXT NOT NULL,
            api_key_hash TEXT NOT NULL,
            ds_chat_session_id TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            message_count INTEGER DEFAULT 0,
            root_message_count INTEGER,
            model TEXT,
            parent_message_id TEXT,
            last_user_msg_id TEXT,
            last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(conv_key, api_key_hash)
        );
    `);

    // Seed/update models to latest set
    const MODEL_VERSION = 2; // bump this to re-seed models
    const versionCheck = db.exec("SELECT COUNT(*) as c FROM models WHERE model_id LIKE 'deepseek-v4%'");
    const hasNewModels = versionCheck.length && versionCheck[0].values[0][0] > 0;
    if (!hasNewModels) {
        db.run("DELETE FROM models");
        const newModels = [
            ["deepseek-v4-pro", "DeepSeek V4 Pro"],
            ["deepseek-v4-pro-thinking", "DeepSeek V4 Pro (Thinking)"],
            ["deepseek-v4-pro-search", "DeepSeek V4 Pro (Search)"],
            ["deepseek-v4-flash", "DeepSeek V4 Flash"],
            ["deepseek-v4-flash-thinking", "DeepSeek V4 Flash (Thinking)"],
            ["deepseek-v4-flash-search", "DeepSeek V4 Flash (Search)"],
            ["deepseek-v4-flash-search-thinking", "DeepSeek V4 Flash (Search+Thinking)"]
        ];
        for (const [mid, name] of newModels) {
            db.run(`INSERT INTO models (model_id, display_name) VALUES ('${mid}', '${name}')`);
        }
    }

    saveDB();
    console.log('[DB] SQLite initialized at', dbPath);
}

function saveDB() {
    if (!db) return;
    const data = db.export();
    fs.writeFileSync(dbPath, Buffer.from(data));
}

// Auto-save every 30 seconds
setInterval(() => { try { saveDB(); } catch {} }, 30000);

// ── Wrapper that mimics better-sqlite3 API ──
// sql.js uses a different API, so we wrap it

function runStmt(sql, params) {
    db.run(sql, params);
    saveDB();
    // Get last insert rowid
    const r = db.exec("SELECT last_insert_rowid() as id");
    const lastId = r.length ? r[0].values[0][0] : 0;
    const c = db.exec("SELECT changes() as c");
    const changes = c.length ? c[0].values[0][0] : 0;
    return { lastInsertRowid: lastId, changes };
}

function getStmt(sql, params) {
    const stmt = db.prepare(sql);
    if (params) stmt.bind(params);
    if (stmt.step()) {
        const row = stmt.getAsObject();
        stmt.free();
        return row;
    }
    stmt.free();
    return null;
}

function allStmt(sql, params) {
    const rows = [];
    const stmt = db.prepare(sql);
    if (params) stmt.bind(params);
    while (stmt.step()) {
        rows.push(stmt.getAsObject());
    }
    stmt.free();
    return rows;
}

// ── Public API that matches what index.js expects ──
// Returns a "db-like" object with a prepare() that returns run/get/all

export function getDB() {
    return {
        prepare: (sql) => ({
            run: (...args) => runStmt(sql, args.length ? args : undefined),
            get: (...args) => getStmt(sql, args.length ? args : undefined),
            all: (...args) => allStmt(sql, args.length ? args : undefined)
        }),
        exec: (sql) => db.run(sql)
    };
}

export function cleanupOldConversations() {
    runStmt("DELETE FROM conversations WHERE last_used < datetime('now', '-24 hours')");
}

export default { getDB, initDB, cleanupOldConversations };
