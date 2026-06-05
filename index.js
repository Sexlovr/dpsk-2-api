import express from 'express';
import { config } from 'dotenv';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { getDB, initDB, cleanupOldConversations } from './lib/database.js';
import {
    initWasm, login as dsLogin, createPowChallenge,
    createNewChat, generatePowHeader, sendChatCompletion, solvePow
} from './lib/deepseekClient.js';
import { buildAdminPage } from './lib/page.js';
config();

var app = express();
app.use(express.json({ limit: '10mb' }));

var PORT = process.env.PORT || 3000;
var ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
var JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
var CONV_TIMEOUT = parseInt(process.env.CONV_TIMEOUT_MINUTES) || 60;

var rrIndex = 0;

// ══════════════════════════════════════════
//  Helper Functions
// ══════════════════════════════════════════

function hashApiKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex').slice(0, 32);
}

function generateId() {
    return 'chatcmpl-' + crypto.randomBytes(12).toString('hex');
}

function getNextAccount() {
    var db = getDB();
    var accounts = db.prepare('SELECT * FROM accounts WHERE active = 1').all();
    if (accounts.length === 0) return null;
    rrIndex = rrIndex % accounts.length;
    var account = accounts[rrIndex];
    rrIndex++;
    return account;
}

function bumpAccountUsage(accountId) {
    getDB().prepare("UPDATE accounts SET request_count = request_count + 1, last_used = datetime('now') WHERE id = ?").run(accountId);
}

/**
 * Get or refresh the bearer token for an account.
 */
async function getAccountToken(account) {
    if (!account.token) {
        throw new Error(`Account ${account.email} has no token provided`);
    }
    return account.token;
}

/**
 * Generate a conversation fingerprint from messages.
 */
function generateConvKey(messages) {
    // Use first 3 user messages to create a stable fingerprint
    var userMsgs = messages.filter(m => m.role === 'user');
    var sample = userMsgs.slice(0, 3).map(m => (m.content || '').slice(0, 200)).join('|||');
    return crypto.createHash('sha256').update(sample).digest('hex');
}

/**
 * Convert OpenAI messages format to a DeepSeek prompt string.
 * DeepSeek just wants a prompt string; we merge chat history.
 */
function messagesToPrompt(messages) {
    var parts = [];
    for (var m of messages) {
        var role = m.role;
        var content = m.content || '';
        if (role === 'system') {
            parts.push(content);
        } else if (role === 'user') {
            parts.push(content);
        } else if (role === 'assistant') {
            // Only include for continuation context
            parts.push(content);
        }
    }
    return parts;
}

/**
 * Build the DeepSeek completion payload.
 */
function buildDSPayload(messages, chatSessionId, model, parentMsgId) {
    // Get the last user message
    var lastUserMsg = '';
    for (var i = messages.length - 1; i >= 0; i--) {
        if (messages[i].role === 'user') {
            lastUserMsg = messages[i].content || '';
            break;
        }
    }

    // Build the system prompt from system messages
    var systemPrompt = messages
        .filter(m => m.role === 'system')
        .map(m => m.content || '')
        .join('\n');

    // For continuation, we only send the latest user message
    var prompt = lastUserMsg;
    if (systemPrompt && !parentMsgId) {
        prompt = systemPrompt + '\n\n' + lastUserMsg;
    }

    var thinking = model === 'deepseek_r1';

    return {
        chat_session_id: chatSessionId,
        parent_message_id: parentMsgId || '0',
        prompt: prompt,
        ref_file_ids: [],
        thinking_enabled: thinking,
        search_enabled: false
    };
}

function buildOpenAIChunk(id, model, delta, finishReason, usage) {
    var obj = {
        id: id,
        object: 'chat.completion.chunk',
        created: Math.floor(Date.now() / 1000),
        model: model,
        choices: [{
            index: 0,
            delta: delta,
            finish_reason: finishReason || null
        }]
    };
    if (usage) obj.usage = usage;
    return 'data: ' + JSON.stringify(obj) + '\n\n';
}

function buildOpenAIResponse(id, model, content, usage) {
    return {
        id: id,
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: model,
        choices: [{
            index: 0,
            message: { role: 'assistant', content: content },
            finish_reason: 'stop'
        }],
        usage: usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
    };
}

// ══════════════════════════════════════════
//  MIDDLEWARE
// ══════════════════════════════════════════

function adminAuth(req, res, next) {
    var authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        var decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        if (decoded.role !== 'admin') throw new Error();
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function apiKeyAuth(req, res, next) {
    var authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: { message: 'Missing API key', type: 'auth_error' } });
    }
    var key = authHeader.split(' ')[1];
    var db = getDB();
    var row = db.prepare('SELECT * FROM api_keys WHERE key = ? AND active = 1').get(key);
    if (!row) {
        return res.status(401).json({ error: { message: 'Invalid API key', type: 'auth_error' } });
    }
    db.prepare('UPDATE api_keys SET request_count = request_count + 1 WHERE id = ?').run(row.id);
    req.apiKey = key;
    req.apiKeyHash = hashApiKey(key);
    next();
}

// ══════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════

app.post('/admin/login', function (req, res) {
    var password = req.body.password;
    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: 'Wrong password' });
    }
    var token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token: token });
});

// ── Accounts ──
app.get('/admin/accounts', adminAuth, function (req, res) {
    var rows = getDB().prepare('SELECT id, email, token, expires_at, active, request_count, last_used FROM accounts').all();
    res.json(rows);
});

app.post('/admin/accounts', adminAuth, async function (req, res) {
    var email = req.body.email;
    var rawToken = req.body.token || '';
    if (!email) return res.status(400).json({ error: 'Email required' });
    if (!rawToken) return res.status(400).json({ error: 'Token required' });

    // cURL Extraction Logic
    if (rawToken.includes('curl ') || rawToken.includes('--cookie') || rawToken.includes('-H \'cookie:')) {
        let cookieMatch = rawToken.match(/(?:--cookie|-H\s+['"]cookie:|-H\s+["']Cookie:)\s*['"]?([^'"]+)/i);
        if (cookieMatch) {
            let cookieStr = cookieMatch[1];
            let dsMatch = cookieStr.match(/ds_session_id=([^;]+)/);
            let wafMatch = cookieStr.match(/aws-waf-token=([^;]+)/);
            
            if (!dsMatch) return res.status(400).json({ error: "Failed to extract ds_session_id from the provided cURL. Are you sure you copied the request from chat.deepseek.com?" });
            
            rawToken = `ds_session_id=${dsMatch[1]}`;
            if (wafMatch) rawToken += `; aws-waf-token=${wafMatch[1]}`;
        }
    }

    var db = getDB();

    try {
        var existing = db.prepare('SELECT id FROM accounts WHERE email = ?').get(email);
        if (existing) {
            db.prepare('UPDATE accounts SET token = ?, active = 1, password = ? WHERE id = ?').run(rawToken, '', existing.id);
            return res.json({ message: 'Token updated & extracted!', id: existing.id });
        }
        var r = db.prepare('INSERT INTO accounts (email, password, token) VALUES (?, ?, ?)').run(email, '', rawToken);
        return res.json({ message: 'Account saved with extracted token!', id: r.lastInsertRowid });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});


app.delete('/admin/accounts/:id', adminAuth, function (req, res) {
    getDB().prepare('DELETE FROM accounts WHERE id = ?').run(req.params.id);
    getDB().prepare('DELETE FROM conversations WHERE account_id = ?').run(req.params.id);
    res.json({ message: 'Deleted' });
});

app.patch('/admin/accounts/:id', adminAuth, function (req, res) {
    if (req.body.active !== undefined) {
        getDB().prepare('UPDATE accounts SET active = ? WHERE id = ?').run(req.body.active ? 1 : 0, req.params.id);
    }
    res.json({ message: 'Updated' });
});

// Playwright-based automated login — captures real token from browser session



// ── API Keys ──
app.get('/admin/keys', adminAuth, function (req, res) {
    var rows = getDB().prepare('SELECT * FROM api_keys').all();
    res.json(rows);
});

app.post('/admin/keys', adminAuth, function (req, res) {
    var name = req.body.name;
    var key = 'sk-ds-' + crypto.randomBytes(24).toString('hex');
    var result = getDB().prepare('INSERT INTO api_keys (name, key) VALUES (?, ?)').run(name || '', key);
    res.json({ message: 'Key created', id: result.lastInsertRowid, key: key });
});

app.delete('/admin/keys/:id', adminAuth, function (req, res) {
    getDB().prepare('DELETE FROM api_keys WHERE id = ?').run(req.params.id);
    res.json({ message: 'Deleted' });
});

app.patch('/admin/keys/:id', adminAuth, function (req, res) {
    if (req.body.active !== undefined) {
        getDB().prepare('UPDATE api_keys SET active = ? WHERE id = ?').run(req.body.active ? 1 : 0, req.params.id);
    }
    res.json({ message: 'Updated' });
});

// ── Models ──
app.get('/admin/models', adminAuth, function (req, res) {
    var rows = getDB().prepare('SELECT * FROM models').all();
    res.json(rows);
});

app.post('/admin/models', adminAuth, function (req, res) {
    var model_id = req.body.model_id;
    var display_name = req.body.display_name;
    if (!model_id) return res.status(400).json({ error: 'model_id required' });
    try {
        var result = getDB().prepare('INSERT INTO models (model_id, display_name) VALUES (?, ?)').run(model_id, display_name || model_id);
        res.json({ message: 'Model added', id: result.lastInsertRowid });
    } catch (e) {
        if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Model already exists' });
        throw e;
    }
});

app.delete('/admin/models/:id', adminAuth, function (req, res) {
    getDB().prepare('DELETE FROM models WHERE id = ?').run(req.params.id);
    res.json({ message: 'Deleted' });
});

app.patch('/admin/models/:id', adminAuth, function (req, res) {
    if (req.body.active !== undefined) {
        getDB().prepare('UPDATE models SET active = ? WHERE id = ?').run(req.body.active ? 1 : 0, req.params.id);
    }
    res.json({ message: 'Updated' });
});

// ── Conversations ──
app.get('/admin/conversations', adminAuth, function (req, res) {
    var rows = getDB().prepare(
        'SELECT c.id, c.conv_key, c.ds_chat_session_id, c.account_id, c.message_count, ' +
        'c.model, c.last_used, c.created_at, a.email ' +
        'FROM conversations c ' +
        'LEFT JOIN accounts a ON c.account_id = a.id ' +
        'ORDER BY c.last_used DESC LIMIT 100'
    ).all();
    res.json(rows);
});

app.delete('/admin/conversations', adminAuth, function (req, res) {
    var result = getDB().prepare('DELETE FROM conversations').run();
    res.json({ message: 'Cleared ' + result.changes + ' conversations' });
});

// ══════════════════════════════════════════
//  OPENAI-COMPATIBLE ROUTES
// ══════════════════════════════════════════

app.get('/v1/models', apiKeyAuth, function (req, res) {
    var rows = getDB().prepare('SELECT * FROM models WHERE active = 1').all();
    res.json({
        object: 'list',
        data: rows.map(function (r) {
            return {
                id: r.model_id,
                object: 'model',
                created: Math.floor(Date.now() / 1000),
                owned_by: 'deepseek'
            };
        })
    });
});

app.post('/v1/chat/completions', apiKeyAuth, async function (req, res) {
    var db = getDB();

    try {
        var messages = req.body.messages;
        var model = req.body.model || 'deepseek_chat';
        var stream = req.body.stream;

        var abortController = new AbortController();
        req.on('close', () => { abortController.abort(); });

        if (!messages || !Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ error: { message: 'messages array required', type: 'invalid_request' } });
        }

        var hasUser = messages.some(m => m.role === 'user');
        if (!hasUser) {
            return res.status(400).json({ error: { message: 'At least one user message required', type: 'invalid_request' } });
        }

        var completionId = generateId();
        var convKey = generateConvKey(messages);
        var apiKeyHash = req.apiKeyHash;

        // ── Look up existing conversation ──
        var timeoutModifier = '-' + CONV_TIMEOUT + ' minutes';
        var conv = db.prepare(
            "SELECT * FROM conversations WHERE conv_key = ? AND api_key_hash = ? AND last_used > datetime('now', ?)"
        ).get(convKey, apiKeyHash, timeoutModifier);

        var account, dsToken, chatSessionId, parentMessageId;

        if (conv && messages.length > conv.message_count) {
            // ═══ CONTINUATION ═══
            account = db.prepare('SELECT * FROM accounts WHERE id = ? AND active = 1').get(conv.account_id);
            if (account) {
                chatSessionId = conv.ds_chat_session_id;
                parentMessageId = conv.parent_message_id || '0';
                console.log(`[Conv] Continuation: ${convKey.slice(0, 12)}... | msgs: ${conv.message_count} -> ${messages.length}`);
            } else {
                db.prepare('DELETE FROM conversations WHERE id = ?').run(conv.id);
                conv = null;
            }
        } else if (conv && messages.length === conv.message_count && conv.parent_message_id) {
            // ═══ REROLL ═══
            account = db.prepare('SELECT * FROM accounts WHERE id = ? AND active = 1').get(conv.account_id);
            if (account) {
                chatSessionId = conv.ds_chat_session_id;
                // For reroll, use the last user msg id as parent (go back one step)
                parentMessageId = conv.last_user_msg_id || conv.parent_message_id || '0';
                console.log(`[Conv] Reroll: ${convKey.slice(0, 12)}... | msgs: ${messages.length}`);
            } else {
                db.prepare('DELETE FROM conversations WHERE id = ?').run(conv.id);
                conv = null;
            }
        } else {
            conv = null;
        }

        if (!conv) {
            // ═══ NEW CONVERSATION ═══
            db.prepare('DELETE FROM conversations WHERE conv_key = ? AND api_key_hash = ?').run(convKey, apiKeyHash);

            account = getNextAccount();
            if (!account) {
                return res.status(503).json({ error: { message: 'No active accounts available', type: 'server_error' } });
            }

            dsToken = await getAccountToken(account);
            chatSessionId = await createNewChat(dsToken);
            parentMessageId = '0';

            db.prepare(
                'INSERT INTO conversations (conv_key, api_key_hash, ds_chat_session_id, account_id, message_count, root_message_count, model) VALUES (?, ?, ?, ?, ?, ?, ?)'
            ).run(convKey, apiKeyHash, chatSessionId, account.id, messages.length, messages.length, model);

            console.log(`[Conv] New: ${convKey.slice(0, 12)}... | msgs: ${messages.length} | account: ${account.email}`);
        }

        if (!dsToken) {
            dsToken = await getAccountToken(account);
        }

        bumpAccountUsage(account.id);

        // ── Solve PoW ──
        var powResponse = await generatePowHeader(dsToken);

        // ── Build payload ──
        var dsPayload = buildDSPayload(messages, chatSessionId, model, parentMessageId);

        // ── Stream from DeepSeek ──
        if (stream) {
            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');

            res.write(buildOpenAIChunk(completionId, model, { role: 'assistant', content: '' }, null, null));

            var lastMsgId = null;
            var lastUserMsgId = null;
            var totalContent = '';

            try {
                for await (var event of sendChatCompletion(dsToken, dsPayload, abortController.signal, powResponse)) {
                    // DeepSeek SSE events have different shapes
                    // Main content comes in choices[0].delta.content or directly in .content
                    if (event.choices && event.choices[0]) {
                        var delta = event.choices[0].delta;
                        if (delta && delta.content !== undefined) {
                            totalContent += delta.content;
                            res.write(buildOpenAIChunk(completionId, model, { content: delta.content }, null, null));
                        }
                        // Track message ID
                        if (event.message_id) lastMsgId = event.message_id;
                    } else if (event.message_id) {
                        lastMsgId = event.message_id;
                        if (event.parent_id) lastUserMsgId = event.parent_id;
                        // content field directly
                        if (event.content !== undefined) {
                            totalContent += event.content;
                            res.write(buildOpenAIChunk(completionId, model, { content: event.content }, null, null));
                        }
                    }
                }
            } catch (streamErr) {
                if (streamErr.name !== 'AbortError') {
                    console.error('[Stream Error]', streamErr.message);
                }
            }

            // Update conversation state
            if (lastMsgId) {
                db.prepare(
                    "UPDATE conversations SET parent_message_id = ?, last_user_msg_id = ?, message_count = ?, model = ?, last_used = datetime('now') WHERE conv_key = ? AND api_key_hash = ?"
                ).run(lastMsgId, lastUserMsgId, messages.length, model, convKey, apiKeyHash);
            }

            res.write(buildOpenAIChunk(completionId, model, {}, 'stop', null));
            res.write('data: [DONE]\n\n');
            res.end();

        } else {
            // ═══ NON-STREAMING ═══
            var allContent = [];
            var lastMsgId = null;
            var lastUserMsgId = null;

            try {
                for await (var event of sendChatCompletion(dsToken, dsPayload, abortController.signal, powResponse)) {
                    if (event.choices && event.choices[0]) {
                        var delta = event.choices[0].delta;
                        if (delta && delta.content !== undefined) allContent.push(delta.content);
                        if (event.message_id) lastMsgId = event.message_id;
                    } else if (event.message_id) {
                        lastMsgId = event.message_id;
                        if (event.parent_id) lastUserMsgId = event.parent_id;
                        if (event.content !== undefined) allContent.push(event.content);
                    }
                }
            } catch (streamErr) {
                console.error('[Stream Error]', streamErr.message);
            }

            if (lastMsgId) {
                db.prepare(
                    "UPDATE conversations SET parent_message_id = ?, last_user_msg_id = ?, message_count = ?, model = ?, last_used = datetime('now') WHERE conv_key = ? AND api_key_hash = ?"
                ).run(lastMsgId, lastUserMsgId, messages.length, model, convKey, apiKeyHash);
            }

            res.json(buildOpenAIResponse(completionId, model, allContent.join('')));
        }

    } catch (err) {
        if (err.name === 'AbortError') {
            console.log('[Abort] Client disconnected.');
            return res.end();
        }
        console.error('[/v1/chat/completions Error]', err);
        if (!res.headersSent) {
            res.status(502).json({
                error: {
                    message: 'Upstream error: ' + err.message,
                    type: 'upstream_error'
                }
            });
        } else {
            res.end();
        }
    }
});

// ── Admin Page ──
app.get('/', function (req, res) {
    res.setHeader('Content-Type', 'text/html');
    res.send(buildAdminPage());
});

// ══════════════════════════════════════════
//  BOOT
// ══════════════════════════════════════════

async function boot() {
    await initDB();
    console.log('[Boot] Database ready');

    await initWasm();
    console.log('[Boot] WASM PoW solver ready');

    setInterval(function () {
        try { cleanupOldConversations(); } catch (e) { console.error('[Cleanup]', e.message); }
    }, 60 * 60 * 1000);

    app.listen(PORT, function () {
        console.log('');
        console.log('  ╔══════════════════════════════════════╗');
        console.log('  ║     DeepSeek2API Reverse Proxy       ║');
        console.log('  ╠══════════════════════════════════════╣');
        console.log('  ║  Admin Panel : http://localhost:' + PORT + '   ║');
        console.log('  ║  API Base    : http://localhost:' + PORT + '/v1 ║');
        console.log('  ╠══════════════════════════════════════╣');
        console.log('  ║  PoW solver  : WASM (sha3)          ║');
        console.log('  ║  Conv timeout: ' + CONV_TIMEOUT + ' min             ║');
        console.log('  ╚══════════════════════════════════════╝');
        console.log('');
    });
}

boot().catch(e => {
    console.error('[FATAL]', e);
    process.exit(1);
});
