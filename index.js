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
 * Map OpenAI-style model name to DeepSeek's internal payload requirements.
 */
function resolveModelParams(modelStr) {
    let m = (modelStr || '').toLowerCase();
    
    // Default fallback values
    let params = {
        model_type: m.includes('flash') || m.includes('instant') || m.includes('default') ? 'default' : 'expert',
        thinking: false,
        search: false
    };

    // Parsing flags
    if (m.includes('thinking') || m.includes('r1') || m.includes('reasoner')) params.thinking = true;
    if (m.includes('search')) params.search = true;

    // Safety constraint: Expert can't have both thinking and search (user directive)
    if (params.model_type === 'expert' && params.thinking && params.search) {
        // Drop search if both are requested on expert
        params.search = false; 
    }

    // Dynamic bypass: if it's none of the hardcoded names, use it as raw model_type just in case
    if (!m.includes('pro') && !m.includes('flash') && !m.includes('expert') && !m.includes('instant') && !m.includes('default')) {
        params.model_type = modelStr;
    }

    return params;
}

/**
 * Build the stateless DeepSeek completion payload.
 * We dump the entire conversation history into a single text prompt.
 */
function buildDSPayload(messages, chatSessionId, modelParams) {
    // Dump everything in one message
    let promptParts = [];
    for (let m of messages) {
        if (!m.content) continue;
        if (m.role === 'system') promptParts.push(`[System]:\n${m.content}`);
        else if (m.role === 'assistant') promptParts.push(`[Assistant]:\n${m.content}`);
        else promptParts.push(`[User]:\n${m.content}`);
    }
    
    let combinedPrompt = promptParts.join('\n\n');

    return {
        chat_session_id: chatSessionId,
        parent_message_id: null,
        model_type: modelParams.model_type,
        prompt: combinedPrompt,
        ref_file_ids: [],
        thinking_enabled: modelParams.thinking,
        search_enabled: modelParams.search,
        action: null,
        preempt: false
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

    // cURL Extraction Logic — handles: -b '...', --cookie '...', -H 'cookie: ...', and 'authorization: Bearer ...'
    if (rawToken.includes('curl ') || rawToken.includes('-b ') || rawToken.includes('--cookie') || rawToken.includes('ds_session_id')) {
        let cookieMatch = rawToken.match(/(?:-b|--cookie)\s+['"]([^'"]+)['"]/i)
            || rawToken.match(/['"]([^'"]*ds_session_id=[^'"]+)['"]/i) || [null, rawToken];
        
        let cookieStr = cookieMatch[1] || rawToken;
        let dsMatch = cookieStr.match(/ds_session_id=([^;\s\\]+)/);
        let wafMatch = cookieStr.match(/aws-waf-token=([^;\s\\'"]+)/);
        let bearerMatch = rawToken.match(/(?:authorization:\s*Bearer|bearer)\s+([A-Za-z0-9+/=a-z0-9_-]+)/i);
        
        if (!dsMatch) return res.status(400).json({ error: "Failed to extract ds_session_id. Make sure you copied the request from chat.deepseek.com using 'Copy as cURL (bash)'." });
        if (!bearerMatch) return res.status(400).json({ error: "Failed to extract Bearer token from the cURL payload. DeepSeek requires both cookies and the JWT token." });
        
        let finalCookie = `ds_session_id=${dsMatch[1].trim()}`;
        if (wafMatch) finalCookie += `; aws-waf-token=${wafMatch[1].trim()}`;
        
        rawToken = JSON.stringify({
            bearer: bearerMatch[1],
            cookie: finalCookie
        });
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
        req.on('aborted', () => { abortController.abort(); });

        if (!messages || !Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ error: { message: 'messages array required', type: 'invalid_request' } });
        }

        var hasUser = messages.some(m => m.role === 'user');
        if (!hasUser) {
            return res.status(400).json({ error: { message: 'At least one user message required', type: 'invalid_request' } });
        }

        var account = getNextAccount();
        if (!account) {
            return res.status(503).json({ error: { message: 'No active accounts available', type: 'server_error' } });
        }

        var completionId = generateId();

        // We are going fully stateless: every API call makes a brand new chat on deepseek
        var dsToken = await getAccountToken(account);
        var chatSessionId = await createNewChat(dsToken);

        bumpAccountUsage(account.id);

        console.log(`[Stateless] New Request: msgs=${messages.length} | model=${model} | account=${account.email}`);

        // ── Solve PoW ──
        var powResponse = await generatePowHeader(dsToken);

        // ── Build payload ──
        var modelParams = resolveModelParams(model);
        var dsPayload = buildDSPayload(messages, chatSessionId, modelParams);

        // ── Stream from DeepSeek ──
        if (stream) {
            console.log("\n[PROXY DS PAYLOAD]:", JSON.stringify(dsPayload, null, 2));

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');

            res.write(buildOpenAIChunk(completionId, model, { role: 'assistant', content: '' }, null, null));

            var lastMsgId = null;
            var lastUserMsgId = null;
            var totalContent = '';

            let isThinking = false;

            try {
                for await (var event of sendChatCompletion(dsToken, dsPayload, abortController.signal, powResponse)) {
                    let contentDelta = null;

                    // DeepSeek JSON Diff Stream parsing
                    if (typeof event.v === 'string') {
                        // Incremental token
                        if (!event.p || event.p.endsWith('/content')) {
                            contentDelta = event.v;
                        }
                    } else if (Array.isArray(event.v) && event.v[0]?.content) {
                        // New fragment appended (e.g transition from THINK to RESPONSE block)
                        let frag = event.v[0];
                        if (frag.type === 'RESPONSE' && isThinking) {
                            contentDelta = "\n</think>\n\n" + frag.content;
                            isThinking = false;
                        } else {
                            contentDelta = frag.content;
                        }
                    } else if (event.v?.response?.fragments?.length > 0) {
                        // Initial root payload
                        let frag = event.v.response.fragments[0];
                        contentDelta = frag.content;
                        if (frag.type === 'THINK') {
                            isThinking = true;
                            contentDelta = "<think>\n" + contentDelta;
                        }
                    }

                    if (contentDelta) {
                        totalContent += contentDelta;
                        res.write(buildOpenAIChunk(completionId, model, { content: contentDelta }, null, null));
                    }
                }
            } catch (streamErr) {
                if (streamErr.name !== 'AbortError') {
                    console.error('[Stream Error]', streamErr.message);
                    res.write(buildOpenAIChunk(completionId, model, { content: `\n\n⚠️ **[PROXY ERROR]** ${streamErr.message}` }, null, null));
                }
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
                let isThinking = false;
                for await (var event of sendChatCompletion(dsToken, dsPayload, abortController.signal, powResponse)) {
                    let contentDelta = null;

                    if (typeof event.v === 'string') {
                        if (!event.p || event.p.endsWith('/content')) {
                            contentDelta = event.v;
                        }
                    } else if (Array.isArray(event.v) && event.v[0]?.content) {
                        let frag = event.v[0];
                        if (frag.type === 'RESPONSE' && isThinking) {
                            contentDelta = "\n</think>\n\n" + frag.content;
                            isThinking = false;
                        } else {
                            contentDelta = frag.content;
                        }
                    } else if (event.v?.response?.fragments?.length > 0) {
                        let frag = event.v.response.fragments[0];
                        contentDelta = frag.content;
                        if (frag.type === 'THINK') {
                            isThinking = true;
                            contentDelta = "<think>\n" + contentDelta;
                        }
                        if (event.v.response.message_id) lastMsgId = event.v.response.message_id;
                        if (event.v.response.parent_id) lastUserMsgId = event.v.response.parent_id;
                    }

                    if (contentDelta) {
                        allContent.push(contentDelta);
                    }
                }
            } catch (streamErr) {
                console.error('[Stream Error]', streamErr.message);
                if (!lastMsgId) {
                    allContent.push(`\n\n⚠️ **[PROXY ERROR]** ${streamErr.message}`);
                }
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
